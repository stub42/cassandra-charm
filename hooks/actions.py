from contextlib import closing
import errno
import glob
import json
import os.path
import re
import shlex
import subprocess

import cassandra
import cassandra.query

from charmhelpers import fetch
from charmhelpers.core import hookenv, host
from charmhelpers.core.fstab import Fstab
from charmhelpers.core.hookenv import WARNING

import helpers
import relations
import rollingrestart


# FOR CHARMHELPERS
def preinstall(servicename):
    '''Preinstallation data_ready hook.'''
    # Only run the preinstall hooks from the actual install hook.
    if hookenv.hook_name() == 'install':
        # Pre-exec
        pattern = os.path.join(hookenv.charm_dir(),
                               'exec.d', '*', 'charm-pre-install')
        for f in sorted(glob.glob(pattern)):
            if os.path.isfile(f) and os.access(f, os.X_OK):
                hookenv.log('Running preinstall hook {}'.format(f))
                subprocess.check_call(['sh', '-c', f])
            else:
                hookenv.log('Ingnoring preinstall hook {}'.format(f),
                            WARNING)
        else:
            hookenv.log('No preinstall hooks found')


# FOR CHARMHELPERS
def swapoff(servicename, fstab='/etc/fstab'):
    '''Turn off swapping in the container, permanently.'''
    # Turn off swap in the current session
    if helpers.is_lxc():
        hookenv.log("In an LXC. Not touching swap.")
        return
    else:
        try:
            subprocess.check_call(['swapoff', '-a'])
        except Exception as e:
            hookenv.log("Got an error trying to turn off swapping. {}. "
                        "We may be in an LXC. Exiting gracefully"
                        "".format(e), WARNING)
            return

    # Disable swap permanently
    with closing(Fstab(fstab)) as fstab:
        while True:
            swap_entry = fstab.get_entry_by_attr('filesystem', 'swap')
            if swap_entry is None:
                break
            fstab.remove_entry(swap_entry)


# FOR CHARMHELPERS
def configure_sources(servicename):
    '''Standard charmhelpers package source configuration.'''
    config = hookenv.config()
    if config.changed('install_sources') or config.changed('install_keys'):
        fetch.configure_sources(True)


def add_implicit_package_signing_keys(servicename):
    # Rather than blindly add these keys, we should sniff
    # config['install_sources'] for apache.org or datastax.com urls and
    # add only the appropriate keys.
    for key in ('apache', 'datastax'):
        path = os.path.join(hookenv.charm_dir(), 'lib', '{}.key'.format(key))
        subprocess.check_call(['apt-key', 'add', path],
                              stdin=subprocess.DEVNULL)


def reset_sysctl(servicename):
    '''Configure sysctl settings for Cassandra'''
    if helpers.is_lxc():
        hookenv.log("In an LXC. Leaving sysctl unchanged.")
    else:
        cassandra_sysctl_file = os.path.join('/', 'etc', 'sysctl.d',
                                             '99-cassandra.conf')
        contents = "vm.max_map_count = 131072\n"
        try:
            host.write_file(cassandra_sysctl_file, contents)
            subprocess.check_call(['sysctl', '-p', cassandra_sysctl_file])
        except OSError as e:
            if e.errno == errno.EACCES:
                hookenv.log("Got Permission Denied trying to set the "
                            "sysctl settings at {}. We may be in an LXC. "
                            "Exiting gracefully".format(cassandra_sysctl_file),
                            WARNING)
            else:
                raise


# FOR CHARMHELPERS
def ensure_package_status(servicename, packages):
    config_dict = hookenv.config()

    package_status = config_dict['package_status']
    # TODO: dse
    # if config_dict['dse']:
    #     packages = ['dse']
    # else:

    if package_status not in ['install', 'hold']:
        raise RuntimeError("package_status must be 'install' or 'hold', "
                           "not {!r}".format(package_status))

    selections = []
    for package in packages:
        selections.append('{} {}\n'.format(package, package_status))
    dpkg = subprocess.Popen(['dpkg', '--set-selections'],
                            stdin=subprocess.PIPE)
    dpkg.communicate(input=''.join(selections).encode('US-ASCII'))


# FOR CHARMHELPERS
def install_packages(servicename, packages):
    packages = list(packages)
    if hookenv.config('extra_packages'):
        packages.extend(hookenv.config('extra_packages').split())
    packages = fetch.filter_installed_packages(packages)
    # if 'ntp' in packages:
    #     fetch.apt_install(['ntp'], fatal=True)  # With autostart
    #     packages.remove('ntp')
    if packages:
        with helpers.autostart_disabled(['cassandra']):
            fetch.apt_install(packages, fatal=True)


def install_cassandra_packages(servicename):
    install_packages(servicename, helpers.get_cassandra_packages())


def ensure_cassandra_package_status(servicename):
    ensure_package_status(servicename, helpers.get_cassandra_packages())


def configure_cassandra_yaml(servicename):
    helpers.configure_cassandra_yaml()


def configure_cassandra_env(servicename):
    cassandra_env_path = helpers.get_cassandra_env_file()
    assert os.path.exists(cassandra_env_path)

    helpers.maybe_backup(cassandra_env_path)

    overrides = [
        ('max_heap_size', re.compile(r'^#?(MAX_HEAP_SIZE)=(.*)$', re.M)),
        ('heap_newsize', re.compile(r'^#?(HEAP_NEWSIZE)=(.*)$', re.M)),
        ('jmx_port', re.compile(r'^#?(JMX_PORT)=(.*)$', re.M)),
    ]

    with open(cassandra_env_path, 'r') as f:
        env = f.read()

    config = hookenv.config()
    for key, regexp in overrides:
        if config[key]:
            val = shlex.quote(str(config[key]))
            env = regexp.sub(r'\g<1>={}  # Juju service config'.format(val),
                             env)
        else:
            env = regexp.sub(r'#\1=\2  # Juju service config', env)
    host.write_file(cassandra_env_path, env.encode('UTF-8'))


# Unfortunately, we can't decommission a unit in its peer
# relation-broken hook. Decomissioning a unit involves streaming its
# data to the remaining nodes. If the entire service is being torn down,
# this will almost certainly fail as the data ends up on fewer and fewer
# units until the remaining units run out of disk space.
#
# def maybe_decommission(servicename):
#     peer_relname = rollingrestart.get_peer_relation_name()
#     if hookenv.hook_name() == '{}-relation-broken'.format(peer_relname):
#         i = 1
#         while True:
#             hookenv.log('Unit leaving service. '
#                         'Decommissioning Cassandra node. '
#                         'Attempt {}.'.format(i), WARNING)
#             rv = subprocess.call(['nodetool', 'decommission'],
#                                  stderr=subprocess.DEVNULL)
#             if rv == 0:
#                 break
#             assert rv == 2, 'Unknown return value from nodetool decommission'
#             time.sleep(max(2 ** i, 120))
#             i += 1
#
#         # Node is dead, so restart will fail.
#         rollingrestart.cancel_restart()


# If any of these config items are changed, Cassandra needs to be
# restarted and maybe remounted.
RESTART_REQUIRED_KEYS = set([
    'cluster_name',
    'data_file_directories',
    'commitlog_directory',
    'saved_caches_directory',
    'cluster_port',
    'cluster_ssl_port',
    'thrift_client_port',
    'native_client_port',
    'jmx_port',
    'partitioner',
    'num_tokens',
    'force_seed_nodes',
    'max_heap_size',
    'heap_newsize',
    'edition',  # TODO: Is it possible to switch edition?
    'jvm'])


# All other config items. By maintaining both lists, we can
# detect any new config items added or changed and ensure
# these lists are updated.
RESTART_NOT_REQUIRED_KEYS = set([
    'extra_packages',
    'package_status',
    'install_sources',
    'install_keys',
    'wait_for_storage_broker',
    'io_scheduler',
    'nagios_context',
    'nagios_servicegroups',
    'nagios_heapchk_warn_pct',
    'nagios_heapchk_crit_pct',
    'nagios_disk_warn_pct',
    'nagios_disk_crit_pct'])


def maybe_schedule_restart(servicename):
    '''Prepare for and schedule a rolling restart if necessary.'''
    # If any of these config items changed, a restart is required.
    config = hookenv.config()
    restart = False
    for key in RESTART_REQUIRED_KEYS:
        if config.changed(key):
            hookenv.log('{} changed. Restart required.'.format(key))
            restart = True

    # If the directory paths have changed, we need to migrate data
    # during a restart. Directory config items have already been picked
    # up in the previous check.
    storage = relations.StorageRelation()
    if storage.needs_remount():
        hookenv.log('Mountpoint changed. Restart and migration required.')
        restart = True

    # If the seedlist has changed, we need to restart.
    config['configured_seeds'] = helpers.get_seeds()
    if config.changed('configured_seeds'):
        hookenv.log('Seed list changed. Restart required.')
        restart = True

    # If our IP address has changed, we need to restart.
    config['unit_private_ip'] = hookenv.unit_private_ip()
    if config.changed('unit_private_ip'):
        hookenv.log('Unit IP address changed. Restart required.')
        restart = True

    if restart:
        rollingrestart.request_restart()


def stop_cassandra(servicename):
    helpers.stop_cassandra()


def start_cassandra(servicename):
    helpers.start_cassandra()


def reset_all_io_schedulers(servicename):
    helpers.reset_all_io_schedulers()


def reset_auth_keyspace_replication_factor(servicename):
    # Cassandra requires you to manually set the replication factor of
    # the system_auth keyspace, to ensure availability and redundancy.
    # The charm can't control how many or which units might get dropped,
    # so for authentication to work we need to set the replication factor
    # on the system_auth keyspace so that every node contains all of the
    # data. Authentication information will remain available, even in the
    # face of all the other nodes having gone away due to an in progress
    # 'juju destroy-service'.
    if not helpers.is_cassandra_running():
        # If Cassandra is not running locally, skip. At least one unit
        # will have a running Cassandra when its cluster-relation-joined
        # hook is invoked, and that is the important place for this to
        # happen.
        return
    num_nodes = len(rollingrestart.get_peers()) + 1
    with helpers.connect() as session:
        r = session.execute(cassandra.query.SimpleStatement('''
            SELECT strategy_options FROM system.schema_keyspaces
            WHERE keyspace_name='system_auth'
            ''', cassandra.ConsistencyLevel.QUORUM))
        if r:
            strategy_options = json.loads(r[0][0])
            rf = int(strategy_options['replication_factor'])
        else:
            rf = 1
        if rf == num_nodes:
            hookenv.log('system_auth rf={}'.format(num_nodes))
        else:
            hookenv.log('Updating system_auth rf={}'.format(num_nodes))
            session.execute(cassandra.query.SimpleStatement('''
                ALTER KEYSPACE system_auth WITH REPLICATION =
                    {'class': 'SimpleStrategy', 'replication_factor': %s}
                ''', cassandra.ConsistencyLevel.QUORUM), (num_nodes,))

    # If the number of nodes, and thus the system_auth rf, we need to
    # repair the system_auth keyspace.
    config = hookenv.config()
    config['num_nodes'] = num_nodes
    if config.changed('num_nodes'):
        subprocess.check_call(['nodetool', 'repair', 'system_auth'])
