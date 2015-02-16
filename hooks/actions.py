# Copyright 2015 Canonical Ltd.
#
# This file is part of the Cassandra Charm for Juju.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from contextlib import closing
import errno
from functools import wraps
import glob
import os.path
import re
import shlex
import subprocess
from textwrap import dedent

from charmhelpers import fetch
from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.contrib.templating import jinja
from charmhelpers.contrib.network import ufw
from charmhelpers.core import hookenv, host
from charmhelpers.core.fstab import Fstab
from charmhelpers.core.hookenv import ERROR, WARNING

import helpers
import relations
import rollingrestart


# These config keys cannot be changed after service deployment.
UNCHANGEABLE_KEYS = set(['cluster_name', 'datacenter', 'rack', 'edition'])

# If any of these config items are changed, Cassandra needs to be
# restarted and maybe remounted.
RESTART_REQUIRED_KEYS = set([
    'data_file_directories',
    'commitlog_directory',
    'saved_caches_directory',
    'storage_port',
    'ssl_storage_port',
    'rpc_port',
    'native_transport_port',
    'partitioner',
    'num_tokens',
    'force_seed_nodes',
    'max_heap_size',
    'heap_newsize',
    'authorizer',
    'compaction_throughput_mb_per_sec',
    'stream_throughput_outbound_megabits_per_sec',
    'tombstone_warn_threshold',
    'tombstone_failure_threshold',
    'jvm'])

ALL_CONFIG_KEYS = UNCHANGEABLE_KEYS.union(RESTART_REQUIRED_KEYS)


# All other config items. By maintaining both lists, we can detect if
# someone forgot to update these lists when they added a new config item.
RESTART_NOT_REQUIRED_KEYS = set([
    'extra_packages',
    'package_status',
    'install_sources',
    'install_keys',
    'http_proxy',
    'wait_for_storage_broker',
    'io_scheduler',
    'nagios_context',
    'nagios_servicegroups',
    'nagios_heapchk_warn_pct',
    'nagios_heapchk_crit_pct',
    'nagios_disk_warn_pct',
    'nagios_disk_crit_pct',
    'post_bootstrap_delay'])


def action(func):
    '''Log and call func, stripping the undesirable servicename argument.
    '''
    @wraps(func)
    def wrapper(servicename, *args, **kw):
        if hookenv.remote_unit():
            hookenv.log("** Action {}/{} ({})".format(hookenv.hook_name(),
                                                      func.__name__,
                                                      hookenv.remote_unit()))
        else:
            hookenv.log("** Action {}/{}".format(hookenv.hook_name(),
                                                 func.__name__))
        return func(*args, **kw)
    return wrapper


@action
def set_proxy():
    config = hookenv.config()
    if config['http_proxy']:
        os.environ['http_proxy'] = config['http_proxy']
        os.environ['https_proxy'] = config['http_proxy']


@action
def revert_unchangeable_config():
    if hookenv.hook_name() == 'install':
        # config.previous() only becomes meaningful after the install
        # hook has run. During the first run on the unit hook, it
        # reports everything has having None as the previous value.
        return

    config = hookenv.config()
    for key in UNCHANGEABLE_KEYS:
        if config.changed(key):
            previous = config.previous(key)
            hookenv.log('{} cannot be changed after service deployment. '
                        'Using original setting {!r}'.format(key, previous),
                        ERROR)
            config[key] = previous


# FOR CHARMHELPERS
@action
def preinstall():
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
@action
def swapoff(fstab='/etc/fstab'):
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
@action
def configure_sources():
    '''Standard charmhelpers package source configuration.'''
    config = hookenv.config()
    if config.changed('install_sources') or config.changed('install_keys'):
        fetch.configure_sources(True)


@action
def add_implicit_package_signing_keys():
    # Rather than blindly add these keys, we should sniff
    # config['install_sources'] for apache.org or datastax.com urls and
    # add only the appropriate keys.
    for key in ('apache', 'datastax'):
        path = os.path.join(hookenv.charm_dir(), 'lib', '{}.key'.format(key))
        subprocess.check_call(['apt-key', 'add', path],
                              stdin=subprocess.DEVNULL)


@action
def cache_oracle_jdk():
    '''Put Oracle JDK tarballs included in this charm into the right location.

    Operators use this feature to avoid the Oracle JDK tarball download
    by branching this charm and placing a copy of the tarball in the
    lib directory. Deploying from the local charm, the tarball gets
    pushed to the remove unit along with the rest of the charm and
    this action copies it to the location that the webupd8 packages
    expect to find it.
    '''
    src_files = sorted(glob.glob(os.path.join(hookenv.charm_dir(),
                                              'lib', 'jdk-7u*.tar.gz')))
    if src_files:
        dest_dir = '/var/cache/oracle-jdk7-installer'
        hookenv.log('Mirroring Oracle Java tarballs {} to {}'.format(
            ','.join(src_files), dest_dir))
        subprocess.check_call(['install', '-CD'] + src_files + [dest_dir])


@action
def reset_sysctl():
    '''Configure sysctl settings for Cassandra'''
    if helpers.is_lxc():
        hookenv.log("In an LXC. Leaving sysctl unchanged.")
    else:
        cassandra_sysctl_file = os.path.join('/', 'etc', 'sysctl.d',
                                             '99-cassandra.conf')
        contents = b"vm.max_map_count = 131072\n"
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


@action
def install_cassandra_packages():
    helpers.install_packages(helpers.get_cassandra_packages())


@action
def ensure_cassandra_package_status():
    helpers.ensure_package_status(helpers.get_cassandra_packages())


@action
def configure_cassandra_yaml():
    helpers.configure_cassandra_yaml()


@action
def configure_cassandra_env():
    cassandra_env_path = helpers.get_cassandra_env_file()
    assert os.path.exists(cassandra_env_path)

    helpers.maybe_backup(cassandra_env_path)

    overrides = [
        ('max_heap_size', re.compile(r'^#?(MAX_HEAP_SIZE)=(.*)$', re.M)),
        ('heap_newsize', re.compile(r'^#?(HEAP_NEWSIZE)=(.*)$', re.M)),
        # We don't allow this to be overridden to ensure that tools
        # will find JMX using the default port.
        # ('jmx_port', re.compile(r'^#?(JMX_PORT)=(.*)$', re.M)),
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


@action
def configure_cassandra_rackdc():
    config = hookenv.config()
    datacenter = config['datacenter'].strip()
    rack = config['rack'].strip() or hookenv.service_name()
    rackdc_properties = dedent('''\
                               dc={}
                               rack={}
                               ''').format(datacenter, rack)
    rackdc_path = helpers.get_cassandra_rackdc_file()
    host.write_file(rackdc_path, rackdc_properties.encode('UTF-8'))


@action
def reset_auth_keyspace_replication():
    # This action only lowers the system_auth keyspace replication
    # values when a node has been decommissioned. The replication settings
    # are also updated during rolling restart, which takes care of when new
    # nodes are added.
    helpers.reset_auth_keyspace_replication()


@action
def store_unit_private_ip():
    hookenv.config()['unit_private_ip'] = hookenv.unit_private_ip()


@action
def set_unit_zero_bootstrapped():
    '''Unit #0 is used as the first node in the cluster.

    Unit #0 is implicitly flagged as bootstrap, and thus befores the
    first node in the cluster and providing a seed for other nodes to
    bootstrap off. We can change this when we have juju leadership,
    making the leader the first node in the cluster. Until then, don't
    attempt to create a multiunit service if you have removed Unit #0.
    '''
    relname = rollingrestart.get_peer_relation_name()
    if helpers.unit_number() == 0 and hookenv.hook_name().startswith(relname):
        helpers.set_bootstrapped(True)


@action
def maybe_schedule_restart():
    '''Prepare for and schedule a rolling restart if necessary.'''
    if not helpers.is_cassandra_running():
        # Short circuit if Cassandra is not running to avoid log spam.
        rollingrestart.request_restart()
        return

    if helpers.is_decommissioned():
        hookenv.log("Decommissioned")
        return

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

    # If our IP address has changed, we need to restart.
    if config.changed('unit_private_ip'):
        hookenv.log('Unit IP address changed. Restart required.')
        restart = True

    # If we have new seeds, we should restart.
    new_seeds = helpers.seed_ips()
    config['configured_seeds'] = sorted(new_seeds)
    if config.changed('configured_seeds'):
        old_seeds = set(config.previous('configured_seeds') or [])
        changed = old_seeds.symmetric_difference(new_seeds)
        # We don't care about the local node in the changes.
        changed.discard(hookenv.unit_private_ip())
        if changed:
            hookenv.log('New seeds {!r}. Restart required.'.format(new_seeds))
            restart = True

    if restart:
        rollingrestart.request_restart()


@action
def stop_cassandra():
    helpers.stop_cassandra()


@action
def start_cassandra():
    helpers.start_cassandra()


@action
def ensure_unit_superuser():
    helpers.ensure_unit_superuser()


@action
def reset_all_io_schedulers():
    helpers.reset_all_io_schedulers()


@action
def publish_cluster_relation():
    # Per Bug #1409763, this functionality is an action rather than a
    # provided_data item.
    relid = rollingrestart.get_peer_relation_id()
    if relid:
        hookenv.relation_set(relid,
                             {'public-address': hookenv.unit_public_ip()})


def _publish_database_relation(relid, superuser):
    # Due to Bug #1409763, this functionality is as action rather than a
    # provided_data item.
    #
    # The Casandra service needs to provide a common set of credentials
    # to a client unit. Juju does not yet provide a leader so we
    # need another mechanism for determine which unit will create the
    # client's account, with the remaining units copying the lead unit's
    # credentials. For the purposes of this charm, the first unit in
    # order is considered the leader and creates the user with a random
    # password. It then tickles the peer relation to ensure the other
    # units get a hook fired and the opportunity to copy and publish
    # these credentials. If the lowest numbered unit is removed before
    # all of the other peers have copied its credentials, then the next
    # lowest will have either already copied the credentials (and the
    # remaining peers will use them), or the process starts again and
    # it will generate new credentials.
    node_list = list(rollingrestart.get_peers()) + [hookenv.local_unit()]
    sorted_nodes = sorted(node_list, key=lambda unit: int(unit.split('/')[-1]))
    first_node = sorted_nodes[0]

    config = hookenv.config()

    try:
        relinfo = hookenv.relation_get(unit=first_node, rid=relid)
    except subprocess.CalledProcessError:
        if first_node == hookenv.local_unit():
            raise
        # relation-get may fail if the specified unit has not yet joined
        # the peer relation, or has just departed. Try again later.
        return

    username = relinfo.get('username')
    password = relinfo.get('password')
    if hookenv.local_unit() == first_node:
        # Lowest numbered unit, at least for now.
        if 'username' not in relinfo:
            # Credentials unset. Generate them.
            username = 'juju_{}'.format(
                relid.replace(':', '_').replace('-', '_'))
            password = host.pwgen()
            # Wake the other peers, if any.
            hookenv.relation_set(rollingrestart.get_peer_relation_id(),
                                 ping=rollingrestart.utcnow_str())
        # Create the account if necessary, and reset the password.
        # We need to reset the password as another unit may have
        # rudely changed it thinking they were the lowest numbered
        # unit. Fix this behavior once juju provides real
        # leadership.
        helpers.ensure_user(username, password, superuser)

    # Publish the information the client needs on the relation where
    # they can find it.
    #  - authentication credentials
    #  - address and port
    #  - cluster_name, so clients can differentiate multiple clusters
    #  - datacenter + rack, so clients know what names they can use
    #    when altering keyspace replication settings.
    hookenv.relation_set(relid,
                         username=username, password=password,
                         host=hookenv.unit_public_ip(),
                         native_transport_port=config['native_transport_port'],
                         rpc_port=config['rpc_port'],
                         cluster_name=config['cluster_name'],
                         datacenter=config['datacenter'],
                         rack=config['rack'])


@action
def publish_database_relations():
    for relid in hookenv.relation_ids('database'):
        _publish_database_relation(relid, superuser=False)


@action
def publish_database_admin_relations():
    for relid in hookenv.relation_ids('database-admin'):
        _publish_database_relation(relid, superuser=True)


@action
def install_maintenance_crontab():
    # Every unit should run repair once per week (at least once per
    # GCGraceSeconds, which defaults to 10 days but can be changed per
    # keyspace). # Distribute the repair time evenly over the week.
    unit_num = int(hookenv.local_unit().split('/')[-1])
    dow, hour, minute = helpers.week_spread(unit_num)
    contents = jinja.render('cassandra_maintenance_cron.tmpl', vars())
    cron_path = "/etc/cron.d/cassandra-maintenance"
    host.write_file(cron_path, contents.encode('US-ASCII'))


@action
def emit_describe_cluster():
    '''Spam 'nodetool describecluster' into the logs.'''
    helpers.emit_describe_cluster()


@action
def emit_auth_keyspace_status():
    '''Spam 'nodetool status system_auth' into the logs.'''
    helpers.emit_auth_keyspace_status()


@action
def emit_netstats():
    '''Spam 'nodetool netstats' into the logs.'''
    helpers.emit_netstats()


@action
def shutdown_before_joining_peers():
    '''Shutdown the node before opening firewall ports for our peers.

    When the peer relation is first joined, the node has already been
    setup and is running as a standalone cluster. This is problematic
    when the peer relation has been formed, as if it is left running
    peers may conect to it and initiate replication before this node
    has been properly reset and bootstrapped. To avoid this, we
    shutdown the node before opening firewall ports to any peers. The
    firewall can then be opened, and peers will not find a node here
    until it starts its bootstrapping.
    '''
    relname = rollingrestart.get_peer_relation_name()
    if hookenv.hook_name() == '{}-relation-joined'.format(relname):
        if not helpers.is_bootstrapped():
            helpers.stop_cassandra(immediate=True)


@action
def configure_firewall():
    '''Configure firewall rules using ufw.

    This is primarily to block access to the replication and JMX ports,
    as juju's default port access controls are not strict enough and
    allow access to the entire environment.
    '''
    config = hookenv.config()
    ufw.enable()

    # Enable SSH from anywhere, relying on Juju and external firewalls
    # to control access.
    ufw.service('ssh', 'open')

    # Clients need client access. These protocols are configured to
    # require authentication.
    client_keys = ['native_transport_port', 'rpc_port']
    client_ports = [config[key] for key in client_keys]

    # Peers need replication and JMX access. These protocols do not
    # require authentication.
    JMX_PORT = 7199
    peer_ports = [config['storage_port'], config['ssl_storage_port'], JMX_PORT]

    # Enable client access from anywhere. Juju and external firewalls
    # can still restrict this further of course (ie. 'juju expose').
    for key in client_keys:
        if config.changed(key) and config.previous(key) is not None:
            # First close old ports. We use this order in the unlikely case
            # someone is trying to swap the native and Thrift ports.
            ufw.service(config.previous(key), 'close')
    for port in client_ports:
        # Then open or close the configured ports.
        ufw.service(port, 'open')

    desired_rules = set()  # ufw.grant_access/remove_access commands.

    # Rules for peers
    for relinfo in hookenv.relations_of_type('cluster'):
        for port in peer_ports:
            desired_rules.add((relinfo['private-address'], 'any', port))

    # External seeds also need access.
    for seed_ip in helpers.seed_ips():
        for port in peer_ports:
            desired_rules.add((seed_ip, 'any', port))

    previous_rules = set(tuple(rule) for rule in config.get('ufw_rules', []))

    # Close any rules previously opened that are no longer desired.
    for rule in sorted(list(previous_rules - desired_rules)):
        ufw.revoke_access(*rule)

    # Open all the desired rules.
    for rule in sorted(list(desired_rules)):
        ufw.grant_access(*rule)

    # Store our rules for next time. Note that this is inherantly racy -
    # this value is only persisted if the hook exits cleanly. If the
    # hook fails, then someone changes port configuration or IP
    # addresses change, then the failed hook retried, we can lose track
    # of previously granted rules and they will never be revoked. It is
    # impossible to remove this race entirely, so we stick with this
    # simple approach.
    config['ufw_rules'] = list(desired_rules)  # A list because JSON.


@action
def nrpe_external_master_relation():
    ''' Configure the nrpe-external-master relation '''
    local_plugins = helpers.local_plugins_dir()
    if os.path.exists(local_plugins):
        src = os.path.join(hookenv.charm_dir(),
                           "files", "check_cassandra_heap.sh")
        with open(src, 'rb') as f:
            host.write_file(os.path.join(local_plugins,
                                         'check_cassandra_heap.sh'),
                            f.read(), perms=0o555)

    nrpe_compat = nrpe.NRPE()
    conf = hookenv.config()

    cassandra_heap_warn = conf.get('nagios_heapchk_warn_pct')
    cassandra_heap_crit = conf.get('nagios_heapchk_crit_pct')
    if cassandra_heap_warn and cassandra_heap_crit:
        nrpe_compat.add_check(
            shortname="cassandra_heap",
            description="Check Cassandra Heap",
            check_cmd="check_cassandra_heap.sh {} {} {}"
                      "".format(hookenv.unit_private_ip(), cassandra_heap_warn,
                                cassandra_heap_crit)
        )

    cassandra_disk_warn = conf.get('nagios_disk_warn_pct')
    cassandra_disk_crit = conf.get('nagios_disk_crit_pct')
    dirs = helpers.get_all_database_directories()
    dirs = set(dirs['data_file_directories'] +
               [dirs['commitlog_directory'], dirs['saved_caches_directory']])
    for disk in dirs:
        check_name = re.sub('/', '_', disk)
        if cassandra_disk_warn and cassandra_disk_crit:
            nrpe_compat.add_check(
                shortname="cassandra_disk{}".format(check_name),
                description="Check Cassandra Disk {}".format(disk),
                check_cmd="check_disk -u GB -w {}% -c {}% -K 5% -p {}"
                          "".format(cassandra_disk_warn, cassandra_disk_crit,
                                    disk)
            )

    nrpe_compat.write()
