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
from charmhelpers.contrib.templating import jinja
from charmhelpers.core import hookenv, host
from charmhelpers.core.fstab import Fstab
from charmhelpers.core.hookenv import ERROR, WARNING

import helpers
import relations
import rollingrestart


# These config keys cannot be changed after service deployment.
UNCHANGEABLE_KEYS = set(['cluster_name', 'datacenter', 'rack'])

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
    'jmx_port',
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
    'edition',  # TODO: Is it possible to switch edition?
    'jvm'])


# All other config items. By maintaining both lists, we can detect if
# someone forgot to update these lists when they added a new config item.
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
    'nagios_disk_crit_pct',
    '_post_bootstrap_wait'])


def action(func):
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
def reset_sysctl():
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
    # This action only resets the system_auth keyspace replication
    # values in the peer relation-broken hook, to lower the
    # replication factor as the nodes leave. The replication settings are
    # also updated during rolling restart, which takes care of when new
    # nodes are added.
    relname = rollingrestart.get_peer_relation_name()
    if hookenv.hook_name() == '{}-relation-broken'.format(relname):
        helpers.reset_auth_keyspace_replication()


@action
def maybe_decommission_node():
    '''If the unit is leaving, decommission.

    This will fail when we are destroying a service where the entire
    dataset cannot fit on a single node - each unit will decommission,
    draining their data to other units, and eventually one will fail.
    We can't fix this until juju provides a way to determine between
    removing a few units or destroying the service. This failure is not
    fatal, as juju will continue destroying the service even if the
    peer relation-broken hooks fail.
    '''
    peer_relname = rollingrestart.get_peer_relation_name()
    if (hookenv.hook_name() == '{}-relation-broken'.format(peer_relname)
            and helpers.num_nodes() > 1):
        helpers.wait_for_normality()
        helpers.decommission_node()
        # Node is dead, so restart will fail.
        rollingrestart.cancel_restart()


@action
def maybe_schedule_restart():
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

    relinfo = hookenv.relation_get(unit=first_node, rid=relid)
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
