# Copyright 2015-2018 Canonical Ltd.
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

import configparser
from contextlib import contextmanager
from distutils.version import LooseVersion
import json
import io
import os.path
import re
import shlex
import subprocess
from textwrap import dedent
import time

import cassandra.auth
import cassandra.cluster
import cassandra.query
import bcrypt
import netifaces
import yaml


from charmhelpers import fetch
from charmhelpers.core import (
    hookenv,
    host,
)
from charmhelpers.core.hookenv import (
    DEBUG,
    ERROR,
    WARNING,
)
from charms import (
    leadership,
    localconfig,
)
import helpers


_cassandra_config = None


def config():
    '''key/value store for local configuration.

    This will contain a copy of the validated charm config,
    and the additional state needed by the charm.
    '''
    global _cassandra_config
    if _cassandra_config is None:
        _cassandra_config = localconfig.LocalConfig('cassandra')
    return _cassandra_config


def emit(*args, **kw):
    print(*args, **kw)


def get_edition():
    return config()['edition']


def get_jre():
    return config()['jre']


def get_cassandra_config_dir():
    edition = get_edition()
    if edition == 'apache-snap':
        return get_snap_env('CASSANDRA_CONF')
    elif edition == 'dse':
        return '/etc/dse/cassandra'
    else:
        return '/etc/cassandra'


def get_cassandra_yaml_path():
    return os.path.join(get_cassandra_config_dir(), "cassandra.yaml")


def get_cassandra_env_path():
    return os.path.join(get_cassandra_config_dir(), "cassandra-env.sh")


def get_cassandra_rackdc_path():
    return os.path.join(get_cassandra_config_dir(), "cassandra-rackdc.properties")


def get_cassandra_pid_path():
    edition = get_edition()
    if edition == 'apache-snap':
        home = get_snap_env('CASSANDRA_HOME')
        pid_file = os.path.join(home, 'cassandra.pid')
    elif edition == 'dse':
        pid_file = "/var/run/dse/dse.pid"
    else:
        pid_file = "/var/run/cassandra/cassandra.pid"
    return pid_file


def get_cqlshrc_path(owner):
    if get_edition() == 'apache-snap':
        base = get_cassandra_config_dir()
        return os.path.join(base, 'cql/cqlshrc')
    else:
        return os.path.expanduser('~{}/.cassandra/cqlshrc'.format(owner))


def write_config_file(path, contents):
    '''Write out the config file to path

    Encodes contents to UTF-8 first. If using a snap edition, write
    to the snap config directory.
    '''
    if get_edition() == 'apache-snap':
        set_snap_config_file(os.path.basename(path), contents)
    else:
        contents = contents.encode('UTF-8')
        host.write_file(path, contents)


def maybe_backup(path):
    '''Copy a file to file.orig, if file.orig does not already exist.'''
    backup_path = path + '.orig'
    if not os.path.exists(backup_path):
        with open(path, 'rb') as f:
            host.write_file(backup_path, f.read(), perms=0o600)


def get_snap_env(envar):
    '''Return the value of an environment variable present in the snap wrapper
    scripts.
    '''
    cmd = ['/snap/bin/cassandra.env-get', envar]
    return subprocess.check_output(cmd, universal_newlines=True).strip('\n')


def get_cassandra_version():
    edition = get_edition()
    if edition == 'apache-snap':
        return get_snap_version('cassandra')
    elif edition == 'dse':
        # Per Product Compatibility: DataStax Enterprise, Apache Cassandra, CQL,
        # and SSTable compatibility
        # https://docs.datastax.com/en/landing_page/doc/landing_page/compatibility.html
        dse_ver = get_package_version('dse-full')
        if not dse_ver:
            return None
        elif LooseVersion(dse_ver) >= LooseVersion('6.0'):
            return '3.11'
        elif LooseVersion(dse_ver) >= LooseVersion('5.1'):
            return '3.10'
        elif LooseVersion(dse_ver) >= LooseVersion('5.0'):
            return '3.0'
        elif LooseVersion(dse_ver) >= LooseVersion('4.7'):
            return '2.1'
        else:
            return '2.0'
    return get_package_version('cassandra')


def get_package_version(package):
    cache = fetch.apt_cache()
    if package not in cache:
        return None
    pkgver = cache[package].current_ver
    if pkgver is not None:
        return pkgver.ver_str
    return None


def get_snap_version(snap):
    '''Get the version string for an installed snap.'''
    cmd = ['snap', 'list', snap]
    out = subprocess.check_output(cmd, universal_newlines=True)
    match = re.search('\n{}\s*(\S*)'.format(snap), out)
    if match:
        return match.groups(0)[0]


def has_cassandra_version(minimum_ver):
    cassandra_version = get_cassandra_version()
    assert cassandra_version is not None, 'Cassandra package not yet installed'
    return LooseVersion(cassandra_version) >= LooseVersion(minimum_ver)


def get_cassandra_service():
    '''Cassandra upstart or systemd service name'''
    if get_edition() == 'apache-snap':
        return 'snap.cassandra.cassandra'
    elif get_edition() == 'dse':
        return 'dse'
    return 'cassandra'


def get_deb_packages():
    packages = set()

    edition = get_edition()
    if edition == 'dse':
        packages.add('dse')
        packages.add('dse-full')
        packages.add('dse-libcassandra')
        packages.add('dse-libgraph')
        packages.add('dse-libhadoop2-client')
        packages.add('dse-libhadoop2-client-native')
        packages.add('dse-liblog4j')
        packages.add('dse-libsolr')
        packages.add('dse-libspark')
        packages.add('dse-libtomcat')
    else:
        packages.add('cassandra')  # 'cassandra-tools'

    jre = get_jre()
    if jre == 'oracle':
        # We can't use a packaged version of the Oracle JRE, as we
        # are not allowed to bypass Oracle's click through license
        # agreement.
        pass
    else:
        # NB. OpenJDK 8 not available in trusty. This needs to come
        # from a PPA or some other configured source.
        packages.add('openjdk-8-jre-headless')

    return packages


def get_cassandra_env():
    cassandra_env_path = get_cassandra_env_path()
    assert os.path.exists(cassandra_env_path)

    overrides = [
        ('max_heap_size', re.compile(r'^#?(MAX_HEAP_SIZE)=(.*)$', re.M)),
        ('heap_newsize', re.compile(r'^#?(HEAP_NEWSIZE)=(.*)$', re.M)),
        # We don't allow this to be overridden to ensure that tools
        # will find JMX using the default port.
        # ('jmx_port', re.compile(r'^#?(JMX_PORT)=(.*)$', re.M)),
    ]

    with open(cassandra_env_path, 'r') as f:
        env = f.read()

    c = config()
    for key, regexp in overrides:
        if c[key]:
            val = shlex.quote(str(c[key]))
            env = regexp.sub(r'\g<1>={}'.format(val),
                             env)
        else:
            env = regexp.sub(r'#\1=\2', env)
    return env


def write_cassandra_env(cassandra_env):
    cassandra_env_path = get_cassandra_env_path()
    maybe_backup(cassandra_env_path)  # Its comments may be useful.
    host.write_file(cassandra_env_path, cassandra_env.encode('UTF-8'))


def get_cassandra_rackdc():
    c = config()
    datacenter = c['datacenter'].strip()
    rack = c['rack'].strip() or hookenv.service_name()
    rackdc_properties = dedent('''\
                               dc={}
                               rack={}
                               ''').format(datacenter, rack)
    return rackdc_properties


def write_cassandra_rackdc(cassandra_rackdc):
    cassandra_rackdc_path = get_cassandra_rackdc_path()
    write_config_file(cassandra_rackdc_path, cassandra_rackdc)


def get_cassandra_yaml(overrides={}, seeds=None):
    '''Return data structure serializable to cassandra.yaml

    Deserializes the existing cassandra.yaml, updates to current
    charm state, adds provided overrides, and returns.
    '''
    c = config()

    cassandra_yaml = read_cassandra_yaml()

    # Most options just copy from config.yaml keys with the same name.
    # Using the same name is preferred to match the actual Cassandra
    # documentation.
    simple_config_keys = ['authenticator', 'authorizer', 'cluster_name',
                          'compaction_throughput_mb_per_sec',
                          'file_cache_size_in_mb', 'native_transport_port',
                          'num_tokens', 'partitioner', 'rpc_port',
                          'ssl_storage_port', 'storage_port',
                          'stream_throughput_outbound_megabits_per_sec',
                          'tombstone_failure_threshold',
                          'tombstone_warn_threshold']

    # Protocol no longer supported, config option ignored. Do not add to cassandra.yaml
    # or DSE 6.0 fails to start.
    if has_cassandra_version('3.0'):
        simple_config_keys.remove('rpc_port')

    # file_cache_size_in_mb defaults to 0 in YAML, because int values need
    # an int default - but if left as default, let cassandra figure it out
    if (c.get('file_cache_size_in_mb') is None or
            c.get('file_cache_size_in_mb') <= 0):
        simple_config_keys.remove('file_cache_size_in_mb')

    cassandra_yaml.update((k, c[k]) for k in simple_config_keys)

    seeds = ','.join(seeds or get_seed_ips())  # Don't include whitespace!
    hookenv.log('Configuring seeds as {!r}'.format(seeds), DEBUG)
    cassandra_yaml['seed_provider'][0]['parameters'][0]['seeds'] = seeds

    cassandra_yaml['listen_address'] = listen_ip_address()
    if c['rpc_interface']:
        cassandra_yaml['rpc_address'] = rpc_broadcast_ip_address()
    else:
        # If no specific interface, we listen on all interfaces.
        cassandra_yaml['rpc_address'] = '0.0.0.0'
        if not get_cassandra_version().startswith('2.0'):
            rpc_addr = rpc_broadcast_ip_address()
            cassandra_yaml['broadcast_rpc_address'] = rpc_addr

    dirs = get_all_database_directories()
    cassandra_yaml.update(dirs)

    # GossipingPropertyFileSnitch is the only snitch recommended for
    # production. It we allow others, we need to consider how to deal
    # with the system_auth keyspace replication settings.
    cassandra_yaml['endpoint_snitch'] = 'GossipingPropertyFileSnitch'

    if not has_cassandra_version('3.0'):
        # Per Bug #1523546 and CASSANDRA-9319, Thrift is disabled by default in
        # Cassandra 2.2. Ensure it is enabled if rpc_port is non-zero.
        # The protocol is no longer supported with later versions, and adding
        # the setting to cassandra.yaml stops DSE 6.0 from starting up.
        if int(c['rpc_port']) > 0:
            cassandra_yaml['start_rpc'] = True

    cassandra_yaml.update(overrides)

    return cassandra_yaml


def read_cassandra_yaml():
    if get_edition() == 'apache-snap':
        f = get_snap_config_file('cassandra.yaml')
        return yaml.safe_load(f)
    else:
        cassandra_yaml_path = get_cassandra_yaml_path()
        with open(cassandra_yaml_path, 'rb') as f:
            return yaml.safe_load(f)


def write_cassandra_yaml(cassandra_yaml):
    cassandra_yaml_path = get_cassandra_yaml_path()
    if get_edition() != 'apache-snap':
        maybe_backup(cassandra_yaml_path)  # Its comments may be useful.
    write_config_file(cassandra_yaml_path, yaml.safe_dump(cassandra_yaml))


def get_snap_config_file(filename):
    '''Get the contents of the named configuration file from the current snap
    data directory.
    '''
    cmd = ['/snap/bin/cassandra.config-get', filename]
    return subprocess.check_output(cmd, universal_newlines=True)


def set_snap_config_file(filename, contents):
    '''Install a new copy of the configuration file with the provided contents
    in the current snap data directory.
    '''
    cmd = ['/snap/bin/cassandra.config-set', filename]
    cs = subprocess.Popen(cmd, stdin=subprocess.PIPE, universal_newlines=True)
    _, err = cs.communicate(input=contents)
    if err:
        hookenv.log('Error calling {}:\n{}'.format(' '.join(cmd), err))
    if cs.returncode != 0:
        msg = '{} exited with code {}'.format(' '.join(cmd), cs.returncode)
        raise RuntimeError(msg)


def get_seed_ips():
    '''Return the set of seed ip addresses.

    We use ip addresses rather than unit names, as we may need to use
    external seed ips at some point.
    '''
    return set((leadership.leader_get('seeds') or '').split(','))


def listen_ip_address():
    c = config()
    return (interface_to_ip(c['listen_interface']) or
            hookenv.unit_private_ip())


def rpc_broadcast_ip_address():
    c = config()
    # TODO: Advertise ingress IP address. But we might have several?
    return (interface_to_ip(c['rpc_interface']) or
            hookenv.unit_public_ip())


def interface_to_ip(interface):
    '''The IP address for interface, or None.

    Also returns None if there are multiple IP addresses.
    '''
    if interface not in netifaces.interfaces():
        hookenv.log('No interface {}'.format(interface), ERROR)
        return None
    full = netifaces.ifaddresses(interface)
    if full.get(netifaces.AF_INET) and full.get(netifaces.AF_INET6):
        hookenv.log('Interface {} has both IPv4 and IPv6 addresses'
                    ''.format(interface), ERROR)
        return None
    if netifaces.AF_INET in full:
        addrs = full[netifaces.AF_INET]
    else:
        addrs = full[netifaces.AF_INET6]
    addrs = set(filter(None, (a.get('addr') for a in addrs)))
    if len(addrs) != 1:
        hookenv.log('Interface {} has {} IP addresses'
                    ''.format(interface, len(addrs)), ERROR)
        return None
    return addrs.pop()


def get_all_database_directories():
    c = config()
    dirs = dict(
        data_file_directories=[get_database_directory(d) for d in (c['data_file_directories'] or 'data').split()],
        commitlog_directory=get_database_directory(c['commitlog_directory'] or 'commitlog'),
        saved_caches_directory=get_database_directory(c['saved_caches_directory'] or 'saved_caches'),
    )
    if has_cassandra_version('3.0'):
        # Not yet configurable. Make configurable with Juju native storage.
        dirs['hints_directory'] = get_database_directory('hints')
    return dirs


def get_database_directory(config_path):
    '''Convert a database path from the service config to an absolute path.

    Entries in the config file may be absolute, relative to
    /var/lib/cassandra, or relative to the mountpoint.
    '''
    # TODO: Juju Storage, maybe BSB.
    # import relations
    # storage = relations.StorageRelation()
    if get_edition() == 'apache-snap':
        root = get_snap_env('SNAP_DATA')
    # elif storage.mountpoint:
    #     root = os.path.join(storage.mountpoint, 'cassandra')
    else:
        root = '/var/lib/cassandra'
    return os.path.join(root, config_path)


def ensure_all_database_directories():
    '''Ensure that directories Cassandra expects to store its data in exist.'''
    db_dirs = get_all_database_directories()
    ensure_database_directory(db_dirs['commitlog_directory'])
    ensure_database_directory(db_dirs['saved_caches_directory'])
    if 'hints_directory' in db_dirs:
        ensure_database_directory(db_dirs['hints_directory'])
    for db_dir in db_dirs['data_file_directories']:
        ensure_database_directory(db_dir)


def ensure_database_directory(config_path):
    '''Create the database directory if it doesn't exist, resetting
    ownership and other settings while we are at it.

    Returns the absolute path.
    '''
    absdir = get_database_directory(config_path)

    # Work around Bug #1427150 by ensuring components of the path are
    # created with the required permissions, if necessary.
    component = os.sep
    for p in absdir.split(os.sep)[1:-1]:
        component = os.path.join(component, p)
        if not os.path.exists(component):
            host.mkdir(component)
    assert component == os.path.split(absdir)[0]
    if get_edition() == 'apache-snap':
        host.mkdir(absdir, owner='root', group='root', perms=0o750)
    else:
        host.mkdir(absdir, owner='cassandra', group='cassandra', perms=0o750)
    return absdir


def stop():
    return host.service_stop(get_cassandra_service())


def start():
    return host.service_start(get_cassandra_service())


def get_node_status():
    '''Return the Cassandra node status.

    May be NORMAL, JOINING, DECOMMISSIONED etc., or None if we can't tell.
    '''
    if not is_cassandra_running():
        return None
    raw = nodetool('netstats')
    m = re.search(r'(?m)^Mode:\s+(\w+)$', raw)
    if m is None:
        return None
    return m.group(1).upper()


def is_decommissioned():
    status = get_node_status()
    if status in ('DECOMMISSIONED', 'LEAVING'):
        hookenv.log('This node is {}'.format(status), WARNING)
        return True
    return False


def nodetool(*cmd, timeout=120):
    if get_edition() == 'apache-snap':
        nodetool_cmd = '/snap/bin/cassandra.nodetool'
    else:
        nodetool_cmd = 'nodetool'
    cmd = [nodetool_cmd] + [str(i) for i in cmd]
    i = 0
    until = time.time() + timeout
    for _ in backoff('nodetool to work'):
        i += 1
        try:
            if timeout is not None:
                timeout = max(0, until - time.time())
            raw = subprocess.check_output(cmd, universal_newlines=True,
                                          timeout=timeout,
                                          stderr=subprocess.STDOUT)

            # Work around CASSANDRA-8776.
            if 'status' in cmd and 'Error:' in raw:
                hookenv.log('Error detected but nodetool returned success.',
                            WARNING)
                raise subprocess.CalledProcessError(99, cmd, raw)

            hookenv.log('{} succeeded'.format(' '.join(cmd)), DEBUG)
            out = raw.expandtabs()
            emit(out)
            return out

        except subprocess.CalledProcessError as x:
            if i > 1:
                emit(x.output.expandtabs())  # Expand tabs for juju debug-log.
            if not is_cassandra_running():
                helpers.status_set('blocked', 'Cassandra has unexpectedly shutdown')
                raise SystemExit(0)
            if time.time() >= until:
                raise


def get_pid_from_path(pid_path):
    try:
        with open(pid_path, 'r') as f:
            pid = int(f.read().strip().split()[0])
            if pid <= 1:
                raise ValueError('Illegal pid {}'.format(pid))
            return pid
    except (ValueError, IndexError) as e:
        hookenv.log("Invalid PID in {}.".format(pid_path), WARNING)
        raise ValueError(e)


def is_cassandra_running():
    edition = get_edition()
    pid_file = get_cassandra_pid_path()

    try:
        for _ in backoff('Cassandra to respond'):
            # We reload the pid every time, in case it has gone away.
            # If it goes away, a FileNotFound exception is raised.
            pid = get_pid_from_path(pid_file)

            # This does not kill the process but checks for its
            # existence. It raises an ProcessLookupError if the process
            # is not running.
            os.kill(pid, 0)

            if edition == 'apache-snap':
                # /snap/bin is not on PATH for the root user.
                nodetool = '/snap/bin/cassandra.nodetool'
            else:
                nodetool = 'nodetool'
            if subprocess.call([nodetool, "status"],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL) == 0:
                hookenv.log("Cassandra PID {} is running and responding".format(pid))
                return True
    except FileNotFoundError:
        hookenv.log("Cassandra is not running. PID file does not exist.")
        return False
    except ProcessLookupError:
        if os.path.exists(pid_file):
            # File disappeared between reading the PID and checking if
            # the PID is running.
            hookenv.log("Cassandra is not running, but pid file exists.", WARNING)
        else:
            hookenv.log("Cassandra is not running. PID file does not exist.")
        return False


CONNECT_TIMEOUT = 60


@contextmanager
def connect(username=None, password=None, timeout=CONNECT_TIMEOUT):
    # We pull the currently configured listen address and port from the
    # yaml, rather than the service configuration, as it may have been
    # overridden.
    cassandra_yaml = read_cassandra_yaml()
    address = cassandra_yaml['rpc_address']
    if address == '0.0.0.0':
        address = 'localhost'
    port = cassandra_yaml['native_transport_port']

    auth_provider = get_auth_provider(username, password)

    # Although we specify a reconnection_policy, it does not apply to
    # the initial connection so we retry in a loop.
    start = time.time()
    until = start + timeout
    while True:
        cluster = cassandra.cluster.Cluster([address], port=port, auth_provider=auth_provider)
        try:
            session = cluster.connect()
            session.default_timeout = timeout
            break
        except cassandra.cluster.NoHostAvailable as x:
            cluster.shutdown()
            if time.time() > until:
                raise
        time.sleep(1)
    try:
        yield session
    finally:
        cluster.shutdown()


def get_auth_provider(username=None, password=None):
    auth = config()['authenticator']
    if auth.lower() == 'allowallauthenticator':
        return None
    if username is None:
        username, password = superuser_credentials()
    return cassandra.auth.PlainTextAuthProvider(username=username, password=password)


def backoff(what_for, max_pause=60):
    i = 0
    while True:
        yield True
        i += 1
        pause = min(max_pause, 2 ** i)
        time.sleep(pause)
        if pause > 10:
            hookenv.log('Recheck {} for {}'.format(i, what_for))


QUERY_TIMEOUT = 60


def query(session, statement, consistency_level, args=None):
    q = cassandra.query.SimpleStatement(statement, consistency_level=consistency_level)
    until = time.time() + QUERY_TIMEOUT
    for _ in backoff('query to execute'):
        try:
            return session.execute(q, args)
        except Exception:
            if time.time() > until:
                raise


def superuser_credentials():
    return leadership.leader_get('username'), leadership.leader_get('password')


def get_cqlshrc_credentials(username):
    '''Return (username, password) stored in the root user's .cqlshrc

    The credentials are persisted in the root user's cqlshrc file,
    making them easily accessible to the command line tools.
    '''
    cqlshrc_path = get_cqlshrc_path('root')
    if not os.path.exists(cqlshrc_path):
        return None, None

    cqlshrc = configparser.ConfigParser(interpolation=None)
    cqlshrc.read([cqlshrc_path])

    try:
        section = cqlshrc['authentication']
        # If there happened to be an existing cqlshrc file, it might
        # contain invalid credentials. Ignore them.
        if section['username'] == username:
            return section['username'], section['password']
    except KeyError:
        pass
    return None, None


def store_cqlshrc_credentials(owner, username, password):
    cqlshrc_path = get_cqlshrc_path(owner)
    hookenv.log('Storing credentials for {} in {}'.format(owner, cqlshrc_path))
    c = config()

    cqlshrc = configparser.ConfigParser(interpolation=None)
    cqlshrc.read([cqlshrc_path])

    # We set items separately, rather than together, so that we have a
    # defined order for the ConfigParser to preserve and the tests to
    # rely on.
    cqlshrc.setdefault('authentication', {})
    cqlshrc['authentication']['username'] = username
    cqlshrc['authentication']['password'] = password
    cqlshrc.setdefault('connection', {})
    cqlshrc['connection']['hostname'] = rpc_broadcast_ip_address()
    if get_cassandra_version().startswith('2.0'):
        cqlshrc['connection']['port'] = str(c['rpc_port'])
    else:
        cqlshrc['connection']['port'] = str(c['native_transport_port'])

    ini = io.StringIO()
    cqlshrc.write(ini)
    host.mkdir(os.path.dirname(cqlshrc_path), perms=0o700, owner=owner)
    host.write_file(cqlshrc_path, ini.getvalue().encode('UTF-8'), perms=0o400, owner=owner)


def encrypt_password(password):
    password = password.encode('ascii')
    # Java doesn't understand bcrypt 2b yet:
    # cassandra.AuthenticationFailed: Failed to authenticate to localhost:
    # code=0000 [Server error] message="java.lang.IllegalArgumentException:
    # Invalid salt revision"
    try:
        salt = bcrypt.gensalt(prefix=b'2a')
        # Newer versions of bcrypt return a bytestring.
        return bcrypt.hashpw(password, salt).decode('ascii')
    except TypeError:
        # Trusty bcrypt doesn't support prefix=
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password, salt)


def ensure_user(session, username, encrypted_password, superuser=False):
    '''Create the DB user if it doesn't already exist & reset the password.'''
    auth = config()['authenticator']
    if auth.lower() == 'allowallauthenticator':
        return  # No authentication means we cannot create users

    if superuser:
        hookenv.log('Creating SUPERUSER {}'.format(username))
    else:
        hookenv.log('Creating user {}'.format(username))

    if has_cassandra_version('2.2'):
        query(session,
              'INSERT INTO system_auth.roles '
              '(role, can_login, is_superuser, salted_hash) '
              'VALUES (%s, TRUE, %s, %s)',
              cassandra.ConsistencyLevel.ALL, (username, superuser, encrypted_password))
    else:
        query(session,
              'INSERT INTO system_auth.users (name, super) VALUES (%s, %s)',
              cassandra.ConsistencyLevel.ALL, (username, superuser))
        query(session,
              'INSERT INTO system_auth.credentials (username, salted_hash) '
              'VALUES (%s, %s)',
              cassandra.ConsistencyLevel.ALL, (username, encrypted_password))


# Do we still need this? Needed to redeploy using existing sstables,
# but better to sstableload them in?
#
# def create_unit_superuser_hard():
#     '''Create or recreate the unit's superuser account.
#
#     This method is used when there are no known superuser credentials
#     to use. We restart the node using the AllowAllAuthenticator and
#     insert our credentials directly into the system_auth keyspace.
#     '''
#     username, password = superuser_credentials()
#     pwhash = encrypt_password(password)
#     hookenv.log('Creating unit superuser {}'.format(username))
#
#     # Restart cassandra without authentication & listening on localhost.
#     reconfigure_and_restart_cassandra(
#         dict(authenticator='AllowAllAuthenticator', rpc_address='localhost'))
#     for _ in backoff('superuser creation'):
#         try:
#             with connect() as session:
#                 ensure_user(session, username, pwhash, superuser=True)
#                 break
#         except Exception as x:
#             print(str(x))
#
#     # Restart Cassandra with regular config.
#     nodetool('flush')  # Ensure our backdoor updates are flushed.
#     reconfigure_and_restart_cassandra()


def get_auth_keyspace_replication(session):
    if has_cassandra_version('3.0'):
        statement = dedent('''\
            SELECT replication FROM system_schema.keyspaces
            WHERE keyspace_name='system_auth'
            ''')
        r = query(session, statement, cassandra.ConsistencyLevel.QUORUM)
        return dict(r[0][0])
    else:
        statement = dedent('''\
            SELECT strategy_options FROM system.schema_keyspaces
            WHERE keyspace_name='system_auth'
            ''')
        r = query(session, statement, cassandra.ConsistencyLevel.QUORUM)
        return json.loads(r[0][0])


def set_auth_keyspace_replication(session, settings):
    # Live operation, so keep status the same.
    statement = 'ALTER KEYSPACE system_auth WITH REPLICATION = %s'
    query(session, statement, cassandra.ConsistencyLevel.ALL, (settings,))


def repair_auth_keyspace():
    # Repair takes a long time, and may need to be retried due to 'snapshot
    # creation' errors, but should certainly complete within an hour since
    # the keyspace is tiny.
    helpers.status_set(None, 'Repairing system_auth keyspace')
    nodetool('repair', 'system_auth', timeout=3600)
