import configparser
from contextlib import contextmanager
import errno
from functools import wraps
import io
import json
import os.path
import re
import shutil
import subprocess
from textwrap import dedent
import time

import bcrypt
from cassandra import ConsistencyLevel
import cassandra.auth
import cassandra.cluster
import cassandra.query
import yaml

from charmhelpers.core import hookenv, host
from charmhelpers.core.hookenv import DEBUG, ERROR, WARNING
from charmhelpers import fetch

import relations
import rollingrestart


RESTART_TIMEOUT = 300


def logged(func):
    @wraps(func)
    def wrapper(*args, **kw):
        hookenv.log("** Helper {}/{}".format(hookenv.hook_name(),
                                             func.__name__))
        return func(*args, **kw)
    return wrapper


# FOR CHARMHELPERS
@contextmanager
def autostart_disabled(services=None, _policy_rc='/usr/sbin/policy-rc.d'):
    '''Tell well behaved Debian packages to not start services when installed.
    '''
    script = ['#!/bin/sh']
    if services is not None:
        for service in services:
            script.append(
                'if [ "$1" = "{}" ]; then exit 101; fi'.format(service))
        script.append('exit 0')
    else:
        script.append('exit 101')  # By default, all daemons disabled.
    try:
        if os.path.exists(_policy_rc):
            shutil.move(_policy_rc, "{}-orig".format(_policy_rc))
        host.write_file(_policy_rc, '\n'.join(script).encode('ASCII'),
                        perms=0o555)
        yield
    finally:
        os.unlink(_policy_rc)
        if os.path.exists("{}-orig".format(_policy_rc)):
            shutil.move("{}-orig".format(_policy_rc), _policy_rc)


# FOR CHARMHELPERS
@logged
def install_packages(packages):
    packages = list(packages)
    if hookenv.config('extra_packages'):
        packages.extend(hookenv.config('extra_packages').split())
    packages = fetch.filter_installed_packages(packages)
    # if 'ntp' in packages:
    #     fetch.apt_install(['ntp'], fatal=True)  # With autostart
    #     packages.remove('ntp')
    if packages:
        with autostart_disabled(['cassandra']):
            fetch.apt_install(packages, fatal=True)


# FOR CHARMHELPERS
@logged
def ensure_package_status(packages):
    config_dict = hookenv.config()

    package_status = config_dict['package_status']

    if package_status not in ['install', 'hold']:
        raise RuntimeError("package_status must be 'install' or 'hold', "
                           "not {!r}".format(package_status))

    selections = []
    for package in packages:
        selections.append('{} {}\n'.format(package, package_status))
    dpkg = subprocess.Popen(['dpkg', '--set-selections'],
                            stdin=subprocess.PIPE)
    dpkg.communicate(input=''.join(selections).encode('US-ASCII'))


def get_seeds():
    '''Return a list of seed nodes.

    This list may be calculated, or manually overridden by the
    force_seed_nodes configuration setting.

    If this is the only unit in the service, then the local unit's IP
    address is returned as the only seed.

    If there is more than one unit in the service, then the IP addresses
    of the three lowest numbered peers are returned. The local unit will
    never be listed as a seed, and ensures that the local unit will always
    bootstrap.
    '''
    config_dict = hookenv.config()

    if config_dict['force_seed_nodes']:
        return config_dict['force_seed_nodes'].split(',')

    peers = rollingrestart.get_peers()
    if not peers:
        hookenv.log('Local seed')
        return [hookenv.unit_private_ip()]

    seeds = [seed for seed in
             sorted(list(peers) + [hookenv.local_unit()],
                    key=lambda x: int(x.split('/')[-1]))[:3]
             if seed != hookenv.local_unit()]
    hookenv.log('Seeds == [{}]'.format(','.join(seeds)))
    relid = rollingrestart.get_peer_relation_id()
    return [hookenv.relation_get('private-address', seed, relid)
            for seed in seeds]


def get_database_directory(config_path):
    '''Convert a database path from the service config to an absolute path.

    Entries in the config file may be absolute, relative to
    /var/lib/cassandra, or relative to the mountpoint.
    '''
    storage = relations.StorageRelation()
    if storage.mountpoint:
        root = os.path.join(storage.mountpoint, 'cassandra')
    else:
        root = '/var/lib/cassandra'
    return os.path.join(root, config_path)


def ensure_database_directory(config_path):
    '''Create the database directory if it doesn't exist, resetting
    ownership and other settings while we are at it.

    Returns the absolute path.
    '''
    # Guard against changing perms on a running db. Although probably
    # harmless, it causes shutil.chown() to fail.
    assert not is_cassandra_running()
    absdir = get_database_directory(config_path)

    host.mkdir(absdir, owner='cassandra', group='cassandra', perms=0o750)
    # If this is an existing database being remounted, we need to
    # ensure ownership is correct due to uid and gid mismatches.
    # TODO: Confirm ownership of DSE files
    recursive_chown(absdir, owner='cassandra', group='cassandra')
    return absdir


def get_all_database_directories():
    config = hookenv.config()
    return dict(
        data_file_directories=[get_database_directory(d)
                               for d in (config['data_file_directories']
                                         or 'data').split()],
        commitlog_directory=get_database_directory(
            config['commitlog_directory'] or 'commitlog'),
        saved_caches_directory=get_database_directory(
            config['saved_caches_directory'] or 'saved_caches'))


# FOR CHARMHELPERS
def is_lxc():
    '''Return True if we are running inside an LXC container.'''
    with open('/proc/1/cgroup', 'r') as f:
        return ':/lxc/' in f.readline()


# FOR CHARMHELPERS
def set_io_scheduler(io_scheduler, directory):
    '''Set the block device io scheduler.'''

    assert os.path.isdir(directory)

    # The block device regex may be a tad simplistic.
    block_regex = re.compile('\/dev\/([a-z]*)', re.IGNORECASE)

    output = subprocess.check_output(['df', directory])

    if not is_lxc():
        hookenv.log("Setting block device of {} to IO scheduler {}"
                    "".format(directory, io_scheduler))
        block_dev = re.findall(block_regex, output)[0]
        sys_file = os.path.join("/", "sys", "block", block_dev,
                                "queue", "scheduler")
        try:
            host.write_file(sys_file, io_scheduler, perms=0o644)
        except Exception as e:
            if e.errno == errno.EACCES:
                hookenv.log("Got Permission Denied trying to set the "
                            "IO scheduler at {}. We may be in an LXC. "
                            "Exiting gracefully".format(sys_file),
                            WARNING)
            elif e.errno == errno.ENOENT:
                hookenv.log("Got no such file or directory trying to "
                            "set the IO scheduler at {}. It may be "
                            "this is an LXC, the device name is as "
                            "yet unknown to the charm, or LVM/RAID is "
                            "hiding the underlying device name. "
                            "Exiting gracefully".format(sys_file),
                            WARNING)
            else:
                raise e
    else:
        # Make no change if we are in an LXC
        hookenv.log("In an LXC. Cannot set io scheduler {}"
                    "".format(io_scheduler))


# FOR CHARMHELPERS
def recursive_chown(directory, owner="root", group="root"):
    '''Change ownership of all files and directories in 'directory'.

    Ownership of 'directory' is also reset.
    '''
    shutil.chown(directory, owner, group)
    for root, dirs, files in os.walk(directory):
        for dirname in dirs:
            shutil.chown(os.path.join(root, dirname), owner, group)
        for filename in files:
            shutil.chown(os.path.join(root, filename), owner, group)


def maybe_backup(path):
    '''Copy a file to file.orig, if file.orig does not already exist.'''
    backup_path = path + '.orig'
    if not os.path.exists(backup_path):
        with open(path, 'rb') as f:
            host.write_file(backup_path, f.read(), perms=0o600)


# FOR CHARMHELPERS
def get_package_version(package):
    cache = fetch.apt_cache()
    if package not in cache:
        return None
    pkgver = cache[package].current_ver
    if pkgver is not None:
        return pkgver.ver_str
    return None


def accept_oracle_jvm_license():
    '''Accept the Oracle JVM license on behalf of the user.

    This method should only be called if the user has explicitly
    chosen options documented as implicitly accepting the Oracle JVM
    license.
    '''
    ORACLE_JVM_ACCEPT_KEY = 'oracle_jvm_license_accepted'  # config() key.
    config = hookenv.config()
    config.setdefault(ORACLE_JVM_ACCEPT_KEY, False)
    if config[ORACLE_JVM_ACCEPT_KEY] is True:
        return True
    # Per documentation in config.yaml, selecting the Oracle JVM or
    # the dse edition implicitly accepts the Oracle license. Because
    # if it was easy, it wouldn't be Enterprise.
    assert get_jvm() == 'oracle', 'No implicit license agreement found'
    p = subprocess.Popen(['debconf-set-selections'],
                         stdin=subprocess.PIPE, stderr=subprocess.STDOUT,
                         stdout=subprocess.PIPE)
    (out, err) = p.communicate(b'oracle-java7-installer '
                               b'shared/accepted-oracle-license-v1-1 '
                               b'select true\n')  # newline required
    if p.returncode == 0:
        config[ORACLE_JVM_ACCEPT_KEY] = True
        hookenv.log('Oracle Java SE licence accepted')
    else:
        hookenv.log('Unable to accept Oracle licence. Using OpenJDK',
                    ERROR)
        hookenv.log(out, DEBUG)
    return config[ORACLE_JVM_ACCEPT_KEY]


def get_jvm():
    # DataStax Enterprise requires the Oracle JVM.
    if get_cassandra_edition() == 'dse':
        return 'oracle'

    config = hookenv.config()
    jvm = config['jvm'].lower()
    if jvm not in ('openjdk', 'oracle'):
        hookenv.log('Unknown jvm {!r} specified. Using OpenJDK'.format(jvm),
                    ERROR)
        jvm = 'openjdk'
    return jvm


def get_cassandra_edition():
    config = hookenv.config()
    edition = config['edition'].lower()
    if edition not in ('community', 'dse'):
        hookenv.log('Unknown edition {!r}. Using community.'.format(edition),
                    ERROR)
        edition = 'community'
    return edition


def get_cassandra_service():
    '''Cassandra upstart service'''
    if get_cassandra_edition() == 'dse':
        return 'dse'
    return 'cassandra'


def get_cassandra_version():
    if get_cassandra_edition() == 'dse':
        # When we support multiple versions, we will need to map
        # DataStax versions to Cassandra versions.
        return '2.1' if get_package_version('dse-full') else None
    return get_package_version('cassandra')


def get_cassandra_config_dir():
    if get_cassandra_edition() == 'dse':
        return '/etc/dse/cassandra'
    else:
        return '/etc/cassandra'


def get_cassandra_yaml_file():
    return os.path.join(get_cassandra_config_dir(), "cassandra.yaml")


def get_cassandra_env_file():
    return os.path.join(get_cassandra_config_dir(), "cassandra-env.sh")


def get_cassandra_rackdc_file():
    return os.path.join(get_cassandra_config_dir(),
                        "cassandra-rackdc.properties")


def get_cassandra_pid_file():
    edition = get_cassandra_edition()
    if edition == 'dse':
        pid_file = "/var/run/dse/dse.pid"
    # elif apt_pkg.version_compare(get_cassandra_version(), "2.0") < 0:
    #     pid_file = "/var/run/cassandra.pid"
    else:
        pid_file = "/var/run/cassandra/cassandra.pid"
    return pid_file


def get_cassandra_packages():
    edition = get_cassandra_edition()
    if edition == 'dse':
        packages = set(['dse-full'])
    else:
        packages = set(['cassandra', 'cassandra-tools'])

    packages.add('ntp')

    jvm = get_jvm()
    if jvm == 'oracle':
        if accept_oracle_jvm_license():
            packages.add('oracle-java7-installer')
            packages.add('oracle-java7-set-default')
    else:
        # Packages pull in OpenJDK, or use what is already installed.
        # Should this explitly ensure OpenJDK 1.7?
        pass

    return packages


@logged
def stop_cassandra():
    if is_cassandra_running():
        host.service_stop(get_cassandra_service())
    assert not is_cassandra_running()


@logged
def start_cassandra():
    if is_cassandra_running():
        return

    host.service_start(get_cassandra_service())

    # Wait for Cassandra to actually start, or abort.
    timeout = time.time() + RESTART_TIMEOUT
    while time.time() < timeout:
        if is_cassandra_running():
            return
        time.sleep(1)
    hookenv.log('Cassandra failed to start.', ERROR)
    raise SystemExit(1)


@logged
def reconfigure_and_restart_cassandra(overrides={}):
    stop_cassandra()
    configure_cassandra_yaml(overrides)
    start_cassandra()


@logged
def remount_cassandra():
    '''If a new mountpoint is ready, migrate data across to it.'''
    assert not is_cassandra_running()  # Guard against data loss.
    storage = relations.StorageRelation()
    if storage.needs_remount():
        if storage.mountpoint is None:
            hookenv.log('External storage AND DATA gone. '
                        'Reverting to local storage. '
                        'In danger of resurrecting old data. ',
                        WARNING)
        else:
            storage.migrate('/var/lib/cassandra', 'cassandra')
            root = os.path.join(storage.mountpoint, 'cassandra')
            os.chmod(root, 0o750)


@logged
def ensure_database_directories():
    '''Ensure that directories Cassandra expects to store its data in exist.'''
    db_dirs = get_all_database_directories()
    unpacked_db_dirs = (db_dirs['data_file_directories']
                        + [db_dirs['commitlog_directory']]
                        + [db_dirs['saved_caches_directory']])
    for db_dir in unpacked_db_dirs:
        ensure_database_directory(db_dir)


@logged
def reset_default_password():
    # If we can connect using the default superuser password
    # 'cassandra', change it to something random. We do the connection
    # test in a loop, as a newly restarted server may not be accepting
    # client connections yet.
    try:
        with connect('cassandra', 'cassandra') as session:
            hookenv.log('Changing default admin password')
            query(session, 'ALTER USER cassandra WITH PASSWORD %s',
                  ConsistencyLevel.ALL, (host.pwgen(),))  # pragma: no branch
    except cassandra.AuthenticationFailed:
        hookenv.log('Default admin password already changed')


CONNECT_TIMEOUT = 120


@contextmanager
def connect(username=None, password=None):
    cassandra_yaml = read_cassandra_yaml()
    address = cassandra_yaml['rpc_address']
    port = cassandra_yaml['native_transport_port']

    if username is None or password is None:
        username, password = superuser_credentials()

    auth_provider = cassandra.auth.PlainTextAuthProvider(username=username,
                                                         password=password)

    # If Cassandra has just been restarted, we might need to wait a
    # while until the initial gossiping has finished and connections
    # start being accepted.
    timeout = time.time() + CONNECT_TIMEOUT

    while True:
        cluster = cassandra.cluster.Cluster([address], port=port,
                                            auth_provider=auth_provider)
        try:
            yield cluster.connect()
            break
        except cassandra.cluster.NoHostAvailable as x:
            if address in x.errors:
                actual = x.errors[address]
                if isinstance(actual, cassandra.AuthenticationFailed):
                    raise actual
            if time.time() > timeout:
                raise
        finally:
            cluster.shutdown()


def query(session, statement, consistency_level, args=None):
    q = cassandra.query.SimpleStatement(statement,
                                        consistency_level=consistency_level)
    return session.execute(q, args)


def ensure_user(username, password):
    '''Create the DB user if it doesn't already exist & reset the password.'''
    hookenv.log('Creating user {}'.format(username))
    with connect() as session:
        query(session, 'CREATE USER IF NOT EXISTS %s WITH PASSWORD %s',
              ConsistencyLevel.QUORUM, (username, password,))
        query(session, 'ALTER USER %s WITH PASSWORD %s',
              ConsistencyLevel.QUORUM, (username, password,))


@logged
def ensure_superuser():
    '''If the unit's superuser account is not working, recreate it.'''
    try:
        with connect():
            hookenv.log('Unit superuser account already setup', DEBUG)
            return
    except cassandra.AuthenticationFailed:
        pass

    create_superuser()  # Doesn't exist or can't access, so create it.

    with connect():
        hookenv.log('Unit superuser password reset successful')


@logged
def create_superuser():
    '''Create or recreate the unit's superuser account.

    As there may be no known superuser credentials to use, we restart
    the node using the AllowAllAuthenticator and insert our user
    directly into the system_auth keyspace.
    '''
    username, password = superuser_credentials()
    hookenv.log('Creating unit superuser {}'.format(username))

    # Restart cassandra without authentication & listening on localhost.
    reconfigure_and_restart_cassandra(
        dict(authenticator='AllowAllAuthenticator', rpc_address='127.0.0.1'))

    with connect() as session:
        pwhash = bcrypt.hashpw(password, bcrypt.gensalt())  # Cassandra 2.1
        statement = dedent('''\
            INSERT INTO system_auth.users (name, super)
            VALUES (%s, TRUE)
            ''')
        query(session, statement, ConsistencyLevel.ALL, (username,))
        statement = dedent('''\
            INSERT INTO system_auth.credentials (username, salted_hash)
            VALUES (%s, %s)
            ''')
        query(session, statement, ConsistencyLevel.ALL, (username, pwhash))

    # Restart Cassandra with regular config.
    reconfigure_and_restart_cassandra()


def get_cqlshrc_path():
    return os.path.expanduser('~root/.cassandra/cqlshrc')


def superuser_username():
    return 'juju_{}'.format(re.subn(r'\W', '_', hookenv.local_unit())[0])


def superuser_credentials():
    '''Return (username, password) to connect to the Cassandra superuser.

    The credentials are persisted in the root user's cqlshrc file,
    making them easily accessible to the command line tools.
    '''
    cqlshrc_path = get_cqlshrc_path()
    cqlshrc = configparser.ConfigParser(interpolation=None)
    cqlshrc.read([cqlshrc_path])

    try:
        section = cqlshrc['authentication']
        return section['username'], section['password']
    except KeyError:
        hookenv.log('Generating superuser credentials into {}'.format(
            cqlshrc_path))

    config = hookenv.config()

    username = superuser_username()
    password = host.pwgen()

    hookenv.log('Generated username {}'.format(username))

    # We set items separately, rather than together, so that we have a
    # defined order for the ConfigParser to preserve and the tests to
    # rely on.
    cqlshrc.setdefault('authentication', {})
    cqlshrc['authentication']['username'] = username
    cqlshrc['authentication']['password'] = password
    cqlshrc.setdefault('connection', {})
    cqlshrc['connection']['hostname'] = hookenv.unit_public_ip()
    cqlshrc['connection']['port'] = str(config['native_client_port'])

    ini = io.StringIO()
    cqlshrc.write(ini)
    host.mkdir(os.path.dirname(cqlshrc_path), perms=0o500)
    host.write_file(cqlshrc_path, ini.getvalue().encode('UTF-8'), perms=0o400)

    return username, password


def num_nodes():
    return len(rollingrestart.get_peers()) + 1


def read_cassandra_yaml():
    cassandra_yaml_path = get_cassandra_yaml_file()
    with open(cassandra_yaml_path, 'rb') as f:
        return yaml.safe_load(f)


@logged
def write_cassandra_yaml(cassandra_yaml):
    cassandra_yaml_path = get_cassandra_yaml_file()
    host.write_file(cassandra_yaml_path,
                    yaml.safe_dump(cassandra_yaml).encode('UTF-8'))


def configure_cassandra_yaml(overrides={}):
    cassandra_yaml_path = get_cassandra_yaml_file()
    config = hookenv.config()

    maybe_backup(cassandra_yaml_path)  # Its comments may be useful.

    cassandra_yaml = read_cassandra_yaml()

    cassandra_yaml['cluster_name'] = config['cluster_name']

    seeds = ','.join(get_seeds())  # Don't include whitespace!
    cassandra_yaml['seed_provider'][0]['parameters'][0]['seeds'] = seeds

    cassandra_yaml['num_tokens'] = int(config['num_tokens'])

    cassandra_yaml['listen_address'] = hookenv.unit_private_ip()
    cassandra_yaml['rpc_address'] = hookenv.unit_public_ip()

    cassandra_yaml['native_transport_port'] = config['native_client_port']
    cassandra_yaml['rpc_port'] = config['thrift_client_port']

    cassandra_yaml['storage_port'] = config['cluster_port']
    cassandra_yaml['ssl_storage_port'] = config['cluster_ssl_port']

    dirs = get_all_database_directories()
    cassandra_yaml.update(dirs)

    cassandra_yaml['partitioner'] = (config['partitioner']
                                     or 'Murmur3Partitioner')

    cassandra_yaml['authenticator'] = 'PasswordAuthenticator'
    cassandra_yaml['authorizer'] = config['authorizer']

    cassandra_yaml['endpoint_snitch'] = 'GossipingPropertyFileSnitch'

    cassandra_yaml.update(overrides)

    write_cassandra_yaml(cassandra_yaml)


def get_pid_from_file(pid_file):
    try:
        with open(pid_file, 'r') as f:
            pid = int(f.read().strip().split()[0])
            if pid <= 1:
                raise ValueError('Illegal pid {}'.format(pid))
            return pid
    except (ValueError, IndexError) as e:
        hookenv.log("Invalid PID in {}.".format(pid_file))
        raise ValueError(e)


def is_cassandra_running():
    pid_file = get_cassandra_pid_file()

    try:
        # Keep checking for full up state with binary backoff
        # up to 256 seconds, or 8.5 minutes total.
        for i in range(9):
            # We reload the pid every time, in case it has gone away.
            pid = get_pid_from_file(pid_file)

            # This does not kill the process but checks for its
            # existence. It raises an OSError if the process is not
            # running.
            os.kill(pid, 0)

            if subprocess.call(["nodetool", "-h",
                                hookenv.unit_private_ip(), "status"],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL) == 0:
                hookenv.log(
                    "Cassandra PID {} is running and responding".format(pid))
                return True
            else:
                hookenv.log("Cassandra PID {} is running but not responding, "
                            "attempt {}.".format(pid, i))
                time.sleep(2 ** i)

        pid = get_pid_from_file(pid_file)
        hookenv.log("Cassandra PID {} is running but not responding to "
                    "nodetool. Please manually check on the state of "
                    "Cassandra".format(pid), ERROR)
        raise SystemExit(1)  # System state is insane, so die.

    except Exception:
        # We check for pid file existance after attempting to check if the
        # system is up, to avoid races where we are checking as the system
        # is shutting itself down.
        if not os.path.exists(pid_file):
            hookenv.log("Cassandra is stopped")
            return False
        else:
            try:
                os.kill(get_pid_from_file(pid_file), 0)
            except ProcessLookupError:
                hookenv.log("Cassandra is not running, but pid file exists.",
                            WARNING)
                return False
        # The system is insane. For example, the pid_file contains '-1'.
        # Reraise the exception.
        raise


@logged
def reset_all_io_schedulers():
    dirs = get_all_database_directories()
    dirs = (dirs['data_file_directories'] + [dirs['commitlog_directory']]
            + [dirs['saved_caches_directory']])
    config = hookenv.config()
    for d in dirs:
        if os.path.isdir(d):  # Directory may not exist yet.
            set_io_scheduler(config['io_scheduler'], d)


@logged
def reset_auth_keyspace_replication():
    # Cassandra requires you to manually set the replication factor of
    # the system_auth keyspace, to ensure availability and redundancy.
    # The charm can't control how many or which units might get dropped,
    # so for authentication to work we need to set the replication factor
    # on the system_auth keyspace so that every node contains all of the
    # data. Authentication information will remain available, even in the
    # face of all the other nodes having gone away due to an in progress
    # 'juju destroy-service'.
    n = num_nodes()
    datacenter = hookenv.config()['datacenter']
    with connect() as session:
        strategy_opts = get_auth_keyspace_replication(session)

        rf = strategy_opts.get(datacenter, 0)
        if rf == n and strategy_opts['class'] == 'NetworkTopologyStrategy':
            hookenv.log('system_auth rf={!r}'.format(strategy_opts))
        else:
            strategy_opts['class'] = 'NetworkTopologyStrategy'
            strategy_opts[datacenter] = n
            if 'replication_factor' in strategy_opts:
                del strategy_opts['replication_factor']
            set_auth_keyspace_replication(session, strategy_opts)


def get_auth_keyspace_replication(session):
    statement = dedent('''\
        SELECT strategy_options FROM system.schema_keyspaces
        WHERE keyspace_name='system_auth'
        ''')
    r = query(session, statement, ConsistencyLevel.QUORUM)
    return json.loads(r[0][0])


def set_auth_keyspace_replication(session, settings):
    hookenv.log('Updating system_auth rf={!r}'.format(settings))
    statement = 'ALTER KEYSPACE system_auth WITH REPLICATION = %s'
    query(session, statement, ConsistencyLevel.QUORUM, (settings,))


@logged
def repair_auth_keyspace():
    # If the number of nodes has changed, so has system_auth replication
    # factor. We need to run nodetool repair on the system_auth
    # keyspace.
    config = hookenv.config()
    config['num_nodes'] = num_nodes()
    if config.changed('num_nodes'):
        subprocess.check_call(['nodetool', 'repair', 'system_auth'])
