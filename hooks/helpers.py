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

import configparser
from contextlib import contextmanager
from datetime import timedelta
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
import cassandra.policies
import cassandra.query
import yaml

from charmhelpers.core import hookenv, host
from charmhelpers.core.hookenv import DEBUG, ERROR, WARNING
from charmhelpers import fetch

import relations
import rollingrestart
from policies import ReconnectUntilReconnectionPolicy, RetryUntilRetryPolicy


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
    packages.add('run-one')

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

    hookenv.log('Starting Cassandra with seeds {!r}'.format(get_seeds()))
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
def wait_for_seeds():
    '''Wait for at least one of our seeds to be contactable.

    Does nothing if we are locally seeded (the only seed is this unit).
    We primarily need to wait until the seeds peer relation-changed hook
    has been run and the seed's firewall rules updated.
    '''
    seed_ips = set(get_seeds())
    seed_ips.discard(hookenv.unit_private_ip())
    if not seed_ips:
        hookenv.log('Self-seeded')
        return
    i = 0
    while True:
        for ip in seed_ips:
            try:
                subprocess.check_output(['nodetool', '--host', ip, 'status'])
                hookenv.log('Seed {} is responding'.format(ip))
                return
            except subprocess.CalledProcessError:
                hookenv.log('Seed {} is not responding'.format(ip))
        i += 1
        time.sleep(max(2**i, 60))


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
        hookenv.config()['bootstrapped_into_cluster'] = False
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
    # 'cassandra', change it to something random.
    try:
        with connect('cassandra', 'cassandra') as session:
            hookenv.log('Changing default admin password')
            query(session, 'ALTER USER cassandra WITH PASSWORD %s',
                  ConsistencyLevel.ALL, (host.pwgen(),))  # pragma: no branch
    except cassandra.AuthenticationFailed:
        hookenv.log('Default admin password already changed')


CONNECT_TIMEOUT = 240
AUTH_TIMEOUT = 15


@contextmanager
def connect(username=None, password=None, timeout=CONNECT_TIMEOUT):
    cassandra_yaml = read_cassandra_yaml()
    addresses = [cassandra_yaml['rpc_address']] + get_seeds()
    port = cassandra_yaml['native_transport_port']

    if username is None or password is None:
        username, password = superuser_credentials()

    auth_provider = cassandra.auth.PlainTextAuthProvider(username=username,
                                                         password=password)

    # Although we specify a reconnection_policy, it does not apply to
    # the initial connection so we retry in a loop.
    start = time.time()
    until = start + CONNECT_TIMEOUT
    auth_until = start + AUTH_TIMEOUT
    while True:
        cluster = cassandra.cluster.Cluster(
            addresses, port=port, auth_provider=auth_provider,
            default_retry_policy=RetryUntilRetryPolicy(until),
            reconnection_policy=ReconnectUntilReconnectionPolicy(until))
        # conviction_policy_factory=OptimisticConvictionPolicy)
        try:
            session = cluster.connect()
            session.default_timeout = CONNECT_TIMEOUT
            break
        except cassandra.cluster.NoHostAvailable as x:
            cluster.shutdown()
            now = time.time()
            # If every node failed auth, reraise one of the
            # AuthenticationFailed exceptions. Unwrapping the exception
            # means call sites don't have to sniff the exception bundle.
            # We don't retry on auth fails; this method should not be
            # called if the system_auth data is inconsistent.
            auth_fails = [af for af in x.errors.values()
                          if isinstance(af, cassandra.AuthenticationFailed)]
            if len(auth_fails) == len(x.errors):
                if now > auth_until:
                    raise auth_fails[0]
            if now > until:
                raise
        time.sleep(1)
    try:
        yield session
    finally:
        cluster.shutdown()


def query(session, statement, consistency_level, args=None):
    q = cassandra.query.SimpleStatement(statement,
                                        consistency_level=consistency_level)

    until = time.time() + 60
    while True:
        try:
            return session.execute(q, args)
        except Exception:
            if time.time() > until:
                raise


def ensure_user(username, password, superuser=False):
    '''Create the DB user if it doesn't already exist & reset the password.'''
    if superuser:
        hookenv.log('Creating SUPERUSER {}'.format(username))
        sup = 'SUPERUSER'
    else:
        hookenv.log('Creating user {}'.format(username))
        sup = 'NOSUPERUSER'
    with connect() as session:
        # We do this in a loop, as there is a race condition between the
        # CREATE USER IF EXISTS and the ALTER USER. It should be nearly
        # impossible to hit it, but hit it I have.
        while True:
            try:
                query(session,
                      'CREATE USER IF NOT EXISTS %s '
                      'WITH PASSWORD %s {}'.format(sup),
                      ConsistencyLevel.ALL, (username, password,))
                query(session, 'ALTER USER %s WITH PASSWORD %s {}'.format(sup),
                      ConsistencyLevel.ALL, (username, password,))
                break
            except cassandra.InvalidRequest:
                pass


@logged
def ensure_unit_superuser():
    '''If the unit's superuser account is not working, recreate it.'''
    try:
        with connect():
            hookenv.log('Unit superuser account already setup', DEBUG)
            return
    except cassandra.AuthenticationFailed:
        pass

    create_unit_superuser()  # Doesn't exist or can't access, so create it.

    with connect():
        hookenv.log('Unit superuser password reset successful')


@logged
def create_unit_superuser():
    '''Create or recreate the unit's superuser account.

    As there may be no known superuser credentials to use, we restart
    the node using the AllowAllAuthenticator and insert our user
    directly into the system_auth keyspace.
    '''
    username, password = superuser_credentials()
    hookenv.log('Creating unit superuser {}'.format(username))

    # Restart cassandra without authentication & listening on localhost.
    wait_for_normality()
    reconfigure_and_restart_cassandra(
        dict(authenticator='AllowAllAuthenticator', rpc_address='127.0.0.1'))
    wait_for_normality()

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
    wait_for_normality()
    reconfigure_and_restart_cassandra()
    wait_for_normality()

    # Ensure auth details replicated to where they need to be.
    repair_auth_keyspace()


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
    cqlshrc['connection']['port'] = str(config['native_transport_port'])

    ini = io.StringIO()
    cqlshrc.write(ini)
    host.mkdir(os.path.dirname(cqlshrc_path), perms=0o700)
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

    # Most options just copy from config.yaml keys with the same name.
    # Using the same name is preferred to match the actual Cassandra
    # documentation.
    simple_config_keys = ['cluster_name', 'num_tokens',
                          'partitioner', 'authorizer',
                          'compaction_throughput_mb_per_sec',
                          'stream_throughput_outbound_megabits_per_sec',
                          'tombstone_warn_threshold',
                          'tombstone_failure_threshold',
                          'native_transport_port', 'rpc_port',
                          'storage_port', 'ssl_storage_port']
    cassandra_yaml.update((k, config[k]) for k in simple_config_keys)

    seeds = ','.join(get_seeds())  # Don't include whitespace!
    cassandra_yaml['seed_provider'][0]['parameters'][0]['seeds'] = seeds

    cassandra_yaml['listen_address'] = hookenv.unit_private_ip()
    cassandra_yaml['rpc_address'] = hookenv.unit_public_ip()

    dirs = get_all_database_directories()
    cassandra_yaml.update(dirs)

    # The charm only supports password authentication. In the future we
    # may also support AllowAllAuthenticator. I'm not sure if others
    # such as Kerboros can be supported or are useful.
    cassandra_yaml['authenticator'] = 'PasswordAuthenticator'

    # GossipingPropertyFileSnitch is the only snitch recommended for
    # production. It we allow others, we need to consider how to deal
    # with the system_auth keyspace replication settings.
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
    # so for authentication to work we set the replication factor
    # on the system_auth keyspace so that every node contains all of the
    # data. Authentication information will remain available on the
    # local node, even in the face of all the other nodes having gone
    # away due to an in progress 'juju destroy-service'.
    n = min(num_nodes(), 5)  # Cap at 5 replicas.
    datacenter = hookenv.config()['datacenter']
    with connect() as session:
        strategy_opts = get_auth_keyspace_replication(session)
        rf = int(strategy_opts.get(datacenter, -1))
        hookenv.log('system_auth rf={!r}'.format(strategy_opts))
        if rf != n:
            strategy_opts['class'] = 'NetworkTopologyStrategy'
            strategy_opts[datacenter] = n
            if 'replication_factor' in strategy_opts:
                del strategy_opts['replication_factor']
            set_auth_keyspace_replication(session, strategy_opts)
            repair_auth_keyspace()


def get_auth_keyspace_replication(session):
    statement = dedent('''\
        SELECT strategy_options FROM system.schema_keyspaces
        WHERE keyspace_name='system_auth'
        ''')
    r = query(session, statement, ConsistencyLevel.ALL)
    return json.loads(r[0][0])


def set_auth_keyspace_replication(session, settings):
    hookenv.log('Updating system_auth rf={!r}'.format(settings))
    statement = 'ALTER KEYSPACE system_auth WITH REPLICATION = %s'
    query(session, statement, ConsistencyLevel.ALL, (settings,))


@logged
def repair_auth_keyspace():
    subprocess.check_call(['nodetool', 'repair', 'system_auth'])


@logged
def decommission_node():
    '''Decommission this node.

    Decommissioning will fail if:
        - Another node is already decommissioning.
        - The remaining nodes do not have enough space to contain this
          node's data.

    (Juju's service leadership feature should allow us to address the
    first point, and the environment goal state feature should allow us
    to tear down the entire service and only trigger the second point
    when it is helpful)
    '''
    hookenv.log('Decommissioning Cassandra node.', WARNING)
    rv = subprocess.call(['nodetool', 'decommission'],
                         stderr=subprocess.STDOUT)
    if rv != 0:
        hookenv.log('Unable to decommission node. '
                    'The cluster will need repair.', ERROR)
    stop_cassandra()
    hookenv.config()['decommissioned'] = True


def is_bootstrapped():
    '''Return True if the node has already bootstrapped into the cluster.'''
    return hookenv.config().get('bootstrapped_into_cluster', False)


@logged
def post_bootstrap():
    '''Maintain state on if the node has bootstrapped into the cluster.

    Per documented procedure for adding new units to a cluster, wait 2
    minutes if the unit has just bootstrapped to ensure no other.
    '''
    config = hookenv.config()
    if num_nodes() == 1:
        # There is no cluster (just us), so we are not bootstrapped into
        # the cluster.
        config['bootstrapped_into_cluster'] = False
    else:
        config['bootstrapped_into_cluster'] = True
        if config.changed('bootstrapped_into_cluster'):
            hookenv.log('Bootstrapped into the cluster. Waiting {}s.'.format(
                config['post_bootstrap_delay']))
            time.sleep(config['post_bootstrap_delay'])


def is_schema_agreed():
    '''Return True if all the nodes that are up agree on a schema.'''
    up_ips = set(up_node_ips())
    # Always include ourself since we may be joining just now.
    up_ips.add(hookenv.unit_private_ip())
    raw = subprocess.check_output(['nodetool', 'describecluster'],
                                  universal_newlines=True)
    # The output of nodetool describe cluster is almost yaml,
    # so we use that tool once we fix the tabs.
    description = yaml.load(raw.replace('\t', ' '))
    versions = description['Cluster Information']['Schema versions'] or {}

    for schema, schema_ips in versions.items():
        schema_ips = set(schema_ips)
        if up_ips.issubset(schema_ips):
            hookenv.log('{!r} agree on schema'.format(up_ips), DEBUG)
            return True
    hookenv.log('{!r} do not agree on schema'.format(up_ips), DEBUG)
    return False


def up_node_ips():
    '''IP addresses of nodes that are up.'''
    raw = subprocess.check_output(['nodetool', 'status'],
                                  universal_newlines=True)
    for line in raw.splitlines():
        if line.startswith('U'):  # Up
            ip = line.split()[1]
            yield ip


@logged
def wait_for_agreed_schema():
    i = 0
    while True:
        if is_schema_agreed():
            return
        i += 1
        hookenv.log('Unit and seeds do not agree on schema, '
                    'check #{}'.format(i))
        time.sleep(min(60, 2 ** i))


def get_peer_ips():
    ips = set()
    relid = rollingrestart.get_peer_relation_id()
    if relid is not None:
        for unit in hookenv.related_units(relid):
            ip = hookenv.relation_get('private-address', unit, relid)
            ips.add(ip)
    return ips


def is_all_normal():
    '''All nodes in the cluster report status Normal.

    Returns false if a node is joining, leaving or moving in the ring.
    '''
    is_all_normal = True
    raw = subprocess.check_output(['nodetool', 'status',
                                   'system_auth'], universal_newlines=True)
    node_status_re = re.compile('^([UD])([NLJM])\s+([\d\.]+)\s')
    for line in raw.splitlines():
        match = node_status_re.search(line)
        if match is not None:
            updown, mode, address = match.groups()
            # updown is purely informative. It would be nice if we could
            # block until down nodes come back up, but unfortunately
            # there are Juju race conditions where a unit can depart
            # completely, yet this unit thinks it is still a peer.
            if updown == 'D':
                hookenv.log('Node {} is down'.format(address))

            if mode == 'L':
                hookenv.log('Node {} is leaving the cluster'.format(address))
                is_all_normal = False
            elif mode == 'J':
                hookenv.log('Node {} is joining the cluster'.format(address))
                is_all_normal = False
            elif mode == 'M':
                hookenv.log('Node {} is moving ring position'.format(address))
                is_all_normal = False
    return is_all_normal


@logged
def wait_for_normality():
    i = 0
    while True:
        if is_all_normal():
            return
        i += 1
        hookenv.log('Cluster operations in progress, check #{}'.format(i))
        time.sleep(min(60, 2 ** i))


@logged
def emit_describe_cluster():
    '''Run nodetool describecluster for the logs.'''
    subprocess.call(['nodetool', 'describecluster'])


@logged
def emit_auth_keyspace_status():
    '''Run 'nodetool status system_auth' for the logs.'''
    subprocess.call(['nodetool', 'status', 'system_auth'])


@logged
def emit_netstats():
    '''Run 'nodetool netstats' for the logs.'''
    subprocess.call(['nodetool', 'netstats'])


# FOR CHARMHELPERS (and think of a better name)
def week_spread(unit_num):
    '''Pick a time for a unit's weekly job.

    Jobs are spread out evenly throughout the week as best we can.
    The chosen time only depends on the unit number, and does not change
    if other units are added and removed; while the chosen time will not
    be perfect, we don't have to worry about skipping a weekly job if
    units are added or removed at the wrong moment.

    Returns (dow, hour, minute) suitable for cron.
    '''
    def vdc(n, base=2):
        '''Van der Corpet sequence. 0, 0.5, 0.25, 0.75, 0.125, 0.625, ...

        http://rosettacode.org/wiki/Van_der_Corput_sequence#Python
        '''
        vdc, denom = 0, 1
        while n:
            denom *= base
            n, remainder = divmod(n, base)
            vdc += remainder / denom
        return vdc
    # We could use the vdc() function to distribute jobs evenly throughout
    # the week, so unit 0==0, unit 1==3.5days, unit 2==1.75 etc. But
    # plain modulo for the day of week is easier for humans and what
    # you expect for 7 units or less.
    sched_dow = unit_num % 7
    # We spread time of day so each batch of 7 units gets the same time,
    # as far spread out from the other batches of 7 units as possible.
    minutes_in_day = 24 * 60
    sched = timedelta(minutes=int(minutes_in_day * vdc(unit_num//7)))
    sched_hour = sched.seconds//(60*60)
    sched_minute = sched.seconds//60 - sched_hour * 60
    return sched_dow, sched_hour, sched_minute
