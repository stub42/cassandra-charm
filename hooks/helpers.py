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
from itertools import chain
import json
import os.path
import re
import shutil
import subprocess
import sys
from textwrap import dedent
import time

import bcrypt
from cassandra import ConsistencyLevel
import cassandra.auth
import cassandra.cluster
import cassandra.query
import yaml

from charmhelpers.contrib import unison
from charmhelpers.core import hookenv, host
from charmhelpers.core.hookenv import DEBUG, ERROR, WARNING
from charmhelpers import fetch

import relations
import rollingrestart


RESTART_TIMEOUT = 600


def logged(func):
    @wraps(func)
    def wrapper(*args, **kw):
        hookenv.log("* Helper {}/{}".format(hookenv.hook_name(),
                                            func.__name__))
        return func(*args, **kw)
    return wrapper


def backoff(what_for, max_pause=60):
    i = 0
    while True:
        yield True
        i += 1
        pause = min(max_pause, 2 ** i)
        time.sleep(pause)
        if pause > 10:
            hookenv.log('Recheck {} for {}'.format(i, what_for))


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


def seed_ips():
    '''Return the set of seed ip addresses.

    If this is the only unit in the service, then the local unit's IP
    address is returned as the only seed.

    If there is more than one unit in the service, then the IP addresses
    of three lowest numbered peers (if bootstrapped) are returned.
    '''
    peers = rollingrestart.get_peers()
    if not peers:
        return set([hookenv.unit_private_ip()])

    # The three lowest numbered units are seeds & may include this unit.
    seeds = sorted(list(peers) + [hookenv.local_unit()],
                   key=lambda x: int(x.split('/')[-1]))[:3]

    relid = rollingrestart.get_peer_relation_id()
    return set(hookenv.relation_get('private-address', seed, relid)
               for seed in seeds if is_bootstrapped(seed))


def actual_seed_ips():
    '''Return the seeds currently in cassandra.yaml'''
    cassandra_yaml = read_cassandra_yaml()
    s = cassandra_yaml['seed_provider'][0]['parameters'][0]['seeds']
    return set(s.split(','))


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

    # Work around Bug #1427150 by ensuring components of the path are
    # created with the required permissions, if necessary.
    component = os.sep
    for p in absdir.split(os.sep)[1:-1]:
        component = os.path.join(component, p)
        if not os.path.exists(p):
            host.mkdir(component)
    assert component == os.path.split(absdir)[0]
    host.mkdir(absdir, owner='cassandra', group='cassandra', perms=0o750)
    return absdir


def get_all_database_directories():
    config = hookenv.config()
    return dict(
        data_file_directories=[get_database_directory(d)
                               for d in (config['data_file_directories'] or
                                         'data').split()],
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

    output = subprocess.check_output(['df', directory],
                                     universal_newlines=True)

    if not is_lxc():
        hookenv.log("Setting block device of {} to IO scheduler {}"
                    "".format(directory, io_scheduler))
        block_dev = re.findall(block_regex, output)[0]
        sys_file = os.path.join("/", "sys", "block", block_dev,
                                "queue", "scheduler")
        try:
            host.write_file(sys_file, io_scheduler.encode('ascii'),
                            perms=0o644)
        except OSError as e:
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


def get_jre():
    # DataStax Enterprise requires the Oracle JRE.
    if get_cassandra_edition() == 'dse':
        return 'oracle'

    config = hookenv.config()
    jre = config['jre'].lower()
    if jre not in ('openjdk', 'oracle'):
        hookenv.log('Unknown JRE {!r} specified. Using OpenJDK'.format(jre),
                    ERROR)
        jre = 'openjdk'
    return jre


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
        return '2.0' if get_package_version('dse-full') else None
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
        packages = set(['cassandra'])  # 'cassandra-tools'

    packages.add('ntp')
    packages.add('run-one')
    packages.add('netcat')

    jre = get_jre()
    if jre == 'oracle':
        # We can't use a packaged version of the Oracle JRE, as we
        # are not allowed to bypass Oracle's click through license
        # agreement.
        pass
    else:
        packages.add('openjdk-7-jre-headless')

    return packages


@logged
def stop_cassandra(immediate=False):
    if is_cassandra_running():
        if not immediate:
            # If there are cluster operations in progress, wait until
            # they are complete before restarting. This might take days.
            wait_for_normality()
        host.service_stop(get_cassandra_service())
    assert not is_cassandra_running()


@logged
def start_cassandra():
    if is_cassandra_running():
        return

    actual_seeds = actual_seed_ips()
    assert actual_seeds, 'Attempting to start cassandra with empty seed list'
    hookenv.log('Starting Cassandra with seeds {!r}'.format(actual_seeds))
    host.service_start(get_cassandra_service())

    # Wait for Cassandra to actually start, or abort.
    timeout = time.time() + RESTART_TIMEOUT
    while time.time() < timeout:
        if is_cassandra_running():
            return
        time.sleep(1)
    hookenv.log('Cassandra failed to start.', ERROR)
    raise SystemExit(1)


def is_responding(ip, port=None, timeout=5):
    if port is None:
        port = hookenv.config()['storage_port']
    try:
        subprocess.check_output(['nc', '-zw', str(timeout), ip, str(port)],
                                stderr=subprocess.STDOUT)
        hookenv.log('{} listening on port {}'.format(ip, port), DEBUG)
        return True
    except subprocess.TimeoutExpired:
        hookenv.log('{} not listening on port {}'.format(ip, port), DEBUG)
        return False


@logged
def are_all_nodes_responding():
    all_contactable = True
    for ip in node_ips():
        if ip == hookenv.unit_private_ip():
            pass
        elif is_responding(ip, timeout=5):
            hookenv.log('{} is responding'.format(ip))
        else:
            all_contactable = False
            hookenv.log('{} is not responding'.format(ip))
    return all_contactable


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
    unpacked_db_dirs = (db_dirs['data_file_directories'] +
                        [db_dirs['commitlog_directory']] +
                        [db_dirs['saved_caches_directory']])
    for db_dir in unpacked_db_dirs:
        ensure_database_directory(db_dir)


@logged
def reset_default_password():
    config = hookenv.config()
    if config.get('default_admin_password_changed', False):
        hookenv.log('Default admin password changed in an earlier hook')
        return

    # If we can connect using the default superuser password
    # 'cassandra', change it to something random. We do this in a loop
    # to ensure the hook that calls this is idempotent.
    try:
        with connect('cassandra', 'cassandra') as session:
            hookenv.log('Changing default admin password')
            query(session, 'ALTER USER cassandra WITH PASSWORD %s',
                  ConsistencyLevel.QUORUM, (host.pwgen(),))
    except cassandra.AuthenticationFailed:
        hookenv.log('Default admin password already changed')

    config['default_admin_password_changed'] = True


CONNECT_TIMEOUT = 300


@contextmanager
def connect(username=None, password=None, timeout=CONNECT_TIMEOUT,
            auth_timeout=CONNECT_TIMEOUT):
    # We pull the currently configured listen address and port from the
    # yaml, rather than the service configuration, as it may have been
    # overridden.
    cassandra_yaml = read_cassandra_yaml()
    address = cassandra_yaml['rpc_address']
    if address == '0.0.0.0':
        address = 'localhost'
    port = cassandra_yaml['native_transport_port']

    if username is None or password is None:
        username, password = superuser_credentials()

    auth_provider = cassandra.auth.PlainTextAuthProvider(username=username,
                                                         password=password)

    # Although we specify a reconnection_policy, it does not apply to
    # the initial connection so we retry in a loop.
    start = time.time()
    until = start + timeout
    auth_until = start + auth_timeout
    while True:
        cluster = cassandra.cluster.Cluster([address], port=port,
                                            auth_provider=auth_provider)
        try:
            session = cluster.connect()
            session.default_timeout = timeout
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
            if auth_fails:
                if now > auth_until:
                    raise auth_fails[0]
            if now > until:
                raise
        time.sleep(1)
    try:
        yield session
    finally:
        cluster.shutdown()


QUERY_TIMEOUT = 60


def query(session, statement, consistency_level, args=None):
    q = cassandra.query.SimpleStatement(statement,
                                        consistency_level=consistency_level)

    until = time.time() + QUERY_TIMEOUT
    for _ in backoff('query to execute'):
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
        query(session,
              'CREATE USER IF NOT EXISTS %s '
              'WITH PASSWORD %s {}'.format(sup),
              ConsistencyLevel.QUORUM, (username, password,))
        query(session, 'ALTER USER %s WITH PASSWORD %s {}'.format(sup),
              ConsistencyLevel.QUORUM, (username, password,))


@logged
def ensure_unit_superuser():
    '''If the unit's superuser account is not working, recreate it.'''
    try:
        with connect(auth_timeout=10):
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
        dict(authenticator='AllowAllAuthenticator', rpc_address='localhost'))
    wait_for_normality()
    emit_cluster_info()
    for _ in backoff('superuser creation'):
        try:
            with connect() as session:
                pwhash = bcrypt.hashpw(password,
                                       bcrypt.gensalt())  # Cassandra 2.1
                statement = dedent('''\
                    INSERT INTO system_auth.users (name, super)
                    VALUES (%s, TRUE)
                    ''')
                query(session, statement, ConsistencyLevel.QUORUM, (username,))
                statement = dedent('''\
                    INSERT INTO system_auth.credentials (username, salted_hash)
                    VALUES (%s, %s)
                    ''')
                query(session, statement,
                      ConsistencyLevel.QUORUM, (username, pwhash))
                break
        except Exception as x:
            print(str(x))

    # Restart Cassandra with regular config.
    nodetool('flush')  # Ensure our backdoor updates are flushed.
    reconfigure_and_restart_cassandra()
    wait_for_normality()


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
    if get_cassandra_version().startswith('2.0'):
        cqlshrc['connection']['port'] = str(config['rpc_port'])
    else:
        cqlshrc['connection']['port'] = str(config['native_transport_port'])

    ini = io.StringIO()
    cqlshrc.write(ini)
    host.mkdir(os.path.dirname(cqlshrc_path), perms=0o700)
    host.write_file(cqlshrc_path, ini.getvalue().encode('UTF-8'), perms=0o400)

    return username, password


def emit(*args, **kw):
    # Just like print, but with plumbing and mocked out in the test suite.
    print(*args, **kw)
    sys.stdout.flush()


def nodetool(*cmd, ip=None, timeout=120):
    cmd = ['nodetool'] + [str(i) for i in cmd]
    if ip is not None:
        assert ip in unison.collect_authed_hosts(
            rollingrestart.get_peer_relation_name())
        cmd = ['sudo', '-Hsu', 'juju_ssh', 'ssh', ip] + cmd
    i = 0
    until = time.time() + timeout
    for _ in backoff('nodetool to work'):
        i += 1
        try:
            raw = subprocess.check_output(cmd, universal_newlines=True,
                                          timeout=max(0, until - time.time()),
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
            if time.time() >= until:
                raise


def node_ips():
    '''IP addresses of all nodes in the Cassandra cluster.'''
    if is_bootstrapped() or num_peers() == 0:
        # If bootstrapped, or standalone, we trust our local info.
        raw = nodetool('status', 'system_auth')
    else:
        # If not bootstrapped, we query a seed.
        authed_ips = unison.collect_authed_hosts(
            rollingrestart.get_peer_relation_name())
        seeds = [ip for ip in seed_ips() if ip in authed_ips]
        assert seeds, 'No seeds'
        raw = nodetool('status', 'system_auth', ip=seeds[0])

    ips = set()
    for line in raw.splitlines():
        match = re.search(r'^(\w)([NLJM])\s+([\d\.]+)\s', line)
        if match is not None and (match.group(1) == 'U'
                                  or match.group(2) != 'L'):
            ips.add(match.group(3))
    return ips


def up_node_ips():
    '''IP addresses of nodes that are up.'''
    raw = nodetool('status', 'system_auth')
    ips = set()
    for line in raw.splitlines():
        match = re.search(r'^(\w)([NLJM])\s+([\d\.]+)\s', line)
        if match is not None and match.group(1) == 'U':  # Up
            ips.add(match.group(3))
    return ips


def num_nodes():
    '''Number of nodes in the Cassandra cluster.

    This is not necessarily the same as the number of peers, as nodes
    may be decommissioned.
    '''
    return len(node_ips())


def num_peers():
    return len(rollingrestart.get_peers())


def read_cassandra_yaml():
    cassandra_yaml_path = get_cassandra_yaml_file()
    with open(cassandra_yaml_path, 'rb') as f:
        return yaml.safe_load(f)


@logged
def write_cassandra_yaml(cassandra_yaml):
    cassandra_yaml_path = get_cassandra_yaml_file()
    host.write_file(cassandra_yaml_path,
                    yaml.safe_dump(cassandra_yaml).encode('UTF-8'))


def configure_cassandra_yaml(overrides={}, seeds=None):
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

    seeds = ','.join(seeds or seed_ips())  # Don't include whitespace!
    assert seeds, 'Attempting to configure cassandra with empty seed list'
    cassandra_yaml['seed_provider'][0]['parameters'][0]['seeds'] = seeds

    cassandra_yaml['listen_address'] = hookenv.unit_private_ip()
    cassandra_yaml['rpc_address'] = '0.0.0.0'
    if not get_cassandra_version().startswith('2.0'):
        cassandra_yaml['broadcast_rpc_address'] = hookenv.unit_public_ip()

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
        for _ in backoff('Cassandra to respond'):
            # We reload the pid every time, in case it has gone away.
            # If it goes away, a FileNotFound exception is raised.
            pid = get_pid_from_file(pid_file)

            # This does not kill the process but checks for its
            # existence. It raises an ProcessLookupError if the process
            # is not running.
            os.kill(pid, 0)

            if subprocess.call(["nodetool", "status", "system_auth"],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL) == 0:
                hookenv.log(
                    "Cassandra PID {} is running and responding".format(pid))
                return True
    except FileNotFoundError:
        hookenv.log("Cassandra is not running. PID file does not exist.")
        return False
    except ProcessLookupError:
        if os.path.exists(pid_file):
            # File disappeared between reading the PID and checking if
            # the PID is running.
            hookenv.log("Cassandra is not running, but pid file exists.",
                        WARNING)
        else:
            hookenv.log("Cassandra is not running. PID file does not exist.")
        return False


@logged
def reset_all_io_schedulers():
    dirs = get_all_database_directories()
    dirs = (dirs['data_file_directories'] + [dirs['commitlog_directory']] +
            [dirs['saved_caches_directory']])
    config = hookenv.config()
    for d in dirs:
        if os.path.isdir(d):  # Directory may not exist yet.
            set_io_scheduler(config['io_scheduler'], d)


@logged
def reset_auth_keyspace_replication():
    # Cassandra requires you to manually set the replication factor of
    # the system_auth keyspace, to ensure availability and redundancy.
    n = max(min(num_nodes(), 3), 1)  # Cap at 1-3 replicas.
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
    r = query(session, statement, ConsistencyLevel.QUORUM)
    return json.loads(r[0][0])


def set_auth_keyspace_replication(session, settings):
    wait_for_normality()
    hookenv.log('Updating system_auth rf={!r}'.format(settings))
    statement = 'ALTER KEYSPACE system_auth WITH REPLICATION = %s'
    query(session, statement, ConsistencyLevel.QUORUM, (settings,))


@logged
def repair_auth_keyspace():
    # First, wait for schema agreement. Attempting to repair a keyspace
    # with inconsistent replication settings will fail.
    wait_for_agreed_schema()
    # We don't use the nodetool helper here, as we only want one attempt
    # without a timeout.
    subprocess.check_call(['nodetool', 'repair', 'system_auth'],
                          universal_newlines=True, stderr=subprocess.STDOUT)


def non_system_keyspaces():
    # If there are only system keyspaces defined, there is no data we
    # may want to preserve and we can safely proceed with the bootstrap.
    # This should always be the case, but it is worth checking for weird
    # situations such as reusing an existing external mount without
    # clearing its data.
    dfds = get_all_database_directories()['data_file_directories']
    keyspaces = set(chain(*[os.listdir(dfd) for dfd in dfds]))
    hookenv.log('keyspaces={!r}'.format(keyspaces), DEBUG)
    return keyspaces - set(['system', 'system_auth', 'system_traces',
                            'dse_system'])


def nuke_local_database():
    '''Destroy the local database, entirely, so this node may bootstrap.

    This needs to be lower level than just removing selected keyspaces
    such as 'system', as commitlogs and other crumbs can also cause the
    bootstrap process to fail disasterously.
    '''
    # This function is dangerous enough to warrent a guard.
    assert not is_bootstrapped()
    assert unit_number() != 0

    keyspaces = non_system_keyspaces()
    if keyspaces:
        hookenv.log('Non-system keyspaces {!r} detected. '
                    'Unable to bootstrap.'.format(keyspaces), ERROR)
        raise SystemExit(1)

    dirs = get_all_database_directories()
    nuke_directory_contents(dirs['saved_caches_directory'])
    nuke_directory_contents(dirs['commitlog_directory'])
    for dfd in dirs['data_file_directories']:
        nuke_directory_contents(dfd)


def nuke_directory_contents(d):
    '''Remove the contents of directory d, leaving d in place.

    We don't remove the top level directory as it may be a mount
    or symlink we cannot recreate.
    '''
    for name in os.listdir(d):
        path = os.path.join(d, name)
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)


def unit_number(unit=None):
    if unit is None:
        unit = hookenv.local_unit()
    return int(unit.split('/')[-1])


def is_bootstrapped(unit=None):
    '''Return True if the node has already bootstrapped into the cluster.'''
    if unit is None:
        unit = hookenv.local_unit()
    if unit.endswith('/0'):
        return True
    relid = rollingrestart.get_peer_relation_id()
    if not relid:
        return False
    return hookenv.relation_get('bootstrapped', unit, relid) == '1'


def set_bootstrapped(flag):
    relid = rollingrestart.get_peer_relation_id()
    if bool(flag) is not is_bootstrapped():
        hookenv.log('Setting bootstrapped to {}'.format(flag))

    if flag:
        hookenv.relation_set(relid, bootstrapped="1")
    else:
        hookenv.relation_set(relid, bootstrapped=None)


def bootstrapped_peers():
    '''Return the ordered list of bootstrapped peers'''
    peer_relid = rollingrestart.get_peer_relation_id()
    return [peer for peer in rollingrestart.get_peers()
            if hookenv.relation_get('bootstrapped', peer, peer_relid) == '1']


def unbootstrapped_peers():
    '''Return the ordered list of unbootstrapped peers'''
    peer_relid = rollingrestart.get_peer_relation_id()
    return [peer for peer in rollingrestart.get_peers()
            if hookenv.relation_get('bootstrapped', peer, peer_relid) != '1']


@logged
def pre_bootstrap():
    """If we are about to bootstrap a node, prepare.

    Only the first node in the cluster is not bootstrapped. All other
    nodes added to the cluster need to bootstrap. To bootstrap, the local
    node needs to be shutdown, the database needs to be completely reset,
    and the node restarted with a valid seed_node.

    Until juju gains the necessary features, the best we can do is assume
    that Unit 0 should be the initial seed node. If the service has been
    running for some time and never had a second unit added, it is almost
    certain that it is Unit 0 that contains data we want to keep. This
    assumption is false if you have removed the only unit in the service
    at some point, so don't do that.
    """
    if is_bootstrapped():
        hookenv.log("Already bootstrapped")
        return

    if num_peers() == 0:
        hookenv.log("No peers, no cluster, no bootstrapping")
        return

    if not seed_ips():
        hookenv.log("No seeds available. Deferring.")
        raise rollingrestart.DeferRestart()

    # Don't attempt to bootstrap until all lower numbered units have
    # bootstrapped. We need to do this as the rollingrestart algorithm
    # fails during initial cluster setup, where two or more newly joined
    # units may restart (and bootstrap) at the same time and exceed
    # Cassandra's limits on the number of nodes that may bootstrap
    # simultaneously.
    for peer in unbootstrapped_peers():
        if unit_number(peer) < unit_number():
            hookenv.log("{} is not bootstrapped. Deferring.".format(peer))
            raise rollingrestart.DeferRestart()

    # Don't attempt to bootstrap until all bootstrapped peers have
    # authorized us.
    peer_relname = rollingrestart.get_peer_relation_name()
    peer_relid = rollingrestart.get_peer_relation_id()
    authed_ips = unison.collect_authed_hosts(peer_relname)
    for peer in bootstrapped_peers():
        peer_ip = hookenv.relation_get('private-address', peer, peer_relid)
        if peer_ip not in authed_ips:
            hookenv.log("{} has not authorized us. Deferring.".format(peer))
            raise rollingrestart.DeferRestart()

    # Bootstrap fail if we haven't yet opened our ports to all
    # the bootstrapped nodes. This is the case if we have not yet
    # joined the peer relationship with the node's unit.
    missing = node_ips() - peer_ips() - set([hookenv.unit_private_ip()])
    if missing:
        hookenv.log("Not yet in a peer relationship with {!r}. "
                    "Deferring bootstrap".format(missing))
        raise rollingrestart.DeferRestart()

    # Bootstrap will fail if all the nodes that contain data that needs
    # to move to the new node are down. If you are storing data in
    # rf==1, bootstrap can fail if a single node is not contactable. As
    # far as this charm is concerned, we should not attempt bootstrap
    # until all the nodes in the cluster and contactable. This also
    # ensures that peers have run their relation-changed hook and
    # opened their firewall ports to the new unit.
    if not are_all_nodes_responding():
        raise rollingrestart.DeferRestart()

    hookenv.log('Joining cluster and need to bootstrap.')

    nuke_local_database()


@logged
def post_bootstrap():
    '''Maintain state on if the node has bootstrapped into the cluster.

    Per documented procedure for adding new units to a cluster, wait 2
    minutes if the unit has just bootstrapped to ensure no other.
    '''
    if num_peers() == 0:
        # There is no cluster (just us), so we are not bootstrapped into
        # the cluster.
        return

    if not is_bootstrapped():
        for _ in backoff('bootstrap to finish'):
            if not is_cassandra_running():
                hookenv.log('Bootstrap failed. Retrying')
                start_cassandra()
                break
            if is_all_normal():
                hookenv.log('Cluster settled after bootstrap.')
                config = hookenv.config()
                hookenv.log('Waiting {}s.'.format(
                    config['post_bootstrap_delay']))
                time.sleep(config['post_bootstrap_delay'])
                if is_cassandra_running():
                    set_bootstrapped(True)
                    break


def is_schema_agreed():
    '''Return True if all the nodes that are up agree on a schema.'''
    up_ips = set(up_node_ips())
    # Always include ourself since we may be joining just now.
    up_ips.add(hookenv.unit_private_ip())
    raw = nodetool('describecluster')
    # The output of nodetool describe cluster is almost yaml,
    # so we use that tool once we fix the tabs.
    description = yaml.load(raw.expandtabs())
    versions = description['Cluster Information']['Schema versions'] or {}

    for schema, schema_ips in versions.items():
        schema_ips = set(schema_ips)
        if up_ips.issubset(schema_ips):
            hookenv.log('{!r} agree on schema'.format(up_ips), DEBUG)
            return True
    hookenv.log('{!r} do not agree on schema'.format(up_ips), DEBUG)
    return False


@logged
def wait_for_agreed_schema():
    for _ in backoff('schema agreement'):
        if is_schema_agreed():
            return


def peer_ips():
    ips = set()
    relid = rollingrestart.get_peer_relation_id()
    if relid is not None:
        for unit in hookenv.related_units(relid):
            ip = hookenv.relation_get('private-address', unit, relid)
            ips.add(ip)
    return ips


def is_all_normal(timeout=120):
    '''All nodes in the cluster report status Normal.

    Returns false if a node is joining, leaving or moving in the ring.
    '''
    is_all_normal = True
    try:
        raw = nodetool('status', 'system_auth', timeout=timeout)
    except subprocess.TimeoutExpired:
        return False
    node_status_re = re.compile('^(.)([NLJM])\s+([\d\.]+)\s')
    for line in raw.splitlines():
        match = node_status_re.search(line)
        if match is not None:
            updown, mode, address = match.groups()
            if updown == 'D':
                # 'Down' is unfortunately just informative. During service
                # teardown, nodes will disappear without decommissioning
                # leaving these entries.
                if address == hookenv.unit_private_ip():
                    is_all_normal = False
                    hookenv.log('Node {} (this node) is down'.format(address))
                else:
                    hookenv.log('Node {} is down'.format(address))
            elif updown == '?':  # CASSANDRA-8791
                is_all_normal = False
                hookenv.log('Node {} is transitioning'.format(address))

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
    for _ in backoff('cluster operators to complete'):
        if is_all_normal():
            return


def is_decommissioned():
    if not is_cassandra_running():
        return False  # Decommissioned nodes are not shut down.

    for _ in backoff('stable node mode'):
        raw = nodetool('netstats')
        if 'Mode: DECOMMISSIONED' in raw:
            hookenv.log('This node is DECOMMISSIONED', WARNING)
            return True
        elif 'Mode: NORMAL' in raw:
            return False


@logged
def emit_describe_cluster():
    '''Run nodetool describecluster for the logs.'''
    nodetool('describecluster')  # Implicit emit


@logged
def emit_auth_keyspace_status():
    '''Run 'nodetool status system_auth' for the logs.'''
    nodetool('status', 'system_auth')  # Implicit emit


@logged
def emit_netstats():
    '''Run 'nodetool netstats' for the logs.'''
    nodetool('netstats')  # Implicit emit


def emit_cluster_info():
    emit_describe_cluster()
    emit_auth_keyspace_status()
    emit_netstats()


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
    sched = timedelta(minutes=int(minutes_in_day * vdc(unit_num // 7)))
    sched_hour = sched.seconds // (60 * 60)
    sched_minute = sched.seconds // 60 - sched_hour * 60
    return (sched_dow, sched_hour, sched_minute)


# FOR CHARMHELPERS. This should be a constant in nrpe.py
def local_plugins_dir():
    return '/usr/local/lib/nagios/plugins'
