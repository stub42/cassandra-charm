from contextlib import contextmanager
import errno
import os.path
import re
import shutil
import subprocess
import time

from charmhelpers.core import hookenv, host
from charmhelpers.core.hookenv import DEBUG, ERROR, WARNING
from charmhelpers import fetch

import relations


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


def get_seeds():
    '''Return a list of seed nodes.

    This is the list of private IPs for all units in the service,
    unless overridden by the force_seed_nodes configuration item.'''

    config_dict = hookenv.config()

    if config_dict['force_seed_nodes']:
        return config_dict['force_seed_nodes'].split(',')

    seeds = []
    for peer in hookenv.relations_of_type(reltype="cluster"):
        seeds.append(peer['private-address'])

    seeds.append(hookenv.unit_private_ip())
    seeds.sort()
    return seeds


def get_database_directory(config_path):
    """Convert a database path from the service config to an absolute path.

    Entries in the config file may be absolute, relative to
    /var/lib/cassandra, or relative to the mountpoint.
    """
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


ORACLE_JVM_ACCEPT_KEY = 'oracle_jvm_license_accepted'  # hookenv.config() key.


def accept_oracle_jvm_license():
    config = hookenv.config()
    if config.get(ORACLE_JVM_ACCEPT_KEY) is None:
        config[ORACLE_JVM_ACCEPT_KEY] = False
    if config[ORACLE_JVM_ACCEPT_KEY] is True:
        return
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
    config = hookenv.config()

    edition = get_cassandra_edition()
    if edition == 'dse':
        packages = set(['dse-full'])
    else:
        packages = set(['cassandra', 'cassandra-tools'])

    packages.add('ntp')

    jvm = get_jvm()
    if jvm == 'oracle':
        accept_oracle_jvm_license()
        if config[ORACLE_JVM_ACCEPT_KEY]:
            packages.add('oracle-java7-installer')
            packages.add('oracle-java7-set-default')
    else:
        # Packages pull in OpenJDK, or use what is already installed.
        # Should this explitly ensure OpenJDK 1.7?
        pass

    return packages


def stop_cassandra():
    if is_cassandra_running():
        host.service_stop(get_cassandra_service())


def start_cassandra():
    if is_cassandra_running():
        return

    host.service_start(get_cassandra_service())

    # Wait for Cassandra to actually start, or abort.
    timeout = time.time() + 300
    while time.time() < timeout:
        if is_cassandra_running():
            return
        time.sleep(1)
    hookenv.log('Cassandra failed to start.', ERROR)
    raise SystemExit(1)


def restart_and_remount_cassandra():
    storage = relations.StorageRelation()
    stop_cassandra()
    assert not is_cassandra_running()
    if storage.needs_remount():
        if storage.mountpoint is None:
            hookenv.log('External storage AND DATA gone.'
                        'Reverting to original local storage. '
                        'Data may be resurrected.', WARNING)
        else:
            storage.migrate('/var/lib/cassandra', 'cassandra')
            root = os.path.join(storage.mountpoint, 'cassandra')
            os.chmod(root, 0o750)
    db_dirs = get_all_database_directories()
    unpacked_db_dirs = (db_dirs['data_file_directories']
                        + [db_dirs['commitlog_directory']]
                        + [db_dirs['saved_caches_directory']])
    for db_dir in unpacked_db_dirs:
        ensure_database_directory(db_dir)
    start_cassandra()


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
            hookenv.log("Cassandra PID {} is running".format(pid))

            if subprocess.call(["nodetool", "-h",
                                hookenv.unit_private_ip(), "info"],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL) == 0:
                hookenv.log("Cassandra is responding")
                return True
            else:
                hookenv.log("Cassandra is still not fully up at attempt {}"
                            "".format(i), WARNING)
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


def reset_all_io_schedulers():
    dirs = get_all_database_directories()
    dirs = (dirs['data_file_directories'] + [dirs['commitlog_directory']]
            + [dirs['saved_caches_directory']])
    config = hookenv.config()
    for d in dirs:
        if os.path.isdir(d):  # Directory may not exist yet.
            set_io_scheduler(config['io_scheduler'], d)


def remount():
    return
#     assert not is_cassandra_running()
#
#     config = hookenv.config()
#
#     old_dirs = get_all_database_directories(config.get('live_mountpoint'))
#
#     dirs = get_all_database_directories()
#     for d in dirs['data_file_directories']:
#         ensure_database_directory(d)
#     ensure_database_directory(dirs['commitlog_directory'])
#     ensure_database_directory(dirs['saved_caches_directory'])
#     reset_all_io_schedulers()
#
#     migrated_directories = set()
#     pass
