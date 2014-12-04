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
def autostart_disabled(policy_rc='/usr/sbin/policy-rc.d'):
    '''Tell well behaved Debian packages to not start services when installed.
    '''
    try:
        if os.path.exists(policy_rc):
            shutil.move(policy_rc, "{}-orig".format(policy_rc))
        host.write_file(policy_rc, b'#!/bin/sh\nexit 101', perms=0o555)
        yield
    finally:
        os.unlink(policy_rc)
        if os.path.exists("{}-orig".format(policy_rc)):
            shutil.move("{}-orig".format(policy_rc), policy_rc)


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
    return seeds


def ensure_directories():
    """Create the directories to store the database (if necessary) and
    reset all relevant filesystem io-schedulers.

    Returns a dictionary containing the full paths to the directories,
    with the same keys as config.yaml.
    """
    bsb_rel = relations.BlockStorageBroker('data')
    assert bsb_rel.is_ready(), 'Block storage broker relation is not ready'

    config = hookenv.config()
    root = bsb_rel.mountpoint or '/var/lib/cassandra'

    def _mkdir(reldir):
        absdir = os.path.join(root, reldir)
        host.mkdir(absdir, owner='cassandra', group='cassandra', perms=0o755)
        # If this is an existing database being remounted, we need to
        # ensure ownership is correct due to uid and gid mismatches.
        recursive_chown(absdir, owner='cassandra', group='cassandra')
        set_io_scheduler(config['io_scheduler'], absdir)
        return absdir

    return dict(
        data_file_directories=[
            _mkdir(d) for d in (config['data_file_directories']
                                or 'data').split()],
        commitlog_directory=_mkdir(config['commitlog_directory']
                                   or 'commitlog'),
        saved_caches_directory=_mkdir(config['saved_caches_directory']
                                      or 'saved_caches_directory'))


#         request_cassandra_restart(just_mounted=True)


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
    '''Change ownership of all files and directories contained in 'directory'.

    Does not modify ownership of 'directory'.
    '''
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


def restart_cassandra():
    if is_cassandra_running():
        host.service_restart(get_cassandra_service())
    else:
        host.service_start(get_cassandra_service())


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
        # up to 256 seconds
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
                               stderr=subprocess.DEVNULL) == 0:
                hookenv.log("Cassandra is running")
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
            hookenv.log("Cassandra is stopped", INFO)
            return False
        # If the pid_file exists, but we got an exception, reraise it.
        # The system is insane. For example, the pid_file contains '-1'.
        raise
