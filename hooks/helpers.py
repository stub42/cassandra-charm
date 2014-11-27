from contextlib import contextmanager
import errno
import os.path
import re
import shutil
import subprocess

from charmhelpers.core import hookenv, host
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
                            'WARN')
            elif e.errno == errno.ENOENT:
                hookenv.log("Got no such file or directory trying to "
                            "set the IO scheduler at {}. It may be "
                            "this is an LXC, the device name is as "
                            "yet unknown to the charm, or LVM/RAID is "
                            "hiding the underlying device name. "
                            "Exiting gracefully".format(sys_file),
                            'WARN')
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


# FOR CHARMHELPERS
def get_package_version(package):
    cache = fetch.apt_cache()
    if package not in cache:
        return None
    pkgver = cache[package].current_ver
    if pkgver is not None:
        return pkgver.ver_str
    return None


@hookenv.cached
def get_cassandra_version():
    version_string = get_package_version('cassandra')
    # if pkgver is None and hookenv.config('dse'):
    #     return "2.1"
    return version_string
