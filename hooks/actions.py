from contextlib import closing
import errno
import glob
import os.path
import re
import shlex
import subprocess

import yaml

from charmhelpers import fetch
from charmhelpers.contrib import peerstorage
from charmhelpers.core import hookenv, host
from charmhelpers.core.fstab import Fstab
from charmhelpers.core.hookenv import WARNING

import helpers


# FOR CHARMHELPERS
def peer_echo(servicename, includes=None):
    peer_relname = helpers.get_peer_relation_name()
    required_hook = '{}-relation-changed'.format(peer_relname)
    if hookenv.hook_name() == required_hook:
        hookenv.log('peerstorage.peer_echo')
        peerstorage.peer_echo(includes)


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
        hookenv.log("In an LXC container. Not touching swap.")
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


def reset_sysctl(servicename):
    '''Configure sysctl settings for Cassandra'''
    if helpers.is_lxc():
        hookenv.log("In an LXC container. Leaving sysctl unchanged.")
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
    if hookenv.config('extra_packages'):
        packages.extend(hookenv.config('extra_packages').split())
    with helpers.autostart_disabled():
        fetch.apt_install(packages, fatal=True)


def install_cassandra_packages(servicename):
    install_packages(servicename, helpers.get_cassandra_packages())


def ensure_cassandra_package_status(servicename):
    ensure_package_status(servicename, helpers.get_cassandra_packages())


def configure_cassandra_yaml(servicename):
    cassandra_yaml_path = helpers.get_cassandra_yaml_file()
    config = hookenv.config()

    helpers.maybe_backup(cassandra_yaml_path)  # Its comments may be useful.

    with open(cassandra_yaml_path, 'rb') as f:
        cassandra_yaml = yaml.safe_load(f)

    cassandra_yaml['cluster_name'] = (config['cluster_name']
                                      or hookenv.service_name())

    seeds = ', '.join(helpers.get_seeds())
    cassandra_yaml['seed_provider'][0]['parameters'][0]['seeds'] = seeds

    cassandra_yaml['num_tokens'] = int(config['num_tokens'])

    cassandra_yaml['listen_address'] = hookenv.unit_private_ip()
    cassandra_yaml['rpc_address'] = hookenv.unit_private_ip()

    cassandra_yaml['native_transport_port'] = 9042
    cassandra_yaml['rpc_port'] = 9160  # Thrift

    cassandra_yaml.update(helpers.ensure_directories())

    cassandra_yaml['partitioner'] = (config['partitioner']
                                     or 'Murmur3Partitioner')

    host.write_file(cassandra_yaml_path,
                    yaml.safe_dump(cassandra_yaml).encode('UTF-8'))


def configure_cassandra_env(servicename):
    cassandra_env_path = helpers.get_cassandra_env_file()
    assert os.path.exists(cassandra_env_path)

    helpers.maybe_backup(cassandra_env_path)

    overrides = [
        ('max_heap_size', re.compile(r'^#?(MAX_HEAP_SIZE)=(.*)$', re.M)),
        ('heap_newsize', re.compile(r'^#?(HEAP_NEWSIZE)=(.*)$', re.M)),
    ]

    with open(cassandra_env_path, 'r') as f:
        env = f.read()

    config = hookenv.config()
    for key, regexp in overrides:
        if config[key]:
            val = shlex.quote(config[key])
            env = regexp.sub(r'\g<1>={}  # Juju service config'.format(val),
                             env)
        else:
            env = regexp.sub(r'#\1=\2  # Juju service config', env)
    host.write_file(cassandra_env_path, env.encode('UTF-8'))


def rolling_restart(servicename):
    flag = os.path.join(hookenv.charm_dir(), '.needs-restart')
    if os.path.exists(flag):
        if helpers.rolling_restart(helpers.restart_cassandra):
            os.remove(flag)
