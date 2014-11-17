import errno
import glob
import os.path
import subprocess

import yaml

from charmhelpers import fetch
from charmhelpers.core import hookenv, host
from charmhelpers.core.hookenv import log

import helpers


# FOR CHARMHELPERS
def preinstall(servicename):
    '''Preinstallation data_ready hook.'''
    # Only run the preinstall hooks from the actual install hook.
    if hookenv.hook_name() == 'install':
        # Pre-exec
        for f in glob.glob('exec.d/*/charm-pre-install'):
            if os.path.isfile(f) and os.access(f, os.X_OK):
                log('Running preinstall hook {}'.format(f))
                subprocess.check_call(['sh', '-c', f])
            else:
                log('Ingnoring preinstall hook {}'.format(f))
        else:
            log('No preinstall hooks found')


# FOR CHARMHELPERS
def swapoff(servicename):
    '''Turn off swapping on the system.'''
    if is_lxc():
        hookenv.log("In an LXC container. Not touching swap.")
    else:
        try:
            subprocess.check_call(['swapoff', '-a'])
        except Exception as e:
            hookenv.log("Got an error trying to turn off swapping. {}. "
                        "We may be in an LXC. Exiting gracefully"
                        "".format(e), "WARN")


# FOR CHARMHELPERS
def configure_sources(servicename):
    '''Standard charmhelpers package source configuration.'''
    config = hookenv.config()
    if config.changed('install_sources') or config.changed('install_keys'):
        fetch.configure_sources(True)


def reset_sysctl(servicename):
    '''Configure sysctl settings for Cassandra'''
    if is_lxc():
        hookenv.log("In an LXC container. Leaving sysctl unchanged.")
    else:
        cassandra_sysctl_file = os.path.join('/', 'etc', 'sysctl.d',
                                            '99-cassandra.conf')
        contents = "vm.max_map_count = 131072\n"
        try:
            host.write_file(cassandra_sysctl_file, contents)
            subprocess.check_call(['sysctl', '-p', cassandra_sysctl_file])
        except Exception as e:
            if e.errno == errno.EACCES:
                hookenv.log("Got Permission Denied trying to set the "
                            "sysctl settings at {}. We may be in an LXC. "
                            "Exiting gracefully".format(cassandra_sysctl_file),
                            "WARN")
            else:
                raise


def ensure_package_status(servicename):
    config_dict = hookenv.config()

    package_status = config_dict['package_status']
    ## if config_dict['dse']:
    ##     packages = ['dse']
    ## else:
    packages = ['cassandra', 'cassandra-tools']

    if package_status not in ['install', 'hold']:
        RuntimeError("package_status must be 'install' or 'hold' not '{}'"
                     "".format(package_status))

    for package in packages:
        selections = ''.join(['{} {}\n'.format(package, package_status)])
        dpkg = subprocess.Popen(['dpkg', '--set-selections'],
                                stdin=subprocess.PIPE)
        dpkg.communicate(input=selections)


def install(servicename):
    packages = ['cassandra', 'cassandra-tools']
    if hookenv.config('extra_packages'):
        packages.extend(hookenv.config('extra_packages').split())
    with helpers.autostart_disabled():
        fetch.apt_install(packages, fatal=True)


def configure_cassandra_yaml(servicename):
    config = hookenv.config()

    cassandra_yaml_path = '/etc/cassandra/cassandra.yaml'

    # Create a backup of the original cassandra.yaml, as its comments
    # may be useful.
    if not os.path.exists(cassandra_yaml_path + '.orig'):
        host.write_file(cassandra_yaml_path + '.orig',
                        open('/etc/cassandra/cassandra.yaml', 'rb').read())

    cassandra_yaml = yaml.safe_load(open(cassandra_yaml_path, 'rb'))

    cassandra_yaml['cluster_name'] = (config['cluster_name']
                                      or hookenv.service_name())

    seeds = ','.join(helpers.get_seeds())
    cassandra_yaml['seed_provider'][0]['parameters'][0]['seeds'] = seeds

    cassandra_yaml['num_tokens'] = int(config['num_tokens'])

    cassandra_yaml['listen_address'] = hookenv.unit_private_ip()

    cassandra_yaml['native_transport_port'] = 9042
    cassandra_yaml['rpc_port'] = 9160  # Thrift

    cassandra_yaml.update(helpers.ensure_directories())

    cassandra_yaml['partitioner'] = (config['partitioner']
                                     or 'Murmur3Partitioner')

    host.write_file(cassandra_yaml_path, yaml.safe_dump(cassandra_yaml))
