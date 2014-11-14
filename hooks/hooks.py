#!/usr/bin/python

from contextlib import contextmanager
import errno
import glob
import os.path
import shutil
import subprocess

from charmhelpers import fetch
from charmhelpers.core import hookenv, host
from charmhelpers.core.hookenv import log, DEBUG
from charmhelpers.core.helpers import RelationContext
from charmhelpers.core.services import ServiceManager


def preinstall(servicename):
    '''Preinstallation hook'''
    # Only run the preinstall hooks from the actual install hook.
    if hookenv.hook_name() == 'install':
        log('Preexec', DEBUG)
        # Pre-exec
        for f in glob.glob('exec.d/*/charm-pre-install'):
            if os.path.isfile(f) and os.access(f, os.X_OK):
                log('Running {}'.format(f))
                subprocess.check_call(['sh', '-c', f])


def swapoff(servicename):
    '''Turn off swapping on the system'''
    try:
        subprocess.check_call(['swapoff', '-a'])
    except Exception as e:
        hookenv.log("Got an error trying to turn off swapping. {}. "
                    "We may be in an LXC. Exiting gracefully"
                    "".format(e), "WARN")


def reset_sysctl(servicename):
    '''Configure sysctl settings for Cassandra'''
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
            raise e


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


def get_seeds():
    '''Return a list of seed nodes'''

    config_dict = hookenv.config()

    if config_dict['force-seed-nodes']:
        return config_dict['force-seed-nodes'].split(',')

    seeds = []
    for peer in hookenv.relations_of_type(reltype="cluster"):
        seeds.append(peer['private-address'])

    seeds.append(hookenv.unit_private_ip())
    return seeds


def install(servicename):
    packages = ['cassandra', 'cassandra-tools']
    if hookenv.config('extra_packages'):
        packages.extend(hookenv.config('extra_packages').split())
    with autostart_disabled():
        fetch.apt_install(packages, fatal=True)


def configure(servicename):
    config = hookenv.config()

    cassandra_yaml_path = '/etc/cassandra/cassandra.yaml'

    # Create a backup of the original cassandra.yaml, as its comments
    # may be useful.
    if not os.path.exists(cassandra_yaml_path + '.orig'):
        host.write_file(cassandra_yaml_path + '.orig'),
                        open('/etc/cassandra/cassandra.yaml', 'rb').read())
    cassandra_yaml = yaml.safe_load(open(cassandra_yaml_path, 'rb'))

    cassandra_yaml['cluster_name'] = (config['cluster_name']
                                      or hookenv.service_name())

    seeds = ','.join(get_seeds())
    cassandra_yaml['seed_provider'][0]['parameters'][0]['seeds'] = seeds

    cassandra_yaml['num_tokens'] = int(config['num-tokens'])

    cassandra_yaml['listen_address'] = hookenv.unit_private_ip()

    cassandra_yaml['native_transport_port'] = 9042
    cassandra_yaml['rpc_port'] = 9160  # Thrift

    host.write_file(cassandra_yaml_path, yaml.safe_dump(cassandra_yaml))


class DatabaseRelation(services.helpers.RelationContext):
    name = 'database'
    interface = 'cassandra'
    def provide_data(self):
        return dict(port=9160, thrift_port=9160, native_port=9042)


class JmxRelation(services.helpers.RelationContext):
    name = 'jmx'
    interface = 'cassandra'
    def provide_data(self):
        return dict(port=7199)


SERVICE_DEFINITIONS = [
    dict(service='cassandra',
         ports=[
             7000,  # Cluster communication
             7001,  # SSL cluster communication
             9160,  # Thrift clients
             9042,  # Native protocol clients
             7199,  # JMX.
         ],
         data_ready=[
             preinstall,
             fetch.configure_sources,
             swapoff,
             reset_sysctl,
             install,
             ensure_package_status,
             configure,
         ],
         provided_data=[
             DatabaseRelation(),
             JmxRelation()
         ])
]


@contextmanager
def autostart_disabled():
    try:
        policy_rc = os.path.join("/", "usr", "sbin", "policy-rc.d")
        if os.path.exists(policy_rc):
            shutil.move(policy_rc, "{}-orig".format(policy_rc))
        shutil.copyfile(os.path.join(hookenv.charm_dir(),
                                     "files", "policy-rc.d"), policy_rc)
        os.chmod(policy_rc, 0555)
        yield
    finally:
        if os.path.exists("{}-orig".format(policy_rc)):
            shutil.move("{}-orig".format(policy_rc), policy_rc)
        else:
            os.unlink(policy_rc)


if __name__ == '__main__':
    service_manager = ServiceManager(SERVICE_DEFINITIONS)
    service_manager.manage()
