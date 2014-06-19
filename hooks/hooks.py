#!/usr/bin/python

import sys
import os
import os.path
import shutil
import socket
import glob
import subprocess
import shutil
import time
import re
import apt_pkg

import _pythonpath
_ = _pythonpath

from charmhelpers.contrib.templating.pyformat import render
from charmhelpers import fetch

from charmhelpers.core import hookenv, host
from charmhelpers.contrib.charmsupport import nrpe

from charmhelpers.payload.archive import extract

hooks = hookenv.Hooks()

# XXX juju logging
# XXX cron mantenance
# XXX io-scheduler
# XXX volume management
# XXX Units to update


def Template(*args, **kw):
    """jinja2.Template with deferred jinja2 import.

    jinja2 may not be importable until the install hook has installed the
    required packages.
    """
    from jinja2 import Template
    return Template(*args, **kw)


def get_cassandra_version():
    apt_pkg.init()
    cache = apt_pkg.Cache()
    pkgver=cache['cassandra'].current_ver
    if pkgver is None and hookenv.config('dse'):
        version_string = "2.0"
    else:
        version_string = pkgver.ver_str
    return version_string



def disable_cassandra_start():
    policy_rc = os.path.join("/", "usr", "sbin", "policy-rc.d")
    if os.path.exists(policy_rc):
        shutil.move(policy_rc, "{}-orig".format(poiicy_rc))

    shutil.copyfile(os.path.join(hookenv.charm_dir(), "files", "policy-rc.d"),
                    policy_rc)
    os.chmod(policy_rc, 0555)


def enable_cassandra_start():
    policy_rc = os.path.join("/", "usr", "sbin", "policy-rc.d")
    if os.path.exists("{}-orig".format(policy_rc)):
        shutil.move("{}-orig".format(poiicy_rc), policy_rc)
    else:
        os.unlink(policy_rc)


def get_cassandra_config_dir():
    if hookenv.config('dse'):
        return '/etc/dse/cassandra/'
    else: 
        return '/etc/cassandra/'


def get_cassandra_yaml_file():
    return os.path.join(get_cassandra_config_dir(), "cassandra.yaml")


def get_cassandra_env_file():
    return os.path.join(get_cassandra_config_dir(), "cassandra-env.sh")


def get_cassandra_rackdc_file():
    return os.path.join(get_cassandra_config_dir(), "cassandra-rackdc.properties")


def get_seeds():
    ''' Return a list of seed nodes'''
    # XXX Do we *need* leader election,
    # "bootstrapping", etc

    config_dict = hookenv.config()

    if config_dict['force-seed-nodes']:
        return config_dict['force-seed-nodes'].split(',')

    if config_dict['allow-single-node']:
        return [hookenv.unit_private_ip()]

    seeds = []
    for peer in hookenv.relations_of_type(reltype="cluster"):
       seeds.append(peer['private-address'])

    seeds.append(hookenv.unit_private_ip())
    return seeds


def cassandra_is_running():
    if hookenv.config('dse'):
        pid_file = "/var/run/dse/dse.pid"
    elif apt_pkg.version_compare(get_cassandra_version(), "2.0") >= 0:
        pid_file = "/var/run/cassandra/cassandra.pid"
    else:
        pid_file = "/var/run/cassandra.pid"

    # XXX Too simplistic and racey
    if not os.path.exists(pid_file):
        hookenv.log("Cassandra is stopped", 'INFO')
        return False
    else:
        f=open (pid_file,"r")
        for line in f:
            pid = int(line.strip())
        if not pid > 1:
            raise RuntimeError("Cassandra pid is less than or equal to 1. Aborting")
        try:
            # This does not kill the process but checks for its existence
            os.kill(pid, 0)
            hookenv.log("Cassandra PID {} is running".format(pid), 'INFO')
        except OSError:
            raise RuntimeError("Cassandra PID file exists but PID {} is not running. Please manually check on the state of Cassandra".format(pid) )
        # Wait for full up state with binary backoff
        # up to 256 seconds
        for i in range(9):
            try:
                # This does not kill the process but checks for its existence
                os.kill(pid, 0)
                hookenv.log("Cassandra PID {} is still running".format(pid), 'INFO')
            except OSError:
                raise RuntimeError("Cassandra PID {} is no longer running. Please manually check on the state of Cassandra".format(pid) )
            try:
                subprocess.check_call(["nodetool", "-h", hookenv.unit_private_ip(), "info"], stderr=open(os.devnull, 'wb'))
                hookenv.log("Cassandra is running", 'INFO')
                return True
            except:
                hookenv.log("Cassandra is still not fully up at attempt {}".format(i), 'INFO')
                time.sleep(2**i)
        raise RuntimeError("Cassandra PID {} is running but not responding to nodetool. Please manually check on the state of Cassandra".format(pid) )


def stop_cassandra():
    if hookenv.config('dse'):
        cassandra = "/etc/init.d/dse"
    else:
        cassandra = "/etc/init.d/cassandra"

    hookenv.log("Stopping Cassandra", 'INFO')
    subprocess.check_call([cassandra, "stop"])

    # XXX wait time for cassandra to process
    if cassandra_is_running():
        raise RuntimeError("Cassandra failed to stop")
    

def start_cassandra():
    if hookenv.config('dse'):
        cassandra = "/etc/init.d/dse"
    else:
        cassandra = "/etc/init.d/cassandra"

    hookenv.log("Starting Cassandra", 'INFO')
    subprocess.check_call([cassandra, "start"])

    if not cassandra_is_running():
        raise RuntimeError("Cassandra failed to start")


def restart_cassandra():
    # XXX Peer aware restarts
    hookenv.log("Restarting Cassandra", 'INFO')
    stop_cassandra()
    start_cassandra()


def cassandra_restart_needed(options):

    config_dict = hookenv.config()
    restart = False
    for option in options:
        if config_dict.changed(option):
            hookenv.log("Config option {} has changed from {} to {}. "
                        "Cassandra needs to restart"
                        "".format(option, config_dict.previous(option),
                                  config_dict.get(option)))
            restart = True
    return restart


def cassandra_yaml_template():
    '''
    Configure the cassandra.yaml file. Return restart value.
    True: Cassandra needs to restart False: Cassandra does not need to restart.
    '''

    config_dict = hookenv.config()

    # XXX Add num_tokens vs initial token check
    # XXX Handle initial tokens if needed
    # XXX DSE vs cassandra and different versions
    # i.e. exception=Cannot create property=commit_failure_policy 

    # If any of these options change Cassandra must be restarted
    # config.yaml options
    options = [ 'cluster-name', 'cluster-port', 'client-port', 'partitioner',
                'endpoint_snitch', 'dse', 'authenticator', 'authorizer',
                'data_file_directories', 'commitlog_directory',
                'saved_caches_directory', 'num-tokens', 'allow-single-node',
                'force-seed-nodes', 'token-map-by-unitname',
                'token-map-by-volid', 'volume-ephemeral-storage', 'volume-map',
                'volume-dev-regexp', 'compaction-throughput',
                'stream-throughput', 'use-simpleauth', 'auth-passwd64',
                'auth-access64', 'commit_failure_policy',
                'tombstone_warn_threshold', 'tombstone_failure_threshold',
                'batch_size_warn_threshold_in_kb',
                'cas_contention_timeout_in_ms', 'preheat_kernel_page_cache']

    # Additional options
    options = options + ['private_address', 'seeds']

    # This bit of insanity sends the full dictionary as a dict member
    # to overcome the use of VAR-NAME rather than VAR_NAME in
    # config.yaml
    config = {}
    for key, value in config_dict.iteritems():
        config[key] = value
    config['config'] = config

    template_file = "{}/templates/cassandra.yaml.tmpl".format(hookenv.charm_dir())
    contents = Template(open(template_file).read()).render(config)
    host.write_file(get_cassandra_yaml_file(), contents )

    return cassandra_restart_needed(options)


def cassandra_env_template():
    '''
    Configure the cassandra-env.sh file. Return restart value.
    True: Cassandra needs to restart False: Cassandra does not need to restart.
    '''

    config_dict = hookenv.config()

    # If any of these options change Cassandra must be restarted
    options = [ 'auto-memory', 'heap-size', 'new-gen-size', 'jmx-port',
                'extra-jvm-opts']
    # XXX Handle simple auth for 1.0.x
    # -Dpasswd.properties=${CASSANDRA_PASSWD}
    # -Daccess.properties=${CASSANDRA_ACCESS}

    # This bit of insanity sends the full dictionary as a dict member
    # to overcome the use of VAR-NAME rather than VAR_NAME in
    # config.yaml
    config = {}
    for key, value in config_dict.iteritems():
        config[key] = value
    config['config'] = config

    template_file = "{}/templates/cassandra-env.tmpl".format(hookenv.charm_dir())
    contents = Template(open(template_file).read()).render(config)
    host.write_file(get_cassandra_env_file(), contents )

    return cassandra_restart_needed(options)


def cassandra_rackdc_template():
    '''
    Configure the cassandra-rackdc.properties file. Return restart value.
    True: Cassandra needs to restart False: Cassandra does not need to restart.
    '''

    config_dict = hookenv.config()

    # If any of these options change Cassandra must be restarted
    options = [ 'prefer_local', 'dc_suffix', 'datacenter', 'rack' ]

    template_file = "{}/templates/cassandra-rackdc.tmpl".format(hookenv.charm_dir())
    contents = Template(open(template_file).read()).render(config_dict)
    host.write_file(get_cassandra_rackdc_file(), contents )

    return cassandra_restart_needed(options)


@hooks.hook('nrpe-external-master-relation-joined',
            'nrpe-external-master-relation-changed')
def nrpe_external_master_relation():
    ''' Configure the nrpe-external-master relation '''

    local_plugins = os.path.join("/", "usr", "local", "lib", "nagios", "plugins")
    if os.path.exists(local_plugins):
        shutil.copyfile(os.path.join(hookenv.charm_dir(), "files", "check_cassandra_heap.sh"),
                        os.path.join(local_plugins, "check_cassandra_heap.sh")
                       )
        os.chmod(os.path.join(local_plugins, "check_cassandra_heap.sh"), 0555)

    nrpe_compat = nrpe.NRPE()
    conf = nrpe_compat.config

    cassandra_heap_warn = conf.get('nagios_heapchk_warn_pct')
    cassandra_heap_crit = conf.get('nagios_heapchk_crit_pct')
    if cassandra_heap_warn and cassandra_heap_crit:
        nrpe_compat.add_check(
            shortname="cassandra_heap",
            description="Check Cassandra Heap",
            check_cmd="check_cassandra_heap.sh {} {} {}".format(hookenv.unit_private_ip(),
                                                                 cassandra_heap_warn,
                                                                 cassandra_heap_crit)
        )

    cassandra_disk_warn = conf.get('nagios_disk_warn_pct')
    cassandra_disk_crit = conf.get('nagios_disk_crit_pct')
    for disk in conf.get('data_file_directories'):
        check_name = re.sub('/', '_', disk)
        if cassandra_disk_warn and cassandra_disk_crit:
            nrpe_compat.add_check(
                shortname="cassandra_disk{}".format(check_name),
                description="Check Cassandra Disk {}".format(disk),
                check_cmd="check_disk -u GB -w {}% -c {}% -K 5% -p {}".format(
                                                                    cassandra_disk_warn,
                                                                    cassandra_disk_crit,
                                                                    disk)
            )

    nrpe_compat.write()


def install_dse():
    java_jna_jar = os.path.join("/", "usr", "share", "java", "jna.jar")
    
    # Install prerequisites
    packages = ['default-jre-headless', 'libcommons-daemon-java', 'libjna-java',
                'python-support']
    fetch.apt_install(packages, fatal=True)

    # Setup Oracle Java
    # XXX Install from package?
    if hookenv.config('private_jre_url'):
        source = fetch.install_remote(hookenv.config('private_jre_url'))
        shutil.move(" ".join(glob.glob(os.path.join(source, "*"))),
                    os.path.join("/", "usr", "lib", "jvm", "oracle-jre"))

        subprocess.check_call(["update-alternatives", "--install", "/usr/bin/java",
                               "java", "/usr/lib/jvm/oracle-jre/bin/java", "1"])
        subprocess.check_call(["update-alternatives", "--set", "java",
                               "/usr/lib/jvm/oracle-jre/bin/java"])

    # Use modern JNA
    if hookenv.config('private_jna_url'):
        source = fetch.install_remote(hookenv.config('private_jna_url'))
        shutil.move(os.path.join(source, "jna"), os.path.join("/", "usr", "share", "java"))
        subprocess.check_call(["rm", "-f", java_jna_jar])
        host.symlink(os.path.join("/", "usr", "share", "java", "jna", "dist", "jna.jar"), java_jna_jar)

    # Install DSE
    if hookenv.config('private_dse_url'):
        # DSE deb install is not amenable to upgrade
        if hookenv.hook_name() == "install":
            source = fetch.install_remote(hookenv.config('private_dse_url'))
            cmd = ['dpkg', "--install" ] + glob.glob(os.path.join(source, "dse", "*"))
            subprocess.check_call(cmd)
    else:
        # XXX package hold
        packages = ['dse-full']
        fetch.apt_install(packages, fatal=True)


@hooks.hook('install', 'upgrade-charm')
def install():
    # Pre-exec
    for f in glob.glob('exec.d/*/charm-pre-install'):
        if os.path.isfile(f) and os.access(f, os.X_OK):
            subprocess.check_call(['sh', '-c', f])

    packages = ['python-jinja2']
    fetch.apt_install(packages, fatal=True)
    
    if hookenv.config('apt-repo-spec'):
        fetch.add_source(hookenv.config('apt-repo-spec'),key=hookenv.config('apt-repo-key'))

    fetch.apt_update(fatal=True)

    if hookenv.config('extra_packages'):
        packages = [hookenv.config('extra_packages')]
        fetch.apt_install(packages, fatal=True)

    if hookenv.config('dse'):
        install_dse() 
    else:
        # The Cassandra package starts Cassandra with default options
        # which may conflict with the soon to be configured options.
        # So stop Cassandra from starting on package install
        disable_cassandra_start()
        packages = ['cassandra']
        # XXX package hold
        fetch.apt_install(packages, fatal=True)
        enable_cassandra_start()


@hooks.hook('config-changed',
            'cluster-relation-joined',
            'cluster-relation-departed')
def config_changed():

    config_dict = hookenv.config()

    if apt_pkg.version_compare(get_cassandra_version(), "2.0") < 1:
        config_dict['commit_failure_policy'] = None
        config_dict['tombstone_warn_threshold'] = None
        config_dict['tombstone_failure_threshold'] = None
        config_dict['batch_size_warn_threshold_in_kb'] = None
        config_dict['cas_contention_timeout_in_ms'] = None
        config_dict['preheat_kernel_page_cache'] = None

    config_dict['private_address'] =  hookenv.unit_private_ip()
    config_dict['seeds'] = get_seeds()
    config_dict['data_file_directories'] = config_dict['data_file_directories'].split()
    config_dict.save()

    restart = False
    # This will always start with false
    # doing this for consistency
    restart = cassandra_yaml_template() or restart
    restart = cassandra_env_template() or restart
    # XXX use regex for long and short value
    if config_dict['endpoint_snitch'] == "GossipingPropertyFileSnitch":
        restart = cassandra_rackdc_template() or restart

    nrpe_external_master_relation()
    # XXX set_io_scheduler()

    # XXX restart cassandra? bash used bzr 
    # See postgresql local_state
    # if something has changed
    if restart:
        restart_cassandra()


@hooks.hook('database-relation-joined', 'database-relation-changed')
def datbase_relation():
    hookenv.log("Setup Cassandra database interface")
    hookenv.relation_set(relation_settings={"port": hookenv.config('client-port')})


@hooks.hook('jmx-relation-joined', 'jmx-relation-changed')
def jmx_relation():
    hookenv.log("Setup Cassandra JMX interface")
    hookenv.relation_set(relation_settings={"port": hookenv.config('jmx-port')})



hook_name = os.path.basename(sys.argv[0])

if __name__ == '__main__':
    hookenv.log("Running {} hook".format(hook_name),'INFO')
    hooks.execute(sys.argv)