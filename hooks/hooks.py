#!/usr/bin/python

import sys
import os
import glob
import subprocess
import shutil
import time
import re
import apt_pkg
import json
import pwd
import grp

import _pythonpath
_ = _pythonpath

from charmhelpers import fetch
from charmhelpers.core import hookenv, host
from charmhelpers.contrib.charmsupport import nrpe

hooks = hookenv.Hooks()


def Template(*args, **kw):
    """jinja2.Template with deferred jinja2 import.

    jinja2 may not be importable until the install hook has installed the
    required packages.
    """
    from jinja2 import Template
    return Template(*args, **kw)


def recursive_chown(directory, user="root", group="root"):
    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(group).gr_gid

    for root, dirs, files in os.walk(directory):
        for dirname in dirs:
            os.chown(os.path.join(root, dirname), uid, gid)
        for filename in files:
            os.chown(os.path.join(root, filename), uid, gid)


def get_cassandra_version():
    apt_pkg.init()
    cache = apt_pkg.Cache()
    pkgver = cache['cassandra'].current_ver
    if pkgver is None and hookenv.config('dse'):
        version_string = "2.0"
    else:
        version_string = pkgver.ver_str
    return version_string


def disable_cassandra_start():
    policy_rc = os.path.join("/", "usr", "sbin", "policy-rc.d")
    if os.path.exists(policy_rc):
        shutil.move(policy_rc, "{}-orig".format(policy_rc))

    shutil.copyfile(os.path.join(hookenv.charm_dir(), "files", "policy-rc.d"),
                    policy_rc)
    os.chmod(policy_rc, 0555)


def enable_cassandra_start():
    policy_rc = os.path.join("/", "usr", "sbin", "policy-rc.d")
    if os.path.exists("{}-orig".format(policy_rc)):
        shutil.move("{}-orig".format(policy_rc), policy_rc)
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
    return os.path.join(get_cassandra_config_dir(),
                        "cassandra-rackdc.properties")


def get_seeds():
    ''' Return a list of seed nodes'''

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


def set_io_scheduler():
    ''' Set the block device io scheduler '''

    config_dict = hookenv.config()
    # For now force directories if using external volume
    if config_dict.get('external_volume_mount'):
        config_dict['data_file_directories'] = os.path.join(
            config_dict.get('external_volume_mount'), 'cassandra', 'data')

    # XXX The block device regex may be a tad simplistic
    block_regex = re.compile('\/dev\/([a-z]*)', re.IGNORECASE)
    lxc_regex = re.compile('\/dev\/disk\/by-label\/cloudimg-rootfs', re.IGNORECASE)

    for directory in config_dict['data_file_directories'].split(' '):
        directory = os.path.dirname(directory)
        if os.path.exists(directory):
            output = subprocess.check_output(['df', directory])
            # Make no change if we are in an LXC
            if not re.findall(lxc_regex, output):
                hookenv.log("Setting block device of {} to IO scheduler {}"
                            "".format(directory, config_dict['io-scheduler']))
                block_dev = re.findall(block_regex, output)[0]
                sys_file = os.path.join("/", "sys", "block", block_dev,
                                        "queue", "scheduler")
                host.write_file(sys_file, config_dict['io-scheduler'],
                                perms=0644)
            else:
                hookenv.log("In an LXC. Cannot set io scheduler {}"
                            "".format(config_dict['io-scheduler']))
        else:
            hookenv.log("Directory {} does not exist. Cannot set io scheduler "
                        "{}".format(config_dict['io-scheduler']))


def is_cassandra_running():
    if hookenv.config('dse'):
        pid_file = "/var/run/dse/dse.pid"
    elif apt_pkg.version_compare(get_cassandra_version(), "2.0") >= 0:
        pid_file = "/var/run/cassandra/cassandra.pid"
    else:
        pid_file = "/var/run/cassandra.pid"

    # XXX needs to wait after a stop somehow
    if not os.path.exists(pid_file):
        hookenv.log("Cassandra is stopped", 'INFO')
        return False
    else:
        f = open(pid_file, "r")
        for line in f:
            pid = int(line.strip())
        if not pid > 1:
            raise RuntimeError("Cassandra pid is less than or equal to 1. "
                               "Aborting")
        try:
            # This does not kill the process but checks for its existence
            os.kill(pid, 0)
            hookenv.log("Cassandra PID {} is running".format(pid), 'INFO')
        except OSError:
            raise RuntimeError("Cassandra PID file exists but PID {} is not "
                               "running. Please manually check on the state "
                               "of Cassandra".format(pid))
        # Wait for full up state with binary backoff
        # up to 256 seconds
        for i in range(9):
            try:
                # This does not kill the process but checks for its existence
                os.kill(pid, 0)
                hookenv.log("Cassandra PID {} is still running".format(pid))
            except OSError:
                raise RuntimeError("Cassandra PID {} is no longer running. "
                                   "Please manually check on the state of "
                                   "Cassandra".format(pid))
            try:
                subprocess.check_call(["nodetool", "-h",
                                      hookenv.unit_private_ip(), "info"],
                                      stderr=open(os.devnull, 'wb'))
                hookenv.log("Cassandra is running", 'INFO')
                return True
            except:
                hookenv.log("Cassandra is still not fully up at attempt {}"
                            "".format(i))
                time.sleep(2 ** i)
        raise RuntimeError("Cassandra PID {} is running but not responding to "
                           "nodetool. Please manually check on the state of "
                           "Cassandra".format(pid))


def stop_cassandra():
    if hookenv.config('dse'):
        cassandra = "/etc/init.d/dse"
    else:
        cassandra = "/etc/init.d/cassandra"

    hookenv.log("Stopping Cassandra", 'INFO')
    subprocess.check_call([cassandra, "stop"])

    # XXX wait time for cassandra to process
    if is_cassandra_running():
        raise RuntimeError("Cassandra failed to stop")


def start_cassandra():
    if hookenv.config('dse'):
        cassandra = "/etc/init.d/dse"
    else:
        cassandra = "/etc/init.d/cassandra"

    hookenv.log("Starting Cassandra", 'INFO')
    subprocess.check_call([cassandra, "start"])

    if not is_cassandra_running():
        raise RuntimeError("Cassandra failed to start")


def restart_cassandra():
    hookenv.log("Restarting Cassandra", 'INFO')
    stop_cassandra()
    start_cassandra()


def does_cassandra_need_to_restart(options=[None]):
    ''' Determine if Cassandra needs to restart
        Check critical options for changes
        Set config_dict['restart_needed'] True or False
        Return True or False
    '''

    config_dict = hookenv.config()
    restart = False
    # Manually read restart request
    restart_request_dict = read_restart_request()
    if restart_request_dict.get('restart_needed'):
        hookenv.log("Cassandra restart previously requested. "
                    "Cassandra needs to restart")
        restart = True
    # Run through options even if the above is true for logging
    for option in options:
        if config_dict.changed(option):
            hookenv.log("Config option {} has changed from {} to {}. "
                        "Cassandra needs to restart"
                        "".format(option, config_dict.previous(option),
                                  config_dict.get(option)))
            # Manually write restart request
            write_restart_request({'restart_needed': True})
            restart = True

    return restart


def read_restart_request():
    # Manually read previous config as hookenv.config().load_previous()
    # has a bug when changing hook contexts
    # config_dict.load_previous()
    restart_request_file = '.restart_request'
    path = os.path.join(hookenv.charm_dir(), restart_request_file)
    if os.path.exists(path):
        with open(path) as f:
            restart_request_dict = json.load(f)
        return restart_request_dict
    else:
        return {}


def write_restart_request(restart_request_dict):
    restart_request_file = '.restart_request'
    path = os.path.join(hookenv.charm_dir(), restart_request_file)
    if restart_request_dict:
        with open(path, 'w') as f:
            json.dump(restart_request_dict, f)


def request_cassandra_restart():
    ''' Make peers aware of restart request.
        Restart if mine is the oldest request '''

    config_dict = hookenv.config()
    restart_request_dict = read_restart_request()

    restart_needed = restart_request_dict.get('restart_needed')
    restart_request_time = restart_request_dict.get('restart_request_time')

    node_id = int(hookenv.local_unit().split('/')[1])
    factor = 100

    if restart_needed:
        hookenv.log("Cassandra restart is requested")

        if (config_dict.get('external_volume_mount') and not
                is_external_volume_mounted()):
            hookenv.log("Do not restart Cassandra, we are waiting on an "
                        "external volume to mount")
            return

        if config_dict['allow-single-node']:
            hookenv.log("This is the only node. Restarting.")
            restart_cassandra()
            return

        if not restart_request_time:
            restart_request_time = int(time.time() * factor)
            # Not in a relation hook. Need to set relation id
            for peer in hookenv.relations_of_type(reltype="cluster"):
                hookenv.relation_set(
                    relation_id=peer['__relid__'],
                    relation_settings={"restart_request_time":
                                       restart_request_time})
            restart_request_dict['restart_request_time'] = restart_request_time
            write_restart_request(restart_request_dict)
            hookenv.log("Setting my restart request time on the peer relation,"
                        " {}. Exiting cleanly to wait my turn."
                        "".format(restart_request_time))
            return
        else:
            restart_request_time = int(restart_request_time)
            hookenv.log("Cassandra restart request time {}"
                        "".format(restart_request_time))
    else:
        hookenv.log("Cassandra does not need a restart. Exiting cleanly")
        return

    restart_request_times = []
    for peer in hookenv.relations_of_type(reltype="cluster"):
        if peer.get('restart_request_time'):
            restart_request_times.append(peer.get('restart_request_time'))

    if len(restart_request_times) > 0:
        # Need to cast type as a int.
        # Comparing to a unicode string gives unexpected results
        oldest_request = int(sorted(restart_request_times)[0])
    else:
        oldest_request = int(9999999999999)

    if restart_request_time == oldest_request:
        hookenv.log("My restart request time equals the oldest_request time. "
                    "{} == {}. Starting over to break the deadlock"
                    "".format(restart_request_time, oldest_request))
        restart_request_time = int((time.time() + node_id) * factor)
        # Reset on on all peer relations so others don't get stuck
        # waiting on a restart that will never happen
        for peer in hookenv.relations_of_type(reltype="cluster"):
            hookenv.relation_set(
                relation_id=peer['__relid__'],
                relation_settings={"restart_request_time":
                                   restart_request_time})

        hookenv.relation_set(
            relation_settings={"restart_request_time": restart_request_time})
        restart_request_dict['restart_request_time'] = restart_request_time
        write_restart_request(restart_request_dict)
    elif restart_request_time < oldest_request:
        hookenv.log("My restart request time is the oldest, {}. Less than {}. "
                    "Out of {}.  {}. Restarting"
                    "".format(restart_request_time, oldest_request,
                              len(restart_request_times),
                              sorted(restart_request_times)))
        restart_cassandra()
        # Tell all peers restart is no longer needed
        hookenv.log("Restart complete. Informing peers.")
        for peer in hookenv.relations_of_type(reltype="cluster"):
            hookenv.relation_set(
                relation_id=peer['__relid__'],
                relation_settings={"restart_request_time": None})
        restart_request_dict['restart_needed'] = False
        restart_request_dict['restart_request_time'] = False
        write_restart_request(restart_request_dict)
    else:
        hookenv.log("My restart request time is NOT the oldest, {}. Greater "
                    "than {}. Out of {}. {} Exiting cleanly to wait my turn."
                    "".format(restart_request_time, oldest_request,
                              len(restart_request_times),
                              sorted(restart_request_times)))


def cassandra_yaml_template():
    '''
    Configure the cassandra.yaml file. Return restart value.
    True: Cassandra needs to restart False: Cassandra does not need to restart.
    '''

    config_dict = hookenv.config()

    # If any of these options change Cassandra must be restarted
    # config.yaml options
    options = ['cluster-name', 'cluster-port', 'client-port', 'partitioner',
               'endpoint_snitch', 'dse', 'authenticator', 'authorizer',
               'data_file_directories', 'commitlog_directory',
               'saved_caches_directory', 'num-tokens', 'allow-single-node',
               'force-seed-nodes', 'compaction-throughput',
               'stream-throughput', 'commit_failure_policy',
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
    config['data_file_directories'] = config['data_file_directories'].split(
        ' ')
    config['config'] = config

    template_file = os.path.join(hookenv.charm_dir(), "templates",
                                 "cassandra.yaml.tmpl")
    contents = Template(open(template_file).read()).render(config)
    host.write_file(get_cassandra_yaml_file(), contents)

    return does_cassandra_need_to_restart(options=options)


def dse_yaml_template():
    '''
    Configure the dse.yaml file. Return restart value.
    True: Cassandra needs to restart False: Cassandra does not need to restart.
    '''

    config_dict = hookenv.config()
    dse_yaml_file = os.path.join("/", "etc", "dse", "dse.yaml")

    # If any of these options change Cassandra must be restarted
    # config.yaml options
    options = ['endpoint_snitch']

    template_file = os.path.join(hookenv.charm_dir(), "templates",
                                 "dse.yaml.tmpl")
    contents = Template(open(template_file).read()).render(config_dict)
    host.write_file(dse_yaml_file, contents)

    return does_cassandra_need_to_restart(options=options)


def cassandra_env_template():
    '''
    Configure the cassandra-env.sh file. Return restart value.
    True: Cassandra needs to restart False: Cassandra does not need to restart.
    '''

    config_dict = hookenv.config()

    # If any of these options change Cassandra must be restarted
    options = ['auto-memory', 'heap-size', 'new-gen-size', 'jmx-port',
               'extra-jvm-opts']

    # This bit of insanity sends the full dictionary as a dict member
    # to overcome the use of VAR-NAME rather than VAR_NAME in
    # config.yaml
    config = {}
    for key, value in config_dict.iteritems():
        config[key] = value
    config['config'] = config

    template_file = os.path.join(hookenv.charm_dir(), "templates",
                                 "cassandra-env.tmpl")
    contents = Template(open(template_file).read()).render(config)
    host.write_file(get_cassandra_env_file(), contents)

    return does_cassandra_need_to_restart(options=options)


def cassandra_rackdc_template():
    '''
    Configure the cassandra-rackdc.properties file. Return restart value.
    True: Cassandra needs to restart False: Cassandra does not need to restart.
    '''

    config_dict = hookenv.config()

    # If any of these options change Cassandra must be restarted
    options = ['prefer_local', 'dc_suffix', 'datacenter', 'rack']

    template_file = os.path.join(hookenv.charm_dir(), "templates",
                                 "cassandra-rackdc.tmpl")
    contents = Template(open(template_file).read()).render(config_dict)
    host.write_file(get_cassandra_rackdc_file(), contents)

    return does_cassandra_need_to_restart(options=options)


def maintenance():
    '''
    Configure weekly staggered nodetool repair crons
    '''

    cron_location = os.path.join("/", "etc", "cron.d", "cassandra-maintenance")
    node_id = int(hookenv.local_unit().split('/')[1])
    repair_day = node_id % 7

    template_dict = {"repair_day": repair_day}
    template_file = os.path.join(hookenv.charm_dir(), "templates",
                                 "cassandra_maintenance_cron.tmpl")
    contents = Template(open(template_file).read()).render(template_dict)
    host.write_file(cron_location, contents)


def ensure_package_status():

    config_dict = hookenv.config()

    package_status = config_dict['package_status']
    if config_dict['dse']:
        packages = ['dse']
    else:
        packages = ['cassandra']

    if package_status not in ['install', 'hold']:
        RuntimeError("package_status must be 'install' or 'hold' not '{}'"
                     "".format(package_status))

    for package in packages:
        selections = ''.join(['{} {}\n'.format(package, package_status)])
        dpkg = subprocess.Popen(['dpkg', '--set-selections'],
                                stdin=subprocess.PIPE)
        dpkg.communicate(input=selections)


@hooks.hook('nrpe-external-master-relation-joined',
            'nrpe-external-master-relation-changed')
def nrpe_external_master_relation():
    ''' Configure the nrpe-external-master relation '''

    local_plugins = os.path.join("/", "usr", "local", "lib", "nagios",
                                 "plugins")
    if os.path.exists(local_plugins):
        shutil.copyfile(os.path.join(hookenv.charm_dir(), "files",
                                     "check_cassandra_heap.sh"),
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
            check_cmd="check_cassandra_heap.sh {} {} {}"
                      "".format(hookenv.unit_private_ip(), cassandra_heap_warn,
                                cassandra_heap_crit)
        )

    cassandra_disk_warn = conf.get('nagios_disk_warn_pct')
    cassandra_disk_crit = conf.get('nagios_disk_crit_pct')
    for disk in conf.get('data_file_directories').split(' '):
        check_name = re.sub('/', '_', disk)
        if cassandra_disk_warn and cassandra_disk_crit:
            nrpe_compat.add_check(
                shortname="cassandra_disk{}".format(check_name),
                description="Check Cassandra Disk {}".format(disk),
                check_cmd="check_disk -u GB -w {}% -c {}% -K 5% -p {}"
                          "".format(cassandra_disk_warn, cassandra_disk_crit,
                                    disk)
            )

    nrpe_compat.write()


def is_external_volume_mounted():
    ''' Check if the external volume is mounted '''

    config_dict = hookenv.config()
    related = False
    mounted = False
    regex = re.compile(config_dict.get('external_volume_mount'))

    for peer in hookenv.relations_of_type(reltype="data"):
        if hookenv.relation_get(attribute="mountpoint",
                                unit=peer['__unit__'],
                                rid=peer['__relid__']):
            related = True

    if related:
        output = subprocess.check_output(['mount'])
        mounted = re.findall(regex, output)
        if mounted:
            return True
        else:
            return False
    else:
        return False


@hooks.hook('data-relation-changed')
def data_relation_changed():
    ''' Setup external volume after confirming it is mounted '''

    if is_external_volume_mounted():
        hookenv.log("External volume is mounted")
        setup_directories()
        set_io_scheduler()
        request_cassandra_restart()
    else:
        hookenv.log("External volume is not yet mounted")


@hooks.hook('data-relation-joined')
def data_relation_joined():
    ''' Request external volume from storage subordinate by setting
        mountpoint '''

    config_dict = hookenv.config()

    if not config_dict.get('external_volume_mount'):
        raise RuntimeError("No external_volume_mount set. Aborting")

    stop_cassandra()

    hookenv.log("Setting mountpoint in the storage data relation: {}"
                "".format(config_dict.get('external_volume_mount')))
    for peer in hookenv.relations_of_type(reltype="data"):
        hookenv.relation_set(
            relation_id=peer['__relid__'],
            relation_settings={"mountpoint":
                               config_dict.get('external_volume_mount')})


def setup_directories():

    config_dict = hookenv.config()

    # For now force directories if using external volume
    if config_dict.get('external_volume_mount'):
        config_dict['data_file_directories'] = os.path.join(
            config_dict.get('external_volume_mount'), 'cassandra', 'data')
        config_dict['commitlog_directory'] = os.path.join(
            config_dict.get('external_volume_mount'), 'cassandra', 'commitlog')
        config_dict['saved_caches_directory'] = os.path.join(
            config_dict.get('external_volume_mount'),
            'cassandra', 'saved_caches')

    for directory in config_dict['data_file_directories'].split(' '):
        directory = os.path.dirname(directory)
        if os.path.exists(directory):
            recursive_chown(directory, user="cassandra", group="cassandra")
        else:
            hookenv.log("Creating cassandra data top directory {}"
                        "".format(directory))
            host.mkdir(directory, owner='cassandra', group='cassandra',
                       perms=0755, force=True)

    directory = os.path.dirname(config_dict['commitlog_directory'])
    if os.path.exists(directory):
        recursive_chown(directory, user="cassandra", group="cassandra")
    else:
        hookenv.log("Creating cassandra commitlog top directory {}"
                    "".format(directory))
        host.mkdir(directory, owner='cassandra', group='cassandra',
                   perms=0755, force=True)

    directory = os.path.dirname(config_dict['saved_caches_directory'])
    if os.path.exists(directory):
        recursive_chown(directory, user="cassandra", group="cassandra")
    else:
        hookenv.log("Creating cassandra saved_caches top directory {}"
                    "".format(directory))
        host.mkdir(directory, owner='cassandra', group='cassandra',
                   perms=0755, force=True)


def install_dse():
    java_jre_dir = os.path.join("/", "usr", "lib", "jvm", "oracle-jre")
    java_jna_dir = os.path.join("/", "usr", "share", "java", "jna")
    java_jna_jar = os.path.join("/", "usr", "share", "java", "jna.jar")

    # Install prerequisites
    packages = ['default-jre-headless', 'libcommons-daemon-java',
                'libjna-java', 'python-support']
    fetch.apt_install(packages, fatal=True)

    # Setup Oracle Java
    # XXX Install from package?
    if hookenv.config('private_jre_url'):
        source = fetch.install_remote(hookenv.config('private_jre_url'))
        if os.path.exists(java_jre_dir):
            shutil.rmtree(java_jre_dir)
        shutil.move(" ".join(glob.glob(os.path.join(source, "*"))),
                    java_jre_dir)

        subprocess.check_call(["update-alternatives", "--install",
                               "/usr/bin/java", "java",
                               "/usr/lib/jvm/oracle-jre/bin/java", "1"])
        subprocess.check_call(["update-alternatives", "--set", "java",
                               "/usr/lib/jvm/oracle-jre/bin/java"])

    # Use modern JNA
    if hookenv.config('private_jna_url'):
        source = fetch.install_remote(hookenv.config('private_jna_url'))
        if os.path.exists(java_jna_dir):
            shutil.rmtree(java_jna_dir)
        shutil.move(os.path.join(source, "jna"), java_jna_dir)
        subprocess.check_call(["rm", "-f", java_jna_jar])
        host.symlink(os.path.join(java_jna_dir,
                                  "dist", "jna.jar"),
                     java_jna_jar)

    # Install DSE
    if hookenv.config('private_dse_url'):
        # DSE deb install is not amenable to upgrade
        if hookenv.hook_name() == "install":
            source = fetch.install_remote(hookenv.config('private_dse_url'))
            cmd = ['dpkg', "--install"] + glob.glob(os.path.join(source,
                                                                 "dse",
                                                                 "*"))
            subprocess.check_call(cmd)
    else:
        packages = ['dse-full']
        fetch.apt_install(packages, fatal=True)


@hooks.hook('install', 'upgrade-charm')
def install():
    ''' Install and upgrade-charm '''

    # Pre-exec
    for f in glob.glob('exec.d/*/charm-pre-install'):
        if os.path.isfile(f) and os.access(f, os.X_OK):
            subprocess.check_call(['sh', '-c', f])

    packages = ['python-jinja2']
    fetch.apt_install(packages, fatal=True)

    if hookenv.config('apt-repo-spec'):
        fetch.add_source(hookenv.config('apt-repo-spec'),
                         key=hookenv.config('apt-repo-key'))

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

    # For now force directories if using external volume
    if config_dict.get('external_volume_mount'):
        config_dict['data_file_directories'] = os.path.join(
            config_dict.get('external_volume_mount'), 'cassandra', 'data')
        config_dict['commitlog_directory'] = os.path.join(
            config_dict.get('external_volume_mount'), 'cassandra', 'commitlog')
        config_dict['saved_caches_directory'] = os.path.join(
            config_dict.get('external_volume_mount'),
            'cassandra', 'saved_caches')

    config_dict['private_address'] = hookenv.unit_private_ip()
    config_dict['seeds'] = get_seeds()
    config_dict.save()

    cassandra_yaml_template()
    cassandra_env_template()
    if hookenv.config('dse'):
        dse_yaml_template()
    if (config_dict['endpoint_snitch'] == "GossipingPropertyFileSnitch" or
        config_dict['endpoint_snitch'] == "org.apache.cassandra.locator."
                                          "GossipingPropertyFileSnitch"):
        cassandra_rackdc_template()

    nrpe_external_master_relation()
    maintenance()
    ensure_package_status()

    # Handle use of an external volume
    if (not config_dict.get('external_volume_mount') or
            is_external_volume_mounted()):
        setup_directories()
        set_io_scheduler()

    # Manually read restart request
    restart_request_dict = read_restart_request()
    if restart_request_dict.get('restart_needed'):
        request_cassandra_restart()


@hooks.hook('cluster-relation-changed')
def cluster_relation():
    # XXX Leader election
    request_cassandra_restart()


@hooks.hook('database-relation-joined', 'database-relation-changed')
def datbase_relation():
    hookenv.log("Setup Cassandra database interface")
    hookenv.relation_set(
        relation_settings={"port": hookenv.config('client-port')})


@hooks.hook('jmx-relation-joined', 'jmx-relation-changed')
def jmx_relation():
    hookenv.log("Setup Cassandra JMX interface")
    hookenv.relation_set(
        relation_settings={"port": hookenv.config('jmx-port')})


hook_name = os.path.basename(sys.argv[0])

if __name__ == '__main__':
    hookenv.log("Running {} hook".format(hook_name))
    hooks.execute(sys.argv)
