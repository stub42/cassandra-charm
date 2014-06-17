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

import _pythonpath
_ = _pythonpath

from charmhelpers.contrib.templating.pyformat import render
from charmhelpers import fetch

from charmhelpers.core import hookenv, host
from charmhelpers.contrib.charmsupport import nrpe

from charmhelpers.payload.archive import extract

hooks = hookenv.Hooks()

# XXX juju logging


def Template(*args, **kw):
    """jinja2.Template with deferred jinja2 import.

    jinja2 may not be importable until the install hook has installed the
    required packages.
    """
    from jinja2 import Template
    return Template(*args, **kw)


def _get_cassandra_config_dir():
    if hookenv.config('dse'):
        return '/etc/dse/cassandra/'
    else: 
        return '/etc/cassandra/'


def _get_cassandra_yaml_file():
    return os.path.join(_get_cassandra_config_dir(), "cassandra.yaml")


def _get_cassandra_env_file():
    return os.path.join(_get_cassandra_config_dir(), "cassandra-env.sh")


def _get_cassandra_rackdc_file():
    return os.path.join(_get_cassandra_config_dir(), "cassandra-rackdc.properties")


def _get_seeds(config_data=None):
    if config_data is None:
        config_data = hookenv.config()

    if config_data['force-seed-nodes']:
        return config_data['force-seed-nodes'].split(',')

    # XXX Peer relation nodes

    else:
        return [hookenv.unit_private_ip()]


def _cassandra_is_running():
    if hookenv.config('dse'):
        pid_file = "/var/run/dse/dse.pid"
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
            raise RuntimeError("Cassandra pid file exists but PID {} is not running. Please manually check on the state of Cassandra".format(pid) )
        # Wait for full up state with binary backoff
        # up to 256 seconds
        for i in range(9):
            try:
                subprocess.check_call(["nodetool", "-h", hookenv.unit_private_ip(), "info"], stderr=open(os.devnull, 'wb'))
                hookenv.log("Cassandra is running", 'INFO')
                return True
            except:
                hookenv.log("Cassandra is still not fully up at attempt {}".format(i), 'INFO')
                time.sleep(2**i)
        raise RuntimeError("Cassandra PID {} is running but not responding to nodetool. Please manually check on the state of Cassandra".format(pid) )


def _stop_cassandra():
    if hookenv.config('dse'):
        cassandra = "/etc/init.d/dse"
    else:
        cassandra = "/etc/init.d/cassandra"

    hookenv.log("Stopping Cassandra", 'INFO')
    subprocess.check_call([cassandra, "stop"])

    # XXX wait time for cassandra to process
    if _cassandra_is_running():
        raise RuntimeError("Cassandra failed to stop")
    

def _start_cassandra():
    if hookenv.config('dse'):
        cassandra = "/etc/init.d/dse"
    else:
        cassandra = "/etc/init.d/cassandra"

    hookenv.log("Starting Cassandra", 'INFO')
    subprocess.check_call([cassandra, "start"])

    if not _cassandra_is_running():
        raise RuntimeError("Cassandra failed to start")


def _restart_cassandra():
    # XXX Peer aware restarts
    hookenv.log("Restarting Cassandra", 'INFO')
    _stop_cassandra()
    _start_cassandra()


def cassandra_yaml_template(config_data=None):
    if config_data is None:
        config_data = hookenv.config()

    # XXX Add num_tokens vs initial token check
    # XXX Handle initial tokens if needed
    # XXX DSE vs cassandra and different versions
    # i.e. exception=Cannot create property=commit_failure_policy 

    # This bit of insanity sends the full dictionary as a dict member
    # to overcome the use of VAR-NAME rather than VAR_NAME in
    # config.yaml
    config_data.update({"config_dict": config_data,
                        "private_address": hookenv.unit_private_ip(),
                        "seeds": _get_seeds(config_data),
                        "data_file_directories": config_data['data_file_directories'].split()
                       })

    template_file = "{}/templates/cassandra.yaml.tmpl".format(hookenv.charm_dir())
    contents = Template(open(template_file).read()).render(config_data)
    host.write_file(_get_cassandra_yaml_file(), contents )


def cassandra_env_template(config_data=None):
    if config_data is None:
        config_data = hookenv.config()

    # XXX Handle simple auth for 1.0.x
    # -Dpasswd.properties=${CASSANDRA_PASSWD}
    # -Daccess.properties=${CASSANDRA_ACCESS}

    # This bit of insanity sends the full dictionary as a dict member
    # to overcome the use of VAR-NAME rather than VAR_NAME in
    # config.yaml
    config_data.update({"config_dict": config_data})

    template_file = "{}/templates/cassandra-env.tmpl".format(hookenv.charm_dir())
    contents = Template(open(template_file).read()).render(config_data)
    host.write_file(_get_cassandra_env_file(), contents )


def cassandra_rackdc_template(config_data=None):
    if config_data is None:
        config_data = hookenv.config()

    # This bit of insanity sends the full dictionary as a dict member
    # to overcome the use of VAR-NAME rather than VAR_NAME in
    # config.yaml
    config_data.update({"config_dict": config_data})

    template_file = "{}/templates/cassandra-rackdc.tmpl".format(hookenv.charm_dir())
    contents = Template(open(template_file).read()).render(config_data)
    host.write_file(_get_cassandra_rackdc_file(), contents )


def update_nrpe_checks():
    nrpe_compat = nrpe.NRPE()
    conf = nrpe_compat.config
    check_http_params = conf.get('nagios_check_http_params')
    if check_http_params:
        nrpe_compat.add_check(
            shortname='vhost',
            description='Check Virtual Host',
            check_cmd='check_http %s' % check_http_params
        )
    nrpe_compat.write()


def install_dse():
    java_jna_jar = os.path.join("/usr", "share", "java", "jna.jar")
    
    # Install prerequisites
    packages = ['default-jre-headless', 'libcommons-daemon-java', 'libjna-java',
                'python-support']
    fetch.apt_install(packages, fatal=True)

    # Setup Oracle Java
    # XXX Install from package?
    if hookenv.config('private_jre_url'):
        source = fetch.install_remote(hookenv.config('private_jre_url'))
        shutil.move(" ".join(glob.glob(os.path.join(source, "*"))),
                    os.path.join("/usr", "lib", "jvm", "oracle-jre"))

        subprocess.check_call(["update-alternatives", "--install", "/usr/bin/java",
                               "java", "/usr/lib/jvm/oracle-jre/bin/java", "1"])
        subprocess.check_call(["update-alternatives", "--set", "java",
                               "/usr/lib/jvm/oracle-jre/bin/java"])

    # Use modern JNA
    if hookenv.config('private_jna_url'):
        source = fetch.install_remote(hookenv.config('private_jna_url'))
        shutil.move(os.path.join(source, "jna"), os.path.join("/usr", "share", "java"))
        subprocess.check_call(["rm", "-f", java_jna_jar])
        host.symlink(os.path.join("/usr", "share", "java", "jna", "dist", "jna.jar"), java_jna_jar)

    # Install DSE
    if hookenv.config('private_dse_url'):
        source = fetch.install_remote(hookenv.config('private_dse_url'))
        cmd = ['dpkg', "--install" ] + glob.glob(os.path.join(source, "dse", "*"))
        subprocess.check_call(cmd)
    else:
        packages = ['dse-full']
        fetch.apt_install(packages, fatal=True)


@hooks.hook()
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
        # XXX disable cassandra start?
        packages = ['cassandra']
        fetch.apt_install(packages, fatal=True)


@hooks.hook('config-changed','upgrade-charm')
def config_changed():
    config_data = hookenv.config()
    update_nrpe_checks()
    cassandra_yaml_template(config_data)
    cassandra_rackdc_template(config_data)
    cassandra_env_template(config_data)
    # XXX restart cassandra? bash used bzr 
    _restart_cassandra()


hook_name = os.path.basename(sys.argv[0])

if __name__ == '__main__':
    hookenv.log("Running {} hook".format(hook_name),'INFO')
    hooks.execute(sys.argv)
