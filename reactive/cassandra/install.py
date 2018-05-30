# Copyright 2015-2018 Canonical Ltd.
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

'''
States:
    cassandra.installed    - Cassandra and support packages are all installed
'''


from contextlib import closing
import errno
import glob
import os.path
import socket
import subprocess
import tempfile
from textwrap import dedent
import time
import urllib

from charmhelpers.core import (
    fstab,
    hookenv,
    host,
    templating,
)
from charmhelpers.core.hookenv import (
    DEBUG,
    ERROR,
    WARNING,
)
from charms import (
    apt,
    reactive,
)
from charms.layer import (
    cassandra,
    snap,
)
from charms.reactive import (
    hook,
    when,
    when_not,
)
from charms.reactive.flags import register_trigger
import helpers


@hook('upgrade-charm')
def upgrade_charm():
    reactive.clear_flag('cassandra.installed')
    reactive.clear_flag('cassandra.swapoff.done')
    reactive.clear_flag('cassandra.kernelsettings.done')
    reactive.clear_flag("cassandra.limits.done")
    reactive.clear_flag('cassandra.crontab.installed')
    reactive.clear_flag('cassandra.io_schedulers.done')
    reactive.clear_flag('cassandra.version.set')
    cassandra.config()['last_version_update'] = 0


register_trigger(when='config.changed', clear_flag='cassandra.installed')
register_trigger(when='config.changed', clear_flag='cassandra.crontab.installed')
register_trigger(when='config.changed', clear_flag='cassandra.etchosts.done')
register_trigger(when='config.changed', clear_flag='cassandra.io_schedulers.done')


@when_not('cassandra.swapoff.done')
def swapoff(fstab_path='/etc/fstab'):
    '''Turn off swapping in the container, permanently.'''
    # Turn off swap in the current session
    if host.is_container():
        hookenv.log("In a container, not touching swap.")
    else:
        try:
            hookenv.log("Turning off swap (swapoff -a)")
            subprocess.check_call(['swapoff', '-a'])
            hookenv.log("Removing swap entries from {}".format(fstab_path))
            with closing(fstab.Fstab(fstab_path)) as f:
                while True:
                    swap_entry = f.get_entry_by_attr('filesystem', 'swap')
                    if swap_entry is None:
                        break
                    f.remove_entry(swap_entry)
        except Exception as e:
            hookenv.log("Ignoring an error trying to turn off swap: {}".format(e), WARNING)
            return  # cassandra.swapoff.done state not set, will be attempted again.
    reactive.set_flag('cassandra.swapoff.done')


@when_not("cassandra.kernelsettings.done")
def reset_sysctl():
    if host.is_container():
        hookenv.log("In a container, not changing kernel settings")
    else:
        cassandra_sysctl_file = os.path.join('/', 'etc', 'sysctl.d', '99-cassandra.conf')
        contents = b"vm.max_map_count = 131072\n"
        try:
            host.write_file(cassandra_sysctl_file, contents)
            subprocess.check_call(['sysctl', '-p', cassandra_sysctl_file])
        except OSError as e:
            if e.errno == errno.EACCES:
                hookenv.log("Ignoring permission Denied trying to set the "
                            "sysctl settings at {}".format(cassandra_sysctl_file),
                            WARNING)
            else:
                raise
    reactive.set_flag("cassandra.kernelsettings.done")


@when_not("cassandra.limits.done")
def reset_limits():
    '''Set /etc/security/limits.d correctly for Ubuntu, so the
    startup scripts don't emit a spurious warning.

    Per Cassandra documentation, Ubuntu needs some extra
    twiddling in /etc/security/limits.d. I have no idea why
    the packages don't do this, since they are already
    setting limits for the cassandra user correctly. The real
    bug is that the limits of the user running the startup script
    are being checked, rather than the limits of the user that will
    actually run the process.
    '''
    contents = dedent('''\
                      # Maintained by Juju
                      root - memlock unlimited
                      root - nofile 100000
                      root - nproc 32768
                      root - as unlimited
                      ubuntu - memlock unlimited
                      ubuntu - nofile 100000
                      ubuntu - nproc 32768
                      ubuntu - as unlimited
                      ''')
    host.write_file('/etc/security/limits.d/cassandra-charm.conf',
                    contents.encode('US-ASCII'))
    reactive.set_flag("cassandra.limits.done")


@when('cassandra.config.validated')
@when_not('cassandra.installed')
def install_packages():
    pin_dse()

    apt.queue_install(cassandra.get_deb_packages())

    if reactive.is_flag_set('apt.queued_installs'):
        with helpers.autostart_disabled():
            if not apt.install_queued():
                return  # apt layer already left us in a blocked state

    if cassandra.get_edition() == 'apache-snap':
        snap.install('cassandra')
    elif cassandra.get_jre() == 'oracle':
        tb = fetch_oracle_jre()
        if tb is None:
            return
        install_oracle_jre_tarball(tb)
    elif cassandra.get_jre() == 'openjdk':
        subprocess.check_call(['update-java-alternatives', '--jre-headless', '--set', 'java-1.8.0-openjdk-amd64'])
    reactive.set_flag('cassandra.installed')


def pin_dse():
    config = cassandra.config()
    ver = config['dse_version']
    content = dedent('''\
                     Package: dse*
                     Pin: version {}*
                     Pin-Priority: 995
                     ''').format(ver)
    d = '/etc/apt/preferences.d'
    if not os.path.exists(d):
        host.mkdir(d, perms=0o755)
    p = os.path.join(d, 'cassandra_charm')
    host.write_file(p, content)


def fetch_oracle_jre():
    config = cassandra.config()
    url = config.get('private_jre_url', None)
    if url and config.get('retrieved_jre', None) != url:
        filename = os.path.join(hookenv.charm_dir(), 'lib', url.split('/')[-1])
        if not filename.endswith('-linux-x64.tar.gz'):
            helpers.status_set('blocked', 'Invalid private_jre_url {}'.format(url))
        helpers.status_set(None, 'Downloading Oracle JRE')
        hookenv.log('Oracle JRE URL is {}'.format(url))
        urllib.request.urlretrieve(url, filename)
        config['retrieved_jre'] = url

    pattern = os.path.join(hookenv.charm_dir(),
                           'lib', 'server-jre-?u*-linux-x64.tar.gz')
    tarballs = glob.glob(pattern)
    if not (url or tarballs):
        helpers.status_set('blocked', 'private_jre_url not set and no local tarballs.')
        return
    elif not tarballs:
        helpers.status_set('blocked', 'Oracle JRE tarball not found ({})'.format(pattern))
        return

    # Latest tarball by filename/version num.
    tarball = sorted(tarballs)[-1]
    return tarball


def install_oracle_jre_tarball(tarball):
    # Same directory as webupd8 to avoid surprising people, but it could
    # be anything.
    if 'jre-7u' in str(tarball):
        dest = '/usr/lib/jvm/java-7-oracle'
    else:
        dest = '/usr/lib/jvm/java-8-oracle'

    if not os.path.isdir(dest):
        host.mkdir(dest)

    jre_exists = os.path.exists(os.path.join(dest, 'bin', 'java'))

    config = cassandra.config()

    # Unpack the latest tarball if necessary.
    if config.get('oracle_jre_tarball', '') == tarball and jre_exists:
        hookenv.log('Already installed {}'.format(tarball))
    else:
        hookenv.log('Unpacking {}'.format(tarball))
        subprocess.check_call(['tar', '-xz', '-C', dest,
                               '--strip-components=1', '-f', tarball])
        config['oracle_jre_tarball'] = tarball

    # Set alternatives, so /usr/bin/java does what we want.
    for tool in ['java', 'javac']:
        tool_path = os.path.join(dest, 'bin', tool)
        subprocess.check_call(['update-alternatives', '--install',
                               os.path.join('/usr/bin', tool),
                               tool, tool_path, '1'])
        subprocess.check_call(['update-alternatives',
                               '--set', tool, tool_path])


@when('cassandra.configured')
@when_not('cassandra.crontab.installed')
def install_maintenance_crontab():
    # Every unit should run repair once per week (at least once per
    # GCGraceSeconds, which defaults to 10 days but can be changed per
    # keyspace).
    unit_num = int(hookenv.local_unit().split('/')[-1])
    # Distribute the repair time evenly over the week.
    dow, hour, minute = helpers.week_spread(unit_num)
    cron_path = "/etc/cron.d/cassandra-maintenance"
    templating.render('cassandra_maintenance_cron.tmpl', cron_path, vars())
    reactive.set_flag('cassandra.crontab.installed')


@when('cassandra.config.validated')
@when_not('cassandra.etchosts.done')
def update_etc_hosts():
    hostname = socket.gethostname()
    addr = cassandra.listen_ip_address()
    hosts_map = {addr: hostname}
    # only need to add myself to /etc/hosts
    update_hosts_file('/etc/hosts', hosts_map)
    reactive.set_flag('cassandra.etchosts.done')


def update_hosts_file(hosts_file, hosts_map):
    """Older versions of Cassandra need own hostname resolution."""
    with open(hosts_file, 'r') as hosts:
        lines = hosts.readlines()

    newlines = []
    for ip, hostname in hosts_map.items():
        if not ip or not hostname:
            continue

        keepers = []
        for line in lines:
            _line = line.split()
            if len(_line) < 2 or not (_line[0] == ip or hostname in _line[1:]):
                keepers.append(line)
            else:
                hookenv.log('Marking line {!r} for update or removal'
                            ''.format(line.strip()), level=DEBUG)

        lines = keepers
        newlines.append('{} {}\n'.format(ip, hostname))

    lines += newlines

    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        with open(tmpfile.name, 'w') as hosts:
            for line in lines:
                hosts.write(line)

    os.rename(tmpfile.name, hosts_file)
    os.chmod(hosts_file, 0o644)


@when('cassandra.installed')
@when('cassandra.config.validated')
@when_not('cassandra.io_schedulers.done')
def reset_all_io_schedulers():
    cassandra.ensure_all_database_directories()
    dirs = cassandra.get_all_database_directories()
    dirs = (dirs['data_file_directories'] + [dirs['commitlog_directory']] +
            [dirs['saved_caches_directory']])
    config = cassandra.config()
    missing = False
    for d in dirs:
        if os.path.isdir(d):
            helpers.set_io_scheduler(config['io_scheduler'], d)
        else:
            # If we see this, we should add guards to run this handler later.
            hookenv.log("{} does not exist, deferring io scheduler update".format(d), WARNING)
            missing = True
    if not missing:
        reactive.set_flag('cassandra.io_schedulers.done')


@when('cassandra.installed')
@when('leadership.is_leader')
def set_application_version():
    config = cassandra.config()
    last_update = config.get('last_version_update', 0)
    if time.time() < last_update + 3600:
        return
    ed = cassandra.get_edition()
    if ed == 'apache-snap':
        ver = cassandra.get_snap_version('cassandra')
    elif ed == 'dse':
        ver = cassandra.get_package_version('dse')
    else:
        ver = cassandra.get_package_version('cassandra')
    if ver:
        hookenv.application_version_set(ver)
        config['last_version_update'] = int(time.time())
    else:
        hookenv.log('Invalid version {!r} extracted'.format(ver), ERROR)


#              data_ready=[actions.configure_firewall,
#              data_ready=[actions.post_bootstrap,
#                          actions.create_unit_superusers,
#                          actions.publish_database_relations,
#                          actions.publish_database_admin_relations,
#                          actions.nrpe_external_master_relation,
#                          actions.emit_cluster_info,
