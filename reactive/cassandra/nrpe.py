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

import os.path
import re

from charmhelpers.core import (
    hookenv,
    host,
)
from charmhelpers.core.hookenv import ERROR
from charmhelpers.contrib.charmsupport import nrpe
from charms import reactive
from charms.layer import cassandra
from charms.reactive import (
    hook,
    when,
    when_not,
)


@hook('upgrade-charm')
def upgrade_charm():
    reactive.clear_flag('cassandra.nrpe.installed')


reactive.register_trigger(when='config.changed', clear_flag='cassandra.nrpe.installed')


def local_plugins_dir():
    return '/usr/local/lib/nagios/plugins'


def mountpoint(path):
    '''Return the mountpoint that path exists on.'''
    path = os.path.realpath(path)
    while path != '/' and not os.path.ismount(path):
        path = os.path.dirname(path)
    return path


@when('nrpe-external-master.available')
@when_not('cassandra.nrpe.installed')
def nrpe_external_master_relation(*ignored):
    ''' Configure the nrpe-external-master relation '''
    local_plugins = local_plugins_dir()
    if not os.path.exists(local_plugins):
        # Error because this should have been created by the subordinate before
        # the nrpe-external-master.available flag was set.
        hookenv.log('plugins directory {} does not exist'.format(local_plugins), ERROR)
        hookenv.status_set('waiting', 'Waiting for {} to exist'.format(local_plugins))
        return

    src = os.path.join(hookenv.charm_dir(), "files", "check_cassandra_heap.sh")
    with open(src, 'rb') as f:
        host.write_file(os.path.join(local_plugins, 'check_cassandra_heap.sh'),
                        f.read(), perms=0o555)

    nrpe_compat = nrpe.NRPE()
    conf = hookenv.config()

    cassandra_heap_warn = conf.get('nagios_heapchk_warn_pct')
    cassandra_heap_crit = conf.get('nagios_heapchk_crit_pct')
    if cassandra_heap_warn and cassandra_heap_crit:
        nrpe_compat.add_check(
            shortname="cassandra_heap",
            description="Check Cassandra Heap",
            check_cmd="check_cassandra_heap.sh localhost {} {}"
                      "".format(cassandra_heap_warn, cassandra_heap_crit))

    cassandra_disk_warn = conf.get('nagios_disk_warn_pct')
    cassandra_disk_crit = conf.get('nagios_disk_crit_pct')
    dirs = cassandra.get_all_database_directories()
    dirs = set(dirs['data_file_directories'] +
               [dirs['commitlog_directory'], dirs['saved_caches_directory']])
    # We need to check the space on the mountpoint, not on the actual
    # directory, as the nagios user won't have access to the actual directory.
    mounts = set(mountpoint(d) for d in dirs)
    for disk in mounts:
        check_name = re.sub('[^A-Za-z0-9_]', '_', disk)
        if cassandra_disk_warn and cassandra_disk_crit:
            shortname = "cassandra_disk{}".format(check_name)
            hookenv.log("Adding disk utilization check {}".format(shortname))
            nrpe_compat.add_check(
                shortname=shortname, description="Check Cassandra Disk {}".format(disk),
                check_cmd="check_disk -u GB -w {}% -c {}% -K 5% -p {}"
                          "".format(cassandra_disk_warn, cassandra_disk_crit, disk))
    nrpe_compat.write()
    reactive.set_flag('cassandra.nrpe.installed')
