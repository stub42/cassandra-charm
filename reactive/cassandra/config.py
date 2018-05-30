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
    cassandra.config.validated  - Charm config passed validation.
    cassandra.configured        - All configuration files are up to date.
    cassandra.auth.enabled      - Authentication is enabled.
    cassandra.auth.disabled     - Authentication is disabled.
'''

from charmhelpers.core import hookenv
from charms import reactive
from charms.reactive import (
    hook,
    when,
    when_not,
)
from charms.layer import cassandra
import helpers


# These config keys cannot be changed after service deployment.
UNCHANGEABLE_KEYS = frozenset([
    'cluster_name',
    'datacenter',
    'rack',
    'edition',
    'dse_version',
])

# If any of these config items are changed, Cassandra needs to be
# restarted and maybe remounted.
RESTART_REQUIRED_KEYS = frozenset([
    'authenticator',
    'authorizer',
    'commitlog_directory',
    'compaction_throughput_mb_per_sec',
    'data_file_directories',
    'file_cache_size_in_mb',
    'heap_newsize',
    'jre',
    'listen_interface',
    'max_heap_size',
    'native_transport_port',
    'num_tokens',
    'partitioner',
    'private_jre_url',
    'rpc_interface',
    'rpc_port',
    'saved_caches_directory',
    'ssl_storage_port',
    'storage_port',
    'stream_throughput_outbound_megabits_per_sec',
    'tombstone_failure_threshold',
    'tombstone_warn_threshold',
])

# All other config items. By maintaining both lists, we can detect if
# someone forgot to update these lists when they added a new config item.
RESTART_NOT_REQUIRED_KEYS = frozenset([
    'extra_packages',
    'package_status',
    'install_sources',
    'install_keys',
    'http_proxy',
    'wait_for_storage_broker',
    'io_scheduler',
    'nagios_context',
    'nagios_servicegroups',
    'nagios_heapchk_warn_pct',
    'nagios_heapchk_crit_pct',
    'nagios_disk_warn_pct',
    'nagios_disk_crit_pct',
])

ENUMS = {
    'authenticator': frozenset(['PasswordAuthenticator', 'AllowAllAuthenticator']),
    'edition': frozenset(['community', 'dse', 'apache-snap']),
    'jre': frozenset(['openjdk', 'oracle']),
    'dse_version': frozenset(['4.7', '4.8', '5.0', '5.1', '6.0']),
}


reactive.register_trigger(when='config.changed', clear_flag='cassandra.config.validated')
reactive.register_trigger(when='config.changed', clear_flag='cassandra.configured')


@hook('upgrade-charm')
def upgrade_charm():
    reactive.clear_flag('cassandra.config.validated')
    reactive.clear_flag('cassandra.configured')
    reactive.clear_flag('cassandra.ports.opened')


@hook('upgrade-charm')
def populate_dse_version():
    if cassandra.get_edition() != 'dse':
        return
    config = cassandra.config()
    if config.get('dse_version', None) is None:
        ver = cassandra.get_package_version('dse')[:3]
        assert ver in ENUMS['dse_version'], 'Extracted invalid DSE version {!r}'.format(ver)
        config['dse_version'] = ver


@when_not('cassandra.config.validated')
def validate_config():
    config = cassandra.config()
    new_config = dict(hookenv.config())

    invalid = False
    for k in UNCHANGEABLE_KEYS:
        old = config.get(k, None)
        new = new_config.get(k, None)
        if old is not None and old != new:
            # While only the most recent will be visible in status,
            # all will be visible in the status log.
            helpers.status_set('blocked', 'Config {!r} may not be changed after deployment, was {!r}'.format(k, old))
            invalid = True

    for k, vals in ENUMS.items():
        for v in vals:
            if new_config[k].lower() == v.lower():
                hookenv.log("new_confg[{}] = {}".format(k, v))
                new_config[k] = v
                break
        else:
            helpers.status_set('blocked', 'Invalid value {!r} for config setting {}'.format(new_config[k], k))
            invalid = True

    if invalid:
        return  # cassandra.config.validated state not set, charm will not continue.

    # Update stored config to match the validated charm config. Convert enums to lowercase.
    gone = set(k for k in config if k not in new_config)
    for k in gone:
        del config[k]
    for k, v in new_config.items():
        if k in UNCHANGEABLE_KEYS:
            # Don't update unchangeable keys once set. Other handlers
            # may need to override, such as populating dse_version from
            # deployments prior to the setting existing.
            config.setdefault(k, v)
        else:
            config[k] = v

    reactive.set_flag('cassandra.config.validated')


@when('cassandra.config.validated')
@when('cassandra.installed')
@when('leadership.set.seeds')
@when_not('cassandra.configured')
def configure_cassandra():
    cassandra.write_cassandra_yaml(cassandra.get_cassandra_yaml())
    cassandra.write_cassandra_env(cassandra.get_cassandra_env())
    cassandra.write_cassandra_rackdc(cassandra.get_cassandra_rackdc())
    reactive.set_flag('cassandra.configured')


@when('cassandra.configured')
@when_not('cassandra.ports.opened')
def open_ports():
    config = cassandra.config()
    if cassandra.has_cassandra_version('3.0'):
        port_keys = ['native_transport_port']
    else:
        port_keys = ['rpc_port', 'native_transport_port']
    for k in port_keys:
        prev_k = '{}.previous'.format(k)
        prev = config.get(prev_k)
        want = config[k]
        if want == prev:
            continue
        hookenv.open_port(want)
        if prev is not None:
            hookenv.close_port(prev)
        config[prev_k] = want
    reactive.set_flag('cassandra.ports.opened')
