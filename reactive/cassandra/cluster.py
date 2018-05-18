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
Flags:
    cassandra.bootstrapped  - Node has been bootstrapped into the Cassandra cluster
    cassandra.live          - Node is bootstrapped and ready for use
'''

import re
import time

from cassandra import ConsistencyLevel
import helpers
from charmhelpers.core import (
    host,
    hookenv,
)
from charmhelpers.core.hookenv import DEBUG
from charms import (
    coordinator,
    leadership,
    reactive,
)
from charms.layer import cassandra
from charms.reactive import (
    hook,
    when,
    when_any,
    when_not,
)
from charms.reactive.flags import register_trigger


@hook('upgrade-charm')
def upgrade_charm():
    if reactive.is_flag_set('leadership.is_leader'):
        # Each node used to have its own set of credentials, which
        # was unnecessarily clever.
        if (reactive.is_flag_set('leadership.set.default_admin_password_changed') and
                not reactive.is_flag_set('leadership.username')):
            username = 'juju_{}'.format(re.subn(r'\W', '_', hookenv.local_unit())[0])
            username, password = cassandra.get_cqlshrc_credentials(username)
            if username is not None and password is not None:
                leadership.leader_set(username=username, password=password)


register_trigger(when='leadership.changed.seeds', clear_flag='cassandra.configured')
register_trigger(when='leadership.changed.seeds', set_flag='cassandra.needs_restart')

register_trigger(when='endpoint.cluster.changed.bootstrapped', clear_flag='cassandra.seeds.done')
register_trigger(when='endpoint.cluster.departed', clear_flag='cassandra.seeds.done')

register_trigger(when='config.changed', clear_flag='cassandra.bootstrapped.published')


@when('leadership.is_leader')
@when('cassandra.config.validated')
@when_not('leadership.set.seeds')
def initial_seeds():
    leadership.leader_set(seeds=cassandra.listen_ip_address())
    reactive.set_flag('cassandra.seeds.done')


@when('leadership.is_leader')
@when('cassandra.config.validated')
@when('endpoint.cluster.joined')
@when('cassandra.bootstrapped')
@when_not('cassandra.seeds.done')
def update_seeds():
    seed_ips = cassandra.get_seed_ips()
    hookenv.log('Current seeds: {!r}'.format(seed_ips), DEBUG)

    bootstrapped_ips = get_bootstrapped_ips()
    hookenv.log('Bootstrapped: {!r}'.format(bootstrapped_ips), DEBUG)

    # Remove any seeds that are no longer bootstrapped, such as dropped
    # units.
    seed_ips.intersection_update(bootstrapped_ips)

    # Add more bootstrapped nodes, if necessary, to get to our maximum
    # of 3 seeds.
    for ip in bootstrapped_ips:
        if len(seed_ips) >= 3:
            break
        seed_ips.add(ip)

    hookenv.log('Updated seeds: {!r}'.format(seed_ips), DEBUG)
    leadership.leader_set(seeds=','.join(sorted(seed_ips)))


def get_bootstrapped_ips():
    ips = set()
    if reactive.is_flag_set('cassandra.bootstrapped'):
        ips.add(cassandra.listen_ip_address())
    u = reactive.endpoint_from_name('cluster')
    if u is not None:
        ips.update(u.get_bootstrapped_ips())
    return ips


@when('cassandra.bootstrapped')
@when('endpoint.cluster.joined')
@when_not('cassandra.bootstrapped.published')
def set_bootstrapped():
    u = reactive.endpoint_from_flag('endpoint.cluster.joined')
    u.set_bootstrapped(cassandra.listen_ip_address())
    reactive.set_flag('cassandra.bootstrapped.published')


@when('cassandra.needs_restart')
@when('cassandra.configured')
@when_any('leadership.is_leader', 'endpoint.cluster.joined')
@when_not('coordinator.requested.restart')
def request_restart_lock():
    coordinator.acquire('restart')


@when('cassandra.needs_restart')
@when('cassandra.configured')
@when('cassandra.bootstrapped')
@when('coordinator.granted.restart')
def restart():
    helpers.status_set('maintenance', 'Stopping Cassandra')
    if not cassandra.stop():
        helpers.status_set('blocked', 'Failed to stop Cassandra')
        return False

    auth_enabled = cassandra.config()['authenticator'] != 'allowallauthenticator'
    reactive.toggle_flag('cassandra.auth.enabled', auth_enabled)
    # cassandra.remount() # TODO: Storage support
    cassandra.ensure_all_database_directories()

    helpers.status_set('maintenance', 'Starting Cassandra')
    if not cassandra.start():
        helpers.status_set('blocked', 'Failed to start Cassandra')
        return False

    timeout = time.time() + 300
    for _ in cassandra.backoff("Cassandra to startup"):
        if cassandra.is_cassandra_running():
            reactive.clear_flag('cassandra.needs_restart')
            return True
        if time.time() > timeout:
            break
    helpers.status_set('blocked', 'Cassandra failed to startup')
    return False


@when('cassandra.needs_restart')
@when('cassandra.configured')
@when('coordinator.granted.restart')
@when_not('cassandra.bootstrapped')
def bootstrap():
    if restart():
        if wait_for_bootstrap():
            reactive.set_flag('cassandra.bootstrapped')


def wait_for_bootstrap():
    helpers.status_set('maintenance', 'Joining cluster')
    interval = 5
    while True:
        time.sleep(interval)
        status = cassandra.get_node_status()
        if status in ['JOINING', 'NORMAL']:
            return True
        if not status:
            helpers.status_set('blocked', 'Failed to retrieve node state')
        else:
            helpers.status_set('blocked', 'Node in unexpected state {!r}'.format(status))
        return False


@when('leadership.is_leader')
@when('cassandra.auth.enabled')
@when('cassandra.bootstrapped')
@when_not('leadership.set.default_admin_password_changed')
def reset_default_password():
    # We need a big timeout here, as the cassandra user actually
    # springs into existence some time after Cassandra has started
    # up and is accepting connections.
    with cassandra.connect('cassandra', 'cassandra', timeout=180) as session:
        # But before we close this security hole, we need to use these
        # credentials to create a different admin account.
        helpers.status_set('maintenance', 'Creating initial superuser account')
        username, password = 'jujucharm', host.pwgen()
        pwhash = cassandra.encrypt_password(password)
        cassandra.ensure_user(session, username, pwhash, superuser=True)
        leadership.leader_set(username=username, password=password)
        helpers.status_set('maintenance', 'Changing default admin password')
        cassandra.query(session, 'ALTER USER cassandra WITH PASSWORD %s',
                        ConsistencyLevel.ALL, (host.pwgen(),))
    hookenv.leader_set(default_admin_password_changed=True)


@when('leadership.set.default_admin_password_changed')
@when_not('leadership.set.username')
def auth_update():
    # We used to have individual superuser credentials for each node,
    # which was unnecessarily clever.
    username = 'juju_{}'.format(re.subn(r'\W', '_', hookenv.local_unit())[0])
    username, password = cassandra.get_cqlshrc_credentials(username)
    leadership.leader_set(username=username, password=password)
    hookenv.log('Migrated charm superuser credentials')


register_trigger(when='config.changed.authenticator', clear_flag='cassandra.live')


@when('cassandra.bootstrapped')
@when('cassandra.auth.enabled')
@when('leadership.set.username')
@when_not('cassandra.live')
def set_live_auth():
    reactive.set_flag('cassandra.live')


@when('cassandra.bootstrapped')
@when_not('cassandra.auth.enabled')
@when_not('cassandra.live')
def set_live_noauth():
    reactive.set_flag('cassandra.live')


@when('leadership.changed.username')
@when('cassandra.installed')
def update_cqlshrc():
    username, password = cassandra.superuser_credentials()
    cassandra.store_cqlshrc_credentials('root', username, password)
    if cassandra.get_edition() != 'apache-snap':
        cassandra.store_cqlshrc_credentials('ubuntu', username, password)


register_trigger(when='endpoint.cluster.departed', clear_flag='cassandra.authkeyspace.done')
register_trigger(when='endpoint.cluster.changed.bootstrapped', clear_flag='cassandra.authkeyspace.done')


@when('leadership.is_leader')
@when('cassandra.live')
@when('cassandra.auth.enabled')
@when_not('coordinator.requested.restart')
@when_not('cassandra.authkeyspace.done')
def request_restart_lock_for_repair():
    coordinator.acquire('restart')


@when('leadership.is_leader')
@when('cassandra.live')
@when('cassandra.auth.enabled')
@when('coordinator.granted.restart')
@when_not('cassandra.authkeyspace.done')
def reset_auth_keyspace_replication():
    # Cassandra requires you to manually set the replication factor of
    # the system_auth keyspace, to ensure availability and redundancy.
    # The recommendation is to set the replication factor so that every
    # node has a copy.
    ep = reactive.endpoint_from_name('cluster')
    num_nodes = len(ep.all_bootstrapped_units) + 1
    datacenter = cassandra.config()['datacenter']
    with cassandra.connect() as session:
        strategy_opts = cassandra.get_auth_keyspace_replication(session)
        rf = int(strategy_opts.get(datacenter, -1))
        hookenv.log('Current system_auth replication strategy is {!r}'.format(strategy_opts))
        if rf != num_nodes:
            strategy_opts['class'] = 'NetworkTopologyStrategy'
            strategy_opts[datacenter] = num_nodes
            if 'replication_factor' in strategy_opts:
                del strategy_opts['replication_factor']
            hookenv.log('New system_auth replication strategy is {!r}'.format(strategy_opts))
            status, msg = hookenv.status_get()
            helpers.status_set(status, 'Updating system_auth rf to {!r}'.format(strategy_opts))
            cassandra.set_auth_keyspace_replication(session, strategy_opts)
            if rf < num_nodes:
                # Increasing rf, need to run repair.
                cassandra.repair_auth_keyspace()
            helpers.status_set(status, msg)
    reactive.set_flag('cassandra.authkeyspace.done')
