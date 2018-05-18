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

from contextlib import closing
import errno
from functools import wraps
import glob
import os.path
import re
import shlex
import socket
import subprocess
from textwrap import dedent
import time
import urllib.request

from charmhelpers import fetch
from charmhelpers.contrib.charmsupport import nrpe
from charmhelpers.contrib.network import ufw
from charmhelpers.contrib.templating import jinja
from charmhelpers.core import hookenv, host

import cassandra

from coordinator import coordinator
import helpers
import relations


def needs_reset_auth_keyspace_replication():
    '''Guard for reset_auth_keyspace_replication.'''
    num_nodes = helpers.num_nodes()
    datacenter = hookenv.config()['datacenter']
    with helpers.connect() as session:
        strategy_opts = helpers.get_auth_keyspace_replication(session)
        rf = int(strategy_opts.get(datacenter, -1))
        hookenv.log('system_auth rf={!r}'.format(strategy_opts))
        # If the node count has changed, we should change the rf.
        return rf != num_nodes


def needs_restart():
    '''Return True if Cassandra is not running or needs to be restarted.'''
    if helpers.is_decommissioned():
        # Decommissioned nodes are never restarted. They remain up
        # telling everyone they are decommissioned.
        helpers.status_set('blocked', 'Decommissioned node')
        return False

    if not helpers.is_cassandra_running():
        if helpers.is_bootstrapped():
            helpers.status_set('waiting', 'Waiting for permission to start')
        else:
            helpers.status_set('waiting',
                               'Waiting for permission to bootstrap')
        return True

    config = hookenv.config()

    # If our IP address has changed, we need to restart.
    if config.changed('_rpc_addr') or config.changed('_listen_addr'):
        helpers.status_set('waiting', 'IP address changed. '
                           'Waiting for restart permission.')
        return True

    # If the directory paths have changed, we need to migrate data
    # during a restart.
    storage = relations.StorageRelation()
    if storage.needs_remount():
        helpers.status_set(hookenv.status_get()[0],
                           'New mounts. Waiting for restart permission')
        return True

    # If any of these config items changed, a restart is required.
    for key in RESTART_REQUIRED_KEYS:
        if config.changed(key):
            hookenv.log('{} changed. Restart required.'.format(key))
    for key in RESTART_REQUIRED_KEYS:
        if config.changed(key):
            helpers.status_set(hookenv.status_get()[0],
                               'Config changes. '
                               'Waiting for restart permission.')
            return True

    # If we have new seeds, we should restart.
    new_seeds = helpers.get_seed_ips()
    if config.get('configured_seeds') != sorted(new_seeds):
        old_seeds = set(config.previous('configured_seeds') or [])
        changed = old_seeds.symmetric_difference(new_seeds)
        # We don't care about the local node in the changes.
        changed.discard(helpers.listen_ip_address())
        if changed:
            helpers.status_set(hookenv.status_get()[0],
                               'Updated seeds {!r}. '
                               'Waiting for restart permission.'
                               ''.format(new_seeds))
            return True

    hookenv.log('Restart not required')
    return False


@action
@coordinator.require('restart', needs_restart)
def maybe_restart():
    '''Restart sequence.

    If a restart is needed, shutdown Cassandra, perform all pending operations
    that cannot be be done while Cassandra is live, and restart it.
    '''
    helpers.status_set('maintenance', 'Stopping Cassandra')
    helpers.stop_cassandra()
    helpers.remount_cassandra()
    helpers.ensure_database_directories()
    if helpers.peer_relid() and not helpers.is_bootstrapped():
        helpers.status_set('maintenance', 'Bootstrapping')
    else:
        helpers.status_set('maintenance', 'Starting Cassandra')
    helpers.start_cassandra()


@action
def post_bootstrap():
    '''Maintain state on if the node has bootstrapped into the cluster.

    Per documented procedure for adding new units to a cluster, wait 2
    minutes if the unit has just bootstrapped to ensure other units
    do not attempt bootstrap too soon. Also, wait until completed joining
    to ensure we keep the lock and ensure other nodes don't restart or
    bootstrap.
    '''
    if not helpers.is_bootstrapped():
        if coordinator.relid is not None:
            helpers.status_set('maintenance', 'Post-bootstrap 2 minute delay')
            hookenv.log('Post-bootstrap 2 minute delay')
            time.sleep(120)  # Must wait 2 minutes between bootstrapping nodes.

        join_msg_set = False
        while True:
            status = helpers.get_node_status()
            if status == 'NORMAL':
                break
            elif status == 'JOINING':
                if not join_msg_set:
                    helpers.status_set('maintenance', 'Still joining cluster')
                    join_msg_set = True
                time.sleep(10)
                continue
            else:
                if status is None:
                    helpers.status_set('blocked',
                                       'Unexpectedly shutdown during '
                                       'bootstrap')
                else:
                    helpers.status_set('blocked',
                                       'Failed to bootstrap ({})'
                                       ''.format(status))
                raise SystemExit(0)

    # Unconditionally call this to publish the bootstrapped flag to
    # the peer relation, as the first unit was bootstrapped before
    # the peer relation existed.
    helpers.set_bootstrapped()


@leader_only
@action
@authentication
def create_unit_superusers():
    # The leader creates and updates accounts for nodes, using the
    # encrypted password they provide in relations.PeerRelation. We
    # don't end up with unencrypted passwords leaving the unit, and we
    # don't need to restart Cassandra in no-auth mode which is slow and
    # I worry may cause issues interrupting the bootstrap.
    if not coordinator.relid:
        return  # No peer relation, no requests yet.

    created_units = helpers.get_unit_superusers()
    uncreated_units = [u for u in hookenv.related_units(coordinator.relid)
                       if u not in created_units]
    for peer in uncreated_units:
        rel = hookenv.relation_get(unit=peer, rid=coordinator.relid)
        username = rel.get('username')
        pwhash = rel.get('pwhash')
        if not username:
            continue
        hookenv.log('Creating {} account for {}'.format(username, peer))
        with helpers.connect() as session:
            helpers.ensure_user(session, username, pwhash, superuser=True)
        created_units.add(peer)
        helpers.set_unit_superusers(created_units)


def _client_credentials(relid):
    '''Return the client credentials used by relation relid.'''
    relinfo = hookenv.relation_get(unit=hookenv.local_unit(), rid=relid)
    username = relinfo.get('username')
    password = relinfo.get('password')
    if username is None or password is None:
        for unit in hookenv.related_units(coordinator.relid):
            try:
                relinfo = hookenv.relation_get(unit=unit, rid=relid)
                username = relinfo.get('username')
                password = relinfo.get('password')
                if username is not None and password is not None:
                    return username, password
            except subprocess.CalledProcessError:
                pass  # Assume the remote unit has not joined yet.
        return None, None
    else:
        return username, password


def _publish_database_relation(relid, superuser):
    # The Casandra service needs to provide a common set of credentials
    # to a client unit. The leader creates these, if none of the other
    # units are found to have published them already (a previously elected
    # leader may have done this). The leader then tickles the other units,
    # firing a hook and giving them the opportunity to copy and publish
    # these credentials.
    username, password = _client_credentials(relid)
    if username is None:
        if hookenv.is_leader():
            # Credentials not set. The leader must generate them. We use
            # the service name so that database permissions remain valid
            # even after the relation is dropped and recreated, or the
            # juju environment rebuild and the database restored from
            # backups.
            service_name = helpers.get_service_name(relid)
            if not service_name:
                # Per Bug #1555261, we might not yet have related units,
                # so no way to calculate the remote service name and thus
                # the user.
                return  # Try again later.
            username = 'juju_{}'.format(helpers.get_service_name(relid))
            if superuser:
                username += '_admin'
            password = host.pwgen()
            pwhash = helpers.encrypt_password(password)
            with helpers.connect() as session:
                helpers.ensure_user(session, username, pwhash, superuser)
            # Wake the peers, if any.
            helpers.leader_ping()
        else:
            return  # No credentials yet. Nothing to do.

    # Publish the information the client needs on the relation where
    # they can find it.
    #  - authentication credentials
    #  - address and port
    #  - cluster_name, so clients can differentiate multiple clusters
    #  - datacenter + rack, so clients know what names they can use
    #    when altering keyspace replication settings.
    config = hookenv.config()
    hookenv.relation_set(relid,
                         username=username, password=password,
                         host=helpers.rpc_broadcast_ip_address(),
                         native_transport_port=config['native_transport_port'],
                         rpc_port=config['rpc_port'],
                         cluster_name=config['cluster_name'],
                         datacenter=config['datacenter'],
                         rack=config['rack'])


@action
def publish_database_relations():
    for relid in hookenv.relation_ids('database'):
        _publish_database_relation(relid, superuser=False)


@action
def publish_database_admin_relations():
    for relid in hookenv.relation_ids('database-admin'):
        _publish_database_relation(relid, superuser=True)


@action
def emit_cluster_info():
    helpers.emit_describe_cluster()
    helpers.emit_status()
    helpers.emit_netstats()


@action
def configure_firewall():
    '''Configure firewall rules using ufw.

    This is primarily to block access to the replication and JMX ports,
    as juju's default port access controls are not strict enough and
    allow access to the entire environment.

    The approach here is a whitelist, which is unsustainable as subordinates
    may want to open arbitrary ports. This method should be rewritten
    to instead blacklist the replication and jmx ports. Or better yet,
    secure those ports with TLS (jmx may be an issue with old Cassandra
    versions).
    '''
    config = hookenv.config()
    ufw.enable(soft_fail=True)

    # Enable SSH from anywhere, relying on Juju and external firewalls
    # to control access.
    ufw.service('ssh', 'open')
    ufw.service('nrpe', 'open')   # Also NRPE for nagios checks.
    ufw.service('rsync', 'open')  # Also rsync for data transfer and backups.
    client_ports = ['9103']       # Default telegraf port, for monitoring.

    # Clients need client access. These protocols are configured to
    # require authentication.
    client_keys = ['native_transport_port', 'rpc_port']
    client_ports.extend([config[key] for key in client_keys])

    # Peers need replication access. This protocols does not
    # require authentication, so firewall it from other nodes.
    peer_ports = [config['storage_port'], config['ssl_storage_port']]

    # Enable client access from anywhere. Juju and external firewalls
    # can still restrict this further of course (ie. 'juju expose').
    for key in client_keys:
        if config.changed(key) and config.previous(key) is not None:
            # First close old ports. We use this order in the unlikely case
            # someone is trying to swap the native and Thrift ports.
            ufw.service(config.previous(key), 'close')
    for port in client_ports:
        # Then open or close the configured ports.
        ufw.service(port, 'open')

    desired_rules = set()  # ufw.grant_access/remove_access commands.

    # Rules for peers
    for relinfo in hookenv.relations_of_type('cluster'):
        if relinfo.get('listen_ip'):
            pa = relinfo['listen_ip']
            for port in peer_ports:
                desired_rules.add((pa, 'any', port))
    # Rules for admin connections. We allow database-admin relations access
    # to the cluster communication ports so that tools like sstableloader
    # can run.
    for relinfo in hookenv.relations_of_type('database-admin'):
        if relinfo['private-address']:
            pa = hookenv._ensure_ip(relinfo['private-address'])
            for port in peer_ports:
                desired_rules.add((pa, 'any', port))

    previous_rules = set(tuple(rule) for rule in config.get('ufw_rules', []))

    # Close any rules previously opened that are no longer desired.
    for rule in sorted(list(previous_rules - desired_rules)):
        ufw.revoke_access(*rule)

    # Open all the desired rules.
    for rule in sorted(list(desired_rules)):
        ufw.grant_access(*rule)

    # Store our rules for next time. Note that this is inherantly racy -
    # this value is only persisted if the hook exits cleanly. If the
    # hook fails, then someone changes port configuration or IP
    # addresses change, then the failed hook retried, we can lose track
    # of previously granted rules and they will never be revoked. It is
    # impossible to remove this race entirely, so we stick with this
    # simple approach.
    config['ufw_rules'] = list(desired_rules)  # A list because JSON.


@action
def nrpe_external_master_relation():
    ''' Configure the nrpe-external-master relation '''
    local_plugins = helpers.local_plugins_dir()
    if os.path.exists(local_plugins):
        src = os.path.join(hookenv.charm_dir(),
                           "files", "check_cassandra_heap.sh")
        with open(src, 'rb') as f:
            host.write_file(os.path.join(local_plugins,
                                         'check_cassandra_heap.sh'),
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
    dirs = helpers.get_all_database_directories()
    dirs = set(dirs['data_file_directories'] +
               [dirs['commitlog_directory'], dirs['saved_caches_directory']])
    # We need to check the space on the mountpoint, not on the actual
    # directory, as the nagios user won't have access to the actual directory.
    mounts = set(helpers.mountpoint(d) for d in dirs)
    for disk in mounts:
        check_name = re.sub('[^A-Za-z0-9_]', '_', disk)
        if cassandra_disk_warn and cassandra_disk_crit:
            shortname = "cassandra_disk{}".format(check_name)
            hookenv.log("Adding disk utilization check {}".format(shortname),
                        DEBUG)
            nrpe_compat.add_check(
                shortname=shortname,
                description="Check Cassandra Disk {}".format(disk),
                check_cmd="check_disk -u GB -w {}% -c {}% -K 5% -p {}"
                          "".format(cassandra_disk_warn, cassandra_disk_crit,
                                    disk))
    nrpe_compat.write()


@action
def set_active():
    # If we got this far, the unit is active. Update the status if it is
    # not already active. We don't do this unconditionally, as the charm
    # may be active but doing stuff, like active but waiting for restart
    # permission.
    if hookenv.status_get()[0] != 'active':
        helpers.set_active()
    else:
        hookenv.log('Unit status already active', DEBUG)


@action
@authentication
def request_unit_superuser():
    relid = helpers.peer_relid()
    if relid is None:
        hookenv.log('Request deferred until peer relation exists')
        return

    relinfo = hookenv.relation_get(unit=hookenv.local_unit(),
                                   rid=relid)
    if relinfo and relinfo.get('username'):
        # We must avoid blindly setting the pwhash on the relation,
        # as we will likely get a different value everytime we
        # encrypt the password due to the random salt.
        hookenv.log('Superuser account request previously made')
    else:
        # Publish the requested superuser and hash to our peers.
        username, password = helpers.superuser_credentials()
        pwhash = helpers.encrypt_password(password)
        hookenv.relation_set(relid, username=username, pwhash=pwhash)
        hookenv.log('Requested superuser account creation')

