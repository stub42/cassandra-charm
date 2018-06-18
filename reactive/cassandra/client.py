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

import time

from charmhelpers.core import (
    hookenv,
    host,
)
from charms import (
    leadership,
    reactive,
)
from charms.layer import cassandra
from charms.reactive import (
    when,
    when_any,
    when_not,
)
from charms.reactive.flags import register_trigger


register_trigger('config.changed', clear_flag='cassandra.client.published')
register_trigger('endpoint.database.joined', clear_flag='cassandra.client.published')
register_trigger('endpoint.database-admin.joined', clear_flag='cassandra.client.published')
register_trigger('leadership.changed.client_rel_ping', clear_flag='cassandra.client.published')


@when('leadership.is_leader')
@when_any('endpoint.database.joined', 'endpoint.database-admin.joined')
@when_not('cassandra.client.published')
def publish():
    for rel in reactive.endpoint_from_name('database').relations:
        if rel.application_name is not None:
            publish_credentials(rel, False)
            publish_general(rel)
    for rel in reactive.endpoint_from_name('database-admin').relations:
        if rel.application_name is not None:
            publish_credentials(rel, True)
            publish_general(rel)
    reactive.set_flag('cassandra.client.published')


@when_not('leadership.is_leader')
@when_any('endpoint.database.joined', 'endpoint.database-admin.joined')
@when_not('cassandra.client.published')
def mirror():
    for relname in ['database', 'database-admin']:
        for rel in reactive.endpoint_from_name(relname).relations:
            mirror_credentials(rel)
            publish_general(rel)


def publish_credentials(rel, superuser):
    pub = rel.to_publish_raw
    config = cassandra.config()
    if config['authenticator'].lower() == 'allowallauthenticator':
        if 'username' in pub:
            del pub['username']
            del pub['password']
        return
    if 'username' in pub:
        hookenv.log("Credentials for {} ({}) already published".format(rel.application_name, rel.relation_id))
        return
    hookenv.log("Publishing credentials for {} ({})".format(rel.application_name, rel.relation_id))
    assert rel.application_name, 'charms.reactive Relation failed to provide application_name property'
    username = 'juju_{}'.format(rel.application_name)
    if superuser:
        username += '_admin'
    password = host.pwgen()
    pwhash = cassandra.encrypt_password(password)
    with cassandra.connect() as session:
        cassandra.ensure_user(session, username, pwhash, superuser)
    pub['username'] = username
    pub['password'] = password
    # Notify peers there are new credentials to be found.
    leadership.leader_set(client_rel_source=hookenv.local_unit(), client_rel_ping=str(time.time()))


def publish_general(rel):
    hookenv.log("Publishing connection details to {} ({})".format(rel.application_name, rel.relation_id))
    config = cassandra.config()
    pub = rel.to_publish_raw
    pub['host'] = cassandra.rpc_broadcast_ip_address()
    pub['native_transport_port'] = str(config['native_transport_port'])
    pub['rpc_port'] = str(config['rpc_port'])
    pub['cluster_name'] = config['cluster_name']
    pub['datacenter'] = config['datacenter']
    pub['rack'] = config['rack']


def mirror_credentials(rel):
    pub = rel.to_publish_raw
    config = cassandra.config()
    if config['authenticator'].lower() == 'allowallauthenticator':
        if 'username' in pub:
            del pub['username']
            del pub['password']
        return
    source_unit = leadership.leader_get('client_rel_source')
    source_data = hookenv.relation_get(unit=source_unit, rid=rel.relation_id)
    if source_data and 'username' in source_data:
        hookenv.log("Mirroring credentials for {} ({}) from {}".format(rel.application_name,
                                                                       rel.relation_id, source_unit))
        pub['username'] = source_data['username']
        pub['password'] = source_data['password']
