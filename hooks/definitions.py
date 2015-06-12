# Copyright 2015 Canonical Ltd.
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

from charmhelpers.core import hookenv
from charmhelpers.core.hookenv import ERROR
from charmhelpers.core import services

import actions
import helpers
import relations


def get_service_definitions():
    # This looks like it could be a module level global list, but
    # unfortunately that makes the module unimportable outside of a
    # hook context. The main culprit is RelationContext, which invokes
    # relation-get from its constructor. By wrapping the service
    # definition list in this function, we can defer constructing it
    # until we have constructed enough of a mock context and perform
    # basic tests.
    config = hookenv.config()

    return [
        # Prepare for the Cassandra service.
        dict(service='install',
             data_ready=[actions.set_proxy,
                         actions.preinstall,
                         actions.emit_meminfo,
                         actions.revert_unchangeable_config,
                         actions.store_unit_private_ip,
                         actions.add_implicit_package_signing_keys,
                         actions.configure_sources,
                         actions.swapoff,
                         actions.reset_sysctl,
                         actions.install_oracle_jre,
                         actions.install_cassandra_packages,
                         actions.emit_java_version,
                         actions.ensure_cassandra_package_status],
             start=[], stop=[]),

        # Get Cassandra running.
        dict(service=helpers.get_cassandra_service(),

             # Open access to client and replication ports. Client
             # protocols require password authentication. Access to
             # the unauthenticated replication ports is protected via
             # ufw firewall rules. We do not open the JMX port, although
             # we could since it is similarly protected by ufw.
             ports=[config['rpc_port'],               # Thrift clients
                    config['native_transport_port'],  # Native clients.
                    config['storage_port'],           # Plaintext replication
                    config['ssl_storage_port']],      # Encrypted replication.

             required_data=[relations.StorageRelation(),
                            relations.PeerRelation()],
             provided_data=[relations.StorageRelation(),
                            relations.PeerRelation()],
             data_ready=[actions.configure_firewall,
                         actions.grant_ssh_access,
                         actions.maintain_seeds,
                         actions.configure_cassandra_yaml,
                         actions.configure_cassandra_env,
                         actions.configure_cassandra_rackdc,
                         actions.reset_all_io_schedulers,
                         actions.maybe_restart],
             start=[services.open_ports],
             stop=[actions.stop_cassandra, services.close_ports]),

        # Actions that must be done while Cassandra is running.
        dict(service='post',
             required_data=[RequiresLiveNode()],
             data_ready=[actions.ensure_unit_superuser,
                         actions.reset_default_password,
                         actions.publish_database_relations,
                         actions.publish_database_admin_relations,
                         actions.install_maintenance_crontab,
                         actions.emit_describe_cluster,
                         actions.emit_auth_keyspace_status,
                         actions.emit_netstats,
                         actions.nrpe_external_master_relation,
                         actions.set_active],
             start=[], stop=[])]


class RequiresLiveNode:
    def __bool__(self):
        return self.is_live()

    def is_live(self):
        if helpers.is_cassandra_running():
            hookenv.log('Cassandra is running')
            if helpers.is_decommissioned():
                # Node is decommissioned and will refuse to talk.
                hookenv.log('Node is decommissioned')
                return False
            try:
                with helpers.connect():
                    hookenv.log("Node live and authentication working")
                    return True
            except Exception as x:
                hookenv.log(
                    'Unable to connect as superuser: {}'.format(str(x)),
                    ERROR)
                return False
        return False


def get_service_manager():
    return services.ServiceManager(get_service_definitions())
