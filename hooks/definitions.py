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
from charmhelpers.core import services

import actions
import helpers
import relations
from coordinator import coordinator


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
             provided_data=[relations.StorageRelation()],
             data_ready=[actions.configure_firewall,
                         actions.maintain_seeds,
                         actions.configure_cassandra_yaml,
                         actions.configure_cassandra_env,
                         actions.configure_cassandra_rackdc,
                         actions.reset_all_io_schedulers,
                         actions.maybe_restart,
                         actions.request_unit_superuser,
                         actions.reset_default_password],
             start=[services.open_ports],
             stop=[actions.stop_cassandra, services.close_ports]),

        # Actions that must be done while Cassandra is running.
        dict(service='post',
             required_data=[RequiresLiveNode()],
             data_ready=[actions.post_bootstrap,
                         actions.publish_bootstrapped_flag,
                         actions.create_unit_superusers,
                         actions.reset_auth_keyspace_replication,
                         actions.publish_database_relations,
                         actions.publish_database_admin_relations,
                         actions.install_maintenance_crontab,
                         actions.nrpe_external_master_relation,
                         actions.emit_cluster_info,
                         actions.set_active],
             start=[], stop=[])]


class RequiresLiveNode:
    def __bool__(self):
        is_live = self.is_live():
        hookenv.log('Requirement RequiresLiveNode: {}'.format(is_live))
        return is_live

    def is_live(self):
        if helpers.is_decommissioned():
            hookenv.log('Node is decommissioned')
            return False

        if helpers.is_cassandra_running():
            hookenv.log('Cassandra is running')
            relinfo = hookenv.relation_get(unit=hookenv.local_unit(),
                                           rid=coordinator.relid) or {}
            username = relinfo.get('username')
            pwhash = relinfo.get('pwhash')
            if helpers.get_unit_superusers().get(username) == pwhash:
                hookenv.log('Credentials exist')
                return True
            else:
                hookenv.log('Credentials do not exist')
                return False

        return False


def get_service_manager():
    return services.ServiceManager(get_service_definitions())
