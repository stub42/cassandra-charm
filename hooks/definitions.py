from charmhelpers.core import hookenv
from charmhelpers.core.services import ServiceManager

import actions
import helpers
import relations
import rollingrestart


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
        dict(service=helpers.get_cassandra_service(),
             ports=[config['cluster_port'],        # Cluster communication.
                    config['cluster_ssl_port'],    # SSL cluster communication.
                    config['thrift_client_port'],  # Thrift clients.
                    config['native_client_port'],  # Native protocol clients.
                    config['jmx_port']],           # JMX management.
             required_data=[relations.StorageRelation()],
             provided_data=[relations.StorageRelation(),
                            relations.DatabaseRelation(),
                            relations.JmxRelation()],
             data_ready=[actions.preinstall,
                         actions.add_implicit_package_signing_keys,
                         actions.configure_sources,
                         actions.swapoff,
                         actions.reset_sysctl,
                         actions.install_cassandra_packages,
                         actions.ensure_cassandra_package_status,
                         actions.configure_cassandra_yaml,
                         actions.configure_cassandra_env,
                         actions.reset_all_io_schedulers,
                         actions.maybe_schedule_restart],
             stop=[actions.stop_cassandra],
             start=[actions.start_cassandra])]


def get_service_manager():
    return ServiceManager(get_service_definitions())
