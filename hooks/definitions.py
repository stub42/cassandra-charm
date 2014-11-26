#!/usr/bin/python3

from charmhelpers.core.services import ServiceManager

import actions
import relations

CASSANDRA_PACKAGES = ['cassandra', 'cassandra-tools']

SERVICE_DEFINITIONS = [
    dict(service='cassandra',
         ports=[
             7000,  # Cluster communication
             7001,  # SSL cluster communication
             9160,  # Thrift clients
             9042,  # Native protocol clients
             7199,  # JMX.
         ],
         required_data=[
             relations.BlockStorageBroker('data'),
         ],
         provided_data=[
             relations.DatabaseRelation(),
             relations.JmxRelation()
         ],
         data_ready=[
             actions.preinstall,
             actions.configure_sources,
             actions.swapoff,
             actions.reset_sysctl,
             actions.install_cassandra_packages,
             actions.ensure_cassandra_package_status,
             actions.configure_cassandra_yaml,
             actions.configure_cassandra_env,
         ])
]


if __name__ == '__main__':
    service_manager = ServiceManager(SERVICE_DEFINITIONS)
    service_manager.manage()
