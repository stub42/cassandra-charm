#!/usr/bin/python3

from charmhelpers.core.services import ServiceManager

import actions
import helpers
import relations


def get_service_definitions():
    return [
        dict(service=helpers.get_cassandra_service(),
             ports=[7000,   # Cluster communication
                    7001,   # SSL cluster communication
                    9160,   # Thrift clients
                    9042,   # Native protocol clients
                    7199],  # JMX.
             required_data=[relations.BlockStorageBroker('data')],
             provided_data=[relations.DatabaseRelation(),
                            relations.JmxRelation()],
             data_ready=[actions.preinstall,
                         actions.add_implicit_package_signing_keys,
                         actions.configure_sources,
                         actions.swapoff,
                         actions.reset_sysctl,
                         actions.install_cassandra_packages,
                         actions.ensure_cassandra_package_status,
                         actions.configure_cassandra_yaml,
                         actions.configure_cassandra_env],
             stop=[actions.stop_cassandra],
             start=[actions.start_cassandra]),
        dict(service='rolling-restart', data_read=actions.rolling_restart,
             start=[], stop=[])]


def get_service_manager():
    return ServiceManager(get_service_definitions())


if __name__ == '__main__':  # pragma: no cover
    get_service_manager().manage()
