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
        # Actions done before or while the Cassandra service is running.
        dict(service=helpers.get_cassandra_service(),
             ports=[config['thrift_client_port'],   # Thrift clients.
                    config['native_client_port']],  # Native protocol clients.
             required_data=[relations.StorageRelation()],
             provided_data=[relations.StorageRelation()],
             data_ready=[actions.preinstall,
                         actions.revert_unchangeable_config,
                         actions.add_implicit_package_signing_keys,
                         actions.configure_sources,
                         actions.publish_cluster_relation,
                         actions.swapoff,
                         actions.reset_sysctl,
                         actions.install_cassandra_packages,
                         actions.ensure_cassandra_package_status,
                         actions.configure_cassandra_yaml,
                         actions.configure_cassandra_env,
                         actions.configure_cassandra_rackdc,
                         actions.reset_all_io_schedulers,
                         actions.maybe_schedule_restart],
             stop=[actions.stop_cassandra], start=[]),

        # Rolling restart. This service will call the restart hook when
        # it is this units turn to restart. This is also where we do
        # actions done while Cassandra is not running, and where we do
        # actions that should only be done by one node at a time.
        rollingrestart.make_service([
            helpers.stop_cassandra,
            helpers.remount_cassandra,
            helpers.ensure_database_directories,
            helpers.start_cassandra,
            helpers.reset_default_password,
            helpers.ensure_superuser,
            helpers.reset_auth_keyspace_replication,
            helpers.repair_auth_keyspace]),

        # Actions that must be done while Cassandra is running.
        dict(service='post',
             required_data=[RequiresCassandra()],  # Yucky hack.
             data_ready=[actions.remove_nodes,
                         actions.publish_database_relations],
             start=[], stop=[])]


class RequiresCassandra:
    def __bool__(self):
        return helpers.is_cassandra_running()


def get_service_manager():
    return ServiceManager(get_service_definitions())
