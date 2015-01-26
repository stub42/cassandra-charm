from charmhelpers.core import hookenv
from charmhelpers.core.services import ServiceManager

import actions
import helpers
import relations
import rollingrestart

import cassandra


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
             ports=[config['rpc_port'],   # Thrift clients.
                    config['native_transport_port']],  # Native clients.
             required_data=[relations.StorageRelation(),
                            RequiresCommissionedNode()],
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
            helpers.emit_describe_cluster,
            helpers.post_bootstrap,
            helpers.wait_for_agreed_schema,
            helpers.wait_for_normality,
            helpers.emit_describe_cluster,
            helpers.reset_default_password,
            helpers.ensure_superuser,
            helpers.reset_auth_keyspace_replication,
            helpers.emit_auth_keyspace_status]),

        # Actions that must be done while Cassandra is running.
        dict(service='post',
             required_data=[RequiresLiveNode()],
             data_ready=[actions.publish_database_relations,
                         actions.publish_database_admin_relations,
                         actions.install_maintenance_crontab,
                         actions.reset_auth_keyspace_replication,
                         actions.emit_describe_cluster,
                         actions.emit_auth_keyspace_status,
                         actions.emit_netstats,
                         actions.maybe_decommission_node],
             start=[], stop=[])]


class RequiresCommissionedNode:
    '''Once a node is decommissioned, don't try and start it again.'''
    def __bool__(self):
        return not hookenv.config().get('decommissioned', False)


class RequiresLiveNode:
    def __bool__(self):
        if helpers.is_cassandra_running():
            try:
                with helpers.connect():
                    hookenv.log("Authentication working")
                    return True
            except cassandra.AuthenticationFailed:
                hookenv.log('Unable to authenticate as superuser')
                return False
        return False


def get_service_manager():
    return ServiceManager(get_service_definitions())
