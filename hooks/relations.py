import os.path

from charmhelpers.core import hookenv
from charmhelpers.core.hookenv import log, WARNING
from charmhelpers.core.services.helpers import RelationContext


class DatabaseRelation(RelationContext):
    name = 'database'
    interface = 'cassandra'

    def provide_data(self):
        return dict(port=9160, thrift_port=9160, native_port=9042)


class JmxRelation(RelationContext):
    name = 'jmx'
    interface = 'cassandra'

    def provide_data(self):
        return dict(port=7199)


# FOR CHARMHELPERS
class BlockStorageBroker(RelationContext):
    '''Wait for the block storage mount to become available.

    Charms using this should add a 'wait_for_storage_broker' boolean
    configuration option in their config.yaml file. This is necessary
    to avoid potential data loss race conditions, because otherwise a
    unit will be started up using local disk before it becomes aware
    that it should be using external storage.

    'relname' is the relation name.

    'mountpount' is the mountpoint. Use the default if you have a single
    block storage broker relation. The default is calculated to avoid
    configs using the unit name (/srv/${service}_${unitnumber}).
    '''
    interface = 'block-storage'

    def __init__(self, name=None, mountpoint=None):
        super(BlockStorageBroker, self).__init__(name)

        if mountpoint is None:
            mountpoint = os.path.join('/srv/',
                                      hookenv.local_unit().replace('/', '_'))
        self._requested_mountpoint = mountpoint

        if len(self) > 0 and mountpoint == self[0].get('mountpoint', None):
            self.mountpoint == mountpoint
        else:
            self.mountpoint = None

    def is_ready(self):
        if hookenv.config('wait_for_storage_broker'):
            if self.mountpoint:
                log("External storage mounted at {}".format(self.mountpoint))
                return True
            else:
                log("Waiting for block storage broker to mount {}".format(
                    self._requested_mountmount), WARNING)
                return False
        return True

    def provide_data(self):
        return dict(mountpoint=self._requested_mountpoint)