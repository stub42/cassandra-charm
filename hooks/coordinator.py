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
from charmhelpers.coordinator import BaseCoordinator


class CassandraCoordinator(BaseCoordinator):
    def default_grant(self, unit, granted, queue):
        '''Grant locks to only one unit at a time, regardless of its name.

        This lets us keep separate locks like repair and restart,
        while ensuring the operations do not occur on different nodes
        at the same time.
        '''
        # Return True if this unit has already been granted a lock.
        if self.grants.get(unit):
            return True

        # Otherwise, return True if the unit is first in the queue.
        return queue[0] == unit


coordinator = CassandraCoordinator()
