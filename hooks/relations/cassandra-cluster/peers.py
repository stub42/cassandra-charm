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

from charms import reactive
from charms.reactive import (
    endpoints,
    when,
)


class CassadraClusterEndpoint(reactive.Endpoint):

    _all_bootstrapped_units = None

    @property
    def all_bootstrapped_units(self):
        if self._all_bootstrapped_units is None:
            self._all_bootstrapped_units = endpoints.CombinedUnitsView(
                unit for unit in self.all_joined_units
                if bool(unit.received_raw.get('bootstrapped', False))
            )
        return self._all_bootstrapped_units

    def set_bootstrapped(self, ip):
        for rel in self.relations:
            rel.to_publish_raw['bootstrapped'] = '1'
            rel.to_publish_raw['listen_ip'] = ip

    def get_bootstrapped_ips(self):
        return set([unit.received_raw.get('listen_ip') for unit in self.all_bootstrapped_units])

    @when('endpoint.{endpoint_name}.changed.bootstrapped')
    def clear_changed(self):
        '''Clear changed flags immediately after triggers have been applied'''
        reactive.clear_flag(self.expand_name('endpoint.{endpoint_name}.changed.bootstrapped'))
