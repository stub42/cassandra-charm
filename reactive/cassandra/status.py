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

from charms.layer import cassandra
from charms.reactive import (
    when,
    when_not,
)

import helpers


@when('cassandra.live')
@when_not('cassandra.needs_restart')
def is_live():
    is_seed = cassandra.listen_ip_address() in cassandra.get_seed_ips()
    if is_seed:
        helpers.status_set('active', 'Live seed')
    else:
        helpers.status_set('active', 'Live')


@when('cassandra.live')
@when('cassandra.needs_restart')
@when_not('coordinator.granted.restart')
def needs_restart():
    helpers.status_set('maintenance', 'Waiting for turn to restart')
