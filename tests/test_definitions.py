#!.venv3/bin/python3

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

import functools
import unittest
from unittest.mock import patch

from charmhelpers.core import hookenv
from charmhelpers.core.services import ServiceManager

import cassandra

from tests.base import TestCaseBase

import definitions


patch = functools.partial(patch, autospec=True)


class TestDefinitions(TestCaseBase):
    def test_get_service_definitions(self):
        # We can't really test this in unit tests, but at least we can
        # ensure the basic data structure is returned and accepted.
        defs = definitions.get_service_definitions()
        self.assertIsInstance(defs, list)
        for d in defs:
            with self.subTest(d=d):
                self.assertIsInstance(d, dict)

    def test_get_service_definitions_closed_ports(self):
        # By default, all ports are closed.
        defs = definitions.get_service_definitions()
        self.assertListEqual(defs[0]['ports'], [])

    def test_get_service_definitions_open_ports(self):
        # Ports are only if explicitly requested in the config.
        config = hookenv.config()
        config['open_client_ports'] = True
        defs = definitions.get_service_definitions()
        expected_ports = [config['rpc_port'], config['native_transport_port']]
        self.assertSetEqual(set(defs[0]['ports']), set(expected_ports))

    def test_get_service_manager(self):
        self.assertIsInstance(definitions.get_service_manager(),
                              ServiceManager)

    @patch('helpers.connect')
    @patch('helpers.is_decommissioned')
    @patch('helpers.is_cassandra_running')
    def test_requires_live_node(self, is_running, is_decommissioned, connect):
        # Is running and can authenticate
        is_running.return_value = True
        # Is not decommissioned
        is_decommissioned.return_value = False
        # connect().__enter__.return_value = sentinel.session
        # connect().__exit__.return_value = False
        self.assertTrue(bool(definitions.RequiresLiveNode()))

        # Is running, but cannot authenticate
        connect().__enter__.side_effect = cassandra.AuthenticationFailed()
        self.assertFalse(bool(definitions.RequiresLiveNode()))

        # Is decommissioned
        is_decommissioned.return_value = True
        self.assertFalse(bool(definitions.RequiresLiveNode()))

        # Is not running
        is_running.return_value = False
        is_decommissioned.side_effect = RuntimeError('fails if not running')
        self.assertFalse(bool(definitions.RequiresLiveNode()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
