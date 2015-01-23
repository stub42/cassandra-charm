#!.venv3/bin/python3

import functools
import unittest
from unittest.mock import patch

from charmhelpers.core.services import ServiceManager

import cassandra

from tests.base import TestCaseBase

import definitions
import helpers


patch = functools.partial(patch, autospec=True)


class TestDefinitions(TestCaseBase):
    def test_get_service_definitions(self, *args):
        # We can't really test this in unit tests, but at least we can
        # ensure the basic data structure is returned and accepted.
        defs = definitions.get_service_definitions()
        self.assertIsInstance(defs, list)
        for d in defs:
            with self.subTest(d=d):
                self.assertIsInstance(d, dict)

    def test_get_service_manager(self, *args):
        self.assertIsInstance(definitions.get_service_manager(),
                              ServiceManager)

    @patch('helpers.connect')
    @patch('helpers.is_cassandra_running')
    def test_requires_live_node(self, is_running, connect):
        # Is running and can authenticate
        is_running.return_value = True
        # connect().__enter__.return_value = sentinel.session
        # connect().__exit__.return_value = False
        self.assertTrue(bool(definitions.RequiresLiveNode()))

        # Is running, but cannot authenticate
        connect().__enter__.side_effect = cassandra.AuthenticationFailed()
        self.assertFalse(bool(definitions.RequiresLiveNode()))

        # Is not running
        is_running.return_value = False
        self.assertFalse(bool(definitions.RequiresLiveNode()))

    @patch('helpers.stop_cassandra')
    @patch('subprocess.call')
    def test_requires_commissioned_node(self, call, stop_cassandra):
        call.return_value = 0
        self.assertTrue(bool(definitions.RequiresCommissionedNode()))
        helpers.decommission_node()
        self.assertFalse(bool(definitions.RequiresCommissionedNode()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
