#!.venv3/bin/python3

import functools
import unittest
from unittest.mock import patch

from charmhelpers.core.services import ServiceManager

from tests.base import TestCaseBase

import definitions


patch = functools.partial(patch, autospec=True)


class TestDefinitions(TestCaseBase):
    @patch('charmhelpers.core.hookenv.relation_get')
    def test_get_service_definitions(self, *args):
        # We can't really test this in unit tests, but at least we can
        # ensure the basic data structure is returned and accepted.
        defs = definitions.get_service_definitions()
        self.assertIsInstance(defs, list)
        for d in defs:
            with self.subTest(d=d):
                self.assertIsInstance(d, dict)

    @patch('charmhelpers.core.hookenv.relation_get')
    def test_get_service_manager(self, *args):
        self.assertIsInstance(definitions.get_service_manager(),
                              ServiceManager)

    @patch('helpers.is_cassandra_running')
    def test_requirescassandra(self, is_running):
        is_running.return_value = True
        self.assertTrue(bool(definitions.RequiresCassandra()))
        is_running.return_value = False
        self.assertFalse(bool(definitions.RequiresCassandra()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
