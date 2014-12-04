#!.venv3/bin/python3

import unittest
from unittest.mock import patch

from charmhelpers.core.services import ServiceManager

from tests.base import TestCaseBase

import definitions


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


if __name__ == '__main__':
    unittest.main(verbosity=2)
