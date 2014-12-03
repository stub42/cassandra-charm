import unittest
from unittest.mock import patch

from testing.mocks import mock_charmhelpers


class TestCaseBase(unittest.TestCase):
    def setUp(self):
        super(TestCaseBase, self).setUp()
        mock_charmhelpers(self)

        is_lxc = patch('helpers.is_lxc', autospec=True, return_value=False)
        is_lxc.start()
        self.addCleanup(is_lxc.stop)
