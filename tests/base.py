import functools
import unittest
from unittest.mock import patch

from testing.mocks import mock_charmhelpers

patch = functools.partial(patch, autospec=True)  # autospec by default.


class TestCaseBase(unittest.TestCase):
    def setUp(self):
        super(TestCaseBase, self).setUp()

        mock_charmhelpers(self)

        is_lxc = patch('helpers.is_lxc', return_value=False)
        is_lxc.start()
        self.addCleanup(is_lxc.stop)
