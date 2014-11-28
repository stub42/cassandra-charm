from datetime import datetime, timedelta
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

        _last_utc_now = datetime(2010, 12, 25, 13, 45)

        def _utcnow():
            nonlocal _last_utc_now
            _last_utc_now += timedelta(seconds=1)
            return _last_utc_now

        utcnow = patch('helpers.utcnow', autospec=True, side_effect=_utcnow)
        utcnow.start()
        self.addCleanup(utcnow.stop)
