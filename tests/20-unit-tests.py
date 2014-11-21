#!.venv/bin/python3

import os.path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.append(os.path.abspath(os.path.join(
    os.path.dirname(__file__), os.pardir, 'hooks')))

import actions
import helpers


@patch('helpers.is_lxc', lambda: False)
class TestsActions(unittest.TestCase):
    @patch('subprocess.check_call')
    def test_swapoff(self, check_call):
        fstab = (
            b'UUID=abc / ext4 errors=remount-ro 0 1\n'
            b'/dev/mapper/cryptswap1 none swap sw 0 0')
        with tempfile.NamedTemporaryFile() as f:
            f.write(fstab)
            f.flush()
            actions.swapoff('', f.name)
            f.seek(0)
            self.assertTrue(b'swap' not in f.read())

        check_call.assert_called_once_with(['swapoff', '-a'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
