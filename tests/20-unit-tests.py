#!.venv/bin/python3

import os.path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.append(os.path.abspath(os.path.join(
    os.path.dirname(__file__), os.pardir, 'hooks')))

from charmhelpers.core import hookenv
import charmhelpers.fetch

import actions
import helpers


@patch('helpers.is_lxc', lambda: False)
class TestsActions(unittest.TestCase):

    def setUp(self):
        # Mock charm environment.
        charm_dir = tempfile.TemporaryDirectory()
        self.addCleanup(charm_dir.cleanup)
        mock_env = patch.dict(os.environ, dict(CHARM_DIR=charm_dir.name))
        mock_env.start()
        self.addCleanup(mock_env.stop)


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

    @patch('charmhelpers.fetch.configure_sources')
    @patch('charmhelpers.core.hookenv.config')
    def test_configure_sources(self, config, configure_sources):
        config.return_value = hookenv.Config()

        def reload_config():
            config().save()
            config.return_value = hookenv.Config()

        # fetch.configure_sources called the first time
        actions.configure_sources('')
        configure_sources.assert_called_once_with(True)

        def reload_config():
            config().save()
            config.return_value = hookenv.Config()

        # fetch.configure_sources not called if relevant config is unchanged.
        reload_config()
        configure_sources.reset_mock()
        actions.configure_sources('')
        self.assertFalse(configure_sources.called)

        # Changing install_sources causes fetch.configure_sources to be
        # called.
        reload_config()
        configure_sources.reset_mock()
        config()['install_sources'] = 'foo'
        actions.configure_sources('')
        configure_sources.assert_called_once_with(True)

        # Changing install_keys causes fetch.configure_sources to be
        # called.
        reload_config()
        configure_sources.reset_mock()
        config()['install_keys'] = 'foo'
        actions.configure_sources('')
        configure_sources.assert_called_once_with(True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
