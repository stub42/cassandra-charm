#!.venv/bin/python3

import os.path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import call, patch

sys.path.append(os.path.abspath(os.path.join(
    os.path.dirname(__file__), os.pardir, 'hooks')))

from charmhelpers.core import hookenv
import charmhelpers.fetch

import actions
import helpers


@patch('helpers.is_lxc', lambda: False)
class TestsActions(unittest.TestCase):

    def setUp(self):
        # Mock charm environment variables.
        charm_dir = tempfile.TemporaryDirectory()
        self.addCleanup(charm_dir.cleanup)
        mock_env = patch.dict(os.environ, dict(CHARM_DIR=charm_dir.name))
        mock_env.start()
        self.addCleanup(mock_env.stop)

        # Magic mock charm-helpers.
        methods = [
            'charmhelpers.core.hookenv.log',
            'actions.log',
        ]
        for m in methods:
            mock = patch(m)
            mock.start()
            self.addCleanup(mock.stop)

    @patch('charmhelpers.core.hookenv.hook_name', lambda: 'install')
    @patch('subprocess.check_call')
    def test_preinstall(self, check_call):
        # Noop if there are no preinstall hooks found.
        actions.preinstall('')
        self.assertFalse(check_call.called)

        hook_dirs = []
        hook_files = []
        for i in range(1, 3):
            hook_dirs.append(os.path.join(hookenv.charm_dir(),
                                          'exec.d', str(i)))
            hook_files.append(os.path.join(hook_dirs[-1], 'charm-pre-install'))

            os.makedirs(hook_dirs[-1])
            with open(hook_files[-1], 'w') as f:
                print('mocked', file=f)
            os.chmod(hook_files[-1], 0o755)

        check_call.reset_mock()
        actions.preinstall('')

        calls = [call(['sh', '-c', f]) for f in hook_files]
        check_call.assert_has_calls(calls)

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

    @patch('charmhelpers.core.host.write_file')
    @patch('subprocess.check_call')
    def test_reset_sysctl(self, check_call, write_file):
        actions.reset_sysctl('')

        ctl_file = '/etc/sysctl.d/99-cassandra.conf'
        # Magic value per Cassandra best practice.
        write_file.assert_called_once_with(ctl_file,
                                           "vm.max_map_count = 131072\n")
        check_call.assert_called_once_with(['sysctl', '-p',
                                            '/etc/sysctl.d/99-cassandra.conf'])

    @patch('subprocess.Popen')
    @patch('charmhelpers.core.hookenv.config')
    def test_ensure_package_status(self, config, popen):
        for status in ['install', 'hold']:
            with self.subTest(status=status):
                popen.reset_mock()
                config.return_value = hookenv.Config(
                    dict(package_status=status))
                actions.ensure_package_status('', ['a_pack', 'b_pack'])

                selections = 'a_pack {}\nb_pack {}\n'.format(status, status)

                self.assertEqual([
                    call(['dpkg', '--set-selections'], stdin=subprocess.PIPE),
                    call().communicate(input=selections),
                    ], popen.mock_calls)


if __name__ == '__main__':
    unittest.main(verbosity=2)
