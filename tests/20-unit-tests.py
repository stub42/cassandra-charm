#!.venv/bin/python3

import os.path
import subprocess
import sys
import tempfile
from textwrap import dedent
import unittest
from unittest.mock import call, patch
import yaml

sys.path.append(os.path.abspath(os.path.join(
    os.path.dirname(__file__), os.pardir, 'hooks')))

from charmhelpers.core import hookenv
import charmhelpers.fetch

import actions
import helpers


def mock_config(config_dict):
    c = hookenv.Config(config_dict)
    def config(scope=None):
        if scope is None:
            return c
        return c.get(scope, None)
    return config


class TestsActions(unittest.TestCase):

    def setUp(self):
        # Mock charm environment variables.
        charm_dir = tempfile.TemporaryDirectory()
        self.addCleanup(charm_dir.cleanup)
        mock_env = patch.dict(os.environ, dict(CHARM_DIR=charm_dir.name))
        mock_env.start()
        self.addCleanup(mock_env.stop)

        # Magic mocks.
        methods = [
            'helpers.is_lxc',
            'charmhelpers.core.hookenv.log',
            'charmhelpers.core.host.log',
            'actions.log',
            'charmhelpers.core.hookenv.hook_name',
            'charmhelpers.core.hookenv.service_name',
            'charmhelpers.core.hookenv.unit_private_ip',
        ]
        for m in methods:
            mock = patch(m, autospec=True)
            mock.start()
            self.addCleanup(mock.stop)

        helpers.is_lxc.return_value = False
        hookenv.unit_private_ip.return_value = '10.6.6.6'
        hookenv.service_name.return_value = 'cassandra'

    @patch('subprocess.check_call')
    def test_preinstall(self, check_call):
        hookenv.hook_name.return_value = 'install'
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

    @patch('helpers.autostart_disabled')
    @patch('charmhelpers.fetch.apt_install')
    @patch('charmhelpers.core.hookenv.config')
    def test_install_packages(self, config, apt_install, autostart_disabled):
        packages = ['a_pack', 'b_pack']
        config.side_effect = mock_config(dict(extra_packages='c_pack d_pack'))
        actions.install_packages('', packages)

        # All packages got installed, and hook aborted if package
        # installation failed.
        apt_install.assert_called_once_with(['a_pack', 'b_pack',
                                             'c_pack', 'd_pack'], fatal=True)

        # The autostart_disabled context manager was used to stop
        # package installation starting services.
        autostart_disabled().__enter__.assert_called_once_with()
        autostart_disabled().__exit__.assert_called_once_with(None, None, None)

    @patch('helpers.ensure_directories')
    @patch('helpers.get_seeds')
    @patch('charmhelpers.core.host.write_file')
    @patch('charmhelpers.core.hookenv.config')
    def test_configure_cassandra_yaml(self, config, write_file,
                                      get_seeds, ensure_directories):
        config.side_effect = mock_config(
            dict(num_tokens=128,
                 cluster_name=None,
                 partitioner='my_partitioner'))

        helpers.get_seeds.return_value = ['10.9.8.7', '6.5.4.3']

        existing_config = '''
            seed_provider:
                - class_name: blah.blah.SimpleSeedProvider
                  parameters:
                      - seeds: 127.0.0.1  # Comma separated list.
            '''

        with tempfile.NamedTemporaryFile('wb') as yaml_config:
            yaml_config.write(existing_config.encode('utf8'))
            yaml_config.flush()

            actions.configure_cassandra_yaml('', yaml_config.name)

            self.assertEqual(write_file.call_count, 2)
            new_config = write_file.call_args[0][1]

            expected_config = dedent('''\
                cluster_name: cassandra
                listen_address: 10.6.6.6
                native_transport_port: 9042
                num_tokens: 128
                partitioner: my_partitioner
                rpc_address: 10.6.6.6
                rpc_port: 9160
                seed_provider:
                    - class_name: blah.blah.SimpleSeedProvider
                      parameters:
                        - seeds: '10.9.8.7,6.5.4.3'
                ''')
            self.assertEqual(yaml.safe_load(new_config),
                             yaml.safe_load(expected_config))

            # Confirm we can use an explicit cluster_name too.
            write_file.reset_mock()
            config()['cluster_name'] = 'fubar'
            actions.configure_cassandra_yaml('', yaml_config.name)
            new_config = write_file.call_args[0][1]
            self.assertEqual(yaml.safe_load(new_config)['cluster_name'],
                             'fubar')

if __name__ == '__main__':
    unittest.main(verbosity=2)
