#!.venv3/bin/python3

import errno
import os.path
import re
import subprocess
import tempfile
from textwrap import dedent
import unittest
from unittest.mock import ANY, call, patch, sentinel
import yaml

from charmhelpers.core import hookenv

from tests.base import TestCaseBase
import actions
import helpers


class TestsActions(TestCaseBase):
    @patch('subprocess.check_call', autospec=True)
    def test_preinstall(self, check_call):
        # Noop if there are no preinstall hooks found running the
        # install hook.
        hookenv.hook_name.return_value = 'install'
        actions.preinstall('')
        self.assertFalse(check_call.called)
        hookenv.log.assert_called_once_with('No preinstall hooks found')

        # If preinstall hooks are found running the install hook,
        # the preinstall hooks are run.
        hook_dirs = []
        hook_files = []
        for i in range(1, 3):
            hook_dirs.append(os.path.join(hookenv.charm_dir(),
                                          'exec.d', str(i)))
            hook_files.append(os.path.join(hook_dirs[-1], 'charm-pre-install'))

            os.makedirs(hook_dirs[-1])
            with open(hook_files[-1], 'w') as f1:
                print('mocked', file=f1)
            os.chmod(hook_files[-1], 0o755)

        check_call.reset_mock()
        actions.preinstall('')

        calls = [call(['sh', '-c', f2]) for f2 in hook_files]
        check_call.assert_has_calls(calls)

        # If a preinstall hook is not executable, a warning is raised.
        hook_dir = os.path.join(hookenv.charm_dir(), 'exec.d', '55')
        hook_file = os.path.join(hook_dir, 'charm-pre-install')
        os.makedirs(hook_dir)
        with open(hook_file, 'w') as f1:
            print('whoops', file=f1)
        os.chmod(hook_file, 0o644)
        check_call.reset_mock()
        hookenv.log.reset_mock()
        actions.preinstall('')
        check_call.assert_has_calls(calls)  # Only previous hooks run.
        hookenv.log.assert_has_calls([
            call(ANY),
            call(ANY),
            call(ANY, hookenv.WARNING)])

        # Nothing happens if the install hook is not being run.
        hookenv.hook_name.return_value = 'config-changed'
        check_call.reset_mock()
        actions.preinstall('')
        self.assertFalse(check_call.called)

    @patch('subprocess.check_call', autospec=True)
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

    @patch('subprocess.check_call', autospec=True)
    def test_swapoff_fails(self, check_call):
        check_call.side_effect = RuntimeError()
        actions.swapoff('', '')
        # A warning is generated if swapoff fails.
        hookenv.log.assert_called_once_with(ANY, hookenv.WARNING)

    @patch('charmhelpers.fetch.configure_sources', autospec=True)
    def test_configure_sources(self, configure_sources):
        config = hookenv.config()

        # fetch.configure_sources called the first time
        actions.configure_sources('')
        configure_sources.assert_called_once_with(True)

        # fetch.configure_sources not called if relevant config is unchanged.
        config.save()
        config.load_previous()
        configure_sources.reset_mock()
        actions.configure_sources('')
        self.assertFalse(configure_sources.called)

        # Changing install_sources causes fetch.configure_sources to be
        # called.
        config.save()
        config.load_previous()
        configure_sources.reset_mock()
        config['install_sources'] = 'foo'
        actions.configure_sources('')
        configure_sources.assert_called_once_with(True)

        # Changing install_keys causes fetch.configure_sources to be
        # called.
        config.save()
        config.load_previous()
        configure_sources.reset_mock()
        config['install_keys'] = 'foo'
        actions.configure_sources('')
        configure_sources.assert_called_once_with(True)

    @patch('charmhelpers.core.host.write_file', autospec=True)
    @patch('subprocess.check_call', autospec=True)
    def test_reset_sysctl(self, check_call, write_file):
        actions.reset_sysctl('')

        ctl_file = '/etc/sysctl.d/99-cassandra.conf'
        # Magic value per Cassandra best practice.
        write_file.assert_called_once_with(ctl_file,
                                           "vm.max_map_count = 131072\n")
        check_call.assert_called_once_with(['sysctl', '-p',
                                            '/etc/sysctl.d/99-cassandra.conf'])

    @patch('subprocess.check_call', autospec=True)
    @patch('charmhelpers.core.host.write_file', autospec=True)
    def test_reset_sysctl_expected_fails(self, write_file, check_call):
        check_call.side_effect = OSError(errno.EACCES, 'Permission Denied')
        actions.reset_sysctl('')
        # A warning is generated if permission denied was raised.
        hookenv.log.assert_called_once_with(ANY, hookenv.WARNING)

    @patch('subprocess.check_call', autospec=True)
    @patch('charmhelpers.core.host.write_file', autospec=True)
    def test_reset_sysctl_expected_fails_badly(self, write_file, check_call):
        # Other OSErrors are reraised since we don't know how to handle
        # them.
        check_call.side_effect = OSError(errno.EFAULT, 'Whoops')
        self.assertRaises(OSError, actions.reset_sysctl, '')

    @patch('subprocess.Popen', autospec=True)
    def test_ensure_package_status(self, popen):
        for status in ['install', 'hold']:
            with self.subTest(status=status):
                popen.reset_mock()
                hookenv.config()['package_status'] = status
                actions.ensure_package_status('', ['a_pack', 'b_pack'])

                selections = 'a_pack {}\nb_pack {}\n'.format(
                    status, status).encode('US-ASCII')

                self.assertEqual([
                    call(['dpkg', '--set-selections'], stdin=subprocess.PIPE),
                    call().communicate(input=selections),
                    ], popen.mock_calls)

    @patch('helpers.autostart_disabled', autospec=True)
    @patch('charmhelpers.fetch.apt_install', autospec=True)
    def test_install_packages(self, apt_install, autostart_disabled):
        packages = ['a_pack', 'b_pack']
        hookenv.config()['extra_packages'] = 'c_pack d_pack'
        actions.install_packages('', packages)

        # All packages got installed, and hook aborted if package
        # installation failed.
        apt_install.assert_called_once_with(['a_pack', 'b_pack',
                                             'c_pack', 'd_pack'], fatal=True)

        # The autostart_disabled context manager was used to stop
        # package installation starting services.
        autostart_disabled().__enter__.assert_called_once_with()
        autostart_disabled().__exit__.assert_called_once_with(None, None, None)

    @patch('helpers.get_cassandra_yaml_file', autospec=True)
    @patch('helpers.ensure_directories', autospec=True)
    @patch('helpers.get_seeds', autospec=True)
    @patch('charmhelpers.core.host.write_file', autospec=True)
    def test_configure_cassandra_yaml(self, write_file, get_seeds,
                                      ensure_directories, yaml_file):
        hookenv.config().update(dict(num_tokens=128,
                                     cluster_name=None,
                                     partitioner='my_partitioner'))

        get_seeds.return_value = ['10.20.0.1', '10.20.0.2', '10.20.0.3']

        existing_config = '''
            seed_provider:
                - class_name: blah.blah.SimpleSeedProvider
                  parameters:
                      - seeds: 127.0.0.1  # Comma separated list.
            '''

        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_config = os.path.join(tmpdir, 'c.yaml')
            yaml_file.return_value = yaml_config
            with open(yaml_config, 'w', encoding='UTF-8') as f:
                f.write(existing_config)

            actions.configure_cassandra_yaml('')

            self.assertEqual(write_file.call_count, 2)
            new_config = write_file.call_args[0][1]

            expected_config = dedent('''\
                cluster_name: service
                listen_address: 10.20.0.1
                native_transport_port: 9042
                num_tokens: 128
                partitioner: my_partitioner
                rpc_address: 10.20.0.1
                rpc_port: 9160
                seed_provider:
                    - class_name: blah.blah.SimpleSeedProvider
                      parameters:
                        - seeds: '10.20.0.1, 10.20.0.2, 10.20.0.3'
                ''')
            self.assertEqual(yaml.safe_load(new_config),
                             yaml.safe_load(expected_config))

            # Confirm we can use an explicit cluster_name too.
            write_file.reset_mock()
            hookenv.config()['cluster_name'] = 'fubar'
            actions.configure_cassandra_yaml('')
            new_config = write_file.call_args[0][1]
            self.assertEqual(yaml.safe_load(new_config)['cluster_name'],
                             'fubar')

    @patch('helpers.get_cassandra_env_file', autospec=True)
    @patch('charmhelpers.core.host.write_file', autospec=True)
    def test_configure_cassandra_env(self, write_file, env_file):
        def _wf(path, contents):
            with open(path, 'wb') as f:
                f.write(contents)
        write_file.side_effect = _wf

        # cassandra-env.sh is a shell script that unfortunately
        # embeds configuration we need to change.
        existing_config = dedent('''\
                                 Everything is ignored
                                 unless a regexp matches
                                 #MAX_HEAP_SIZE="1G"
                                 #HEAP_NEWSIZE="800M"
                                 And done
                                 ''')

        with tempfile.TemporaryDirectory() as tempdir:
            cassandra_env = os.path.join(tempdir, 'c.sh')
            env_file.return_value = cassandra_env

            with open(cassandra_env, 'w', encoding='UTF-8') as f:
                f.write(existing_config)

            overrides = [
                ('max_heap_size', re.compile('^MAX_HEAP_SIZE=(.*)$', re.M)),
                ('heap_newsize', re.compile('^HEAP_NEWSIZE=(.*)$', re.M)),
            ]

            # By default, nothing is overrridden. The settings will be
            # commented out.
            actions.configure_cassandra_env('')
            with open(cassandra_env, 'r', encoding='UTF-8') as f:
                generated_env = f.read()
            for config_key, regexp in overrides:
                with self.subTest(override=config_key):
                    self.assertIsNone(regexp.search(generated_env))

            # Settings can be overridden.
            for config_key, regexp in overrides:
                hookenv.config()[config_key] = '{} val'.format(config_key)
            actions.configure_cassandra_env('')
            with open(cassandra_env, 'r') as f:
                generated_env = f.read()
            for config_key, regexp in overrides:
                with self.subTest(override=config_key):
                    match = regexp.search(generated_env)
                    self.assertIsNotNone(match)
                    # Note the value has been shell quoted.
                    self.assertTrue(
                        match.group(1).startswith(
                            "'{} val'".format(config_key)))

            # Settings can be returned to the defaults.
            for config_key, regexp in overrides:
                hookenv.config()[config_key] = ''
            actions.configure_cassandra_env('')
            with open(cassandra_env, 'r', encoding='UTF-8') as f:
                generated_env = f.read()
            for config_key, regexp in overrides:
                with self.subTest(override=config_key):
                    self.assertIsNone(regexp.search(generated_env))

    @patch('charmhelpers.contrib.peerstorage.peer_echo')
    def test_peer_echo(self, peer_echo):
        # peerstorage.peer_echo is not called from most hooks.
        hookenv.hook_name.return_value = 'cluster-relation-joined'
        actions.peer_echo('', includes=sentinel.peer_includes)
        self.assertFalse(peer_echo.called)

        # peerstorage.peer_echo is only called from the peer
        # relation-changed hook.
        hookenv.hook_name.return_value = 'cluster-relation-changed'
        actions.peer_echo('', includes=sentinel.peer_includes)
        peer_echo.assert_called_once_with(sentinel.peer_includes)

    @patch('helpers.rolling_restart')
    def test_rolling_restart(self, restart):
        restart.return_value = False

        # If there is no request, nothing happens
        actions.rolling_restart('')
        self.assertFalse(restart.called)

        # After a request, rolling_restart keeps being called...
        helpers.request_rolling_restart()
        actions.rolling_restart('')
        self.assertEqual(restart.call_count, 1)
        actions.rolling_restart('')
        self.assertEqual(restart.call_count, 2)

        # ... until it succeeds ...
        restart.return_value = True
        actions.rolling_restart('')
        self.assertEqual(restart.call_count, 3)

        # ... and stops again.
        actions.rolling_restart('')
        self.assertEqual(restart.call_count, 3)

if __name__ == '__main__':
    unittest.main(verbosity=2)
