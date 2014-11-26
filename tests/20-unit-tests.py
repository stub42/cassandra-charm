#!.venv/bin/python3

import os.path
import subprocess
import sys
import tempfile
from textwrap import dedent
import unittest
from unittest.mock import call, patch
import yaml

CHARM_DIR = os.path.abspath(os.path.join(
    os.path.dirname(__file__), os.pardir))
sys.path.append(CHARM_DIR)
sys.path.append(os.path.join(CHARM_DIR, 'hooks'))

from charmhelpers.core import hookenv, host

import actions
import helpers
from testing.mocks import mock_charmhelpers


class TestCaseBase(unittest.TestCase):
    def setUp(self):
        super(TestCaseBase, self).setUp()
        mock_charmhelpers(self)

        is_lxc = patch('helpers.is_lxc', autospec=True, return_value=False)
        is_lxc.start()
        self.addCleanup(is_lxc.stop)


class TestsActions(TestCaseBase):
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
            with open(hook_files[-1], 'w') as f1:
                print('mocked', file=f1)
            os.chmod(hook_files[-1], 0o755)

        check_call.reset_mock()
        actions.preinstall('')

        calls = [call(['sh', '-c', f2]) for f2 in hook_files]
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

    @patch('helpers.autostart_disabled')
    @patch('charmhelpers.fetch.apt_install')
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

    @patch('helpers.ensure_directories')
    @patch('helpers.get_seeds')
    @patch('charmhelpers.core.host.write_file')
    def test_configure_cassandra_yaml(self, write_file,
                                      get_seeds, ensure_directories):
        hookenv.config().update(dict(num_tokens=128,
                                     cluster_name=None,
                                     partitioner='my_partitioner'))

        helpers.get_seeds.return_value = ['10.20.0.1', '10.20.0.2',
                                          '10.20.0.3']

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
            actions.configure_cassandra_yaml('', yaml_config.name)
            new_config = write_file.call_args[0][1]
            self.assertEqual(yaml.safe_load(new_config)['cluster_name'],
                             'fubar')


class TestHelpers(TestCaseBase):
    def test_autostart_disabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:

            prc = os.path.join(tmpdir, 'policy-rc.d')
            prc_backup = prc + '-orig'

            with helpers.autostart_disabled(prc):
                # No existing policy-rc.d, so no backup made.
                self.assertFalse(os.path.exists(prc_backup))

                # A policy-rc.d file has been created that will disable
                # package autostart per spec (ie. returns a 101 exit code).
                self.assertTrue(os.path.exists(prc))
                self.assertEqual(subprocess.call([prc]), 101)

                with helpers.autostart_disabled(prc):
                    # A second time, we have a backup made.
                    # policy-rc.d still works
                    self.assertTrue(os.path.exists(prc_backup))
                    self.assertEqual(subprocess.call([prc]), 101)

                # Backup removed, and policy-rc.d still works.
                self.assertFalse(os.path.exists(prc_backup))
                self.assertEqual(subprocess.call([prc]), 101)

            # Neither backup nor policy-rc.d exist now we are out of the
            # context manager.
            self.assertFalse(os.path.exists(prc_backup))
            self.assertFalse(os.path.exists(prc))

    def test_get_seeds_forced(self):
        hookenv.config()['force_seed_nodes'] = 'a,b,c'
        self.assertEqual(['a', 'b', 'c'], sorted(helpers.get_seeds()))

    def test_get_seeds(self):
        self.assertEqual(
            sorted(['10.20.0.1', '10.20.0.2', '10.20.0.3']),
            sorted(helpers.get_seeds()))

    @patch('helpers.set_io_scheduler')
    @patch('charmhelpers.core.host.mkdir')
    @patch('relations.BlockStorageBroker', autospec=True)
    def test_ensure_directories_mounted(self, bsb, mkdir, set_io_scheduler):
        with tempfile.TemporaryDirectory() as tmpdir:
            bsb().mountpoint = tmpdir
            bsb().is_ready.return_value = True

            helpers.ensure_directories()

        for dir in ['data', 'commitlog', 'saved_caches']:
            with self.subTest(dir=dir):
                path = os.path.join(tmpdir, dir)
                host.mkdir.assert_any_call(path, owner='cassandra',
                                           group='cassandra', perms=0o755)
                set_io_scheduler.assert_any_call('noop', path)

    @patch('helpers.set_io_scheduler')
    @patch('charmhelpers.core.host.mkdir')
    @patch('relations.BlockStorageBroker', autospec=True)
    def test_ensure_directories_unmounted(self, bsb, mkdir, set_io_scheduler):
        bsb().is_ready.return_value = True
        bsb().mountpoint = None

        helpers.ensure_directories()

        for dir in ['data', 'commitlog', 'saved_caches']:
            with self.subTest(dir=dir):
                path = os.path.join('/var/lib/cassandra', dir)
                host.mkdir.assert_any_call(path, owner='cassandra',
                                           group='cassandra', perms=0o755)
                set_io_scheduler.assert_any_call('noop', path)

    @patch('helpers.set_io_scheduler')
    @patch('charmhelpers.core.host.mkdir')
    @patch('relations.BlockStorageBroker', autospec=True)
    def test_ensure_directories_overrides(self, bsb, mkdir, set_io_scheduler):
        hookenv.config()['io_scheduler'] = 'foo-sched'
        with tempfile.TemporaryDirectory() as tmpdir:
            bsb().mountpoint = tmpdir
            bsb().is_ready.return_value = True
            hookenv.config()['data_file_directories'] = 'd1 d2'
            hookenv.config()['commitlog_directory'] = 'cl'
            hookenv.config()['saved_caches_directory'] = 'scd'

            helpers.ensure_directories()

        for dir in ['d1', 'd2', 'cl', 'scd']:
            with self.subTest(dir=dir):
                path = os.path.join(tmpdir, dir)
                host.mkdir.assert_any_call(path, owner='cassandra',
                                           group='cassandra', perms=0o755)
                set_io_scheduler.assert_any_call('foo-sched', path)

    @patch('helpers.set_io_scheduler')
    @patch('charmhelpers.core.host.mkdir')
    @patch('relations.BlockStorageBroker', autospec=True)
    def test_ensure_directories_abspath(self, bsb, mkdir, set_io_scheduler):
        with tempfile.TemporaryDirectory() as tmpdir:
            bsb().mountpoint = tmpdir
            bsb().is_ready.return_value = True
            hookenv.config()['data_file_directories'] = '/d'
            hookenv.config()['commitlog_directory'] = '/cl'
            hookenv.config()['saved_caches_directory'] = '/scd'

            helpers.ensure_directories()

        for path in ['/d', '/cl', '/scd']:
            with self.subTest(path=path):
                host.mkdir.assert_any_call(path, owner='cassandra',
                                           group='cassandra', perms=0o755)
                set_io_scheduler.assert_any_call('noop', path)

    @patch('charmhelpers.core.host.write_file')
    @patch('os.path.isdir')
    @patch('subprocess.check_output')
    def test_set_io_scheduler(self, check_output, isdir, write_file):
        check_output.return_value = 'foo\n/dev/sdq 1 2 3 1% /foo\n'
        isdir.return_value = True

        helpers.set_io_scheduler('fnord', '/foo')

        write_file.assert_called_once_with('/sys/block/sdq/queue/scheduler',
                                           'fnord', perms=0o644)


class TestIsLxc(unittest.TestCase):
    def test_is_lxc(self):
        # Test the function runs under the current environmnet.
        # Unfortunately we can't sanely test that it is returning the
        # correct value
        helpers.is_lxc()


if __name__ == '__main__':
    unittest.main(verbosity=2)
