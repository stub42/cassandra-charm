#!.venv3/bin/python3

from collections import namedtuple
import errno
import os.path
import subprocess
import tempfile
import unittest
from unittest.mock import ANY, call, patch, sentinel

from charmhelpers.core import hookenv, host

from tests.base import TestCaseBase
import helpers


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

    @patch('helpers.recursive_chown', autospec=True)
    @patch('helpers.set_io_scheduler', autospec=True)
    @patch('charmhelpers.core.host.mkdir', autospec=True)
    @patch('relations.BlockStorageBroker', autospec=True)
    def test_ensure_directories_mounted(self, bsb, mkdir, set_io_scheduler,
                                        recursive_chown):
        # Directories are relative to the external mount
        # point if there is one.
        with tempfile.TemporaryDirectory() as tmpdir:
            bsb().mountpoint = tmpdir
            bsb().is_ready.return_value = True

            helpers.ensure_directories()

        for dir in ['data', 'commitlog', 'saved_caches']:
            with self.subTest(dir=dir):
                path = os.path.join(tmpdir, dir)
                host.mkdir.assert_any_call(path, owner='cassandra',
                                           group='cassandra', perms=0o755)
                recursive_chown.assert_any_call(path, owner='cassandra',
                                                group='cassandra')
                set_io_scheduler.assert_any_call('noop', path)

    @patch('helpers.recursive_chown', autospec=True)
    @patch('helpers.set_io_scheduler', autospec=True)
    @patch('charmhelpers.core.host.mkdir', autospec=True)
    @patch('relations.BlockStorageBroker', autospec=True)
    def test_ensure_directories_unmounted(self, bsb, mkdir, set_io_scheduler,
                                          recursive_chown):
        # Directories are relative to the /var/lib/cassandra
        # if there is no external mount.
        bsb().is_ready.return_value = True
        bsb().mountpoint = None

        helpers.ensure_directories()

        for dir in ['data', 'commitlog', 'saved_caches']:
            with self.subTest(dir=dir):
                path = os.path.join('/var/lib/cassandra', dir)
                host.mkdir.assert_any_call(path, owner='cassandra',
                                           group='cassandra', perms=0o755)
                recursive_chown.assert_any_call(path, owner='cassandra',
                                                group='cassandra')
                set_io_scheduler.assert_any_call('noop', path)

    @patch('helpers.recursive_chown', autospec=True)
    @patch('helpers.set_io_scheduler', autospec=True)
    @patch('charmhelpers.core.host.mkdir', autospec=True)
    @patch('relations.BlockStorageBroker', autospec=True)
    def test_ensure_directories_overrides(self, bsb, mkdir, set_io_scheduler,
                                          recursive_chown):
        # Directory names may be overridden in the service level
        # configuration.
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
                recursive_chown.assert_any_call(path, owner='cassandra',
                                                group='cassandra')
                set_io_scheduler.assert_any_call('foo-sched', path)

    @patch('helpers.recursive_chown', autospec=True)
    @patch('helpers.set_io_scheduler', autospec=True)
    @patch('charmhelpers.core.host.mkdir', autospec=True)
    @patch('relations.BlockStorageBroker', autospec=True)
    def test_ensure_directories_abspath(self, bsb, mkdir, set_io_scheduler,
                                        recursive_chown):
        # Directory overrides in the service level configuration may be
        # absolute paths.
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
                recursive_chown.assert_any_call(path, owner='cassandra',
                                                group='cassandra')
                set_io_scheduler.assert_any_call('noop', path)

    @patch('charmhelpers.core.host.write_file', autospec=True)
    @patch('os.path.isdir', autospec=True)
    @patch('subprocess.check_output', autospec=True)
    def test_set_io_scheduler(self, check_output, isdir, write_file):
        # Normal operation, the device is detected and the magic
        # file written.
        check_output.return_value = 'foo\n/dev/sdq 1 2 3 1% /foo\n'
        isdir.return_value = True

        helpers.set_io_scheduler('fnord', '/foo')

        write_file.assert_called_once_with('/sys/block/sdq/queue/scheduler',
                                           'fnord', perms=0o644)

        # Some OSErrors we log warnings for, and continue.
        for e in (errno.EACCES, errno.ENOENT):
            write_file.side_effect = OSError(e, 'Whoops')
            hookenv.log.reset_mock()
            helpers.set_io_scheduler('fnord', '/foo')
            hookenv.log.assert_has_calls([call(ANY),
                                          call(ANY, hookenv.WARNING)])

        # Other OSErrors just fail hard.
        write_file.side_effect = OSError(errno.EFAULT, 'Whoops')
        self.assertRaises(OSError, helpers.set_io_scheduler, 'fnord', '/foo')

        # If we are not under lxc, nothing happens at all except a log
        # message.
        helpers.is_lxc.return_value = True
        hookenv.log.reset_mock()
        write_file.reset_mock()
        helpers.set_io_scheduler('fnord', '/foo')
        self.assertFalse(write_file.called)
        hookenv.log.assert_called_once_with(ANY)  # A single INFO message.

    @patch('shutil.chown', autospec=True)
    def test_recursive_chown(self, chown):
        with tempfile.TemporaryDirectory() as tmpdir:
            os.makedirs(os.path.join(tmpdir, 'a', 'bb', 'ccc'))
            with open(os.path.join(tmpdir, 'top file'), 'w') as f:
                f.write('top file')
            with open(os.path.join(tmpdir, 'a', 'bb', 'midfile'), 'w') as f:
                f.write('midfile')
            helpers.recursive_chown(tmpdir, 'un', 'gn')
        chown.assert_has_calls(
            [call(os.path.join(tmpdir, 'a'), 'un', 'gn'),
             call(os.path.join(tmpdir, 'a', 'bb'), 'un', 'gn'),
             call(os.path.join(tmpdir, 'a', 'bb', 'ccc'), 'un', 'gn'),
             call(os.path.join(tmpdir, 'top file'), 'un', 'gn'),
             call(os.path.join(tmpdir, 'a', 'bb', 'midfile'), 'un', 'gn')],
            any_order=True)

    def test_maybe_backup(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Our file is backed up to a .orig
            path = os.path.join(tmpdir, 'foo.conf')
            host.write_file(path, b'hello', perms=0o644)
            helpers.maybe_backup(path)
            path_orig = path + '.orig'
            self.assertTrue(os.path.exists(path_orig))
            with open(path_orig, 'rb') as f:
                self.assertEqual(f.read(), b'hello')
            # Safe permissions
            self.assertEqual(os.lstat(path_orig).st_mode & 0o777, 0o600)

            # A second call, nothing happens as the .orig is already
            # there.
            host.write_file(path, b'second')
            helpers.maybe_backup(path)
            with open(path_orig, 'rb') as f:
                self.assertEqual(f.read(), b'hello')

    @patch('charmhelpers.fetch.apt_cache', autospec=True)
    def test_get_package_version(self, apt_cache):
        version = namedtuple('Version', 'ver_str')('1.0-foo')
        package = namedtuple('Package', 'current_ver')(version)
        apt_cache.return_value = dict(package=package)
        ver = helpers.get_package_version('package')
        self.assertEqual(ver, '1.0-foo')

    @patch('charmhelpers.fetch.apt_cache', autospec=True)
    def test_get_package_version_not_found(self, apt_cache):
        version = namedtuple('Version', 'ver_str')('1.0-foo')
        package = namedtuple('Package', 'current_ver')(version)
        apt_cache.return_value = dict(package=package)
        self.assertIsNone(helpers.get_package_version('notfound'))

    @patch('charmhelpers.fetch.apt_cache', autospec=True)
    def test_get_package_version_not_installed(self, apt_cache):
        package = namedtuple('Package', 'current_ver')(None)
        apt_cache.return_value = dict(package=package)
        self.assertIsNone(helpers.get_package_version('package'))

    def test_get_jvm(self):
        hookenv.config()['jvm'] = 'opEnjdk'  # Case insensitive
        self.assertEqual(helpers.get_jvm(), 'openjdk')

        hookenv.config()['jvm'] = 'oRacle'  # Case insensitive
        self.assertEqual(helpers.get_jvm(), 'oracle')

    def test_get_jvm_unknown(self):
        hookenv.config()['jvm'] = 'OopsJDK'
        self.assertEqual(helpers.get_jvm(), 'openjdk')
        # An error was logged.
        hookenv.log.assert_called_once_with(ANY, hookenv.ERROR)

    def test_get_jvm_dse_override(self):
        hookenv.config()['edition'] = 'dse'
        self.assertEqual(helpers.get_jvm(), 'oracle')

    def test_get_cassandra_service(self):
        self.assertEqual(helpers.get_cassandra_service(), 'cassandra')

    def test_get_cassandra_service_dse_override(self):
        hookenv.config()['edition'] = 'dse'
        self.assertEqual(helpers.get_cassandra_service(), 'dse')

    @patch('helpers.get_package_version', autospec=True)
    def test_get_cassandra_version(self, get_package_version):
        # Return cassandra package version if it is installed.
        get_package_version.return_value = '1.2.3-2~64'
        self.assertEqual(helpers.get_cassandra_version(), '1.2.3-2~64')
        get_package_version.assert_called_with('cassandra')

    @patch('helpers.get_package_version', autospec=True)
    def test_get_cassandra_version_uninstalled(self, get_package_version):
        # Return none if the main cassandra package is not installed
        get_package_version.return_value = None
        self.assertEqual(helpers.get_cassandra_version(), None)
        get_package_version.assert_called_with('cassandra')

    @patch('helpers.get_package_version', autospec=True)
    def test_get_cassandra_version_dse(self, get_package_version):
        # Return the cassandra version equivalent if using dse.
        hookenv.config()['edition'] = 'dse'
        get_package_version.return_value = '4.5-beta2~88'
        self.assertEqual(helpers.get_cassandra_version(), '2.1')
        get_package_version.assert_called_with('dse-full')

    @patch('helpers.get_package_version', autospec=True)
    def test_get_cassandra_version_dse_uninstalled(self, get_package_version):
        # Return the cassandra version equivalent if using dse.
        hookenv.config()['edition'] = 'dse'
        get_package_version.return_value = None
        self.assertEqual(helpers.get_cassandra_version(), None)
        get_package_version.assert_called_with('dse-full')

    def test_get_cassandra_config_dir(self):
        self.assertEqual(helpers.get_cassandra_config_dir(),
                         '/etc/cassandra')
        hookenv.config()['edition'] = 'dse'
        self.assertEqual(helpers.get_cassandra_config_dir(),
                         '/etc/dse/cassandra')

    @patch('helpers.get_cassandra_config_dir', autospec=True)
    def test_get_cassandra_yaml_file(self, get_cassandra_config_dir):
        get_cassandra_config_dir.return_value = '/foo'
        self.assertEqual(helpers.get_cassandra_yaml_file(),
                         '/foo/cassandra.yaml')

    @patch('helpers.get_cassandra_config_dir', autospec=True)
    def test_get_cassandra_env_file(self, get_cassandra_config_dir):
        get_cassandra_config_dir.return_value = '/foo'
        self.assertEqual(helpers.get_cassandra_env_file(),
                         '/foo/cassandra-env.sh')

    @patch('helpers.get_cassandra_config_dir', autospec=True)
    def test_get_cassandra_rackdc_file(self, get_cassandra_config_dir):
        get_cassandra_config_dir.return_value = '/foo'
        self.assertEqual(helpers.get_cassandra_rackdc_file(),
                         '/foo/cassandra-rackdc.properties')

    @patch('subprocess.Popen', autospec=False)
    def test_accept_oracle_jvm_license(self, popen):
        popen().communicate.return_value = ('', None)
        popen.reset_mock()

        # Fails hard unless a config option specifying the Oracle JVM
        # has been selected.
        self.assertRaises(AssertionError, helpers.accept_oracle_jvm_license)
        self.assertFalse(popen.called)
        self.assertFalse(hookenv.config()[helpers.ORACLE_JVM_ACCEPT_KEY])

        # When the user selects the Oracle JVM in the charm service
        # configuration, they are implicitly accepting the Oracle Java
        # license per the documentation of the option in config.yaml.
        hookenv.config()['jvm'] = 'oracle'

        # If the selection fails, the charm warns and continues to use
        # OpenJDK.
        hookenv.log.reset_mock()
        popen().returncode = 1
        helpers.accept_oracle_jvm_license()
        hookenv.log.assert_any_call(ANY, hookenv.ERROR)
        self.assertFalse(hookenv.config()[helpers.ORACLE_JVM_ACCEPT_KEY])

        # If selection works, the flag is set in the persistent config.
        popen().returncode = 0
        popen.reset_mock()
        helpers.accept_oracle_jvm_license()
        popen.assert_called_once_with(['debconf-set-selections'],
                                      stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT)
        instructions = (b'oracle-java7-installer '
                        b'shared/accepted-oracle-license-v1-1 '
                        b'select true\n')  # trailing newline is required.
        popen().communicate.assert_called_once_with(instructions)
        self.assertTrue(hookenv.config()[helpers.ORACLE_JVM_ACCEPT_KEY])

        # Further calls do nothing.
        popen.reset_mock()
        helpers.accept_oracle_jvm_license()
        self.assertFalse(popen.called)
        self.assertTrue(hookenv.config()[helpers.ORACLE_JVM_ACCEPT_KEY])

    @patch('helpers.accept_oracle_jvm_license', autospec=True)
    def test_get_cassandra_packages(self, accept_oracle_jvm_license):
        # Default
        self.assertSetEqual(helpers.get_cassandra_packages(),
                            set(['cassandra', 'cassandra-tools']))
        self.assertFalse(accept_oracle_jvm_license.called)

    @patch('helpers.accept_oracle_jvm_license', autospec=True)
    def test_get_cassandra_packages_oracle_jvm(self,
                                               accept_oracle_jvm_license):
        # Oracle JVM
        hookenv.config()['jvm'] = 'oracle'
        hookenv.config()[helpers.ORACLE_JVM_ACCEPT_KEY] = True
        self.assertSetEqual(helpers.get_cassandra_packages(),
                            set(['cassandra', 'cassandra-tools',
                                 'oracle-java7-installer',
                                 'oracle-java7-set-default']))
        # It was called. We don't care that the mock did nothing, as
        # we explicitly set the magic config item just before.
        self.assertTrue(accept_oracle_jvm_license.called)

    @patch('helpers.accept_oracle_jvm_license', autospec=True)
    def test_get_cassandra_packages_oracle_jvm_fail(self,
                                                    accept_oracle_jvm_license):
        # If we specified the Oracle JVM, but the license could not be
        # accepted, we fall back to the default jdk.
        hookenv.config()['jvm'] = 'oracle'

        hookenv.config()[helpers.ORACLE_JVM_ACCEPT_KEY] = False
        self.assertSetEqual(helpers.get_cassandra_packages(),
                            set(['cassandra', 'cassandra-tools']))
        self.assertTrue(accept_oracle_jvm_license.called)

    @patch('helpers.accept_oracle_jvm_license', autospec=True)
    def test_get_cassandra_packages_dse(self, accept_oracle_jvm_license):
        # DataStax Enterprise, and implicit Oracle JVM.
        hookenv.config()['edition'] = 'dsE'  # Insensitive.
        hookenv.config()[helpers.ORACLE_JVM_ACCEPT_KEY] = True
        self.assertSetEqual(helpers.get_cassandra_packages(),
                            set(['dse-full',
                                 'oracle-java7-installer',
                                 'oracle-java7-set-default']))
        self.assertTrue(accept_oracle_jvm_license.called)

    @patch('helpers.get_cassandra_service')
    @patch('charmhelpers.core.host.service_stop')
    @patch('helpers.is_cassandra_running', autospec=True)
    def test_stop_cassandra(self, is_cassandra_running,
                            service_stop, get_service):
        get_service.return_value = 'wobbly'
        is_cassandra_running.return_value = False
        helpers.stop_cassandra()
        self.assertFalse(service_stop.called)

        is_cassandra_running.return_value = True
        helpers.stop_cassandra()
        service_stop.assert_called_once_with('wobbly')

    @patch('helpers.get_cassandra_service')
    @patch('charmhelpers.core.host.service_restart')
    @patch('charmhelpers.core.host.service_start')
    @patch('helpers.is_cassandra_running', autospec=True)
    def test_restart_cassandra(self, is_cassandra_running,
                               service_start, service_restart, get_service):
        get_service.return_value = 'wobbly'
        is_cassandra_running.return_value = False
        helpers.restart_cassandra()
        service_start.assert_called_once_with('wobbly')
        self.assertFalse(service_restart.called)

        service_start.reset_mock()
        service_restart.reset_mock()
        is_cassandra_running.return_value = True
        helpers.restart_cassandra()
        self.assertFalse(service_start.called)
        service_restart.assert_called_once_with('wobbly')

    def test_get_pid_from_file(self):
        with tempfile.NamedTemporaryFile('w') as pid_file:
            pid_file.write(' 42\t')
            pid_file.flush()
            self.assertEqual(helpers.get_pid_from_file(pid_file.name), 42)
            pid_file.write('\nSome Noise')
            pid_file.flush()
            self.assertEqual(helpers.get_pid_from_file(pid_file.name), 42)

        for invalid_pid in ['-1', '0', 'fred']:
            with self.subTest(invalid_pid=invalid_pid):
                with tempfile.NamedTemporaryFile('w') as pid_file:
                    pid_file.write(invalid_pid)
                    pid_file.flush()
                    self.assertRaises(ValueError,
                                      helpers.get_pid_from_file, pid_file.name)

        with tempfile.TemporaryDirectory() as tmpdir:
            self.assertRaises(OSError, helpers.get_pid_from_file,
                              os.path.join(tmpdir, 'invalid.pid'))

    @patch('os.path.exists', autospec=True)
    @patch('helpers.get_cassandra_pid_file', autospec=True)
    def test_is_cassandra_running_not_running(self, get_pid_file, exists):
        # When Cassandra is not running, there is no pidfile.
        get_pid_file.return_value = sentinel.pid_file
        exists.return_value = False
        self.assertFalse(helpers.is_cassandra_running())
        exists.assert_called_once_with(sentinel.pid_file)

    @patch('os.path.exists', autospec=True)
    @patch('helpers.get_pid_from_file', autospec=True)
    def test_is_cassandra_running_invalid_pid(self, get_pid_from_file, exists):
        # get_pid_from_file raises a ValueError if the pid is illegal.
        get_pid_from_file.side_effect = ValueError('Whoops')
        exists.return_value = True  # The pid file is there, just insane.

        # is_cassandra_running() fails hard in this case, since we
        # cannot safely continue when the system is insane.
        self.assertRaises(ValueError, helpers.is_cassandra_running)

    @patch('time.sleep', autospec=True)
    @patch('os.kill', autospec=True)
    @patch('helpers.get_pid_from_file', autospec=True)
    @patch('subprocess.call', autospec=True)
    def test_is_cassandra_running_starting_up(self, call, get_pid_from_file,
                                              kill, sleep):
        sleep.return_value = None  # Don't actually sleep in unittests.
        os.kill.return_value = True  # There is a running pid.
        get_pid_from_file.return_value = 42
        subprocess.call.side_effect = iter([3, 2, 1, 0])  # 4th time the charm
        self.assertTrue(helpers.is_cassandra_running())

    @patch('time.sleep', autospec=True)
    @patch('os.kill', autospec=True)
    @patch('subprocess.call', autospec=True)
    @patch('os.path.exists', autospec=True)
    @patch('helpers.get_pid_from_file', autospec=True)
    def test_is_cassandra_running_shutting_down(self, get_pid_from_file,
                                                exists, call, kill, sleep):
        # If Cassandra is in the process of shutting down, it might take
        # several failed checks before the pid file disappears.
        os.kill.return_value = None  # The process is running
        call.return_value = 1  # But nodetool is not succeeding.
        sleep.return_value = None  # Don't actually sleep in unittests.

        # Fourth time, the pid file is gone.
        get_pid_from_file.side_effect = iter([42, 42, 42, OSError('Whoops')])
        exists.return_value = False
        self.assertFalse(helpers.is_cassandra_running())
        exists.assert_called_once_with(helpers.get_cassandra_pid_file())

    @patch('time.sleep')
    @patch('os.kill')
    @patch('subprocess.call')
    @patch('os.path.exists')
    @patch('helpers.get_pid_from_file')
    def test_is_cassandra_running_hung(self, get_pid, exists, subprocess_call,
                                       kill, sleep):
        get_pid.return_value = 42  # The pid is known.
        os.kill.return_value = None  # The process is running.
        subprocess_call.return_value = 1  # nodetool is failing.
        sleep.return_value = None  # Don't actually sleep between retries.

        self.assertRaises(SystemExit, helpers.is_cassandra_running)

        # Binary backoff up to 256 seconds, or up to 8.5 minutes total.
        sleep.assert_has_calls([call(i) for i in
                                [1, 2, 4, 8, 16, 32, 64, 128, 256]])


class TestIsLxc(unittest.TestCase):
    def test_is_lxc(self):
        # Test the function runs under the current environmnet.
        # Unfortunately we can't sanely test that it is returning the
        # correct value
        helpers.is_lxc()


if __name__ == '__main__':
    unittest.main(verbosity=2)
