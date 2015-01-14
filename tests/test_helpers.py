#!.venv3/bin/python3

from collections import namedtuple
import errno
import functools
import os.path
import subprocess
import tempfile
from textwrap import dedent
import unittest
from unittest.mock import ANY, call, MagicMock, patch, sentinel

from cassandra import AuthenticationFailed, ConsistencyLevel
from cassandra.cluster import NoHostAvailable
import yaml

from charmhelpers.core import hookenv, host

from tests.base import TestCaseBase
import helpers


patch = functools.partial(patch, autospec=True)


class TestHelpers(TestCaseBase):
    def test_autostart_disabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:

            prc = os.path.join(tmpdir, 'policy-rc.d')
            prc_backup = prc + '-orig'

            with helpers.autostart_disabled(_policy_rc=prc):
                # No existing policy-rc.d, so no backup made.
                self.assertFalse(os.path.exists(prc_backup))

                # A policy-rc.d file has been created that will disable
                # package autostart per spec (ie. returns a 101 exit code).
                self.assertTrue(os.path.exists(prc))
                self.assertEqual(subprocess.call([prc]), 101)

                with helpers.autostart_disabled(_policy_rc=prc):
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

    def test_autostart_disabled_partial(self):
        with tempfile.TemporaryDirectory() as tmpdir:

            prc = os.path.join(tmpdir, 'policy-rc.d')
            prc_backup = prc + '-orig'

            with helpers.autostart_disabled(['foo', 'bar'], _policy_rc=prc):
                # No existing policy-rc.d, so no backup made.
                self.assertFalse(os.path.exists(prc_backup))

                # A policy-rc.d file has been created that will disable
                # package autostart per spec (ie. returns a 101 exit code).
                self.assertTrue(os.path.exists(prc))
                self.assertEqual(subprocess.call([prc, 'foo']), 101)
                self.assertEqual(subprocess.call([prc, 'bar']), 101)
                self.assertEqual(subprocess.call([prc, 'baz']), 0)

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

    @patch('relations.StorageRelation')
    def test_get_database_directory(self, storage_relation):
        storage_relation().mountpoint = None

        # Relative paths are relative to /var/lib/cassandra
        self.assertEqual(helpers.get_database_directory('bar'),
                         '/var/lib/cassandra/bar')

        # If there is an external mount, relative paths are relative to
        # it. Note the extra 'cassandra' directory - life is easier
        # if we store all our data in a subdirectory on the external
        # mount rather than in its root.
        storage_relation().mountpoint = '/srv/foo'
        self.assertEqual(helpers.get_database_directory('bar'),
                         '/srv/foo/cassandra/bar')

        # Absolute paths are absolute and passed through unmolested.
        self.assertEqual(helpers.get_database_directory('/bar'), '/bar')

    @patch('relations.StorageRelation')
    def test_get_all_database_directories(self, storage_relation):
        storage_relation().mountpoint = '/s'
        self.assertDictEqual(
            helpers.get_all_database_directories(),
            dict(data_file_directories=['/s/cassandra/data'],
                 commitlog_directory='/s/cassandra/commitlog',
                 saved_caches_directory='/s/cassandra/saved_caches'))

    @patch('helpers.recursive_chown')
    @patch('charmhelpers.core.host.mkdir')
    @patch('helpers.get_database_directory')
    @patch('helpers.is_cassandra_running')
    def test_ensure_database_directory(self, is_running, get_db_dir, mkdir,
                                       recursive_chown):
        is_running.return_value = False
        get_db_dir.return_value = sentinel.absolute_dir

        # ensure_database_directory() returns the absolute path.
        self.assertIs(
            helpers.ensure_database_directory(sentinel.some_dir),
            sentinel.absolute_dir)

        # The directory will have been made.
        mkdir.assert_called_once_with(sentinel.absolute_dir,
                                      owner='cassandra', group='cassandra',
                                      perms=0o750)

        # The ownership of the contents has been reset.
        recursive_chown.assert_called_once_with(sentinel.absolute_dir,
                                                owner='cassandra',
                                                group='cassandra')

    @patch('charmhelpers.core.host.write_file')
    @patch('os.path.isdir')
    @patch('subprocess.check_output')
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

    @patch('shutil.chown')
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

    @patch('charmhelpers.fetch.apt_cache')
    def test_get_package_version(self, apt_cache):
        version = namedtuple('Version', 'ver_str')('1.0-foo')
        package = namedtuple('Package', 'current_ver')(version)
        apt_cache.return_value = dict(package=package)
        ver = helpers.get_package_version('package')
        self.assertEqual(ver, '1.0-foo')

    @patch('charmhelpers.fetch.apt_cache')
    def test_get_package_version_not_found(self, apt_cache):
        version = namedtuple('Version', 'ver_str')('1.0-foo')
        package = namedtuple('Package', 'current_ver')(version)
        apt_cache.return_value = dict(package=package)
        self.assertIsNone(helpers.get_package_version('notfound'))

    @patch('charmhelpers.fetch.apt_cache')
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

    @patch('subprocess.Popen', autospec=False)
    def test_accept_oracle_jvm_license(self, popen):
        popen().communicate.return_value = ('', None)
        popen.reset_mock()

        # Fails hard unless a config option specifying the Oracle JVM
        # has been selected.
        self.assertRaises(AssertionError, helpers.accept_oracle_jvm_license)
        self.assertFalse(popen.called)

        # When the user selects the Oracle JVM in the charm service
        # configuration, they are implicitly accepting the Oracle Java
        # license per the documentation of the option in config.yaml.
        hookenv.config()['jvm'] = 'oracle'

        # If the selection fails, the charm warns and continues to use
        # OpenJDK.
        hookenv.log.reset_mock()
        popen().returncode = 1
        self.assertFalse(helpers.accept_oracle_jvm_license())
        hookenv.log.assert_any_call(ANY, hookenv.ERROR)

        # If selection works, the flag is set in the persistent config.
        popen().returncode = 0
        popen.reset_mock()
        self.assertTrue(helpers.accept_oracle_jvm_license())
        popen.assert_called_once_with(['debconf-set-selections'],
                                      stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT)
        instructions = (b'oracle-java7-installer '
                        b'shared/accepted-oracle-license-v1-1 '
                        b'select true\n')  # trailing newline is required.
        popen().communicate.assert_called_once_with(instructions)

        # Further calls do nothing.
        popen.reset_mock()
        self.assertTrue(helpers.accept_oracle_jvm_license())
        self.assertFalse(popen.called)  # No need to repeat commands.

    @patch('helpers.get_cassandra_edition')
    def test_get_cassandra_service(self, get_edition):
        get_edition.return_value = 'whatever'
        self.assertEqual(helpers.get_cassandra_service(), 'cassandra')
        get_edition.return_value = 'dse'
        self.assertEqual(helpers.get_cassandra_service(), 'dse')

    def test_get_cassandra_service_dse_override(self):
        hookenv.config()['edition'] = 'dse'
        self.assertEqual(helpers.get_cassandra_service(), 'dse')

    @patch('helpers.get_package_version')
    def test_get_cassandra_version(self, get_package_version):
        # Return cassandra package version if it is installed.
        get_package_version.return_value = '1.2.3-2~64'
        self.assertEqual(helpers.get_cassandra_version(), '1.2.3-2~64')
        get_package_version.assert_called_with('cassandra')

    @patch('helpers.get_package_version')
    def test_get_cassandra_version_uninstalled(self, get_package_version):
        # Return none if the main cassandra package is not installed
        get_package_version.return_value = None
        self.assertEqual(helpers.get_cassandra_version(), None)
        get_package_version.assert_called_with('cassandra')

    @patch('helpers.get_package_version')
    def test_get_cassandra_version_dse(self, get_package_version):
        # Return the cassandra version equivalent if using dse.
        hookenv.config()['edition'] = 'dse'
        get_package_version.return_value = '4.5-beta2~88'
        self.assertEqual(helpers.get_cassandra_version(), '2.1')
        get_package_version.assert_called_with('dse-full')

    @patch('helpers.get_package_version')
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

    @patch('helpers.get_cassandra_config_dir')
    def test_get_cassandra_yaml_file(self, get_cassandra_config_dir):
        get_cassandra_config_dir.return_value = '/foo'
        self.assertEqual(helpers.get_cassandra_yaml_file(),
                         '/foo/cassandra.yaml')

    @patch('helpers.get_cassandra_config_dir')
    def test_get_cassandra_env_file(self, get_cassandra_config_dir):
        get_cassandra_config_dir.return_value = '/foo'
        self.assertEqual(helpers.get_cassandra_env_file(),
                         '/foo/cassandra-env.sh')

    @patch('helpers.get_cassandra_config_dir')
    def test_get_cassandra_rackdc_file(self, get_cassandra_config_dir):
        get_cassandra_config_dir.return_value = '/foo'
        self.assertEqual(helpers.get_cassandra_rackdc_file(),
                         '/foo/cassandra-rackdc.properties')

    @patch('helpers.get_cassandra_edition')
    def test_get_cassandra_pid_file(self, get_edition):
        get_edition.return_value = 'whatever'
        self.assertEqual(helpers.get_cassandra_pid_file(),
                         '/var/run/cassandra/cassandra.pid')
        get_edition.return_value = 'dse'
        self.assertEqual(helpers.get_cassandra_pid_file(),
                         '/var/run/dse/dse.pid')

    @patch('helpers.accept_oracle_jvm_license')
    def test_get_cassandra_packages(self, accept_oracle_jvm_license):
        # Default
        self.assertSetEqual(helpers.get_cassandra_packages(),
                            set(['cassandra', 'cassandra-tools', 'ntp']))
        self.assertFalse(accept_oracle_jvm_license.called)

    @patch('helpers.accept_oracle_jvm_license')
    def test_get_cassandra_packages_oracle_jvm(self,
                                               accept_oracle_jvm_license):
        # Oracle JVM
        hookenv.config()['jvm'] = 'oracle'
        accept_oracle_jvm_license.return_value = True
        self.assertSetEqual(helpers.get_cassandra_packages(),
                            set(['cassandra', 'cassandra-tools', 'ntp',
                                 'oracle-java7-installer',
                                 'oracle-java7-set-default']))
        # It was called. We don't care that the mock did nothing, as
        # we explicitly set the magic config item just before.
        self.assertTrue(accept_oracle_jvm_license.called)

    @patch('helpers.accept_oracle_jvm_license')
    def test_get_cassandra_packages_oracle_jvm_fail(self,
                                                    accept_oracle_jvm_license):
        # If we specified the Oracle JVM, but the license could not be
        # accepted, we fall back to the default jdk.
        hookenv.config()['jvm'] = 'oracle'
        accept_oracle_jvm_license.return_value = False

        self.assertSetEqual(helpers.get_cassandra_packages(),
                            set(['cassandra', 'cassandra-tools', 'ntp']))
        self.assertTrue(accept_oracle_jvm_license.called)

    @patch('helpers.accept_oracle_jvm_license')
    def test_get_cassandra_packages_dse(self, accept_oracle_jvm_license):
        # DataStax Enterprise, and implicit Oracle JVM.
        hookenv.config()['edition'] = 'dsE'  # Insensitive.
        accept_oracle_jvm_license.return_value = True
        self.assertSetEqual(helpers.get_cassandra_packages(),
                            set(['dse-full', 'ntp',
                                 'oracle-java7-installer',
                                 'oracle-java7-set-default']))
        self.assertTrue(accept_oracle_jvm_license.called)

    @patch('helpers.get_cassandra_service')
    @patch('charmhelpers.core.host.service_stop')
    @patch('helpers.is_cassandra_running')
    def test_stop_cassandra(self, is_cassandra_running,
                            service_stop, get_service):
        get_service.return_value = sentinel.service_name
        is_cassandra_running.side_effect = iter([True, False])
        helpers.stop_cassandra()
        service_stop.assert_called_once_with(sentinel.service_name)

    @patch('helpers.get_cassandra_service')
    @patch('charmhelpers.core.host.service_stop')
    @patch('helpers.is_cassandra_running')
    def test_stop_cassandra_noop(self, is_cassandra_running,
                                 service_stop, get_service):
        get_service.return_value = sentinel.service_name
        is_cassandra_running.return_value = False
        helpers.stop_cassandra()
        self.assertFalse(service_stop.called)

    @patch('helpers.get_cassandra_service')
    @patch('charmhelpers.core.host.service_stop')
    @patch('helpers.is_cassandra_running')
    def test_stop_cassandra_failure(self, is_cassandra_running,
                                    service_stop, get_service):
        get_service.return_value = sentinel.service_name
        is_cassandra_running.side_effect = iter([True, True])
        self.assertRaises(AssertionError, helpers.stop_cassandra)
        service_stop.assert_called_once_with(sentinel.service_name)

    @patch('time.sleep')
    @patch('helpers.get_cassandra_service')
    @patch('charmhelpers.core.host.service_start')
    @patch('helpers.is_cassandra_running')
    def test_start_cassandra(self, is_cassandra_running,
                             service_start, get_service, sleep):
        get_service.return_value = sentinel.service_name
        is_cassandra_running.return_value = True
        helpers.start_cassandra()
        self.assertFalse(service_start.called)

        is_cassandra_running.side_effect = iter([False, False, False, True])
        helpers.start_cassandra()
        service_start.assert_called_once_with(sentinel.service_name)

    @patch('time.time')
    @patch('time.sleep')
    @patch('helpers.get_cassandra_service')
    @patch('charmhelpers.core.host.service_start')
    @patch('helpers.is_cassandra_running')
    def test_start_cassandra_timeout(self, is_cassandra_running,
                                     service_start, get_service, sleep, time):
        get_service.return_value = sentinel.service_name
        is_cassandra_running.return_value = False
        time.side_effect = iter([10, 20, 30, 40, 3600])
        self.assertRaises(SystemExit, helpers.start_cassandra)
        service_start.assert_called_once_with(sentinel.service_name)
        # An error was logged.
        hookenv.log.assert_has_calls([call(ANY, hookenv.ERROR)])

    @patch('helpers.configure_cassandra_yaml')
    @patch('helpers.stop_cassandra')
    @patch('helpers.start_cassandra')
    def test_reconfigure_and_restart_cassandra(self, start, stop, reconf):
        helpers.reconfigure_and_restart_cassandra(sentinel.overrides)
        stop.assert_called_once_with()
        reconf.assert_called_once_with(sentinel.overrides)
        start.assert_called_once_with()

    @patch('os.chmod')
    @patch('helpers.is_cassandra_running')
    @patch('relations.StorageRelation')
    def test_remount_cassandra(self, storage, is_running, chmod):
        storage().needs_remount.return_value = True
        storage().mountpoint = '/srv/foo'
        is_running.return_value = False
        hookenv.config()['data_file_directories'] = '/srv/ext/data1 data2'

        helpers.remount_cassandra()
        storage().migrate.assert_called_once_with('/var/lib/cassandra',
                                                  'cassandra')
        chmod.assert_called_once_with('/srv/foo/cassandra', 0o750)

    @patch('os.chmod')
    @patch('helpers.is_cassandra_running')
    @patch('relations.StorageRelation')
    def test_remount_cassandra_noop(self, storage, is_running, chmod):
        storage().needs_remount.return_value = False
        storage().mountpoint = None
        is_running.return_value = False

        helpers.remount_cassandra()
        self.assertFalse(storage().migrate.called)
        self.assertFalse(chmod.called)

    @patch('helpers.is_cassandra_running')
    @patch('relations.StorageRelation')
    def test_remount_cassandra_unmount(self, storage, is_running):
        storage().needs_remount.return_value = True
        storage().mountpoint = None  # Reverting to local disk.
        is_running.return_value = False
        hookenv.config()['data_file_directories'] = '/srv/ext/data1 data2'

        helpers.remount_cassandra()

        # We cannot migrate data back to local disk, as by the time our
        # hooks are called the data is gone.
        self.assertFalse(storage().migrate.called)

        # We warn in this case, as reverting to local disk may resurrect
        # old data (if the cluster was ever time while using local
        # disk).
        hookenv.log.assert_any_call(ANY, hookenv.WARNING)

    @patch('helpers.ensure_database_directory')
    @patch('helpers.get_all_database_directories')
    def test_ensure_database_directories(self, get_all_dirs, ensure_dir):
        get_all_dirs.return_value = dict(
            data_file_directories=[sentinel.data_file_dir_1,
                                   sentinel.data_file_dir_2],
            commitlog_directory=sentinel.commitlog_dir,
            saved_caches_directory=sentinel.saved_caches_dir)
        helpers.ensure_database_directories()
        ensure_dir.assert_has_calls([
            call(sentinel.data_file_dir_1),
            call(sentinel.data_file_dir_2),
            call(sentinel.commitlog_dir),
            call(sentinel.saved_caches_dir)], any_order=True)

    @patch('charmhelpers.core.host.pwgen')
    @patch('helpers.query')
    @patch('helpers.connect')
    def test_reset_default_password(self, connect, query, pwgen):
        pwgen.return_value = sentinel.password
        helpers.reset_default_password()
        connect.assert_called_once_with('cassandra', 'cassandra')
        with connect() as session:
            query.assert_called_once_with(
                session, 'ALTER USER cassandra WITH PASSWORD %s',
                ConsistencyLevel.ALL, (sentinel.password,))

    @patch('cassandra.cluster.Cluster')
    @patch('cassandra.auth.PlainTextAuthProvider')
    @patch('helpers.superuser_credentials')
    @patch('helpers.read_cassandra_yaml')
    def test_connect(self, yaml, creds, auth_provider, cluster):
        # host and port are pulled from the current active
        # cassandra.yaml file, rather than configuration, as
        # configuration may not match reality (if for no other reason
        # that we are running this code in order to make reality match
        # the desired configuration).
        yaml.return_value = dict(rpc_address='1.2.3.4',
                                 native_transport_port=666)

        creds.return_value = ('un', 'pw')
        auth_provider.return_value = sentinel.ap

        cluster().connect.return_value = sentinel.session
        cluster.reset_mock()

        with helpers.connect() as session:
            auth_provider.assert_called_once_with(username='un',
                                                  password='pw')
            cluster.assert_called_once_with(['1.2.3.4'], port=666,
                                            auth_provider=sentinel.ap)
            self.assertIs(session, sentinel.session)
            self.assertFalse(cluster().shutdown.called)

        cluster().shutdown.assert_called_once_with()

    @patch('cassandra.cluster.Cluster')
    @patch('cassandra.auth.PlainTextAuthProvider')
    @patch('helpers.superuser_credentials')
    @patch('helpers.read_cassandra_yaml')
    def test_connect_with_creds(self, yaml, creds, auth_provider, cluster):
        # host and port are pulled from the current active
        # cassandra.yaml file, rather than configuration, as
        # configuration may not match reality (if for no other reason
        # that we are running this code in order to make reality match
        # the desired configuration).
        yaml.return_value = dict(rpc_address='1.2.3.4',
                                 native_transport_port=666)

        auth_provider.return_value = sentinel.ap

        cluster().connect.return_value = sentinel.session
        cluster.reset_mock()

        with helpers.connect(username='explicit', password='boo') as session:
            auth_provider.assert_called_once_with(username='explicit',
                                                  password='boo')
            cluster.assert_called_once_with(['1.2.3.4'], port=666,
                                            auth_provider=sentinel.ap)
            self.assertIs(session, sentinel.session)
            self.assertFalse(cluster().shutdown.called)

        cluster().shutdown.assert_called_once_with()

    @patch('cassandra.cluster.Cluster')
    @patch('helpers.superuser_credentials')
    @patch('helpers.read_cassandra_yaml')
    def test_connect_badauth(self, yaml, creds, cluster):
        # host and port are pulled from the current active
        # cassandra.yaml file, rather than configuration, as
        # configuration may not match reality (if for no other reason
        # that we are running this code in order to make reality match
        # the desired configuration).
        yaml.return_value = dict(rpc_address='1.2.3.4',
                                 native_transport_port=666)

        creds.return_value = ('un', 'pw')

        x = NoHostAvailable('whoops', {'1.2.3.4': AuthenticationFailed()})
        cluster().connect.side_effect = x

        self.assertRaises(AuthenticationFailed, helpers.connect().__enter__)

        cluster().shutdown.assert_called_once_with()

    @patch('cassandra.cluster.Cluster')
    @patch('cassandra.auth.PlainTextAuthProvider')
    @patch('helpers.superuser_credentials')
    @patch('helpers.read_cassandra_yaml')
    def test_connect_retry(self, yaml, creds, auth_provider, cluster):
        # host and port are pulled from the current active
        # cassandra.yaml file, rather than configuration, as
        # configuration may not match reality (if for no other reason
        # that we are running this code in order to make reality match
        # the desired configuration).
        yaml.return_value = dict(rpc_address='1.2.3.4',
                                 native_transport_port=666)

        creds.return_value = ('un', 'pw')
        auth_provider.return_value = sentinel.ap

        cluster().connect.side_effect = [NoHostAvailable('1', {}),
                                         NoHostAvailable('2', {}),
                                         NoHostAvailable('3', {}),
                                         sentinel.session]
        cluster.reset_mock()

        with helpers.connect() as session:
            auth_provider.assert_called_once_with(username='un',
                                                  password='pw')
            cluster.assert_called_with(['1.2.3.4'],
                                       port=666, auth_provider=sentinel.ap)
            self.assertEqual(cluster().connect.call_count, 4)
            self.assertIs(session, sentinel.session)

        self.assertEqual(cluster().shutdown.call_count, 4)

    @patch('time.time')
    @patch('cassandra.cluster.Cluster')
    @patch('cassandra.auth.PlainTextAuthProvider')
    @patch('helpers.superuser_credentials')
    @patch('helpers.read_cassandra_yaml')
    def test_connect_timeout(self, yaml, creds, auth_provider, cluster, time):
        # host and port are pulled from the current active
        # cassandra.yaml file, rather than configuration, as
        # configuration may not match reality (if for no other reason
        # that we are running this code in order to make reality match
        # the desired configuration).
        yaml.return_value = dict(rpc_address='1.2.3.4',
                                 native_transport_port=666)

        creds.return_value = ('un', 'pw')
        auth_provider.return_value = sentinel.ap

        cluster().connect.side_effect = [
            NoHostAvailable('1', {}),
            NoHostAvailable('2', {'1.2.3.4': Exception()}),
            NoHostAvailable('3', {}),
            sentinel.session]
        cluster.reset_mock()

        # Force a timeout
        time.side_effect = [10, 20, 60, 70]

        self.assertRaises(NoHostAvailable, helpers.connect().__enter__)

        self.assertEqual(cluster().connect.call_count, 2)
        self.assertEqual(cluster().shutdown.call_count, 2)

    @patch('cassandra.query.SimpleStatement')
    def test_query(self, simple_statement):
        simple_statement.return_value = sentinel.s_statement
        session = MagicMock()
        session.execute.return_value = sentinel.results
        self.assertEqual(helpers.query(session, sentinel.statement,
                                       sentinel.consistency, sentinel.args),
                         sentinel.results)
        simple_statement.assert_called_once_with(
            sentinel.statement, consistency_level=sentinel.consistency)
        session.execute.assert_called_once_with(simple_statement(''),
                                                sentinel.args)

    @patch('helpers.query')
    @patch('helpers.connect')
    def test_ensure_user(self, connect, query):
        connect().__enter__.return_value = sentinel.session
        connect().__exit__.return_value = False
        helpers.ensure_user(sentinel.username, sentinel.password)
        query.assert_has_calls([
            call(sentinel.session,
                 'CREATE USER IF NOT EXISTS %s WITH PASSWORD %s',
                 ConsistencyLevel.QUORUM,
                 (sentinel.username, sentinel.password)),
            call(sentinel.session,
                 'ALTER USER %s WITH PASSWORD %s',
                 ConsistencyLevel.QUORUM,
                 (sentinel.username, sentinel.password))])

    @patch('helpers.create_superuser')
    @patch('helpers.connect')
    def test_ensure_superuser(self, connect, create_superuser):
        connect().__enter__.side_effect = iter([AuthenticationFailed(),
                                                sentinel.session])
        connect().__exit__.return_value = False
        connect.reset_mock()

        helpers.ensure_superuser()
        create_superuser.assert_called_once_with()  # Account created.

    @patch('helpers.create_superuser')
    @patch('helpers.connect')
    def test_ensure_superuser_exists(self, connect, create_superuser):
        connect().__enter__.return_value = sentinel.session
        connect().__exit__.return_value = False
        connect.reset_mock()

        # If connect works, nothing happens
        helpers.ensure_superuser()
        connect.assert_called_once_with()  # Superuser connection attempted.
        self.assertFalse(create_superuser.called)  # No need to create.

    @patch('helpers.query')
    @patch('bcrypt.gensalt')
    @patch('bcrypt.hashpw')
    @patch('helpers.reconfigure_and_restart_cassandra')
    @patch('helpers.connect')
    @patch('helpers.superuser_credentials')
    def test_create_superuser(self, creds, connect, restart,
                              bhash, bsalt, query):
        creds.return_value = ('super', 'secret')
        connect().__enter__.return_value = sentinel.session
        connect().__exit__.return_value = False
        connect.reset_mock()

        bsalt.return_value = sentinel.salt
        bhash.return_value = 'pwhash'

        helpers.create_superuser()

        # Cassandra was restarted twice, first with authentication
        # disabled and again with the normal configuration.
        restart.assert_has_calls([
            call(dict(authenticator='AllowAllAuthenticator',
                      rpc_address='127.0.0.1')),
            call()])

        # A connection was made as the superuser.
        connect.assert_called_once_with()

        # Statements run to create or update the user.
        query.assert_has_calls([
            call(sentinel.session,
                 dedent('''\
                        INSERT INTO system_auth.users (name, super)
                        VALUES (%s, TRUE)
                        '''),
                 ConsistencyLevel.ALL, ('super',)),
            call(sentinel.session,
                 dedent('''\
                    INSERT INTO system_auth.credentials (username, salted_hash)
                    VALUES (%s, %s)
                        '''),
                 ConsistencyLevel.ALL, ('super', 'pwhash'))])

    def test_cqlshrc_path(self):
        self.assertEqual(helpers.get_cqlshrc_path(),
                         '/root/.cassandra/cqlshrc')

    def test_superuser_username(self):
        self.assertEqual(hookenv.local_unit(), 'service/1')
        self.assertEqual(helpers.superuser_username(), 'juju_service_1')

    @patch('helpers.superuser_username')
    @patch('helpers.get_cqlshrc_path')
    @patch('charmhelpers.core.host.pwgen')
    def test_superuser_credentials(self, pwgen,
                                   get_cqlshrc_path, get_username):
        with tempfile.NamedTemporaryFile() as cqlshrc_file:
            get_cqlshrc_path.return_value = cqlshrc_file.name
            get_username.return_value = 'foo'
            pwgen.return_value = 'secret'
            hookenv.unit_public_ip.return_value = '1.2.3.4'
            hookenv.config()['native_client_port'] = 666

            # First time generates username & password.
            username, password = helpers.superuser_credentials()
            self.assertEqual(username, 'foo')
            self.assertEqual(password, 'secret')

            # Credentials are stored in the cqlshrc file.
            expected_cqlshrc = dedent('''\
                                      [authentication]
                                      username = foo
                                      password = secret

                                      [connection]
                                      hostname = 1.2.3.4
                                      port = 666
                                      ''').strip()
            with open(cqlshrc_file.name, 'r') as f:
                self.assertEqual(f.read().strip(), expected_cqlshrc)

            # If the credentials have been stored, they are not
            # regenerated.
            get_username.return_value = 'bar'
            pwgen.return_value = 'secret2'
            username, password = helpers.superuser_credentials()
            self.assertEqual(username, 'foo')
            self.assertEqual(password, 'secret')
            with open(cqlshrc_file.name, 'r') as f:
                self.assertEqual(f.read().strip(), expected_cqlshrc)

    @patch('charmhelpers.core.hookenv.relation_get')
    def test_get_node_public_addresses(self, relation_get):
        hookenv.unit_public_ip.return_value = '9.8.7.6'
        relation_get.side_effect = iter(['1.2.3.4', '5.6.7.8'])
        self.assertSetEqual(helpers.get_node_public_addresses(),
                            set(['1.2.3.4', '5.6.7.8', '9.8.7.6']))
        relation_get.assert_has_calls([
            call('public-address', 'service/2', 'cluster:1'),
            call('public-address', 'service/3', 'cluster:1')], any_order=True)

    @patch('charmhelpers.core.hookenv.relation_get')
    def test_get_node_private_addresses(self, relation_get):
        hookenv.unit_private_ip.return_value = '9.8.7.6'
        relation_get.side_effect = iter(['1.2.3.4', '5.6.7.8'])
        self.assertSetEqual(helpers.get_node_private_addresses(),
                            set(['1.2.3.4', '5.6.7.8', '9.8.7.6']))
        relation_get.assert_has_calls([
            call('private-address', 'service/2', 'cluster:1'),
            call('private-address', 'service/3', 'cluster:1')], any_order=True)

    @patch('rollingrestart.get_peers')
    def test_num_nodes(self, get_peers):
        get_peers.return_value = ['a', 'b']
        self.assertEqual(helpers.num_nodes(), 3)

    @patch('helpers.get_cassandra_yaml_file')
    def test_read_cassandra_yaml(self, get_cassandra_yaml_file):
        with tempfile.NamedTemporaryFile('w') as f:
            f.write('a: one')
            f.flush()
            get_cassandra_yaml_file.return_value = f.name
            self.assertDictEqual(helpers.read_cassandra_yaml(),
                                 dict(a='one'))

    @patch('helpers.get_cassandra_yaml_file')
    def test_write_cassandra_yaml(self, get_cassandra_yaml_file):
        with tempfile.NamedTemporaryFile() as f:
            get_cassandra_yaml_file.return_value = f.name
            helpers.write_cassandra_yaml([1, 2, 3])
            with open(f.name, 'r') as f2:
                self.assertEqual(f2.read(), '[1, 2, 3]\n')

    @patch('charmhelpers.core.hookenv.relation_get')
    @patch('helpers.get_cassandra_yaml_file')
    @patch('helpers.get_seeds')
    @patch('charmhelpers.core.host.write_file')
    def test_configure_cassandra_yaml(self, write_file, get_seeds, yaml_file,
                                      relation_get):
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

            helpers.configure_cassandra_yaml()

            self.assertEqual(write_file.call_count, 2)
            new_config = write_file.call_args[0][1]

            expected_config = dedent('''\
                cluster_name: service
                authenticator: PasswordAuthenticator
                num_tokens: 128
                partitioner: my_partitioner
                listen_address: 10.20.0.1
                rpc_address: 10.30.0.1
                rpc_port: 9160
                native_transport_port: 9042
                storage_port: 7000
                ssl_storage_port: 7001
                authorizer: AllowAllAuthorizer
                seed_provider:
                    - class_name: blah.blah.SimpleSeedProvider
                      parameters:
                        # No whitespace in seeds is important.
                        - seeds: '10.20.0.1,10.20.0.2,10.20.0.3'
                data_file_directories:
                    - /var/lib/cassandra/data
                commitlog_directory: /var/lib/cassandra/commitlog
                saved_caches_directory: /var/lib/cassandra/saved_caches
                ''')
            self.maxDiff = None
            self.assertEqual(yaml.safe_load(new_config),
                             yaml.safe_load(expected_config))

            # Confirm we can use an explicit cluster_name too.
            write_file.reset_mock()
            hookenv.config()['cluster_name'] = 'fubar'
            helpers.configure_cassandra_yaml()
            new_config = write_file.call_args[0][1]
            self.assertEqual(yaml.safe_load(new_config)['cluster_name'],
                             'fubar')

    @patch('charmhelpers.core.hookenv.relation_get')
    @patch('helpers.get_cassandra_yaml_file')
    @patch('helpers.get_seeds')
    @patch('charmhelpers.core.host.write_file')
    def test_configure_cassandra_yaml_overrides(self, write_file, get_seeds,
                                                yaml_file, relation_get):
        hookenv.config().update(dict(num_tokens=128,
                                     cluster_name=None,
                                     partitioner='my_partitioner'))

        get_seeds.return_value = ['10.20.0.1', '10.20.0.2', '10.20.0.3']

        existing_config = dedent('''\
            seed_provider:
                - class_name: blah.blah.SimpleSeedProvider
                  parameters:
                      - seeds: 127.0.0.1  # Comma separated list.
            ''')
        overrides = dict(partitioner='overridden_partitioner')

        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_config = os.path.join(tmpdir, 'c.yaml')
            yaml_file.return_value = yaml_config
            with open(yaml_config, 'w', encoding='UTF-8') as f:
                f.write(existing_config)

            helpers.configure_cassandra_yaml(overrides=overrides)

            self.assertEqual(write_file.call_count, 2)
            new_config = write_file.call_args[0][1]

            self.assertEqual(yaml.safe_load(new_config)['partitioner'],
                             'overridden_partitioner')

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

    @patch('os.path.exists')
    @patch('helpers.get_cassandra_pid_file')
    def test_is_cassandra_running_not_running(self, get_pid_file, exists):
        # When Cassandra is not running, there is no pidfile.
        get_pid_file.return_value = sentinel.pid_file
        exists.return_value = False
        self.assertFalse(helpers.is_cassandra_running())
        exists.assert_called_once_with(sentinel.pid_file)

    @patch('os.path.exists')
    @patch('helpers.get_pid_from_file')
    def test_is_cassandra_running_invalid_pid(self, get_pid_from_file, exists):
        # get_pid_from_file raises a ValueError if the pid is illegal.
        get_pid_from_file.side_effect = ValueError('Whoops')
        exists.return_value = True  # The pid file is there, just insane.

        # is_cassandra_running() fails hard in this case, since we
        # cannot safely continue when the system is insane.
        self.assertRaises(ValueError, helpers.is_cassandra_running)

    @patch('time.sleep')
    @patch('os.kill')
    @patch('helpers.get_pid_from_file')
    @patch('subprocess.call')
    def test_is_cassandra_running_starting_up(self, call, get_pid_from_file,
                                              kill, sleep):
        sleep.return_value = None  # Don't actually sleep in unittests.
        os.kill.return_value = True  # There is a running pid.
        get_pid_from_file.return_value = 42
        subprocess.call.side_effect = iter([3, 2, 1, 0])  # 4th time the charm
        self.assertTrue(helpers.is_cassandra_running())

    @patch('time.sleep')
    @patch('os.kill')
    @patch('subprocess.call')
    @patch('os.path.exists')
    @patch('helpers.get_pid_from_file')
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

    @patch('os.path.isdir')
    @patch('helpers.get_all_database_directories')
    @patch('helpers.set_io_scheduler')
    def test_reset_all_io_schedulers(self, set_io_scheduler, dbdirs, isdir):
        hookenv.config()['io_scheduler'] = sentinel.io_scheduler
        dbdirs.return_value = dict(
            data_file_directories=[sentinel.d1, sentinel.d2],
            commitlog_directory=sentinel.cl,
            saved_caches_directory=sentinel.sc)
        isdir.return_value = True
        helpers.reset_all_io_schedulers()
        set_io_scheduler.assert_has_calls([
            call(sentinel.io_scheduler, sentinel.d1),
            call(sentinel.io_scheduler, sentinel.d2),
            call(sentinel.io_scheduler, sentinel.cl),
            call(sentinel.io_scheduler, sentinel.sc)],
            any_order=True)

        # If directories don't exist yet, nothing happens.
        set_io_scheduler.reset_mock()
        isdir.return_value = False
        helpers.reset_all_io_schedulers()
        self.assertFalse(set_io_scheduler.called)

    @patch('helpers.query')
    @patch('helpers.connect')
    def test_get_auth_keyspace_replication_factor(self, connect, query):
        connect().__enter__.return_value = sentinel.session
        connect().__exit__.return_value = False
        query.return_value = [('{"replication_factor":"12"}',)]
        self.assertEqual(helpers.get_auth_keyspace_replication_factor(), 12)
        connect.assert_called_with()  # Connected as the superuser
        query.assert_called_with(sentinel.session, dedent('''\
            SELECT strategy_options FROM system.schema_keyspaces
            WHERE keyspace_name='system_auth'
            '''), ConsistencyLevel.QUORUM)

    @patch('helpers.query')
    @patch('helpers.connect')
    def test_set_auth_keyspace_replication_factor(self, connect, query):
        connect().__enter__.return_value = sentinel.session
        connect().__exit__.return_value = False
        helpers.set_auth_keyspace_replication_factor(22)
        connect.assert_called_with()  # Connected as the superuser
        query.assert_called_with(sentinel.session, dedent('''\
            ALTER KEYSPACE system_auth WITH REPLICATION =
                {'class': 'SimpleStrategy', 'replication_factor': %s}
            '''), ConsistencyLevel.QUORUM, (22,))


class TestIsLxc(unittest.TestCase):
    def test_is_lxc(self):
        # Test the function runs under the current environmnet.
        # Unfortunately we can't sanely test that it is returning the
        # correct value
        helpers.is_lxc()


if __name__ == '__main__':
    unittest.main(verbosity=2)
