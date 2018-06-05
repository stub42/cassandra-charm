# Copyright 2015-2018 Canonical Ltd.
#
# This file is part of the Cassandra Charm for Juju.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from collections import namedtuple
import errno
import functools
from itertools import repeat
import os.path
import subprocess
import tempfile
from textwrap import dedent
import unittest
from unittest.mock import ANY, call, MagicMock, patch, sentinel

from cassandra import AuthenticationFailed, ConsistencyLevel
from cassandra.cluster import NoHostAvailable
import netifaces
import yaml

from charmhelpers.core import hookenv, host

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

import charms  # noqa

charms.leadership = MagicMock()

from charms.layer import cassandra  # noqa


patch = functools.partial(patch, autospec=True)


class TestHelpers(unittest.TestCase):
    @patch('time.sleep')
    def test_backoff(self, sleep):
        i = 0
        for _ in cassandra.backoff('foo to bar'):
            i += 1
            if i == 10:
                break
        sleep.assert_has_calls([
            call(2), call(4), call(8), call(16), call(32),
            call(60), call(60), call(60), call(60)])

        i = 0
        for _ in cassandra.backoff('foo to bar', max_pause=10):
            i += 1
            if i == 10:
                break
        sleep.assert_has_calls([
            call(2), call(4), call(8), call(10), call(10),
            call(10), call(10), call(10), call(10)])

    def test_autostart_disabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:

            prc = os.path.join(tmpdir, 'policy-rc.d')
            prc_backup = prc + '-orig'

            with cassandra.autostart_disabled(_policy_rc=prc):
                # No existing policy-rc.d, so no backup made.
                self.assertFalse(os.path.exists(prc_backup))

                # A policy-rc.d file has been created that will disable
                # package autostart per spec (ie. returns a 101 exit code).
                self.assertTrue(os.path.exists(prc))
                self.assertEqual(subprocess.call([prc]), 101)

                with cassandra.autostart_disabled(_policy_rc=prc):
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

            with cassandra.autostart_disabled(['foo', 'bar'], _policy_rc=prc):
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

    def test_encrypt_password(self):
        self.assertEqual(type(cassandra.encrypt_password('')), str)

    @patch('charmhelpers.core.hookenv.leader_get')
    def test_get_seed_ips(self, leader_get):
        leader_get.return_value = '1.2.3.4,5.6.7.8'
        self.assertSetEqual(cassandra.get_seed_ips(), set(['1.2.3.4',
                                                         '5.6.7.8']))

    @patch('cassandra.read_cassandra_yaml')
    def test_actual_seed_ips(self, read_yaml):
        read_yaml.return_value = yaml.load(dedent('''\
                                                  seed_provider:
                                                    - class_name: blah
                                                      parameters:
                                                        - seeds: a,b,c
                                                  '''))
        self.assertSetEqual(cassandra.actual_seed_ips(),
                            set(['a', 'b', 'c']))

    @patch('relations.StorageRelation')
    def test_get_database_directory(self, storage_relation):
        storage_relation().mountpoint = None

        # Relative paths are relative to /var/lib/cassandra
        self.assertEqual(cassandra.get_database_directory('bar'),
                         '/var/lib/cassandra/bar')

        # If there is an external mount, relative paths are relative to
        # it. Note the extra 'cassandra' directory - life is easier
        # if we store all our data in a subdirectory on the external
        # mount rather than in its root.
        storage_relation().mountpoint = '/srv/foo'
        self.assertEqual(cassandra.get_database_directory('bar'),
                         '/srv/foo/cassandra/bar')

        # Absolute paths are absolute and passed through unmolested.
        self.assertEqual(cassandra.get_database_directory('/bar'), '/bar')

    @patch('cassandra.get_cassandra_version')
    @patch('relations.StorageRelation')
    def test_get_all_database_directories(self, storage_relation, ver):
        ver.return_value = '2.2'
        storage_relation().mountpoint = '/s'
        self.assertDictEqual(
            cassandra.get_all_database_directories(),
            dict(data_file_directories=['/s/cassandra/data'],
                 commitlog_directory='/s/cassandra/commitlog',
                 saved_caches_directory='/s/cassandra/saved_caches'))

    @patch('cassandra.get_cassandra_version')
    @patch('relations.StorageRelation')
    def test_get_all_database_directories_30(self, storage_relation, ver):
        ver.return_value = '3.0'
        storage_relation().mountpoint = '/s'
        self.assertDictEqual(
            cassandra.get_all_database_directories(),
            dict(data_file_directories=['/s/cassandra/data'],
                 commitlog_directory='/s/cassandra/commitlog',
                 saved_caches_directory='/s/cassandra/saved_caches',
                 hints_directory='/s/cassandra/hints'))

    @patch('cassandra.recursive_chown')
    @patch('charmhelpers.core.host.mkdir')
    @patch('cassandra.get_database_directory')
    @patch('cassandra.is_cassandra_running')
    def test_ensure_database_directory(self, is_running, get_db_dir, mkdir,
                                       recursive_chown):
        absdir = '/an/absolute/dir'
        is_running.return_value = False
        get_db_dir.return_value = absdir

        # ensure_database_directory() returns the absolute path.
        self.assertEqual(cassandra.ensure_database_directory(absdir), absdir)

        # The directory will have been made.
        mkdir.assert_has_calls([
            call('/an'),
            call('/an/absolute'),
            call('/an/absolute/dir',
                 owner='cassandra', group='cassandra', perms=0o750)])

        # The ownership of the contents has not been reset. Rather than
        # attempting to remount an existing database, which requires
        # resetting permissions, it is better to use sstableloader to
        # import the data into the cluster.
        self.assertFalse(recursive_chown.called)

    @patch('charmhelpers.core.host.write_file')
    @patch('os.path.isdir')
    @patch('subprocess.check_output')
    def test_set_io_scheduler(self, check_output, isdir, write_file):
        # Normal operation, the device is detected and the magic
        # file written.
        check_output.return_value = 'foo\n/dev/sdq 1 2 3 1% /foo\n'
        isdir.return_value = True

        cassandra.set_io_scheduler('fnord', '/foo')

        write_file.assert_called_once_with('/sys/block/sdq/queue/scheduler',
                                           b'fnord', perms=0o644)

        # Some OSErrors we log warnings for, and continue.
        for e in (errno.EACCES, errno.ENOENT):
            with self.subTest(errno=e):
                write_file.side_effect = repeat(OSError(e, 'Whoops'))
                hookenv.log.reset_mock()
                cassandra.set_io_scheduler('fnord', '/foo')
                hookenv.log.assert_has_calls([call(ANY),
                                              call(ANY, hookenv.WARNING)])

        # Other OSErrors just fail hard.
        write_file.side_effect = iter([OSError(errno.EFAULT, 'Whoops')])
        self.assertRaises(OSError, cassandra.set_io_scheduler, 'fnord', '/foo')

        # If we are not under lxc, nothing happens at all except a log
        # message.
        cassandra.is_lxc.return_value = True
        hookenv.log.reset_mock()
        write_file.reset_mock()
        cassandra.set_io_scheduler('fnord', '/foo')
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
            cassandra.recursive_chown(tmpdir, 'un', 'gn')
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
            cassandra.maybe_backup(path)
            path_orig = path + '.orig'
            self.assertTrue(os.path.exists(path_orig))
            with open(path_orig, 'rb') as f:
                self.assertEqual(f.read(), b'hello')
            # Safe permissions
            self.assertEqual(os.lstat(path_orig).st_mode & 0o777, 0o600)

            # A second call, nothing happens as the .orig is already
            # there.
            host.write_file(path, b'second')
            cassandra.maybe_backup(path)
            with open(path_orig, 'rb') as f:
                self.assertEqual(f.read(), b'hello')

    @patch('charmhelpers.fetch.apt_cache')
    def test_get_package_version(self, apt_cache):
        version = namedtuple('Version', 'ver_str')('1.0-foo')
        package = namedtuple('Package', 'current_ver')(version)
        apt_cache.return_value = dict(package=package)
        ver = cassandra.get_package_version('package')
        self.assertEqual(ver, '1.0-foo')

    @patch('charmhelpers.fetch.apt_cache')
    def test_get_package_version_not_found(self, apt_cache):
        version = namedtuple('Version', 'ver_str')('1.0-foo')
        package = namedtuple('Package', 'current_ver')(version)
        apt_cache.return_value = dict(package=package)
        self.assertIsNone(cassandra.get_package_version('notfound'))

    @patch('charmhelpers.fetch.apt_cache')
    def test_get_package_version_not_installed(self, apt_cache):
        package = namedtuple('Package', 'current_ver')(None)
        apt_cache.return_value = dict(package=package)
        self.assertIsNone(cassandra.get_package_version('package'))

    def test_get_jre(self):
        hookenv.config()['jre'] = 'opEnjdk'  # Case insensitive
        self.assertEqual(cassandra.get_jre(), 'openjdk')

        hookenv.config()['jre'] = 'oRacle'  # Case insensitive
        self.assertEqual(cassandra.get_jre(), 'oracle')

    def test_get_jre_unknown(self):
        hookenv.config()['jre'] = 'OopsJDK'
        self.assertEqual(cassandra.get_jre(), 'openjdk')
        # An error was logged.
        hookenv.log.assert_called_once_with(ANY, hookenv.ERROR)

    @patch('charmhelpers.core.host.lsb_release')
    def test_get_cassandra_edition(self, lsb_release):
        lsb_release.return_value = {'DISTRIB_CODENAME': 'trusty'}

        hookenv.config()['edition'] = 'community'
        self.assertEqual(cassandra.get_cassandra_edition(), 'community')

        hookenv.config()['edition'] = 'DSE'  # Case insensitive
        self.assertEqual(cassandra.get_cassandra_edition(), 'dse')

        self.assertFalse(hookenv.log.called)

        hookenv.log.reset_mock()
        hookenv.config()['edition'] = 'typo'  # Default to community
        self.assertEqual(cassandra.get_cassandra_edition(), 'community')
        hookenv.log.assert_any_call(ANY, hookenv.ERROR)  # Logs an error.

        hookenv.log.reset_mock()
        hookenv.config()['edition'] = 'apache-snap'  # Default to community
        self.assertEqual(cassandra.get_cassandra_edition(), 'community')
        hookenv.log.assert_any_call(ANY, hookenv.ERROR)  # Logs an error.

        lsb_release.reset_mock()
        lsb_release.return_value = {'DISTRIB_CODENAME': 'xenial'}
        hookenv.config()['edition'] = 'apache-snap'
        self.assertEqual(cassandra.get_cassandra_edition(), 'apache-snap')

    @patch('cassandra.get_cassandra_edition')
    def test_get_cassandra_service(self, get_edition):
        get_edition.return_value = 'whatever'
        self.assertEqual(cassandra.get_cassandra_service(), 'cassandra')
        get_edition.return_value = 'dse'
        self.assertEqual(cassandra.get_cassandra_service(), 'dse')

    def test_get_cassandra_service_dse_override(self):
        hookenv.config()['edition'] = 'dse'
        self.assertEqual(cassandra.get_cassandra_service(), 'dse')

    @patch('cassandra.get_package_version')
    def test_get_cassandra_version(self, get_package_version):
        # Return cassandra package version if it is installed.
        get_package_version.return_value = '1.2.3-2~64'
        self.assertEqual(cassandra.get_cassandra_version(), '1.2.3-2~64')
        get_package_version.assert_called_with('cassandra')

    @patch('cassandra.get_package_version')
    def test_get_cassandra_version_uninstalled(self, get_package_version):
        # Return none if the main cassandra package is not installed
        get_package_version.return_value = None
        self.assertEqual(cassandra.get_cassandra_version(), None)
        get_package_version.assert_called_with('cassandra')

    @patch('cassandra.get_package_version')
    def test_get_cassandra_version_dse(self, get_package_version):
        # Return the cassandra version equivalent if using dse.
        hookenv.config()['edition'] = 'dse'
        get_package_version.return_value = '4.7-beta2~88'
        self.assertEqual(cassandra.get_cassandra_version(), '2.1')
        get_package_version.assert_called_with('dse-full')

    @patch('cassandra.get_package_version')
    def test_get_cassandra_version_dse_uninstalled(self, get_package_version):
        # Return the cassandra version equivalent if using dse.
        hookenv.config()['edition'] = 'dse'
        get_package_version.return_value = None
        self.assertEqual(cassandra.get_cassandra_version(), None)
        get_package_version.assert_called_with('dse-full')

    def test_get_cassandra_config_dir(self):
        self.assertEqual(cassandra.get_cassandra_config_dir(),
                         '/etc/cassandra')
        hookenv.config()['edition'] = 'dse'
        self.assertEqual(cassandra.get_cassandra_config_dir(),
                         '/etc/dse/cassandra')

    @patch('cassandra.get_cassandra_config_dir')
    def test_get_cassandra_yaml_file(self, get_cassandra_config_dir):
        get_cassandra_config_dir.return_value = '/foo'
        self.assertEqual(cassandra.get_cassandra_yaml_file(),
                         '/foo/cassandra.yaml')

    @patch('cassandra.get_cassandra_config_dir')
    def test_get_cassandra_env_file(self, get_cassandra_config_dir):
        get_cassandra_config_dir.return_value = '/foo'
        self.assertEqual(cassandra.get_cassandra_env_file(),
                         '/foo/cassandra-env.sh')

    @patch('cassandra.get_cassandra_config_dir')
    def test_get_cassandra_rackdc_file(self, get_cassandra_config_dir):
        get_cassandra_config_dir.return_value = '/foo'
        self.assertEqual(cassandra.get_cassandra_rackdc_file(),
                         '/foo/cassandra-rackdc.properties')

    @patch('cassandra.get_cassandra_edition')
    def test_write_config(self, get_edition):
        get_edition.return_value = 'whatever'
        expected = 'some config'
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'foo')
            cassandra.write_config(path, expected)
            with open(path, 'r') as fp:
                self.assertEqual(fp.read(), expected)

    @patch('subprocess.Popen')
    @patch('cassandra.get_cassandra_edition')
    def test_write_config_snap(self, get_edition, popen):
        get_edition.return_value = 'apache-snap'
        popen.return_value.returncode = 0
        popen.return_value.communicate.return_value = ('', '')
        cassandra.write_config('/some/path/to/config.yaml', 'some config')
        expected = 'some config'
        self.assertEqual([call(['/snap/bin/cassandra.config-set',
                                'config.yaml'],
                               stdin=subprocess.PIPE, universal_newlines=True),
                          call().communicate(input=expected)],
                         popen.mock_calls)

    @patch('cassandra.get_cassandra_edition')
    def test_get_cassandra_pid_file(self, get_edition):
        get_edition.return_value = 'whatever'
        self.assertEqual(cassandra.get_cassandra_pid_file(),
                         '/var/run/cassandra/cassandra.pid')
        get_edition.return_value = 'dse'
        self.assertEqual(cassandra.get_cassandra_pid_file(),
                         '/var/run/dse/dse.pid')

    def test_get_cassandra_packages(self):
        # Default
        self.assertSetEqual(cassandra.get_cassandra_packages(),
                            set(['cassandra', 'run-one',
                                 'netcat', 'openjdk-8-jre-headless']))

    def test_get_cassandra_packages_oracle_jre(self):
        # Oracle JRE
        hookenv.config()['jre'] = 'oracle'
        self.assertSetEqual(cassandra.get_cassandra_packages(),
                            set(['cassandra', 'run-one', 'netcat']))

    def test_get_cassandra_packages_dse(self):
        # DataStax Enterprise, and implicit Oracle JRE.
        hookenv.config()['edition'] = 'dsE'  # Insensitive.
        self.assertSetEqual(cassandra.get_cassandra_packages(),
                            set(['dse-full', 'run-one', 'netcat']))

    @patch('cassandra.get_cassandra_service')
    @patch('charmhelpers.core.host.service_stop')
    @patch('cassandra.is_cassandra_running')
    def test_stop_cassandra(self, is_cassandra_running,
                            service_stop, get_service):
        get_service.return_value = sentinel.service_name
        is_cassandra_running.side_effect = iter([True, False])
        cassandra.stop_cassandra()
        service_stop.assert_called_once_with(sentinel.service_name)

    @patch('cassandra.get_cassandra_service')
    @patch('charmhelpers.core.host.service_stop')
    @patch('cassandra.is_cassandra_running')
    def test_stop_cassandra_noop(self, is_cassandra_running,
                                 service_stop, get_service):
        get_service.return_value = sentinel.service_name
        is_cassandra_running.return_value = False
        cassandra.stop_cassandra()
        self.assertFalse(service_stop.called)

    @patch('charmhelpers.core.hookenv.status_set')
    @patch('cassandra.get_cassandra_service')
    @patch('charmhelpers.core.host.service_stop')
    @patch('cassandra.is_cassandra_running')
    def test_stop_cassandra_failure(self, is_cassandra_running,
                                    service_stop, get_service, status_set):
        get_service.return_value = sentinel.service_name
        is_cassandra_running.side_effect = iter([True, True])
        self.assertRaises(SystemExit, cassandra.stop_cassandra)
        service_stop.assert_called_once_with(sentinel.service_name)
        status_set.assert_called_once_with('blocked',
                                           'Cassandra failed to shut down')

    @patch('cassandra.actual_seed_ips')
    @patch('time.sleep')
    @patch('cassandra.get_cassandra_service')
    @patch('charmhelpers.core.host.service_start')
    @patch('cassandra.is_cassandra_running')
    def test_start_cassandra(self, is_cassandra_running,
                             service_start, get_service, sleep, seed_ips):
        get_service.return_value = sentinel.service_name
        seed_ips.return_value = set(['1.2.3.4'])
        is_cassandra_running.return_value = True
        cassandra.start_cassandra()
        self.assertFalse(service_start.called)

        is_cassandra_running.side_effect = iter([False, False, False, True])
        cassandra.start_cassandra()
        service_start.assert_called_once_with(sentinel.service_name)

        # A side effect of starting cassandra is storing the current live
        # seed list, so we can tell when it has changed.
        self.assertEqual(hookenv.config()['configured_seeds'], ['1.2.3.4'])

    @patch('os.chmod')
    @patch('cassandra.is_cassandra_running')
    @patch('relations.StorageRelation')
    def test_remount_cassandra(self, storage, is_running, chmod):
        config = hookenv.config()
        storage().needs_remount.return_value = True
        storage().mountpoint = '/srv/foo'
        is_running.return_value = False
        config['data_file_directories'] = '/srv/ext/data1 data2'
        config['bootstrapped_into_cluster'] = True

        cassandra.remount_cassandra()
        storage().migrate.assert_called_once_with('/var/lib/cassandra',
                                                  'cassandra')
        chmod.assert_called_once_with('/srv/foo/cassandra', 0o750)
        self.assertEqual(config['bootstrapped_into_cluster'], False)

    @patch('os.chmod')
    @patch('cassandra.is_cassandra_running')
    @patch('relations.StorageRelation')
    def test_remount_cassandra_noop(self, storage, is_running, chmod):
        storage().needs_remount.return_value = False
        storage().mountpoint = None
        is_running.return_value = False

        cassandra.remount_cassandra()
        self.assertFalse(storage().migrate.called)
        self.assertFalse(chmod.called)

    @patch('cassandra.is_cassandra_running')
    @patch('relations.StorageRelation')
    def test_remount_cassandra_unmount(self, storage, is_running):
        storage().needs_remount.return_value = True
        storage().mountpoint = None  # Reverting to local disk.
        is_running.return_value = False
        hookenv.config()['data_file_directories'] = '/srv/ext/data1 data2'

        cassandra.remount_cassandra()

        # We cannot migrate data back to local disk, as by the time our
        # hooks are called the data is gone.
        self.assertFalse(storage().migrate.called)

        # We warn in this case, as reverting to local disk may resurrect
        # old data (if the cluster was ever time while using local
        # disk).
        hookenv.log.assert_any_call(ANY, hookenv.WARNING)

    @patch('cassandra.ensure_database_directory')
    @patch('cassandra.get_all_database_directories')
    def test_ensure_database_directories(self, get_all_dirs, ensure_dir):
        get_all_dirs.return_value = dict(
            data_file_directories=[sentinel.data_file_dir_1,
                                   sentinel.data_file_dir_2],
            commitlog_directory=sentinel.commitlog_dir,
            saved_caches_directory=sentinel.saved_caches_dir)
        cassandra.ensure_database_directories()
        ensure_dir.assert_has_calls([
            call(sentinel.data_file_dir_1),
            call(sentinel.data_file_dir_2),
            call(sentinel.commitlog_dir),
            call(sentinel.saved_caches_dir)], any_order=True)

    @patch('cassandra.cluster.Cluster')
    @patch('cassandra.auth.PlainTextAuthProvider')
    @patch('cassandra.superuser_credentials')
    @patch('cassandra.read_cassandra_yaml')
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

        with cassandra.connect() as session:
            auth_provider.assert_called_once_with(username='un',
                                                  password='pw')
            cluster.assert_called_once_with(['1.2.3.4'], port=666,
                                            auth_provider=sentinel.ap)
            self.assertIs(session, sentinel.session)
            self.assertFalse(cluster().shutdown.called)

        cluster().shutdown.assert_called_once_with()

    @patch('cassandra.cluster.Cluster')
    @patch('cassandra.auth.PlainTextAuthProvider')
    @patch('cassandra.superuser_credentials')
    @patch('cassandra.read_cassandra_yaml')
    def test_connect_with_creds(self, yaml, creds, auth_provider, cluster):
        # host and port are pulled from the current active
        # cassandra.yaml file, rather than configuration, as
        # configuration may not match reality (if for no other reason
        # that we are running this code in order to make reality match
        # the desired configuration).
        yaml.return_value = dict(rpc_address='1.2.3.4',
                                 native_transport_port=666)

        auth_provider.return_value = sentinel.ap

        with cassandra.connect(username='explicit', password='boo'):
            auth_provider.assert_called_once_with(username='explicit',
                                                  password='boo')

    @patch('time.sleep')
    @patch('time.time')
    @patch('cassandra.cluster.Cluster')
    @patch('cassandra.superuser_credentials')
    @patch('cassandra.read_cassandra_yaml')
    def test_connect_badauth(self, yaml, creds, cluster, time, sleep):
        # host and port are pulled from the current active
        # cassandra.yaml file, rather than configuration, as
        # configuration may not match reality (if for no other reason
        # that we are running this code in order to make reality match
        # the desired configuration).
        yaml.return_value = dict(rpc_address='1.2.3.4',
                                 native_transport_port=666)
        time.side_effect = [0, 7, 99999]

        creds.return_value = ('un', 'pw')

        x = NoHostAvailable('whoops', {'1.2.3.4': AuthenticationFailed()})
        cluster().connect.side_effect = x

        self.assertRaises(AuthenticationFailed, cassandra.connect().__enter__)

        # Authentication failures are retried, but for a shorter time
        # than other connection errors which are retried for a few
        # minutes.
        self.assertEqual(cluster().connect.call_count, 2)
        self.assertEqual(cluster().shutdown.call_count, 2)

    @patch('time.sleep')
    @patch('time.time')
    @patch('cassandra.cluster.Cluster')
    @patch('cassandra.superuser_credentials')
    @patch('cassandra.read_cassandra_yaml')
    def test_connect_timeout(self, yaml, creds, cluster, time, sleep):
        yaml.return_value = dict(rpc_address='1.2.3.4',
                                 native_transport_port=666)
        time.side_effect = [0, 1, 2, 3, 10, 20, 30, 40, 99999]

        creds.return_value = ('un', 'pw')

        x = NoHostAvailable('whoops', {'1.2.3.4': sentinel.exception})
        cluster().connect.side_effect = x

        self.assertRaises(NoHostAvailable, cassandra.connect().__enter__)

        # Authentication failures fail immediately, unlike other
        # connection errors which are retried.
        self.assertEqual(cluster().connect.call_count, 5)
        self.assertEqual(cluster().shutdown.call_count, 5)
        self.assertEqual(sleep.call_count, 4)

    @patch('cassandra.query.SimpleStatement')
    def test_query(self, simple_statement):
        simple_statement.return_value = sentinel.s_statement
        session = MagicMock()
        session.execute.return_value = sentinel.results
        self.assertEqual(cassandra.query(session, sentinel.statement,
                                       sentinel.consistency, sentinel.args),
                         sentinel.results)
        simple_statement.assert_called_once_with(
            sentinel.statement, consistency_level=sentinel.consistency)
        session.execute.assert_called_once_with(simple_statement(''),
                                                sentinel.args)

    @patch('cassandra.query.SimpleStatement')
    @patch('cassandra.backoff')
    def test_query_retry(self, backoff, simple_statement):
        backoff.return_value = repeat(True)
        simple_statement.return_value = sentinel.s_statement
        session = MagicMock()
        session.execute.side_effect = iter([RuntimeError(), sentinel.results])
        self.assertEqual(cassandra.query(session, sentinel.statement,
                                       sentinel.consistency, sentinel.args),
                         sentinel.results)
        self.assertEqual(session.execute.call_count, 2)

    @patch('time.time')
    @patch('cassandra.query.SimpleStatement')
    @patch('cassandra.backoff')
    def test_query_timeout(self, backoff, simple_statement, time):
        backoff.return_value = repeat(True)
        # Timeout is 600
        time.side_effect = iter([0, 1, 2, 3, 500, 700, RuntimeError()])
        simple_statement.return_value = sentinel.s_statement
        session = MagicMock()

        class Whoops(Exception):
            pass

        session.execute.side_effect = repeat(Whoops('Fail'))
        self.assertRaises(Whoops, cassandra.query, session, sentinel.statement,
                          sentinel.consistency, sentinel.args)
        self.assertEqual(session.execute.call_count, 4)

    @patch('cassandra.get_cassandra_version')
    @patch('cassandra.query')
    def test_ensure_user(self, query, ver):
        ver.return_value = '2.1'
        cassandra.ensure_user(sentinel.session,
                            sentinel.username, sentinel.pwhash,
                            superuser=sentinel.supflag)
        query.assert_has_calls([
            call(sentinel.session,
                 'INSERT INTO system_auth.users (name, super) VALUES (%s, %s)',
                 ConsistencyLevel.ALL, (sentinel.username, sentinel.supflag)),
            call(sentinel.session,
                 'INSERT INTO system_auth.credentials (username, salted_hash) '
                 'VALUES (%s, %s)',
                 ConsistencyLevel.ALL,
                 (sentinel.username, sentinel.pwhash))])

    @patch('cassandra.get_cassandra_version')
    @patch('cassandra.query')
    def test_ensure_user_22(self, query, ver):
        ver.return_value = '2.2'
        cassandra.ensure_user(sentinel.session,
                            sentinel.username, sentinel.pwhash,
                            superuser=sentinel.supflag)
        query.assert_called_once_with(sentinel.session,
                                      'INSERT INTO system_auth.roles (role, '
                                      'can_login, is_superuser, salted_hash) '
                                      'VALUES (%s, TRUE, %s, %s)',
                                      ConsistencyLevel.ALL,
                                      (sentinel.username, sentinel.supflag,
                                       sentinel.pwhash))

    @patch('cassandra.ensure_user')
    @patch('cassandra.encrypt_password')
    @patch('cassandra.nodetool')
    @patch('cassandra.reconfigure_and_restart_cassandra')
    @patch('cassandra.connect')
    @patch('cassandra.superuser_credentials')
    def test_create_unit_superuser_hard(self, creds, connect, restart,
                                        nodetool, encrypt_password,
                                        ensure_user):
        creds.return_value = (sentinel.username, sentinel.password)
        connect().__enter__.return_value = sentinel.session
        connect().__exit__.return_value = False
        connect.reset_mock()

        encrypt_password.return_value = sentinel.pwhash

        cassandra.create_unit_superuser_hard()

        # Cassandra was restarted twice, first with authentication
        # disabled and again with the normal configuration.
        restart.assert_has_calls([
            call(dict(authenticator='AllowAllAuthenticator',
                      rpc_address='localhost')),
            call()])

        # A connection was made as the superuser, which words because
        # authentication has been disabled on this node.
        connect.assert_called_once_with()

        # The user was created.
        encrypt_password.assert_called_once_with(sentinel.password)
        ensure_user.assert_called_once_with(sentinel.session,
                                            sentinel.username,
                                            sentinel.pwhash,
                                            superuser=True)

        # Local Cassandra was flushed. This is probably unnecessary.
        nodetool.assert_called_once_with('flush')

    def test_cqlshrc_path(self):
        self.assertEqual(cassandra.get_cqlshrc_path(),
                         '/root/.cassandra/cqlshrc')

    def test_superuser_username(self):
        self.assertEqual(hookenv.local_unit(), 'service/1')
        self.assertEqual(cassandra.superuser_username(), 'juju_service_1')

    @patch('cassandra.superuser_username')
    @patch('cassandra.get_cqlshrc_path')
    @patch('cassandra.get_cassandra_version')
    @patch('charmhelpers.core.host.pwgen')
    def test_superuser_credentials_20(self, pwgen, get_cassandra_version,
                                      get_cqlshrc_path, get_username):
        get_cassandra_version.return_value = '2.0'
        with tempfile.TemporaryDirectory() as dotcassandra_dir:
            cqlshrc_path = os.path.join(dotcassandra_dir, 'cqlshrc')
            get_cqlshrc_path.return_value = cqlshrc_path
            get_username.return_value = 'foo'
            pwgen.return_value = 'secret'
            hookenv.config()['rpc_port'] = 666
            hookenv.config()['native_transport_port'] = 777

            # First time generates username & password.
            username, password = cassandra.superuser_credentials()
            self.assertEqual(username, 'foo')
            self.assertEqual(password, 'secret')

            # Credentials are stored in the cqlshrc file.
            expected_cqlshrc = dedent('''\
                                      [authentication]
                                      username = foo
                                      password = secret

                                      [connection]
                                      hostname = 10.30.0.1
                                      port = 666
                                      ''').strip()
            with open(cqlshrc_path, 'r') as f:
                self.assertEqual(f.read().strip(), expected_cqlshrc)

            # If the credentials have been stored, they are not
            # regenerated.
            pwgen.return_value = 'secret2'
            username, password = cassandra.superuser_credentials()
            self.assertEqual(username, 'foo')
            self.assertEqual(password, 'secret')
            with open(cqlshrc_path, 'r') as f:
                self.assertEqual(f.read().strip(), expected_cqlshrc)

    @patch('cassandra.superuser_username')
    @patch('cassandra.get_cqlshrc_path')
    @patch('cassandra.get_cassandra_version')
    @patch('charmhelpers.core.host.pwgen')
    def test_superuser_credentials(self, pwgen, get_cassandra_version,
                                   get_cqlshrc_path, get_username):
        # Cassandra 2.1 or higher uses native protocol in its cqlshrc
        get_cassandra_version.return_value = '2.1'
        with tempfile.TemporaryDirectory() as dotcassandra_dir:
            cqlshrc_path = os.path.join(dotcassandra_dir, 'cqlshrc')
            get_cqlshrc_path.return_value = cqlshrc_path
            get_username.return_value = 'foo'
            pwgen.return_value = 'secret'
            hookenv.config()['rpc_port'] = 666
            hookenv.config()['native_transport_port'] = 777

            # First time generates username & password.
            username, password = cassandra.superuser_credentials()
            self.assertEqual(username, 'foo')
            self.assertEqual(password, 'secret')

            # Credentials are stored in the cqlshrc file.
            expected_cqlshrc = dedent('''\
                                      [authentication]
                                      username = foo
                                      password = secret

                                      [connection]
                                      hostname = 10.30.0.1
                                      port = 777
                                      ''').strip()
            with open(cqlshrc_path, 'r') as f:
                self.assertEqual(f.read().strip(), expected_cqlshrc)

    @patch('subprocess.check_output')
    def test_nodetool(self, check_output):
        check_output.return_value = 'OK'
        self.assertEqual(cassandra.nodetool('status', 'system_auth'), 'OK')

        # The expected command was run against the local node.
        check_output.assert_called_once_with(
            ['nodetool', 'status', 'system_auth'],
            universal_newlines=True, stderr=subprocess.STDOUT, timeout=119)

        # The output was emitted.
        cassandra.emit.assert_called_once_with('OK')

    @patch('cassandra.is_cassandra_running')
    @patch('cassandra.backoff')
    @patch('subprocess.check_output')
    def test_nodetool_CASSANDRA_8776(self, check_output, backoff, is_running):
        is_running.return_value = True
        backoff.return_value = repeat(True)
        check_output.side_effect = iter(['ONE Error: stuff', 'TWO OK'])
        self.assertEqual(cassandra.nodetool('status'), 'TWO OK')

        # The output was emitted.
        cassandra.emit.assert_called_once_with('TWO OK')

    @patch('cassandra.is_cassandra_running')
    @patch('cassandra.backoff')
    @patch('subprocess.check_output')
    def test_nodetool_retry(self, check_output, backoff, is_running):
        backoff.return_value = repeat(True)
        is_running.return_value = True
        check_output.side_effect = iter([
            subprocess.CalledProcessError([], 1, 'fail 1'),
            subprocess.CalledProcessError([], 1, 'fail 2'),
            subprocess.CalledProcessError([], 1, 'fail 3'),
            subprocess.CalledProcessError([], 1, 'fail 4'),
            subprocess.CalledProcessError([], 1, 'fail 5'),
            'OK'])
        self.assertEqual(cassandra.nodetool('status'), 'OK')

        # Later fails and final output was emitted.
        cassandra.emit.assert_has_calls([call('fail 5'), call('OK')])

    @patch('cassandra.get_bootstrapped_ips')
    def test_num_nodes(self, bootstrapped_ips):
        bootstrapped_ips.return_value = ['10.0.0.1', '10.0.0.2']
        self.assertEqual(cassandra.num_nodes(), 2)

    @patch('cassandra.get_cassandra_yaml_file')
    def test_read_cassandra_yaml(self, get_cassandra_yaml_file):
        with tempfile.NamedTemporaryFile('w') as f:
            f.write('a: one')
            f.flush()
            get_cassandra_yaml_file.return_value = f.name
            self.assertDictEqual(cassandra.read_cassandra_yaml(),
                                 dict(a='one'))

    @patch('cassandra.get_cassandra_yaml_file')
    def test_write_cassandra_yaml(self, get_cassandra_yaml_file):
        with tempfile.NamedTemporaryFile() as f:
            get_cassandra_yaml_file.return_value = f.name
            cassandra.write_cassandra_yaml([1, 2, 3])
            with open(f.name, 'r') as f2:
                self.assertEqual(f2.read(), '[1, 2, 3]\n')

    @patch('cassandra.get_cassandra_version')
    @patch('cassandra.get_cassandra_yaml_file')
    @patch('cassandra.get_seed_ips')
    @patch('charmhelpers.core.host.write_file')
    def test_configure_cassandra_yaml_20(self, write_file, seed_ips, yaml_file,
                                         get_cassandra_version):
        get_cassandra_version.return_value = '2.0'
        hookenv.config().update(dict(num_tokens=128,
                                     cluster_name='test_cluster_name',
                                     file_cache_size_in_mb=768,
                                     partitioner='test_partitioner'))

        seed_ips.return_value = ['10.20.0.1', '10.20.0.2', '10.20.0.3']

        existing_config = '''
            seed_provider:
                - class_name: blah.SimpleSeedProvider
                  parameters:
                      - seeds: 127.0.0.1  # Comma separated list.
            '''

        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_config = os.path.join(tmpdir, 'c.yaml')
            yaml_file.return_value = yaml_config
            with open(yaml_config, 'w', encoding='UTF-8') as f:
                f.write(existing_config)

            cassandra.configure_cassandra_yaml()

            self.assertEqual(write_file.call_count, 2)
            new_config = write_file.call_args[0][1]

            expected_config = dedent('''\
                cluster_name: test_cluster_name
                authenticator: PasswordAuthenticator
                num_tokens: 128
                file_cache_size_in_mb: 768
                partitioner: test_partitioner
                listen_address: 10.20.0.1
                rpc_address: 0.0.0.0
                rpc_port: 9160
                native_transport_port: 9042
                storage_port: 7000
                ssl_storage_port: 7001
                authorizer: AllowAllAuthorizer
                seed_provider:
                    - class_name: blah.SimpleSeedProvider
                      parameters:
                        # No whitespace in seeds is important.
                        - seeds: '10.20.0.1,10.20.0.2,10.20.0.3'
                endpoint_snitch: GossipingPropertyFileSnitch
                data_file_directories:
                    - /var/lib/cassandra/data
                commitlog_directory: /var/lib/cassandra/commitlog
                saved_caches_directory: /var/lib/cassandra/saved_caches
                compaction_throughput_mb_per_sec: 16
                stream_throughput_outbound_megabits_per_sec: 200
                tombstone_warn_threshold: 1000
                tombstone_failure_threshold: 100000
                start_rpc: true
                ''')
            self.maxDiff = None
            self.assertEqual(yaml.safe_load(new_config),
                             yaml.safe_load(expected_config))

            # Confirm we can use an explicit cluster_name too.
            write_file.reset_mock()
            hookenv.config()['cluster_name'] = 'fubar'
            cassandra.configure_cassandra_yaml()
            new_config = write_file.call_args[0][1]
            self.assertEqual(yaml.safe_load(new_config)['cluster_name'],
                             'fubar')

    @patch('cassandra.get_cassandra_version')
    @patch('cassandra.get_cassandra_yaml_file')
    @patch('cassandra.get_seed_ips')
    @patch('charmhelpers.core.host.write_file')
    def test_configure_cassandra_yaml_22(self, write_file, seed_ips, yaml_file,
                                         get_cassandra_version):
        get_cassandra_version.return_value = '2.0'
        hookenv.config().update(dict(num_tokens=128,
                                     cluster_name='test_cluster_name',
                                     file_cache_size_in_mb=768,
                                     partitioner='test_partitioner'))

        seed_ips.return_value = ['10.20.0.1', '10.20.0.2', '10.20.0.3']

        existing_config = '''
            seed_provider:
                - class_name: blah.SimpleSeedProvider
                  parameters:
                      - seeds: 127.0.0.1  # Comma separated list.
            start_rpc: false  # Defaults to False starting 2.2
            '''

        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_config = os.path.join(tmpdir, 'c.yaml')
            yaml_file.return_value = yaml_config
            with open(yaml_config, 'w', encoding='UTF-8') as f:
                f.write(existing_config)

            cassandra.configure_cassandra_yaml()

            self.assertEqual(write_file.call_count, 2)
            new_config = write_file.call_args[0][1]

            expected_config = dedent('''\
                start_rpc: true
                cluster_name: test_cluster_name
                authenticator: PasswordAuthenticator
                num_tokens: 128
                file_cache_size_in_mb: 768
                partitioner: test_partitioner
                listen_address: 10.20.0.1
                rpc_address: 0.0.0.0
                rpc_port: 9160
                native_transport_port: 9042
                storage_port: 7000
                ssl_storage_port: 7001
                authorizer: AllowAllAuthorizer
                seed_provider:
                    - class_name: blah.SimpleSeedProvider
                      parameters:
                        # No whitespace in seeds is important.
                        - seeds: '10.20.0.1,10.20.0.2,10.20.0.3'
                endpoint_snitch: GossipingPropertyFileSnitch
                data_file_directories:
                    - /var/lib/cassandra/data
                commitlog_directory: /var/lib/cassandra/commitlog
                saved_caches_directory: /var/lib/cassandra/saved_caches
                compaction_throughput_mb_per_sec: 16
                stream_throughput_outbound_megabits_per_sec: 200
                tombstone_warn_threshold: 1000
                tombstone_failure_threshold: 100000
                ''')
            self.maxDiff = None
            self.assertEqual(yaml.safe_load(new_config),
                             yaml.safe_load(expected_config))

            # Confirm we can use an explicit cluster_name too.
            write_file.reset_mock()
            hookenv.config()['cluster_name'] = 'fubar'
            cassandra.configure_cassandra_yaml()
            new_config = write_file.call_args[0][1]
            self.assertEqual(yaml.safe_load(new_config)['cluster_name'],
                             'fubar')

    @patch('cassandra.get_cassandra_version')
    @patch('cassandra.get_cassandra_yaml_file')
    @patch('cassandra.get_seed_ips')
    @patch('charmhelpers.core.host.write_file')
    def test_configure_cassandra_yaml(self, write_file, seed_ips,
                                      yaml_file, get_cassandra_version):
        get_cassandra_version.return_value = '2.1'
        hookenv.config().update(dict(num_tokens=128,
                                     file_cache_size_in_mb=768,
                                     cluster_name='test_cluster_name',
                                     partitioner='test_partitioner'))

        seed_ips.return_value = ['10.20.0.1', '10.20.0.2', '10.20.0.3']

        existing_config = '''
            seed_provider:
                - class_name: blah.SimpleSeedProvider
                  parameters:
                      - seeds: 127.0.0.1  # Comma separated list.
            '''

        with tempfile.TemporaryDirectory() as tmpdir:
            yaml_config = os.path.join(tmpdir, 'c.yaml')
            yaml_file.return_value = yaml_config
            with open(yaml_config, 'w', encoding='UTF-8') as f:
                f.write(existing_config)

            cassandra.configure_cassandra_yaml()

            self.assertEqual(write_file.call_count, 2)
            new_config = write_file.call_args[0][1]

            expected_config = dedent('''\
                cluster_name: test_cluster_name
                authenticator: PasswordAuthenticator
                num_tokens: 128
                file_cache_size_in_mb: 768
                partitioner: test_partitioner
                listen_address: 10.20.0.1
                rpc_address: 0.0.0.0
                broadcast_rpc_address: 10.30.0.1
                start_rpc: true
                rpc_port: 9160
                native_transport_port: 9042
                storage_port: 7000
                ssl_storage_port: 7001
                authorizer: AllowAllAuthorizer
                seed_provider:
                    - class_name: blah.SimpleSeedProvider
                      parameters:
                        # No whitespace in seeds is important.
                        - seeds: '10.20.0.1,10.20.0.2,10.20.0.3'
                endpoint_snitch: GossipingPropertyFileSnitch
                data_file_directories:
                    - /var/lib/cassandra/data
                commitlog_directory: /var/lib/cassandra/commitlog
                saved_caches_directory: /var/lib/cassandra/saved_caches
                compaction_throughput_mb_per_sec: 16
                stream_throughput_outbound_megabits_per_sec: 200
                tombstone_warn_threshold: 1000
                tombstone_failure_threshold: 100000
                ''')
            self.maxDiff = None
            self.assertEqual(yaml.safe_load(new_config),
                             yaml.safe_load(expected_config))

    @patch('cassandra.get_cassandra_version')
    @patch('cassandra.get_cassandra_yaml_file')
    @patch('cassandra.get_seed_ips')
    @patch('charmhelpers.core.host.write_file')
    def test_configure_cassandra_yaml_overrides(self, write_file, seed_ips,
                                                yaml_file, version):
        version.return_value = '2.1'
        hookenv.config().update(dict(num_tokens=128,
                                     cluster_name=None,
                                     partitioner='my_partitioner'))

        seed_ips.return_value = ['10.20.0.1', '10.20.0.2', '10.20.0.3']

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

            cassandra.configure_cassandra_yaml(overrides=overrides)

            self.assertEqual(write_file.call_count, 2)
            new_config = write_file.call_args[0][1]

            self.assertEqual(yaml.safe_load(new_config)['partitioner'],
                             'overridden_partitioner')

    def test_get_pid_from_file(self):
        with tempfile.NamedTemporaryFile('w') as pid_file:
            pid_file.write(' 42\t')
            pid_file.flush()
            self.assertEqual(cassandra.get_pid_from_file(pid_file.name), 42)
            pid_file.write('\nSome Noise')
            pid_file.flush()
            self.assertEqual(cassandra.get_pid_from_file(pid_file.name), 42)

        for invalid_pid in ['-1', '0', 'fred']:
            with self.subTest(invalid_pid=invalid_pid):
                with tempfile.NamedTemporaryFile('w') as pid_file:
                    pid_file.write(invalid_pid)
                    pid_file.flush()
                    self.assertRaises(ValueError,
                                      cassandra.get_pid_from_file, pid_file.name)

        with tempfile.TemporaryDirectory() as tmpdir:
            self.assertRaises(OSError, cassandra.get_pid_from_file,
                              os.path.join(tmpdir, 'invalid.pid'))

    @patch('cassandra.get_cassandra_pid_file')
    def test_is_cassandra_running_not_running(self, get_pid_file):
        # When Cassandra is not running, the pidfile does not exist.
        get_pid_file.return_value = 'does not exist'
        self.assertFalse(cassandra.is_cassandra_running())

    @patch('os.path.exists')
    @patch('cassandra.get_pid_from_file')
    def test_is_cassandra_running_invalid_pid(self, get_pid_from_file, exists):
        # get_pid_from_file raises a ValueError if the pid is illegal.
        get_pid_from_file.side_effect = repeat(ValueError('Whoops'))
        exists.return_value = True  # The pid file is there, just insane.

        # is_cassandra_running() fails hard in this case, since we
        # cannot safely continue when the system is insane.
        self.assertRaises(ValueError, cassandra.is_cassandra_running)

    @patch('os.kill')
    @patch('os.path.exists')
    @patch('cassandra.get_pid_from_file')
    def test_is_cassandra_running_missing_process(self, get_pid_from_file,
                                                  exists, kill):
        # get_pid_from_file raises a ValueError if the pid is illegal.
        get_pid_from_file.return_value = sentinel.pid_file
        exists.return_value = True  # The pid file is there
        kill.side_effect = repeat(ProcessLookupError())  # The process isn't
        self.assertFalse(cassandra.is_cassandra_running())

    @patch('os.kill')
    @patch('os.path.exists')
    @patch('cassandra.get_pid_from_file')
    def test_is_cassandra_running_wrong_user(self, get_pid_from_file,
                                             exists, kill):
        # get_pid_from_file raises a ValueError if the pid is illegal.
        get_pid_from_file.return_value = sentinel.pid_file
        exists.return_value = True  # The pid file is there
        kill.side_effect = repeat(PermissionError())  # But the process isn't
        self.assertRaises(PermissionError, cassandra.is_cassandra_running)

    @patch('time.sleep')
    @patch('os.kill')
    @patch('cassandra.get_pid_from_file')
    @patch('subprocess.call')
    def test_is_cassandra_running_starting_up(self, call, get_pid_from_file,
                                              kill, sleep):
        sleep.return_value = None  # Don't actually sleep in unittests.
        os.kill.return_value = True  # There is a running pid.
        get_pid_from_file.return_value = 42
        subprocess.call.side_effect = iter([3, 2, 1, 0])  # 4th time the charm
        self.assertTrue(cassandra.is_cassandra_running())

    @patch('cassandra.backoff')
    @patch('os.kill')
    @patch('subprocess.call')
    @patch('cassandra.get_pid_from_file')
    def test_is_cassandra_running_shutting_down(self, get_pid_from_file,
                                                call, kill, backoff):
        # If Cassandra is in the process of shutting down, it might take
        # several failed checks before the pid file disappears.
        backoff.return_value = repeat(True)
        os.kill.return_value = None  # The process is running
        call.return_value = 1  # But nodetool is not succeeding.

        # Fourth time, the pid file is gone.
        get_pid_from_file.side_effect = iter([42, 42, 42,
                                              FileNotFoundError('Whoops')])
        self.assertFalse(cassandra.is_cassandra_running())

    @patch('os.kill')
    @patch('subprocess.call')
    @patch('os.path.exists')
    @patch('cassandra.get_pid_from_file')
    def test_is_cassandra_running_failsafe(self, get_pid_from_file,
                                           exists, subprocess_call, kill):
        get_pid_from_file.return_value = sentinel.pid_file
        exists.return_value = True  # The pid file is there
        subprocess_call.side_effect = repeat(RuntimeError('whoops'))
        # Weird errors are reraised.
        self.assertRaises(RuntimeError, cassandra.is_cassandra_running)

    @patch('cassandra.get_cassandra_version')
    @patch('cassandra.query')
    def test_get_auth_keyspace_replication(self, query, ver):
        ver.return_value = '2.2'
        query.return_value = [('{"json": true}',)]
        settings = cassandra.get_auth_keyspace_replication(sentinel.session)
        self.assertDictEqual(settings, dict(json=True))
        query.assert_called_once_with(
            sentinel.session, dedent('''\
                SELECT strategy_options FROM system.schema_keyspaces
                WHERE keyspace_name='system_auth'
                '''), ConsistencyLevel.QUORUM)

    @patch('cassandra.get_cassandra_version')
    @patch('cassandra.query')
    def test_get_auth_keyspace_replication_30(self, query, ver):
        ver.return_value = '3.0'
        query.return_value = [({"json": True},)]  # Decoded under 3.0
        settings = cassandra.get_auth_keyspace_replication(sentinel.session)
        self.assertDictEqual(settings, dict(json=True))
        query.assert_called_once_with(
            sentinel.session, dedent('''\
                SELECT replication FROM system_schema.keyspaces
                WHERE keyspace_name='system_auth'
                '''), ConsistencyLevel.QUORUM)

    @patch('cassandra.status_set')
    @patch('charmhelpers.core.hookenv.status_get')
    @patch('cassandra.query')
    def test_set_auth_keyspace_replication(self, query,
                                           status_get, status_set):
        status_get.return_value = ('active', '')
        settings = dict(json=True)
        cassandra.set_auth_keyspace_replication(sentinel.session, settings)
        query.assert_called_once_with(sentinel.session,
                                      'ALTER KEYSPACE system_auth '
                                      'WITH REPLICATION = %s',
                                      ConsistencyLevel.ALL, (settings,))

    @patch('cassandra.status_set')
    @patch('charmhelpers.core.hookenv.status_get')
    @patch('cassandra.nodetool')
    def test_repair_auth_keyspace(self, nodetool, status_get, status_set):
        status_get.return_value = (sentinel.status, '')
        cassandra.repair_auth_keyspace()
        status_set.assert_called_once_with(sentinel.status,
                                           'Repairing system_auth keyspace')
        # The repair operation may still fail, and I am currently regularly
        # seeing 'snapshot creation' errors. Repair also takes ages with
        # Cassandra 2.0. So retry until success, up to 1 hour.
        nodetool.assert_called_once_with('repair', 'system_auth', timeout=3600)

    def test_is_bootstrapped(self):
        self.assertFalse(cassandra.is_bootstrapped())
        cassandra.set_bootstrapped()
        self.assertTrue(cassandra.is_bootstrapped())

    @patch('cassandra.get_node_status')
    def test_is_decommissioned(self, get_node_status):
        get_node_status.return_value = 'DECOMMISSIONED'
        self.assertTrue(cassandra.is_decommissioned())
        get_node_status.return_value = 'LEAVING'
        self.assertTrue(cassandra.is_decommissioned())
        get_node_status.return_value = 'NORMAL'
        self.assertFalse(cassandra.is_decommissioned())

    @patch('cassandra.nodetool')
    def test_emit_describe_cluster(self, nodetool):
        cassandra.emit_describe_cluster()
        nodetool.assert_called_once_with('describecluster')

    @patch('cassandra.nodetool')
    def test_emit_status(self, nodetool):
        cassandra.emit_status()
        nodetool.assert_called_once_with('status')

    @patch('cassandra.nodetool')
    def test_emit_netstats(self, nodetool):
        cassandra.emit_netstats()
        nodetool.assert_called_once_with('netstats')

    def test_week_spread(self):
        # The first seven units run midnight on different days.
        for i in range(0, 7):  # There is no unit 0
            with self.subTest(unit=i):
                self.assertTupleEqual(cassandra.week_spread(i), (i, 0, 0))

        # The next seven units run midday on different days.
        for i in range(7, 14):
            with self.subTest(unit=i):
                self.assertTupleEqual(cassandra.week_spread(i), (i - 7, 12, 0))

        # And the next seven units at 6 am on different days.
        for i in range(14, 21):
            with self.subTest(unit=i):
                self.assertTupleEqual(cassandra.week_spread(i), (i - 14, 6, 0))

        # This keeps going as best we can, subdividing the hours.
        self.assertTupleEqual(cassandra.week_spread(811), (6, 19, 18))

        # The granularity is 1 minute, so eventually we wrap after about
        # 7000 units.
        self.assertTupleEqual(cassandra.week_spread(0), (0, 0, 0))
        for i in range(1, 7168):
            with self.subTest(unit=i):
                self.assertNotEqual(cassandra.week_spread(i), (0, 0, 0))
        self.assertTupleEqual(cassandra.week_spread(7168), (0, 0, 0))

    def test_local_plugins_dir(self):
        self.assertEqual(cassandra.local_plugins_dir(),
                         '/usr/local/lib/nagios/plugins')

    def test_update_hosts_file_new_entry(self):
        org = dedent("""\
                     127.0.0.1 localhost
                     10.0.1.2 existing
                     """)
        new = dedent("""\
                     127.0.0.1 localhost
                     10.0.1.2 existing
                     10.0.1.3 newname
                     """)
        with tempfile.NamedTemporaryFile(mode='w') as f:
            f.write(org)
            f.flush()
            m = {'10.0.1.3': 'newname'}
            cassandra.update_hosts_file(f.name, m)
            self.assertEqual(new.strip(), open(f.name, 'r').read().strip())

    def test_update_hosts_file_changed_entry(self):
        org = dedent("""\
                     127.0.0.1 localhost
                     10.0.1.2 existing
                     """)
        new = dedent("""\
                     127.0.0.1 localhost
                     10.0.1.3 existing
                     """)
        with tempfile.NamedTemporaryFile(mode='w') as f:
            f.write(org)
            f.flush()
            m = {'10.0.1.3': 'existing'}
            cassandra.update_hosts_file(f.name, m)
            self.assertEqual(new.strip(), open(f.name, 'r').read().strip())


@patch('netifaces.ifaddresses')
@patch('netifaces.interfaces')
@patch('charmhelpers.core.hookenv.log')
class TestInterfaceToIp(unittest.TestCase):

    def test_ipv4(self, log, interfaces, ifaddresses):
        interfaces.return_value = [sentinel.interface]
        ifaddresses.return_value = {
            netifaces.AF_INET: [{'addr': sentinel.v4_addr}],
        }
        self.assertEqual(cassandra.interface_to_ip(sentinel.interface),
                         sentinel.v4_addr)
        self.assertFalse(log.called)

    def test_ipv6(self, log, interfaces, ifaddresses):
        interfaces.return_value = [sentinel.interface]
        ifaddresses.return_value = {
            netifaces.AF_INET6: [{'addr': sentinel.v6_addr}]
        }
        self.assertEqual(cassandra.interface_to_ip(sentinel.interface),
                         sentinel.v6_addr)
        self.assertFalse(log.called)

    def test_ipv4_and_ipv6(self, log, interfaces, ifaddresses):
        interfaces.return_value = [sentinel.interface]
        ifaddresses.return_value = {
            netifaces.AF_INET: [{'addr': sentinel.v4_addr}],
            netifaces.AF_INET6: [{'addr': sentinel.v6_addr}],
        }
        self.assertIsNone(cassandra.interface_to_ip(sentinel.interface))
        log.assert_called_once_with(ANY, hookenv.ERROR)

    def test_missing_interface(self, log, interfaces, ifaddresses):
        interfaces.return_value = [sentinel.interface]
        self.assertIsNone(cassandra.interface_to_ip(sentinel.different))
        log.assert_called_once_with(ANY, hookenv.ERROR)

    def test_empty_addr_entry(self, log, interfaces, ifaddresses):
        interfaces.return_value = [sentinel.interface]
        ifaddresses.return_value = {
            netifaces.AF_INET: [{}, {'addr': sentinel.v4_addr}],
        }
        self.assertEqual(cassandra.interface_to_ip(sentinel.interface),
                         sentinel.v4_addr)
        self.assertFalse(log.called)

    def test_multi_addr(self, log, interfaces, ifaddresses):
        interfaces.return_value = [sentinel.interface]
        ifaddresses.return_value = {
            netifaces.AF_INET: [{'addr': sentinel.addr1},
                                {'addr': sentinel.addr2}],
        }
        self.assertIsNone(cassandra.interface_to_ip(sentinel.interface))
        log.assert_called_once_with(ANY, hookenv.ERROR)

    def test_no_addr(self, log, interfaces, ifaddresses):
        interfaces.return_value = [sentinel.interface]
        ifaddresses.return_value = {
            netifaces.AF_INET: [],
        }
        self.assertIsNone(cassandra.interface_to_ip(sentinel.interface))
        log.assert_called_once_with(ANY, hookenv.ERROR)


if __name__ == '__main__':
    unittest.main(verbosity=2)
