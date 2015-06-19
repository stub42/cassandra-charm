#!.venv3/bin/python3

# Copyright 2015 Canonical Ltd.
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
import yaml

from charmhelpers import fetch
from charmhelpers.core import hookenv, host

from tests.base import TestCaseBase
import helpers


patch = functools.partial(patch, autospec=True)


class TestHelpers(TestCaseBase):
    @patch('time.sleep')
    def test_backoff(self, sleep):
        i = 0
        for _ in helpers.backoff('foo to bar'):
            i += 1
            if i == 10:
                break
        sleep.assert_has_calls([
            call(2), call(4), call(8), call(16), call(32),
            call(60), call(60), call(60), call(60)])

        i = 0
        for _ in helpers.backoff('foo to bar', max_pause=10):
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

    @patch('helpers.autostart_disabled')
    @patch('charmhelpers.fetch.apt_install')
    def test_install_packages(self, apt_install, autostart_disabled):
        packages = ['a_pack', 'b_pack']
        helpers.install_packages(packages)

        # All packages got installed, and hook aborted if package
        # installation failed.
        apt_install.assert_called_once_with(['a_pack', 'b_pack'], fatal=True)

        # The autostart_disabled context manager was used to stop
        # package installation starting services.
        autostart_disabled().__enter__.assert_called_once_with()
        autostart_disabled().__exit__.assert_called_once_with(None, None, None)

    @patch('helpers.autostart_disabled')
    @patch('charmhelpers.fetch.apt_install')
    def test_install_packages_extras(self, apt_install, autostart_disabled):
        packages = ['a_pack', 'b_pack']
        hookenv.config()['extra_packages'] = 'c_pack d_pack'
        helpers.install_packages(packages)

        # All packages got installed, and hook aborted if package
        # installation failed.
        apt_install.assert_called_once_with(['a_pack', 'b_pack',
                                             'c_pack', 'd_pack'], fatal=True)

        # The autostart_disabled context manager was used to stop
        # package installation starting services.
        autostart_disabled().__enter__.assert_called_once_with()
        autostart_disabled().__exit__.assert_called_once_with(None, None, None)

    @patch('helpers.autostart_disabled')
    @patch('charmhelpers.fetch.apt_install')
    def test_install_packages_noop(self, apt_install, autostart_disabled):
        # Everything is already installed. Nothing to do.
        fetch.filter_installed_packages.side_effect = lambda pkgs: []

        packages = ['a_pack', 'b_pack']
        hookenv.config()['extra_packages'] = 'c_pack d_pack'
        helpers.install_packages(packages)

        # All packages got installed, and hook aborted if package
        # installation failed.
        self.assertFalse(apt_install.called)

        # Autostart wasn't messed with.
        self.assertFalse(autostart_disabled.called)

    @patch('subprocess.Popen')
    def test_ensure_package_status(self, popen):
        for status in ['install', 'hold']:
            with self.subTest(status=status):
                popen.reset_mock()
                hookenv.config()['package_status'] = status
                helpers.ensure_package_status(['a_pack', 'b_pack'])

                selections = 'a_pack {}\nb_pack {}\n'.format(
                    status, status).encode('US-ASCII')

                self.assertEqual(
                    [call(['dpkg', '--set-selections'], stdin=subprocess.PIPE),
                     call().communicate(input=selections)], popen.mock_calls)

        popen.reset_mock()
        hookenv.config()['package_status'] = 'invalid'
        self.assertRaises(RuntimeError,
                          helpers.ensure_package_status, ['a_pack', 'b_back'])
        self.assertFalse(popen.called)

    @patch('helpers.is_bootstrapped')
    def test_get_seed_ips(self, is_bootstrapped):
        hookenv.local_unit.return_value = 'service/1'
        get_peers.return_value = set(['service/2', 'service/3', 'service/4'])
        is_bootstrapped.return_value = True

        # The first three units are used as the seed list.
        self.assertSetEqual(helpers.get_seed_ips(), set(['10.20.0.1',
                                                         '10.20.0.2',
                                                         '10.20.0.3']))

    def test_seed_ips_alone(self):
        hookenv.local_unit.return_value = 'service/1'
        get_peers.return_value = set()

        # # The first three units are used as the seed list, except for
        # # the local unit (so seed nodes list up to two seeds and the
        # # remaining nodes list up to three seeds).
        # self.assertEqual(hookenv.unit_private_ip(), '10.20.0.1')

        self.assertSetEqual(helpers.get_seed_ips(), set(['10.20.0.1']))

    @patch('helpers.read_cassandra_yaml')
    def test_actual_seed_ips(self, read_yaml):
        read_yaml.return_value = yaml.load(dedent('''\
                                                  seed_provider:
                                                    - class_name: blah
                                                      parameters:
                                                        - seeds: a,b,c
                                                  '''))
        self.assertSetEqual(helpers.actual_seed_ips(),
                            set(['a', 'b', 'c']))

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
        absdir = '/an/absolute/dir'
        is_running.return_value = False
        get_db_dir.return_value = absdir

        # ensure_database_directory() returns the absolute path.
        self.assertEqual(helpers.ensure_database_directory(absdir), absdir)

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

        helpers.set_io_scheduler('fnord', '/foo')

        write_file.assert_called_once_with('/sys/block/sdq/queue/scheduler',
                                           b'fnord', perms=0o644)

        # Some OSErrors we log warnings for, and continue.
        for e in (errno.EACCES, errno.ENOENT):
            with self.subTest(errno=e):
                write_file.side_effect = repeat(OSError(e, 'Whoops'))
                hookenv.log.reset_mock()
                helpers.set_io_scheduler('fnord', '/foo')
                hookenv.log.assert_has_calls([call(ANY),
                                              call(ANY, hookenv.WARNING)])

        # Other OSErrors just fail hard.
        write_file.side_effect = iter([OSError(errno.EFAULT, 'Whoops')])
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

    def test_get_jre(self):
        hookenv.config()['jre'] = 'opEnjdk'  # Case insensitive
        self.assertEqual(helpers.get_jre(), 'openjdk')

        hookenv.config()['jre'] = 'oRacle'  # Case insensitive
        self.assertEqual(helpers.get_jre(), 'oracle')

    def test_get_jre_unknown(self):
        hookenv.config()['jre'] = 'OopsJDK'
        self.assertEqual(helpers.get_jre(), 'openjdk')
        # An error was logged.
        hookenv.log.assert_called_once_with(ANY, hookenv.ERROR)

    def test_get_jre_dse_override(self):
        hookenv.config()['edition'] = 'dse'
        self.assertEqual(helpers.get_jre(), 'oracle')

    def test_get_cassandra_edition(self):
        hookenv.config()['edition'] = 'community'
        self.assertEqual(helpers.get_cassandra_edition(), 'community')

        hookenv.config()['edition'] = 'DSE'  # Case insensitive
        self.assertEqual(helpers.get_cassandra_edition(), 'dse')

        self.assertFalse(hookenv.log.called)

        hookenv.config()['edition'] = 'typo'  # Default to community
        self.assertEqual(helpers.get_cassandra_edition(), 'community')
        hookenv.log.assert_any_call(ANY, hookenv.ERROR)  # Logs an error.

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
        self.assertEqual(helpers.get_cassandra_version(), '2.0')
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

    def test_get_cassandra_packages(self):
        # Default
        self.assertSetEqual(helpers.get_cassandra_packages(),
                            set(['cassandra', 'ntp', 'run-one',
                                 'netcat', 'openjdk-7-jre-headless']))

    def test_get_cassandra_packages_oracle_jre(self):
        # Oracle JRE
        hookenv.config()['jre'] = 'oracle'
        self.assertSetEqual(helpers.get_cassandra_packages(),
                            set(['cassandra', 'ntp', 'run-one', 'netcat']))

    def test_get_cassandra_packages_dse(self):
        # DataStax Enterprise, and implicit Oracle JRE.
        hookenv.config()['edition'] = 'dsE'  # Insensitive.
        self.assertSetEqual(helpers.get_cassandra_packages(),
                            set(['dse-full', 'ntp', 'run-one', 'netcat']))

    @patch('helpers.wait_for_normality')
    @patch('helpers.get_cassandra_service')
    @patch('charmhelpers.core.host.service_stop')
    @patch('helpers.is_cassandra_running')
    def test_stop_cassandra(self, is_cassandra_running, service_stop,
                            get_service, wait_for_normality):
        get_service.return_value = sentinel.service_name
        is_cassandra_running.side_effect = iter([True, False])
        helpers.stop_cassandra()
        service_stop.assert_called_once_with(sentinel.service_name)
        wait_for_normality.assert_called_once_with()

    @patch('helpers.wait_for_normality')
    @patch('helpers.get_cassandra_service')
    @patch('charmhelpers.core.host.service_stop')
    @patch('helpers.is_cassandra_running')
    def test_stop_cassandra_immediate(self, is_cassandra_running, service_stop,
                                      get_service, wait_for_normality):
        get_service.return_value = sentinel.service_name
        is_cassandra_running.side_effect = iter([True, False])
        helpers.stop_cassandra(immediate=True)
        service_stop.assert_called_once_with(sentinel.service_name)
        self.assertFalse(wait_for_normality.called)

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
        self.assertRaises(AssertionError,
                          helpers.stop_cassandra, immediate=True)
        service_stop.assert_called_once_with(sentinel.service_name)

    @patch('helpers.actual_seed_ips')
    @patch('time.sleep')
    @patch('helpers.get_cassandra_service')
    @patch('charmhelpers.core.host.service_start')
    @patch('helpers.is_cassandra_running')
    def test_start_cassandra(self, is_cassandra_running,
                             service_start, get_service, sleep, seed_ips):
        get_service.return_value = sentinel.service_name
        seed_ips.return_value = sentinel.just_for_logging
        is_cassandra_running.return_value = True
        helpers.start_cassandra()
        self.assertFalse(service_start.called)

        is_cassandra_running.side_effect = iter([False, False, False, True])
        helpers.start_cassandra()
        service_start.assert_called_once_with(sentinel.service_name)

    @patch('helpers.actual_seed_ips')
    @patch('time.time')
    @patch('time.sleep')
    @patch('helpers.get_cassandra_service')
    @patch('charmhelpers.core.host.service_start')
    @patch('helpers.is_cassandra_running')
    def test_start_cassandra_timeout(self, is_cassandra_running,
                                     service_start, get_service, sleep, time,
                                     seed_ips):
        get_service.return_value = sentinel.service_name
        seed_ips.return_value = sentinel.just_for_logging
        is_cassandra_running.return_value = False
        time.side_effect = iter([10, 20, 30, 40, 3600])
        self.assertRaises(SystemExit, helpers.start_cassandra)
        service_start.assert_called_once_with(sentinel.service_name)
        # An error was logged.
        hookenv.log.assert_has_calls([call(ANY, hookenv.ERROR)])

    @patch('helpers.is_responding')
    @patch('helpers.node_ips')
    def test_are_all_nodes_responding(self, node_ips, is_responding):
        node_ips.return_value = set([sentinel.ip1, sentinel.ip2])
        is_responding.return_value = sentinel.success
        self.assertTrue(helpers.are_all_nodes_responding())
        is_responding.assert_has_calls([call(ip=sentinel.ip1, timeout=5),
                                        call(ip=sentinel.ip2, timeout=5)],
                                       any_order=True)

    @patch('helpers.is_responding')
    @patch('helpers.node_ips')
    def test_are_all_nodes_responding_fail(self, node_ips, is_responding):
        node_ips.return_value = set([sentinel.ip1, sentinel.ip2])
        is_responding.side_effect = iter([True, False, Exception('only two')])
        self.assertFalse(helpers.are_all_nodes_responding())

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
        config = hookenv.config()
        storage().needs_remount.return_value = True
        storage().mountpoint = '/srv/foo'
        is_running.return_value = False
        config['data_file_directories'] = '/srv/ext/data1 data2'
        config['bootstrapped_into_cluster'] = True

        helpers.remount_cassandra()
        storage().migrate.assert_called_once_with('/var/lib/cassandra',
                                                  'cassandra')
        chmod.assert_called_once_with('/srv/foo/cassandra', 0o750)
        self.assertEqual(config['bootstrapped_into_cluster'], False)

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
        connect().__enter__.return_value = sentinel.session
        connect().__exit__.return_value = False
        connect.reset_mock()
        helpers.reset_default_password()
        connect.assert_called_once_with('cassandra', 'cassandra')
        query.assert_called_once_with(
            sentinel.session, 'ALTER USER cassandra WITH PASSWORD %s',
            ConsistencyLevel.QUORUM, (sentinel.password,))

        # Second time, nothing.
        connect.reset_mock()
        helpers.reset_default_password()
        self.assertFalse(connect.called)

    @patch('helpers.query')
    @patch('helpers.connect')
    def test_reset_default_password_already_done(self, connect, query):
        connect().__enter__.side_effect = repeat(AuthenticationFailed())
        connect().__exit__.return_value = False
        helpers.reset_default_password()
        self.assertFalse(query.called)  # Nothing happened.

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

        with helpers.connect(username='explicit', password='boo'):
            auth_provider.assert_called_once_with(username='explicit',
                                                  password='boo')

    @patch('time.sleep')
    @patch('time.time')
    @patch('cassandra.cluster.Cluster')
    @patch('helpers.superuser_credentials')
    @patch('helpers.read_cassandra_yaml')
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

        self.assertRaises(AuthenticationFailed, helpers.connect().__enter__)

        # Authentication failures are retried, but for a shorter time
        # than other connection errors which are retried for a few
        # minutes.
        self.assertEqual(cluster().connect.call_count, 2)
        self.assertEqual(cluster().shutdown.call_count, 2)

    @patch('time.sleep')
    @patch('time.time')
    @patch('cassandra.cluster.Cluster')
    @patch('helpers.superuser_credentials')
    @patch('helpers.read_cassandra_yaml')
    def test_connect_timeout(self, yaml, creds, cluster, time, sleep):
        yaml.return_value = dict(rpc_address='1.2.3.4',
                                 native_transport_port=666)
        time.side_effect = [0, 10, 20, 30, 40, 99999]

        creds.return_value = ('un', 'pw')

        x = NoHostAvailable('whoops', {'1.2.3.4': sentinel.exception})
        cluster().connect.side_effect = x

        self.assertRaises(NoHostAvailable, helpers.connect().__enter__)

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
        self.assertEqual(helpers.query(session, sentinel.statement,
                                       sentinel.consistency, sentinel.args),
                         sentinel.results)
        simple_statement.assert_called_once_with(
            sentinel.statement, consistency_level=sentinel.consistency)
        session.execute.assert_called_once_with(simple_statement(''),
                                                sentinel.args)

    @patch('cassandra.query.SimpleStatement')
    @patch('helpers.backoff')
    def test_query_retry(self, backoff, simple_statement):
        backoff.return_value = repeat(True)
        simple_statement.return_value = sentinel.s_statement
        session = MagicMock()
        session.execute.side_effect = iter([RuntimeError(), sentinel.results])
        self.assertEqual(helpers.query(session, sentinel.statement,
                                       sentinel.consistency, sentinel.args),
                         sentinel.results)
        self.assertEqual(session.execute.call_count, 2)

    @patch('time.time')
    @patch('cassandra.query.SimpleStatement')
    @patch('helpers.backoff')
    def test_query_timeout(self, backoff, simple_statement, time):
        backoff.return_value = repeat(True)
        # Timeout is 600
        time.side_effect = iter([0, 1, 2, 3, 500, 700, RuntimeError()])
        simple_statement.return_value = sentinel.s_statement
        session = MagicMock()

        class Whoops(Exception):
            pass

        session.execute.side_effect = repeat(Whoops('Fail'))
        self.assertRaises(Whoops, helpers.query, session, sentinel.statement,
                          sentinel.consistency, sentinel.args)
        self.assertEqual(session.execute.call_count, 4)

    @patch('helpers.query')
    @patch('helpers.connect')
    def test_ensure_user(self, connect, query):
        connect().__enter__.return_value = sentinel.session
        connect().__exit__.return_value = False
        helpers.ensure_user(sentinel.username, sentinel.password)
        query.assert_has_calls([
            call(sentinel.session,
                 'CREATE USER IF NOT EXISTS %s WITH PASSWORD %s NOSUPERUSER',
                 ConsistencyLevel.QUORUM,
                 (sentinel.username, sentinel.password)),
            call(sentinel.session,
                 'ALTER USER %s WITH PASSWORD %s NOSUPERUSER',
                 ConsistencyLevel.QUORUM,
                 (sentinel.username, sentinel.password))])

    @patch('helpers.query')
    @patch('helpers.connect')
    def test_ensure_user_superuser(self, connect, query):
        connect().__enter__.return_value = sentinel.session
        connect().__exit__.return_value = False
        helpers.ensure_user(sentinel.username, sentinel.password, True)
        query.assert_has_calls([
            call(sentinel.session,
                 'CREATE USER IF NOT EXISTS %s WITH PASSWORD %s SUPERUSER',
                 ConsistencyLevel.QUORUM,
                 (sentinel.username, sentinel.password)),
            call(sentinel.session,
                 'ALTER USER %s WITH PASSWORD %s SUPERUSER',
                 ConsistencyLevel.QUORUM,
                 (sentinel.username, sentinel.password))])

    @patch('helpers.create_unit_superuser')
    @patch('helpers.connect')
    def test_ensure_unit_superuser(self, connect, create_unit_superuser):
        connect().__enter__.side_effect = iter([AuthenticationFailed(),
                                                sentinel.session])
        connect().__exit__.return_value = False
        connect.reset_mock()

        helpers.ensure_unit_superuser()
        create_unit_superuser.assert_called_once_with()  # Account created.

    @patch('helpers.create_unit_superuser')
    @patch('helpers.connect')
    def test_ensure_unit_superuser_exists(self, connect,
                                          create_unit_superuser):
        connect().__enter__.return_value = sentinel.session
        connect().__exit__.return_value = False
        connect.reset_mock()

        # If connect works, nothing happens
        helpers.ensure_unit_superuser()
        connect.assert_called_once_with(auth_timeout=10)  # As Superuser.
        self.assertFalse(create_unit_superuser.called)  # No need to create.

    @patch('helpers.emit_cluster_info')
    @patch('helpers.wait_for_normality')
    @patch('helpers.query')
    @patch('bcrypt.gensalt')
    @patch('bcrypt.hashpw')
    @patch('helpers.nodetool')
    @patch('helpers.reconfigure_and_restart_cassandra')
    @patch('helpers.connect')
    @patch('helpers.superuser_credentials')
    def test_create_unit_superuser(self, creds, connect, restart, nodetool,
                                   bhash, bsalt, query, normwait, emit_info):
        creds.return_value = ('super', 'secret')
        connect().__enter__.return_value = sentinel.session
        connect().__exit__.return_value = False
        connect.reset_mock()

        bsalt.return_value = sentinel.salt
        bhash.return_value = 'pwhash'

        helpers.create_unit_superuser()

        # Cassandra was restarted twice, first with authentication
        # disabled and again with the normal configuration.
        restart.assert_has_calls([
            call(dict(authenticator='AllowAllAuthenticator',
                      rpc_address='localhost')),
            call()])

        # We also waited several times, guarding the necessary node
        # restarts.
        self.assertTrue(normwait.called)

        # A connection was made as the superuser.
        connect.assert_called_once_with()

        # Statements run to create or update the user.
        query.assert_has_calls([
            call(sentinel.session,
                 dedent('''\
                        INSERT INTO system_auth.users (name, super)
                        VALUES (%s, TRUE)
                        '''),
                 ConsistencyLevel.QUORUM, ('super',)),
            call(sentinel.session,
                 dedent('''\
                    INSERT INTO system_auth.credentials (username, salted_hash)
                    VALUES (%s, %s)
                        '''),
                 ConsistencyLevel.QUORUM, ('super', 'pwhash'))])

        # Local Cassandra was flushed.
        nodetool.assert_called_once_with('flush')

    def test_cqlshrc_path(self):
        self.assertEqual(helpers.get_cqlshrc_path(),
                         '/root/.cassandra/cqlshrc')

    def test_superuser_username(self):
        self.assertEqual(hookenv.local_unit(), 'service/1')
        self.assertEqual(helpers.superuser_username(), 'juju_service_1')

    @patch('helpers.superuser_username')
    @patch('helpers.get_cqlshrc_path')
    @patch('helpers.get_cassandra_version')
    @patch('charmhelpers.core.host.pwgen')
    def test_superuser_credentials(self, pwgen, get_cassandra_version,
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
            username, password = helpers.superuser_credentials()
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
            get_username.return_value = 'bar'
            pwgen.return_value = 'secret2'
            username, password = helpers.superuser_credentials()
            self.assertEqual(username, 'foo')
            self.assertEqual(password, 'secret')
            with open(cqlshrc_path, 'r') as f:
                self.assertEqual(f.read().strip(), expected_cqlshrc)

    @patch('helpers.superuser_username')
    @patch('helpers.get_cqlshrc_path')
    @patch('helpers.get_cassandra_version')
    @patch('charmhelpers.core.host.pwgen')
    def test_superuser_credentials_21plus(self, pwgen, get_cassandra_version,
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
            username, password = helpers.superuser_credentials()
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
        self.assertEqual(helpers.nodetool('status', 'system_auth'), 'OK')

        # The expected command was run against the local node.
        check_output.assert_called_once_with(
            ['nodetool', 'status', 'system_auth'],
            universal_newlines=True, stderr=subprocess.STDOUT, timeout=119)

        # The output was emitted.
        helpers.emit.assert_called_once_with('OK')

    @patch('helpers.backoff')
    @patch('subprocess.check_output')
    def test_nodetool_CASSANDRA_8776(self, check_output, backoff):
        backoff.return_value = repeat(True)
        check_output.side_effect = iter(['ONE Error: stuff', 'TWO OK'])
        self.assertEqual(helpers.nodetool('status', 'system_auth'), 'TWO OK')

        # The output was emitted.
        helpers.emit.assert_called_once_with('TWO OK')

    @patch('helpers.backoff')
    @patch('subprocess.check_output')
    def test_nodetool_retry(self, check_output, backoff):
        backoff.return_value = repeat(True)
        check_output.side_effect = iter([
            subprocess.CalledProcessError([], 1, 'fail 1'),
            subprocess.CalledProcessError([], 1, 'fail 2'),
            subprocess.CalledProcessError([], 1, 'fail 3'),
            subprocess.CalledProcessError([], 1, 'fail 4'),
            subprocess.CalledProcessError([], 1, 'fail 5'),
            'OK'])
        self.assertEqual(helpers.nodetool('status', 'system_auth'), 'OK')

        # Later fails and final output was emitted.
        helpers.emit.assert_has_calls([call('fail 5'), call('OK')])

    @patch('helpers.node_ips')
    def test_num_nodes(self, node_ips):
        node_ips.return_value = ['10.0.0.1', '10.0.0.2']
        self.assertEqual(helpers.num_nodes(), 2)

    def test_num_peers(self):
        get_peers.return_value = ['a', 'b']
        self.assertEqual(helpers.num_peers(), 2)

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

    @patch('helpers.get_cassandra_version')
    @patch('helpers.get_cassandra_yaml_file')
    @patch('helpers.get_seed_ips')
    @patch('charmhelpers.core.host.write_file')
    def test_configure_cassandra_yaml(self, write_file, seed_ips, yaml_file,
                                      get_cassandra_version):
        get_cassandra_version.return_value = '2.0'
        hookenv.config().update(dict(num_tokens=128,
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

            helpers.configure_cassandra_yaml()

            self.assertEqual(write_file.call_count, 2)
            new_config = write_file.call_args[0][1]

            expected_config = dedent('''\
                cluster_name: test_cluster_name
                authenticator: PasswordAuthenticator
                num_tokens: 128
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
            helpers.configure_cassandra_yaml()
            new_config = write_file.call_args[0][1]
            self.assertEqual(yaml.safe_load(new_config)['cluster_name'],
                             'fubar')

    @patch('helpers.get_cassandra_version')
    @patch('helpers.get_cassandra_yaml_file')
    @patch('helpers.get_seed_ips')
    @patch('charmhelpers.core.host.write_file')
    def test_configure_cassandra_yaml_21(self, write_file, seed_ips,
                                         yaml_file, get_cassandra_version):
        get_cassandra_version.return_value = '2.1'
        hookenv.config().update(dict(num_tokens=128,
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

            helpers.configure_cassandra_yaml()

            self.assertEqual(write_file.call_count, 2)
            new_config = write_file.call_args[0][1]

            expected_config = dedent('''\
                cluster_name: test_cluster_name
                authenticator: PasswordAuthenticator
                num_tokens: 128
                partitioner: test_partitioner
                listen_address: 10.20.0.1
                rpc_address: 0.0.0.0
                broadcast_rpc_address: 10.30.0.1
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

    @patch('helpers.get_cassandra_version')
    @patch('helpers.get_cassandra_yaml_file')
    @patch('helpers.get_seed_ips')
    @patch('charmhelpers.core.host.write_file')
    def test_configure_cassandra_yaml_overrides(self, write_file, seed_ips,
                                                yaml_file, version):
        version.return_value = '2.0'
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

    @patch('helpers.get_cassandra_pid_file')
    def test_is_cassandra_running_not_running(self, get_pid_file):
        # When Cassandra is not running, the pidfile does not exist.
        get_pid_file.return_value = 'does not exist'
        self.assertFalse(helpers.is_cassandra_running())

    @patch('os.path.exists')
    @patch('helpers.get_pid_from_file')
    def test_is_cassandra_running_invalid_pid(self, get_pid_from_file, exists):
        # get_pid_from_file raises a ValueError if the pid is illegal.
        get_pid_from_file.side_effect = repeat(ValueError('Whoops'))
        exists.return_value = True  # The pid file is there, just insane.

        # is_cassandra_running() fails hard in this case, since we
        # cannot safely continue when the system is insane.
        self.assertRaises(ValueError, helpers.is_cassandra_running)

    @patch('os.kill')
    @patch('os.path.exists')
    @patch('helpers.get_pid_from_file')
    def test_is_cassandra_running_missing_process(self, get_pid_from_file,
                                                  exists, kill):
        # get_pid_from_file raises a ValueError if the pid is illegal.
        get_pid_from_file.return_value = sentinel.pid_file
        exists.return_value = True  # The pid file is there
        kill.side_effect = repeat(ProcessLookupError())  # The process isn't
        self.assertFalse(helpers.is_cassandra_running())

    @patch('os.kill')
    @patch('os.path.exists')
    @patch('helpers.get_pid_from_file')
    def test_is_cassandra_running_wrong_user(self, get_pid_from_file,
                                             exists, kill):
        # get_pid_from_file raises a ValueError if the pid is illegal.
        get_pid_from_file.return_value = sentinel.pid_file
        exists.return_value = True  # The pid file is there
        kill.side_effect = repeat(PermissionError())  # But the process isn't
        self.assertRaises(PermissionError, helpers.is_cassandra_running)

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

    @patch('helpers.backoff')
    @patch('os.kill')
    @patch('subprocess.call')
    @patch('helpers.get_pid_from_file')
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
        self.assertFalse(helpers.is_cassandra_running())

    @patch('os.kill')
    @patch('subprocess.call')
    @patch('os.path.exists')
    @patch('helpers.get_pid_from_file')
    def test_is_cassandra_running_failsafe(self, get_pid_from_file,
                                           exists, subprocess_call, kill):
        get_pid_from_file.return_value = sentinel.pid_file
        exists.return_value = True  # The pid file is there
        subprocess_call.side_effect = repeat(RuntimeError('whoops'))
        # Weird errors are reraised.
        self.assertRaises(RuntimeError, helpers.is_cassandra_running)

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

    @patch('helpers.repair_auth_keyspace')
    @patch('helpers.set_auth_keyspace_replication')
    @patch('helpers.get_auth_keyspace_replication')
    @patch('helpers.connect')
    @patch('helpers.num_nodes')
    def test_reset_auth_keyspace_replication(self, num_nodes, connect,
                                             get_rep, set_rep, repair):
        connect().__enter__.return_value = sentinel.session
        connect().__exit__.return_value = False
        num_nodes.return_value = 8
        get_rep.return_value = {'replication_factor': 18}
        helpers.reset_auth_keyspace_replication()
        set_rep.assert_called_once_with(sentinel.session,
                                        {'class': 'NetworkTopologyStrategy',
                                         'juju': 3})  # Capped rf==3
        repair.assert_called_once_with()

    @patch('helpers.repair_auth_keyspace')
    @patch('helpers.set_auth_keyspace_replication')
    @patch('helpers.get_auth_keyspace_replication')
    @patch('helpers.connect')
    @patch('helpers.num_nodes')
    def test_reset_auth_keyspace_replication_cap(self, num_nodes, connect,
                                                 get_rep, set_rep, repair):
        connect().__enter__.return_value = sentinel.session
        connect().__exit__.return_value = False
        num_nodes.return_value = 8
        get_rep.return_value = {'class': 'NetworkTopologyStrategy',
                                'juju': 8,
                                'other_dc': 2}
        helpers.reset_auth_keyspace_replication()
        self.assertTrue(set_rep.called)  # Reset to our cap of rf==5
        self.assertTrue(repair.called)

    @patch('helpers.repair_auth_keyspace')
    @patch('helpers.set_auth_keyspace_replication')
    @patch('helpers.get_auth_keyspace_replication')
    @patch('helpers.connect')
    @patch('helpers.num_nodes')
    def test_reset_auth_keyspace_replication_noop(self, num_nodes, connect,
                                                  get_rep, set_rep, repair):
        connect().__enter__.return_value = sentinel.session
        connect().__exit__.return_value = False
        num_nodes.return_value = 8
        get_rep.return_value = {'class': 'NetworkTopologyStrategy',
                                'juju': 3,
                                'other_dc': 2}
        helpers.reset_auth_keyspace_replication()
        self.assertFalse(set_rep.called)  # Already at our cap of rf==3
        self.assertFalse(repair.called)

    @patch('helpers.query')
    def test_get_auth_keyspace_replication(self, query):
        query.return_value = [('{"json": true}',)]
        settings = helpers.get_auth_keyspace_replication(sentinel.session)
        self.assertDictEqual(settings, dict(json=True))
        query.assert_called_once_with(
            sentinel.session, dedent('''\
                SELECT strategy_options FROM system.schema_keyspaces
                WHERE keyspace_name='system_auth'
                '''), ConsistencyLevel.QUORUM)

    @patch('helpers.wait_for_normality')
    @patch('helpers.query')
    def test_set_auth_keyspace_replication(self, query, wait):
        settings = dict(json=True)
        helpers.set_auth_keyspace_replication(sentinel.session, settings)
        wait.assert_called_once_with()  # Block until bootstraps etc. complete.
        query.assert_called_once_with(sentinel.session,
                                      'ALTER KEYSPACE system_auth '
                                      'WITH REPLICATION = %s',
                                      ConsistencyLevel.QUORUM, (settings,))

    @patch('helpers.nodetool')
    @patch('helpers.wait_for_agreed_schema')
    def test_repair_auth_keyspace(self, wait_for_schema, nodetool):
        helpers.repair_auth_keyspace()
        # First, we waited for schema sync to try to ensure
        # repair does not explode.
        wait_for_schema.assert_called_once_with()
        # The repair operation may still fail, and I am currently regularly
        # seeing 'snapshot creation' errors. Repair also takes ages with
        # Cassandra 2.0. So retry until success, up to 1 hour.
        nodetool.assert_called_once_with('repair', 'system_auth', timeout=3600)

    @patch('helpers.get_all_database_directories')
    def test_non_system_keyspaces(self, dbdirs):
        with tempfile.TemporaryDirectory() as dfd:
            for keyspace in ['system', 'system_auth', 'system_traces',
                             'dse_system', 'fred']:
                os.mkdir(os.path.join(dfd, keyspace))
            dbdirs.return_value = dict(data_file_directories=[dfd])
            self.assertSetEqual(helpers.non_system_keyspaces(), set(['fred']))

    @patch('helpers.nuke_directory_contents')
    @patch('helpers.get_all_database_directories')
    @patch('helpers.non_system_keyspaces')
    @patch('helpers.unit_number')
    @patch('helpers.is_bootstrapped')
    def test_nuke_local_database(self, is_bootstrapped, unit_number,
                                 non_system_keyspaces, dbdirs, nuke_dir):
        # Fails if called for a bootstrapped unit.
        is_bootstrapped.return_value = True
        self.assertRaises(AssertionError, helpers.nuke_local_database)

        # Fails if called for unit #0.
        is_bootstrapped.return_value = False
        unit_number.return_value = 0
        self.assertRaises(AssertionError, helpers.nuke_local_database)

        # Fails if there are non system keyspaces present, possibly
        # containing important data.
        unit_number.return_value = sentinel.unitnum
        non_system_keyspaces.return_value = set([sentinel.nsk])
        self.assertRaises(SystemExit, helpers.nuke_local_database)

        non_system_keyspaces.return_value = set()
        dbdirs.return_value = dict(saved_caches_directory=sentinel.scd,
                                   commitlog_directory=sentinel.cld,
                                   data_file_directories=[sentinel.dfd1,
                                                          sentinel.dfd2])
        helpers.nuke_local_database()
        nuke_dir.assert_has_calls([call(sentinel.scd),
                                   call(sentinel.cld),
                                   call(sentinel.dfd1),
                                   call(sentinel.dfd2)], any_order=True)

    def test_nuke_directory_contents(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, 'subdir'))
            with open(os.path.join(d, 'subdir', 'file'), 'w') as f:
                f.write('data')
            with open(os.path.join(d, 'topfile'), 'w') as f:
                f.write('data')
            helpers.nuke_directory_contents(d)
            self.assertSetEqual(set(os.listdir(d)), set())

    def test_unit_number(self):
        hookenv.local_unit.return_value = 'foo/0'
        self.assertEqual(helpers.unit_number(), 0)
        hookenv.local_unit.return_value = 'foo/94'
        self.assertEqual(helpers.unit_number(), 94)

    def test_is_bootstrapped(self):
        self.assertFalse(helpers.is_bootstrapped())
        helpers.set_bootstrapped(True)
        self.assertTrue(helpers.is_bootstrapped())
        helpers.set_bootstrapped(False)
        self.assertFalse(helpers.is_bootstrapped())

    @patch('charmhelpers.contrib.unison.collect_authed_hosts')
    @patch('helpers.get_seed_ips')
    @patch('helpers.peer_ips')
    @patch('helpers.node_ips')
    @patch('helpers.nuke_local_database')
    @patch('helpers.are_all_nodes_responding')
    @patch('helpers.num_peers')
    @patch('helpers.is_bootstrapped')
    def test_pre_bootstrap(self, is_bootstrapped, num_peers,
                           are_nodes_responding, nuke_all,
                           node_ips, peer_ips, seed_ips, authed_ips):
        is_bootstrapped.return_value = False
        num_peers.return_value = 1
        are_nodes_responding.return_value = True
        authed_ips.return_value = ['1.1.1.1']
        node_ips.return_value = set(['1.1.1.1'])
        peer_ips.return_value = set(['1.1.1.1'])
        seed_ips.return_value = set(['1.1.1.1'])

        helpers.pre_bootstrap()

        # Existing node destroyed.
        nuke_all.assert_called_once_with()

    @patch('helpers.is_cassandra_running')
    @patch('time.sleep')
    def test_post_bootstrap(self, sleep, is_running):
        hookenv.local_unit.return_value = 'foo/1'
        num_nodes.return_value = 3
        is_running.return_value = True
        is_normal.return_value = True
        self.assertFalse(helpers.is_bootstrapped())
        helpers.post_bootstrap()
        # Wait 2 minutes between nodes when initializing new nodes into
        # the cluster.
        sleep.assert_called_once_with(120)
        self.assertTrue(helpers.is_bootstrapped())

    @patch('helpers.unit_number')
    @patch('helpers.set_bootstrapped')
    @patch('helpers.num_peers')
    def test_post_bootstrap_alone(self, num_peers, set_bootstrapped, unum):
        unum.return_value = 1
        num_peers.return_value = 0  # Just us.
        helpers.post_bootstrap()  # Noop
        self.assertFalse(set_bootstrapped.called)

    @patch('helpers.nodetool')
    def test_up_node_ips(self, nodetool):
        nodetool.return_value = dedent('''\
                UN 10.0.0.1 whatever
                ?N 10.0.0.2 whatever
                UL 10.0.0.3 whatever
                ''')
        self.assertSetEqual(set(helpers.up_node_ips()), set(['10.0.0.1',
                                                             '10.0.0.3']))
        self.assertTrue(nodetool.called)

    @patch('helpers.up_node_ips')
    @patch('helpers.nodetool')
    def test_is_schema_agreed(self, nodetool, up_node_ips):
        up_node_ips.return_value = ['10.0.0.2', '10.0.0.3']
        self.assertEqual(hookenv.unit_private_ip(), '10.20.0.1')
        nodetool.return_value = dedent('''\
            Cluster Information:
            \tName: juju
            \tSnitch: org.apache.cassandra.locator.DynamicEndpointSnitch
            \tPartitioner: org.apache.cassandra.dht.Murmur3Partitioner
            \tSchema versions:
            \t\t15056434--0e7a98bbb067: [10.0.0.2, 10.20.0.1, 10.0.0.3]
            ''')
        self.assertTrue(helpers.is_schema_agreed())
        nodetool.assert_called_once_with('describecluster')

        nodetool.return_value = dedent('''\
            Cluster Information:
            \tName: juju
            \tSnitch: org.apache.cassandra.locator.DynamicEndpointSnitch
            \tPartitioner: org.apache.cassandra.dht.Murmur3Partitioner
            \tSchema versions:
            \t\t15056434--0e7a98bbb067: [10.0.0.3, 10.20.0.1]
            \t\t98735432--234567890111: [10.0.0.2]
            ''')
        self.assertFalse(helpers.is_schema_agreed())

    @patch('helpers.backoff')
    @patch('helpers.is_schema_agreed')
    def test_wait_for_agreed_schema(self, is_agreed, backoff):
        is_agreed.side_effect = iter([False, False, True, RuntimeError()])
        backoff.return_value = repeat(True)
        helpers.wait_for_agreed_schema()
        self.assertEqual(is_agreed.call_count, 3)

    def test_peer_ips(self):
        # IP addresses of the peers. Does not include the current unit.
        self.assertEqual(hookenv.unit_private_ip(), '10.20.0.1')
        self.assertSetEqual(helpers.peer_ips(),
                            set(['10.20.0.2', '10.20.0.3']))

    @patch('helpers.nodetool')
    def test_is_all_normal(self, nodetool):
        nodetool.return_value = dedent('''
            Datacenter: juju
            ================
            Status=Up/Down
            |/ State=Normal/Leaving/Joining/Moving
            --  Address     Load       Tokens  Owns (eff)  Host ID   Rack
            UN  10.0.3.179  131.72 KB  256     66.7%       bc1d-29   r1
            UN  10.0.3.197  123.94 KB  256     69.3%       65b2-d8   r1
            UN  10.0.3.236  109.75 KB  256     64.1%       e549-cf   r1
            ''')
        self.assertTrue(helpers.is_all_normal())

        nodetool.assert_called_once_with('status', 'system_auth', timeout=ANY)

        nodetool.return_value = 'UN  10.0.3.197 ...'
        self.assertTrue(helpers.is_all_normal())

        # Down is normal. Units destroyed without decommissioning leave
        # these entries, such as during service teardown. Be stricter
        # here once juju gives us more control and information during the
        # decommissioning process.
        nodetool.return_value = 'DN  10.0.3.197 ...'
        self.assertTrue(helpers.is_all_normal())

        # There is also an undocumented '?' Up/Down state which appears
        # while a node is bootstrapping. It is important we don't miss
        # this, or nodes will reboot without first waiting for any
        # in progress bootstraps and sabotaging them. CASSANDRA-8791.
        nodetool.return_value = '?N  10.0.3.197 ...'
        self.assertFalse(helpers.is_all_normal())

        nodetool.return_value = 'UJ  10.0.3.197 ...'
        self.assertFalse(helpers.is_all_normal())
        nodetool.return_value = 'DJ  10.0.3.197 ...'
        self.assertFalse(helpers.is_all_normal())

        nodetool.return_value = 'UM  10.0.3.197 ...'
        self.assertFalse(helpers.is_all_normal())
        nodetool.return_value = 'DM  10.0.3.197 ...'
        self.assertFalse(helpers.is_all_normal())

        nodetool.return_value = 'UL  10.0.3.197 ...'
        self.assertFalse(helpers.is_all_normal())
        nodetool.return_value = 'DL  10.0.3.197 ...'
        self.assertFalse(helpers.is_all_normal())

    @patch('helpers.backoff')
    @patch('helpers.is_all_normal')
    def test_wait_for_normality(self, is_all_normal, backoff):
        is_all_normal.side_effect = iter([False, False, True, RuntimeError()])
        backoff.return_value = repeat(True)
        helpers.wait_for_normality()
        self.assertEqual(is_all_normal.call_count, 3)

    @patch('helpers.backoff')
    @patch('helpers.nodetool')
    @patch('helpers.is_cassandra_running')
    def test_is_decommissioned(self, is_cassandra_running, nodetool, backoff):
        backoff.return_value = repeat(True)
        is_cassandra_running.return_value = True

        nodetool.return_value = 'rhubarb rhubarb Mode: NORMAL rhubarb'
        self.assertFalse(helpers.is_decommissioned())

        nodetool.return_value = 'rhubarb rhubarb Mode: DECOMMISSIONED rhubarb'
        self.assertTrue(helpers.is_decommissioned())

        # Unknown states are retried until NORMAL or DECOMMISSIONED is
        # reached.
        nodetool.side_effect = iter(['Mode: ONFIRE', 'Mode: NORMAL',
                                     'Mode: DECOMMISSIONED'])
        self.assertFalse(helpers.is_decommissioned())
        nodetool.side_effect = iter(['Mode: ONFIRE', 'Mode: DECOMMISSIONED',
                                     'Mode: NORMAL'])
        self.assertTrue(helpers.is_decommissioned())

        # Decommissioned nodes are not shut down. Therefore, if
        # Cassandra is not running it is not decommissioned.
        nodetool.reset_mock()
        is_cassandra_running.return_value = False
        self.assertFalse(helpers.is_decommissioned())

    @patch('helpers.nodetool')
    def test_emit_describe_cluster(self, nodetool):
        helpers.emit_describe_cluster()
        nodetool.assert_called_once_with('describecluster')

    @patch('helpers.nodetool')
    def test_emit_auth_keyspace_status(self, nodetool):
        helpers.emit_auth_keyspace_status()
        nodetool.assert_called_once_with('status', 'system_auth')

    @patch('helpers.nodetool')
    def test_emit_netstats(self, nodetool):
        helpers.emit_netstats()
        nodetool.assert_called_once_with('netstats')

    def test_week_spread(self):
        # The first seven units run midnight on different days.
        for i in range(0, 7):  # There is no unit 0
            with self.subTest(unit=i):
                self.assertTupleEqual(helpers.week_spread(i), (i, 0, 0))

        # The next seven units run midday on different days.
        for i in range(7, 14):
            with self.subTest(unit=i):
                self.assertTupleEqual(helpers.week_spread(i), (i - 7, 12, 0))

        # And the next seven units at 6 am on different days.
        for i in range(14, 21):
            with self.subTest(unit=i):
                self.assertTupleEqual(helpers.week_spread(i), (i - 14, 6, 0))

        # This keeps going as best we can, subdividing the hours.
        self.assertTupleEqual(helpers.week_spread(811), (6, 19, 18))

        # The granularity is 1 minute, so eventually we wrap after about
        # 7000 units.
        self.assertTupleEqual(helpers.week_spread(0), (0, 0, 0))
        for i in range(1, 7168):
            with self.subTest(unit=i):
                self.assertNotEqual(helpers.week_spread(i), (0, 0, 0))
        self.assertTupleEqual(helpers.week_spread(7168), (0, 0, 0))

    def test_local_plugins_dir(self):
        self.assertEqual(helpers.local_plugins_dir(),
                         '/usr/local/lib/nagios/plugins')


class TestIsLxc(unittest.TestCase):
    def test_is_lxc(self):
        # Test the function runs under the current environmnet.
        # Unfortunately we can't sanely test that it is returning the
        # correct value
        helpers.is_lxc()


if __name__ == '__main__':
    unittest.main(verbosity=2)
