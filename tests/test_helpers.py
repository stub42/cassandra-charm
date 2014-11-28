#!.venv3/bin/python3

from collections import namedtuple
from datetime import datetime
import os.path
import subprocess
import tempfile
import unittest
from unittest.mock import ANY, call, mock_open, patch
import yaml

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
        check_output.return_value = 'foo\n/dev/sdq 1 2 3 1% /foo\n'
        isdir.return_value = True

        helpers.set_io_scheduler('fnord', '/foo')

        write_file.assert_called_once_with('/sys/block/sdq/queue/scheduler',
                                           'fnord', perms=0o644)

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
        py_ver = helpers.get_package_version('package')
        self.assertEqual(py_ver, '1.0-foo')

    @patch('helpers.get_package_version', autospec=True)
    def test_get_cassandra_version(self, get_package_version):
        # Return cassandra package version if it is installed.
        get_package_version.return_value = '1.2.3-2~64'
        self.assertEqual(helpers.get_cassandra_version(), '1.2.3-2~64')
        get_package_version.assert_called_with('cassandra')

        # Return a fake '2.1' if DSE is enabled.
        hookenv.config()['dse'] = True
        self.assertEqual(helpers.get_cassandra_version(), '2.1')

        # Return None if cassandra package is not installed and no DSE.
        hookenv.config()['dse'] = False
        get_package_version.return_value = None
        self.assertIsNone(helpers.get_cassandra_version())

    def test_get_cassandra_config_dir(self):
        self.assertEqual(helpers.get_cassandra_config_dir(),
                         '/etc/cassandra')
        hookenv.config()['dse'] = True
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

    def test_peer_relation_name(self):
        metadata = dict(peers=dict(peer1=dict(interface='int1'),
                                   peer2=dict(interface='int2')))
        metadata_yaml = yaml.safe_dump(metadata)
        with patch('helpers.open', mock_open(read_data=metadata_yaml),
                   create=True) as m:
            peer_relname = helpers.get_peer_relation_name()
            m.assert_called_once_with(os.path.join(hookenv.charm_dir(),
                                                   'metadata.yaml'), 'r')
            # First peer relation in alphabetical order.
            self.assertEqual(peer_relname, 'peer1')

    @patch('helpers.get_peer_relation_name', autospec=True)
    def test_get_peers(self, get_peer_relation_name):
        get_peer_relation_name.return_value = 'cluster'
        self.assertSetEqual(helpers.get_peers(),
                            set(['service/2', 'service/3']))

    def test_utcnow(self):
        # helpers.utcnow simply wraps datetime.datetime.utcnow().
        # We use it because, unlike datetime.utcnow(), it can be
        # mocked in tests making them stable.
        self.assertEqual(helpers.utcnow(), datetime(2010, 12, 25, 13, 45, 1))

        # Our mock always gives predictable values.
        self.assertEqual(helpers.utcnow(), datetime(2010, 12, 25, 13, 45, 2))

        # Mocked values always increase.
        self.assertLess(helpers.utcnow(), helpers.utcnow())

    def test_utcnow_str(self):
        # utcnow() as a readable and sortable string.
        self.assertEqual(helpers.utcnow_str(),
                         '2010-12-25 13:45:01.000000Z')
        # Our mock returns increasing values.
        self.assertLess(helpers.utcnow_str(), helpers.utcnow_str())

    @patch('helpers.rolling_restart', autospec=True)
    def test_rolling_restart_cassandra(self, rolling_restart):
        # A trivial wrapper around helpers.rolling_restart.
        helpers.rolling_restart_cassandra()
        rolling_restart.assert_called_once_with(helpers.restart_cassandra)

    @patch('charmhelpers.contrib.peerstorage.peer_store', autospec=True)
    @patch('helpers.get_peers', autospec=True)
    @patch('helpers.restart_cassandra', autospec=True)
    def test_rolling_restart_no_peers(self, restart, get_peers, peer_store):
        # If there are no peers, restart happens immediately.
        # This includes if a restart is requested before the unit
        # has joined the peer relation, which is fine since we have no
        # reason to block restarts on a unit that is still being setup.
        get_peers.return_value = set()
        self.assertTrue(helpers.rolling_restart(restart))
        restart.assert_called_once_with()

        # Peer storage was not used. It will fail without any peers.
        self.assertFalse(peer_store.called)

    @patch('charmhelpers.contrib.peerstorage.peer_store', autospec=True)
    @patch('charmhelpers.contrib.peerstorage.peer_retrieve', autospec=True)
    @patch('helpers.restart_cassandra', autospec=True)
    def test_rolling_restart_empty_queue(self, restart, peer_retrieve,
                                         peer_store):
        # If the restart queue is empty, the unit joins it but does
        # not restart yet.
        peer_retrieve.return_value = dict(foo='ignored because unknown')
        self.assertFalse(helpers.rolling_restart(restart))

        # Restart did not happen. We are only queueing.
        self.assertFalse(restart.called)

        # The queue was looked up, returning nothing.
        peer_retrieve.assert_called_once_with('-', 'cluster')

        # An entry for the unit was added to the queue.
        peer_store.assert_called_once_with('restart_needed_service_1',
                                           '2010-12-25 13:45:01.000000Z',
                                           'cluster')

    @patch('charmhelpers.contrib.peerstorage.peer_store', autospec=True)
    @patch('charmhelpers.contrib.peerstorage.peer_retrieve', autospec=True)
    @patch('helpers.restart_cassandra', autospec=True)
    def test_rolling_restart_stuck_in_queue(self, restart, peer_retrieve,
                                            peer_store):
        # If the unit is already in the restart queue, and there are
        # other units before it, it must wait.
        first, second = helpers.utcnow(), helpers.utcnow()
        peer_retrieve.return_value = dict(foo='ignored',
                                          restart_needed_service_1=second,
                                          restart_needed_service_2=first)
        self.assertFalse(helpers.rolling_restart(restart))

        # Restart did not happen. We are stuck in the queue.
        self.assertFalse(restart.called)

        # The queue was looked up, returning nothing.
        peer_retrieve.assert_called_once_with('-', 'cluster')

        # No change was made to the queue, since we are already in it.
        self.assertFalse(peer_store.called)

    @patch('charmhelpers.contrib.peerstorage.peer_store', autospec=True)
    @patch('charmhelpers.contrib.peerstorage.peer_retrieve', autospec=True)
    @patch('helpers.restart_cassandra', autospec=True)
    def test_rolling_restart_next_in_queue(self, restart, peer_retrieve,
                                           peer_store):
        first, second = helpers.utcnow(), helpers.utcnow()
        peer_retrieve.return_value = dict(restart_needed_service_1=first,
                                          restart_needed_service_2=second)
        self.assertTrue(helpers.rolling_restart(restart))
        self.assertTrue(restart.called)
        peer_retrieve.assert_called_once_with('-', 'cluster')
        peer_store.assert_called_once_with('restart_needed_service_1',
                                           None, 'cluster')

    @patch('os.path.exists', autospec=True)
    @patch('charmhelpers.core.host.write_file', autospec=True)
    def test_request_rolling_restart(self, write_file, exists):
        exists.return_value = False
        helpers.request_rolling_restart()
        write_file.assert_called_once_with(
            os.path.join(hookenv.charm_dir(), '.needs-restart'), ANY)


class TestIsLxc(unittest.TestCase):
    def test_is_lxc(self):
        # Test the function runs under the current environmnet.
        # Unfortunately we can't sanely test that it is returning the
        # correct value
        helpers.is_lxc()


if __name__ == '__main__':
    unittest.main(verbosity=2)
