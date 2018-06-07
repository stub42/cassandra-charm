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

import errno
from itertools import repeat
import os.path
import re
import shutil
import subprocess
import tempfile
from textwrap import dedent
import unittest
from unittest.mock import ANY, call, patch, sentinel
import yaml

import cassandra
from charmhelpers.core import hookenv

from tests.base import TestCaseBase
import actions
from coordinator import coordinator
import helpers


class TestActions(TestCaseBase):
    def test_set_proxy(self):
        # NB. Environment is already mocked.
        os.environ['http_proxy'] = ''
        os.environ['https_proxy'] = ''
        actions.set_proxy('')
        self.assertEqual(os.environ['http_proxy'], '')
        self.assertEqual(os.environ['https_proxy'], '')
        hookenv.config()['http_proxy'] = 'foo'
        actions.set_proxy('')
        self.assertEqual(os.environ['http_proxy'], 'foo')
        self.assertEqual(os.environ['https_proxy'], 'foo')

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

    @patch('subprocess.check_call')
    def test_swapoff_fails(self, check_call):
        check_call.side_effect = RuntimeError()
        actions.swapoff('', '')
        # A warning is generated if swapoff fails.
        hookenv.log.assert_any_call(ANY, hookenv.WARNING)

    @patch('subprocess.check_call')
    def test_swapoff_lxc(self, check_call):
        # Under LXC, the swapoff action does nothing except log.
        helpers.is_lxc.return_value = True
        actions.swapoff('')
        self.assertFalse(check_call.called)

    @patch('charmhelpers.core.host.write_file')
    @patch('subprocess.check_call')
    def test_reset_sysctl(self, check_call, write_file):
        actions.reset_sysctl('')

        ctl_file = '/etc/sysctl.d/99-cassandra.conf'
        # Magic value per Cassandra best practice.
        write_file.assert_called_once_with(ctl_file,
                                           b"vm.max_map_count = 131072\n")
        check_call.assert_called_once_with(['sysctl', '-p',
                                            '/etc/sysctl.d/99-cassandra.conf'])

    @patch('subprocess.check_call')
    @patch('charmhelpers.core.host.write_file')
    def test_reset_sysctl_expected_fails(self, write_file, check_call):
        check_call.side_effect = repeat(OSError(errno.EACCES,
                                                'Permission Denied'))
        actions.reset_sysctl('')
        # A warning is generated if permission denied was raised.
        hookenv.log.assert_any_call(ANY, hookenv.WARNING)

    @patch('subprocess.check_call')
    @patch('charmhelpers.core.host.write_file')
    def test_reset_sysctl_fails_badly(self, write_file, check_call):
        # Other OSErrors are reraised since we don't know how to handle
        # them.
        check_call.side_effect = repeat(OSError(errno.EFAULT, 'Whoops'))
        self.assertRaises(OSError, actions.reset_sysctl, '')

    @patch('subprocess.check_call')
    def test_reset_sysctl_lxc(self, check_call):
        helpers.is_lxc.return_value = True
        actions.reset_sysctl('')
        self.assertFalse(check_call.called)
        hookenv.log.assert_any_call('In an LXC. '
                                    'Leaving sysctl unchanged.')

    @patch('helpers.get_cassandra_edition')
    @patch('helpers.ensure_cassandra_snap_installed')
    @patch('helpers.get_cassandra_packages')
    @patch('helpers.ensure_package_status')
    def test_ensure_cassandra_package_status_snap(self, ensure_package_status,
                                                  get_cassandra_packages,
                                                  ensure_snap_installed,
                                                  get_cassandra_edition):
        get_cassandra_packages.return_value = sentinel.cassandra_packages
        get_cassandra_edition.return_value = 'apache-snap'
        actions.ensure_cassandra_package_status('')
        ensure_package_status.assert_called_once_with(
            sentinel.cassandra_packages)
        ensure_snap_installed.assert_called_once_with()

    @patch('subprocess.check_call')
    @patch('helpers.get_jre')
    @patch('helpers.get_cassandra_packages')
    @patch('helpers.install_packages')
    def test_install_cassandra_packages(self, install_packages,
                                        get_cassandra_packages,
                                        get_jre, check_call):
        get_cassandra_packages.return_value = sentinel.cassandra_packages
        get_jre.return_value = 'openjdk'
        actions.install_cassandra_packages('')
        install_packages.assert_called_once_with(sentinel.cassandra_packages)
        check_call.assert_called_once_with(['update-java-alternatives',
                                            '--jre-headless', '--set',
                                            'java-1.8.0-openjdk-amd64'])

    @patch('subprocess.check_call')
    @patch('helpers.get_jre')
    @patch('helpers.get_cassandra_packages')
    @patch('helpers.install_packages')
    def test_install_cassandra_packages_oracle(self, install_packages,
                                               get_cassandra_packages,
                                               get_jre, check_call):
        get_cassandra_packages.return_value = sentinel.cassandra_packages
        get_jre.return_value = 'oracle'
        actions.install_cassandra_packages('')
        install_packages.assert_called_once_with(sentinel.cassandra_packages)
        # No alternatives selected, as the Oracle JRE installer method
        # handles this.
        self.assertFalse(check_call.called)

    @patch('actions._install_oracle_jre_tarball')
    @patch('actions._fetch_oracle_jre')
    def test_install_oracle_jre(self, fetch, install_tarball):
        fetch.return_value = sentinel.tarball

        actions.install_oracle_jre('')
        self.assertFalse(fetch.called)
        self.assertFalse(install_tarball.called)

        hookenv.config()['jre'] = 'oracle'
        actions.install_oracle_jre('')
        fetch.assert_called_once_with()
        install_tarball.assert_called_once_with(sentinel.tarball)

    @patch('helpers.status_set')
    @patch('urllib.request')
    def test_fetch_oracle_jre(self, req, status_set):
        config = hookenv.config()
        url = 'https://foo.example.com/server-jre-7u42-linux-x64.tar.gz'
        expected_tarball = os.path.join(hookenv.charm_dir(), 'lib',
                                        'server-jre-7u42-linux-x64.tar.gz')
        config['private_jre_url'] = url

        # Create a dummy tarball, since the mock urlretrieve won't.
        os.makedirs(os.path.dirname(expected_tarball))
        with open(expected_tarball, 'w'):
            pass  # Empty file

        self.assertEqual(actions._fetch_oracle_jre(), expected_tarball)
        req.urlretrieve.assert_called_once_with(url, expected_tarball)

    def test_fetch_oracle_jre_local(self):
        # Create an existing tarball. If it is found, it will be used
        # without needing to specify a remote url or actually download
        # anything.
        expected_tarball = os.path.join(hookenv.charm_dir(), 'lib',
                                        'server-jre-7u42-linux-x64.tar.gz')
        os.makedirs(os.path.dirname(expected_tarball))
        with open(expected_tarball, 'w'):
            pass  # Empty file

        self.assertEqual(actions._fetch_oracle_jre(), expected_tarball)

    @patch('helpers.status_set')
    def test_fetch_oracle_jre_notfound(self, status_set):
        with self.assertRaises(SystemExit) as x:
            actions._fetch_oracle_jre()
            self.assertEqual(x.code, 0)
            status_set.assert_called_once_with('blocked', ANY)

    @patch('subprocess.check_call')
    @patch('charmhelpers.core.host.mkdir')
    @patch('os.path.isdir')
    def test_install_oracle_jre_tarball(self, isdir, mkdir, check_call):
        isdir.return_value = False

        dest = '/usr/lib/jvm/java-8-oracle'

        actions._install_oracle_jre_tarball(sentinel.tarball)
        mkdir.assert_called_once_with(dest)
        check_call.assert_has_calls([
            call(['tar', '-xz', '-C', dest,
                  '--strip-components=1', '-f', sentinel.tarball]),
            call(['update-alternatives', '--install',
                  '/usr/bin/java', 'java',
                  os.path.join(dest, 'bin', 'java'), '1']),
            call(['update-alternatives', '--set', 'java',
                  os.path.join(dest, 'bin', 'java')]),
            call(['update-alternatives', '--install',
                  '/usr/bin/javac', 'javac',
                  os.path.join(dest, 'bin', 'javac'), '1']),
            call(['update-alternatives', '--set', 'javac',
                  os.path.join(dest, 'bin', 'javac')])])

    @patch('os.path.exists')
    @patch('subprocess.check_call')
    @patch('charmhelpers.core.host.mkdir')
    @patch('os.path.isdir')
    def test_install_oracle_jre_tarball_already(self, isdir,
                                                mkdir, check_call, exists):
        isdir.return_value = True
        exists.return_value = True  # jre already installed

        # Store the version previously installed.
        hookenv.config()['oracle_jre_tarball'] = sentinel.tarball

        dest = '/usr/lib/jvm/java-8-oracle'

        actions._install_oracle_jre_tarball(sentinel.tarball)

        self.assertFalse(mkdir.called)  # The jvm dir already existed.

        exists.assert_called_once_with('/usr/lib/jvm/java-8-oracle/bin/java')

        # update-alternatives done, but tarball not extracted.
        check_call.assert_has_calls([
            call(['update-alternatives', '--install',
                  '/usr/bin/java', 'java',
                  os.path.join(dest, 'bin', 'java'), '1']),
            call(['update-alternatives', '--set', 'java',
                  os.path.join(dest, 'bin', 'java')]),
            call(['update-alternatives', '--install',
                  '/usr/bin/javac', 'javac',
                  os.path.join(dest, 'bin', 'javac'), '1']),
            call(['update-alternatives', '--set', 'javac',
                  os.path.join(dest, 'bin', 'javac')])])

    @patch('helpers.configure_cassandra_yaml')
    def test_configure_cassandra_yaml(self, configure_cassandra_yaml):
        # actions.configure_cassandra_yaml is just a wrapper around the
        # helper.
        actions.configure_cassandra_yaml('')
        configure_cassandra_yaml.assert_called_once_with()

    @patch('helpers.get_cassandra_env_file')
    @patch('charmhelpers.core.host.write_file')
    def test_configure_cassandra_env(self, write_file, env_file):
        def _wf(path, contents, perms=None):
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
                                 #JMX_PORT="1234"
                                 And done
                                 ''')

        with tempfile.TemporaryDirectory() as tempdir:
            cassandra_env = os.path.join(tempdir, 'c.sh')
            env_file.return_value = cassandra_env

            with open(cassandra_env, 'w', encoding='UTF-8') as f:
                f.write(existing_config)

            overrides = dict(
                max_heap_size=re.compile('^MAX_HEAP_SIZE=(.*)$', re.M),
                heap_newsize=re.compile('^HEAP_NEWSIZE=(.*)$', re.M))

            for key in overrides:
                hookenv.config()[key] = ''

            # By default, the settings will be commented out.
            actions.configure_cassandra_env('')
            with open(cassandra_env, 'r', encoding='UTF-8') as f:
                generated_env = f.read()
            for config_key, regexp in overrides.items():
                with self.subTest(override=config_key):
                    self.assertIsNone(regexp.search(generated_env))

            # Settings can be overridden.
            for config_key, regexp in overrides.items():
                hookenv.config()[config_key] = '{} val'.format(config_key)
            actions.configure_cassandra_env('')
            with open(cassandra_env, 'r') as f:
                generated_env = f.read()
            for config_key, regexp in overrides.items():
                with self.subTest(override=config_key):
                    match = regexp.search(generated_env)
                    self.assertIsNotNone(match)
                    # Note the value has been shell quoted.
                    self.assertTrue(
                        match.group(1).startswith(
                            "'{} val'".format(config_key)))

            # Settings can be returned to the defaults.
            for config_key, regexp in overrides.items():
                hookenv.config()[config_key] = ''
            actions.configure_cassandra_env('')
            with open(cassandra_env, 'r', encoding='UTF-8') as f:
                generated_env = f.read()
            for config_key, regexp in overrides.items():
                with self.subTest(override=config_key):
                    self.assertIsNone(regexp.search(generated_env))

    @patch('helpers.get_cassandra_rackdc_file')
    def test_configure_cassandra_rackdc(self, rackdc_file):
        hookenv.config()['datacenter'] = 'test_dc'
        hookenv.config()['rack'] = 'test_rack'
        with tempfile.NamedTemporaryFile() as rackdc:
            rackdc_file.return_value = rackdc.name
            actions.configure_cassandra_rackdc('')
            with open(rackdc.name, 'r') as f:
                self.assertEqual(f.read().strip(),
                                 'dc=test_dc\nrack=test_rack')

    @patch('helpers.connect')
    @patch('helpers.get_auth_keyspace_replication')
    @patch('helpers.num_nodes')
    def test_needs_reset_auth_keyspace_replication(self, num_nodes,
                                                   get_auth_ks_rep,
                                                   connect):
        num_nodes.return_value = 4
        connect().__enter__.return_value = sentinel.session
        connect().__exit__.return_value = False
        get_auth_ks_rep.return_value = {'another': '8'}
        self.assertTrue(actions.needs_reset_auth_keyspace_replication())

    @patch('helpers.connect')
    @patch('helpers.get_auth_keyspace_replication')
    @patch('helpers.num_nodes')
    def test_needs_reset_auth_keyspace_replication_false(self, num_nodes,
                                                         get_auth_ks_rep,
                                                         connect):
        config = hookenv.config()
        config['datacenter'] = 'mydc'
        connect().__enter__.return_value = sentinel.session
        connect().__exit__.return_value = False

        num_nodes.return_value = 3
        get_auth_ks_rep.return_value = {'another': '8',
                                        'mydc': '3'}
        self.assertFalse(actions.needs_reset_auth_keyspace_replication())

    @patch('helpers.set_active')
    @patch('helpers.repair_auth_keyspace')
    @patch('helpers.connect')
    @patch('helpers.set_auth_keyspace_replication')
    @patch('helpers.get_auth_keyspace_replication')
    @patch('helpers.num_nodes')
    @patch('charmhelpers.core.hookenv.is_leader')
    def test_reset_auth_keyspace_replication(self, is_leader, num_nodes,
                                             get_auth_ks_rep,
                                             set_auth_ks_rep,
                                             connect, repair, set_active):
        is_leader.return_value = True
        num_nodes.return_value = 4
        coordinator.grants = {}
        coordinator.requests = {hookenv.local_unit(): {}}
        coordinator.grant('repair', hookenv.local_unit())
        config = hookenv.config()
        config['datacenter'] = 'mydc'
        connect().__enter__.return_value = sentinel.session
        connect().__exit__.return_value = False
        get_auth_ks_rep.return_value = {'another': '8'}
        self.assertTrue(actions.needs_reset_auth_keyspace_replication())
        actions.reset_auth_keyspace_replication('')
        set_auth_ks_rep.assert_called_once_with(
            sentinel.session,
            {'class': 'NetworkTopologyStrategy', 'another': '8', 'mydc': 4})
        repair.assert_called_once_with()
        set_active.assert_called_once_with()

    @patch('helpers.stop_cassandra')
    def test_stop_cassandra(self, helpers_stop_cassandra):
        actions.stop_cassandra('ignored')
        helpers_stop_cassandra.assert_called_once_with()

    @patch('helpers.start_cassandra')
    def test_start_cassandra(self, helpers_start_cassandra):
        actions.start_cassandra('ignored')
        helpers_start_cassandra.assert_called_once_with()

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
        actions.reset_all_io_schedulers('')
        set_io_scheduler.assert_has_calls([
            call(sentinel.io_scheduler, sentinel.d1),
            call(sentinel.io_scheduler, sentinel.d2),
            call(sentinel.io_scheduler, sentinel.cl),
            call(sentinel.io_scheduler, sentinel.sc)],
            any_order=True)

        # If directories don't exist yet, nothing happens.
        set_io_scheduler.reset_mock()
        isdir.return_value = False
        actions.reset_all_io_schedulers('')
        self.assertFalse(set_io_scheduler.called)

    def test_config_key_lists_complete(self):
        # Ensure that we have listed all keys in either
        # RESTART_REQUIRED_KEYS, RESTART_NOT_REQUIRED_KEYS or
        # UNCHANGEABLE_KEYS. This is to ensure that RESTART_REQUIRED_KEYS
        # is maintained as new config items are added over time.
        config_path = os.path.join(os.path.dirname(__file__), os.pardir,
                                   'config.yaml')
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        combined = actions.RESTART_REQUIRED_KEYS.union(
            actions.RESTART_NOT_REQUIRED_KEYS).union(
                actions.UNCHANGEABLE_KEYS)

        for key in config['options']:
            with self.subTest(key=key):
                self.assertIn(key, combined)

    @patch('charmhelpers.core.host.write_file')
    def test_install_maintenance_crontab(self, write_file):
        # First 7 units get distributed, one job per day.
        hookenv.local_unit.return_value = 'foo/0'
        actions.install_maintenance_crontab('')
        write_file.assert_called_once_with('/etc/cron.d/cassandra-maintenance',
                                           ANY)
        contents = write_file.call_args[0][1]
        # Not the complete command, but includes all the expanded
        # variables.
        expected = (b'\n0 0 * * 0 cassandra run-one-until-success '
                    b'nodetool repair -pr')
        self.assertIn(expected, contents)

        # Next 7 units distributed 12 hours out of sync with the first
        # batch.
        hookenv.local_unit.return_value = 'foo/8'
        actions.install_maintenance_crontab('')
        contents = write_file.call_args[0][1]
        expected = (b'\n0 12 * * 1 cassandra run-one-until-success '
                    b'nodetool repair -pr')
        self.assertIn(expected, contents)

        # Later units per helpers.week_spread()
        hookenv.local_unit.return_value = 'foo/411'
        actions.install_maintenance_crontab('')
        contents = write_file.call_args[0][1]
        expected = (b'\n37 8 * * 5 cassandra run-one-until-success '
                    b'nodetool repair -pr')
        self.assertIn(expected, contents)

    @patch('helpers.mountpoint')
    @patch('helpers.get_cassandra_version')
    @patch('charmhelpers.core.host.write_file')
    @patch('charmhelpers.contrib.charmsupport.nrpe.NRPE')
    @patch('helpers.local_plugins_dir')
    def test_nrpe_external_master_relation(self, local_plugins_dir, nrpe,
                                           write_file, cassandra_version,
                                           mountpoint):
        mountpoint.side_effect = os.path.dirname
        cassandra_version.return_value = '2.2'
        # The fake charm_dir() needs populating.
        plugin_src_dir = os.path.join(os.path.dirname(__file__),
                                      os.pardir, 'files')
        shutil.copytree(plugin_src_dir,
                        os.path.join(hookenv.charm_dir(), 'files'))

        with tempfile.TemporaryDirectory() as d:
            local_plugins_dir.return_value = d
            actions.nrpe_external_master_relation('')

            # The expected file was written to the expected filename
            # with required perms.
            with open(os.path.join(plugin_src_dir, 'check_cassandra_heap.sh'),
                      'rb') as f:
                write_file.assert_called_once_with(
                    os.path.join(d, 'check_cassandra_heap.sh'), f.read(),
                    perms=0o555)

            nrpe().add_check.assert_has_calls([
                call(shortname='cassandra_heap',
                     description='Check Cassandra Heap',
                     check_cmd='check_cassandra_heap.sh localhost 80 90'),
                call(description=('Check Cassandra Disk '
                                  '/var/lib/cassandra'),
                     shortname='cassandra_disk_var_lib_cassandra',
                     check_cmd=('check_disk -u GB -w 50% -c 25% -K 5% '
                                '-p /var/lib/cassandra'))],
                any_order=True)

            nrpe().write.assert_called_once_with()

    @patch('helpers.get_cassandra_version')
    @patch('charmhelpers.core.host.write_file')
    @patch('os.path.exists')
    @patch('charmhelpers.contrib.charmsupport.nrpe.NRPE')
    def test_nrpe_external_master_relation_no_local(self, nrpe, exists,
                                                    write_file, ver):
        ver.return_value = '2.2'
        # If the local plugins directory doesn't exist, we don't attempt
        # to write files to it. Wait until the subordinate has set it
        # up.
        exists.return_value = False
        actions.nrpe_external_master_relation('')
        self.assertFalse(write_file.called)

    @patch('helpers.mountpoint')
    @patch('helpers.get_cassandra_version')
    @patch('os.path.exists')
    @patch('charmhelpers.contrib.charmsupport.nrpe.NRPE')
    def test_nrpe_external_master_relation_disable_heapchk(self, nrpe, exists,
                                                           ver, mountpoint):
        ver.return_value = '2.2'
        exists.return_value = False
        mountpoint.side_effect = os.path.dirname

        # Disable our checks
        config = hookenv.config()
        config['nagios_heapchk_warn_pct'] = 0  # Only one needs to be disabled.
        config['nagios_heapchk_crit_pct'] = 90

        actions.nrpe_external_master_relation('')
        exists.assert_called_once_with(helpers.local_plugins_dir())

        nrpe().add_check.assert_has_calls([
            call(shortname='cassandra_disk_var_lib_cassandra',
                 description=ANY, check_cmd=ANY)], any_order=True)

    @patch('helpers.get_cassandra_version')
    @patch('os.path.exists')
    @patch('charmhelpers.contrib.charmsupport.nrpe.NRPE')
    def test_nrpe_external_master_relation_disable_diskchk(self, nrpe,
                                                           exists, ver):
        ver.return_value = '2.2'
        exists.return_value = False

        # Disable our checks
        config = hookenv.config()
        config['nagios_disk_warn_pct'] = 0  # Only one needs to be disabled.
        config['magios_disk_crit_pct'] = 50

        actions.nrpe_external_master_relation('')
        exists.assert_called_once_with(helpers.local_plugins_dir())

        nrpe().add_check.assert_called_once_with(shortname='cassandra_heap',
                                                 description=ANY,
                                                 check_cmd=ANY)

    @patch('helpers.get_bootstrapped_ips')
    @patch('helpers.get_seed_ips')
    @patch('charmhelpers.core.hookenv.leader_set')
    @patch('charmhelpers.core.hookenv.is_leader')
    def test_maintain_seeds(self, is_leader, leader_set,
                            seed_ips, bootstrapped_ips):
        is_leader.return_value = True

        seed_ips.return_value = set(['1.2.3.4'])
        bootstrapped_ips.return_value = set(['2.2.3.4', '3.2.3.4',
                                             '4.2.3.4', '5.2.3.4'])

        actions.maintain_seeds('')
        leader_set.assert_called_once_with(seeds='2.2.3.4,3.2.3.4,4.2.3.4')

    @patch('helpers.get_bootstrapped_ips')
    @patch('helpers.get_seed_ips')
    @patch('charmhelpers.core.hookenv.leader_set')
    @patch('charmhelpers.core.hookenv.is_leader')
    def test_maintain_seeds_start(self, is_leader, leader_set,
                                  seed_ips, bootstrapped_ips):
        seed_ips.return_value = set()
        bootstrapped_ips.return_value = set()
        actions.maintain_seeds('')
        # First seed is the first leader, which lets is get everything
        # started.
        leader_set.assert_called_once_with(seeds=hookenv.unit_private_ip())

    @patch('charmhelpers.core.host.pwgen')
    @patch('helpers.query')
    @patch('helpers.set_unit_superusers')
    @patch('helpers.ensure_user')
    @patch('helpers.encrypt_password')
    @patch('helpers.superuser_credentials')
    @patch('helpers.connect')
    @patch('charmhelpers.core.hookenv.is_leader')
    @patch('charmhelpers.core.hookenv.leader_set')
    @patch('charmhelpers.core.hookenv.leader_get')
    def test_reset_default_password(self, leader_get, leader_set, is_leader,
                                    connect, sup_creds, encrypt_password,
                                    ensure_user, set_sups, query, pwgen):
        is_leader.return_value = True
        leader_get.return_value = None
        connect().__enter__.return_value = sentinel.session
        connect().__exit__.return_value = False
        connect.reset_mock()

        sup_creds.return_value = (sentinel.username, sentinel.password)
        encrypt_password.return_value = sentinel.pwhash
        pwgen.return_value = sentinel.random_password

        actions.reset_default_password('')

        # First, a superuser account for the unit was created.
        connect.assert_called_once_with('cassandra', 'cassandra',
                                        timeout=120, auth_timeout=120)
        encrypt_password.assert_called_once_with(sentinel.password)
        ensure_user.assert_called_once_with(sentinel.session,
                                            sentinel.username,
                                            sentinel.pwhash,
                                            superuser=True)
        set_sups.assert_called_once_with([hookenv.local_unit()])

        # After that, the default password is reset.
        query.assert_called_once_with(sentinel.session,
                                      'ALTER USER cassandra WITH PASSWORD %s',
                                      cassandra.ConsistencyLevel.ALL,
                                      (sentinel.random_password,))

        # Flag stored to avoid attempting this again.
        leader_set.assert_called_once_with(default_admin_password_changed=True)

    @patch('helpers.connect')
    @patch('charmhelpers.core.hookenv.is_leader')
    @patch('charmhelpers.core.hookenv.leader_get')
    def test_reset_default_password_noop(self, leader_get, is_leader, connect):
        leader_get.return_value = True
        is_leader.return_value = True
        actions.reset_default_password('')  # noop
        self.assertFalse(connect.called)

    @patch('helpers.update_hosts_file')
    @patch('socket.gethostname')
    def test_update_etc_hosts(self, gethostname, update_hosts_file):
        gethostname.return_value = sentinel.hostname
        actions.update_etc_hosts('')
        update_hosts_file.assert_called_once_with(
            '/etc/hosts', {'10.20.0.1': sentinel.hostname})


if __name__ == '__main__':
    unittest.main(verbosity=2)
