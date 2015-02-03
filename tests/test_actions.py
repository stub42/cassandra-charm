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
import functools
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


patch = functools.partial(patch, autospec=True)  # autospec=True as default.


class TestsActions(TestCaseBase):
    def test_action_wrapper(self):
        @actions.action
        def somefunc(*args, **kw):
            return 42, args, kw

        hookenv.hook_name.return_value = 'catch-fire'

        # The wrapper stripts the servicename argument, which we have no
        # use for, logs a message and invokes the wrapped function.
        hookenv.remote_unit.return_value = None
        self.assertEqual(somefunc('sn', 1, foo=4), (42, (1,), dict(foo=4)))
        hookenv.log.assert_called_once_with('** Action catch-fire/somefunc')

        # Different log message if there is a remote unit.
        hookenv.log.reset_mock()
        os.environ['JUJU_REMOTE_UNIT'] = 'foo'
        self.assertEqual(somefunc('sn', 1, foo=4), (42, (1,), dict(foo=4)))
        hookenv.log.assert_called_once_with(
            '** Action catch-fire/somefunc (foo)')

    def test_revert_unchangeable_config(self):
        hookenv.hook_name.return_value = 'config-changed'
        config = hookenv.config()

        self.assertIn('datacenter', actions.UNCHANGEABLE_KEYS)

        config['datacenter'] = 'mission_control'
        config.save()
        config.load_previous()
        config['datacenter'] = 'orbital_1'

        self.assertTrue(config.changed('datacenter'))

        actions.revert_unchangeable_config('')
        self.assertEqual(config['datacenter'], 'mission_control')  # Reverted

        hookenv.log.assert_any_call(ANY, hookenv.ERROR)

    def test_revert_unchangeable_config_install(self):
        hookenv.hook_name.return_value = 'install'
        config = hookenv.config()

        self.assertIn('datacenter', actions.UNCHANGEABLE_KEYS)

        config['datacenter'] = 'mission_control'
        config.save()
        config.load_previous()
        config['datacenter'] = 'orbital_1'

        self.assertTrue(config.changed('datacenter'))

        # In the install hook, revert_unchangeable_config() does
        # nothing.
        actions.revert_unchangeable_config('')
        self.assertEqual(config['datacenter'], 'orbital_1')

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
    def test_preinstall(self, check_call):
        # Noop if there are no preinstall hooks found running the
        # install hook.
        hookenv.hook_name.return_value = 'install'
        actions.preinstall('')
        self.assertFalse(check_call.called)
        hookenv.log.assert_any_call('No preinstall hooks found')

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

    @patch('charmhelpers.core.hookenv.charm_dir')
    @patch('subprocess.check_call')
    def test_add_implicit_package_signing_keys(self, check_call, charm_dir):
        charm_dir.return_value = os.path.join(os.path.dirname(__file__),
                                              os.pardir)
        actions.add_implicit_package_signing_keys('')

        keys = ['apache', 'datastax']

        self.assertEqual(check_call.call_count, len(keys))

        for k in keys:
            with self.subTest(key=k):
                path = os.path.join(hookenv.charm_dir(),
                                    'lib', '{}.key'.format(k))
                self.assertTrue(os.path.exists(path))
                check_call.assert_any_call(['apt-key', 'add', path],
                                           stdin=subprocess.DEVNULL)

    @patch('subprocess.check_call')
    def test_cache_oracle_jdk(self, check_call):
        tarball_paths = [os.path.join(hookenv.charm_dir(),
                                      'lib', 'jdk-7u1.tar.gz'),
                         os.path.join(hookenv.charm_dir(),
                                      'lib', 'jdk-7u2.tar.gz')]
        os.mkdir(os.path.join(hookenv.charm_dir(), 'lib'))
        for path in tarball_paths:
            with open(path, 'w') as f:
                f.write('fake')
        actions.cache_oracle_jdk('')
        check_call.assert_called_once_with(
            ['install', '-CD', tarball_paths[0], tarball_paths[1],
             '/var/cache/oracle-jdk7-installer'])

    @patch('subprocess.check_call')
    def test_cache_oracle_jdk_noop(self, check_call):
        actions.cache_oracle_jdk('')
        self.assertFalse(check_call.called)

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

    @patch('subprocess.check_call')
    @patch('charmhelpers.core.host.write_file')
    def test_reset_sysctl_expected_fails(self, write_file, check_call):
        check_call.side_effect = OSError(errno.EACCES, 'Permission Denied')
        actions.reset_sysctl('')
        # A warning is generated if permission denied was raised.
        hookenv.log.assert_any_call(ANY, hookenv.WARNING)

    @patch('subprocess.check_call')
    @patch('charmhelpers.core.host.write_file')
    def test_reset_sysctl_fails_badly(self, write_file, check_call):
        # Other OSErrors are reraised since we don't know how to handle
        # them.
        check_call.side_effect = OSError(errno.EFAULT, 'Whoops')
        self.assertRaises(OSError, actions.reset_sysctl, '')

    @patch('subprocess.check_call')
    def test_reset_sysctl_lxc(self, check_call):
        helpers.is_lxc.return_value = True
        actions.reset_sysctl('')
        self.assertFalse(check_call.called)
        hookenv.log.assert_any_call('In an LXC. '
                                    'Leaving sysctl unchanged.')

    @patch('helpers.get_cassandra_packages')
    @patch('helpers.ensure_package_status')
    def test_ensure_cassandra_package_status(self, ensure_package_status,
                                             get_cassandra_packages):
        get_cassandra_packages.return_value = sentinel.cassandra_packages
        actions.ensure_cassandra_package_status('')
        ensure_package_status.assert_called_once_with(
            sentinel.cassandra_packages)

    @patch('helpers.get_cassandra_packages')
    @patch('helpers.install_packages')
    def test_install_cassandra_packages(self, install_packages,
                                        get_cassandra_packages):
        get_cassandra_packages.return_value = sentinel.cassandra_packages
        actions.install_cassandra_packages('')
        install_packages.assert_called_once_with(sentinel.cassandra_packages)

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

    @patch('helpers.reset_auth_keyspace_replication')
    def test_reset_auth_keyspace_replication(self, reset_auth_helper):
        # Normally this action does nothing.
        hookenv.hook_name.return_value = 'whatever'
        actions.reset_auth_keyspace_replication('')
        self.assertFalse(reset_auth_helper.called)

        # In the peer relation-broken hook however, it lowers the
        # replication level of the system_auth keyspace.
        hookenv.hook_name.return_value = 'cluster-relation-broken'
        actions.reset_auth_keyspace_replication('')
        reset_auth_helper.assert_called_once_with()

    @patch('rollingrestart.cancel_restart')
    @patch('helpers.decommission_node')
    @patch('helpers.wait_for_normality')
    @patch('helpers.num_nodes')
    def test_maybe_decomission_node(self, num_nodes, wait_for_normality,
                                    decommission_node, cancel_restart):
        # In the peer relation-broken hook, if there is at least one
        # remaining peer the node is properly decomissioned
        hookenv.hook_name.return_value = 'cluster-relation-broken'
        num_nodes.return_value = 3
        actions.maybe_decommission_node('')
        wait_for_normality.assert_called_once_with()
        decommission_node.assert_called_once_with()
        cancel_restart.assert_called_once_with()

    @patch('helpers.decommission_node')
    @patch('helpers.num_nodes')
    def test_maybe_decomission_node_other_hook(self, num_nodes,
                                               decommission_node):
        # If this is not the peer relation-broken hook, nothing happens.
        hookenv.hook_name.return_value = 'cluster-relation-joined'
        num_nodes.return_value = 3
        actions.maybe_decommission_node('')
        self.assertFalse(decommission_node.called)

    @patch('helpers.decommission_node')
    @patch('helpers.num_nodes')
    def test_maybe_decomission_node_no_peers(self, num_nodes,
                                             decommission_node):
        # If this is not the peer relation-broken hook, nothing happens.
        hookenv.hook_name.return_value = 'cluster-relation-broken'
        num_nodes.return_value = 1  # Just me.
        actions.maybe_decommission_node('')
        self.assertFalse(decommission_node.called)

    @patch('helpers.get_seeds')
    @patch('relations.StorageRelation')
    @patch('rollingrestart.request_restart')
    def test_maybe_schedule_restart_need_remount(self, request_restart,
                                                 storage_relation, get_seeds):
        config = hookenv.config()

        # Storage says we need to restart.
        storage_relation().needs_remount.return_value = True

        # Seedlist does not.
        get_seeds.return_value = 'seed list'
        config['configured_seeds'] = get_seeds()

        # IP address is unchanged.
        config['unit_private_ip'] = hookenv.unit_private_ip()

        # Config items are unchanged.
        config.save()
        config.load_previous()

        actions.maybe_schedule_restart('')
        request_restart.assert_called_once_with()
        hookenv.log.assert_any_call('Mountpoint changed. '
                                    'Restart and migration required.')

    @patch('helpers.get_seeds')
    @patch('relations.StorageRelation')
    @patch('rollingrestart.request_restart')
    def test_maybe_schedule_restart_seeds_changed(self, request_restart,
                                                  storage_relation, get_seeds):
        config = hookenv.config()

        # Storage says we do not need to restart.
        storage_relation().needs_remount.return_value = False

        # Seedlist has changed.
        get_seeds.return_value = 'seed list'
        config['configured_seeds'] = 'old seed list'

        # IP address is unchanged.
        config['unit_private_ip'] = hookenv.unit_private_ip()

        # Config items are unchanged.
        config.save()
        config.load_previous()

        actions.maybe_schedule_restart('')
        request_restart.assert_called_once_with()
        hookenv.log.assert_any_call('Seed list changed. '
                                    'Restart required.')

    @patch('helpers.get_seeds')
    @patch('relations.StorageRelation')
    @patch('rollingrestart.request_restart')
    def test_maybe_schedule_restart_unchanged(self, request_restart,
                                              storage_relation, get_seeds):
        config = hookenv.config()

        # Storage says we do not need to restart.
        storage_relation().needs_remount.return_value = False

        # Seedlist does not.
        get_seeds.return_value = 'seed list'
        config['configured_seeds'] = get_seeds()

        # IP address is unchanged.
        config['unit_private_ip'] = hookenv.unit_private_ip()

        # Config items are unchanged, except for ones that do not
        # matter.
        config.save()
        config.load_previous()
        config['package_status'] = 'new'
        self.assertTrue(config.changed('package_status'))

        actions.maybe_schedule_restart('')
        self.assertFalse(request_restart.called)

    @patch('helpers.get_seeds')
    @patch('relations.StorageRelation')
    @patch('rollingrestart.request_restart')
    def test_maybe_schedule_restart_config_changed(self, request_restart,
                                                   storage_relation,
                                                   get_seeds):
        config = hookenv.config()

        # Storage says we do not need to restart.
        storage_relation().needs_remount.return_value = False

        # Seedlist does not.
        get_seeds.return_value = 'seed list'
        config['configured_seeds'] = get_seeds()

        # IP address is unchanged.
        config['unit_private_ip'] = hookenv.unit_private_ip()

        # Config items are changed.
        config.save()
        config.load_previous()
        config['package_status'] = 'new'
        self.assertTrue(config.changed('package_status'))  # Doesn't matter.
        config['max_heap_size'] = 'lots and lots'
        self.assertTrue(config.changed('max_heap_size'))  # Requires restart.

        actions.maybe_schedule_restart('')
        request_restart.assert_called_once_with()
        hookenv.log.assert_any_call('max_heap_size changed. Restart required.')

    @patch('helpers.get_seeds')
    @patch('relations.StorageRelation')
    @patch('rollingrestart.request_restart')
    def test_maybe_schedule_restart_ip_changed(self, request_restart,
                                               storage_relation, get_seeds):
        config = hookenv.config()

        # Storage says we do not need to restart.
        storage_relation().needs_remount.return_value = False

        # Seedlist does not.
        get_seeds.return_value = 'seed list'
        config['configured_seeds'] = get_seeds()

        # IP address has changed.
        config['unit_private_ip'] = 'old ip address'

        # Config items are unchanged.
        config.save()
        config.load_previous()

        actions.maybe_schedule_restart('')
        request_restart.assert_called_once_with()
        hookenv.log.assert_any_call('Unit IP address changed. '
                                    'Restart required.')

    @patch('helpers.stop_cassandra')
    def test_stop_cassandra(self, helpers_stop_cassandra):
        actions.stop_cassandra('ignored')
        helpers_stop_cassandra.assert_called_once_with()

    @patch('helpers.start_cassandra')
    def test_start_cassandra(self, helpers_start_cassandra):
        actions.start_cassandra('ignored')
        helpers_start_cassandra.assert_called_once_with()

    @patch('helpers.ensure_unit_superuser')
    def test_ensure_unit_superuser(self, helpers_ensure_unit_superuser):
        actions.ensure_unit_superuser('ignored')
        helpers_ensure_unit_superuser.assert_called_once_with()

    @patch('helpers.reset_all_io_schedulers')
    def test_reset_all_io_schedulers(self, helpers_reset_all_io_schedulers):
        actions.reset_all_io_schedulers('ignored')
        helpers_reset_all_io_schedulers.assert_called_once_with()

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

    def test_publish_cluster_relation(self):
        actions.publish_cluster_relation('')
        hookenv.relation_set.assert_called_once_with(
            'cluster:1', {'public-address': '10.30.0.1'})

    @patch('rollingrestart.get_peer_relation_id')
    def test_publish_cluster_relation_not_yet(self, get_relid):
        get_relid.return_value = None  # Peer relation not yet joined.
        actions.publish_cluster_relation('')  # Noop
        self.assertFalse(hookenv.relation_set.called)

    @patch('actions._publish_database_relation')
    def test_publish_database_relations(self, publish_db_rel):
        actions.publish_database_relations('')
        publish_db_rel.assert_called_once_with('database:1', superuser=False)

    @patch('actions._publish_database_relation')
    def test_publish_database_admin_relations(self, publish_db_rel):
        actions.publish_database_admin_relations('')
        publish_db_rel.assert_called_once_with('database-admin:1',
                                               superuser=True)

    @patch('rollingrestart.utcnow_str')
    @patch('helpers.ensure_user')
    @patch('charmhelpers.core.host.pwgen')
    @patch('rollingrestart.get_peers')
    def test_publish_database_relation(self, get_peers, pwgen,
                                       ensure_user, utcnow_str):
        get_peers.return_value = set()
        pwgen.side_effect = iter(['secret1', 'secret2'])
        hookenv.relation_get.return_value = {}
        config = hookenv.config()
        config['native_transport_port'] = 666
        config['rpc_port'] = 777
        config['cluster_name'] = 'fred'
        config['datacenter'] = 'mission_control'
        config['rack'] = '01'
        utcnow_str.return_value = 'whenever'

        actions._publish_database_relation('database:1', sentinel.superuser)

        # Checked this unit for existing data.
        hookenv.relation_get.assert_called_once_with(rid='database:1',
                                                     unit='service/1')

        ensure_user.assert_called_once_with('juju_database_1', 'secret1',
                                            sentinel.superuser)

        hookenv.relation_set.assert_has_calls([
            call('cluster:1', ping='whenever'),
            call('database:1',
                 username='juju_database_1', password='secret1',
                 host='10.30.0.1', native_transport_port=666, rpc_port=777,
                 cluster_name='fred', datacenter='mission_control',
                 rack='01')])

    @patch('rollingrestart.get_peers')
    def test_publish_database_relation_fail(self, get_peers):
        # If we fail to retrieve details from the first unit, don't
        # fail. This could just be an edge case where the first unit
        # hasn't joined the relation yet, causing relation-get to barf
        # unpredictably.
        get_peers.return_value = ['service/1', 'service/2']
        hookenv.local_unit.return_value = 'service/99'
        hookenv.relation_get.side_effect = subprocess.CalledProcessError(1, '')
        actions._publish_database_relation('database:1', sentinel.superuser)
        self.assertFalse(hookenv.relation_set.called)

        # If we fail to retrieve details from the first unit, and it is
        # us, something is very wrong and the exception propagated.
        get_peers.return_value = ['service/1', 'service/2']
        hookenv.local_unit.return_value = 'service/0'
        hookenv.relation_get.side_effect = subprocess.CalledProcessError(1, '')
        self.assertRaises(subprocess.CalledProcessError,
                          actions._publish_database_relation,
                          'database:1', sentinel.superuser)

    @patch('rollingrestart.utcnow_str')
    @patch('helpers.ensure_user')
    @patch('rollingrestart.get_peers')
    def test_publish_database_relation_alone(self, get_peers,
                                             ensure_user, utcnow_str):
        get_peers.return_value = set()
        # There are existing credentials on the relation.
        hookenv.relation_set(relation_id='database:1',
                             username='un', password='pw')
        config = hookenv.config()
        config['native_transport_port'] = 666
        config['rpc_port'] = 777
        config['cluster_name'] = 'fred'
        config['datacenter'] = 'mission_control'
        config['rack'] = '01'
        utcnow_str.return_value = 'whenever'

        actions._publish_database_relation('database:1', sentinel.superuser)

        # Checked this unit for existing data.
        hookenv.relation_get.assert_called_once_with(rid='database:1',
                                                     unit='service/1')

        # Even if the stored creds are unchanged, we ensure the password
        # is valid and reset it if necessary.
        ensure_user.assert_called_once_with('un', 'pw', sentinel.superuser)

        hookenv.relation_set.assert_has_calls([
            # Credentials unchanged, so no peer wakeup.
            # call('cluster:1', ping='whenever'),

            # relation_set still called, despite no credentials being
            # changed, in case the other details have changed.
            call('database:1', username='un', password='pw',
                 host='10.30.0.1', native_transport_port=666, rpc_port=777,
                 cluster_name='fred', datacenter='mission_control',
                 rack='01')])

    @patch('rollingrestart.utcnow_str')
    @patch('helpers.ensure_user')
    @patch('charmhelpers.core.host.pwgen')
    @patch('rollingrestart.get_peers')
    def test_publish_database_relation_leader(self, get_peers, pwgen,
                                              ensure_user, utcnow_str):
        get_peers.return_value = set(['service/2', 'service/3'])
        pwgen.side_effect = iter(['secret1', 'secret2'])
        hookenv.relation_get.return_value = {}
        config = hookenv.config()
        config['native_transport_port'] = 666
        config['rpc_port'] = 777
        config['cluster_name'] = 'fred'
        config['datacenter'] = 'mission_control'
        config['rack'] = '01'
        utcnow_str.return_value = 'whenever'

        actions._publish_database_relation('database:1', sentinel.superuser)

        # Checked this unit for existing data.
        hookenv.relation_get.assert_called_once_with(rid='database:1',
                                                     unit='service/1')

        ensure_user.assert_called_once_with('juju_database_1', 'secret1',
                                            sentinel.superuser)

        hookenv.relation_set.assert_has_calls([
            call('cluster:1', ping='whenever'),
            call('database:1',
                 username='juju_database_1', password='secret1',
                 host='10.30.0.1', native_transport_port=666, rpc_port=777,
                 cluster_name='fred', datacenter='mission_control',
                 rack='01')])

    @patch('rollingrestart.utcnow_str')
    @patch('helpers.ensure_user')
    @patch('rollingrestart.get_peers')
    def test_publish_database_relation_leader2(self, get_peers,
                                               ensure_user, utcnow_str):
        get_peers.return_value = set()
        # There are existing credentials on the relation.
        hookenv.relation_set(relation_id='database:1',
                             username='un', password='pw')
        config = hookenv.config()
        config['native_transport_port'] = 666
        config['rpc_port'] = 777
        config['cluster_name'] = 'fred'
        config['datacenter'] = 'mission_control'
        config['rack'] = '01'
        utcnow_str.return_value = 'whenever'

        actions._publish_database_relation('database:1', sentinel.superuser)

        # Checked this unit for existing data.
        hookenv.relation_get.assert_called_once_with(rid='database:1',
                                                     unit='service/1')

        # Even if the stored creds are unchanged, we ensure the password
        # is valid and reset it if necessary.
        ensure_user.assert_called_once_with('un', 'pw', sentinel.superuser)

        hookenv.relation_set.assert_has_calls([
            # Credentials unchanged, so no peer wakeup.
            # call('cluster:1', ping='whenever'),

            # relation_set still called, despite no credentials being
            # changed, in case the ports have changed.
            call('database:1', username='un', password='pw',
                 host='10.30.0.1', native_transport_port=666, rpc_port=777,
                 cluster_name='fred', datacenter='mission_control',
                 rack='01')])

    @patch('rollingrestart.utcnow_str')
    @patch('helpers.ensure_user')
    @patch('charmhelpers.core.host.pwgen')
    @patch('rollingrestart.get_peers')
    def test_publish_database_relation_follow(self, get_peers, pwgen,
                                              ensure_user, utcnow_str):
        hookenv.local_unit.return_value = 'service/4'
        get_peers.return_value = set(['service/2', 'service/3'])
        pwgen.side_effect = iter(['secret1', 'secret2'])
        config = hookenv.config()
        config['native_transport_port'] = 666
        config['rpc_port'] = 777
        config['cluster_name'] = 'fred'
        config['datacenter'] = 'mission_control'
        config['rack'] = '01'
        utcnow_str.return_value = 'whenever'

        actions._publish_database_relation('database:1', sentinel.superuser)

        # Checked first unit for existing data.
        # There are no existing credentials on the relation.
        hookenv.relation_get.assert_called_once_with(rid='database:1',
                                                     unit='service/2')

        self.assertFalse(ensure_user.called)

        hookenv.relation_set.assert_has_calls([
            # No wakeup, because we are following. Only the leader
            # sets creds.
            # call('cluster:1', ping='whenever'),
            call('database:1',
                 # Still publish details, despite no creds, in case we
                 # are not using password authentication.
                 username=None, password=None,
                 host='10.30.0.4', native_transport_port=666, rpc_port=777,
                 cluster_name='fred', datacenter='mission_control',
                 rack='01')])

    @patch('rollingrestart.utcnow_str')
    @patch('helpers.ensure_user')
    @patch('charmhelpers.core.host.pwgen')
    @patch('rollingrestart.get_peers')
    def test_publish_database_relation_follow2(self, get_peers, pwgen,
                                               ensure_user, utcnow_str):
        get_peers.return_value = set(['service/2', 'service/3'])
        pwgen.side_effect = iter(['secret1', 'secret2'])
        # Existing credentials on the relation.
        hookenv.local_unit.return_value = 'service/2'
        hookenv.relation_set(relation_id='database:1',
                             username='un', password='pw')
        hookenv.local_unit.return_value = 'service/4'
        hookenv.relation_get.reset_mock()
        config = hookenv.config()
        config['native_transport_port'] = 666
        config['rpc_port'] = 777
        config['cluster_name'] = 'fred'
        config['datacenter'] = 'mission_control'
        config['rack'] = '01'
        utcnow_str.return_value = 'whenever'

        actions._publish_database_relation('database:1', sentinel.superuser)

        # Checked first unit for existing data.
        hookenv.relation_get.assert_called_once_with(rid='database:1',
                                                     unit='service/2')

        self.assertFalse(ensure_user.called)

        hookenv.relation_set.assert_has_calls([
            # No wakeup, because we are following. Only the leader
            # sets creds.
            # call('cluster:1', ping='whenever'),
            call('database:1',
                 username='un', password='pw',
                 host='10.30.0.4', native_transport_port=666, rpc_port=777,
                 cluster_name='fred', datacenter='mission_control',
                 rack='01')])

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

    @patch('helpers.emit_describe_cluster')
    def test_emit_describe_cluster(self, helpers_emit):
        actions.emit_describe_cluster('')
        helpers_emit.assert_called_once_with()

    @patch('helpers.emit_auth_keyspace_status')
    def test_emit_auth_keyspace_status(self, helpers_emit):
        actions.emit_auth_keyspace_status('')
        helpers_emit.assert_called_once_with()

    @patch('helpers.emit_netstats')
    def test_emit_netstats(self, helpers_emit):
        actions.emit_netstats('')
        helpers_emit.assert_called_once_with()

    @patch('charmhelpers.core.hookenv.relations_of_type')
    @patch('actions.ufw')
    def test_configure_firewall(self, ufw, rel_of_type):
        rel_of_type.side_effect = iter([
            [{'private-address': '1.1.0.1'}, {'private-address': '1.1.0.2'}],
            [{'private-address': '1.2.0.1'}, {'private-address': '1.2.0.2'}],
            [{'private-address': '1.3.0.1'}, {'private-address': '1.3.0.2'}]])

        actions.configure_firewall('')

        rel_of_type.assert_has_calls([call('cluster'),
                                      call('database'),
                                      call('database-admin')])

        ufw.enable.assert_called_once_with()  # Always enabled.

        # SSH is always opened. The database ports by default have the
        # global allow rule removed, disabling access unless explicitly
        # allowed in following steps.
        ufw.service.assert_has_calls([call('ssh', 'open'),
                                      call(9042, 'close'),
                                      call(9160, 'close')])

        # This test is running for the first time, so there are no
        # previously applied rules to remove. It opens necessary access
        # to peers and other related units. The 1.1.* addresses are
        # peers, and they get storage (7000), ssl_storage (7001),
        # JMX (7199), Thrift (9160) and native (9042). The remaining
        # addresses are clients, getting just Thrift and native.
        ufw.grant_access.assert_has_calls([call('1.1.0.1', 'any', 7000),
                                           call('1.1.0.1', 'any', 7001),
                                           call('1.1.0.1', 'any', 7199),
                                           call('1.1.0.1', 'any', 9042),
                                           call('1.1.0.1', 'any', 9160),

                                           call('1.1.0.2', 'any', 7000),
                                           call('1.1.0.2', 'any', 7001),
                                           call('1.1.0.2', 'any', 7199),
                                           call('1.1.0.2', 'any', 9042),
                                           call('1.1.0.2', 'any', 9160),

                                           call('1.2.0.1', 'any', 9042),
                                           call('1.2.0.1', 'any', 9160),
                                           call('1.2.0.2', 'any', 9042),
                                           call('1.2.0.2', 'any', 9160),

                                           call('1.3.0.1', 'any', 9042),
                                           call('1.3.0.1', 'any', 9160),
                                           call('1.3.0.2', 'any', 9042),
                                           call('1.3.0.2', 'any', 9160)],
                                          any_order=True)

        # If things change in a later hook, unwanted rules are removed
        # and new ones added.
        rel_of_type.side_effect = iter([
            [{'private-address': '1.1.0.1'}],
            [{'private-address': '1.2.0.2'}],
            [{'private-address': '1.3.0.1'}, {'private-address': '1.3.0.2'}]])
        config = hookenv.config()
        config.save()
        config.load_previous()
        config['native_transport_port'] = 7777  # 9042 -> 7777
        config['open_client_ports'] = True
        ufw.reset_mock()

        actions.configure_firewall('')

        # Three ports now globally open. Yes, having the globally open
        # native and Thrift ports does make the later more specific
        # rules meaningless, but we add the specific rules anyway.
        ufw.service.assert_has_calls([call('ssh', 'open'),
                                      call(9042, 'close'),
                                      call(7777, 'open'),
                                      call(9160, 'open')], any_order=True)
        ufw.revoke_access.assert_has_calls([call('1.1.0.1', 'any', 9042),
                                            call('1.1.0.2', 'any', 7000),
                                            call('1.1.0.2', 'any', 7001),
                                            call('1.1.0.2', 'any', 7199),
                                            call('1.1.0.2', 'any', 9042),
                                            call('1.1.0.2', 'any', 9160),

                                            call('1.2.0.1', 'any', 9042),
                                            call('1.2.0.1', 'any', 9160),
                                            call('1.2.0.2', 'any', 9042),

                                            call('1.3.0.1', 'any', 9042),
                                            call('1.3.0.2', 'any', 9042)],
                                           any_order=True)
        ufw.grant_access.assert_has_calls([call('1.1.0.1', 'any', 7777),
                                           call('1.2.0.2', 'any', 7777),
                                           call('1.3.0.1', 'any', 7777),
                                           call('1.3.0.2', 'any', 7777)],
                                          any_order=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
