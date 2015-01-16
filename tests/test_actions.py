#!.venv3/bin/python3

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

from charmhelpers import fetch
from charmhelpers.core import hookenv

from tests.base import TestCaseBase
import actions
import helpers


patch = functools.partial(patch, autospec=True)  # autospec=True as default.


class TestsActions(TestCaseBase):
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

        hookenv.log.assert_called_once_with(ANY, hookenv.ERROR)

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

        self.assertFalse(hookenv.log.called)

    @patch('subprocess.check_call')
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
        hookenv.log.assert_called_once_with(ANY, hookenv.WARNING)

    @patch('subprocess.check_call')
    def test_swapoff_lxc(self, check_call):
        # Under LXC, the swapoff action does nothing except log.
        helpers.is_lxc.return_value = True
        actions.swapoff('')
        self.assertFalse(check_call.called)
        hookenv.log.assert_called_once_with(ANY)

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
        hookenv.log.assert_called_once_with(ANY, hookenv.WARNING)

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
        hookenv.log.assert_called_once_with("In an LXC. "
                                            "Leaving sysctl unchanged.")

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

        popen.reset_mock()
        hookenv.config()['package_status'] = 'invalid'
        self.assertRaises(RuntimeError,
                          actions.ensure_package_status,
                          '', ['a_pack', 'b_back'])
        self.assertFalse(popen.called)

    @patch('helpers.get_cassandra_packages')
    @patch('actions.ensure_package_status')
    def test_ensure_cassandra_package_status(self, ensure_package_status,
                                             get_cassandra_packages):
        get_cassandra_packages.return_value = sentinel.cassandra_packages
        actions.ensure_cassandra_package_status(sentinel.servicename)
        ensure_package_status.assert_called_once_with(
            sentinel.servicename, sentinel.cassandra_packages)

    @patch('helpers.autostart_disabled')
    @patch('charmhelpers.fetch.apt_install')
    def test_install_packages(self, apt_install, autostart_disabled):
        packages = ['a_pack', 'b_pack']
        actions.install_packages('', packages)

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
        actions.install_packages('', packages)

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
        actions.install_packages('', packages)

        # All packages got installed, and hook aborted if package
        # installation failed.
        self.assertFalse(apt_install.called)

        # Autostart wasn't messed with.
        self.assertFalse(autostart_disabled.called)

    @patch('helpers.get_cassandra_packages')
    @patch('actions.install_packages')
    def test_install_cassandra_packages(self, install_packages,
                                        get_cassandra_packages):
        get_cassandra_packages.return_value = sentinel.cassandra_packages
        actions.install_cassandra_packages(sentinel.servicename)
        install_packages.assert_called_once_with(
            sentinel.servicename, sentinel.cassandra_packages)

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
                heap_newsize=re.compile('^HEAP_NEWSIZE=(.*)$', re.M),
                jmx_port=re.compile('^JMX_PORT=(.*)$', re.M))

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
                self.assertEqual(f.read(), 'dc=test_dc\nrack=test_rack')

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
        hookenv.log.assert_called_once_with('Mountpoint changed. '
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
        hookenv.log.assert_called_once_with('Seed list changed. '
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
        hookenv.log.assert_called_once_with('max_heap_size changed. '
                                            'Restart required.')

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
        hookenv.log.assert_called_once_with('Unit IP address changed. '
                                            'Restart required.')

    @patch('helpers.stop_cassandra')
    def test_stop_cassandra(self, helpers_stop_cassandra):
        actions.stop_cassandra('ignored')
        helpers_stop_cassandra.assert_called_once_with()

    @patch('helpers.start_cassandra')
    def test_start_cassandra(self, helpers_start_cassandra):
        actions.start_cassandra('ignored')
        helpers_start_cassandra.assert_called_once_with()

    @patch('helpers.reset_default_password')
    def test_reset_default_password(self, helpers_reset_default_password):
        actions.reset_default_password('ignored')
        helpers_reset_default_password.assert_called_once_with()

    @patch('helpers.ensure_superuser')
    def test_ensure_superuser(self, helpers_ensure_superuser):
        actions.ensure_superuser('ignored')
        helpers_ensure_superuser.assert_called_once_with()

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

    @patch('helpers.connect')
    @patch('helpers.is_cassandra_running')
    def test_reset_auth_keyspace_rf_down(self, is_running, connect):
        is_running.return_value = False
        actions.reset_auth_keyspace_replication_factor('')  # Noop
        self.assertFalse(connect.called)  # No attempt was made.

    @patch('helpers.set_auth_keyspace_replication_factor')
    @patch('helpers.get_auth_keyspace_replication_factor')
    @patch('helpers.num_nodes')
    @patch('helpers.is_cassandra_running')
    def test_reset_auth_keyspace_rf_changed(self, is_running, num_nodes,
                                            get_auth_rf, set_auth_rf):
        is_running.return_value = True
        num_nodes.return_value = 2
        get_auth_rf.return_value = 3

        # If the number of nodes does not match the system_auth
        # keyspace's replication factor, the system_auth keyspace's
        # replication factor is updated to match.
        actions.reset_auth_keyspace_replication_factor('')
        set_auth_rf.assert_called_once_with(2)

    @patch('helpers.set_auth_keyspace_replication_factor')
    @patch('helpers.get_auth_keyspace_replication_factor')
    @patch('helpers.num_nodes')
    @patch('helpers.is_cassandra_running')
    def test_reset_auth_keyspace_rf_unchanged(self, is_running, num_nodes,
                                              get_auth_rf, set_auth_rf):
        is_running.return_value = True
        num_nodes.return_value = 3
        get_auth_rf.return_value = 3

        # If the number of nodes matches the system_auth
        # keyspace's replication factor, nothing happens.
        actions.reset_auth_keyspace_replication_factor('')
        self.assertFalse(set_auth_rf.called)

    @patch('subprocess.check_call')
    @patch('helpers.num_nodes')
    def test_repair_auth_keyspace(self, num_nodes, check_call):
        # If the number of nodes has changed, we need to run
        # 'nodetool repair system_auth' on all the units.
        num_nodes.return_value = 2

        # First time, there is no preserved state, and we repair.
        actions.repair_auth_keyspace('')
        check_call.assert_called_once_with(['nodetool',
                                            'repair', 'system_auth'])

        hookenv.config().save()
        hookenv.config().load_previous()
        check_call.reset_mock()

        # Next time, there is no change so do nothing.
        actions.repair_auth_keyspace('')
        self.assertFalse(check_call.called)

        hookenv.config().save()
        hookenv.config().load_previous()
        check_call.reset_mock()

        # If the number of nodes changes from preserved state, we
        # repair.
        num_nodes.return_value = 3
        actions.repair_auth_keyspace('')
        check_call.assert_called_once_with(['nodetool',
                                            'repair', 'system_auth'])

    def test_publish_cluster_relation(self):
        actions.publish_cluster_relation('')
        hookenv.relation_set.assert_called_once_with(
            'cluster:1', {'public-address': '10.30.0.1'})

    @patch('rollingrestart.get_peer_relation_id')
    def test_publish_cluster_relation_not_yet(self, get_relid):
        get_relid.return_value = None  # Peer relation not yet joined.
        actions.publish_cluster_relation('')  # Noop
        self.assertFalse(hookenv.relation_set.called)

    @patch('rollingrestart.utcnow_str')
    @patch('helpers.ensure_user')
    @patch('charmhelpers.core.host.pwgen')
    @patch('rollingrestart.get_peers')
    def test_publish_database_relations_alone(self, get_peers, pwgen,
                                              ensure_user, utcnow_str):
        get_peers.return_value = set()
        pwgen.side_effect = iter(['secret1', 'secret2'])
        hookenv.relation_get.return_value = {}
        config = hookenv.config()
        config['native_client_port'] = 666
        config['thrift_client_port'] = 777
        config['cluster_name'] = 'fred'
        config['datacenter'] = 'mission_control'
        config['rack'] = '01'
        utcnow_str.return_value = 'whenever'

        actions.publish_database_relations('')

        # Checked this unit for existing data.
        hookenv.relation_get.assert_called_once_with(rid='database:1',
                                                     unit='service/1')

        ensure_user.assert_called_once_with('juju_database_1', 'secret1')

        hookenv.relation_set.assert_has_calls([
            call('cluster:1', ping='whenever'),
            call('database:1',
                 username='juju_database_1', password='secret1',
                 host='10.30.0.1', port=666, thrift_port=777,
                 cluster_name='fred', datacenter='mission_control',
                 rack='01')])

    @patch('rollingrestart.utcnow_str')
    @patch('helpers.ensure_user')
    @patch('rollingrestart.get_peers')
    def test_publish_database_relations_alone2(self, get_peers,
                                               ensure_user, utcnow_str):
        get_peers.return_value = set()
        # There are existing credentials on the relation.
        hookenv.relation_set(relation_id='database:1',
                             username='un', password='pw')
        config = hookenv.config()
        config['native_client_port'] = 666
        config['thrift_client_port'] = 777
        config['cluster_name'] = 'fred'
        config['datacenter'] = 'mission_control'
        config['rack'] = '01'
        utcnow_str.return_value = 'whenever'

        actions.publish_database_relations('')

        # Checked this unit for existing data.
        hookenv.relation_get.assert_called_once_with(rid='database:1',
                                                     unit='service/1')

        # Even if the stored creds are unchanged, we ensure the password
        # is valid and reset it if necessary.
        ensure_user.assert_called_once_with('un', 'pw')

        hookenv.relation_set.assert_has_calls([
            # Credentials unchanged, so no peer wakeup.
            # call('cluster:1', ping='whenever'),

            # relation_set still called, despite no credentials being
            # changed, in case the other details have changed.
            call('database:1', username='un', password='pw',
                 host='10.30.0.1', port=666, thrift_port=777,
                 cluster_name='fred', datacenter='mission_control',
                 rack='01')])

    @patch('rollingrestart.utcnow_str')
    @patch('helpers.ensure_user')
    @patch('charmhelpers.core.host.pwgen')
    @patch('rollingrestart.get_peers')
    def test_publish_database_relations_leader(self, get_peers, pwgen,
                                               ensure_user, utcnow_str):
        get_peers.return_value = set(['service/2', 'service/3'])
        pwgen.side_effect = iter(['secret1', 'secret2'])
        hookenv.relation_get.return_value = {}
        config = hookenv.config()
        config['native_client_port'] = 666
        config['thrift_client_port'] = 777
        config['cluster_name'] = 'fred'
        config['datacenter'] = 'mission_control'
        config['rack'] = '01'
        utcnow_str.return_value = 'whenever'

        actions.publish_database_relations('')

        # Checked this unit for existing data.
        hookenv.relation_get.assert_called_once_with(rid='database:1',
                                                     unit='service/1')

        ensure_user.assert_called_once_with('juju_database_1', 'secret1')

        hookenv.relation_set.assert_has_calls([
            call('cluster:1', ping='whenever'),
            call('database:1',
                 username='juju_database_1', password='secret1',
                 host='10.30.0.1', port=666, thrift_port=777,
                 cluster_name='fred', datacenter='mission_control',
                 rack='01')])

    @patch('rollingrestart.utcnow_str')
    @patch('helpers.ensure_user')
    @patch('rollingrestart.get_peers')
    def test_publish_database_relations_leader2(self, get_peers,
                                                ensure_user, utcnow_str):
        get_peers.return_value = set()
        # There are existing credentials on the relation.
        hookenv.relation_set(relation_id='database:1',
                             username='un', password='pw')
        config = hookenv.config()
        config['native_client_port'] = 666
        config['thrift_client_port'] = 777
        config['cluster_name'] = 'fred'
        config['datacenter'] = 'mission_control'
        config['rack'] = '01'
        utcnow_str.return_value = 'whenever'

        actions.publish_database_relations('')

        # Checked this unit for existing data.
        hookenv.relation_get.assert_called_once_with(rid='database:1',
                                                     unit='service/1')

        # Even if the stored creds are unchanged, we ensure the password
        # is valid and reset it if necessary.
        ensure_user.assert_called_once_with('un', 'pw')

        hookenv.relation_set.assert_has_calls([
            # Credentials unchanged, so no peer wakeup.
            # call('cluster:1', ping='whenever'),

            # relation_set still called, despite no credentials being
            # changed, in case the ports have changed.
            call('database:1', username='un', password='pw',
                 host='10.30.0.1', port=666, thrift_port=777,
                 cluster_name='fred', datacenter='mission_control',
                 rack='01')])

    @patch('charmhelpers.core.hookenv.local_unit')
    @patch('rollingrestart.utcnow_str')
    @patch('helpers.ensure_user')
    @patch('charmhelpers.core.host.pwgen')
    @patch('rollingrestart.get_peers')
    def test_publish_database_relations_follow(self, get_peers, pwgen,
                                               ensure_user, utcnow_str,
                                               local_unit):
        local_unit.return_value = 'service/4'
        get_peers.return_value = set(['service/2', 'service/3'])
        pwgen.side_effect = iter(['secret1', 'secret2'])
        config = hookenv.config()
        config['native_client_port'] = 666
        config['thrift_client_port'] = 777
        config['cluster_name'] = 'fred'
        config['datacenter'] = 'mission_control'
        config['rack'] = '01'
        utcnow_str.return_value = 'whenever'

        actions.publish_database_relations('')

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
                 host='10.30.0.1', port=666, thrift_port=777,
                 cluster_name='fred', datacenter='mission_control',
                 rack='01')])

    @patch('charmhelpers.core.hookenv.local_unit')
    @patch('rollingrestart.utcnow_str')
    @patch('helpers.ensure_user')
    @patch('charmhelpers.core.host.pwgen')
    @patch('rollingrestart.get_peers')
    def test_publish_database_relations_follow2(self, get_peers, pwgen,
                                                ensure_user, utcnow_str,
                                                local_unit):
        get_peers.return_value = set(['service/2', 'service/3'])
        pwgen.side_effect = iter(['secret1', 'secret2'])
        # Existing credentials on the relation.
        hookenv.local_unit.return_value = 'service/2'
        hookenv.relation_set(relation_id='database:1',
                             username='un', password='pw')
        hookenv.local_unit.return_value = 'service/4'
        hookenv.relation_get.reset_mock()
        config = hookenv.config()
        config['native_client_port'] = 666
        config['thrift_client_port'] = 777
        config['cluster_name'] = 'fred'
        config['datacenter'] = 'mission_control'
        config['rack'] = '01'
        utcnow_str.return_value = 'whenever'

        actions.publish_database_relations('')

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
                 host='10.30.0.1', port=666, thrift_port=777,
                 cluster_name='fred', datacenter='mission_control',
                 rack='01')])


if __name__ == '__main__':
    unittest.main(verbosity=2)
