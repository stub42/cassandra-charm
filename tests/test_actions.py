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

from charmhelpers import fetch
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

    @patch('subprocess.check_call', autospec=True)
    def test_swapoff_lxc(self, check_call):
        # Under LXC, the swapoff action does nothing except log.
        helpers.is_lxc.return_value = True
        actions.swapoff('')
        self.assertFalse(check_call.called)
        hookenv.log.assert_called_once_with(ANY)

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
    def test_reset_sysctl_fails_badly(self, write_file, check_call):
        # Other OSErrors are reraised since we don't know how to handle
        # them.
        check_call.side_effect = OSError(errno.EFAULT, 'Whoops')
        self.assertRaises(OSError, actions.reset_sysctl, '')

    @patch('subprocess.check_call', autospec=True)
    def test_reset_sysctl_lxc(self, check_call):
        helpers.is_lxc.return_value = True
        actions.reset_sysctl('')
        self.assertFalse(check_call.called)
        hookenv.log.assert_called_once_with("In an LXC. "
                                            "Leaving sysctl unchanged.")

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

        popen.reset_mock()
        hookenv.config()['package_status'] = 'invalid'
        self.assertRaises(RuntimeError,
                          actions.ensure_package_status,
                          '', ['a_pack', 'b_back'])
        self.assertFalse(popen.called)

    @patch('helpers.get_cassandra_packages', autospec=True)
    @patch('actions.ensure_package_status', autospec=True)
    def test_ensure_cassandra_package_status(self, ensure_package_status,
                                             get_cassandra_packages):
        get_cassandra_packages.return_value = sentinel.cassandra_packages
        actions.ensure_cassandra_package_status(sentinel.servicename)
        ensure_package_status.assert_called_once_with(
            sentinel.servicename, sentinel.cassandra_packages)

    @patch('helpers.autostart_disabled', autospec=True)
    @patch('charmhelpers.fetch.apt_install', autospec=True)
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

    @patch('helpers.autostart_disabled', autospec=True)
    @patch('charmhelpers.fetch.apt_install', autospec=True)
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

    @patch('helpers.autostart_disabled', autospec=True)
    @patch('charmhelpers.fetch.apt_install', autospec=True)
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

    @patch('helpers.get_cassandra_packages', autospec=True)
    @patch('actions.install_packages', autospec=True)
    def test_install_cassandra_packages(self, install_packages,
                                        get_cassandra_packages):
        get_cassandra_packages.return_value = sentinel.cassandra_packages
        actions.install_cassandra_packages(sentinel.servicename)
        install_packages.assert_called_once_with(
            sentinel.servicename, sentinel.cassandra_packages)

    @patch('helpers.configure_cassandra_yaml', autospec=True)
    def test_configure_cassandra_yaml(self, configure_cassandra_yaml):
        # actions.configure_cassandra_yaml is just a wrapper around the
        # helper.
        actions.configure_cassandra_yaml('')
        configure_cassandra_yaml.assert_called_once_with()

    @patch('helpers.get_cassandra_env_file', autospec=True)
    @patch('charmhelpers.core.host.write_file', autospec=True)
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

    @patch('helpers.get_seeds', autospec=True)
    @patch('relations.StorageRelation', autospec=True)
    @patch('rollingrestart.request_restart', autospec=True)
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

    @patch('helpers.get_seeds', autospec=True)
    @patch('relations.StorageRelation', autospec=True)
    @patch('rollingrestart.request_restart', autospec=True)
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

    @patch('helpers.get_seeds', autospec=True)
    @patch('relations.StorageRelation', autospec=True)
    @patch('rollingrestart.request_restart', autospec=True)
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

    @patch('helpers.get_seeds', autospec=True)
    @patch('relations.StorageRelation', autospec=True)
    @patch('rollingrestart.request_restart', autospec=True)
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

    @patch('helpers.get_seeds', autospec=True)
    @patch('relations.StorageRelation', autospec=True)
    @patch('rollingrestart.request_restart', autospec=True)
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

    @patch('helpers.reset_all_io_schedulers')
    def test_reset_all_io_schedulers(self, helpers_reset_all_io_schedulers):
        actions.reset_all_io_schedulers('ignored')
        helpers_reset_all_io_schedulers.assert_called_once_with()

    def test_restart_keys_complete(self):
        # Ensure that we have listed all keys in either
        # RESTART_REQUIRED_KEYS or RESTART_NOT_REQUIRED_KEYS. This
        # is to ensure that RESTART_REQUIRED_KEYS is maintained as new
        # config items are added over time.
        config_path = os.path.join(os.path.dirname(__file__), os.pardir,
                                   'config.yaml')
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        combined = actions.RESTART_REQUIRED_KEYS.union(
            actions.RESTART_NOT_REQUIRED_KEYS)

        for key in config['options']:
            with self.subTest(key=key):
                self.assertIn(key, combined)


if __name__ == '__main__':
    unittest.main(verbosity=2)
