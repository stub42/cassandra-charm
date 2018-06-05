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

import errno
import functools
from itertools import repeat
import os.path
import subprocess
import tempfile
import unittest
from unittest.mock import ANY, call, patch

from charmhelpers.core import hookenv

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'lib'))

import helpers  # noqa


patch = functools.partial(patch, autospec=True)


class TestHelpers(unittest.TestCase):
    def setUp(self):
        p = patch('charmhelpers.core.hookenv.log')
        p.start()
        self.addCleanup(p.stop)
        p = patch('charmhelpers.core.host.log')
        p.start()
        self.addCleanup(p.stop)

    @patch('os.fchown')
    def test_autostart_disabled(self, _fchown):
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

    @patch('os.fchown')
    def test_autostart_disabled_partial(self, _fchown):
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

    @patch('charmhelpers.core.host.is_container')
    @patch('charmhelpers.core.host.write_file')
    @patch('os.path.exists')
    @patch('os.path.isdir')
    @patch('subprocess.check_output')
    def test_set_io_scheduler(self, check_output, isdir, exists, write_file, is_container):
        is_container.return_value = False
        # Normal operation, the device is detected and the magic
        # file written.
        check_output.return_value = 'foo\n/dev/sdq 1 2 3 1% /foo\n'
        isdir.return_value = True
        exists.return_value = True

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
        is_container.return_value = True
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
