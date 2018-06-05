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

'''Misc helpers

Useful stuff that should be pushed to shared libraries or layers.
'''

from contextlib import contextmanager
from datetime import timedelta
import os.path
import re
import shutil
import subprocess

from charmhelpers.core import (
    hookenv,
    host,
)
from charmhelpers.core.hookenv import (
    DEBUG,
    WARNING,
)


# For charm-helpers or apt layer
@contextmanager
def autostart_disabled(services=None, _policy_rc='/usr/sbin/policy-rc.d'):
    '''Tell well behaved Debian packages to not start services when installed.
    '''
    script = ['#!/bin/sh']
    if services is not None:
        for service in services:
            script.append(
                'if [ "$1" = "{}" ]; then exit 101; fi'.format(service))
        script.append('exit 0')
    else:
        script.append('exit 101')  # By default, all daemons disabled.
    try:
        if os.path.exists(_policy_rc):
            shutil.move(_policy_rc, "{}-orig".format(_policy_rc))
        host.write_file(_policy_rc, '\n'.join(script).encode('ASCII'),
                        perms=0o555)
        yield
    finally:
        os.unlink(_policy_rc)
        if os.path.exists("{}-orig".format(_policy_rc)):
            shutil.move("{}-orig".format(_policy_rc), _policy_rc)


def set_io_scheduler(io_scheduler, directory):
    '''Set the block device io scheduler.'''

    if host.is_container():
        return

    hookenv.log("Setting block device of {} to IO scheduler {}"
                "".format(directory, io_scheduler))

    assert os.path.isdir(directory)

    # The block device regex may be a tad simplistic.
    block_regex = re.compile('\/dev\/([a-z]*)', re.IGNORECASE)

    output = subprocess.check_output(['df', directory],
                                     universal_newlines=True)
    try:
        block_dev = re.findall(block_regex, output)[0]
    except IndexError:
        hookenv.log("Unable to locate block device of {}".format(directory))
        return
    sys_file = os.path.join("/", "sys", "block", block_dev,
                            "queue", "scheduler")
    if not os.path.exists(sys_file):
        hookenv.log("Got no such file or directory trying to "
                    "set the IO scheduler at {}. It may be "
                    "this is an LXC, the device name is as "
                    "yet unknown to the charm, or LVM/RAID is "
                    "hiding the underlying device name."
                    "".format(sys_file),
                    WARNING)
        return

    available = open(sys_file, 'r').read().split()
    if '[{}]'.format(io_scheduler) in available:
        hookenv.log('{} already {}'.format(sys_file, io_scheduler), DEBUG)
        return

    if io_scheduler not in available:
        hookenv.log('{} is not valid for {}'.format(io_scheduler, sys_file),
                    WARNING)
        return

    host.write_file(sys_file, io_scheduler.encode('ascii'),
                    perms=0o644)


def week_spread(unit_num):
    '''Pick a time for a unit's weekly job.

    Jobs are spread out evenly throughout the week as best we can.
    The chosen time only depends on the unit number, and does not change
    if other units are added and removed; while the chosen time will not
    be perfect, we don't have to worry about skipping a weekly job if
    units are added or removed at the wrong moment.

    Returns (dow, hour, minute) suitable for cron.
    '''
    def vdc(n, base=2):
        '''Van der Corpet sequence. 0, 0.5, 0.25, 0.75, 0.125, 0.625, ...

        http://rosettacode.org/wiki/Van_der_Corput_sequence#Python
        '''
        vdc, denom = 0, 1
        while n:
            denom *= base
            n, remainder = divmod(n, base)
            vdc += remainder / denom
        return vdc
    # We could use the vdc() function to distribute jobs evenly throughout
    # the week, so unit 0==0, unit 1==3.5days, unit 2==1.75 etc. But
    # plain modulo for the day of week is easier for humans and what
    # you expect for 7 units or less.
    sched_dow = unit_num % 7
    # We spread time of day so each batch of 7 units gets the same time,
    # as far spread out from the other batches of 7 units as possible.
    minutes_in_day = 24 * 60
    sched = timedelta(minutes=int(minutes_in_day * vdc(unit_num // 7)))
    sched_hour = sched.seconds // (60 * 60)
    sched_minute = sched.seconds // 60 - sched_hour * 60
    return (sched_dow, sched_hour, sched_minute)


def recursive_chown(directory, owner="root", group="root"):
    '''Change ownership of all files and directories in 'directory'.

    Ownership of 'directory' is also reset.
    '''
    shutil.chown(directory, owner, group)
    for root, dirs, files in os.walk(directory):
        for dirname in dirs:
            shutil.chown(os.path.join(root, dirname), owner, group)
        for filename in files:
            shutil.chown(os.path.join(root, filename), owner, group)


def status_set(status, msg):
    if not status:
        status = hookenv.status_get()[0]
    hookenv.log('{}: {}'.format(status, msg))
    hookenv.status_set(status, msg)
