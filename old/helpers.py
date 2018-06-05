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
import configparser
from contextlib import contextmanager
from datetime import timedelta
from distutils.version import LooseVersion
from functools import wraps
import io
import json
import os.path
import re
import shutil
import subprocess
import sys
import tempfile
from textwrap import dedent
import time

import bcrypt
from cassandra import ConsistencyLevel
import cassandra.auth
import cassandra.cluster
import cassandra.query
import netifaces
import yaml

from charmhelpers.core import hookenv, host
from charmhelpers.core.hookenv import DEBUG, ERROR, WARNING
from charmhelpers import fetch
from charmhelpers.core.host import is_container


from coordinator import coordinator


RESTART_TIMEOUT = 600


def logged(func):
    @wraps(func)
    def wrapper(*args, **kw):
        hookenv.log("* Helper {}/{}".format(hookenv.hook_name(),
                                            func.__name__))
        return func(*args, **kw)
    return wrapper


def actual_seed_ips():
    '''Return the seeds currently in cassandra.yaml'''
    cassandra_yaml = read_cassandra_yaml()
    s = cassandra_yaml['seed_provider'][0]['parameters'][0]['seeds']
    return set(s.split(','))


def mountpoint(path):
    '''Return the mountpoint that path exists on.'''
    path = os.path.realpath(path)
    while path != '/' and not os.path.ismount(path):
        path = os.path.dirname(path)
    return path


@logged
def stop_cassandra():
    if is_cassandra_running():
        hookenv.log('Shutting down Cassandra')
        host.service_stop(get_cassandra_service())
    if is_cassandra_running():
        hookenv.status_set('blocked', 'Cassandra failed to shut down')
        raise SystemExit(0)


@logged
def start_cassandra():
    if is_cassandra_running():
        return

    actual_seeds = sorted(actual_seed_ips())
    assert actual_seeds, 'Attempting to start cassandra with empty seed list'
    hookenv.config()['configured_seeds'] = actual_seeds

    if is_bootstrapped():
        status_set('maintenance',
                   'Starting Cassandra with seeds {!r}'
                   .format(','.join(actual_seeds)))
    else:
        status_set('maintenance',
                   'Bootstrapping with seeds {}'
                   .format(','.join(actual_seeds)))

    host.service_start(get_cassandra_service())

    # Wait for Cassandra to actually start, or abort.
    timeout = time.time() + RESTART_TIMEOUT
    while time.time() < timeout:
        if is_cassandra_running():
            return
        time.sleep(1)
    status_set('blocked', 'Cassandra failed to start')
    raise SystemExit(0)


@logged
def reconfigure_and_restart_cassandra(overrides={}):
    stop_cassandra()
    configure_cassandra_yaml(overrides)
    start_cassandra()


@logged
def remount_cassandra():
    '''If a new mountpoint is ready, migrate data across to it.'''
    assert not is_cassandra_running()  # Guard against data loss.
    import relations
    storage = relations.StorageRelation()
    if storage.needs_remount():
        status_set('maintenance', 'Migrating data to new mountpoint')
        hookenv.config()['bootstrapped_into_cluster'] = False
        if storage.mountpoint is None:
            hookenv.log('External storage AND DATA gone. '
                        'Reverting to local storage. '
                        'In danger of resurrecting old data. ',
                        WARNING)
        else:
            storage.migrate('/var/lib/cassandra', 'cassandra')
            root = os.path.join(storage.mountpoint, 'cassandra')
            os.chmod(root, 0o750)


def num_nodes():
    return len(get_bootstrapped_ips())


def unit_to_listen_ip(unit):
    if unit is None or unit == hookenv.local_unit():
        return listen_ip_address()
    elif coordinator.relid:
        return hookenv.relation_get(rid=coordinator.relid,
                                    unit=unit).get('listen_ip')
    else:
        return None


def get_node_status():
    '''Return the Cassandra node status.

    May be NORMAL, JOINING, DECOMMISSIONED etc., or None if we can't tell.
    '''
    if not is_cassandra_running():
        return None
    raw = nodetool('netstats')
    m = re.search(r'(?m)^Mode:\s+(\w+)$', raw)
    if m is None:
        return None
    return m.group(1).upper()


def is_decommissioned():
    status = get_node_status()
    if status in ('DECOMMISSIONED', 'LEAVING'):
        hookenv.log('This node is {}'.format(status), WARNING)
        return True
    return False


@logged
def emit_describe_cluster():
    '''Run nodetool describecluster for the logs.'''
    nodetool('describecluster')  # Implicit emit


@logged
def emit_status():
    '''Run 'nodetool status' for the logs.'''
    nodetool('status')  # Implicit emit


@logged
def emit_netstats():
    '''Run 'nodetool netstats' for the logs.'''
    nodetool('netstats')  # Implicit emit


def emit_cluster_info():
    emit_describe_cluster()
    emit_status()
    emit_netstats()


# FOR CHARMHELPERS. This should be a constant in nrpe.py
def local_plugins_dir():
    return '/usr/local/lib/nagios/plugins'


def leader_ping():
    '''Make a change in the leader settings, waking the non-leaders.'''
    assert hookenv.is_leader()
    last = int(hookenv.leader_get('ping') or 0)
    hookenv.leader_set(ping=str(last + 1))


def get_unit_superusers():
    '''Return the set of units that have had their superuser accounts created.
    '''
    raw = hookenv.leader_get('superusers')
    return set(json.loads(raw or '[]'))


def set_unit_superusers(superusers):
    hookenv.leader_set(superusers=json.dumps(sorted(superusers)))


def service_status_set(state, message):
    '''Set the service status and log a message.'''
    try:
        subprocess.check_call(['status-set', '--application', state, message])
        hookenv.log('{} application state: {}'.format(state, message))
    except subprocess.CalledProcessError as x:
        hookenv.log('Unable to set application state: {}'.format(x))
        hookenv.log('Application state: {} {}'.format(state, message))


def get_service_name(relid):
    '''Return the service name for the other end of relid.'''
    units = hookenv.related_units(relid)
    if units:
        return units[0].split('/', 1)[0]
    else:
        return None


def peer_relid():
    return coordinator.relid


@logged
def set_active():
    '''Set happy state'''
    if listen_ip_address() in get_seed_ips():
        msg = 'Live seed'
    else:
        msg = 'Live node'
    status_set('active', msg)

    if hookenv.is_leader():
        n = num_nodes()
        if n == 1:
            n = 'Single'
        service_status_set('active', '{} node cluster'.format(n))
