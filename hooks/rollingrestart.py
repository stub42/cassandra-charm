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

from datetime import datetime
import os.path

from charmhelpers.contrib import peerstorage
from charmhelpers.core import hookenv, host
from charmhelpers.core.hookenv import DEBUG


def request_restart():
    '''Request a rolling restart.'''
    # We store the local restart request as a flag on the filesystem,
    # for rolling_restart() to deal with later. This allows
    # rolling_restart to know that this is a new entry to be queued for
    # a future hook to handle, or an existing entry in the queue that
    # may be restarted this hook.
    flag = os.path.join(hookenv.charm_dir(), '.needs-restart')
    if os.path.exists(flag):
        return
    host.write_file(flag, utcnow_str().encode('US-ASCII'))


def is_waiting_for_restart():
    '''Is there an outstanding rolling restart request.'''
    flag = os.path.join(hookenv.charm_dir(), '.needs-restart')
    return os.path.exists(flag)


def cancel_restart():
    '''Cancel the rolling restart request, if any, and dequeue.'''
    _enqueue(False)
    flag = os.path.join(hookenv.charm_dir(), '.needs-restart')
    if os.path.exists(flag):
        os.remove(flag)


def get_restart_queue():
    '''The sorted list of units waiting for a rolling restart.

    The local unit will not be included until after rolling_restart
    has been called.
    '''
    relid = get_peer_relation_id()
    if relid is None:
        return []

    all_units = set(get_peers())
    all_units.add(hookenv.local_unit())

    queue = []

    # Iterate over all units, retrieving restartrequest flags.
    # We can't use the peerstorage helpers here, as that will only
    # retrieve data that has been echoed and may be out of date if
    # the necessary relation-changed hooks have not yet been invoked.
    for unit in all_units:
        relinfo = hookenv.relation_get(unit=unit, rid=relid)
        request = relinfo.get('rollingrestart_{}'.format(unit))
        if request is not None:
            queue.append((request, unit))
    queue.sort()
    return [unit for _, unit in queue]


def _enqueue(flag):
    '''Add or remove an entry from peerstorage queue.'''
    relid = get_peer_relation_id()
    if not relid:
        # No peer relation, no problems. If there is no peer relation,
        # there are no peers to coordinate with.
        return

    unit = hookenv.local_unit()
    queue = get_restart_queue()
    if flag and unit in queue:
        return  # Already queued.

    key = _peerstorage_key()
    value = utcnow_str() if flag else None
    hookenv.log('Restart queue {} = {}'.format(key, value))
    hookenv.relation_set(relid, {key: value})


def rolling_restart(restart_hooks):
    '''To ensure availability, only restart one unit at a time.

    Returns:
        True if the queued restart has occurred and restart_hook called.
        True if no restart request has been queued.
        False if we are still waiting on a queued restart.

    restart_hooks is a list of callables that takes no parameters.

    For best results, call rolling_restart() unconditionally at the
    beginning and end of every hook.

    At a minimum, rolling_restart() must be called every peer
    relation-changed hook, and after any non-peer hook calls
    request_restart(), or the system will deadlock.
    '''
    _peer_echo()  # Always call this, or peerstorage will fail.

    if not is_waiting_for_restart():
        cancel_restart()  # Clear any errant queue entries.
        return True

    def _restart():
        for restart_hook in restart_hooks:
            restart_hook()
        hookenv.log('Restart complete.')
        cancel_restart()
        hookenv.log('Restart queue entries purged.')
        return True

    # If there are no peers, restart the service now since there is
    # nobody to coordinate with.
    if len(get_peers()) == 0:
        hookenv.log('Restart request with no peers. Restarting.')
        return _restart()

    local_unit = hookenv.local_unit()
    queue = get_restart_queue()

    # If we are not in the restart queue, join it and restart later.
    # If there are peers, we cannot restart in the same hook we made
    # the request or we will race with other units trying to restart.
    if local_unit not in queue:
        hookenv.log('Joining rolling restart queue')
        _enqueue(True)
        return False

    if local_unit == queue[0]:
        hookenv.log('First in rolling restart queue. Restarting.')
        return _restart()

    queue_str = ', '.join(queue)
    hookenv.log('Waiting in rolling restart queue ({})'.format(queue_str))
    return False


def _peerstorage_key():
    return 'rollingrestart_{}'.format(hookenv.local_unit())


def _peer_echo():
    peer_relname = get_peer_relation_name()
    changed_hook = '{}-relation-changed'.format(peer_relname)

    # If we are in the peer relation-changed hook, we must invoke
    # peerstorage.peer_echo() or peerstorage will fail.
    if hookenv.hook_name() == changed_hook:
        # We only want to echo the restart entry for the remote unit, as
        # any other information it has for other peers may be stale.
        includes = ['rollingrestart_{}'.format(hookenv.remote_unit())]
        hookenv.log('peerstorage.peer_echo for rolling restart.')
        hookenv.log('peer_echo(includes={!r})'.format(includes), DEBUG)
        # This method only works from the peer relation-changed hook.
        peerstorage.peer_echo(includes)

    # If a peer is departing, clean out any rubbish it left in the
    # peerstorage.
    departed_hook = '{}-relation-departed'.format(peer_relname)
    if hookenv.hook_name() == departed_hook:
        key = 'rollingrestart_{}'.format(hookenv.remote_unit())
        peerstorage.peer_store(key, None, peer_relname)


def get_peer_relation_name():
    # Make this the charmhelpers.contrib.peerstorage default?
    # Although it is normal to have a single peer relation, it is
    # possible to have many. We use the first in alphabetical order.
    md = hookenv.metadata()
    assert 'peers' in md, 'No peer relations in metadata.yaml'
    return sorted(md['peers'].keys())[0]


def get_peer_relation_id():
    for relid in hookenv.relation_ids(get_peer_relation_name()):
        return relid
    return None


# Unneeded
# def get_peer_relation_interface():
#     relname = get_peer_relation_name()
#     md = hookenv.metadata()
#     return md['peers'][relname]['interface']


def get_peers():
    """Return the sorted list of peer units.

    Peers only. Does not include the local unit.
    """
    for relid in hookenv.relation_ids(get_peer_relation_name()):
        return sorted(hookenv.related_units(relid),
                      key=lambda x: int(x.split('/')[-1]))
    return []


def utcnow():
    return datetime.utcnow()


def utcnow_str():
    return utcnow().strftime('%Y-%m-%d %H:%M:%S.%fZ')


def make_service(restart_hooks):
    """Create a service dictionary for rolling restart.

    This needs to be a separate service, rather than a data_ready or
    provided_data item on an existing service, because the rolling_restart()
    function must be called for all hooks to avoid deadlocking the system.
    It would only be safe to list rolling_restart() as a data_ready item in
    a service with no requirements.
    """
    def data_ready(servicename):
        rolling_restart(restart_hooks)

    return dict(service='rollingrestart', data_ready=data_ready,
                stop=[], start=[])
