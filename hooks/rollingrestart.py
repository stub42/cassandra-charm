from datetime import datetime
import os.path

from charmhelpers.contrib import peerstorage
from charmhelpers.core import hookenv, host
from charmhelpers.core.hookenv import DEBUG
import yaml


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
    # Maps unit -> sortable timestamp
    try:
        queue_map = peerstorage.peer_retrieve_by_prefix(
            'rollingrestart', get_peer_relation_name())
    except ValueError:
        return []

    queue = [unit for unit, _ in sorted(queue_map.items(),
                                        key=lambda x: tuple(reversed(x)))]
    return queue


def _enqueue(flag):
    '''Add or remove an entry from peerstorage queue.'''
    if flag is (hookenv.local_unit() in get_restart_queue()):
        return
    value = utcnow_str() if flag else None
    try:
        peerstorage.peer_store(_peerstorage_key(), value,
                               get_peer_relation_name())
    except ValueError:
        # No peer storage, no queue, no problem. If there is no peer
        # storage, there are no peers, and restarts will happen
        # immediately.
        pass


def rolling_restart(restart_hook):
    '''To ensure availability, only restart one unit at a time.

    Returns:
        True if the queued restart has occurred and restart_hook called.
        True if no restart request has been queued.
        False if we are still waiting on a queued restart.

    restart_hook takes no parameters, and its return value is ignored.

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
        restart_hook()
        cancel_restart()
        return True

    # If there are no peers, restart the service now since there is
    # nobody to coordinate with.
    if len(get_peers()) == 0:
        hookenv.log('Restart request with no peers')
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

        # Calculate the includes list, since we can't (yet) ask
        # peerstorage to echo by prefix.
        rdata = hookenv.relation_get()
        includes = [k for k in rdata if k.startswith('rollingrestart_')]
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
    # Make this the charmhelpers.contrib.peerstorage default.
    with open(os.path.join(hookenv.charm_dir(), 'metadata.yaml'), 'r') as mdf:
        md = yaml.safe_load(mdf)
    assert 'peers' in md, 'No peer relations in metadata.yaml'
    return sorted(md['peers'].keys())[0]


def get_peers():
    for relid in hookenv.relation_ids(get_peer_relation_name()):
        return set(hookenv.related_units(relid))
    return []


def utcnow():
    return datetime.utcnow()


def utcnow_str():
    return utcnow().strftime('%Y-%m-%d %H:%M:%S.%fZ')
