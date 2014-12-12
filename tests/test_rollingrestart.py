#!.venv3/bin/python3

from datetime import datetime, timedelta
import os.path
import unittest
from unittest.mock import MagicMock, patch, sentinel

from charmhelpers.core import hookenv

from tests.base import TestCaseBase
import rollingrestart


class TestRollingRestart(TestCaseBase):
    def setUp(self):
        super(TestRollingRestart, self).setUp()

        _last_utc_now = datetime(2010, 12, 25, 13, 45)

        def _utcnow():
            nonlocal _last_utc_now
            _last_utc_now += timedelta(seconds=1)
            return _last_utc_now

        utcnow = patch('rollingrestart.utcnow', autospec=True,
                       side_effect=_utcnow)
        utcnow.start()
        self.addCleanup(utcnow.stop)

    @patch('rollingrestart._enqueue', autospec=True)
    def test_requests(self, enqueue):
        # The restart request flag is stored as a file on the
        # filesystem, and thus persists across hooks.
        flag = os.path.join(hookenv.charm_dir(), '.needs-restart')
        self.assertFalse(rollingrestart.is_waiting_for_restart())
        self.assertFalse(os.path.exists(flag))

        # Requesting a restart creates the flag. It does not add the
        # request to the queue; that is the responsibility of
        # rolling_restart()
        enqueue.reset_mock()
        rollingrestart.request_restart()
        self.assertTrue(rollingrestart.is_waiting_for_restart())
        self.assertTrue(os.path.exists(flag))
        self.assertFalse(enqueue.called)

        # Requesting a restart more than once is safe, and is a noop.
        enqueue.reset_mock()
        rollingrestart.request_restart()
        self.assertTrue(rollingrestart.is_waiting_for_restart())
        self.assertTrue(os.path.exists(flag))
        self.assertFalse(enqueue.called)

        # A request can be cancelled. This removed the filesystem flag,
        # and purges any peerstorage queue entry.
        enqueue.reset_mock()
        rollingrestart.cancel_restart()
        self.assertFalse(rollingrestart.is_waiting_for_restart())
        self.assertFalse(os.path.exists(flag))
        enqueue.assert_called_once_with(False)

        # A request can safely be cancelled even if not requested.
        enqueue.reset_mock()
        rollingrestart.cancel_restart()
        self.assertFalse(rollingrestart.is_waiting_for_restart())
        self.assertFalse(os.path.exists(flag))
        enqueue.assert_called_once_with(False)

    @patch('charmhelpers.core.hookenv.local_unit')
    @patch('rollingrestart.get_peer_relation_name')
    @patch('charmhelpers.contrib.peerstorage.peer_retrieve')
    @patch('charmhelpers.contrib.peerstorage.peer_store')
    def test_restart_queue(self, store, retrieve, relname, local_unit):
        # The restart queue is stored in peerstorage.
        relname.return_value = sentinel.relname
        peer_storage = {sentinel.relname: {}}

        def _store(key, value, relation_name):
            if value is None:
                if key in peer_storage[relation_name]:
                    del peer_storage[relation_name][key]
            else:
                peer_storage[relation_name][key] = value

        def _retrieve(key, relation_name):
            if key == '-':
                return dict(peer_storage[relation_name])
            return peer_storage[relation_name].get(key)

        store.side_effect = _store
        retrieve.side_effect = _retrieve

        # The queue starts empty
        self.assertListEqual(rollingrestart.get_restart_queue(), [])

        def enqueue_unit(unit, flag):
            local_unit.return_value = unit
            rollingrestart._enqueue(flag)

        # Adding units grows it.
        enqueue_unit('unit/1', True)
        self.assertListEqual(rollingrestart.get_restart_queue(), ['unit/1'])

        # They are returned in order added.
        enqueue_unit('unit/0', True)
        enqueue_unit('unit/6', True)
        enqueue_unit('unit/8', True)
        self.assertListEqual(rollingrestart.get_restart_queue(),
                             ['unit/1', 'unit/0', 'unit/6', 'unit/8'])

        # They can be removed.
        enqueue_unit('unit/0', False)
        self.assertListEqual(rollingrestart.get_restart_queue(),
                             ['unit/1', 'unit/6', 'unit/8'])
        enqueue_unit('unit/1', False)
        self.assertListEqual(rollingrestart.get_restart_queue(),
                             ['unit/6', 'unit/8'])

        # Adding a unit again does nothing, and the unit maintains its
        # position in the queue.
        enqueue_unit('unit/6', True)
        self.assertListEqual(rollingrestart.get_restart_queue(),
                             ['unit/6', 'unit/8'])
        enqueue_unit('unit/6', False)
        self.assertListEqual(rollingrestart.get_restart_queue(),
                             ['unit/8'])

    @patch('charmhelpers.contrib.peerstorage.peer_retrieve', autospec=True)
    @patch('charmhelpers.contrib.peerstorage.peer_store', autospec=True)
    def test_restart_queue_no_peers(self, peer_store, peer_retrieve):
        # Peerstorage signals lack of a suitable peer relation by
        # raising a ValueError exception. The enqueue helper ignores
        # this, and silently does nothing. This is desirable, because if
        # there is no suitable peer relation there are no peers. If
        # there are no peers, rolling_restart() will restart things
        # immediately because there are no peers to coordinate with.
        peer_store.side_effect = ValueError('foo')
        peer_retrieve.side_effect = ValueError('foo')

        self.assertListEqual(rollingrestart.get_restart_queue(), [])
        rollingrestart._enqueue(True)
        self.assertListEqual(rollingrestart.get_restart_queue(), [])
        rollingrestart._enqueue(False)
        self.assertListEqual(rollingrestart.get_restart_queue(), [])

    @patch('rollingrestart.cancel_restart', autospec=True)
    @patch('rollingrestart.is_waiting_for_restart', autospec=True)
    def test_rolling_restart_no_request(self, is_waiting, cancel_restart):
        is_waiting.return_value = False
        restart_hook = MagicMock()
        # rolling_restart returns True if there is no outstanding
        # request, without restarting anything.
        self.assertTrue(rollingrestart.rolling_restart(restart_hook))
        self.assertFalse(restart_hook.called)

        # It does however remove the unit from the queue using
        # cancel_restart.
        cancel_restart.assert_called_once_with()

    @patch('rollingrestart._peer_echo', autospec=True)
    @patch('rollingrestart.get_peers', autospec=True)
    @patch('rollingrestart.cancel_restart', autospec=True)
    @patch('rollingrestart.is_waiting_for_restart', autospec=True)
    def test_rolling_restart_no_peers(self, is_waiting, cancel_restart,
                                      get_peers, peer_echo):
        is_waiting.return_value = True
        restart_hook = MagicMock()
        get_peers.return_value = []
        # If there are no peers, a restart request will happen
        # immediately. We don't put things in the queue, because without
        # peers there is no peerstorage and no queue, and nobody to
        # coordinate with in any case.
        self.assertTrue(rollingrestart.rolling_restart(restart_hook))
        restart_hook.assert_called_once_with()

        # We must always call this, even if there are currently no
        # peers.
        peer_echo.assert_called_once_with()

    @patch('rollingrestart._peer_echo', autospec=True)
    @patch('rollingrestart._enqueue', autospec=True)
    @patch('rollingrestart.get_restart_queue', autospec=True)
    @patch('rollingrestart.get_peers', autospec=True)
    @patch('rollingrestart.is_waiting_for_restart', autospec=True)
    def test_rolling_restart_empty_queue(self, is_waiting, get_peers,
                                         get_queue, enqueue, peer_echo):
        is_waiting.return_value = True
        restart_hook = MagicMock()
        get_peers.return_value = ['unit/1', 'unit/2']
        get_queue.return_value = []

        # If there are no units queued, but there are peers,
        # rolling_restart() adds the unit to the queue and returns
        # False. No restart is done, because we first need to wait for
        # this request to be published before we can tell if there are
        # other units attempting to restart at the same time (this is
        # common, as all units in a service will tend to want to restart
        # at the same time).
        self.assertFalse(rollingrestart.rolling_restart(restart_hook))
        enqueue.assert_called_once_with(True)
        self.assertFalse(restart_hook.called)
        peer_echo.assert_called_once_with()  # peer_echo helper called.

    @patch('rollingrestart._peer_echo', autospec=True)
    @patch('rollingrestart._enqueue', autospec=True)
    @patch('rollingrestart.get_restart_queue', autospec=True)
    @patch('rollingrestart.get_peers', autospec=True)
    @patch('rollingrestart.is_waiting_for_restart', autospec=True)
    def test_rolling_restart_with_queue(self, is_waiting, get_peers,
                                        get_queue, enqueue, peer_echo):
        is_waiting.return_value = True
        restart_hook = MagicMock()
        get_peers.return_value = ['unit/1', 'unit/2']
        get_queue.return_value = ['unit/1']

        self.assertFalse(rollingrestart.rolling_restart(restart_hook))
        enqueue.assert_called_once_with(True)
        self.assertFalse(restart_hook.called)
        peer_echo.assert_called_once_with()  # peer_echo helper called.

    @patch('rollingrestart._peer_echo', autospec=True)
    @patch('rollingrestart.get_restart_queue', autospec=True)
    @patch('rollingrestart.get_peers', autospec=True)
    @patch('rollingrestart.is_waiting_for_restart', autospec=True)
    def test_rolling_restart_stuck_in_queue(self, is_waiting, get_peers,
                                            get_queue, peer_echo):
        is_waiting.return_value = True
        restart_hook = MagicMock()
        get_peers.return_value = ['unit/1', 'unit/2']
        get_queue.return_value = ['unit/1', hookenv.local_unit()]

        self.assertFalse(rollingrestart.rolling_restart(restart_hook))
        self.assertFalse(restart_hook.called)
        peer_echo.assert_called_once_with()  # peer_echo helper called.

    @patch('rollingrestart._peer_echo', autospec=True)
    @patch('rollingrestart.get_restart_queue', autospec=True)
    @patch('rollingrestart.get_peers', autospec=True)
    @patch('rollingrestart.cancel_restart', autospec=True)
    @patch('rollingrestart.is_waiting_for_restart', autospec=True)
    def test_rolling_restart_first_in_queue(self, is_waiting, cancel_restart,
                                            get_peers, get_queue, peer_echo):
        is_waiting.return_value = True
        restart_hook = MagicMock()
        get_peers.return_value = ['unit/1', 'unit/2']
        get_queue.return_value = [hookenv.local_unit(), 'unit/1']

        self.assertTrue(rollingrestart.rolling_restart(restart_hook))
        cancel_restart.assert_called_once_with()
        restart_hook.assert_called_once_with()
        peer_echo.assert_called_once_with()  # peer_echo helper called.

    @patch('rollingrestart._peer_echo', autospec=True)
    @patch('rollingrestart.get_restart_queue', autospec=True)
    @patch('rollingrestart.get_peers', autospec=True)
    @patch('rollingrestart.cancel_restart', autospec=True)
    @patch('rollingrestart.is_waiting_for_restart', autospec=True)
    def test_rolling_restart_fails(self, is_waiting, cancel_restart,
                                   get_peers, get_queue, peer_echo):
        is_waiting.return_value = True
        restart_hook = MagicMock()
        restart_hook.side_effect = RuntimeError('Kaboom')
        get_peers.return_value = ['unit/1', 'unit/2']
        get_queue.return_value = [hookenv.local_unit(), 'unit/1']

        # If restart raises an exception, rolling_restart does not
        # handle it. This is how you communicate a failed restart to
        # your charm.
        self.assertRaises(RuntimeError,
                          rollingrestart.rolling_restart, restart_hook)
        restart_hook.assert_called_once_with()
        peer_echo.assert_called_once_with()  # peer_echo helper called.

        # The restart request has not been cancelled, and will be
        # attempted again next time rolling_restart() is called.
        self.assertFalse(cancel_restart.called)

    @patch('charmhelpers.core.hookenv.local_unit', autospec=True)
    def test_peerstorage_key(self, local_unit):
        local_unit.return_value = 'me/42'
        self.assertEqual(rollingrestart._peerstorage_key(),
                         'rollingrestart_me/42')

    @patch('charmhelpers.core.hookenv.remote_unit', autospec=True)
    @patch('charmhelpers.contrib.peerstorage.peer_echo', autospec=True)
    def test_peer_echo_changed(self, peer_echo, remote_unit):
        remote_unit.return_value = 'service/62'

        # _peer_echo() calls peerstorage.peer_echo() if we are in the
        # peer relation-changed hook.
        relname = rollingrestart.get_peer_relation_name()
        hookenv.hook_name.return_value = '{}-relation-changed'.format(relname)

        rollingrestart._peer_echo()
        peer_echo.assert_called_once_with(['rollingrestart_service/62'])

    @patch('charmhelpers.core.hookenv.remote_unit')
    @patch('charmhelpers.core.hookenv.hook_name')
    @patch('charmhelpers.contrib.peerstorage.peer_store')
    def test_peer_echo_departed(self, peer_store, hook_name, remote_unit):
        # When _peer_echo is called from a peer relation-departed hook,
        # it cleans out any entry for the departing unit from peer
        # storage. Note that all surviving peers will clear up any
        # atavism in the queue, which is not optimal but better than
        # none of the surviving peers doing the cleanup.
        relname = rollingrestart.get_peer_relation_name()
        hook_name.return_value = '{}-relation-departed'.format(relname)
        remote_unit.return_value = 'unit/99'
        rollingrestart._peer_echo()
        peer_store.assert_called_once_with('rollingrestart_unit/99',
                                           None, relname)

    @patch('charmhelpers.core.hookenv.hook_name')
    @patch('charmhelpers.contrib.peerstorage.peer_store')
    @patch('charmhelpers.contrib.peerstorage.peer_echo')
    def test_peer_echo_misc_hook(self, peer_echo, peer_store, hook_name):
        # _peer_echo() does nothing unless it is called for a
        # peer relation-changed or relation-departed hook.
        hook_name.return_value = 'config-changed'
        rollingrestart._peer_echo()
        self.assertFalse(peer_store.called)
        self.assertFalse(peer_echo.called)

    @patch('charmhelpers.core.hookenv.metadata')
    def test_peer_relation_name(self, metadata):
        metadata.return_value = dict(peers=dict(peer1=dict(interface='int1'),
                                                peer2=dict(interface='int2')))
        # First peer relation in alphabetical order.
        peer_relname = rollingrestart.get_peer_relation_name()
        self.assertEqual(peer_relname, 'peer1')

    @patch('rollingrestart.get_peer_relation_name', autospec=True)
    def test_get_peers(self, get_peer_relation_name):
        get_peer_relation_name.return_value = 'cluster'
        self.assertSetEqual(rollingrestart.get_peers(),
                            set(['service/2', 'service/3']))

        # If the peer relation has yet to be joined, returns get_peers
        # returns an empty list.
        hookenv.relation_ids.side_effect = None
        hookenv.relation_ids.return_value = []
        self.assertListEqual(rollingrestart.get_peers(), [])

    def test_utcnow(self):
        # helpers.utcnow simply wraps datetime.datetime.utcnow().
        # We use it because, unlike datetime.utcnow(), it can be
        # mocked in tests making them stable.
        self.assertEqual(rollingrestart.utcnow(),
                         datetime(2010, 12, 25, 13, 45, 1))

        # Our mock always gives predictable values.
        self.assertEqual(rollingrestart.utcnow(),
                         datetime(2010, 12, 25, 13, 45, 2))

        # Mocked values always increase. Never the same, and never
        # backwards.
        self.assertLess(rollingrestart.utcnow(),
                        rollingrestart.utcnow())

    def test_utcnow_str(self):
        # utcnow() as a readable and sortable string.
        self.assertEqual(rollingrestart.utcnow_str(),
                         '2010-12-25 13:45:01.000000Z')
        # Our mock returns increasing values.
        self.assertLess(rollingrestart.utcnow_str(),
                        rollingrestart.utcnow_str())

    # @patch('charmhelpers.contrib.peerstorage.peer_store', autospec=True)
    # @patch('charmhelpers.contrib.peerstorage.peer_retrieve', autospec=True)
    # def test_rolling_restart_stuck_in_queue(self, peer_retrieve, peer_store):
    #     restart = MagicMock()

    #     # If the unit is already in the restart queue, and there are
    #     # other units before it, it must wait.
    #     first, second = rollingrestart.utcnow(), rollingrestart.utcnow()
    #     peer_retrieve.return_value = dict(foo='ignored',
    #                                       restart_needed_service_1=second,
    #                                       restart_needed_service_2=first)
    #     self.assertFalse(rollingrestart.rolling_restart(restart))

    #     # Restart did not happen. We are stuck in the queue.
    #     self.assertFalse(restart.called)

    #     # The queue was looked up, returning nothing.
    #     peer_retrieve.assert_called_once_with('-', 'cluster')

    #     # No change was made to the queue, since we are already in it.
    #     self.assertFalse(peer_store.called)

    # @patch('charmhelpers.contrib.peerstorage.peer_store', autospec=True)
    # @patch('charmhelpers.contrib.peerstorage.peer_retrieve', autospec=True)
    # def test_rolling_restart_next_in_queue(self, peer_retrieve, peer_store):
    #     restart = MagicMock()
    #     first, second = rollingrestart.utcnow(), rollingrestart.utcnow()
    #     peer_retrieve.return_value = dict(restart_needed_service_1=first,
    #                                       restart_needed_service_2=second)
    #     self.assertTrue(rollingrestart.rolling_restart(restart))
    #     self.assertTrue(restart.called)
    #     peer_retrieve.assert_called_once_with('-', 'cluster')
    #     peer_store.assert_called_once_with('restart_needed_service_1',
    #                                        None, 'cluster')


class TestUtc(unittest.TestCase):
    def test_utcnow(self):
        # Prove as best we can helpers.utcnow() wraps datetime.utcnow()
        first_real = datetime.utcnow()
        second_wrapped = rollingrestart.utcnow()
        self.assertLessEqual(first_real, second_wrapped)
        self.assertIsInstance(second_wrapped, datetime)


if __name__ == '__main__':
    unittest.main(verbosity=2)
