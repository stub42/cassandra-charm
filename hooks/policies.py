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

import time

import cassandra.policies

from charmhelpers.core import hookenv
from charmhelpers.core.hookenv import DEBUG


class OptimisticConvictionPolicy(cassandra.policies.ConvictionPolicy):
    def add_failure(self, connection_exc):
        hookenv.log('Not convicting node', DEBUG)
        return False

    def reset(self):
        return


class ReconnectUntilReconnectionPolicy(cassandra.policies.ReconnectionPolicy):
    def __init__(self, until):
        self.until = until

    def new_schedule(self):
        return self

    def __next__(self):
        if time.time() > self.until:
            hookenv.log('Reconnect timeout', DEBUG)
            raise StopIteration
        hookenv.log('Reconnect triggered', DEBUG)
        time.sleep(1)
        return 2


class RetryUntilRetryPolicy(cassandra.policies.RetryPolicy):
    def __init__(self, until):
        self.until = until

    def on_read_timeout(self, query, consistency, *args, **kw):
        if time.time() > self.until:
            hookenv.log('Read timeout, abort', DEBUG)
            return (cassandra.policies.RetryPolicy.RETHROW, None)
        hookenv.log('Read timeout, retry', DEBUG)
        time.sleep(1)
        return (cassandra.policies.RetryPolicy.RETRY, consistency)

    def on_write_timeout(self, query, consistency, *args, **kw):
        if time.time() > self.until:
            hookenv.log('Write timeout, abort', DEBUG)
            return (cassandra.policies.RetryPolicy.RETHROW, None)
        hookenv.log('Write timeout, retry', DEBUG)
        time.sleep(1)
        return (cassandra.policies.RetryPolicy.RETRY, consistency)

    def on_unavailable(self, query, consistency, *args, **kw):
        if time.time() > self.until:
            hookenv.log('Unavailable, abort', DEBUG)
            return (cassandra.policies.RetryPolicy.RETHROW, None)
        hookenv.log('Unavailable, retry', DEBUG)
        time.sleep(1)
        return (cassandra.policies.RetryPolicy.RETRY, consistency)
