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
        return 2


class RetryUntilRetryPolicy(cassandra.policies.RetryPolicy):
    def __init__(self, until):
        self.until = until

    def on_read_timeout(self, query, consistency, *args, **kw):
        if time.time() > self.until:
            hookenv.log('Read timeout, abort', DEBUG)
            return (cassandra.policies.RetryPolicy.RETHROW, None)
        hookenv.log('Read timeout, retry', DEBUG)
        return (cassandra.policies.RetryPolicy.RETRY, consistency)

    def on_write_timeout(self, query, consistency, *args, **kw):
        if time.time() > self.until:
            hookenv.log('Write timeout, abort', DEBUG)
            return (cassandra.policies.RetryPolicy.RETHROW, None)
        hookenv.log('Write timeout, retry', DEBUG)
        return (cassandra.policies.RetryPolicy.RETRY, consistency)

    def on_unavailable(self, query, consistency, *args, **kw):
        if time.time() > self.until:
            hookenv.log('Unavailable, abort', DEBUG)
            return (cassandra.policies.RetryPolicy.RETHROW, None)
        hookenv.log('Unavailable, retru', DEBUG)
        return (cassandra.policies.RetryPolicy.RETRY, consistency)
