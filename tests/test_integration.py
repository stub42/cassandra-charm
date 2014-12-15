#!.venv3/bin/python3

import os
import subprocess
import time
import unittest
import warnings

warnings.filterwarnings('ignore', 'The blist library is not available')

from cassandra import ConsistencyLevel
from cassandra.cluster import Cluster
from cassandra.query import SimpleStatement
import yaml

from testing.amuletfixture import AmuletFixture


SERIES = os.environ.get('SERIES', 'trusty')


class TestDeploymentBase(unittest.TestCase):
    rf = 1
    deployment = None

    config = dict(max_heap_size='128M',
                  heap_newsize='32M')

    @classmethod
    def setUpClass(cls):
        deployment = AmuletFixture(series=SERIES)
        deployment.setUp()
        cls.deployment = deployment

        deployment.add('cassandra', units=cls.rf)
        deployment.configure('cassandra', cls.config)

        # No official trusty branch of the storage charm, yet.
        deployment.add('storage', 'lp:~stub/charms/trusty/storage/trunk')
        deployment.configure('storage', dict(provider='local'))
        deployment.deploy()

    @classmethod
    def tearDownClass(cls):
        cls.deployment.tearDown()
        cls.deployment = None

    def setUp(self):
        session = self.cluster().connect()
        try:
            session.execute('DROP KEYSPACE test')
        except Exception:
            pass
        # It might take a while for the DROP KEYSPACE to propagate,
        # so retry the CREATE KEYSPACE for a while.
        timeout = time.time() + 120
        while True:
            try:
                # We create a keyspace with a replication factor equal
                # to the number of units. This ensures that all records
                # are replicated to all nodes, and we can cofirm that
                # all nodes are working by doing an insert with
                # ConsistencyLevel.ALL.
                session.execute('''
                                CREATE KEYSPACE test WITH REPLICATION = {
                                    'class': 'SimpleStrategy',
                                    'replication_factor': %s}
                                ''', (self.rf,))
                break
            except Exception:
                if time.time() > timeout:
                    raise
                time.sleep(1)

        while True:
            try:
                self.session()  # Ensure the CREATE KEYSPACE has replicated.
                break
            except Exception:
                if time.time() > timeout:
                    raise
                time.sleep(1)

    def juju_status(self):
        status_yaml = subprocess.check_output(['juju', 'status',
                                               '--format=yaml'])
        if not status_yaml.strip():
            return None
        return yaml.safe_load(status_yaml)

    def cluster(self):
        status = self.juju_status()
        ips = []
        for unit, detail in status['services']['cassandra']['units'].items():
            ips.append(detail['public-address'])
        cluster = Cluster(ips)
        self.addCleanup(cluster.shutdown)
        return cluster

    def session(self):
        session = self.cluster().connect('test')
        self.addCleanup(session.shutdown)
        return session


class Test3UnitDeployment(TestDeploymentBase):
    """Tests run on both a 3 node cluster and a single node cluster."""
    rf = 3
    config = dict(max_heap_size='128M',
                  heap_newsize='32M',
                  jvm='openjdk')

    def test_database_basics(self):
        session = self.session()
        session.execute('CREATE TABLE Foo (x varchar PRIMARY KEY)')

        # Insert some data, ensuring that it has been stored on
        # all of our juju units. Note that the replication factor
        # of our keyspace has been set to the number of units we
        # deployed. Because it might take a while for the cluster to get
        # its act together, we retry this in a loop with a timeout.
        timeout = time.time() + 120
        while True:
            value = 'hello {}'.format(time.time())
            query = SimpleStatement(
                "INSERT INTO Foo (x) VALUES (%s)",
                consistency_level=ConsistencyLevel.ALL)
            try:
                session.execute(query, (value,))
                break
            except Exception:
                if time.time() > timeout:
                    raise

        # We can get the data out again. This isn't testing our charm,
        # but nice to know anyway...
        r = session.execute('SELECT * FROM Foo LIMIT 1')
        self.assertTrue(r[0].x.startswith('hello'))

    def test_external_mount(self):
        # Not only does this test migrating data from local disk to an
        # external mount, it also exercises the rolling restart logic.
        # If rf==1, the restart will happen in the
        # storage-relation-changed hook as soon as the mount is ready.
        # If rf > 1, the restart will happen in the
        # cluster-relation-changed hook once the unit has determined
        # that it is its turn to restart.
        self.deployment.relate('cassandra:data', 'storage:data')
        self.deployment.sentry.wait()
        # Per Bug #1254766 and Bug #1254766, the sentry.wait() above
        # will return before the hooks have actually finished running
        # and data migrated. Instead, keep checking until our condition
        # is met, or a timeout reached.
        timeout = time.time() + 300
        for unit_num in range(0, self.rf):
            unit = 'cassandra/{}'.format(unit_num)
            with self.subTest(unit=unit):
                while True:
                    s = self.deployment.sentry['cassandra/0']
                    try:
                        contents = s.directory_contents(
                            '/srv/cassandra_0/cassandra/data')
                        self.assertSetEqual(set(contents['directories']),
                                            set(['system_traces', 'test',
                                                 'system']))
                        break
                    except Exception:
                        if time.time() > timeout:
                            raise
                        time.sleep(5)


class Test1UnitDeployment(Test3UnitDeployment):
    """Tests run on a single node cluster."""
    rf = 1
    config = dict(max_heap_size='128M',
                  heap_newsize='32M',
                  jvm='openjdk')


class TestOracleJVMDeployment(Test3UnitDeployment):
    """Basic test with the Oracle JVM.

    This test is slow, as downloads of the Oracle JVM have been made
    deliberately uncachable.
    """
    rf = 1
    config = dict(max_heap_size='128M',
                  heap_newsize='32M',
                  edition='community',
                  jvm='Oracle')


class TestDSEDeployment(Test3UnitDeployment):
    """Tests run on a single node DataStax Enterprise cluster.

    These are *very slow* tests, due to the DSE and Oracle JVM
    downloads. In addition, the DSE_SOURCE environment variable
    needs to be set as DataStax do not allow unauthenticated
    downloads of their software.

    Due to the authentication requirement, these tests will not be run
    by the automatic test runners and we can accordingly expect DSE
    support in this charm to break on occasions.
    """
    rf = 1
    config = dict(max_heap_size='128M',
                  heap_newsize='32M',
                  edition='DSE',  # Forces Oracle JVM
                  install_sources=yaml.safe_dump([os.environ.get('DSE_SOURCE'),
                                                 'ppa:webupd8team/java']),
                  install_keys=yaml.safe_dump([None, None]))

    @classmethod
    @unittest.skipIf('DSE_SOURCE' not in os.environ,
                     'DSE_SOURCE environment variable not configured')
    def setUpClass(cls):
        super(TestDSEDeployment, cls).setUpClass()


if __name__ == '__main__':
    unittest.main(verbosity=2)
