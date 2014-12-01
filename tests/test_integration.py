#!.venv3/bin/python3

import os
import subprocess
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
    jvm = 'openjdk'
    deployment = None

    @classmethod
    def setUpClass(cls):
        deployment = AmuletFixture(series=SERIES)
        deployment.add('cassandra', units=cls.rf)
        deployment.configure('cassandra', dict(max_heap_size='128M',
                                               heap_newsize='32M',
                                               jvm=cls.jvm))
        deployment.setUp()

        cls.deployment = deployment

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
        # We create a keyspace with a replication factor equal to the
        # number of units. This ensures that all records are replicated
        # to all nodes, and we can cofirm that all nodes are working by
        # doing an insert with ConsistencyLevel.ALL.
        session.execute('''
                        CREATE KEYSPACE test WITH REPLICATION = {
                            'class': 'SimpleStrategy',
                            'replication_factor': %s}
                        ''', (self.rf,))

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
    jvm = 'openjdk'

    def test_database_basics(self):
        session = self.session()
        session.execute('CREATE TABLE Foo (x varchar PRIMARY KEY)')

        # Insert some data, ensuring that it has been stored on
        # all of our juju units. Note that the replication factor
        # of our keyspace has been set to the number of units we
        # deployed.
        query = SimpleStatement(
            "INSERT INTO Foo (x) VALUES (%s)",
            consistency_level=ConsistencyLevel.ALL)
        session.execute(query, ('hello',))

        # We can get the data out again. This isn't testing our charm,
        # but nice to know anyway...
        r = session.execute('SELECT * FROM Foo LIMIT 1')
        self.assertEqual(r[0].x, 'hello')


class Test1UnitDeployment(Test3UnitDeployment):
    """Tests run on a single node cluster."""
    rf = 1
    jvm = 'oracle'  # At least one test needs to install the Oracle JVM.


if __name__ == '__main__':
    unittest.main(verbosity=2)
