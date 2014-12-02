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
    config = dict(max_heap_size='128M',
                  heap_newsize='32M',
                  jvm='Oracle')

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
    config = dict(max_heap_size='128M',
                  heap_newsize='32M',
                  jvm='openjdk')


class TestDSEDeployment(Test3UnitDeployment):
    """Tests run on a single node DataStax Enterprise cluster.
    """
    rf = 1
    jvm = 'Oracle'
    edition = 'DSE'
    config = dict(max_heap_size='128M',
                  heap_newsize='32M',
                  edition='DSE',
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
