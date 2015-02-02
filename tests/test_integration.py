#!.venv3/bin/python3

import configparser
import os
import subprocess
import time
import unittest
import uuid
import warnings

warnings.filterwarnings('ignore', 'The blist library is not available')

from cassandra import ConsistencyLevel
from cassandra.auth import PlainTextAuthProvider
from cassandra.cluster import Cluster
from cassandra.query import SimpleStatement
import yaml

import helpers
from testing.amuletfixture import AmuletFixture


SERIES = os.environ.get('SERIES', 'trusty')


class TestDeploymentBase(unittest.TestCase):
    rf = 1
    deployment = None

    common_config = dict(max_heap_size='128M',
                         heap_newsize='32M',
                         open_client_ports=True,
                         post_bootstrap_delay=0)
    test_config = dict()

    @classmethod
    def setUpClass(cls):
        deployment = AmuletFixture(series=SERIES)
        deployment.setUp()
        cls.deployment = deployment

        deployment.add('cassandra', units=cls.rf)
        config = dict()
        config.update(cls.common_config)
        config.update(cls.test_config)  # Test subclass overrides
        deployment.configure('cassandra', config)

        # No official trusty branch of the storage charm, yet.
        deployment.add('storage', 'lp:~stub/charms/trusty/storage/trunk')
        deployment.configure('storage', dict(provider='local'))

        # A stub client charm.
        empty_path = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                  os.pardir, 'lib',
                                                  'testcharms', 'empty'))
        deployment.add('client', empty_path)
        deployment.relate('cassandra:database', 'client:database')
        deployment.relate('cassandra:database-admin', 'client:database-admin')

        deployment.deploy()

    @classmethod
    def tearDownClass(cls):
        cls.deployment.tearDown()
        cls.deployment = None

    def setUp(self):
        self.reconfigure_cassandra()  # Reset cassandra configuration.

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

        # Get some valid credentials - unit's superuser account will do.
        unit = list(status['services']['cassandra']['units'].keys())[0]
        cqlshrc_path = helpers.get_cqlshrc_path()
        cqlshrc = configparser.ConfigParser(interpolation=None)
        cqlshrc.read_string(
            self.deployment.sentry[unit].file_contents(cqlshrc_path))
        username = cqlshrc['authentication']['username']
        password = cqlshrc['authentication']['password']
        auth_provider = PlainTextAuthProvider(username=username,
                                              password=password)

        # Get the IP addresses
        ips = []
        for unit, detail in status['services']['cassandra']['units'].items():
            ips.append(detail['public-address'])
        cluster = Cluster(ips, auth_provider=auth_provider)
        self.addCleanup(cluster.shutdown)
        return cluster

    def session(self):
        session = self.cluster().connect('test')
        self.addCleanup(session.shutdown)
        return session

    def client_session(self, relname):
        '''A session using the client's credentials.

        We currently just steal the client's credentials and use
        them from the local machine, but we could tunnel through the
        client with a little more effort.
        '''
        relinfo = self.get_client_relinfo(relname)
        self.assertIn('host', relinfo.keys())
        ips = [relinfo['host']]
        port = int(relinfo['native_transport_port'])
        auth_provider = PlainTextAuthProvider(username=relinfo['username'],
                                              password=relinfo['password'])
        cluster = Cluster(ips, auth_provider=auth_provider, port=port)
        self.addCleanup(cluster.shutdown)
        session = cluster.connect('test')
        self.addCleanup(session.shutdown)
        return session

    def get_client_relinfo(self, relname):
        # We only need one unit, even if rf > 1
        s = self.deployment.sentry['cassandra/0']
        relinfo = s.relation(relname, 'client:{}'.format(relname))
        return relinfo

    def is_port_open(self, port):
        status = self.juju_status()
        detail = list(status['services']['cassandra']['units'].values())[0]
        address = detail['public-address']
        rc = subprocess.call(['nc', '-z', '-w', '2', address, str(port)])
        return rc == 0

    def reconfigure_cassandra(self, **overrides):
        config = dict()
        config.update(self.common_config)
        config.update(self.test_config)
        config.update(overrides)
        self.deployment.configure('cassandra', config)
        self.deployment.sentry.wait()


class Test1UnitDeployment(TestDeploymentBase):
    """Tests run on both a single node cluster and a 3 node cluster."""
    rf = 1
    test_config = dict(jvm='openjdk')

    def test_basics_unit_superuser(self):
        # Basic tests using unit superuser credentials
        session = self.session()
        self._test_database_basics(session)

    def test_basics_client_relation(self):
        # Basic tests using standard client relation credentials.
        session = self.client_session('database')
        self._test_database_basics(session)

    def test_basics_client_admin_relation(self):
        # Basic tests using administrative client relation credentials.
        session = self.client_session('database-admin')
        self._test_database_basics(session)

    def _test_database_basics(self, session):
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
                    s = self.deployment.sentry[unit]
                    try:
                        contents = s.directory_contents(
                            '/srv/cassandra_{}/cassandra/data'.format(
                                unit_num))
                        self.assertSetEqual(set(contents['directories']),
                                            set(['system_traces', 'test',
                                                 'system', 'system_auth']))
                        break
                    except Exception:
                        if time.time() > timeout:
                            raise
                        time.sleep(5)

    def test_ports_closed(self):
        # The internal Cassandra ports are always closed, except to
        # peers. Opening the JMX or replication ports to the Internet
        # would be a very bad idea - even if we added authentication,
        # it would still be a DOS target.
        self.assertFalse(self.is_port_open(7000), 'Storage port open')
        self.assertFalse(self.is_port_open(7001), 'SSL Storage port open')
        self.assertFalse(self.is_port_open(7199), 'JMX port open')

        self.reconfigure_cassandra(open_client_ports=False)
        self.assertFalse(self.is_port_open(9042), 'Native trans port open')
        self.assertFalse(self.is_port_open(9160), 'Thrift RPC port open')

    def test_ports_open(self):
        # By default, our tests have open_client_ports set to True
        # making the database accessible. Other tests rely on this.
        self.assertTrue(self.is_port_open(9042), 'Native trans port closed')
        self.assertTrue(self.is_port_open(9160), 'Thrift RPC port closed')


class Test3UnitDeployment(Test1UnitDeployment):
    """Tests run on a three node cluster."""
    rf = 3
    config = dict(max_heap_size='128M',
                  heap_newsize='32M',
                  open_client_ports=True,
                  jvm='openjdk',
                  post_bootstrap_delay=0)

    def test_add_and_drop_node(self):
        # We need to be able to add a node correctly into the ring,
        # without an operator needing to repair keyspaces to ensure data
        # is located on the expected nodes.
        # To test this, first create a keyspace with rf==1 and enough
        # data too it so each node should have some.
        s = self.session()
        s.execute('''
                  CREATE KEYSPACE addndrop WITH REPLICATION = {
                  'class': 'SimpleStrategy', 'replication_factor': 1}
                  ''')
        s.set_keyspace('addndrop')
        s.execute('CREATE TABLE dat (x varchar PRIMARY KEY)')

        def count():
            return s.execute('SELECT COUNT(*) FROM dat')[0][0]

        total = 300
        for _ in range(0, total):
            s.execute('INSERT INTO dat (x) VALUES (%s)', (str(uuid.uuid1()),))

        self.assertEqual(count(), total)

        self.deployment.add_unit()
        self.deployment.wait()
        self.assertEqual(count(), total)

        # When a node is dropped, it needs to decommission itself and
        # move its data to the remaining nodes so no data is lost.
        status = self.juju_status()
        unit = list(status['services']['cassandra']['units'].keys())[0]
        self.deployment.remove_unit(unit)
        self.deployment.wait()
        self.assertEqual(count(), total)


class TestOracleJVMDeployment(Test3UnitDeployment):
    """Basic test with the Oracle JVM.

    This test is slow, as downloads of the Oracle JVM have been made
    deliberately uncachable.
    """
    rf = 1
    test_config = dict(jvm='Oracle', edition='community')


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
    test_config = dict(
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
