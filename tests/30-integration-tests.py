#!.venv/bin/python3

import os.path
import shutil
import subprocess
import tempfile
import unittest
import warnings

warnings.filterwarnings('ignore', 'The blist library is not available')

import amulet
from cassandra import ConsistencyLevel
from cassandra.cluster import Cluster
from cassandra.query import SimpleStatement
import yaml


SERIES = 'trusty'
CHARM_DIR = os.path.join(os.path.dirname(__file__), os.pardir)


class AmuletFixture(object):
    def __init__(self, series, charm_dir):
        self.temp_dirs = []
        self.series = series
        self.src_charm_dir = charm_dir

        # Explicitly reset $JUJU_REPOSITORY to ensure amulet and juju-deployer
        # don't mess with your real one, per Bug #1393792
        self.org_repo = os.environ.get('JUJU_REPOSITORY', None)
        temp_repo = tempfile.TemporaryDirectory(suffix='.repo')
        self.temp_dirs.append(temp_repo)
        os.environ['JUJU_REPOSITORY'] = temp_repo.name
        os.makedirs(os.path.join(temp_repo.name, SERIES),
                    mode=0o700, exist_ok=False)

        # Repackage our charm to a temporary directory, allowing us
        # to strip our virtualenv symlinks that would otherwise cause
        # juju to abort. We also strip the .bzr directory, working
        # around Bug #1394078.
        self.repackage_charm()

        self.deployment = amulet.Deployment(series=self.series)

    def setUp(self, timeout=900):
        self.reset_environment()
        try:
            self.deployment.setup(timeout=timeout)
            self.deployment.sentry.wait()
        except amulet.helpers.TimeoutError:
            # Don't skip tests on timeout. This hides real failures,
            # such as deadlocks between peers.
            # raise unittest.SkipTest("Environment wasn't stood up in time")
            raise

    def tearDown(self, reset_environment=True):
        if reset_environment:
            self.reset_environment()
        if self.org_repo is None:
            del os.environ['JUJU_REPOSITORY']
        else:
            os.environ['JUJU_REPOSITORY'] = self.org_repo
        for temp_dir in self.temp_dirs:
            temp_dir.cleanup()

    def reset_environment(self):
        subprocess.check_call(['juju-deployer', '-T'])

    def repackage_charm(self):
        """Mirror the charm into a staging area.

        We do this to work around issues with Amulet, juju-deployer
        and juju. In particular:
            - symlinks in the Python virtual env pointing outside of the
            charm directory.
            - odd bzr interactions, such as tests being run on the committed
            version of the charm, rather than the working tree.

        Returns the test charm directory.
        """
        with open(os.path.join(self.src_charm_dir,
                               'metadata.yaml'), 'r') as s:
            self.charm_name = yaml.safe_load(s)['name']

        repack_root = tempfile.TemporaryDirectory(suffix='.charm')
        self.temp_dirs.append(repack_root)

        self.charm_dir = os.path.join(repack_root.name, self.charm_name)

        # Ignore .bzr to work around weird bzr interactions with
        # juju-deployer, per Bug #1394078, and ignore .venv
        # due to a) it containing symlinks juju will reject and b) to avoid
        # infinite recursion.
        shutil.copytree(self.src_charm_dir, self.charm_dir, symlinks=True,
                        ignore=shutil.ignore_patterns('.venv', '.bzr'))


class TestDeploymentBase(unittest.TestCase):
    rf = 1
    deployment = None

    @classmethod
    def setUpClass(cls):
        cls.amulet = AmuletFixture(charm_dir=CHARM_DIR, series=SERIES)
        cls.amulet.deployment.add('cassandra',
                                  cls.amulet.charm_dir, units=cls.rf)
        cls.amulet.setUp()

    @classmethod
    def tearDownClass(cls):
        cls.amulet.tearDown()
        cls.amulet = None

    def setUp(self):
        session = self.cluster().connect()
        try:
            session.execute('DROP KEYSPACE test')
        except Exception:
            pass
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
