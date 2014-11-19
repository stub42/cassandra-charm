#!.venv/bin/python3

from contextlib import contextmanager
import os.path
import shutil
import subprocess
import unittest
import warnings

warnings.filterwarnings('ignore', 'The blist library is not available')

import amulet
from cassandra import ConsistencyLevel
from cassandra.cluster import Cluster, InvalidRequest
from cassandra.query import SimpleStatement
import yaml


SERIES = 'trusty'


# Explicitly reset $JUJU_REPOSITORY to ensure amulet and juju-deployer
# don't mess with your real one, per Bug #1393792
os.environ['JUJU_REPOSITORY'] = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '.venv', 'repo'))
os.makedirs(os.path.join(os.environ['JUJU_REPOSITORY'], SERIES),
            mode=0o700, exist_ok=True)


def repackage_charm(charm_dir):
    """Mirror the charm into a staging area.

    We do this to work around issues with Amulet and juju-deployer,
    in particular:
        - symlinks in the Python virtual env pointing outside of the
          charm directory.
        - juju-deployer messing with the directory pointed to by your
          existing $JUJU_REPOSITORY
        - odd bzr interactions, such as tests being run on the committed
          version of the charm, rather than the working tree.

    Returns the test charm directory.
    """
    with open(os.path.join(charm_dir, 'metadata.yaml'), 'rb') as s:
        charm_name = yaml.safe_load(s)['name']

    repack_root = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                               '.venv', 'repack'))
    os.makedirs(repack_root, 0o700, exist_ok=True)

    repack_charm_dir = os.path.join(repack_root, charm_name)
    shutil.rmtree(repack_charm_dir, ignore_errors=True)

    # Ignore .bzr to work around weird bzr interactions with
    # juju-deployer, per Bug #1394078, and ignore .venv
    # due to it containing symlinks juju will reject and to avoid
    # infinite recursion.
    shutil.copytree(charm_dir, repack_charm_dir, symlinks=True,
                    ignore=shutil.ignore_patterns('.venv', '.bzr'))

    return repack_charm_dir


def reset_environment():
    subprocess.check_call(['juju-deployer', '-T'])


class Test1UnitDeployment(unittest.TestCase):
    rf = 1
    deployment = None

    @classmethod
    def setUpClass(cls):
        cassandra_charm = repackage_charm(
            os.path.join(os.path.dirname(__file__), os.pardir))
        reset_environment()

        cls.deployment = amulet.Deployment(series=SERIES)
        cls.deployment.add('cassandra', cassandra_charm, units=cls.rf)
        try:
            cls.deployment.setup(timeout=900)
            cls.deployment.sentry.wait()
        except amulet.helpers.TimeoutError:
            amulet.raise_status(amulet.SKIP,
                                msg="Environment wasn't stood up in time")

    @classmethod
    def tearDownClass(cls):
        reset_environment()
        cls.deployment = None

    def setUp(self):
        self.needs_reset = True

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
        cluster = self.cluster()
        if self.needs_reset:
            session = self.cluster().connect()
            try:
                session.execute('drop keyspace test')
            except Exception:
                pass
            session.execute('''
                            create keyspace test with replication = {
                                'class': 'SimpleStrategy',
                                'replication_factor': %s}
                            ''', (self.rf,))
            session.set_keyspace('test')
            self.needs_reset = False
        else:
            session = self.cluster().connect('test')
        self.addCleanup(session.shutdown)
        return session

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

# Now you can use self.deployment.sentry.unit[UNIT] to address each of
# the units and perform more in-depth steps.  You can also reference
# the first unit as self.unit.
# There are three test statuses that can be triggered with
# amulet.raise_status():
#   - amulet.PASS
#   - amulet.FAIL
#   - amulet.SKIP
# Each unit has the following methods:
#   - .info - An array of the information of that unit from Juju
#   - .file(PATH) - Get the details of a file on that unit
#   - .file_contents(PATH) - Get plain text output of PATH file from that unit
#   - .directory(PATH) - Get details of directory
#   - .directory_contents(PATH) - List files and folders in PATH on that unit
#   - .relation(relation, service:rel) - Get relation data from return service
#          add tests here to confirm service is up and working properly
# For example, to confirm that it has a functioning HTTP server:
#     page = requests.get('http://{}'.format(self.unit.info['public-address']))
#     page.raise_for_status()
# More information on writing Amulet tests can be found at:
#     https://juju.ubuntu.com/docs/tools-amulet.html


class Test3UnitDeployment(Test1UnitDeployment):
    rf = 3


if __name__ == '__main__':
    unittest.main(verbosity=2)
