import os
import shutil
import subprocess
import tempfile

import amulet
import yaml


class AmuletFixture(amulet.Deployment):
    def __init__(self, *args, **kw):
        super(AmuletFixture, self).__init__(*args, **kw)

        self._temp_dirs = []

        # Repackage our charm to a temporary directory, allowing us
        # to strip our virtualenv symlinks that would otherwise cause
        # juju to abort. We also strip the .bzr directory, working
        # around Bug #1394078.
        self.repackage_charm()

        # Fix amulet.Deployment so it doesn't depend on environment
        # variables or the current working directory, but rather the
        # environment we have introspected.
        with open(os.path.join(self.charm_dir, 'metadata.yaml'), 'r') as s:
            self.charm_name = yaml.safe_load(s)['name']
        self.charm_cache.test_charm = None
        self.charm_cache.fetch(self.charm_name, self.charm_dir, self.series)

        # Explicitly reset $JUJU_REPOSITORY to ensure amulet and juju-deployer
        # does not mess with the real one, per Bug #1393792
        self.org_repo = os.environ.get('JUJU_REPOSITORY', None)
        temp_repo = tempfile.TemporaryDirectory(suffix='.repo')
        self._temp_dirs.append(temp_repo)
        os.environ['JUJU_REPOSITORY'] = temp_repo.name
        os.makedirs(os.path.join(temp_repo.name, self.series), mode=0o700)

    def setUp(self, timeout=900):
        self.reset_environment()
        try:
            self.setup(timeout=timeout)
            self.sentry.wait()
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
        for temp_dir in self._temp_dirs:
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
        # Find the charm_dir we are testing
        src_charm_dir = os.path.dirname(__file__)
        while True:
            if os.path.exists(os.path.join(src_charm_dir,
                                           'metadata.yaml')):
                break
            assert src_charm_dir != os.sep, 'metadata.yaml not found'
            src_charm_dir = os.path.abspath(os.path.join(src_charm_dir,
                                                         os.pardir))

        with open(os.path.join(src_charm_dir, 'metadata.yaml'), 'r') as s:
            self.charm_name = yaml.safe_load(s)['name']

        repack_root = tempfile.TemporaryDirectory(suffix='.charm')
        self._temp_dirs.append(repack_root)

        self.charm_dir = os.path.join(repack_root.name, self.charm_name)

        # Ignore .bzr to work around weird bzr interactions with
        # juju-deployer, per Bug #1394078, and ignore .venv
        # due to a) it containing symlinks juju will reject and b) to avoid
        # infinite recursion.
        shutil.copytree(src_charm_dir, self.charm_dir, symlinks=True,
                        ignore=shutil.ignore_patterns('.venv', '.bzr'))
