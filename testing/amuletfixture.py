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

import os
import shutil
import subprocess
import tempfile
import time

import amulet
import yaml


class AmuletFixture(amulet.Deployment):
    def setUp(self):
        self._temp_dirs = []

        self.reset_environment()

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

        # Explicitly reset $JUJU_REPOSITORY to ensure amulet and
        # juju-deployer does not mess with the real one, per Bug #1393792
        self.org_repo = os.environ.get('JUJU_REPOSITORY', None)
        temp_repo = tempfile.TemporaryDirectory(suffix='.repo')
        self._temp_dirs.append(temp_repo)
        os.environ['JUJU_REPOSITORY'] = temp_repo.name
        os.makedirs(os.path.join(temp_repo.name, self.series), mode=0o700)

    def tearDown(self, reset_environment=True):
        if reset_environment:
            self.reset_environment()
        if self.org_repo is None:
            del os.environ['JUJU_REPOSITORY']
        else:
            os.environ['JUJU_REPOSITORY'] = self.org_repo

    def deploy(self, timeout=None):
        '''Deploying or updating the configured system.

        Invokes amulet.Deployer.setup with a nicer name and standard
        timeout handling.
        '''
        if timeout is None:
            timeout = int(os.environ.get('AMULET_TIMEOUT', 900))

        until = time.time() + timeout

        # If setUp fails, tearDown is never called leaving the
        # environment setup. This is useful for debugging.
        self.setup(timeout=timeout)

        # Work around Bug #1421195 by retrying failed waits.
        # self.sentry.wait(timeout=timeout)
        while True:
            timeout = int(min(max(until - time.time(), 0), 300))
            try:
                self.sentry.wait(timeout=timeout)
                break
            except (OSError, amulet.helpers.TimeoutError):
                if time.time() > until:
                    raise

    def __del__(self):
        for temp_dir in self._temp_dirs:
            if os.path.exists(temp_dir.name):
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
                        ignore=shutil.ignore_patterns('.venv?', '.bzr'))
