# Copyright 2015-2018 Canonical Ltd.
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

from distutils.version import LooseVersion
import json
import os
import shutil
import subprocess
import tempfile
import time

import amulet
import amulet.helpers
import amulet.sentry
import yaml


class AmuletFixture(amulet.Deployment):
    def __init__(self, series, charm_dir):
        self.charm_dir = charm_dir
        # We use a wrapper around juju-deployer so we can adjust how it is
        # invoked. In particular, only make noise on failure.
        juju_deployer = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                     os.pardir, 'lib', 'juju-deployer-wrapper.py'))
        super(AmuletFixture, self).__init__(series=series, juju_deployer=juju_deployer)

    def setUp(self, keep=None):
        self._temp_dirs = []

        if keep:
            self.reset_environment(keep=keep)
        else:
            self.reset_environment(force=True)

        # Fix amulet.Deployment so it doesn't depend on environment
        # variables or the current working directory, but rather the
        # environment we have introspected.
        with open(os.path.join(self.charm_dir, 'metadata.yaml'), 'r') as s:
            self.charm_name = yaml.safe_load(s)['name']
        self.charm_cache.test_charm = None
        self.charm_cache.fetch(self.charm_name, self.charm_dir,
                               series=self.series)

        # Explicitly reset $JUJU_REPOSITORY to ensure amulet and
        # juju-deployer does not mess with the real one, per Bug #1393792
        self.org_repo = os.environ.get('JUJU_REPOSITORY', None)
        temp_repo = tempfile.mkdtemp(suffix='.repo')
        self._temp_dirs.append(temp_repo)
        os.environ['JUJU_REPOSITORY'] = temp_repo
        os.makedirs(os.path.join(temp_repo, self.series), mode=0o700)

    def tearDown(self, reset_environment=True, keep=None):
        if reset_environment:
            self.reset_environment(keep=keep)
        if self.org_repo is None:
            del os.environ['JUJU_REPOSITORY']
        else:
            os.environ['JUJU_REPOSITORY'] = self.org_repo

    def deploy(self, timeout=None, keep=None):
        '''Deploying or updating the configured system.

        Invokes amulet.Deployer.setup with a nicer name and standard
        timeout handling.
        '''
        # First, ensure any existing environment is completely
        # torn down. juju-deployer seems to forget to deploy
        # services if there is an existing service in the environment
        # in the process of being destroyed.
        self.reset_environment(keep=keep)
        if timeout is None:
            timeout = int(os.environ.get('AMULET_TIMEOUT', 900))

        # If setUp fails, tearDown is never called leaving the
        # environment setup. This is useful for debugging.
        self.setup(timeout=timeout)
        self.wait(timeout=timeout)

    def __del__(self):
        if self._temp_dirs:
            for temp_dir in self._temp_dirs:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)

    def add_unit(self, service, units=1, target=None, timeout=None):
        # Work around Bug #1510000
        if not isinstance(units, int) or units < 1:
            raise ValueError('Only positive integers can be used for units')
        if target is not None and units != 1:
            raise ValueError("Can't deploy more than one unit when specifying a target.")
        if service not in self.services:
            raise ValueError('Service needs to be added before you can scale')

        self.services[service]['num_units'] = self.services[service].get('num_units', 1) + units

        if self.deployed:
            args = ['add-unit', service, '-n', str(units)]
            if target is not None:
                args.extend(["--to", target])
            amulet.helpers.juju(args)
            if timeout is None:
                timeout = int(os.environ.get('AMULET_TIMEOUT', 900))
            self.sentry = amulet.sentry.Talisman(self.services, timeout=timeout)

    def get_status(self):
        try:
            raw = subprocess.check_output(['juju', 'status', '--format=json'], universal_newlines=True)
        except subprocess.CalledProcessError as x:
            print(x.output)
            raise
        if raw:
            status = json.loads(raw)
            # Quick hack for Juju 1->Juju 2 compatibility.
            if 'services' not in status:
                status['services'] = status['applications']
            return status
        return None

    def wait(self, timeout=None):
        '''Wait until the environment has reached a stable state.'''
        cmd = ['juju', 'wait', '-q']
        if timeout is None:
            timeout = int(os.environ.get('AMULET_TIMEOUT', 900))
        cmd = ['timeout', str(timeout)] + cmd
        try:
            subprocess.check_output(cmd, universal_newlines=True)
        except subprocess.CalledProcessError as x:
            print(x.output)
            raise

    def reset_environment(self, force=False, keep=None):
        keep = keep or frozenset()

        status = self.get_status()
        keep_machines = set()
        service_items = status.get('services', {}).items()
        for service_name, service in service_items:
            if service_name in keep:
                # Don't mess with this service.
                keep_machines.update([unit['machine'] for unit in service['units'].values()])
            elif service.get('life', '') not in ('dying', 'dead'):
                if self.has_juju_version('2.0'):
                    cmd = ['juju', 'remove-application', service_name]
                else:
                    cmd = ['juju', 'destroy-service', service_name]
                subprocess.call(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        machines = set(status.get('machines', {}).keys()) - keep_machines
        if machines:
            subprocess.call(['juju', 'remove-machine', '--force'] + list(machines),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        timeout = time.time() + 60
        while True:
            status = self.get_status()
            services = set(k for k in status.get('services', {}).keys() if k not in keep)
            if not services:
                break
            if time.time() > timeout:
                raise RuntimeError("Failed to remove services: {!r}".format(services))
            time.sleep(1)

    def juju_version(self):
        return subprocess.check_output(['juju', '--version'], universal_newlines=True).strip()

    def has_juju_version(self, minver):
        return LooseVersion(self.juju_version()) >= LooseVersion(minver)
