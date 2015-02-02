#!/usr/bin/make -f

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

default:
	@echo Missing target
	@echo 'Usage: make [ lint | unittest | test | clean | sync ]'
	env

# Calculate the CHARM_DIR (the directory this Makefile is in)
THIS_MAKEFILE_PATH:=$(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST))
CHARM_DIR:=$(shell cd $(dir $(THIS_MAKEFILE_PATH));pwd)
VENV3:=$(CHARM_DIR)/.venv3

# Set the PATH so the correct tools are found.
export PATH:=$(VENV3)/bin:$(PATH)

SITE_PACKAGES=$(wildcard $(VENV3)/lib/python*/site-packages)

deps: packages venv3

lint: deps
	charm proof $(CHARM_DIR)
	flake8 --exclude=charmhelpers,.venv2,.venv3 hooks tests testing

unittest: lint
	nosetests -sv \
	    tests.test_actions        --cover-package=actions \
	    tests.test_helpers        --cover-package=helpers \
	    tests.test_rollingrestart --cover-package=rollingrestart \
	    tests.test_definitions    --cover-package=definitions \
	    --cover-package=policies \
	    --with-coverage --cover-branches

test: unittest
	AMULET_TIMEOUT=3600 \
	nosetests -sv tests.test_integration
	
ftest: unittest
	nosetests -sv tests.test_integration:Test1UnitDeployment

3test: unittest
	nosetests -sv tests.test_integration:Test3UnitDeployment

# Set the DSE_SOURCE environment variable for this to work:
# DSE_SOURCE="deb http://un:pw@debian.datastax.com/enterprise stable main"
# You will also need a cache like squid-deb-proxy and have tweaked it to
# cache the authenticated files, or the tests will likely timeout waiting
# for huge downloads to complete. Alternatively, mirror the DataStax
# packages into your own private archive. Due to the authentication
# requirement, this test will not be run by the automatic test runners
# and we can accordingly expect DSE support in this charm to break on
# occasions.
dsetest: unittest
	AMULET_TIMEOUT=3600 \
	nosetests -sv tests.test_integration:TestDSEDeployment

coverage: lint
	nosetests -sv \
	    tests.test_actions        --cover-package=actions \
	    tests.test_helpers        --cover-package=helpers \
	    tests.test_rollingrestart --cover-package=rollingrestart \
	    tests.test_definitions    --cover-package=definitions \
	    --cover-package=policies \
	    --with-coverage --cover-branches \
	    --cover-html --cover-html-dir=coverage \
	    --cover-min-percentage=100 || \
		(gnome-open coverage/index.html; false)

clean:
	rm -rf .venv? tests/.venv? .stamp-* coverage .coverage
	find . -name __pycache__ -type d | xargs rm -rf

packages: .stamp-packages
.stamp-packages:
	# Install bootstrap debs, and Python packages not available
	# via pip.
	sudo apt-get install -y \
	    python3 python3-pip python3-apt python3-dev python-virtualenv \
	    charm-tools build-essential libev4 libev-dev libffi-dev \
	    netcat
	touch .stamp-packages

venv3: packages .stamp-venv3
.stamp-venv3:
	# Build a Python virtualenv to run our tests.
	virtualenv -p python3 --system-site-packages ${VENV3}
	
	# Create a .pth so our tests can locate everything without
	# sys.path hacks.
	(echo ${CHARM_DIR}/hooks; echo ${CHARM_DIR}) \
	    > ${VENV3}/lib/python3.4/site-packages/tests.pth

	# Pip install packages.
	pip install -q amulet flake8 bcrypt cassandra-driver blist
	pip install -qI nose
	pip install -q --upgrade coverage

	# Create a link for test shebang lines.
	(cd tests && ln -s ${VENV3} .venv3)

	touch .stamp-venv3

venv2: packages .stamp-venv2
.stamp-venv2:
	virtualenv -p python2.7 --system-site-packages .venv2
	.venv2/bin/pip install -q bundletester
	touch .stamp-venv2
 
bundletest: venv2
	.venv2/bin/bundletester

sync:
	@bzr cat \
            lp:charm-helpers/tools/charm_helpers_sync/charm_helpers_sync.py \
                > .charm_helpers_sync.py
	@python .charm_helpers_sync.py -c charm-helpers.yaml
	#@python .charm_helpers_sync.py \
	#	-c lib/testcharms/testclient/charm-helpers.yaml
	@rm .charm_helpers_sync.py
