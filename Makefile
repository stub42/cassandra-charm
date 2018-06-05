#!/usr/bin/make -f

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

BUILDDEST ?= ${JUJU_REPOSITORY}
BUILDDEST ?= ./build

SHELL := /bin/bash
export SHELLOPTS:=errexit:pipefail


charmbuild:
	charm build --no-local-layers -w wheelhouse_overrides.txt -o ${BUILDDEST}

testdeps:
	sudo apt install tox
	sudo snap install juju-wait

test: unittest

unittest:
	tox


# ftest: unittest Test1UnitDeployment
# Test1UnitDeployment: deps
# 	date
# 	AMULET_TIMEOUT=5400 \
# 	$(NOSETESTS) tests.test_integration:Test1UnitDeployment 2>&1 | ts
# 	
# 20test: unittest Test20Deployment
# Test20Deployment: deps
# 	date
# 	AMULET_TIMEOUT=5400 \
# 	$(NOSETESTS) tests.test_integration:Test20Deployment 2>&1 | ts
# 
# 21test: unittest Test21Deployment
# Test21Deployment: deps
# 	date
# 	AMULET_TIMEOUT=5400 \
# 	$(NOSETESTS) tests.test_integration:Test21Deployment 2>&1 | ts
# 
# 22test: unittest Test22Deployment
# Test22Deployment: deps
# 	date
# 	AMULET_TIMEOUT=5400 \
# 	$(NOSETESTS) tests.test_integration:Test22Deployment 2>&1 | ts
# 			
# 3test: unittest Test3UnitDeployment
# Test3UnitDeployment: deps
# 	date
# 	AMULET_TIMEOUT=7200 \
# 	$(NOSETESTS) tests.test_integration:Test3UnitDeployment 2>&1 | ts
# 
# authtest: unittest TestAllowAllAuthenticatorDeployment
# TestAllowAllAuthenticatorDeployment: deps
# 	date
# 	AMULET_TIMEOUT=7200 \
# 	$(NOSETESTS) \
# 	tests.test_integration:TestAllowAllAuthenticatorDeployment 2>&1 | ts
# 
# # Place a copy of the Oracle Java SE 8 Server Runtime tarball in ./lib
# # to run these tests.
# jretest: unittest
# 	AMULET_TIMEOUT=5400 \
# 	$(NOSETESTS) tests.test_integration:TestOracleJREDeployment 2>&1 | ts
# 
# # You need the Oracle JRE (per jretest) and set the DSE_SOURCE environment
# # variable for this to work:
# #     DSE_SOURCE="deb http://un:pw@debian.datastax.com/enterprise stable main"
# # You will also need a cache like squid-deb-proxy and have tweaked it to
# # cache the authenticated files, or the tests will likely timeout waiting
# # for huge downloads to complete. Alternatively, mirror the DataStax
# # packages into your own private archive.
# dsetest: unittest
# 	AMULET_TIMEOUT=5400 \
# 	$(NOSETESTS) tests.test_integration:TestDSEDeployment 2>&1 | ts
# 
# coverage: lint
# 	$(NOSETESTS) \
# 	    tests.test_actions        --cover-package=actions \
# 	    tests.test_helpers        --cover-package=helpers \
# 	    tests.test_definitions    --cover-package=definitions \
# 	    --with-coverage --cover-branches \
# 	    --cover-html --cover-html-dir=coverage \
# 	    --cover-min-percentage=100 || \
# 		(gnome-open coverage/index.html; false)
# 
# clean:
# 	rm -rf .venv? tests/.venv? .stamp-* coverage .coverage
# 	find . -name __pycache__ -type d | xargs rm -rf
# 	find . -name \*~ -type f | xargs rm -f
# 
# 
# 
# venv3: .stamp-venv3
# .stamp-venv3:
# 	# Build a Python virtualenv to run our tests.
# 	virtualenv -p python3 --system-site-packages ${VENV3}
# 	
# 	# Create a .pth so our tests can locate everything without
# 	# sys.path hacks.
# 	(echo ${CHARM_DIR}/hooks; echo ${CHARM_DIR}) \
# 	    > ${VENV3}/lib/python${PYVER}/site-packages/tests.pth
# 
# 	echo 'pip: ' `which pip`
# 
# 	# Pip install packages needed by the test suite but not used
# 	# by the charm.
# 	# $(PIP) install bcrypt cassandra-driver blist
# 	# $(PIP) install --upgrade -I nose flake8
# 	# $(PIP) install --upgrade \
# 	#     coverage amulet mock juju-deployer juju-wait netifaces
# 
# 	echo 'nosetests:' `which nosetests`
# 	echo 'flake8:' `which flake8`
# 
# 	# Create a link for test shebang lines.
# 	(cd tests && ln -s ${VENV3} .venv3)
# 
# 	touch .stamp-venv3
# 
# venv2: packages .stamp-venv2
# .stamp-venv2:
# 	virtualenv -p python2.7 --system-site-packages .venv2
# 	.venv2/bin/pip install -q bundletester
# 	touch .stamp-venv2
#  
# bundletest: venv2
# 	.venv2/bin/bundletester
# 
# publish-devel:
# 	@if [ -n "`git status --porcelain`" ]; then \
# 	    echo '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'; \
# 	    echo '!!! There are uncommitted changes !!!'; \
# 	    echo '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'; \
# 	    false; \
# 	fi
# 	git clean -fdx
# 	export rev=`charm push . $(CHARM_STORE_URL) 2>&1 \
#                 | tee /dev/tty | grep url: | cut -f 2 -d ' '` \
# 	&& git tag -f -m "$$rev" `echo $$rev | tr -s '~:/' -` \
# 	&& git push --tags $(REPO) \
# 	&& charm release -c development $$rev
# 
# 
# publish-stable:
# 	@if [ -n "`git status --porcelain`" ]; then \
# 	    echo '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'; \
# 	    echo '!!! There are uncommitted changes !!!'; \
# 	    echo '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'; \
# 	    false; \
# 	fi
# 	git clean -fdx
# 	export rev=`charm push . $(CHARM_STORE_URL) 2>&1 \
#                 | tee /dev/tty | grep url: | cut -f 2 -d ' '` \
# 	&& git tag -f -m "$$rev" `echo $$rev | tr -s '~:/' -` \
# 	&& git push --force --tags $(REPO) \
# 	&& charm release -c stable $$rev
