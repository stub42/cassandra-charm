#!/usr/bin/make -f

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

lint: deps
	charm proof $(CHARM_DIR)
	flake8 --exclude=charmhelpers,.venv2,.venv3 hooks tests testing

unittest: deps lint
	nosetests -v \
	    tests.test_actions --cover-package=actions \
	    tests.test_helpers --cover-package=helpers \
	    --with-coverage --cover-min-percentage=100

test: deps unittest
	nosetests -v tests.test_integration
	
ftest: deps unittest
	nosetests -v tests.test_integration:Test1UnitDeployment

deps: .stamp-deps
.stamp-deps:
	# Install bootstrap debs, and Python packages not available
	# via pip.
	sudo apt-get install -y \
	    python3 python3-pip python3-apt python-virtualenv charm-tools

	# Build a Python virtualenv to run our tests.
	virtualenv -p python3 --system-site-packages ${CHARM_DIR}/.venv3
	
	# Create a .pth so our tests can locate everything without
	# sys.path hacks.
	(echo ${CHARM_DIR}/hooks; echo ${CHARM_DIR}) \
	    > ${VENV3}/lib/python3.4/site-packages/tests.pth

	# Pip install packages.
	pip install -q amulet
	pip install -q flake8
	pip install -qI nose
	pip install -q coverage
	pip install -q cassandra-driver

	touch .stamp-deps

clean:
	rm -rf .venv? tests/.venv? .stamp-*
	find . -name __pycache__ -type d | xargs rm -rf

venv2: deps .stamp-venv2
.stamp-venv2:
	virtualenv -p python2.7 --system-site-packages .venv2
	.venv2/bin/pip install -q bundletester \
 	    --allow-external lazr.authentication \
	    --allow-unverified lazr.authentication
	touch .stamp-venv2
 
bundletest: venv2
	.venv2/bin/bundletester

sync:
	@bzr cat \
            lp:charm-helpers/tools/charm_helpers_sync/charm_helpers_sync.py \
                > .charm_helpers_sync.py
	@python .charm_helpers_sync.py -c charm-helpers.yaml
	@rm .charm_helpers_sync.py
