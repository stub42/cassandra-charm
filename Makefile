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

deps: packages venv3

lint: deps
	charm proof $(CHARM_DIR)
	flake8 --exclude=charmhelpers,.venv2,.venv3 hooks tests testing

unittest: lint
	nosetests -v \
	    tests.test_actions --cover-package=actions \
	    tests.test_helpers --cover-package=helpers \
	    --with-coverage --cover-branches --cover-min-percentage=100 

test: unittest
	nosetests -v tests.test_integration
	
ftest: unittest
	nosetests -v tests.test_integration:Test1UnitDeployment

coverage: lint
	-nosetests -v \
	    tests.test_actions --cover-package=actions \
	    tests.test_helpers --cover-package=helpers \
	    --with-coverage --cover-branches \
	    --cover-html --cover-html-dir=coverage
	gnome-open coverage/index.html

clean:
	rm -rf .venv? tests/.venv? .stamp-* coverage
	find . -name __pycache__ -type d | xargs rm -rf

packages: .stamp-packages
.stamp-packages:
	# Install bootstrap debs, and Python packages not available
	# via pip.
	sudo apt-get install -y \
	    python3 python3-pip python3-apt python-virtualenv charm-tools
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
	pip install -q amulet
	pip install -q flake8
	pip install -qI nose
	pip install -q coverage
	pip install -q cassandra-driver

	# Create a link for test shebang lines.
	(cd tests && ln -s ${VENV3} .venv3)

	touch .stamp-venv3

venv2: packages .stamp-venv2
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
