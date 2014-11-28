default:
	@echo Missing target
	@echo 'Usage: make [ deps | lint | test | clean | sync ]'

deps: clean packages venv3

packages: .stamp-packages
.stamp-packages:
	tests/00-setup-packages.sh
	touch .stamp-packages

venv3: packages .stamp-venv3
.stamp-venv3:
	tests/01-setup-venv.sh
	touch .stamp-venv3

lint: venv3
	tests/10-lint.sh

unittest: lint
	tests/20-unit-tests.sh --cover-min-percentage=100

ftest: lint
	tests/20-unit-tests.sh
	.venv3/bin/nosetests -v tests/test_integration.py:Test1UnitDeployment

test: lint
	tests/20-unit-tests.sh
	tests/30-integration-tests.sh

clean:
	rm -rf .venv? tests/.venv? .stamp-*
	find . -name __pycache__ -type d | xargs rm -rf

venv2: .stamp-venv2
.stamp-venv2:
	virtualenv -p python2.7 --system-site-packages .venv2
	.venv2/bin/pip install -q bundletester \
	    --allow-external lazr.authentication \
	    --allow-unverified lazr.authentication
	touch .stamp-venv2

bundletest: venv2
	.venv2/bin/bundletester --skip-implicit

sync:
	@bzr cat \
            lp:charm-helpers/tools/charm_helpers_sync/charm_helpers_sync.py \
                > .charm_helpers_sync.py
	@python .charm_helpers_sync.py -c charm-helpers.yaml
	@rm .charm_helpers_sync.py
