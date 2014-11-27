default:
	@echo Missing target
	@echo 'Usage: make [ deps | lint | test | clean | sync ]'

deps: clean packages venv

packages: .stamp-packages
.stamp-packages:
	tests/00-setup-packages
	touch .stamp-packages

venv: packages .stamp-venv
.stamp-venv:
	tests/01-setup-venv
	touch .stamp-venv

lint: venv
	tests/10-lint.sh

test: venv lint
	tests/20-unit-tests.py
	tests/30-integration-tests.py

ftest: venv lint
	tests/20-unit-tests.py
	tests/30-integration-tests.py Test1UnitDeployment

unittest: venv lint
	tests/20-unit-tests.py

clean:
	rm -rf .venv tests/.venv .stamp-*
	find . -name __pycache__ -type d | xargs rm -rf

sync:
	@bzr cat \
            lp:charm-helpers/tools/charm_helpers_sync/charm_helpers_sync.py \
                > .charm_helpers_sync.py
	@python .charm_helpers_sync.py -c charm-helpers.yaml
	@rm .charm_helpers_sync.py
