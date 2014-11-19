default:
	@echo Missing target

lint:
	@flake8 hooks/*.py tests/*.py

deps: packages venv

packages: .stamp-packages
.stamp-packages:
	tests/00-setup-packages
	touch .stamp-packages

venv: .stamp-venv
.stamp-venv:
	tests/01-setup-venv
	touch .stamp-venv

test: deps lint
	tests/10-test.py

clean:
	rm -rf .venv tests/.venv .stamp-*

sync:
	@bzr cat \
            lp:charm-helpers/tools/charm_helpers_sync/charm_helpers_sync.py \
                > .charm_helpers_sync.py
	@python .charm_helpers_sync.py -c charm-helpers.yaml
	@rm .charm_helpers_sync.py
