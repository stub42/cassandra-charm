all: runtests check
build: runtests

runtests:
	$(MAKE) -C tests test

clean:
	$(MAKE) -C tests clean

lint:
	@flake8 ./hooks/*.py

sync:
	@bzr cat \
            lp:charm-helpers/tools/charm_helpers_sync/charm_helpers_sync.py \
                > .charm_helpers_sync.py
	@python .charm_helpers_sync.py -c charm-helpers.yaml
	@rm .charm_helpers_sync.py
