all: runtests check
build: runtests

runtests:
	$(MAKE) -C tests test

clean:
	$(MAKE) -C tests clean

check:
	@pyflakes ./hooks/*.py
	@pep8 ./hooks/*.py
