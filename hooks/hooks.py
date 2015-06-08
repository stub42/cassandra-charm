#!/usr/bin/python3

from charmhelpers import fetch
from charmhelpers.core import hookenv


def bootstrap():
    try:
        import bcrypt     # NOQA: flake8
        import cassandra  # NOQA: flake8
    except ImportError:
        packages = ['python3-bcrypt', 'python3-cassandra']
        fetch.add_source('ppa:stub/cassandra')
        fetch.apt_update(fatal=True)
        fetch.apt_install(packages, fatal=True)
        import bcrypt     # NOQA: flake8
        import cassandra  # NOQA: flake8


def default_hook():
    # These need to be imported after bootstrap() or required Python
    # packages may not have been installed.
    import definitions
    from loglog import loglog

    # Only useful for debugging, or perhaps have this enabled with a config
    # option?
    loglog('/var/log/cassandra/system.log', prefix='C*: ')

    hookenv.log('*** {} Hook Start'.format(hookenv.hook_name()))
    sm = definitions.get_service_manager()
    sm.manage()
    hookenv.log('*** {} Hook Done'.format(hookenv.hook_name()))
