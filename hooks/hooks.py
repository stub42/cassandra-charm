#!/usr/bin/python3

import subprocess

from charmhelpers import fetch
from charmhelpers.core import hookenv


def bootstrap():
    try:
        import bcrypt  # NOQA: flake8
    except ImportError:
        packages = ['python3-bcrypt',
                    # These packages are only required for the pip
                    # install of the Cassandra driver.
                    'python3-pip', 'build-essential', 'python3-dev',
                    'libev4', 'libev-dev']
        fetch.apt_install(packages, fatal=True)
        import bcrypt  # NOQA: flake8

    try:
        import cassandra  # NOQA: flake8
    except ImportError:
        # Alas, the Cassandra driver isn't packaged in Ubuntu so we need
        # to install it via pip.
        subprocess.check_call(['pip3', 'install',
                               'cassandra-driver', 'blist'])
        import cassandra  # NOQA: flake8


def default_hook():
    # These need to be imported after bootstrap() or required Python
    # packages may not have been installed.
    import definitions

    hookenv.log('*** {} Hook Start'.format(hookenv.hook_name()))
    sm = definitions.get_service_manager()
    sm.manage()
    hookenv.log('*** {} Hook Done'.format(hookenv.hook_name()))

if __name__ == '__main__':
    bootstrap()
    default_hook()
