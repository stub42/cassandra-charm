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
'''
This file injects environment variables before hook bootstrap

Perhaps this functionality should be part of the base layer?

We set the CASS_DRIVER_NO_CYTHON environment variable so pip
installs of cassandra-driver do not attempt to compile the
very large driver.
'''
import os
from pkgutil import extend_path
import sys

__path__ = extend_path(__path__, __name__)

print('Injecting environment variables (in {})'.format(__file__), file=sys.stderr)
os.environ['CASS_DRIVER_NO_CYTHON'] = '1'
