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

import os

from charmhelpers.core import hookenv


def set_proxy():
    '''Set the http proxy for the charm to use from charm config.

    Installed using hookenv.atstart

    TODO: Ask field engineering if this feature is still needed.
    Either drop it, or create a layer so other charms can share
    behaviour.
    '''
    proxy = hookenv.config().get('http_proxy')
    if proxy:
        os.environ['ftp_proxy'] = proxy
        os.environ['http_proxy'] = proxy
        os.environ['https_proxy'] = proxy


hookenv.atstart(set_proxy)
