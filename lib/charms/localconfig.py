# Copyright 2018 Canonical Ltd.
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

'''The LocalConfig key/value store.'''

from collections import UserDict

from charmhelpers.core import unitdata


class LocalConfig(UserDict):
    '''Key/Value store for local configuration.

    This is a wrapper around the global, shared unitdata.kv() which
    automatically namespaces keys using the supplied prefix.
    '''

    _prefix = None

    def __init__(self, prefix):
        assert type(prefix) == str
        self._prefix = prefix + '.'
        super().__init__(unitdata.kv().getrange(self._prefix, strip=True))

    def __setitem__(self, k, v):
        unitdata.kv().update({k: v}, prefix=self._prefix)
        self.data[k] = v

    def __delitem__(self, k):
        unitdata.kv().unsetrange([k], prefix=self._prefix)
        del self.data[k]
