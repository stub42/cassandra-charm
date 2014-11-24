'''
charm-helpers mocks.
'''
import os.path
import tempfile
from unittest.mock import call, patch

import yaml

from charmhelpers.core import hookenv


CHARM_DIR = os.path.abspath(os.path.join(
    os.path.dirname(__file__), os.pardir))


def mock_charmhelpers(test_case):
    hookenv.cache.clear()  # Clear the hookenv memorisation.

    mocks = []

    # Mock environment
    charm_dir = tempfile.TemporaryDirectory()
    test_case.addCleanup(charm_dir.cleanup)
    mock_env = patch.dict(os.environ, dict(CHARM_DIR=charm_dir.name))
    mock_env.start()
    test_case.addCleanup(mock_env.stop)

    # Mock config.
    # Set items:
    #     hookenv.config()['foo'] = 'bar'
    # Reset 'previous' state:
    #     hookenv.config().save();
    #     hookenv.config().load_previous()
    config = hookenv.Config()
    tmp = tempfile.NamedTemporaryFile(suffix='.config')
    config.CONFIG_FILE_NAME = tmp.name
    test_case.addCleanup(tmp.close)
    with open(os.path.join(CHARM_DIR, 'config.yaml'), 'rb') as f:
        defaults = yaml.safe_load(f)['options']
    for k, v in defaults.items():
        opt_type = v.get('type', 'string')
        opt_val = v.get('default', None)
        if opt_val is None:
            config[k] = None
        elif opt_type == 'string':
            config[k] = str(opt_val)
        elif opt_type == 'int':
            config[k] = int(opt_val)
        elif opt_type == 'boolean':
            config[k] = bool(opt_val)
    def mock_config(scope=None):
        if scope is None:
            return config
        return config.get(scope, None)
    mocks.append(patch('charmhelpers.core.hookenv.config',
                        side_effect=mock_config, autospec=True))

    # A mock write_file that can only write root owned files to
    # the tempdir.
    def mock_write_file(path, contents, owner='root', group='root',
                        perms=0o444):
        assert owner == 'root'
        assert group == 'root'
        assert path.startswith(tempfile.gettempdir())
        # TODO: This is emulating a bug in charm-helpers. Fix
        # charmhelpers to correctly use text or binary mode
        # depending on the 'contents' type.
        with open(path, 'w') as f:
            f.write(contents)
        os.chmod(path, perms)
    write_file = patch('charmhelpers.core.host.write_file',
                    side_effect=mock_write_file, autospec=True)
    mocks.append(write_file)

    # Magic mocks.
    methods = [
        'charmhelpers.core.hookenv.log',
        'charmhelpers.core.host.log',
        'charmhelpers.core.hookenv.hook_name',
        'charmhelpers.core.hookenv.related_units',
        'charmhelpers.core.hookenv.relation_ids',
        'charmhelpers.core.hookenv.relation_for_unit',
        'charmhelpers.core.hookenv.relation_type',
        'charmhelpers.core.hookenv.service_name',
        'charmhelpers.core.hookenv.unit_private_ip',
    ]
    for m in methods:
        mocks.append(patch(m, autospec=True))

    for mock in mocks:
        mock.start()
        test_case.addCleanup(mock.stop)

    os.environ['JUJU_UNIT_NAME'] = 'service/1'
    hookenv.unit_private_ip.return_value = '10.20.0.1'
    hookenv.service_name.return_value = 'service'
    hookenv.relation_ids.side_effect = lambda x: ['{}:1'.format(x)]
    hookenv.related_units.return_value = ('service/2', 'service/3')

    def mock_relation_for_unit(unit=None, rid=None):
        if unit is None:
            unit = hookenv.remote_unit()
        service, unit_num = unit.split('/')
        unit_num = int(unit_num)
        return {'private-address': '10.20.0.{}'.format(unit_num)}
    hookenv.relation_for_unit.side_effect = mock_relation_for_unit
