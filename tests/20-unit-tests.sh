#!/bin/sh -e

TESTDIR=$(readlink -f $(dirname $0))
$TESTDIR/.venv3/bin/nosetests \
    $TESTDIR/test_actions.py --cover-package=actions \
    $TESTDIR/test_helpers.py --cover-package=helpers \
    -v --with-coverage $*
