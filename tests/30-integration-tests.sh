#!/bin/sh -e

TESTDIR=$(readlink -f $(dirname $0))
$TESTDIR/.venv3/bin/nosetests -v $TESTDIR/test_integration.py $*
