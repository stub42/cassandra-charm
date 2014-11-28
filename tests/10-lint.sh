#!/bin/sh -e

CHARMDIR=$(dirname $(dirname $0))

charm proof $CHARMDIR

FLAKE8=$CHARMDIR/tests/.venv3/bin/flake8

$FLAKE8 --exclude=charmhelpers,.venv2,.venv3 \
    $CHARMDIR/hooks \
    $CHARMDIR/tests \
    $CHARMDIR/testing
