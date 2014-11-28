#!/bin/sh -e

CHARMDIR=$(dirname $(dirname $0))

charm proof $CHARMDIR

FLAKE8=$CHARMDIR/tests/.venv/bin/flake8

$FLAKE8 --exclude=charmhelpers,.venv \
    $CHARMDIR/hooks \
    $CHARMDIR/tests \
    $CHARMDIR/testing
