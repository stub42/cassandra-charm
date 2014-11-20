#!/bin/sh -e

CHARMDIR=$(dirname $(dirname $0))

charm proof $CHARMDIR

FLAKE8=$CHARMDIR/tests/.venv/bin/flake8

$FLAKE8 --exclude=charmhelpers $CHARMDIR/hooks
$FLAKE8 --exclude=.venv $CHARMDIR/tests 
