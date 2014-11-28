#!/bin/sh -ex

TESTDIR=$(readlink -f $(dirname $0))
CHARMDIR=$(dirname $TESTDIR)

# We need --system-site-packages for python3-apt.
virtualenv -p python3.4 --system-site-packages $TESTDIR/.venv3

# Create a .pth so our tests can locate everything without sys.path
# hacks.
echo $CHARMDIR/hooks > $TESTDIR/.venv3/lib/python3.4/site-packages/tests.pth
echo $CHARMDIR >> $TESTDIR/.venv3/lib/python3.4/site-packages/tests.pth

# Tests don't consistently run in a particular working directory.
# Create a symbolic link in the other potential working directory.
# This symbolic link must be relative to keep amulet and juju-deployer
# happy.
(cd $CHARMDIR && ln -sf tests/.venv3 .)

PIP3=$TESTDIR/.venv3/bin/pip3

$PIP3 install -q --upgrade amulet
$PIP3 install -q flake8
$PIP3 install -qI nose
$PIP3 install -q coverage
$PIP3 install -q cassandra-driver
