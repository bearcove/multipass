#!/bin/bash
# Creates a loopback alias for the second QUIC path, runs the failover test
# (which blackholes the alias mid-run to simulate silent interface loss), and
# always removes the alias afterward. Needs sudo for ifconfig.
set -u

ALIAS=127.0.0.2
cleanup() { ifconfig lo0 -alias "$ALIAS" 2>/dev/null; }
trap cleanup EXIT

cleanup                      # clear any stale alias
ifconfig lo0 alias "$ALIAS" 255.0.0.0 || { echo "failed to add alias"; exit 1; }
echo "alias $ALIAS up; running test (test will blackhole it at t=2s)"
echo
./target/debug/mqvpn-rs
echo
echo "alias after test: $(ifconfig lo0 | grep -c "$ALIAS") (0 = removed)"
