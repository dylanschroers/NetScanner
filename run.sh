#!/usr/bin/env bash
# Build, make sure the binary may capture, and run it.
#
# Capabilities live on the file, and cargo drops them every time it relinks, so
# re-granting belongs to the build rather than to one-off setup.
set -euo pipefail

bin=target/debug/netscanner
getcap=$(command -v getcap || echo /usr/sbin/getcap)

cargo build

# Skipped when the grant is already in place, so the common case needs no sudo.
if ! "$getcap" "$bin" 2>/dev/null | grep -q cap_net_raw; then
    echo "Granting cap_net_raw to $bin (needs sudo)"
    sudo setcap cap_net_raw+ep "$bin"
fi

exec "$bin"
