#!/usr/bin/env bash
#
# Install / update the AuspexAI coordinator's maintenance timer units (the C14 regime-2
# settle-sweep + the result-retention age-off) into systemd.
#
# We eat our own dog food: these units are version-controlled in packaging/systemd/ and
# installed by this script — NOT hand-dropped one-off files. Re-run it on every coordinator
# update; it is idempotent (overwrites the units, daemon-reloads, re-enables the timers).
# Adding a new maintenance timer = drop a auspexai-coordinator-<x>.{service,timer} pair in
# systemd/ and re-run; this script picks it up by glob.
#
# Requires sudo (writes to /etc/systemd/system). Run AFTER the coordinator package is
# installed into /opt (the units' ExecStart points at /opt/auspexai-coordinator/bin/...).
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/systemd" && pwd)"
DEST=/etc/systemd/system

echo "==> installing coordinator maintenance units from ${SRC}"
sudo install -m 0644 \
    "${SRC}"/auspexai-coordinator-*.service \
    "${SRC}"/auspexai-coordinator-*.timer \
    "${DEST}/"

sudo systemctl daemon-reload

# Enable + start every TIMER we ship. The paired .service units are oneshots the timers
# drive; they are never enabled directly.
for timer in "${SRC}"/auspexai-coordinator-*.timer; do
    name="$(basename "${timer}")"
    echo "==> enable --now ${name}"
    sudo systemctl enable --now "${name}"
done

echo "==> active coordinator timers:"
systemctl list-timers 'auspexai-coordinator-*' --all --no-pager || true
echo "Done. (Run any sweep manually for a dry-run report, e.g. 'auspexai-coordinator settle'.)"
