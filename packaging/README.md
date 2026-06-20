# Coordinator packaging — systemd maintenance timers

Version-controlled systemd units for the coordinator's periodic maintenance sweeps, plus an
idempotent installer. These live in the repo (not as hand-dropped one-off files) so every
deployment runs the same reviewable units — we eat our own dog food.

## Units (`systemd/`)

| Timer | Sweep | Cadence | Effect |
|-------|-------|---------|--------|
| `auspexai-coordinator-settle.timer` | `coordinator settle --apply` | every 10 min | **C14 regime-2:** completes capacity-stuck units at their achieved replication once the eligible fleet is exhausted + quiescent — instead of stalling forever |
| `auspexai-coordinator-age-off.timer` | `coordinator age-off --apply` | daily 03:30 | **M-Results retention:** blanks expired result payloads (rows / signatures / hashes / receipts preserved) |

Both `.service` units are `Type=oneshot`, run as `User=jason` with
`AUSPEXAI_STATE_DIR=/var/lib/auspexai-coordinator`, `AUSPEXAI_RECEIPTS_MODE=operational`
(settle only — its receipts must be labelled like the daemon's), and `ProtectSystem=strict`
+ `ReadWritePaths=` the state dir — matching `auspexai-coordinator.service`. They are no-ops
when nothing qualifies.

## Install / update

Run **after** the coordinator package is installed into `/opt/auspexai-coordinator`:

```sh
make install-timers          # from the platform/ repo root
# or directly:
./packaging/install-timers.sh
```

The script is idempotent — re-run it on every coordinator update. It copies the units,
`daemon-reload`s, and `enable --now`s the timers. Adding a new maintenance timer = drop a
`auspexai-coordinator-<x>.{service,timer}` pair in `systemd/`; the installer globs it in.

> These units are tuned for the single-host **rage** deployment (hardcoded `User=jason` and
> the `/opt` + `/var/lib` paths, mirroring `auspexai-coordinator.service`). A multi-host
> setup would template them.
