# Coordinator packaging — systemd maintenance timers

Version-controlled systemd units for the coordinator's periodic maintenance sweeps, plus an
idempotent installer. These live in the repo (not as hand-dropped one-off files) so every
deployment runs the same reviewable units — we eat our own dog food.

## Units (`systemd/`)

| Timer | Sweep | Cadence | Effect |
|-------|-------|---------|--------|
| `auspexai-coordinator-settle.timer` | `coordinator settle --apply` | every 10 min | **C14 regime-2:** completes capacity-stuck units at their achieved replication once the eligible fleet is exhausted + quiescent — instead of stalling forever |
| `auspexai-coordinator-ageoff.timer` | `coordinator age-off --apply` | daily 03:30 | **M-Results retention:** blanks expired result payloads (rows / signatures / hashes / receipts preserved) |
| `auspexai-coordinator-backfill-rekor.timer` | `coordinator attestation backfill-rekor --apply` | hourly | **A1/A2 durability:** anchors un-anchored attestation COSE blobs into the public Rekor transparency log |

`settle` is new (this is its first timer). `ageoff` + `backfill-rekor` were **captured
byte-identically from the running rage deployment** to bring previously hand-installed
one-offs under version control. All `.service` units are `Type=oneshot`, run as `User=jason`
with `AUSPEXAI_STATE_DIR=/var/lib/auspexai-coordinator`, and `ProtectSystem=strict` +
`ReadWritePaths=` the state dir — mirroring `auspexai-coordinator.service`. They are no-ops
when nothing qualifies.

## Install / update

Run **after** the coordinator package is installed into `/opt/auspexai-coordinator`:

```sh
make install-timers          # from the platform/ repo root
# or directly:
./packaging/install-timers.sh
```

The script is idempotent — re-run it on every coordinator update. It copies the units,
`daemon-reload`s, and `enable --now`s the timers (a no-op for already-installed identical
units). Adding a new maintenance timer = drop a `auspexai-coordinator-<x>.{service,timer}`
pair in `systemd/`; the installer globs it in.

> **The repo is now the source of truth** for these units — edit them here and re-run the
> installer, not `/etc` directly (a re-install reverts hand edits in `/etc`).
> Units are tuned for the single-host **rage** deployment (hardcoded `User=jason` + the `/opt`
> + `/var/lib` paths, mirroring `auspexai-coordinator.service`). A multi-host setup would
> template them.
