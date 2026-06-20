"""Eager download conductor (M3b, §9 #39 §3b).

Decides which models a worker should *pre-stage* — pull before it's assigned a
unit needing them — so a model-gated experiment isn't bottlenecked on
first-assignment pulls. Runs per-worker when the worker polls
GET /workers/{id}/prestage:

  1. **Mark-acquired** any of the worker's open directives whose model now
     appears in its heartbeat inventory (the pull finished).
  2. **Plan** new directives: for each approved experiment the worker is
     tier-eligible for, for each required model the worker lacks that the
     manifest gives acquisition coords for, create a directive **iff** the
     model is under-supplied — `holders + in-flight pre-stages < replication
     need + churn_margin`. The supply check bounds the fan-out (no thundering
     herd): each eligible worker's poll adds at most one directive per
     under-supplied model until supply reaches the target.

Only auto-acquire workers are planned for — a worker that won't honour a
directive (no `pull-then-run` consent) isn't asked to. Coords come from the
manifest (M3 self-describing `hf_repo`/`hf_filename`); a required model with no
coords is left to the demand-board (#32), not pre-staged.
"""

from __future__ import annotations

from datetime import datetime

from auspexai_platform.db.models import ExperimentStatus, Worker
from auspexai_platform.db.repositories import (
    ExperimentRepository,
    ManifestRepository,
    ModelPrestageRepository,
    WorkerRepository,
)
from auspexai_platform.scheduler import replication_floor_for_tier

DEFAULT_CHURN_MARGIN = 1


def _coords_for_models(manifest_json: dict) -> dict[str, tuple[str, str]]:
    """Map model_id -> (hf_repo, hf_filename) for manifest models that carry both
    acquisition coords (M3). Models without coords are omitted (not pre-stageable)."""
    out: dict[str, tuple[str, str]] = {}
    for m in manifest_json.get("models") or []:
        mid = m.get("id")
        repo = m.get("hf_repo")
        fname = m.get("hf_filename")
        if (
            isinstance(mid, str)
            and isinstance(repo, str)
            and repo
            and isinstance(fname, str)
            and fname
        ):
            out[mid] = (repo, fname)
    return out


def plan_prestage_for_worker(
    worker: Worker,
    *,
    experiment_repository: ExperimentRepository,
    manifest_repository: ManifestRepository,
    worker_repository: WorkerRepository,
    prestage_repository: ModelPrestageRepository,
    heartbeat_cutoff: datetime,
    churn_margin: int = DEFAULT_CHURN_MARGIN,
) -> list:
    """Reconcile + extend `worker`'s pre-stage directives; return its open
    directives (the models it should pull now). Idempotent per poll."""
    inventory = set(worker.capabilities.get("models", []) or [])

    # 1. Mark-acquired: a pull that finished now shows in the heartbeat inventory.
    for d in prestage_repository.list_open_for_worker(worker.worker_id):
        if d.model_id in inventory:
            prestage_repository.mark_acquired(model_id=d.model_id, worker_id=worker.worker_id)

    # 2. Plan — only for auto-acquire workers (others won't honour a directive).
    if worker.capabilities.get("auto_acquire") is True:
        tier_floor = replication_floor_for_tier(worker.trust_tier)
        for exp in experiment_repository.list_all(status=ExperimentStatus.APPROVED):
            required = (exp.required_capabilities or {}).get("models", [])
            if not required:
                continue
            repl = exp.replication_target  # C14: source of truth (decoupled from the map)
            if tier_floor > repl:
                continue  # worker can't take this experiment's units anyway
            need = repl + churn_margin
            manifest = manifest_repository.get(exp.manifest_hash)
            if manifest is None:
                continue
            coords = _coords_for_models(manifest.manifest_json)
            for model_id in required:
                if model_id in inventory:
                    continue  # already held
                if model_id not in coords:
                    continue  # no acquisition coords → demand-board, not pre-stage
                if prestage_repository.has_open(model_id=model_id, worker_id=worker.worker_id):
                    continue  # already directed to this worker
                holders = worker_repository.count_capable(
                    required_models=[model_id], heartbeat_cutoff=heartbeat_cutoff
                )
                in_flight = prestage_repository.count_open_for_model(model_id)
                if holders + in_flight >= need:
                    continue  # enough supply already (held or in-flight) — bound the fan-out
                hf_repo, hf_filename = coords[model_id]
                prestage_repository.create(
                    model_id=model_id,
                    hf_repo=hf_repo,
                    hf_filename=hf_filename,
                    worker_id=worker.worker_id,
                    requested_by="conductor",
                    experiment_id=exp.experiment_id,
                )

    return prestage_repository.list_open_for_worker(worker.worker_id)
