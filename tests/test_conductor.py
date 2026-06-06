"""Eager download conductor (M3b) — pre-stage planning + sizing bound."""

from __future__ import annotations

from datetime import UTC, datetime

from auspexai_platform.db.models import ExperimentStatus
from auspexai_platform.db.repositories import ModelPrestageRepository
from auspexai_platform.scheduler.conductor import plan_prestage_for_worker
from auspexai_platform.worker_status import heartbeat_cutoff

_COORDS_MODEL = {
    "id": "m-x",
    "version": "1",
    "local_weights_required": True,
    "hf_repo": "Org/M-GGUF",
    "hf_filename": "M-Q4.gguf",
}


def _approved_exp_requiring_mx(manifest_repository, experiment_repository, *, tenant_id):
    manifest = manifest_repository.insert(
        tenant_id=tenant_id,
        manifest_json={"tenant_id": tenant_id, "experiment_id": "exp-label", "models": [_COORDS_MODEL]},
        signature_json={},
    )
    exp = experiment_repository.create(
        tenant_id=tenant_id,
        tenant_experiment_label="exp-label",
        manifest_hash=manifest.manifest_hash,
        required_capabilities={"models": ["m-x"]},
    )
    experiment_repository.update_status(exp.experiment_id, ExperimentStatus.APPROVED)
    return experiment_repository.get_by_id(exp.experiment_id)


def _enroll(worker_repository, *, worker_id, caps):
    worker_repository.enroll(worker_id=worker_id, pubkey_hex=worker_id_hex(worker_id))
    worker_repository.record_heartbeat(worker_id, capabilities=caps)
    return worker_repository.get_by_id(worker_id)


def worker_id_hex(worker_id: str) -> str:
    # deterministic 64-hex pubkey from the id
    import hashlib

    return hashlib.sha256(worker_id.encode()).hexdigest()


def _plan(worker, *, db, experiment_repository, manifest_repository, worker_repository):
    return plan_prestage_for_worker(
        worker,
        experiment_repository=experiment_repository,
        manifest_repository=manifest_repository,
        worker_repository=worker_repository,
        prestage_repository=ModelPrestageRepository(db),
        heartbeat_cutoff=heartbeat_cutoff(datetime.now(UTC)),
    )


def test_conductor_directs_eligible_auto_acquire_worker(
    db, manifest_repository, experiment_repository, worker_repository, registered_tenant
):
    _, binding = registered_tenant
    _approved_exp_requiring_mx(manifest_repository, experiment_repository, tenant_id=binding.tenant_id)
    w = _enroll(
        worker_repository,
        worker_id="wkr-aa",
        caps={"os": "linux", "auto_acquire": True},  # eligible, lacks m-x
    )
    directives = _plan(
        w, db=db, experiment_repository=experiment_repository,
        manifest_repository=manifest_repository, worker_repository=worker_repository,
    )
    assert [d.model_id for d in directives] == ["m-x"]
    assert directives[0].hf_repo == "Org/M-GGUF"
    assert directives[0].hf_filename == "M-Q4.gguf"
    # Idempotent: a second poll doesn't create a duplicate.
    again = _plan(
        w, db=db, experiment_repository=experiment_repository,
        manifest_repository=manifest_repository, worker_repository=worker_repository,
    )
    assert len(again) == 1


def test_conductor_skips_non_auto_acquire_worker(
    db, manifest_repository, experiment_repository, worker_repository, registered_tenant
):
    _, binding = registered_tenant
    _approved_exp_requiring_mx(manifest_repository, experiment_repository, tenant_id=binding.tenant_id)
    w = _enroll(worker_repository, worker_id="wkr-no", caps={"os": "linux"})  # no auto_acquire
    assert _plan(
        w, db=db, experiment_repository=experiment_repository,
        manifest_repository=manifest_repository, worker_repository=worker_repository,
    ) == []


def test_conductor_marks_acquired_when_model_appears(
    db, manifest_repository, experiment_repository, worker_repository, registered_tenant
):
    _, binding = registered_tenant
    _approved_exp_requiring_mx(manifest_repository, experiment_repository, tenant_id=binding.tenant_id)
    w = _enroll(worker_repository, worker_id="wkr-aa", caps={"os": "linux", "auto_acquire": True})
    _plan(  # creates the directive
        w, db=db, experiment_repository=experiment_repository,
        manifest_repository=manifest_repository, worker_repository=worker_repository,
    )
    # Worker now reports m-x in inventory → next poll marks it acquired (no open directive left).
    worker_repository.record_heartbeat(
        "wkr-aa", capabilities={"os": "linux", "auto_acquire": True, "models": ["m-x"]}
    )
    w2 = worker_repository.get_by_id("wkr-aa")
    directives = _plan(
        w2, db=db, experiment_repository=experiment_repository,
        manifest_repository=manifest_repository, worker_repository=worker_repository,
    )
    assert directives == []
    repo = ModelPrestageRepository(db)
    assert repo.count_open_for_model("m-x") == 0


def test_conductor_bounds_fanout_by_supply(
    db, manifest_repository, experiment_repository, worker_repository, registered_tenant
):
    # need = replication (3, STANDARD default) + churn_margin (1) = 4. Once 4 open
    # rows exist, a 5th eligible worker is not directed.
    _, binding = registered_tenant
    _approved_exp_requiring_mx(manifest_repository, experiment_repository, tenant_id=binding.tenant_id)
    for i in range(4):
        w = _enroll(
            worker_repository, worker_id=f"wkr-{i}", caps={"os": "linux", "auto_acquire": True}
        )
        assert len(_plan(
            w, db=db, experiment_repository=experiment_repository,
            manifest_repository=manifest_repository, worker_repository=worker_repository,
        )) == 1
    fifth = _enroll(
        worker_repository, worker_id="wkr-5", caps={"os": "linux", "auto_acquire": True}
    )
    assert _plan(
        fifth, db=db, experiment_repository=experiment_repository,
        manifest_repository=manifest_repository, worker_repository=worker_repository,
    ) == []  # supply (4 in-flight) already meets need
