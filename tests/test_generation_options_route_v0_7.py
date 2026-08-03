"""v0.7 — the v3 submit path: the worker-SIGNED generation chain is verified,
persisted onto the result's environment, and surfaces in the governance
footprint as `effective` (distinct from the manifest's `declared`).

This is the leg that makes the footprint honest. Before v3 the environment
recorded which software and weights ran but nothing recorded the generation
parameters, so the serving provider's own defaults governed unrecorded and the
footprint reported the DECLARATION while describing it as the actual.
"""

from __future__ import annotations

from tests._result_helpers import sign_result_body
from tests.test_assignments_route import _seed_units, _signed_get, _signed_post

_TS = "2026-08-03T12:00:00+00:00"

# What the v0.7 worker emits for a greedy unit: argmax pinned, penalties neutral.
_CHAIN = [
    {
        "temperature": 0,
        "seed": 0,
        "top_k": 1,
        "top_p": 1.0,
        "min_p": 0.0,
        "typical_p": 1.0,
        "repeat_penalty": 1.0,
        "repeat_last_n": 0,
        "presence_penalty": 0.0,
        "frequency_penalty": 0.0,
        "mirostat": 0,
    }
]


def _submit(client, *, privkey, pubkey_hex, worker_id, schema_version, chain, payload=None):
    payload = payload if payload is not None else {"output": 7}
    pick = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        path=f"/api/v0/workers/{worker_id}/assignments",
    ).json()
    assert pick["work_unit"] is not None, "worker was not assigned a unit"
    unit_id = pick["work_unit"]["unit_id"]
    signed = dict(
        unit_id=unit_id,
        completed_at=_TS,
        exit_code=0,
        payload=payload,
        schema_version=schema_version,
        ran_under="permissive",
    )
    if schema_version >= 3:
        signed["generation_options"] = chain
    sig = sign_result_body(privkey, pubkey_hex, **signed)
    body = {
        "unit_id": unit_id,
        "worker_pubkey": pubkey_hex,
        "completed_at": _TS,
        "exit_code": 0,
        "payload": payload,
        "worker_signature": sig,
        "schema_version": schema_version,
        "ran_under": "permissive",
    }
    if schema_version >= 3:
        body["generation_options"] = chain
    resp = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        path=f"/api/v0/workers/{worker_id}/assignments/{unit_id}/result",
        payload=body,
    )
    return unit_id, resp


def test_v3_chain_is_accepted_and_persisted_on_the_environment(
    client, enrolled_worker, approved_experiment, per_job_factory
):
    from auspexai_platform.db.repositories.results import ResultRepository

    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])

    unit_id, resp = _submit(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        worker_id=worker.worker_id,
        schema_version=3,
        chain=_CHAIN,
    )
    assert resp.status_code == 201, resp.text
    stored = ResultRepository(per_job_factory.get(experiment.experiment_id)).list_for_unit(unit_id)
    assert stored[0].environment is not None
    assert stored[0].environment["generation_options"] == _CHAIN


def test_v3_chain_reaches_the_governance_footprint_as_effective(
    client, enrolled_worker, approved_experiment, per_job_factory
):
    """The whole point: a reader of the evidence sees the parameters that
    actually generated the text, not a restatement of the declaration."""
    from auspexai_platform.footprint import collect_generation_chains, generation_footprint

    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])

    _unit, resp = _submit(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        worker_id=worker.worker_id,
        schema_version=3,
        chain=_CHAIN,
    )
    assert resp.status_code == 201, resp.text

    per_job_db = per_job_factory.get(experiment.experiment_id)
    fp = generation_footprint(
        {"inference_determinism": {"temperature": 0, "seed": 0}},
        observed_chains=collect_generation_chains(per_job_db),
    )
    assert fp["mode"] == "greedy"
    assert fp["effective_source"] == "worker_signed"
    # argmax is pinned, and the provider's repeat_penalty 1.1 is displaced.
    assert fp["effective"]["top_k"] == 1
    assert fp["effective"]["repeat_penalty"] == 1.0


def test_a_tampered_chain_fails_the_signature_check(
    client, enrolled_worker, approved_experiment, per_job_factory
):
    """The chain is only worth recording because it is BOUND — a worker cannot
    report parameters other than the ones it signed."""
    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])

    pick = _signed_get(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments",
    ).json()
    unit_id = pick["work_unit"]["unit_id"]
    payload = {"output": 7}
    sig = sign_result_body(
        privkey,
        worker.pubkey_hex,
        unit_id=unit_id,
        completed_at=_TS,
        exit_code=0,
        payload=payload,
        schema_version=3,
        ran_under="permissive",
        generation_options=_CHAIN,
    )
    resp = _signed_post(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/workers/{worker.worker_id}/assignments/{unit_id}/result",
        payload={
            "unit_id": unit_id,
            "worker_pubkey": worker.pubkey_hex,
            "completed_at": _TS,
            "exit_code": 0,
            "payload": payload,
            "worker_signature": sig,
            "schema_version": 3,
            "ran_under": "permissive",
            # Claim Ollama's defaults while having signed the neutral chain.
            "generation_options": [{**_CHAIN[0], "top_k": 40, "repeat_penalty": 1.1}],
        },
    )
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]["error"]["code"] == "worker_signature_invalid"


def test_pre_v3_worker_still_ingests_and_reads_as_unrecorded(
    client, enrolled_worker, approved_experiment, per_job_factory
):
    """No flag day: an un-rolled worker submits v2 and the footprint says
    `unrecorded` rather than presenting the declaration as the actual."""
    from auspexai_platform.footprint import collect_generation_chains, generation_footprint

    privkey, worker = enrolled_worker
    _, _, experiment, _ = approved_experiment
    _seed_units(per_job_factory, experiment.experiment_id, ["u1"])

    _unit, resp = _submit(
        client,
        privkey=privkey,
        pubkey_hex=worker.pubkey_hex,
        worker_id=worker.worker_id,
        schema_version=2,
        chain=None,
    )
    assert resp.status_code == 201, resp.text

    per_job_db = per_job_factory.get(experiment.experiment_id)
    assert collect_generation_chains(per_job_db) == []
    fp = generation_footprint(None, observed_chains=collect_generation_chains(per_job_db))
    assert fp["effective_source"] == "unrecorded"
