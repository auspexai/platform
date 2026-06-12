"""Result-set completion attestation (#34, §6.3 of the reduction/control-loop design).

When an experiment is COMPLETED, the coordinator emits a **model-blind**,
tamper-evident anchor over the final result set so a tenant-side reduce (and the
#35 `run_until` reduce) has a reproducible, attested input — without the
coordinator ever interpreting a payload.

The attested object is a Merkle root over the experiment's per-unit consensus
set, sorted by `unit_id`:

    leaf_i  = SHA-256( 0x00 || canonical_json({unit_id, consensus_result_hash, receipt_id}) )
    node    = SHA-256( 0x01 || left || right )      # odd level → duplicate the last node
    root    = <top node>                            # empty set → SHA-256(0x00) sentinel

The root + the ordered unit list go into an in-toto v1 Statement (predicate type
`https://auspexai.network/result-set/v0`), which is COSE-signed with the §5.16
receipt-signing key and (optionally) anchored in Rekor — exactly the receipt
infrastructure, reused. The tenant can then re-pull the consensus set, recompute
the root the same way, verify the signature against the authorized signer, and
reproduce its aggregate. The coordinator only hashes/orders the
already-computed per-unit consensus hashes it holds; it never reads a payload.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

import cbor2

from auspexai_platform.receipts.intoto import (
    AUSPEXAI_RESULT_SET_PREDICATE_TYPE_V1,
    build_result_set_statement,
)
from auspexai_platform.receipts.rekor import NoOpRekorClient, RekorClient
from auspexai_platform.receipts.signing import SigningKey, cose_sign1_encode

RESULT_SET_ALGORITHM = "sha256-merkle-v0"
# EB-1 (§9 #47): v1 leaves additionally bind the INPUT — unit_payload_sha256 —
# so "result R was produced from parameters P" is cryptographic, not a DB-row
# linkage. Environment metadata rides the signed predicate, NOT the leaf:
# leaves hold only what a verifier can independently recompute from data in
# hand; environment is coordinator-asserted.
RESULT_SET_ALGORITHM_V1 = "sha256-merkle-v1"

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


@dataclass(frozen=True)
class ResultSetEntry:
    """One unit's contribution to the attested set: its consensus payload hash
    and the receipt that attests the per-unit quorum. v1 (EB-1) adds the input
    binding (`unit_payload_sha256`, in the leaf) and coordinator-asserted
    `environment` (predicate-only metadata: worker serving-stack snapshot)."""

    unit_id: str
    consensus_result_hash: str
    receipt_id: str
    unit_payload_sha256: str | None = None
    environment: dict[str, object] | None = None


def unit_payload_sha256(payload_json: str) -> str:
    """The shared input-hash convention (leaf + SDK recompute): SHA-256 over the
    CANONICAL re-serialization of the work-unit payload (sorted keys, compact
    separators) — robust to storage/transport formatting differences."""
    canonical = json.dumps(json.loads(payload_json), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _leaf_bytes(entry: ResultSetEntry, *, schema_version: int = 0) -> bytes:
    fields = {
        "unit_id": entry.unit_id,
        "consensus_result_hash": entry.consensus_result_hash,
        "receipt_id": entry.receipt_id,
    }
    if schema_version >= 1:
        fields["unit_payload_sha256"] = entry.unit_payload_sha256 or ""
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(_LEAF_PREFIX + canonical).digest()


def merkle_root(entries: list[ResultSetEntry], *, schema_version: int = 0) -> str:
    """Hex SHA-256 Merkle root over `entries` **sorted by unit_id**. Empty set →
    a fixed sentinel (SHA-256 of the leaf-domain prefix) so the function is total.
    Deterministic + domain-separated (leaf vs node prefixes prevent
    second-preimage / leaf-as-node confusion); the SDK recomputes it identically.
    `schema_version=1` (EB-1) widens each leaf with `unit_payload_sha256`; v0
    leaves are byte-identical to the M7 format (honor-forever)."""
    if not entries:
        return hashlib.sha256(_LEAF_PREFIX).hexdigest()
    ordered = sorted(entries, key=lambda e: e.unit_id)
    level = [_leaf_bytes(e, schema_version=schema_version) for e in ordered]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # duplicate the last node on an odd level
        level = [
            hashlib.sha256(_NODE_PREFIX + level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    return level[0].hex()


def _unit_payload_hashes(per_job_db) -> dict[str, str]:
    """{unit_id: unit_payload_sha256} over the experiment's work units — the
    reproducibility triple's input leg, hashed per the shared canonical
    convention."""
    rows = per_job_db.execute("SELECT unit_id, payload_json FROM work_units")
    return {r["unit_id"]: unit_payload_sha256(r["payload_json"]) for r in rows}


class IncompleteAttestationSetError(Exception):
    """The collected attestation entries do not cover every consensus unit
    that holds an issued receipt — signing this set would put the coordinator's
    signature on a claim narrower than the data (the D1 bug family). Refuse to
    canonicalize; the divergence is the finding."""

    def __init__(self, missing_units: list[str], extra_units: list[str]) -> None:
        self.missing_units = missing_units
        self.extra_units = extra_units
        super().__init__(
            f"attestation set diverges from the consensus set: "
            f"missing={missing_units} extra={extra_units}"
        )


def receipt_map_from_per_job(per_job_db) -> dict[str, str]:
    """{result_id: receipt_id} derived from the AUTHORITATIVE per-job tables
    (receipts ⨝ results) — NOT the control-DB `receipt_index`.

    The index is a best-effort display cache: its write is swallowed-on-error
    at issuance, so deciding attestation-leaf membership from it let one failed
    index write silently narrow the signed set while the claim stayed
    "complete" (the 2026-06-12 signature-scope finding, D1's sibling). Signing
    and bundle-membership paths use this map; the index keeps serving the
    cross-experiment display routes it was built for.

    Receipts are keyed back to results by joining each receipt body's
    (worker_pubkey, work_unit_ids) to the results table. Deterministic:
    receipts walk in (issued_at, receipt_id) order and the first receipt for a
    (unit, worker) wins, so a rebuilt map reproduces the same leaves."""
    from auspexai_platform.receipts.models import decode_cbor

    by_unit_worker: dict[tuple[str, str], str] = {}
    for row in per_job_db.execute(
        "SELECT receipt_id, receipt_body_cbor FROM receipts ORDER BY issued_at, receipt_id"
    ):
        try:
            receipt = decode_cbor(row["receipt_body_cbor"])
        except Exception:
            # An undecodable body cannot claim a leaf. Skipping narrows the
            # set, so the assert_entries_cover_consensus guard (whose
            # unit-level predicate does NOT decode bodies) refuses to sign it.
            continue
        pubkey = receipt.worker_pubkey.hex().lower()
        for unit_id in receipt.work_unit_ids:
            by_unit_worker.setdefault((unit_id, pubkey), row["receipt_id"])
    out: dict[str, str] = {}
    for row in per_job_db.execute("SELECT result_id, unit_id, worker_pubkey_hex FROM results"):
        receipt_id = by_unit_worker.get((row["unit_id"], row["worker_pubkey_hex"].lower()))
        if receipt_id is not None:
            out[row["result_id"]] = receipt_id
    return out


def assert_entries_cover_consensus(per_job_db, entries: list[ResultSetEntry]) -> None:
    """Independent persist-time recount (D1-family guard): every consensus unit
    for which ANY receipt row exists must appear in the attested entries, and
    nothing else may. Deliberately a different code path from the collection
    join — a raw SQL existence check that doesn't decode receipt bodies — so a
    bug in either path surfaces as divergence instead of a short signed set.
    Raises IncompleteAttestationSetError on divergence."""
    rows = per_job_db.execute(
        """
        SELECT r.unit_id FROM results r
        WHERE r.is_consensus = 1 AND r.semantic_hash IS NOT NULL
          AND EXISTS (
            SELECT 1 FROM receipts rc
            WHERE rc.work_unit_ids_json LIKE '%"' || r.unit_id || '"%'
          )
        """
    )
    expected = {row["unit_id"] for row in rows}
    attested = {e.unit_id for e in entries}
    if expected != attested:
        raise IncompleteAttestationSetError(
            missing_units=sorted(expected - attested),
            extra_units=sorted(attested - expected),
        )


def collect_result_set_entries(
    per_job_db,
    *,
    receipt_id_by_result: dict[str, str],
    page_size: int = 500,
) -> list[ResultSetEntry]:
    """Gather the attestable per-unit consensus set from a per-job DB: every
    consensus result that reached agreement (has a `semantic_hash`) AND has an
    issued receipt, as (unit_id, consensus_result_hash, receipt_id) — plus, for
    v1 (EB-1), the unit's input hash and the coordinator-asserted environment
    snapshot captured at submission. Pages through ALL consensus rows — no
    silent cap. Shared by the on-demand endpoint and the emit-on-complete path
    so they produce byte-identical roots."""
    from auspexai_platform.db.repositories import ResultRepository

    repo = ResultRepository(per_job_db)
    payload_hashes = _unit_payload_hashes(per_job_db)
    entries: list[ResultSetEntry] = []
    after_completed_at: str | None = None
    after_result_id: str | None = None
    while True:
        rows = repo.list_consensus(
            limit=page_size,
            after_completed_at=after_completed_at,
            after_result_id=after_result_id,
        )
        for r in rows:
            receipt_id = receipt_id_by_result.get(r.result_id)
            if receipt_id is None or r.semantic_hash is None:
                continue
            entries.append(
                ResultSetEntry(
                    unit_id=r.unit_id,
                    consensus_result_hash=r.semantic_hash,
                    receipt_id=receipt_id,
                    unit_payload_sha256=payload_hashes.get(r.unit_id),
                    environment=r.environment,
                )
            )
        if len(rows) < page_size:
            break
        after_completed_at = rows[-1].completed_at.isoformat()
        after_result_id = rows[-1].result_id
    return entries


@dataclass(frozen=True)
class ResultSetAttestation:
    """The built attestation, ready for the API response + persistence-free
    return. `cose_signed_blob` is the canonical artifact verifiers consume;
    `predicate` is the decoded body echoed for convenience."""

    attestation_id: str
    experiment_id: str  # tenant-facing label (matches the receipt convention)
    tenant_id: str
    merkle_root: str
    algorithm: str
    unit_count: int
    entries: list[ResultSetEntry]
    cose_signed_blob: bytes
    signing_key_pubkey_hex: str
    rekor_log_index: int
    rekor_entry_uuid: str
    # M9 leg 2: True for a checkpoint/partial attestation (the experiment had not
    # COMPLETED — the set is a consensus-so-far snapshot, not the final set). The
    # flag is part of the COSE-signed predicate (tamper-evident), so a verifier
    # can never mistake a partial set for the complete one.
    partial: bool = False


def build_result_set_attestation(
    *,
    attestation_id: str,
    tenant_experiment_label: str,
    tenant_id: str,
    entries: list[ResultSetEntry],
    signing_key: SigningKey,
    rekor_client: RekorClient | NoOpRekorClient | None = None,
    partial: bool = False,
    schema_version: int = 1,
) -> ResultSetAttestation:
    """Build + COSE-sign (+ Rekor-anchor) the result-set attestation. Pure given
    its inputs — the same set yields a byte-identical root, so the endpoint can
    build it on demand without storing it.

    `partial=True` (M9 leg 2 checkpoint) marks an over-a-non-complete-set snapshot:
    the Merkle root is unchanged (purely over `entries`), but the signed predicate
    carries `partial: true`. When False the key is OMITTED entirely so a COMPLETED
    attestation's predicate (and thus its COSE bytes) stays byte-identical to the
    M7 format — a checkpoint never silently rewrites the completed attestation.

    `schema_version=1` (EB-1, the default for NEW attestations) widens leaves with
    `unit_payload_sha256` and the predicate units with that hash + the
    coordinator-asserted `environment` snapshot; predicateType becomes
    result-set/v1 and algorithm sha256-merkle-v1. Pass 0 only to reproduce the
    legacy format (already-persisted v0 rows are served as stored, never
    rebuilt)."""
    ordered = sorted(entries, key=lambda e: e.unit_id)
    root = merkle_root(ordered, schema_version=schema_version)
    units: list[dict] = []
    for e in ordered:
        unit: dict = {
            "unit_id": e.unit_id,
            "consensus_result_hash": e.consensus_result_hash,
            "receipt_id": e.receipt_id,
        }
        if schema_version >= 1:
            unit["unit_payload_sha256"] = e.unit_payload_sha256 or ""
            if e.environment is not None:
                unit["environment"] = e.environment
        units.append(unit)
    predicate = {
        "merkle_root": root,
        "algorithm": RESULT_SET_ALGORITHM_V1 if schema_version >= 1 else RESULT_SET_ALGORITHM,
        "experiment_id": tenant_experiment_label,
        "tenant_id": tenant_id,
        "unit_count": len(ordered),
        "units": units,
    }
    if partial:
        predicate["partial"] = True
    predicate_cbor = cbor2.dumps(predicate, canonical=True)
    statement_kwargs: dict = {}
    if schema_version >= 1:
        statement_kwargs["predicate_type"] = AUSPEXAI_RESULT_SET_PREDICATE_TYPE_V1
    statement_cbor = build_result_set_statement(
        predicate_cbor=predicate_cbor, attestation_id=attestation_id, **statement_kwargs
    )
    cose_blob = cose_sign1_encode(payload=statement_cbor, signing_key=signing_key)

    rekor = rekor_client or NoOpRekorClient()
    try:
        entry = rekor.record(cose_blob)
    except Exception:  # pragma: no cover — defensive, mirrors issuance
        entry = NoOpRekorClient().record(cose_blob)

    return ResultSetAttestation(
        attestation_id=attestation_id,
        experiment_id=tenant_experiment_label,
        tenant_id=tenant_id,
        merkle_root=root,
        algorithm=RESULT_SET_ALGORITHM_V1 if schema_version >= 1 else RESULT_SET_ALGORITHM,
        unit_count=len(ordered),
        entries=ordered,
        cose_signed_blob=cose_blob,
        signing_key_pubkey_hex=signing_key.pubkey_hex,
        rekor_log_index=entry.log_index,
        rekor_entry_uuid=entry.entry_uuid,
        partial=partial,
    )
