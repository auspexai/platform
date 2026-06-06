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

from auspexai_platform.receipts.intoto import build_result_set_statement
from auspexai_platform.receipts.rekor import NoOpRekorClient, RekorClient
from auspexai_platform.receipts.signing import SigningKey, cose_sign1_encode

RESULT_SET_ALGORITHM = "sha256-merkle-v0"

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


@dataclass(frozen=True)
class ResultSetEntry:
    """One unit's contribution to the attested set: its consensus payload hash
    and the receipt that attests the per-unit quorum."""

    unit_id: str
    consensus_result_hash: str
    receipt_id: str


def _leaf_bytes(entry: ResultSetEntry) -> bytes:
    canonical = json.dumps(
        {
            "unit_id": entry.unit_id,
            "consensus_result_hash": entry.consensus_result_hash,
            "receipt_id": entry.receipt_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(_LEAF_PREFIX + canonical).digest()


def merkle_root(entries: list[ResultSetEntry]) -> str:
    """Hex SHA-256 Merkle root over `entries` **sorted by unit_id**. Empty set →
    a fixed sentinel (SHA-256 of the leaf-domain prefix) so the function is total.
    Deterministic + domain-separated (leaf vs node prefixes prevent
    second-preimage / leaf-as-node confusion); the SDK recomputes it identically."""
    if not entries:
        return hashlib.sha256(_LEAF_PREFIX).hexdigest()
    ordered = sorted(entries, key=lambda e: e.unit_id)
    level = [_leaf_bytes(e) for e in ordered]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # duplicate the last node on an odd level
        level = [
            hashlib.sha256(_NODE_PREFIX + level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    return level[0].hex()


def collect_result_set_entries(
    per_job_db,
    *,
    receipt_id_by_result: dict[str, str],
    page_size: int = 500,
) -> list[ResultSetEntry]:
    """Gather the attestable per-unit consensus set from a per-job DB: every
    consensus result that reached agreement (has a `semantic_hash`) AND has an
    issued receipt, as (unit_id, consensus_result_hash, receipt_id). Pages
    through ALL consensus rows — no silent cap. Shared by the on-demand endpoint
    and the emit-on-complete path so they produce byte-identical roots."""
    from auspexai_platform.db.repositories import ResultRepository

    repo = ResultRepository(per_job_db)
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


def build_result_set_attestation(
    *,
    attestation_id: str,
    tenant_experiment_label: str,
    tenant_id: str,
    entries: list[ResultSetEntry],
    signing_key: SigningKey,
    rekor_client: RekorClient | NoOpRekorClient | None = None,
) -> ResultSetAttestation:
    """Build + COSE-sign (+ Rekor-anchor) the result-set attestation. Pure given
    its inputs — the same set yields a byte-identical root, so the endpoint can
    build it on demand without storing it."""
    ordered = sorted(entries, key=lambda e: e.unit_id)
    root = merkle_root(ordered)
    predicate = {
        "merkle_root": root,
        "algorithm": RESULT_SET_ALGORITHM,
        "experiment_id": tenant_experiment_label,
        "tenant_id": tenant_id,
        "unit_count": len(ordered),
        "units": [
            {
                "unit_id": e.unit_id,
                "consensus_result_hash": e.consensus_result_hash,
                "receipt_id": e.receipt_id,
            }
            for e in ordered
        ],
    }
    predicate_cbor = cbor2.dumps(predicate, canonical=True)
    statement_cbor = build_result_set_statement(
        predicate_cbor=predicate_cbor, attestation_id=attestation_id
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
        algorithm=RESULT_SET_ALGORITHM,
        unit_count=len(ordered),
        entries=ordered,
        cose_signed_blob=cose_blob,
        signing_key_pubkey_hex=signing_key.pubkey_hex,
        rekor_log_index=entry.log_index,
        rekor_entry_uuid=entry.entry_uuid,
    )
