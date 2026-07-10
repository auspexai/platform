"""G6+F4 (ratified 2026-07-06): researcher publication actions.

POST /experiments/{id}/actions/authorize-benchmark-publication  (standing ≥ R1)
POST /experiments/{id}/actions/mint-doi                         (standing ≥ R3)

The authorization endpoint returns a coordinator-SIGNED block the SDK embeds
in the published entry (the board CI verifies it like custody — the R-gate
travels with the artifact). Every action writes an audit row and a
publication record carrying COORDINATOR FACTS (standing at issue, attestation
roots + Rekor ids from our own records) beside the RESEARCHER'S CLAIMED
summary (peak/breadth — never re-scored; the descriptive-only line holds).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from auspexai_platform.db.models import CredentialClass
from auspexai_platform.db.repositories.publications import PublicationRepository

AUTHORIZATION_SCHEMA = "auspexai-publication-authorization/v0"


class BenchmarkPublicationRequest(BaseModel):
    reference_experiment_id: str
    peak_eu: float | None = None
    breadth: float | None = None
    byte_divergence_rate: float | None = None
    entry_intent: str | None = Field(default=None, max_length=200)


class MintDoiRequest(BaseModel):
    title: str | None = Field(default=None, max_length=300)


def _canonical(block: dict[str, Any]) -> bytes:
    return json.dumps(block, sort_keys=True, separators=(",", ":")).encode()


def _typed_409(code: str, message: str) -> HTTPException:
    return HTTPException(status_code=409, detail={"error": {"code": code, "message": message}})


def create_publications_router(
    *,
    experiment_repository,
    account_repository,
    attestation_repository,
    audit_repository,
    publication_repository: PublicationRepository,
    receipt_index_repository=None,
    raw_transit=None,
    signing_key,
    credential_dep,
    zenodo_client_factory,
    pre_registration_repository=None,
    doi_mint_repository=None,
) -> APIRouter:
    router = APIRouter()

    def _own_completed_experiment(experiment_id: str, credential):
        experiment = experiment_repository.get_by_id(experiment_id)
        if experiment is None or credential.tenant_id != experiment.tenant_id:
            raise HTTPException(
                status_code=404,
                detail={"error": {"code": "experiment_not_found", "message": "no such experiment"}},
            )
        status_val = getattr(experiment.status, "value", experiment.status)
        if status_val != "completed":
            raise _typed_409(
                "experiment_not_completed", "publication actions require a completed experiment"
            )
        return experiment

    def _standing(credential) -> int:
        account = (
            account_repository.get_by_id(credential.account_id) if credential.account_id else None
        )
        standing = getattr(account, "research_standing", None)
        return int(getattr(standing, "value", standing) or 0)

    def _attestation_facts(experiment_id: str) -> dict[str, str | None]:
        att = attestation_repository.get_final(experiment_id)
        return {
            "merkle_root": getattr(att, "merkle_root", None),
            "rekor_uuid": getattr(att, "rekor_entry_uuid", None),
        }

    @router.post("/experiments/{experiment_id}/actions/authorize-benchmark-publication")
    async def authorize_benchmark_publication(
        experiment_id: str,
        body: BenchmarkPublicationRequest,
        credential=Depends(credential_dep),  # noqa: B008
    ) -> dict:
        experiment = _own_completed_experiment(experiment_id, credential)
        standing = _standing(credential)
        if standing < 1:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": {
                        "code": "research_standing_too_low",
                        "message": "benchmark publication requires research standing R1+ "
                        f"(yours: R{standing}); complete identity verification first",
                    }
                },
            )
        summary = body.model_dump()
        obs = _attestation_facts(experiment_id)
        ref = _attestation_facts(body.reference_experiment_id)
        block: dict[str, Any] = {
            "schema": AUTHORIZATION_SCHEMA,
            "action": "benchmark-publication",
            "experiment_id": experiment_id,
            "tenant_id": experiment.tenant_id,
            "publisher_pubkey": credential.pubkey_hex,
            "standing_at_issue": standing,
            "summary_sha256": hashlib.sha256(_canonical(summary)).hexdigest(),
            "issued_at": datetime.now(UTC).isoformat(),
        }
        block["coordinator_pubkey_hex"] = signing_key.pubkey_hex
        block["coordinator_signature"] = signing_key.private_key.sign(
            _canonical({k: v for k, v in block.items() if k != "coordinator_pubkey_hex"})
        ).hex()
        publication_repository.record(
            experiment_id=experiment_id,
            kind="benchmark",
            tenant_id=experiment.tenant_id,
            publisher_pubkey=credential.pubkey_hex,
            standing_at_issue=standing,
            summary=summary,
            obs_merkle_root=obs["merkle_root"],
            obs_rekor_uuid=obs["rekor_uuid"],
            ref_merkle_root=ref["merkle_root"],
            ref_rekor_uuid=ref["rekor_uuid"],
        )
        audit_repository.append(
            actor_class=CredentialClass.RESEARCHER,
            action="publication.benchmark_authorized",
            resource_type="experiment",
            resource_id=experiment_id,
            payload={"standing_at_issue": standing, **summary},
        )
        return {"authorization": block}

    @router.post("/experiments/{experiment_id}/actions/mint-doi")
    async def mint_doi(
        experiment_id: str,
        body: MintDoiRequest,
        credential=Depends(credential_dep),  # noqa: B008
    ) -> dict:
        experiment = _own_completed_experiment(experiment_id, credential)
        standing = _standing(credential)
        if standing < 3:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": {
                        "code": "research_standing_too_low",
                        "message": f"DOI issuance requires research standing R3 (yours: R{standing})",
                    }
                },
            )
        att = attestation_repository.get_final(experiment_id)
        if att is None:
            raise _typed_409("attestation_missing", "no final attestation — nothing citable yet")
        if getattr(att, "doi", None):
            raise _typed_409("doi_already_minted", f"experiment already has DOI {att.doi}")
        # Ratified TECHNICAL gate (F4/D16.2): no DOI without the prereg chain.
        if pre_registration_repository is not None:
            prereg = pre_registration_repository.get(experiment_id)
            if prereg is None:
                raise _typed_409(
                    "pre_registration_missing",
                    "the citable gate is technical: no DOI without a pre-registration chain",
                )
        # USER req #5 (ratified): benchmark-before-DOI, refused coordinator-side.
        if not publication_repository.has_benchmark_publication(experiment_id):
            raise _typed_409(
                "benchmark_publication_required",
                "publish a benchmark for this experiment before requesting a DOI",
            )
        try:
            zenodo = zenodo_client_factory()
        except Exception as e:
            raise HTTPException(
                status_code=503,
                detail={"error": {"code": "doi_registrar_not_configured", "message": str(e)}},
            ) from e
        from auspexai_platform.zenodo import ZenodoError, experiment_doi_metadata

        label = getattr(experiment, "tenant_experiment_label", None) or experiment_id
        title = body.title or f"AuspexAI verified experiment: {label}"
        rekor_url = (
            f"https://search.sigstore.dev/?uuid={att.rekor_entry_uuid}"
            if getattr(att, "rekor_entry_uuid", None)
            else None
        )
        description = (
            f"<p>Result-set attestation (Merkle root <code>{att.merkle_root}</code>) for "
            f"experiment <code>{experiment_id}</code> on the AuspexAI volunteer research "
            f"network. Metadata-and-verification record only; the evidence verifies "
            f"independently via the open AuspexAI tooling.</p>"
        )
        related = [u for u in ["https://auspexai.network/benchmarks.html", rekor_url] if u]
        # F4 (USER 2026-07-06): opted-in volunteer contributors → the DOI's
        # DataCite contributor list — the citable public credit surface. Consent
        # is the per-receipt public_attribution_at_issue snapshot (forward-only);
        # identity is the verified GitHub display_name, never a self-set name.
        contributors: list[str] = []
        if receipt_index_repository is not None:
            for acct_id in receipt_index_repository.opted_in_account_ids(experiment_id):
                acct = account_repository.get_by_id(acct_id)
                name = getattr(acct, "display_name", None)
                if name:
                    contributors.append(name)
        # The DOI's attestation.json — a SELF-CONTAINED, independently-verifiable
        # record (NOT an empty {}): the result-set root + transparency-log anchor +
        # the benchmark finding + how to verify with the open tooling. This is the
        # durable evidence the DOI cites; the Zenodo metadata only points at it.
        bench_pubs = publication_repository.list_for_experiment(experiment_id, kind="benchmark")
        verification = {
            "schema": "auspexai-doi-verification/v1",
            "experiment_id": experiment_id,
            "label": getattr(experiment, "tenant_experiment_label", None),
            "manifest_hash": getattr(experiment, "manifest_hash", None),
            "result_set": {
                "merkle_root": att.merkle_root,
                "algorithm": getattr(att, "algorithm", None),
                "unit_count": getattr(att, "unit_count", None),
            },
            "transparency_log": {
                "rekor_entry_uuid": getattr(att, "rekor_entry_uuid", None),
                "rekor_log_index": getattr(att, "rekor_log_index", None),
                "search_url": rekor_url,
            },
            "benchmark": bench_pubs[0].summary if bench_pubs else None,
            "contributors": contributors,
            "how_to_verify": (
                "Independently verifiable with the open AuspexAI tooling (auspexai-tenant, "
                "PyPI): fetch the result-set bundle, recompute the Merkle root above, and "
                "check the Rekor inclusion proof against the public transparency log. "
                "Metadata + verification only — never model content. See https://auspexai.network."
            ),
        }
        # Idempotent + resumable mint. If a prior attempt reserved a Zenodo draft
        # (persisted below via on_draft) but died before we recorded the DOI,
        # reconcile against that record instead of minting a duplicate: already
        # published → return that DOI; still a draft → resume it. Closes the
        # lost-final-response double-mint hole (a permanent duplicate + gaming
        # vector) and stops orphan drafts accumulating on retry.
        inflight = doi_mint_repository.get(experiment_id) if doi_mint_repository else None
        resume_record_id = (
            inflight.record_id if inflight and inflight.status != "published" else None
        )

        def _on_draft(record_id: str, reserved_doi: str | None) -> None:
            if doi_mint_repository is not None:
                doi_mint_repository.record_draft(
                    experiment_id,
                    attestation_id=att.attestation_id,
                    record_id=record_id,
                    reserved_doi=reserved_doi,
                    mode=zenodo.mode,
                )

        try:
            minted = zenodo.mint_doi(
                experiment_doi_metadata(
                    title=title,
                    description_html=description,
                    # Empty → the RDM-correct organizational-creator default in
                    # experiment_doi_metadata. The legacy `[{"name": ...}]` deposit
                    # shape is DROPPED by the records API on create, then rejected at
                    # publish (`metadata.creators: Missing`) — which silently failed
                    # every DOI mint at the final step (2026-07-09).
                    creators=[],
                    related_urls=related,
                    contributors=contributors,
                ),
                verification=verification,
                resume_record_id=resume_record_id,
                on_draft=_on_draft,
            )
        except ZenodoError as e:
            raise HTTPException(
                status_code=502,
                detail={"error": {"code": "doi_registrar_error", "message": str(e)}},
            ) from e
        attestation_repository.set_doi(att.attestation_id, minted["doi"])
        if doi_mint_repository is not None:
            doi_mint_repository.mark_published(
                experiment_id,
                doi=minted["doi"],
                record_url=minted.get("record_url"),
                mode=minted.get("mode"),
            )
        # Guard the ledger too: a resumed mint must not append a SECOND doi
        # publication record for the same result.
        already_recorded = bool(
            publication_repository.list_for_experiment(experiment_id, kind="doi")
        )
        if not already_recorded:
            publication_repository.record(
                experiment_id=experiment_id,
                kind="doi",
                tenant_id=experiment.tenant_id,
                publisher_pubkey=credential.pubkey_hex,
                standing_at_issue=standing,
                summary={"title": title, "mode": minted["mode"]},
                obs_merkle_root=att.merkle_root,
                obs_rekor_uuid=getattr(att, "rekor_entry_uuid", None),
                doi=minted["doi"],
            )
            audit_repository.append(
                actor_class=CredentialClass.RESEARCHER,
                action="publication.doi_minted",
                resource_type="experiment",
                resource_id=experiment_id,
                payload={
                    "doi": minted["doi"],
                    "mode": minted["mode"],
                    "standing_at_issue": standing,
                },
            )
        return {
            "doi": minted["doi"],
            "record_url": minted.get("record_url"),
            "mode": minted["mode"],
        }

    @router.get("/experiments/{experiment_id}/raw-content")
    async def collect_raw_content(
        experiment_id: str,
        credential=Depends(credential_dep),  # noqa: B008
    ) -> dict:
        """D20 (ratified 2026-07-06): collect the run's raw model outputs from
        the ephemeral transit buffer — R3-only, audited, live (buffered items
        only; raw never rests on the coordinator, so post-hoc/post-restart it is
        gone). The researcher's driver polls this DURING the run. Ownership +
        legal responsibility transfer on collection (TENANT_TERMS)."""
        exp = experiment_repository.get_by_id(experiment_id)
        if exp is None or credential.tenant_id != exp.tenant_id:
            raise HTTPException(
                status_code=404,
                detail={"error": {"code": "experiment_not_found", "message": "no such experiment"}},
            )
        if _standing(credential) < 3:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": {
                        "code": "research_standing_too_low",
                        "message": "raw-content collection requires research standing R3",
                    }
                },
            )
        if raw_transit is None:
            return {"raw": {}, "note": "raw transit buffer not configured"}
        import time as _time

        signed = raw_transit.collect_experiment_signed(
            experiment_id=experiment_id, now=_time.monotonic()
        )
        # `raw` stays the flat {result_id: text} map (backward-compatible); AUD-26
        # adds a parallel `signatures` map so the driver can verify each item's
        # detached worker signature independently of the coordinator.
        raw = {rid: it["raw"] for rid, it in signed.items()}
        signatures = {
            rid: {"raw_signature": it["raw_signature"], "worker_pubkey": it["worker_pubkey"]}
            for rid, it in signed.items()
        }
        audit_repository.append(
            actor_class=CredentialClass.RESEARCHER,
            action="raw_content.collected",
            resource_type="experiment",
            resource_id=experiment_id,
            payload={"count": len(raw)},
        )
        return {"raw": raw, "signatures": signatures, "count": len(raw)}

    @router.get("/experiments/{experiment_id}/publications")
    async def list_publications(
        experiment_id: str,
        credential=Depends(credential_dep),  # noqa: B008
    ) -> dict:
        """Console + R-D surface: the experiment's publication records.
        Maintainer sees all; a researcher sees their own experiment's."""
        experiment = experiment_repository.get_by_id(experiment_id)
        # AUD-29 (A9 audit): the Credential class field is `.kind`, not
        # `credential_class` — the old getattr always returned None, so the
        # maintainer branch was dead code and a maintainer token 404'd on every
        # experiment's publications (the console G6 panel). Use the real predicate.
        is_maintainer = credential.is_maintainer()
        if experiment is None or not (
            is_maintainer or credential.tenant_id == experiment.tenant_id
        ):
            raise HTTPException(
                status_code=404,
                detail={"error": {"code": "experiment_not_found", "message": "no such experiment"}},
            )
        return {
            "publications": [
                {
                    "record_id": r.record_id,
                    "kind": r.kind,
                    "standing_at_issue": r.standing_at_issue,
                    "summary": r.summary,
                    "obs_merkle_root": r.obs_merkle_root,
                    "obs_rekor_uuid": r.obs_rekor_uuid,
                    "ref_merkle_root": r.ref_merkle_root,
                    "ref_rekor_uuid": r.ref_rekor_uuid,
                    "doi": r.doi,
                    "created_at": r.created_at,
                }
                for r in publication_repository.list_for_experiment(experiment_id)
            ]
        }

    return router
