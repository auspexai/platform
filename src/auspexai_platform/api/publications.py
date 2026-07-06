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
    signing_key,
    credential_dep,
    zenodo_client_factory,
    pre_registration_repository=None,
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
            prereg = pre_registration_repository.get(experiment.manifest_hash)
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
        try:
            minted = zenodo.mint_doi(
                experiment_doi_metadata(
                    title=title,
                    description_html=description,
                    creators=[{"name": "AuspexAI Network"}],
                    related_urls=related,
                )
            )
        except ZenodoError as e:
            raise HTTPException(
                status_code=502,
                detail={"error": {"code": "doi_registrar_error", "message": str(e)}},
            ) from e
        attestation_repository.set_doi(att.attestation_id, minted["doi"])
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
            payload={"doi": minted["doi"], "mode": minted["mode"], "standing_at_issue": standing},
        )
        return {
            "doi": minted["doi"],
            "record_url": minted.get("record_url"),
            "mode": minted["mode"],
        }

    @router.get("/experiments/{experiment_id}/publications")
    async def list_publications(
        experiment_id: str,
        credential=Depends(credential_dep),  # noqa: B008
    ) -> dict:
        """Console + R-D surface: the experiment's publication records.
        Maintainer sees all; a researcher sees their own experiment's."""
        experiment = experiment_repository.get_by_id(experiment_id)
        is_maintainer = getattr(credential, "credential_class", None) == CredentialClass.MAINTAINER
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
