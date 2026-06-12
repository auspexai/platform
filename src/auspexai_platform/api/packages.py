"""Executor-package courier routes (§9 #40a — coordinator-served provisioning).

  POST /api/v0/packages           — RESEARCHER uploads the executor package
                                    blob (raw `.tar.gz` body).
  GET  /api/v0/packages/{digest}  — ENROLLED WORKER fetches it (streamed).

Custody posture (mirrors the evidence bundle's verify-don't-trust rule in the
upload direction): the coordinator NEVER trusts the uploader's digest claim.
The body is extracted path-traversal-safe into a throwaway temp dir, the
package digest is recomputed with the shared `compute_package_digest`
contract, and the blob is stored content-addressed only when the recomputed
digest equals the claimed `X-Package-Digest` (422 `digest_mismatch`
otherwise). Workers independently re-derive the same digest after download
(`auspexai_worker.provisioning`), so a corrupted blob fails closed at both
hops. Re-upload of an existing digest is idempotent (200 `already_exists`).

Binary-body signing (the #40a contract asked this to be verified +
documented): the RFC-9421 verifier (`auth/signature.py`) hashes the *raw
request body bytes* into `content-digest` (RFC 9530 sha-256) with no
content-type assumption — `verify_content_digest` operates on `bytes` — so a
researcher's Ed25519 signature covers the gzip body exactly as it covers
JSON. No special-casing was needed; the normal researcher credential
dependency authenticates the upload. `X-Package-Digest` is therefore NOT a
covered/signed component: it is an unauthenticated *claim* that the
coordinator independently recomputes from the signature-covered body
(signature → body bytes → extracted tree → recomputed digest must equal the
claim), so a tampered claim or body can only yield a 4xx — never a blob
stored under the wrong address.

No dispatch changes: workers decide to fetch from the manifest
`executor.package_sha256` they already receive with an assignment.

Rate limits: none — both routes are authenticated (researcher / enrolled
worker), and the documented posture (`rate_limit.py`) reserves slowapi
decorators for anonymous-public endpoints whose abuse surface auth doesn't
already bound. (No `@limiter.limit` here also means the
slowapi/future-annotations gotcha doesn't apply to this module.)
"""

from __future__ import annotations

import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from pydantic import BaseModel

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.dependency import require_worker
from auspexai_platform.db.repositories import AuditRepository
from auspexai_platform.events import EventBus
from auspexai_platform.packages import (
    InvalidPackageError,
    PackageStore,
    UnsafePackageError,
    digest_of_package_body,
)

# HTTP-level cap on the compressed upload body. Over → 413. (The extraction
# side has its own decompressed-size guard in `packages.py`.)
MAX_PACKAGE_BYTES = 64 * 1024 * 1024

_ACCEPTED_CONTENT_TYPES = frozenset({"application/gzip", "application/x-gzip"})
_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")


class PackageUploadResponse(BaseModel):
    digest: str
    size_bytes: int
    status: Literal["stored", "already_exists"]


def _error(status_code: int, code: str, message: str, details: dict | None = None) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"error": {"code": code, "message": message, "details": details or {}}},
    )


def build_router(
    credential_dep,
    audit_repository: AuditRepository,
    package_store: PackageStore,
    *,
    event_bus: EventBus | None = None,
) -> APIRouter:
    router = APIRouter()

    @router.post(
        "/packages",
        response_model=PackageUploadResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def upload_package(
        request: Request,
        response: Response,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> PackageUploadResponse:
        """Researcher uploads an executor package. Raw `.tar.gz` body; the
        `X-Package-Digest` header claims the package digest (over the
        extracted tree); the coordinator recomputes and verifies it before
        storing. 201 `stored` on first upload, 200 `already_exists` on an
        idempotent re-upload of the same digest."""
        if not credential.is_researcher() or not credential.tenant_id:
            raise _error(
                status.HTTP_403_FORBIDDEN,
                "researcher_required",
                "a researcher credential is required to upload an executor package",
                {"credential_class": credential.kind.value},
            )

        # The credential dependency already buffered the body for signature
        # verification (Starlette caches it on the Request), so this is a
        # re-read of the in-memory bytes, not a second network read.
        body = await request.body()
        if len(body) > MAX_PACKAGE_BYTES:
            raise _error(
                status.HTTP_413_CONTENT_TOO_LARGE,
                "package_too_large",
                f"package body exceeds the {MAX_PACKAGE_BYTES}-byte cap",
                {"size_bytes": len(body), "max_bytes": MAX_PACKAGE_BYTES},
            )

        content_type = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
        if content_type not in _ACCEPTED_CONTENT_TYPES:
            raise _error(
                status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "package upload body must be Content-Type: application/gzip",
                {"content_type": content_type or None},
            )

        claimed = (request.headers.get("X-Package-Digest") or "").strip().lower()
        if not _DIGEST_RE.match(claimed):
            raise _error(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "invalid_package_digest_header",
                "X-Package-Digest header is required and must be 64 lowercase hex chars "
                "(the compute_package_digest over the extracted package tree)",
            )

        try:
            computed = digest_of_package_body(body)
        except UnsafePackageError as e:
            raise _error(
                status.HTTP_400_BAD_REQUEST,
                "unsafe_package",
                f"archive rejected: {e.message}",
            ) from e
        except InvalidPackageError as e:
            raise _error(
                status.HTTP_400_BAD_REQUEST,
                "invalid_package",
                f"archive rejected: {e.message}",
            ) from e

        if computed != claimed:
            raise _error(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "digest_mismatch",
                "recomputed package digest does not match the X-Package-Digest claim",
                {"claimed": claimed, "computed": computed},
            )

        stored_new = package_store.put(computed, body)
        audit_repository.append(
            actor_class=CredentialClass.RESEARCHER,
            actor_identifier=credential.pubkey_hex,
            actor_tenant_id=credential.tenant_id,
            action="package.uploaded",
            resource_type="package",
            resource_id=computed,
            payload={
                "digest": computed,
                "tenant": credential.tenant_id,
                "size_bytes": len(body),
                "already_exists": not stored_new,
            },
        )
        if stored_new and event_bus is not None:
            event_bus.publish(
                "package.uploaded",
                experiment_id=None,
                data={"digest": computed, "tenant_id": credential.tenant_id},
            )

        if not stored_new:
            response.status_code = status.HTTP_200_OK
        return PackageUploadResponse(
            digest=computed,
            size_bytes=len(body),
            status="stored" if stored_new else "already_exists",
        )

    @router.get("/packages/{digest}")
    async def fetch_package(
        digest: str,
        credential: Credential = Depends(credential_dep),  # noqa: B008
    ) -> FileResponse:
        """Enrolled worker fetches a package blob by digest. Streams the
        stored `.tar.gz`; 404 on unknown digest. The address space is exactly
        64-hex digests, so a malformed `digest` is definitionally unknown
        (404) — and never touches the filesystem."""
        require_worker(credential)
        if not _DIGEST_RE.match(digest):
            raise _error(
                status.HTTP_404_NOT_FOUND,
                "package_not_found",
                "no package stored under this digest",
            )
        blob_path = package_store.path_for(digest)
        if not blob_path.is_file():
            raise _error(
                status.HTTP_404_NOT_FOUND,
                "package_not_found",
                "no package stored under this digest",
            )
        return FileResponse(
            blob_path,
            media_type="application/gzip",
            filename=f"{digest}.tar.gz",
        )

    return router
