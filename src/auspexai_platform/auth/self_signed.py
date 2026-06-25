"""Self-keyid (proof-of-possession) verification for UNREGISTERED keys.

Some surfaces are signed by a key that is not yet registered anywhere — the
tenant-application submit, and the Tier-1 account-key bind. What they need is
proof the caller POSSESSES the private half of the key it asks the coordinator
to bind; `verify_request` still checks the Ed25519 signature against the keyid
bytes. Every other signed surface resolves keyids through the
tenant/worker/account registries instead.
"""

from __future__ import annotations

from fastapi import HTTPException, Request, status

from auspexai_platform.auth.credential import Credential, CredentialClass
from auspexai_platform.auth.errors import AuthError
from auspexai_platform.auth.signature import RequestSummary, verify_request


class _SelfKeyResolver:
    """Resolves ANY keyid to a credential carrying that keyid — deliberately
    skipping registry lookup (the key is unregistered by design here)."""

    def resolve(self, pubkey_hex: str) -> Credential:
        return Credential(kind=CredentialClass.ANONYMOUS, pubkey_hex=pubkey_hex)


_SELF_RESOLVER = _SelfKeyResolver()


async def verify_self_signed_request(request: Request) -> str:
    """Verify the RFC 9421 signature against its OWN keyid; return the keyid.

    Raises HTTPException(401) on missing headers or any signature failure,
    using the same error envelope as the standard auth dependency.
    """
    signature_input_header = request.headers.get("Signature-Input")
    signature_header = request.headers.get("Signature")
    if not signature_input_header or not signature_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": {
                    "code": "signature_required",
                    "message": (
                        "this endpoint requires an RFC 9421 signature by the calling "
                        "key (Signature-Input + Signature headers)"
                    ),
                    "details": {},
                }
            },
        )
    body = await request.body()
    summary = RequestSummary(
        method=request.method,
        path=request.url.path,
        authority=request.url.netloc,
        body=body,
        signature_input_header=signature_input_header,
        signature_header=signature_header,
        content_digest_header=request.headers.get("Content-Digest"),
    )
    try:
        credential = verify_request(summary, _SELF_RESOLVER)
    except AuthError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": e.code, "message": e.message, "details": e.details}},
        ) from e
    assert credential.pubkey_hex is not None
    return credential.pubkey_hex
