"""Tests for the RFC 9421 Ed25519 signature verifier (+ symmetric signer).

M5 update: signature verification now goes through the DB-backed TenantRegistry.
Tests consume the `tenant_registry` fixture (DB-backed) which is already
populated by the `registered_tenant` fixture chain.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auspexai_platform.auth.errors import (
    InvalidSignatureError,
    SignatureExpiredError,
    UnsupportedAlgorithmError,
)
from auspexai_platform.auth.signature import (
    RequestSummary,
    compute_content_digest,
    parse_signature_header,
    parse_signature_input,
    sign_request,
    verify_content_digest,
    verify_request,
)
from auspexai_platform.auth.tenant_registry import TenantRegistry
from auspexai_platform.db.repositories import TenantRepository


def _make_summary(
    *,
    privkey: Ed25519PrivateKey,
    pubkey_hex: str,
    method: str = "POST",
    path: str = "/api/v0/experiments/exp-abc",
    authority: str = "coordinator.local:8080",
    body: bytes = b'{"action": "abort"}',
    created: int | None = None,
) -> RequestSummary:
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method=method,
        path=path,
        authority=authority,
        body=body,
        created=created,
    )
    return RequestSummary(
        method=method,
        path=path,
        authority=authority,
        body=body,
        signature_input_header=headers["Signature-Input"],
        signature_header=headers["Signature"],
        content_digest_header=headers.get("Content-Digest"),
    )


def test_round_trip_verifies(registered_tenant, tenant_registry: TenantRegistry) -> None:
    privkey, binding = registered_tenant
    summary = _make_summary(privkey=privkey, pubkey_hex=binding.pubkey_hex)
    credential = verify_request(summary, tenant_registry)
    assert credential.is_researcher()
    assert credential.tenant_id == binding.tenant_id
    assert credential.pubkey_hex == binding.pubkey_hex


def test_tampered_body_fails_verification(
    registered_tenant, tenant_registry: TenantRegistry
) -> None:
    privkey, binding = registered_tenant
    summary = _make_summary(privkey=privkey, pubkey_hex=binding.pubkey_hex)
    # Replace body but keep the signed Content-Digest — verifier should reject
    # via content-digest mismatch BEFORE checking the Ed25519 signature.
    tampered = RequestSummary(
        method=summary.method,
        path=summary.path,
        authority=summary.authority,
        body=summary.body + b" tampered",
        signature_input_header=summary.signature_input_header,
        signature_header=summary.signature_header,
        content_digest_header=summary.content_digest_header,
    )
    with pytest.raises(InvalidSignatureError, match="Content-Digest"):
        verify_request(tampered, tenant_registry)


def test_tampered_path_fails_verification(
    registered_tenant, tenant_registry: TenantRegistry
) -> None:
    privkey, binding = registered_tenant
    summary = _make_summary(privkey=privkey, pubkey_hex=binding.pubkey_hex)
    tampered = RequestSummary(
        method=summary.method,
        path="/api/v0/experiments/SOMEONE-ELSES",  # changed
        authority=summary.authority,
        body=summary.body,
        signature_input_header=summary.signature_input_header,
        signature_header=summary.signature_header,
        content_digest_header=summary.content_digest_header,
    )
    with pytest.raises(InvalidSignatureError, match="verification failed"):
        verify_request(tampered, tenant_registry)


def test_unknown_keyid_rejected(
    tenant_keypair: tuple[Ed25519PrivateKey, str],
    tenant_registry: TenantRegistry,
) -> None:
    """A fresh keypair, NOT registered with the registry."""
    privkey, pubkey_hex = tenant_keypair
    summary = _make_summary(privkey=privkey, pubkey_hex=pubkey_hex)
    with pytest.raises(InvalidSignatureError, match="unknown keyid"):
        verify_request(summary, tenant_registry)


def test_expired_signature_rejected(registered_tenant, tenant_registry: TenantRegistry) -> None:
    privkey, binding = registered_tenant
    long_ago = int((datetime.now(UTC) - timedelta(hours=1)).timestamp())
    summary = _make_summary(privkey=privkey, pubkey_hex=binding.pubkey_hex, created=long_ago)
    with pytest.raises(SignatureExpiredError):
        verify_request(summary, tenant_registry)


def test_clock_skew_within_window_accepted(
    registered_tenant, tenant_registry: TenantRegistry
) -> None:
    privkey, binding = registered_tenant
    # 4 minutes in the past — within the 5-minute window.
    summary = _make_summary(
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        created=int((datetime.now(UTC) - timedelta(minutes=4)).timestamp()),
    )
    credential = verify_request(summary, tenant_registry)
    assert credential.is_researcher()


def test_unsupported_algorithm_rejected(registered_tenant, tenant_registry: TenantRegistry) -> None:
    privkey, binding = registered_tenant
    summary = _make_summary(privkey=privkey, pubkey_hex=binding.pubkey_hex)
    # Swap alg in the Signature-Input header.
    sig_input = summary.signature_input_header.replace('alg="ed25519"', 'alg="rsa-pss-sha512"')
    tampered = RequestSummary(
        method=summary.method,
        path=summary.path,
        authority=summary.authority,
        body=summary.body,
        signature_input_header=sig_input,
        signature_header=summary.signature_header,
        content_digest_header=summary.content_digest_header,
    )
    with pytest.raises(UnsupportedAlgorithmError):
        verify_request(tampered, tenant_registry)


def test_missing_required_covered_component_rejected(
    registered_tenant, tenant_registry: TenantRegistry
) -> None:
    privkey, binding = registered_tenant
    body = b""
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        method="GET",
        path="/api/v0/health",
        authority="localhost",
        body=body,
        covered=("@method",),
    )
    summary = RequestSummary(
        method="GET",
        path="/api/v0/health",
        authority="localhost",
        body=body,
        signature_input_header=headers["Signature-Input"],
        signature_header=headers["Signature"],
        content_digest_header=None,
    )
    with pytest.raises(InvalidSignatureError, match="must cover"):
        verify_request(summary, tenant_registry)


def test_empty_body_does_not_require_content_digest(
    registered_tenant, tenant_registry: TenantRegistry
) -> None:
    privkey, binding = registered_tenant
    summary = _make_summary(privkey=privkey, pubkey_hex=binding.pubkey_hex, method="GET", body=b"")
    credential = verify_request(summary, tenant_registry)
    assert credential.is_researcher()


# ---- TenantRegistry façade smoke tests -------------------------------------


def test_registry_register_persists_to_db(
    tenant_repository: TenantRepository,
    tenant_registry: TenantRegistry,
) -> None:
    binding = tenant_registry.register(tenant_id="new-tenant", pubkey_hex="c" * 64)
    # Visible via the underlying repository.
    tenant = tenant_repository.get_by_pubkey("c" * 64)
    assert tenant is not None
    assert tenant.tenant_id == "new-tenant"
    # And via the registry lookup.
    assert tenant_registry.get_tenant_for_pubkey("c" * 64) == binding


def test_registry_register_rejects_duplicate(tenant_registry: TenantRegistry) -> None:
    tenant_registry.register(tenant_id="t-a", pubkey_hex="c" * 64)
    with pytest.raises(ValueError):
        tenant_registry.register(tenant_id="t-a", pubkey_hex="d" * 64)


def test_registry_get_returns_none_for_unknown(tenant_registry: TenantRegistry) -> None:
    assert tenant_registry.get_tenant_for_pubkey("e" * 64) is None


# ---- low-level parser unit tests (unchanged) -------------------------------


def test_parse_signature_input_extracts_fields() -> None:
    raw = 'sig1=("@method" "@path" "@authority");created=1716123456;alg="ed25519";keyid="abc"'
    parsed = parse_signature_input(raw)
    assert parsed.label == "sig1"
    assert parsed.covered == ("@method", "@path", "@authority")
    assert parsed.created == 1716123456
    assert parsed.alg == "ed25519"
    assert parsed.keyid == "abc"


def test_parse_signature_input_rejects_malformed() -> None:
    with pytest.raises(InvalidSignatureError):
        parse_signature_input("garbage")


def test_parse_signature_input_requires_created() -> None:
    raw = 'sig1=("@method");alg="ed25519";keyid="abc"'
    with pytest.raises(InvalidSignatureError, match="created"):
        parse_signature_input(raw)


def test_parse_signature_header_extracts_bytes() -> None:
    label, sig = parse_signature_header("sig1=:Zm9vYmFy:")
    assert label == "sig1"
    assert sig == b"foobar"


def test_compute_and_verify_content_digest_round_trip() -> None:
    body = b'{"hello": "world"}'
    header = compute_content_digest(body)
    assert header.startswith("sha-256=:")
    verify_content_digest(header, body)


def test_verify_content_digest_rejects_mismatch() -> None:
    header = compute_content_digest(b"original")
    with pytest.raises(InvalidSignatureError, match="does not match"):
        verify_content_digest(header, b"different")
