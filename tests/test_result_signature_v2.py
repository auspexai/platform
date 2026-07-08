"""A2 #32 — result schema v2 signs `ran_under` (the containment claim).

These lock the WIRE CONTRACT: the canonical v2 body is a byte-for-byte mirror of
the worker's signer, so the known-vector here is the spec the worker must match.
They also prove (a) v0/v1 stay byte-identical — no flag day for the un-rolled
fleet — and (b) the signature genuinely BINDS ran_under, so a worker can't sign
"strict" and have it verify against a "permissive" claim (the accountability the
flip's containment guard rests on).
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auspexai_platform.result_signature import (
    canonical_raw_bytes,
    canonical_result_bytes,
    verify_raw_signature,
    verify_result_signature,
)
from tests._result_helpers import sign_result_body

# The EXACT canonical bytes for a fully-specified v2 body — the worker's
# canonical_result_bytes MUST produce these same bytes. Keys sorted, compact
# separators, ran_under + served-weights-value lower-cased.
_V2_KNOWN_VECTOR = (
    b'{"completed_at":"2026-06-19T00:00:00+00:00","exit_code":0,'
    b'"payload":{"k":"v"},"ran_under":"strict","schema_version":2,'
    b'"served_weights":{"m":"aabb"},"unit_id":"u","worker_pubkey":"ab"}'
)


def test_v2_canonical_known_vector():
    """Pin the exact v2 wire bytes (drift guard vs the worker signer). Note
    ran_under is lower-cased ("STRICT" -> "strict")."""
    out = canonical_result_bytes(
        unit_id="u",
        worker_pubkey="ab",
        completed_at="2026-06-19T00:00:00+00:00",
        exit_code=0,
        payload={"k": "v"},
        schema_version=2,
        served_weights={"m": "AABB"},
        ran_under="STRICT",
    )
    assert out == _V2_KNOWN_VECTOR


def test_v0_and_v1_unchanged_by_ran_under():
    """Backward-compat: ran_under is ignored below v2, so an un-rolled v0/v1 fleet
    signs byte-identical bodies — no flag day."""
    common = dict(
        unit_id="u",
        worker_pubkey="ab",
        completed_at="2026-06-19T00:00:00+00:00",
        exit_code=0,
        payload={"k": "v"},
    )
    assert canonical_result_bytes(**common, schema_version=0, ran_under="strict") == (
        canonical_result_bytes(**common, schema_version=0)
    )
    assert canonical_result_bytes(
        **common, schema_version=1, served_weights={"m": "aabb"}, ran_under="strict"
    ) == canonical_result_bytes(**common, schema_version=1, served_weights={"m": "aabb"})


def test_v2_binds_ran_under_distinct_bytes():
    """The signature input differs by ran_under, so strict and permissive are not
    interchangeable under one signature."""
    common = dict(
        unit_id="u",
        worker_pubkey="ab",
        completed_at="2026-06-19T00:00:00+00:00",
        exit_code=0,
        payload={"k": "v"},
        schema_version=2,
        served_weights={"m": "aabb"},
    )
    assert canonical_result_bytes(**common, ran_under="strict") != canonical_result_bytes(
        **common, ran_under="permissive"
    )


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub_hex = (
        priv.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    return priv, pub_hex


def test_v2_roundtrip_verifies_and_tampered_ran_under_fails():
    """A v2 signature over ran_under='strict' verifies as strict, and does NOT
    verify if re-checked as 'permissive' — a worker is bound to what it signed."""
    priv, pub_hex = _keypair()
    body = dict(
        unit_id="u-1",
        completed_at="2026-06-19T00:00:00+00:00",
        exit_code=0,
        payload={"x": 1},
        schema_version=2,
        served_weights={"m": "aabb"},
    )
    sig = sign_result_body(priv, pub_hex, **body, ran_under="strict")

    assert verify_result_signature(
        worker_pubkey=pub_hex, signature_b64=sig, **body, ran_under="strict"
    )
    # Same signature, but the coordinator checks it as a permissive claim → fails.
    assert not verify_result_signature(
        worker_pubkey=pub_hex, signature_b64=sig, **body, ran_under="permissive"
    )


# ── AUD-26: detached raw-content signature (byte-for-byte worker mirror) ────────

# The EXACT canonical bytes for the detached raw body — the worker's
# canonical_raw_bytes MUST produce these same bytes (sha256("hi"), keys sorted,
# worker_pubkey lower-cased).
_RAW_KNOWN_VECTOR = (
    b'{"raw_response_sha256":'
    b'"8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",'
    b'"unit_id":"u","worker_pubkey":"ab"}'
)


def test_raw_canonical_known_vector():
    assert (
        canonical_raw_bytes(unit_id="u", worker_pubkey="AB", raw_response="hi") == _RAW_KNOWN_VECTOR
    )


def test_raw_signature_roundtrip_and_tamper():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw().hex()
    raw = "some untrusted model text"
    sig = base64.b64encode(
        priv.sign(canonical_raw_bytes(unit_id="u1", worker_pubkey=pub, raw_response=raw))
    ).decode()
    assert verify_raw_signature(
        worker_pubkey=pub, signature_b64=sig, unit_id="u1", raw_response=raw
    )
    # tampered raw ⇒ different digest ⇒ signature no longer verifies
    assert not verify_raw_signature(
        worker_pubkey=pub, signature_b64=sig, unit_id="u1", raw_response=raw + "!"
    )
    # wrong unit binding ⇒ fails
    assert not verify_raw_signature(
        worker_pubkey=pub, signature_b64=sig, unit_id="u2", raw_response=raw
    )
    # malformed signature ⇒ False, never raises
    assert not verify_raw_signature(
        worker_pubkey=pub, signature_b64="!!!", unit_id="u1", raw_response=raw
    )
