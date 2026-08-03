"""v0.7 — result schema v3 signs `generation_options` (the chain that ran).

Before v3 nothing in the signed evidence recorded the parameters that produced
the text. The footprint restated the manifest's DECLARATION and the serving
provider's own defaults governed every key the declaration was silent about — on
Ollama 0.30-0.32 that is `top_k 40`, `top_p 0.9` and `repeat_penalty 1.1` over a
64-token window. A bundle could therefore attest a `greedy` run the backend never
performed.

These lock the WIRE CONTRACT: the canonical v3 body is a byte-for-byte mirror of
the worker's signer, so the known-vector here is the spec the worker must match.
They also prove v0-v2 stay byte-identical (no flag day for the un-rolled fleet)
and that the signature genuinely BINDS the chain — a worker cannot sign one set
of sampler parameters and have it verify against another.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auspexai_platform.result_signature import (
    canonical_result_bytes,
    verify_result_signature,
)
from tests._result_helpers import sign_result_body

# The EXACT canonical bytes for a fully-specified v3 body. Keys sorted, compact
# separators; the chain's KEYS sort but the list ORDER is preserved (it is
# first-seen order and is meaningful).
_V3_KNOWN_VECTOR = (
    b'{"completed_at":"2026-08-03T00:00:00+00:00","exit_code":0,'
    b'"generation_options":[{"repeat_penalty":1.0,"temperature":0,"top_k":1}],'
    b'"payload":{"k":"v"},"ran_under":"strict","schema_version":3,'
    b'"served_weights":{"m":"aabb"},"unit_id":"u","worker_pubkey":"ab"}'
)

_CHAIN = [{"top_k": 1, "temperature": 0, "repeat_penalty": 1.0}]


def _common(**over):
    base = dict(
        unit_id="u",
        worker_pubkey="ab",
        completed_at="2026-08-03T00:00:00+00:00",
        exit_code=0,
        payload={"k": "v"},
        served_weights={"m": "AABB"},
        ran_under="strict",
    )
    base.update(over)
    return base


def test_v3_canonical_known_vector():
    out = canonical_result_bytes(schema_version=3, generation_options=_CHAIN, **_common())
    assert out == _V3_KNOWN_VECTOR


def test_v3_chain_list_order_is_preserved():
    """Two chains in the order the worker first saw them — sort_keys must not
    reorder the list, or a multi-chain unit's evidence would misdescribe it."""
    chains = [{"seed": 7}, {"seed": 0}]
    out = canonical_result_bytes(schema_version=3, generation_options=chains, **_common())
    assert b'"generation_options":[{"seed":7},{"seed":0}]' in out


def test_v0_v1_v2_bytes_unchanged_by_v3():
    """No flag day: an un-rolled fleet's already-signed results still verify."""
    for version in (0, 1, 2):
        without = canonical_result_bytes(schema_version=version, **_common())
        with_chain = canonical_result_bytes(
            schema_version=version, generation_options=_CHAIN, **_common()
        )
        assert without == with_chain
        assert b"generation_options" not in without


def test_empty_chain_is_still_emitted_at_v3():
    """A non-inference unit signs `[]` rather than omitting the field — the
    version, not the content, decides the body shape."""
    out = canonical_result_bytes(schema_version=3, generation_options=None, **_common())
    assert b'"generation_options":[]' in out


def test_signature_binds_the_chain():
    priv = Ed25519PrivateKey.generate()
    pub = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        .hex()
    )
    args = _common(worker_pubkey=pub)
    sign_args = {k: v for k, v in args.items() if k != "worker_pubkey"}
    sig = sign_result_body(priv, pub, schema_version=3, generation_options=_CHAIN, **sign_args)

    assert verify_result_signature(
        signature_b64=sig, schema_version=3, generation_options=_CHAIN, **_verify_args(args, pub)
    )
    # A different chain must NOT verify — otherwise the recorded parameters
    # would be unaccountable and the whole point of v3 is lost.
    tampered = [{"top_k": 40, "temperature": 0, "repeat_penalty": 1.1}]
    assert not verify_result_signature(
        signature_b64=sig,
        schema_version=3,
        generation_options=tampered,
        **_verify_args(args, pub),
    )
    # Dropping the field (claiming v2) must not verify either.
    assert not verify_result_signature(
        signature_b64=sig, schema_version=2, **_verify_args(args, pub)
    )


def _verify_args(args, pub):
    return {
        "worker_pubkey": pub,
        "unit_id": args["unit_id"],
        "completed_at": args["completed_at"],
        "exit_code": args["exit_code"],
        "payload": args["payload"],
        "served_weights": args["served_weights"],
        "ran_under": args["ran_under"],
    }
