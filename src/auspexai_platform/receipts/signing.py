"""Receipt signing — persistent Ed25519 key + minimal RFC 9052 COSE Sign1.

The coordinator's receipt-signing key is **persistent** across restarts.
On first startup, generate an Ed25519 keypair and write the private key
to `<state_dir>/coordinator_receipt_signing_key.pem` at file mode `0600`.
On subsequent startups, load that file. The same key signs all receipts
until an explicit rotation event (e.g., the §5.16 Fulcio-attestation
ceremony, which either re-anchors the same key or replaces it with a
freshly-generated attested key).

Why persistent and not ephemeral: receipts are persistent citable
records. An ephemeral key would make every receipt signed before a
restart unverifiable after restart — breaking the trust property at
the core of §6.8.1.

We use a minimal in-house COSE Sign1 implementation (~80 LOC) rather
than pull in pycose. The Sign1 structure is tightly specified by
RFC 9052 §4.1 and Ed25519 (alg=-8) is the only algorithm we need;
rolling it keeps the dependency surface small.

COSE Sign1 wire shape:

    COSE_Sign1 = [
      protected   : bstr (canonical-CBOR-encoded map),
      unprotected : map,
      payload     : bstr / nil,
      signature   : bstr,
    ]

Signature is over Sig_structure:

    Sig_structure = [
      context           : "Signature1",
      body_protected    : bstr (same as COSE_Sign1.protected),
      external_aad      : bstr (empty for our use),
      payload           : bstr,
    ]
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# COSE algorithm identifiers (RFC 8152 §16.4.1)
_COSE_ALG_EDDSA = -8
# COSE header label codes (RFC 9052 §3.1)
_COSE_HEADER_ALG = 1
_COSE_HEADER_KID = 4


class CoseDecodeError(Exception):
    """Raised when a COSE_Sign1 blob is malformed (wrong shape, bad CBOR, etc)."""


class CoseVerificationError(Exception):
    """Raised when a COSE_Sign1 signature does not verify against the given key."""


@dataclass(frozen=True)
class SigningKey:
    """The coordinator's receipt-signing key.

    Holds the private key for signing and exposes the public key + its
    lowercase-hex form for embedding into COSE headers + storing alongside
    each receipt row (so verifiers can identify which key signed a given
    receipt without needing additional out-of-band lookups).
    """

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    pubkey_hex: str

    @classmethod
    def _from_private(cls, private_key: Ed25519PrivateKey) -> SigningKey:
        public_key = private_key.public_key()
        pubkey_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return cls(
            private_key=private_key,
            public_key=public_key,
            pubkey_hex=pubkey_bytes.hex(),
        )


def load_or_generate_signing_key(path: Path) -> SigningKey:
    """Load the coordinator's receipt-signing key, generating it on first call.

    The key is written PEM-encoded at file mode `0600` (root-only readable
    by the coordinator's run-as user). Parent directory is created if
    missing. If the file already exists, it's read in and parsed; mismatch
    or corruption raises ValueError.
    """
    path = Path(path)
    if path.exists():
        private_pem = path.read_bytes()
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError(
                f"signing key at {path} is not an Ed25519 private key "
                f"(got {type(private_key).__name__})"
            )
        return SigningKey._from_private(private_key)

    # First startup: generate, persist, return.
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Write to a temp file then rename — atomic against partial-write races.
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(pem)
    tmp.chmod(0o600)
    tmp.replace(path)
    return SigningKey._from_private(private_key)


def _protected_header_bytes(pubkey_hex: str) -> bytes:
    """Canonical CBOR-encoded protected header.

    Algorithm and kid go in the protected header because verifiers need
    both to make a trust decision and a tampering attempt should
    invalidate the signature.
    """
    header_map = {
        _COSE_HEADER_ALG: _COSE_ALG_EDDSA,
        _COSE_HEADER_KID: pubkey_hex.encode("ascii"),
    }
    return cbor2.dumps(header_map, canonical=True)


def _sig_structure(protected_bytes: bytes, payload: bytes) -> bytes:
    """Build the Sig_structure bytes per RFC 9052 §4.4."""
    return cbor2.dumps(
        ["Signature1", protected_bytes, b"", payload],
        canonical=True,
    )


def cose_sign1_encode(*, payload: bytes, signing_key: SigningKey) -> bytes:
    """Wrap a payload in a COSE_Sign1 structure, signed by `signing_key`.

    Args:
        payload: The raw bytes to sign (typically `encode_cbor(receipt)`).
        signing_key: The persistent coordinator signing key.

    Returns:
        Canonical CBOR-encoded COSE_Sign1 bytes.
    """
    protected = _protected_header_bytes(signing_key.pubkey_hex)
    to_sign = _sig_structure(protected, payload)
    signature = signing_key.private_key.sign(to_sign)
    cose_sign1 = [protected, {}, payload, signature]
    return cbor2.dumps(cose_sign1, canonical=True)


def cose_sign1_decode(
    cose_bytes: bytes,
    *,
    expected_pubkey: Ed25519PublicKey | None = None,
) -> tuple[bytes, str]:
    """Decode a COSE_Sign1 blob, optionally verifying its signature.

    Args:
        cose_bytes: The COSE_Sign1 bytes produced by `cose_sign1_encode`.
        expected_pubkey: If supplied, verify the signature against this
            key. If None, the signature is NOT verified — caller is
            expected to either trust the kid header or perform out-of-band
            verification.

    Returns:
        (payload_bytes, kid_string) — the inner payload and the key
        identifier from the protected header (which is the signer's
        pubkey hex per our convention).

    Raises:
        CoseDecodeError: malformed input.
        CoseVerificationError: `expected_pubkey` supplied but signature
            doesn't verify.
    """
    try:
        outer = cbor2.loads(cose_bytes)
    except cbor2.CBORDecodeError as exc:
        raise CoseDecodeError(f"COSE_Sign1 outer CBOR malformed: {exc}") from exc
    if not isinstance(outer, list) or len(outer) != 4:
        raise CoseDecodeError(
            f"COSE_Sign1 must be a 4-element array, got {type(outer).__name__} "
            f"len={len(outer) if hasattr(outer, '__len__') else 'n/a'}"
        )
    protected_bytes, _unprotected, payload, signature = outer
    if not isinstance(protected_bytes, bytes) or not isinstance(payload, bytes):
        raise CoseDecodeError("COSE_Sign1 protected and payload must be byte strings")
    if not isinstance(signature, bytes):
        raise CoseDecodeError("COSE_Sign1 signature must be a byte string")
    try:
        protected_map = cbor2.loads(protected_bytes) if protected_bytes else {}
    except cbor2.CBORDecodeError as exc:
        raise CoseDecodeError(f"COSE_Sign1 protected header malformed: {exc}") from exc
    if not isinstance(protected_map, dict):
        raise CoseDecodeError(
            f"COSE_Sign1 protected header must be a CBOR map, got {type(protected_map).__name__}"
        )
    alg = protected_map.get(_COSE_HEADER_ALG)
    if alg != _COSE_ALG_EDDSA:
        raise CoseDecodeError(f"COSE_Sign1 alg must be EdDSA ({_COSE_ALG_EDDSA}), got {alg!r}")
    kid_raw = protected_map.get(_COSE_HEADER_KID)
    if not isinstance(kid_raw, (bytes, bytearray)):
        raise CoseDecodeError(f"COSE_Sign1 kid must be bytes, got {type(kid_raw).__name__}")
    kid = bytes(kid_raw).decode("ascii")

    if expected_pubkey is not None:
        to_verify = _sig_structure(protected_bytes, payload)
        try:
            expected_pubkey.verify(signature, to_verify)
        except InvalidSignature as exc:
            raise CoseVerificationError(
                "COSE_Sign1 signature does not verify against the given key"
            ) from exc

    return payload, kid
