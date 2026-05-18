"""RFC 9421 HTTP Message Signatures — Ed25519 verifier (and matching signer).

The coordinator accepts a deliberately narrow subset of RFC 9421:

  - Algorithm: ed25519 only. Anything else → UnsupportedAlgorithmError.
  - Covered components (fixed list): @method, @path, @authority, content-digest,
    @signature-params (the last automatically by RFC 9421 rules).
  - `created` (Unix timestamp) is REQUIRED. Coordinator rejects signatures
    older than `CREATED_WINDOW` seconds.
  - `keyid` is the lowercase hex Ed25519 public key (64 chars). The coordinator
    looks it up in the tenant registry; unknown keys → InvalidSignatureError.
  - One signature per request (label `sig1`). Multi-signature is not supported.
  - No `nonce`. The `created` window is the only replay defense for v0.

The `content-digest` field carries SHA-256 of the request body (per RFC 9530)
and is REQUIRED on non-empty bodies. For GET / DELETE with empty body, callers
MAY omit it; if present it must validate.

The signer (`build_signature_input` + `sign_request`) is the symmetric pair —
exposed here so tests and the SDK can sign requests using the same canonical-
ization the coordinator verifies. The SDK currently has Ed25519 keys but no
HTTP-signing helper; that helper will live in the SDK and call `sign_request`
or replicate its logic (decision deferred to SDK task #12).

Note on canonicalization: this implementation hand-rolls the SF subset we need
(quoted strings, inner-list of strings, dict-style parameters) rather than
depending on `http-message-signatures` or `httpsig`. Reasons: pinned algorithm
set keeps the surface narrow; no need for the structured-fields library; the
SDK's existing crypto layer goes straight to `cryptography` so this matches.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from auspexai_platform.auth.credential import Credential
from auspexai_platform.auth.errors import (
    InvalidSignatureError,
    SignatureExpiredError,
    UnsupportedAlgorithmError,
)
from auspexai_platform.auth.tenant_registry import TenantRegistry

CREATED_WINDOW = timedelta(minutes=5)
SUPPORTED_ALG = "ed25519"
SIGNATURE_LABEL = "sig1"

# Components the verifier *requires* in every signature.
REQUIRED_COVERED: tuple[str, ...] = ("@method", "@path", "@authority")
# `content-digest` is conditionally required (when body is non-empty).
CONDITIONAL_COVERED: str = "content-digest"


@dataclass(frozen=True)
class ParsedSignatureInput:
    """The structured contents of a Signature-Input header value."""

    label: str
    covered: tuple[str, ...]
    created: int
    alg: str
    keyid: str
    # The raw covered/params string, used verbatim in the signature base.
    raw_covered_and_params: str


# ---- Signature-Input / Signature header parsing -----------------------------

# Pattern matching `label=(...)<params>`. The covered list is `("a" "b" "c")`;
# params follow as `;key=value` repeated.
_SIG_INPUT_HEAD = re.compile(
    r"^(?P<label>[A-Za-z0-9_-]+)=(?P<rest>\(.*\))(?P<params>(?:;[^;]+)*)\s*$"
)
_COVERED_LIST = re.compile(r'^\(\s*((?:"[^"]+"\s*)*)\)$')
_PARAM_KV = re.compile(r";\s*([A-Za-z0-9_-]+)\s*=\s*([^;]+?)\s*(?=$|;)")


def parse_signature_input(header_value: str) -> ParsedSignatureInput:
    """Parse a Signature-Input header value.

    Example:
        sig1=("@method" "@path" "@authority" "content-digest");created=1716123456;alg="ed25519";keyid="abc..."
    """
    match = _SIG_INPUT_HEAD.match(header_value.strip())
    if not match:
        raise InvalidSignatureError("malformed Signature-Input header")
    label = match.group("label")
    covered_part = match.group("rest")
    params_part = match.group("params")

    covered_match = _COVERED_LIST.match(covered_part)
    if not covered_match:
        raise InvalidSignatureError("malformed covered-components list")
    items = [m.strip('"') for m in covered_match.group(1).split()]
    if not items:
        raise InvalidSignatureError("covered-components list is empty")

    params: dict[str, str] = {}
    for key, raw_value in _PARAM_KV.findall(params_part):
        value = raw_value.strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        params[key.lower()] = value

    try:
        created = int(params["created"])
    except KeyError:
        raise InvalidSignatureError("missing required `created` parameter") from None
    except ValueError as e:
        raise InvalidSignatureError(f"`created` is not an integer: {e}") from e

    alg = params.get("alg", "")
    keyid = params.get("keyid", "")

    if not alg:
        raise InvalidSignatureError("missing required `alg` parameter")
    if not keyid:
        raise InvalidSignatureError("missing required `keyid` parameter")

    return ParsedSignatureInput(
        label=label,
        covered=tuple(items),
        created=created,
        alg=alg.lower(),
        keyid=keyid.lower(),
        raw_covered_and_params=covered_part + params_part,
    )


_SIG_HEADER = re.compile(r"^(?P<label>[A-Za-z0-9_-]+)=:(?P<b64>[A-Za-z0-9+/=]+):\s*$")


def parse_signature_header(header_value: str) -> tuple[str, bytes]:
    """Parse a Signature header. Returns (label, raw signature bytes)."""
    match = _SIG_HEADER.match(header_value.strip())
    if not match:
        raise InvalidSignatureError("malformed Signature header")
    label = match.group("label")
    try:
        sig_bytes = base64.b64decode(match.group("b64"), validate=True)
    except (ValueError, base64.binascii.Error) as e:
        raise InvalidSignatureError(f"Signature value is not valid base64: {e}") from e
    return label, sig_bytes


# ---- content-digest ---------------------------------------------------------

_CONTENT_DIGEST = re.compile(r"^sha-256=:(?P<b64>[A-Za-z0-9+/=]+):\s*$")


def compute_content_digest(body: bytes) -> str:
    """Build a Content-Digest header value for `body`. RFC 9530 `sha-256` only."""
    digest = hashlib.sha256(body).digest()
    return f"sha-256=:{base64.b64encode(digest).decode('ascii')}:"


def verify_content_digest(header_value: str, body: bytes) -> None:
    """Raise InvalidSignatureError if the digest header doesn't match the body."""
    match = _CONTENT_DIGEST.match(header_value.strip())
    if not match:
        raise InvalidSignatureError(
            "Content-Digest header is malformed or uses unsupported algorithm"
        )
    try:
        claimed = base64.b64decode(match.group("b64"), validate=True)
    except (ValueError, base64.binascii.Error) as e:
        raise InvalidSignatureError(f"Content-Digest is not valid base64: {e}") from e
    actual = hashlib.sha256(body).digest()
    if claimed != actual:
        raise InvalidSignatureError("Content-Digest does not match request body")


# ---- signature base construction --------------------------------------------


def build_signature_base(
    *,
    parsed: ParsedSignatureInput,
    method: str,
    path: str,
    authority: str,
    content_digest_header: str | None,
) -> bytes:
    """Reconstruct the signature base bytes per RFC 9421 §2.5.

    Each covered component becomes one line: `"<name>": <value>\n`. The final
    line is `"@signature-params": <verbatim covered+params from Signature-Input>`.
    """
    lines: list[str] = []
    for component in parsed.covered:
        if component == "@method":
            lines.append(f'"@method": {method.upper()}')
        elif component == "@path":
            lines.append(f'"@path": {path}')
        elif component == "@authority":
            lines.append(f'"@authority": {authority.lower()}')
        elif component == "content-digest":
            if content_digest_header is None:
                raise InvalidSignatureError(
                    "Signature-Input covers `content-digest` but the request "
                    "has no Content-Digest header"
                )
            lines.append(f'"content-digest": {content_digest_header.strip()}')
        else:
            raise InvalidSignatureError(
                f"unsupported covered component {component!r} (v0 supports "
                "@method, @path, @authority, content-digest)"
            )
    lines.append(f'"@signature-params": {parsed.raw_covered_and_params}')
    return "\n".join(lines).encode("utf-8")


# ---- verification + signing -------------------------------------------------


@dataclass(frozen=True)
class RequestSummary:
    """The HTTP-level inputs the verifier needs. Decoupled from FastAPI's
    Request to keep this module testable without a request lifecycle."""

    method: str
    path: str
    authority: str
    body: bytes
    signature_input_header: str
    signature_header: str
    content_digest_header: str | None


def verify_request(
    request: RequestSummary,
    registry: TenantRegistry,
    *,
    now: datetime | None = None,
    created_window: timedelta = CREATED_WINDOW,
) -> Credential:
    """Verify an RFC 9421-signed request. Returns the resulting Credential.

    Raises:
        InvalidSignatureError — bad signature, unknown keyid, body digest mismatch.
        SignatureExpiredError — `created` outside the accepted window.
        UnsupportedAlgorithmError — `alg` is not `ed25519`.
    """
    parsed = parse_signature_input(request.signature_input_header)
    label, sig_bytes = parse_signature_header(request.signature_header)

    if label != parsed.label:
        raise InvalidSignatureError(
            f"Signature label {label!r} does not match Signature-Input label {parsed.label!r}"
        )

    if parsed.alg != SUPPORTED_ALG:
        raise UnsupportedAlgorithmError(
            f"unsupported algorithm {parsed.alg!r}; coordinator v0 accepts only {SUPPORTED_ALG!r}"
        )

    # Required-coverage check.
    for required in REQUIRED_COVERED:
        if required not in parsed.covered:
            raise InvalidSignatureError(
                f"Signature-Input must cover {required!r} (covered={parsed.covered})"
            )
    if request.body and CONDITIONAL_COVERED not in parsed.covered:
        raise InvalidSignatureError(
            "Signature-Input must cover 'content-digest' when the request body is non-empty"
        )

    # Body digest check (only meaningful if content-digest is covered).
    if CONDITIONAL_COVERED in parsed.covered and request.content_digest_header:
        verify_content_digest(request.content_digest_header, request.body)

    # Created-window check.
    now = now or datetime.now(UTC)
    created_dt = datetime.fromtimestamp(parsed.created, tz=UTC)
    age = now - created_dt
    if age > created_window or age < -created_window:
        raise SignatureExpiredError(
            f"signature `created` is {age.total_seconds():.0f}s from server clock; "
            f"window is +/- {created_window.total_seconds():.0f}s",
            details={"created": parsed.created, "server_time": int(now.timestamp())},
        )

    # Resolve pubkey → tenant.
    binding = registry.get_tenant_for_pubkey(parsed.keyid)
    if binding is None:
        raise InvalidSignatureError(
            f"unknown keyid {parsed.keyid!r}; tenant must register the pubkey before signing requests"
        )

    # Verify Ed25519 signature over the canonical base.
    base = build_signature_base(
        parsed=parsed,
        method=request.method,
        path=request.path,
        authority=request.authority,
        content_digest_header=request.content_digest_header,
    )
    try:
        pubkey = Ed25519PublicKey.from_public_bytes(bytes.fromhex(parsed.keyid))
    except ValueError as e:
        raise InvalidSignatureError(f"keyid is not a valid 32-byte Ed25519 pubkey: {e}") from e
    try:
        pubkey.verify(sig_bytes, base)
    except InvalidSignature as e:
        raise InvalidSignatureError("Ed25519 verification failed") from e

    return Credential.researcher(tenant_id=binding.tenant_id, pubkey_hex=parsed.keyid)


# ---- signing (for tests + the eventual SDK helper) --------------------------


def sign_request(
    *,
    privkey: Ed25519PrivateKey,
    pubkey_hex: str,
    method: str,
    path: str,
    authority: str,
    body: bytes,
    created: int | None = None,
    covered: tuple[str, ...] | None = None,
) -> dict[str, str]:
    """Produce Signature-Input + Signature (+ Content-Digest if body non-empty)
    headers for an Ed25519-signed request. Symmetric to `verify_request`.

    Returns a dict suitable for direct use as `request.headers` extension.
    """
    if created is None:
        created = int(datetime.now(UTC).timestamp())
    if covered is None:
        covered = ("@method", "@path", "@authority") + (("content-digest",) if body else ())

    covered_list = " ".join(f'"{c}"' for c in covered)
    raw_covered_and_params = (
        f'({covered_list});created={created};alg="{SUPPORTED_ALG}";keyid="{pubkey_hex.lower()}"'
    )
    signature_input_value = f"{SIGNATURE_LABEL}={raw_covered_and_params}"
    parsed = ParsedSignatureInput(
        label=SIGNATURE_LABEL,
        covered=tuple(covered),
        created=created,
        alg=SUPPORTED_ALG,
        keyid=pubkey_hex.lower(),
        raw_covered_and_params=raw_covered_and_params,
    )

    content_digest_header: str | None = None
    if "content-digest" in covered:
        content_digest_header = compute_content_digest(body)

    base = build_signature_base(
        parsed=parsed,
        method=method,
        path=path,
        authority=authority,
        content_digest_header=content_digest_header,
    )
    sig = privkey.sign(base)
    sig_value = f"{SIGNATURE_LABEL}=:{base64.b64encode(sig).decode('ascii')}:"

    headers = {
        "Signature-Input": signature_input_value,
        "Signature": sig_value,
    }
    if content_digest_header:
        headers["Content-Digest"] = content_digest_header
    return headers
