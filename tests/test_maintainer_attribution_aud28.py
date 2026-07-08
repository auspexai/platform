"""AUD-28 (A9 audit) — X-Maintainer-Login audit-attribution attack surface.

The trusted-proxy header may name the individual maintainer behind a request
ONLY when the presented bearer is the login-less SERVICE/root token (the
operator console's trusted proxy). A per-maintainer token (`token issue`) is
already bound to its owner; its holder must NOT be able to rewrite the audit
actor via the header — that would defeat per-maintainer non-repudiation.
"""

from __future__ import annotations

from pathlib import Path

from starlette.requests import Request

from auspexai_platform.auth.bearer import TokenStore
from auspexai_platform.auth.credential import CredentialClass
from auspexai_platform.auth.dependency import make_credential_dependency


def _store(tmp_path: Path) -> TokenStore:
    store = TokenStore(tmp_path / "maintainer.token")
    store.initialize()  # the login-less service/root token
    return store


def _request(headers: dict[str, str]) -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v0/accounts/x/suspend",
            "query_string": b"",
            "headers": raw,
        }
    )


async def _resolve(store: TokenStore, headers: dict[str, str]):
    # The bearer path never touches the resolver, so a stand-in is fine here.
    get_credential = make_credential_dependency(store, resolver=None)
    return await get_credential(_request(headers))


async def test_per_maintainer_token_header_cannot_impersonate(tmp_path: Path) -> None:
    store = _store(tmp_path)
    alice = store.issue(login="alice")
    cred = await _resolve(store, {"Authorization": f"Bearer {alice}", "X-Maintainer-Login": "bob"})
    assert cred.kind == CredentialClass.MAINTAINER
    # The header is IGNORED for a bound token: attribution stays alice, not bob.
    assert cred.maintainer_login == "alice"


async def test_per_maintainer_token_attributes_to_own_login(tmp_path: Path) -> None:
    store = _store(tmp_path)
    alice = store.issue(login="alice")
    cred = await _resolve(store, {"Authorization": f"Bearer {alice}"})
    assert cred.maintainer_login == "alice"


async def test_service_token_honors_proxy_header(tmp_path: Path) -> None:
    # The console's login-less service token supplies the actor via the header.
    store = _store(tmp_path)
    root = store.active_tokens()[0]
    cred = await _resolve(store, {"Authorization": f"Bearer {root}", "X-Maintainer-Login": "carol"})
    assert cred.maintainer_login == "carol"


async def test_service_token_without_header_has_no_specific_login(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = store.active_tokens()[0]
    cred = await _resolve(store, {"Authorization": f"Bearer {root}"})
    assert cred.maintainer_login is None
