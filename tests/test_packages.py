"""§9 #40a — executor-package courier (coordinator-served provisioning).

Covers the pinned contract:
  - the digest cross-test: platform's `compute_package_digest` reproduces
    GOLDEN digests computed from the tenant-SDK and worker reference
    implementations on known fixture trees (byte-for-byte format contract),
  - upload happy path (researcher-signed binary body, audit + firehose event),
  - 422 digest_mismatch, 400 traversal/symlink/absolute-path rejection,
  - 413 size cap, idempotent re-upload (200 already_exists),
  - researcher-only upload (worker/anon 403), worker-only fetch
    (researcher/anon 403), 404 unknown digest,
  - the full round-trip: upload → worker fetch → extract → digest matches.

The binary body rides the NORMAL RFC-9421 researcher signature: the verifier
hashes raw body bytes into `content-digest` with no content-type assumption,
so `sign_request` over the gzip bytes is all the upload needs.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from auspexai_platform.auth.signature import sign_request
from auspexai_platform.events import GLOBAL
from auspexai_platform.packages import (
    InvalidPackageError,
    UnsafePackageError,
    compute_package_digest,
    extract_package,
)

# ---- fixture trees + golden digests ------------------------------------------
#
# GOLDEN values were computed by running BOTH reference implementations —
# `auspexai_tenant.manifest.compute_package_digest` (tenant-sdk) and
# `auspexai_worker.provisioning.compute_package_digest` (worker) — over these
# exact trees. All three implementations must agree byte-for-byte; if this
# test breaks, the platform reimplementation has drifted from the shared
# format contract (do NOT update the goldens without re-deriving them from
# the SDK/worker implementations).

SIMPLE_TREE = {
    "run.py": b"print('hello')\n",
    "data/params.json": b'{"alpha": 1}',
}
SIMPLE_GOLDEN = "2b77633789e8318eae0573ba294e09a9e7357210ca2aca1c910179e6232ab665"

# Same payload files as EQUIV_TREE plus every excluded class: top-level
# manifest.json / manifest.json.sig, a *.pyc outside __pycache__, and a
# __pycache__/ dir (whose NON-pyc contents are excluded too).
WITH_EXCLUDED_TREE = {
    **SIMPLE_TREE,
    "lib/util.py": b"X = 1\n",
    "manifest.json": b'{"schema_version": "0.1"}',
    "manifest.json.sig": b"sig-bytes",
    "__pycache__/run.cpython-312.pyc": b"\x00\x01",
    "__pycache__/notes.txt": b"inside pycache",
    "lib/util.pyc": b"\x02\x03",
}
EQUIV_TREE = {**SIMPLE_TREE, "lib/util.py": b"X = 1\n"}
EXCLUDED_GOLDEN = "e6d9d4e8c7270c24026fc9a6232b281730ed886126384070bf44e7c62ee2ef46"


def _build_tree(root: Path, tree: dict[str, bytes]) -> None:
    for rel, data in tree.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def _tar_gz(tree: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel in sorted(tree):
            data = tree[rel]
            info = tarfile.TarInfo(name=rel)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# ---- digest cross-contract tests ---------------------------------------------


def test_digest_matches_sdk_and_worker_golden(tmp_path: Path) -> None:
    _build_tree(tmp_path, SIMPLE_TREE)
    assert compute_package_digest(tmp_path) == SIMPLE_GOLDEN


def test_digest_exclusions_match_golden_and_equivalent_tree(tmp_path: Path) -> None:
    with_excluded = tmp_path / "with_excluded"
    equiv = tmp_path / "equiv"
    with_excluded.mkdir()
    equiv.mkdir()
    _build_tree(with_excluded, WITH_EXCLUDED_TREE)
    _build_tree(equiv, EQUIV_TREE)
    assert compute_package_digest(with_excluded) == EXCLUDED_GOLDEN
    # manifest.json(.sig) / *.pyc / __pycache__ contribute nothing: the tree
    # WITH them digests identically to the tree WITHOUT them.
    assert compute_package_digest(equiv) == EXCLUDED_GOLDEN


def test_digest_nested_manifest_json_is_hashed(tmp_path: Path) -> None:
    """The exclusion is top-level exact-match only — `sub/manifest.json` is
    package content (same semantics as the SDK's `rel in EXCLUDE` check)."""
    base = tmp_path / "base"
    with_nested = tmp_path / "with_nested"
    _build_tree(base, SIMPLE_TREE)
    _build_tree(with_nested, {**SIMPLE_TREE, "sub/manifest.json": b"{}"})
    assert compute_package_digest(base) != compute_package_digest(with_nested)


# ---- extraction-safety unit tests --------------------------------------------


def _tar_gz_with_member(info: tarfile.TarInfo, data: bytes = b"") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data) if data else None)
    return buf.getvalue()


def test_extract_rejects_traversal_member(tmp_path: Path) -> None:
    body = _tar_gz_with_member(tarfile.TarInfo(name="../evil.txt"), b"pwn")
    with pytest.raises(UnsafePackageError, match="traversal"):
        extract_package(body, tmp_path)
    assert not (tmp_path.parent / "evil.txt").exists()


def test_extract_rejects_absolute_path_member(tmp_path: Path) -> None:
    body = _tar_gz_with_member(tarfile.TarInfo(name="/etc/evil.txt"), b"pwn")
    with pytest.raises(UnsafePackageError, match="absolute"):
        extract_package(body, tmp_path)


def test_extract_rejects_symlink_member(tmp_path: Path) -> None:
    info = tarfile.TarInfo(name="link.py")
    info.type = tarfile.SYMTYPE
    info.linkname = "/etc/passwd"
    body = _tar_gz_with_member(info)
    with pytest.raises(UnsafePackageError, match="link"):
        extract_package(body, tmp_path)


def test_extract_rejects_non_archive_body(tmp_path: Path) -> None:
    with pytest.raises(InvalidPackageError):
        extract_package(b"definitely not a gzip stream", tmp_path)


# ---- signed-request helpers ----------------------------------------------------


def _signed_upload(
    client: TestClient,
    *,
    privkey,
    pubkey_hex: str,
    body: bytes,
    claimed_digest: str | None,
    content_type: str = "application/gzip",
):
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="POST",
        path="/api/v0/packages",
        authority="testserver",
        body=body,
    )
    headers["Content-Type"] = content_type
    if claimed_digest is not None:
        headers["X-Package-Digest"] = claimed_digest
    return client.post("/api/v0/packages", headers=headers, content=body)


def _signed_fetch(client: TestClient, *, privkey, pubkey_hex: str, digest: str):
    path = f"/api/v0/packages/{digest}"
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="GET",
        path=path,
        authority="testserver",
        body=b"",
    )
    return client.get(path, headers=headers)


PKG_BODY_TREE = SIMPLE_TREE
PKG_DIGEST = SIMPLE_GOLDEN


# ---- POST /packages ------------------------------------------------------------


def test_upload_happy_path_stores_audits_and_publishes(
    client: TestClient, registered_tenant, audit_repository, config
) -> None:
    privkey, binding = registered_tenant
    body = _tar_gz(PKG_BODY_TREE)
    bus = client.app.state.event_bus
    with bus.subscribe(GLOBAL) as q:
        r = _signed_upload(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            body=body,
            claimed_digest=PKG_DIGEST,
        )
        assert r.status_code == 201, r.text
        ev = q.get_nowait()
    assert r.json() == {"digest": PKG_DIGEST, "size_bytes": len(body), "status": "stored"}
    # Content-addressed blob on disk, byte-identical to the upload.
    blob = config.state_dir / "packages" / f"{PKG_DIGEST}.tar.gz"
    assert blob.is_file()
    assert blob.read_bytes() == body
    # Audit: package.uploaded {digest, tenant}.
    entries = [e for e in audit_repository.latest() if e.action == "package.uploaded"]
    assert len(entries) == 1
    assert entries[0].resource_id == PKG_DIGEST
    assert entries[0].payload["digest"] == PKG_DIGEST
    assert entries[0].payload["tenant"] == binding.tenant_id
    # Firehose event.
    assert ev.type == "package.uploaded"
    assert ev.data == {"digest": PKG_DIGEST, "tenant_id": binding.tenant_id}


def test_upload_digest_mismatch_422_and_not_stored(
    client: TestClient, registered_tenant, config
) -> None:
    privkey, binding = registered_tenant
    wrong = "0" * 64
    r = _signed_upload(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        body=_tar_gz(PKG_BODY_TREE),
        claimed_digest=wrong,
    )
    assert r.status_code == 422, r.text
    err = r.json()["detail"]["error"]
    assert err["code"] == "digest_mismatch"
    assert err["details"] == {"claimed": wrong, "computed": PKG_DIGEST}
    assert not (config.state_dir / "packages").exists()


def test_upload_missing_or_malformed_digest_header_422(
    client: TestClient, registered_tenant
) -> None:
    privkey, binding = registered_tenant
    body = _tar_gz(PKG_BODY_TREE)
    for claimed in (None, "not-a-digest", "ABC123"):
        r = _signed_upload(
            client,
            privkey=privkey,
            pubkey_hex=binding.pubkey_hex,
            body=body,
            claimed_digest=claimed,
        )
        assert r.status_code == 422, r.text
        assert r.json()["detail"]["error"]["code"] == "invalid_package_digest_header"


def test_upload_traversal_tar_rejected_400(client: TestClient, registered_tenant) -> None:
    privkey, binding = registered_tenant
    body = _tar_gz_with_member(tarfile.TarInfo(name="../evil.txt"), b"pwn")
    r = _signed_upload(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        body=body,
        claimed_digest=PKG_DIGEST,
    )
    assert r.status_code == 400, r.text
    assert r.json()["detail"]["error"]["code"] == "unsafe_package"


def test_upload_symlink_tar_rejected_400(client: TestClient, registered_tenant) -> None:
    privkey, binding = registered_tenant
    info = tarfile.TarInfo(name="link.py")
    info.type = tarfile.SYMTYPE
    info.linkname = "/etc/passwd"
    r = _signed_upload(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        body=_tar_gz_with_member(info),
        claimed_digest=PKG_DIGEST,
    )
    assert r.status_code == 400, r.text
    assert r.json()["detail"]["error"]["code"] == "unsafe_package"


def test_upload_non_archive_body_rejected_400(client: TestClient, registered_tenant) -> None:
    privkey, binding = registered_tenant
    r = _signed_upload(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        body=b"not a tarball at all",
        claimed_digest=PKG_DIGEST,
    )
    assert r.status_code == 400, r.text
    assert r.json()["detail"]["error"]["code"] == "invalid_package"


def test_upload_size_cap_413(client: TestClient, registered_tenant) -> None:
    from auspexai_platform.api.packages import MAX_PACKAGE_BYTES

    privkey, binding = registered_tenant
    body = b"\x00" * (MAX_PACKAGE_BYTES + 1)
    r = _signed_upload(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        body=body,
        claimed_digest=PKG_DIGEST,
    )
    assert r.status_code == 413, r.text
    assert r.json()["detail"]["error"]["code"] == "package_too_large"


def test_upload_wrong_content_type_415(client: TestClient, registered_tenant) -> None:
    privkey, binding = registered_tenant
    r = _signed_upload(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        body=_tar_gz(PKG_BODY_TREE),
        claimed_digest=PKG_DIGEST,
        content_type="application/json",
    )
    assert r.status_code == 415, r.text
    assert r.json()["detail"]["error"]["code"] == "unsupported_media_type"


def test_upload_idempotent_reupload_200_already_exists(
    client: TestClient, registered_tenant, config
) -> None:
    privkey, binding = registered_tenant
    body = _tar_gz(PKG_BODY_TREE)
    first = _signed_upload(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        body=body,
        claimed_digest=PKG_DIGEST,
    )
    assert first.status_code == 201, first.text
    blob = config.state_dir / "packages" / f"{PKG_DIGEST}.tar.gz"
    original_bytes = blob.read_bytes()

    second = _signed_upload(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        body=body,
        claimed_digest=PKG_DIGEST,
    )
    assert second.status_code == 200, second.text
    assert second.json()["status"] == "already_exists"
    assert second.json()["digest"] == PKG_DIGEST
    # First write wins; the stored blob is untouched.
    assert blob.read_bytes() == original_bytes


def test_upload_requires_researcher_worker_and_anon_403(
    client: TestClient, enrolled_worker
) -> None:
    body = _tar_gz(PKG_BODY_TREE)
    # Enrolled worker (valid signature, wrong credential class) → 403.
    worker_priv, worker = enrolled_worker
    r = _signed_upload(
        client,
        privkey=worker_priv,
        pubkey_hex=worker.pubkey_hex,
        body=body,
        claimed_digest=PKG_DIGEST,
    )
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["error"]["code"] == "researcher_required"
    # Anonymous (no signature) → 403.
    r = client.post(
        "/api/v0/packages",
        headers={"Content-Type": "application/gzip", "X-Package-Digest": PKG_DIGEST},
        content=body,
    )
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["error"]["code"] == "researcher_required"


# ---- GET /packages/{digest} ------------------------------------------------------


def _upload_pkg(client: TestClient, registered_tenant) -> bytes:
    privkey, binding = registered_tenant
    body = _tar_gz(PKG_BODY_TREE)
    r = _signed_upload(
        client,
        privkey=privkey,
        pubkey_hex=binding.pubkey_hex,
        body=body,
        claimed_digest=PKG_DIGEST,
    )
    assert r.status_code == 201, r.text
    return body


def test_fetch_requires_worker_researcher_and_anon_403(
    client: TestClient, registered_tenant
) -> None:
    _upload_pkg(client, registered_tenant)
    # Researcher (valid signature, wrong credential class) → 403.
    privkey, binding = registered_tenant
    r = _signed_fetch(client, privkey=privkey, pubkey_hex=binding.pubkey_hex, digest=PKG_DIGEST)
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["error"]["code"] == "worker_required"
    # Anonymous → 403.
    r = client.get(f"/api/v0/packages/{PKG_DIGEST}")
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["error"]["code"] == "worker_required"


def test_fetch_unknown_digest_404(client: TestClient, enrolled_worker) -> None:
    worker_priv, worker = enrolled_worker
    for digest in ("f" * 64, "not-hex-at-all"):
        r = _signed_fetch(client, privkey=worker_priv, pubkey_hex=worker.pubkey_hex, digest=digest)
        assert r.status_code == 404, r.text
        assert r.json()["detail"]["error"]["code"] == "package_not_found"


def test_round_trip_upload_fetch_extract_digest_matches(
    client: TestClient, registered_tenant, enrolled_worker, tmp_path: Path
) -> None:
    """The full courier loop: researcher uploads, worker fetches, the fetched
    blob extracts safely, and the digest re-derived over the extracted tree
    (the worker-side verification step) matches the content address."""
    body = _upload_pkg(client, registered_tenant)

    worker_priv, worker = enrolled_worker
    r = _signed_fetch(client, privkey=worker_priv, pubkey_hex=worker.pubkey_hex, digest=PKG_DIGEST)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/gzip"
    fetched = r.content
    assert fetched == body

    dest = tmp_path / "staged"
    dest.mkdir()
    extract_package(fetched, dest)
    for rel, data in PKG_BODY_TREE.items():
        assert (dest / rel).read_bytes() == data
    assert compute_package_digest(dest) == PKG_DIGEST


def _signed_fetch_path(client: TestClient, *, privkey, pubkey_hex: str, path: str):
    headers = sign_request(
        privkey=privkey,
        pubkey_hex=pubkey_hex,
        method="GET",
        path=path,
        authority="testserver",
        body=b"",
    )
    return client.get(path, headers=headers)


def test_fetch_by_manifest_resolves_pin(
    client: TestClient, registered_tenant, enrolled_worker, manifest_repository
) -> None:
    """The worker's natural fetch key is the manifest hash (the digest pin
    lives INSIDE the manifest) — the integration gap that stalled the first
    live #40a run: workers fetched /packages/{manifest_sha256} against a
    digest-keyed store. The by-manifest route resolves hash -> pin -> blob."""
    _upload_pkg(client, registered_tenant)
    _, binding = registered_tenant
    manifest = manifest_repository.insert(
        tenant_id=binding.tenant_id,
        manifest_json={
            "tenant_id": binding.tenant_id,
            "experiment_id": "by-manifest-test",
            "executor": {"package_sha256": PKG_DIGEST},
        },
        signature_json={"alg": "ed25519", "sig": "opaque"},
    )
    worker_priv, worker = enrolled_worker
    r = _signed_fetch_path(
        client,
        privkey=worker_priv,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/packages/by-manifest/{manifest.manifest_hash}",
    )
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/gzip"
    # Served archive = stored blob + injected manifest(.sig) — not byte-equal
    # to the upload; the digest-covered members must ride through untouched.
    import io as _io
    import tarfile as _tarfile

    with _tarfile.open(fileobj=_io.BytesIO(r.content), mode="r:gz") as tar:
        for name, content in PKG_BODY_TREE.items():
            assert tar.extractfile(name).read() == content


def test_fetch_by_manifest_unknown_404(client: TestClient, enrolled_worker) -> None:
    worker_priv, worker = enrolled_worker
    r = _signed_fetch_path(
        client,
        privkey=worker_priv,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/packages/by-manifest/{'ab' * 32}",
    )
    assert r.status_code == 404
    assert r.json()["detail"]["error"]["code"] == "package_not_found"


def test_fetch_by_manifest_injects_manifest(
    client: TestClient, registered_tenant, enrolled_worker, manifest_repository
) -> None:
    """The served archive must carry the manifest beside the code: the blob
    deliberately holds only digest-covered files, but the worker's verifier
    needs a top-level manifest.json (the gap that refused the second live
    #40a attempt). Injection is digest-neutral and worker-verifiable."""
    import io as _io
    import tarfile as _tarfile

    _upload_pkg(client, registered_tenant)
    _, binding = registered_tenant
    manifest = manifest_repository.insert(
        tenant_id=binding.tenant_id,
        manifest_json={
            "tenant_id": binding.tenant_id,
            "experiment_id": "inject-test",
            "executor": {"package_sha256": PKG_DIGEST},
        },
        signature_json={"alg": "ed25519", "sig": "opaque"},
    )
    worker_priv, worker = enrolled_worker
    r = _signed_fetch_path(
        client,
        privkey=worker_priv,
        pubkey_hex=worker.pubkey_hex,
        path=f"/api/v0/packages/by-manifest/{manifest.manifest_hash}",
    )
    assert r.status_code == 200, r.text
    with _tarfile.open(fileobj=_io.BytesIO(r.content), mode="r:gz") as tar:
        names = tar.getnames()
        assert "manifest.json" in names
        assert "manifest.json.sig" in names
        # The original digest-covered files ride along untouched.
        for expected in PKG_BODY_TREE:
            assert expected in names
        import json as _json

        body = _json.loads(tar.extractfile("manifest.json").read())
        assert body["executor"]["package_sha256"] == PKG_DIGEST
        # Injection preserves the manifest's canonical hash — the worker's
        # hash_manifest check against the dispatch pin must still pass.
        canonical = _json.dumps(body, sort_keys=True, separators=(",", ":"))
        import hashlib as _hashlib

        assert _hashlib.sha256(canonical.encode()).hexdigest() == manifest.manifest_hash
