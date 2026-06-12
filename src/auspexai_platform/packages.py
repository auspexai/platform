"""Content-addressed executor-package store + the shared package-digest
contract (§9 #40a — coordinator-served provisioning, "the courier").

Three pieces, all dependency-light (stdlib only) so any layer can import them
without circular-import risk (same posture as `hashing.py`):

  - `compute_package_digest` — byte-for-byte reimplementation of the digest
    the tenant SDK computes (`auspexai_tenant.manifest.compute_package_digest`)
    and the worker re-derives (`auspexai_worker.provisioning
    .compute_package_digest`). The shared contract is the FORMAT, not shared
    code (SDK Apache / worker AGPL / platform AGPL): every regular file under
    the package root — except top-level `manifest.json` / `manifest.json.sig`,
    any `*.pyc`, and anything under a `__pycache__/` directory — contributes
    one line ``<posix-relpath>\\x00<sha256-hex>``; lines sorted by relpath,
    joined by ``\\n``, and the digest is the SHA-256 hex of that blob.
    `tests/test_packages.py` pins this with golden digests computed from the
    SDK + worker implementations on known fixture trees.

  - `extract_package` — PATH-TRAVERSAL-SAFE extraction of an uploaded
    `.tar.gz` body. Every member is pre-screened (absolute paths, `..`
    components, symlinks/hardlinks, and special files are rejected with
    `UnsafePackageError`) and the extraction itself runs under
    `tarfile`'s ``filter="data"`` as defense-in-depth. A decompression-size
    guard (`MAX_UNCOMPRESSED_BYTES`) keeps a small gzip bomb from exhausting
    the temp filesystem while the coordinator recomputes the digest.

  - `PackageStore` — content-addressed blobs at
    ``<state_dir>/packages/<package_digest>.tar.gz``. The address is the
    digest over the EXTRACTED tree (verified by the upload route before
    `put`), not the blob's own sha256 — two byte-different tar.gz streams
    with the same tree share one address, first write wins, which is sound
    because every consumer (the worker) re-derives the tree digest after
    extraction and refuses on mismatch.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import os
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

# Files the package digest skips. Top-level exact matches only (a nested
# `sub/manifest.json` is real package content and IS hashed) — kept in
# lockstep with auspexai_tenant.manifest._PACKAGE_DIGEST_EXCLUDE and
# auspexai_worker.provisioning._PACKAGE_DIGEST_EXCLUDE.
_PACKAGE_DIGEST_EXCLUDE = ("manifest.json", "manifest.json.sig")

# Guard on the *decompressed* size of an uploaded package (the HTTP-level
# 64 MiB cap in api/packages.py bounds the compressed body; this bounds the
# extraction work a gzip bomb could otherwise inflate it into).
MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024


class PackageError(Exception):
    """Base for package-body failures. `message` is operator-safe."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class InvalidPackageError(PackageError):
    """Body is not a valid .tar.gz archive (or exceeds extraction bounds)."""


class UnsafePackageError(PackageError):
    """Archive contains a member that could escape or abuse the extraction
    root (absolute path, `..` traversal, link, or special file)."""


def compute_package_digest(package_dir: Path) -> str:
    """Digest over the executor *files* in `package_dir`, byte-for-byte
    identical to `auspexai_tenant.manifest.compute_package_digest` (the tenant
    computes it; the worker re-derives it; the coordinator recomputes it on
    upload so it never trusts the uploader's claim). Standalone replica, not
    an import — the shared contract is the format, not shared code.

    Each regular file except top-level `manifest.json` / `manifest.json.sig`,
    `__pycache__/` contents, and `*.pyc` contributes
    ``<posix-relpath>\\x00<sha256-hex>``; lines sorted by relpath, joined by
    ``\\n``, SHA-256'd.
    """
    lines: list[str] = []
    for path in sorted(package_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(package_dir).as_posix()
        parts = rel.split("/")
        if rel in _PACKAGE_DIGEST_EXCLUDE or rel.endswith(".pyc") or "__pycache__" in parts:
            continue
        file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{rel}\x00{file_hash}")
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def _check_member_safe(member: tarfile.TarInfo) -> None:
    """Reject any member that could write outside (or abuse) the extraction
    root. Stricter than tarfile's `data` filter: ALL links are refused, even
    ones that would resolve inside the destination — an executor package is a
    plain file tree and has no business shipping links or device nodes."""
    name = member.name
    if name.startswith("/"):
        raise UnsafePackageError(f"absolute path in archive: {name!r}")
    if ".." in PurePosixPath(name).parts:
        raise UnsafePackageError(f"path traversal in archive member: {name!r}")
    if member.issym() or member.islnk():
        raise UnsafePackageError(f"link member not allowed: {name!r}")
    if not (member.isfile() or member.isdir()):
        raise UnsafePackageError(f"special member not allowed: {name!r}")


def extract_package(body: bytes, dest: Path) -> None:
    """Extract a `.tar.gz` request body into `dest`, refusing unsafe members.

    Raises:
        UnsafePackageError — traversal/absolute/link/special member.
        InvalidPackageError — not a gzip'd tarball, truncated/corrupt stream,
            or decompressed size over `MAX_UNCOMPRESSED_BYTES`.
    """
    try:
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tar:
            members = tar.getmembers()
            total_size = 0
            for member in members:
                _check_member_safe(member)
                total_size += max(member.size, 0)
            if total_size > MAX_UNCOMPRESSED_BYTES:
                raise InvalidPackageError(
                    f"decompressed package size {total_size} exceeds {MAX_UNCOMPRESSED_BYTES} bytes"
                )
            # Defense-in-depth: the pre-screen above already rejected every
            # unsafe member; `data` filter enforces the same class of
            # guarantees inside tarfile itself.
            tar.extractall(dest, members=members, filter="data")
    except PackageError:
        raise
    except (tarfile.TarError, EOFError, OSError, ValueError) as e:
        raise InvalidPackageError(f"body is not a valid .tar.gz archive: {e}") from e


def digest_of_package_body(body: bytes) -> str:
    """Extract `body` to a throwaway temp dir (path-traversal-safe) and return
    the recomputed package digest over the extracted tree. The upload route's
    verify-before-store step."""
    with tempfile.TemporaryDirectory(prefix="auspexai-pkg-") as tmp:
        dest = Path(tmp)
        extract_package(body, dest)
        return compute_package_digest(dest)


class PackageStore:
    """Content-addressed executor-package blobs:
    ``<packages_dir>/<package_digest>.tar.gz``.

    Same custody posture as the model-prestage store: blobs are immutable
    once written (the address IS the verified content identity), writes are
    atomic (temp file + `os.replace`), and re-uploads of an existing digest
    are no-ops.
    """

    def __init__(self, packages_dir: Path) -> None:
        self._dir = packages_dir

    def path_for(self, digest: str) -> Path:
        return self._dir / f"{digest}.tar.gz"

    def exists(self, digest: str) -> bool:
        return self.path_for(digest).is_file()

    def put(self, digest: str, blob: bytes) -> bool:
        """Store `blob` under `digest`. Returns True if newly stored, False
        if the digest was already present (idempotent re-upload)."""
        if self.exists(digest):
            return False
        self._dir.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=self._dir, prefix=f".{digest}.", suffix=".part")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(blob)
            os.replace(tmp_name, self.path_for(digest))
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise
        return True
