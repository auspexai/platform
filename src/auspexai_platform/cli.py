"""auspexai-coordinator CLI entrypoint.

M2 adds the `token` subgroup for maintainer-token management:
    auspexai-coordinator serve
    auspexai-coordinator token init       # first-run; writes <state>/maintainer.token
    auspexai-coordinator token rotate     # generate new; old expires after 5min overlap
    auspexai-coordinator token show       # list active tokens (and any in overlap window)

Future M-milestones add:
    auspexai-coordinator tenant register  # M5: register a tenant pubkey
    auspexai-coordinator db migrate       # M4: run pending DB migrations
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import click
import uvicorn

from auspexai_platform import __version__
from auspexai_platform.auth.bearer import DEFAULT_OVERLAP, TokenStore, TokenStoreError
from auspexai_platform.config import Config


def _resolve_config(state_dir: Path | None) -> Config:
    return Config.from_env(state_dir=state_dir)


_state_dir_option = click.option(
    "--state-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Coordinator state directory. Overrides AUSPEXAI_STATE_DIR; default ./state/.",
)


@click.group()
@click.version_option(version=__version__, prog_name="auspexai-coordinator")
def main() -> None:
    """AuspexAI coordinator daemon control surface."""


# ----------------------------------------------------------------------------
# serve
# ----------------------------------------------------------------------------


@main.command()
@click.option(
    "--host",
    default="127.0.0.1",
    show_default=True,
    help="Interface to bind. Default localhost; pass 0.0.0.0 to expose externally.",
)
@click.option(
    "--port",
    default=8080,
    show_default=True,
    type=int,
    help="Port to bind.",
)
@click.option(
    "--reload",
    is_flag=True,
    help="Reload on source changes (dev only).",
)
def serve(host: str, port: int, reload: bool) -> None:
    """Run the coordinator HTTP server.

    Uses uvicorn's factory pattern (`factory=True`) — uvicorn calls
    `create_app()` exactly once to build the app. The alternative
    (`auspexai_platform.main:app` as a module-level instance) double-
    registers slowapi rate-limit decorators whenever tests also call
    `create_app()` themselves, since the decorators have no idempotency
    and append to the limiter's per-route list on each invocation.
    """
    uvicorn.run(
        "auspexai_platform.main:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


# ----------------------------------------------------------------------------
# age-off (M-Results retention sweep)
# ----------------------------------------------------------------------------


@main.command("age-off")
@_state_dir_option
@click.option(
    "--apply",
    "apply_changes",
    is_flag=True,
    help="Actually blank expired result payloads. Default is a dry-run report.",
)
def age_off(state_dir: Path | None, apply_changes: bool) -> None:
    """Age off expired result payloads (M-Results retention).

    DRY-RUN by default — prints what *would* be aged off without mutating; pass
    `--apply` to blank the payloads (rows, signatures, hashes, and receipts are
    preserved). Experiments under a retention hold are skipped. Intended to run
    from a systemd timer for periodic retention, or on demand by an operator.
    """
    from datetime import UTC, datetime

    from auspexai_platform.db.database import Database
    from auspexai_platform.db.migrations import MigrationRunner
    from auspexai_platform.maintenance import age_off_sweep

    config = _resolve_config(state_dir)
    db = Database(config.control_db_path)
    try:
        MigrationRunner(db).apply_all()  # idempotent; ensures retention columns exist
        report = age_off_sweep(config.jobs_dir, db, apply=apply_changes, now=datetime.now(UTC))
    finally:
        db.close()
    click.echo(report.summary())
    if not apply_changes and report.total_aged:
        click.echo("\nRe-run with --apply to blank these payloads.")


@main.command("settle")
@_state_dir_option
@click.option(
    "--apply",
    "apply_changes",
    is_flag=True,
    help="Actually settle eligible units at their achieved replication. Default is a dry-run.",
)
def settle(state_dir: Path | None, apply_changes: bool) -> None:
    """Settle capacity-stuck units at their achieved replication (C14 regime-2).

    Completes IN_PROGRESS units that have met their replication FLOOR but cannot reach their
    TARGET because the eligible fleet is exhausted and quiescent — instead of stalling
    forever. DRY-RUN by default; pass `--apply` to settle. A settled unit runs the same
    post-completion path (receipts / consensus / attestation) as a normal completion.
    Intended to run from a systemd timer alongside `age-off`.
    """
    from datetime import UTC, datetime

    from auspexai_platform.maintenance import settle_sweep

    config = _resolve_config(state_dir)
    report = settle_sweep(config, apply=apply_changes, now=datetime.now(UTC))
    click.echo(report.summary())
    if not apply_changes and report.settled:
        click.echo("\nRe-run with --apply to settle these units.")


# ----------------------------------------------------------------------------
# attestation group (A2 — Rekor anchoring backfill)
# ----------------------------------------------------------------------------


@main.group()
def attestation() -> None:
    """Result-set attestation maintenance."""


@attestation.command("backfill-rekor")
@_state_dir_option
@click.option(
    "--apply",
    "apply_changes",
    is_flag=True,
    help="Actually submit un-anchored attestations to Rekor. Default is a dry-run count.",
)
@click.option(
    "--rekor-url",
    default=None,
    help="Rekor instance URL (default: config / public sigstore).",
)
def attestation_backfill_rekor(
    state_dir: Path | None, apply_changes: bool, rekor_url: str | None
) -> None:
    """Anchor persisted attestations still carrying the NoOp Rekor placeholder.

    The completion path persists attestations fast with a placeholder anchor (no
    network on the request path); this sweep submits each un-anchored COSE blob
    to Rekor and records the log index + entry UUID. DRY-RUN by default — pass
    `--apply` to anchor. Idempotent + per-row fault-tolerant. Intended to run
    from a systemd timer (mirrors `age-off`) or on demand.
    """
    from auspexai_platform.db.database import Database
    from auspexai_platform.db.migrations import MigrationRunner
    from auspexai_platform.receipts.attestation_backfill import backfill_rekor_anchors
    from auspexai_platform.receipts.rekor import RekorClient
    from auspexai_platform.receipts.signing import load_or_generate_signing_key

    config = _resolve_config(state_dir)
    db = Database(config.control_db_path)
    try:
        MigrationRunner(db).apply_all()  # idempotent; ensures the attestations table exists
        signing_key = load_or_generate_signing_key(config.receipt_signing_key_path)
        client = RekorClient(rekor_url or config.rekor_url, signing_key=signing_key)
        report = backfill_rekor_anchors(db, rekor_client=client, apply=apply_changes)
    finally:
        db.close()
    click.echo(report.summary())
    if not apply_changes and report.candidates:
        click.echo("\nRe-run with --apply to anchor these in Rekor.")


@main.group()
def receipts() -> None:
    """Receipt maintenance."""


@receipts.command("rebuild-index")
@_state_dir_option
@click.option(
    "--experiment",
    "experiment_id",
    default=None,
    help="Rebuild for one experiment only (default: all experiments with a per-job DB).",
)
@click.option(
    "--apply",
    "apply_changes",
    is_flag=True,
    help="Actually insert missing index rows. Default is a dry-run count.",
)
def receipts_rebuild_index(
    state_dir: Path | None, experiment_id: str | None, apply_changes: bool
) -> None:
    """Reconcile the control-DB receipt_index against the per-job receipts tables.

    The index write at issuance is best-effort (a failure is logged, never
    fatal — the per-job receipt row is the source of truth). This is the
    promised rebuild sweep: it re-derives each experiment's
    {result_id: receipt_id} map from the per-job receipts ⨝ results join and
    inserts any rows the index is missing. DRY-RUN by default. NB: signing
    paths no longer depend on the index (they derive membership from the
    per-job tables directly); this keeps the display routes complete.
    """
    from auspexai_platform.db.database import Database
    from auspexai_platform.db.migrations import MigrationRunner
    from auspexai_platform.db.per_job import PerJobDatabaseFactory
    from auspexai_platform.db.repositories import ReceiptIndexRepository
    from auspexai_platform.receipts.attestation import receipt_map_from_per_job

    config = _resolve_config(state_dir)
    db = Database(config.control_db_path)
    try:
        MigrationRunner(db).apply_all()
        index_repo = ReceiptIndexRepository(db)
        factory = PerJobDatabaseFactory(config.jobs_dir)
        if experiment_id is not None:
            experiment_ids = [experiment_id]
        else:
            experiment_ids = sorted(p.stem for p in config.jobs_dir.glob("*.db"))
        total_missing = 0
        total_inserted = 0
        for exp_id in experiment_ids:
            per_job_db = factory.get(exp_id)
            if per_job_db is None:
                click.echo(f"{exp_id}: no per-job DB, skipped")
                continue
            indexed = {
                e.result_id
                for e in index_repo.list_for_experiment(exp_id)
                if e.result_id is not None
            }
            authoritative = receipt_map_from_per_job(per_job_db)
            worker_by_result = {
                row["result_id"]: (row["worker_id"], row["worker_pubkey_hex"], row["unit_id"])
                for row in per_job_db.execute(
                    "SELECT result_id, worker_id, worker_pubkey_hex, unit_id FROM results"
                )
            }
            missing = sorted(set(authoritative) - indexed)
            total_missing += len(missing)
            inserted = 0
            for result_id in missing:
                if not apply_changes:
                    continue
                worker_id, worker_pubkey, unit_id = worker_by_result[result_id]
                try:
                    index_repo.record(
                        receipt_id=authoritative[result_id],
                        experiment_id=exp_id,
                        worker_id=worker_id,
                        worker_pubkey=worker_pubkey,
                        result_id=result_id,
                        unit_id=unit_id,  # A4: backfill per-account-per-unit trust
                    )
                    inserted += 1
                except Exception as e:  # per-row fault tolerance, mirror backfill-rekor
                    click.echo(f"{exp_id}: failed to index {result_id}: {e}")
            total_inserted += inserted
            if missing:
                click.echo(
                    f"{exp_id}: {len(missing)} missing index row(s)"
                    + (f", {inserted} inserted" if apply_changes else "")
                )
        click.echo(
            f"done: {total_missing} missing across {len(experiment_ids)} experiment(s)"
            + (f", {total_inserted} inserted" if apply_changes else " (dry-run)")
        )
        if not apply_changes and total_missing:
            click.echo("Re-run with --apply to insert the missing rows.")
    finally:
        db.close()


# ----------------------------------------------------------------------------
# token group
# ----------------------------------------------------------------------------


@main.group()
def token() -> None:
    """Maintainer-token management."""


@token.command("init")
@_state_dir_option
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite an existing maintainer.token file.",
)
def token_init(state_dir: Path | None, force: bool) -> None:
    """Generate the first maintainer token. Idempotent only with --force."""
    config = _resolve_config(state_dir)
    store = TokenStore(config.maintainer_token_path)
    try:
        new_token = store.initialize(force=force)
    except TokenStoreError as e:
        click.echo(f"ERROR: {e}", err=True)
        raise SystemExit(1) from e
    click.echo(f"Maintainer token initialized at {config.maintainer_token_path}")
    click.echo(f"Token: {new_token}")
    click.echo("Pass this token via `Authorization: Bearer <token>` on operator-console requests.")
    click.echo("Re-run with --force to rotate via re-initialization, or use `token rotate` for an")
    click.echo("overlap-window rotation.")


@token.command("rotate")
@_state_dir_option
@click.option(
    "--overlap-minutes",
    type=int,
    default=int(DEFAULT_OVERLAP.total_seconds() // 60),
    show_default=True,
    help="How long the previous active token remains valid after rotation (minutes).",
)
def token_rotate(state_dir: Path | None, overlap_minutes: int) -> None:
    """Rotate the maintainer token. Previous token valid for the overlap window."""
    config = _resolve_config(state_dir)
    store = TokenStore(config.maintainer_token_path)
    if not config.maintainer_token_path.exists():
        click.echo(
            f"ERROR: no maintainer token at {config.maintainer_token_path}. Run `token init` first.",
            err=True,
        )
        raise SystemExit(1)
    new_token = store.rotate(overlap=timedelta(minutes=overlap_minutes))
    click.echo(f"Rotated maintainer token at {config.maintainer_token_path}")
    click.echo(f"New token: {new_token}")
    click.echo(f"Previous token remains valid for {overlap_minutes} minute(s).")


@token.command("show")
@_state_dir_option
def token_show(state_dir: Path | None) -> None:
    """List all currently-valid maintainer tokens with login attribution."""
    config = _resolve_config(state_dir)
    store = TokenStore(config.maintainer_token_path)
    if not config.maintainer_token_path.exists():
        click.echo(f"No maintainer.token at {config.maintainer_token_path}.", err=True)
        raise SystemExit(1)
    entries = store.active_entries()
    if not entries:
        click.echo(
            "No active tokens — all have expired. Run `token rotate` or `token init --force`."
        )
        raise SystemExit(1)
    for i, e in enumerate(entries, 1):
        login_label = e.login or "(legacy — no login)"
        expires = f"expires {e.expires_at.isoformat()}" if e.expires_at else "active"
        click.echo(f"[{i}] {login_label}  {e.token}  ({expires})")


@token.command("issue")
@_state_dir_option
@click.option("--login", required=True, help="GitHub login of the Maintainer to issue a token for.")
def token_issue(state_dir: Path | None, login: str) -> None:
    """Issue a per-maintainer token. If the login already has one, the old token
    is expired with a 5-minute overlap and a fresh one is appended."""
    config = _resolve_config(state_dir)
    store = TokenStore(config.maintainer_token_path)
    if not config.maintainer_token_path.exists():
        click.echo(
            f"ERROR: no maintainer.token at {config.maintainer_token_path}. Run `token init` first.",
            err=True,
        )
        raise SystemExit(1)
    new_token = store.issue(login=login)
    click.echo(f"Issued token for {login}:")
    click.echo(f"Token: {new_token}")
    click.echo(
        "Pass via `Authorization: Bearer <token>` — audit trail will attribute actions to this login."
    )


@token.command("revoke")
@_state_dir_option
@click.option("--login", required=True, help="GitHub login whose tokens to revoke.")
def token_revoke(state_dir: Path | None, login: str) -> None:
    """Immediately revoke all tokens for a Maintainer login."""
    config = _resolve_config(state_dir)
    store = TokenStore(config.maintainer_token_path)
    if not config.maintainer_token_path.exists():
        click.echo(f"No maintainer.token at {config.maintainer_token_path}.", err=True)
        raise SystemExit(1)
    count = store.revoke(login=login)
    if count == 0:
        click.echo(f"No active tokens found for {login}.")
    else:
        click.echo(f"Revoked {count} token(s) for {login}.")


@main.group("certification")
def certification() -> None:
    """Promotion-gate certifications (RFC 0001 / Research Ethics Policy §6.7)."""


@certification.command("issue")
@_state_dir_option
@click.option(
    "--manifest",
    "manifest_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Built starter manifest.json (e.g. `experiment build pkg/ --profile starter`).",
)
@click.option(
    "--snapshot", required=True, help="Released snapshot version, e.g. vigiles-tenant@v0.1.0."
)
@click.option(
    "--profile",
    "profile_name",
    required=True,
    help="The profile name being certified (e.g. starter).",
)
@click.option(
    "--certified-by",
    "certified_by",
    required=True,
    help="Maintainer identity recorded on the certificate.",
)
@click.option(
    "--advisor",
    default=None,
    help="External advisor co-signer — HIGH-risk certs only; omit for a low-risk starter (§6.7.4).",
)
@click.option(
    "--max-units",
    "max_units_ceiling",
    type=int,
    default=None,
    help="Certified unit-count ceiling (§6.7.3).",
)
@click.option(
    "--apply",
    "apply_changes",
    is_flag=True,
    help="Actually sign + register. Default is a dry-run that runs the §6.7.2 checks.",
)
@click.option(
    "--reissue",
    "reissue",
    is_flag=True,
    help="Replace an EXISTING certification for this package (label/version correction "
    "or re-cut release of identical content). Re-signs, re-labels, re-anchors; audited.",
)
def certification_issue(
    state_dir: Path | None,
    manifest_path: Path,
    snapshot: str,
    profile_name: str,
    certified_by: str,
    advisor: str | None,
    max_units_ceiling: int | None,
    apply_changes: bool,
    reissue: bool,
) -> None:
    """Certify a curated starter profile (§6.7): auto-check the §6.7.2 bar, sign the
    certificate with the coordinator key, and register it so runs of this exact
    profile auto-clear §6 (§6.7.5). DRY-RUN by default — `--apply` to commit.

    Low-risk path (the default): the certificate is coordinator-signed and
    maintainer-authenticated; independence is transparency + contestability (no
    advisor). Pass `--advisor` only for a high-risk certification."""
    import json as _json

    from auspexai_platform.certification import (
        auto_check,
        envelope_from_manifest,
        sign_certificate,
    )
    from auspexai_platform.db.database import Database
    from auspexai_platform.db.migrations import MigrationRunner
    from auspexai_platform.db.repositories.certified_profiles import (
        CertifiedProfileRepository,
        DuplicateCertificationError,
        NoCertificationError,
    )
    from auspexai_platform.receipts.signing import load_or_generate_signing_key

    manifest = _json.loads(manifest_path.read_text())
    check = auto_check(manifest)
    if not check.passed:
        click.echo("FAILED the §6.7.2 safe-to-expose auto-checks:", err=True)
        for f in check.failures:
            click.echo(f"  - {f}", err=True)
        raise SystemExit(1)

    envelope = envelope_from_manifest(
        manifest,
        snapshot_version=snapshot,
        profile_name=profile_name,
        certified_by=certified_by,
        advisor=advisor,
        max_units_ceiling=max_units_ceiling,
    )
    click.echo("Certifying (review before --apply):")
    click.echo(f"  snapshot:       {envelope.snapshot_version}")
    click.echo(f"  tenant/profile: {envelope.tenant_id} / {envelope.profile_name}")
    click.echo(f"  package:        {envelope.package_sha256[:16]}…")
    click.echo(f"  model(s):       {', '.join(envelope.model_ids)}")
    click.echo(f"  research_class: {envelope.research_class}")
    click.echo(f"  sensitive flags: {envelope.sensitive_content_flags}")
    click.echo(f"  replication floor: {envelope.replication_floor}")
    click.echo(f"  duration ≤:     {envelope.duration_hours_ceiling}")
    click.echo(
        f"  tolerance envelope: {envelope.comparison_envelope or '(none — no comparison features)'}"
    )
    click.echo(f"  advisor:        {envelope.advisor or '(none — low-risk: publish + contest)'}")
    click.echo("  §6.7.2 auto-checks: PASS")
    if not apply_changes:
        click.echo("\nDRY-RUN. Re-run with --apply to sign + register.")
        return

    config = _resolve_config(state_dir)
    db = Database(config.control_db_path)
    try:
        MigrationRunner(db).apply_all()
        signing_key = load_or_generate_signing_key(config.receipt_signing_key_path)
        blob = sign_certificate(envelope, signing_key=signing_key)
        repo = CertifiedProfileRepository(db)
        _cert_fields = dict(
            package_sha256=envelope.package_sha256,
            snapshot_version=envelope.snapshot_version,
            tenant_id=envelope.tenant_id,
            profile_name=envelope.profile_name,
            research_class=envelope.research_class,
            sensitive_content_flags=envelope.sensitive_content_flags,
            model_ids=envelope.model_ids,
            replication_floor=envelope.replication_floor,
            max_units_ceiling=envelope.max_units_ceiling,
            duration_hours_ceiling=envelope.duration_hours_ceiling,
            comparison_envelope=envelope.comparison_envelope,
            cose_signed_blob=blob,
            signing_key_pubkey_hex=signing_key.pubkey_hex,
            certified_by=envelope.certified_by,
            advisor=envelope.advisor,
        )
        if reissue:
            from auspexai_platform.auth.credential import CredentialClass
            from auspexai_platform.db.repositories import AuditRepository

            try:
                old_snapshot, rec = repo.reissue(**_cert_fields)
            except NoCertificationError as e:
                click.echo(f"--reissue: {e}. Drop --reissue to certify a new package.", err=True)
                raise SystemExit(1) from None
            AuditRepository(db).append(
                actor_class=CredentialClass.MAINTAINER,
                actor_identifier=envelope.certified_by,
                actor_tenant_id=None,
                action="certification.reissue",
                resource_type="certified_profile",
                resource_id=envelope.package_sha256,
                payload={
                    "from_snapshot": old_snapshot,
                    "to_snapshot": envelope.snapshot_version,
                    "profile": f"{envelope.tenant_id}/{envelope.profile_name}",
                },
            )
            click.echo(f"  reissued: {old_snapshot} → {envelope.snapshot_version}")
        else:
            try:
                rec = repo.insert(**_cert_fields)
            except DuplicateCertificationError:
                click.echo(
                    f"Already certified: package {envelope.package_sha256[:16]}… is in the registry. "
                    "Re-certifying identical content is a no-op; pass --reissue to re-label/re-cut.",
                    err=True,
                )
                raise SystemExit(1) from None
        repo.supersede_others(
            tenant_id=rec.tenant_id, profile_name=rec.profile_name, keep_package=rec.package_sha256
        )
        # Publish to the transparency log (§6.7.4 "publish"): anchor the signed cert
        # in Rekor so it is publicly auditable + contestable. Best-effort — on failure
        # the cert is registered un-anchored and `certification backfill-rekor` catches it.
        anchor_note = "  (Rekor anchor deferred — run `certification backfill-rekor`)"
        try:
            from auspexai_platform.receipts.rekor import RekorClient

            entry = RekorClient(config.rekor_url, signing_key=signing_key).record(blob)
            repo.set_rekor(envelope.package_sha256, log_index=entry.log_index)
            anchor_note = f"  published to the transparency log: Rekor logIndex {entry.log_index}"
        except Exception as e:
            anchor_note = f"  (Rekor anchor deferred: {e}; run `certification backfill-rekor`)"
    finally:
        db.close()
    click.echo(
        f"\n✓ certified {envelope.tenant_id}/{envelope.profile_name} @ {envelope.snapshot_version}"
    )
    click.echo(
        f"  signed by {signing_key.pubkey_hex[:16]}… (coordinator key, maintainer-authenticated)"
    )
    click.echo(anchor_note)
    click.echo("  Open it to contestation per §6.7.4 (sign + publish + contest).")


@certification.command("revoke")
@_state_dir_option
@click.option(
    "--package", "package_sha256", required=True, help="The certified package digest to revoke."
)
@click.option("--reason", required=True, help="Why it is revoked (recorded; §6.7.6).")
@click.option(
    "--apply", "apply_changes", is_flag=True, help="Actually revoke. Default is a dry-run."
)
def certification_revoke(
    state_dir: Path | None, package_sha256: str, reason: str, apply_changes: bool
) -> None:
    """Revoke a certification (§6.7.6): its standing approval is removed and runs
    of that profile revert to requiring a §6.1 application. DRY-RUN by default."""
    from auspexai_platform.db.database import Database
    from auspexai_platform.db.migrations import MigrationRunner
    from auspexai_platform.db.repositories.certified_profiles import CertifiedProfileRepository

    config = _resolve_config(state_dir)
    db = Database(config.control_db_path)
    try:
        MigrationRunner(db).apply_all()
        repo = CertifiedProfileRepository(db)
        rec = repo.get_by_package(package_sha256)
        if rec is None:
            click.echo(f"No certification for package {package_sha256[:16]}….", err=True)
            raise SystemExit(1)
        click.echo(
            f"{rec.tenant_id}/{rec.profile_name} @ {rec.snapshot_version} (status: {rec.status})"
        )
        if not apply_changes:
            click.echo("DRY-RUN. Re-run with --apply to revoke.")
            return
        repo.revoke(package_sha256, reason=reason)
    finally:
        db.close()
    click.echo("✓ revoked — the standing approval is removed.")


@certification.command("list")
@_state_dir_option
def certification_list(state_dir: Path | None) -> None:
    """List the certifications in the registry."""
    from auspexai_platform.db.database import Database
    from auspexai_platform.db.migrations import MigrationRunner
    from auspexai_platform.db.repositories.certified_profiles import CertifiedProfileRepository

    config = _resolve_config(state_dir)
    db = Database(config.control_db_path)
    try:
        MigrationRunner(db).apply_all()
        records = CertifiedProfileRepository(db).list_all()
    finally:
        db.close()
    if not records:
        click.echo("No certifications.")
        return
    for r in records:
        anchor = f"rekor {r.rekor_log_index}" if r.rekor_log_index is not None else "un-anchored"
        click.echo(
            f"{r.status:10} {r.tenant_id}/{r.profile_name} @ {r.snapshot_version}  "
            f"pkg {r.package_sha256[:12]}…  floor {r.replication_floor}  {anchor}"
        )


@certification.command("backfill-rekor")
@_state_dir_option
@click.option(
    "--apply",
    "apply_changes",
    is_flag=True,
    help="Actually anchor un-anchored certifications in Rekor. Default is a dry-run count.",
)
@click.option(
    "--rekor-url", default=None, help="Rekor instance URL (default: config / public sigstore)."
)
def certification_backfill_rekor(
    state_dir: Path | None, apply_changes: bool, rekor_url: str | None
) -> None:
    """Anchor signed certifications in the transparency log (§6.7.4 "publish").

    `certification issue` anchors inline; this sweep catches anything left
    un-anchored (a Rekor hiccup, or a cert issued before anchoring shipped).
    DRY-RUN by default — pass `--apply`. Idempotent + per-row fault-tolerant;
    intended to run from a systemd timer alongside the attestation backfill."""
    from auspexai_platform.certification_backfill import backfill_cert_rekor
    from auspexai_platform.db.database import Database
    from auspexai_platform.db.migrations import MigrationRunner
    from auspexai_platform.receipts.rekor import RekorClient
    from auspexai_platform.receipts.signing import load_or_generate_signing_key

    config = _resolve_config(state_dir)
    db = Database(config.control_db_path)
    try:
        MigrationRunner(db).apply_all()
        signing_key = load_or_generate_signing_key(config.receipt_signing_key_path)
        client = RekorClient(rekor_url or config.rekor_url, signing_key=signing_key)
        report = backfill_cert_rekor(db, rekor_client=client, apply=apply_changes)
    finally:
        db.close()
    click.echo(report.summary())
    if not apply_changes and report.candidates:
        click.echo("\nRe-run with --apply to anchor these in Rekor.")


if __name__ == "__main__":
    main()
