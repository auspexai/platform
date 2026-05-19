"""Tests for the AuditRepository."""

from __future__ import annotations

import pytest

from auspexai_platform.auth.credential import CredentialClass
from auspexai_platform.db.repositories import AuditRepository


def test_append_records_minimal_entry(audit_repository: AuditRepository) -> None:
    entry = audit_repository.append(
        actor_class=CredentialClass.MAINTAINER,
        action="tenant.register",
    )
    assert entry.id is not None
    assert entry.actor_class is CredentialClass.MAINTAINER
    assert entry.action == "tenant.register"
    assert entry.actor_identifier is None
    assert entry.payload is None
    assert entry.occurred_at is not None


def test_append_records_full_entry(audit_repository: AuditRepository) -> None:
    entry = audit_repository.append(
        actor_class=CredentialClass.RESEARCHER,
        actor_identifier="a" * 64,
        actor_tenant_id="synth-doubler",
        action="experiment.abort",
        resource_type="experiment",
        resource_id="exp-001",
        payload={"reason": "operator request", "elapsed_seconds": 600},
    )
    assert entry.actor_identifier == "a" * 64
    assert entry.actor_tenant_id == "synth-doubler"
    assert entry.resource_type == "experiment"
    assert entry.payload == {"reason": "operator request", "elapsed_seconds": 600}


def test_append_rejects_empty_action(audit_repository: AuditRepository) -> None:
    with pytest.raises(ValueError, match="non-empty"):
        audit_repository.append(actor_class=CredentialClass.MAINTAINER, action="")


def test_latest_returns_newest_first(audit_repository: AuditRepository) -> None:
    for i in range(5):
        audit_repository.append(
            actor_class=CredentialClass.MAINTAINER,
            action=f"action.{i}",
        )
    rows = audit_repository.latest(limit=3)
    assert [r.action for r in rows] == ["action.4", "action.3", "action.2"]


def test_latest_with_zero_limit_returns_empty(audit_repository: AuditRepository) -> None:
    audit_repository.append(
        actor_class=CredentialClass.MAINTAINER,
        action="tenant.register",
    )
    assert audit_repository.latest(limit=0) == []


def test_payload_round_trips_through_json(audit_repository: AuditRepository) -> None:
    payload = {
        "nested": {"key": "value"},
        "list": [1, 2, 3],
        "bool": True,
        "null": None,
    }
    audit_repository.append(
        actor_class=CredentialClass.MAINTAINER,
        action="test.payload",
        payload=payload,
    )
    rows = audit_repository.latest(limit=1)
    assert rows[0].payload == payload
