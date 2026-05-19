"""Unit tests for the field-exposure filter.

Covers:
  - ExposureTag extraction from Annotated metadata
  - is_visible() decision matrix across (tag x credential x tenant match)
  - filter_for_credential() applies the matrix to a Pydantic model
  - Fail-closed default (untagged field → operator-only)
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel

from auspexai_platform.auth.credential import Credential
from auspexai_platform.exposure import (
    ExposureTag,
    field_exposure_tag,
    filter_for_credential,
    is_visible,
)

# ---- ExposureTag extraction ------------------------------------------------


class _SampleModel(BaseModel):
    a: Annotated[str | None, ExposureTag.PUBLIC] = None
    b: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
    c: Annotated[str | None, ExposureTag.ACCOUNT_SCOPED] = None
    d: Annotated[str | None, ExposureTag.OPERATOR_ONLY] = None
    e: str | None = None  # untagged → fail-closed → OPERATOR_ONLY


def test_field_exposure_tag_extracts_public() -> None:
    assert field_exposure_tag(_SampleModel.model_fields["a"]) is ExposureTag.PUBLIC


def test_field_exposure_tag_extracts_tenant_scoped() -> None:
    assert field_exposure_tag(_SampleModel.model_fields["b"]) is ExposureTag.TENANT_SCOPED


def test_field_exposure_tag_extracts_account_scoped() -> None:
    assert field_exposure_tag(_SampleModel.model_fields["c"]) is ExposureTag.ACCOUNT_SCOPED


def test_field_exposure_tag_extracts_operator_only() -> None:
    assert field_exposure_tag(_SampleModel.model_fields["d"]) is ExposureTag.OPERATOR_ONLY


def test_field_exposure_tag_defaults_to_operator_only_when_untagged() -> None:
    assert field_exposure_tag(_SampleModel.model_fields["e"]) is ExposureTag.OPERATOR_ONLY


# ---- is_visible decision matrix --------------------------------------------


def test_maintainer_sees_everything() -> None:
    cred = Credential.maintainer()
    for tag in ExposureTag:
        assert is_visible(tag, cred) is True, f"maintainer should see {tag}"


def test_anonymous_sees_only_public() -> None:
    cred = Credential.anonymous()
    assert is_visible(ExposureTag.PUBLIC, cred) is True
    assert is_visible(ExposureTag.TENANT_SCOPED, cred) is False
    assert is_visible(ExposureTag.ACCOUNT_SCOPED, cred) is False
    assert is_visible(ExposureTag.OPERATOR_ONLY, cred) is False


def test_researcher_sees_public_always() -> None:
    cred = Credential.researcher(tenant_id="t-a", pubkey_hex="a" * 64)
    assert is_visible(ExposureTag.PUBLIC, cred) is True


def test_researcher_sees_own_tenant_scoped() -> None:
    cred = Credential.researcher(tenant_id="t-a", pubkey_hex="a" * 64)
    assert is_visible(ExposureTag.TENANT_SCOPED, cred, resource_tenant_id="t-a") is True


def test_researcher_does_not_see_other_tenants_scoped() -> None:
    cred = Credential.researcher(tenant_id="t-a", pubkey_hex="a" * 64)
    assert is_visible(ExposureTag.TENANT_SCOPED, cred, resource_tenant_id="t-b") is False


def test_researcher_does_not_see_unbound_tenant_scoped() -> None:
    """resource_tenant_id is None — the resource isn't tenant-bound at all,
    so tenant-scoped fields aren't visible to anyone except the operator."""
    cred = Credential.researcher(tenant_id="t-a", pubkey_hex="a" * 64)
    assert is_visible(ExposureTag.TENANT_SCOPED, cred, resource_tenant_id=None) is False


def test_researcher_does_not_see_account_scoped() -> None:
    cred = Credential.researcher(tenant_id="t-a", pubkey_hex="a" * 64)
    assert is_visible(ExposureTag.ACCOUNT_SCOPED, cred) is False


def test_researcher_does_not_see_operator_only() -> None:
    cred = Credential.researcher(tenant_id="t-a", pubkey_hex="a" * 64)
    assert is_visible(ExposureTag.OPERATOR_ONLY, cred) is False


# ---- filter_for_credential round-trip --------------------------------------


def _populate(model_cls: type[_SampleModel]) -> _SampleModel:
    return model_cls(a="A", b="B", c="C", d="D", e="E")


def test_filter_for_maintainer_keeps_everything() -> None:
    src = _populate(_SampleModel)
    filtered = filter_for_credential(src, Credential.maintainer())
    dumped = filtered.model_dump()
    assert dumped == {"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"}


def test_filter_for_anonymous_keeps_only_public() -> None:
    src = _populate(_SampleModel)
    filtered = filter_for_credential(src, Credential.anonymous())
    dumped = filtered.model_dump()
    assert dumped["a"] == "A"
    assert dumped["b"] is None
    assert dumped["c"] is None
    assert dumped["d"] is None
    assert dumped["e"] is None  # untagged → fail-closed


def test_filter_for_matching_researcher_keeps_public_and_tenant() -> None:
    src = _populate(_SampleModel)
    cred = Credential.researcher(tenant_id="t-a", pubkey_hex="a" * 64)
    filtered = filter_for_credential(src, cred, resource_tenant_id="t-a")
    dumped = filtered.model_dump()
    assert dumped["a"] == "A"
    assert dumped["b"] == "B"
    assert dumped["c"] is None
    assert dumped["d"] is None
    assert dumped["e"] is None


def test_filter_for_other_researcher_keeps_only_public() -> None:
    src = _populate(_SampleModel)
    cred = Credential.researcher(tenant_id="t-a", pubkey_hex="a" * 64)
    filtered = filter_for_credential(src, cred, resource_tenant_id="t-b")
    dumped = filtered.model_dump()
    assert dumped["a"] == "A"
    assert dumped["b"] is None  # different tenant


def test_filter_returns_same_type() -> None:
    """filter_for_credential preserves the input model type."""
    src = _populate(_SampleModel)
    filtered = filter_for_credential(src, Credential.anonymous())
    assert isinstance(filtered, _SampleModel)
