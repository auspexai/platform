"""Field-exposure filter implementation.

Two layers:

  - `is_visible(tag, credential, ...)` — pure decision function. Given a tag,
    a requesting credential, and the resource's tenant/account context, decide
    whether the field is visible.
  - `filter_for_credential(model, credential, ...)` — applies `is_visible` to
    each field on a Pydantic model. Returns a *new* model instance constructed
    via `model_construct` (bypasses validation; we're producing legal-by-design
    output where invisible fields become None).

Combine with `response_model_exclude_none=True` on the FastAPI route so the
None-marked invisible fields drop from the rendered JSON.

This module does NOT recurse into nested Pydantic models. For v0 the parent
field's tag gates the entire subtree. When a resource model carries nested
sub-models with their own per-field tags (Receipt with nested QuorumAgreement,
Worker with nested Capabilities, etc.), the route is responsible for either
flattening to a single tag-tier per sub-tree, or filtering the sub-model
explicitly with its own `filter_for_credential` call. We can grow recursion
into this module when M5+ routes demonstrate the need.
"""

from __future__ import annotations

from typing import TypeVar

from pydantic import BaseModel
from pydantic.fields import FieldInfo

from auspexai_platform.auth.credential import Credential
from auspexai_platform.exposure.tags import ExposureTag

ModelT = TypeVar("ModelT", bound=BaseModel)


def field_exposure_tag(field_info: FieldInfo) -> ExposureTag:
    """Extract the ExposureTag from a field's Annotated metadata.

    Default: `ExposureTag.OPERATOR_ONLY` (fail-closed). A response model that
    forgets to tag a field hides it from everyone except the maintainer.
    """
    for m in field_info.metadata:
        if isinstance(m, ExposureTag):
            return m
    return ExposureTag.OPERATOR_ONLY


def is_visible(
    tag: ExposureTag,
    credential: Credential,
    *,
    resource_tenant_id: str | None = None,
    resource_account_id: str | None = None,
) -> bool:
    """Decide whether a field with `tag` is visible to `credential`.

    Maintainer credential always sees everything (operator union view per §5.18).
    For others, the tag chooses the rule.

    `resource_tenant_id` / `resource_account_id` are the tenant / account that
    owns the resource being serialized. They're the comparison target for
    tenant-scoped / account-scoped fields. None means "not bound to anyone,"
    which fails visibility for those scopes (since `credential.tenant_id ==
    None` is not the same as "matches" — the request itself isn't tenant-bound).
    """
    if credential.is_maintainer():
        return True

    if tag is ExposureTag.PUBLIC:
        return True

    if tag is ExposureTag.TENANT_SCOPED:
        if (
            credential.is_researcher()
            and credential.tenant_id is not None
            and resource_tenant_id is not None
            and credential.tenant_id == resource_tenant_id
        ):
            return True
        # Tier-1: the ACCOUNT that RAN this experiment (under a public tenant it
        # does not own) sees its OWN run's tenant-scoped fields. Scoped strictly
        # to the runner account (account_id == resource_account_id, which the
        # experiment routes set to submitted_by_account_id) — so an account never
        # sees another account's run, nor the owning tenant's other rows.
        return (
            credential.is_account()
            and credential.account_id is not None
            and resource_account_id is not None
            and credential.account_id == resource_account_id
        )

    if tag is ExposureTag.ACCOUNT_SCOPED:
        # b-lite: visible to a credential that proves membership of the account
        # owning the resource. A researcher credential carries account_id once
        # its tenant is linked (tenants.account_id); a worker credential carries
        # it once account-bound. Either passes when the ids match. Credentials
        # with no linked account (account_id is None) see nothing here — only
        # the maintainer (short-circuited above) does.
        return (
            credential.account_id is not None
            and resource_account_id is not None
            and credential.account_id == resource_account_id
        )

    if tag is ExposureTag.OPERATOR_ONLY:
        return False

    # Defensive: an unknown tag is fail-closed.
    return False


def filter_for_credential(
    model: ModelT,
    credential: Credential,
    *,
    resource_tenant_id: str | None = None,
    resource_account_id: str | None = None,
) -> ModelT:
    """Return a copy of `model` with non-visible fields set to None.

    Caller must use `response_model_exclude_none=True` on the FastAPI route
    for the None fields to drop from the rendered JSON.

    The returned model is built via `model_construct`, which skips field
    validation — necessary because the filtered version may legally hold None
    where the source value was required. Routes should ensure their response
    models declare filtered fields as Optional (`T | None` with a default).
    """
    cls = type(model)
    raw = model.model_dump(mode="python")
    masked: dict[str, object] = {}
    for name, info in cls.model_fields.items():
        tag = field_exposure_tag(info)
        if is_visible(
            tag,
            credential,
            resource_tenant_id=resource_tenant_id,
            resource_account_id=resource_account_id,
        ):
            masked[name] = raw.get(name)
        else:
            masked[name] = None
    return cls.model_construct(**masked)
