"""Field-exposure filter (§5.18, M3).

Every response field carries an `ExposureTag` declared via Pydantic
`Annotated[T, ExposureTag.X]`. At response time, the coordinator filters
fields per the requester's credential class + tenant_id at field-level
granularity. Same endpoints serve all credential classes; the response body
is filtered, not the API.

Four tags:
  - `public`        — visible to any credential class, incl. anonymous
  - `tenant-scoped` — visible when requester's tenant matches the resource's
  - `account-scoped` — visible only to the bound account (Phase 2-3; the hooks
                      exist now so adding it later is a filter implementation,
                      not a refactor)
  - `operator-only` — maintainer only

Fail-closed default: a field without an explicit tag is treated as
`operator-only`. Routes that forget to tag a new field don't accidentally
leak it to anonymous/researcher callers.

Usage pattern:

    class FooResponse(BaseModel):
        public_field: Annotated[str, ExposureTag.PUBLIC]
        tenant_field: Annotated[str | None, ExposureTag.TENANT_SCOPED] = None
        secret_field: Annotated[str | None, ExposureTag.OPERATOR_ONLY] = None

    @router.get("/foo", response_model=FooResponse, response_model_exclude_none=True)
    async def foo(credential = Depends(get_credential)):
        payload = FooResponse(...)
        return filter_for_credential(payload, credential, resource_tenant_id=...)
"""

from auspexai_platform.exposure.filter import (
    field_exposure_tag,
    filter_for_credential,
    is_visible,
)
from auspexai_platform.exposure.tags import ExposureTag

__all__ = [
    "ExposureTag",
    "field_exposure_tag",
    "filter_for_credential",
    "is_visible",
]
