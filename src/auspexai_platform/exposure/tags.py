"""ExposureTag — the four field-level visibility tags from §5.18."""

from __future__ import annotations

from enum import StrEnum


class ExposureTag(StrEnum):
    """Declares which credential classes can see a field.

    Tags are declared at field level via `Annotated[T, ExposureTag.X]`. The
    filter inspects `model_fields[name].metadata` to find the tag at
    serialization time.
    """

    PUBLIC = "public"
    TENANT_SCOPED = "tenant-scoped"
    ACCOUNT_SCOPED = "account-scoped"
    OPERATOR_ONLY = "operator-only"
