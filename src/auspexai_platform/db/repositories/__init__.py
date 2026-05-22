"""Repositories — typed CRUD over the SQLite control DB.

One module per resource (matches the table layout in 0001_init.sql + future
migrations). Each Repository class takes a `Database` in its constructor;
methods return Pydantic models from `db.models`.

Why per-resource files instead of one big repositories.py: each repository
will grow scheduler-ish methods (find_eligible_workers, claim_next_unit,
etc.) by M6. Splitting now keeps the surface manageable.
"""

from auspexai_platform.db.repositories.accounts import AccountRepository
from auspexai_platform.db.repositories.assignments import AssignmentRepository
from auspexai_platform.db.repositories.audit import AuditRepository
from auspexai_platform.db.repositories.experiments import ExperimentRepository
from auspexai_platform.db.repositories.manifests import ManifestRepository
from auspexai_platform.db.repositories.results import ResultRepository
from auspexai_platform.db.repositories.retired_keys import RetiredKeyRepository
from auspexai_platform.db.repositories.tenants import TenantRepository
from auspexai_platform.db.repositories.work_units import WorkUnitRepository
from auspexai_platform.db.repositories.workers import WorkerRepository

__all__ = [
    "AccountRepository",
    "AssignmentRepository",
    "AuditRepository",
    "ExperimentRepository",
    "ManifestRepository",
    "ResultRepository",
    "RetiredKeyRepository",
    "TenantRepository",
    "WorkUnitRepository",
    "WorkerRepository",
]
