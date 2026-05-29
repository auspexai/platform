"""AuspexAI coordinator daemon and platform infrastructure.

The platform speaks JSON over HTTP to four Phase 1 consumers: the worker daemon,
the tenant SDK, the operator console, and the researcher dashboard. The public
receipt verifier is a fifth consumer via the anonymous-public credential class.
See `Documentation/AuspexAI/v0.1.0/operator_console_design.md` (in the
companion Documentation/ tree) and §5.18 of the Principles & Scope doc for
the API contract.
"""

from importlib.metadata import version as _v

# Git-derived (hatch-vcs), read from installed package metadata — no
# hand-maintained string. See version_provenance.md.
__version__ = _v("auspexai-platform")
