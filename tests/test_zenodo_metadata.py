"""Zenodo DOI metadata shape (records API).

Regression (2026-07-09): the mint uses the modern RDM records API, which requires
creators in the `person_or_org` shape. Passing the legacy deposit shape
(`[{"name": ...}]`) is DROPPED on draft-create and then rejected at publish
(`metadata.creators: Missing data for required field`) — which silently failed
EVERY DOI mint at the final step. These lock the RDM shape in.
"""

from __future__ import annotations

from auspexai_platform.zenodo import experiment_doi_metadata


def test_default_creators_are_rdm_person_or_org():
    md = experiment_doi_metadata(
        title="t", description_html="<p>d</p>", creators=[], related_urls=[]
    )
    # The ratified default: AuspexAI Network as an ORGANIZATIONAL creator, in the
    # records-API `person_or_org` envelope — NOT the legacy `{"name": ...}`.
    assert md["creators"] == [
        {"person_or_org": {"type": "organizational", "name": "AuspexAI Network"}}
    ]


def test_contributors_are_rdm_person_or_org():
    md = experiment_doi_metadata(
        title="t", description_html="<p>d</p>", creators=[], related_urls=[], contributors=["Ada"]
    )
    assert md["contributors"] == [
        {"person_or_org": {"type": "personal", "family_name": "Ada"}, "role": {"id": "other"}}
    ]


def test_required_publish_fields_present():
    """The fields Zenodo validates at publish — a missing one 400s the whole mint."""
    md = experiment_doi_metadata(
        title="AuspexAI verified experiment: x",
        description_html="<p>d</p>",
        creators=[],
        related_urls=["https://auspexai.network/benchmarks.html"],
    )
    for field in ("title", "publication_date", "resource_type", "creators", "publisher"):
        assert md.get(field), f"missing required publish field: {field}"
