-- 0029_tenant_application_research_classes.sql — structured research classes
-- on tenant applications.
--
-- Applicants may now declare which of the §11 research-envelope
-- enabled-today classes their work falls under (behavioral_drift,
-- eval_sweeps, refusal_boundary_mapping, cross_model_comparison,
-- quantization_effects, prompt_sensitivity, other — the taxonomy lives in
-- `api/tenant_applications.py` as RESEARCH_CLASSES). Stored as a JSON array
-- of validated, deduplicated class ids. NULL = no classes declared
-- (pre-migration rows, or summary-only applications) — surfaced as [] in
-- API responses, so the column is additive. With this, `research_summary`
-- becomes optional at the API layer: at least one of (classes, summary) is
-- required at submit time; the existing NOT NULL column stores '' when the
-- summary is omitted.

ALTER TABLE tenant_applications ADD COLUMN research_classes_json TEXT;
