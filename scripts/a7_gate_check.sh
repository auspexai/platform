#!/usr/bin/env bash
# A7 gate-green check — run BEFORE flipping `trust_model_policy` ON (the firewall-#1
# equal-trust activation). Verifies the 5 A7 conditions + the #32 containment
# binding live on the fleet + the flip-activation REHEARSAL, and confirms the flip
# is still OFF. All GREEN ⇒ the gate is green and the flip is a safe, deliberate
# next act. Read-only except the rehearsal, which runs on a throwaway test DB and
# never touches the live coordinator. Run on rage from the platform repo.
#
#   bash scripts/a7_gate_check.sh
#
# See Documentation/AuspexAI/v0.1.0/a7_gate_green_check.md for what each line means.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

PASS=0
FAIL=0
g() { printf "  \033[32m● GREEN\033[0m  %s\n" "$1"; PASS=$((PASS + 1)); }
r() { printf "  \033[31m● RED  \033[0m  %s\n" "$1"; FAIL=$((FAIL + 1)); }

DB=/var/lib/auspexai-coordinator/coordinator.db
echo "═══ A7 gate-green check ═══"

# ── #3 floor + #4 instrumentation + #5 conformance + #32 binding + flip rehearsal ──
# The named proofs (a6 manifest is the index). All must pass — incl. the rehearsal
# that flips ON in a test DB and shows a STRICT v2 divergence earning equal trust.
if uv run --extra dev pytest -q \
  tests/test_firewall_conformance_a6.py \
  tests/test_independence_floor_a4.py \
  tests/test_signals_a5.py \
  tests/test_equal_trust_accrual_a2.py \
  tests/test_result_signature_v2.py \
  tests/test_containment_binding_route_a2.py \
  tests/test_a7_gate_rehearsal.py >/tmp/a7_gate.log 2>&1; then
  g "#3 A4 floor · #4 A5 instrumentation · #5 A6 conformance (8/8) · #32 binding · flip rehearsal — all proofs pass"
else
  r "conformance/flip proofs FAILED — see /tmp/a7_gate.log"; tail -6 /tmp/a7_gate.log
fi

# ── #1 (M3 served-weights verify-at-submit) + the deployed coordinator ──
H=$(curl -s --max-time 5 127.0.0.1:4226/api/v0/health/public 2>/dev/null)
if echo "$H" | grep -q '"version":"0.1.60"'; then
  g "#1 M3 + deployed coordinator: live at v0.1.60 (verify-at-submit + #32 v2-verify shipped)"
else
  r "coordinator not at v0.1.60 (M3/#32 may not be deployed): ${H:-no response}"
fi

# ── #2 (B1 STRICT containment red-team) — latest redteam.yml on the GCP runner ──
RT=$(gh run list --repo auspexai/worker --workflow=redteam.yml --limit 1 \
  --json conclusion -q '.[0].conclusion' 2>/dev/null)
[ "$RT" = "success" ] &&
  g "#2 B1 STRICT containment: latest redteam.yml run green (7/7 under cgroup delegation)" ||
  r "#2 B1 red-team not green (latest redteam.yml conclusion='${RT:-unknown}')"

# ── #32 LIVE on the fleet: workers signing v2 (worker_version >= 0.2.20) ──
VERS=$(sudo sqlite3 "$DB" \
  "SELECT DISTINCT json_extract(capabilities_json,'\$.worker_version') FROM workers WHERE retired_at IS NULL;" \
  2>/dev/null | tr '\n' ' ')
if echo "$VERS" | grep -qE "0\.2\.(2[0-9]|[3-9][0-9])"; then
  g "#32 fleet signing v2 ran_under: worker versions [$VERS]"
else
  r "fleet not on a v2-signing worker (>=0.2.20): [${VERS:-none}]"
fi

# ── Sanity: the flip is still OFF (activation is the deliberate next act) ──
OFF=$(sudo sqlite3 "$DB" "SELECT equal_trust_enabled FROM trust_model_policy;" 2>/dev/null)
[ "$OFF" = "0" ] &&
  g "trust_model_policy currently OFF — flipping ON is the pending deliberate governance act" ||
  r "trust_model_policy is already '${OFF:-?}' (expected 0/OFF)"

echo "───────────────────────────"
if [ "$FAIL" -eq 0 ]; then
  printf "  \033[32mGATE GREEN\033[0m — %d/%d checks pass. Safe to flip when there is a reason to.\n" "$PASS" "$PASS"
  echo "  Flip:  POST /api/v0/trust-model-policy {\"equal_trust_enabled\": true, \"reason\": \"...\"}  (maintainer, reason required)"
else
  printf "  \033[31mGATE NOT GREEN\033[0m — %d check(s) RED. Do NOT flip.\n" "$FAIL"
fi
exit "$FAIL"
