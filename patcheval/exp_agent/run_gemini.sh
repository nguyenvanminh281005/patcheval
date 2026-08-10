#!/usr/bin/env bash
# run_gemini.sh — PatchEval Go runner (Gemini & OpenRouter)
#
# Usage:
#   bash run_gemini.sh smoke            # Docker-based agent run — 1 CVE (sanity check)
#   bash run_gemini.sh full             # Docker-based agent run — all Go CVEs
#   bash run_gemini.sh eval             # Evaluate latest full run (run PoC)
#   bash run_gemini.sh eval_smoke       # Evaluate latest smoke run
#   bash run_gemini.sh poc              # Snippet-level: generate patches + run PoC evaluation
#   bash run_gemini.sh poc_smoke        # Snippet-level: 1 CVE only
#   bash run_gemini.sh all              # smoke → full → eval
#
# Provider selection (default: openrouter):
#   API_PROVIDER=gemini      bash run_gemini.sh smoke
#   API_PROVIDER=openrouter  bash run_gemini.sh poc
#
# API keys — set in shell or copy .env.example → .env and fill in:
#   export GEMINI_API_KEY="AIzaSy..."
#   export OPENROUTER_API_KEY="sk-or-v1-..."
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Load .env if present (supports bash export KEY=VAL and fish set -x KEY VAL) ─
if [[ -f "$SCRIPT_DIR/.env" ]]; then
  while IFS= read -r _line || [[ -n "$_line" ]]; do
    # Skip empty lines and comments
    [[ "$_line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${_line//[[:space:]]/}" ]] && continue
    # bash: export KEY=VALUE  or  KEY=VALUE
    if [[ "$_line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      _k="${BASH_REMATCH[2]}"
      _v="${BASH_REMATCH[3]}"
      # Strip surrounding quotes
      _v="${_v#\"}" _v="${_v%\"}" _v="${_v#\'}" _v="${_v%\'}"
      export "$_k"="$_v"
    # fish: set -x KEY VALUE  or  set -gx KEY VALUE  or  set -Ux KEY VALUE
    elif [[ "$_line" =~ ^[[:space:]]*set[[:space:]]+-[a-zA-Z]*x[a-zA-Z]*[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]+(.*)$ ]]; then
      _k="${BASH_REMATCH[1]}"
      _v="${BASH_REMATCH[2]}"
      _v="${_v#\"}" _v="${_v%\"}" _v="${_v#\'}" _v="${_v%\'}"
      export "$_k"="$_v"
    fi
  done < "$SCRIPT_DIR/.env"
  unset _line _k _v
fi

if [[ -z "${GEMINI_API_KEY:-}" && -z "${OPENROUTER_API_KEY:-}" ]]; then
  echo "[!] WARNING: No API keys found." >&2
  echo "    Set GEMINI_API_KEY or OPENROUTER_API_KEY, or create $SCRIPT_DIR/.env" >&2
fi

export API_PROVIDER="${API_PROVIDER:-gemini}"
export GEMINI_MODEL="${GEMINI_MODEL:-gemini-3.5-flash}"

TOOLKIT="$SCRIPT_DIR/patcheval_toolkit.py"
DATASET_FULL="$SCRIPT_DIR/../datasets/patcheval_verified.json"
GO_DATASET="$SCRIPT_DIR/../datasets/patcheval_verified_go.json"

# ── Helpers ───────────────────────────────────────────────────────────────────

banner() {
  echo ""
  echo "══════════════════════════════════════════════════════════════════"
  echo "  PatchEval — Go / $API_PROVIDER Runner"
  echo "  Mode: ${1}"
  echo "══════════════════════════════════════════════════════════════════"
}

create_go_subset() {
  if [[ -f "$GO_DATASET" ]]; then
    echo "[✓] Go dataset already exists: $GO_DATASET"
  else
    echo "[~] Creating Go subset from patcheval_verified.json ..."
    python3 -c "
import json
src = '$DATASET_FULL'
dst = '$GO_DATASET'
with open(src) as f: data = json.load(f)
go = [d for d in data if d.get('programing_language','').lower() == 'go']
with open(dst, 'w') as f: json.dump(go, f, indent=2)
print(f'[✓] Go CVEs written: {len(go)}')
"
  fi
}

check_env() {
  echo "[Step] Validating environment..."
  if [[ "$API_PROVIDER" == "gemini" && -z "${GEMINI_API_KEY:-}" ]]; then
    echo "[✗] GEMINI_API_KEY is not set." >&2; exit 1
  elif [[ "$API_PROVIDER" == "openrouter" && -z "${OPENROUTER_API_KEY:-}" ]]; then
    echo "[✗] OPENROUTER_API_KEY is not set." >&2; exit 1
  fi
  echo "[✓] Provider: $API_PROVIDER"
}

# ── Docker-based agent runs (patch_agent_runner.py) ──────────────────────────

run_smoke() {
  echo "[Step] Starting Docker-based smoke test (1 CVE, provider: $API_PROVIDER)..."
  DATASET="$GO_DATASET" \
  LIMIT=1 \
  CONCURRENCY=1 \
  AGENT_TIMEOUT=1800 \
  bash "$SCRIPT_DIR/run_infer.sh" gemini go_smoke
  echo "[✓] Smoke test done. Check agent_runs/ for output."
}

run_full() {
  echo "[Step] Starting Docker-based full run (all Go CVEs, provider: $API_PROVIDER)..."
  DATASET="$GO_DATASET" \
  CONCURRENCY=4 \
  AGENT_TIMEOUT=1800 \
  bash "$SCRIPT_DIR/run_infer.sh" gemini go_full
  echo "[✓] Full run done."
}

# ── PoC evaluation (run_eval.sh → run_evaluation.py) ─────────────────────────

run_eval() {
  local label="${1:-go_full}"
  echo "[Step] Running PoC evaluation for label: $label ..."
  DATASET="$GO_DATASET" \
  MAX_WORKERS=4 \
  bash "$SCRIPT_DIR/run_eval.sh" "$label"
  echo ""
  echo "━━━ RESULTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  local report="$SCRIPT_DIR/../evaluation/results/$label/summary_report.txt"
  # Fallback path used by some versions of run_evaluation.py
  local report2="$SCRIPT_DIR/../evaluation/evaluation_output/results/$label/summary_report.txt"
  if [[ -f "$report" ]]; then
    cat "$report"
  elif [[ -f "$report2" ]]; then
    cat "$report2"
  else
    echo "[!] Report not found yet. Check evaluation/results/$label/"
  fi
}

# ── Snippet-level: go-generate + PoC ─────────────────────────────────────────
#
# This path skips Docker entirely.  It uses `patcheval_toolkit.py go-generate`
# to produce a .jsonl of unified-diff patches from the snippet in the dataset,
# then feeds them to run_evaluation.py (which spins up Docker containers itself
# to apply the patch and run the PoC).

run_poc() {
  local label="${1:-go_poc}"
  local limit="${2:--1}"
  local patches_jsonl="$SCRIPT_DIR/eval_inputs/${label}.jsonl"

  echo "[Step] Snippet-level patch generation (provider: $API_PROVIDER, limit: $limit)..."
  mkdir -p "$(dirname "$patches_jsonl")"

  python3 "$TOOLKIT" go-generate \
    --input "$GO_DATASET" \
    --output "$patches_jsonl" \
    --provider "$API_PROVIDER" \
    --model "${GEMINI_MODEL:-gemini-2.0-flash}" \
    --or-model "${OPENROUTER_MODEL:-google/gemma-3-27b-it}" \
    --limit "$limit" \
    --max_tokens 6000

  echo ""

  # Guard: skip evaluation if no patches were actually generated
  local n_patches=0
  if [[ -f "$patches_jsonl" ]]; then
    n_patches=$(grep -c . "$patches_jsonl" 2>/dev/null || echo 0)
  fi
  if [[ "$n_patches" -eq 0 ]]; then
    echo "[✗] No patches generated — skipping PoC evaluation."
    echo "    Check API key / provider / model and retry."
    exit 1
  fi

  echo "[✓] $n_patches patch(es) written to $patches_jsonl"
  echo ""
  echo "[Step] Running PoC evaluation on generated patches..."

  (
    cd "$SCRIPT_DIR/../evaluation"
    python3 run_evaluation.py \
      --output "results/${label}" \
      --patch_file "$patches_jsonl" \
      --input_file "$GO_DATASET" \
      --max_workers "${MAX_WORKERS:-4}" \
      --log_level "${LOG_LEVEL:-INFO}"
  )

  echo ""
  echo "━━━ RESULTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  local report="$SCRIPT_DIR/../evaluation/results/${label}/summary_report.txt"
  if [[ -f "$report" ]]; then
    cat "$report"
  else
    echo "[!] Report not found at $report — check evaluation/results/${label}/"
  fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
MODE="${1:-smoke}"
banner "$MODE"

case "$MODE" in
  smoke)
    check_env; create_go_subset; run_smoke
    ;;
  full)
    check_env; create_go_subset; run_full
    ;;
  eval)
    create_go_subset; run_eval "go_full"
    ;;
  eval_smoke)
    create_go_subset; run_eval "go_smoke"
    ;;
  poc)
    # Snippet-level: generate patches then run PoC (no Docker agent)
    check_env; create_go_subset
    run_poc "go_poc" "${LIMIT:--1}"
    ;;
  poc_smoke)
    # Snippet-level: only 1 CVE
    check_env; create_go_subset
    run_poc "go_poc_smoke" 1
    ;;
  all)
    check_env; create_go_subset
    run_smoke; run_full; run_eval "go_full"
    ;;
  *)
    echo "Usage: bash run_gemini.sh [smoke|full|eval|eval_smoke|poc|poc_smoke|all]"
    echo ""
    echo "  smoke      — Docker agent run with 1 CVE (quick sanity check)"
    echo "  full       — Docker agent run with all Go CVEs"
    echo "  eval       — Run PoC evaluation on go_full results"
    echo "  eval_smoke — Run PoC evaluation on go_smoke results"
    echo "  poc        — Snippet-level: generate patches via API + run PoC"
    echo "  poc_smoke  — Snippet-level: 1 CVE only (fastest test)"
    echo "  all        — smoke + full + eval"
    echo ""
    echo "Environment variables:"
    echo "  API_PROVIDER      gemini | openrouter  (default: openrouter)"
    echo "  GEMINI_API_KEY    Required when API_PROVIDER=gemini"
    echo "  OPENROUTER_API_KEY Required when API_PROVIDER=openrouter"
    echo "  GEMINI_MODEL      Gemini model name (default: gemini-2.0-flash)"
    echo "  OPENROUTER_MODEL  OpenRouter model (default: google/gemma-3-27b-it:free)"
    echo "  LIMIT             Max CVEs to process for poc/poc_smoke (default: -1 = all)"
    echo "  MAX_WORKERS       Parallel workers for PoC evaluation (default: 4)"
    exit 1
    ;;
esac
