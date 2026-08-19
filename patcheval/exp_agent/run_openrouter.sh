#!/usr/bin/env bash
# run_openrouter.sh — PatchEval runner via OpenRouter — Go, JavaScript & Python
#
# Default model: poolside/laguna-s-2.1:free
#   (Verified FREE as of 2026-08-19 via GET /api/v1/models — pricing=0)
#
# Output labels (evaluation results):
#   Go         → evaluation_output/results/gogemma_poc/
#   JavaScript → evaluation_output/results/jsgemma_poc/
#   Python     → evaluation_output/results/ptgemma_poc/
#
# Usage:
#   bash run_openrouter.sh poc            # Go: generate patches + run PoC
#   bash run_openrouter.sh poc_smoke      # Go: 1 CVE only
#   bash run_openrouter.sh js-poc         # JavaScript: generate patches + run PoC
#   bash run_openrouter.sh js-poc_smoke   # JavaScript: 1 CVE only
#   bash run_openrouter.sh pt-poc         # Python: generate patches + run PoC
#   bash run_openrouter.sh pt-poc_smoke   # Python: 1 CVE only
#   bash run_openrouter.sh all-poc        # All 3 languages sequentially
#
# Override model at runtime:
#   OPENROUTER_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free  bash run_openrouter.sh poc
#   OPENROUTER_MODEL=nvidia/nemotron-3-super-120b-a12b:free  bash run_openrouter.sh js-poc
#
# ── CONFIRMED FREE MODELS (live-verified 2026-08-19, pricing=0/0) ────────────
#
#   CODING (recommended for patch generation):
#     poolside/laguna-s-2.1:free          ctx=262k  out=32k  ← DEFAULT, coding-specialist
#     poolside/laguna-xs-2.1:free         ctx=262k  out=32k  ← smaller/faster Laguna
#     cohere/north-mini-code:free         ctx=256k  out=64k  ← code-focused MoE
#     nvidia/nemotron-3-super-120b-a12b:free  ctx=262k  out=262k  ← large, high quality
#
#   REASONING (for analysis / complex logic):
#     nvidia/nemotron-3-ultra-550b-a55b:free  ctx=1M  out=64k  ← largest free model
#     nvidia/nemotron-3.5-lightning:free      ctx=1M  out=64k  ← fast MoE
#     z-ai/glm-5.2:free                       ctx=256k  out=256k ← reasoning
#
#   LIGHTWEIGHT (log parsing, quick tasks):
#     openai/gpt-oss-20b:free             ctx=131k  out=32k
#     nvidia/nemotron-3-nano-30b-a3b:free ctx=256k
#     google/gemma-4-26b-a4b-it:free      ctx=262k  out=32k
#     openrouter/free                     ctx=200k  (random free model)
#
# API key — set in shell or add to .env:
#   export OPENROUTER_API_KEY="sk-or-v1-..."
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Load .env if present ──────────────────────────────────────────────────────
if [[ -f "$SCRIPT_DIR/.env" ]]; then
  while IFS= read -r _line || [[ -n "$_line" ]]; do
    [[ "$_line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${_line//[[:space:]]/}" ]] && continue
    if [[ "$_line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      _k="${BASH_REMATCH[2]}"
      _v="${BASH_REMATCH[3]}"
      _v="${_v#\"}" _v="${_v%\"}" _v="${_v#\'}" _v="${_v%\'}"
      export "$_k"="$_v"
    elif [[ "$_line" =~ ^[[:space:]]*set[[:space:]]+-[a-zA-Z]*x[a-zA-Z]*[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]+(.*)$ ]]; then
      _k="${BASH_REMATCH[1]}"
      _v="${BASH_REMATCH[2]}"
      _v="${_v#\"}" _v="${_v%\"}" _v="${_v#\'}" _v="${_v%\'}"
      export "$_k"="$_v"
    fi
  done < "$SCRIPT_DIR/.env"
  unset _line _k _v
fi

# ── Force OpenRouter + default model ─────────────────────────────────────────
export API_PROVIDER="openrouter"
export OPENROUTER_MODEL="${OPENROUTER_MODEL:-poolside/laguna-s-2.1:free}"

if [[ -z "${OPENROUTER_API_KEY:-}" ]]; then
  echo "[✗] OPENROUTER_API_KEY is not set." >&2
  echo "    Set it in your shell or add to $SCRIPT_DIR/.env" >&2
  exit 1
fi

TOOLKIT="$SCRIPT_DIR/patcheval_toolkit.py"
DATASET_FULL="$SCRIPT_DIR/../datasets/patcheval_verified.json"
GO_DATASET="$SCRIPT_DIR/../datasets/patcheval_verified_go.json"
JS_DATASET="$SCRIPT_DIR/../datasets/patcheval_verified_js.json"
PY_DATASET="$SCRIPT_DIR/../datasets/patcheval_verified_python.json"

# ── Helpers ───────────────────────────────────────────────────────────────────

banner() {
  echo ""
  echo "══════════════════════════════════════════════════════════════════"
  echo "  PatchEval — OpenRouter Runner (Go / JS / Python)"
  echo "  Model : $OPENROUTER_MODEL"
  echo "  Mode  : ${1}"
  echo "══════════════════════════════════════════════════════════════════"
}

create_go_subset() {
  if [[ -f "$GO_DATASET" ]]; then
    echo "[✓] Go dataset already exists: $GO_DATASET"
  else
    echo "[~] Creating Go subset..."
    python3 -c "
import json
with open('$DATASET_FULL') as f: data = json.load(f)
go = [d for d in data if d.get('programing_language','').lower() == 'go']
with open('$GO_DATASET', 'w') as f: json.dump(go, f, indent=2)
print(f'[✓] Go CVEs written: {len(go)}')
"
  fi
}

create_js_subset() {
  if [[ -f "$JS_DATASET" ]]; then
    echo "[✓] JavaScript dataset already exists: $JS_DATASET"
  else
    echo "[~] Creating JavaScript subset..."
    python3 -c "
import json
with open('$DATASET_FULL') as f: data = json.load(f)
js = [d for d in data if d.get('programing_language','').lower() == 'javascript']
with open('$JS_DATASET', 'w') as f: json.dump(js, f, indent=2)
print(f'[✓] JavaScript CVEs written: {len(js)}')
"
  fi
}

create_py_subset() {
  if [[ -f "$PY_DATASET" ]]; then
    echo "[✓] Python dataset already exists: $PY_DATASET"
  else
    echo "[~] Creating Python subset..."
    python3 -c "
import json
with open('$DATASET_FULL') as f: data = json.load(f)
py = [d for d in data if d.get('programing_language','').lower() == 'python']
with open('$PY_DATASET', 'w') as f: json.dump(py, f, indent=2)
print(f'[✓] Python CVEs written: {len(py)}')
"
  fi
}

# ── Generic snippet-level PoC runner ─────────────────────────────────────────
#
# run_poc <label> <limit> <dataset_file> <toolkit_command>

run_poc() {
  local label="${1}"
  local limit="${2:--1}"
  local dataset="${3}"
  local toolkit_cmd="${4}"
  local patches_jsonl="$SCRIPT_DIR/eval_inputs/${label}.jsonl"

  echo "[Step] Snippet-level patch generation"
  echo "       cmd     : $toolkit_cmd"
  echo "       model   : $OPENROUTER_MODEL"
  echo "       label   : $label"
  echo "       limit   : $limit"
  mkdir -p "$(dirname "$patches_jsonl")"

  python3 "$TOOLKIT" "$toolkit_cmd" \
    --input "$dataset" \
    --output "$patches_jsonl" \
    --provider openrouter \
    --or-model "$OPENROUTER_MODEL" \
    --limit "$limit" \
    --max_tokens 6000

  echo ""

  # Guard: skip evaluation if no patches were generated
  local n_patches=0
  if [[ -f "$patches_jsonl" ]]; then
    n_patches=$(grep -c . "$patches_jsonl" 2>/dev/null || echo 0)
  fi
  if [[ "$n_patches" -eq 0 ]]; then
    echo "[✗] No patches generated — skipping PoC evaluation."
    echo "    Check OPENROUTER_API_KEY / model name and retry."
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
      --input_file "$dataset" \
      --max_workers "${MAX_WORKERS:-4}" \
      --log_level "${LOG_LEVEL:-INFO}" \
      --skip_existing \
      --limit "$limit" \
      --remove_images
  )

  # ── Docker cleanup ────────────────────────────────────────────────────────────
  echo ""
  echo "[Step] Cleaning up Docker containers..."
  local stale_containers
  stale_containers=$(docker ps -aq --filter "status=exited" --filter "status=created" 2>/dev/null || true)
  if [[ -n "$stale_containers" ]]; then
    # shellcheck disable=SC2086
    docker rm -f $stale_containers 2>/dev/null && echo "[✓] Docker containers removed." || echo "[!] Some containers could not be removed."
  else
    echo "[✓] No stale Docker containers to remove."
  fi

  echo ""
  echo "━━━ RESULTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  local report="$SCRIPT_DIR/../evaluation/results/${label}/summary_report.txt"
  local report2="$SCRIPT_DIR/../evaluation/evaluation_output/results/${label}/summary_report.txt"
  if [[ -f "$report" ]]; then
    cat "$report"
  elif [[ -f "$report2" ]]; then
    cat "$report2"
  else
    echo "[!] Report not found — check evaluation/results/${label}/"
  fi

  echo ""
  # ── Save evaluation results & failure analysis for EDA ─────────────────────
  local eval_dir="$SCRIPT_DIR/../evaluation/evaluation_output/results/${label}"
  if [[ ! -d "$eval_dir" ]]; then
    eval_dir="$SCRIPT_DIR/../evaluation/results/${label}"
  fi
  python3 "$TOOLKIT" save-eval \
    --patch-file "$patches_jsonl" \
    --eval-dir "$eval_dir" \
    --dataset "$dataset" \
    --eda-dir "$SCRIPT_DIR/eda"
}

# ── Main ──────────────────────────────────────────────────────────────────────
MODE="${1:-poc}"
banner "$MODE"

case "$MODE" in
  poc)
    # Go: generate patches then run PoC → gogemma_poc
    create_go_subset
    run_poc "gogemma_poc" "${LIMIT:--1}" "$GO_DATASET" "go-generate"
    ;;
  poc_smoke)
    # Go: only 1 CVE → gogemma_poc_smoke
    create_go_subset
    run_poc "gogemma_poc_smoke" 1 "$GO_DATASET" "go-generate"
    ;;
  js-poc)
    # JavaScript: generate patches then run PoC → jsgemma_poc
    create_js_subset
    run_poc "jsgemma_poc" "${LIMIT:--1}" "$JS_DATASET" "js-generate"
    ;;
  js-poc_smoke)
    # JavaScript: only 1 CVE → jsgemma_poc_smoke
    create_js_subset
    run_poc "jsgemma_poc_smoke" 1 "$JS_DATASET" "js-generate"
    ;;
  pt-poc)
    # Python: generate patches then run PoC → ptgemma_poc
    create_py_subset
    run_poc "ptgemma_poc" "${LIMIT:--1}" "$PY_DATASET" "py-generate"
    ;;
  pt-poc_smoke)
    # Python: only 1 CVE → ptgemma_poc_smoke
    create_py_subset
    run_poc "ptgemma_poc_smoke" 1 "$PY_DATASET" "py-generate"
    ;;
  all-poc)
    # All 3 languages sequentially
    create_go_subset; create_js_subset; create_py_subset
    echo ""
    echo "━━━ [1/3] Go ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    run_poc "gogemma_poc" "${LIMIT:--1}" "$GO_DATASET" "go-generate"
    echo ""
    echo "━━━ [2/3] JavaScript ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    run_poc "jsgemma_poc" "${LIMIT:--1}" "$JS_DATASET" "js-generate"
    echo ""
    echo "━━━ [3/3] Python ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    run_poc "ptgemma_poc" "${LIMIT:--1}" "$PY_DATASET" "py-generate"
    ;;
  *)
    echo "Usage: bash run_openrouter.sh [poc|poc_smoke|js-poc|js-poc_smoke|pt-poc|pt-poc_smoke|all-poc]"
    echo ""
    echo "  ── Go (→ gogemma_poc) ──────────────────────────────────────────────"
    echo "  poc          — Generate Go patches via OpenRouter + run PoC"
    echo "  poc_smoke    — 1 Go CVE only (fastest test)"
    echo ""
    echo "  ── JavaScript (→ jsgemma_poc) ──────────────────────────────────────"
    echo "  js-poc       — Generate JS patches via OpenRouter + run PoC"
    echo "  js-poc_smoke — 1 JS CVE only"
    echo ""
    echo "  ── Python (→ ptgemma_poc) ──────────────────────────────────────────"
    echo "  pt-poc       — Generate Python patches via OpenRouter + run PoC"
    echo "  pt-poc_smoke — 1 Python CVE only"
    echo ""
    echo "  ── All ─────────────────────────────────────────────────────────────"
    echo "  all-poc      — Run all 3 languages sequentially"
    echo ""
    echo "Environment variables:"
    echo "  OPENROUTER_API_KEY  Required (sk-or-v1-...)"
    echo "  OPENROUTER_MODEL    Model to use (default: poolside/laguna-s-2.1:free)"
    echo "                      ── CONFIRMED FREE (live-verified 2026-08-19) ──"
    echo "                      CODING (patch generation):"
    echo "                        poolside/laguna-s-2.1:free          ctx=262k ← DEFAULT"
    echo "                        poolside/laguna-xs-2.1:free          ctx=262k (smaller)"
    echo "                        cohere/north-mini-code:free          ctx=256k"
    echo "                        nvidia/nemotron-3-super-120b-a12b:free  ctx=262k"
    echo "                      REASONING:"
    echo "                        nvidia/nemotron-3-ultra-550b-a55b:free  ctx=1M"
    echo "                        nvidia/nemotron-3.5-lightning:free       ctx=1M"
    echo "                        z-ai/glm-5.2:free                       ctx=256k"
    echo "                      LIGHTWEIGHT:"
    echo "                        openai/gpt-oss-20b:free               ctx=131k"
    echo "                        google/gemma-4-26b-a4b-it:free        ctx=262k"
    echo "                        openrouter/free                        (random free)"
    echo "  LIMIT               Max CVEs to process (default: -1 = all)"
    echo "  MAX_WORKERS         Parallel workers for PoC evaluation (default: 4)"
    exit 1
    ;;
esac
