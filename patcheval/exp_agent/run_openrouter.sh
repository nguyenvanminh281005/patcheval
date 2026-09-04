#!/usr/bin/env bash
# run_openrouter.sh — PatchEval runner via OpenRouter — Go, JavaScript & Python
#
# Default model: deepseek/deepseek-v4-0731
#   (DeepSeek V4 — 0731 snapshot via OpenRouter)
#
# Output structure (organized by model → language):
#   evaluation_output/results/
#   └── deepseek_v4_0731/
#       ├── go/
#       │   ├── summary_report.txt
#       │   ├── results.json
#       │   ├── pass/    ← CVE-xxx.json (per-CVE detailed result)
#       │   └── fail/    ← CVE-yyy.json
#       ├── javascript/
#       └── python/
#
# eval_inputs (patch generation outputs, organized by model):
#   eval_inputs/
#   └── deepseek_v4_0731/
#       ├── go.jsonl
#       ├── javascript.jsonl
#       └── python.jsonl
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
#   OPENROUTER_MODEL=deepseek/deepseek-r1-0528:free         bash run_openrouter.sh poc
#   OPENROUTER_MODEL=deepseek/deepseek-chat-v3-0324:free    bash run_openrouter.sh js-poc
#
# ── CONFIRMED FREE MODELS (live-verified 2026-08-19, pricing=0/0) ────────────
#
#   CODING (recommended for patch generation):
#     poolside/laguna-s-2.1:free          ctx=262k  out=32k  ← coding-specialist
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
export OPENROUTER_MODEL="${OPENROUTER_MODEL:-deepseek/deepseek-v4-flash-0731}"

if [[ -z "${OPENROUTER_API_KEY:-}" ]]; then
  echo "[✗] OPENROUTER_API_KEY is not set." >&2
  echo "    Set it in your shell or add to $SCRIPT_DIR/.env" >&2
  exit 1
fi

# ── Derive a filesystem-safe MODEL_NAME from OPENROUTER_MODEL ────────────────
# e.g. "deepseek/deepseek-v4-0731"  → "deepseek_v4_0731"
#      "poolside/laguna-s-2.1:free"  → "laguna_s_2_1"
MODEL_NAME="$(echo "$OPENROUTER_MODEL" \
  | sed 's|.*/||'              \
  | sed 's/:.*$//'             \
  | sed 's/[^a-zA-Z0-9]/_/g'  \
  | sed 's/__*/_/g'            \
  | sed 's/^_//;s/_$//')"

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
  echo "  Model     : $OPENROUTER_MODEL"
  echo "  Model name: $MODEL_NAME"
  echo "  Mode      : ${1}"
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
# run_poc <language_label> <limit> <dataset_file> <toolkit_command>
#   language_label: go | javascript | python

run_poc() {
  local lang_label="${1}"        # e.g. go, javascript, python
  local limit="${2:--1}"
  local dataset="${3}"
  local toolkit_cmd="${4}"

  # eval_inputs: organized by model → language (prevents cross-model overwrite)
  local patches_jsonl="$SCRIPT_DIR/eval_inputs/${MODEL_NAME}/${lang_label}.jsonl"

  # evaluation output: organized by model → language
  local output_label="results/${MODEL_NAME}/${lang_label}"

  echo "[Step] Snippet-level patch generation"
  echo "       cmd     : $toolkit_cmd"
  echo "       model   : $OPENROUTER_MODEL ($MODEL_NAME)"
  echo "       language: $lang_label"
  echo "       limit   : $limit"
  echo "       patches → $patches_jsonl"
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
  echo "       output → evaluation_output/${output_label}/"

  (
    cd "$SCRIPT_DIR/../evaluation"
    local skip_arg=()
    if [[ "${SKIP_EXISTING:-true}" == "true" ]]; then
      skip_arg+=(--skip_existing)
    fi

    python3 run_evaluation.py \
      --output "$output_label" \
      --patch_file "$patches_jsonl" \
      --input_file "$dataset" \
      --max_workers "${MAX_WORKERS:-4}" \
      --log_level "${LOG_LEVEL:-INFO}" \
      --limit "$limit" \
      --remove_images \
      "${skip_arg[@]}"
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
  docker system prune -f 2>/dev/null || true

  echo ""
  echo "━━━ RESULTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  local eval_dir="$SCRIPT_DIR/../evaluation/evaluation_output/${output_label}"
  local report="${eval_dir}/summary_report.txt"
  local report2="$SCRIPT_DIR/../evaluation/${output_label}/summary_report.txt"
  if [[ -f "$report" ]]; then
    cat "$report"
  elif [[ -f "$report2" ]]; then
    eval_dir="$SCRIPT_DIR/../evaluation/${output_label}"
    cat "$report2"
  else
    echo "[!] Report not found — check evaluation/evaluation_output/${output_label}/"
  fi

  echo ""
  # ── Save per-CVE PASS/FAIL JSON + results.json for EDA ──────────────────────
  echo "[Step] Saving per-CVE results (pass/ fail/ results.json)..."
  python3 "$TOOLKIT" save-eval \
    --patch-file "$patches_jsonl" \
    --eval-dir "$eval_dir" \
    --dataset "$dataset" \
    --model "$OPENROUTER_MODEL" \
    --language "$lang_label" \
    --eda-dir "$SCRIPT_DIR/eda"
}

# ── Main ──────────────────────────────────────────────────────────────────────
MODE="${1:-poc}"
banner "$MODE"

case "$MODE" in
  poc)
    # Go: generate patches then run PoC
    create_go_subset
    run_poc "go" "${LIMIT:--1}" "$GO_DATASET" "go-generate"
    ;;
  poc_smoke)
    # Go: only 1 CVE
    create_go_subset
    run_poc "go" 1 "$GO_DATASET" "go-generate"
    ;;
  js-poc)
    # JavaScript: generate patches then run PoC
    create_js_subset
    run_poc "javascript" "${LIMIT:--1}" "$JS_DATASET" "js-generate"
    ;;
  js-poc_smoke)
    # JavaScript: only 1 CVE
    create_js_subset
    run_poc "javascript" 1 "$JS_DATASET" "js-generate"
    ;;
  pt-poc)
    # Python: generate patches then run PoC
    create_py_subset
    run_poc "python" "${LIMIT:--1}" "$PY_DATASET" "py-generate"
    ;;
  pt-poc_smoke)
    # Python: only 1 CVE
    create_py_subset
    run_poc "python" 1 "$PY_DATASET" "py-generate"
    ;;
  all-poc)
    # All 3 languages sequentially
    create_go_subset; create_js_subset; create_py_subset
    echo ""
    echo "━━━ [1/3] Go ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    run_poc "go" "${LIMIT:--1}" "$GO_DATASET" "go-generate"
    echo ""
    echo "━━━ [2/3] JavaScript ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    run_poc "javascript" "${LIMIT:--1}" "$JS_DATASET" "js-generate"
    echo ""
    echo "━━━ [3/3] Python ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    run_poc "python" "${LIMIT:--1}" "$PY_DATASET" "py-generate"
    ;;
  *)
    echo "Usage: bash run_openrouter.sh [poc|poc_smoke|js-poc|js-poc_smoke|pt-poc|pt-poc_smoke|all-poc]"
    echo ""
    echo "  ── Go ──────────────────────────────────────────────────────────────"
    echo "  poc          — Generate Go patches via OpenRouter + run PoC"
    echo "  poc_smoke    — 1 Go CVE only (fastest test)"
    echo ""
    echo "  ── JavaScript ──────────────────────────────────────────────────────"
    echo "  js-poc       — Generate JS patches via OpenRouter + run PoC"
    echo "  js-poc_smoke — 1 JS CVE only"
    echo ""
    echo "  ── Python ──────────────────────────────────────────────────────────"
    echo "  pt-poc       — Generate Python patches via OpenRouter + run PoC"
    echo "  pt-poc_smoke — 1 Python CVE only"
    echo ""
    echo "  ── All ─────────────────────────────────────────────────────────────"
    echo "  all-poc      — Run all 3 languages sequentially"
    echo ""
    echo "Environment variables:"
    echo "  OPENROUTER_API_KEY  Required (sk-or-v1-...)"
    echo "  OPENROUTER_MODEL    Model to use (default: deepseek/deepseek-v4-0731)"
    echo "                      ── CONFIRMED FREE (live-verified 2026-08-19) ──"
    echo "                      CODING (patch generation):"
    echo "                        deepseek/deepseek-v4-0731           ← DEFAULT"
    echo "                        poolside/laguna-s-2.1:free          ctx=262k"
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
