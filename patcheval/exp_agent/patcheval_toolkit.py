#!/usr/bin/env python3
"""PatchEval toolkit — Python EDA/generate/export + Go patch generation (Gemini & OpenRouter).

Sub-commands
────────────
  eda             EDA for Python CVE subset
  complexity      Structural complexity analysis (Python, requires radon)
  generate        Batch patch generation for Python CVEs via Gemini API
  export          HTML/CSV analysis report + gap analysis

  go-generate     Batch snippet-level patch generation for Go CVEs
                  (supports --provider gemini|openrouter)
  go-agent        Agent mode used by Docker runner (patch_agent_runner.py)
                  reads a prompt file, discovers Go files, asks LLM to select
                  the most relevant ones, then writes fix.patch to /workspace/fix.patch

  check-bytes     Debug: detect hidden \\r\\n in .jsonl files
  extract-patch   Extract a single CVE's patch to a standalone .patch file
"""

from __future__ import annotations

import argparse
import ast
import csv
import datetime
import difflib
import json
import os
import re
import sys
import textwrap
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional

try:
    from radon.complexity import cc_visit
    HAS_RADON = True
except ImportError:
    HAS_RADON = False


# =====================================================================
# Shared logging helper
# =====================================================================

def _log(msg: str, log_path: str = "/results/agent_live_status.log") -> None:
    print(f"[AGENT LOG] {msg}", file=sys.stderr, flush=True)
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[AGENT LOG] {msg}\n")
    except Exception:
        pass


# =====================================================================
# Token usage persistence
# =====================================================================

def _token_usage_path(output_path: str) -> str:
    """Return the companion token usage JSON path for a given .jsonl output path.
    E.g.  eval_inputs/gogemma_poc.jsonl  →  eval_inputs/gogemma_poc.token_usage.json
    """
    p = Path(output_path)
    return str(p.parent / (p.stem + ".token_usage.json"))


def _save_token_usage(
    output_path: str,
    cve_rows: list,          # list of per-CVE dicts accumulated during run
    model: str,
    provider: str,
) -> None:
    """Merge new cve_rows into the companion token_usage.json and write it atomically.

    File schema:
    {
      "model":    "poolside/laguna-s-2.1:free",
      "provider": "openrouter",
      "updated_at": "2026-08-19T01:11:08",
      "session_total": { "prompt_tokens": N, "completion_tokens": N, "total_tokens": N },
      "cves": [
        { "cve": "CVE-...", "prompt_tokens": N, "completion_tokens": N,
          "total_tokens": N, "timestamp": "2026-08-19T01:11:08" },
        ...
      ]
    }
    """
    usage_path = _token_usage_path(output_path)

    # Load existing data so resume runs accumulate correctly
    existing: dict = {}
    if os.path.exists(usage_path):
        try:
            with open(usage_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = {}

    # Merge: keep existing CVE rows; overwrite if same CVE re-processed
    existing_by_cve: dict = {r["cve"]: r for r in existing.get("cves", [])}
    for row in cve_rows:
        existing_by_cve[row["cve"]] = row

    all_rows = sorted(existing_by_cve.values(), key=lambda r: r.get("timestamp", ""))

    total_prompt     = sum(r.get("prompt_tokens", 0)     for r in all_rows)
    total_completion = sum(r.get("completion_tokens", 0) for r in all_rows)

    payload = {
        "model":    model,
        "provider": provider,
        "updated_at": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "session_total": {
            "prompt_tokens":     total_prompt,
            "completion_tokens": total_completion,
            "total_tokens":      total_prompt + total_completion,
        },
        "cves": all_rows,
    }

    Path(usage_path).parent.mkdir(parents=True, exist_ok=True)
    with open(usage_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"[✓] Token usage saved → {usage_path}  ({len(all_rows)} CVEs total)")


# =====================================================================
# Evaluation results persistence & EDA failure breakdown
# =====================================================================

def _eval_results_path(output_path: str) -> str:
    """Return the companion evaluation results JSON path for a given .jsonl output path.
    E.g.  eval_inputs/gogemma_poc.jsonl  →  eval_inputs/gogemma_poc.eval_results.json
    """
    p = Path(output_path)
    return str(p.parent / (p.stem + ".eval_results.json"))


def _extract_error_preview(error_text: str, vtype: str) -> str:
    """Extract a concise preview of why the patch or evaluation failed."""
    if not error_text:
        return ""
    if vtype == "apply_fail":
        lines = [l.strip() for l in error_text.splitlines() if "patch does not apply" in l or "patch failed" in l or "error:" in l]
        if lines:
            return "; ".join(lines[:3])
    elif vtype == "compilation_fail":
        lines = [l.strip() for l in error_text.splitlines() if re.search(r"(\.go:\d+:\d+:|SyntaxError|TypeError|IndentationError|undefined)", l)]
        if lines:
            return "; ".join(lines[:3])
    elif vtype == "validation_fail":
        lines = [l.strip() for l in error_text.splitlines() if l.startswith("--- FAIL:") or l.startswith("FAIL:") or ("FAIL" in l and "\t" in l)]
        if lines:
            return "; ".join(lines[:3])

    if "Standard Error" in error_text:
        part = error_text.split("Standard Error")[1].split("Finish Evaluation")[0].strip("- \n")
        lines = [l.strip() for l in part.splitlines() if l.strip()]
        if lines:
            return "; ".join(lines[:3])
    return "Evaluation failed"


def _find_eval_summary_and_logs(eval_dir_or_path: str) -> tuple[Optional[Path], Optional[Path]]:
    """Locate summary.json and logs directory from a provided path or directory name."""
    p = Path(eval_dir_or_path)
    candidates = [
        p,
        Path.cwd() / p,
        Path.cwd() / "evaluation" / "evaluation_output" / p,
        Path.cwd() / "evaluation" / p,
        Path.cwd() / "evaluation_output" / p,
        Path.cwd().parent / "evaluation" / "evaluation_output" / p,
        Path.cwd().parent / "evaluation" / p,
    ]
    for c in candidates:
        if c.is_file() and c.name == "summary.json":
            logs = c.parent / "logs"
            return c, (logs if logs.is_dir() else None)
        if c.is_dir():
            s = c / "summary.json"
            if s.is_file():
                logs = c / "logs"
                return s, (logs if logs.is_dir() else None)
    return None, None


def _save_eval_results(
    patch_file: str,
    eval_dir: str,
    dataset_path: Optional[str] = None,
    eda_dir: Optional[str] = None,
) -> dict:
    """Consolidate PoC evaluation output, failure analysis breakdown (apply_fail,
    compilation_fail, validation_fail), per-CVE results, and token usage into:
      1. Companion JSON: eval_inputs/<label>.eval_results.json
      2. EDA JSON: <eda_dir>/<label>_eda.json and <eda_dir>/all_eval_summary.json

    Prints a clear summary matching the token usage output pattern.
    """
    summary_path, logs_dir = _find_eval_summary_and_logs(eval_dir)
    if not summary_path or not summary_path.is_file():
        print(f"[!] Warning: summary.json not found in {eval_dir}, skipping eval_results save.")
        return {}

    summary_data = {}
    try:
        with open(summary_path, "r", encoding="utf-8") as f:
            summary_data = json.load(f)
    except Exception as e:
        print(f"[!] Error reading {summary_path}: {e}")
        return {}

    # Read token usage companion if available
    token_usage_file = _token_usage_path(patch_file)
    token_usage_data = {}
    if os.path.exists(token_usage_file):
        try:
            with open(token_usage_file, "r", encoding="utf-8") as f:
                token_usage_data = json.load(f)
        except Exception:
            token_usage_data = {}

    token_by_cve = {r["cve"]: r for r in token_usage_data.get("cves", [])}
    model_name = token_usage_data.get("model", "")
    provider_name = token_usage_data.get("provider", "")

    # Read patch lines to map CVE info & language & fallback tokens
    patch_records = {}
    if os.path.exists(patch_file):
        try:
            with open(patch_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        rec = json.loads(line)
                        patch_records[rec["cve"]] = rec
                        if not model_name and "model" in rec:
                            model_name = rec["model"]
        except Exception:
            pass

    # Read dataset if provided for CWE / complexity / repo mapping
    dataset_map = {}
    if dataset_path and os.path.exists(dataset_path):
        try:
            with open(dataset_path, "r", encoding="utf-8") as f:
                d_items = json.load(f)
                for item in d_items:
                    dataset_map[item["cve_id"]] = item
        except Exception:
            pass

    # Extract success and failure summaries from summary.json
    poc_eval = summary_data.get("poc_evaluation", {})
    fail_analysis = summary_data.get("failure_analysis", {})
    failed_cves_map = fail_analysis.get("failed_cves", {})
    successful_cves_map = poc_eval.get("successful_cves", {})

    # Map each CVE to failure reason / validation type
    cve_status_map = {}
    for lang, cves in successful_cves_map.items():
        for c in cves:
            cve_status_map[c] = ("pass", "Repair Success", f"{lang}_Repair_Success", lang)

    for fail_key, cves in failed_cves_map.items():
        # e.g. fail_key = "Go_apply_fail" -> vtype = "apply_fail", lang = "Go"
        parts = fail_key.split("_", 1)
        lang = parts[0] if len(parts) > 1 else "Unknown"
        vtype = parts[1] if len(parts) > 1 else fail_key
        for c in cves:
            cve_status_map[c] = ("fail", vtype, fail_key, lang)

    # If logs_dir exists, inspect each CVE's log file for detailed status & error preview
    cve_error_previews = {}
    if logs_dir and logs_dir.is_dir():
        for cve_dir in sorted(logs_dir.iterdir()):
            if not cve_dir.is_dir():
                continue
            cve = cve_dir.name
            err_log = cve_dir / "error_output.log"
            succ_log = cve_dir / "success_output.log"
            if succ_log.exists():
                if cve not in cve_status_map:
                    lang = patch_records.get(cve, {}).get("language", "Unknown")
                    cve_status_map[cve] = ("pass", "Repair Success", f"{lang}_Repair_Success", lang)
            elif err_log.exists():
                try:
                    text = err_log.read_text(encoding="utf-8", errors="replace")
                    m = re.search(r"\[Validation TYPE\]:\s*(\S+)", text)
                    vtype = m.group(1) if m else "unknown_fail"
                    lang = patch_records.get(cve, {}).get("language", "Unknown")
                    fail_key = f"{lang}_{vtype}" if not vtype.startswith(lang) else vtype
                    cve_status_map[cve] = ("fail", vtype, fail_key, lang)
                    cve_error_previews[cve] = _extract_error_preview(text, vtype)
                except Exception:
                    pass

    # Build per-CVE detailed entries
    all_cves = sorted(set(list(patch_records.keys()) + list(cve_status_map.keys())))
    cve_entries = []
    for cve in all_cves:
        status, vtype, fail_cat, lang = cve_status_map.get(
            cve, ("unknown", "unknown", "unknown", patch_records.get(cve, {}).get("language", "Unknown"))
        )
        if lang == "Unknown" and cve in patch_records:
            lang = patch_records[cve].get("language", "Unknown")
        if lang == "Unknown" and cve in dataset_map:
            lang = dataset_map[cve].get("programing_language", "Unknown")

        # Tokens
        tok = token_by_cve.get(cve) or patch_records.get(cve, {}).get("token_usage", {})
        prompt_tokens = tok.get("prompt_tokens")
        completion_tokens = tok.get("completion_tokens")
        total_tokens = tok.get("total_tokens")
        timestamp = tok.get("timestamp") or datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

        # Dataset info
        ds_info = dataset_map.get(cve, {})
        cwe_ids = list(ds_info.get("cwe_info", {}).keys())
        primary_cwe = cwe_ids[0] if cwe_ids else ds_info.get("cwe", "UNKNOWN")
        cwe_name = ds_info.get("cwe_info", {}).get(primary_cwe, {}).get("name", "")

        entry = {
            "cve": cve,
            "language": lang,
            "status": status,
            "validation_type": vtype,
            "failure_category": fail_cat if status == "fail" else "Repair Success",
            "error_preview": cve_error_previews.get(cve, ""),
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "cwe_id": primary_cwe,
            "cwe_name": cwe_name,
            "model": patch_records.get(cve, {}).get("model", model_name),
            "timestamp": timestamp,
        }
        cve_entries.append(entry)

    # Load existing companion file to allow cumulative merging
    eval_results_file = _eval_results_path(patch_file)
    existing_eval: dict = {}
    if os.path.exists(eval_results_file):
        try:
            with open(eval_results_file, "r", encoding="utf-8") as f:
                existing_eval = json.load(f)
        except Exception:
            existing_eval = {}

    existing_by_cve = {r["cve"]: r for r in existing_eval.get("cves", [])}
    for row in cve_entries:
        existing_by_cve[row["cve"]] = row

    all_cve_rows = sorted(existing_by_cve.values(), key=lambda r: r.get("timestamp", ""))

    total_eval = len(all_cve_rows)
    n_pass = sum(1 for c in all_cve_rows if c["status"] == "pass")
    n_fail = sum(1 for c in all_cve_rows if c["status"] == "fail")
    pass_rate_val = (n_pass / total_eval * 100) if total_eval else 0.0

    fail_counts = Counter(c["failure_category"] for c in all_cve_rows if c["status"] == "fail")
    fail_pct = {k: f"{(v / total_eval * 100):.1f}%" for k, v in fail_counts.items()} if total_eval else {}
    success_counts = Counter(c["language"] for c in all_cve_rows if c["status"] == "pass")

    total_prompt = sum(c.get("prompt_tokens") or 0 for c in all_cve_rows)
    total_completion = sum(c.get("completion_tokens") or 0 for c in all_cve_rows)
    total_tokens = total_prompt + total_completion

    label = Path(patch_file).stem

    payload = {
        "label": label,
        "model": model_name or existing_eval.get("model", "unknown"),
        "provider": provider_name or existing_eval.get("provider", "unknown"),
        "updated_at": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "evaluation_summary": {
            "total_cases": total_eval,
            "total_success": n_pass,
            "total_failed": n_fail,
            "pass_rate": f"{pass_rate_val:.2f}%",
            "success_breakdown": dict(success_counts),
            "failure_breakdown": dict(sorted(fail_counts.items(), key=lambda x: -x[1])),
            "failure_percentages": fail_pct,
        },
        "session_tokens": {
            "prompt_tokens": total_prompt,
            "completion_tokens": total_completion,
            "total_tokens": total_tokens,
        },
        "cves": all_cve_rows,
    }

    # 1. Write companion evaluation results JSON
    Path(eval_results_file).parent.mkdir(parents=True, exist_ok=True)
    with open(eval_results_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    print(f"[✓] Evaluation results & failure analysis saved → {eval_results_file}  ({total_eval} CVEs evaluated: {n_pass} pass, {n_fail} fail)")
    if fail_counts:
        fail_str = ", ".join(f"{k}: {v}" for k, v in sorted(fail_counts.items()))
        print(f"    Failures breakdown: {fail_str}")

    # 2. Write / update EDA summary
    eda_outdir = Path(eda_dir) if eda_dir else Path(patch_file).parent.parent / "eda"
    eda_outdir.mkdir(parents=True, exist_ok=True)
    label_eda_path = eda_outdir / f"{label}_eda.json"
    with open(label_eda_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"[✓] EDA summary saved → {label_eda_path}")

    # 3. Update cumulative EDA registry
    all_summary_path = eda_outdir / "all_eval_summary.json"
    all_summary = {}
    if all_summary_path.exists():
        try:
            with open(all_summary_path, "r", encoding="utf-8") as f:
                all_summary = json.load(f)
        except Exception:
            all_summary = {}

    all_summary[label] = {
        "label": label,
        "model": payload["model"],
        "provider": payload["provider"],
        "updated_at": payload["updated_at"],
        "total_cases": total_eval,
        "total_success": n_pass,
        "total_failed": n_fail,
        "pass_rate": f"{pass_rate_val:.2f}%",
        "failure_breakdown": dict(fail_counts),
        "total_tokens": total_tokens,
    }
    with open(all_summary_path, "w", encoding="utf-8") as f:
        json.dump(all_summary, f, indent=2, ensure_ascii=False)

    return payload


def cmd_save_eval(args):
    """CLI command handler for save-eval."""
    _save_eval_results(
        patch_file=args.patch_file,
        eval_dir=args.eval_dir,
        dataset_path=getattr(args, "dataset", None),
        eda_dir=getattr(args, "eda_dir", "./eda"),
    )


# =====================================================================
# eda — Part A: EDA for CVE dataset & Evaluation Results in PatchEval
# =====================================================================

def _eda_load_dataset_subset(input_path: str, lang: str = "all") -> list:
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not lang or lang.lower() == "all":
        return data
    return [d for d in data if d.get("programing_language", "").lower() == lang.lower()]


def _eda_complexity_tier(lines: int) -> str:
    if lines <= 5:
        return "Easy"
    elif lines <= 10:
        return "Medium"
    elif lines <= 20:
        return "Hard"
    else:
        return "VeryHard"


def _eda_analyze(items: list, eval_map: Optional[dict] = None) -> list:
    rows = []
    for d in items:
        cve_id = d["cve_id"]
        year = int(cve_id.split("-")[1]) if "-" in cve_id else 0
        cwe_ids = list(d.get("cwe_info", {}).keys())
        primary_cwe = cwe_ids[0] if cwe_ids else "UNKNOWN"
        cwe_name = d.get("cwe_info", {}).get(primary_cwe, {}).get("name", "")
        lang = d.get("programing_language", "Unknown")

        vul_entries = d.get("vul_func", [])
        patch_lines = sum(
            len(loc.get("patch_lines", []))
            for vf in vul_entries
            for loc in vf.get("vul_localization", [])
        )
        patch_locations = len(vul_entries)
        patch_files = len({vf["file_path"] for vf in vul_entries if "file_path" in vf}) or 1

        eval_info = (eval_map or {}).get(cve_id, {})
        status = eval_info.get("status", "not_evaluated")
        vtype = eval_info.get("validation_type", "")
        fail_cat = eval_info.get("failure_category", "")
        prompt_tokens = eval_info.get("prompt_tokens")
        completion_tokens = eval_info.get("completion_tokens")
        total_tokens = eval_info.get("total_tokens")

        rows.append({
            "cve_id": cve_id,
            "language": lang,
            "year": year,
            "repo": d.get("repo"),
            "cwe_ids": cwe_ids,
            "primary_cwe": primary_cwe,
            "cwe_name": cwe_name,
            "patch_lines": patch_lines,
            "patch_locations": patch_locations,
            "patch_files": patch_files,
            "complexity_tier": _eda_complexity_tier(patch_lines),
            "eval_status": status,
            "validation_type": vtype,
            "failure_category": fail_cat,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
        })
    return rows


def _eda_summarize(rows: list) -> dict:
    n = len(rows)
    if not n:
        return {"n_cve": 0}
    year_counts = Counter(r["year"] for r in rows)
    cwe_counts = Counter(r["primary_cwe"] for r in rows)
    tier_counts = Counter(r["complexity_tier"] for r in rows)
    lang_counts = Counter(r["language"] for r in rows)

    lines_vals = sorted(r["patch_lines"] for r in rows)
    files_vals = sorted(r["patch_files"] for r in rows)

    def median(vals):
        m = len(vals)
        mid = m // 2
        return vals[mid] if m % 2 else (vals[mid - 1] + vals[mid]) / 2

    # Eval metrics if available
    evaluated = [r for r in rows if r.get("eval_status") in ("pass", "fail")]
    n_eval = len(evaluated)
    n_pass = sum(1 for r in evaluated if r.get("eval_status") == "pass")
    n_fail = sum(1 for r in evaluated if r.get("eval_status") == "fail")
    fail_counts = Counter(r["failure_category"] for r in evaluated if r.get("eval_status") == "fail")

    summary = {
        "n_cve": n,
        "languages": dict(lang_counts),
        "n_repo": len({r["repo"] for r in rows}),
        "year_range": [min(year_counts), max(year_counts)],
        "year_distribution": dict(sorted(year_counts.items())),
        "top10_cwe": cwe_counts.most_common(10),
        "n_distinct_cwe": len(cwe_counts),
        "complexity_tier_counts": dict(tier_counts),
        "complexity_tier_pct": {k: round(v / n * 100, 1) for k, v in tier_counts.items()},
        "patch_lines_mean": round(sum(lines_vals) / n, 2),
        "patch_lines_median": median(lines_vals),
        "patch_lines_max": max(lines_vals),
        "patch_files_mean": round(sum(files_vals) / n, 2),
        "patch_files_median": median(files_vals),
        "patch_files_max": max(files_vals),
    }

    if n_eval > 0:
        summary["evaluation"] = {
            "total_evaluated": n_eval,
            "pass_count": n_pass,
            "fail_count": n_fail,
            "pass_rate": f"{(n_pass / n_eval * 100):.2f}%",
            "failure_breakdown": dict(sorted(fail_counts.items(), key=lambda x: -x[1])),
            "failure_percentages": {k: f"{(v / n_eval * 100):.1f}%" for k, v in fail_counts.items()},
        }
        tier_eval = defaultdict(lambda: {"pass": 0, "fail": 0})
        for r in evaluated:
            tier_eval[r["complexity_tier"]]["pass" if r["eval_status"] == "pass" else "fail"] += 1
        summary["evaluation"]["pass_rate_by_complexity_tier"] = {
            tier: f"{(counts['pass'] / (counts['pass'] + counts['fail']) * 100):.1f}% ({counts['pass']}/{counts['pass'] + counts['fail']})"
            for tier, counts in tier_eval.items()
        }

    return summary


def cmd_eda(args):
    os.makedirs(args.outdir, exist_ok=True)
    lang = getattr(args, "lang", "all")
    items = _eda_load_dataset_subset(args.input, lang=lang)

    # Load eval results if provided
    eval_map = {}
    eval_path = getattr(args, "eval_results", None)
    if eval_path and os.path.exists(eval_path):
        try:
            with open(eval_path, "r", encoding="utf-8") as f:
                edata = json.load(f)
                if "cves" in edata:
                    eval_map = {c["cve"]: c for c in edata["cves"]}
                elif "failure_analysis" in edata:
                    # summary.json format
                    for k, cves in edata.get("failure_analysis", {}).get("failed_cves", {}).items():
                        parts = k.split("_", 1)
                        vtype = parts[1] if len(parts) > 1 else k
                        for c in cves:
                            eval_map[c] = {"status": "fail", "validation_type": vtype, "failure_category": k}
                    for k, cves in edata.get("poc_evaluation", {}).get("successful_cves", {}).items():
                        for c in cves:
                            eval_map[c] = {"status": "pass", "validation_type": "Repair Success", "failure_category": "Repair Success"}
        except Exception as e:
            print(f"[!] Warning reading eval_results {eval_path}: {e}")

    rows = _eda_analyze(items, eval_map=eval_map)
    summary = _eda_summarize(rows)

    prefix = f"{lang.lower()}_" if lang.lower() != "all" else ""
    table_file = os.path.join(args.outdir, f"{prefix}cve_table.json")
    summary_file = os.path.join(args.outdir, f"{prefix}eda_summary.json")

    with open(table_file, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"\n[✓] Wrote EDA table   → {table_file}")
    print(f"[✓] Wrote EDA summary → {summary_file}")


# =====================================================================
# complexity — Part A2: structural complexity (cyclomatic/loop/branch/depth)
# =====================================================================

def _cx_safe_parse_and_measure(snippet: str):
    """Dedent snippet; if still fails (e.g. method body without class), wrap in a dummy class."""
    code = textwrap.dedent(snippet)
    tree = None
    used_code = code
    for candidate in (code, "class _Wrap:\n" + snippet):
        try:
            tree = ast.parse(candidate)
            used_code = candidate
            break
        except SyntaxError:
            continue
    if tree is None:
        return None

    num_loops = sum(isinstance(n, (ast.For, ast.While)) for n in ast.walk(tree))
    num_branches = sum(isinstance(n, ast.If) for n in ast.walk(tree))

    def max_func_depth(node, depth=0):
        best = depth
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                best = max(best, max_func_depth(child, depth + 1))
            else:
                best = max(best, max_func_depth(child, depth))
        return best

    nesting_depth = max_func_depth(tree)

    cyclomatic = None
    if HAS_RADON:
        try:
            cc_results = cc_visit(used_code)
            cyclomatic = max((r.complexity for r in cc_results), default=1)
        except Exception:
            cyclomatic = None

    return {
        "num_loops": num_loops,
        "num_branches": num_branches,
        "func_nesting_depth": nesting_depth,
        "cyclomatic_complexity": cyclomatic,
    }


def _cx_structural_tier(cyclomatic):
    """McCabe thresholds: 1-4 simple, 5-10 medium, 11-20 complex, 20+ very complex."""
    if cyclomatic is None:
        return "UNKNOWN"
    if cyclomatic <= 4:
        return "Easy"
    elif cyclomatic <= 10:
        return "Medium"
    elif cyclomatic <= 20:
        return "Hard"
    else:
        return "VeryHard"


def cmd_complexity(args):
    if not HAS_RADON:
        raise SystemExit("Install radon first: pip install radon --break-system-packages")

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)
    py_items = [d for d in data if d["programing_language"] == "Python"]

    rows = []
    fail_count = 0
    for d in py_items:
        snippet = d["vul_func"][0]["snippet"]
        m = _cx_safe_parse_and_measure(snippet)
        if m is None:
            fail_count += 1
            m = {"num_loops": None, "num_branches": None,
                 "func_nesting_depth": None, "cyclomatic_complexity": None}
        rows.append({
            "cve_id": d["cve_id"],
            **m,
            "structural_tier": _cx_structural_tier(m["cyclomatic_complexity"]),
        })

    tier_counts = Counter(r["structural_tier"] for r in rows)
    print(f"Parsed successfully: {len(rows) - fail_count}/{len(rows)}")
    print("Structural tier distribution (based on cyclomatic complexity of root function):")
    for tier in ["Easy", "Medium", "Hard", "VeryHard", "UNKNOWN"]:
        if tier in tier_counts:
            pct = tier_counts[tier] / len(rows) * 100
            print(f"  {tier:10s}: {tier_counts[tier]:3d} ({pct:.1f}%)")

    os.makedirs(args.outdir, exist_ok=True)
    out_path = os.path.join(args.outdir, "python_structural_complexity.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)
    print(f"\nWrote {out_path}")


# =====================================================================
# generate — Part B: batch patch generation for Python CVEs via Gemini
# =====================================================================

GEMINI_URL_TMPL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

GEN_PROMPT_TEMPLATE = """You are a code security expert. Your task is to fix the following vulnerability.

# Vulnerability Information
CVE: {cve_id}
CWE: {cwe_id} - {cwe_name}
Description: {cve_description}

# Vulnerable Function
File: {file_path}
```{lang}
{vul_snippet}
```

# Instructions
1. Analyze the root cause of the vulnerability.
2. Propose a minimal fix that removes the vulnerability without changing unrelated behavior.
3. Output ONLY the full corrected version of the function/code block above, inside a single
   code fence. Do not add explanations outside the code fence.
"""


def _gen_build_prompt(cve_record, vul_entry, lang="python"):
    cwe_ids = list(cve_record.get("cwe_info", {}).keys())
    cwe_id = cwe_ids[0] if cwe_ids else "UNKNOWN"
    cwe_name = cve_record.get("cwe_info", {}).get(cwe_id, {}).get("name", "")
    return GEN_PROMPT_TEMPLATE.format(
        cve_id=cve_record["cve_id"],
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        cve_description=cve_record.get("cve_description", ""),
        file_path=vul_entry["file_path"],
        lang=lang,
        vul_snippet=vul_entry["snippet"],
    )


def _gen_call_gemini_rest(prompt: str, model: str, api_key: str, max_tokens: int, max_retries: int = 3) -> tuple:
    """Call Gemini REST API directly using urllib (no requests dependency).
    Returns (text, usage_dict) where usage_dict has prompt_tokens, completion_tokens, total_tokens.
    """
    url = f"{GEMINI_URL_TMPL.format(model=model)}?key={api_key}"
    payload = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0, "maxOutputTokens": max_tokens},
    }).encode("utf-8")
    headers = {"Content-Type": "application/json"}

    last_err = None
    for attempt in range(max_retries):
        req = urllib.request.Request(url, data=payload, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if "error" in data:
                raise RuntimeError(f"API error: {data['error']}")
            candidates = data.get("candidates", [])
            if not candidates:
                raise RuntimeError(f"No candidates. Response: {json.dumps(data)[:500]}")
            parts = candidates[0].get("content", {}).get("parts", [])
            text = "".join(p.get("text", "") for p in parts)
            finish_reason = candidates[0].get("finishReason")
            if not text:
                raise RuntimeError(f"Empty content (finishReason={finish_reason}).")
            meta = data.get("usageMetadata", {})
            usage = {
                "prompt_tokens":     meta.get("promptTokenCount", 0),
                "completion_tokens": meta.get("candidatesTokenCount", 0),
                "total_tokens":      meta.get("totalTokenCount", 0),
            }
            return text, usage
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8")
            except Exception:
                pass
            if e.code == 429:
                wait_s = 15 + attempt * 15
                print(f"    [429] Rate limited. Waiting {wait_s}s... (attempt {attempt + 1}/{max_retries})")
                time.sleep(wait_s)
                last_err = "429 Too Many Requests"
                continue
            last_err = f"HTTP {e.code}: {body[:400]}"
            print(f"    [DEBUG] {last_err}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
        except Exception as e:
            last_err = e
            print(f"    [Retry {attempt + 1}/{max_retries}] Error: {e}")
            time.sleep(2 ** attempt)
    raise RuntimeError(f"Gemini call failed after {max_retries} attempts: {last_err}")


def _gen_call_openrouter(prompt: str, model: str, api_key: str, max_tokens: int = 4096, max_retries: int = 5) -> tuple:
    """Call OpenRouter chat completions API using urllib.
    Returns (text, usage_dict) where usage_dict has prompt_tokens, completion_tokens, total_tokens.
    """
    url = "https://openrouter.ai/api/v1/chat/completions"
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": max_tokens,
    }).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "HTTP-Referer": "https://patcheval.local",
        "X-Title": "PatchEval",
    }

    last_err = None
    for attempt in range(max_retries):
        req = urllib.request.Request(url, data=payload, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read().decode("utf-8"))
            # Handle cases where the model returned an error inside the JSON
            if "error" in result:
                err_msg = result["error"].get("message", str(result["error"]))
                raise RuntimeError(f"OpenRouter API error: {err_msg}")
            choices = result.get("choices", [])
            if not choices:
                raise RuntimeError(f"No choices in response: {json.dumps(result)[:300]}")
            content = choices[0].get("message", {}).get("content", "")
            if not content:
                finish_reason = choices[0].get("finish_reason", "unknown")
                raise RuntimeError(f"Empty content (finish_reason={finish_reason}). Model may not support free tier.")
            raw_usage = result.get("usage", {})
            usage = {
                "prompt_tokens":     raw_usage.get("prompt_tokens", 0),
                "completion_tokens": raw_usage.get("completion_tokens", 0),
                "total_tokens":      raw_usage.get("total_tokens", 0),
            }
            return content, usage
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8")
            except Exception:
                pass
            if e.code == 429:
                # Free-tier: start with 15s then grow; avoid hammering the quota
                wait_s = 15 + attempt * 20
                print(f"    [429] Rate limited. Waiting {wait_s}s... (attempt {attempt + 1}/{max_retries})")
                time.sleep(wait_s)
                last_err = "429 Too Many Requests"
                continue
            elif e.code == 402:
                raise RuntimeError("Error 402: OpenRouter credits depleted. Use a :free model or add credits.")
            elif e.code == 400:
                raise RuntimeError(f"Error 400: Bad request (context length?). {body[:300]}")
            elif e.code == 503:
                wait_s = 10 * (attempt + 1)
                print(f"    [503] Service unavailable. Waiting {wait_s}s... (attempt {attempt + 1}/{max_retries})")
                time.sleep(wait_s)
                last_err = f"HTTP 503"
                continue
            else:
                last_err = f"HTTP {e.code}: {body[:300]}"
                print(f"    [Error] {last_err}")
                if attempt == max_retries - 1:
                    raise RuntimeError(last_err)
                time.sleep(10)
        except Exception as e:
            last_err = e
            print(f"    [Retry {attempt + 1}/{max_retries}] Error: {e}")
            if attempt == max_retries - 1:
                raise
            time.sleep(10)
    raise RuntimeError(f"OpenRouter call failed after {max_retries} attempts: {last_err}")



def _call_llm(provider: str, prompt: str, gemini_model: str = "gemini-2.0-flash",
              openrouter_model: str = "poolside/laguna-s-2.1:free",
              max_tokens: int = 6000) -> tuple:
    """Unified LLM call dispatcher supporting gemini and openrouter providers.
    Returns (text, usage_dict) where usage_dict has prompt_tokens, completion_tokens, total_tokens.
    """
    if provider == "gemini":
        api_key = os.environ.get("GEMINI_API_KEY", "")
        if not api_key:
            raise SystemExit("GEMINI_API_KEY environment variable not set.")
        return _gen_call_gemini_rest(prompt, gemini_model, api_key, max_tokens)
    elif provider == "openrouter":
        api_key = os.environ.get("OPENROUTER_API_KEY", "")
        if not api_key:
            raise SystemExit("OPENROUTER_API_KEY environment variable not set.")
        return _gen_call_openrouter(prompt, openrouter_model, api_key, max_tokens=max_tokens)
    else:
        raise ValueError(f"Unknown provider: {provider!r}. Choose 'gemini' or 'openrouter'.")


def _gen_extract_code_block(model_output: str) -> str:
    """Extract the first code block from markdown-fenced output."""
    lines = model_output.splitlines()
    in_block = False
    block = []
    for line in lines:
        if line.strip().startswith("```"):
            if in_block:
                break
            in_block = True
            continue
        if in_block:
            block.append(line)
    return "\n".join(block) if block else model_output.strip()


def _gen_normalize_trailing_blank(old_snippet: str) -> str:
    """Ensure snippet ends with a newline (preserving actual content from dataset)."""
    if not old_snippet.endswith("\n"):
        old_snippet += "\n"
    return old_snippet


def _gen_ensure_matching_trailing_blank(old_snippet: str, new_code: str) -> str:
    """If old_snippet ends with a whitespace-only line, ensure new_code ends with the same line."""
    old_lines = old_snippet.splitlines()
    if not old_lines or old_lines[-1].strip():
        return new_code
    boundary_line = old_lines[-1]
    new_lines = new_code.splitlines()
    if new_lines and new_lines[-1] == boundary_line:
        return new_code
    return new_code.rstrip("\n") + "\n" + boundary_line + "\n"


def _gen_reindent_to_match(old_snippet: str, new_code: str) -> str:
    """Re-apply the base indent of old_snippet to new_code (LLMs often strip leading indent)."""
    old_lines = old_snippet.splitlines()
    base_indent = ""
    for line in old_lines:
        if line.strip():
            base_indent = line[: len(line) - len(line.lstrip())]
            break
    if not base_indent:
        return new_code

    new_lines = new_code.splitlines()
    if not new_lines:
        return new_code
    first_nonempty = next((l for l in new_lines if l.strip()), "")
    if first_nonempty.startswith(base_indent):
        return new_code

    reindented = [base_indent + line if line.strip() else line for line in new_lines]
    return "\n".join(reindented)


def _gen_build_unified_diff(file_path, old_snippet, new_snippet, start_line=1):
    """Build a git-compatible unified diff from old and new snippets."""
    if not old_snippet.endswith("\n"):
        old_snippet = old_snippet + "\n"
    if not new_snippet.endswith("\n"):
        new_snippet = new_snippet + "\n"

    old_lines = old_snippet.splitlines()
    new_lines = new_snippet.splitlines()
    diff = difflib.unified_diff(
        old_lines, new_lines,
        fromfile=f"a/{file_path}", tofile=f"b/{file_path}",
        lineterm="", n=3,
    )
    diff_text = "\n".join(diff)

    def _fix_hunk_header(text, start):
        def repl(m):
            return f"@@ -{start},{m.group(1)} +{start},{m.group(2)} @@"
        return re.sub(r"@@ -1,(\d+) \+1,(\d+) @@", repl, text, count=1)

    diff_text = _fix_hunk_header(diff_text, start_line)
    header = f"diff --git a/{file_path} b/{file_path}\n"
    return header + diff_text + "\n"


def cmd_generate(args):
    """Batch patch generation for Python CVEs via Gemini or OpenRouter."""
    provider = getattr(args, "provider", "gemini")
    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)
    py_items = [d for d in data if d["programing_language"] == "Python"]

    done_cves = set()
    if os.path.exists(args.output):
        with open(args.output, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    done_cves.add(json.loads(line)["cve"])
        if done_cves:
            print(f"[RESUME] Already have {len(done_cves)} CVEs in {args.output}, skipping.")
        py_items = [d for d in py_items if d["cve_id"] not in done_cves]

    if args.limit > 0:
        py_items = py_items[: args.limit]

    consecutive_429_fails = 0
    total_prompt_tokens = 0
    total_completion_tokens = 0
    token_usage_rows: list = []
    model_label = getattr(args, "or_model", args.model) if provider == "openrouter" else args.model
    for i, d in enumerate(py_items):
        cve_id = d["cve_id"]
        vul_entry = d["vul_func"][0]
        prompt = _gen_build_prompt(d, vul_entry, lang="python")
        try:
            raw_output, usage = _call_llm(provider, prompt,
                                   gemini_model=args.model,
                                   openrouter_model=getattr(args, "or_model", "poolside/laguna-s-2.1:free"),
                                   max_tokens=args.max_tokens)
            consecutive_429_fails = 0
        except Exception as e:
            print(f"[FAIL] {cve_id}: {e}")
            if "429" in str(e):
                consecutive_429_fails += 1
                if consecutive_429_fails >= 2:
                    print("\n>>> Likely daily quota exhausted. Stop and retry after midnight (Pacific).\n")
                    break
            continue

        total_prompt_tokens     += usage.get("prompt_tokens", 0)
        total_completion_tokens += usage.get("completion_tokens", 0)
        token_usage_rows.append({
            "cve":               cve_id,
            "prompt_tokens":     usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
            "total_tokens":      usage.get("total_tokens", 0),
            "timestamp":         datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        })

        old_snippet = _gen_normalize_trailing_blank(vul_entry["snippet"])
        new_code = _gen_extract_code_block(raw_output)
        new_code = _gen_reindent_to_match(old_snippet, new_code)
        new_code = _gen_ensure_matching_trailing_blank(old_snippet, new_code)
        fix_patch = _gen_build_unified_diff(
            vul_entry["file_path"], old_snippet, new_code,
            start_line=vul_entry.get("start_line", 1),
        )
        record = {
            "cve": cve_id, "fix_patch": fix_patch, "language": "Python", "model": args.model,
            "token_usage": {
                "prompt_tokens":     usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens":      usage.get("total_tokens", 0),
            },
        }
        with open(args.output, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"[OK] {cve_id}  "
              f"[tokens: prompt={usage.get('prompt_tokens',0):,}  "
              f"completion={usage.get('completion_tokens',0):,}  "
              f"total={usage.get('total_tokens',0):,}]")

        if i < len(py_items) - 1:
            # OpenRouter free tier: ~20 req/min → 3s min; Gemini free: 5 req/min → 13s
            sleep_s = 3 if provider == "openrouter" else 13
            time.sleep(sleep_s)

    total_now = 0
    if os.path.exists(args.output):
        with open(args.output, encoding="utf-8") as f:
            total_now = sum(1 for _ in f)
    print(f"\nDone. Total CVEs now in {args.output}: {total_now}")
    print(f"Session tokens — prompt: {total_prompt_tokens:,}  "
          f"completion: {total_completion_tokens:,}  "
          f"total: {total_prompt_tokens + total_completion_tokens:,}")
    if token_usage_rows:
        _save_token_usage(args.output, token_usage_rows, model_label, provider)


def _go_looks_truncated(new_code: str, old_snippet: str) -> bool:
    """Heuristic: detect if the LLM's output was cut off mid-way.

    A truncated response typically has far fewer lines than the original and
    ends without a closing brace — the classic sign that the model ran out of
    output tokens while rewriting a large function.

    We require BOTH conditions to be true to avoid false-positives on valid
    but concise fixes (e.g. a minimal patch that is naturally shorter):
      1. The output is very short in absolute terms (< 10 lines) AND
         less than 40% of the original length.
      2. The output does NOT end with a closing brace or paren.

    If the output ends properly (}) we never treat it as truncated,
    regardless of how short it is.
    """
    old_lines = len(old_snippet.splitlines())
    new_lines = len(new_code.splitlines())
    stripped_end = new_code.rstrip()
    ends_closed = stripped_end.endswith("}") or stripped_end.endswith(")")
    # A properly closed output is never considered truncated
    if ends_closed:
        return False
    # Without a closing brace, flag only when suspiciously short both
    # relatively (< 40% of original) AND absolutely (< 10 lines)
    if new_lines < old_lines * 0.4 and new_lines < 10:
        return True
    return False


def _go_clean_raw_diff(raw_output: str, file_path: str) -> str:
    """Normalise raw diff output from the large-snippet diff-mode prompt.

    The model may wrap the diff in a code fence even though we asked it not to.
    Strip fences, ensure the diff --git header is present, and return the
    clean unified diff string.
    """
    text = raw_output.strip()

    # Strip markdown code fences if present (```diff ... ``` or ``` ... ```)
    if text.startswith("```"):
        lines = text.splitlines()
        # Drop opening fence line
        lines = lines[1:]
        # Drop closing fence line
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    # Ensure diff --git header so git apply can find the file
    if text.startswith("---") and not text.startswith("diff --git"):
        text = f"diff --git a/{file_path} b/{file_path}\n" + text

    if not text.endswith("\n"):
        text += "\n"
    return text


# =====================================================================
# go-generate — Batch snippet-level patch generation for Go CVEs
# =====================================================================


# Prompt for short snippets (≤ LARGE_SNIPPET_THRESHOLD lines): ask for full corrected function.
GO_GEN_PROMPT_TEMPLATE = """You are a Go security engineer performing a minimal, surgical patch.

## Vulnerability
CVE: {cve_id}
CWE: {cwe_id} - {cwe_name}

## Description
{cve_description}

## Exploitation insight for {cwe_id}
{cwe_hint}

## Vulnerable code
File: {file_path}
```go
{vul_snippet}
```

{imports_section}
## Task
Apply the SMALLEST possible change that eliminates the vulnerability.
Rules:
- Do NOT rewrite or restructure logic that is unrelated to the vulnerability.
- Do NOT remove error handling, logging, or security checks that already exist.
- Preserve the exact function signature, return types, and package-level variables.
- ONLY use packages that appear in the ## Available imports section above (if provided).
  Do NOT add import statements anywhere in your output.

Output ONLY the complete corrected function/code block inside a single ```go ... ``` fence.
Do not add any explanation, comments, or text outside the fence.
"""

# Prompt for large snippets (> LARGE_SNIPPET_THRESHOLD lines): ask for unified diff directly.
GO_GEN_DIFF_PROMPT_TEMPLATE = """You are a Go security engineer performing a minimal, surgical patch.

## Vulnerability
CVE: {cve_id}
CWE: {cwe_id} - {cwe_name}

## Description
{cve_description}

## Exploitation insight for {cwe_id}
{cwe_hint}

## Vulnerable code (LARGE — {snippet_lines} lines)
File: {file_path}
```go
{vul_snippet}
```

{imports_section}
## Task
Because the function is large, output ONLY a unified diff (patch format) with the minimal
changes required to fix the vulnerability. Do not rewrite the entire function.

Rules:
- Use standard unified diff format (--- a/file / +++ b/file / @@ hunks).
- Include 3 lines of context around each changed block.
- Touch ONLY the lines necessary to fix the vulnerability.
- ONLY use packages that appear in the ## Available imports section above (if provided).
  Do NOT add import statements in the diff.
- Do NOT output a markdown code fence. Output raw diff text only.
"""

# CWE-specific exploitation hints to improve fix accuracy
_CWE_HINTS = {
    "CWE-22":  "Path traversal: reject names that escape the intended directory. Use filepath.Clean(name) and then check that it does not contain '..' as a path component (e.g. strings.Contains(filepath.Clean(name), '..') or filepath.Base). IMPORTANT: filepath and strings are almost always already imported — do NOT add a new import statement.",
    "CWE-73":  "External control of file name (same class as CWE-22): use filepath.Base(name) to strip any directory component, or filepath.Clean + reject '..' — the chart/archive name should be a plain filename with no slashes. IMPORTANT: do NOT add a new import statement; path/filepath is almost always already imported.",
    "CWE-79":  "XSS: user-controlled data is reflected into HTML without escaping. Use html.EscapeString or template auto-escaping.",
    "CWE-89":  "SQL injection: build queries with parameterised placeholders (db.Query with '?'), never fmt.Sprintf into SQL strings.",
    "CWE-94":  "Code injection: user input reaches eval/exec. Validate strictly against an allow-list or avoid dynamic execution entirely.",
    "CWE-200": "Information exposure: sensitive data (tokens, passwords, stack traces) must be stripped from error messages returned to clients.",
    "CWE-284": "Improper access control: add an authorisation check before the privileged operation.",
    "CWE-307": "Brute-force: the regulation/rate-limit lookup must use the canonical (normalised) identity — look up the real username from the directory first, then pass that canonical form to the regulator so username and email are treated as the same account.",
    "CWE-400": "Resource exhaustion: cap input size or iteration count before processing.",
    "CWE-601": "Open redirect: validate that the redirect target is on an allow-listed domain or is a relative path.",
    "CWE-918": "SSRF: parse the URL and reject private/loopback addresses before making outbound requests.",
}
_DEFAULT_CWE_HINT = "Identify the exact insecure operation and add the minimum guard (input validation, sanitisation, or access check) required to prevent exploitation."

LARGE_SNIPPET_THRESHOLD = 80  # lines — above this use diff-output mode


def _go_fetch_imports(image_url: str, file_path: str, timeout: int = 60) -> str:
    """Spin up the CVE Docker image, extract the import block of the vulnerable file,
    then immediately remove the container. Returns a formatted string suitable for
    embedding in the prompt, or empty string if Docker is unavailable / fetch fails."""
    import subprocess
    if not image_url:
        return ""
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "bash",
             image_url, "-c",
             # Find the file (may be under /workspace/<repo>/...) and extract import block
             f"find /workspace -path '*/{file_path}' 2>/dev/null | head -1 | "
             f"xargs -I{{}} awk '/^import/,/^\\)/' {{}} 2>/dev/null || true"],
            capture_output=True, text=True, timeout=timeout,
        )
        imports_raw = result.stdout.strip()
        if imports_raw:
            return f"## Available imports (from the real file — use ONLY these)\n```go\n{imports_raw}\n```\n"
    except Exception:
        pass
    return ""


def _go_gen_build_prompt(cve_record, vul_entry):
    cwe_ids = list(cve_record.get("cwe_info", {}).keys())
    cwe_id = cwe_ids[0] if cwe_ids else "UNKNOWN"
    cwe_name = cve_record.get("cwe_info", {}).get(cwe_id, {}).get("name", "")
    cwe_hint = _CWE_HINTS.get(cwe_id, _DEFAULT_CWE_HINT)
    snippet = vul_entry["snippet"]
    snippet_lines = len(snippet.splitlines())
    image_url = cve_record.get("image_url", "")
    imports_section = _go_fetch_imports(image_url, vul_entry["file_path"])

    if snippet_lines > LARGE_SNIPPET_THRESHOLD:
        return GO_GEN_DIFF_PROMPT_TEMPLATE.format(
            cve_id=cve_record["cve_id"],
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            cve_description=cve_record.get("cve_description", ""),
            cwe_hint=cwe_hint,
            file_path=vul_entry["file_path"],
            snippet_lines=snippet_lines,
            vul_snippet=snippet,
            imports_section=imports_section,
        )

    return GO_GEN_PROMPT_TEMPLATE.format(
        cve_id=cve_record["cve_id"],
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        cve_description=cve_record.get("cve_description", ""),
        cwe_hint=cwe_hint,
        file_path=vul_entry["file_path"],
        vul_snippet=snippet,
        imports_section=imports_section,
    )


def cmd_go_generate(args):
    """Batch snippet-level patch generation for Go CVEs (Gemini or OpenRouter)."""
    provider = getattr(args, "provider", "gemini")

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)
    go_items = [d for d in data if d.get("programing_language", "").lower() == "go"]
    print(f"[INFO] Loaded {len(go_items)} Go CVEs from {args.input}")

    done_cves = set()
    if os.path.exists(args.output):
        with open(args.output, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    done_cves.add(json.loads(line)["cve"])
        if done_cves:
            print(f"[RESUME] Already have {len(done_cves)} CVEs in {args.output}, skipping.")
        go_items = [d for d in go_items if d["cve_id"] not in done_cves]

    if args.limit > 0:
        go_items = go_items[: args.limit]

    print(f"[INFO] Will generate patches for {len(go_items)} CVEs using provider={provider}")

    consecutive_429_fails = 0
    total_prompt_tokens = 0
    total_completion_tokens = 0
    token_usage_rows: list = []
    for i, d in enumerate(go_items):
        cve_id = d["cve_id"]
        vul_entries = d.get("vul_func", [])
        if not vul_entries:
            print(f"[SKIP] {cve_id}: no vul_func entries")
            continue
        vul_entry = vul_entries[0]
        snippet_lines = len(vul_entry["snippet"].splitlines())
        large_mode = snippet_lines > LARGE_SNIPPET_THRESHOLD
        prompt = _go_gen_build_prompt(d, vul_entry)
        mode_tag = f"diff-mode ({snippet_lines}L)" if large_mode else f"full-mode ({snippet_lines}L)"
        print(f"[GEN]  {cve_id}  [{mode_tag}]")

        try:
            raw_output, usage = _call_llm(provider, prompt,
                                   gemini_model=args.model,
                                   openrouter_model=getattr(args, "or_model", "poolside/laguna-s-2.1:free"),
                                   max_tokens=args.max_tokens)
            consecutive_429_fails = 0
        except Exception as e:
            print(f"[FAIL] {cve_id}: {e}")
            if "429" in str(e):
                consecutive_429_fails += 1
                if consecutive_429_fails >= 2:
                    print("\n>>> Likely daily quota exhausted. Stop and retry after midnight (Pacific).\n")
                    break
            continue

        total_prompt_tokens     += usage.get("prompt_tokens", 0)
        total_completion_tokens += usage.get("completion_tokens", 0)
        token_usage_rows.append({
            "cve":               cve_id,
            "prompt_tokens":     usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
            "total_tokens":      usage.get("total_tokens", 0),
            "timestamp":         datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        })

        old_snippet = _gen_normalize_trailing_blank(vul_entry["snippet"])

        if large_mode:
            # LLM was asked to output a raw diff directly
            fix_patch = _go_clean_raw_diff(raw_output, vul_entry["file_path"])
        else:
            new_code = _gen_extract_code_block(raw_output)
            # Truncation guard: if output ends mid-statement, warn and skip
            if _go_looks_truncated(new_code, old_snippet):
                print(f"[WARN] {cve_id}: output looks truncated (new={len(new_code.splitlines())}L vs old={snippet_lines}L), skipping")
                continue
            new_code = _gen_reindent_to_match(old_snippet, new_code)
            new_code = _gen_ensure_matching_trailing_blank(old_snippet, new_code)
            fix_patch = _gen_build_unified_diff(
                vul_entry["file_path"], old_snippet, new_code,
                start_line=vul_entry.get("start_line", 1),
            )

        if not fix_patch.strip():
            print(f"[WARN] {cve_id}: empty patch generated, skipping")
            continue

        model_label = args.model if provider == "gemini" else getattr(args, "or_model", "openrouter")
        record = {
            "cve": cve_id, "fix_patch": fix_patch, "language": "Go", "model": model_label,
            "token_usage": {
                "prompt_tokens":     usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens":      usage.get("total_tokens", 0),
            },
        }
        with open(args.output, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"[OK]   {cve_id}  "
              f"[tokens: prompt={usage.get('prompt_tokens',0):,}  "
              f"completion={usage.get('completion_tokens',0):,}  "
              f"total={usage.get('total_tokens',0):,}]")

        if i < len(go_items) - 1:
            # OpenRouter free tier: ~20 req/min → 3s min; Gemini free: 5 req/min → 13s
            sleep_s = 3 if provider == "openrouter" else 13
            time.sleep(sleep_s)

    total_now = 0
    if os.path.exists(args.output):
        with open(args.output, encoding="utf-8") as f:
            total_now = sum(1 for _ in f)
    print(f"\nDone. Total Go CVEs now in {args.output}: {total_now}")
    print(f"Session tokens — prompt: {total_prompt_tokens:,}  "
          f"completion: {total_completion_tokens:,}  "
          f"total: {total_prompt_tokens + total_completion_tokens:,}")
    if token_usage_rows:
        _save_token_usage(args.output, token_usage_rows, model_label, provider)


# =====================================================================
# js-generate — Batch snippet-level patch generation for JavaScript CVEs
# =====================================================================


# Prompt for short snippets: ask for full corrected function.
JS_GEN_PROMPT_TEMPLATE = """You are a JavaScript security engineer performing a minimal, surgical patch.

## Vulnerability
CVE: {cve_id}
CWE: {cwe_id} - {cwe_name}

## Description
{cve_description}

## Exploitation insight for {cwe_id}
{cwe_hint}

## Vulnerable code
File: {file_path}
```javascript
{vul_snippet}
```

## Task
Apply the SMALLEST possible change that eliminates the vulnerability.
Rules:
- Do NOT rewrite or restructure logic that is unrelated to the vulnerability.
- Do NOT remove error handling, logging, or security checks that already exist.
- Preserve the exact function signature and any existing module.exports.
- Do NOT add new require() / import statements unless strictly necessary.

Output ONLY the complete corrected function/code block inside a single ```javascript ... ``` fence.
Do not add any explanation, comments, or text outside the fence.
"""

# Prompt for large snippets: ask for unified diff directly.
JS_GEN_DIFF_PROMPT_TEMPLATE = """You are a JavaScript security engineer performing a minimal, surgical patch.

## Vulnerability
CVE: {cve_id}
CWE: {cwe_id} - {cwe_name}

## Description
{cve_description}

## Exploitation insight for {cwe_id}
{cwe_hint}

## Vulnerable code (LARGE — {snippet_lines} lines)
File: {file_path}
```javascript
{vul_snippet}
```

## Task
Because the function is large, output ONLY a unified diff (patch format) with the minimal
changes required to fix the vulnerability. Do not rewrite the entire function.

Rules:
- Use standard unified diff format (--- a/file / +++ b/file / @@ hunks).
- Include 3 lines of context around each changed block.
- Touch ONLY the lines necessary to fix the vulnerability.
- Do NOT output a markdown code fence. Output raw diff text only.
"""

# CWE-specific hints for JavaScript
_JS_CWE_HINTS = {
    "CWE-22":  "Path traversal: use path.basename() or path.resolve() + check the result stays inside the intended directory. Never concatenate user input directly into file paths.",
    "CWE-79":  "XSS: escape user-controlled data before inserting into HTML. Use a library like DOMPurify or the built-in template auto-escaping. Never use innerHTML with untrusted input.",
    "CWE-89":  "SQL injection: use parameterised queries / prepared statements. Never concatenate user input into SQL strings.",
    "CWE-94":  "Code injection / eval: never pass user input to eval(), new Function(), or vm.runInNewContext(). Validate against a strict allow-list.",
    "CWE-200": "Information exposure: strip sensitive fields (stack traces, internal paths, credentials) from error responses sent to clients.",
    "CWE-284": "Improper access control: add an authorisation check (e.g. req.user.role check) before the privileged operation.",
    "CWE-400": "Resource exhaustion / ReDoS: cap input length before regex matching, or rewrite the regex to be non-backtracking.",
    "CWE-601": "Open redirect: validate that the redirect URL is relative or matches an allow-listed domain before calling res.redirect().",
    "CWE-918": "SSRF: parse the destination URL, block private/loopback ranges and custom protocols before making outbound HTTP requests.",
    "CWE-1321": "Prototype pollution: use Object.create(null) for lookup maps, or guard with Object.prototype.hasOwnProperty.call() / hasOwn(). Reject keys like '__proto__', 'constructor', 'prototype'.",
}
_JS_DEFAULT_CWE_HINT = "Identify the exact insecure operation and add the minimum guard (input validation, sanitisation, or access check) required to prevent exploitation."


def _js_gen_build_prompt(cve_record, vul_entry):
    """Build the LLM prompt for a JavaScript CVE."""
    cwe_ids   = list(cve_record.get("cwe_info", {}).keys())
    cwe_id    = cwe_ids[0] if cwe_ids else "UNKNOWN"
    cwe_name  = cve_record.get("cwe_info", {}).get(cwe_id, {}).get("name", "")
    cwe_hint  = _JS_CWE_HINTS.get(cwe_id, _JS_DEFAULT_CWE_HINT)
    snippet   = vul_entry["snippet"]
    snippet_lines = len(snippet.splitlines())

    if snippet_lines > LARGE_SNIPPET_THRESHOLD:
        return JS_GEN_DIFF_PROMPT_TEMPLATE.format(
            cve_id=cve_record["cve_id"],
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            cve_description=cve_record.get("cve_description", ""),
            cwe_hint=cwe_hint,
            file_path=vul_entry["file_path"],
            snippet_lines=snippet_lines,
            vul_snippet=snippet,
        )

    return JS_GEN_PROMPT_TEMPLATE.format(
        cve_id=cve_record["cve_id"],
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        cve_description=cve_record.get("cve_description", ""),
        cwe_hint=cwe_hint,
        file_path=vul_entry["file_path"],
        vul_snippet=snippet,
    )


def cmd_js_generate(args):
    """Batch snippet-level patch generation for JavaScript CVEs (Gemini or OpenRouter)."""
    provider = getattr(args, "provider", "gemini")

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)
    js_items = [d for d in data if d.get("programing_language", "").lower() == "javascript"]
    print(f"[INFO] Loaded {len(js_items)} JavaScript CVEs from {args.input}")

    # Resume: skip CVEs already in output file
    done_cves = set()
    if os.path.exists(args.output):
        with open(args.output, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    done_cves.add(json.loads(line)["cve"])
        if done_cves:
            print(f"[RESUME] Already have {len(done_cves)} CVEs in {args.output}, skipping.")
        js_items = [d for d in js_items if d["cve_id"] not in done_cves]

    if args.limit > 0:
        js_items = js_items[: args.limit]

    print(f"[INFO] Will generate patches for {len(js_items)} CVEs using provider={provider}")

    consecutive_429_fails = 0
    total_prompt_tokens = 0
    total_completion_tokens = 0
    token_usage_rows: list = []
    model_label = getattr(args, "or_model", args.model) if provider == "openrouter" else args.model
    for i, d in enumerate(js_items):
        cve_id      = d["cve_id"]
        vul_entries = d.get("vul_func", [])
        if not vul_entries:
            print(f"[SKIP] {cve_id}: no vul_func entries")
            continue
        vul_entry     = vul_entries[0]
        snippet_lines = len(vul_entry["snippet"].splitlines())
        large_mode    = snippet_lines > LARGE_SNIPPET_THRESHOLD
        prompt        = _js_gen_build_prompt(d, vul_entry)
        mode_tag      = f"diff-mode ({snippet_lines}L)" if large_mode else f"full-mode ({snippet_lines}L)"
        print(f"[GEN]  {cve_id}  [{mode_tag}]")

        try:
            raw_output, usage = _call_llm(
                provider, prompt,
                gemini_model=args.model,
                openrouter_model=getattr(args, "or_model", "poolside/laguna-s-2.1:free"),
                max_tokens=args.max_tokens,
            )
            consecutive_429_fails = 0
        except Exception as e:
            print(f"[FAIL] {cve_id}: {e}")
            if "429" in str(e):
                consecutive_429_fails += 1
                if consecutive_429_fails >= 2:
                    print("\n>>> Likely daily quota exhausted. Stop and retry after midnight (Pacific).\n")
                    break
            continue

        total_prompt_tokens     += usage.get("prompt_tokens", 0)
        total_completion_tokens += usage.get("completion_tokens", 0)
        token_usage_rows.append({
            "cve":               cve_id,
            "prompt_tokens":     usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
            "total_tokens":      usage.get("total_tokens", 0),
            "timestamp":         datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        })

        old_snippet = _gen_normalize_trailing_blank(vul_entry["snippet"])

        if large_mode:
            fix_patch = _go_clean_raw_diff(raw_output, vul_entry["file_path"])
        else:
            new_code = _gen_extract_code_block(raw_output)
            if _go_looks_truncated(new_code, old_snippet):
                print(f"[WARN] {cve_id}: output looks truncated (new={len(new_code.splitlines())}L vs old={snippet_lines}L), skipping")
                continue
            new_code  = _gen_reindent_to_match(old_snippet, new_code)
            new_code  = _gen_ensure_matching_trailing_blank(old_snippet, new_code)
            fix_patch = _gen_build_unified_diff(
                vul_entry["file_path"], old_snippet, new_code,
                start_line=vul_entry.get("start_line", 1),
            )

        if not fix_patch.strip():
            print(f"[WARN] {cve_id}: empty patch generated, skipping")
            continue

        record = {
            "cve": cve_id, "fix_patch": fix_patch, "language": "JavaScript", "model": model_label,
            "token_usage": {
                "prompt_tokens":     usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens":      usage.get("total_tokens", 0),
            },
        }
        with open(args.output, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"[OK]   {cve_id}  "
              f"[tokens: prompt={usage.get('prompt_tokens',0):,}  "
              f"completion={usage.get('completion_tokens',0):,}  "
              f"total={usage.get('total_tokens',0):,}]")

        if i < len(js_items) - 1:
            # OpenRouter free tier: ~20 req/min → 3s min; Gemini free: 5 req/min → 13s
            sleep_s = 3 if provider == "openrouter" else 13
            time.sleep(sleep_s)

    total_now = 0
    if os.path.exists(args.output):
        with open(args.output, encoding="utf-8") as f:
            total_now = sum(1 for _ in f)
    print(f"\nDone. Total JavaScript CVEs now in {args.output}: {total_now}")
    print(f"Session tokens — prompt: {total_prompt_tokens:,}  "
          f"completion: {total_completion_tokens:,}  "
          f"total: {total_prompt_tokens + total_completion_tokens:,}")
    if token_usage_rows:
        _save_token_usage(args.output, token_usage_rows, model_label, provider)


# =====================================================================
# go-agent — Agent mode for Docker runner (patch_agent_runner.py)
#
# This replaces the old my_gemini_agent.py. It is invoked inside a Docker
# container by patch_agent_runner.py via agents/gemini.sh. It:
#   1. Discovers .go / go.mod files in the workdir.
#   2. Pre-filters to ≤60 files, then asks the LLM to pick the 5 most relevant.
#   3. Reads those files and asks the LLM to produce a unified diff patch.
#   4. Writes the patch to /workspace/fix.patch.
# =====================================================================

def _agent_get_all_filepaths(workdir: str) -> list:
    all_files = []
    for root, dirs, files in os.walk(workdir):
        for skip in (".git", "vendor", "testdata", "node_modules"):
            if skip in dirs:
                dirs.remove(skip)
        for file in files:
            if file.endswith(".go") or file == "go.mod":
                all_files.append(os.path.relpath(os.path.join(root, file), workdir))
    return all_files


def _agent_prefilter_files(all_files: list, prompt: str, max_files: int = 60) -> list:
    """Heuristic pre-filter: prioritise files whose path contains keywords from the prompt."""
    if len(all_files) <= max_files:
        return all_files
    words = set(w.lower() for w in prompt.split() if len(w) > 4 and w.isalpha())
    scored = []
    for f in all_files:
        f_lower = f.lower()
        score = sum(1 for w in words if w in f_lower)
        scored.append((score, f))
    scored.sort(key=lambda x: -x[0])
    return [f for _, f in scored[:max_files]]


def cmd_go_agent(args):
    """Agent mode: read prompt file, discover Go files, ask LLM for patch, write fix.patch."""
    _log("Agent (go-agent) started.")
    provider = getattr(args, "provider", "gemini")
    gemini_model = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
    or_model = getattr(args, "or_model", "poolside/laguna-s-2.1:free")
    _log(f"Provider: {provider} | Gemini model: {gemini_model} | OR model: {or_model}")
    _log(f"Working directory: {args.workdir}")

    with open(args.prompt_file, "r", encoding="utf-8") as f:
        prompt = f.read()

    # STEP 1: discover files
    _log("STEP 1: Discovering Go files in workspace...")
    all_files = _agent_get_all_filepaths(args.workdir)
    _log(f"Found {len(all_files)} Go files.")

    candidate_files = _agent_prefilter_files(all_files, prompt, max_files=60)
    _log(f"Pre-filtered to {len(candidate_files)} candidate files for LLM selection.")
    file_list_str = "\n".join(candidate_files)

    selection_prompt = (
        f"{prompt}\n\n"
        f"Here are the most relevant file paths in the codebase:\n{file_list_str}\n\n"
        "Based on the vulnerability description, which 5 files are most likely to need "
        "modification to fix this vulnerability? "
        "Output ONLY a comma-separated list of the exact file paths, and absolutely nothing else."
    )

    # STEP 2: LLM file selection
    _log("STEP 2: Asking LLM to select the most relevant files...")
    try:
        selected_files_str, sel_usage = _call_llm(provider, selection_prompt,
                                                  gemini_model=gemini_model,
                                                  openrouter_model=or_model,
                                                  max_tokens=512)
    except Exception as e:
        _log(f"Error during file selection: {e}")
        sys.exit(1)

    _log(f"LLM file selection tokens: prompt={sel_usage.get('prompt_tokens',0)}, completion={sel_usage.get('completion_tokens',0)}")
    _log(f"LLM file selection response: {selected_files_str}")
    selected_files = [f.strip(' `"\n') for f in selected_files_str.split(",")]
    valid_files = [f for f in selected_files if f in all_files]

    if not valid_files:
        _log("Warning: LLM did not return valid files. Falling back to first 10 files.")
        valid_files = all_files[:10]
    else:
        _log(f"Validated {len(valid_files)} files: {', '.join(valid_files)}")

    # STEP 3: read selected files
    _log("STEP 3: Compiling selected file contents into prompt context...")
    code_context = ""
    for rel_path in valid_files:
        filepath = os.path.join(args.workdir, rel_path)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            code_context += f"--- {rel_path} ---\n{content}\n\n"
        except Exception:
            pass

    # STEP 4: patch generation
    full_prompt = (
        f"{prompt}\n\n"
        f"Here is the content of the most relevant files:\n\n{code_context}\n\n"
        "Please provide a unified diff (.patch format) that fixes the vulnerability. "
        "Only output the raw diff content. Do not wrap it in markdown code blocks. "
        "The diff must be applicable directly to the files."
    )

    _log("STEP 4: Requesting patch generation from LLM...")
    try:
        text, patch_usage = _call_llm(provider, full_prompt,
                                      gemini_model=gemini_model,
                                      openrouter_model=or_model,
                                      max_tokens=4096)
    except Exception as e:
        _log(f"Error during patch generation: {e}")
        sys.exit(1)

    _log(f"Successfully received patch from LLM. Tokens: prompt={patch_usage.get('prompt_tokens',0)}, completion={patch_usage.get('completion_tokens',0)}")

    # Strip markdown fences if present
    if text.startswith("```"):
        lines = text.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines)

    # STEP 5: write patch
    patch_path = "/workspace/fix.patch"
    _log(f"STEP 5: Writing patch to {patch_path}...")
    with open(patch_path, "w", encoding="utf-8") as f:
        f.write(text)

    _log(f"Agent finished successfully. Patch generated by {provider}.")


# =====================================================================
# export — HTML/CSV analysis report + gap analysis (based on Docker eval)
# =====================================================================

def _exp_cwe_category(cwe_name: str) -> str:
    name = (cwe_name or "").lower()
    if "sql" in name:
        return "SQL Injection"
    if "deserial" in name or "pickle" in name:
        return "Deserialization"
    if "command" in name or "os command" in name or "code injection" in name or "eval" in name:
        return "Injection/RCE"
    if "path" in name or "directory traversal" in name or "file name" in name:
        return "Path/File Control"
    if "redirect" in name or "ssrf" in name or "server-side request" in name:
        return "SSRF/Redirect"
    if "access control" in name or "authoriz" in name or "permission" in name:
        return "Access Control"
    if "authent" in name or "session" in name or "credential" in name:
        return "Auth & Session"
    if "information" in name or "disclosure" in name or "exposure" in name:
        return "Info Disclosure"
    if "input validation" in name or "improper input" in name:
        return "Input Validation"
    return "Other"


def _exp_structural_metrics(snippet: str):
    if not snippet:
        return {"loops": 0, "branches": 0, "depth": 0, "cyclomatic": 1}
    code = textwrap.dedent(snippet)
    tree = None
    used_code = code
    for candidate in (code, "class _Wrap:\n" + snippet):
        try:
            tree = ast.parse(candidate)
            used_code = candidate
            break
        except SyntaxError:
            continue
    if tree is None:
        return {"loops": 0, "branches": 0, "depth": 0, "cyclomatic": None}

    loops = sum(isinstance(n, (ast.For, ast.While)) for n in ast.walk(tree))
    branches = sum(isinstance(n, ast.If) for n in ast.walk(tree))

    def max_depth(node, depth=0):
        best = depth
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                best = max(best, max_depth(child, depth + 1))
            else:
                best = max(best, max_depth(child, depth))
        return best

    cyclomatic = 1
    if HAS_RADON:
        try:
            results = cc_visit(used_code)
            cyclomatic = max((r.complexity for r in results), default=1)
        except Exception:
            cyclomatic = None

    return {"loops": loops, "branches": branches, "depth": max_depth(tree), "cyclomatic": cyclomatic}


def _exp_classify_fix_pattern(fix_patch: str) -> str:
    added = [l[1:] for l in fix_patch.splitlines() if l.startswith("+") and not l.startswith("+++")]
    removed = [l[1:] for l in fix_patch.splitlines() if l.startswith("-") and not l.startswith("---")]
    added_text = " ".join(added).lower()

    check_kw = ["if ", "raise ", "assert ", "not in", "startswith", "endswith", "validate", "sanitize",
                "return err", "errors.new", "fmt.errorf"]
    has_new_check = any(kw in added_text for kw in check_kw) and len(removed) <= len(added)

    if len(added) > 0 and len(removed) == 0:
        return "ADD_CHECK" if has_new_check else "ADD_CODE"
    if len(removed) > len(added) * 1.5:
        return "SIMPLIFY"
    if has_new_check and len(added) >= len(removed):
        return "ADD_CHECK"
    if abs(len(added) - len(removed)) <= 2:
        return "REPLACE"
    return "RESTRUCTURE"


def _exp_classify_failure_type(cwe_cat: str, cyclomatic, code_lines: int, fail_reason: str) -> str:
    cyclomatic = cyclomatic or 1
    if cwe_cat in ("SSRF/Redirect", "Auth & Session", "Deserialization") and cyclomatic < 6:
        return "Domain knowledge gap"
    if code_lines <= 10 and cyclomatic <= 3 and fail_reason in ("PoC Fail", "exploit_still_works"):
        return "Library/stdlib behavior gap"
    if cyclomatic >= 11 or code_lines >= 30:
        return "Code complexity gap"
    if fail_reason in ("compile_error", "apply_error", "SyntaxError"):
        return "Syntax/Format error"
    return "Logic gap"


def _exp_load_eval_results(eval_summary_paths, model_names):
    out = {}
    for path, model in zip(eval_summary_paths, model_names):
        with open(path, encoding="utf-8") as f:
            summary = json.load(f)
        success_set = set()
        for lang, cves in summary.get("poc_evaluation", {}).get("successful_cves", {}).items():
            success_set.update(cves)
        fail_reason = {}
        for key, cves in summary.get("failure_analysis", {}).get("failed_cves", {}).items():
            reason = key.split("_", 1)[1] if "_" in key else key
            for c in cves:
                fail_reason[c] = reason
        for c in success_set:
            out[c] = {"success": True, "fail_reason": None, "model": model}
        for c, r in fail_reason.items():
            out[c] = {"success": False, "fail_reason": r, "model": model}
    return out


def _exp_load_patches(patch_paths):
    out = {}
    for path in patch_paths:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                out[r["cve"]] = {"fix_patch": r["fix_patch"], "model": r.get("model", Path(path).stem)}
    return out


def cmd_export(args):
    if len(args.eval_summary) != len(args.patches):
        raise SystemExit("Number of --eval_summary must match number of --patches (same order).")

    with open(args.dataset, encoding="utf-8") as f:
        gt_data = json.load(f)
    gt_map = {d["cve_id"]: d for d in gt_data}

    model_names = [Path(p).stem for p in args.patches]
    patches = _exp_load_patches(args.patches)
    eval_results = _exp_load_eval_results(args.eval_summary, model_names)

    rows = []
    for cve_id, patch_info in patches.items():
        gt = gt_map.get(cve_id, {})
        vul_entry = (gt.get("vul_func") or [{}])[0]
        snippet = vul_entry.get("snippet", "")
        metrics = _exp_structural_metrics(snippet)

        cwe_ids = list(gt.get("cwe_info", {}).keys())
        cwe_id = cwe_ids[0] if cwe_ids else "?"
        cwe_name = gt.get("cwe_info", {}).get(cwe_id, {}).get("name", "") if cwe_ids else ""
        cwe_cat = _exp_cwe_category(cwe_name)

        eval_r = eval_results.get(cve_id, {"success": None, "fail_reason": "not_evaluated", "model": patch_info["model"]})
        code_lines = len(snippet.splitlines()) if snippet else 0
        fix_pattern = _exp_classify_fix_pattern(patch_info["fix_patch"])

        fail_type = None
        if eval_r["success"] is False:
            fail_type = _exp_classify_failure_type(cwe_cat, metrics["cyclomatic"], code_lines, eval_r["fail_reason"] or "")

        rows.append({
            "cve_id": cve_id,
            "model": eval_r["model"],
            "status": "pass" if eval_r["success"] else ("fail" if eval_r["success"] is False else "not_evaluated"),
            "cwe_id": cwe_id,
            "cwe_name": cwe_name,
            "cwe_category": cwe_cat,
            "code_lines": code_lines,
            "loops": metrics["loops"],
            "branches": metrics["branches"],
            "depth": metrics["depth"],
            "cyclomatic": metrics["cyclomatic"],
            "fix_pattern": fix_pattern,
            "fail_reason": eval_r["fail_reason"],
            "fail_type": fail_type,
        })

    Path(args.outdir).mkdir(parents=True, exist_ok=True)

    csv_cols = ["status", "model", "cve_id", "cwe_id", "cwe_name", "cwe_category",
                "code_lines", "loops", "branches", "depth", "cyclomatic",
                "fix_pattern", "fail_reason", "fail_type"]
    with open(f"{args.outdir}/analysis_report.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=csv_cols)
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {args.outdir}/analysis_report.csv ({len(rows)} rows)")

    evaluated = [r for r in rows if r["status"] != "not_evaluated"]
    n_pass = sum(1 for r in evaluated if r["status"] == "pass")
    n_fail = sum(1 for r in evaluated if r["status"] == "fail")
    total = len(evaluated)

    def group_rate(rows_list, key_fn):
        g = defaultdict(lambda: {"pass": 0, "fail": 0})
        for r in rows_list:
            k = key_fn(r)
            g[k]["pass" if r["status"] == "pass" else "fail"] += 1
        return g

    by_cwe = group_rate(evaluated, lambda r: r["cwe_category"])
    by_pattern = group_rate(evaluated, lambda r: r["fix_pattern"])
    by_model = group_rate(evaluated, lambda r: r["model"])
    by_failtype = defaultdict(int)
    for r in evaluated:
        if r["fail_type"]:
            by_failtype[r["fail_type"]] += 1

    print(f"\n=== SUMMARY ===")
    if total:
        print(f"Evaluated: {total} CVEs | Pass: {n_pass} ({n_pass/total*100:.1f}%) | Fail: {n_fail}")
    else:
        print("No CVEs evaluated yet (check --eval_summary).")

    def print_group(title, g):
        print(f"\n-- {title} --")
        for k, v in sorted(g.items(), key=lambda x: -(x[1]["pass"] + x[1]["fail"])):
            t = v["pass"] + v["fail"]
            print(f"  {k:25s}: {v['pass']}/{t} ({v['pass']/t*100:.0f}%)")

    if total:
        print_group("By CWE category", by_cwe)
        print_group("By fix pattern", by_pattern)
        print_group("By model", by_model)
        print(f"\n-- Failure taxonomy --")
        for k, v in sorted(by_failtype.items(), key=lambda x: -x[1]):
            pct = v / n_fail * 100 if n_fail else 0
            print(f"  {k:28s}: {v} CVEs ({pct:.0f}% of failures)")

    def table_html(g, title):
        html = f"<h3>{title}</h3><table border=1 cellpadding=6 style='border-collapse:collapse'>"
        html += "<tr style='background:#2c3e50;color:#fff'><th>Category</th><th>Pass</th><th>Fail</th><th>Total</th><th>Rate</th></tr>"
        for k, v in sorted(g.items(), key=lambda x: -(x[1]["pass"] + x[1]["fail"])):
            t = v["pass"] + v["fail"]
            pct = v["pass"] / t * 100 if t else 0
            color = "#2ecc71" if pct >= 70 else "#f1c40f" if pct >= 40 else "#e74c3c"
            html += (f"<tr><td>{k}</td><td style='color:#2ecc71'>{v['pass']}</td>"
                     f"<td style='color:#e74c3c'>{v['fail']}</td><td>{t}</td>"
                     f"<td style='background:{color};color:#fff;text-align:center'>{pct:.0f}%</td></tr>")
        return html + "</table>"

    rows_html = ""
    for r in sorted(evaluated, key=lambda x: (0 if x["status"] == "pass" else 1, x["cve_id"])):
        bg = "#f0fff4" if r["status"] == "pass" else "#fff5f5"
        icon = "✅ PASS" if r["status"] == "pass" else "❌ FAIL"
        rows_html += (f"<tr style='background:{bg}'><td>{icon}</td><td>{r['model']}</td>"
                      f"<td><code>{r['cve_id']}</code></td><td>{r['cwe_category']}</td>"
                      f"<td>{r['fix_pattern']}</td><td>{r['code_lines']}</td>"
                      f"<td>{r['branches']}</td><td>{r['loops']}</td><td>{r['cyclomatic']}</td>"
                      f"<td>{r['fail_reason'] or '-'}</td><td>{r['fail_type'] or '-'}</td></tr>")

    models_str = ", ".join(sorted(set(r["model"] for r in evaluated))) if evaluated else "N/A"
    pass_pct = (n_pass / total * 100) if total else 0

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>PatchEval — Analysis Report</title>
<style>
body {{ font-family: -apple-system, "Segoe UI", sans-serif; margin:0; padding:24px; background:#f8f9fa; color:#2c3e50; }}
h1 {{ border-bottom:3px solid #3498db; padding-bottom:12px; }}
.stat-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin:16px 0; }}
.stat {{ background:#fff; border-radius:10px; padding:20px; text-align:center; box-shadow:0 2px 8px rgba(0,0,0,.08); }}
.stat-num {{ font-size:38px; font-weight:bold; }}
table {{ font-size:13px; margin-bottom:20px; }}
th {{ padding:6px 10px; }} td {{ padding:5px 10px; }}
.card {{ background:#fff; border-radius:10px; padding:20px; margin:16px 0; box-shadow:0 2px 8px rgba(0,0,0,.08); overflow-x:auto; }}
</style></head><body>
<h1>PatchEval — Analysis Report</h1>
<p>Models: <b>{models_str}</b> | Dataset: PatchEval Verified</p>
<div class="stat-grid">
  <div class="stat"><div class="stat-num">{total}</div><div>Total evaluated</div></div>
  <div class="stat"><div class="stat-num" style="color:#2ecc71">{n_pass}</div><div>Pass ({pass_pct:.1f}%)</div></div>
  <div class="stat"><div class="stat-num" style="color:#e74c3c">{n_fail}</div><div>Fail</div></div>
  <div class="stat"><div class="stat-num" style="color:#3498db">{pass_pct:.0f}%</div><div>Pass Rate</div></div>
</div>
<div class="card">{table_html(by_cwe, "By CWE Category")}</div>
<div class="card">{table_html(by_pattern, "By Fix Pattern")}</div>
<div class="card">{table_html(by_model, "By Model")}</div>
<div class="card"><h3>Full CVE Table</h3><table border=1 cellpadding=5 style="border-collapse:collapse;width:100%">
<tr style="background:#2c3e50;color:#fff"><th>Status</th><th>Model</th><th>CVE</th><th>CWE Category</th>
<th>Fix Pattern</th><th>Lines</th><th>Branches</th><th>Loops</th><th>Cyclomatic</th><th>Fail Reason</th><th>Fail Type</th></tr>
{rows_html}
</table></div>
</body></html>"""

    with open(f"{args.outdir}/analysis_report.html", "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\nWrote {args.outdir}/analysis_report.html")


# =====================================================================
# check-bytes — detect hidden \r\n in .jsonl files (Windows newline debug)
# =====================================================================

def cmd_check_bytes(args):
    path = args.path
    with open(path, "rb") as f:
        raw_bytes = f.read()

    if b"\r\n" in raw_bytes:
        count = raw_bytes.count(b"\r\n")
        print(f"DETECTED \\r\\n in .jsonl file! ({count} occurrences) — this is the cause.")
    else:
        print("No \\r\\n found in .jsonl file — file is clean.")

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            fix_patch = record["fix_patch"]
            if "\r" in fix_patch:
                print(f"HIDDEN \\r in fix_patch of CVE {record['cve']}!")
                print(repr(fix_patch[:200]))
            else:
                print(f"CVE {record['cve']}: fix_patch is clean, no \\r.")


# =====================================================================
# extract-patch — extract a single CVE's patch to a standalone .patch file
# =====================================================================

def cmd_extract_patch(args):
    with open(args.jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            if record["cve"] == args.cve_id:
                with open(args.out_path, "w", encoding="utf-8", newline="\n") as fo:
                    fo.write(record["fix_patch"])
                print(f"Wrote {args.out_path} ({len(record['fix_patch'])} chars)")
                with open(args.out_path, "rb") as fcheck:
                    raw = fcheck.read()
                print("Contains \\r\\n:", b"\r\n" in raw)
                return
        print(f"CVE {args.cve_id} not found in {args.jsonl_path}")


# =====================================================================
# CLI
# =====================================================================

def build_parser():
    ap = argparse.ArgumentParser(
        prog="patcheval_toolkit.py",
        description=(
            "PatchEval toolkit — Python EDA/generate/export "
            "+ Go patch generation (Gemini & OpenRouter) + agent mode"
        ),
    )
    sub = ap.add_subparsers(dest="command", required=True)

    # ── eda ──────────────────────────────────────────────────────────
    p_eda = sub.add_parser("eda", help="EDA for CVE dataset and evaluation results (failure analysis & metrics)")
    p_eda.add_argument("--input", required=True, help="Dataset JSON (patcheval_verified.json or language subset)")
    p_eda.add_argument("--lang", default="all", help="Language filter: all | Python | Go | JavaScript (default: all)")
    p_eda.add_argument("--eval-results", default=None, help="Companion eval_results.json or evaluation summary.json")
    p_eda.add_argument("--outdir", default="./eda", help="Output directory for EDA tables and summaries")
    p_eda.set_defaults(func=cmd_eda)

    # ── save-eval ────────────────────────────────────────────────────
    p_save_eval = sub.add_parser("save-eval", help="Save evaluation results, failure analysis (apply_fail, compilation_fail, validation_fail) & tokens to companion JSON & EDA")
    p_save_eval.add_argument("--patch-file", required=True, help="eval_inputs/<label>.jsonl")
    p_save_eval.add_argument("--eval-dir", required=True, help="Path to evaluation_output/results/<label> or summary.json")
    p_save_eval.add_argument("--dataset", default=None, help="Dataset JSON (patcheval_verified_go.json or patcheval_verified.json)")
    p_save_eval.add_argument("--eda-dir", default="./eda", help="Directory to save EDA summaries (default: ./eda)")
    p_save_eval.set_defaults(func=cmd_save_eval)

    # ── complexity ───────────────────────────────────────────────────
    p_cx = sub.add_parser("complexity", help="Structural complexity analysis for Python (requires radon)")
    p_cx.add_argument("--input", required=True)
    p_cx.add_argument("--outdir", default="./output_python")
    p_cx.set_defaults(func=cmd_complexity)

    # ── generate (Python) ────────────────────────────────────────────
    p_gen = sub.add_parser("generate", help="Batch patch generation for Python CVEs")
    p_gen.add_argument("--input", required=True, help="patcheval_verified.json")
    p_gen.add_argument("--output", default="python_patches_gemini.jsonl")
    p_gen.add_argument("--model", default="gemini-2.0-flash", help="Gemini model name")
    p_gen.add_argument("--or-model", dest="or_model", default="poolside/laguna-s-2.1:free",
                       help="OpenRouter model name (default: poolside/laguna-s-2.1:free — best free coding model)")
    p_gen.add_argument("--provider", choices=["gemini", "openrouter"], default="gemini")
    p_gen.add_argument("--limit", type=int, default=-1, help="-1 = run all")
    p_gen.add_argument("--max_tokens", type=int, default=6000)
    p_gen.set_defaults(func=cmd_generate)

    # ── py-generate (alias for generate, consistent naming with go/js) ───
    p_pygen = sub.add_parser("py-generate", help="Batch patch generation for Python CVEs (alias for 'generate')")
    p_pygen.add_argument("--input", required=True, help="patcheval_verified.json or python subset")
    p_pygen.add_argument("--output", default="python_patches.jsonl")
    p_pygen.add_argument("--model", default="gemini-2.0-flash", help="Gemini model name")
    p_pygen.add_argument("--or-model", dest="or_model", default="poolside/laguna-s-2.1:free",
                         help="OpenRouter model name (default: poolside/laguna-s-2.1:free — best free coding model)")
    p_pygen.add_argument("--provider", choices=["gemini", "openrouter"], default="gemini")
    p_pygen.add_argument("--limit", type=int, default=-1, help="-1 = run all")
    p_pygen.add_argument("--max_tokens", type=int, default=6000)
    p_pygen.set_defaults(func=cmd_generate)

    # ── go-generate ──────────────────────────────────────────────────
    p_gogen = sub.add_parser("go-generate", help="Batch snippet-level patch generation for Go CVEs")
    p_gogen.add_argument("--input", required=True, help="patcheval_verified.json or go subset")
    p_gogen.add_argument("--output", default="go_patches.jsonl")
    p_gogen.add_argument("--model", default="gemini-2.0-flash", help="Gemini model name")
    p_gogen.add_argument("--or-model", dest="or_model", default="poolside/laguna-s-2.1:free",
                         help="OpenRouter model name (default: poolside/laguna-s-2.1:free — best free coding model)")
    p_gogen.add_argument("--provider", choices=["gemini", "openrouter"], default="gemini")
    p_gogen.add_argument("--limit", type=int, default=-1, help="-1 = run all")
    p_gogen.add_argument("--max_tokens", type=int, default=6000)
    p_gogen.set_defaults(func=cmd_go_generate)

    # ── js-generate ──────────────────────────────────────────────────
    p_jsgen = sub.add_parser("js-generate", help="Batch snippet-level patch generation for JavaScript CVEs")
    p_jsgen.add_argument("--input", required=True, help="patcheval_verified.json or js subset")
    p_jsgen.add_argument("--output", default="js_patches.jsonl")
    p_jsgen.add_argument("--model", default="gemini-2.0-flash", help="Gemini model name")
    p_jsgen.add_argument("--or-model", dest="or_model", default="poolside/laguna-s-2.1:free",
                         help="OpenRouter model name (default: poolside/laguna-s-2.1:free — best free coding model)")
    p_jsgen.add_argument("--provider", choices=["gemini", "openrouter"], default="gemini")
    p_jsgen.add_argument("--limit", type=int, default=-1, help="-1 = run all")
    p_jsgen.add_argument("--max_tokens", type=int, default=6000)
    p_jsgen.set_defaults(func=cmd_js_generate)

    # ── go-agent ─────────────────────────────────────────────────────
    p_agent = sub.add_parser("go-agent", help="Agent mode for Docker runner (replaces my_gemini_agent.py)")
    p_agent.add_argument("prompt_file", help="Path to the prompt text file written by patch_agent_runner.py")
    p_agent.add_argument("workdir", help="Repository root inside the Docker container")
    p_agent.add_argument("--provider", choices=["gemini", "openrouter"], default="gemini")
    p_agent.add_argument("--or-model", dest="or_model", default="poolside/laguna-s-2.1:free",
                         help="OpenRouter model (only used when --provider openrouter)")
    p_agent.set_defaults(func=cmd_go_agent)

    # ── export ───────────────────────────────────────────────────────
    p_exp = sub.add_parser("export", help="Generate HTML/CSV analysis report + gap analysis")
    p_exp.add_argument("--dataset", required=True)
    p_exp.add_argument("--patches", nargs="+", required=True)
    p_exp.add_argument("--eval_summary", nargs="+", required=True,
                       help="One summary.json per --patches file, in the same order")
    p_exp.add_argument("--outdir", default="./report")
    p_exp.set_defaults(func=cmd_export)

    # ── check-bytes ──────────────────────────────────────────────────
    p_cb = sub.add_parser("check-bytes", help="Detect hidden \\r\\n in .jsonl files")
    p_cb.add_argument("path", nargs="?", default="go_patches.jsonl")
    p_cb.set_defaults(func=cmd_check_bytes)

    # ── extract-patch ────────────────────────────────────────────────
    p_ep = sub.add_parser("extract-patch", help="Extract a single CVE's patch to a standalone .patch file")
    p_ep.add_argument("jsonl_path")
    p_ep.add_argument("cve_id")
    p_ep.add_argument("out_path", nargs="?", default="test.patch")
    p_ep.set_defaults(func=cmd_extract_patch)

    return ap


def main():
    ap = build_parser()
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
