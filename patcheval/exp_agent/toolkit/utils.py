"""Shared utilities: logging, token usage, eval results, LLM callers, diff builders."""
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


def _log(msg: str, log_path: str = "/results/agent_live_status.log") -> None:
    print(f"[AGENT LOG] {msg}", file=sys.stderr, flush=True)
    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[AGENT LOG] {msg}\n")
    except Exception:
        pass


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
    """CLI command handler for save-eval.

    In addition to the legacy _save_eval_results() logic (companion JSON + EDA),
    this also writes:
      - <eval_dir>/pass/CVE-xxxx.json  for each PASS CVE
      - <eval_dir>/fail/CVE-yyyy.json  for each FAIL CVE
      - <eval_dir>/results.json        compact summary for Pandas / benchmark table
    """
    import datetime as _dt

    patch_file = args.patch_file
    eval_dir   = args.eval_dir
    dataset    = getattr(args, "dataset", None)
    model_id   = getattr(args, "model", "unknown")
    language   = getattr(args, "language", "unknown")
    eda_dir    = getattr(args, "eda_dir", "./eda")

    # ── 1. Legacy save (companion JSON + EDA all_eval_summary) ───────────────
    _save_eval_results(
        patch_file=patch_file,
        eval_dir=eval_dir,
        dataset_path=dataset,
        eda_dir=eda_dir,
    )

    # ── 2. Per-CVE PASS/FAIL JSON files + results.json ───────────────────────
    eval_path = Path(eval_dir)
    pass_dir  = eval_path / "pass"
    fail_dir  = eval_path / "fail"
    pass_dir.mkdir(parents=True, exist_ok=True)
    fail_dir.mkdir(parents=True, exist_ok=True)

    # Load generated patches
    patches = {}
    if os.path.isfile(patch_file):
        with open(patch_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                cve = rec.get("cve") or rec.get("cve_id", "")
                patches[cve] = rec

    # Load dataset for ground-truth and original code
    ground_truth = {}
    if dataset and os.path.isfile(dataset):
        with open(dataset, "r", encoding="utf-8") as f:
            ds_items = json.load(f)
        for item in ds_items:
            cve_id = item.get("cve_id", "")
            gt_lines = []
            for vf in item.get("vul_func", []):
                for loc in vf.get("vul_localization", []):
                    gt_lines.extend(loc.get("patch_lines", []))
            ground_truth[cve_id] = {
                "ground_truth_patch": "\n".join(gt_lines),
                "original_code": item.get("vul_func", [{}])[0].get("snippet", "") if item.get("vul_func") else "",
            }

    # Determine PASS/FAIL per CVE from logs directory
    logs_dir = eval_path / "logs"
    cve_results = {}
    if logs_dir.is_dir():
        for cve_dir in sorted(logs_dir.iterdir()):
            if not cve_dir.is_dir():
                continue
            cve_id      = cve_dir.name
            success_log = cve_dir / "success_output.log"
            error_log   = cve_dir / "error_output.log"

            if success_log.exists():
                log_text       = success_log.read_text(encoding="utf-8", errors="replace")
                status         = "PASS"
                failure_reason = None
                compile_pass   = "compilation_fail" not in log_text
                poc_pass       = True
            else:
                log_text = error_log.read_text(encoding="utf-8", errors="replace") if error_log.exists() else ""
                status   = "FAIL"
                if "apply_fail" in log_text:
                    failure_reason = "Patch does not apply (apply_fail)"
                    compile_pass   = False
                    poc_pass       = False
                elif "compilation_fail" in log_text:
                    failure_reason = "Patch compiles but contains syntax/compilation error (compilation_fail)"
                    compile_pass   = False
                    poc_pass       = False
                elif "validation_fail" in log_text:
                    failure_reason = "Patch compiles but does not fix vulnerability (validation_fail)"
                    compile_pass   = True
                    poc_pass       = False
                else:
                    failure_reason = "Unknown failure — check error_output.log"
                    compile_pass   = None
                    poc_pass       = False

            # Parse validation_type from log
            validation_type = None
            for line in log_text.splitlines():
                if "[Validation TYPE]:" in line:
                    validation_type = line.split("[Validation TYPE]:")[1].strip()
                    break

            cve_results[cve_id] = {
                "status":          status,
                "compile":         compile_pass,
                "poc_pass":        poc_pass,
                "validation_type": validation_type,
                "failure_reason":  failure_reason,
            }

    # Patches with no log entry
    for cve_id in patches:
        if cve_id not in cve_results:
            cve_results[cve_id] = {
                "status":          "UNKNOWN",
                "compile":         None,
                "poc_pass":        None,
                "validation_type": None,
                "failure_reason":  "No evaluation log found",
            }

    timestamp      = _dt.datetime.now(_dt.timezone.utc).isoformat()
    results_summary = []
    n_pass = n_fail = n_unknown = 0

    for cve_id, res in sorted(cve_results.items()):
        patch_rec = patches.get(cve_id, {})
        gt_rec    = ground_truth.get(cve_id, {})
        status    = res["status"]

        cve_doc = {
            "cve_id":             cve_id,
            "language":           language,
            "model":              model_id,
            "status":             status,
            "original_code":      gt_rec.get("original_code", ""),
            "generated_patch":    patch_rec.get("fix_patch", ""),
            "ground_truth_patch": gt_rec.get("ground_truth_patch", ""),
            "evaluation": {
                "poc_pass":        res["poc_pass"],
                "compile":         res["compile"],
                "validation_type": res["validation_type"],
            },
            "timestamp": timestamp,
        }
        if status == "FAIL":
            cve_doc["failure_reason"] = res["failure_reason"]

        safe_name = cve_id.replace("/", "_").replace("\\", "_") + ".json"
        if status == "PASS":
            out_path = pass_dir / safe_name
            n_pass += 1
        elif status == "FAIL":
            out_path = fail_dir / safe_name
            n_fail += 1
        else:
            out_path = eval_path / f"unknown_{safe_name}"
            n_unknown += 1

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(cve_doc, f, indent=2, ensure_ascii=False)

        results_summary.append({
            "cve_id":   cve_id,
            "status":   status,
            "language": language,
            "model":    model_id,
        })

    # Write results.json
    total     = n_pass + n_fail + n_unknown
    pass_rate = round(n_pass / total * 100, 2) if total > 0 else 0.0
    results_json = {
        "model":     model_id,
        "language":  language,
        "timestamp": timestamp,
        "stats": {
            "total":     total,
            "pass":      n_pass,
            "fail":      n_fail,
            "unknown":   n_unknown,
            "pass_rate": f"{pass_rate:.2f}%",
        },
        "results": results_summary,
    }
    results_path = eval_path / "results.json"
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(results_json, f, indent=2, ensure_ascii=False)

    print("")
    print("━" * 60)
    print(f"  [save-eval] Per-CVE results written")
    print(f"  Model    : {model_id}")
    print(f"  Language : {language}")
    print(f"  Total    : {total}  |  PASS: {n_pass}  |  FAIL: {n_fail}" +
          (f"  |  UNKNOWN: {n_unknown}" if n_unknown else ""))
    print(f"  Pass Rate: {pass_rate:.2f}%")
    print(f"  pass/ → {pass_dir}  ({n_pass} CVEs)")
    print(f"  fail/ → {fail_dir}  ({n_fail} CVEs)")
    print(f"  results.json → {results_path}")
    print("━" * 60)



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
