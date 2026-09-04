"""EDA and complexity analysis commands."""
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

from toolkit.utils import _log, _save_eval_results, _find_eval_summary_and_logs

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
