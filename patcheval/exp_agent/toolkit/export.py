"""HTML/CSV analysis report + gap analysis."""
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

from toolkit.utils import _log

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
