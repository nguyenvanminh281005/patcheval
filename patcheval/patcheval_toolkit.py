#!/usr/bin/env python3

import argparse
import ast
import csv
import difflib
import json
import os
import re
import sys
import textwrap
import time
from collections import Counter, defaultdict
from pathlib import Path

try:
    from radon.complexity import cc_visit
    HAS_RADON = True
except ImportError:
    HAS_RADON = False


# =====================================================================
# eda — Part A: EDA co ban cho subset Python (70 CVE) trong PatchEval-Verified
# =====================================================================

def _eda_load_python_subset(input_path):
    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return [d for d in data if d["programing_language"] == "Python"]


def _eda_complexity_tier(lines):
    # Ranh gioi phong theo cung logic paper goc (Table 9) va khop voi
    # nguong "Easy = 1-5 dong" TT da dung. CAN xac nhan lai voi TT truoc khi
    # dung so nay de bao cao chinh thuc cho nhom.
    if lines <= 5:
        return "Easy"
    elif lines <= 10:
        return "Medium"
    elif lines <= 20:
        return "Hard"
    else:
        return "VeryHard"


def _eda_analyze(py_items):
    rows = []
    for d in py_items:
        cve_id = d["cve_id"]
        year = int(cve_id.split("-")[1])
        cwe_ids = list(d.get("cwe_info", {}).keys())
        primary_cwe = cwe_ids[0] if cwe_ids else "UNKNOWN"

        vul_entries = d.get("vul_func", [])
        patch_lines = sum(
            len(loc.get("patch_lines", []))
            for vf in vul_entries
            for loc in vf.get("vul_localization", [])
        )
        patch_locations = len(vul_entries)
        patch_files = len({vf["file_path"] for vf in vul_entries}) or 1

        rows.append({
            "cve_id": cve_id,
            "year": year,
            "repo": d.get("repo"),
            "cwe_ids": cwe_ids,
            "primary_cwe": primary_cwe,
            "patch_lines": patch_lines,
            "patch_locations": patch_locations,
            "patch_files": patch_files,
            "complexity_tier": _eda_complexity_tier(patch_lines),
        })
    return rows


def _eda_summarize(rows):
    n = len(rows)
    year_counts = Counter(r["year"] for r in rows)
    cwe_counts = Counter(r["primary_cwe"] for r in rows)
    tier_counts = Counter(r["complexity_tier"] for r in rows)

    lines_vals = sorted(r["patch_lines"] for r in rows)
    files_vals = sorted(r["patch_files"] for r in rows)

    def median(vals):
        m = len(vals)
        mid = m // 2
        return vals[mid] if m % 2 else (vals[mid - 1] + vals[mid]) / 2

    return {
        "n_cve": n,
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


def cmd_eda(args):
    os.makedirs(args.outdir, exist_ok=True)
    py_items = _eda_load_python_subset(args.input)
    rows = _eda_analyze(py_items)
    summary = _eda_summarize(rows)

    with open(os.path.join(args.outdir, "python_cve_table.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)
    with open(os.path.join(args.outdir, "python_eda_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(json.dumps(summary, indent=2, ensure_ascii=False))


# =====================================================================
# complexity — Part A2: structural complexity (cyclomatic/loop/branch/depth)
# =====================================================================

def _cx_safe_parse_and_measure(snippet: str):
    """Dedent snippet; neu van loi (vi du snippet la method body thieu class
    bao ngoai) thi bao trong 1 class gia de giu nguyen indent."""
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
    """Nguong tham khao theo chuan cyclomatic complexity pho bien trong
    software engineering (McCabe): 1-4 don gian, 5-10 vua, 11-20 phuc tap,
    20+ rat phuc tap/kho test. CAN THONG NHAT LAI VOI NHOM truoc khi dung
    chinh thuc - day chi la mot de xuat ban dau."""
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
        raise SystemExit("Can cai radon truoc: pip install radon --break-system-packages")

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
    print(f"Parse thanh cong: {len(rows) - fail_count}/{len(rows)}")
    print("Phan bo structural tier (dua tren cyclomatic complexity cua ham goc):")
    for tier in ["Easy", "Medium", "Hard", "VeryHard", "UNKNOWN"]:
        if tier in tier_counts:
            pct = tier_counts[tier] / len(rows) * 100
            print(f"  {tier:10s}: {tier_counts[tier]:3d} ({pct:.1f}%)")

    os.makedirs(args.outdir, exist_ok=True)
    out_path = os.path.join(args.outdir, "python_structural_complexity.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)
    print(f"\nDa ghi {out_path}")


# =====================================================================
# generate — Part B: sinh patch bang Gemini API (KHONG qua OpenRouter)
# =====================================================================
#
# CAN: export GEMINI_API_KEY=AIzaSy...
#      (lay tai https://aistudio.google.com/apikey - khong can the)
#
# Model khuyen dung: gemini-2.0-flash (khong phai model "thinking" nhu
# gemini-2.5-flash/pro, tranh lap lai loi tung gap - ton het token cho
# reasoning, khong kip tra loi).

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


def _gen_build_prompt(cve_record, vul_entry):
    cwe_ids = list(cve_record.get("cwe_info", {}).keys())
    cwe_id = cwe_ids[0] if cwe_ids else "UNKNOWN"
    cwe_name = cve_record.get("cwe_info", {}).get(cwe_id, {}).get("name", "")
    return GEN_PROMPT_TEMPLATE.format(
        cve_id=cve_record["cve_id"],
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        cve_description=cve_record.get("cve_description", ""),
        file_path=vul_entry["file_path"],
        lang="python",
        vul_snippet=vul_entry["snippet"],
    )


def _gen_call_llm(prompt: str, model: str, api_key: str, max_tokens: int, max_retries: int = 3) -> str:
    url = f"{GEMINI_URL_TMPL.format(model=model)}?key={api_key}"
    import requests
    generation_config = {"temperature": 0, "maxOutputTokens": max_tokens}
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": generation_config,
    }

    last_err = None
    for attempt in range(max_retries):
        try:
            resp = requests.post(url, json=payload, timeout=120)

            if resp.status_code >= 400:
                print(f"    [DEBUG] HTTP {resp.status_code}. Response: {resp.text[:800]}")

            if resp.status_code == 429:
                wait_s = 15 + attempt * 15
                print(f"    [429] Qua tai. Cho {wait_s}s roi thu lai...")
                time.sleep(wait_s)
                last_err = "429 Too Many Requests"
                continue

            resp.raise_for_status()
            data = resp.json()

            if "error" in data:
                raise RuntimeError(f"API tra ve error: {data['error']}")
            candidates = data.get("candidates", [])
            if not candidates:
                raise RuntimeError(f"Khong co candidate nao. Response: {json.dumps(data)[:500]}")

            candidate = candidates[0]
            finish_reason = candidate.get("finishReason")
            parts = candidate.get("content", {}).get("parts", [])
            text = "".join(p.get("text", "") for p in parts)

            if not text:
                print(f"    [DEBUG] Content rong. Response day du: {json.dumps(data, ensure_ascii=False)[:1000]}")
                raise RuntimeError(f"Content rong (finishReason={finish_reason}).")

            return text
        except Exception as e:
            last_err = e
            print(f"    [Retry {attempt + 1}/{max_retries}] Loi: {e}")
            time.sleep(2 ** attempt)
    raise RuntimeError(f"Gemini call that bai sau {max_retries} lan: {last_err}")


def _gen_extract_code_block(model_output: str) -> str:
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
    """(Da xac nhan qua Docker THAT: dong trang cuoi snippet trong dataset
    LA CHINH XAC (co whitespace that su, khong phai rong) - KHONG can
    chuan hoa gi ca. Ham nay gio chi dam bao co newline cuoi, giu nguyen
    noi dung nhu dataset da luu.)"""
    if not old_snippet.endswith("\n"):
        old_snippet += "\n"
    return old_snippet


def _gen_build_repo_relative_path(file_path: str, repo_url: str) -> str:
    """(KHONG con dung trong main() - giu lai de tham khao lich su debug.)
    QUAN TRONG - da xac nhan qua Docker THAT: fix-run.sh chay tu
    /workspace, nhung repo duoc checkout vao /workspace/<ten_repo>/, nen
    file_path trong dataset (tuong doi voi GOC REPO) phai duoc ghep them
    tien to ten repo moi ra dung duong dan tu /workspace. Thieu buoc nay
    khien git apply tim sai vi tri hoan toan, la nguyen nhan chinh gay
    fail xuyen suot qua trinh debug (sau do phat hien fix-run.sh da tu
    cd vao dung thu muc repo, nen buoc nay hoa ra khong can thiet)."""
    repo_name = repo_url.rstrip("/").split("/")[-1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]
    return f"{repo_name}/{file_path}"


def _gen_ensure_matching_trailing_blank(old_snippet: str, new_code: str) -> str:
    """Neu old_snippet ket thuc bang dong chi co whitespace (blank-ish),
    dam bao new_code cung ket thuc bang DUNG NOI DUNG do (khong doi) - de
    dong do tro thanh context khong doi thay vi bi model xoa/ghi de."""
    old_lines = old_snippet.splitlines()
    if not old_lines or old_lines[-1].strip():
        return new_code
    boundary_line = old_lines[-1]
    new_lines = new_code.splitlines()
    if new_lines and new_lines[-1] == boundary_line:
        return new_code
    return new_code.rstrip("\n") + "\n" + boundary_line + "\n"


def _gen_reindent_to_match(old_snippet: str, new_code: str) -> str:
    """LLM thuong tra ve code KHONG giu dung thut le goc - gay diff sai
    lech, khien git apply khong tim thay context khop. Tu dong them lai
    dung thut le cua dong dau tien trong old_snippet vao new_code."""
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
    # Dam bao ca 2 ben deu ket thuc bang "\n" - neu khong, git apply hieu
    # sai patch.
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

    # KHONG dua dong "index 0000..1111" gia vao - se bi hieu nham la tao
    # file moi, khong phai sua file da co.
    header = f"diff --git a/{file_path} b/{file_path}\n"
    return header + diff_text + "\n"


def cmd_generate(args):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise SystemExit("Chua set bien moi truong GEMINI_API_KEY.")

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
            print(f"[RESUME] Da co {len(done_cves)} CVE trong {args.output}, se bo qua.")
        py_items = [d for d in py_items if d["cve_id"] not in done_cves]

    if args.limit > 0:
        py_items = py_items[: args.limit]

    consecutive_429_fails = 0
    for i, d in enumerate(py_items):
        cve_id = d["cve_id"]
        vul_entry = d["vul_func"][0]
        prompt = _gen_build_prompt(d, vul_entry)
        try:
            raw_output = _gen_call_llm(prompt, args.model, api_key, args.max_tokens)
            consecutive_429_fails = 0
        except Exception as e:
            print(f"[FAIL] {cve_id}: {e}")
            if "429" in str(e):
                consecutive_429_fails += 1
                if consecutive_429_fails >= 2:
                    print("\n>>> Nhieu kha nang het quota ngay. Dung lai, doi reset")
                    print(">>> (nua dem gio Pacific) roi chay tiep.\n")
                    break
            continue

        old_snippet = _gen_normalize_trailing_blank(vul_entry["snippet"])
        new_code = _gen_extract_code_block(raw_output)
        new_code = _gen_reindent_to_match(old_snippet, new_code)
        new_code = _gen_ensure_matching_trailing_blank(old_snippet, new_code)
        # KHONG them tien to ten repo - da xac nhan qua fix-run.sh that:
        # no tu "cd /workspace/<repo>" truoc khi chay git apply, nen
        # file_path goc (tuong doi voi goc repo) la DUNG.
        fix_patch = _gen_build_unified_diff(
            vul_entry["file_path"], old_snippet, new_code,
            start_line=vul_entry.get("start_line", 1),
        )
        record = {"cve": cve_id, "fix_patch": fix_patch, "language": "Python", "model": args.model}
        with open(args.output, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"[OK] {cve_id}")

        if i < len(py_items) - 1:
            time.sleep(13)  # gemini-3.6-flash: limit 5 request/phut o free tier
                            # (60/5=12s toi thieu) - de 13s cho an toan

    total_now = 0
    if os.path.exists(args.output):
        with open(args.output, encoding="utf-8") as f:
            total_now = sum(1 for _ in f)
    print(f"\nHoan tat luot chay nay. Tong so CVE hien co trong {args.output}: {total_now}")


# =====================================================================
# export — Bao cao HTML/CSV tong hop + gap analysis (dua tren Docker that)
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

    check_kw = ["if ", "raise ", "assert ", "not in", "startswith", "endswith", "validate", "sanitize"]
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
        raise SystemExit("So luong --eval_summary phai khop voi so luong --patches (cung thu tu).")

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
    with open(f"{args.outdir}/analysis_report_python.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=csv_cols)
        w.writeheader()
        w.writerows(rows)
    print(f"Da ghi {args.outdir}/analysis_report_python.csv ({len(rows)} dong)")

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

    print(f"\n=== TONG QUAN ===")
    if total:
        print(f"Da danh gia: {total} CVE | Pass: {n_pass} ({n_pass/total*100:.1f}%) | Fail: {n_fail}")
    else:
        print("Chua co CVE nao duoc danh gia (kiem tra lai --eval_summary).")

    def print_group(title, g):
        print(f"\n-- {title} --")
        for k, v in sorted(g.items(), key=lambda x: -(x[1]["pass"] + x[1]["fail"])):
            t = v["pass"] + v["fail"]
            print(f"  {k:25s}: {v['pass']}/{t} ({v['pass']/t*100:.0f}%)")

    if total:
        print_group("Theo CWE category", by_cwe)
        print_group("Theo fix pattern", by_pattern)
        print_group("Theo model", by_model)
        print(f"\n-- Failure taxonomy (tai sao fail) --")
        for k, v in sorted(by_failtype.items(), key=lambda x: -x[1]):
            pct = v / n_fail * 100 if n_fail else 0
            print(f"  {k:28s}: {v} CVE ({pct:.0f}% cua so fail)")

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
        icon = "PASS" if r["status"] == "pass" else "FAIL"
        rows_html += (f"<tr style='background:{bg}'><td>{icon}</td><td>{r['model']}</td>"
                      f"<td><code>{r['cve_id']}</code></td><td>{r['cwe_category']}</td>"
                      f"<td>{r['fix_pattern']}</td><td>{r['code_lines']}</td>"
                      f"<td>{r['branches']}</td><td>{r['loops']}</td><td>{r['cyclomatic']}</td>"
                      f"<td>{r['fail_reason'] or '-'}</td><td>{r['fail_type'] or '-'}</td></tr>")

    models_str = ", ".join(sorted(set(r["model"] for r in evaluated))) if evaluated else "N/A"
    pass_pct = (n_pass / total * 100) if total else 0

    html = f"""<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8">
<title>PatchEval Python — Analysis Report</title>
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
<h1>PatchEval Python — Analysis Report</h1>
<p>Models: <b>{models_str}</b> | Dataset: PatchEval Verified</p>
<div class="stat-grid">
  <div class="stat"><div class="stat-num">{total}</div><div>Total evaluated</div></div>
  <div class="stat"><div class="stat-num" style="color:#2ecc71">{n_pass}</div><div>Pass ({pass_pct:.1f}%)</div></div>
  <div class="stat"><div class="stat-num" style="color:#e74c3c">{n_fail}</div><div>Fail</div></div>
  <div class="stat"><div class="stat-num" style="color:#3498db">{pass_pct:.0f}%</div><div>Pass Rate</div></div>
</div>
<div class="card">{table_html(by_cwe, "Theo CWE Category")}</div>
<div class="card">{table_html(by_pattern, "Theo Fix Pattern")}</div>
<div class="card">{table_html(by_model, "Theo Model")}</div>
<div class="card"><h3>Full CVE Table</h3><table border=1 cellpadding=5 style="border-collapse:collapse;width:100%">
<tr style="background:#2c3e50;color:#fff"><th>Status</th><th>Model</th><th>CVE</th><th>CWE Category</th>
<th>Fix Pattern</th><th>Lines</th><th>Branches</th><th>Loops</th><th>Cyclomatic</th><th>Fail Reason</th><th>Fail Type</th></tr>
{rows_html}
</table></div>
</body></html>"""

    with open(f"{args.outdir}/analysis_report_python.html", "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\nDa ghi {args.outdir}/analysis_report_python.html")


# =====================================================================
# check-bytes — kiem tra \r\n an trong file .jsonl (debug Windows newline)
# =====================================================================

def cmd_check_bytes(args):
    path = args.path
    with open(path, "rb") as f:
        raw_bytes = f.read()

    if b"\r\n" in raw_bytes:
        count = raw_bytes.count(b"\r\n")
        print(f"CO PHAT HIEN \\r\\n trong file .jsonl! ({count} lan) - day la nguyen nhan.")
    else:
        print("KHONG co \\r\\n trong file .jsonl - file nay sach.")

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            fix_patch = record["fix_patch"]
            if "\r" in fix_patch:
                print(f"CO \\r AN TRONG noi dung fix_patch cua CVE {record['cve']}!")
                print(repr(fix_patch[:200]))
            else:
                print(f"CVE {record['cve']}: fix_patch sach, khong co \\r.")


# =====================================================================
# extract-patch — trich 1 CVE ra file .patch rieng de test truc tiep
# =====================================================================

def cmd_extract_patch(args):
    with open(args.jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            if record["cve"] == args.cve_id:
                with open(args.out_path, "w", encoding="utf-8", newline="\n") as fo:
                    fo.write(record["fix_patch"])
                print(f"Da ghi {args.out_path} ({len(record['fix_patch'])} ky tu)")
                with open(args.out_path, "rb") as fcheck:
                    raw = fcheck.read()
                print("Co \\r\\n khong:", b"\r\n" in raw)
                return
        print(f"Khong tim thay CVE {args.cve_id} trong {args.jsonl_path}")


# =====================================================================
# CLI
# =====================================================================

def build_parser():
    ap = argparse.ArgumentParser(
        prog="patcheval_toolkit.py",
        description="PatchEval Python track — toolkit gop (eda, complexity, generate[Gemini], export, debug tools)",
    )
    sub = ap.add_subparsers(dest="command", required=True)

    p_eda = sub.add_parser("eda", help="Part A — EDA co ban (patch-size tier)")
    p_eda.add_argument("--input", required=True)
    p_eda.add_argument("--outdir", default="./output_python")
    p_eda.set_defaults(func=cmd_eda)

    p_cx = sub.add_parser("complexity", help="Part A2 — structural complexity (radon)")
    p_cx.add_argument("--input", required=True)
    p_cx.add_argument("--outdir", default="./output_python")
    p_cx.set_defaults(func=cmd_complexity)

    p_gen = sub.add_parser("generate", help="Part B — sinh patch bang Gemini API")
    p_gen.add_argument("--input", required=True, help="patcheval_verified.json")
    p_gen.add_argument("--output", default="python_patches_gemini.jsonl")
    p_gen.add_argument("--model", default="gemini-3.6-flash")
    p_gen.add_argument("--limit", type=int, default=-1, help="-1 = chay het")
    p_gen.add_argument("--max_tokens", type=int, default=6000)
    p_gen.set_defaults(func=cmd_generate)

    p_exp = sub.add_parser("export", help="Xuat bao cao HTML/CSV + gap analysis")
    p_exp.add_argument("--dataset", required=True)
    p_exp.add_argument("--patches", nargs="+", required=True)
    p_exp.add_argument("--eval_summary", nargs="+", required=True,
                        help="1 summary.json cho MOI file trong --patches, cung thu tu")
    p_exp.add_argument("--outdir", default="./report_python")
    p_exp.set_defaults(func=cmd_export)

    p_cb = sub.add_parser("check-bytes", help="Kiem tra \\r\\n an trong file .jsonl")
    p_cb.add_argument("path", nargs="?", default="python_patches_gemini.jsonl")
    p_cb.set_defaults(func=cmd_check_bytes)

    p_ep = sub.add_parser("extract-patch", help="Trich 1 CVE ra file .patch rieng")
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
