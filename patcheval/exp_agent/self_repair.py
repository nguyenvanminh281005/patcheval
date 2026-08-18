#!/usr/bin/env python3
"""
self_repair.py — Vong lap tu sua loi (self-repair loop) cho PatchEval.

Y tuong: thay vi goi Gemini 1 lan roi dung, moi CVE se duoc thu toi da
`--max_rounds` lan. Neu patch fail (compile loi hoac validation fail),
loi build/test se duoc dua NGUOC lai vao prompt de Gemini tu sua, roi
thu lai. Dung ngay khi PASS, hoac het so vong.

QUAN TRONG: script nay PHAI dat CUNG THU MUC voi run_evaluation.py
(vd: patcheval/evaluation/self_repair.py), vi no import truc tiep
DockerManager va Evaluation tu file do de tai su dung logic Docker
(khong viet lai tu dau).

Cach dung — GEMINI (vi du cho Go, 5 CVE dau tien, toi da 3 vong tu sua):
    cd patcheval/evaluation
    export GEMINI_API_KEY="AIzaSy..."
    python3 self_repair.py \
        --input ../datasets/patcheval_verified_go.json \
        --output ../exp_agent/eval_inputs/go_poc_selfrepair.jsonl \
        --lang Go \
        --provider gemini \
        --model gemini-2.0-flash \
        --max_rounds 3 \
        --limit 5

Cach dung — OPENROUTER (vi du model google/gemma-3-27b-it):
    export OPENROUTER_API_KEY="sk-or-v1-..."
    python3 self_repair.py \
        --input ../datasets/patcheval_verified_go.json \
        --output ../exp_agent/eval_inputs/go_poc_selfrepair_or.jsonl \
        --lang Go \
        --provider openrouter \
        --model google/gemma-3-27b-it \
        --max_rounds 3 \
        --limit 5

Cho JavaScript, chi doi --lang va --input (giu nguyen --provider/--model):
    python3 self_repair.py \
        --input ../datasets/patcheval_verified_js.json \
        --output ../exp_agent/eval_inputs/js_poc_selfrepair.jsonl \
        --lang JavaScript \
        --provider openrouter \
        --model google/gemma-3-27b-it \
        --max_rounds 3 \
        --limit 5

Ket qua ghi ra --output theo dinh dang .jsonl giong het go_poc.jsonl /
js_poc.jsonl hien co (co the dua thang vao run_evaluation.py --patch_file
de re-evaluate lai lan cuoi, hoac dung luon field "rounds_used" /
"final_status" duoc ghi kem trong moi dong de biet vong nao thanh cong).
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import sys
import time
from pathlib import Path

import requests

# ── Import lai logic Docker tu run_evaluation.py (khong viet lai) ───────────
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from run_evaluation import DockerManager, Evaluation
except ImportError as e:
    raise SystemExit(
        "Khong import duoc DockerManager/Evaluation tu run_evaluation.py.\n"
        "Hay dat self_repair.py CUNG THU MUC voi run_evaluation.py "
        f"(vd: patcheval/evaluation/). Loi goc: {e}"
    )

import logging

GEMINI_URL_TMPL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# ── Prompt: vong dau tien (giong generate binh thuong) ──────────────────────
INITIAL_PROMPT_TEMPLATE = """You are a code security expert. Your task is to fix the following vulnerability.

# Vulnerability Information
CVE: {cve_id}
CWE: {cwe_id} - {cwe_name}
Description: {cve_description}

# Vulnerable Function
File: {file_path}
```{lang_fence}
{vul_snippet}
```

# Instructions
1. Analyze the root cause of the vulnerability.
2. Propose a minimal fix that removes the vulnerability without changing unrelated behavior.
3. Output ONLY the full corrected version of the function/code block above, inside a single
   code fence. Do not add explanations outside the code fence.
"""

# ── Prompt: vong sua loi (co dua log loi vong truoc vao) ────────────────────
REPAIR_PROMPT_TEMPLATE = """You are a code security expert. Your previous attempt to fix a vulnerability
FAILED when applied and tested. Fix it again, taking the error below into account.

# Vulnerability Information
CVE: {cve_id}
CWE: {cwe_id} - {cwe_name}
Description: {cve_description}

# Original Vulnerable Function
File: {file_path}
```{lang_fence}
{vul_snippet}
```

# Your Previous Attempt (this FAILED)
```{lang_fence}
{previous_code}
```

# Error / Test Output From Previous Attempt
```
{error_log}
```

# Instructions
1. Diagnose exactly why the previous attempt failed, based on the error above.
2. Produce a corrected, full version of the function/code block that fixes BOTH the
   original vulnerability AND the error from the previous attempt.
3. Output ONLY the full corrected version, inside a single code fence. No explanations
   outside the code fence.
"""

LANG_FENCE = {"Go": "go", "JavaScript": "javascript", "Python": "python"}


# ── Cac ham xu ly text (copy tu patcheval_toolkit.py, khong phu thuoc ngon ngu) ──

def _call_gemini(prompt: str, model: str, api_key: str, max_tokens: int, max_retries: int = 3) -> str:
    url = f"{GEMINI_URL_TMPL.format(model=model)}?key={api_key}"
    generation_config = {"temperature": 0, "maxOutputTokens": max_tokens}
    payload = {"contents": [{"parts": [{"text": prompt}]}], "generationConfig": generation_config}
    last_err = None
    for attempt in range(max_retries):
        try:
            resp = requests.post(url, json=payload, timeout=120)
            if resp.status_code == 429:
                wait_s = 15 + attempt * 15
                print(f"    [429] Qua tai. Cho {wait_s}s...")
                time.sleep(wait_s)
                last_err = "429"
                continue
            if resp.status_code == 503:
                wait_s = 10 + attempt * 10
                print(f"    [503] Model qua tai. Cho {wait_s}s...")
                time.sleep(wait_s)
                last_err = "503"
                continue
            resp.raise_for_status()
            data = resp.json()
            if "error" in data:
                raise RuntimeError(f"API error: {data['error']}")
            candidates = data.get("candidates", [])
            if not candidates:
                raise RuntimeError(f"Khong co candidate. Response: {json.dumps(data)[:400]}")
            parts = candidates[0].get("content", {}).get("parts", [])
            text = "".join(p.get("text", "") for p in parts)
            if not text:
                raise RuntimeError(f"Content rong. finishReason={candidates[0].get('finishReason')}")
            return text
        except Exception as e:
            last_err = e
            print(f"    [Retry {attempt + 1}/{max_retries}] Loi: {e}")
            time.sleep(2 ** attempt)
    raise RuntimeError(f"Gemini call that bai sau {max_retries} lan: {last_err}")


def _call_openrouter(prompt: str, model: str, api_key: str, max_tokens: int, max_retries: int = 3) -> str:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": max_tokens,
    }
    last_err = None
    for attempt in range(max_retries):
        try:
            resp = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=120)
            if resp.status_code == 429:
                wait_s = 15 + attempt * 15
                print(f"    [429] Qua tai. Cho {wait_s}s...")
                time.sleep(wait_s)
                last_err = "429"
                continue
            if resp.status_code in (502, 503):
                wait_s = 10 + attempt * 10
                print(f"    [{resp.status_code}] Model qua tai. Cho {wait_s}s...")
                time.sleep(wait_s)
                last_err = str(resp.status_code)
                continue
            resp.raise_for_status()
            data = resp.json()
            if "error" in data:
                raise RuntimeError(f"API error: {data['error']}")
            choices = data.get("choices", [])
            if not choices:
                raise RuntimeError(f"Khong co choice nao. Response: {json.dumps(data)[:400]}")
            text = choices[0].get("message", {}).get("content", "")
            if not text:
                raise RuntimeError(f"Content rong. finish_reason={choices[0].get('finish_reason')}")
            return text
        except Exception as e:
            last_err = e
            print(f"    [Retry {attempt + 1}/{max_retries}] Loi: {e}")
            time.sleep(2 ** attempt)
    raise RuntimeError(f"OpenRouter call that bai sau {max_retries} lan: {last_err}")


def call_llm(prompt: str, provider: str, model: str, api_key: str, max_tokens: int, max_retries: int = 3) -> str:
    if provider == "openrouter":
        return _call_openrouter(prompt, model, api_key, max_tokens, max_retries)
    return _call_gemini(prompt, model, api_key, max_tokens, max_retries)


def extract_code_block(model_output: str) -> str:
    lines = model_output.splitlines()
    in_block, block = False, []
    for line in lines:
        if line.strip().startswith("```"):
            if in_block:
                break
            in_block = True
            continue
        if in_block:
            block.append(line)
    return "\n".join(block) if block else model_output.strip()


def normalize_trailing_blank(old_snippet: str) -> str:
    if not old_snippet.endswith("\n"):
        old_snippet += "\n"
    return old_snippet


def ensure_matching_trailing_blank(old_snippet: str, new_code: str) -> str:
    old_lines = old_snippet.splitlines()
    if not old_lines or old_lines[-1].strip():
        return new_code
    boundary_line = old_lines[-1]
    new_lines = new_code.splitlines()
    if new_lines and new_lines[-1] == boundary_line:
        return new_code
    return new_code.rstrip("\n") + "\n" + boundary_line + "\n"


def reindent_to_match(old_snippet: str, new_code: str) -> str:
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
    return "\n".join(base_indent + l if l.strip() else l for l in new_lines)


def build_unified_diff(file_path, old_snippet, new_snippet, start_line=1):
    if not old_snippet.endswith("\n"):
        old_snippet += "\n"
    if not new_snippet.endswith("\n"):
        new_snippet += "\n"
    old_lines, new_lines = old_snippet.splitlines(), new_snippet.splitlines()
    diff = difflib.unified_diff(old_lines, new_lines, fromfile=f"a/{file_path}",
                                 tofile=f"b/{file_path}", lineterm="", n=3)
    diff_text = "\n".join(diff)

    def repl(m):
        return f"@@ -{start_line},{m.group(1)} +{start_line},{m.group(2)} @@"

    diff_text = re.sub(r"@@ -1,(\d+) \+1,(\d+) @@", repl, diff_text, count=1)
    return f"diff --git a/{file_path} b/{file_path}\n" + diff_text + "\n"


def build_patch_from_code(old_snippet, raw_output, file_path, start_line):
    old_snippet_n = normalize_trailing_blank(old_snippet)
    new_code = extract_code_block(raw_output)
    new_code = reindent_to_match(old_snippet_n, new_code)
    new_code = ensure_matching_trailing_blank(old_snippet_n, new_code)
    fix_patch = build_unified_diff(file_path, old_snippet_n, new_code, start_line=start_line)
    return new_code, fix_patch


def truncate_log(text: str, max_chars: int = 3000) -> str:
    if len(text) <= max_chars:
        return text
    head = text[: max_chars // 2]
    tail = text[-max_chars // 2:]
    return head + "\n... [truncated] ...\n" + tail


# ── Vong lap chinh cho 1 CVE ──────────────────────────────────────────────

def self_repair_one_cve(cve_record, provider, api_key, model, max_tokens, max_rounds, logger):
    cve_id = cve_record["cve_id"]
    vul_entry = cve_record["vul_func"][0]
    cwe_ids = list(cve_record.get("cwe_info", {}).keys())
    cwe_id = cwe_ids[0] if cwe_ids else "UNKNOWN"
    cwe_name = cve_record.get("cwe_info", {}).get(cwe_id, {}).get("name", "")
    language = cve_record.get("programing_language", "Go")
    lang_fence = LANG_FENCE.get(language, language.lower())
    image_name = cve_record.get("image_url")
    if not image_name:
        return {"cve": cve_id, "status": "no_image", "rounds_used": 0}

    old_snippet = vul_entry["snippet"]
    file_path = vul_entry["file_path"]
    start_line = vul_entry.get("start_line", 1)

    previous_code = None
    previous_error = None
    last_patch = None
    last_result_type = None

    evaluation = Evaluation(logger=logger, cve=cve_id)

    for round_num in range(1, max_rounds + 1):
        print(f"  [Round {round_num}/{max_rounds}] {cve_id}")

        if round_num == 1:
            prompt = INITIAL_PROMPT_TEMPLATE.format(
                cve_id=cve_id, cwe_id=cwe_id, cwe_name=cwe_name,
                cve_description=cve_record.get("cve_description", ""),
                file_path=file_path, lang_fence=lang_fence, vul_snippet=old_snippet,
            )
        else:
            prompt = REPAIR_PROMPT_TEMPLATE.format(
                cve_id=cve_id, cwe_id=cwe_id, cwe_name=cwe_name,
                cve_description=cve_record.get("cve_description", ""),
                file_path=file_path, lang_fence=lang_fence, vul_snippet=old_snippet,
                previous_code=previous_code, error_log=truncate_log(previous_error or ""),
            )

        try:
            raw_output = call_llm(prompt, provider, model, api_key, max_tokens)
        except Exception as e:
            print(f"    [FAIL] LLM call error: {e}")
            return {"cve": cve_id, "status": "llm_error", "rounds_used": round_num,
                    "fix_patch": last_patch or "", "error": str(e)}

        new_code, fix_patch = build_patch_from_code(old_snippet, raw_output, file_path, start_line)
        last_patch = fix_patch
        previous_code = new_code

        run_poc_result, run_poc_msg, validation_type = evaluation.run_evaluation(
            cve=cve_id, llm_patch=fix_patch, language=language,
            test_name="self_repair", image_name=image_name,
        )
        last_result_type = validation_type

        if run_poc_result:
            print(f"    [PASS] {cve_id} sau {round_num} vong")
            return {
                "cve": cve_id, "language": language, "model": model,
                "fix_patch": fix_patch, "status": "pass",
                "rounds_used": round_num,
            }

        # Fail -> chuan bi log loi cho vong sau
        previous_error = run_poc_msg or "Khong co log loi chi tiet."
        print(f"    [FAIL] {cve_id} ({validation_type}) — thu lai..." if round_num < max_rounds
              else f"    [FAIL] {cve_id} ({validation_type}) — het so vong, dung lai.")

    return {
        "cve": cve_id, "language": language, "model": model,
        "fix_patch": last_patch or "", "status": "fail",
        "final_fail_type": last_result_type, "rounds_used": max_rounds,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="dataset json (vd patcheval_verified_go.json)")
    ap.add_argument("--output", required=True, help="file .jsonl de ghi ket qua")
    ap.add_argument("--lang", required=True, help="Go | JavaScript | Python — loc dataset theo ngon ngu nay")
    ap.add_argument("--provider", default="gemini", choices=["gemini", "openrouter"],
                     help="gemini (mac dinh) | openrouter")
    ap.add_argument("--model", default=None,
                     help="Mac dinh: gemini-2.0-flash (gemini) hoac google/gemma-3-27b-it (openrouter)")
    ap.add_argument("--max_tokens", type=int, default=6000)
    ap.add_argument("--max_rounds", type=int, default=3, help="So vong tu sua toi da moi CVE")
    ap.add_argument("--limit", type=int, default=-1, help="-1 = chay het")
    args = ap.parse_args()

    if args.model is None:
        args.model = "google/gemma-3-27b-it" if args.provider == "openrouter" else "gemini-2.0-flash"

    if args.provider == "openrouter":
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            raise SystemExit("Chua set OPENROUTER_API_KEY.")
    else:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise SystemExit("Chua set GEMINI_API_KEY.")

    with open(args.input, encoding="utf-8") as f:
        data = json.load(f)
    items = [d for d in data if d.get("programing_language", "").lower() == args.lang.lower()]

    # Resume: bo qua CVE da co trong output
    done_cves = set()
    if os.path.exists(args.output):
        with open(args.output, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    done_cves.add(json.loads(line)["cve"])
        if done_cves:
            print(f"[RESUME] Da co {len(done_cves)} CVE trong {args.output}, se bo qua.")
        items = [d for d in items if d["cve_id"] not in done_cves]

    if args.limit > 0:
        items = items[: args.limit]

    logging.basicConfig(level=logging.WARNING)
    logger = logging.getLogger("self_repair")

    print(f"[INFO] Se chay self-repair cho {len(items)} CVE "
          f"(lang={args.lang}, provider={args.provider}, model={args.model}, max_rounds={args.max_rounds})")

    n_pass, n_fail = 0, 0
    for i, cve_record in enumerate(items):
        result = self_repair_one_cve(cve_record, args.provider, api_key, args.model, args.max_tokens,
                                      args.max_rounds, logger)
        with open(args.output, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(result, ensure_ascii=False) + "\n")

        if result["status"] == "pass":
            n_pass += 1
        else:
            n_fail += 1

        if i < len(items) - 1:
            time.sleep(5)  # nghi giua cac CVE de tranh rate limit

    print(f"\n[DONE] Pass: {n_pass} | Fail: {n_fail} | Tong: {n_pass + n_fail}")
    print(f"Ket qua ghi tai: {args.output}")


if __name__ == "__main__":
    main()