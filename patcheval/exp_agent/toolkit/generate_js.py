"""Batch snippet-level patch generation for JavaScript CVEs."""
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

from toolkit.utils import (
    _log, _call_llm, _save_token_usage,
    _gen_extract_code_block, _gen_normalize_trailing_blank,
    _gen_ensure_matching_trailing_blank, _gen_reindent_to_match,
    _gen_build_unified_diff,
)
from toolkit.generate_go import _go_looks_truncated, _go_clean_raw_diff, LARGE_SNIPPET_THRESHOLD

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
