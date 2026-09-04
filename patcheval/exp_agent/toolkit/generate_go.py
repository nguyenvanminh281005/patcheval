"""Batch snippet-level patch generation for Go CVEs."""
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
