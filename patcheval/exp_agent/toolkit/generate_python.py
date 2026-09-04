"""Batch patch generation for Python CVEs."""
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
    _log, _save_token_usage, _call_llm,
    _gen_build_prompt, _gen_extract_code_block,
    _gen_normalize_trailing_blank, _gen_ensure_matching_trailing_blank,
    _gen_reindent_to_match, _gen_build_unified_diff,
)

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
