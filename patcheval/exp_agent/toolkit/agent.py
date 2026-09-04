"""Go agent mode for Docker runner (patch_agent_runner.py)."""
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

from toolkit.utils import _log, _call_llm

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
