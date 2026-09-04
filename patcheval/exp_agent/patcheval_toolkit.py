#!/usr/bin/env python3
"""patcheval_toolkit.py — entry-point wrapper.

The actual implementation has been refactored into the `toolkit/` package:
  toolkit/utils.py           — shared helpers, LLM callers, diff builders
  toolkit/eda.py             — EDA and complexity analysis
  toolkit/generate_python.py — Python CVE patch generation
  toolkit/generate_go.py     — Go CVE patch generation
  toolkit/generate_js.py     — JavaScript CVE patch generation
  toolkit/agent.py           — Go agent mode
  toolkit/export.py          — HTML/CSV report generation
  toolkit/misc.py            — check-bytes, extract-patch
  toolkit/cli.py             — build_parser + main

This wrapper exists so that existing scripts (run_gemini.sh, run_openrouter.sh)
that call `python3 patcheval_toolkit.py <command>` continue to work unchanged.
"""
import sys
import os

# Ensure the exp_agent directory is on sys.path so `toolkit` package is found
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from toolkit.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
