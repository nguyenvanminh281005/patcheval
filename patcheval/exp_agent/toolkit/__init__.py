"""toolkit package — refactored from patcheval_toolkit.py.

Sub-modules:
  utils           — shared helpers, LLM callers, diff builders
  eda             — EDA and complexity analysis
  generate_python — Python CVE patch generation
  generate_go     — Go CVE patch generation
  generate_js     — JavaScript CVE patch generation
  agent           — Go agent mode (Docker runner)
  export          — HTML/CSV report generation
  misc            — check-bytes, extract-patch
  cli             — build_parser + main entry point
"""
from toolkit.cli import build_parser, main
