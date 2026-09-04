#!/usr/bin/env python3
"""patch_agent_runner.py — entry-point wrapper.

The actual implementation has been refactored into the `runner/` package:
  runner/models.py       — CommandResult, GenerationResult dataclasses
  runner/docker_utils.py — Docker helpers
  runner/agent.py        — core orchestration (_run_one, _main)
  runner/cli.py          — build_parser + main

This wrapper exists so that existing scripts (run_infer.sh, etc.) that call
`python3 patch_agent_runner.py` continue to work unchanged.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from runner.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
