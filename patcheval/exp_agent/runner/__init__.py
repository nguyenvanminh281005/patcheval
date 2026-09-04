"""runner package — refactored from patch_agent_runner.py.

Sub-modules:
  models       — CommandResult, GenerationResult dataclasses
  docker_utils — Docker helpers (_run, _docker_exec, _detect_workdir, ...)
  agent        — core orchestration (_run_one, _main)
  cli          — build_parser + main entry point
"""
from runner.cli import build_parser, main
