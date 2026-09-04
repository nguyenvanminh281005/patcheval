"""Data models for patch_agent_runner."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shlex
import shutil
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional


DEFAULT_AGENT_TIMEOUT_S = 3600
STREAM_READER_LIMIT = 16 * 1024 * 1024



@dataclass
class CommandResult:
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False


@dataclass
class GenerationResult:
    index: int
    cve: str
    instance_id: str
    image: str
    workdir: str
    container_name: str
    status: str
    patch_generated: bool
    agent_exit_code: Optional[int]
    timed_out: bool
    duration_s: float
    patch_path: str
    error: str = ""
    error_type: str = ""
