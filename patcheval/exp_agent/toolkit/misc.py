"""Miscellaneous CLI commands: check-bytes, extract-patch."""
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


def cmd_check_bytes(args):
    path = args.path
    with open(path, "rb") as f:
        raw_bytes = f.read()

    if b"\r\n" in raw_bytes:
        count = raw_bytes.count(b"\r\n")
        print(f"DETECTED \\r\\n in .jsonl file! ({count} occurrences) — this is the cause.")
    else:
        print("No \\r\\n found in .jsonl file — file is clean.")

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            fix_patch = record["fix_patch"]
            if "\r" in fix_patch:
                print(f"HIDDEN \\r in fix_patch of CVE {record['cve']}!")
                print(repr(fix_patch[:200]))
            else:
                print(f"CVE {record['cve']}: fix_patch is clean, no \\r.")


# =====================================================================
# extract-patch — extract a single CVE's patch to a standalone .patch file
# =====================================================================

def cmd_extract_patch(args):
    with open(args.jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            record = json.loads(line)
            if record["cve"] == args.cve_id:
                with open(args.out_path, "w", encoding="utf-8", newline="\n") as fo:
                    fo.write(record["fix_patch"])
                print(f"Wrote {args.out_path} ({len(record['fix_patch'])} chars)")
                with open(args.out_path, "rb") as fcheck:
                    raw = fcheck.read()
                print("Contains \\r\\n:", b"\r\n" in raw)
                return
        print(f"CVE {args.cve_id} not found in {args.jsonl_path}")
