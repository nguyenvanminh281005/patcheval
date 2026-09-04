"""Docker helper functions."""
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

from runner.models import CommandResult, STREAM_READER_LIMIT

def _safe_name(value: str, max_len: int = 100) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip())
    return (value.strip(".-") or "sample")[:max_len]


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")



def _log(message: str) -> None:
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}", flush=True)



def _require_dataset_images(samples: list[dict[str, Any]]) -> None:
    missing: list[str] = []
    for sample in samples:
        cve = str(sample["cve_id"])
        if not sample.get("image_url"):
            missing.append(cve)
    if missing:
        preview = ", ".join(missing[:10])
        suffix = "" if len(missing) <= 10 else f", ... ({len(missing)} total)"
        raise ValueError(f"dataset samples missing image_url: {preview}{suffix}")


def _image_url(sample: dict[str, Any]) -> str:
    image = str(sample.get("image_url") or "").strip()
    if not image:
        raise ValueError(f"dataset sample {sample.get('cve_id', '<unknown>')} missing image_url")
    return image


def _repo_basename(repo_url: str) -> str:
    name = repo_url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return name



async def _run(args: list[str], *, timeout_s: Optional[int] = None) -> CommandResult:
    started = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=STREAM_READER_LIMIT,
    )
    try:
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        timed_out = False
    except asyncio.TimeoutError:
        proc.kill()
        out_b, err_b = await proc.communicate()
        timed_out = True
    return CommandResult(
        command=args,
        exit_code=int(proc.returncode if proc.returncode is not None else 124),
        stdout=(out_b or b"").decode("utf-8", errors="replace"),
        stderr=(err_b or b"").decode("utf-8", errors="replace"),
        duration_s=time.monotonic() - started,
        timed_out=timed_out,
    )


async def _docker_exec(container: str, command: str, *, workdir: str = "/", timeout_s: int = 600) -> CommandResult:
    args = ["docker", "exec", "-w", workdir, container, "bash", "-lc", command]
    return await _run(args, timeout_s=timeout_s)


def _parse_mounts(items: list[str]) -> list[tuple[str, str, str]]:
    mounts = []
    for item in items:
        parts = item.split(":")
        if len(parts) not in (2, 3):
            raise ValueError(f"expected HOST:CONTAINER[:ro|rw], got: {item}")
        mode = parts[2] if len(parts) == 3 else "rw"
        if mode not in {"ro", "rw"}:
            raise ValueError(f"invalid mount mode: {item}")
        mounts.append((str(Path(parts[0]).expanduser().resolve()), parts[1], mode))
    return mounts


def _docker_run_args(container: str, image: str, result_dir: Path, mounts: list[tuple[str, str, str]]) -> list[str]:
    cmd = ["docker", "run", "-d", "--name", container, "-v", f"{result_dir.resolve()}:/results:rw"]
    for host, dst, mode in mounts:
        cmd.extend(["-v", f"{host}:{dst}:{mode}"])
    cmd.extend([image, "bash", "-lc", "tail -f /dev/null"])
    return cmd



async def _detect_workdir(container: str, sample: dict[str, Any]) -> str:
    workdir_hint = str(sample.get("workdir") or "").rstrip("/")
    if workdir_hint:
        check = await _docker_exec(container, f"test -d {shlex.quote(workdir_hint)}/.git", timeout_s=60)
        if check.exit_code == 0:
            return workdir_hint
        raise RuntimeError(f"dataset workdir is not a git repository in image: {workdir_hint}")

    repo_name = _repo_basename(str(sample.get("repo") or ""))
    if repo_name:
        check = await _docker_exec(container, f"test -d /workspace/{shlex.quote(repo_name)}/.git", timeout_s=60)
        if check.exit_code == 0:
            return f"/workspace/{repo_name}"
        lower_repo_name = repo_name.lower()
        if lower_repo_name != repo_name:
            check = await _docker_exec(container, f"test -d /workspace/{shlex.quote(lower_repo_name)}/.git", timeout_s=60)
            if check.exit_code == 0:
                return f"/workspace/{lower_repo_name}"

    check = await _docker_exec(container, "test -d /workspace/.git", timeout_s=60)
    if check.exit_code == 0:
        return "/workspace"

    if repo_name:
        raise RuntimeError(
            f"could not locate git workdir for repo {repo_name!r}; "
            "check that dataset image_url matches this CVE or add dataset workdir"
        )

    find_repo = await _docker_exec(
        container,
        "find /workspace -mindepth 2 -maxdepth 3 -type d -name .git 2>/dev/null | head -n 2",
        timeout_s=60,
    )
    candidates = [line.rsplit("/.git", 1)[0] for line in find_repo.stdout.splitlines() if line.strip()]
    if len(candidates) == 1:
        return candidates[0]

    return "/workspace"


async def _hide_workspace_payload(container: str, workdir: str, session_key: str) -> None:
    if workdir.rstrip("/") == "/workspace":
        result = await _docker_exec(container, "rm -f /workspace/fix.patch", timeout_s=300)
        if result.exit_code != 0:
            raise RuntimeError(result.stderr or result.stdout)
        return

    if not workdir.startswith("/workspace/"):
        raise RuntimeError(f"target workdir is outside /workspace: {workdir}")

    script = f"""
set -e
rm -f /workspace/fix.patch
mkdir -p /tmp/{_safe_name(session_key)}
workdir={shlex.quote(workdir)}
top_name=${{workdir#/workspace/}}
top_name=${{top_name%%/*}}
find /workspace -mindepth 1 -maxdepth 1 ! -name "$top_name" -exec mv -t /tmp/{_safe_name(session_key)} -- {{}} + 2>/dev/null || true
"""
    result = await _docker_exec(container, script, timeout_s=300)
    if result.exit_code != 0:
        raise RuntimeError(result.stderr or result.stdout)



async def _collect_patch(container: str, workdir: str, result_dir: Path) -> CommandResult:
    script = f"""
set -e
cd {shlex.quote(workdir)}
if [ -s /workspace/fix.patch ]; then
  cp /workspace/fix.patch /results/llm.patch
elif git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git diff HEAD -U3 > /results/llm.patch
else
  echo "target workdir is not a git repository: $(pwd)" >&2
  exit 1
fi
test -s /results/llm.patch
"""
    return await _docker_exec(container, script, workdir=workdir, timeout_s=300)


async def _remove_container(container: str) -> None:
    await _run(["docker", "rm", "-f", container], timeout_s=120)
