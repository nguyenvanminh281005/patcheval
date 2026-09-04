"""Core agent orchestration: run_one and _main."""
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

from runner.models import CommandResult, GenerationResult, DEFAULT_AGENT_TIMEOUT_S, STREAM_READER_LIMIT
from runner.docker_utils import (
    _safe_name, _read_json, _write_json, _log,
    _require_dataset_images, _image_url, _repo_basename,
    _run, _docker_exec, _parse_mounts, _docker_run_args,
    _detect_workdir, _hide_workspace_payload, _collect_patch, _remove_container,
)

def _prompt(sample: dict[str, Any], workdir_hint: str) -> str:
    return (
        "## USER\n\n"
        "Please fix the vulnerabilities in the code repository based on the following information:"
        + str(sample.get("cve_description") or "").strip()
        + "\n\n"
        + "Task runtime information:\n"
        + "- Target workdir: "
        + workdir_hint
        + "\n"
        + "- All tool path arguments must stay under this directory.\n"
        + "- Start exploration from this workspace root instead of guessing a path under /workspace.\n"
        + "- Before stopping, write the final repository diff to `/workspace/fix.patch` from the target workdir."
        + "\n\n"
        + "Repair-source restrictions:\n"
        + "- Do not search the web for this vulnerability, CVE, advisory, GHSA, release note, issue, pull request, or upstream patch.\n"
        + "- Do not run network commands such as curl, wget, git fetch, git pull, git ls-remote, npm view, pip index, or package/advisory lookups to find the fix.\n"
    )



async def _run_agent(container: str, workdir: str, command_template: str, result_dir: Path, env: dict[str, str], timeout_s: int) -> CommandResult:
    values = {
        "prompt_file": "/results/prompt.txt",
        "workdir": workdir,
    }
    command = command_template.format(**values)
    started = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        "docker", "exec", "-w", workdir,
        *sum((["-e", f"{k}={v}"] for k, v in env.items()), []),
        container, "bash", "-lc", command,
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
    stdout = (out_b or b"").decode("utf-8", errors="replace")
    stderr = (err_b or b"").decode("utf-8", errors="replace")
    (result_dir / "agent_stdout.txt").write_text(stdout, encoding="utf-8")
    (result_dir / "agent_stderr.txt").write_text(stderr, encoding="utf-8")
    return CommandResult(["docker", "exec", container, "bash", "-lc", command], int(proc.returncode if proc.returncode is not None else 124), stdout, stderr, time.monotonic() - started, timed_out)



async def _run_one(sample: dict[str, Any], index: int, args: argparse.Namespace, sem: asyncio.Semaphore, mounts: list[tuple[str, str, str]]) -> GenerationResult:
    async with sem:
        started = time.monotonic()
        cve = str(sample["cve_id"])
        instance_id = f"patcheval_{cve}"
        image = _image_url(sample)
        run_id = f"{index:05d}-{instance_id}"
        container = f"{args.container_prefix}-{_safe_name(run_id)}-{os.getpid()}"
        run_root = Path(args.run_root)
        work = run_root / ".work" / run_id
        work.mkdir(parents=True, exist_ok=True)
        patch_path = run_root / "patches" / f"{cve}.patch"
        status = "failed"
        error = ""
        workdir = "/workspace"
        agent_result: Optional[CommandResult] = None
        timed_out = False
        try:
            env = {"PATCHAGENT_SESSION_ID": container}
            run_result = await _run(_docker_run_args(container, image, work, mounts), timeout_s=1200)
            if run_result.exit_code != 0:
                raise RuntimeError(f"docker run failed: {run_result.stderr or run_result.stdout}")
            workdir = await _detect_workdir(container, sample)
            await _hide_workspace_payload(container, workdir, container)
            prompt = _prompt(sample, workdir)
            (work / "prompt.txt").write_text(prompt, encoding="utf-8")
            agent_result = await _run_agent(container, workdir, args.agent_command, work, env, args.agent_timeout)
            timed_out = agent_result.timed_out
            # Always attempt patch collection even if agent exited non-zero or was killed/timed out.
            # The agent may have written a patch before being killed.
            collect = await _collect_patch(container, workdir, work)
            if collect.exit_code == 0:
                patch_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(work / "llm.patch", patch_path)
                status = "generated"
                if agent_result.exit_code != 0:
                    _log(f"{run_id}: patch collected despite exit_code={agent_result.exit_code} (timed_out={timed_out})")
            else:
                raise RuntimeError(f"agent failed with exit_code={agent_result.exit_code}, no patch collected: {collect.stderr or collect.stdout}")
        except Exception as exc:
            error = str(exc)
            patch_path.parent.mkdir(parents=True, exist_ok=True)
            patch_path.write_text("", encoding="utf-8")
            _log(f"{run_id}: failed: {error}")
        finally:
            await _remove_container(container)
        error_type = ""
        if status != "generated":
            if timed_out:
                error_type = "agent_timeout"
            elif agent_result and agent_result.exit_code != 0:
                error_type = f"agent_exit_{agent_result.exit_code}"
            elif "docker run failed" in error:
                error_type = "docker_start_fail"
            elif "target workdir" in error or "git repository" in error:
                error_type = "workdir_error"
            elif "no patch collected" in error:
                error_type = "no_patch_collected"
            else:
                error_type = "generation_fail"
        result = GenerationResult(index, cve, instance_id, image, workdir, container, status, status == "generated", agent_result.exit_code if agent_result else None, timed_out, time.monotonic() - started, str(patch_path), error, error_type)
        return result


async def _main(args: argparse.Namespace) -> int:
    samples = _read_json(Path(args.input))
    indexed = list(enumerate(samples))
    if args.offset > 0:
        indexed = indexed[args.offset:]
    selected = indexed if args.limit < 0 else indexed[:args.limit]
    _require_dataset_images([sample for _, sample in selected])
    run_root = Path(args.output_dir) / f"{time.strftime('%Y%m%d_%H%M%S')}-{_safe_name(args.run_label or 'run')}"
    for sub in ["patches", ".work"]:
        (run_root / sub).mkdir(parents=True, exist_ok=True)
    args.run_root = str(run_root)
    _write_json(run_root / "run_metadata.json", vars(args) | {"run_root": str(run_root), "total_cases": len(selected)})
    mounts = _parse_mounts(args.mount)
    sem = asyncio.Semaphore(args.concurrency)
    tasks = [asyncio.create_task(_run_one(sample, idx, args, sem, mounts)) for idx, sample in selected]
    results_path = run_root / "results.jsonl"
    results = []
    with results_path.open("w", encoding="utf-8") as f:
        for i, task in enumerate(asyncio.as_completed(tasks), 1):
            result = await task
            results.append(result)
            f.write(json.dumps(asdict(result), ensure_ascii=False) + "\n")
            f.flush()
            _log(f"progress {i}/{len(tasks)}: {result.cve} {result.status}")
    generated = sum(r.patch_generated for r in results)
    failed = len(results) - generated
    failure_breakdown = Counter(r.error_type for r in results if not r.patch_generated)
    failed_cves = defaultdict(list)
    for r in results:
        if not r.patch_generated:
            failed_cves[r.error_type or "unknown"].append(r.cve)

    summary_payload = {
        "total": len(results),
        "generated": generated,
        "failed": failed,
        "generation_success_rate": f"{(generated / len(results) * 100) if results else 0:.2f}%",
        "failure_breakdown": dict(sorted(failure_breakdown.items())),
        "failed_cves": dict(failed_cves),
        "mean_duration_s": round(sum(r.duration_s for r in results) / len(results), 2) if results else 0,
        "total_duration_s": round(sum(r.duration_s for r in results), 2) if results else 0,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    _write_json(run_root / "summary.json", summary_payload)
    print(f"Run directory: {run_root}")
    print(f"Generated patches: {generated}/{len(results)}")
    if failure_breakdown:
        print(f"Generation failures: {dict(failure_breakdown)}")
    return 0 if generated == len(results) else 1

