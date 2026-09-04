"""CLI entry point for patch_agent_runner."""
import asyncio
import argparse
from runner.models import DEFAULT_AGENT_TIMEOUT_S
from runner.agent import _main

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", default="../datasets/patcheval_verified.json")
    p.add_argument("--output-dir", default="outputs")
    p.add_argument("--limit", type=int, default=1)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--run-label", default="")
    p.add_argument("--agent-command", required=True)
    p.add_argument("--mount", action="append", default=[])
    p.add_argument("--agent-timeout", type=int, default=DEFAULT_AGENT_TIMEOUT_S)
    p.add_argument("--container-prefix", default="patcheval-agent")
    return p


def main() -> int:
    return asyncio.run(_main(build_parser().parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
