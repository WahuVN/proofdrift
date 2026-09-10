#!/usr/bin/env python3
"""Verify the Docker L2 backend on a real Docker daemon."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path


def run_checked(args: list[str], *, cwd: Path, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        args,
        cwd=cwd,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"command failed ({completed.returncode}): {args!r}\nstdout={completed.stdout!r}\nstderr={completed.stderr!r}"
        )
    return completed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proofdrift", type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()

    binary = args.proofdrift.resolve()
    if not binary.exists():
        raise SystemExit(f"ProofDrift binary not found: {binary}")
    if "@sha256:" not in args.image:
        raise SystemExit("--image must be an immutable digest reference")

    shell_check = r'''
set -eu
test "$(id -u)" = "65534"
grep -Eq '^CapEff:[[:space:]]+0+$' /proc/self/status
grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status
test ! -e /sys/class/net/eth0
if touch /proofdrift-root-write-test 2>/dev/null; then exit 41; fi
if touch /workspace/proofdrift-workspace-write-test 2>/dev/null; then exit 42; fi
touch /tmp/proofdrift-tmp-write-ok
printf 'L2_OK'
'''.strip()

    with tempfile.TemporaryDirectory(prefix="proofdrift-l2-e2e-") as temp:
        workspace = Path(temp)
        completed = run_checked(
            [
                str(binary),
                "--json",
                "run",
                "--isolate",
                "docker",
                "--docker-image",
                args.image,
                "--",
                "sh",
                "-c",
                shell_check,
            ],
            cwd=workspace,
        )
        envelope = json.loads(completed.stdout)
        data = envelope["data"]
        if data["status_code"] != 0:
            raise AssertionError(f"isolated payload failed: {data!r}")
        if data["enforcement_level"] != "L2":
            raise AssertionError(f"CLI did not report L2: {data!r}")
        if "docker-container" not in data["enforcement_scope"]:
            raise AssertionError(f"CLI omitted Docker enforcement scope: {data!r}")
        if "L2_OK" not in data["stdout"]:
            raise AssertionError(f"container security assertions did not complete: {data!r}")
        if data["events_recorded"] != 2:
            raise AssertionError(f"expected dispatch+completion evidence, got {data!r}")

        report = run_checked(
            [str(binary), "--json", "report", data["session_id"]],
            cwd=workspace,
        )
        report_data = json.loads(report.stdout)["data"]
        if not report_data["valid"] or len(report_data["events"]) != 2:
            raise AssertionError(f"invalid L2 evidence chain: {report_data!r}")
        for stored in report_data["events"]:
            event = stored["event"]
            if event["enforcement_level"] != "L2":
                raise AssertionError(f"evidence downgraded/mislabeled: {event!r}")
            if event["adapter_id"] != "proofdrift-runtime-docker-isolation":
                raise AssertionError(f"wrong L2 adapter id: {event!r}")
            scope = event.get("extensions", {}).get("enforcement_scope", "")
            if "digest-pinned image" not in scope or "network none" not in scope:
                raise AssertionError(f"L2 scope missing from evidence: {event!r}")
            context = event.get("normalized_args", {})
            if context.get("runner_enforcement_level") != "L2_ISOLATED":
                raise AssertionError(f"policy/evidence request was not bound to L2: {event!r}")

    print("DOCKER_L2_E2E_PASS")


if __name__ == "__main__":
    main()
