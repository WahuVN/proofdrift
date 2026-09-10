#!/usr/bin/env python3
"""End-to-end checks for ProofDrift's MCP 2026-07-28 proxy transports."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

PROTOCOL = "2026-07-28"


def meta() -> dict[str, Any]:
    return {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL,
            "io.modelcontextprotocol/clientInfo": {"name": "proofdrift-e2e", "version": "1"},
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    }


def request(request_id: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def run_proxy(
    binary: Path,
    config: Path,
    requests: list[dict[str, Any]],
    *,
    timeout: int = 25,
) -> list[dict[str, Any]]:
    payload = "".join(json.dumps(item, separators=(",", ":")) + "\n" for item in requests)
    completed = subprocess.run(
        [str(binary), "mcp", "proxy", "--config", str(config)],
        input=payload,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"proxy failed with {completed.returncode}: stderr={completed.stderr!r} stdout={completed.stdout!r}"
        )
    return [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]


def write_config(
    path: Path,
    *,
    server_id: str,
    evidence_root: Path,
    transport: dict[str, Any],
) -> None:
    path.write_text(
        json.dumps(
            {
                "server_id": server_id,
                "policy": "constrained-mcp",
                "evidence_root": str(evidence_root),
                "transport": transport,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def assert_mcp_evidence(binary: Path, evidence_root: Path) -> None:
    listing = subprocess.run(
        [str(binary), "--json", "report"],
        cwd=evidence_root,
        text=True,
        capture_output=True,
        timeout=10,
        check=True,
    )
    sessions = json.loads(listing.stdout)["data"]["sessions"]
    if not sessions:
        raise AssertionError("MCP proxy did not persist any evidence session")
    report = subprocess.run(
        [str(binary), "--json", "report", sessions[-1]],
        cwd=evidence_root,
        text=True,
        capture_output=True,
        timeout=10,
        check=True,
    )
    data = json.loads(report.stdout)["data"]
    if not data["valid"] or not data["events"]:
        raise AssertionError(f"invalid/empty MCP evidence report: {data!r}")
    for stored in data["events"]:
        event = stored["event"]
        if event["enforcement_level"] != "L1":
            raise AssertionError(f"unexpected MCP enforcement level: {event!r}")
        scope = event.get("extensions", {}).get("enforcement_scope", "")
        if "mcp-call-dispatch-boundary" not in scope:
            raise AssertionError(f"missing MCP enforcement scope: {event!r}")


def stdio_roundtrip(binary: Path, fixture: Path, root: Path) -> None:
    state = root / "stdio-state.json"
    evidence = root / "stdio-evidence"
    evidence.mkdir()
    config = root / "stdio.json"
    write_config(
        config,
        server_id="stdio-fixture",
        evidence_root=evidence,
        transport={
            "type": "stdio",
            "program": sys.executable,
            "args": [str(fixture), "--state-file", str(state)],
        },
    )
    common = meta()
    rows = run_proxy(
        binary,
        config,
        [
            request(1, "server/discover", common),
            request(2, "tools/list", common),
            request(
                3,
                "tools/call",
                {**common, "name": "echo", "arguments": {"text": "stdio-ok"}},
            ),
        ],
    )
    assert rows[0]["result"]["supportedVersions"] == [PROTOCOL]
    assert rows[1]["result"]["tools"][0]["title"] == "Synthetic echo"
    assert rows[2]["result"]["structuredContent"]["echo"]["text"] == "stdio-ok"
    assert json.loads(state.read_text(encoding="utf-8")) == {"call_count": 1, "list_count": 2}
    assert_mcp_evidence(binary, evidence)


def rug_pull_is_blocked(binary: Path, fixture: Path, root: Path) -> None:
    state = root / "rug-state.json"
    evidence = root / "rug-evidence"
    evidence.mkdir()
    config = root / "rug.json"
    write_config(
        config,
        server_id="rug-fixture",
        evidence_root=evidence,
        transport={
            "type": "stdio",
            "program": sys.executable,
            "args": [
                str(fixture),
                "--state-file",
                str(state),
                "--rug-pull-after-first-list",
            ],
        },
    )
    common = meta()
    rows = run_proxy(
        binary,
        config,
        [
            request(1, "tools/list", common),
            request(
                2,
                "tools/call",
                {**common, "name": "echo", "arguments": {"text": "must-not-dispatch"}},
            ),
        ],
    )
    assert rows[1]["error"]["code"] == -32042
    state_value = json.loads(state.read_text(encoding="utf-8"))
    assert state_value["list_count"] == 2
    assert state_value["call_count"] == 0


def mrtr_roundtrip(binary: Path, fixture: Path, root: Path) -> None:
    state = root / "mrtr-state.json"
    evidence = root / "mrtr-evidence"
    evidence.mkdir()
    config = root / "mrtr.json"
    write_config(
        config,
        server_id="mrtr-fixture",
        evidence_root=evidence,
        transport={
            "type": "stdio",
            "program": sys.executable,
            "args": [str(fixture), "--state-file", str(state)],
        },
    )
    common = meta()
    rows = run_proxy(
        binary,
        config,
        [
            request(1, "tools/list", common),
            request(
                2,
                "tools/call",
                {
                    **common,
                    "name": "echo",
                    "arguments": {"text": "round-one"},
                    "requestState": "need-input",
                },
            ),
            request(
                3,
                "tools/call",
                {
                    **common,
                    "name": "echo",
                    "arguments": {"text": "round-two"},
                    "requestState": "need-input",
                    "inputResponses": {"answer": "ok"},
                },
            ),
        ],
    )
    assert rows[1]["result"]["resultType"] == "input_required"
    assert rows[1]["result"]["requestState"] == "need-input"
    assert rows[2]["result"]["resultType"] == "complete"
    assert json.loads(state.read_text(encoding="utf-8")) == {"call_count": 2, "list_count": 3}


def http_sse_roundtrip(binary: Path, fixture: Path, root: Path) -> None:
    state = root / "http-state.json"
    evidence = root / "http-evidence"
    evidence.mkdir()
    config = root / "http.json"
    server = subprocess.Popen(
        [
            sys.executable,
            str(fixture),
            "--transport",
            "http",
            "--port",
            "0",
            "--state-file",
            str(state),
            "--sse",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert server.stdout is not None
        ready = server.stdout.readline().strip()
        if not ready.startswith("READY "):
            stderr = server.stderr.read() if server.stderr else ""
            raise AssertionError(f"HTTP fixture failed to become ready: {ready!r} {stderr!r}")
        endpoint = f"http://{ready.removeprefix('READY ')}/mcp"
        write_config(
            config,
            server_id="http-fixture",
            evidence_root=evidence,
            transport={"type": "streamable_http", "endpoint": endpoint},
        )
        common = meta()
        rows = run_proxy(
            binary,
            config,
            [
                request(1, "tools/list", common),
                request(
                    2,
                    "tools/call",
                    {
                        **common,
                        "name": "echo",
                        "arguments": {"text": "http-ok", "region": "vn"},
                    },
                ),
            ],
        )
        assert rows[1]["result"]["structuredContent"]["echo"]["region"] == "vn"
        assert json.loads(state.read_text(encoding="utf-8")) == {"call_count": 1, "list_count": 2}
    finally:
        server.terminate()
        try:
            server.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=3)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proofdrift", type=Path, required=True)
    args = parser.parse_args()
    binary = args.proofdrift.resolve()
    if not binary.exists():
        raise SystemExit(f"ProofDrift binary not found: {binary}")
    fixture = Path(__file__).with_name("mcp2026_server.py").resolve()
    os.environ.setdefault("PYTHONUTF8", "1")
    with tempfile.TemporaryDirectory(prefix="proofdrift-mcp2026-e2e-") as temp:
        root = Path(temp)
        stdio_roundtrip(binary, fixture, root)
        rug_pull_is_blocked(binary, fixture, root)
        mrtr_roundtrip(binary, fixture, root)
        http_sse_roundtrip(binary, fixture, root)
    print("MCP_2026_E2E_PASS")


if __name__ == "__main__":
    main()
