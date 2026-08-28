# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""End-to-end: source delivered over MCP is the tree ASH actually scans.

The unit tests in ``test_source_delivery.py`` cover the delivery functions
directly, and ``test_session_identity.py`` covers resolving the session. Neither
proves the thing an adopter depends on: that a client which shares no filesystem
with the server can hand over a tree and get findings from *that* tree back. The
pieces existed in the tree for a while without being reachable over the protocol
at all, so this test drives the whole path through a real server.

Shaped like the Bedrock AgentCore Runtime target on purpose:

* streamable-http transport with ``stateless_http=True``, which that target
  requires -- a stateful server answers 404 to the session id the platform
  generates.
* the session id arrives ONLY as an ``Mcp-Session-Id`` request header, which is
  how the platform supplies it. Nothing passes a session id as a tool argument.
* ``ASH_MCP_ALLOWED_ROOTS`` names a directory that does NOT contain the session
  workspace. The delivered tree is therefore scannable only through the
  per-session allowance in ``validate_scan_target``; if ``run_ash_scan`` stopped
  passing the session id, this test would fail with a refusal rather than pass
  quietly.

The assertions name findings -- rule id, file, and line -- rather than counting
them. A count assertion would still pass if the scanner ran against the server's
own working directory instead of the delivered tree, which is the failure this
test exists to catch. ``completed_scanners``/``total_scanners`` are asserted
alongside, because a scan where nothing ran reports zero findings the same way a
clean scan does.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import threading
import time
import zipfile
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, Iterator

import pytest

# Each entry plants exactly one bandit rule with a stable id. The bodies are
# scanner fixtures written to a temp directory and read only by bandit -- nothing
# here is imported or executed.
PLANTED_SOURCES: Dict[str, str] = {
    "app/shell_injection.py": (
        "import subprocess\n"
        "\n"
        "def run(cmd):\n"
        "    # bandit B602: subprocess call with shell=True\n"
        "    return subprocess.call(cmd, shell=True)\n"
    ),
    "app/weak_hash.py": (
        "import hashlib\n"
        "\n"
        "def digest(data: bytes) -> str:\n"
        "    # bandit B324: insecure hash function\n"
        "    return hashlib.md5(data).hexdigest()\n"
    ),
    "app/dynamic_exec.py": (
        "def evaluate(expr: str):\n    # bandit B307: use of eval\n    return eval(expr)\n"
    ),
}

# rule id -> (file the finding must be reported in, line it must be on).
EXPECTED_FINDINGS = {
    "B602": ("app/shell_injection.py", 5),
    "B324": ("app/weak_hash.py", 5),
    "B307": ("app/dynamic_exec.py", 3),
}

SESSION_ID = "e2e-delivered-source-session"
UPLOAD_ID = "e2e-delivered-source-upload"
CHUNK_BYTES = 1024 * 1024


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(host: str, port: int, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with closing(socket.create_connection((host, port), timeout=0.5)):
                return
        except OSError as e:
            last = e
            time.sleep(0.05)
    raise RuntimeError(f"Server never accepted on {host}:{port}: {last}")


class _ResilientFalseCtx:
    """Stand-in typer.Context with ``resilient_parsing == False``."""

    resilient_parsing = False


def _tool_payload(result: Any) -> Dict[str, Any]:
    """Extract the dict a tool returned from its MCP result.

    The SDK may deliver it as structured content or as a JSON text block
    depending on version, so both are handled rather than pinning one.
    """
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        inner = structured.get("result", structured)
        if isinstance(inner, dict):
            return inner
    for block in result.content or []:
        text = getattr(block, "text", None)
        if not text:
            continue
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    raise AssertionError(f"No JSON object in tool result: {result!r}")


@pytest.fixture(scope="module")
def delivered_source_server(tmp_path_factory) -> Iterator[Dict[str, Any]]:
    """Run the MCP server AgentCore-style, with the workspace outside the allowlist."""
    base = tmp_path_factory.mktemp("mcp-delivered-source")
    workspace_root = base / "workspace"
    allowed_root = base / "allowlisted-elsewhere"
    staging = base / "staging"
    for path in (workspace_root, allowed_root, staging):
        path.mkdir(parents=True, exist_ok=True)

    for rel, body in PLANTED_SOURCES.items():
        target = staging / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)

    zip_path = base / "planted.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel in PLANTED_SOURCES:
            zf.write(staging / rel, arcname=rel)
    zip_bytes = zip_path.read_bytes()

    # Set directly rather than via monkeypatch: this fixture is module-scoped and
    # the function-scoped monkeypatch fixture cannot be used from one. Restored
    # in the teardown below.
    previous = {
        key: os.environ.get(key)
        for key in ("ASH_MCP_WORKSPACE_ROOT", "ASH_MCP_ALLOWED_ROOTS")
    }
    os.environ["ASH_MCP_WORKSPACE_ROOT"] = str(workspace_root)
    os.environ["ASH_MCP_ALLOWED_ROOTS"] = str(allowed_root)

    host = "127.0.0.1"
    port = _free_port()
    mount_path = "/mcp"
    errors: list[BaseException] = []

    from automated_security_helper.cli.mcp import mcp_command

    def _run() -> None:
        try:
            mcp_command(
                ctx=_ResilientFalseCtx(),
                transport="streamable-http",
                host=host,
                port=port,
                mount_path=mount_path,
                stateless_http=True,
                quiet=True,
            )
        except SystemExit:
            pass
        except BaseException as exc:  # pragma: no cover - surfaced via errors
            errors.append(exc)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    _wait_for_port(host, port)

    yield {
        "url": f"http://{host}:{port}{mount_path}",
        "workspace_root": workspace_root,
        "allowed_root": allowed_root,
        "zip_bytes": zip_bytes,
        "zip_sha256": hashlib.sha256(zip_bytes).hexdigest(),
        "errors": errors,
    }

    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    assert not errors, f"Server thread raised: {errors!r}"


@pytest.mark.integration
@pytest.mark.slow
def test_uploaded_source_is_scanned_and_reports_its_own_findings(
    delivered_source_server,
) -> None:
    """Upload a tree, scan it without naming it, and get findings from it back."""
    import anyio
    import httpx
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    server = delivered_source_server
    collected: Dict[str, Any] = {}

    async def _run() -> None:
        # The platform injects this header; nothing in the tool arguments below
        # carries a session id.
        headers = {"Mcp-Session-Id": SESSION_ID}
        async with httpx.AsyncClient(headers=headers, timeout=120.0) as http_client:
            async with streamable_http_client(
                server["url"], http_client=http_client
            ) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()

                    listed = {t.name for t in (await session.list_tools()).tools}
                    collected["tools"] = listed

                    zip_bytes = server["zip_bytes"]
                    chunks = [
                        zip_bytes[i : i + CHUNK_BYTES]
                        for i in range(0, len(zip_bytes), CHUNK_BYTES)
                    ]
                    for sequence, blob in enumerate(chunks):
                        chunk_result = _tool_payload(
                            await session.call_tool(
                                "set_source_zip_chunk",
                                {
                                    "upload_id": UPLOAD_ID,
                                    "sequence": sequence,
                                    "data_b64": base64.b64encode(blob).decode(),
                                    "last": sequence == len(chunks) - 1,
                                },
                            )
                        )
                        assert chunk_result.get("success"), (
                            f"chunk {sequence} rejected: {chunk_result}"
                        )

                    collected["finalize"] = _tool_payload(
                        await session.call_tool(
                            "set_source_zip_finalize",
                            {
                                "upload_id": UPLOAD_ID,
                                "expected_sha256": server["zip_sha256"],
                            },
                        )
                    )

                    # Snapshot the extracted tree before scanning. The scan
                    # writes .ash/ash_output/ inside it, so a listing taken
                    # afterwards no longer shows what was delivered.
                    if collected["finalize"].get("success"):
                        delivered = Path(collected["finalize"]["source_dir"])
                        collected["extracted"] = sorted(
                            p.relative_to(delivered).as_posix()
                            for p in delivered.rglob("*")
                            if p.is_file()
                        )

                    # No source_dir: the delivered tree has to be the default.
                    collected["started"] = _tool_payload(
                        await session.call_tool("run_ash_scan", {})
                    )
                    scan_id = collected["started"].get("scan_id")
                    if not scan_id:
                        return

                    deadline = time.monotonic() + 600
                    progress: Dict[str, Any] = {}
                    while time.monotonic() < deadline:
                        progress = _tool_payload(
                            await session.call_tool(
                                "get_scan_progress", {"scan_id": scan_id}
                            )
                        )
                        if progress.get("is_complete") or progress.get("status") in (
                            "completed",
                            "failed",
                            "cancelled",
                        ):
                            break
                        await anyio.sleep(5)
                    collected["progress"] = progress

    anyio.run(_run)

    # --- the tools are actually exposed ------------------------------------
    for name in (
        "set_source_git",
        "set_source_zip_chunk",
        "set_source_zip_finalize",
        "clear_source",
    ):
        assert name in collected["tools"], (
            f"{name} missing from tools/list: {sorted(collected['tools'])}"
        )

    # --- the tree landed in this session's workspace ------------------------
    finalize = collected["finalize"]
    assert finalize.get("success"), f"finalize failed: {finalize}"
    source_dir = Path(finalize["source_dir"])
    assert SESSION_ID in source_dir.parts, (
        f"delivered tree is not scoped to the session header: {source_dir}"
    )
    assert source_dir.is_relative_to(server["workspace_root"]), (
        f"{source_dir} is outside the configured workspace root"
    )
    assert collected["extracted"] == sorted(PLANTED_SOURCES), (
        f"extracted tree does not match what was uploaded: {collected['extracted']}"
    )

    # --- run_ash_scan defaulted to it, and was not refused ------------------
    started = collected["started"]
    assert started.get("success"), f"scan did not start: {started}"
    assert started.get("error_type") != "scan_target_not_permitted", (
        "the delivered tree was refused by the root policy, which means the "
        f"session allowance did not apply: {started}"
    )
    assert Path(started["directory_path"]) == source_dir, (
        "run_ash_scan with no source_dir did not target the delivered tree: "
        f"{started['directory_path']}"
    )

    # Every tool that resolves a session echoes the id it resolved. This is what
    # lets an operator check, against a real AgentCore runtime, whether the
    # inbound header is stable across calls -- so it has to be the header value
    # and it has to agree across the upload and the scan.
    assert finalize["session_id"] == SESSION_ID, finalize
    assert started["session_id"] == SESSION_ID, started

    # --- the scan really ran ------------------------------------------------
    progress = collected["progress"]
    assert progress.get("status") == "completed", f"scan did not complete: {progress}"
    total_scanners = progress.get("total_scanners")
    completed_scanners = progress.get("completed_scanners")
    assert total_scanners, (
        f"no scanners were registered, so zero findings would prove nothing: {progress}"
    )
    assert completed_scanners == total_scanners, (
        f"only {completed_scanners}/{total_scanners} scanners completed: {progress}"
    )

    # --- the findings are from the delivered files --------------------------
    results_file = source_dir / ".ash" / "ash_output" / "ash_aggregated_results.json"
    assert results_file.is_file(), (
        f"no aggregated results written inside the delivered tree: {results_file}"
    )
    aggregated = json.loads(results_file.read_text())

    found: Dict[str, set] = {}
    for run in aggregated.get("sarif", {}).get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            for location in result.get("locations", []):
                physical = location.get("physicalLocation", {})
                uri = physical.get("artifactLocation", {}).get("uri", "")
                line = physical.get("region", {}).get("startLine")
                found.setdefault(rule_id, set()).add((uri, line))

    for rule_id, (want_file, want_line) in EXPECTED_FINDINGS.items():
        assert rule_id in found, (
            f"planted rule {rule_id} not reported. Rules seen: {sorted(found)}"
        )
        assert (want_file, want_line) in found[rule_id], (
            f"{rule_id} was reported, but not at {want_file}:{want_line}. "
            f"Locations: {sorted(found[rule_id])}"
        )
