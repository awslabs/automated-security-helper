# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Helpers for the MCP result snapshots; the fixtures are in conftest.py beside it.

What these snapshots pin, and what they leave to the wire golden
----------------------------------------------------------------
``.github/actions/validate-mcp/tool_surface.golden.json`` pins the *shape* of the
MCP surface: tool names, argument and output schemas, resource URIs, prompt
arguments. It cannot see what a tool returns. A reworded refusal, a renamed
``error_type``, a status that reads ``completed`` where it used to read
``incomplete``, a resource whose text changed -- none of that is in a schema.
The snapshots under this directory pin those payloads, so a change to what an MCP
client is told fails here until someone updates the snapshot on purpose.

Each snapshot is a :func:`record`: the tool's name, the dict it returned, and
every message it sent the client through ``Context`` (``info``, ``warning``,
``error``, progress). The log lines are included because a client renders them;
they are as user-visible as the return value.

How the tools are called
------------------------
Through the async wrappers in ``cli/mcp_server.py``, the functions ``@mcp.tool()``
registers, so the snapshot is what a client receives rather than what the
``mcp_*`` helper underneath returns. The ``Context`` is a ``MagicMock(spec=Context)``
as in tests/unit/cli/test_mcp_server_tool_wrappers.py: its log methods are async,
and a call to a method ``Context`` does not define fails.

No scanner runs. Where a tool would start a scan, the launcher
(``interactions.run_ash_scan.run_ash_scan``, which ``_run_scan_async`` calls in an
executor) is replaced by a function that writes a results file the test built, or
raises the exit a real scan would. Everything between the tool and that launcher
-- target confinement, registration, the runner's status transitions -- is real.

Isolation
---------
Every piece of process-global MCP state is reset per test: the scan registry, the
profile registry and session bindings, the delivered-source map and the session
registry. The working directory is a fresh directory under ``tmp_path``, because
several tools default to it (``get_config`` discovers a config there, the prompts
name it), and the confinement roots and the session workspace root point under
``tmp_path`` too. So every path a payload carries masks to ``<TMP>``.
"""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

from mcp.server.mcpserver import Context

#: A results document with every section a client reads: findings from two
#: scanners (one finding suppressed), scanner statuses, and summary counts.
#: Fixed values throughout, so the only thing a snapshot sees change is ASH.
FINDINGS = [
    {
        "scanner": "bandit",
        "rule": "B602",
        "level": "error",
        "severity": "HIGH",
        "message": "subprocess call with shell=True identified, security issue.",
        "path": "src/app.py",
        "line": 12,
        "suppressed": False,
    },
    {
        "scanner": "bandit",
        "rule": "B101",
        "level": "note",
        "severity": "LOW",
        "message": "Use of assert detected.",
        "path": "tests/test_app.py",
        "line": 4,
        "suppressed": True,
    },
    {
        "scanner": "detect-secrets",
        "rule": "SECRET-AWS-ACCESS-KEY",
        "level": "error",
        "severity": "CRITICAL",
        "message": "AWS Access Key detected in configuration file.",
        "path": "config/settings.ini",
        "line": 3,
        "suppressed": False,
    },
]


#: The ASH version the fixture results claim to come from.
FIXTURE_ASH_VERSION = "0.0.0+snapshot-fixture"


def _write_bytes(path: Path, text: str) -> None:
    """Write ``text`` with LF newlines on every OS.

    ``Path.write_text`` translates newlines on Windows, which would change the
    sizes get_scan_result_paths reports.
    """
    path.write_bytes(text.encode("utf-8"))


def _sarif_result(finding: Dict[str, Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ruleId": finding["rule"],
        "level": finding["level"],
        "kind": "fail",
        "message": {"text": finding["message"]},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding["path"]},
                    "region": {
                        "startLine": finding["line"],
                        "endLine": finding["line"],
                    },
                }
            }
        ],
        "properties": {
            "scanner_name": finding["scanner"],
            "issue_severity": finding["severity"],
            "tags": [finding["scanner"]],
        },
    }
    if finding["suppressed"]:
        result["suppressions"] = [
            {
                "kind": "external",
                "justification": "Asserts are expected in tests.",
            }
        ]
    return result


def aggregated_results(
    *,
    findings: Optional[List[Dict[str, Any]]] = None,
    scanner_statuses: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """An ``ash_aggregated_results.json`` document, as ASH writes one.

    Built from ``AshAggregatedResults()`` so every section the model defines is
    present with the model's own defaults, then filled in with fixed findings and
    scanner results.
    """
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    findings = FINDINGS if findings is None else findings
    document = json.loads(AshAggregatedResults().model_dump_json())
    document["metadata"]["generated_at"] = "2026-01-02T03:04:05+00:00"
    document["metadata"]["report_id"] = "ASH-20260102"
    document["metadata"]["project_name"] = "snapshot-fixture"
    # Pinned rather than left at the running ASH version: get_scan_result_paths
    # reports this file's size in bytes, and a version string of another length
    # would change it on every release.
    document["metadata"]["tool_version"] = FIXTURE_ASH_VERSION
    run = document["sarif"]["runs"][0]
    run["tool"]["driver"]["version"] = FIXTURE_ASH_VERSION
    run["results"] = [_sarif_result(f) for f in findings]
    counts = {"suppressed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    counts["info"] = 0
    for finding in findings:
        if finding["suppressed"]:
            counts["suppressed"] += 1
        else:
            counts[finding["severity"].lower()] += 1
    stats = document["metadata"]["summary_stats"]
    stats["severity_counts"] = counts
    stats["total"] = len(findings)
    stats["actionable"] = sum(1 for f in findings if not f["suppressed"])
    if scanner_statuses is None:
        scanner_statuses = {
            "bandit": {
                "status": "FAILED",
                "finding_count": 2,
                "actionable_finding_count": 1,
                "suppressed_finding_count": 1,
                "dependencies_satisfied": True,
                "excluded": False,
                "severity_counts": {"high": 1, "suppressed": 1},
            },
            "detect-secrets": {
                "status": "FAILED",
                "finding_count": 1,
                "actionable_finding_count": 1,
                "suppressed_finding_count": 0,
                "dependencies_satisfied": True,
                "excluded": False,
                "severity_counts": {"critical": 1},
            },
        }
    document["scanner_results"] = copy.deepcopy(scanner_statuses)
    stats["failed"] = sum(
        1 for s in scanner_statuses.values() if s.get("status") == "FAILED"
    )
    stats["missing"] = sum(
        1 for s in scanner_statuses.values() if s.get("status") == "MISSING"
    )
    return document


def write_results(output_dir: Path, document: Dict[str, Any]) -> Path:
    """Write ``document`` where ASH would, plus one per-scanner result file."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "ash_aggregated_results.json"
    _write_bytes(path, json.dumps(document, indent=2))
    for scanner, status in document.get("scanner_results", {}).items():
        target = output_dir / "scanners" / scanner / "source"
        target.mkdir(parents=True, exist_ok=True)
        _write_bytes(
            target / "ASH.ScanResults.json",
            json.dumps({"severity_counts": status.get("severity_counts", {})}),
        )
    return path


def write_reports(output_dir: Path) -> None:
    """The report files get_scan_result_paths looks for, with fixed contents."""
    reports = output_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    _write_bytes(reports / "ash.sarif", '{"version": "2.1.0"}')
    _write_bytes(reports / "ash.summary.md", "# ASH summary\n")
    _write_bytes(reports / "ash.flat.json", "[]")


def make_ctx(headers: Optional[Dict[str, str]] = None) -> MagicMock:
    """A Context double limited to the protocol's real surface."""
    ctx = MagicMock(spec=Context)
    ctx.headers = headers if headers is not None else {}
    return ctx


def client_messages(ctx: MagicMock) -> List[List[Any]]:
    """Every message the tool sent the client, in order, as ``[method, *args]``.

    Keyword arguments are included sorted, so ``report_progress(progress=0.0,
    total=1.0, message=...)`` records all three.
    """
    messages: List[List[Any]] = []
    for name, args, kwargs in ctx.method_calls:
        entry: List[Any] = [name, *args]
        entry.extend(f"{k}={kwargs[k]!r}" for k in sorted(kwargs))
        messages.append(entry)
    return messages


def record(tool: str, result: Any, ctx: Optional[MagicMock] = None) -> Dict[str, Any]:
    """The unit every MCP result snapshot stores.

    ``tool`` is what test_snapshot_mcp_tool_coverage.py reads back out of the
    stored snapshots to prove every registered tool has one.
    """
    entry: Dict[str, Any] = {"tool": tool, "result": result}
    if ctx is not None:
        entry["client_messages"] = client_messages(ctx)
    return entry


async def drain_background_tasks() -> None:
    """Wait for every task the tool started (the scan runner, the monitor)."""
    current = asyncio.current_task()
    pending = [t for t in asyncio.all_tasks() if t is not current]
    if pending:
        await asyncio.gather(*pending)
