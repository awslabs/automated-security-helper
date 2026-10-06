# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Snapshots of the finding, config and inventory tools' results.

Covers explain_finding, suggest_suppression, diff_scan_results, get_config,
validate_config, list_scanners and check_installation. The finding tools read
the shared fixture results (tests/snapshot/mcp/mcp_snapshot_support.py), so the
finding ids they are asked about are the ids ASH derives from those findings --
looked up, never hard-coded, so a change to how ids are derived shows up as a
snapshot diff rather than as a lookup that silently stops matching.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Any, Dict

import pytest

from automated_security_helper.cli import mcp_server
from tests.snapshot.mcp.mcp_snapshot_support import (
    FINDINGS,
    aggregated_results,
    make_ctx,
    record,
    write_results,
)


async def _call(tool: str, *args, **kwargs) -> Dict[str, Any]:
    """Call a tool; a Context, if the tool takes one, is passed positionally.

    A tool whose first parameter is ``ctx`` gets a stdio-shaped one (no session
    header) when the test passes none, so its messages are recorded too.
    """
    fn = getattr(mcp_server, tool)
    params = list(inspect.signature(fn).parameters)
    if not args and params and params[0] == "ctx":
        args = (make_ctx(),)
    result = fn(*args, **kwargs)
    if inspect.isawaitable(result):
        result = await result
    ctx = args[0] if args else None
    return record(tool, result, ctx)


def _finding_ids(output_dir: Path) -> Dict[str, str]:
    """Rule id -> the finding id ASH derives for the fixture finding."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    model = AshAggregatedResults.from_json(
        (output_dir / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    return {v.rule_id: v.id for v in model.to_flat_vulnerabilities()}


@pytest.mark.asyncio
async def test_explain_finding(project, tmp_path, snapshot):
    output_dir = project / ".ash" / "ash_output"
    ids = _finding_ids(output_dir)

    found = {
        rule: await _call(
            "explain_finding", finding_id=finding_id, results_path=str(output_dir)
        )
        for rule, finding_id in sorted(ids.items())
    }
    not_found = await _call(
        "explain_finding",
        finding_id="bandit-B999-00000000",
        results_path=str(output_dir),
    )
    no_results = await _call(
        "explain_finding",
        finding_id=ids["B602"],
        results_path=str(project.parent / "never-scanned"),
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    refused = await _call(
        "explain_finding", finding_id=ids["B602"], results_path=str(outside)
    )

    assert found == snapshot(name="found_by_rule")
    assert not_found == snapshot(name="unknown_finding_id")
    assert no_results == snapshot(name="no_results_file")
    assert refused == snapshot(name="results_path_outside_roots")


@pytest.mark.asyncio
async def test_suggest_suppression(project, snapshot):
    results_file = project / ".ash" / "ash_output" / "ash_aggregated_results.json"
    ids = _finding_ids(results_file.parent)

    pinned = await _call(
        "suggest_suppression",
        finding_id=ids["B602"],
        results_path=str(results_file),
        expiration="2031-01-31",
        justification="Input is a constant; no user data reaches the shell.",
    )
    unknown = await _call(
        "suggest_suppression",
        finding_id="bandit-B999-00000000",
        results_path=str(results_file),
    )
    missing = await _call(
        "suggest_suppression",
        finding_id=ids["B602"],
        results_path=str(project / "nope.json"),
    )
    corrupt = project / "corrupt.json"
    corrupt.write_text("{not json", encoding="utf-8")
    unparseable = await _call(
        "suggest_suppression", finding_id=ids["B602"], results_path=str(corrupt)
    )

    assert pinned == snapshot(name="with_expiration_and_justification")
    assert unknown == snapshot(name="unknown_finding_id")
    assert missing == snapshot(name="results_file_missing")
    assert unparseable == snapshot(name="results_file_unparseable")


@pytest.mark.asyncio
async def test_suggest_suppression_defaults(project, snapshot):
    """The default expiration is 90 days out, so it is checked, not snapshotted.

    A date 90 days from today is neither fixed nor today, so the normalizer
    leaves it alone and a snapshot would go stale daily. The default
    justification text is user-visible and is snapshotted.
    """
    from datetime import date, timedelta

    results_file = project / ".ash" / "ash_output" / "ash_aggregated_results.json"
    ids = _finding_ids(results_file.parent)

    defaulted = await _call(
        "suggest_suppression", finding_id=ids["B602"], results_path=str(results_file)
    )
    expected = (date.today() + timedelta(days=90)).strftime("%Y-%m-%d")
    assert defaulted["result"]["json"]["expiration"] == expected
    assert f"expiration: '{expected}'" in defaulted["result"]["yaml"]
    assert defaulted["result"]["json"]["reason"] == snapshot(
        name="default_justification"
    )


@pytest.mark.asyncio
async def test_diff_scan_results(allowed, snapshot):
    before = write_results(allowed / "before", aggregated_results())
    after_findings = [dict(f) for f in FINDINGS[:1]]
    after_findings[0]["severity"] = "CRITICAL"
    after_findings.append(
        {
            "scanner": "bandit",
            "rule": "B105",
            "level": "warning",
            "severity": "MEDIUM",
            "message": "Possible hardcoded password: 'hunter2'",  # pragma: allowlist secret
            "path": "src/settings.py",
            "line": 7,
            "suppressed": False,
        }
    )
    after = write_results(
        allowed / "after", aggregated_results(findings=after_findings)
    )
    garbage = allowed / "garbage.json"
    garbage.write_text("[]", encoding="utf-8")

    changed = await _call(
        "diff_scan_results", before_path=str(before), after_path=str(after)
    )
    same = await _call(
        "diff_scan_results", before_path=str(before), after_path=str(before)
    )
    missing_before = await _call(
        "diff_scan_results",
        before_path=str(allowed / "absent.json"),
        after_path=str(after),
    )
    missing_after = await _call(
        "diff_scan_results",
        before_path=str(before),
        after_path=str(allowed / "absent.json"),
    )
    unparseable = await _call(
        "diff_scan_results", before_path=str(garbage), after_path=str(after)
    )

    assert changed == snapshot(name="new_resolved_and_severity_changed")
    assert same == snapshot(name="identical")
    assert missing_before == snapshot(name="before_path_missing")
    assert missing_after == snapshot(name="after_path_missing")
    assert unparseable == snapshot(name="unparseable")


@pytest.mark.asyncio
async def test_get_config(isolated_mcp_state, snapshot):
    cwd = Path.cwd()
    defaults = await _call("get_config")
    config = cwd / ".ash" / ".ash.yaml"
    config.parent.mkdir()
    config.write_text(
        "project_name: snapshot-project\n"
        "fail_on_findings: false\n"
        "global_settings:\n"
        "  severity_threshold: HIGH\n",
        encoding="utf-8",
    )
    discovered_raw = await _call("get_config", raw=True)
    explicit = await _call("get_config", config_path=str(config))
    missing = await _call("get_config", config_path=str(cwd / "absent.yaml"))

    assert defaults == snapshot(name="no_config_found_returns_defaults")
    assert discovered_raw == snapshot(name="discovered_raw")
    assert explicit == snapshot(name="explicit_path_resolved")
    assert missing == snapshot(name="explicit_path_missing_returns_defaults")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "valid",
        "unknown_field",
        "wrong_type",
        "yaml_syntax_error",
        "file_valid",
        "file_not_found",
        "no_input",
    ],
)
async def test_validate_config(case, allowed, tmp_path, monkeypatch, snapshot):
    """validate_config results, including the parse error a client is shown.

    Content is validated by writing it to a NamedTemporaryFile, and a YAML parse
    error quotes that file's path, random name included. The temp directory and
    the name generator are pinned so the quoted path is stable; the path itself
    is left in the snapshot, because it is what a client receives.
    """
    import tempfile

    server_tmp = tmp_path / "server-tmp"
    server_tmp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(server_tmp))
    monkeypatch.setattr(
        tempfile, "_get_candidate_names", lambda: iter(["validate_config"])
    )
    contents = {
        "valid": "project_name: demo\nfail_on_findings: true\n",
        "unknown_field": "project_name: demo\nnot_a_setting: 1\n",
        "wrong_type": "project_name: demo\nfail_on_findings: [1, 2]\n",
        "yaml_syntax_error": "project_name: [unclosed\n",
    }
    if case in contents:
        kwargs = {"config_content": contents[case]}
    elif case == "file_valid":
        path = allowed / ".ash.yaml"
        path.write_text(contents["valid"], encoding="utf-8")
        kwargs = {"config_path": str(path)}
    elif case == "file_not_found":
        kwargs = {"config_path": str(allowed / "absent.yaml")}
    else:
        kwargs = {}

    assert await _call("validate_config", **kwargs) == snapshot(name="result")


@pytest.mark.asyncio
async def test_check_installation(snapshot):
    assert await _call("check_installation", make_ctx()) == snapshot(name="result")


@pytest.mark.asyncio
async def test_list_scanners(monkeypatch, snapshot, snapshot_normalizer):
    """The scanner inventory, for a deployment where every dependency is present.

    What a scanner reports here depends on the machine: which binaries are on
    PATH and which tool versions are installed. Both are pinned, not normalized.
    Every scanner's dependency check is replaced by one that passes, and the
    binary version probe is replaced by one that finds nothing, so no external
    command runs. The versions the bundled Python scanners report come from the
    installed packages, which move with the lock file, so each one is registered
    as a literal and appears as ``<NAME_VERSION>``; a scanner that stops
    reporting a version still shows up, as ``None``.
    """
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core import scanner_inventory

    for cls in mcp_tools._loaded_scanner_classes():
        monkeypatch.setattr(cls, "validate_plugin_dependencies", lambda self: True)
    monkeypatch.setattr(scanner_inventory, "_probe_tool_version", lambda _: None)
    # cdk-nag reads its version from installed metadata at import: present when ASH's
    # `cdk` extra is in the venv (CI), "unavailable" (reported as None) without it.
    # Pinned to a present version, as for every other dependency here.
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        cdk_nag_scanner,
    )

    monkeypatch.setattr(cdk_nag_scanner, "_cdk_nag_version", "0.0.0-snapshot")

    listed = await _call("list_scanners")
    for entry in listed["result"]:
        if entry.get("version"):
            snapshot_normalizer.add_literal(
                entry["version"], f"{entry['name'].upper()}_VERSION"
            )

    # Keyed by name, because the order is not ASH's to promise: it depends on
    # which plugin packages earlier code in the same process already registered
    # (measured: this list came back with trivy_repo before or after ferret_scan
    # and snyk_code depending on which tests ran first). The count is asserted so
    # a duplicated name cannot hide behind the dict.
    by_name = {entry["name"]: entry for entry in listed["result"]}
    assert len(by_name) == len(listed["result"])
    assert {"tool": listed["tool"], "result": by_name} == snapshot(name="result")


def test_the_fixture_findings_are_what_the_snapshots_describe():
    """Guard the fixture: three findings, one suppressed, two scanners."""
    document = aggregated_results()
    results = document["sarif"]["runs"][0]["results"]
    assert len(results) == 3
    assert sum(1 for r in results if r.get("suppressions")) == 1
    assert (
        json.dumps(document["scanner_results"], sort_keys=True).count(
            '"status": "FAILED"'
        )
        == 2
    )
