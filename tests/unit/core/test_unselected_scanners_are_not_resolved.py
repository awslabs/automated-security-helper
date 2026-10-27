# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner the run did not select is not resolved: no ``uv tool run`` for it.

The scan phase constructs every registered scanner, because a scanner's selectable
name is only known on an instance. bandit, checkov and semgrep probe their version
while they are constructed, with ``uv tool run --from <spec> <tool> --version``,
and uv resolves that spec against the package index whenever the environment is
not already cached. So ``ash scan --scanners detect-secrets`` online reached the
index for three scanners it was never going to run (one run was measured at 23
connections), and so did a scanner the operator excluded.

Construction in the scan phase now defers those probes, and the scan phase
resolves one only for a scanner that was selected, before its dependency check,
so a selected scanner's version is still in its report.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

import pytest

from automated_security_helper.core.enums import ExecutionStrategy


@pytest.fixture
def probes(monkeypatch, tmp_path):
    """Every uv version probe, as (tool, spec); each answers 9.9.9 without spawning."""
    from automated_security_helper.utils import uv_tool_runner

    calls: List[Tuple[str, Optional[str]]] = []

    def fake_get_tool_version(self, tool_name, package_name=None, *args, **kwargs):
        calls.append((tool_name, package_name))
        return "9.9.9"

    monkeypatch.setattr(
        uv_tool_runner.UVToolRunner, "get_tool_version", fake_get_tool_version
    )
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    return calls


def _scan(tmp_path, **kwargs):
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    source = tmp_path / "repo"
    source.mkdir(exist_ok=True)
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    try:
        return run_ash_scan(
            source_dir=str(source),
            output_dir=str(tmp_path / "out"),
            strategy=ExecutionStrategy.SEQUENTIAL,
            progress=False,
            fail_on_findings=False,
            fail_on_incomplete_scanners=False,
            show_summary=False,
            quiet=True,
            color=False,
            **kwargs,
        )
    except SystemExit:
        return None


#: Converters run in the convert phase whatever --scanners selects, so their
#: probes are not a scanner selection's to suppress. Named rather than filtered by
#: pattern, so a scanner probe can never hide among them.
CONVERTER_TOOLS = {"jupyter-nbconvert"}


def _probed(calls) -> List[str]:
    return sorted({tool for tool, _ in calls if tool not in CONVERTER_TOOLS})


def test_a_scan_of_one_scanner_probes_no_other(probes, tmp_path):
    _scan(tmp_path, scanners=["detect-secrets"])

    assert _probed(probes) == [], f"unselected scanners were resolved: {probes}"


def test_an_excluded_scanner_is_not_probed(probes, tmp_path, monkeypatch):
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        bandit_scanner,
    )

    # bandit stays selected but is reported MISSING, so nothing executes it.
    monkeypatch.setattr(
        bandit_scanner.BanditScanner, "validate_plugin_dependencies", lambda self: False
    )
    _scan(
        tmp_path,
        scanners=["bandit", "checkov"],
        exclude_scanners=["checkov"],
    )

    assert "checkov" not in _probed(probes), probes


def test_control_a_selected_scanner_is_still_probed_and_reports_its_version(
    probes, tmp_path, monkeypatch
):
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        bandit_scanner,
    )

    seen = {}

    def no_tool(self):
        seen["version"] = self.tool_version
        return False

    monkeypatch.setattr(
        bandit_scanner.BanditScanner, "validate_plugin_dependencies", no_tool
    )
    _scan(tmp_path, scanners=["bandit"])

    assert _probed(probes) == ["bandit"], probes
    assert seen == {"version": "9.9.9"}


def test_a_scanner_constructed_outside_a_scan_defers_its_probe(
    probes, test_plugin_context
):
    """`ash dependencies`, the MCP server and tests build scanners directly;
    construction names the tool (defer_tool_version_probe) and runs nothing,
    and the first resolve runs the probe once."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
    )

    scanner = BanditScanner(context=test_plugin_context)

    assert scanner.tool_version is None
    assert _probed(probes) == []

    scanner.resolve_deferred_tool_version()

    assert scanner.tool_version == "9.9.9"
    assert _probed(probes) == ["bandit"]
