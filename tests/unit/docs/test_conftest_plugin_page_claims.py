# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""docs/plugins/alpha/conftest-plugin.md says what the Conftest plugin does, and it is true.

Each test pins a sentence of the page with ``assert_on_page`` and probes the code or the
committed capture that makes it true, the two halves ``test_page_claims.py`` uses, so the
page is doctested from the day it is written (``test_every_page_is_doctested.py``).

What is pinned: the pinned release and the platforms it installs on, the argv ASH runs,
the policy gate, the severity table, and the rule-id shape and the missing line the
suppression section relies on. Not pinned: the prose on why a ``deny`` is HIGH rather than
CRITICAL, which is a choice the severity table already holds to the code.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.unit.docs.test_page_claims import assert_on_page

pytestmark = pytest.mark.unit

CONFTEST_PLUGIN = "docs/plugins/alpha/conftest-plugin.md"
CAPTURED = (
    Path(__file__).resolve().parents[2]
    / "test_data"
    / "scanners"
    / "conftest"
    / "captured"
    / "positive.sarif"
)


def _scanner(source: Path, tmp_path: Path):
    """A scanner over ``source`` whose options came from the operator."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.plugin_modules.ash_conftest_plugins.conftest_scanner import (
        ConftestScanner,
        ConftestScannerConfig,
    )
    from automated_security_helper.utils.config_trust import record_provenance

    config = get_default_config()
    record_provenance(config, in_tree=[], trusted=AshConfig())
    output = tmp_path / "out"
    return ConftestScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=config,
        ),
        config=ConftestScannerConfig(),
    )


def test_the_page_names_the_pinned_release_and_its_platforms():
    from automated_security_helper.utils.tool_downloads import (
        TOOL_VERSIONS,
        supported_platforms,
    )

    version = TOOL_VERSIONS["conftest"]
    assert_on_page(
        CONFTEST_PLUGIN,
        f"ASH pins Conftest {version}: one release archive per platform, with a "
        "SHA256 for each archive and for the executable inside it",
    )
    assert_on_page(
        CONFTEST_PLUGIN,
        "Linux, macOS and Windows on x86_64 and arm64 are supported.",
    )
    assert supported_platforms("conftest") == sorted(
        (platform, arch)
        for platform in ("darwin", "linux", "windows")
        for arch in ("amd64", "arm64")
    )


def test_the_page_states_the_argv_the_scanner_builds(tmp_path):
    assert_on_page(
        CONFTEST_PLUGIN,
        "ASH runs `conftest test --output=sarif --no-fail --no-color "
        "--policy=<dir> --all-namespaces -- <files>`",
    )
    source = tmp_path / "src"
    (source / "policy").mkdir(parents=True)
    scanner = _scanner(source, tmp_path)
    policy = (source / "policy").as_posix()
    assert scanner._build_arguments(["deploy/app.yaml"]) == [
        "conftest",
        "test",
        "--output=sarif",
        "--no-fail",
        "--no-color",
        f"--policy={policy}",
        "--all-namespaces",
        "--",
        "deploy/app.yaml",
    ]


def test_the_policy_gate_skips_a_tree_without_rego(tmp_path):
    assert_on_page(
        CONFTEST_PLUGIN,
        "No `.rego` file in the policy directory: ASH does not start Conftest.",
    )
    source = tmp_path / "src"
    (source / "policy").mkdir(parents=True)
    (source / "deploy.yaml").write_text("kind: Pod\n", encoding="utf-8")
    scanner = _scanner(source, tmp_path)
    reason = scanner.nothing_to_scan_reason()
    assert reason is not None and "no .rego file" in reason
    # Planted control: one .rego file and the gate opens.
    (source / "policy" / "base.rego").write_text("package main\n", encoding="utf-8")
    assert scanner.nothing_to_scan_reason() is None


def test_the_severity_table_is_the_level_map():
    from automated_security_helper.plugin_modules.ash_conftest_plugins import (
        conftest_scanner as cs,
    )

    for row in (
        "| `deny` | `error` | HIGH |",
        "| `warn` | `warning` | MEDIUM |",
        "| no level | `warning` | MEDIUM |",
        "| any other level | `error` | HIGH |",
    ):
        assert_on_page(CONFTEST_PLUGIN, row)
    assert {
        level: (written.value, severity)
        for level, (written, severity) in cs.CONFTEST_LEVEL_MAP.items()
    } == {"error": ("error", "HIGH"), "warning": ("warning", "MEDIUM")}
    assert (cs._MISSING_LEVEL[0].value, cs._MISSING_LEVEL[1]) == ("warning", "MEDIUM")
    assert (cs._UNKNOWN_LEVEL[0].value, cs._UNKNOWN_LEVEL[1]) == ("error", "HIGH")


def test_the_rule_id_shape_and_the_missing_line_are_the_captured_report():
    assert_on_page(
        CONFTEST_PLUGIN,
        "The rule id is `<namespace>/deny` or `<namespace>/warn`, for example "
        "`main/deny`",
    )
    assert_on_page(
        CONFTEST_PLUGIN,
        "Conftest reports the file and no line, so a suppression names no line range.",
    )
    report = json.loads(CAPTURED.read_text(encoding="utf-8"))
    results = report["runs"][0]["results"]
    assert {"main/deny", "main/warn"} <= {r["ruleId"] for r in results}
    locations = [loc["physicalLocation"] for r in results for loc in r["locations"]]
    assert locations and all("region" not in loc for loc in locations)
