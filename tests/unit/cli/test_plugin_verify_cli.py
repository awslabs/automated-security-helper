# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash plugin verify``: the promotion bar as a command.

The usage errors and one smoke test over the real corpus live here; the smoke test
checks only the SHAPE of the output, so recording a corpus or promoting a scanner cannot
break it. The behavior of the command over a plugin in a known state (exit codes,
``--live-result``, damaged transcript directories) is tested over the fixture plugin in
``tests/unit/plugin_conformance/test_the_verify_command_over_the_fixture_plugin.py``.
"""

import json
import re

import pytest
import typer
from typer.testing import CliRunner

from automated_security_helper.cli.main import _LAZY_SUBCOMMANDS
from automated_security_helper.cli.plugin import plugin_group

pytestmark = pytest.mark.unit

runner = CliRunner()


def _verify(*args: str):
    return runner.invoke(plugin_group, ["verify", *args])


def test_the_plugin_group_carries_list_and_verify_and_the_cli_mounts_the_group() -> (
    None
):
    assert set(typer.main.get_command(plugin_group).commands) == {"list", "verify"}
    assert _LAZY_SUBCOMMANDS["plugin"] == (
        "automated_security_helper.cli.plugin",
        "plugin_group",
    )


def test_the_two_plugin_apps_are_built_by_one_factory() -> None:
    from automated_security_helper.cli.plugin import plugin_app

    for app in (plugin_app, plugin_group):
        assert app.info.name == "plugin" and app.info.help == "Manage ASH plugins"
        assert app.pretty_exceptions_enable is True
        assert app.pretty_exceptions_short is True


def test_an_unknown_scanner_is_a_usage_error_naming_the_ones_with_manifests() -> None:
    result = _verify("no-such-scanner")
    assert result.exit_code == 2
    assert "'no-such-scanner' has no manifest" in result.output
    assert "hadolint" in result.output


def test_naming_nothing_and_naming_both_are_usage_errors() -> None:
    assert _verify().exit_code == 2
    both = _verify("hadolint", "--all")
    assert both.exit_code == 2 and "not both" in both.output


def test_a_missing_transcript_directory_is_a_usage_error(tmp_path) -> None:
    result = _verify("hadolint", "--transcripts-root", str(tmp_path / "absent"))
    assert result.exit_code == 2 and "no transcript directory" in result.output


def test_a_malformed_live_result_is_a_usage_error() -> None:
    result = _verify("hadolint", "--live-result", "linux/amd64=maybe")
    assert result.exit_code == 2 and "PLATFORM=pass" in result.output


def test_the_real_corpus_smoke_text_output_has_a_header_and_five_numbered_rows() -> (
    None
):
    result = _verify("hadolint")
    assert result.exit_code in (0, 1, 3), result.output
    lines = result.output.splitlines()
    assert re.fullmatch(r"hadolint \(\w+\): (pass|fail|incomplete)", lines[0]), lines[0]
    row_lines = [line for line in lines if re.match(r"  \d\. \[", line)]
    assert [line[2] for line in row_lines] == ["1", "2", "3", "4", "5"]
    assert all(
        re.match(r"  \d\. \[(green|red|not-run)\] \S", line) for line in row_lines
    )


def test_the_real_corpus_smoke_json_output_is_one_report_per_scanner_with_five_rows() -> (
    None
):
    result = _verify("hadolint", "--json")
    assert result.exit_code in (0, 1, 3)
    reports = json.loads(result.output)
    assert [r["scanner"] for r in reports] == ["hadolint"]
    assert [row["row"] for row in reports[0]["rows"]] == [1, 2, 3, 4, 5]
    assert reports[0]["verdict"] in ("pass", "fail", "incomplete")
    assert {"scanner", "tier", "verdict", "rows", "verdicts"} <= set(reports[0])


def test_all_verifies_every_manifest_scanner() -> None:
    from automated_security_helper.plugin_manifests import scanner_manifests

    result = _verify("--all", "--json")
    assert result.exit_code in (0, 1, 3), result.output
    names = [r["scanner"] for r in json.loads(result.output)]
    assert names == [m.name for m in scanner_manifests()]
