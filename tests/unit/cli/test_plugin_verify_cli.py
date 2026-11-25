# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash plugin verify``: the promotion bar as a command (design 4.5, unit A6)."""

import json

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


def test_a_scanner_with_nothing_red_but_rows_not_run_exits_three() -> None:
    result = _verify("hadolint")
    assert result.exit_code == 3, result.output
    assert "hadolint (alpha): incomplete" in result.output
    assert "[green] facets green over committed transcripts" in result.output
    assert "[not-run] live-tool cell" in result.output
    assert "[not-run] docs generated from the manifest" in result.output


def test_a_scanner_with_a_red_row_exits_one_and_names_why() -> None:
    # cdk-nag's facets row went green once the cdk-nag prep made its recorded
    # CSV reports readable; its red row is now the unconfirmed operational cell.
    result = _verify("cdk-nag")
    assert result.exit_code == 1, result.output
    assert "cdk-nag (supported): fail" in result.output
    assert "[green] facets green over committed transcripts" in result.output
    assert "[red] operational declarations complete" in result.output
    assert "unconfirmed cell" in result.output


def test_one_red_scanner_among_several_makes_the_whole_run_exit_one() -> None:
    assert _verify("hadolint", "cdk-nag").exit_code == 1


def test_json_output_is_one_report_per_scanner_with_five_rows() -> None:
    result = _verify("hadolint", "--json")
    assert result.exit_code == 3
    reports = json.loads(result.output)
    assert [r["scanner"] for r in reports] == ["hadolint"]
    assert [row["row"] for row in reports[0]["rows"]] == [1, 2, 3, 4, 5]
    assert reports[0]["verdict"] == "incomplete"


def test_a_supplied_live_result_reaches_row_three() -> None:
    red = _verify("hadolint", "--json", "--live-result", "linux/amd64=fail")
    row3 = json.loads(red.output)[0]["rows"][2]
    assert row3["status"] == "red"
    assert any("linux/amd64" in d for d in row3["details"])
    assert red.exit_code == 1


def test_all_verifies_every_manifest_scanner() -> None:
    from automated_security_helper.plugin_manifests import scanner_manifests

    result = _verify("--all", "--json")
    names = [r["scanner"] for r in json.loads(result.output)]
    assert names == [m.name for m in scanner_manifests()]
    assert result.exit_code == 1  # at least cdk-nag's facets are red
