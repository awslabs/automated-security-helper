# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``ash merge``'s configuration refusals keep their lines and never trace back.

Two refusals share the exit code 3 and the "Invalid configuration:" label but
not their shape. Every configuration refusal is one line, and a newline in it
can only be one the operator typed (a ``--config`` path, a ``--config-overrides``
entry), so it is written ``\\x0a`` (``_invalid_config_text``). The one exception
is the shards' recorded configurations disagreeing on an exit-code setting
(``ShardSettingsDisagreeError``): it is written as a header, one line per setting
and the advice, and is printed on those lines (``_invalid_config_lines``); the
one-line form wrote every break as the two characters ``\\x0a``.

``resolve_operator_config`` asks ``Path.is_file`` before it reads. Before Python
3.14 that call answers False for a missing file but re-raises every other stat
error, so a ``--config`` under a parent this user cannot search (EACCES) or with a
name over the limit (ENAMETOOLONG) escaped as a traceback where the read errors
beside it were refused with exit 3.
"""

from __future__ import annotations

import errno
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.merge import resolve_operator_config
from automated_security_helper.core.exceptions import ASHConfigSourceError
from tests.unit.cli.merge_shard_support import _build_config, build_shards, write_shards


def _merge(args):
    """``ash merge`` through the registered command, with no reporter discovered."""
    from automated_security_helper.cli.main import app

    manager = MagicMock()
    manager.plugin_modules.return_value = []
    with (
        patch("automated_security_helper.cli.merge.ash_plugin_manager", manager),
        patch("automated_security_helper.cli.merge.load_plugins"),
    ):
        return CliRunner().invoke(app, ["merge", *args], env={"COLUMNS": "300"})


def _results_args(tmp_path: Path, shards) -> list:
    args = []
    for path in write_shards(tmp_path / "artifacts", shards):
        args += ["--results", path]
    return args + ["--output-dir", str(tmp_path / "merged")]


def test_the_shard_disagreement_refusal_prints_on_its_lines(tmp_path):
    shards = build_shards(2)
    shards[0].ash_config = _build_config(fail_on_findings=True)
    shards[1].ash_config = _build_config(fail_on_findings=False)

    result = _merge(_results_args(tmp_path, shards))

    assert result.exit_code == 3, result.output
    assert "Invalid configuration:" in result.output
    assert "recorded configurations disagree on settings" in result.output
    lines = result.output.splitlines()
    assert any(line.startswith("  fail_on_findings:") for line in lines), result.output
    # The advice sentence follows the setting lines on a line of its own.
    assert any(line.startswith("One ") and "covers the" in line for line in lines), (
        result.output
    )
    assert "\\x0a" not in result.output, result.output
    assert not (tmp_path / "merged").exists()


def test_an_invalid_override_with_line_breaks_is_refused_on_one_line(tmp_path):
    """The refusal quotes the override as the operator typed it, so a line break
    in it must not start a log line of its own: the message is one line, with the
    breaks written as escapes. Only the shard-disagreement refusal, above, is
    written on several lines."""
    override = "no-separator\r\nforged: first line\nforged: second line"

    result = _merge(
        [
            "--config-overrides",
            override,
            *_results_args(tmp_path, build_shards(2)),
        ]
    )

    assert result.exit_code == 3, result.output
    lines = result.output.splitlines()
    forged = [line for line in lines if line.startswith("forged:")]
    assert not forged, result.output
    assert (
        "Invalid config override: "
        "'no-separator\\x0d\\x0aforged: first line\\x0aforged: second line'"
    ) in result.output, result.output
    assert len([line for line in lines if "Invalid configuration:" in line]) == 1
    assert "Traceback" not in result.output
    assert not (tmp_path / "merged").exists()


def test_control_an_invalid_override_without_line_breaks_prints_on_one_line(tmp_path):
    result = _merge(
        [
            "--config-overrides",
            "no-separator",
            *_results_args(tmp_path, build_shards(2)),
        ]
    )

    assert result.exit_code == 3, result.output
    assert (
        "Invalid configuration: Invalid config override: 'no-separator'. "
        "Expected format: key.path=value"
    ) in result.output, result.output
    assert not (tmp_path / "merged").exists()


def test_a_config_name_over_the_limit_is_refused_not_traced(tmp_path):
    """A name over the limit: exit 3 in one of the two refusal shapes.

    The stat answers "not a file" for a name over NAME_MAX (``Path.is_file``
    reads the ENAMETOOLONG as False), so the refusal is the existence arm's;
    the read arm ("could not be read") is reached by the EACCES test below.
    Either way the refusal names the config path and no traceback is printed.
    """
    too_long = tmp_path / ("a" * 300 + ".yaml")

    result = _merge(
        ["--config", str(too_long), *_results_args(tmp_path, build_shards(2))]
    )

    assert result.exit_code == 3, result.output
    assert "Invalid configuration:" in result.output
    assert "a" * 300 in result.output, result.output
    assert (
        "does not exist or is not a file" in result.output
        or "could not be read" in result.output
    ), result.output
    assert "Traceback" not in result.output
    assert not (tmp_path / "merged").exists()


def test_a_config_under_an_unsearchable_parent_is_refused_not_traced(
    tmp_path, monkeypatch
):
    """EACCES from the stat, as a root-less user reads it under a 0o000 parent."""
    target = tmp_path / "locked" / "ash.yaml"

    def denied(self):
        raise PermissionError(errno.EACCES, "Permission denied", str(self))

    monkeypatch.setattr(Path, "is_file", denied)

    with pytest.raises(ASHConfigSourceError) as excinfo:
        resolve_operator_config(str(target))

    text = str(excinfo.value)
    assert "could not be read" in text
    assert "Permission denied" in text
