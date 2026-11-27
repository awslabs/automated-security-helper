# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A root option typed before a group reaches the command the group's words name.

``ashx --config c.yaml results report`` hands ``--config`` to ``report``, as the
spelling 4.0 removed (``ashx --config c.yaml report``) handed it to the command. The
words can go more than one group down: ``results inspect findings`` is ``findings``
under ``inspect`` under ``results``, and the option reaches ``findings``. A group
takes none of these options itself, so stopping at ``inspect`` refused them as
options ``results inspect`` does not take.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.core.enums import AshExitCode

pytestmark = pytest.mark.unit


def _run(argv: list[str]):
    return CliRunner().invoke(app, argv, prog_name="ashx")


def _one_line(output: str) -> str:
    return " ".join(output.split())


@pytest.fixture
def findings_module():
    from automated_security_helper.cli.inspect import inspect_findings_app

    return inspect_findings_app


@pytest.fixture
def results_dir(tmp_path: Path) -> Path:
    """An output directory holding a results file at the place findings reads first
    when it is given --output-dir directly."""
    out = tmp_path / "out"
    out.mkdir()
    (out / "ash_aggregated_results.json").write_text("{}", encoding="utf-8")
    return out


def test_a_root_option_reaches_a_command_three_levels_down(
    monkeypatch, findings_module, results_dir
):
    """`ashx --output-dir OUT results inspect findings` reads OUT's results: the root's
    --output-dir reaches findings, two groups below the root's own word."""
    loaded: list[Path] = []
    # load_model returning None ends the command with its own "no model" message.
    monkeypatch.setattr(
        findings_module,
        "AshAggregatedResults",
        SimpleNamespace(load_model=lambda path: loaded.append(Path(path))),
    )

    result = _run(["--output-dir", str(results_dir), "results", "inspect", "findings"])

    text = _one_line(result.output)
    assert "does not take" not in text, text
    assert loaded == [results_dir / "ash_aggregated_results.json"], text
    assert result.exit_code == AshExitCode.SCAN_ERRORS, text


def test_a_root_config_reaches_a_command_three_levels_down(
    monkeypatch, findings_module, results_dir, tmp_path
):
    """`ashx --config C results inspect findings` saves suppressions to C: the explorer
    is opened with the config file the root's --config named."""
    config = tmp_path / "suppressions.yaml"
    opened: list[Path] = []

    class _Explorer:
        def __init__(self, findings, *, config_path, **_):
            opened.append(config_path)

        def run(self):
            return None

    model = SimpleNamespace(baseline_filtered=False)
    monkeypatch.setattr(
        findings_module,
        "AshAggregatedResults",
        SimpleNamespace(load_model=lambda path: model),
    )
    monkeypatch.setattr(findings_module, "extract_findings", lambda loaded: [object()])
    monkeypatch.setattr(findings_module, "scanned_directory", lambda path: tmp_path)
    monkeypatch.setattr(findings_module, "source_snippet_masker", lambda loaded: None)
    monkeypatch.setattr(findings_module, "FindingsExplorerApp", _Explorer)

    result = _run(
        [
            "--config",
            str(config),
            "results",
            "inspect",
            "findings",
            "--output-dir",
            str(results_dir),
        ]
    )

    text = _one_line(result.output)
    assert "does not take" not in text, text
    assert result.exit_code == 0, text
    assert opened == [config], text


def test_a_root_config_reaches_results_report(tmp_path):
    """`ashx --config C results report` reads C as report's own --config: a C that is
    not there is report's refusal of that file, not a refusal of the option."""
    out = tmp_path / "out"
    out.mkdir()
    missing = tmp_path / "missing.yaml"

    result = _run(
        ["--config", str(missing), "results", "report", "--output-dir", str(out)]
    )

    text = _one_line(result.output)
    assert "does not take" not in text, text
    assert result.exit_code == AshExitCode.INVALID_CONFIG, text
    assert "Configuration file not found" in text, text
    assert "missing.yaml" in text, text


def test_a_root_option_a_nested_command_does_not_take_names_all_its_words():
    """A root option the command does not take is refused naming the command the
    operator would type, all its words, never a group on the way to it."""
    result = _run(["--scanners", "bandit", "results", "inspect", "findings"])

    text = _one_line(result.output)
    assert result.exit_code == ASH_EXIT_USAGE_ERROR, text
    assert "'ashx results inspect findings' does not take --scanners" in text, text
    assert "(see 'ashx results inspect findings --help')" in text, text
    assert "'ashx results inspect' does not take" not in text, text
