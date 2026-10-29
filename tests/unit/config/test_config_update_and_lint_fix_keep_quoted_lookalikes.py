"""A quoted ``${VAR}``-shaped literal survives the config rewriters.

A file can hold a value that only looks like an environment reference,
kept literal by its quotes: ``project_name: '${ASH_X} ...'``. The save
path's dumper quotes such a string back (config_writer._represent_text),
so a saved file reloads to the same text. ``ash config update`` and
``ash config lint --fix`` write through IndentableYamlDumper, which must
quote the same shapes; a plain dump would turn the literal into a live
reference the next load resolves.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.config_sources import load_config_document

pytestmark = pytest.mark.unit

VAR = "ASH_C2H_LOOKALIKE_VAR"
CANARY = "lookalike-canary-value"
LOOKALIKE = "${ASH_C2H_LOOKALIKE_VAR} kept literal"


def _update(path: Path):
    return CliRunner().invoke(
        app,
        [
            "config",
            "update",
            "--config",
            str(path),
            "--set",
            "global_settings.severity_threshold=LOW",
        ],
    )


def test_class_config_update_keeps_a_quoted_lookalike_literal(tmp_path, monkeypatch):
    monkeypatch.setenv(VAR, CANARY)
    path = tmp_path / ".ash.yaml"
    path.write_text(f"project_name: '{LOOKALIKE}'\n", encoding="utf-8")
    result = _update(path)
    # The control: the update ran and wrote the file.
    assert result.exit_code == 0, result.output[-2000:]
    assert load_config_document(path)["global_settings"]["severity_threshold"] == "LOW"
    assert load_config_document(path)["project_name"] == LOOKALIKE, path.read_text(
        encoding="utf-8"
    )


def test_class_control_config_update_refuses_a_real_reference(tmp_path, monkeypatch):
    monkeypatch.setenv(VAR, CANARY)
    path = tmp_path / ".ash.yaml"
    before = f"project_name: {LOOKALIKE}\n".encode("utf-8")
    path.write_bytes(before)
    result = _update(path)
    assert result.exit_code == 1, result.output[-2000:]
    assert path.read_bytes() == before


def test_class_config_lint_fix_keeps_a_quoted_lookalike_literal(tmp_path, monkeypatch):
    monkeypatch.setenv(VAR, CANARY)
    path = tmp_path / ".ash.yaml"
    before = (
        f"project_name: '{LOOKALIKE}'\n"
        "global_settings:\n"
        "  suppressions:\n"
        "  - rule_id: R1\n"
        "    path: a.py\n"
        "    line_start: 3\n"
        "    reason: kept\n"
    )
    path.write_text(before, encoding="utf-8")
    result = CliRunner().invoke(
        app, ["config", "lint", "--config", str(path), "--fix", "--non-interactive"]
    )
    after = path.read_text(encoding="utf-8")
    # The control: --fix rewrote the file (it set the missing line_end).
    assert after != before, (result.exit_code, result.output[-2000:])
    assert load_config_document(path)["project_name"] == LOOKALIKE, after
