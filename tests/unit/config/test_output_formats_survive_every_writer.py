# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config with ``output_formats`` keeps it through every command that writes it.

Why this exists
---------------
``output_formats`` is the one config field read from a file as ``ExportFormat``
members, and a Python-mode dump of those members breaks the YAML writers:
``ash config update`` and ``wizard`` would write ``!!python/object/apply`` tags no
later load can read, and ``AshConfig.save`` and the MCP session config, which use
``safe_dump``, would raise. A scan of a file that fails to load falls back to the
default configuration, so the damage would show up as reports and a severity
threshold the file did not ask for. Two things prevent it: ``AshConfig``
serializes the names, and every writer dumps in JSON mode
(``config/config_writer.user_config_data``). Either alone passes this test.

test_output_formats_from_config.py round-trips each writer from a fresh config.
This module runs one file through all of them in turn -- ``update``, ``get``
(its printed YAML saved as the next file), ``wizard``, ``save`` and the MCP session
config -- because a writer that loses or mangles the field breaks every step
after it, and only a chain shows which. ``severity_threshold: LOW`` rides along:
a load that fell back to the default would read MEDIUM.

It also checks the other side: ``ash config validate`` refuses a misspelled name
in ``output_formats``, in each spelling the field accepts, with exit 3 (an
invalid configuration), the entry it refuses and every format it accepts.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli.config import (
    _get_reporter_names,
    _get_scanner_names,
)
from automated_security_helper.cli.main import app
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.enums import ExportFormat

FORMATS = [ExportFormat.SARIF, ExportFormat.GITHUB_GHAS]
NAMES = [fmt.value for fmt in FORMATS]
INVALID_CONFIG = 3
VALID_LIST = re.compile(r"Valid formats are: ((?:[a-z0-9-]+, )*[a-z0-9-]+)")


@pytest.fixture(autouse=True)
def _in_tmp(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp"))


def _ash(*args: str, stdin: str | None = None):
    return CliRunner().invoke(
        app, list(args), input=stdin, env={"COLUMNS": "300", "NO_COLOR": "1"}
    )


def _loaded(path: Path, source_dir: Path) -> AshConfig:
    """The file as a scan loads it, with no fallback to the default config."""
    assert "!!python" not in path.read_text(encoding="utf-8"), path.read_text()
    return resolve_config(
        config_path=path, source_dir=source_dir, fallback_to_default=False
    )


def _assert_kept(config: AshConfig, project_name: str) -> None:
    assert config.output_formats == FORMATS
    assert config.global_settings.severity_threshold == "LOW"
    assert config.project_name == project_name


def _wizard_answers(project_name: str) -> str:
    """Keep every scanner and reporter enabled, no offline mode, no new modules."""
    lines = [project_name]
    lines += ["Y"] * len(_get_scanner_names())
    lines += ["Y"] * len(_get_reporter_names())
    lines += ["n", ""]
    return "\n".join(lines) + "\n"


def _printed_yaml(stdout: str) -> str:
    """``ash config get``'s YAML, without rich's colors and line padding."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", stdout)
    return "\n".join(line.rstrip() for line in text.splitlines()) + "\n"


def test_one_file_keeps_output_formats_through_every_writer(tmp_path):
    from automated_security_helper.cli.mcp.profile_registry import (
        materialize_session_config,
    )

    first = tmp_path / ".ash" / ".ash.yaml"
    first.parent.mkdir()
    first.write_text(
        "project_name: p\n"
        f"output_formats: [{', '.join(NAMES)}]\n"
        "global_settings:\n  severity_threshold: LOW\n",
        encoding="utf-8",
    )

    updated = _ash("config", "update", str(first), "--set", "project_name=updated")
    assert updated.exit_code == 0, updated.output
    _assert_kept(_loaded(first, tmp_path), "updated")

    got = _ash("config", "get", "--config", str(first), "--no-color")
    assert got.exit_code == 0, got.output
    from_get = tmp_path / "from-get.yaml"
    from_get.write_text(_printed_yaml(got.stdout), encoding="utf-8")
    assert yaml.safe_load(from_get.read_text(encoding="utf-8"))["output_formats"] == (
        NAMES
    )
    _assert_kept(_loaded(from_get, tmp_path), "updated")

    wizard = _ash(
        "config",
        "wizard",
        "--config",
        str(from_get),
        stdin=_wizard_answers("wizarded"),
    )
    assert wizard.exit_code == 0, wizard.output
    _assert_kept(_loaded(from_get, tmp_path), "wizarded")

    saved = tmp_path / "saved.yaml"
    _loaded(from_get, tmp_path).save(saved, as_written=False)
    _assert_kept(_loaded(saved, tmp_path), "wizarded")

    session = Path(materialize_session_config("session-a", _loaded(saved, tmp_path)))
    _assert_kept(_loaded(session, session.parent), "wizarded")


@pytest.mark.parametrize(
    "spelling, entry",
    [
        ("output_formats:\n  - sarif\n  - sarfi\n", "output_formats[1]"),
        ("output_formats: sarfi\n", "output_formats[0]"),
        ("output_formats: sarif, sarfi\n", "output_formats[1]"),
    ],
    ids=["list", "one-name", "comma-list"],
)
def test_config_validate_refuses_a_misspelled_format_with_exit_3(
    tmp_path, spelling, entry
):
    """The misspelled name itself prints as ``<value>``, as every value the file
    holds does (``config_validator.REDACTED``). The list of valid formats is
    ASH's own: a valid name the file also lists, ``sarif`` here, has to stay in
    it, or the reader is told sarif is not a format."""
    path = tmp_path / "ash.yaml"
    path.write_text("project_name: p\n" + spelling, encoding="utf-8")

    result = _ash("config", "validate", "--config", str(path), "--no-color")

    assert result.exit_code == INVALID_CONFIG, result.output
    printed = " ".join(result.output.split())
    assert f"Invalid value at '{entry}'" in printed, result.output
    listed = VALID_LIST.search(printed)
    assert listed, result.output
    assert set(listed.group(1).split(", ")) == {fmt.value for fmt in ExportFormat}


def test_control_config_validate_accepts_the_correct_spelling(tmp_path):
    path = tmp_path / "ash.yaml"
    path.write_text("project_name: p\noutput_formats: sarif, csv\n", encoding="utf-8")

    result = _ash("config", "validate", "--config", str(path), "--no-color")

    assert result.exit_code == 0, result.output
