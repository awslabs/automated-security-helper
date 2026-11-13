# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan's config line names the file the scan loaded, and only once it is loaded.

A second discovery in _run_local_mode,
made before the orchestrator resolves and loads the configuration, would log
"Using config file specified at: <path>" for a --config that does not exist (the
scan then going on with the default configuration and exiting 0) and for one that
does not validate (exit 3 after the line). The line is logged by the one
resolution that loads the file, after it has loaded, and a --config that does not
exist exits 3 before anything is logged about it.

The phases are stubbed out, so no scanner runs.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config import resolve_config as resolve_config_module
from automated_security_helper.core import execution_engine
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

_LINE = "Using ASH configuration from"


@pytest.fixture
def scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "home" / "bin"))
    monkeypatch.setenv("UV_OFFLINE", "1")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        execution_engine.ScanExecutionEngine,
        "execute_phases",
        lambda self, phases=None: AshAggregatedResults(),
    )
    (tmp_path / "src").mkdir()

    def _scan(*args: str):
        result = CliRunner().invoke(
            app, ["scan", "--source-dir", "src", "--output-dir", "out", *args]
        )
        log = tmp_path / "out" / "ash.log"
        logged = log.read_text(encoding="utf-8") if log.exists() else ""
        # The record is what the scan logged to ash.log: one line per record, whatever
        # width the console is. The console shows a record on a line of its own only
        # when CI is set (the live display is off then), and wraps its path onto the
        # next line there, so a console line is read as joined text, never per line.
        record = [
            line
            for line in logged.splitlines()
            if _LINE in line or "Using config file" in line
        ]
        console = " ".join(result.output.split())
        console_names = [
            phrase for phrase in (_LINE, "Using config file") if phrase in console
        ]
        return result, record, console_names

    return _scan


def test_a_discovered_config_is_named_once_it_has_loaded(tmp_path, scan):
    (tmp_path / "src" / ".ash").mkdir()
    (tmp_path / "src" / ".ash" / ".ash.yaml").write_text(
        "project_name: discovered\n", encoding="utf-8"
    )

    result, record, _ = scan()

    assert result.exit_code == 0, result.output
    assert record and all(".ash/.ash.yaml" in line for line in record), record


def test_a_named_config_is_named_once_it_has_loaded(tmp_path, scan):
    (tmp_path / "given.yaml").write_text("project_name: named\n", encoding="utf-8")

    result, record, _ = scan("--config", "given.yaml")

    assert result.exit_code == 0, result.output
    assert record and all("given.yaml" in line for line in record), record


def test_a_named_config_that_does_not_exist_exits_3_and_is_not_named(scan):
    """A --config that does not exist exits 3, and no line names it as specified."""
    result, record, console = scan("--config", "absent.yaml")

    assert result.exit_code == 3, result.output
    assert "absent.yaml" in result.output
    assert record == [] and console == [], (record, console)


def test_the_line_goes_with_the_loader(tmp_path, scan, monkeypatch):
    """Break the loader, and the line goes: it reports what loaded, not what was found."""
    (tmp_path / "src" / ".ash").mkdir()
    (tmp_path / "src" / ".ash" / ".ash.yaml").write_text(
        "project_name: discovered\n", encoding="utf-8"
    )

    def _broken(*args, **kwargs):
        raise ASHConfigValidationError("the loader is broken")

    monkeypatch.setattr(resolve_config_module, "resolve_config_source", _broken)

    result, record, console = scan()

    assert result.exit_code == 3, result.output
    assert record == [] and console == [], (record, console)


def test_the_line_names_the_file_the_loader_read(tmp_path, scan, monkeypatch):
    """Point discovery elsewhere, and the line follows it."""
    (tmp_path / "src" / ".ash").mkdir()
    (tmp_path / "src" / ".ash" / ".ash.yaml").write_text(
        "project_name: discovered\n", encoding="utf-8"
    )
    (tmp_path / "src" / ".ashrc.yaml").write_text(
        "project_name: elsewhere\n", encoding="utf-8"
    )
    real = resolve_config_module.discover_config_source

    def _prefers_ashrc(source_dir, permit=None):
        # resolve_config.py passes the caller's gate as ``permit=``
        # (discover_config_source(source_dir, permit=permit_base)).
        discovery = real(source_dir, permit=permit)
        ashrc = [s for s in [discovery.selected, *discovery.ignored] if s is not None]
        chosen = next(s for s in ashrc if s.path.name == ".ashrc.yaml")
        return type(discovery)(
            selected=chosen,
            ignored=[s for s in ashrc if s is not chosen],
        )

    monkeypatch.setattr(resolve_config_module, "discover_config_source", _prefers_ashrc)

    result, record, _ = scan()

    assert result.exit_code == 0, result.output
    assert record and all(".ashrc.yaml" in line for line in record), record
