# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A failed import's log line redacts the run's env-read values, like its refusal.

A plugin module named literally in the config is logged by its own name, with
its import error's text -- and that text can quote any value the run's
configuration read from the environment, not only the module's name: here the
module's ImportError quotes a variable another config entry read with ``!ENV``.
The refusal already comes out redacted (the error is raised through a carrier
and every failure printer redacts with the carried values), but the loader's
"Failed to import plugin module ..." WARNING printed ``str(error)`` raw, before
any carrier existed, and the recorded text that feeds the refusal and
``metadata.plugin_load_errors`` was stored raw too.

The planted module raises ImportError quoting the env value directly, so any
surface printing the raw text shows the value verbatim.
"""

from __future__ import annotations

import json
import logging
import sys

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.utils.log import ASH_LOGGER

BROKEN = "warnleak_ash_plugins"
#: The env-read value nothing may print.
SECRET = "warnleak-secret-4417"
VARIABLE = "ASH_WARNLEAK_REASON"


class _Sink(logging.Handler):
    def __init__(self):
        super().__init__(level=1)
        self.messages: list = []

    def emit(self, record):
        self.messages.append(record.getMessage())


@pytest.fixture
def log_records():
    """Every ash log record's message, whatever handlers the command sets up:
    the workspace prewarm's warning fires before any console handler exists,
    so the command's own output cannot show it."""
    sink = _Sink()
    level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(sink)
    ASH_LOGGER.setLevel(1)
    yield sink.messages
    ASH_LOGGER.removeHandler(sink)
    ASH_LOGGER.setLevel(level)


@pytest.fixture
def planted(tmp_path, monkeypatch):
    """The broken module on sys.path and the secret in the environment."""
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_CONFIG", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(VARIABLE, SECRET)
    modules = tmp_path / "modules"
    (modules / BROKEN).mkdir(parents=True)
    (modules / BROKEN / "__init__.py").write_text(
        f'import os\nraise ImportError("cannot use " + os.environ["{VARIABLE}"])\n',
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(modules))
    monkeypatch.delitem(sys.modules, BROKEN, raising=False)
    yield tmp_path
    sys.modules.pop(BROKEN, None)


def _config_text() -> str:
    return (
        "project_name: api\n"
        f"ash_plugin_modules:\n  - {BROKEN}\n"
        "global_settings:\n"
        "  ignore_paths:\n"
        "    - path: 'vendor'\n"
        f"      reason: !ENV ${{{VARIABLE}}}\n"
    )


def test_a_workspace_scans_output_never_shows_the_value(
    planted, monkeypatch, log_records
):
    root = planted / "ws"
    (root / "api" / ".ash").mkdir(parents=True)
    (root / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (root / "api" / ".ash" / ".ash.yaml").write_text(_config_text(), encoding="utf-8")
    workspace = root / "dev.code-workspace"
    workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    monkeypatch.chdir(planted)

    result = CliRunner().invoke(app, ["scan", "--workspace", str(workspace)])

    assert result.exit_code == 3, (result.exit_code, result.output[-4000:])
    assert BROKEN in result.output, result.output[-4000:]
    assert SECRET not in result.output, result.output[-4000:]
    joined = " ".join(log_records)
    assert "Failed to import plugin module" in joined, log_records
    # The DEBUG traceback keeps the cause findable for a masked module whose
    # refusal withholds the error text; the sink is at level 1, so the SECRET
    # assert below covers that line too.
    assert "Plugin module import failure traceback" in joined, log_records
    assert SECRET not in joined, joined


def test_a_single_scans_output_never_shows_the_value(planted, monkeypatch, log_records):
    source = planted / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    (source / ".ash.yaml").write_text(_config_text(), encoding="utf-8")
    monkeypatch.chdir(source)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "local",
            "--no-progress",
            "--source-dir",
            str(source),
            "--output-dir",
            str(planted / "out"),
        ],
    )

    assert result.exit_code == 3, (result.exit_code, result.output[-4000:])
    assert BROKEN in result.output, result.output[-4000:]
    assert SECRET not in result.output, result.output[-4000:]
    assert SECRET not in " ".join(log_records), log_records
