# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A configured plugin module that fails to import refuses the workspace run.

A single scan refuses with exit 3 when a module its configuration names fails
to import, whatever the selection shape. In workspace mode the one load for
every project happens in ``prewarm_plugin_registry``, which tolerated the
failure: ``--dry-run`` printed the plan and exited 0 for a command line whose
real run must refuse, and a ``--scanners`` selection naming the failed
module's scanner was answered "None of the requested scanners exist" with
exit 5 -- a usage error, for a configuration error the operator can only fix
in the config or the environment.

The planted module imports a dependency that does not exist, so the import
fails; nothing else about the workspace is wrong, so any refusal is the
import's.
"""

from __future__ import annotations

import json
import sys

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

#: The refusal's own words, which both cells must see with exit 3.
WORDS = "which failed to import, so the plugins it declares are not loaded"

BROKEN = "wsbroken_ash_plugins"
DEPENDENCY = "wsbrokendep_for_workspace"


@pytest.fixture
def workspace_with_broken_module(tmp_path, monkeypatch):
    """A one-project workspace whose project config names the broken module."""
    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_CONFIG", "ASH_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)

    modules = tmp_path / "modules"
    (modules / BROKEN).mkdir(parents=True)
    (modules / BROKEN / "__init__.py").write_text(
        f"import {DEPENDENCY}  # noqa: F401\nASH_REPORTERS = []\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(modules))
    monkeypatch.delitem(sys.modules, BROKEN, raising=False)

    root = tmp_path / "ws"
    (root / "api" / ".ash").mkdir(parents=True)
    (root / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (root / "api" / ".ash" / ".ash.yaml").write_text(
        f"project_name: api\nash_plugin_modules:\n  - {BROKEN}\n", encoding="utf-8"
    )
    workspace = root / "dev.code-workspace"
    workspace.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    yield str(workspace)
    sys.modules.pop(BROKEN, None)


def test_a_dry_run_refuses_what_the_real_run_refuses(workspace_with_broken_module):
    """--dry-run exits 3 in the refusal's words, not 0 with a plan: a dry run
    that reports the command line good for a run the scan refuses sends the
    operator into the refusal twice."""
    result = CliRunner().invoke(
        app, ["scan", "--workspace", workspace_with_broken_module, "--dry-run"]
    )

    assert result.exit_code == 3, (result.exit_code, result.output[-4000:])
    assert WORDS in result.output, result.output[-4000:]
    assert BROKEN in result.output, result.output[-4000:]


def test_a_scanners_selection_is_refused_as_the_configuration_error_it_is(
    workspace_with_broken_module,
):
    """--scanners naming only the failed module's scanner: exit 3 for the
    import failure, not 5 for a selection that matches nothing -- the selection
    is only unanswerable because the configured module did not load."""
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--workspace",
            workspace_with_broken_module,
            "--scanners",
            "wsbroken-scanner",
        ],
    )

    assert result.exit_code == 3, (result.exit_code, result.output[-4000:])
    assert WORDS in result.output, result.output[-4000:]
