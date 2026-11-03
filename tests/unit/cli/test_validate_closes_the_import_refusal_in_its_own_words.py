# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash config validate` closes a plugin-module refusal in the check's own words.

The agreement suite (test_config_validate_agrees_with_scan) pins that validate
prints the scan's NAMING of a refused module and leaves each surface's closing
to itself. These cells pin that other half of the contract for the import
class: the closing is the check's ("Nothing was imported. Install what the
module needs, or remove the entry from the config file or --config-overrides."),
never the scan's, whose sentences say nothing was scanned and name options no
check has (--ash-plugin-modules, ASH_PLUGIN_MODULES). The namespace class keeps
its own distinct advice, so the two arms cannot be collapsed into one closing
without a cell going red.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

IMPORT_NAMING = "which failed to import, so the plugins it declares are not loaded."
IMPORT_CLOSING = (
    "Nothing was imported. Install what the module needs, or remove the entry "
    "from the config file or --config-overrides."
)
NAMESPACE_CLOSING = (
    "Nothing was imported. Rename the package or name the packages inside it, "
    "or remove the entry from the config file or --config-overrides."
)


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    for name in ("ASH_PLUGIN_MODULES", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    # Configs live outside the scanned tree (the cwd is the empty src/), so
    # ash_plugin_modules entries are the operator's and plugin_module_trust
    # does not filter them. Tidying this to chdir(tmp_path) would turn the
    # by-file cell red for the wrong reason: the entry would be dropped as
    # an in-tree config's, not refused by the import check.
    source = tmp_path / "src"
    source.mkdir()
    monkeypatch.chdir(source)
    return tmp_path


def _validate(config: Path, *overrides: str) -> tuple[int, str]:
    args = ["config", "validate", "--config", str(config)]
    for override in overrides:
        args += ["--config-overrides", override]
    result = CliRunner().invoke(app, args)
    return result.exit_code, " ".join(result.output.split())


def _never_the_scans(output: str) -> None:
    # The scan's closing sentences describe a run validate does not make and
    # option spellings it does not take. Case-insensitive: the compound
    # namespace closing spells "nothing was scanned" in lowercase.
    assert "nothing was scanned" not in output.lower(), output[-2000:]
    assert "ASH_PLUGIN_MODULES" not in output, output[-2000:]
    assert "--ash-plugin-modules" not in output, output[-2000:]


def test_an_unfindable_module_by_file_gets_the_checks_closing(project):
    # absent_ash_plugins (here and in the override cell) is named to pass the
    # plugin-naming rule, so the refusal lands on the import arm; a name like
    # absent_module would hit the naming arm and close with its advice instead.
    config = project / "by-file.yaml"
    config.write_text(
        "project_name: demo\nash_plugin_modules:\n  - absent_ash_plugins\n",
        encoding="utf-8",
    )

    exit_code, output = _validate(config)

    assert exit_code == 3, (exit_code, output[-2000:])
    assert IMPORT_NAMING in output, output[-2000:]
    assert IMPORT_CLOSING in output, output[-2000:]
    _never_the_scans(output)


def test_an_unfindable_module_by_override_gets_the_checks_closing(project):
    """The override route, the shape of the agreement suite's own cell: the
    module reaches the check only through --config-overrides, and the closing
    is still the check's."""
    config = project / "plain.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")

    exit_code, output = _validate(config, 'ash_plugin_modules+=["absent_ash_plugins"]')

    assert exit_code == 3, (exit_code, output[-2000:])
    assert IMPORT_NAMING in output, output[-2000:]
    assert IMPORT_CLOSING in output, output[-2000:]
    _never_the_scans(output)


def test_a_namespace_module_keeps_its_own_distinct_advice(project):
    """The control for the arms staying apart: a namespace refusal's advice is
    about naming, and telling that operator to install what a standard-library
    module needs points at dependencies that are not the problem."""
    config = project / "namespace.yaml"
    config.write_text(
        "project_name: demo\nash_plugin_modules:\n  - wsgiref\n", encoding="utf-8"
    )

    exit_code, output = _validate(config)

    assert exit_code == 3, (exit_code, output[-2000:])
    assert NAMESPACE_CLOSING in output, output[-2000:]
    assert "Install what the module needs" not in output, output[-2000:]
    _never_the_scans(output)
