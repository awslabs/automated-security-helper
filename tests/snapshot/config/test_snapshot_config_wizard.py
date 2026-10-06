# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ashx config wizard`, driven through every prompt with scripted answers.

The wizard asks one yes/no question per built-in scanner and reporter, in field
order. The answers are built from that same field list (via the wizard's own
helpers), so adding a scanner adds a prompt here instead of shifting every later
answer onto the wrong question. Defaults shown in the prompts ([Y/n] vs [y/N]) depend
on the host for semgrep and opengrep, so each case renders once per host.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from automated_security_helper.cli.config import _get_reporter_names, _get_scanner_names
from tests.snapshot.support.cli import (
    CONFIG_HOSTS,
    DISPLAYED_CWD,
    displayed_cwd,
    run_cli,
    simulated_host,
)

# Scanner and reporter answers that differ from pressing Enter.
SCANNER_ANSWERS = {"checkov": "n", "grype": "n"}
REPORTER_ANSWERS = {"html": "n", "yaml": "y"}

EXISTING_CONFIG = """\
project_name: existing-project
ash_plugin_modules:
  - my_org.legacy_plugins
scanners:
  bandit:
    enabled: false
"""


def _answers(project_name: str, *, keep_existing_modules: int = 0) -> str:
    lines = [project_name]
    lines += [SCANNER_ANSWERS.get(alias, "") for _, alias in _get_scanner_names()]
    lines += [REPORTER_ANSWERS.get(alias, "") for _, alias in _get_reporter_names()]
    lines.append("y")  # the ASH_OFFLINE reminder comment
    lines += ["n"] * keep_existing_modules  # drop each module already configured
    lines += ["my_org.ash_plugins", ""]  # add one module, then finish
    return "\n".join(lines) + "\n"


@pytest.fixture
def project_dir(tmp_path: Path, monkeypatch, snapshot_normalizer) -> Path:
    project = tmp_path / "demo-project"
    project.mkdir()
    monkeypatch.chdir(project)
    for spelling in (PurePosixPath(DISPLAYED_CWD), PureWindowsPath(DISPLAYED_CWD)):
        snapshot_normalizer.add_root(spelling, "WORKSPACE")
    return project


@pytest.mark.parametrize("host", CONFIG_HOSTS, ids=lambda h: h.id)
def test_config_wizard_from_defaults(host, project_dir, monkeypatch, text_snapshot):
    with simulated_host(monkeypatch, host), displayed_cwd(monkeypatch):
        run = run_cli(["config", "wizard"], stdin=_answers("wizard-demo"))

    assert run.exit_code == 0, run.output
    written = (project_dir / ".ash" / ".ash.yaml").read_text(encoding="utf-8")
    assert "project_name: wizard-demo" in written
    assert "- my_org.ash_plugins" in written
    assert text_snapshot("txt")(name="stdout") == run.document
    assert text_snapshot("yaml")(name="ash-yaml") == written


@pytest.mark.parametrize("host", CONFIG_HOSTS, ids=lambda h: h.id)
def test_config_wizard_edits_existing(host, project_dir, monkeypatch, text_snapshot):
    config = project_dir / ".ash" / ".ash.yaml"
    config.parent.mkdir()
    config.write_text(EXISTING_CONFIG, encoding="utf-8")

    with simulated_host(monkeypatch, host), displayed_cwd(monkeypatch):
        # Enter keeps the existing project name.
        run = run_cli(["config", "wizard"], stdin=_answers("", keep_existing_modules=1))

    assert run.exit_code == 0, run.output
    written = config.read_text(encoding="utf-8")
    assert "project_name: existing-project" in written
    assert "my_org.legacy_plugins" not in written
    assert text_snapshot("txt")(name="stdout") == run.document
    assert text_snapshot("yaml")(name="ash-yaml") == written
