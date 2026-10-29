# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner config confinement replays overrides folded, and confines respect_gitignore.

Two behaviors of ``config/tool_config_trust.py``:

* ferret-scan's ``respect_gitignore`` has the tool skip the files the scanned
  tree's own ``.gitignore`` names, so a repository's config could choose which
  of its files the scan reads. It is an operator's choice like ``profile``: a
  repository config's ``true`` is replaced by the trusted value (off) and named
  in the warning.
* The scanner overrides are replayed onto the trusted base folded onto its own
  section spellings (``resolve_config._folded_onto_trusted``): when the
  repository's in-tree config spells an undeclared plugin section one way and
  the operator's file another, the scan's own apply makes the operator type
  the repository's spelling, and a raw replay refused that spelling, so no
  spelling passed both applications and the scan could not run.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.config.tool_config_trust import confine_tool_versions
from automated_security_helper.utils.log import ASH_LOGGER
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

PLUGIN = "my-plugin-scanner"


def _trusted_pin() -> AshConfig:
    return AshConfig.model_validate(
        {"scanners": {PLUGIN: {"options": {"tool_version": "==1.2.3"}}}}
    )


def _pin_of(config: AshConfig) -> object:
    section = config.get_plugin_config("scanner", PLUGIN) or {}
    return (section.get("options") or {}).get("tool_version")


def test_the_operators_pin_is_restored_when_the_section_omits_it(tmp_path):
    """A plugin section's dict holds only what was written; a repository
    config that leaves tool_version out left the plugin on its default
    constraint in place of the operator's pin."""
    config = AshConfig.model_validate({"scanners": {PLUGIN: {"options": {}}}})

    confine_tool_versions(config, _trusted_pin(), [], [tmp_path / ".ash.yaml"])

    assert _pin_of(config) == "==1.2.3"


def test_the_operators_pin_is_restored_when_the_section_has_no_options(tmp_path):
    config = AshConfig.model_validate({"scanners": {PLUGIN: {"enabled": True}}})

    confine_tool_versions(config, _trusted_pin(), [], [tmp_path / ".ash.yaml"])

    assert _pin_of(config) == "==1.2.3"


def test_the_operators_pin_is_restored_when_the_section_is_absent(tmp_path):
    config = AshConfig.model_validate({"project_name": "repo"})

    confine_tool_versions(config, _trusted_pin(), [], [tmp_path / ".ash.yaml"])

    assert _pin_of(config) == "==1.2.3"


@pytest.fixture(autouse=True)
def _no_operator_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


@pytest.fixture
def ash_log():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Collect(level=logging.DEBUG)
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous_level)


def _checkout(tmp_path: Path, repo_text: str) -> Path:
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    (checkout / ".ash").mkdir()
    (checkout / ".ash" / ".ash.yaml").write_text(repo_text, encoding="utf-8")
    return checkout


def test_a_repository_configs_respect_gitignore_is_the_operators_choice(
    tmp_path, ash_log
):
    checkout = _checkout(
        tmp_path,
        "project_name: repo\nscanners:\n  ferret-scan:\n    options:\n"
        "      respect_gitignore: true\n",
    )

    config = resolve_config(source_dir=checkout)

    section = config.get_plugin_config("scanner", "ferret-scan") or {}
    assert section.get("options", {}).get("respect_gitignore") is False
    warnings = [
        r.getMessage()
        for r in ash_log
        if r.levelno == logging.WARNING
        and "scanners.ferret-scan.options.respect_gitignore" in r.getMessage()
    ]
    assert warnings, [r.getMessage() for r in ash_log if r.levelno == logging.WARNING]


def test_the_repositorys_spelling_of_a_plugin_section_replays_onto_the_trusted_base(
    tmp_path,
):
    """The lockout shape: the repository spells the undeclared section
    ``MyPluginScanner``, the operator's file ``my-plugin-scanner``, and the
    override is typed the way the scan's own apply demands (the repository's).
    The confinement's replay onto the trusted base folds it onto the operator's
    key instead of refusing it, so the scan resolves and the override lands."""
    checkout = _checkout(
        tmp_path,
        "project_name: repo\nscanners:\n  MyPluginScanner:\n    options:\n"
        "      timeout: 1\n",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        "project_name: op\nscanners:\n  my-plugin-scanner:\n    options:\n"
        "      timeout: 1\n",
        encoding="utf-8",
    )

    config = resolve_config(
        source_dir=checkout,
        trusted_config_path=operator,
        config_overrides=["scanners.MyPluginScanner.options.timeout=2"],
    )

    extra = config.scanners.model_extra or {}
    assert extra["MyPluginScanner"]["options"]["timeout"] == 2
