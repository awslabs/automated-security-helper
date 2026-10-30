# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner config confinement replays overrides folded, and confines respect_gitignore.

Two behaviors of ``config/tool_config_trust.py``:

* ferret-scan's ``respect_gitignore`` has the tool skip the files the scanned
  tree's own ``.gitignore`` names, so a repository's config could choose which
  of its files the scan reads. It is an operator's choice like ``profile``: a
  repository config's ``true`` gives way to the trusted value (off: the
  scanner's own default, since the trusted base pins nothing for a plugin
  section) and is named in the warning.
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


def test_the_operators_pin_is_restored_when_options_is_left_empty(tmp_path):
    """``options:`` with nothing under it reads as None: no mapping for the pin
    to land in, and no warning either, since nothing was written there. A
    mapping is made for it, as for a section with no options key."""
    config = AshConfig.model_validate({"scanners": {PLUGIN: {"options": None}}})

    confine_tool_versions(config, _trusted_pin(), [], [tmp_path / ".ash.yaml"])

    assert _pin_of(config) == "==1.2.3"


def test_a_non_mapping_options_value_is_named_in_a_warning_and_left(tmp_path):
    """A plugin section whose ``options`` is not a mapping cannot hold the pin.
    The value is left as written for the plugin to refuse, and a warning names
    the section and the pin, so the omission is not silent."""
    config = AshConfig.model_validate({"scanners": {PLUGIN: {"options": "oops"}}})
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        confine_tool_versions(config, _trusted_pin(), [], [tmp_path / ".ash.yaml"])
    finally:
        ASH_LOGGER.removeHandler(handler)

    section = config.get_plugin_config("scanner", PLUGIN) or {}
    assert section.get("options") == "oops", section
    warnings = [r.getMessage() for r in records if r.levelno == logging.WARNING]
    assert any(
        f"scanners.{PLUGIN}.options is not a mapping" in w and "tool_version" in w
        for w in warnings
    ), warnings


def test_the_operators_pin_is_restored_when_the_section_is_absent(tmp_path):
    config = AshConfig.model_validate({"project_name": "repo"})

    confine_tool_versions(config, _trusted_pin(), [], [tmp_path / ".ash.yaml"])

    assert _pin_of(config) == "==1.2.3"


@pytest.mark.parametrize("spelling", ["MyPluginScanner", "my_plugin_scanner"])
def test_a_respelled_section_takes_the_pin_and_no_second_section_is_made(
    tmp_path, spelling
):
    """The repository spells the plugin's section another way than the
    operator's file. The section is the plugin's under either spelling (the
    lookup folds case and separators), so the pin lands in the section the
    plugin reads; a second section spelled the operator's way, holding only
    the pin, was made beside it and is not."""
    config = AshConfig.model_validate({"scanners": {spelling: {"options": {}}}})

    confine_tool_versions(config, _trusted_pin(), [], [tmp_path / ".ash.yaml"])

    extra = config.scanners.model_extra or {}
    assert list(extra) == [spelling], extra
    assert extra[spelling]["options"]["tool_version"] == "==1.2.3"
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
    """The repository's ``true`` is dropped and named in the warning.

    ferret-scan is a plugin section, a plain dict holding only what a file
    wrote, and the trusted base (the defaults, no operator config) pins
    nothing for it, so the confinement removes the written key and the
    scanner reads its own default, off (``SCANNER_CONFIG_CHOICE_OPTIONS``).
    """
    checkout = _checkout(
        tmp_path,
        "project_name: repo\nscanners:\n  ferret-scan:\n    options:\n"
        "      respect_gitignore: true\n",
    )

    config = resolve_config(source_dir=checkout)

    section = config.get_plugin_config("scanner", "ferret-scan") or {}
    options = section.get("options", {})
    assert options.get("respect_gitignore", False) is False, options
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
