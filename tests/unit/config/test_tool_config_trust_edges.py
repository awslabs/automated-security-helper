# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Edges of the scanner config confinement (``config/tool_config_trust.py``).

* A plugin scanner's section that a config leaves out, or holds with no options
  mapping, is given the operator's values for the confined options: a file in
  the tree replaces the operator's config, so skipping the section dropped them.
* A built-in scanner's option the file never wrote is not named in the
  "Ignoring ... from <file>" warning, though it still gives way to the
  operator's value.
* A tightening value (``disable_telemetry: true``) counts as written by the
  file only when the file wrote it, also on a config that
  ``apply_config_overrides`` rebuilt: the rebuild puts every field in
  ``model_fields_set``.
* A plugin section the trusted base holds as a scalar, and an options mapping
  with a key that is not a string, no longer raise out of the confinement.
* An override that only the trusted base refuses is left out of the replay with
  one warning that names its key, instead of aborting the resolution; a
  respelled section is still refused.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable, List, cast

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.config.tool_config_trust import (
    confine_scanner_config_files,
    confine_tool_versions,
)
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    ASHRespelledOverrideError,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

FERRET = "ferret-scan"
PLUGIN = "my-plugin-scanner"


@pytest.fixture
def ash_log():
    """ASH_LOGGER's records; it does not propagate, so caplog would see nothing."""
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


def _warnings_naming(records: List[logging.LogRecord], text: str) -> List[str]:
    return [
        r.getMessage()
        for r in records
        if r.levelno == logging.WARNING and text in r.getMessage()
    ]


def _extra(config: AshConfig, name: str) -> Any:
    return (config.scanners.model_extra or {}).get(name)


def _operator_ferret(options: dict) -> AshConfig:
    return AshConfig.model_validate({"scanners": {FERRET: {"options": options}}})


class _ScalarSection:
    """A trusted base that reads one plugin's section as a scalar.

    Every other section is the wrapped config's own. A plugin section in a
    config file can be written as a scalar or a list.
    """

    def __init__(self, name: str) -> None:
        self._name = name
        self._base = AshConfig()
        self.scanners = self._base.scanners
        self.converters = self._base.converters

    def get_plugin_config(self, plugin_type: str, plugin_name: str) -> Any:
        if plugin_name == self._name:
            return "quick"
        return self._base.get_plugin_config(plugin_type, plugin_name)


def test_an_absent_plugin_scanner_section_gets_the_operators_choices(tmp_path):
    config = AshConfig.model_validate({"project_name": "repo"})
    trusted = _operator_ferret({"profile": "quick", "use_default_config": False})

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    assert _extra(config, FERRET) == {
        "options": {"profile": "quick", "use_default_config": False}
    }


def test_a_plugin_scanner_section_without_options_gets_the_operators_choices(tmp_path):
    config = AshConfig.model_validate({"scanners": {FERRET: {"enabled": True}}})
    trusted = _operator_ferret({"profile": "quick"})

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    section = _extra(config, FERRET)
    assert section["enabled"] is True
    assert section["options"] == {"profile": "quick"}


def test_control_an_absent_section_stays_absent_when_the_operator_set_nothing(
    tmp_path,
):
    config = AshConfig.model_validate({"project_name": "repo"})

    confine_scanner_config_files(config, AshConfig(), [], [tmp_path / ".ash.yaml"])

    assert _extra(config, FERRET) is None


def test_the_warning_does_not_name_an_option_the_file_never_wrote(tmp_path, ash_log):
    """opengrep's options model reads an unwritten ``config`` as ``p/ci``."""
    config = AshConfig.model_validate({"project_name": "repo"})
    trusted = AshConfig.model_validate(
        {"scanners": {"opengrep": {"options": {"config": "p/custom"}}}}
    )

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    assert config.scanners.opengrep.options.config == "p/custom"
    assert not _warnings_naming(ash_log, "scanners.opengrep.options.config")


def test_control_the_warning_names_an_option_the_file_wrote(tmp_path, ash_log):
    config = AshConfig.model_validate(
        {"scanners": {"opengrep": {"options": {"config": "p/mine"}}}}
    )
    trusted = AshConfig.model_validate(
        {"scanners": {"opengrep": {"options": {"config": "p/custom"}}}}
    )

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    assert config.scanners.opengrep.options.config == "p/custom"
    assert _warnings_naming(ash_log, "scanners.opengrep.options.config")


def test_an_unrelated_override_does_not_make_a_default_count_as_written(tmp_path):
    """The rebuild an override causes puts every field in ``model_fields_set``,
    so a trivy ``disable_telemetry`` the file never wrote read as the file's
    tightening value and kept the operator's ``false`` out."""
    config = apply_config_overrides(
        AshConfig.model_validate({"project_name": "repo"}), ["project_name=other"]
    )
    trusted = AshConfig.model_validate(
        {"scanners": {"trivy": {"options": {"disable_telemetry": False}}}}
    )

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    assert config.scanners.trivy.options.disable_telemetry is False


def test_control_a_tightening_value_the_file_wrote_is_kept_after_an_override(
    tmp_path,
):
    config = apply_config_overrides(
        AshConfig.model_validate(
            {"scanners": {"trivy": {"options": {"disable_telemetry": True}}}}
        ),
        ["project_name=other"],
    )
    trusted = AshConfig.model_validate(
        {"scanners": {"trivy": {"options": {"disable_telemetry": False}}}}
    )

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    assert config.scanners.trivy.options.disable_telemetry is True


@pytest.mark.parametrize("name", [FERRET, "detect-secrets"])
def test_a_scalar_plugin_section_in_the_trusted_base_does_not_raise(tmp_path, name):
    config = AshConfig.model_validate({"project_name": "repo"})
    trusted = cast(AshConfig, _ScalarSection(name))

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])


def test_a_scalar_plugin_section_in_the_trusted_base_holds_no_choice(tmp_path):
    config = AshConfig.model_validate(
        {"scanners": {FERRET: {"options": {"profile": "deep"}}}}
    )
    trusted = cast(AshConfig, _ScalarSection(FERRET))

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    assert "profile" not in _extra(config, FERRET)["options"]


def test_a_scalar_plugin_section_in_the_trusted_base_does_not_raise_for_versions(
    tmp_path,
):
    config = AshConfig.model_validate(
        {"scanners": {FERRET: {"options": {"tool_version": "==9.9"}}}}
    )
    trusted = cast(AshConfig, _ScalarSection(FERRET))

    confine_tool_versions(config, trusted, [], [tmp_path / ".ash.yaml"])

    assert "tool_version" not in _extra(config, FERRET)["options"]


def test_an_options_key_that_is_not_a_string_does_not_raise(tmp_path):
    """A YAML ``1:`` under a plugin's options is a key no option is spelled as."""
    config = AshConfig.model_validate({"scanners": {PLUGIN: {"options": {}}}})
    _extra(config, PLUGIN)["options"][1] = "x"
    trusted = AshConfig.model_validate(
        {"scanners": {PLUGIN: {"options": {"tool_version": "==1.2.3"}}}}
    )

    confine_tool_versions(config, trusted, [], [tmp_path / ".ash.yaml"])

    options = _extra(config, PLUGIN)["options"]
    assert options["tool_version"] == "==1.2.3"
    assert options[1] == "x"


@pytest.fixture
def trusted_base_refuses_one_section(monkeypatch: pytest.MonkeyPatch) -> None:
    """``apply_config_overrides`` refuses any set naming ``refused-section``.

    The refusal stands for an override that applied to the resolved config and
    that only the trusted base's own document refuses.
    """
    import automated_security_helper.config.resolve_config as resolve_module

    real = resolve_module.apply_config_overrides

    def refusing(config: AshConfig, overrides: List[str]) -> AshConfig:
        if any("refused-section" in override for override in overrides):
            raise ASHConfigValidationError("refused")
        return real(config, overrides)

    monkeypatch.setattr(resolve_module, "apply_config_overrides", refusing)


OVERRIDES = [
    "scanners.refused-section.options.x=hidden-value",
    "scanners.opengrep.options.config=p/custom",
]


def test_an_override_only_the_trusted_base_refuses_does_not_abort_the_scan_config(
    tmp_path, ash_log, trusted_base_refuses_one_section
):
    config = AshConfig.model_validate({"project_name": "repo"})
    trusted = AshConfig.model_validate({"project_name": "op"})

    confine_scanner_config_files(config, trusted, OVERRIDES, [tmp_path / ".ash.yaml"])

    assert config.scanners.opengrep.options.config == "p/custom"
    named = _warnings_naming(ash_log, "scanners.refused-section.options.x")
    assert len(named) == 1, named
    assert not _warnings_naming(ash_log, "hidden-value")


def test_an_override_only_the_trusted_base_refuses_does_not_abort_the_versions(
    tmp_path, ash_log, trusted_base_refuses_one_section
):
    config = AshConfig.model_validate({"project_name": "repo"})
    trusted = AshConfig.model_validate({"project_name": "op"})

    confine_tool_versions(config, trusted, OVERRIDES, [tmp_path / ".ash.yaml"])

    named = _warnings_naming(ash_log, "scanners.refused-section.options.x")
    assert len(named) == 1, named
    assert not _warnings_naming(ash_log, "hidden-value")


@pytest.mark.parametrize(
    "confine",
    [confine_scanner_config_files, confine_tool_versions],
    ids=lambda function: function.__name__,
)
def test_a_respelled_section_is_still_refused(
    tmp_path, monkeypatch, confine: Callable[..., None]
):
    import automated_security_helper.config.resolve_config as resolve_module

    def respelled(config: AshConfig, overrides: List[str]) -> AshConfig:
        raise ASHRespelledOverrideError("respelled")

    monkeypatch.setattr(resolve_module, "apply_config_overrides", respelled)
    config = AshConfig.model_validate({"project_name": "repo"})
    trusted = AshConfig.model_validate({"project_name": "op"})

    with pytest.raises(ASHRespelledOverrideError):
        confine(config, trusted, OVERRIDES, [Path(tmp_path) / ".ash.yaml"])
