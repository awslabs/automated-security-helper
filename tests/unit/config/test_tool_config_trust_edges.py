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
  respelled section is still refused. The value such an override set on the
  resolved config is the operator's and is left as it is, not reset to the
  trusted base's. A list valid only together is not split by one refused entry,
  and one dropped override is one warning across both steps.
* A section the trusted base spells another way is made once.
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
    replay_overrides_onto,
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


#: Each plugin scanner section (not a typed field of the scanners segment) with
#: an option ``SCANNER_CONFIG_CHOICE_OPTIONS`` confines, and a value the
#: operator can choose for it.
PLUGIN_CHOICES = [
    pytest.param(FERRET, "profile", "quick", id="ferret-scan"),
    pytest.param("snyk-code", "honor_tree_exclusions", True, id="snyk-code"),
    pytest.param("trivy-repo", "disable_telemetry", False, id="trivy-repo"),
]


def _operator_choice(scanner: str, option: str, value: Any) -> AshConfig:
    return AshConfig.model_validate(
        {"scanners": {scanner: {"options": {option: value}}}}
    )


def test_an_absent_plugin_scanner_section_gets_the_operators_choices(tmp_path):
    config = AshConfig.model_validate({"project_name": "repo"})
    trusted = _operator_ferret({"profile": "quick", "use_default_config": False})

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    assert _extra(config, FERRET) == {
        "options": {"profile": "quick", "use_default_config": False}
    }


@pytest.mark.parametrize(("scanner", "option", "value"), PLUGIN_CHOICES)
def test_an_absent_section_of_each_plugin_scanner_gets_its_choice(
    tmp_path, scanner, option, value
):
    config = AshConfig.model_validate({"project_name": "repo"})
    trusted = _operator_choice(scanner, option, value)

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    assert _extra(config, scanner) == {"options": {option: value}}


def test_a_plugin_scanner_section_without_options_gets_the_operators_choices(tmp_path):
    config = AshConfig.model_validate({"scanners": {FERRET: {"enabled": True}}})
    trusted = _operator_ferret({"profile": "quick"})

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    section = _extra(config, FERRET)
    assert section["enabled"] is True
    assert section["options"] == {"profile": "quick"}


@pytest.mark.parametrize(("scanner", "option", "value"), PLUGIN_CHOICES)
def test_control_an_absent_section_stays_absent_when_the_operator_set_nothing(
    tmp_path, scanner, option, value
):
    config = AshConfig.model_validate({"project_name": "repo"})

    confine_scanner_config_files(config, AshConfig(), [], [tmp_path / ".ash.yaml"])

    assert _extra(config, scanner) is None


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


def test_each_override_the_trusted_base_refuses_gets_its_own_warning(
    tmp_path, ash_log, trusted_base_refuses_one_section
):
    config = AshConfig.model_validate({"project_name": "repo"})
    trusted = AshConfig.model_validate({"project_name": "op"})
    overrides = [
        "scanners.refused-section.options.x=hidden-value",
        "scanners.refused-section.options.y=hidden-value",
        "scanners.opengrep.options.config=p/custom",
    ]

    confine_scanner_config_files(config, trusted, overrides, [tmp_path / ".ash.yaml"])

    assert config.scanners.opengrep.options.config == "p/custom"
    named = _warnings_naming(ash_log, "scanners.refused-section.")
    assert len(named) == 2, named
    assert sorted("options.x" in message for message in named) == [False, True]
    assert not _warnings_naming(ash_log, "hidden-value")


def test_an_override_only_the_trusted_base_refuses_does_not_abort_the_versions(
    tmp_path, ash_log, trusted_base_refuses_one_section
):
    """The tool-version step replays the same scanners entries as the scan
    config step and leaves reporting them to it; it raises nothing."""
    config = AshConfig.model_validate({"project_name": "repo"})
    trusted = AshConfig.model_validate({"project_name": "op"})

    confine_tool_versions(config, trusted, OVERRIDES, [tmp_path / ".ash.yaml"])

    assert not _warnings_naming(ash_log, "scanners.refused-section.options.x")


def test_one_dropped_scanners_override_is_one_warning_across_both_steps(
    tmp_path, ash_log, trusted_base_refuses_one_section
):
    """Every route runs both steps with the same override list."""
    config = AshConfig.model_validate({"project_name": "repo"})
    trusted = AshConfig.model_validate({"project_name": "op"})
    files = [tmp_path / ".ash.yaml"]

    confine_scanner_config_files(config, trusted, OVERRIDES, files)
    confine_tool_versions(config, trusted, OVERRIDES, files)

    named = _warnings_naming(ash_log, "scanners.refused-section.options.x")
    assert len(named) == 1, named


def test_a_dropped_converters_override_is_reported_by_the_versions_step(
    tmp_path, ash_log, trusted_base_refuses_one_section
):
    config = AshConfig.model_validate({"project_name": "repo"})
    trusted = AshConfig.model_validate({"project_name": "op"})
    files = [tmp_path / ".ash.yaml"]
    overrides = ["converters.refused-section.options.x=hidden-value"]

    confine_scanner_config_files(config, trusted, overrides, files)
    confine_tool_versions(config, trusted, overrides, files)

    named = _warnings_naming(ash_log, "converters.refused-section.options.x")
    assert len(named) == 1, named
    assert not _warnings_naming(ash_log, "hidden-value")


def _refuse_on_the_trusted_base(monkeypatch: pytest.MonkeyPatch, token: str) -> None:
    """``apply_config_overrides`` refuses a set naming ``token`` on the trusted
    base only (its ``project_name`` is ``op``); the resolved config takes it."""
    import automated_security_helper.config.resolve_config as resolve_module

    real = resolve_module.apply_config_overrides

    def refusing(config: AshConfig, overrides: List[str]) -> AshConfig:
        if config.project_name == "op" and any(token in item for item in overrides):
            raise ASHConfigValidationError("refused")
        return real(config, overrides)

    monkeypatch.setattr(resolve_module, "apply_config_overrides", refusing)


def test_a_refused_override_at_a_confined_path_keeps_the_operators_value(
    tmp_path, ash_log, monkeypatch
):
    """The override applied to the resolved config; the trusted base could not
    take it, so it has nothing to put in its place. The operator's value stays
    and is not named as the repository's."""
    override = "scanners.opengrep.options.config=p/custom"
    config = apply_config_overrides(
        AshConfig.model_validate({"project_name": "repo"}), [override]
    )
    trusted = AshConfig.model_validate({"project_name": "op"})
    _refuse_on_the_trusted_base(monkeypatch, "opengrep")

    confine_scanner_config_files(config, trusted, [override], [tmp_path / ".ash.yaml"])

    assert config.scanners.opengrep.options.config == "p/custom"
    assert not _warnings_naming(ash_log, "Ignoring")
    named = _warnings_naming(ash_log, "scanners.opengrep.options.config")
    assert len(named) == 1, named
    assert "cannot take" in named[0]


def test_a_refused_tool_version_override_keeps_the_operators_pin(
    tmp_path, ash_log, monkeypatch
):
    override = "scanners.bandit.options.tool_version===1.7.9"
    config = apply_config_overrides(
        AshConfig.model_validate({"project_name": "repo"}), [override]
    )
    trusted = AshConfig.model_validate({"project_name": "op"})
    _refuse_on_the_trusted_base(monkeypatch, "bandit")

    confine_tool_versions(config, trusted, [override], [tmp_path / ".ash.yaml"])

    assert str(config.scanners.bandit.options.tool_version) == "==1.7.9"
    assert not _warnings_naming(ash_log, "Ignoring")


def test_overrides_valid_only_together_are_not_dropped_for_a_refused_one(monkeypatch):
    """A is valid only with B and C is refused: the one-at-a-time replay
    dropped A as well, the leave-one-out search drops only C."""
    import automated_security_helper.config.resolve_config as resolve_module

    real = resolve_module.apply_config_overrides
    first = "scanners.opengrep.options.config=p/custom"
    partner = "scanners.opengrep.options.metrics=off"
    refused = "scanners.refused-section.options.x=1"

    def refusing(config: AshConfig, overrides: List[str]) -> AshConfig:
        if any("refused-section" in item for item in overrides):
            raise ASHConfigValidationError("refused")
        if first in overrides and partner not in overrides:
            raise ASHConfigValidationError("needs its partner")
        return real(config, overrides)

    monkeypatch.setattr(resolve_module, "apply_config_overrides", refusing)
    trusted = AshConfig.model_validate({"project_name": "op"})

    replay = replay_overrides_onto(trusted, [first, partner, refused])

    assert replay.config.scanners.opengrep.options.config == "p/custom"
    assert replay.config.scanners.opengrep.options.metrics == "off"
    assert [item.key for item in replay.dropped] == [
        "scanners.refused-section.options.x"
    ]


def test_a_respelled_section_found_one_override_at_a_time_is_still_refused(
    monkeypatch,
):
    """Two independent refusals leave no single removal that repairs the set,
    so the overrides apply one at a time; a respelled one still raises."""
    import automated_security_helper.config.resolve_config as resolve_module

    real = resolve_module.apply_config_overrides

    def refusing(config: AshConfig, overrides: List[str]) -> AshConfig:
        if len(overrides) == 1 and "respelled-c" in overrides[0]:
            raise ASHRespelledOverrideError("respelled")
        if any("refused-" in item for item in overrides):
            raise ASHConfigValidationError("refused")
        return real(config, overrides)

    monkeypatch.setattr(resolve_module, "apply_config_overrides", refusing)
    trusted = AshConfig.model_validate({"project_name": "op"})
    overrides = [
        "scanners.refused-a.options.x=1",
        "scanners.refused-b.options.x=1",
        "scanners.respelled-c.options.x=1",
    ]

    with pytest.raises(ASHRespelledOverrideError):
        replay_overrides_onto(trusted, overrides)


def test_a_section_the_trusted_base_spells_another_way_is_made_once(tmp_path):
    """The base spells the section ``ferret_scan``; the config has none. The
    scan config step makes ``ferret-scan`` for the operator's choice and the
    tool-version step must pin that section, not make a second one."""
    config = AshConfig.model_validate({"project_name": "repo"})
    trusted = AshConfig.model_validate(
        {
            "scanners": {
                "ferret_scan": {
                    "options": {"profile": "quick", "tool_version": "==1.0.1"}
                }
            }
        }
    )
    files = [tmp_path / ".ash.yaml"]

    confine_scanner_config_files(config, trusted, [], files)
    confine_tool_versions(config, trusted, [], files)

    spellings = [
        key
        for key in (config.scanners.model_extra or {})
        if key.replace("_", "-") == FERRET
    ]
    assert spellings == [FERRET], spellings
    assert _extra(config, FERRET)["options"] == {
        "profile": "quick",
        "tool_version": "==1.0.1",
    }


#: A tightening value, the scanner and option it narrows, and the loosening
#: value an operator may choose; the scanner sections are plugin dicts (trivy-repo)
#: and typed models (semgrep, opengrep).
TIGHTENING = [
    pytest.param("trivy-repo", "disable_telemetry", True, False, id="trivy-repo"),
    pytest.param("semgrep", "metrics", "off", "on", id="semgrep"),
    pytest.param("opengrep", "metrics", "off", "on", id="opengrep"),
]


@pytest.mark.parametrize(("scanner", "option", "tight", "loose"), TIGHTENING)
def test_a_tightening_value_the_file_wrote_is_kept_after_an_override(
    tmp_path, scanner, option, tight, loose
):
    config = apply_config_overrides(
        AshConfig.model_validate({"scanners": {scanner: {"options": {option: tight}}}}),
        ["project_name=other"],
    )
    trusted = _operator_choice(scanner, option, loose)

    confine_scanner_config_files(config, trusted, [], [tmp_path / ".ash.yaml"])

    section = config.get_plugin_config("scanner", scanner)
    assert section["options"][option] == tight


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


APPEND = "scanners.opengrep.options.patterns+=operator-rule"


def _opengrep_patterns(config: AshConfig) -> List[str]:
    return list(config.scanners.opengrep.options.patterns)


def test_a_repository_item_in_a_confined_list_is_confined_under_a_refused_append(
    tmp_path, ash_log, monkeypatch
):
    """The operator appended an item and the trusted base could not take the
    append, so the resolved list holds the repository's items beside it.
    Leaving the path alone kept them, and opengrep's ``patterns`` replaces
    every rule config. What is left is the trusted base's list and the
    operator's item."""
    config = apply_config_overrides(
        AshConfig.model_validate(
            {
                "project_name": "repo",
                "scanners": {"opengrep": {"options": {"patterns": ["repo-rule"]}}},
            }
        ),
        [APPEND],
    )
    assert _opengrep_patterns(config) == ["repo-rule", "operator-rule"]
    trusted = AshConfig.model_validate({"project_name": "op"})
    _refuse_on_the_trusted_base(monkeypatch, "opengrep")

    confine_scanner_config_files(config, trusted, [APPEND], [tmp_path / ".ash.yaml"])

    assert _opengrep_patterns(config) == ["operator-rule"]
    named = _warnings_naming(ash_log, "Ignoring")
    assert len(named) == 1, named
    assert "scanners.opengrep.options.patterns" in named[0]
    assert not _warnings_naming(ash_log, "operator-rule")


def test_an_appended_item_follows_the_trusted_bases_list_and_is_not_blamed_on_the_file(
    tmp_path, ash_log, monkeypatch
):
    """The file wrote no ``patterns``: the list is the operator's item alone,
    and the confined list is the trusted base's with that item after it."""
    config = apply_config_overrides(
        AshConfig.model_validate({"project_name": "repo"}), [APPEND]
    )
    trusted = AshConfig.model_validate(
        {
            "project_name": "op",
            "scanners": {"opengrep": {"options": {"patterns": ["base-rule"]}}},
        }
    )
    _refuse_on_the_trusted_base(monkeypatch, "opengrep")

    confine_scanner_config_files(config, trusted, [APPEND], [tmp_path / ".ash.yaml"])

    assert _opengrep_patterns(config) == ["base-rule", "operator-rule"]
    assert not _warnings_naming(ash_log, "Ignoring")


def test_a_refused_append_onto_a_scalar_option_keeps_the_operators_value(
    tmp_path, ash_log, monkeypatch
):
    """An append onto a value that is not a list sets it (``config`` is a
    string); the operator's value is what the apply set and stays."""
    override = "scanners.opengrep.options.config+=p/custom"
    config = apply_config_overrides(
        AshConfig.model_validate({"project_name": "repo"}), [override]
    )
    trusted = AshConfig.model_validate({"project_name": "op"})
    _refuse_on_the_trusted_base(monkeypatch, "opengrep")

    confine_scanner_config_files(config, trusted, [override], [tmp_path / ".ash.yaml"])

    assert config.scanners.opengrep.options.config == "p/custom"
    assert not _warnings_naming(ash_log, "Ignoring")


#: The spelling an override is typed in and the other spelling of the same
#: plugin's section; a file can hold both (``ferret-scan`` is not a declared
#: field of the scanners segment, so neither is folded onto the other).
SPELLINGS = [
    pytest.param("ferret-scan", "ferret_scan", id="kebab"),
    pytest.param("ferret_scan", "ferret-scan", id="snake"),
]


def _operator_base(options: dict) -> AshConfig:
    """The trusted base the refusing stub treats as the operator's (``op``)."""
    return AshConfig.model_validate(
        {"project_name": "op", "scanners": {FERRET: {"options": options}}}
    )


def _repository_with_both_spellings(option: str) -> AshConfig:
    return AshConfig.model_validate(
        {
            "project_name": "repo",
            "scanners": {
                "ferret-scan": {"options": {option: "repository"}},
                "ferret_scan": {"options": {option: "repository"}},
            },
        }
    )


@pytest.mark.parametrize(("landed", "other"), SPELLINGS)
def test_only_the_section_a_refused_override_landed_on_keeps_its_value(
    tmp_path, monkeypatch, landed, other
):
    """The file holds the plugin's section under both spellings and the
    override changed one of them. The other is the repository's, so it is
    confined; matching every spelling that folds together left it alone."""
    override = f"scanners.{landed}.options.profile=quick"
    config = apply_config_overrides(
        _repository_with_both_spellings("profile"), [override]
    )
    assert _extra(config, landed)["options"]["profile"] == "quick"
    assert _extra(config, other)["options"]["profile"] == "repository"
    trusted = _operator_base({"profile": "standard"})
    _refuse_on_the_trusted_base(monkeypatch, "ferret")

    confine_scanner_config_files(config, trusted, [override], [tmp_path / ".ash.yaml"])

    assert _extra(config, landed)["options"]["profile"] == "quick"
    assert _extra(config, other)["options"]["profile"] == "standard"


@pytest.mark.parametrize(("landed", "other"), SPELLINGS)
def test_only_the_section_a_refused_tool_version_landed_on_keeps_its_pin(
    tmp_path, monkeypatch, landed, other
):
    override = f"scanners.{landed}.options.tool_version===2.0.0"
    config = apply_config_overrides(
        _repository_with_both_spellings("tool_version"), [override]
    )
    assert _extra(config, landed)["options"]["tool_version"] == "==2.0.0"
    trusted = _operator_base({"tool_version": "==1.0.1"})
    _refuse_on_the_trusted_base(monkeypatch, "ferret")

    confine_tool_versions(config, trusted, [override], [tmp_path / ".ash.yaml"])

    assert _extra(config, landed)["options"]["tool_version"] == "==2.0.0"
    assert _extra(config, other)["options"]["tool_version"] == "==1.0.1"
