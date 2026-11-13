# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner-name alias table, measured end to end at the config model.

The semgrep scanner plugin was removed in v4 and its name became an alias of
the opengrep plugin (``utils/scanner_names.SCANNER_NAME_ALIASES``). These tests
pin the two behaviors operators depend on:

* a config that sets ``scanners.semgrep`` (enabled and options) resolves to the
  opengrep plugin's section, with one log line naming the mapping, so the
  settings take effect on the scanner that actually runs;
* ``--scanners semgrep`` / ``--exclude-scanners semgrep`` select opengrep
  (``core/phases/scan_phase._resolve_scanner_name_aliases``).

Without the fold, a retired name would land in the segment's ``extra="allow"``
bucket and read as an unknown third-party scanner: never instantiated, never
run, and ``semgrep: enabled: false`` silently ignored while opengrep ran.
"""

import logging

import pytest

from automated_security_helper.config.ash_config import (
    AshConfig,
    ScannerConfigSegment,
)
from automated_security_helper.core.phases.scan_phase import (
    _resolve_scanner_name_aliases,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.scanner_names import (
    SCANNER_NAME_ALIASES,
    SCANNER_TAG_NAMES,
    canonical_scanner_name,
)


@pytest.fixture
def ash_log():
    """Capture ASH_LOGGER records; it does not propagate, so caplog sees nothing."""
    records: list[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
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


def _messages(records) -> list[str]:
    return [r.getMessage() for r in records]


class TestTheAliasTable:
    def test_semgrep_resolves_to_opengrep(self):
        assert canonical_scanner_name("semgrep") == "opengrep"

    @pytest.mark.parametrize("spelling", ["Semgrep", "SEMGREP", "sem-grep", "sem_grep"])
    def test_spellings_resolve_like_the_config_lookup_does(self, spelling):
        """The same punctuation-stripped, lowered reading get_plugin_config uses."""
        assert canonical_scanner_name(spelling) == "opengrep"

    def test_a_non_alias_passes_through_in_its_own_spelling(self):
        assert canonical_scanner_name("opengrep") == "opengrep"
        assert canonical_scanner_name("Bandit") == "Bandit"

    def test_every_alias_target_is_a_shipped_scanner(self):
        """Control: an alias to a retired or misspelled target would re-create
        the silent-extra problem one level down."""
        for canonical in SCANNER_NAME_ALIASES.values():
            assert canonical in SCANNER_TAG_NAMES

    def test_no_alias_is_itself_a_shipped_scanner_name(self):
        for alias in SCANNER_NAME_ALIASES:
            assert alias not in SCANNER_TAG_NAMES


class TestTheConfigFold:
    def test_a_semgrep_section_reaches_the_opengrep_plugin(self, ash_log):
        config = AshConfig.model_validate(
            {
                "project_name": "alias-test",
                "scanners": {
                    "semgrep": {
                        "enabled": False,
                        "options": {"exclude_rule": ["generic.x"]},
                    }
                },
            }
        )

        dumped = config.scanners.model_dump(by_alias=True)
        assert "semgrep" not in dumped
        assert dumped["opengrep"]["enabled"] is False
        assert dumped["opengrep"]["options"]["exclude_rule"] == ["generic.x"]
        # The section the runtime lookup reads is the folded one.
        section = config.get_plugin_config("scanner", "opengrep")
        assert section["enabled"] is False
        assert any(
            "scanners.semgrep is an alias of the opengrep plugin" in m
            for m in _messages(ash_log)
        ), _messages(ash_log)

    def test_alias_only_options_are_dropped_with_a_warning(self, ash_log):
        segment = ScannerConfigSegment.model_validate(
            {
                "semgrep": {
                    "options": {
                        "tool_version": ">=1.0",
                        "install_timeout": 60,
                        "exclude": ["kept.py"],
                    }
                }
            }
        )

        options = segment.model_dump(by_alias=True)["opengrep"]["options"]
        assert options["exclude"] == ["kept.py"]
        assert "tool_version" not in options
        assert "install_timeout" not in options
        warnings = [
            m
            for r, m in zip(ash_log, _messages(ash_log))
            if r.levelno == logging.WARNING
        ]
        assert any("install_timeout" in m and "tool_version" in m for m in warnings), (
            warnings
        )

    def test_the_alias_section_overlays_a_canonical_one_key_by_key(self):
        """The alias side wins where both set the same key.

        The case that decides the direction is not a hand-written config (lint
        flags those): ``apply_config_overrides`` round-trips through
        ``model_dump()``, which emits the canonical section with every default
        filled in, so on any override run the canonical side is machine-written
        defaults and the alias side is what the operator wrote.
        """
        segment = ScannerConfigSegment.model_validate(
            {
                "semgrep": {
                    "enabled": False,
                    "options": {"exclude_rule": ["from.alias"]},
                },
                "opengrep": {"enabled": True},
            }
        )

        dumped = segment.model_dump(by_alias=True)
        assert dumped["opengrep"]["enabled"] is False, (
            "the alias section holds the operator's words and must win"
        )
        assert dumped["opengrep"]["options"]["exclude_rule"] == ["from.alias"], (
            "keys only the alias set still carry over"
        )

    def test_a_semgrep_override_survives_the_dump_round_trip(self):
        """`--config-overrides scanners.semgrep.enabled=false` must disable
        opengrep: apply_config_overrides round-trips through model_dump(), so
        the dumped opengrep defaults sit beside the override's semgrep section
        and must not overwrite it."""
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.config.resolve_config import (
            apply_config_overrides,
        )

        config = apply_config_overrides(
            AshConfig(project_name="alias-roundtrip"),
            ["scanners.semgrep.enabled=false"],
        )
        assert config.scanners.opengrep.enabled is False

    def test_an_unknown_extra_scanner_is_left_alone(self):
        """Control: the fold must not eat real third-party scanner sections."""
        segment = ScannerConfigSegment.model_validate({"myscanner": {"enabled": True}})
        assert "myscanner" in segment.model_dump(by_alias=True)

    def test_a_folded_config_round_trips_stably(self):
        first = ScannerConfigSegment.model_validate({"semgrep": {"enabled": False}})
        second = ScannerConfigSegment.model_validate(first.model_dump(by_alias=True))
        assert second.model_dump(by_alias=True)["opengrep"]["enabled"] is False


class TestTheCliNameResolution:
    def test_scanners_semgrep_selects_opengrep(self, ash_log):
        assert _resolve_scanner_name_aliases(["semgrep"]) == ["opengrep"]
        assert any("alias of the opengrep plugin" in m for m in _messages(ash_log)), (
            _messages(ash_log)
        )

    def test_other_names_and_order_are_kept(self):
        assert _resolve_scanner_name_aliases(["bandit", "semgrep", "syft"]) == [
            "bandit",
            "opengrep",
            "syft",
        ]

    def test_dependencies_install_takes_the_same_aliases(self):
        """`ashx dependencies install --tool semgrep` installs opengrep's tool,
        through the same case- and punctuation-insensitive lookup as every
        other entry point; the exact-name table stays for ArchiveConverter."""
        from automated_security_helper.cli.dependencies import (
            DEPRECATED_TOOL_ALIASES,
            _resolve_tool_aliases,
        )

        for alias, canonical in SCANNER_NAME_ALIASES.items():
            assert _resolve_tool_aliases([alias]) == {alias: canonical}
            spelled = alias.upper()
            assert _resolve_tool_aliases([spelled]) == {spelled: canonical}
        assert DEPRECATED_TOOL_ALIASES == {"ArchiveConverter": "archive"}
        assert _resolve_tool_aliases(["ArchiveConverter"]) == {
            "ArchiveConverter": "archive"
        }
        assert _resolve_tool_aliases(["bandit"]) == {"bandit": "bandit"}
