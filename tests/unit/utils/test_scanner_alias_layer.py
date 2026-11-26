# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The retired-scanner alias layer: one table, one lookup, one comparison key.

``SCANNER_NAME_ALIASES`` is empty today -- no shipped scanner is retired -- so
every live behavior is unchanged: ``canonical_scanner_name`` answers the name
it was given and ``selection_key`` is strip-then-lower. These tests pin the
mechanism itself by patching one alias row in, so the day a retirement adds a
real row, the row is the whole change: the config fold, the scan phase's
resolution and the dependencies tool lookup are already wired through the
table. Adapted from the v4 program (#981), whose table carried a live row.
"""

import logging

import pytest

from automated_security_helper.utils import scanner_names
from automated_security_helper.utils.scanner_names import (
    SCANNER_NAME_ALIASES,
    canonical_scanner_name,
    selection_key,
)

pytestmark = pytest.mark.unit


def test_the_table_is_empty_until_a_scanner_is_retired():
    assert SCANNER_NAME_ALIASES == {}


@pytest.mark.parametrize(
    "typed, key",
    [
        ("Bandit", "bandit"),
        (" bandit ", "bandit"),
        ("OpenGrep", "opengrep"),
        ("cfn-nag", "cfn-nag"),
    ],
)
def test_the_key_strips_and_lowers_with_an_empty_table(typed, key):
    assert selection_key(typed) == key


@pytest.fixture
def retired_oldname(monkeypatch):
    """One synthetic retirement: ``oldname`` is served by the bandit plugin."""
    monkeypatch.setitem(scanner_names.SCANNER_NAME_ALIASES, "oldname", "bandit")
    return "oldname"


@pytest.mark.parametrize("spelling", ["oldname", "Old-Name", " old_name ", "OLDNAME"])
def test_a_retired_name_resolves_in_any_spelling(retired_oldname, spelling):
    assert canonical_scanner_name(spelling.strip()) == "bandit"
    assert selection_key(spelling) == "bandit"


def test_an_unretired_name_answers_itself_in_the_callers_spelling(retired_oldname):
    assert canonical_scanner_name("Checkov") == "Checkov"


def test_a_retired_name_and_its_replacement_share_a_key(retired_oldname):
    assert selection_key("Old-Name") == selection_key("bandit")


def test_the_scan_phase_resolves_and_logs_the_mapping(retired_oldname, caplog):
    from automated_security_helper.core.phases.scan_phase import (
        _resolve_scanner_name_aliases,
    )

    with caplog.at_level(logging.INFO, logger="ash"):
        resolved = _resolve_scanner_name_aliases(["oldname", "checkov"])
    assert resolved == ["bandit", "checkov"]
    assert any(
        "oldname is an alias of the bandit plugin" in record.getMessage()
        for record in caplog.records
    )


def test_the_dependencies_tool_lookup_resolves_a_retired_name(retired_oldname):
    from automated_security_helper.cli.dependencies import _resolve_tool_aliases

    assert _resolve_tool_aliases(["Oldname"])["Oldname"] == "bandit"


def test_the_dependencies_tool_lookup_still_passes_unknown_names_through():
    from automated_security_helper.cli.dependencies import _resolve_tool_aliases

    assert _resolve_tool_aliases(["no-such-tool"])["no-such-tool"] == "no-such-tool"


def test_the_config_fold_applies_a_retired_section_to_the_serving_plugin(
    retired_oldname, caplog
):
    from automated_security_helper.config.ash_config import ScannerConfigSegment

    with caplog.at_level(logging.INFO, logger="ash"):
        segment = ScannerConfigSegment.model_validate(
            {"oldname": {"name": "oldname", "enabled": False}}
        )
    assert segment.bandit.enabled is False
    # The alias section never lands in the extra="allow" bucket as an unknown
    # third-party scanner, and its name literal does not reach the fold target.
    assert "oldname" not in (segment.__pydantic_extra__ or {})
    assert str(segment.bandit.name) == "bandit"
    assert any(
        "scanners.oldname is an alias of the bandit plugin" in record.getMessage()
        for record in caplog.records
    )


def test_the_fold_drops_options_the_serving_plugin_does_not_declare(
    retired_oldname, caplog
):
    from automated_security_helper.config.ash_config import ScannerConfigSegment

    with caplog.at_level(logging.WARNING, logger="ash"):
        segment = ScannerConfigSegment.model_validate(
            {"oldname": {"enabled": True, "options": {"retired_only_knob": 5}}}
        )
    assert segment.bandit.enabled is True
    assert not hasattr(segment.bandit.options, "retired_only_knob")
    assert any(
        "retired_only_knob" in record.getMessage() and "dropped" in record.getMessage()
        for record in caplog.records
    )


def test_the_operators_alias_section_wins_over_the_canonical_defaults(retired_oldname):
    from automated_security_helper.config.ash_config import ScannerConfigSegment

    segment = ScannerConfigSegment.model_validate(
        {"bandit": {"enabled": True}, "oldname": {"enabled": False}}
    )
    assert segment.bandit.enabled is False


def test_without_a_table_row_the_fold_changes_nothing():
    from automated_security_helper.config.ash_config import ScannerConfigSegment

    segment = ScannerConfigSegment.model_validate({"bandit": {"enabled": False}})
    assert segment.bandit.enabled is False
