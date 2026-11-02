# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A never-validated raw section's values present as the types the file gave.

An external plugin's config section is kept by the segment models as an extra
and never validated, so a value a config file read from the environment is
still the resolver's marker (``utils/redacted_model.EnvResolvedScalar``, a str
subclass) when a consumer reads the section directly. A consumer that formats
or stores such a value takes the downcast view (``without_env_scalars``), so a
message names the type the file gave -- a str -- and never the marker class,
and no marker escapes into a data structure a tool answer carries.

These cells pin the two direct consumers the measurement found, at the unit
level; ``test_not_enabled_warning_quotes_no_env_value.py`` pins the warning on
a real scan's console and logs.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from automated_security_helper.base.reporter_plugin import (
    enabled_value_kind,
    reset_unenabled_off_host_section_warnings,
    warn_off_host_section_without_enabled,
)
from automated_security_helper.core.phases.report_phase import (
    _warn_if_configured_but_not_enabled,
)
from automated_security_helper.core.scanner_inventory import describe_scanner
from automated_security_helper.utils.redacted_model import env_resolved_scalar

pytestmark = pytest.mark.unit

CANARY = "ash-canary-zq9"
VARIABLE = "ASH_ENABLED_CANARY"


class _OffHostReporter:
    """A reporter class shape the warning helper reads: a config key comes from
    the class name (``plugin_config_key``), and an empty requested-format list
    selects every reporter (``reporter_matches_requested_formats``). It sends
    findings off the host, as the reporters this warning is for do."""

    sends_off_host = True


def test_the_warning_names_the_base_type_of_an_env_read_value(caplog):
    section = {"enabled": env_resolved_scalar(CANARY, VARIABLE)}

    with caplog.at_level(logging.WARNING):
        _warn_if_configured_but_not_enabled(_OffHostReporter(), section, [])

    # The control: the warning fired, naming the key.
    assert "is not run" in caplog.text, caplog.text
    assert "sets enabled to a str" in caplog.text, caplog.text
    # Never the marker class, and never the value it carries.
    assert "EnvResolvedScalar" not in caplog.text, caplog.text
    assert CANARY not in caplog.text, caplog.text


def test_the_warning_still_names_a_real_non_string_type(caplog):
    """The must-not-flag control: the view changes nothing for a value the
    file wrote directly, so a number is still named as one."""
    with caplog.at_level(logging.WARNING):
        _warn_if_configured_but_not_enabled(_OffHostReporter(), {"enabled": 7}, [])

    assert "sets enabled to an int" in caplog.text, caplog.text


@pytest.mark.parametrize(
    "value",
    [7, 1.5, "yes", None, ["true"], env_resolved_scalar(CANARY, VARIABLE)],
    ids=["int", "float", "str", "null", "list", "env-read-str"],
)
def test_the_two_warnings_name_the_type_in_the_same_words(caplog, value):
    """The report phase and the shared reporter warning name the type
    ``enabled`` was set to through one helper, so the article and the marker
    class cannot drift between them ("a int" against "an int", or the marker's
    own name in one)."""
    reset_unenabled_off_host_section_warnings()
    section = {"enabled": value}
    with caplog.at_level(logging.WARNING):
        _warn_if_configured_but_not_enabled(_OffHostReporter(), section, [])
        phase_text = caplog.text
        caplog.clear()
        reset_unenabled_off_host_section_warnings()
        warn_off_host_section_without_enabled(_OffHostReporter, section)
        shared_text = caplog.text
    reset_unenabled_off_host_section_warnings()

    expected = f"sets enabled to {enabled_value_kind(value)},"
    assert expected in phase_text, phase_text
    assert expected in shared_text, shared_text
    for text in (phase_text, shared_text):
        assert "EnvResolvedScalar" not in text, text
        assert CANARY not in text, text


class _InventoryScanner:
    """The smallest scanner ``describe_scanner`` can ask about itself."""

    offline_strategy = None

    def __init__(self, context):
        self.config = SimpleNamespace(name="fake-scanner", enabled=True)

    def validate_plugin_dependencies(self):
        return False


def test_the_inventory_entry_shows_an_env_read_enabled_as_its_reference():
    """The entry is data a tool answer carries, so a value the file read from
    the environment is reported as its reference spelling, never by value:
    the downcast view strips the marker TYPE but keeps the TEXT, and the text
    came from the environment."""
    marker = env_resolved_scalar(CANARY, VARIABLE)
    default_config = SimpleNamespace(
        get_plugin_config=lambda plugin_type, plugin_name: {"enabled": marker}
    )

    entry = describe_scanner(
        _InventoryScanner, context=None, default_config=default_config
    )

    assert CANARY not in str(entry["enabled"]), entry
    assert entry["enabled"] == "${" + VARIABLE + "}", entry
    # Still a plain str, not the marker: a str subclass fails any later
    # SafeDumper write.
    assert type(entry["enabled"]) is str, type(entry["enabled"]).__name__


def test_the_inventory_entry_keeps_a_directly_written_enabled():
    """The must-not-flag control: a value the file wrote directly is not an
    environment read, so it passes through unchanged."""
    default_config = SimpleNamespace(
        get_plugin_config=lambda plugin_type, plugin_name: {"enabled": False}
    )

    entry = describe_scanner(
        _InventoryScanner, context=None, default_config=default_config
    )

    assert entry["enabled"] is False, entry
