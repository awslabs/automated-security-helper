# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two extra sections of one plugin name: one is read, and the log says so.

``AshConfig.get_plugin_config`` indexes every section key under the spellings
``plugin_section_claims`` lists and reads the key spelled as the plugin's reduced
name if there is one, else the first key to claim the name. Keys claim in two
passes: a key whose name without punctuation is the plugin's first, one that is only
once its Converter, Scanner or Reporter word is removed after every such key. When
two extra scanner sections share a name (``snyk.code`` beside ``Snyk_Code``) the
other is never read, so the lookup logs a warning that names both keys and the one
it reads. A configuration warns once for each such pair. A lookup that names a key
exactly (``acme-sink``) is told only of the keys that claimed the name in the same
pass: ``acme-sink-reporter`` is another plugin, read by its own exact name, and
draws no warning. A lookup that names no key (``AcmeSinkReporter``) cannot tell
which plugin is meant, so it is told of every key it does not read.
"""

from __future__ import annotations

import logging

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()

SNYK_CODE = "snyk-code"

#: Two spellings of one extra scanner, in each order the file can write them.
ORDERS = [
    pytest.param(("snyk.code", "Snyk_Code"), id="dotted-first"),
    pytest.param(("Snyk_Code", "snyk.code"), id="underscored-first"),
]


@pytest.fixture
def ash_log():
    """Every message ASH's logger logs during the test, as (level, text)."""
    records: list = []

    class _Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append((record.levelno, record.getMessage()))

    handler = _Keep(level=logging.DEBUG)
    level_before = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level_before)


def _config(sections: dict) -> AshConfig:
    return AshConfig.model_validate({"project_name": "t", "scanners": sections})


def _shared_name_warnings(records) -> list:
    return [
        text
        for level, text in records
        if level == logging.WARNING and "name the same scanner" in text
    ]


@pytest.mark.parametrize("order", ORDERS)
def test_the_first_of_two_extra_sections_is_the_one_read(order):
    """The enabled section is the first one written, in either order."""
    first, second = order
    config = _config({first: {"enabled": True}, second: {"enabled": False}})

    assert config.get_plugin_config("scanner", SNYK_CODE)["enabled"] is True


@pytest.mark.parametrize("order", ORDERS)
def test_the_warning_names_both_keys_and_the_one_read(order, ash_log):
    first, second = order
    config = _config({first: {"enabled": True}, second: {"enabled": False}})

    config.get_plugin_config("scanner", SNYK_CODE)

    warnings = _shared_name_warnings(ash_log)
    assert len(warnings) == 1
    assert (
        f"scanners.{first} and scanners.{second} name the same scanner" in warnings[0]
    )
    assert f"Only scanners.{first} is read" in warnings[0]


def test_the_warning_is_made_once_for_a_configuration(ash_log):
    sections = {"snyk.code": {"enabled": True}, "Snyk_Code": {"enabled": False}}
    config = _config(sections)

    config.get_plugin_config("scanner", SNYK_CODE)
    config.get_plugin_config("scanner", SNYK_CODE)
    assert len(_shared_name_warnings(ash_log)) == 1

    _config(sections).get_plugin_config("scanner", SNYK_CODE)
    assert len(_shared_name_warnings(ash_log)) == 2


def test_the_warning_names_the_section_read_when_the_second_key_is_the_reduced_name(
    ash_log,
):
    """A key that is the reduced name itself is read before the first claimant."""
    config = _config({"Snyk_Code": {"enabled": True}, "snykcode": {"enabled": False}})

    read = config.get_plugin_config("scanner", SNYK_CODE)

    warnings = _shared_name_warnings(ash_log)
    assert read["enabled"] is False
    assert len(warnings) == 1
    assert "scanners.snykcode and scanners.Snyk_Code name the same" in warnings[0]
    assert "Only scanners.snykcode is read" in warnings[0]


def _config_of_reporters(sections: dict) -> AshConfig:
    return AshConfig.model_validate({"project_name": "t", "reporters": sections})


def _shared_reporter_warnings(records) -> list:
    return [
        text
        for level, text in records
        if level == logging.WARNING and "name the same reporter" in text
    ]


def test_two_reporters_that_differ_by_their_type_word_draw_no_warning(ash_log):
    """``acme-sink`` and ``acme-sink-reporter`` are two plugins that fold to one name
    only once the type word is stripped, and each is read by its exact name."""
    config = _config_of_reporters(
        {"acme-sink": {"enabled": True}, "acme-sink-reporter": {"enabled": False}}
    )

    first = config.get_plugin_config("reporter", "acme-sink")
    second = config.get_plugin_config("reporter", "acme-sink-reporter")

    assert first["enabled"] is True
    assert second["enabled"] is False
    assert _shared_reporter_warnings(ash_log) == []


def test_control_two_plain_spellings_of_a_reporter_still_draw_the_warning(ash_log):
    config = _config_of_reporters(
        {"acme.sink": {"enabled": True}, "Acme_Sink": {"enabled": False}}
    )

    config.get_plugin_config("reporter", "acme-sink")

    warnings = _shared_reporter_warnings(ash_log)
    assert len(warnings) == 1
    assert "Only reporters.acme.sink is read" in warnings[0]


def test_a_class_name_lookup_warns_of_every_section_it_does_not_read(ash_log):
    """A lookup by ``AcmeSinkReporter`` names no key, so it cannot tell which of the
    two plugins is meant. It reads ``acme-sink`` and says so about
    ``acme-sink-reporter``; only a lookup that names a key exactly is told that the
    other plugin reads its own section."""
    config = _config_of_reporters(
        {"acme-sink": {"enabled": True}, "acme-sink-reporter": {"enabled": False}}
    )

    read = config.get_plugin_config("reporter", "AcmeSinkReporter")

    warnings = _shared_reporter_warnings(ash_log)
    assert read["enabled"] is True
    assert len(warnings) == 1
    assert "reporters.acme-sink and reporters.acme-sink-reporter name" in warnings[0]
    assert "Only reporters.acme-sink is read" in warnings[0]


def test_a_reduced_name_lookup_warns_of_a_type_word_spelling_it_does_not_read(
    ash_log,
):
    config = _config({"snyk.code": {"enabled": True}, "snyk-code-scanner": {}})

    config.get_plugin_config("scanner", "SnykCodeScanner")

    warnings = _shared_name_warnings(ash_log)
    assert len(warnings) == 1
    assert "scanners.snyk.code and scanners.snyk-code-scanner name" in warnings[0]


def test_control_one_section_of_a_scanner_draws_no_warning(ash_log):
    config = _config({"Snyk_Code": {"enabled": True}})

    config.get_plugin_config("scanner", SNYK_CODE)

    assert _shared_name_warnings(ash_log) == []


def test_control_two_different_extra_scanners_draw_no_warning(ash_log):
    config = _config({"Snyk_Code": {"enabled": True}, "snyk-other": {"enabled": True}})

    config.get_plugin_config("scanner", SNYK_CODE)
    config.get_plugin_config("scanner", "snyk-other")

    assert _shared_name_warnings(ash_log) == []
