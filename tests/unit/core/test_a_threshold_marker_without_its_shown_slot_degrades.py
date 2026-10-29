# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The shown form of an env-read threshold, when the marker lacks its shown slot.

An external scanner section's ``severity_threshold`` read from the environment
is an ``EnvResolvedScalar``. Its ``shown`` slot holds the form a summary row
prints in the value's place: the reference without its default (a glued tail
kept) when the variable was read, or the default's own text when the default
was used. It is not the reference as the file wrote it, which is what
``EnvironmentReference.written`` holds. A marker restored from older state has
no ``shown`` slot, and the calculator must not raise AttributeError over it: it
shows the bare reference rebuilt from the variable's name, and grades by the
resolved text as before.

The copy protocols keep the slots (copy, deepcopy and pickle carry them), so
the only way to the slotless marker is to delete a slot, which is what the
degrade cells do. The marker also carries ``from_environment``: False when the
reference's default supplied the text, in which case the row shows the graded
level and not a reference, and a marker without that slot reads as read. The
cells that keep the slots are the must-not-flag controls: they pin that a shown
form the bare name could not rebuild (a glued tail, a used default's text) is
carried as it is.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.utils.redacted_model import (
    EnvResolvedScalar,
    env_resolved_scalar,
)

VARIABLE = "ASH_DEGRADE_SEV"
SCANNER = "zz-ext-scanner"


def _config_with_external_scanner(threshold_value):
    return AshConfig.model_validate(
        {
            "project_name": "zz-degrade",
            "scanners": {
                SCANNER: {
                    "enabled": True,
                    "options": {"severity_threshold": threshold_value},
                }
            },
        }
    )


def _full_resolution(config):
    """(grading value, shown form, source, read from the environment)."""
    return ScannerStatisticsCalculator._threshold_resolution(
        SimpleNamespace(ash_config=config), SCANNER
    )


def _resolution(config):
    """(grading value, shown form, source); the fourth element, the from-env
    provenance flag, is read by ``_full_resolution``."""
    return _full_resolution(config)[:3]


@pytest.fixture
def holding(monkeypatch):
    """Make the calculator read exactly this marker for the scanner's threshold.

    The calculator asks the config for the scanner's entry on every read, and a
    config may hand back a copy; serving the entry from here keeps the marker the
    cell shaped (a deleted slot, say) the one the calculator sees.
    """

    def _hold(marker):
        entry = {"options": {"severity_threshold": marker}}
        monkeypatch.setattr(
            AshConfig,
            "get_plugin_config",
            lambda self, plugin_type, plugin_name: entry,
        )
        return _config_with_external_scanner("MEDIUM")

    return _hold


def test_a_marker_without_its_shown_slot_is_the_premise():
    marker = env_resolved_scalar("MEDIUM", VARIABLE)
    assert hasattr(marker, "shown")
    del marker.shown
    assert not hasattr(marker, "shown")
    assert isinstance(marker, EnvResolvedScalar) and marker == "MEDIUM"


def test_a_marker_without_its_shown_slot_shows_the_rebuilt_name(holding):
    marker = env_resolved_scalar("MEDIUM", VARIABLE)
    del marker.shown
    assert not hasattr(marker, "shown")

    threshold, shown, source = _resolution(holding(marker))

    assert (threshold, shown, source) == ("MEDIUM", "${" + VARIABLE + "}", "config")
    assert type(threshold) is str and type(shown) is str


def test_a_marker_with_its_shown_slot_shows_what_the_slot_holds(holding):
    """The must-not-flag control: the degrade is only for the missing slot."""
    marker = env_resolved_scalar("MEDIUM", VARIABLE, "${" + VARIABLE + "}tail")

    threshold, shown, source = _resolution(holding(marker))

    assert (threshold, shown, source) == (
        "MEDIUM",
        "${" + VARIABLE + "}tail",
        "config",
    )


def test_a_marker_that_used_its_default_shows_the_graded_level(holding):
    """``${VAR:LOW}`` with the variable unset resolves to its default, which is
    the file's own level: the resolver's marker shows that level and says it was
    not read from the environment, so the row shows what is graded."""
    marker = env_resolved_scalar("LOW", VARIABLE, "LOW", from_environment=False)

    resolution = _full_resolution(holding(marker))

    assert resolution == ("LOW", "LOW", "config", False)


def test_a_marker_without_its_from_environment_slot_reads_as_environment(holding):
    """A marker restored from older state has no ``from_environment`` slot
    either; the calculator takes it as read, as a marker built from the name
    alone is, and shows the kept form."""
    marker = env_resolved_scalar("MEDIUM", VARIABLE, "${" + VARIABLE + "}tail")
    del marker.from_environment
    assert not hasattr(marker, "from_environment")

    resolution = _full_resolution(holding(marker))

    assert resolution == ("MEDIUM", "${" + VARIABLE + "}tail", "config", True)


def test_a_marker_without_either_slot_degrades_to_the_rebuilt_name(holding):
    marker = env_resolved_scalar("MEDIUM", VARIABLE)
    del marker.shown
    del marker.from_environment

    resolution = _full_resolution(holding(marker))

    assert resolution == ("MEDIUM", "${" + VARIABLE + "}", "config", True)
