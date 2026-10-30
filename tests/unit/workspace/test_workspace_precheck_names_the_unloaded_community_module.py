# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace pre-check refuses an unloaded community scanner in the engine's words.

Why this file exists
--------------------
``refuse_unresolvable_scanner_selection`` refuses a ``--scanners`` selection no
project could run before any project starts, with the builders the engine and
the scan phase share, so the three refuse in the same words. One of those
builders was missing here: a request naming a community scanner ASH ships whose
plugin module this run did not load (``--scanners snyk-code`` without
``ash_snyk_plugins`` listed) was refused as a spelling error, while the engine
and the scan phase name the module to add
(``core.scanner_selection.community_scanner_refusal``). The operator read the
workspace refusal, checked a name that was right, and got the module hint only
from a single scan.

The contract these cases pin:

- the workspace pre-check's text for such a request is byte for byte the text
  ``community_scanner_refusal`` builds from the same inputs, so it names the
  module and reads as the engine's;
- a misspelled name requested beside it is named in the same refusal;
- a request that resolves to a declared scanner is not refused (control), and a
  request that names no community scanner keeps the spelling refusal (control).
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.exceptions import ScannerSelectionError
from automated_security_helper.core.scanner_selection import (
    community_scanner_refusal,
)
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    refuse_unresolvable_scanner_selection,
)
from tests.unit.workspace.test_execution import _make_workspace

pytestmark = pytest.mark.unit


class _NameField:
    default = "bandit"


class _NamedConfig:
    model_fields = {"name": _NameField()}


class _ConfigField:
    annotation = _NamedConfig


class _NamedScanner:
    """Declares its name the way a scanner's own config class does; its module
    is this test's, so no community module counts as loaded through it."""

    model_fields = {"config": _ConfigField()}


@pytest.fixture
def one_declared_scanner(monkeypatch):
    """The registry read of the pre-check sees one declared scanner, ``bandit``."""

    def plugin_modules(plugin_type, filter_callback=None):
        assert plugin_type == "scanner"
        return [_NamedScanner]

    monkeypatch.setattr(ash_plugin_manager, "plugin_modules", plugin_modules)
    return [_NamedScanner]


def _precheck(tmp_path, *requested):
    _, plan = _make_workspace(tmp_path, ("api", "MEDIUM"))
    settings = ProjectScanSettings(
        output_dir=tmp_path / "out", enabled_scanners=tuple(requested)
    )
    refuse_unresolvable_scanner_selection(plan, settings)


def test_an_unloaded_community_scanner_is_refused_in_the_engines_words(
    tmp_path, one_declared_scanner
):
    with pytest.raises(ScannerSelectionError) as refused:
        _precheck(tmp_path, "snyk-code")

    text = str(refused.value)
    assert text == community_scanner_refusal(
        ["snyk-code"], ["bandit"], one_declared_scanner
    )
    assert "community scanner" in text
    assert "ash_snyk_plugins" in text
    assert "--ash-plugin-modules" in text
    assert "check the spelling" not in text


def test_a_misspelled_name_is_named_beside_the_unloaded_community_scanner(
    tmp_path, one_declared_scanner
):
    with pytest.raises(ScannerSelectionError) as refused:
        _precheck(tmp_path, "snyk-code", "bandt")

    text = str(refused.value)
    assert "ash_snyk_plugins" in text
    assert "bandt" in text
    assert "check the spelling" in text


def test_a_declared_name_beside_an_unloaded_community_scanner_is_not_refused(
    tmp_path, one_declared_scanner
):
    """Control: the request resolves to something; each project's scan phase
    warns about the rest."""
    _precheck(tmp_path, "bandit", "snyk-code")


def test_a_name_that_is_no_community_scanner_keeps_the_spelling_refusal(
    tmp_path, one_declared_scanner
):
    """Control: the other builder still answers for a plain misspelling."""
    with pytest.raises(ScannerSelectionError) as refused:
        _precheck(tmp_path, "no-such-scanner")

    assert "community scanner" not in str(refused.value)
