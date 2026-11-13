# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The bundled ferret-scan config turns ``show_match`` off everywhere.

With ``show_match`` on, ferret-scan writes each matched value into its own
results file and log. ASH masks the values in its reports
(``test_ferret_matches_are_masked_in_reports.py``), but not in the scanner's own
output, so no profile ASH ships turns it on: choosing a bundled profile must not
put matched values on disk.
"""

import pytest
import yaml

from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    DEFAULT_FERRET_CONFIG,
)

pytestmark = pytest.mark.unit


def _bundled():
    return yaml.safe_load(DEFAULT_FERRET_CONFIG.read_text(encoding="utf-8"))


def test_the_default_settings_hide_matches():
    assert _bundled()["defaults"]["show_match"] is False


def test_no_bundled_profile_shows_matches():
    profiles = _bundled()["profiles"]

    shown = sorted(
        name
        for name, profile in profiles.items()
        if (profile or {}).get("show_match") is not False
        and "show_match" in (profile or {})
    )
    assert shown == []


def test_the_profiles_that_used_to_show_matches_still_set_the_key():
    """So the setting reads as decided rather than inherited."""
    profiles = _bundled()["profiles"]

    for name in (
        "comprehensive",
        "json-api",
        "debug",
        "person-name",
        "enhanced-metadata",
        "social-media",
    ):
        assert profiles[name]["show_match"] is False, name
