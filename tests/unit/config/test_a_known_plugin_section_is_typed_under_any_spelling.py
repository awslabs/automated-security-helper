# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A section naming a known plugin is typed whatever its spelling.

The scanner, reporter and converter segments allow extra sections for plugins
ASH does not ship. A section whose name is a known plugin's under another
spelling (case, separators) landed there: unvalidated, so a value the
canonical spelling refuses (a string scan_timeout, an env reference) loaded
into the extras copy, and a lookup by class name could reach it while the
construction lookup by the canonical key got the defaults.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from automated_security_helper.config.ash_config import AshConfig

SPELLINGS = ["cdk-nag", "cdk_nag", "CdkNag", "CDK-NAG", "cdknag"]


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_a_string_scan_timeout_is_refused_under_any_spelling(spelling):
    """What the canonical spelling refuses, every spelling refuses: a string
    where strict typing wants an integer."""
    with pytest.raises(ValidationError):
        AshConfig.model_validate(
            {
                "project_name": "t",
                "scanners": {spelling: {"options": {"scan_timeout": "67"}}},
            },
            strict=True,
        )


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_a_section_under_any_spelling_reaches_the_plugin_field(spelling):
    """The section's values land on the declared field, not an extras copy."""
    config = AshConfig.model_validate(
        {"project_name": "t", "scanners": {spelling: {"enabled": False}}},
        strict=True,
    )

    assert config.scanners.cdk_nag.enabled is False
    assert spelling not in (config.scanners.model_extra or {}), (
        config.scanners.model_extra
    )


def test_an_unknown_section_stays_an_extra():
    """Control: a section naming no known plugin keeps the extras path, where
    a plugin ASH does not ship reads its own config."""
    config = AshConfig.model_validate(
        {"project_name": "t", "scanners": {"my-scanner": {"enabled": False}}},
        strict=True,
    )

    assert "my-scanner" in (config.scanners.model_extra or {})
