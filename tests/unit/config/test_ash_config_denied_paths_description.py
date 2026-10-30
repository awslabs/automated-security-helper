# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The published ``denied_paths`` description names every plugin section ASH
always denies.

The description lists the sections of the plugins that send data off the host,
which ``ALWAYS_DENIED_PATHS`` adds to every ``denied_paths`` list whatever a
profile writes. It named the s3, aws-security-hub, cloudwatch-logs and
bedrock-summary-reporter reporters and six scanners, and left out trivy and
zizmor, which the constant denies too, so an operator reading the schema was
told a client could still configure them. Red at the base: trivy and zizmor
were missing from the description.
"""

from __future__ import annotations

import re

import pytest

from automated_security_helper.config.ash_config import (
    ALWAYS_DENIED_PATHS,
    RuntimeOverridesConfig,
)

pytestmark = pytest.mark.unit

_WHOLE_SECTION = re.compile(r"^/(scanners|reporters)/([^/*]+)/\*\*$")


def _always_denied_sections() -> list:
    found = []
    for entry in ALWAYS_DENIED_PATHS:
        matched = _WHOLE_SECTION.match(entry)
        if matched:
            found.append(matched.group(2))
    return found


def test_the_premise_the_constant_denies_whole_plugin_sections():
    sections = _always_denied_sections()

    assert "trivy" in sections and "zizmor" in sections, sections
    assert "s3" in sections, sections


def test_the_description_names_every_always_denied_plugin_section():
    description = RuntimeOverridesConfig.model_fields["denied_paths"].description
    named = set(re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)*", description))

    missing = [name for name in _always_denied_sections() if name not in named]

    assert missing == [], missing
