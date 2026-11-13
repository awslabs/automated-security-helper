# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One function says which section key a reduced plugin name reads.

``plugin_section_lookup`` tries the caller's own spelling as a key first. When that
is not a key it reads the key spelled as the reduced name, and failing that the
first key to claim the name (``plugin_section_claims``). ``plugin_section_key`` is
those last two steps, so a reader that must agree with the lookup, such as the
workspace plan's scanner list, asks it instead of repeating the rule.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig, plugin_section_key

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()

SNYK_CODE = "snyk-code"


@pytest.mark.parametrize(
    "keys, reduced, expected",
    [
        pytest.param(["Snyk_Code", "snykcode"], "snykcode", "snykcode", id="literal"),
        pytest.param(
            ["snyk.code", "Snyk_Code"], "snykcode", "snyk.code", id="first-claimant"
        ),
        pytest.param(
            ["snyk-code-scanner", "snyk.code"], "snykcode", "snyk.code", id="two-pass"
        ),
        pytest.param(["snyk-other"], "snykcode", None, id="no-claimant"),
        pytest.param(["snyk-other"], "", None, id="empty-name"),
    ],
)
def test_the_key_read_for_a_reduced_name(keys, reduced, expected):
    """The key spelled as the reduced name, else the first key to claim it: a
    plain spelling written later outranks a type-word spelling written earlier."""
    assert plugin_section_key(keys, reduced) == expected


@pytest.mark.parametrize(
    "sections",
    [
        pytest.param(
            {"Snyk_Code": {"enabled": False}, "snykcode": {"enabled": True}},
            id="literal-second",
        ),
        pytest.param(
            {"snyk-code-scanner": {"enabled": False}, "snyk.code": {"enabled": True}},
            id="plain-spelling-second",
        ),
    ],
)
def test_the_lookup_reads_the_key_the_function_names(sections):
    config = AshConfig.model_validate({"project_name": "t", "scanners": sections})

    key = plugin_section_key(list(sections), "snykcode")
    read = config.get_plugin_config("scanner", SNYK_CODE)

    assert read["enabled"] is sections[key]["enabled"]
    assert read["enabled"] is True
