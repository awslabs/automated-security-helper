# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``section_enabled`` reads a text ``enabled`` the way a bool field would, not by truthiness.

An external plugin's config section is kept without validation, so ``enabled``
can arrive as text (the value of an environment reference). ``bool("false")`` is
true, so a section that said ``enabled: !ENV ${SCAN_X:false}`` left the plugin on.
A spelling of false now disables it; an empty string stays off; text that is no
spelling of false leaves the plugin enabled, because a scanner that silently does
not run is the worse error.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_config import section_enabled

pytestmark = pytest.mark.unit


class _Model:
    def __init__(self, enabled):
        self.enabled = enabled


@pytest.mark.parametrize(
    "text",
    ["false", "False", " FALSE ", "no", "n", "off", "f", "0", "", "  ", "\t\n"],
)
def test_a_text_spelling_of_false_disables_the_plugin(text):
    assert section_enabled({"enabled": text}) is False
    assert section_enabled(_Model(text)) is False


@pytest.mark.parametrize("text", ["true", "True", "yes", "on", "1", "maybe"])
def test_any_other_text_leaves_the_plugin_enabled(text):
    assert section_enabled({"enabled": text}) is True
    assert section_enabled(_Model(text)) is True


def test_a_real_bool_and_the_defaults_are_unchanged():
    assert section_enabled(None) is True
    assert section_enabled({}) is True
    assert section_enabled({"enabled": True}) is True
    assert section_enabled({"enabled": False}) is False
    assert section_enabled(_Model(False)) is False
    assert section_enabled({"enabled": 0}) is False
