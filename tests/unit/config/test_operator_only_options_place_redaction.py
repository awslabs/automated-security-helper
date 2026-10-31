# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``redacted_places`` hides a place's key, never the fixed words around it.

A place string is ``reporters.<key>.options.<option>`` (or ``reporters.<key>``).
Only the key is built from the configuration's own text, so only the key is
searched for the section keys the configuration read from the environment. A
short key read elsewhere in the configuration must not hide ``options`` or a
word of an option's name.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.operator_only_options import redacted_places

pytestmark = pytest.mark.unit

PLACE = "reporters.aws-security-hub.options.findings_scope"


@pytest.mark.parametrize("short_key", ["scope", "findings", "options", "reporters"])
def test_a_short_key_read_elsewhere_leaves_the_fixed_words_whole(short_key):
    """The environment gave some other section the key ``short_key``, which is
    also a word of this place. The place's own key does not contain it."""
    assert redacted_places(PLACE, [short_key]) == PLACE


def test_the_key_of_a_place_is_hidden_and_the_option_name_is_not():
    shown = redacted_places("reporters.scope.options.findings_scope", ["scope"])

    assert shown.startswith("reporters.")
    assert shown.endswith(".options.findings_scope")
    assert "reporters.scope." not in shown


@pytest.mark.parametrize("read_as", ["aws-security-hub", "aws_security_hub"])
def test_a_key_is_hidden_in_either_separator_spelling(read_as):
    shown = redacted_places(PLACE, [read_as])

    assert "security" not in shown
    assert shown.endswith(".options.findings_scope")


def test_each_place_of_a_list_is_read_by_its_own_key():
    text = (
        "reporters.alpha.options.findings_scope, "
        "scanners.beta.options.max_worker_output_mib, reporters.gamma"
    )

    shown = redacted_places(text, ["alpha", "gamma"])

    assert "alpha" not in shown
    assert "gamma" not in shown
    assert "scanners.beta.options.max_worker_output_mib" in shown
    assert ".options.findings_scope, scanners." in shown


def test_text_that_is_not_a_place_is_searched_whole():
    assert "alpha" not in redacted_places("see alpha here", ["alpha"])
