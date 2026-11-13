# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``plugin_section_peers`` splits the keys that claim one reduced name by rank.

``plugin_section_claims`` lets a key claim a plugin's reduced name in two passes: the
key as written, or with punctuation removed, in the first, and only once its
Converter, Scanner or Reporter word is removed as well in the second. The keys of
the rank of the key a lookup read are that plugin's other spellings; the keys of the
other rank are other plugins, each read by its own exact name. The configuration's
warning takes the split from this function, and so does the workspace plan when it
groups the sections of a scanner; the plan then returns its twins by reduced name,
the keys of both ranks together.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import (
    plugin_section_claims,
    plugin_section_peers,
)

pytestmark = pytest.mark.unit

ACME = ["acme-sink", "acme-sink-reporter", "Acme_Sink"]


@pytest.mark.parametrize(
    "read, expected",
    [
        pytest.param("acme-sink", ["Acme_Sink"], id="first-pass-key"),
        pytest.param("Acme_Sink", ["acme-sink"], id="other-first-pass-key"),
        pytest.param("acme-sink-reporter", [], id="type-word-key"),
    ],
)
def test_the_peers_of_a_key_are_the_other_keys_of_its_rank(read, expected):
    claims = plugin_section_claims(ACME)

    assert plugin_section_peers(claims, read, "acmesink") == expected


def test_two_type_word_keys_are_peers_of_each_other():
    claims = plugin_section_claims(["acme-sink-reporter", "acme_sink_reporter"])

    assert plugin_section_peers(claims, "acme-sink-reporter", "acmesink") == [
        "acme_sink_reporter"
    ]


def test_a_name_no_key_claims_has_no_peers():
    claims = plugin_section_claims(ACME)

    assert plugin_section_peers(claims, "acme-sink", "other") == []
