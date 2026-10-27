# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A declared scanner's section is the one every name of its plugin reads.

``AshConfig.get_plugin_config`` finds a section by the name the caller passes:
the config key as written, or a reduced spelling of it (``reduced_plugin_name``:
ASCII case, the Converter, Scanner or Reporter word and every character outside
``[a-z0-9+]`` dropped). A declared scanner can have another spelling of its name
beside it, ``detect.secrets`` beside ``detect-secrets``. The exact key is read
for the exact name; a caller that passes the Python field name, the class name
or the reduced name reaches the section through an index of reduced spellings,
and that index has to give the declared key the spelling it shares with the
extra one. These tests look the section up under each of those names and expect
the declared section every time.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import (
    AshConfig,
    plugin_section_lookup,
)

AshConfig.model_rebuild()

DECLARED = "detect-secrets"
BESIDE = "detect.secrets"

#: Every name a caller can look the declared scanner up by. The config key is
#: the control: it is read by an exact match, so it never reaches the index.
NAMES = [
    pytest.param("detect-secrets", id="config-key"),
    pytest.param("detect_secrets", id="python-field-name"),
    pytest.param("DetectSecretsScanner", id="class-name"),
    pytest.param("DetectSecrets", id="class-name-without-the-type-word"),
    pytest.param("detectsecrets", id="reduced-name"),
]

#: The same two sections written in each order. ``model_dump`` lists the declared
#: field before an extra whatever order the config file wrote them in.
SECTIONS = [
    pytest.param(
        {DECLARED: {"enabled": True}, BESIDE: {"enabled": False}},
        id="spelling-written-last",
    ),
    pytest.param(
        {BESIDE: {"enabled": False}, DECLARED: {"enabled": True}},
        id="spelling-written-first",
    ),
]


@pytest.mark.parametrize("sections", SECTIONS)
@pytest.mark.parametrize("name", NAMES)
def test_every_name_of_the_plugin_reads_the_declared_section(sections, name):
    config = AshConfig.model_validate({"project_name": "t", "scanners": sections})

    read = config.get_plugin_config("scanner", name)

    assert read is not None
    assert read["enabled"] is True


@pytest.mark.parametrize("name", NAMES)
def test_a_plain_dump_gives_a_spelling_to_the_key_listed_first(name):
    """``resolve_config`` looks a section up in a merged dump that is not a model,
    where the key order is the dump's own. The first key to claim a reduced
    spelling keeps it, so a declared key listed before its respelling keeps it."""
    sections = {DECLARED: {"enabled": True}, BESIDE: {"enabled": False}}

    assert plugin_section_lookup(sections, "scanner", name, []) is sections[DECLARED]
