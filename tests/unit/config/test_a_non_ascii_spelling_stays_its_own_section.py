# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The spelling fold reads ASCII only, and the deny respelling reads the same.

``folded_section_name`` decides which spellings of a known plugin's section are
one name. The runtime-patch deny policy decides which spellings of a plugin's
path a denial covers (``plugin_key_lookup_names``). The two have to agree:
a spelling the fold reads as detect-secrets' section but the deny does not
cover is a denied write under a spelling the policy cannot see. Unicode case
rules split them: ``casefold`` reads the long s (U+017F) as ``s`` while the
deny's lowering does not, so the fold is ASCII-only and the deny's lowering
goes through it. A non-ASCII spelling stays its own section, an unknown extra.
"""

import pytest

from automated_security_helper.config.ash_config import (
    AshConfig,
    plugin_key_lookup_names,
    reduced_plugin_name,
)
from automated_security_helper.config.plugin_section_names import folded_section_name
from automated_security_helper.config.runtime_patch import _denied_path_reason

# "detect-ſecrets": the long s casefolds to "s" but is not an ASCII letter.
LONG_S = "detect-ſecrets"
ASCII_SPELLINGS = [
    "DetectSecrets",
    "detect_secrets",
    "DETECT-SECRETS",
    "Detect_Secrets",
]


def test_the_fold_is_ascii_only():
    assert folded_section_name(LONG_S) != folded_section_name("detect-secrets")
    for spelling in ASCII_SPELLINGS:
        assert folded_section_name(spelling) == folded_section_name("detect-secrets")


@pytest.mark.parametrize("where", ["model", "document"])
def test_a_long_s_spelling_stays_an_extra(tmp_path, monkeypatch, where):
    if where == "model":
        config = AshConfig.model_validate(
            {"project_name": "t", "scanners": {LONG_S: {"enabled": False}}},
            strict=True,
        )
    else:
        from automated_security_helper.config.resolve_config import (
            load_config_file_for_run,
        )

        monkeypatch.delenv("ASH_CONFIG", raising=False)
        path = tmp_path / "ash.yaml"
        path.write_text(
            f"project_name: t\nscanners:\n  {LONG_S}:\n    enabled: false\n",
            encoding="utf-8",
        )
        _, config = load_config_file_for_run(path)
    # The long-s spelling is its own section, so detect-secrets keeps its
    # default and the written spelling stays an extra key.
    assert config.scanners.detect_secrets.enabled is True
    assert LONG_S in (config.scanners.model_extra or {})


def test_the_deny_and_the_fold_agree_on_every_spelling():
    reduced_declared = reduced_plugin_name("detect-secrets")
    for spelling in ASCII_SPELLINGS:
        assert reduced_declared in plugin_key_lookup_names(spelling)
    assert reduced_declared not in plugin_key_lookup_names(LONG_S)


@pytest.mark.parametrize("spelling", ASCII_SPELLINGS)
def test_control_a_deny_covers_an_ascii_respelling(spelling):
    reason = _denied_path_reason(
        "/scanners/detect-secrets/enabled", f"/scanners/{spelling}/enabled"
    )
    assert reason is not None
