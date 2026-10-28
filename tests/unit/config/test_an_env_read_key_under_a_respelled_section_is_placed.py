# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An env-read key under a respelled known-plugin section is placed.

``_written_key_mappings`` folds each file's as-written parse the way the load
folded the document, so a mapping whose key the file reads from the
environment, sitting under a respelled known-plugin section, is named at the
place the merged configuration uses. The profile rules then find the section
there; a mapping with no place is refused outright, so the fold decides the
quality of the refusal's placement, not whether the refusal fires.
"""

import pytest

from automated_security_helper.config.resolve_config import load_config_file_for_run
from automated_security_helper.config.runtime_patch import (
    PROFILE_KEY_CAN_NAME_A_BUILT_IN_REFUSAL,
    _mappings_holding_a_key_read_from_the_environment,
    _refuse_a_profile_whose_key_can_name_a_built_in,
)

VAR_FIELD = "ASH_TEST_KEYMAP_FIELD"


@pytest.fixture
def base(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(VAR_FIELD, "enabled")
    path = tmp_path / "ash.yaml"
    path.write_text(
        f"project_name: t\nscanners:\n  DetectSecrets:\n    ${{{VAR_FIELD}}}: false\n",
        encoding="utf-8",
    )
    _, config = load_config_file_for_run(path)
    assert config.scanners.detect_secrets.enabled is False
    return config


def test_the_mapping_is_placed_in_the_dump(base):
    # The fold names the mapping at the place the configuration uses, so the
    # rules find the section there instead of refusing it as placeless.
    _, found = _mappings_holding_a_key_read_from_the_environment(base)
    places = [where for where, _, _ in found]
    assert places and all(where is not None for where in places), places


def test_a_profile_with_that_key_is_refused(base):
    # Every op on such a profile is refused with the one text, whether the
    # mapping is placed or not.
    with pytest.raises(Exception) as refused:
        _refuse_a_profile_whose_key_can_name_a_built_in(base)
    assert PROFILE_KEY_CAN_NAME_A_BUILT_IN_REFUSAL in str(refused.value)
