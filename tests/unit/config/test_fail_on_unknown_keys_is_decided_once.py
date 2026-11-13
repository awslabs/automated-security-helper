# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``fail_on_unknown_keys`` set by an override is read one way at every site.

The load (``_unknown_entry_keys_are_fatal``, from the override's text) and the
override application (``apply_config_overrides``, from the value as it was
typed: ``1`` an int, ``yes`` a string) both decide whether an unknown key in a
suppression entry refuses the config. Two readings let an entry an override
added be only warned about when the operator had asked for the refusal, and the
dash spelling of the key inverted the other way.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.resolve_config import build_config

pytestmark = pytest.mark.unit

BAD_ENTRY = (
    "global_settings.suppressions+="
    '[{"rule_id":"X","path":"a.py","reason":"r","expiraton":"2099-01-01"}]'
)


def _clean() -> dict:
    return {
        "project_name": "decided-once",
        "global_settings": {"suppressions": [{"path": "clean.py", "reason": "r"}]},
    }


@pytest.mark.parametrize("key", ["fail_on_unknown_keys", "fail-on-unknown-keys"])
@pytest.mark.parametrize("value", ["true", "yes", "1"])
def test_an_override_that_asks_for_the_refusal_refuses_an_override_added_entry(
    key, value
):
    with pytest.raises(ValueError) as excinfo:
        build_config(_clean(), config_overrides=[f"{key}={value}", BAD_ENTRY])
    assert "expiraton" in str(excinfo.value)


@pytest.mark.parametrize("key", ["fail_on_unknown_keys", "fail-on-unknown-keys"])
@pytest.mark.parametrize("value", ["false", "no", "0"])
def test_an_override_that_does_not_ask_for_it_only_warns(key, value):
    config = build_config(_clean(), config_overrides=[f"{key}={value}", BAD_ENTRY])
    warned = [w for w in config._resolution_warnings if "expiraton" in w]
    assert len(warned) == 1, config._resolution_warnings
    assert config.global_settings.suppressions[1].has_unknown_keys


@pytest.mark.parametrize("key", ["fail_on_unknown_keys", "fail-on-unknown-keys"])
def test_an_override_turning_the_flag_off_wins_over_the_file_in_either_spelling(key):
    data = _clean()
    data["fail_on_unknown_keys"] = True
    data["global_settings"]["suppressions"].append(
        {"rule_id": "X", "path": "a.py", "reason": "r", "expiraton": "2099-01-01"}
    )
    config = build_config(data, config_overrides=[f"{key}=false"])
    assert [w for w in config._resolution_warnings if "expiraton" in w]


def test_control_without_the_flag_the_added_entry_only_warns():
    config = build_config(_clean(), config_overrides=[BAD_ENTRY])
    assert [w for w in config._resolution_warnings if "expiraton" in w]
