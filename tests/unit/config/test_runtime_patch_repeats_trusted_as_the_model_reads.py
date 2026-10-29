# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A client-patched copy that repeats the trusted profile in another serialization is not a change.

``config_document_denials`` exempts a leaf whose value equals what the trusted
config has at the same place. A session's client-patched profile copy
(``repeats_trusted``) is the trusted profile written whole, so a leaf it repeats
can differ from the trusted dump only in how it is written: an entry without the
keys the model defaults, a spelling the model normalizes. Compared as text, such
a leaf read as the client's change and a policy denying the field refused the
operator's own entries in the copy. The leaf is now also compared as the model
reads the whole document, so only a value the client changed is refused.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.runtime_patch import config_document_denials

pytestmark = pytest.mark.unit

#: The operator's entries as a profile file writes them: no defaulted keys.
_OPERATOR_SUPPRESSION = {
    "rule_id": "B101",
    "path": "src/vendored.py",
    "reason": "vendored",
}
_OPERATOR_IGNORE = {"path": "operator-ignored/**", "reason": "operator"}

_DENIED = ["/global_settings/suppressions", "/global_settings/ignore_paths"]


def _trusted() -> AshConfig:
    return AshConfig.model_validate(
        {
            "project_name": "operator",
            "global_settings": {
                "suppressions": [dict(_OPERATOR_SUPPRESSION)],
                "ignore_paths": [dict(_OPERATOR_IGNORE)],
            },
        }
    )


def _copy(**global_settings: Any) -> Dict[str, Any]:
    """A patched copy of the profile: project_name changed, the entries as written."""
    settings: Dict[str, Any] = {
        "suppressions": [dict(_OPERATOR_SUPPRESSION)],
        "ignore_paths": [dict(_OPERATOR_IGNORE)],
    }
    settings.update(global_settings)
    return {"project_name": "x", "global_settings": settings}


def _denied_keys(document: Dict[str, Any], *, repeats_trusted: bool) -> List[str]:
    allowlist = RuntimeOverridesConfig(
        enabled=True, allowed_paths=["/project_name"], denied_paths=list(_DENIED)
    )
    return [
        denial.key
        for denial in config_document_denials(
            document,
            allowlist=allowlist,
            config=_trusted(),
            repeats_trusted=repeats_trusted,
        )
    ]


def test_the_trusted_dump_carries_the_defaulted_keys_the_copy_leaves_out() -> None:
    """The control: the two serializations of one entry differ as text."""
    dumped = _trusted().model_dump(mode="json", by_alias=True)
    entry = dumped["global_settings"]["ignore_paths"][0]
    assert entry != _OPERATOR_IGNORE
    assert {key: entry[key] for key in _OPERATOR_IGNORE} == _OPERATOR_IGNORE


def test_a_copy_repeating_the_profiles_entries_as_written_is_not_refused() -> None:
    assert _denied_keys(_copy(), repeats_trusted=True) == []


def test_a_copy_whose_entry_the_client_changed_is_still_refused() -> None:
    """The must-flag control: a changed value differs after validation too."""
    changed = dict(_OPERATOR_SUPPRESSION, reason="the client's reason")
    keys = _denied_keys(_copy(suppressions=[changed]), repeats_trusted=True)
    assert keys == ["global_settings.suppressions"]


def test_a_copy_with_an_entry_the_client_added_is_still_refused() -> None:
    added = [dict(_OPERATOR_IGNORE), {"path": "client/**", "reason": "the client's"}]
    keys = _denied_keys(_copy(ignore_paths=added), repeats_trusted=True)
    assert keys == ["global_settings.ignore_paths"]


def test_the_model_read_compare_applies_to_a_client_patched_copy_only() -> None:
    """Any other delivered document keeps the text compare, as before."""
    keys = _denied_keys(_copy(), repeats_trusted=False)
    assert sorted(keys) == [
        "global_settings.ignore_paths",
        "global_settings.suppressions",
    ]


def test_a_copy_the_model_refuses_gets_no_exemption() -> None:
    """An entry with a key the model does not declare cannot be read, so it is
    compared as written and refused."""
    unreadable = [dict(_OPERATOR_IGNORE, unknown_key="x")]
    keys = _denied_keys(_copy(ignore_paths=unreadable), repeats_trusted=True)
    assert "global_settings.ignore_paths" in keys
