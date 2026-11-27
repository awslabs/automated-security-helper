"""A ``fail_on_unknown_keys-=`` override does not choose how unknown keys are handled.

``_unknown_entry_keys_are_fatal`` reads the flag from the raw document before the
model is built, and an override that sets the flag wins over the document (the
last one counts). Its answer chooses whether an unknown key in a suppression or
ignore-path entry of the file refuses the load or marks the entry inert with a
warning. The read mirrors the apply: a replacement sets the bool, and so does an
append, which replaces a value that is no list. A removal (``-=``) sets no value:
the flag is no list, and the apply refuses to remove items from it. Read as a
set, ``fail_on_unknown_keys-=false`` would build a file that says
``fail_on_unknown_keys: true`` in warn mode, which loads the entries that file
asked to have refused.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest
from pydantic import ValidationError

from automated_security_helper.config import resolve_config as resolve_config_module
from automated_security_helper.config.resolve_config import build_config

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _own_notice_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """A notice set of this test's own: an append onto a value that is no list
    says so once per run, and the notices given here must not reach another
    test."""
    monkeypatch.setattr(
        resolve_config_module, "_OVERRIDE_NOTICES_GIVEN", set(), raising=False
    )


def _document(**entry: Any) -> Dict[str, Any]:
    """A config document that says ``fail_on_unknown_keys: true`` and holds one
    suppression with the extra keys given."""
    return {
        "project_name": "removal-test",
        "fail_on_unknown_keys": True,
        "global_settings": {
            "suppressions": [
                {"rule_id": "RULE-1", "path": "src/app.py", "reason": "test", **entry}
            ]
        },
    }


def test_a_removal_of_the_flag_leaves_the_files_value_deciding() -> None:
    """A control: the file says true, so its unknown suppression key refuses the
    load whatever ``fail_on_unknown_keys-=false`` says. It must hold both while a
    key ending in ``-`` names nothing the read looks for and once ``-=`` is read
    as a removal; a read that cuts the operator off the key without checking
    which one it was takes ``false`` from the removal and loads the entry in warn
    mode."""
    from automated_security_helper.config.resolve_config import (
        _unknown_entry_keys_are_fatal,
    )

    document = _document(resource="Stack/Role/Resource")
    overrides = ["fail_on_unknown_keys-=false"]

    assert _unknown_entry_keys_are_fatal(document, overrides) is True
    with pytest.raises(ValidationError) as refused:
        build_config(document, config_overrides=overrides)
    assert "Unknown key 'resource'" in str(refused.value)


@pytest.mark.parametrize(
    "override",
    ["fail_on_unknown_keys=false", "fail_on_unknown_keys+=false"],
    ids=["set", "append"],
)
def test_control_an_override_that_sets_the_flag_still_decides(override: str) -> None:
    """A control: an override that sets the flag wins over the file's true, so the
    file's unknown suppression key warns and its entry is inert. The append row is
    there because the apply sets the bool for ``+=`` as it does for ``=``: a read
    that counted only ``=`` would refuse the entry while the configuration the
    override builds says false."""
    from automated_security_helper.config.resolve_config import (
        _unknown_entry_keys_are_fatal,
    )

    document = _document(expiraton="2099-12-31")

    assert _unknown_entry_keys_are_fatal(document, [override]) is False
    config = build_config(document, config_overrides=[override])
    assert config.fail_on_unknown_keys is False
    warnings = [
        warning
        for warning in config._resolution_warnings
        if "Unknown key 'expiraton'" in warning
    ]
    assert len(warnings) == 1, config._resolution_warnings
    assert config.global_settings.suppressions[0].has_unknown_keys
