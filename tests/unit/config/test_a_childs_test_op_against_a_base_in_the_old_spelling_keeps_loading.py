"""A child's ``test`` op written against a base in the old spelling keeps loading.

A ``test`` op compares its value with the document the child's bases resolved
to. A base is read in the canonical spelling before it is merged, and the op's
value is read as the model its path names, so the two sides agree whichever
spelling each file wrote. The root pointer names the whole document, so a value
there is read as the whole configuration.
"""

from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = [
    pytest.mark.unit,
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
]

#: The base's one suppression, its expiry in the old spelling.
_ENTRY = {
    "rule_id": "B101",
    "path": "src/app.py",
    "reason": "reviewed",
    "expiration": "2099-01-01",
}

#: The same entry with a reason the base does not hold.
_NOT_THE_BASES = {**_ENTRY, "reason": "not what the base holds"}

_REVIEWED_AGAIN = {
    "op": "replace",
    "path": "/global_settings/suppressions/0/reason",
    "value": "re-reviewed",
}


def _write(path: Path, document: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _child_patching(tmp_path: Path, ops: List[Any]) -> Path:
    """A base holding ``_ENTRY``, and a child whose ``patch`` is ``ops``."""
    _write(
        tmp_path / "cfg" / "org.yaml",
        {"global_settings": {"suppressions": [dict(_ENTRY)]}},
    )
    return _write(tmp_path / "cfg" / "repo.yaml", {"extends": "org.yaml", "patch": ops})


def test_a_childs_test_op_with_the_whole_entry_in_the_old_spelling_keeps_loading(
    tmp_path: Path,
) -> None:
    """A ``test`` op's value at an entry is read as that entry, so it equals the
    base's entry whichever spelling each file wrote."""
    child = _child_patching(
        tmp_path,
        [
            {
                "op": "test",
                "path": "/global_settings/suppressions/0",
                "value": dict(_ENTRY),
            },
            _REVIEWED_AGAIN,
        ],
    )

    config = AshConfig.from_file(child)

    (suppression,) = config.global_settings.suppressions
    assert suppression.reason == "re-reviewed"
    assert suppression.expires == "2099-01-01"


def test_a_childs_root_test_op_against_a_base_in_the_old_spelling_keeps_loading(
    tmp_path: Path,
) -> None:
    """The root pointer names the whole document, so a ``test`` op there reads its
    value as the whole configuration and it equals the base's document."""
    child = _child_patching(
        tmp_path,
        [
            {
                "op": "test",
                "path": "",
                "value": {"global_settings": {"suppressions": [dict(_ENTRY)]}},
            },
            _REVIEWED_AGAIN,
        ],
    )

    config = AshConfig.from_file(child)

    (suppression,) = config.global_settings.suppressions
    assert suppression.reason == "re-reviewed"
    assert suppression.expires == "2099-01-01"


@pytest.mark.parametrize(
    "path,value",
    [
        ("/global_settings/suppressions/0", _NOT_THE_BASES),
        ("", {"global_settings": {"suppressions": [_NOT_THE_BASES]}}),
    ],
    ids=["entry", "root"],
)
def test_a_childs_test_op_the_base_does_not_hold_is_still_refused(
    tmp_path: Path, path: str, value: Any
) -> None:
    """The control: the op's value is compared at an entry and at the root, so a
    value the base does not hold is refused."""
    child = _child_patching(tmp_path, [{"op": "test", "path": path, "value": value}])

    with pytest.raises(ASHConfigValidationError) as refused:
        AshConfig.from_file(child)

    assert "does not equal the value the test op gives" in str(refused.value)
