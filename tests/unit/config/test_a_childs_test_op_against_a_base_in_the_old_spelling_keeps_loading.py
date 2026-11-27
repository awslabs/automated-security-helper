"""A child's ``test`` op written against a base in the old spelling keeps loading.

A ``test`` op compares its value with the document the child's bases resolved
to. A base is read in the canonical spelling before it is merged, and the op's
value is read as the model its path names, so the two sides agree whichever
spelling each file wrote. The root pointer names the whole document, so a value
there is read as the whole configuration.

A pointer reaches that model through each spelling the loader resolves it by: a
key's ``-``/``_`` twin (``global-settings``) and a plugin section's case variant
(``Bandit``) as well as the canonical key. So a ``test`` of the entry, a
``replace`` or ``remove`` of its expiry by the old spelling, and an ``add`` of an
entry that writes the old spelling all reach the base's entry through such a
pointer, and the old spelling the op names is said once, naming the child's file.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest
import yaml

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = [
    pytest.mark.unit,
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
]

DEPRECATION = "deprecated spelling of 'expires'"

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

#: The base's one Bandit excluded path, its expiry in the old spelling too.
_EXCLUDED = {"path": "tests/", "reason": "reviewed", "expiration": "2099-01-01"}


def _write(path: Path, document: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _child_of(tmp_path: Path, base: Dict[str, Any], ops: List[Any]) -> Path:
    """The base ``base``, and a child whose ``patch`` is ``ops``."""
    _write(tmp_path / "cfg" / "org.yaml", base)
    return _write(tmp_path / "cfg" / "repo.yaml", {"extends": "org.yaml", "patch": ops})


def _child_patching(tmp_path: Path, ops: List[Any]) -> Path:
    """A base holding ``_ENTRY``, and a child whose ``patch`` is ``ops``."""
    return _child_of(
        tmp_path, {"global_settings": {"suppressions": [dict(_ENTRY)]}}, ops
    )


def _excluded_paths_base(entry: Dict[str, Any]) -> Dict[str, Any]:
    """A base whose Bandit section, spelled as its manifest names it, holds
    ``entry`` as its one excluded path."""
    return {"scanners": {"bandit": {"options": {"excluded_paths": [entry]}}}}


def _deprecation_lines(config: AshConfig) -> List[str]:
    return [line for line in config._resolution_warnings if DEPRECATION in line]


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


# ---------------------------------------------------------------------------
# A pointer through another spelling of a section on the way to the entry
# ---------------------------------------------------------------------------


def _ops(list_pointer: str, op: str, entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The child's ``patch``: one ``op`` at the base's one entry of the list at
    ``list_pointer``, or at the end of that list for ``add``.

    A ``test`` holds ``entry`` as the base wrote it, and a write follows it, so
    the load shows the patch ran on past it. A ``replace`` and a ``remove`` name
    the expiry in the old spelling, and an ``add`` appends an entry that writes
    it.
    """
    at_entry = f"{list_pointer}/0"
    expiry = f"{at_entry}/expiration"
    if op == "test":
        return [
            {"op": "test", "path": at_entry, "value": dict(entry)},
            {"op": "replace", "path": f"{at_entry}/reason", "value": "re-reviewed"},
        ]
    if op == "replace":
        return [{"op": "replace", "path": expiry, "value": "2199-12-31"}]
    if op == "remove":
        return [{"op": "remove", "path": expiry}]
    added = {**entry, "path": "src/other.py", "expiration": "2099-02-02"}
    return [{"op": "add", "path": f"{list_pointer}/-", "value": added}]


_OPS = ["test", "replace", "remove", "add"]

#: Each entry's reason and expiry once the child's op has applied.
_LOADED: Dict[str, List[Tuple[str, Optional[str]]]] = {
    "test": [("re-reviewed", "2099-01-01")],
    "replace": [("reviewed", "2199-12-31")],
    "remove": [("reviewed", None)],
    "add": [("reviewed", "2099-01-01"), ("reviewed", "2099-02-02")],
}


def _said_once_for_each_file(config: AshConfig) -> None:
    """The deprecation is said once for each file that writes the old spelling,
    naming it: the base, and the child whose op names it."""
    lines = _deprecation_lines(config)
    assert len(lines) == 2, lines
    assert sum("org.yaml" in line for line in lines) == 1, lines
    assert sum("repo.yaml" in line for line in lines) == 1, lines


#: The base's suppressions, by how a pointer spells the key that holds them: its
#: ``-``/``_`` twin, and the key itself.
_SUPPRESSIONS_TWIN = "/global-settings/suppressions"
_SUPPRESSIONS = "/global_settings/suppressions"


@pytest.mark.parametrize(
    "suppressions,op",
    [
        (_SUPPRESSIONS_TWIN, "test"),
        (_SUPPRESSIONS_TWIN, "replace"),
        (_SUPPRESSIONS_TWIN, "remove"),
        (_SUPPRESSIONS_TWIN, "add"),
        # The guards: the key itself. Its ``test`` is the whole-entry test above.
        (_SUPPRESSIONS, "replace"),
        (_SUPPRESSIONS, "remove"),
        (_SUPPRESSIONS, "add"),
    ],
    ids=[
        "twin-test",
        "twin-replace",
        "twin-remove",
        "twin-add",
        "canonical-replace",
        "canonical-remove",
        "canonical-add",
    ],
)
def test_a_childs_op_through_either_spelling_of_global_settings_keeps_loading(
    tmp_path: Path, suppressions: str, op: str
) -> None:
    """An op whose pointer writes ``global-settings`` reaches the base's
    suppression as one that writes ``global_settings`` does: the entry is
    patched, and the old spelling the op names is said for the child's file."""
    child = _child_patching(tmp_path, _ops(suppressions, op, _ENTRY))

    config = AshConfig.from_file(child)

    entries = config.global_settings.suppressions
    assert [(entry.reason, entry.expires) for entry in entries] == _LOADED[op]
    _said_once_for_each_file(config)


#: The base's Bandit excluded paths, by how a pointer spells the scanner's
#: section: a case variant of its name, and the name its manifest declares.
_EXCLUDED_PATHS_VARIANT = "/scanners/Bandit/options/excluded_paths"
_EXCLUDED_PATHS = "/scanners/bandit/options/excluded_paths"


@pytest.mark.parametrize("op", _OPS)
@pytest.mark.parametrize(
    "excluded_paths",
    [_EXCLUDED_PATHS_VARIANT, _EXCLUDED_PATHS],
    ids=["case-variant", "canonical"],
)
def test_a_childs_op_through_either_spelling_of_a_scanner_section_keeps_loading(
    tmp_path: Path, excluded_paths: str, op: str
) -> None:
    """The same through a scanner's section: an op whose pointer writes
    ``Bandit`` reaches the excluded path of a base that writes ``bandit``, as
    one that writes ``bandit`` does. The canonical spelling is the guard."""
    child = _child_of(
        tmp_path,
        _excluded_paths_base(dict(_EXCLUDED)),
        _ops(excluded_paths, op, _EXCLUDED),
    )

    config = AshConfig.from_file(child)

    entries = config.scanners.bandit.options.excluded_paths
    assert [(entry.reason, entry.expires) for entry in entries] == _LOADED[op]
    _said_once_for_each_file(config)
