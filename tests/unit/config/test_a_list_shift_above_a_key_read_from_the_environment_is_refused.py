# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An add or remove at an index of a list holding a mapping with a key the
profile read from the environment is refused.

``_refuse_a_key_read_from_the_environment`` protects such a mapping by its path,
the list index included. An add or remove at an index of that list moved the
mapping to another index, so every later op's path was matched against an index
the mapping no longer had, and an op through its keys applied. The shift is now
refused outright, whatever the index: tracking it would move the protection
with the mapping and still let the shifting op decide the mapping's place.

The variable is ``ASH_KEY_NAME``, not ``ASH_KEY``: a name ending in ``_KEY`` is
secret-shaped, so the loader never reads it and a reference to it stays a
literal key.

Red at the base: the add at the mapping's own index was read as a replacement of
the mapping and applied.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import RuntimeOverridesConfig
from automated_security_helper.config.runtime_patch import (
    LIST_SHIFT_ABOVE_A_KEY_READ_FROM_THE_ENVIRONMENT_REFUSAL,
    RuntimePatchDeniedError,
    apply_runtime_patch,
)

pytestmark = pytest.mark.unit

CANARY = "ash-canary-x25l-0123456789"
PROFILE = (
    "scanners:\n"
    "  customx:\n"
    "    enabled: true\n"
    "    options:\n"
    "      items:\n"
    "        - ${ASH_KEY_NAME}: x\n"
    "          kept: y\n"
    "        - kept: z\n"
)
ALLOW_SCANNERS = RuntimeOverridesConfig(
    enabled=True, allowed_paths=["/scanners/**"], denied_paths=[]
)


@pytest.fixture
def base(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    monkeypatch.setenv("ASH_KEY_NAME", CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / ".ash.yaml"
    path.write_text(PROFILE, encoding="utf-8")
    _, config = load_config_file_for_run(path)
    mappings = list(getattr(config, "_written_key_mappings", ()) or ())
    assert any(
        place is not None and place[:4] == ("scanners", "customx", "options", "items")
        for place, _ in mappings
    ), "the control: the profile reads a key from the environment in the list"
    return config


def _rule(base, op: dict) -> str | None:
    try:
        apply_runtime_patch(base, [op], allowlist=ALLOW_SCANNERS)
    except RuntimePatchDeniedError as refused:
        return refused.rule
    return None


@pytest.mark.parametrize(
    "op",
    [
        {
            "op": "add",
            "path": "/scanners/customx/options/items/0",
            "value": {"kept": "w"},
        },
        {
            "op": "add",
            "path": "/scanners/customx/options/items/1",
            "value": {"kept": "w"},
        },
        {"op": "remove", "path": "/scanners/customx/options/items/0"},
        {"op": "remove", "path": "/scanners/customx/options/items/1"},
    ],
    ids=["add-at-the-mapping", "add-after-it", "remove-the-mapping", "remove-after-it"],
)
def test_a_shifting_op_on_the_list_is_refused(base, op) -> None:
    assert _rule(base, op) == LIST_SHIFT_ABOVE_A_KEY_READ_FROM_THE_ENVIRONMENT_REFUSAL


def test_an_append_moves_nothing_and_applies(base) -> None:
    """The control: an append at the end of the list shifts no entry."""
    assert (
        _rule(
            base,
            {
                "op": "add",
                "path": "/scanners/customx/options/items/-",
                "value": {"kept": "w"},
            },
        )
        is None
    )


def test_a_replace_of_another_entrys_text_key_applies(base) -> None:
    """The control: an op that moves no entry and names a key the profile
    writes as text is patched as before."""
    assert (
        _rule(
            base,
            {
                "op": "replace",
                "path": "/scanners/customx/options/items/1/kept",
                "value": "w",
            },
        )
        is None
    )


# A set the profile read from the environment, in the first entry of the same
# list. A set has no positions, so the profile's reference is kept at the
# unknown index of its container and followed by the container's path. These
# cells guard:
#   - the shift cells: an add or remove at an index of the list moves the set to
#     another index, and is refused with one text, whatever the index; an
#     append moves nothing and applies.
#   - the move and copy cells: the patch entry point refuses both ops before any
#     reference is read, so the second guard, the tracker's, is read on its own: a
#     move or a copy from the set, from the entry that holds it or from the
#     mapping above it is refused, and one from another place is not.
#   - the write cells: an op that writes at or above the set makes it the
#     client's, and the configuration then holds no reference for it.
SET_MEMBER = "ash-canary-set-9c41-0123456789"
SET_PROFILE = (
    "scanners:\n"
    "  customx:\n"
    "    enabled: true\n"
    "    options:\n"
    "      items:\n"
    "        - tags: !!set\n"
    "            ? ${ASH_TEST_SET_MEMBER}\n"
    "          kept: y\n"
    "        - kept: z\n"
)
CONTAINER = ("scanners", "customx", "options", "items", 0, "tags")


@pytest.fixture
def set_base(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from automated_security_helper.config.environment_record import UNKNOWN_INDEX
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    monkeypatch.setenv("ASH_TEST_SET_MEMBER", SET_MEMBER)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / ".ash.yaml"
    path.write_text(SET_PROFILE, encoding="utf-8")
    _, config = load_config_file_for_run(path)
    held = [
        rewrite.path
        for rewrite in config._written_references
        if rewrite.path and rewrite.path[-1] is UNKNOWN_INDEX
    ]
    assert held == [(*CONTAINER, UNKNOWN_INDEX)], (
        "the control: the load recorded the set's member at the unknown index"
    )
    return config


def _set_refusal() -> str:
    from automated_security_helper.config.runtime_patch import (
        SET_READ_FROM_THE_ENVIRONMENT_REFUSAL,
    )

    return SET_READ_FROM_THE_ENVIRONMENT_REFUSAL


def _members_left(config) -> tuple[int, int]:
    """How many rewrites and references the configuration holds at the unknown
    index."""
    from automated_security_helper.config.environment_record import UNKNOWN_INDEX

    rewrites = [
        r for r in config._written_references if r.path and r.path[-1] is UNKNOWN_INDEX
    ]
    references = [
        r
        for r in config._environment_references
        if r.path and r.path[-1] is UNKNOWN_INDEX
    ]
    return len(rewrites), len(references)


@pytest.mark.parametrize(
    "op",
    [
        {
            "op": "add",
            "path": "/scanners/customx/options/items/0",
            "value": {"kept": "w"},
        },
        {
            "op": "add",
            "path": "/scanners/customx/options/items/1",
            "value": {"kept": "w"},
        },
        {"op": "remove", "path": "/scanners/customx/options/items/0"},
        {"op": "remove", "path": "/scanners/customx/options/items/1"},
    ],
    ids=["add-at-the-entry", "add-after-it", "remove-the-entry", "remove-after-it"],
)
def test_a_shifting_op_on_a_list_above_a_set_is_refused(set_base, op) -> None:
    assert _rule(set_base, op) == _set_refusal()


def test_the_refusal_of_a_shift_above_a_set_names_no_value_or_place(set_base) -> None:
    """The refusal names no op and its text names neither the set's value nor
    where the set is, so it reads the same for every op and every entry."""
    with pytest.raises(RuntimePatchDeniedError) as refused:
        apply_runtime_patch(
            set_base,
            [{"op": "remove", "path": "/scanners/customx/options/items/0"}],
            allowlist=ALLOW_SCANNERS,
        )

    message = str(refused.value)
    named = [
        word
        for word in (SET_MEMBER, "ASH_TEST_SET_MEMBER", "tags", "items", "customx")
        if word in message
    ]
    assert named == [], named
    assert refused.value.op is None


def test_an_append_beside_a_set_moves_nothing_and_applies(set_base) -> None:
    """The control: an append at the end of the list shifts no entry."""
    assert (
        _rule(
            set_base,
            {
                "op": "add",
                "path": "/scanners/customx/options/items/-",
                "value": {"kept": "w"},
            },
        )
        is None
    )


@pytest.mark.parametrize(
    "op",
    [
        {
            "op": "move",
            "from": "/scanners/customx/options/items/0/tags",
            "path": "/scanners/customx/options/elsewhere",
        },
        {
            "op": "copy",
            "from": "/scanners/customx/options/items/0/tags",
            "path": "/scanners/customx/options/elsewhere",
        },
        {
            "op": "move",
            "from": "/scanners/customx/options/items/0",
            "path": "/scanners/customx/options/elsewhere",
        },
        {
            "op": "copy",
            "from": "/scanners/customx/options",
            "path": "/scanners/customx/elsewhere",
        },
    ],
    ids=["move-the-set", "copy-the-set", "move-its-entry", "copy-the-mapping-above"],
)
def test_the_tracker_refuses_a_move_or_copy_from_a_set_or_above_it(
    set_base, op
) -> None:
    from automated_security_helper.config.runtime_patch import _ReferencesThroughPatch

    tracker = _ReferencesThroughPatch(
        set_base, set_base.model_dump(mode="python", by_alias=False)
    )

    with pytest.raises(RuntimePatchDeniedError) as refused:
        tracker.refuse_a_write_over(op)

    assert refused.value.rule == _set_refusal()


def test_the_tracker_lets_a_copy_from_another_place_pass(set_base) -> None:
    """The control: a copy from an entry that holds no set reads nothing the
    set's rewrite names."""
    from automated_security_helper.config.runtime_patch import _ReferencesThroughPatch

    tracker = _ReferencesThroughPatch(
        set_base, set_base.model_dump(mode="python", by_alias=False)
    )

    tracker.refuse_a_write_over(
        {
            "op": "copy",
            "from": "/scanners/customx/options/items/1/kept",
            "path": "/scanners/customx/options/elsewhere",
        }
    )


@pytest.mark.parametrize("op_name", ["move", "copy"])
def test_the_entry_point_refuses_a_move_or_copy_before_the_tracker_reads_one(
    set_base, op_name
) -> None:
    """The control for the cells above: a client's move or copy is forbidden as
    an op type whatever it names, so the tracker's rule is a second guard."""
    refused = _rule(
        set_base,
        {
            "op": op_name,
            "from": "/scanners/customx/options/items/1/kept",
            "path": "/scanners/customx/options/elsewhere",
        },
    )

    assert refused == f"op type {op_name!r} is forbidden (move/copy)"


def test_an_op_elsewhere_keeps_the_sets_reference(set_base) -> None:
    """The control for the write cells: an op that writes beside the set leaves
    the rewrite and the reference in place."""
    patched = apply_runtime_patch(
        set_base,
        [
            {
                "op": "replace",
                "path": "/scanners/customx/options/items/1/kept",
                "value": "w",
            }
        ],
        allowlist=ALLOW_SCANNERS,
    )

    assert _members_left(patched) == (1, 1)


@pytest.mark.parametrize(
    "op",
    [
        {
            "op": "replace",
            "path": "/scanners/customx/options/items/0/tags",
            "value": ["x"],
        },
        {
            "op": "add",
            "path": "/scanners/customx/options/items/0/tags",
            "value": ["x"],
        },
        {"op": "remove", "path": "/scanners/customx/options/items/0/tags"},
        {
            "op": "replace",
            "path": "/scanners/customx/options/items/0",
            "value": {"kept": "w"},
        },
        {"op": "replace", "path": "/scanners/customx/options/items", "value": []},
    ],
    ids=["replace-the-set", "add-over-the-set", "remove-the-set", "entry", "list"],
)
def test_an_op_that_writes_at_or_above_a_set_drops_its_reference(set_base, op) -> None:
    patched = apply_runtime_patch(set_base, [op], allowlist=ALLOW_SCANNERS)

    assert _members_left(patched) == (0, 0)
