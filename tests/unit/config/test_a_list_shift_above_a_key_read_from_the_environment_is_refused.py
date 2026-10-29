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
