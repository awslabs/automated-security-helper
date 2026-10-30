# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An override the trusted base cannot take spoils only the keys it writes to.

``ConfigProvenance.trusted_value`` used to replay every override of a top-level
section onto the trusted base in one call, so one override the bare base could
not take (one writing under a section only the tree's config introduced) made the
whole section unresolvable, and every key under ``scanners`` then read as not the
operator's. The overrides are now replayed one at a time, and only the keys under
or above a failed override's key are unresolvable. ``operator_paths`` decides
provenance per entry for the same reason: an entry the operator appended to a
list a tree config also fills is theirs. The replay is driven through a stand-in
for ``apply_config_overrides`` over a dict, so the mechanism is tested on its own.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

import pytest

from automated_security_helper.config import resolve_config
from automated_security_helper.utils.config_trust import (
    NOT_THE_OPERATORS,
    ConfigProvenance,
    operator_paths,
    set_by_operator,
)

pytestmark = pytest.mark.unit


class _Config:
    """What ``set_by_operator`` reads: an object carrying a provenance record."""

    def __init__(self, provenance: ConfigProvenance) -> None:
        self._provenance = provenance


def _apply_to_dict(config: Dict[str, Any], overrides: List[str]) -> Dict[str, Any]:
    """A stand-in for ``resolve_config.apply_config_overrides`` over a dict.

    ``a.b.c=v`` sets ``v`` (read as JSON) at that path and raises, as the real
    one does, when a key on the way is not there; ``a.b.c+=v`` appends to the
    list there.
    """
    for override in overrides:
        key, _, raw = override.partition("=")
        appends = key.endswith("+")
        parts = key.removesuffix("+").split(".")
        current: Any = config
        for part in parts[:-1]:
            if part not in current:
                raise KeyError(part)
            current = current[part]
        value = json.loads(raw)
        if appends:
            current[parts[-1]] = [*current.get(parts[-1], []), value]
        else:
            current[parts[-1]] = value
    return config


@pytest.fixture
def dict_overrides(monkeypatch):
    monkeypatch.setattr(resolve_config, "apply_config_overrides", _apply_to_dict)


def test_an_override_the_base_cannot_take_leaves_the_other_keys_resolved(
    dict_overrides, tmp_path
):
    trusted = {"scanners": {"bandit": {"enabled": True}, "semgrep": {"enabled": True}}}
    config = _Config(
        ConfigProvenance(
            in_tree=(tmp_path / ".ash" / ".ash.yaml",),
            trusted=trusted,
            overrides=(
                "scanners.plugin-only.options.x=1",
                "scanners.semgrep.enabled=false",
            ),
        )
    )

    # The override the base took vouches for its value; the untouched key keeps
    # the trusted base's.
    assert set_by_operator(config, "scanners.semgrep.enabled", False) is True
    assert set_by_operator(config, "scanners.bandit.enabled", True) is True
    # The failed override spoils its own key, the keys under it and the section
    # above it, and nothing else.
    assert set_by_operator(config, "scanners.plugin-only.options.x", 1) is False
    assert set_by_operator(config, "scanners.plugin-only.options.x.y", 1) is False
    assert set_by_operator(config, "scanners", trusted["scanners"]) is False
    assert set_by_operator(config, "scanners.semgrep", {"enabled": False}) is True


def test_operator_paths_accepts_the_entry_the_operator_appended(
    dict_overrides, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()
    operators = tmp_path / "operator-rules"
    operators.mkdir()
    trees = tmp_path / "tree-rules"
    trees.mkdir()
    key = "scanners.guard.options.rules_paths"
    config = _Config(
        ConfigProvenance(
            in_tree=(repo / ".ash" / ".ash.yaml",),
            trusted={"scanners": {"guard": {"options": {"rules_paths": []}}}},
            overrides=(f"{key}+={json.dumps(str(operators))}",),
        )
    )

    chosen = operator_paths(config, key, [str(trees), str(operators)], repo)

    assert [(c.path, c.refusal) for c in chosen] == [
        (None, NOT_THE_OPERATORS),
        (operators.resolve(), None),
    ]
