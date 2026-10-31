# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An override the trusted base cannot take spoils only the keys it writes to.

``ConfigProvenance.trusted_value`` used to replay every override of a top-level
section onto the trusted base in one call, so one override the bare base could
not take (one writing under a section only the tree's config introduced) made the
whole section unresolvable, and every key under ``scanners`` then read as not the
operator's. The overrides are now replayed together first, as the scan applies
them, and one at a time only when the batch raises, so only the keys under or
above a failed override's key are unresolvable and a pair of overrides valid only
together stays the operator's. ``operator_paths`` decides provenance per entry for
the same reason: an entry the operator appended to a list a tree config also fills
is theirs, while a list that leaves one of the operator's entries out is refused
whole. The replay is driven through a stand-in for ``apply_config_overrides`` over
a dict, so the mechanism is tested on its own.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

import pytest

from automated_security_helper.config import resolve_config
from automated_security_helper.utils.config_trust import (
    NOT_THE_OPERATORS,
    ConfigProvenance,
    _override_key,
    operator_paths,
    operator_value,
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


def _bandit_config(tmp_path, override_key: str) -> _Config:
    return _Config(
        ConfigProvenance(
            in_tree=(tmp_path / ".ash" / ".ash.yaml",),
            trusted={
                "scanners": {"bandit": {"options": {"config_file": "/ops/base.yaml"}}}
            },
            overrides=(f'{override_key}="/ops/b.yaml"',),
        )
    )


def test_a_failed_override_under_another_plugin_spelling_spoils_the_folded_key(
    dict_overrides, tmp_path
):
    """The base has no ``Bandit`` section, so the override fails, and it is
    recorded under the key as written. The key a scanner asks about is spelled
    ``bandit``: both fold to one plugin, so the failure spoils it, and the
    trusted base's value is not offered as the operator's."""
    config = _bandit_config(tmp_path, "scanners.Bandit.options.config_file")
    key = "scanners.bandit.options.config_file"

    assert operator_value(config, key) == (False, None)
    assert set_by_operator(config, key, "/ops/base.yaml") is False
    # The dashed and underscored spellings of one name fold too.
    config = _bandit_config(tmp_path, "scanners.band-it.options.config_file")
    assert operator_value(config, key) == (False, None)


def test_an_override_key_loses_its_append_marker_before_its_padding():
    """``key +=value`` writes to ``key``: the marker comes off the end of the
    text before the padding is stripped, or the key keeps a trailing space and
    never matches the key a scanner asks about."""
    assert _override_key("scanners.bandit.options.x +=1") == (
        "scanners.bandit.options.x"
    )
    assert _override_key("scanners.bandit.options.x+=1") == (
        "scanners.bandit.options.x"
    )
    assert _override_key(" scanners.bandit.options.x = 1") == (
        "scanners.bandit.options.x"
    )


def test_control_an_override_that_applies_under_the_plain_spelling_resolves(
    dict_overrides, tmp_path
):
    config = _bandit_config(tmp_path, "scanners.bandit.options.config_file")

    assert operator_value(config, "scanners.bandit.options.config_file") == (
        True,
        "/ops/b.yaml",
    )


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


def _apply_to_dict_validating(config: Dict[str, Any], overrides: List[str]):
    """``_apply_to_dict`` plus the validation the real apply runs on the result:
    a scanner whose ``options.mode`` is ``"file"`` must name ``options.path``.
    ``apply_config_overrides`` validates the configuration it returns, so a pair
    of overrides valid only together passes in one call and fails one at a time.
    """
    _apply_to_dict(config, overrides)
    for section in config.get("scanners", {}).values():
        options = section.get("options", {}) if isinstance(section, dict) else {}
        if options.get("mode") == "file" and "path" not in options:
            raise ValueError("options.mode is file, so options.path is required")
    return config


@pytest.fixture
def validating_dict_overrides(monkeypatch):
    monkeypatch.setattr(
        resolve_config, "apply_config_overrides", _apply_to_dict_validating
    )


def test_overrides_valid_only_together_are_the_operators(
    validating_dict_overrides, tmp_path
):
    """The scan applies a run's overrides in one call, so a mode and the path that
    mode requires pass together. The replay applies them together first, and
    the operator's own values read as the operator's; replayed one at a time
    alone, the mode failed without its path, the path failed without its mode,
    and both read as not the operator's."""
    trusted = {"scanners": {"x": {"options": {"mode": "off"}}}}
    config = _Config(
        ConfigProvenance(
            in_tree=(tmp_path / ".ash" / ".ash.yaml",),
            trusted=trusted,
            overrides=(
                'scanners.x.options.mode="file"',
                'scanners.x.options.path="/p"',
            ),
        )
    )

    assert set_by_operator(config, "scanners.x.options.mode", "file") is True
    assert set_by_operator(config, "scanners.x.options.path", "/p") is True
    assert set_by_operator(config, "scanners.x.options.mode", "off") is False


def test_a_batch_that_fails_still_replays_the_rest_one_at_a_time(
    validating_dict_overrides, tmp_path
):
    """When the batch raises (one override the bare base cannot take), the
    replay falls back to one at a time and the other keys stay resolved, as
    before."""
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

    assert set_by_operator(config, "scanners.semgrep.enabled", False) is True
    assert set_by_operator(config, "scanners.plugin-only.options.x", 1) is False


def test_operator_paths_refuses_a_list_that_leaves_the_operators_entries_out(
    dict_overrides, tmp_path
):
    """The operator's ``rules_paths`` is ``[A, B]`` and the tree's config writes
    ``[A]``. Taking ``A`` as the operator's would let the repository drop ``B``
    with no refusal and no warning, so the whole list is refused, one refusal
    per entry, and the caller warns and falls back as it does for a list the
    operator did not set. A list that holds every operator entry keeps per-entry
    provenance: the operator's entries are theirs, the tree's additions are
    refused."""
    repo = tmp_path / "repo"
    repo.mkdir()
    first = tmp_path / "rules-a"
    first.mkdir()
    second = tmp_path / "rules-b"
    second.mkdir()
    trees = tmp_path / "tree-rules"
    trees.mkdir()
    key = "scanners.guard.options.rules_paths"
    config = _Config(
        ConfigProvenance(
            in_tree=(repo / ".ash" / ".ash.yaml",),
            trusted={"scanners": {"guard": {"options": {"rules_paths": []}}}},
            overrides=(f"{key}={json.dumps([str(first), str(second)])}",),
        )
    )

    left_out = operator_paths(config, key, [str(first)], repo)
    assert [(c.path, c.refusal) for c in left_out] == [(None, NOT_THE_OPERATORS)]

    superset = operator_paths(config, key, [str(first), str(trees), str(second)], repo)
    assert [(c.path, c.refusal) for c in superset] == [
        (first.resolve(), None),
        (None, NOT_THE_OPERATORS),
        (second.resolve(), None),
    ]
