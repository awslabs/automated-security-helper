# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config answered as parsed stays inside the chain's anchor-expansion budgets.

The config chain gives every aliased place its own container and refuses a
file whose anchors multiply past the expansion budgets
(``test_an_aliased_document_past_the_expansion_bound_is_refused.py``). Two
parses never go through the chain: ``get_config(raw=True)`` answers the
document as parsed, and ``select_profile``'s ``override_yaml`` is parsed in
the tool. Both hand a document whose shared nodes are written out once per
place it is reachable from, so the same budgets apply to them.

What the budgets charge is pinned here: every place counts, scalars
included, since an aliased scalar is written once per place it is reachable
from; each string's length counts against a text budget; and the place
budget is spent child by child, so the guard's own walk stops at the bound
and a refusal can land partway through one container. The wording cells pin
each surface's frame: the raw path's refusal opens with the file's name so
the frame names it once, and the override path's refusal carries the
``override_yaml`` error prefix.

Every cell is small and bounded. The bound is lowered to 50 places and each
document expands to a few hundred at most; the refusal fires first, so no
large expansion is ever materialized.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_all_session_state,
    register_profiles,
    set_profile_registry,
)
from automated_security_helper.cli.mcp_tools import mcp_get_config, mcp_select_profile
from automated_security_helper.config import config_sources
from automated_security_helper.core.exceptions import ASHConfigSourceError

LOWERED_BOUND = 50


def _stack(levels: int, width: int) -> str:
    """Flow-style anchors, each level aliasing the one below ``width`` times.

    Expands to ``width ** levels`` leaf mappings from a few hundred bytes.
    """
    lines = ["project_name: bounded", "a0: &a0 {leaf: 1}"]
    for level in range(1, levels + 1):
        refs = ", ".join(f"k{j}: *a{level - 1}" for j in range(width))
        lines.append(f"a{level}: &a{level} {{{refs}}}")
    return "\n".join(lines) + "\n"


def _scalar_sharing(width: int) -> str:
    """One anchored scalar aliased from ``width`` places.

    The containers stay at two, so a guard that charges only mappings and
    sequences admits it however wide it gets; written out, it is ``width``
    scalar places plus the few around them.
    """
    refs = ", ".join(f"k{j}: *s0" for j in range(width))
    return f"project_name: bounded\ns0: &s0 shared-text\nuse: {{{refs}}}\n"


@pytest.fixture(autouse=True)
def _isolate_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    # Materialized session configs land under the allowed roots.
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    clear_profile_registry()
    clear_all_session_state()
    yield
    clear_profile_registry()
    clear_all_session_state()


@pytest.fixture
def lowered_bound(monkeypatch):
    monkeypatch.setattr(config_sources, "_UNALIASED_CONTAINER_BOUND", LOWERED_BOUND)


def test_raw_get_config_refuses_a_document_past_the_bound(tmp_path, lowered_bound):
    config = tmp_path / ".ash.yaml"
    config.write_text(_stack(levels=3, width=9), encoding="utf-8")

    result = mcp_get_config(config_path=str(config), raw=True)

    said = json.dumps(result, default=str)
    assert "expands to more than" in said and "anchors" in said, said
    assert "a3" not in result, "the parsed document was answered"


def test_raw_get_config_names_the_file_once_in_the_refusal(tmp_path, lowered_bound):
    config = tmp_path / ".ash.yaml"
    config.write_text(_stack(levels=3, width=9), encoding="utf-8")

    result = mcp_get_config(config_path=str(config), raw=True)

    error = result["error"]
    # The refusal's own text opens with the file's name, so the frame leaves
    # its copy out instead of naming the same file a second time.
    assert error.startswith("Configuration file cannot be loaded: "), error
    assert "expands to more than" in error, error


def test_raw_get_config_refuses_shared_scalar_places_past_the_bound(
    tmp_path, lowered_bound
):
    config = tmp_path / ".ash.yaml"
    config.write_text(_scalar_sharing(width=60), encoding="utf-8")

    result = mcp_get_config(config_path=str(config), raw=True)

    said = json.dumps(result, default=str)
    assert "expands to more than" in said, said
    assert "use" not in result, "the parsed document was answered"


def test_raw_get_config_answers_modest_sharing_as_written(tmp_path, lowered_bound):
    config = tmp_path / ".ash.yaml"
    config.write_text(
        "project_name: shared\nbase: &b {x: 1}\nuse: {first: *b, second: *b}\n",
        encoding="utf-8",
    )

    result = mcp_get_config(config_path=str(config), raw=True)

    assert result == {
        "project_name": "shared",
        "base": {"x": 1},
        "use": {"first": {"x": 1}, "second": {"x": 1}},
    }


def _install_profile(tmp_path: Path) -> None:
    file = tmp_path / "default.yaml"
    file.write_text("project_name: profile\n", encoding="utf-8")
    set_profile_registry(register_profiles([f"default={file}"]))


ALIAS_REFUSED = "does not accept YAML aliases"


def test_override_yaml_refuses_a_document_past_the_bound(tmp_path, lowered_bound):
    """``override_yaml`` is parsed with the config loader, which composes no alias
    at all (``mcp_tools._select_profile``: safe tags only and no aliases), so an
    anchored stack is refused as a parse error before any expansion budget is
    charged; the raw ``get_config`` path above is the one that expands and
    bounds."""
    _install_profile(tmp_path)

    result = mcp_select_profile("default", override_yaml=_stack(levels=3, width=9))

    assert result["success"] is False
    assert ALIAS_REFUSED in result["error"], result["error"]
    assert "override_yaml" in result["error"], result["error"]


def test_override_yaml_refusal_carries_the_validation_error_prefix(
    tmp_path, lowered_bound
):
    _install_profile(tmp_path)

    result = mcp_select_profile("default", override_yaml=_stack(levels=3, width=9))

    assert result["success"] is False
    assert result["error"].startswith("override_yaml parse error: "), result["error"]
    assert ALIAS_REFUSED in result["error"], result["error"]


def test_override_yaml_refuses_shared_scalar_places_past_the_bound(
    tmp_path, lowered_bound
):
    _install_profile(tmp_path)

    result = mcp_select_profile("default", override_yaml=_scalar_sharing(width=60))

    assert result["success"] is False
    assert ALIAS_REFUSED in result["error"], result["error"]


def test_override_yaml_with_modest_sharing_binds_the_alias_free_document(
    tmp_path, lowered_bound
):
    """An override whose entries share one anchored node is refused as written
    (the loader composes no alias), and the same document with the shared node
    written out in each place binds, the materialized config holding that
    alias-free spelling in each place, exactly as the raw path answers one.
    """
    profile = tmp_path / "default.yaml"
    profile.write_text(
        yaml.safe_dump(
            {
                "project_name": "profile",
                "global_settings": {
                    "mcp": {
                        "runtime_overrides": {
                            "enabled": True,
                            "allowed_paths": [
                                "/converters",
                                "/converters/*",
                                "/converters/**",
                            ],
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    set_profile_registry(register_profiles([f"default={profile}"]))
    override = (
        "project_name: profile\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths:\n"
        '        ["/converters", "/converters/*", "/converters/**"]\n'
        "converters:\n"
        "  shared_one: &shared {enabled: true, options: {note: same}}\n"
        "  shared_two: *shared\n"
    )

    aliased = mcp_select_profile("default", override_yaml=override, session_id="shared")
    assert aliased["success"] is False, aliased
    assert ALIAS_REFUSED in aliased["error"], aliased["error"]

    written_out = override.replace(
        "  shared_two: *shared\n",
        "  shared_two: {enabled: true, options: {note: same}}\n",
    ).replace("&shared ", "")
    result = mcp_select_profile(
        "default", override_yaml=written_out, session_id="shared"
    )

    assert result["success"] is True, result
    materialized = yaml.safe_load(
        Path(result["config_path"]).read_text(encoding="utf-8")
    )
    alias_free = {"enabled": True, "options": {"note": "same"}}
    assert materialized["converters"]["shared_one"] == alias_free
    assert materialized["converters"]["shared_two"] == alias_free


class _Counting(dict):
    """A mapping whose ``values()`` counts every child it yields."""

    yielded = 0

    def values(self):
        for child in super().values():
            type(self).yielded += 1
            yield child


def test_the_guard_stops_at_the_bound_whatever_the_document_expands_to(
    lowered_bound,
):
    wide = _Counting({f"k{j}": j for j in range(1_000)})
    _Counting.yielded = 0

    with pytest.raises(ASHConfigSourceError) as refused:
        config_sources.refuse_past_expansion_bound(wide, "the document")

    assert "expands to more than" in str(refused.value)
    # 1000 children lie under this one mapping while the bound is 50: the
    # budget is spent per yielded child, so the guard stops partway through
    # the container instead of scanning its whole width for one charge.
    assert _Counting.yielded <= LOWERED_BOUND + 1, _Counting.yielded


def test_long_shared_text_is_charged_against_the_byte_budget(monkeypatch):
    monkeypatch.setattr(config_sources, "_UNALIASED_BYTE_BOUND", 200, raising=False)
    text = "y" * 90
    document = {"a": text, "b": text, "c": text}

    with pytest.raises(ASHConfigSourceError) as refused:
        config_sources.refuse_past_expansion_bound(document, "the document")

    assert "expands to more than" in str(refused.value)
