# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A non-mapping override_yaml is refused by its shape, not a raw TypeError.

The strict-extra gate iterated the loaded document before checking it is a
mapping, so a client's non-mapping text got whatever iteration raised or
produced: a list of lists answered the generic "Error selecting profile:
cannot use 'list' as a set element" with error_type TypeError, a number
"'int' object is not iterable", and plain text was read as its own
characters, "unknown top-level field(s):  , e, j, s, t, u, x" (each measured
through the real tool). The refusal now names the shape, in the family's
words, before anything iterates the document.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, Iterator

import pytest

from automated_security_helper.cli import mcp_server
from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_all_session_state,
    register_profiles,
    set_profile_registry,
)

pytestmark = pytest.mark.unit


class _Context:
    headers = {"mcp-session-id": "non-mapping-override"}

    async def info(self, message: str) -> None:
        return None

    error = warning = debug = info

    async def report_progress(self, **kwargs: Any) -> None:
        return None


@pytest.fixture
def wide_profile(tmp_path, monkeypatch) -> Iterator[None]:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    profile = tmp_path / "wide.yaml"
    profile.write_text(
        "project_name: t\nglobal_settings:\n  mcp:\n    runtime_overrides:\n"
        '      enabled: true\n      allowed_paths: ["/**"]\n',
        encoding="utf-8",
    )
    clear_profile_registry()
    clear_all_session_state()
    set_profile_registry(register_profiles([f"wide={profile}"]))
    yield
    clear_profile_registry()
    clear_all_session_state()


def _select(override_yaml: str) -> Dict[str, Any]:
    answer = asyncio.run(
        mcp_server.select_profile(
            _Context(), profile_name="wide", override_yaml=override_yaml
        )
    )
    json.dumps(answer)
    return answer


@pytest.mark.parametrize(
    "override, kind",
    [
        pytest.param("- [1]\n", "list", id="a-list-of-lists"),
        pytest.param("42\n", "int", id="a-number"),
        pytest.param("just text\n", "str", id="plain-text"),
    ],
)
def test_a_non_mapping_override_yaml_is_refused_by_its_shape(
    wide_profile, override: str, kind: str
) -> None:
    answer = _select(override)

    assert answer.get("success") is False, answer
    error = str(answer.get("error", ""))
    assert error.startswith("override_yaml validation error"), answer
    assert f"must be a mapping, got {kind}" in error, answer
    assert "error_type" not in answer, answer
    assert "Error selecting profile" not in error, answer
    assert "unknown top-level field" not in error, answer


def test_control_a_mapping_override_still_binds(wide_profile) -> None:
    # The override restates the profile's runtime-override policy: an override
    # that leaves global_settings.mcp out is the patch that clears it, and
    # '/global_settings/mcp' is in the shipped denied_paths
    # (ash_config.RuntimeOverridesConfig's default list).
    answer = _select(
        "project_name: plain\nglobal_settings:\n  mcp:\n    runtime_overrides:\n"
        '      enabled: true\n      allowed_paths: ["/**"]\n'
    )
    assert answer.get("success") is True, answer
    assert answer.get("mode") == "override", answer


@pytest.mark.parametrize(
    "override, kinds",
    [
        pytest.param("on: x\n", "bool", id="a-boolean-key"),
        pytest.param("1: x\n", "int", id="a-number-key"),
        # Not `1` beside `on`: True == 1 in Python, so YAML's mapping merges
        # those two keys into one and only one kind remains.
        pytest.param("1: x\n2024-01-01: y\n", "date, int", id="mixed-kinds"),
    ],
)
def test_a_non_string_top_level_key_is_refused_by_its_kind(
    wide_profile, override: str, kinds: str
) -> None:
    """A mapping whose plain keys YAML reads as another kind (``on`` is a
    boolean, ``1`` a number) passed the shape check, and the strict-extra
    gate's set difference and join over those keys raised a raw TypeError:
    the generic answer the shape check exists to prevent. Refused by the
    keys' kind, never their text."""
    answer = _select(override)

    assert answer.get("success") is False, answer
    error = str(answer.get("error", ""))
    assert error.startswith("override_yaml validation error"), answer
    assert f"keys must be strings, got {kinds}" in error, answer
    assert "error_type" not in answer, answer
    assert "Error selecting profile" not in error, answer
    assert "unknown top-level field" not in error, answer
