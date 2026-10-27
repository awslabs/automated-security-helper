# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""select_profile answers an override_yaml the same for a right and a wrong
guess of a key or a value the profile read from the environment.

An override is a whole configuration, and the profile's place for such a key or
value holds the guess the client wrote there: a section of ``reporters`` or
``scanners`` named the guess, ``project_name`` set to it, or an
``ignore_paths`` entry's ``path``. Each cell sends the same override twice, once
with the value the variable holds and once with another, and compares the whole
response, and the configuration the session is bound to, with the guess written
as ``GUESS``. Under a policy that allows the setting and under one that allows
nothing, both answers have to be the same.

The controls are the same overrides of a profile that writes the setting as
text: there an override that keeps it and one that changes it answer
differently under the policy that allows nothing, so a cell does not pass only
because no override reaches the rules.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import pytest

CANARY = "ash-canary-7f3e-0123456789"
# The same length as CANARY, so a right and a wrong guess differ only in text.
OTHER = "ash-canary-0000-9876543210"
LITERAL = "literal-control-0123456789"

ALLOWING = (
    "  mcp:\n"
    "    runtime_overrides:\n"
    "      enabled: true\n"
    "      allowed_paths:\n"
    "        - /project_name\n"
    "        - /global_settings/ignore_paths\n"
    "        - /global_settings/ignore_paths/**\n"
    "        - /reporters/**\n"
    "        - /scanners/**\n"
    "      denied_paths: []\n"
)
# Overrides are on, and no path is allowed: every op is refused.
NOTHING = (
    "  mcp:\n"
    "    runtime_overrides:\n"
    "      enabled: true\n"
    "      allowed_paths:\n"
    "        - /nothing-is-allowed\n"
    "      denied_paths: []\n"
)
POLICIES = {"allowing": ALLOWING, "allowing-nothing": NOTHING}


def _document(shape: str, text: str, policy: str) -> str:
    """A configuration with ``text`` at the place ``shape`` names."""
    if shape in ("reporters-key", "scanners-key"):
        section = shape.split("-")[0]
        return (
            "project_name: demo\n"
            "global_settings:\n"
            + policy
            + f"{section}:\n  {text}:\n    enabled: false\n"
        )
    if shape == "project-name":
        return f"project_name: {text}\nglobal_settings:\n" + policy
    if shape == "ignore-path":
        return (
            "project_name: demo\n"
            "global_settings:\n"
            "  ignore_paths:\n"
            f"    - path: {text}\n"
            "      reason: vendored\n" + policy
        )
    raise AssertionError(shape)


SHAPES = ["reporters-key", "scanners-key", "project-name", "ignore-path"]


@pytest.fixture
def select(tmp_path: Path, monkeypatch):
    """select_profile with an override, as a client calls it: the response and
    the text of the configuration the session is bound to."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_KEY", CANARY)

    def _select(
        profile_text: str, override: str
    ) -> Tuple[Dict[str, Any], Optional[str]]:
        profile = tmp_path / "operator.ash.yaml"
        profile.write_text(profile_text, encoding="utf-8")
        profile_registry.clear_profile_registry()
        profile_registry.clear_all_session_state()
        profile_registry.set_profile_registry(
            profile_registry.register_profiles([f"op={profile}"])
        )
        try:
            result = mcp_select_profile(
                "op", override_yaml=override, session_id="session-a"
            )
        finally:
            profile_registry.clear_profile_registry()
            profile_registry.clear_all_session_state()
        bound = None
        if result.get("success") and result.get("config_path"):
            bound = Path(result["config_path"]).read_text(encoding="utf-8")
        return result, bound

    return _select


def _neutral(answer: Tuple[Dict[str, Any], Optional[str]], guess: str) -> str:
    result, bound = answer
    return json.dumps([result, bound], sort_keys=True).replace(guess, "GUESS")


@pytest.mark.parametrize("policy", sorted(POLICIES))
@pytest.mark.parametrize("shape", SHAPES)
def test_an_override_answers_a_right_guess_as_a_wrong_one(select, shape, policy):
    profile = _document(shape, "${ASH_KEY}", POLICIES[policy])
    right = _neutral(
        select(profile, _document(shape, CANARY, POLICIES[policy])), CANARY
    )
    wrong = _neutral(select(profile, _document(shape, OTHER, POLICIES[policy])), OTHER)
    # Booleans, so a failure does not print the value.
    same = right == wrong
    assert same, "the override's answer tells a right guess from a wrong one"


@pytest.mark.parametrize("shape", SHAPES)
def test_the_control_an_override_of_text_answers_by_its_change(select, shape):
    """The same overrides of a profile that writes the setting as text: one that
    keeps it is bound, and one that changes it is refused."""
    profile = _document(shape, LITERAL, NOTHING)
    kept, _ = select(profile, _document(shape, LITERAL, NOTHING))
    changed, _ = select(profile, _document(shape, OTHER, NOTHING))
    assert kept.get("success") is True, kept.get("error")
    assert changed.get("success") is False


def test_an_override_that_writes_the_reference_keeps_the_profile_s_value(select):
    """An override that writes the setting as the profile does, as its
    reference, changes nothing, and the session keeps the value the profile
    read from the environment, recorded as the reference."""
    profile = _document("project-name", "${ASH_KEY}", NOTHING)
    result, bound = select(profile, profile)
    assert result.get("success") is True, result.get("error")
    kept = bound is not None and "${ASH_KEY}" in bound and CANARY not in bound
    assert kept, "the bound configuration does not hold the reference"
