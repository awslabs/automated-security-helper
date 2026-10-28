# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A patch op's outcome does not depend on a key the profile read from the
environment.

A mapping can hold a key a profile read from the environment: a section of
``reporters``, ``scanners`` or ``converters`` named ``${VAR}``, or a key of an
extra plugin's ``options``. An op whose path goes through a key of that mapping
applies only when the key exists, ``replace /reporters/<name>/enabled`` say, so
its outcome depends on the variable's value. Such an op is refused, with
one text, whether or not its key is the value. Where the mapping has built-in
keys (a plugin section), every op on the profile is refused first, with one
text (test_runtime_patch_refuses_a_profile_whose_key_can_name_a_built_in.py).
Elsewhere a key the profile writes as text is patched like any other.

The variable is ``ASH_KEY_NAME``, not ``ASH_KEY``: a name ending in ``_KEY`` is
secret-shaped (core/constants.py, ``ASH_CONFIG_ENV_VAR_SECRET_SUFFIXES``), so the
loader never reads it and a reference to it stays a literal key.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import RuntimeOverridesConfig
from automated_security_helper.config.runtime_patch import (
    KEY_READ_FROM_THE_ENVIRONMENT_REFUSAL,
    PROFILE_KEY_CAN_NAME_A_BUILT_IN_REFUSAL,
    RuntimePatchDeniedError,
    apply_runtime_patch,
)

CANARY = "ash-canary-7f3e-0123456789"
# The same length as CANARY, so a right and a wrong guess differ only in text.
OTHER = "ash-canary-0000-9876543210"


def _base(tmp_path: Path, monkeypatch, text: str):
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    monkeypatch.setenv("ASH_KEY_NAME", CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / ".ash.yaml"
    path.write_text(text, encoding="utf-8")
    _, base = load_config_file_for_run(path)
    keyed = any(rewrite.kind == "key" for rewrite in base._written_references)
    assert keyed, "the control: the profile reads a key from the environment"
    return base


SECTIONS = {
    "reporters": "reporters:\n  ${ASH_KEY_NAME}:\n    enabled: false\n  sarif:\n    enabled: true\n",
    "scanners": "scanners:\n  ${ASH_KEY_NAME}:\n    enabled: false\n  bandit:\n    enabled: true\n",
    "converters": "converters:\n  ${ASH_KEY_NAME}:\n    enabled: false\n  jupyter:\n    enabled: true\n",
}
ALLOW_ALL = RuntimeOverridesConfig(
    enabled=True,
    allowed_paths=["/reporters/**", "/scanners/**", "/converters/**"],
    denied_paths=[],
)


def _refusal(base, op, guess: str = "") -> str:
    """The refusal's rule, with the client's own guess in it written GUESS: a
    rule may name the op's path, which the client wrote."""
    with pytest.raises(RuntimePatchDeniedError) as refused:
        apply_runtime_patch(base, [op], allowlist=ALLOW_ALL)
    rule = refused.value.rule
    return rule.replace(guess, "GUESS") if guess else rule


@pytest.mark.parametrize("segment", sorted(SECTIONS))
@pytest.mark.parametrize("shape", ["replace", "remove", "test", "add"])
def test_a_right_guess_is_refused_as_a_wrong_one(tmp_path, monkeypatch, segment, shape):
    base = _base(tmp_path, monkeypatch, SECTIONS[segment])
    ops = {
        guess: {
            "replace": {
                "op": "replace",
                "path": f"/{segment}/{guess}/enabled",
                "value": True,
            },
            "remove": {"op": "remove", "path": f"/{segment}/{guess}"},
            "test": {
                "op": "test",
                "path": f"/{segment}/{guess}/enabled",
                "value": False,
            },
            "add": {
                "op": "add",
                "path": f"/{segment}/{guess}",
                "value": {"enabled": True},
            },
        }[shape]
        for guess in (CANARY, OTHER)
    }
    right = _refusal(base, ops[CANARY], CANARY)
    wrong = _refusal(base, ops[OTHER], OTHER)
    # Booleans, so a failure does not print the value.
    same = right == wrong
    assert same, "the refusal tells a right guess from a wrong one"


def test_an_extra_plugin_s_option_key_read_from_the_environment(tmp_path, monkeypatch):
    base = _base(
        tmp_path,
        monkeypatch,
        "scanners:\n  customx:\n    enabled: true\n    options:\n      ${ASH_KEY_NAME}: x\n",
    )
    rules = [
        _refusal(
            base,
            {
                "op": "replace",
                "path": f"/scanners/customx/options/{guess}",
                "value": "y",
            },
            guess,
        )
        for guess in (CANARY, OTHER)
    ]
    same = rules[0] == rules[1]
    assert same, "the refusal tells a right guess from a wrong one"


@pytest.mark.parametrize(
    ("segment", "known"),
    [
        pytest.param("reporters", "sarif", id="a-key-the-profile-writes"),
        pytest.param("reporters", "markdown", id="a-default-key"),
        pytest.param("scanners", "bandit", id="a-scanner-the-profile-writes"),
        pytest.param("converters", "archive", id="a-default-converter"),
    ],
)
def test_a_plugin_section_s_known_key_is_refused_with_the_profile(
    tmp_path, monkeypatch, segment, known
):
    """A plugin section has built-in keys, which the variable can name, so even
    a key the profile writes as text, or a default one, is refused there: the
    whole profile is, with one text."""
    base = _base(tmp_path, monkeypatch, SECTIONS[segment])
    rule = _refusal(
        base, {"op": "replace", "path": f"/{segment}/{known}/enabled", "value": False}
    )
    refused = rule == PROFILE_KEY_CAN_NAME_A_BUILT_IN_REFUSAL
    assert refused, "the op was not refused with the profile's text"


OPTIONS = (
    "scanners:\n  customx:\n    enabled: true\n    options:\n"
    "      ${ASH_KEY_NAME}: x\n      known: y\n"
)


def test_an_option_the_profile_writes_as_text_is_patched(tmp_path, monkeypatch):
    """An extra plugin's options have no built-in keys: there, a key the profile
    writes as text beside one read from the environment is patched."""
    base = _base(tmp_path, monkeypatch, OPTIONS)
    patched = apply_runtime_patch(
        base,
        [{"op": "replace", "path": "/scanners/customx/options/known", "value": "z"}],
        allowlist=ALLOW_ALL,
    )
    options = patched.scanners.model_dump(by_alias=False)["customx"]["options"]
    applied = options["known"] == "z"
    assert applied, "the op was not applied"


def _outcome(base, op) -> str:
    """What applying ``op`` answers: the refusal's rule, or that it applied."""
    try:
        apply_runtime_patch(base, [op], allowlist=ALLOW_ALL)
    except RuntimePatchDeniedError as refused:
        return f"refused: {refused.rule}"
    return "applied"


@pytest.mark.parametrize(
    ("segment", "default"),
    [
        pytest.param("reporters", "markdown", id="a-default-reporter"),
        pytest.param("scanners", "semgrep", id="a-default-scanner"),
        pytest.param("converters", "archive", id="a-default-converter"),
    ],
)
def test_an_op_at_a_default_key_answers_the_same_whatever_the_variable_holds(
    tmp_path, monkeypatch, segment, default
):
    """``replace /reporters/markdown/enabled`` where the profile's section named
    ${ASH_KEY_NAME} is that default's name, or another: the profile is refused
    either way, so the op's answer does not tell which."""
    op = {"op": "replace", "path": f"/{segment}/{default}/enabled", "value": False}
    answers = []
    for value in (default, CANARY):
        base = _base_reading(tmp_path, monkeypatch, SECTIONS[segment], value)
        answers.append(_outcome(base, op))
    same = answers[0] == answers[1]
    assert same, "the op's answer tells whether the variable holds a default key"
    refused = answers[0] == f"refused: {PROFILE_KEY_CAN_NAME_A_BUILT_IN_REFUSAL}"
    assert refused, "the op at a default key was not refused with the profile"


def _base_reading(tmp_path: Path, monkeypatch, text: str, value: str):
    """``_base`` with ASH_KEY_NAME holding ``value``."""
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    monkeypatch.setenv("ASH_KEY_NAME", value)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / f"{value}.ash.yaml"
    path.write_text(text, encoding="utf-8")
    _, base = load_config_file_for_run(path)
    keyed = any(rewrite.kind == "key" for rewrite in base._written_references)
    assert keyed, "the control: the profile reads a key from the environment"
    return base


def test_a_mapping_the_client_replaced_holds_the_client_s_keys(tmp_path, monkeypatch):
    """Once an op replaces the whole mapping, its keys are the client's, and a
    later op may name them."""
    base = _base(tmp_path, monkeypatch, OPTIONS)
    patched = apply_runtime_patch(
        base,
        [
            {
                "op": "replace",
                "path": "/scanners/customx/options",
                "value": {"customy": "a"},
            },
            {
                "op": "replace",
                "path": "/scanners/customx/options/customy",
                "value": "b",
            },
        ],
        allowlist=ALLOW_ALL,
    )
    options = patched.scanners.model_dump(by_alias=False)["customx"]["options"]
    applied = options == {"customy": "b"}
    assert applied, "the op was not applied"


def test_a_mapping_with_no_key_read_from_the_environment_is_unchanged(
    tmp_path, monkeypatch
):
    """The control: a missing section in a mapping whose keys are all text is
    refused as an op that cannot apply."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    path = tmp_path / ".ash.yaml"
    path.write_text("scanners:\n  bandit:\n    enabled: true\n", encoding="utf-8")
    _, base = load_config_file_for_run(path)
    rule = _refusal(
        base, {"op": "replace", "path": f"/scanners/{OTHER}/enabled", "value": True}
    )
    applying = rule.startswith("patch apply failed")
    assert applying, "the op was refused by another rule"


def test_select_profile_answers_a_right_guess_as_a_wrong_one(tmp_path, monkeypatch):
    """The MCP tool, as a client calls it: the whole response is the same text."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_KEY_NAME", CANARY)
    profile = tmp_path / "operator.ash.yaml"
    profile.write_text(
        "reporters:\n"
        "  ${ASH_KEY_NAME}:\n"
        "    enabled: false\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths:\n"
        "        - /reporters/**\n"
        "      denied_paths: []\n",
        encoding="utf-8",
    )
    answers = {}
    for guess in (CANARY, OTHER):
        profile_registry.clear_profile_registry()
        profile_registry.clear_all_session_state()
        profile_registry.set_profile_registry(
            profile_registry.register_profiles([f"op={profile}"])
        )
        try:
            result = mcp_select_profile(
                "op",
                patch_ops=[
                    {
                        "op": "replace",
                        "path": f"/reporters/{guess}/enabled",
                        "value": True,
                    }
                ],
                session_id="session-a",
            )
        finally:
            profile_registry.clear_profile_registry()
            profile_registry.clear_all_session_state()
        answers[guess] = json.dumps(result, sort_keys=True).replace(guess, "GUESS")
    same = answers[CANARY] == answers[OTHER]
    assert same, "the response tells a right guess from a wrong one"
    refused = '"success": false' in answers[CANARY]
    assert refused, "the op through the variable's key applied"


def test_an_override_that_leaves_the_section_out_names_no_key(tmp_path, monkeypatch):
    """select_profile's override_yaml: an override without the profile's
    section named ${ASH_KEY_NAME} becomes a remove op through that key. It is
    refused with the one text, which names neither the op nor the key."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_KEY_NAME", CANARY)
    policy = (
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths:\n"
        "        - /project_name\n"
        "      denied_paths: []\n"
    )
    profile = tmp_path / "operator.ash.yaml"
    profile.write_text(
        "project_name: demo\n"
        + policy
        + "reporters:\n  ${ASH_KEY_NAME}:\n    enabled: false\n",
        encoding="utf-8",
    )
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    profile_registry.set_profile_registry(
        profile_registry.register_profiles([f"op={profile}"])
    )
    try:
        result = mcp_select_profile(
            "op",
            override_yaml="project_name: client\n" + policy,
            session_id="session-a",
        )
    finally:
        profile_registry.clear_profile_registry()
        profile_registry.clear_all_session_state()
    refused = result["success"] is False
    assert refused, "the override was not refused"
    # Booleans, so a failure does not print the value.
    shown = CANARY in json.dumps(result)
    assert not shown, "the denial names the key"


def _outcome_reading(tmp_path: Path, monkeypatch, text: str, value, op) -> str:
    """``_outcome`` of ``op`` on the profile ``text``, loaded with ASH_KEY_NAME
    holding ``value`` (None: unset)."""
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    if value is None:
        monkeypatch.delenv("ASH_KEY_NAME", raising=False)
    else:
        monkeypatch.setenv("ASH_KEY_NAME", value)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / f"{value}.ash.yaml"
    path.write_text(text, encoding="utf-8")
    _, base = load_config_file_for_run(path)
    return _outcome(base, op)


def test_an_option_key_written_as_a_reference_whatever_the_variable_holds(
    tmp_path, monkeypatch
):
    """``${ASH_KEY_NAME:opt}`` in an extra plugin's options: the key is the default
    the file wrote when the variable is unset, and the variable's value when it
    is set. An op through it answers the same either way, from the file as
    written."""
    text = (
        "scanners:\n  customx:\n    enabled: true\n    options:\n"
        "      ${ASH_KEY_NAME:opt}: x\n"
    )
    op = {"op": "replace", "path": "/scanners/customx/options/opt", "value": "y"}
    answers = [
        _outcome_reading(tmp_path, monkeypatch, text, value, op)
        for value in (None, "opt")
    ]
    same = answers[0] == answers[1]
    assert same, "the op's answer tells whether the variable is set"
    refused = answers[0] == f"refused: {KEY_READ_FROM_THE_ENVIRONMENT_REFUSAL}"
    assert refused, "the op through the key was not refused with the one text"


NESTED_OPTIONS = (
    "scanners:\n  customx:\n    enabled: true\n    options:\n"
    "      known:\n        a: 1\n      ${ASH_KEY_NAME}:\n        b: 2\n"
)


@pytest.mark.parametrize(
    ("text", "op"),
    [
        pytest.param(
            OPTIONS,
            {
                "op": "test",
                "path": "/scanners/customx/options",
                "value": {"known": "y"},
            },
            id="at-the-mapping",
        ),
        pytest.param(
            OPTIONS,
            {
                "op": "test",
                "path": "/scanners/customx",
                "value": {"enabled": True, "options": {"known": "y"}},
            },
            id="above-the-mapping",
        ),
        pytest.param(
            NESTED_OPTIONS,
            {
                "op": "test",
                "path": "/scanners/customx/options/known",
                "value": {"a": 1},
            },
            id="through-a-key-written-as-text",
        ),
    ],
)
def test_a_test_op_beside_an_option_key_read_from_the_environment(
    tmp_path, monkeypatch, text, op
):
    """A key the profile writes as text, beside one read from the environment:
    where the variable names that key, the two merge, so a test op at the
    mapping, above it or through it would tell which. Such a test op is refused,
    whatever the variable holds; a replace through the key written as text is
    applied (test_an_option_the_profile_writes_as_text_is_patched)."""
    answers = [
        _outcome_reading(tmp_path, monkeypatch, text, value, op)
        for value in ("known", CANARY)
    ]
    same = answers[0] == answers[1]
    assert same, "the test op's answer tells whether the variable names the key"
    refused = answers[0] == f"refused: {KEY_READ_FROM_THE_ENVIRONMENT_REFUSAL}"
    assert refused, "the test op was not refused with the one text"
