# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A profile that reads a key from the environment where the configuration has
built-in keys is not patched, overridden or tested.

A section of ``reporters`` or ``scanners`` named ``${ASH_KEY}`` is a built-in's
section when the variable names a built-in (``markdown``, ``bandit``): the
profile's settings merge with the built-in's. The profile as written then has
no section under the built-in's name, and another value leaves the built-in's
default section in place. A client's override that keeps the reference, one
that adds the built-in's section, and a test op at the built-in's section would
each be answered by one of those two shapes, so the answer would tell whether the
variable names a built-in. Every mutation of such a profile is refused with one
text, whatever the variable holds. A profile that writes the built-in's name as
text is patched, and so is one whose key read from the environment sits
where the configuration has no built-in keys.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.config.runtime_patch import (
    PROFILE_KEY_CAN_NAME_A_BUILT_IN_REFUSAL,
)

#: Each section's built-in name, and a near miss that names no built-in.
NAMES = {"reporters": ("markdown", "markdowm"), "scanners": ("bandit", "banditt")}

POLICIES = {
    "none": (
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths: []\n"
        "      denied_paths: []\n"
    ),
    "all": (
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths:\n"
        "        - /**\n"
        "      denied_paths: []\n"
    ),
}


def _profile(section: str, policy: str) -> str:
    return (
        "project_name: demo\n"
        + POLICIES[policy]
        + f"{section}:\n  ${{ASH_KEY}}:\n    enabled: false\n"
    )


def _override(section: str, policy: str, kind: str) -> str:
    """An override_yaml a client sends: the profile as written, which keeps the
    reference, alone or with the built-in's section added."""
    name = NAMES[section][0]
    text = _profile(section, policy)
    if kind == "ref-plus-name-on":
        text += f"  {name}:\n    enabled: true\n"
    elif kind == "ref-plus-name-off":
        text += f"  {name}:\n    enabled: false\n"
    return text


@pytest.fixture
def select(tmp_path, monkeypatch):
    """select_profile on a registered profile with ASH_KEY holding a value: the
    response, and the config path the session was bound to, or None."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    def _select(value: str | None, profile_text: str, **mode):
        # None leaves ASH_KEY unset.
        if value is None:
            monkeypatch.delenv("ASH_KEY", raising=False)
        else:
            monkeypatch.setenv("ASH_KEY", value)
        profile = tmp_path / f"{value}.ash.yaml"
        profile.write_text(profile_text, encoding="utf-8")
        profile_registry.clear_profile_registry()
        profile_registry.clear_session_state()
        try:
            profile_registry.set_profile_registry(
                profile_registry.register_profiles([f"op={profile}"])
            )
            result = mcp_select_profile("op", session_id="session-a", **mode)
            bound = profile_registry.resolve_session_config_path("session-a")
        finally:
            profile_registry.clear_profile_registry()
            profile_registry.clear_session_state()
        return result, bound

    return _select


def _mode(section: str, policy: str, kind: str) -> dict:
    name = NAMES[section][0]
    if kind == "test-op":
        return {
            "patch_ops": [
                {"op": "test", "path": f"/{section}/{name}/enabled", "value": True}
            ]
        }
    if kind == "replace-op":
        return {
            "patch_ops": [
                {"op": "replace", "path": f"/{section}/{name}/enabled", "value": True}
            ]
        }
    return {"override_yaml": _override(section, policy, kind)}


CASES = [
    pytest.param(section, policy, kind, id=f"{section}-{policy}-{kind}")
    for section in sorted(NAMES)
    for policy in ("none", "all")
    for kind in ("ref-kept", "ref-plus-name-on", "ref-plus-name-off")
] + [
    pytest.param(section, "all", kind, id=f"{section}-all-{kind}")
    for section in sorted(NAMES)
    for kind in ("test-op", "replace-op")
]


@pytest.mark.parametrize(("section", "policy", "kind"), CASES)
def test_a_built_in_name_is_answered_as_a_near_miss(select, section, policy, kind):
    built_in, near_miss = NAMES[section]
    profile = _profile(section, policy)
    mode = _mode(section, policy, kind)
    answers = {value: select(value, profile, **mode) for value in (built_in, near_miss)}
    responses = {
        value: json.dumps(result, sort_keys=True)
        for value, (result, _) in answers.items()
    }
    # Booleans, so a failure prints no response.
    same = responses[built_in] == responses[near_miss]
    assert same, "the answer tells whether the variable names a built-in"
    refused = all(result["success"] is False for result, _ in answers.values())
    assert refused, "a mutation of the profile was not refused"
    one_text = all(
        PROFILE_KEY_CAN_NAME_A_BUILT_IN_REFUSAL in result["error"]
        for result, _ in answers.values()
    )
    assert one_text, "the refusal is not the one text"
    unbound = all(bound is None for _, bound in answers.values())
    assert unbound, "a refused call bound the session"


def _same_refusal(answers: dict) -> None:
    """Every answer is the one refusal, the same response, and no session bound."""
    responses = {json.dumps(result, sort_keys=True) for result, _ in answers.values()}
    # Booleans, so a failure prints no response.
    same = len(responses) == 1
    assert same, "the answer tells what the variable holds"
    refused = all(result["success"] is False for result, _ in answers.values())
    assert refused, "a mutation of the profile was not refused"
    one_text = all(
        PROFILE_KEY_CAN_NAME_A_BUILT_IN_REFUSAL in result["error"]
        for result, _ in answers.values()
    )
    assert one_text, "the refusal is not the one text"
    unbound = all(bound is None for _, bound in answers.values())
    assert unbound, "a refused call bound the session"


#: Profiles whose file writes a reporters key as a reference, and the values of
#: ASH_KEY (None: unset) a client must not tell apart. Decided from the file as
#: written: whether the variable is set, and whether its value is a key the
#: profile also writes as text, change nothing.
WRITTEN_KEYS = {
    "a-default-naming-a-built-in": (
        "reporters:\n  ${ASH_KEY:markdown}:\n    enabled: false\n",
        (None, "markdown"),
    ),
    "a-default-naming-no-built-in": (
        "reporters:\n  ${ASH_KEY:markdowm}:\n    enabled: false\n",
        (None, "markdowm"),
    ),
    "beside-the-built-in-it-can-name": (
        "reporters:\n  markdown:\n    enabled: true\n  ${ASH_KEY}:\n    enabled: false\n",
        ("markdown", "markdowm"),
    ),
}


def _mutation(kind: str, profile: str) -> dict:
    return {
        "replace-op": {
            "patch_ops": [
                {"op": "replace", "path": "/reporters/markdown/enabled", "value": True}
            ]
        },
        "test-op": {
            "patch_ops": [
                {"op": "test", "path": "/reporters/markdown/enabled", "value": True}
            ]
        },
        "no-op": {"patch_ops": []},
        "override-as-written": {"override_yaml": profile},
    }[kind]


@pytest.mark.parametrize("shape", sorted(WRITTEN_KEYS))
@pytest.mark.parametrize(
    "kind", ["replace-op", "test-op", "no-op", "override-as-written"]
)
def test_a_key_the_file_writes_as_a_reference_is_answered_whatever_it_reads(
    select, shape, kind
):
    section, values = WRITTEN_KEYS[shape]
    profile = "project_name: demo\n" + POLICIES["all"] + section
    _same_refusal(
        {value: select(value, profile, **_mutation(kind, profile)) for value in values}
    )


@pytest.mark.parametrize("shape", sorted(WRITTEN_KEYS))
def test_a_workspace_override_on_a_key_written_as_a_reference(
    tmp_path, monkeypatch, shape
):
    from automated_security_helper.cli.mcp.workspace import _gate_client_overrides
    from automated_security_helper.config.runtime_patch import (
        RuntimePatchDeniedError,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    section, values = WRITTEN_KEYS[shape]
    rules = []
    for value in values:
        if value is None:
            monkeypatch.delenv("ASH_KEY", raising=False)
        else:
            monkeypatch.setenv("ASH_KEY", value)
        profile = tmp_path / f"{value}.ash.yaml"
        profile.write_text(
            "project_name: demo\n" + POLICIES["all"] + section, encoding="utf-8"
        )
        try:
            _gate_client_overrides(["reporters.markdown.enabled=true"], str(profile))
        except RuntimePatchDeniedError as refused:
            rules.append(refused.rule)
        else:
            rules.append(None)
    same = rules == [PROFILE_KEY_CAN_NAME_A_BUILT_IN_REFUSAL] * len(values)
    assert same, "the workspace answer is not the one refusal for every value"


#: A suppression entry whose key is read from the environment. AshSuppression
#: has fixed fields, so the key names one of them, and the entry as written
#: differs with it.
SUPPRESSION = (
    "  suppressions:\n    - path: a.py\n      reason: r\n      ${ASH_KEY}: pkg\n"
)
SUPPRESSION_KEYS = ("package_name", "package_path")


def _entry_as_written(tmp_path, monkeypatch, guess: str):
    """The suppression entry as the profile's record writes it when ASH_KEY
    holds ``guess``: the value a client's test op compares for that guess."""
    from automated_security_helper.config.resolve_config import load_config_file_for_run
    from automated_security_helper.config.runtime_patch import _as_written

    monkeypatch.setenv("ASH_KEY", guess)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / f"guess-{guess}.ash.yaml"
    path.write_text(
        "project_name: demo\n" + POLICIES["all"] + SUPPRESSION, encoding="utf-8"
    )
    _, base = load_config_file_for_run(path)
    dumped = base.model_dump(mode="python", by_alias=False)
    written = _as_written(base, base._written_references, dumped)
    return json.loads(json.dumps(written["global_settings"]["suppressions"][0]))


@pytest.mark.parametrize(
    "at", ["/global_settings/suppressions/0", "/global_settings/suppressions"]
)
def test_a_list_entry_s_key_read_from_the_environment_is_not_tested(
    tmp_path, monkeypatch, select, at
):
    """A test op at a suppression entry, or at the list, with the entry as the
    profile's record writes it for each guess: a right guess and a wrong one are
    answered alike."""
    entries = {
        guess: _entry_as_written(tmp_path, monkeypatch, guess)
        for guess in SUPPRESSION_KEYS
    }
    profile = "project_name: demo\n" + POLICIES["all"] + SUPPRESSION
    answers = {}
    for value in SUPPRESSION_KEYS:
        for guess, entry in entries.items():
            compared = entry if at.endswith("/0") else [entry]
            answers[(value, guess)] = select(
                value,
                profile,
                patch_ops=[{"op": "test", "path": at, "value": compared}],
            )
    _same_refusal(answers)


@pytest.mark.parametrize("section", sorted(NAMES))
def test_a_profile_that_writes_the_built_in_name_is_patched(select, section):
    """The control: the built-in's name written as text, no key read from the
    environment."""
    name = NAMES[section][0]
    profile = (
        "project_name: demo\n"
        + POLICIES["all"]
        + f"{section}:\n  {name}:\n    enabled: false\n"
    )
    result, bound = select(
        name,
        profile,
        patch_ops=[
            {"op": "replace", "path": f"/{section}/{name}/enabled", "value": True}
        ],
    )
    applied = result["success"] is True and bound is not None
    assert applied, "a patch of a profile with no key read from the environment failed"


def test_a_key_read_where_there_are_no_built_in_keys_is_patched(select):
    """The control: an extra plugin's options read a key from the environment.
    The configuration has no built-in keys there, so the profile's other
    settings are patched."""
    profile = (
        "project_name: demo\n"
        + POLICIES["all"]
        + "scanners:\n  customx:\n    enabled: true\n    options:\n"
        "      ${ASH_KEY}: x\n"
    )
    result, bound = select(
        "anything",
        profile,
        patch_ops=[
            {"op": "replace", "path": "/scanners/customx/enabled", "value": False}
        ],
    )
    applied = result["success"] is True and bound is not None
    assert applied, "the patch was refused"


@pytest.mark.parametrize("section", sorted(NAMES))
def test_a_workspace_override_is_refused_with_the_one_text(
    tmp_path, monkeypatch, section
):
    """A workspace scan's config_overrides are checked against the session's
    profile the same way (cli/mcp/workspace._gate_client_overrides)."""
    from automated_security_helper.cli.mcp.workspace import _gate_client_overrides
    from automated_security_helper.config.runtime_patch import (
        RuntimePatchDeniedError,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    rules = []
    for value in NAMES[section]:
        monkeypatch.setenv("ASH_KEY", value)
        profile = tmp_path / f"{value}.ash.yaml"
        profile.write_text(_profile(section, "all"), encoding="utf-8")
        with pytest.raises(RuntimePatchDeniedError) as refused:
            _gate_client_overrides(
                [f"{section}.{NAMES[section][0]}.enabled=true"], str(profile)
            )
        rules.append(refused.value.rule)
    same = rules[0] == rules[1] == PROFILE_KEY_CAN_NAME_A_BUILT_IN_REFUSAL
    assert same, "the workspace refusal is not the one text for both values"
