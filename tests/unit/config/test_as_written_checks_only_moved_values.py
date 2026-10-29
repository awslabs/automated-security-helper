# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A session config is checked only where a patch moved the profile's values.

Were the check that a session config holds no value the profile read from the
environment as text to compare every string of the whole dump, defaults
included, with each such value, a valid profile whose value is also a default
string (``markdown``, a reporter's name; ``opengrep``, a scanner's) would not be
written, with no patch at all. And a client's own string equal to a value
would be refused, or written as the profile's reference: either way the client
would learn the value was right.

Each value is followed through the patch's ops to where it lands, and only
there is it checked. A string an op wrote is the client's text, whatever it
holds: written as the client wrote it, shown by get_config as the client wrote
it, and indistinguishable from a wrong guess.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

CANARY = "ash-canary-7f3e-0123456789"
SHORT = "c7f3e0"
# The same length as CANARY, so a right and a wrong guess differ only in text.
OTHER = "ash-canary-0000-9876543210"


@pytest.fixture
def environment(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    yield tmp_path
    from automated_security_helper.cli.mcp import profile_registry

    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()


def _allowing(paths: list, replace_default_denied_paths: bool = False) -> str:
    listed = "".join(f"        - {path}\n" for path in paths)
    replaced = "      replace_default_denied_paths: true\n"
    return (
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths:\n"
        f"{listed}"
        "      denied_paths: []\n"
        f"{replaced if replace_default_denied_paths else ''}"
    )


def _select(tmp_path: Path, profile_text: str, ops) -> dict:
    """select_profile for a profile, as a client calls it, and the session
    config's path when it was written.

    The session stays bound until the test ends, as it does for a client: a
    patched copy holds each reference as quoted text, and get_config shows it
    against the operator's copy, which the binding records
    (``resolve_session_trusted_config_path``).
    """
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    profile = tmp_path / "operator.ash.yaml"
    profile.write_text(profile_text, encoding="utf-8")
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    profile_registry.set_profile_registry(
        profile_registry.register_profiles([f"op={profile}"])
    )
    result = mcp_select_profile("op", patch_ops=ops, session_id="session-a")
    if result["success"]:
        result["path"] = Path(profile_registry.resolve_session_config_path("session-a"))
    return result


@pytest.mark.parametrize(
    ("profile_text", "variable", "value", "read"),
    [
        pytest.param(
            "output_formats:\n  - ${ASH_FMT}\n",
            "ASH_FMT",
            "markdown",
            lambda config: config.output_formats == ["markdown"],
            id="output-format-markdown",
        ),
        pytest.param(
            "output_formats:\n  - ${ASH_FMT}\n",
            "ASH_FMT",
            "cyclonedx",
            lambda config: config.output_formats == ["cyclonedx"],
            id="output-format-cyclonedx",
        ),
        pytest.param(
            "project_name: ${ASH_PN}\n",
            "ASH_PN",
            "opengrep",
            lambda config: config.project_name == "opengrep",
            id="project-name-opengrep",
        ),
        pytest.param(
            "project_name: ${ASH_PN}\n",
            "ASH_PN",
            "npm-audit",
            lambda config: config.project_name == "npm-audit",
            id="project-name-npm-audit",
        ),
    ],
)
def test_a_static_select_writes_a_value_that_is_also_a_default_string(
    environment, monkeypatch, profile_text, variable, value, read
):
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.setenv(variable, value)
    result = _select(environment, profile_text + _allowing(["/project_name"]), None)
    written = result["success"] is True
    assert written, "the session config was not written"
    text = result["path"].read_text(encoding="utf-8")
    referenced = "${" + variable + "}" in text
    assert referenced, "the profile's reference was not written"
    assert read(resolve_config(result["path"])), "the reference reads another value"


PROJECT = "project_name: ${ASH_PN}\n" + _allowing(["/project_name"])
# A value the client may not patch, which a client string can still equal.
DENIED = (
    "project_name: demo\n"
    "reporters:\n"
    "  gitlab-cyclonedx:\n"
    "    options:\n"
    "      package_manager_override: ${ASH_DENIED}\n"
) + _allowing(["/project_name"])
LIST = ("external_reports_to_include:\n  - ${ASH_PN}\n  - other.sarif\n") + _allowing(
    ["/external_reports_to_include", "/external_reports_to_include/**"]
)
# A key the profile read from the environment, in a mapping the client may
# replace. An extra plugin's options: a mapping with built-in keys (a plugin
# section) makes every patch of the profile refused
# (test_runtime_patch_refuses_a_profile_whose_key_can_name_a_built_in.py). The
# variable is ASH_KEY_NAME: a name ending in _KEY is secret-shaped
# (core/constants.py, ASH_CONFIG_ENV_VAR_SECRET_SUFFIXES) and never read. The
# default denied paths include one inside every scanner's options
# (/scanners/*/options/offline), and a patch that replaces the whole mapping
# writes over it, so the profile sets its own.
KEYED = (
    "scanners:\n  customx:\n    enabled: true\n    options:\n      ${ASH_KEY_NAME}: x\n"
) + _allowing(["/scanners/customx/options"], replace_default_denied_paths=True)


def _session(environment, monkeypatch, profile_text, ops) -> dict:
    """The session config and get_config's answer for it, each with the
    client's guess in place of the text the client wrote."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    result = _select(environment, profile_text, ops)
    assert result["success"] is True, "the patch was refused"
    text = result["path"].read_text(encoding="utf-8")
    shown = json.dumps(
        mcp_get_config(config_path=str(result["path"]), session_id="session-a")
    )
    return {"text": text, "shown": shown}


@pytest.mark.parametrize(
    ("profile_text", "variable", "op_for"),
    [
        pytest.param(
            PROJECT,
            "ASH_PN",
            lambda guess: {"op": "replace", "path": "/project_name", "value": guess},
            id="over-the-profile-s-own-value",
        ),
        pytest.param(
            PROJECT,
            "ASH_PN",
            lambda guess: {
                "op": "replace",
                "path": "/project_name",
                "value": guess + "-suffix",
            },
            id="the-value-then-text",
        ),
        pytest.param(
            DENIED,
            "ASH_DENIED",
            lambda guess: {"op": "replace", "path": "/project_name", "value": guess},
            id="equal-to-a-denied-value",
        ),
        pytest.param(
            LIST,
            "ASH_PN",
            lambda guess: {
                "op": "replace",
                "path": "/external_reports_to_include/0",
                "value": guess,
            },
            id="over-a-list-entry-s-value",
        ),
        pytest.param(
            LIST,
            "ASH_PN",
            lambda guess: {
                "op": "add",
                "path": "/external_reports_to_include/-",
                "value": guess,
            },
            id="a-new-entry-beside-the-profile-s",
        ),
        pytest.param(
            LIST,
            "ASH_PN",
            lambda guess: {
                "op": "add",
                "path": "/external_reports_to_include/0",
                "value": guess,
            },
            id="a-new-entry-before-the-profile-s",
        ),
        pytest.param(
            KEYED,
            "ASH_KEY_NAME",
            lambda guess: {
                "op": "replace",
                "path": "/scanners/customx/options",
                "value": {guess: "y"},
            },
            id="a-mapping-with-the-key",
        ),
    ],
)
def test_a_right_guess_reads_as_a_wrong_one(
    environment, monkeypatch, profile_text, variable, op_for
):
    """The session config, and what get_config shows of it, are the same text
    for a client string that equals the value and for one that does not."""
    monkeypatch.setenv(variable, CANARY)
    right = _session(environment, monkeypatch, profile_text, [op_for(CANARY)])
    wrong = _session(environment, monkeypatch, profile_text, [op_for(OTHER)])
    # Booleans, so a failure does not print the value.
    same_file = right["text"].replace(CANARY, "GUESS") == wrong["text"].replace(
        OTHER, "GUESS"
    )
    assert same_file, "the session config tells a right guess from a wrong one"
    same_shown = right["shown"].replace(CANARY, "GUESS") == wrong["shown"].replace(
        OTHER, "GUESS"
    )
    assert same_shown, "get_config tells a right guess from a wrong one"


MARKER = "<from ${ASH_PN}>"


@pytest.mark.parametrize(
    ("ops", "expected"),
    [
        pytest.param(
            [],
            [MARKER, "other.sarif"],
            id="d-no-patch",
        ),
        pytest.param(
            [{"op": "add", "path": "/external_reports_to_include/-", "value": CANARY}],
            [MARKER, "other.sarif", CANARY],
            id="a-the-value-appended",
        ),
        pytest.param(
            [{"op": "add", "path": "/external_reports_to_include/0", "value": CANARY}],
            [CANARY, MARKER, "other.sarif"],
            id="b-the-value-added-before",
        ),
        pytest.param(
            [{"op": "add", "path": "/external_reports_to_include/0", "value": OTHER}],
            [OTHER, MARKER, "other.sarif"],
            id="b-another-string-added-before",
        ),
        pytest.param(
            [
                {
                    "op": "replace",
                    "path": "/external_reports_to_include/0",
                    "value": CANARY,
                }
            ],
            [CANARY, "other.sarif"],
            id="c-the-value-over-the-reference",
        ),
        pytest.param(
            [
                {
                    "op": "replace",
                    "path": "/external_reports_to_include/0",
                    "value": OTHER,
                }
            ],
            [OTHER, "other.sarif"],
            id="c-another-string-over-the-reference",
        ),
    ],
)
def test_get_config_marks_the_reference_at_its_entry_after_the_patch(
    environment, monkeypatch, ops, expected
):
    """get_config on the session config marks the profile's reference at the
    entry the patch moved it to, and a client's entry as written, whatever it
    holds."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    monkeypatch.setenv("ASH_PN", CANARY)
    result = _select(environment, LIST, ops or None)
    assert result["success"] is True, "the patch was refused"
    shown = mcp_get_config(config_path=str(result["path"]), session_id="session-a")
    # A boolean, so a failure does not print the value.
    placed = shown["external_reports_to_include"] == expected
    assert placed, "an entry is not shown as expected"


def test_get_config_shows_a_client_string_equal_to_a_denied_value_as_written(
    environment, monkeypatch
):
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    monkeypatch.setenv("ASH_DENIED", CANARY)
    result = _select(
        environment,
        DENIED,
        [{"op": "replace", "path": "/project_name", "value": CANARY}],
    )
    assert result["success"] is True, "the patch was refused"
    shown = mcp_get_config(config_path=str(result["path"]), session_id="session-a")
    as_written = shown["project_name"] == CANARY
    assert as_written, "the client's string is not shown as the client wrote it"
    # The control: the profile's own reference is still shown as one.
    options = json.dumps(shown["reporters"])
    marked = "<from ${ASH_DENIED}>" in options and CANARY not in options
    assert marked, "the profile's reference is not shown as its marker"


def test_a_setting_confinement_takes_from_the_operator_keeps_its_reference(
    tmp_path, monkeypatch
):
    """An in-tree file's sandbox grants are replaced with the operator's
    (confine_sandbox_grants). Marked by location, those values are marked
    where the operator's file wrote the reference, and their values are
    redacted like the file's own."""
    from automated_security_helper.config.config_validator import record_of_config
    from automated_security_helper.config.environment_record import (
        environment_marker,
        record_environment_references,
    )
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_RP", f"/opt/{CANARY}")
    operator = tmp_path / "operator.ash.yaml"
    operator.write_text(
        "sandbox:\n  extra_read_paths:\n    - ${ASH_RP}\n", encoding="utf-8"
    )
    tree = tmp_path / "repo"
    tree.mkdir()
    in_tree = tree / ".ash.yaml"
    in_tree.write_text("project_name: demo\n", encoding="utf-8")
    config = resolve_config(
        config_path=in_tree,
        source_dir=tree,
        scanned_root=tree,
        trusted_config_path=operator,
    )
    # The control: the operator's grant is the one applied.
    applied = config.sandbox.extra_read_paths == [f"/opt/{CANARY}"]
    assert applied, "the control: the operator's grant was not applied"
    # As get_config shows a configuration (mcp_tools.mcp_get_config's shown_config).
    shown = json.dumps(
        record_environment_references(
            config.model_dump(),
            config._environment_references,
            mark=environment_marker,
        )
    )
    marked = "<from ${ASH_RP}>" in shown and CANARY not in shown
    assert marked, "get_config shows the operator's value"
    recorded = json.dumps(record_of_config(config, config.model_dump()))
    referenced = "${ASH_RP}" in recorded and CANARY not in recorded
    assert referenced, "the record holds the operator's value"
    redacted = f"/opt/{CANARY}" in config._environment_values
    assert redacted, "the operator's value is not among those redacted"


@pytest.mark.parametrize("value", [CANARY, SHORT], ids=["long-value", "short-value"])
def test_a_value_its_reference_does_not_follow_refuses_the_patch(
    environment, monkeypatch, value
):
    """With the references left where they were, the value of any length moved
    by the op is refused rather than written as text, and the refusal names no
    value."""
    from automated_security_helper.config import runtime_patch

    monkeypatch.setenv("ASH_PN", value)
    ops = [{"op": "add", "path": "/external_reports_to_include/0", "value": "c.sarif"}]
    with monkeypatch.context() as unfollowed:
        unfollowed.setattr(
            runtime_patch._ReferencesThroughPatch, "follow", lambda self, op, doc: None
        )
        result = _select(environment, LIST, ops)
    refused = result["success"] is False
    assert refused, "the patch was not refused"
    quoted = value in json.dumps(result)
    assert not quoted, "the refusal names the value"
    # The control: following the reference, the same patch is written.
    followed = _select(environment, LIST, ops)
    assert followed["success"] is True, "the control patch was refused"
