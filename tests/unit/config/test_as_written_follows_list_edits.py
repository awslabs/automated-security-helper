# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A session config keeps a list entry's reference where a patch moves it.

The profile's references are located by path, a list entry by its index. A
client's patch that adds or removes an entry before one the profile read from
the environment moves it to another index; a reference left at the old
one would have the session config hold the variable's value as text, a value no
longer read from the environment, which no redaction knows. The reference
follows its entry. A patch that would move a value where its reference does
not follow is refused (test_as_written_checks_only_moved_values.py), and the
writer refuses a config that would hold a value as text where its file wrote
the reference.
"""

from __future__ import annotations

from pathlib import Path

import pytest

CANARY = "ash-canary-7f3e-0123456789"


def _profile(entries: list) -> str:
    listed = "".join(f"  - {entry}\n" for entry in entries)
    return (
        f"external_reports_to_include:\n{listed}"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths:\n"
        "        - /external_reports_to_include\n"
        "        - /external_reports_to_include/**\n"
        "      denied_paths: []\n"
    )


@pytest.fixture
def environment(tmp_path, monkeypatch):
    # The client does not know the value.
    monkeypatch.setenv("ASH_PN", CANARY)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    return tmp_path


def _select(tmp_path: Path, entries: list, ops: list) -> dict:
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    profile = tmp_path / "operator.ash.yaml"
    profile.write_text(_profile(entries), encoding="utf-8")
    profile_registry.clear_profile_registry()
    profile_registry.clear_session_state()
    profile_registry.set_profile_registry(
        profile_registry.register_profiles([f"op={profile}"])
    )
    try:
        result = mcp_select_profile("op", patch_ops=ops, session_id="session-a")
        if result["success"]:
            result["path"] = Path(
                profile_registry.resolve_session_config_path("session-a")
            )
        return result
    finally:
        profile_registry.clear_profile_registry()
        profile_registry.clear_session_state()


@pytest.mark.parametrize(
    ("entries", "op", "expected"),
    [
        pytest.param(
            ["${ASH_PN}", "other.sarif"],
            {"op": "add", "path": "/external_reports_to_include/0", "value": "c.sarif"},
            ["c.sarif", CANARY, "other.sarif"],
            id="add-before-it",
        ),
        pytest.param(
            ["first.sarif", "${ASH_PN}"],
            {"op": "remove", "path": "/external_reports_to_include/0"},
            [CANARY],
            id="remove-before-it",
        ),
        pytest.param(
            ["${ASH_PN}", "other.sarif"],
            {"op": "add", "path": "/external_reports_to_include/-", "value": "c.sarif"},
            [CANARY, "other.sarif", "c.sarif"],
            id="append-after-it",
        ),
        pytest.param(
            ["a.sarif", "${ASH_PN}", "b.sarif"],
            {"op": "remove", "path": "/external_reports_to_include/2"},
            ["a.sarif", CANARY],
            id="remove-after-it",
        ),
    ],
)
def test_the_reference_follows_its_entry(environment, entries, op, expected):
    from automated_security_helper.config.resolve_config import resolve_config

    result = _select(environment, entries, [op])
    assert result["success"] is True, result.get("error")
    text = result["path"].read_text(encoding="utf-8")
    # Booleans, so a failure does not print the value.
    written = CANARY not in text
    assert written, "the session config holds the value"
    kept = text.count("${ASH_PN}") == 1
    assert kept, "the reference was not kept"
    read = resolve_config(result["path"]).external_reports_to_include == expected
    assert read, "the reference does not read the value at its entry"


def test_removing_the_entry_removes_its_reference(environment):
    from automated_security_helper.config.resolve_config import resolve_config

    result = _select(
        environment,
        ["${ASH_PN}", "other.sarif"],
        [{"op": "remove", "path": "/external_reports_to_include/0"}],
    )
    assert result["success"] is True, result.get("error")
    text = result["path"].read_text(encoding="utf-8")
    gone = CANARY not in text and "${ASH_PN}" not in text
    assert gone, "the removed entry is still written"
    read = resolve_config(result["path"]).external_reports_to_include == ["other.sarif"]
    assert read, "the remaining entry changed"


def test_the_writer_does_not_refuse_a_patch_that_holds_the_value_in_its_text(
    environment, monkeypatch
):
    """A client's patch over the value is the client's text, whatever it
    holds, and is written as the client wrote it
    (test_as_written_keeps_literals_literal.py)."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile
    from automated_security_helper.config.resolve_config import resolve_config

    patched = "pre-" + CANARY + "-x"
    profile = environment / "project.ash.yaml"
    profile.write_text(
        "project_name: ${ASH_PN}\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths:\n"
        "        - /project_name\n"
        "      denied_paths: []\n",
        encoding="utf-8",
    )
    profile_registry.clear_profile_registry()
    profile_registry.clear_session_state()
    profile_registry.set_profile_registry(
        profile_registry.register_profiles([f"op={profile}"])
    )
    try:
        result = mcp_select_profile(
            "op",
            patch_ops=[{"op": "replace", "path": "/project_name", "value": patched}],
            session_id="session-a",
        )
        written = result["success"] is True
        assert written, "the patch was refused"
        path = Path(profile_registry.resolve_session_config_path("session-a"))
    finally:
        profile_registry.clear_profile_registry()
        profile_registry.clear_session_state()
    kept = resolve_config(path).project_name == patched
    assert kept, "the patch did not read back as the client wrote it"


def test_the_writer_refuses_a_value_it_would_write_as_text(environment, monkeypatch):
    """Defense in depth: a configuration whose record holds a value it read
    from the environment as text, where its file wrote the reference, is not
    written."""
    from automated_security_helper.config import config_validator
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    profile = environment / "operator.ash.yaml"
    profile.write_text(_profile(["${ASH_PN}"]), encoding="utf-8")
    _, config = load_config_file_for_run(profile)
    # The control: the value is located, and written as its reference.
    target = environment / "out.yaml"
    config.save(target, as_written=True)
    located = "${ASH_PN}" in target.read_text(encoding="utf-8")
    assert located, "the control: the reference is written"
    # A record that writes no reference (as one that failed to locate it would).
    monkeypatch.setattr(
        config_validator, "record_of_config", lambda config, dumped, mark=None: dumped
    )
    refused_target = environment / "refused.yaml"
    with pytest.raises(RuntimeError) as refused:
        config.save(refused_target, as_written=True)
    quoted = CANARY in str(refused.value)
    assert not quoted, "the refusal quotes the value"
    assert not refused_target.exists(), "the file was written"
