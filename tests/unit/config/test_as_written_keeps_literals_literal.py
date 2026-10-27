# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config saved as written reads back each literal as the same literal.

``AshConfig.save(..., as_written=True)`` (the MCP server's session config)
writes each value the profile read from the environment as its reference, so
the scan resolves it again. Only those locations are written as references.
A string that only looks like one, a profile's quoted ``'!ENV ${VAR}'`` or
``'${VAR}'`` or the same text from a client's patch, is written so that it
reads back as that text, never as a reference the scan resolves.
"""

from __future__ import annotations

from pathlib import Path

import pytest

CANARY = "ash-canary-7f3e-0123456789"
TAGGED = "!ENV ${ASH_FC_TAG}"
PLAIN = "${ASH_FC_LOOK}"
# Both variables are also read by real references, so the text of each literal
# is the text of a reference the file holds.
PROFILE = (
    "project_name: '{literal}'\n"
    "reporters:\n"
    "  gitlab-cyclonedx:\n"
    "    options:\n"
    "      package_manager_override: !ENV ${{ASH_FC_TAG}}\n"
    "      language_override: ${{ASH_FC_LOOK}}\n"
    "global_settings:\n"
    "  mcp:\n"
    "    runtime_overrides:\n"
    "      enabled: true\n"
    "      allowed_paths:\n"
    "        - /project_name\n"
    "      denied_paths: []\n"
)


@pytest.fixture
def environment(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_FC_TAG", CANARY)
    monkeypatch.setenv("ASH_FC_LOOK", CANARY)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    return tmp_path


def _materialized(tmp_path: Path, literal: str, patched: str | None) -> Path:
    """The session config select_profile wrote for the profile holding
    ``literal``, with ``project_name`` patched to ``patched`` if given."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    profile = tmp_path / "operator.ash.yaml"
    profile.write_text(PROFILE.format(literal=literal), encoding="utf-8")
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    profile_registry.set_profile_registry(
        profile_registry.register_profiles([f"op={profile}"])
    )
    try:
        ops = (
            None
            if patched is None
            else [{"op": "replace", "path": "/project_name", "value": patched}]
        )
        result = mcp_select_profile("op", patch_ops=ops, session_id="session-a")
        assert result["success"] is True, result.get("error")
        return Path(profile_registry.resolve_session_config_path("session-a"))
    finally:
        profile_registry.clear_profile_registry()
        profile_registry.clear_all_session_state()


def _reloaded(path: Path):
    from automated_security_helper.config.resolve_config import resolve_config

    return resolve_config(path)


CELLS = [
    pytest.param(TAGGED, None, id="env-tag-text-in-the-profile"),
    pytest.param("vendor", TAGGED, id="env-tag-text-from-a-patch"),
    pytest.param(PLAIN, None, id="reference-text-in-the-profile"),
    pytest.param("vendor", PLAIN, id="reference-text-from-a-patch"),
]


@pytest.mark.parametrize(("literal", "patched"), CELLS)
def test_a_literal_reads_back_as_the_same_literal(environment, literal, patched):
    expected = patched if patched is not None else literal
    config = _reloaded(_materialized(environment, literal, patched))
    # Booleans, so a failure does not print the value read in its place.
    kept = config.project_name == expected
    assert kept, "the literal did not read back as itself"
    shown = CANARY in config.project_name
    assert not shown, "the literal read back as the variable's value"


@pytest.mark.parametrize(("literal", "patched"), CELLS)
def test_the_profile_s_references_read_the_environment(environment, literal, patched):
    """The control: the locations the profile read from the environment are
    still written as references, and read the value again."""
    path = _materialized(environment, literal, patched)
    text = path.read_text(encoding="utf-8")
    written = CANARY not in text
    assert written, "the materialized file holds the value"
    options = _reloaded(path).reporters.model_dump(by_alias=True)["gitlab-cyclonedx"][
        "options"
    ]
    read = (
        options["package_manager_override"] == CANARY
        and options["language_override"] == CANARY
    )
    assert read, "a reference no longer reads the environment"


# A patch at a location the profile read from the environment, with text that
# holds that variable's value (KNOWN: the client knows it). Whatever it holds,
# it is the client's text, written so it reads back as itself: no reference,
# to that variable or another, is made from it.

KNOWN = "known-project-value-7f3e"
PROJECT_PROFILE = (
    "project_name: ${ASH_PN}\n"
    "global_settings:\n"
    "  mcp:\n"
    "    runtime_overrides:\n"
    "      enabled: true\n"
    "      allowed_paths:\n"
    "        - /project_name\n"
    "      denied_paths: []\n"
)


def _patched_project(tmp_path: Path, monkeypatch, patched: str) -> Path:
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    monkeypatch.setenv("ASH_PN", KNOWN)
    profile = tmp_path / "project.ash.yaml"
    profile.write_text(PROJECT_PROFILE, encoding="utf-8")
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    profile_registry.set_profile_registry(
        profile_registry.register_profiles([f"op={profile}"])
    )
    try:
        result = mcp_select_profile(
            "op",
            patch_ops=[{"op": "replace", "path": "/project_name", "value": patched}],
            session_id="session-a",
        )
        assert result["success"] is True, result.get("error")
        return Path(profile_registry.resolve_session_config_path("session-a"))
    finally:
        profile_registry.clear_profile_registry()
        profile_registry.clear_all_session_state()


@pytest.mark.parametrize(
    "patched",
    [
        pytest.param(
            "${ASH_FC_TAG:" + KNOWN + "}", id="reference-with-the-value-as-default"
        ),
        pytest.param(
            "!ENV ${ASH_FC_TAG:" + KNOWN + "}", id="env-tag-with-the-value-as-default"
        ),
        pytest.param("${ASH_FC_TAG}" + KNOWN, id="reference-then-the-value"),
        pytest.param("pre-" + KNOWN + "-${ASH_FC_TAG:z}", id="value-inside-other-text"),
        pytest.param(KNOWN + "\nmore", id="the-value-then-a-new-line"),
        pytest.param(KNOWN + "}", id="the-value-then-a-brace"),
        pytest.param(KNOWN + "-}x", id="the-value-then-a-brace-inside"),
        pytest.param(KNOWN + ": x", id="the-value-then-a-colon"),
        pytest.param(KNOWN + " #c", id="the-value-then-a-comment"),
        pytest.param(KNOWN + "${ASH_FC_TAG}", id="the-value-then-a-reference"),
        pytest.param(KNOWN + "-" + KNOWN, id="the-value-twice"),
        pytest.param("x-" + KNOWN, id="text-then-the-value"),
        pytest.param("!ENV " + KNOWN, id="a-tag-then-the-value"),
    ],
)
def test_a_patch_holding_the_value_reads_back_as_the_patch(
    environment, monkeypatch, patched
):
    config = _reloaded(_patched_project(environment, monkeypatch, patched))
    shown = CANARY in config.project_name
    assert not shown, "the patch read another variable's value"
    kept = config.project_name == patched
    assert kept, "the patch did not read back as itself"


# The profile's own value, which the configuration holds with other text: the
# string record_of_config replaces only the variable's part of. A client's patch
# never reaches this (its rewrite is dropped); a value the model changed does,
# simulated here by setting the field after the load.
WRITTEN_AS_A_REFERENCE = [
    pytest.param("\nmore", id="a-new-line"),
    pytest.param("\tx", id="a-tab"),
    pytest.param(": x", id="a-colon"),
    pytest.param(" #c", id="a-comment"),
    pytest.param("-suffix", id="text"),
]
NOT_WRITTEN = [
    pytest.param("}", id="a-brace"),
    pytest.param("-}x", id="a-brace-inside"),
    pytest.param("${ASH_FC_TAG}", id="a-reference"),
    pytest.param("-" + KNOWN, id="the-value-again"),
]


def _held_with(tmp_path: Path, monkeypatch, held: str):
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    monkeypatch.setenv("ASH_PN", KNOWN)
    profile = tmp_path / "project.ash.yaml"
    profile.write_text(PROJECT_PROFILE, encoding="utf-8")
    _, config = load_config_file_for_run(profile)
    config.project_name = held
    return config


@pytest.mark.parametrize("after", WRITTEN_AS_A_REFERENCE)
def test_the_profile_s_value_with_text_is_written_as_a_reference_that_reads_it_back(
    environment, monkeypatch, after
):
    """Written tagged, so the loader reads it from the environment however the
    emitter quotes it, and only where the loader resolves the reference back to
    the same string."""
    held = KNOWN + after
    config = _held_with(environment, monkeypatch, held)
    target = environment / "session.yaml"
    config.save(target, as_written=True)
    text = target.read_text(encoding="utf-8")
    written = KNOWN not in text and "${ASH_PN}" in text
    assert written, "the value was not written as its reference"
    read = _reloaded(target).project_name == held
    assert read, "the reference did not read back as the string it replaced"


@pytest.mark.parametrize("after", NOT_WRITTEN)
def test_the_profile_s_value_no_reference_reads_back_is_not_written(
    environment, monkeypatch, after
):
    """A string the loader would not resolve back to itself is neither written
    as a reference (it would read as other text, or another variable) nor as
    text (the value would be a literal no redaction knows)."""
    held = KNOWN + after
    config = _held_with(environment, monkeypatch, held)
    target = environment / "session.yaml"
    with pytest.raises(RuntimeError) as refused:
        config.save(target, as_written=True)
    quoted = KNOWN in str(refused.value)
    assert not quoted, "the refusal quotes the value"
    assert not target.exists(), "the file was written"


@pytest.mark.parametrize(
    "patched",
    [
        pytest.param(KNOWN, id="the-value"),
        pytest.param(KNOWN + "-suffix", id="the-value-then-text"),
    ],
)
def test_a_patch_that_is_the_value_is_the_client_s_text(
    environment, monkeypatch, patched
):
    """The value, alone or followed by text, is written as the client wrote
    it, not as the profile's reference, so the written config does not tell the
    client whether its string is the value
    (test_as_written_checks_only_moved_values.py)."""
    path = _patched_project(environment, monkeypatch, patched)
    text = path.read_text(encoding="utf-8")
    unreferenced = "${ASH_PN}" not in text
    assert unreferenced, "the client's text was written as the profile's reference"
    read = _reloaded(path).project_name == patched
    assert read, "the client's text did not read back as written"


FORMATS = "sarif,html"


def _formats_profile(tmp_path: Path, monkeypatch):
    """A profile whose ``output_formats`` is one reference, which the model reads
    as the list of formats the variable names."""
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    monkeypatch.setenv("ASH_FMT", FORMATS)
    profile = tmp_path / "formats.ash.yaml"
    profile.write_text(
        "project_name: demo\noutput_formats: ${ASH_FMT}\n", encoding="utf-8"
    )
    _, config = load_config_file_for_run(profile)
    return config


def _written_formats(target: Path):
    import yaml

    return yaml.safe_load(target.read_text(encoding="utf-8"))["output_formats"]


def test_a_reference_the_model_reads_as_a_list_is_written_as_the_reference(
    environment, monkeypatch
):
    """The list the model made of the variable's value is the variable's value:
    written as the reference, which reads back as the same list."""
    config = _formats_profile(environment, monkeypatch)
    assert [item.value for item in config.output_formats] == ["sarif", "html"]
    target = environment / "session.yaml"

    config.save(target, as_written=True)

    assert _written_formats(target) == "${ASH_FMT}"
    reread = [item.value for item in _reloaded(target).output_formats]
    assert reread == ["sarif", "html"]


def test_a_list_set_after_the_load_is_written_as_the_configuration_holds_it(
    environment, monkeypatch
):
    """The control: a list the configuration holds in place of the one the
    variable gave is no value read from the environment, so it is written as it
    is."""
    config = _formats_profile(environment, monkeypatch)
    config.output_formats = ["json"]
    target = environment / "session.yaml"

    config.save(target, as_written=True)

    assert _written_formats(target) == ["json"]


def test_the_writer_refuses_a_list_read_from_the_environment_left_as_text(
    environment, monkeypatch
):
    """The writer's own check, with the record made to leave the list as the
    model holds it: refused, and nothing written."""
    from automated_security_helper.config import config_validator

    config = _formats_profile(environment, monkeypatch)
    monkeypatch.setattr(
        config_validator, "record_of_config", lambda config, dumped, mark=None: dumped
    )
    target = environment / "session.yaml"

    with pytest.raises(RuntimeError, match="was not written"):
        config.save(target, as_written=True)
    assert not target.exists()
