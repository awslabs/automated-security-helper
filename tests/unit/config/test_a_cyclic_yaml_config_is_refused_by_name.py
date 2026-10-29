# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A YAML config whose alias sits inside the node it names is refused by name.

PyYAML builds such a document as a mapping or list that contains itself, and
the load's walks of it (the record of what the file read from the environment
first) recursed to Python's recursion limit: a raw RecursionError from the
run load, "maximum recursion depth exceeded" with exit 1 from ``ash config
validate``. The file is refused as one that does not parse instead, naming
the problem and its place.

ASH's config loader refuses every YAML alias, not only one inside its own node
(``_NoAliasSafeLoader``), so the refusal a config load gives is the parser's
``ComposerError`` at the first alias: ``could not be parsed (ComposerError at
line N, column M)``, which quotes none of the file. A shared alias of a complete
node is refused the same way, and the same document written out in each place
loads. The readers that answer a document as written (``get_config(raw=True)``
and the suppression save) read with ``NoRecursiveAliasLoader`` instead, which
refuses only an alias inside its own node, in ``RecursiveAliasError``'s words;
the cells for those two, and for the loader alone, are unchanged.

Some test names still say "recursive alias" or "shared alias ... loads" from the
older contract; they are kept so a test's id stays the same across the change.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

VALUE = "cycle-env-value-7731"

CYCLES = {
    "mapping": "project_name: t\nreporters: &loop\n  markdown:\n    again: *loop\n",
    "list": "project_name: t\nglobal_settings:\n  ignore_paths: &loop\n  - *loop\n",
    "top-level": "&top\nproject_name: t\nself: *top\n",
    "env-read": (
        "project_name: ${ASH_CYCLE_VALUE}\n"
        "reporters: &loop\n  markdown:\n    again: *loop\n"
    ),
}


@pytest.fixture
def cyclic(tmp_path, monkeypatch, request):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_CYCLE_VALUE", VALUE)
    path = tmp_path / "ash.yaml"
    path.write_text(CYCLES[request.param], encoding="utf-8")
    return path


@pytest.mark.parametrize("cyclic", sorted(CYCLES), indirect=True)
def test_the_run_load_refuses_a_recursive_alias_as_a_parse_error(cyclic):
    """The run load raises a parser's refusal, as it does for any YAML that does
    not parse, which every caller names (unparsed_config_reason): never the
    RecursionError a walk of the cyclic document reached."""
    import yaml

    from automated_security_helper.config.config_sources import (
        is_config_parse_error,
        unparsed_config_reason,
    )
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    with pytest.raises(yaml.YAMLError) as refused:
        load_config_file_for_run(cyclic)
    assert is_config_parse_error(refused.value)
    text = unparsed_config_reason(cyclic, refused.value)
    assert "could not be parsed (ComposerError at line" in text, text
    assert VALUE not in text, text


@pytest.mark.parametrize("cyclic", sorted(CYCLES), indirect=True)
def test_the_scan_resolution_refuses_a_recursive_alias_by_name(cyclic):
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    with pytest.raises(ASHConfigValidationError) as refused:
        resolve_config(
            config_path=cyclic, source_dir=cyclic.parent, fallback_to_default=True
        )
    text = str(refused.value)
    assert "could not be parsed (ComposerError at line" in text, text
    assert "RecursionError" not in text and "recursion depth" not in text, text
    assert VALUE not in text, text


@pytest.mark.parametrize("cyclic", sorted(CYCLES), indirect=True)
def test_config_validate_refuses_a_recursive_alias_with_exit_3(cyclic):
    result = CliRunner().invoke(app, ["config", "validate", "--config", str(cyclic)])
    flat = " ".join(result.output.split())
    assert result.exit_code == 3, (result.exit_code, flat[-800:])
    assert "could not be parsed (ComposerError at line" in flat, flat[-800:]
    assert "recursion depth" not in flat, flat[-800:]
    assert VALUE not in flat, flat[-800:]


def test_a_shared_alias_of_a_complete_node_still_loads(tmp_path, monkeypatch):
    """An alias of an anchor whose node is complete is a shared value, not a
    cycle, and it is refused all the same: the config loader accepts no alias.
    The control is the same document with the shared value written out in each
    place, which loads."""
    import yaml

    from automated_security_helper.config.config_sources import (
        is_config_parse_error,
        unparsed_config_reason,
    )
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / "ash.yaml"
    path.write_text(
        "project_name: t\n"
        "reporters:\n"
        "  markdown: &shared\n"
        "    enabled: false\n"
        "  text: *shared\n",
        encoding="utf-8",
    )
    with pytest.raises(yaml.YAMLError) as refused:
        load_config_file_for_run(path)
    assert is_config_parse_error(refused.value)
    text = unparsed_config_reason(path, refused.value)
    assert "could not be parsed (ComposerError at line" in text, text
    assert "*shared" not in text, text

    written_out = tmp_path / "written-out.yaml"
    written_out.write_text(
        "project_name: t\n"
        "reporters:\n"
        "  markdown:\n"
        "    enabled: false\n"
        "  text:\n"
        "    enabled: false\n",
        encoding="utf-8",
    )
    _, config = load_config_file_for_run(written_out)
    assert config.project_name == "t"
    assert config.reporters.markdown.enabled is False
    assert config.reporters.text.enabled is False


def test_the_suppression_save_refuses_a_recursive_alias_unchanged(
    tmp_path, monkeypatch
):
    """The save's own loader refuses the alias while parsing, so the file is
    refused in the save's left-unchanged words. Loaded, the document contains
    itself, and the save's write-check walked it to Python's recursion limit:
    a raw RecursionError in place of the refusal, measured through this same
    call."""
    from automated_security_helper.config.ash_config import add_suppression_to_config
    from automated_security_helper.models.core import AshSuppression

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / ".ash.yaml"
    path.write_text(CYCLES["mapping"], encoding="utf-8")
    before = path.read_bytes()

    with pytest.raises(ValueError) as refused:
        add_suppression_to_config(
            path, AshSuppression(rule_id="R1", path="a.py", reason="kept")
        )

    message = str(refused.value)
    # The save's loader now refuses every alias, as the scan's loader does
    # (ash_config._NoAliasSafeLoader), so the cycle is refused as the first
    # alias met, a ComposerError, in the same left-unchanged words.
    assert "could not be parsed (ComposerError at line" in message, message
    assert message.endswith(f"{path} is unchanged"), message
    assert path.read_bytes() == before


def test_mcp_get_config_raw_refuses_a_recursive_alias(tmp_path, monkeypatch):
    """The raw read's loader refuses the alias while parsing, so the tool
    answers its own load refusal, and the answer serializes. Built, the
    document contains itself: the tool returned it and the MCP transport's
    serialization was what failed, measured through this same call."""
    import json

    from automated_security_helper.cli import mcp_tools

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / "ash.yaml"
    path.write_text(CYCLES["mapping"], encoding="utf-8")

    answer = mcp_tools.mcp_get_config(config_path=str(path), raw=True)

    json.dumps(answer)
    assert answer.get("success") is False, answer
    text = str(answer.get("error", ""))
    assert "could not be parsed (RecursiveAliasError at line" in text, answer
    assert "recursion depth" not in text, answer


def test_mcp_select_profile_refuses_a_recursive_alias_in_override_yaml(
    tmp_path, monkeypatch
):
    """override_yaml is the MCP client's own text. Loaded with a recursive
    alias under a section the model keeps as an extra, it validated, and the
    session config's dump then failed with "Circular reference detected", a
    generic "Error selecting profile" answer naming a ValueError. The text is
    refused as a parse error instead, in the words every other override_yaml
    parse error gets, and the answer serializes."""
    import asyncio
    import json

    from automated_security_helper.cli import mcp_server
    from automated_security_helper.cli.mcp.profile_registry import (
        clear_profile_registry,
        clear_all_session_state,
        register_profiles,
        set_profile_registry,
    )

    class _Context:
        headers = {"mcp-session-id": "cyclic-override"}

        async def info(self, message):
            return None

        error = warning = debug = info

        async def report_progress(self, **kwargs):
            return None

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
    try:
        answer = asyncio.run(
            mcp_server.select_profile(
                _Context(),
                profile_name="wide",
                override_yaml=(
                    "project_name: t\nreporters:\n  custom-thing: &c\n    nested: *c\n"
                ),
            )
        )
    finally:
        clear_profile_registry()
        clear_all_session_state()

    json.dumps(answer)
    assert answer.get("success") is False, answer
    error = str(answer.get("error", ""))
    assert error.startswith("override_yaml parse error"), answer
    # override_yaml is parsed with the config loader, which refuses every
    # alias: the parser's words for it, and where it stopped.
    assert "does not accept YAML aliases" in error, answer
    assert "ComposerError at line" in error, answer
    assert "Circular reference" not in error and "error_type" not in answer, answer


def test_mcp_select_profile_binds_a_shared_alias_in_override_yaml(
    tmp_path, monkeypatch
):
    """The cell above, for an alias of an anchor whose node is complete: a
    shared value, not a cycle, and refused all the same, because override_yaml
    is parsed with the config loader, which accepts no alias. The control,
    through the same tool, is the same override with the shared value written
    out in each place: it binds, and each place holds the value."""
    import asyncio
    import json

    from automated_security_helper.cli import mcp_server
    from automated_security_helper.cli.mcp.profile_registry import (
        clear_profile_registry,
        clear_all_session_state,
        get_session_state,
        register_profiles,
        set_profile_registry,
    )

    def _context(session_id):
        class _Context:
            headers = {"mcp-session-id": session_id}

            async def info(self, message):
                return None

            error = warning = debug = info

            async def report_progress(self, **kwargs):
                return None

        return _Context()

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
    try:
        refused = asyncio.run(
            mcp_server.select_profile(
                _context("shared-alias-override"),
                profile_name="wide",
                override_yaml=(
                    "project_name: t\nreporters:\n  markdown: &shared\n"
                    "    enabled: false\n  text: *shared\n"
                ),
            )
        )
        answer = asyncio.run(
            mcp_server.select_profile(
                _context("written-out-override"),
                profile_name="wide",
                override_yaml=(
                    "project_name: t\nreporters:\n  markdown:\n"
                    "    enabled: false\n  text:\n    enabled: false\n"
                ),
            )
        )
        state = get_session_state("written-out-override")
        bound = state.bound_config if state is not None else None
    finally:
        clear_profile_registry()
        clear_all_session_state()

    json.dumps(refused)
    assert refused.get("success") is False, refused
    said = str(refused.get("error", ""))
    assert said.startswith("override_yaml parse error"), refused
    assert "does not accept YAML aliases" in said, refused
    assert "ComposerError at line" in said, refused

    json.dumps(answer)
    assert answer.get("success") is True, answer
    assert bound is not None, answer
    assert bound.reporters.markdown.enabled is False
    assert bound.reporters.text.enabled is False


def _load_with(loader_class, text):
    loader = loader_class(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def test_the_loader_refuses_only_an_alias_inside_its_own_node():
    """The loader alone: the alias's place is the problem mark and the anchor's
    the context mark, and a sibling alias of a complete node is not refused."""
    from automated_security_helper.utils.yaml_aliases import (
        NoRecursiveAliasLoader,
        RecursiveAliasError,
    )

    with pytest.raises(RecursiveAliasError) as refused:
        _load_with(NoRecursiveAliasLoader, "a: &x\n  b: *x\n")
    assert (refused.value.problem_mark.line, refused.value.context_mark.line) == (1, 0)
    assert _load_with(NoRecursiveAliasLoader, "a: &x [1, 2]\nb: *x\n") == {
        "a": [1, 2],
        "b": [1, 2],
    }
