# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/generate_mcp_tool_reference.py: the run_ash_scan caveat names every
refusal the tool returns, and the two generated pages carry the same text.

The caveat used to say every other refusal returns ``scan_start_failure``, while
the tool returns ``committed_output_files``, ``session_identity_required``,
``session_scan_limit`` and ``source_delivery_busy`` as their own error types. An
agent branching on ``error_type`` as the caveat tells it to would have had no
branch for any of them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
GENERATED_PAGES = (
    REPO_ROOT / "docs" / "content" / "reference" / "mcp-tools.md",
    REPO_ROOT
    / "ash-agent-plugins"
    / "agentic-coding"
    / "transpiler"
    / "_base"
    / "references"
    / "tool-reference.md",
)
UNDOCUMENTED_AT_THE_BASE = (
    "committed_output_files",
    "session_identity_required",
    "session_scan_limit",
    "source_delivery_busy",
)


@pytest.fixture
def generator(script_loader):
    return script_loader("generate_mcp_tool_reference")


@pytest.fixture
def run_ash_scan_caveats(generator) -> str:
    return "\n".join(generator.TOOL_NOTES["run_ash_scan"]["caveats"])


class TestArgsParser:
    """At the base the Args block was cut at any terminator word and every
    ``Word:`` line started a parameter."""

    DOC = (
        "Scan a directory.\n"
        "\n"
        "Args:\n"
        "    source_dir: Path to scan. Note: a relative path is resolved\n"
        "        against the server's cwd. Example: /tmp/project\n"
        "    config_path (str): Custom config path, read before the\n"
        "        discovered one.\n"
        "    clean_output: Wipe first. Default:\n"
        "        false\n"
        "\n"
        "A paragraph after the block that belongs to no parameter.\n"
        "\n"
        "Returns:\n"
        "    A dict.\n"
    )

    def test_a_terminator_word_inside_a_description_does_not_cut_the_block(
        self, generator
    ):
        notes = generator.parse_arg_notes(self.DOC)
        assert set(notes) == {"source_dir", "config_path", "clean_output"}
        assert notes["source_dir"].endswith("Example: /tmp/project")

    def test_a_google_style_typed_head_starts_its_own_parameter(self, generator):
        notes = generator.parse_arg_notes(self.DOC)
        assert notes["config_path"] == (
            "Custom config path, read before the discovered one."
        )

    def test_a_wrapped_word_colon_line_is_a_continuation(self, generator):
        notes = generator.parse_arg_notes(self.DOC)
        assert notes["clean_output"] == "Wipe first. Default: false"

    def test_prose_after_the_block_is_not_folded_into_the_last_parameter(
        self, generator
    ):
        notes = generator.parse_arg_notes(self.DOC)
        assert "paragraph after the block" not in notes["clean_output"]

    def test_a_pipe_in_a_note_is_escaped(self, generator):
        notes = generator.parse_arg_notes("Args:\n    mode: `a | b`\n")
        assert notes["mode"] == r"`a \| b`"

    def test_a_function_without_a_docstring_has_no_notes(self, generator):
        assert generator._docstring_arg_notes(None) == {}


class TestTypeName:
    def test_an_integer_enum_is_an_integer(self, generator):
        """At the base every enum rendered as string."""
        assert generator._type_name({"enum": [1, 2, 3]}) == "integer"
        assert generator._type_name({"enum": [True, False]}) == "boolean"
        assert generator._type_name({"enum": ["a", "b"]}) == "string"
        assert generator._type_name({"type": "integer", "enum": [1, 2]}) == "integer"

    def test_a_ref_is_rendered_by_what_it_points_at(self, generator):
        """At the base a $ref or allOf schema fell through to `any`."""
        root = {
            "$defs": {"Level": {"enum": ["full", "summary"], "type": "string"}},
            "properties": {"level": {"$ref": "#/$defs/Level"}},
        }
        assert generator._type_name(root["properties"]["level"], root) == "string"
        assert (
            generator._type_name({"allOf": [{"$ref": "#/$defs/Level"}]}, root)
            == "string"
        )

    def test_an_unresolvable_ref_is_an_object(self, generator):
        assert generator._type_name({"$ref": "#/$defs/Missing"}, {"$defs": {}}) == (
            "object"
        )


class TestCells:
    def test_a_default_with_a_pipe_is_escaped(self, generator):
        assert generator._default_display({"default": "a|b"}, False) == '`"a\\|b"`'

    def test_counts_agree_with_their_nouns(self, generator):
        assert generator._plural(1, "tool") == "one tool"
        assert generator._plural(5, "resource") == "five resources"

    def test_a_template_resource_has_a_uri(self, generator):
        from types import SimpleNamespace

        template = SimpleNamespace(uriTemplate="ash://scan/{scan_id}")
        assert generator._resource_uri(template) == "ash://scan/{scan_id}"
        fixed = SimpleNamespace(uri="ash://help")
        assert generator._resource_uri(fixed) == "ash://help"


class TestRenderTool:
    def test_a_note_for_a_parameter_the_tool_lacks_is_an_error(
        self, generator, monkeypatch
    ):
        """At the base such a note was dropped silently."""
        monkeypatch.setitem(
            generator.TOOL_NOTES,
            "demo_tool",
            {"params": {"gone": {"notes": "stale"}}},
        )
        schema = {"properties": {"kept": {"type": "string"}}, "required": []}
        with pytest.raises(SystemExit, match="gone"):
            generator._render_tool("demo_tool", "", schema, None)

    def test_a_tool_without_a_module_function_uses_its_description(self, generator):
        schema = {"properties": {}}
        lines = generator._render_tool(
            "other", "Registered under a name.", schema, None
        )
        assert lines[2] == "Registered under a name."


class TestEditorialNotes:
    def test_list_active_scans_is_scoped_to_the_session(self, generator):
        intro = generator.TOOL_NOTES["list_active_scans"]["intro"]
        assert "This session's scans" in intro
        assert "All scans the server tracks" not in intro

    def test_result_paths_caveat_names_the_nested_files_shape(self, generator):
        caveat = "\n".join(generator.TOOL_NOTES["get_scan_result_paths"]["caveats"])
        assert "`files`" in caveat and "`size_bytes`" in caveat
        assert "mapping format names to absolute paths" not in caveat


@pytest.mark.parametrize("error_type", UNDOCUMENTED_AT_THE_BASE)
def test_the_caveat_names_the_refusal(run_ash_scan_caveats, error_type):
    assert f"`{error_type}`" in run_ash_scan_caveats


def test_scan_start_failure_is_still_the_catch_all(run_ash_scan_caveats):
    assert "`error_type: scan_start_failure`" in run_ash_scan_caveats


@pytest.mark.parametrize("page", GENERATED_PAGES, ids=lambda p: p.name)
@pytest.mark.parametrize("error_type", UNDOCUMENTED_AT_THE_BASE)
def test_the_generated_pages_carry_the_same_text(page, error_type):
    assert f"`{error_type}`" in page.read_text(encoding="utf-8")
