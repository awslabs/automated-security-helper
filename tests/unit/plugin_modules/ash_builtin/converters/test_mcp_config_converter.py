# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP config converter: one script and one span sidecar per command-declaring server.

The goldens under ``tests/test_data/mcp_config_converted`` are the whole output tree
(scripts, sidecars and the converted-sources record) for each of the twenty
fixtures under ``tests/test_data/mcp_config``. The other rows pin what the goldens
cannot: the sidecar's spans land on the entry in the config file, a config can
choose no path outside the converter's directory, a config that does not parse is a
recorded failed input that never quotes the file, a url-only remote entry writes
nothing (one with a command writes its script), and the converter starts no process.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin import converters as pkg
from automated_security_helper.plugin_modules.ash_builtin.converters.mcp_config_converter import (
    McpConfigConverter,
    McpConfigConverterConfig,
    SPANMAP_SUFFIX,
)
from automated_security_helper.utils.mcp_config import FORMATS
from automated_security_helper.utils.scan_output_dirs import (
    CONVERTED_SOURCES_FILE_NAME,
)

pytestmark = pytest.mark.unit

MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters."
    "mcp_config_converter"
)
TEST_DATA = Path(__file__).resolve().parents[4] / "test_data"
FIXTURES = TEST_DATA / "mcp_config"
GOLDENS = TEST_DATA / "mcp_config_converted"

KINDS = ["benign", "violating"]
CASES = [(fmt.format_id, kind) for fmt in FORMATS for kind in KINDS]


def stage(context, monkeypatch, files: Dict[str, str]) -> List[str]:
    """Write ``files`` (repo-relative path -> text) under the source dir; list them."""
    tree = Path(context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, text in files.items():
        path = tree / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        paths.append(str(path))
    monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: list(paths))
    return paths


def stage_fixture(context, monkeypatch, fmt: str, kind: str) -> List[str]:
    """Copy the fixture tree of one format and kind into the source dir."""
    tree = Path(context.source_dir)
    shutil.copytree(FIXTURES / fmt / kind, tree, dirs_exist_ok=True)
    paths = sorted(str(p) for p in tree.rglob("*") if p.is_file())
    monkeypatch.setattr(f"{MODULE}.scan_set", lambda **kwargs: list(paths))
    return paths


def make_converter(context) -> McpConfigConverter:
    return McpConfigConverter(context=context, config=McpConfigConverterConfig())


def output_tree(converter) -> Dict[str, bytes]:
    """Every script and sidecar written. The converted-sources record is left out of
    the goldens (the repo's JSON hook rewrites its key order); a row of its own pins it.
    """
    root = Path(converter.results_dir)
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file() and p.name != CONVERTED_SOURCES_FILE_NAME
    }


def golden_tree(fmt: str, kind: str) -> Dict[str, bytes]:
    root = GOLDENS / fmt / kind
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def test_the_converter_is_registered_with_the_builtin_converters():
    from automated_security_helper.plugin_modules import ash_builtin

    assert McpConfigConverter in ash_builtin.ASH_CONVERTERS
    assert "McpConfigConverter" in pkg.__all__
    assert McpConfigConverterConfig().name == "mcp_config"


def test_the_converter_builds_without_a_config_and_is_named_for_itself(
    test_plugin_context,
):
    converter = McpConfigConverter(context=test_plugin_context)

    assert converter.config.name == "mcp_config"
    assert Path(converter.results_dir).name == "mcp_config"
    assert converter.validate_plugin_dependencies() is True


@pytest.mark.parametrize("fmt,kind", CASES)
def test_the_output_tree_matches_its_golden(
    test_plugin_context, monkeypatch, fmt, kind
):
    stage_fixture(test_plugin_context, monkeypatch, fmt, kind)
    converter = make_converter(test_plugin_context)

    results = converter.convert()

    produced = output_tree(converter)
    expected = golden_tree(fmt, kind)
    assert sorted(produced) == sorted(expected)
    for name in expected:
        assert produced[name] == expected[name], name
    scripts = sorted(
        Path(p).relative_to(converter.results_dir).as_posix() for p in results
    )
    assert scripts == sorted(n for n in expected if n.endswith(".sh"))
    assert not converter.failed_inputs and not converter.refused_inputs


@pytest.mark.parametrize("fmt,kind", CASES)
def test_every_script_line_has_a_row_and_the_rows_land_on_the_entry(
    test_plugin_context, monkeypatch, fmt, kind
):
    paths = stage_fixture(test_plugin_context, monkeypatch, fmt, kind)
    converter = make_converter(test_plugin_context)
    converter.convert()
    config_text = Path(paths[0]).read_text(encoding="utf-8")
    config_lines = config_text.split("\n")
    root = Path(converter.results_dir)

    sidecars = sorted(root.rglob("*" + SPANMAP_SUFFIX))
    for sidecar in sidecars:
        script = sidecar.with_name(sidecar.name[: -len(SPANMAP_SUFFIX)])
        script_lines = script.read_text(encoding="utf-8").split("\n")[:-1]
        rows = json.loads(sidecar.read_text(encoding="utf-8"))

        assert [r["script_line"] for r in rows] == list(range(1, len(script_lines) + 1))
        for row in rows:
            assert (
                row["source_file"]
                == Path(paths[0]).relative_to(test_plugin_context.source_dir).as_posix()
            )
            assert 1 <= row["line"] <= row["end_line"] <= len(config_lines)
            # The span opens on the entry's own name or value, in the file.
            assert config_lines[row["line"] - 1][row["col"] - 1 :].strip()
        comment = json.loads(script_lines[1].split(": ", 1)[1])
        assert comment["source"] == rows[0]["source_file"]
        assert comment["pointer"] == rows[0]["pointer"]
        assert (comment["line"], comment["col"]) == (rows[0]["line"], rows[0]["col"])


@pytest.mark.parametrize("fmt", [f.format_id for f in FORMATS if f.syntax == "json"])
def test_a_json_span_encloses_exactly_the_entry_the_script_was_made_from(
    test_plugin_context, monkeypatch, fmt
):
    paths = stage_fixture(test_plugin_context, monkeypatch, fmt, "violating")
    converter = make_converter(test_plugin_context)
    converter.convert()
    config_lines = Path(paths[0]).read_text(encoding="utf-8").split("\n")
    root = Path(converter.results_dir)

    seen = 0
    for sidecar in sorted(root.rglob("*" + SPANMAP_SUFFIX)):
        row = json.loads(sidecar.read_text(encoding="utf-8"))[0]
        script = sidecar.with_name(sidecar.name[: -len(SPANMAP_SUFFIX)])
        exec_line = script.read_text(encoding="utf-8").split("\n")[2]
        if row["line"] == row["end_line"]:
            region = config_lines[row["line"] - 1][row["col"] - 1 : row["end_col"] - 1]
        else:
            region = "\n".join(
                [config_lines[row["line"] - 1][row["col"] - 1 :]]
                + config_lines[row["line"] : row["end_line"] - 1]
                + [config_lines[row["end_line"] - 1][: row["end_col"] - 1]]
            )
        # The vscode fixture is JSONC: drop the trailing commas it allows.
        entry = json.loads(re.sub(r",(\s*[}\]])", r"\1", region))
        assert f"exec '{entry['command']}'" in exec_line
        for argument in entry.get("args", []):
            assert f"'{argument}'" in exec_line
        seen += 1
    assert seen >= 1


def test_a_remote_entry_writes_no_script(test_plugin_context, monkeypatch):
    stage(
        test_plugin_context,
        monkeypatch,
        {
            ".mcp.json": json.dumps(
                {"mcpServers": {"r": {"type": "http", "url": "https://example.com/m"}}}
            )
        },
    )
    converter = make_converter(test_plugin_context)

    results = converter.convert()

    assert results == []
    assert not Path(converter.results_dir).exists()
    assert not converter.failed_inputs


def test_a_decoy_url_beside_a_command_still_writes_the_script(
    test_plugin_context, monkeypatch
):
    """An entry with both a command and a url is classed remote; the script scanners
    must still read its command, so the decoy url key does not suppress the script."""
    stage(
        test_plugin_context,
        monkeypatch,
        {
            ".mcp.json": json.dumps(
                {
                    "mcpServers": {
                        "both": {
                            "type": "stdio",
                            "command": "sudo",
                            "args": ["/usr/local/bin/mcp-files"],
                            "url": "http://127.0.0.1:1/",
                        }
                    }
                }
            )
        },
    )
    converter = make_converter(test_plugin_context)

    results = converter.convert()

    assert [p.name for p in results] == ["both.sh"]
    text = results[0].read_text(encoding="utf-8")
    assert "exec 'sudo' '/usr/local/bin/mcp-files'" in text
    assert results[0].with_name("both.sh" + SPANMAP_SUFFIX).is_file()


def test_a_tree_with_no_mcp_config_writes_nothing(test_plugin_context, monkeypatch):
    stage(test_plugin_context, monkeypatch, {"README.md": "hello\n", "a.json": "{}"})
    converter = make_converter(test_plugin_context)

    assert converter.convert() == []
    assert not Path(converter.results_dir).exists()


def test_a_name_from_the_config_chooses_no_path_outside_the_converter_directory(
    test_plugin_context, monkeypatch
):
    config = {
        "mcpServers": {
            "../../escape": {"command": "a"},
            "/abs/path": {"command": "b"},
            ".hidden": {"command": "c"},
            "a/b": {"command": "d"},
            "a_b": {"command": "e"},
        }
    }
    stage(test_plugin_context, monkeypatch, {".mcp.json": json.dumps(config)})
    converter = make_converter(test_plugin_context)

    results = converter.convert()

    root = Path(converter.results_dir).resolve()
    assert len(results) == 5
    for path in results:
        assert Path(path).resolve().parent == (root / "mcp.json").resolve()
        assert Path(path).is_file()
    everything = {
        p.resolve()
        for p in Path(test_plugin_context.work_dir).rglob("*")
        if p.is_file()
    }
    assert all(root in p.parents for p in everything)
    assert len({Path(p).name for p in results}) == 5


def test_a_config_that_does_not_parse_is_a_failed_input_that_quotes_nothing(
    test_plugin_context, monkeypatch
):
    secret = "sk-test-0123456789-not-a-real-token"
    stage(
        test_plugin_context,
        monkeypatch,
        {".mcp.json": '{"mcpServers": {"x": ' + secret + " }}"},
    )
    converter = make_converter(test_plugin_context)

    results = converter.convert()

    assert results == []
    assert len(converter.failed_inputs) == 1
    recorded = converter.failed_inputs[0].model_dump_json()
    assert ".mcp.json" in recorded
    assert secret not in recorded


def test_a_config_that_is_not_utf8_is_a_failed_input(test_plugin_context, monkeypatch):
    stage(test_plugin_context, monkeypatch, {".mcp.json": "{}"})
    Path(test_plugin_context.source_dir, ".mcp.json").write_bytes(b'{"a": "\xff\xfe"}')
    converter = make_converter(test_plugin_context)

    assert converter.convert() == []
    assert len(converter.failed_inputs) == 1


def test_a_config_that_is_too_large_is_a_failed_input(test_plugin_context, monkeypatch):
    monkeypatch.setattr(f"{MODULE}.MAX_CONFIG_BYTES", 64)
    stage(
        test_plugin_context,
        monkeypatch,
        {".mcp.json": '{"mcpServers": {"a": {"command": "' + "x" * 200 + '"}}}'},
    )
    converter = make_converter(test_plugin_context)

    assert converter.convert() == []
    assert len(converter.failed_inputs) == 1


def test_the_converter_starts_no_process(test_plugin_context, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("the converter started a process")

    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, refuse)
    monkeypatch.setattr("os.system", refuse)
    monkeypatch.setattr("os.execv", refuse)
    stage_fixture(test_plugin_context, monkeypatch, "claude_code", "violating")
    converter = make_converter(test_plugin_context)

    assert len(converter.convert()) == 2


def test_a_value_that_looks_like_a_command_is_written_as_text_only(
    test_plugin_context, monkeypatch
):
    marker = Path(test_plugin_context.source_dir) / "pwned"
    config = {
        "mcpServers": {
            "s": {
                "command": f"touch {marker}; $(touch {marker})",
                "args": [f"`touch {marker}`"],
                "env": {"X": f"$(touch {marker})"},
            }
        }
    }
    stage(test_plugin_context, monkeypatch, {".mcp.json": json.dumps(config)})
    converter = make_converter(test_plugin_context)

    results = converter.convert()

    assert not marker.exists()
    text = Path(results[0]).read_text(encoding="utf-8")
    assert f"exec 'touch {marker}; $(touch {marker})' '`touch {marker}`'" in text


def test_the_converted_sources_record_names_the_config_each_file_came_from(
    test_plugin_context, monkeypatch
):
    stage_fixture(test_plugin_context, monkeypatch, "cursor", "violating")
    converter = make_converter(test_plugin_context)
    converter.convert()

    record = json.loads(
        (Path(converter.results_dir) / CONVERTED_SOURCES_FILE_NAME).read_text()
    )

    written = sorted(
        p.relative_to(test_plugin_context.work_dir).as_posix()
        for p in Path(converter.results_dir).rglob("*")
        if p.is_file() and p.name != CONVERTED_SOURCES_FILE_NAME
    )
    assert len(written) == 4
    assert record == dict.fromkeys(written, ".cursor/mcp.json")


def test_an_ignored_config_path_is_not_converted(test_plugin_context, monkeypatch):
    stage_fixture(test_plugin_context, monkeypatch, "claude_code", "violating")
    test_plugin_context.config.global_settings.ignore_paths = [
        IgnorePathWithReason(path=".mcp.json", reason="vendored copy")
    ]
    converter = make_converter(test_plugin_context)

    assert converter.convert() == []


def test_two_runs_over_one_tree_write_identical_bytes(test_plugin_context, monkeypatch):
    stage_fixture(test_plugin_context, monkeypatch, "kiro", "violating")
    converter = make_converter(test_plugin_context)
    converter.convert()
    first = output_tree(converter)
    shutil.rmtree(converter.results_dir)

    converter.convert()

    assert output_tree(converter) == first
