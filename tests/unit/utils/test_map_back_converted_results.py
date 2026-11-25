# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Findings in a generated file with a span sidecar land on the original span.

The MCP config converter writes a shell script per stdio server and a
``.spanmap.json`` beside it. ``map_back_converted_results`` runs at the converter
result boundary, after ``mark_converted_results``: a result on a generated line is
moved to the config file's own span, and keyed by the original path. These tests
pin that, and that a converted file with no sidecar (every other converter's
output) is left exactly as it was.
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_builtin.converters.mcp_config_converter import (
    McpConfigConverter,
    McpConfigConverterConfig,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.scan_output_dirs import (
    CONVERTED_FROM_PROPERTY,
    map_back_converted_results,
    mark_converted_results,
)

pytestmark = pytest.mark.unit

MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters."
    "mcp_config_converter"
)
CONFIG = """{
  "mcpServers": {
    "elevated": {
      "command": "sudo",
      "args": ["/usr/local/bin/mcp-files"]
    }
  }
}
"""


def _result(uri: str, line: int, rule: str = "R1", **region) -> Result:
    return Result(
        ruleId=rule,
        message=Message(text="finding"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri=uri),
                    region=Region(startLine=line, **region),
                )
            )
        ],
    )


def _report(*results: Result) -> SarifReport:
    return SarifReport(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="semgrep")),
                results=list(results),
            )
        ]
    )


@pytest.fixture
def converted(test_plugin_context, monkeypatch):
    """A converted config: the script path, and the context it was converted in."""
    context = test_plugin_context
    tree = Path(context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    (tree / ".mcp.json").write_text(CONFIG, encoding="utf-8")
    monkeypatch.setattr(
        f"{MODULE}.scan_set", lambda **kwargs: [str(tree / ".mcp.json")]
    )
    converter = McpConfigConverter(context=context, config=McpConfigConverterConfig())
    (script,) = converter.convert()
    return script, context


def _sidecar_rows(script: Path):
    return json.loads(
        script.with_name(script.name + ".spanmap.json").read_text(encoding="utf-8")
    )


def _first(report: SarifReport) -> Result:
    return report.runs[0].results[0]


def _where(result: Result):
    physical = result.locations[0].physicalLocation.root
    return physical.artifactLocation.uri, physical.region


def test_a_result_on_a_generated_line_lands_on_the_original_span(converted):
    script, context = converted
    rows = _sidecar_rows(script)
    command_row = rows[-1]
    report = _report(_result(script.as_posix(), command_row["script_line"]))
    mark_converted_results(report, context)

    assert map_back_converted_results(report, context) == 1

    uri, region = _where(_first(report))
    assert uri == ".mcp.json"
    assert (region.startLine, region.startColumn) == (
        command_row["line"],
        command_row["col"],
    )
    assert (region.endLine, region.endColumn) == (
        command_row["end_line"],
        command_row["end_col"],
    )
    original = CONFIG.splitlines()[command_row["line"] - 1]
    assert "elevated" in original or "sudo" in original


def test_a_mapped_result_names_the_generated_file_and_drops_its_converted_path(
    converted,
):
    script, context = converted
    report = _report(_result(script.as_posix(), 3))
    mark_converted_results(report, context)
    assert getattr(_first(report).properties, "converted_path", None)

    map_back_converted_results(report, context)

    properties = _first(report).properties
    assert getattr(properties, "converted_path", None) is None
    work = Path(context.work_dir).resolve()
    assert getattr(properties, CONVERTED_FROM_PROPERTY) == (
        script.resolve().relative_to(work).as_posix()
    )


def test_a_line_with_no_sidecar_row_is_left_where_it_was(converted):
    script, context = converted
    report = _report(_result(script.as_posix(), 99))
    mark_converted_results(report, context)
    before = report.model_dump_json()

    assert map_back_converted_results(report, context) == 0

    assert report.model_dump_json() == before


def test_a_converted_file_with_no_sidecar_is_untouched(test_plugin_context):
    """The archive and notebook converters write no sidecar: the hook no-ops."""
    context = test_plugin_context
    work = Path(context.work_dir)
    member = work / "archive" / "bundle.zip-extracted" / "member.py"
    member.parent.mkdir(parents=True)
    member.write_text("import os\n", encoding="utf-8")
    report = _report(_result(member.as_posix(), 1, startColumn=2, endColumn=8))
    mark_converted_results(report, context)
    before = report.model_dump_json()

    assert map_back_converted_results(report, context) == 0

    assert report.model_dump_json() == before
    assert getattr(_first(report).properties, "converted_path") == (
        "archive/bundle.zip-extracted/member.py"
    )


def test_a_result_in_the_scanned_tree_is_untouched(converted):
    _, context = converted
    report = _report(_result(".mcp.json", 3))
    before = report.model_dump_json()

    assert map_back_converted_results(report, context) == 0

    assert report.model_dump_json() == before


@pytest.mark.parametrize(
    "sidecar_text",
    [
        "not json",
        '{"script_line": 3}',
        json.dumps(
            [
                {
                    "script_line": 3,
                    "source_file": "/etc/passwd",
                    "line": 1,
                    "col": 1,
                    "end_line": 1,
                    "end_col": 2,
                }
            ]
        ),
        json.dumps(
            [
                {
                    "script_line": 3,
                    "source_file": "../outside.json",
                    "line": 1,
                    "col": 1,
                    "end_line": 1,
                    "end_col": 2,
                }
            ]
        ),
        json.dumps(
            [
                {
                    "script_line": 3,
                    "source_file": ".mcp.json",
                    "line": "1",
                    "col": 1,
                    "end_line": 1,
                    "end_col": 2,
                }
            ]
        ),
    ],
    ids=["not-json", "not-a-list", "absolute-source", "escaping-source", "text-number"],
)
def test_an_unusable_sidecar_row_maps_nothing(converted, sidecar_text):
    script, context = converted
    script.with_name(script.name + ".spanmap.json").write_text(
        sidecar_text, encoding="utf-8"
    )
    report = _report(_result(script.as_posix(), 3))
    mark_converted_results(report, context)
    before = report.model_dump_json()

    assert map_back_converted_results(report, context) == 0

    assert report.model_dump_json() == before


def test_a_mapped_finding_is_keyed_by_the_original_file_and_line(converted):
    """Identity comes from the original path: the converted tree is out of the key."""
    script, context = converted
    row = _sidecar_rows(script)[-1]
    unmapped = _report(_result(script.as_posix(), row["script_line"]))
    mark_converted_results(unmapped, context)
    mapped = _report(_result(script.as_posix(), row["script_line"]))
    mark_converted_results(mapped, context)
    map_back_converted_results(mapped, context)

    def flat(report: SarifReport) -> FlatVulnerability:
        return FlatVulnerability.from_sarif_result(
            _first(report), "semgrep", "SAST", run=report.runs[0]
        )

    mapped_flat = flat(mapped)
    unmapped_flat = flat(unmapped)

    assert mapped_flat.file_path == ".mcp.json"
    assert mapped_flat.line_start == row["line"]
    assert mapped_flat.id != unmapped_flat.id
    assert mapped_flat._identity.base.get("tree") is None
    assert unmapped_flat._identity.base.get("tree") == "converted"
    assert mapped_flat._identity.base["file"] == ".mcp.json"


def test_a_suppression_written_against_the_original_path_matches(converted):
    from automated_security_helper.utils.sarif_utils import (
        apply_suppressions_to_sarif,
    )

    script, context = converted
    row = _sidecar_rows(script)[-1]
    context.config.global_settings.suppressions = [
        AshSuppression(
            rule_id="R1",
            path=".mcp.json",
            line_start=row["line"],
            line_end=row["end_line"],
            reason="vendored fixture",
        )
    ]
    report = _report(_result(script.as_posix(), row["script_line"]))
    mark_converted_results(report, context)
    map_back_converted_results(report, context)

    suppressed = apply_suppressions_to_sarif(
        sarif_report=report, plugin_context=context, scanner_name="semgrep"
    )

    assert _first(suppressed).suppressions
    assert "vendored fixture" in _first(suppressed).suppressions[0].justification


def test_the_hook_is_wired_after_the_marking_in_the_scanner_executor():
    """The executor runs the mark, then the map-back, before suppressions."""
    import inspect

    from automated_security_helper.core.phases import scanner_executor

    source = inspect.getsource(scanner_executor)
    mark = source.index("mark_converted_results(raw_results")
    mapback = source.index("map_back_converted_results(raw_results")
    suppress = source.index("apply_suppressions_to_sarif(", mapback)
    assert mark < mapback < suppress


def test_the_plugin_context_type_is_what_the_hook_reads(test_plugin_context):
    assert isinstance(test_plugin_context, PluginContext)
    assert isinstance(test_plugin_context.config, AshConfig)
