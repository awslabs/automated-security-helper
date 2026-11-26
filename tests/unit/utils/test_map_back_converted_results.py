# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Findings in a generated file with a span sidecar land on the original span.

The MCP config converter writes a shell script per stdio server and a
``.spanmap.json`` beside it, and records both in its ``converted-sources.json``.
``place_converted_results`` runs at the converter result boundary: a result on a
generated line is moved to the config file's own span and keyed by the original
path, and what is still in a converted file is then marked. These tests pin that,
that a sidecar the converter did not record or whose rows are not plain paths to
files in the scanned tree maps nothing, and that a converted file with no sidecar
(every other converter's output) is left exactly as it was.
"""

import json
import re
from pathlib import Path

import pytest

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_builtin.converters.mcp_config_converter import (
    McpConfigConverter,
    McpConfigConverterConfig,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactChange,
    ArtifactLocation,
    Fix,
    Location,
    Message,
    PhysicalLocation,
    Region,
    Replacement,
    Result,
    Run,
    SarifReport,
    Stack,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.finding_identity import CONVERTED_FROM_PROPERTY
from automated_security_helper.utils.scan_output_dirs import (
    CONVERTED_SOURCES_FILE_NAME,
    MAX_SPAN_MAP_BYTES,
    place_converted_results,
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


def _location(uri: str, line: int, **region) -> Location:
    return Location(
        physicalLocation=PhysicalLocation(
            artifactLocation=ArtifactLocation(uri=uri),
            region=Region(startLine=line, **region),
        )
    )


def _result(uri: str, line: int, rule: str = "R1", **region) -> Result:
    return Result(
        ruleId=rule,
        message=Message(text="finding"),
        locations=[_location(uri, line, **region)],
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


def _convert(context, monkeypatch):
    """Convert the config in *context*'s tree; the script path it wrote."""
    tree = Path(context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    (tree / ".mcp.json").write_text(CONFIG, encoding="utf-8")
    monkeypatch.setattr(
        f"{MODULE}.scan_set", lambda **kwargs: [str(tree / ".mcp.json")]
    )
    converter = McpConfigConverter(context=context, config=McpConfigConverterConfig())
    (script,) = converter.convert()
    return script


@pytest.fixture
def converted(test_plugin_context, monkeypatch):
    """A converted config: the script path, and the context it was converted in."""
    return _convert(test_plugin_context, monkeypatch), test_plugin_context


def _sidecar(script: Path) -> Path:
    return script.with_name(script.name + ".spanmap.json")


def _sidecar_rows(script: Path):
    return json.loads(_sidecar(script).read_text(encoding="utf-8"))


def _record_file(script: Path) -> Path:
    return script.parent.parent / CONVERTED_SOURCES_FILE_NAME


def _row(**changes):
    row = {
        "script_line": 3,
        "source_file": ".mcp.json",
        "line": 2,
        "col": 3,
        "end_line": 5,
        "end_col": 6,
    }
    row.update(changes)
    return row


def _first(report: SarifReport) -> Result:
    return report.runs[0].results[0]


def _where(result: Result, index: int = 0):
    physical = result.locations[index].physicalLocation.root
    return physical.artifactLocation.uri, physical.region


def _flat(result: Result, report: SarifReport) -> FlatVulnerability:
    return FlatVulnerability.from_sarif_result(
        result, "semgrep", "SAST", run=report.runs[0]
    )


def test_a_result_on_a_generated_line_lands_on_the_original_span(converted):
    script, context = converted
    command_row = _sidecar_rows(script)[-1]
    report = _report(_result(script.as_posix(), command_row["script_line"]))

    assert place_converted_results(report, context) == (1, 0)

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
    assert '"elevated"' in CONFIG.splitlines()[command_row["line"] - 1]


def test_a_mapped_result_names_the_generated_file_and_is_never_marked(converted):
    script, context = converted
    report = _report(_result(script.as_posix(), 3))

    place_converted_results(report, context)

    properties = _first(report).properties
    assert getattr(properties, "converted_path", None) is None
    work = Path(context.work_dir).resolve()
    assert getattr(properties, CONVERTED_FROM_PROPERTY) == (
        script.resolve().relative_to(work).as_posix()
    )


def test_a_line_with_no_sidecar_row_stays_on_the_generated_file_and_is_marked(
    converted,
):
    script, context = converted
    report = _report(_result(script.as_posix(), 99))

    assert place_converted_results(report, context) == (0, 1)

    assert _where(_first(report))[0] == script.as_posix()
    assert getattr(_first(report).properties, "converted_path")
    assert getattr(_first(report).properties, CONVERTED_FROM_PROPERTY, None) is None


def test_a_converted_file_with_no_sidecar_is_marked_and_not_moved(test_plugin_context):
    """The archive and notebook converters write no sidecar: the hook no-ops."""
    context = test_plugin_context
    work = Path(context.work_dir)
    member = work / "archive" / "bundle.zip-extracted" / "member.py"
    member.parent.mkdir(parents=True)
    member.write_text("import os\n", encoding="utf-8")
    report = _report(_result(member.as_posix(), 1, startColumn=2, endColumn=8))

    assert place_converted_results(report, context) == (0, 1)

    assert _where(_first(report))[0] == member.as_posix()
    assert getattr(_first(report).properties, "converted_path") == (
        "archive/bundle.zip-extracted/member.py"
    )


def test_a_result_in_the_scanned_tree_is_untouched(converted):
    _, context = converted
    report = _report(_result(".mcp.json", 3))
    before = report.model_dump_json()

    assert place_converted_results(report, context) == (0, 0)

    assert report.model_dump_json() == before


def _not_mapped_back(context, script: Path) -> None:
    report = _report(_result(script.as_posix(), 3))

    mapped, _ = place_converted_results(report, context)

    assert mapped == 0
    assert _where(_first(report))[0] == script.as_posix()
    assert getattr(_first(report).properties, CONVERTED_FROM_PROPERTY, None) is None


def test_a_sidecar_inside_an_archive_the_converter_did_not_record_maps_nothing(
    converted,
):
    """A vendored archive can hold a script and a sidecar naming the config."""
    _, context = converted
    work = Path(context.work_dir)
    member = work / "archive" / "bundle.zip-extracted" / "evil.sh"
    member.parent.mkdir(parents=True)
    member.write_text("echo hi\n", encoding="utf-8")
    member.with_name("evil.sh.spanmap.json").write_text(
        json.dumps([_row()]), encoding="utf-8"
    )
    # What the archive converter records is the extraction directory.
    (work / "archive" / CONVERTED_SOURCES_FILE_NAME).write_text(
        json.dumps({"archive/bundle.zip-extracted/": "bundle.zip"}), encoding="utf-8"
    )

    _not_mapped_back(context, member)


def test_a_sidecar_the_converter_did_not_record_maps_nothing(converted):
    script, context = converted
    record = _record_file(script)
    recorded = json.loads(record.read_text(encoding="utf-8"))
    sidecar_key = [key for key in recorded if key.endswith(".spanmap.json")]
    assert sidecar_key
    for key in sidecar_key:
        del recorded[key]
    record.write_text(json.dumps(recorded), encoding="utf-8")

    _not_mapped_back(context, script)


def test_a_row_naming_another_file_than_the_recorded_source_maps_nothing(converted):
    script, context = converted
    (context.source_dir / "other.json").write_text("{}\n", encoding="utf-8")
    _sidecar(script).write_text(
        json.dumps([_row(source_file="other.json")]), encoding="utf-8"
    )

    _not_mapped_back(context, script)


@pytest.mark.parametrize(
    "contents",
    [
        "not json",
        '{"script_line": 3}',
        "[" * 200_000 + "]" * 200_000,
        json.dumps([_row(source_file="/etc/passwd")]),
        json.dumps([_row(source_file="../outside.json")]),
        json.dumps([_row(source_file="file:///etc/passwd")]),
        json.dumps([_row(source_file="https://example.com/x.json")]),
        json.dumps([_row(source_file="C:/Windows/x.json")]),
        json.dumps([_row(source_file="sub\\config.json")]),
        json.dumps([_row(source_file="missing.json")]),
        json.dumps([_row(source_file="subdir")]),
        json.dumps([_row(line="1")]),
        json.dumps([_row(line=0)]),
        json.dumps([_row(line=4, end_line=3)]),
        json.dumps([_row(line=3, col=5, end_line=3, end_col=4)]),
    ],
    ids=[
        "not-json",
        "not-a-list",
        "deeply-nested",
        "absolute-source",
        "escaping-source",
        "file-uri",
        "https-uri",
        "drive-path",
        "backslash",
        "missing-file",
        "a-directory",
        "text-number",
        "zero-line",
        "end-line-before-line",
        "end-column-before-column",
    ],
)
def test_an_unusable_sidecar_row_maps_nothing(converted, contents):
    script, context = converted
    (context.source_dir / "subdir").mkdir(exist_ok=True)
    _sidecar(script).write_text(contents, encoding="utf-8")

    _not_mapped_back(context, script)


def test_a_source_that_resolves_outside_the_tree_through_a_link_maps_nothing(converted):
    script, context = converted
    outside = Path(context.source_dir).parent / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    (context.source_dir / "link.json").symlink_to(outside)
    _sidecar(script).write_text(
        json.dumps([_row(source_file="link.json")]), encoding="utf-8"
    )

    _not_mapped_back(context, script)


def test_an_oversized_sidecar_maps_nothing(converted):
    script, context = converted
    padding = " " * (MAX_SPAN_MAP_BYTES + 1)
    _sidecar(script).write_text(json.dumps([_row()]) + padding, encoding="utf-8")

    _not_mapped_back(context, script)


def test_a_sidecar_that_is_a_link_maps_nothing(converted):
    script, context = converted
    target = Path(context.source_dir).parent / "rows.json"
    target.write_text(json.dumps([_row()]), encoding="utf-8")
    _sidecar(script).unlink()
    _sidecar(script).symlink_to(target)

    _not_mapped_back(context, script)


def test_a_mapped_result_drops_what_describes_the_generated_script(converted):
    script, context = converted
    row = _sidecar_rows(script)[-1]
    result = _result(script.as_posix(), row["script_line"])
    physical = result.locations[0].physicalLocation.root
    physical.artifactLocation.index = 4
    physical.contextRegion = Region(startLine=1, endLine=9)
    result.locations[0].annotations = [Region(startLine=2, endLine=4)]
    result.relatedLocations = [_location(script.as_posix(), 1)]
    result.codeFlows = []
    result.stacks = [Stack(frames=[])]
    result.fixes = [
        Fix(
            artifactChanges=[
                ArtifactChange(
                    artifactLocation=ArtifactLocation(uri=script.as_posix()),
                    replacements=[Replacement(deletedRegion=Region(startLine=3))],
                )
            ]
        )
    ]
    report = _report(result)

    place_converted_results(report, context)

    mapped = _first(report)
    physical = mapped.locations[0].physicalLocation.root
    assert physical.artifactLocation.index is None
    assert physical.contextRegion is None
    assert mapped.locations[0].annotations is None
    assert mapped.relatedLocations is None
    assert mapped.codeFlows is None
    assert mapped.stacks is None
    assert mapped.fixes is None


def test_a_mapped_result_keeps_the_fingerprints_the_scanner_gave_it(converted):
    """Fingerprints are the scanner's own identity for the finding, not coordinates."""
    script, context = converted
    row = _sidecar_rows(script)[-1]
    result = _result(script.as_posix(), row["script_line"])
    result.partialFingerprints = {"primaryLocationLineHash": "abc123:1"}
    result.fingerprints = {"fp/v1": "def456"}
    report = _report(result)

    place_converted_results(report, context)

    assert _first(report).partialFingerprints == {"primaryLocationLineHash": "abc123:1"}
    assert _first(report).fingerprints == {"fp/v1": "def456"}


def test_a_result_with_one_location_mapped_and_one_not_keeps_its_converted_path(
    converted,
):
    """A location left in the generated file still needs the converted path."""
    script, context = converted
    row = _sidecar_rows(script)[-1]
    result = _result(script.as_posix(), 99)
    result.locations.append(_location(script.as_posix(), row["script_line"]))
    report = _report(result)

    assert place_converted_results(report, context) == (1, 1)

    assert _where(_first(report), 0)[0] == script.as_posix()
    assert _where(_first(report), 1)[0] == ".mcp.json"
    work = Path(context.work_dir).resolve()
    assert getattr(_first(report).properties, "converted_path") == (
        script.resolve().relative_to(work).as_posix()
    )


def test_a_result_mapped_at_its_primary_location_is_keyed_by_the_original_file(
    converted,
):
    """locations[0] is mapped, a later location is on a script line with no row.

    The result is judged by its primary location, which is the one the finding is
    keyed by: it moved to ``.mcp.json``, so the later location in the script must
    not mark the result with the script's converted path (the key would name the
    script with ``.mcp.json``'s line numbers).
    """
    script, context = converted
    row = _sidecar_rows(script)[-1]
    result = _result(script.as_posix(), row["script_line"])
    result.locations.append(_location(script.as_posix(), 99))
    report = _report(result)

    assert place_converted_results(report, context) == (1, 0)

    assert _where(_first(report), 0)[0] == ".mcp.json"
    assert _where(_first(report), 1)[0] == script.as_posix()
    assert getattr(_first(report).properties, "converted_path", None) is None
    flat = _flat(_first(report), report)
    assert flat.file_path == ".mcp.json"
    assert flat.line_start == row["line"]
    assert flat._identity.base["file"] == ".mcp.json"
    assert flat._identity.base.get("tree") is None
    assert flat._identity.base["convertedFrom"]


def test_a_mapped_finding_is_keyed_by_the_original_file_and_line(converted):
    """Identity comes from the original path: the converted tree is out of the key."""
    script, context = converted
    row = _sidecar_rows(script)[-1]
    unmapped = _report(_result(script.as_posix(), 99))
    mapped = _report(_result(script.as_posix(), row["script_line"]))
    place_converted_results(unmapped, context)
    place_converted_results(mapped, context)

    mapped_flat = _flat(_first(mapped), mapped)
    unmapped_flat = _flat(_first(unmapped), unmapped)

    assert mapped_flat.file_path == ".mcp.json"
    assert mapped_flat.line_start == row["line"]
    assert mapped_flat.id != unmapped_flat.id
    assert mapped_flat._identity.base.get("tree") is None
    assert unmapped_flat._identity.base.get("tree") == "converted"
    assert mapped_flat._identity.base["file"] == ".mcp.json"


def test_a_mapped_finding_is_not_the_source_tree_scanners_finding_at_that_place(
    converted,
):
    """Two scans of one file: the tree's own result and the generated script's."""
    script, context = converted
    row = _sidecar_rows(script)[-1]
    generated = _report(
        _result(script.as_posix(), row["script_line"], startColumn=row["col"])
    )
    tree = _report(
        _result(
            ".mcp.json", row["line"], startColumn=row["col"], endLine=row["end_line"]
        )
    )
    place_converted_results(generated, context)
    place_converted_results(tree, context)

    mapped_flat = _flat(_first(generated), generated)
    tree_flat = _flat(_first(tree), tree)

    assert (mapped_flat.file_path, mapped_flat.line_start) == (
        tree_flat.file_path,
        tree_flat.line_start,
    )
    assert mapped_flat.id != tree_flat.id
    assert tree_flat._identity.base.get("convertedFrom") is None
    assert mapped_flat._identity.base["convertedFrom"] == getattr(
        _first(generated).properties, CONVERTED_FROM_PROPERTY
    )


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
    place_converted_results(report, context)

    suppressed = apply_suppressions_to_sarif(
        sarif_report=report, plugin_context=context, scanner_name="semgrep"
    )

    assert _first(suppressed).suppressions
    assert "vendored fixture" in _first(suppressed).suppressions[0].justification


def test_the_scanner_executor_places_results_through_the_one_call():
    from automated_security_helper.core.phases import scanner_executor
    from automated_security_helper.utils import scan_output_dirs

    assert (
        scanner_executor.place_converted_results
        is scan_output_dirs.place_converted_results
    )


PLACE_CALL = "place_converted_results(raw_results"
SUPPRESS_CALL = "apply_suppressions_to_sarif("
#: PLACE_CALL as the formatter may lay it out: the image branch pushed the call
#: one indent deeper, past the line length, so it can wrap after the paren.
PLACE_CALL_PATTERN = re.compile(r"place_converted_results\(\s*raw_results")


def _places_before_suppressing(source: str) -> bool:
    """Whether the first placement call precedes the first suppression call."""
    placed = PLACE_CALL_PATTERN.search(source)
    suppressed = source.find(SUPPRESS_CALL)
    return placed is not None and placed.start() < suppressed


def test_the_scanner_executor_places_before_it_applies_suppressions():
    """A suppression written against the original file matches only a placed result."""
    from automated_security_helper.core.phases import scanner_executor

    source = Path(scanner_executor.__file__).read_text(encoding="utf-8")

    assert len(PLACE_CALL_PATTERN.findall(source)) == 1
    assert _places_before_suppressing(source)


def test_the_order_check_flags_a_suppression_before_the_placement():
    swapped = f"{SUPPRESS_CALL}raw)\n{PLACE_CALL}, ctx)\n"
    absent = f"{SUPPRESS_CALL}raw)\n"

    assert _places_before_suppressing(f"{PLACE_CALL}, ctx)\n{SUPPRESS_CALL}raw)\n")
    assert not _places_before_suppressing(swapped)
    assert not _places_before_suppressing(absent)


def _map_through_source(context, script: Path, source_name: str) -> SarifReport:
    """Record *source_name* as the script's source, with a row naming it, and map."""
    record = _record_file(script)
    recorded = json.loads(record.read_text(encoding="utf-8"))
    relative = script.resolve().relative_to(Path(context.work_dir).resolve())
    recorded[relative.as_posix()] = source_name
    record.write_text(json.dumps(recorded), encoding="utf-8")
    (context.source_dir / source_name).write_text("{}\n", encoding="utf-8")
    _sidecar(script).write_text(
        json.dumps([_row(source_file=source_name)]), encoding="utf-8"
    )
    report = _report(_result(script.as_posix(), 3))
    place_converted_results(report, context)
    return report


@pytest.mark.parametrize(
    "name",
    ["my:config.json", "sub\\config.json", "a'b.json"],
    ids=["colon-in-name", "backslash-in-name", "quote-in-name"],
)
def test_a_posix_file_name_with_a_colon_or_backslash_is_a_source(converted, name):
    """Containment is the check on a name; the text refusals are scheme and drive."""
    script, context = converted

    report = _map_through_source(context, script, name)

    assert _where(_first(report))[0] == name


def test_a_name_that_is_a_drive_or_scheme_still_maps_nothing(converted):
    script, context = converted
    for name in ("C:/x.json", "c:\\x.json", "file:x.json", "FILE:///x", "s3://b/x"):
        report = _report(_result(script.as_posix(), 3))
        _sidecar(script).write_text(
            json.dumps([_row(source_file=name)]), encoding="utf-8"
        )
        recorded = json.loads(_record_file(script).read_text(encoding="utf-8"))
        relative = script.resolve().relative_to(Path(context.work_dir).resolve())
        recorded[relative.as_posix()] = name
        _record_file(script).write_text(json.dumps(recorded), encoding="utf-8")

        assert place_converted_results(report, context)[0] == 0, name


def test_the_record_is_not_read_for_a_scan_with_no_result_in_a_converted_file(
    converted, monkeypatch
):
    """A source-tree or image scan places nothing, so it need not read the record."""
    from automated_security_helper.utils import scan_output_dirs

    _, context = converted
    reads = []
    real = scan_output_dirs.converted_sources_of
    monkeypatch.setattr(
        scan_output_dirs,
        "converted_sources_of",
        lambda ctx: reads.append(1) or real(ctx),
    )
    report = _report(_result(".mcp.json", 3), _result("app/main.py", 7))

    assert place_converted_results(report, context) == (0, 0)

    assert reads == []


def test_the_record_is_read_once_for_a_scan_with_results_in_a_converted_file(
    converted, monkeypatch
):
    from automated_security_helper.utils import scan_output_dirs

    script, context = converted
    reads = []
    real = scan_output_dirs.converted_sources_of
    monkeypatch.setattr(
        scan_output_dirs,
        "converted_sources_of",
        lambda ctx: reads.append(1) or real(ctx),
    )
    report = _report(
        _result(script.as_posix(), 3),
        _result(script.as_posix(), 99),
        _result(script.as_posix(), 3, rule="R2"),
    )

    assert place_converted_results(report, context) == (2, 1)

    assert len(reads) == 1


def test_an_unreadable_record_warns_that_the_findings_are_not_mapped_back(
    converted, monkeypatch
):
    script, context = converted
    _record_file(script).write_text("not json", encoding="utf-8")
    warnings = []
    from automated_security_helper.utils import scan_output_dirs

    monkeypatch.setattr(
        scan_output_dirs.ASH_LOGGER,
        "warning",
        lambda text, *a, **k: warnings.append(text),
    )

    scan_output_dirs.converted_sources_of(context)

    assert warnings
    assert all("mapped back" in text for text in warnings)
    _record_file(script).write_text("[]", encoding="utf-8")
    warnings.clear()
    scan_output_dirs.converted_sources_of(context)
    assert warnings
    assert all("mapped back" in text for text in warnings)
