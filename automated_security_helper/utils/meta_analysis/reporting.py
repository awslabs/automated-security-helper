# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Report generation: HTML reports, JQ queries, reporter mappings, field presence."""

import html
import json
import re
import shlex
from typing import Any, Dict, List, Optional, Set

from automated_security_helper.utils.meta_analysis.field_mapping import (
    PathStep,
    get_value_from_path,
    parse_field_path,
)

#: The names the aggregated report is analyzed under: ``ash`` (its file is
#: ``reports/ash.sarif``, named by its stem) and the older ``ash-aggregated``.
#: One tuple for the field analysis and this report, which read ``ash-aggregated``
#: alone and so pointed every aggregate field's JQ example at a scanners
#: directory that does not exist.
AGGREGATE_SCANNER_NAMES = ("ash", "ash-aggregated")

#: The directory the JQ examples name when the caller gives none.
DEFAULT_SARIF_DIR = ".ash/ash_output"

#: Keys of the SARIF document itself. A path that starts with any other key is
#: read as relative to a result, as the validation's field paths are.
_DOCUMENT_KEYS = frozenset(
    {"$schema", "version", "runs", "inlineExternalProperties", "properties"}
)

#: A key jq accepts after a bare ``.``: an identifier.
_JQ_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _escaped(value: Any) -> str:
    """*value* as text safe to place in HTML content or a quoted attribute.

    Field paths, scanner names and original values come from SARIF files and
    directory names ASH did not write, so a ``<`` or ``&`` in one is data, not
    markup.
    """
    return html.escape(str(value), quote=True)


# ---------------------------------------------------------------------------
# generate_jq_query
# ---------------------------------------------------------------------------


def _jq_steps(steps: List[PathStep]) -> str:
    """*steps* as a jq path: ``.a["b-c"][]``. A bracket at the start is written
    ``.[...]``, since a bare ``["x"]`` is an array literal to jq."""
    rendered = ""
    for kind, value in steps:
        if kind == "key" and _JQ_IDENTIFIER.match(value):
            rendered += f".{value}"
            continue
        bracket = (
            f"[{json.dumps(value, ensure_ascii=False)}]" if kind == "key" else "[]"
        )
        rendered += bracket if rendered else f".{bracket}"
    return rendered


def _jq_condition(steps: List[PathStep]) -> str:
    """Whether the value at *steps* is set, with each array along the way read
    as ``any(.array[]; ...)`` so the test is one boolean, not a generator.

    A path that ends in an array tests the elements themselves: ``tags[]``
    reads as ``any(.tags[]; . != null)``. Without the ``.`` the condition was
    the empty path, `` != null``, which jq refuses to compile."""
    arrays = [index for index, (kind, _) in enumerate(steps) if kind == "any"]
    if not arrays:
        return f"{_jq_steps(steps) or '.'} != null"
    first = arrays[0]
    head = _jq_steps(steps[: first + 1])
    return f"any({head}; {_jq_condition(steps[first + 1 :])})"


def generate_jq_query(field_path: str) -> str:
    """
    Generate a JQ query to find the findings that carry the specified field.

    A path under ``runs[].results[]`` becomes ``.runs[].results[] |
    select(<the rest is set>)``, which outputs each result that has the field.
    An index reads as ``[]`` (``runs[0]`` is ``runs[]``), and so does a bare
    ``runs`` or ``results`` key, since both are arrays. A path that starts with
    a key the document itself has, with no array segment, selects the document
    (``. | select(has("version")) | select(.version != null)``); one under an
    array other than results streams that array (``.runs[] | select(...)``).
    A path that starts with a result's own key (``message.text``, the form the
    validation reports) is read as relative to a result. Arrays below the
    streamed one are tested with ``any(.x[]; ...)``: a generator inside
    ``select`` printed the document once per matching element. A key that is
    not a jq identifier is written ``["key"]``, so a fingerprint key such as
    ``bandit/v1`` does not fail to compile.

    Args:
        field_path: The field path to search for (e.g., 'runs[0].results[0].suppressions[0].kind')

    Returns:
        A JQ query string that will return findings containing the field
    """
    steps = parse_field_path(str(field_path))
    if steps is None or steps[0][0] != "key":
        return f". | select(.{str(field_path)} != null)"

    # Every index is any element; a bare runs or results key is its array.
    normalized: List[PathStep] = []
    for position, (kind, value) in enumerate(steps):
        if kind == "index":
            normalized.append(("any", None))
            continue
        normalized.append((kind, value))
        following = steps[position + 1] if position + 1 < len(steps) else None
        if (
            kind == "key"
            and value in ("runs", "results")
            and following is not None
            and following[0] == "key"
        ):
            normalized.append(("any", None))

    first_key = normalized[0][1]
    if first_key not in _DOCUMENT_KEYS:
        # Relative to a result.
        return f".runs[].results[] | select({_jq_condition(normalized)})"

    arrays = [index for index, (kind, _) in enumerate(normalized) if kind == "any"]
    if not arrays:
        key = json.dumps(first_key, ensure_ascii=False)
        return f". | select(has({key})) | select({_jq_steps(normalized)} != null)"

    # Stream through the arrays up to results[] when the path has one, else
    # through every array; what follows is the condition on each element.
    stream_end = arrays[-1]
    for index in arrays:
        if index > 0 and normalized[index - 1] == ("key", "results"):
            stream_end = index
            break
    stream = _jq_steps(normalized[: stream_end + 1])
    rest = normalized[stream_end + 1 :]
    if not rest:
        return f"{stream} | select(. != null)"
    return f"{stream} | select({_jq_condition(rest)})"


# ---------------------------------------------------------------------------
# get_reporter_mappings
# ---------------------------------------------------------------------------

#: The static mappings, keyed by the reporter names the report's columns use.
_STATIC_REPORTER_MAPPINGS: Dict[str, Dict[str, str]] = {
    # OCSF mappings
    "ocsf": {
        "runs[].tool.driver.rules[].id": "vulnerabilities[].cve.uid",
        "runs[].results[].message.text": "vulnerabilities[].desc",
        "runs[].results[].ruleId": "vulnerabilities[].title",
        "runs[].results[].level": "severity",
        "runs[].results[].locations[].physicalLocation.artifactLocation.uri": "affected_code[].file.path",
        "runs[].results[].locations[].physicalLocation.region.startLine": "affected_code[].start_line",
        "runs[].results[].locations[].physicalLocation.region.endLine": "affected_code[].end_line",
    },
    # ASFF mappings
    "asff": {
        "runs[].results[].ruleId": "Findings[].Types[]",
        "runs[].results[].message.text": "Findings[].Description",
        "runs[].results[].level": "Findings[].Severity.Label",
        "runs[].results[].locations[].physicalLocation.artifactLocation.uri": "Findings[].Resources[].Details.AwsEc2Instance.Path",
        "runs[].tool.driver.name": "Findings[].ProductFields.aws/securityhub/ProductName",
    },
    # CSV mappings
    "csv": {
        "runs[].results[].ruleId": "Rule ID",
        "runs[].results[].message.text": "Description",
        "runs[].results[].level": "Severity",
        "runs[].results[].locations[].physicalLocation.artifactLocation.uri": "File Path",
        "runs[].results[].locations[].physicalLocation.region.startLine": "Line Start",
        "runs[].tool.driver.name": "Scanner",
    },
    # Flat JSON mappings
    "flat-json": {
        "runs[].results[].ruleId": "rule_id",
        "runs[].results[].message.text": "description",
        "runs[].results[].level": "severity",
        "runs[].results[].locations[].physicalLocation.artifactLocation.uri": "file_path",
        "runs[].results[].locations[].physicalLocation.region.startLine": "line_start",
        "runs[].results[].locations[].physicalLocation.region.endLine": "line_end",
        "runs[].tool.driver.name": "scanner",
    },
    # JUnit XML mappings
    "junitxml": {
        "runs[].results[].ruleId": "testcase.classname",
        "runs[].results[].message.text": "testcase.name",
        "runs[].results[].level": "testcase.result.type",
        "runs[].tool.driver.name": "testsuite.name",
    },
    # Markdown mappings
    "markdown": {
        "runs[].results[].ruleId": "Finding.title",
        "runs[].results[].message.text": "Finding.description",
        "runs[].results[].level": "Finding.severity",
        "runs[].results[].locations[].physicalLocation.artifactLocation.uri": "Finding.location",
        "runs[].tool.driver.name": "Finding.scanner",
    },
    # HTML mappings
    "html": {
        "runs[].results[].ruleId": "table.row.rule",
        "runs[].results[].message.text": "table.row.message",
        "runs[].results[].level": "table.row.severity",
        "runs[].results[].locations[].physicalLocation.artifactLocation.uri": "table.row.location",
        "runs[].tool.driver.name": "table.section.scanner",
    },
}

#: A reporter class name, lower-cased without "Reporter", to the key its static
#: mappings use, where the two differ. FlatJsonReporter derived "flatjson" and
#: landed beside the static "flat-json" as a second column.
_REPORTER_KEY_ALIASES = {"flatjson": "flat-json"}


def _reporter_key(reporter: type) -> str:
    name = reporter.__name__.replace("Reporter", "").lower()
    return _REPORTER_KEY_ALIASES.get(name, name)


def get_reporter_mappings() -> Dict[str, Dict[str, str]]:
    """
    Get field mappings from registered reporters.

    This function collects SARIF field mappings from all registered reporter plugins.
    Each reporter can define how it maps SARIF fields to its own output format.
    The static mappings are the floor: they are returned when the reporter
    plugins cannot be imported, and a reporter's own ``sarif_field_mappings``
    are merged into the entry of its name.

    Returns:
        Dictionary mapping reporter names to their field mappings
    """
    mappings: Dict[str, Dict[str, str]] = {
        name: dict(fields) for name, fields in _STATIC_REPORTER_MAPPINGS.items()
    }

    # Try to import reporter plugins dynamically
    try:
        from automated_security_helper.plugin_modules.ash_builtin.reporters import (
            CsvReporter,
            CycloneDXReporter,
            HtmlReporter,
            FlatJsonReporter,
            JunitXmlReporter,
            MarkdownReporter,
            OcsfReporter,
            SarifReporter,
            SpdxReporter,
            TextReporter,
            YamlReporter,
        )
    except ImportError:
        # Without the reporters, the static mappings defined above stand.
        return mappings

    # Try to get mappings from reporter instances if they have a sarif_field_mappings attribute
    reporters = [
        CsvReporter,
        CycloneDXReporter,
        HtmlReporter,
        FlatJsonReporter,
        JunitXmlReporter,
        MarkdownReporter,
        OcsfReporter,
        SarifReporter,
        SpdxReporter,
        TextReporter,
        YamlReporter,
    ]

    for reporter in reporters:
        if hasattr(reporter, "sarif_field_mappings") and callable(
            getattr(reporter, "sarif_field_mappings")
        ):
            reporter_mappings = reporter.sarif_field_mappings()
            if reporter_mappings:
                mappings.setdefault(_reporter_key(reporter), {}).update(
                    reporter_mappings
                )

    return mappings


# ---------------------------------------------------------------------------
# check_field_presence_in_reports
# ---------------------------------------------------------------------------


def _mapping_key(path: str) -> str:
    """*path* as the reporter mappings key it: every index as ``[]``."""
    return re.sub(r"\[\d+\]", "[]", str(path))


def check_field_presence_in_reports(
    field_paths: Dict[str, Dict[str, Set[str]]],
    aggregate_report: Dict,
    flat_reports: Optional[Dict[str, Dict]] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Check if fields are present in aggregate and flat reports.

    A field path is looked up in the aggregate as written (``runs[0].results[0].x``
    or ``runs[].results[].x``, both of which ``get_value_from_path`` reads) and
    in the reporter mappings with every index read as ``[]``, the form their
    keys use; the two notations never met before, so no mapping was ever found.
    A mapped field is looked up in a dict report by the same grammar, so
    ``vulnerabilities[].desc`` is present when some element has ``desc`` (it was
    tested as a literal key, and a scalar on the way raised TypeError). A text
    report shows a field when its mapped name appears in it; with no mapping, a
    text report can say nothing, so it is not read as showing the field because
    the path's last segment happens to occur in it.

    Args:
        field_paths: Dictionary of field paths from original reports
        aggregate_report: The aggregated SARIF report
        flat_reports: Optional dictionary of flat report formats (CSV, JSON)

    Returns:
        Dictionary mapping field paths to presence information
    """
    presence_info: Dict[str, Dict[str, Any]] = {}
    reporter_mappings = get_reporter_mappings()

    # First, initialize the presence_info dictionary with all fields
    for path, info in field_paths.items():
        if path not in presence_info:
            presence_info[path] = {
                "type": sorted(info["type"]),
                "scanners": sorted(info["scanners"]),
                "in_aggregate": False,
                "in_flat": {},
                "reporter_mappings": {},
            }
        else:
            # If the path already exists, merge the scanner information
            scanners_set = set(presence_info[path]["scanners"])
            scanners_set.update(info["scanners"])
            presence_info[path]["scanners"] = sorted(scanners_set)

            # Do the same for types
            types_set = set(presence_info[path]["type"])
            types_set.update(info["type"])
            presence_info[path]["type"] = sorted(types_set)

        # Check presence in aggregate report
        if aggregate_report:
            result = get_value_from_path(aggregate_report, path)
            presence_info[path]["in_aggregate"] = result["exists"]

        # Check presence in flat reports
        if flat_reports:
            lookup = _mapping_key(path)
            for report_type, report_data in flat_reports.items():
                presence_info[path]["in_flat"][report_type] = False

                # Get the mapping for this report type if available
                mapped_field = reporter_mappings.get(report_type, {}).get(lookup)
                if mapped_field is not None:
                    # Check if the mapped field exists in the flat report
                    if isinstance(report_data, dict):
                        presence_info[path]["in_flat"][report_type] = (
                            get_value_from_path(report_data, mapped_field)["exists"]
                        )
                    elif isinstance(report_data, str):
                        # For text-based formats, check if the field name appears in the content
                        presence_info[path]["in_flat"][report_type] = (
                            mapped_field in report_data
                        )
                elif isinstance(report_data, dict):
                    # Fallback to checking if the last part of the path exists in the report
                    field_name = path.split(".")[-1]
                    if field_name in report_data:
                        presence_info[path]["in_flat"][report_type] = True

    # Add reporter mappings if available
    for path in presence_info:
        lookup = _mapping_key(path)
        for reporter_name, reporter_map in reporter_mappings.items():
            if lookup in reporter_map:
                presence_info[path]["reporter_mappings"][reporter_name] = reporter_map[
                    lookup
                ]

    return presence_info


# ---------------------------------------------------------------------------
# generate_html_report  (aliased as generate_field_mapping_html_report)
# ---------------------------------------------------------------------------


def _example_file(scanners: Set[str], sarif_dir: str) -> str:
    """The file the JQ command of a field reads: a scanner's reports when a
    scanner carries the field, the aggregate when only the aggregate does."""
    root = shlex.quote(sarif_dir)
    # A set: iterate it sorted so the example names the same scanner on every
    # run.
    for scanner in sorted(scanners):
        if scanner not in AGGREGATE_SCANNER_NAMES:
            # The scanner name is a directory name ASH did not choose; quoted for
            # the shell so a space or a quote in it stays one argument. The glob
            # is left outside the quotes so the shell expands it.
            return f"{root}/scanners/{shlex.quote(scanner)}/**/*.sarif"
    return f"{root}/reports/ash.sarif"


def generate_html_report(
    validation_results: Dict,
    output_path: str,
    field_presence: Dict[str, Dict[str, Any]] = None,
    root: Optional[str] = None,
    sarif_dir: Optional[str] = None,
) -> None:
    """
    Generate a comprehensive HTML report showing SARIF field analysis and validation results.

    Args:
        validation_results: Validation results dictionary. Its ``summary`` may
            carry ``unit``: ``"fields"`` when the counts are field paths (the
            field analysis), else they are findings.
        output_path: Path to write the HTML report
        field_presence: Optional dictionary with field presence information
        root: The directory the report is written below, for a caller that has
            registered no writable root (the ``ash inspect`` CLI): the write then
            follows no link at any component below it
        sarif_dir: The directory the analyzed SARIF files were read from, which
            the JQ example commands name; ``.ash/ash_output`` when not given
    """
    sarif_dir = sarif_dir or DEFAULT_SARIF_DIR
    html = []
    html.append("<!DOCTYPE html>")
    html.append("<html>")
    html.append("<head>")
    # The file is written as UTF-8; said so, or a field path or scanner name
    # outside ASCII is rendered in the browser's default encoding.
    html.append('  <meta charset="utf-8">')
    html.append("  <title>SARIF Field Analysis Report</title>")
    # Add CSS for sortable headers and filtering
    html.append("  <style>")
    html.append("    body { font-family: Arial, sans-serif; margin: 20px; }")
    html.append("    h1, h2, h3 { color: #333; }")
    html.append(
        "    .summary { background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }"
    )
    html.append(
        "    .scanner { margin-bottom: 30px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }"
    )
    html.append(
        "    .scanner-header { display: flex; justify-content: space-between; align-items: center; }"
    )
    html.append("    .stats { display: flex; gap: 20px; margin: 10px 0; }")
    html.append(
        "    .stat { background-color: #eee; padding: 10px; border-radius: 3px; }"
    )
    html.append("    .critical { color: #d32f2f; }")
    html.append("    .important { color: #f57c00; }")
    html.append("    .informational { color: #388e3c; }")
    html.append("    .present { color: #388e3c; }")
    html.append("    .missing { color: #d32f2f; }")
    html.append(
        "    .field-table { width: 100%; border-collapse: collapse; margin: 15px 0; }"
    )
    html.append(
        "    .field-table th, .field-table td { padding: 8px; text-align: left; border: 1px solid #ddd; }"
    )
    html.append("    .field-table th { background-color: #f2f2f2; }")
    html.append("    .field-table tr:nth-child(even) { background-color: #f9f9f9; }")
    html.append("    .field-path { font-family: monospace; font-weight: bold; }")
    html.append(
        "    .field-value { font-family: monospace; color: #666; white-space: pre-wrap; }"
    )
    html.append(
        "    .collapsible { cursor: pointer; padding: 10px; background-color: #f1f1f1; }"
    )
    html.append("    .content { display: none; padding: 10px; overflow: hidden; }")
    html.append("    .active { display: block; }")
    html.append(
        "    .tab { overflow: hidden; border: 1px solid #ccc; background-color: #f1f1f1; }"
    )
    html.append(
        "    .tab button { background-color: inherit; float: left; border: none; outline: none; cursor: pointer; padding: 14px 16px; transition: 0.3s; }"
    )
    html.append("    .tab button:hover { background-color: #ddd; }")
    html.append("    .tab button.active { background-color: #ccc; }")
    html.append(
        "    .tabcontent { display: none; padding: 6px 12px; border: 1px solid #ccc; border-top: none; }"
    )
    html.append("    .search-container { margin: 10px 0; }")
    html.append("    #fieldSearch { width: 300px; padding: 8px; margin-right: 10px; }")
    html.append("    .reporter-mapping { margin-top: 5px; color: #0066cc; }")
    # Add styles for sortable headers
    html.append("    .sortable { cursor: pointer; position: relative; }")
    html.append(
        "    .sortable:after { content: '\\25BC'; font-size: 0.7em; position: absolute; right: 5px; opacity: 0.5; }"
    )
    html.append("    .sortable.asc:after { content: '\\25B2'; opacity: 1; }")
    html.append("    .sortable.desc:after { content: '\\25BC'; opacity: 1; }")
    html.append(
        "    .filter-row input { width: 100%; padding: 5px; box-sizing: border-box; margin-bottom: 5px; }"
    )
    html.append("    .jq-query { font-size: 0.8em; margin-top: 5px; color: #666; }")
    html.append(
        "    .jq-query code { background-color: #f5f5f5; padding: 2px 4px; border-radius: 3px; }"
    )
    # Add styles for dropdown
    html.append(
        "    .dropdown { position: relative; display: inline-block; margin-left: 10px; }"
    )
    html.append(
        "    .dropbtn { background-color: #f1f1f1; color: #333; padding: 5px; font-size: 12px; border: none; cursor: pointer; border-radius: 3px; }"
    )
    html.append(
        "    .dropdown-content { display: none; position: absolute; background-color: #f9f9f9; min-width: 300px; box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2); z-index: 1; padding: 10px; }"
    )
    html.append("    .dropdown:hover .dropdown-content { display: block; }")
    html.append(
        "    .dropdown-content code { display: block; padding: 5px; background-color: #f5f5f5; margin-bottom: 5px; white-space: pre-wrap; word-break: break-all; }"
    )
    html.append(
        "    .copy-btn { background-color: #4CAF50; color: white; border: none; padding: 5px 10px; text-align: center; text-decoration: none; display: inline-block; font-size: 12px; margin: 4px 2px; cursor: pointer; border-radius: 3px; }"
    )
    html.append("  </style>")
    html.append("</head>")
    html.append("<body>")

    # Add title and tabs
    html.append("  <h1>SARIF Field Analysis Report</h1>")

    html.append("  <div class='tab'>")
    html.append(
        "    <button class='tablinks active' onclick='openTab(event, \"FieldAnalysis\")'>Field Analysis</button>"
    )
    html.append(
        "    <button class='tablinks' onclick='openTab(event, \"ValidationResults\")'>Validation Results</button>"
    )
    html.append(
        "    <button class='tablinks' onclick='openTab(event, \"SarifFieldTable\")'>SARIF Field Table</button>"
    )
    html.append("  </div>")

    # Field Analysis Tab
    html.append("  <div id='FieldAnalysis' class='tabcontent' style='display: block;'>")
    html.append("    <h2>Field Analysis by Scanner</h2>")

    # Extract all scanners and fields from validation results
    all_scanners = set()
    all_fields = {}

    for scanner, importance_categories in validation_results["missing_fields"].items():
        all_scanners.add(scanner)
        for importance, fields in importance_categories.items():
            for field_info in fields:
                path = field_info["path"]
                if path not in all_fields:
                    all_fields[path] = {
                        "type": set(),
                        "scanners": {scanner},
                        "in_aggregate": False,
                    }
                else:
                    all_fields[path]["scanners"].add(scanner)

    # Add scanner sections. Sorted by name: callers build match_statistics from
    # set iteration, so its insertion order changes with PYTHONHASHSEED.
    for scanner, stats in sorted(validation_results["match_statistics"].items()):
        # The share of results that matched: match_rate where the caller gives
        # it, else the older field whose value was that share.
        match_rate = stats.get("match_rate", stats.get("field_preservation_rate", 0))
        html.append("    <div class='scanner'>")
        html.append("      <div class='scanner-header'>")
        html.append(f"        <h3>{_escaped(scanner)}</h3>")
        html.append(
            f"        <div>Match Rate: {stats['matched_results']}/{stats['total_results']} ({match_rate:.2%})</div>"
        )
        html.append("      </div>")

        # Add missing fields sections
        for importance in ["critical", "important", "informational"]:
            missing_fields = validation_results["missing_fields"][scanner][importance]
            if missing_fields:
                html.append(
                    f"      <div class='collapsible {importance}'>{importance.capitalize()} Missing Fields ({len(missing_fields)})</div>"
                )
                html.append("      <div class='content'>")
                html.append("        <table class='field-table'>")
                html.append(
                    "          <tr><th>Field Path</th><th>Original Value</th></tr>"
                )

                for field in missing_fields:
                    html.append("          <tr>")
                    html.append(
                        f"            <td class='field-path'>{_escaped(field['path'])}</td>"
                    )
                    html.append(
                        f"            <td class='field-value'>{_escaped(json.dumps(field['original_value'], indent=2))}</td>"
                    )
                    html.append("          </tr>")

                html.append("        </table>")
                html.append("      </div>")

        html.append("    </div>")

    html.append("  </div>")

    # Validation Results Tab
    html.append("  <div id='ValidationResults' class='tabcontent'>")

    # Add validation summary section. The counts are findings, or field paths
    # when the caller says so: the field analysis counted field paths under a
    # "Total Findings" label.
    summary = validation_results["summary"]
    counts_fields = summary.get("unit") == "fields"
    total_label = "Total Fields" if counts_fields else "Total Findings"
    matched_label = "Fields in Aggregate" if counts_fields else "Matched Findings"
    html.append("    <div class='summary'>")
    html.append("      <h2>Validation Summary</h2>")
    html.append("      <div class='stats'>")
    html.append(
        f"        <div class='stat'>{total_label}: {summary['total_findings']}</div>"
    )
    # A run whose SARIF files hold no results has nothing to match; report 0%
    # rather than dividing by zero.
    total_findings = summary["total_findings"]
    matched_findings = summary["matched_findings"]
    matched_share = matched_findings / total_findings if total_findings else 0.0
    html.append(
        f"        <div class='stat'>{matched_label}: {matched_findings} ({matched_share:.2%})</div>"
    )
    html.append("      </div>")
    html.append("      <div class='stats'>")
    html.append(
        f"        <div class='stat critical'>Critical Missing Fields: {summary['critical_missing_fields']}</div>"
    )
    html.append(
        f"        <div class='stat important'>Important Missing Fields: {summary['important_missing_fields']}</div>"
    )
    html.append(
        f"        <div class='stat informational'>Informational Missing Fields: {summary['informational_missing_fields']}</div>"
    )
    html.append("      </div>")
    html.append("    </div>")

    # Add scanner results table
    html.append("    <h2>Scanner Results</h2>")
    html.append("    <table class='field-table'>")
    html.append("      <tr>")
    html.append("        <th>Scanner</th>")
    html.append("        <th>Matched/Total</th>")
    html.append("        <th>Match Rate</th>")
    html.append("        <th>Critical Missing</th>")
    html.append("        <th>Important Missing</th>")
    html.append("        <th>Informational Missing</th>")
    html.append("      </tr>")

    for scanner, stats in sorted(validation_results["match_statistics"].items()):
        match_rate = (
            stats.get("match_rate", stats.get("field_preservation_rate", 0)) * 100
        )
        html.append("      <tr>")
        html.append(f"        <td>{_escaped(scanner)}</td>")
        html.append(
            f"        <td>{stats['matched_results']}/{stats['total_results']}</td>"
        )
        html.append(f"        <td>{match_rate:.2f}%</td>")
        html.append(
            f"        <td class='critical'>{stats.get('critical_fields_missing', 0)}</td>"
        )
        html.append(
            f"        <td class='important'>{stats.get('important_fields_missing', 0)}</td>"
        )
        html.append(
            f"        <td class='informational'>{stats.get('informational_fields_missing', 0)}</td>"
        )
        html.append("      </tr>")

    html.append("    </table>")
    html.append("  </div>")

    # SARIF Field Table Tab
    html.append("  <div id='SarifFieldTable' class='tabcontent'>")
    html.append("    <h2>SARIF Field Analysis Table</h2>")
    html.append("    <div class='search-container'>")
    html.append(
        "      <input type='text' id='fieldSearch' placeholder='Search for fields...' onkeyup='applyFilters()'>"
    )
    html.append("    </div>")
    html.append("    <table class='field-table' id='sarifFieldTable'>")
    html.append("      <thead>")
    html.append("      <tr>")
    html.append("        <th class='sortable'>SARIF Field</th>")
    html.append("        <th class='sortable'>Supporting Scanners</th>")
    html.append("        <th class='sortable'>Field Type</th>")
    html.append("        <th class='sortable'>Aggregated Results Includes?</th>")

    # Add a column for each reporter type
    reporter_mappings = get_reporter_mappings()
    reporter_types = sorted(reporter_mappings.keys())
    for reporter_type in reporter_types:
        html.append(f"        <th class='sortable'>{_escaped(reporter_type)}</th>")

    html.append("      </tr>")
    html.append("      <tr class='filter-row'>")
    html.append("        <td><input type='text' placeholder='Filter by field...'></td>")
    html.append(
        "        <td><input type='text' placeholder='Filter by scanner...'></td>"
    )
    html.append("        <td><input type='text' placeholder='Filter by type...'></td>")
    html.append(
        "        <td><input type='text' placeholder='Filter by presence...'></td>"
    )

    # Add filter inputs for each reporter type
    for _ in reporter_types:
        html.append(
            "        <td><input type='text' placeholder='Filter by mapping...'></td>"
        )

    html.append("      </tr>")
    html.append("      </thead>")
    html.append("      <tbody>")

    # Collect all fields from all scanners
    all_fields_by_path = {}

    # First, add fields from validation_results
    for scanner, importance_categories in validation_results["missing_fields"].items():
        for importance, fields in importance_categories.items():
            for field_info in fields:
                path = field_info["path"]
                if path not in all_fields_by_path:
                    all_fields_by_path[path] = {
                        "scanners": {scanner},
                        "type": set(),
                        "in_aggregate": False,
                        "intentionally_excluded": False,
                    }
                else:
                    all_fields_by_path[path]["scanners"].add(scanner)

    # Then, if field_presence is provided, add or update with that information.
    # The intentionally_excluded flag travels with the entry: the row below reads
    # it, and dropping it here rendered every excluded field as "No" in the
    # missing (red) style.
    if field_presence:
        for path, info in field_presence.items():
            # Ensure scanners and types are lists, not strings: a string went
            # into set() and was split into its characters.
            scanners = info.get("scanners", [])
            if isinstance(scanners, str):
                scanners = [scanners]
            types = info.get("type", [])
            if isinstance(types, str):
                types = [types]

            if path not in all_fields_by_path:
                all_fields_by_path[path] = {
                    "scanners": set(scanners),
                    "type": set(types),
                    "in_aggregate": info.get("in_aggregate", False),
                    "in_flat": info.get("in_flat", {}),
                    "reporter_mappings": info.get("reporter_mappings", {}),
                    "intentionally_excluded": bool(
                        info.get("intentionally_excluded", False)
                    ),
                }
            else:
                all_fields_by_path[path]["intentionally_excluded"] = bool(
                    info.get(
                        "intentionally_excluded",
                        all_fields_by_path[path].get("intentionally_excluded", False),
                    )
                )
                all_fields_by_path[path]["scanners"].update(set(scanners))
                all_fields_by_path[path]["type"].update(set(types))
                all_fields_by_path[path]["in_aggregate"] = info.get(
                    "in_aggregate", all_fields_by_path[path].get("in_aggregate", False)
                )
                all_fields_by_path[path]["in_flat"] = info.get(
                    "in_flat", all_fields_by_path[path].get("in_flat", {})
                )
                all_fields_by_path[path]["reporter_mappings"] = info.get(
                    "reporter_mappings",
                    all_fields_by_path[path].get("reporter_mappings", {}),
                )

    # Sort fields by path for better readability
    for row_index, path in enumerate(sorted(all_fields_by_path.keys())):
        info = all_fields_by_path[path]
        scanners_list = ", ".join(sorted(info["scanners"]))

        # Determine field type - use a default if not available
        field_type = "unknown"
        if info["type"]:
            field_type = ", ".join(sorted(info["type"]))

        # Generate JQ query for this field
        jq_query = generate_jq_query(path)

        # Find an example file that contains this field
        example_file = _example_file(info["scanners"], sarif_dir)

        # shlex.quote closes and reopens the single quotes around a quote in the
        # query, which a field key can hold.
        jq_command = f"jq {shlex.quote(jq_query)} {example_file}"

        # Create a unique ID for this field's JQ query. The row index is unique by
        # construction and stable across runs; hash(path) was neither, since
        # string hashing is randomized per process.
        field_id = f"jq-{row_index}"

        # Add row to table. The field path is in its own span, so the search box
        # and the column filter read the name alone and not the JQ command and
        # button labels beside it.
        html.append("      <tr>")
        html.append(f"""
        <td class='field-path'>
            <span class='field-name'>{_escaped(path)}</span>
            <div class='dropdown'>
                <button class='dropbtn'>JQ</button>
                <div class='dropdown-content'>
                    <code id='{field_id}'>{_escaped(jq_command)}</code>
                    <button id='btn-{field_id}' class='copy-btn' onclick="copyToClipboard('{field_id}')">Copy</button>
                </div>
            </div>
        </td>
        """)
        html.append(f"        <td>{_escaped(scanners_list)}</td>")
        html.append(f"        <td>{_escaped(field_type)}</td>")

        # In Aggregate column with proper styling
        in_agg_class = "present" if info.get("in_aggregate", False) else "missing"
        in_agg_text = "Yes" if info.get("in_aggregate", False) else "No"

        if info.get("intentionally_excluded", False):
            in_agg_text += " (Intentionally Excluded)"
            in_agg_class = "informational"

        html.append(f"        <td class='{in_agg_class}'>{in_agg_text}</td>")

        # Add a cell for each reporter type
        for reporter_type in reporter_types:
            # The mapping the presence check found for this path, else the
            # reporter's own, looked up the way check_field_presence_in_reports
            # looks it up: the mappings key every index as ``[]``, so a path
            # written ``runs[0].results[0].x`` found none and its column was blank.
            mapped_field = (info.get("reporter_mappings") or {}).get(
                reporter_type
            ) or reporter_mappings.get(reporter_type, {}).get(_mapping_key(path), "")

            html.append(f"        <td class='field-path'>{_escaped(mapped_field)}</td>")
        html.append("      </tr>")

    html.append("      </tbody>")
    html.append("    </table>")
    html.append("  </div>")

    # Add JavaScript for collapsible sections, tabs, and search
    html.append("  <script>")
    html.append("    // Collapsible sections")
    html.append("    var coll = document.getElementsByClassName('collapsible');")
    html.append("    for (var i = 0; i < coll.length; i++) {")
    html.append("      coll[i].addEventListener('click', function() {")
    html.append("        this.classList.toggle('active');")
    html.append("        var content = this.nextElementSibling;")
    html.append("        if (content.style.display === 'block') {")
    html.append("          content.style.display = 'none';")
    html.append("        } else {")
    html.append("          content.style.display = 'block';")
    html.append("        }")
    html.append("      });")
    html.append("    }")

    html.append("    // Tab functionality")
    html.append("    function openTab(evt, tabName) {")
    html.append("      var i, tabcontent, tablinks;")
    html.append("      tabcontent = document.getElementsByClassName('tabcontent');")
    html.append("      for (i = 0; i < tabcontent.length; i++) {")
    html.append("        tabcontent[i].style.display = 'none';")
    html.append("      }")
    html.append("      tablinks = document.getElementsByClassName('tablinks');")
    html.append("      for (i = 0; i < tablinks.length; i++) {")
    html.append(
        "        tablinks[i].className = tablinks[i].className.replace(' active', '');"
    )
    html.append("      }")
    html.append("      document.getElementById(tabName).style.display = 'block';")
    html.append("      evt.currentTarget.className += ' active';")
    html.append("    }")

    # The text a table entry is filtered on: the field name alone for the first
    # column, since that entry also holds the JQ command and its button labels.
    html.append("    // Filtering: every filter applies at once")
    html.append("    function entryText(entry) {")
    html.append("      const name = entry.querySelector('.field-name');")
    html.append("      const node = name ? name : entry;")
    html.append("      return (node.textContent || node.innerText || '').trim();")
    html.append("    }")
    # One pass computes each row's visibility from the search box and every
    # column filter together; each input used to reset every row from its own
    # value alone, so combining filters showed rows another filter had hidden.
    html.append("    function applyFilters() {")
    html.append("      const table = document.getElementById('sarifFieldTable');")
    html.append("      const search = document.getElementById('fieldSearch');")
    html.append("      const searchValue = search ? search.value.toUpperCase() : '';")
    html.append(
        "      const filters = Array.from(document.querySelectorAll('.filter-row input'));"
    )
    html.append("      const rows = table.querySelectorAll('tbody tr');")
    html.append("      rows.forEach(row => {")
    html.append("        const entries = row.querySelectorAll('td');")
    html.append("        let visible = true;")
    html.append("        if (searchValue && entries[0]) {")
    html.append(
        "          visible = entryText(entries[0]).toUpperCase().indexOf(searchValue) > -1;"
    )
    html.append("        }")
    html.append("        filters.forEach((input, index) => {")
    html.append("          const value = input.value.toUpperCase();")
    html.append("          if (!visible || !value || !entries[index]) { return; }")
    html.append(
        "          visible = entryText(entries[index]).toUpperCase().indexOf(value) > -1;"
    )
    html.append("        });")
    html.append("        row.style.display = visible ? '' : 'none';")
    html.append("      });")
    html.append("    }")

    # Add copy to clipboard functionality
    html.append("    function copyToClipboard(elementId) {")
    html.append("      const element = document.getElementById(elementId);")
    html.append("      const text = element.textContent;")
    html.append("      ")
    html.append("      navigator.clipboard.writeText(text).then(function() {")
    html.append("        const button = document.getElementById('btn-' + elementId);")
    html.append("        const originalText = button.textContent;")
    html.append("        button.textContent = 'Copied!';")
    html.append("        setTimeout(function() {")
    html.append("          button.textContent = originalText;")
    html.append("        }, 1000);")
    html.append("      }, function() {")
    html.append("        alert('Failed to copy text');")
    html.append("      });")
    html.append("    }")

    # Add sorting functionality. The comparator returns 0 for equal entries, so
    # it is consistent for Array.prototype.sort; one that never did left the
    # order of ties (every 'unknown' type) to the engine.
    html.append("    // Sorting function")
    html.append("    function sortTable(table, column, asc = true) {")
    html.append("      const dirModifier = asc ? 1 : -1;")
    html.append("      const tBody = table.tBodies[0];")
    html.append("      const rows = Array.from(tBody.querySelectorAll('tr'));")
    html.append("      ")
    html.append("      const sortedRows = rows.sort((a, b) => {")
    html.append(
        "        const aColText = entryText(a.querySelector(`td:nth-child(${column + 1})`));"
    )
    html.append(
        "        const bColText = entryText(b.querySelector(`td:nth-child(${column + 1})`));"
    )
    html.append("        ")
    html.append("        return aColText.localeCompare(bColText) * dirModifier;")
    html.append("      });")
    html.append("      ")
    html.append("      while (tBody.firstChild) {")
    html.append("        tBody.removeChild(tBody.firstChild);")
    html.append("      }")
    html.append("      ")
    html.append("      tBody.append(...sortedRows);")
    html.append("      ")
    html.append(
        "      table.querySelectorAll('th').forEach(th => th.classList.remove('asc', 'desc'));"
    )
    html.append(
        "      table.querySelector(`th:nth-child(${column + 1})`).classList.toggle('asc', asc);"
    )
    html.append(
        "      table.querySelector(`th:nth-child(${column + 1})`).classList.toggle('desc', !asc);"
    )
    html.append("    }")

    # Add event listeners for sorting and filtering
    html.append("    document.addEventListener('DOMContentLoaded', function() {")
    html.append("      const table = document.getElementById('sarifFieldTable');")
    html.append("      const headers = table.querySelectorAll('th.sortable');")
    html.append("      ")
    html.append("      headers.forEach((header, index) => {")
    html.append("        header.addEventListener('click', () => {")
    html.append("          const isAscending = header.classList.contains('asc');")
    html.append("          sortTable(table, index, !isAscending);")
    html.append("        });")
    html.append("      });")
    html.append("      ")
    html.append(
        "      const filterInputs = document.querySelectorAll('.filter-row input');"
    )
    html.append("      filterInputs.forEach(input => {")
    html.append("        input.addEventListener('keyup', applyFilters);")
    html.append("      });")
    html.append("    });")
    html.append("  </script>")

    html.append("</body>")
    html.append("</html>")

    # Write the HTML file; below an output directory, never through a link there.
    from automated_security_helper.utils.sandbox.fs_guard import open_for_write

    with open_for_write(output_path, root=root) as f:
        f.write("\n".join(html))
