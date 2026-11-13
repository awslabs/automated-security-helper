# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""More names that are not UTF-8, given to the results after they are built, are saved.

The result models put such a name in its record form (the surrogate as the six
characters \\udcNN) when they are validated. pydantic validates neither a value
assigned to a field afterwards nor a model made with ``model_construct``. Beside the
places test_names_set_after_a_record_is_built.py holds, each of these must reach the
results file, every report and every dump without raising, and read back in the
record form:

- a workspace project's directory names the report's ``project_name``;
- a scanner's MISSING or SKIPPED reason reaches the results through its container;
- every builtin report, decoded as its format reads it, holds no lone surrogate;
- a dump in Python mode, which some reporters write from themselves;
- the SARIF reporter's rule and tool references, built with ``model_construct`` from
  values it copies out of results that were validated.

Values that may hold a lone surrogate are compared through ascii(): pytest's diff of
two such str cannot be sent between xdist workers.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
    complete_results_for_the_dump,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

pytestmark = pytest.mark.unit

# The constant below is a file name that is not UTF-8.
if os.name == "nt":
    pytest.skip(
        "a file name that is not UTF-8 cannot exist on NTFS (names are UTF-16)",
        allow_module_level=True,
    )

ODD = os.fsdecode(b"templ\xe9.yaml")
RECORDED = "templ\\udce9.yaml"
#: A plain name the same shape as RECORDED: a backslash and five letters where the
#: escape is. A report writes the two alike, so its count of this one is the
#: yardstick for RECORDED's.
SAME_SHAPE = "templ\\vdce9.yaml"
#: Any surrogate code point.
_SURROGATE = re.compile("[\ud800-\udfff]")


def _result(uri: str, rule: str = "R1") -> Result:
    return Result(
        ruleId=rule,
        message=Message(text="finding"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri=uri)
                )
            )
        ],
        properties=PropertyBag(scanner_name="scripted"),
    )


def _report(*results: Result) -> SarifReport:
    return SarifReport(
        runs=[
            Run(tool=Tool(driver=ToolComponent(name="cfn_nag")), results=list(results))
        ]
    )


def _saved_and_read_back(
    model: AshAggregatedResults, out: Path
) -> AshAggregatedResults:
    model.save_model(out)
    return AshAggregatedResults.model_validate_json(
        (out / "ash_aggregated_results.json").read_bytes()
    )


def test_a_project_name_from_a_directory_named_so_is_saved(tmp_path: Path):
    """A workspace names each project's report after its directory, by assigning
    the label to metadata.project_name once the results exist."""
    model = AshAggregatedResults(sarif=_report(_result("app.py")))
    model.metadata.project_name = os.fsdecode(b"caf\xe9")

    back = _saved_and_read_back(model, tmp_path)

    assert ascii(back.metadata.project_name) == ascii("caf\\udce9")
    assert [r.ruleId for r in back.sarif.get_all_results()] == ["R1"]


def _processed(tmp_path: Path, container: ScanResultsContainer) -> AshAggregatedResults:
    """*container* merged into fresh aggregated results, as the scan phase does."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.phases.scan_result_processor import (
        ScanResultProcessor,
    )

    out = tmp_path / "out"
    context = PluginContext(source_dir=tmp_path, output_dir=out, config=AshConfig())
    model = AshAggregatedResults(sarif=_report(_result("app.py")))
    return ScanResultProcessor(context).process_container(container, model)


def test_a_missing_reason_naming_the_file_is_saved(tmp_path: Path):
    """The executor assigns a MISSING row's reason after the container is built."""
    container = ScanResultsContainer(
        scanner_name="scripted", target_type="source", status=ScannerStatus.MISSING
    )
    container.missing_reason = f"cannot read '{ODD}'"

    back = _saved_and_read_back(_processed(tmp_path, container), tmp_path / "saved")

    row = back.additional_reports["scripted"]["source"]
    assert ascii(row["missing_reason"]) == ascii(f"cannot read '{RECORDED}'")
    assert [r.ruleId for r in back.sarif.get_all_results()] == ["R1"]


def test_a_skipped_reason_naming_the_file_is_saved(tmp_path: Path):
    container = ScanResultsContainer(
        scanner_name="scripted", target_type="source", status=ScannerStatus.SKIPPED
    )
    container.skipped_reason = f"no template parsed: '{ODD}'"

    back = _saved_and_read_back(_processed(tmp_path, container), tmp_path / "saved")

    row = back.additional_reports["scripted"]["source"]
    assert ascii(row["skipped_reason"]) == ascii(f"no template parsed: '{RECORDED}'")


def _scan_like_results(uri: str, raw_after: bool) -> AshAggregatedResults:
    """One finding, as a scanner reports it; with *raw_after*, its URI is set to the
    undecodable name after the results are built."""
    result = Result(
        ruleId="SECRET-AWS-ACCESS-KEY",
        level="error",
        kind="fail",
        message=Message(text="Secret of type 'AWS Access Key' detected"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri=uri)
                )
            )
        ],
        properties=PropertyBag(
            scanner_name="detect-secrets", tags=["detect-secrets", "secret"]
        ),
    )
    model = AshAggregatedResults(
        sarif=SarifReport(
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="detect-secrets")),
                    results=[result],
                )
            ]
        )
    )
    if raw_after:
        location = model.sarif.runs[0].results[0].locations[0]
        location.physicalLocation.root.artifactLocation.uri = ODD
    return model


def _every_reporter():
    """The builtin reporters and a configuration that enables each of them."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.plugin_modules.ash_builtin import ASH_REPORTERS

    probe = PluginContext(source_dir=Path.cwd(), output_dir=Path.cwd())
    names = [reporter(context=probe).config.name for reporter in ASH_REPORTERS]
    return (
        ASH_REPORTERS,
        names,
        AshConfig(reporters={name: {"enabled": True} for name in names}),
    )


def _run_the_report_phase(model: AshAggregatedResults, out: Path):
    """Every builtin reporter over *model*, as a scan's report phase runs them.
    Returns the model the phase hands on, and each report written, by file name."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.core.phases.report_phase import ReportPhase
    from automated_security_helper.core.progress import LiveProgressDisplay

    reporters, names, every = _every_reporter()
    context = PluginContext(source_dir=out, output_dir=out, config=every)
    phase = ReportPhase(
        plugins=list(reporters),
        plugin_context=context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=model,
    )
    handed_on = phase.execute(
        report_dir=out / "reports",
        cli_output_formats=names,
        aggregated_results=model,
        python_based_plugins_only=False,
    )
    written = {
        entry.name: entry.read_bytes().decode("utf-8")
        for entry in sorted((out / "reports").iterdir())
        if entry.is_file()
    }
    return handed_on, written


def _texts(name: str, document: str) -> str:
    """The text *document* holds, as its format decodes it, so that a name written as
    a JSON or YAML escape of the surrogate reads as the surrogate, not as the record
    form."""
    import yaml
    from defusedxml import ElementTree as ET

    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for key, item in value.items():
                yield from strings(key)
                yield from strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from strings(item)

    if name.endswith((".json", ".sarif")):
        return "\n".join(strings(json.loads(document)))
    if name.endswith(".yaml"):
        return "\n".join(strings(yaml.safe_load(document)))
    if name.endswith(".xml"):
        root = ET.fromstring(document)
        return "\n".join(
            part
            for element in root.iter()
            for part in (element.text, element.tail, *element.attrib.values())
            if part
        )
    return document


def _name_runs(text: str, tail: str) -> list:
    """Backslash-run lengths at each naming of the file in *text*: the record
    form's naming carries one backslash, the shown (one-line) form two, and a
    markdown context escapes each of those again for odd and plain alike."""
    return sorted(len(m.group(1)) for m in re.finditer(r"templ(\\+)" + tail, text))


def _conforms(name: str, odd_runs: list, plain_runs: list) -> bool:
    """Does the odd report name the file as the plain one does, with every
    shown sink doubling the record form's backslash? The record form reads as
    an escape, so the one-line form shows it with the backslash doubled:

    - the markdown and text summaries show every naming that way, so each odd
      run is its plain run doubled;
    - the HTML report shows the findings table that way and embeds the record
      form as data (the finding's code element and the copy attribute), so the
      naming count matches, every naming is the record or the doubled form,
      and the table's naming is the doubled one;
    - every other report is machine-read and holds the record form unchanged.
    """
    if name in ("ash.summary.md", "ash.summary.txt"):
        return odd_runs == sorted(2 * run for run in plain_runs)
    if name == "ash.html":
        return (
            len(odd_runs) == len(plain_runs)
            and set(plain_runs) == {1}
            and set(odd_runs) <= {1, 2}
            and 2 in odd_runs
        )
    return odd_runs == plain_runs


def test_every_builtin_report_holds_no_lone_surrogate_and_names_the_file(
    tmp_path: Path,
):
    """Each report is written, holds no lone surrogate once its format is decoded, and
    names the file as often as the same report names a plain file of the same shape:
    in the record form where a machine reads it, with the backslash doubled where a
    human report shows it on one line."""
    _, odd = _run_the_report_phase(
        _scan_like_results("app.py", raw_after=True), tmp_path / "odd"
    )
    _, plain = _run_the_report_phase(
        _scan_like_results(SAME_SHAPE, raw_after=False), tmp_path / "plain"
    )

    reporters, names, _ = _every_reporter()
    assert sorted(odd) == sorted(plain)
    # One report or more from each builtin reporter, the ones disabled by default too.
    assert len(odd) >= len(reporters), sorted(odd)
    assert {"ash.yaml", "ash.spdx.json"} <= set(odd), sorted(odd)
    decoded = {name: _texts(name, odd[name]) for name in odd}
    holding = sorted(name for name, text in decoded.items() if _SURROGATE.search(text))
    assert holding == [], holding
    counts = {
        name: (
            _name_runs(decoded[name], r"udce9\.yaml"),
            _name_runs(_texts(name, plain[name]), r"vdce9\.yaml"),
        )
        for name in plain
    }
    differ = {name: runs for name, runs in counts.items() if not _conforms(name, *runs)}
    assert differ == {}, differ
    assert counts["ash.sarif"][1] and counts["ash.flat.json"][1], counts


def test_a_dump_in_python_mode_holds_the_record_form():
    """The reporters that write JSON themselves (flat JSON, OCSF, GitLab, GHAS) dump to
    Python first; what they write from that dump holds the recorded text."""
    model = AshAggregatedResults(sarif=_report(_result("app.py")))
    model.additional_reports["scripted"] = {"source": {"errors": [ODD]}}

    dumped = model.model_dump(mode="python")

    errors = dumped["additional_reports"]["scripted"]["source"]["errors"]
    assert ascii(errors) == ascii([RECORDED])


def _saved_document(out: Path) -> dict:
    return json.loads((out / "ash_aggregated_results.json").read_bytes())


def test_a_name_as_a_dict_key_is_saved_in_the_record_form(tmp_path: Path):
    """A plugin's own report keyed by file name holds such a name as a dict KEY.
    A JSON dump cannot encode a lone surrogate in a key any more than in a value,
    so the key is written in the record form and the results file is saved."""
    model = AshAggregatedResults(sarif=_report(_result("app.py")))
    model.additional_reports["scripted"] = {"files": {ODD: ["x"]}}

    back = _saved_and_read_back(model, tmp_path)

    files = _saved_document(tmp_path)["additional_reports"]["scripted"]["files"]
    assert ascii(list(files)) == ascii([RECORDED])
    assert list(files.values()) == [["x"]]
    assert [r.ruleId for r in back.sarif.get_all_results()] == ["R1"]


def test_a_plugins_report_keyed_by_the_name_keeps_the_scanners_row(tmp_path: Path):
    """A scanner whose raw report is not SARIF and is keyed by file name, as
    detect-secrets' own output is: the per-scanner merge dumps its container
    with that key in it. The merge keeps the scanner's row, and the saved file
    writes the key in the record form."""
    container = ScanResultsContainer(
        scanner_name="scripted", target_type="source", status=ScannerStatus.PASSED
    )
    container.raw_results = {"results": {ODD: [{"type": "Secret Keyword"}]}}

    back = _saved_and_read_back(_processed(tmp_path, container), tmp_path / "saved")

    row = _saved_document(tmp_path / "saved")["additional_reports"]["scripted"]
    results = row["source"]["raw_results"]["results"]
    assert ascii(list(results)) == ascii([RECORDED])
    assert list(results.values()) == [[{"type": "Secret Keyword"}]]
    assert [r.ruleId for r in back.sarif.get_all_results()] == ["R1"]


def test_a_name_in_a_set_is_in_the_record_form_in_a_python_dump():
    """used_suppressions is a set, which a dump in Python mode keeps as one. A
    name added to it after the results are built is in the record form there,
    as a name anywhere else in the dump is."""
    model = AshAggregatedResults(sarif=_report(_result("app.py")))
    model.used_suppressions.add(ODD)

    dumped = model.model_dump(mode="python")

    assert ascii(sorted(dumped["used_suppressions"])) == ascii([RECORDED])
    json.dumps(sorted(dumped["used_suppressions"]), ensure_ascii=False).encode()


def test_a_name_in_a_path_value_is_in_the_record_form_in_a_python_dump():
    """A dump in Python mode keeps a Path as a Path. One that holds such a name
    reads in the record form, so a reporter that writes the dump as JSON (str()
    of a value it cannot serialize) writes text a strict UTF-8 reader takes."""
    model = AshAggregatedResults(sarif=_report(_result("app.py")))
    model.additional_reports["scripted"] = {"source": {"file": Path(ODD)}}

    dumped = model.model_dump(mode="python")

    value = dumped["additional_reports"]["scripted"]["source"]["file"]
    assert ascii(str(value)) == ascii(RECORDED)
    json.dumps(dumped["additional_reports"], default=str, ensure_ascii=False).encode()


def test_the_sarif_reporters_references_carry_only_recorded_text():
    """Its model_construct calls copy the rule id and the extension name out of results
    and rules that were validated, so they hold the record form already."""
    result = _result("app.py", rule=ODD)
    report = SarifReport(
        runs=[
            Run(
                tool=Tool(
                    driver=ToolComponent(name="ash"),
                    extensions=[
                        ToolComponent(
                            name="scripted", rules=[ReportingDescriptor(id=ODD)]
                        )
                    ],
                ),
                results=[result],
            )
        ]
    )

    restore = complete_results_for_the_dump(report)
    try:
        written = report.model_dump_json(
            by_alias=True, exclude_none=True, exclude_unset=True
        )
    finally:
        restore()

    dumped = json.loads(written)["runs"][0]["results"][0]
    assert ascii(dumped["ruleId"]) == ascii(RECORDED)
    assert ascii(dumped["rule"]["id"]) == ascii(RECORDED)
    assert dumped["rule"]["toolComponent"]["name"] == "scripted"
