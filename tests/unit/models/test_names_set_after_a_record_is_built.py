# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A file name that is not UTF-8, set on a result after it is built, is recorded too.

The result models put such a name in its record form (the surrogate as the six
characters \\udcNN) when they are validated. pydantic validates neither a value
assigned to a field afterwards nor a model made with ``model_construct``, so each place
that does either is held here:

- cfn-nag points its findings back at the template by assigning the template's path;
- the aggregated results are built empty and filled in as the scan runs: each
  scanner's error text goes into ``additional_reports``, and the phases append
  ``validation_checkpoints``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cfn_nag_scanner,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Suppression,
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


def test_cfn_nag_points_a_finding_at_the_template_in_the_record_form(tmp_path: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    staged = run_dir / cfn_nag_scanner._CFN_NAG_INPUT_DIR / "copy.yaml"
    report = _report(_result(staged.as_posix()))

    cfn_nag_scanner._restore_cfn_nag_uris(
        report, staged, os.path.join(str(run_dir), ODD), run_dir
    )

    written = report.model_dump_json(exclude_none=True)
    back = SarifReport.model_validate_json(written)
    uri = (
        back.runs[0].results[0].locations[0].physicalLocation.root.artifactLocation.uri
    )
    assert uri == RECORDED


def test_a_name_assigned_to_a_nested_field_after_the_report_is_built_is_recorded(
    tmp_path: Path,
):
    """Any code that sets a result's URI after validation, as cfn-nag's restore did.
    The scanner's own SARIF write and the aggregated results' write both hold it."""
    model = AshAggregatedResults(sarif=_report(_result("app.py"), _result("b.py")))
    location = model.sarif.runs[0].results[1].locations[0]
    location.physicalLocation.root.artifactLocation.uri = ODD

    scanner_file = SarifReport.model_validate_json(model.sarif.model_dump_json())
    model.save_model(tmp_path)
    back = AshAggregatedResults.model_validate_json(
        (tmp_path / "ash_aggregated_results.json").read_bytes()
    )

    for report in (scanner_file, back.sarif):
        uris = [
            r.locations[0].physicalLocation.root.artifactLocation.uri
            for r in report.get_all_results()
        ]
        assert uris == ["app.py", RECORDED]


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


def _run_the_report_phase(model: AshAggregatedResults, out: Path):
    """Every builtin reporter over *model*, as a scan's report phase runs them.
    Returns the model the phase hands on, and each report written, by file name."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.phases.report_phase import ReportPhase
    from automated_security_helper.core.progress import LiveProgressDisplay
    from automated_security_helper.plugin_modules.ash_builtin import ASH_REPORTERS

    every = AshConfig(reporters={"spdx": {"enabled": True}, "yaml": {"enabled": True}})
    context = PluginContext(source_dir=out, output_dir=out, config=every)
    names = [reporter(context=context).config.name for reporter in ASH_REPORTERS]
    phase = ReportPhase(
        plugins=list(ASH_REPORTERS),
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


def test_every_builtin_reporter_writes_a_name_set_after_the_results_were_built(
    tmp_path: Path,
):
    """Each report is written and holds the name in the record form, as often as the
    same report names a file whose UTF-8 name is the recorded text."""
    _, odd = _run_the_report_phase(
        _scan_like_results("app.py", raw_after=True), tmp_path / "odd"
    )
    _, spelled = _run_the_report_phase(
        _scan_like_results(RECORDED, raw_after=False), tmp_path / "spelled"
    )

    from automated_security_helper.plugin_modules.ash_builtin import ASH_REPORTERS

    assert sorted(odd) == sorted(spelled)
    # One report or more from each builtin reporter, the two disabled by default too.
    assert len(odd) >= len(ASH_REPORTERS), sorted(odd)
    assert {"ash.yaml", "ash.spdx.json"} <= set(odd), sorted(odd)
    counts = {
        name: (
            _texts(name, odd[name]).count(RECORDED),
            _texts(name, spelled[name]).count(RECORDED),
        )
        for name in spelled
    }
    differ = {name: count for name, count in counts.items() if count[0] != count[1]}
    assert differ == {}, differ
    assert counts["ash.sarif"][1] > 0 and counts["ash.flat.json"][1] > 0, counts


def test_what_a_reporter_does_to_the_results_is_in_the_results_the_run_goes_on_with(
    tmp_path: Path,
):
    """With such a name present the phase reads a copy in the record form; the run
    goes on with that copy, so a reporter's effect on the results is kept: here the
    flattening's count of suppressed findings, which the saved results carry."""
    model = _scan_like_results("app.py", raw_after=True)
    model.sarif.runs[0].results[0].suppressions = [
        Suppression(kind="external", justification="reviewed")
    ]

    handed_on, _ = _run_the_report_phase(model, tmp_path / "out")
    handed_on.save_model(tmp_path / "saved")
    saved = AshAggregatedResults.model_validate_json(
        (tmp_path / "saved" / "ash_aggregated_results.json").read_bytes()
    )

    assert handed_on.metadata.summary_stats.suppressed >= 1
    assert saved.metadata.summary_stats.suppressed == (
        handed_on.metadata.summary_stats.suppressed
    )
    uri = saved.sarif.runs[0].results[0].locations[0]
    assert uri.physicalLocation.root.artifactLocation.uri == RECORDED


def test_text_added_to_the_aggregated_results_as_the_scan_runs_is_recorded(
    tmp_path: Path,
):
    """As the result processor and the scan phase fill the model in."""
    model = AshAggregatedResults(sarif=_report(_result("app.py")))
    model.additional_reports["scripted"] = {
        "source": {"errors": [f"OSError: [Errno 13] Permission denied: '{ODD}'"]}
    }
    model.validation_checkpoints.append({"phase": "scan", "file": ODD})

    model.save_model(tmp_path)
    back = AshAggregatedResults.model_validate_json(
        (tmp_path / "ash_aggregated_results.json").read_bytes()
    )

    assert [r.ruleId for r in back.sarif.get_all_results()] == ["R1"]
    error = back.additional_reports["scripted"]["source"]["errors"][0]
    assert error == f"OSError: [Errno 13] Permission denied: '{RECORDED}'"
    assert back.validation_checkpoints[-1]["file"] == RECORDED


def test_a_dump_to_python_holds_the_record_form_too():
    """The reporters that write JSON themselves (flat JSON, OCSF, GitLab, GHAS) dump to
    Python first; a later read of what they wrote then gets the recorded text."""
    model = AshAggregatedResults(sarif=_report(_result("app.py")))
    model.additional_reports["scripted"] = {"source": {"errors": [ODD]}}

    dumped = json.dumps(model.model_dump(mode="json"))

    assert json.loads(dumped)["additional_reports"]["scripted"]["source"]["errors"] == [
        RECORDED
    ]
