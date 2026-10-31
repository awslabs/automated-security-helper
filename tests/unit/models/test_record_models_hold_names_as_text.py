# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A result model holds a file name that is not UTF-8 as text, and can be written and read back.

Python lists a file name byte that is not UTF-8 as a lone surrogate. pydantic cannot
write one as JSON, and a model that strips whitespace refuses one when it is built.
One such name in a SARIF result, or in the aggregated results, is held in its
record form, so each dump writes every file's results. The result models hold
each such name in its
record form, the surrogate written as the six characters \\udcNN
(utils/undecodable_text.py), so the scanner or plugin that built the record needs to
do nothing.

The first test is the guard: every model in the result modules derives from the base
that applies the form, so a model added there without it fails here.
"""

from __future__ import annotations

import inspect
import sys
import typing
from pathlib import Path
from types import ModuleType
from typing import List

import pytest
from pydantic import BaseModel, RootModel

from automated_security_helper.models import asharp_model, flat_vulnerability
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
    RefusedInputInfo,
    ReportMetadata,
    ScannerTargetStatusInfo,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas import sarif_schema_model
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils import undecodable_text
from automated_security_helper.utils.undecodable_text import text_of_undecodable

pytestmark = pytest.mark.unit

#: A latin-1 file name as Python lists it, and as a record holds it. Decoded with
#: surrogateescape on every platform: os.fsdecode gives that on POSIX, but on
#: Windows the filesystem encoding is UTF-8 with surrogatepass (PEP 529), so the
#: lone 0xe9 would raise UnicodeDecodeError while this module is collected.
ODD = b"secr\xe9t.py".decode(sys.getfilesystemencoding(), "surrogateescape")
RECORDED = "secr\\udce9t.py"


def test_the_odd_name_round_trips_to_its_bytes():
    """The name is the one Python lists for the file on a POSIX filesystem: the
    undecodable byte is kept as a lone surrogate, and encoding it back with the
    same handler gives the bytes the file has."""
    assert ODD.encode(sys.getfilesystemencoding(), "surrogateescape") == b"secr\xe9t.py"
    assert ODD == "secr\udce9t.py"


RESULT_MODULES: List[ModuleType] = [
    sarif_schema_model,
    asharp_model,
    flat_vulnerability,
]


def _models_defined_in(module: ModuleType):
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if issubclass(obj, BaseModel) and obj.__module__ == module.__name__:
            yield obj


def _model_types_in(annotation) -> List[type]:
    found = []
    for arg in typing.get_args(annotation) or (annotation,):
        if inspect.isclass(arg) and issubclass(arg, BaseModel):
            found.append(arg)
        elif typing.get_args(arg):
            found.extend(_model_types_in(arg))
    return found


def _strips(model: type) -> bool:
    return bool(model.model_config.get("str_strip_whitespace"))


@pytest.mark.parametrize("module", RESULT_MODULES, ids=lambda m: m.__name__)
def test_every_result_model_holds_names_in_the_record_form(module):
    """A RootModel can't take the base; its root is then a model that does, or a
    str a pattern keeps to ASCII (DeprecatedGuid). A model that strips whitespace
    takes StrippedRecordModel, apart from AshAggregatedResults, whose str fields are
    named by its own before-validator."""
    RecordModel = getattr(undecodable_text, "RecordModel", None)
    StrippedRecordModel = getattr(undecodable_text, "StrippedRecordModel", None)
    assert RecordModel is not None and StrippedRecordModel is not None
    unrecorded = []
    for model in _models_defined_in(module):
        if issubclass(model, RootModel):
            root = model.model_fields["root"]
            types = _model_types_in(root.annotation)
            if types:
                unrecorded += [
                    f"{model.__name__}.root: {t.__name__}"
                    for t in types
                    if not issubclass(t, RecordModel)
                ]
            elif not any(getattr(m, "pattern", None) for m in root.metadata):
                unrecorded.append(f"{model.__name__}.root: str with no pattern")
        elif not issubclass(model, RecordModel):
            unrecorded.append(model.__name__)
        elif (
            _strips(model)
            and not issubclass(model, StrippedRecordModel)
            and model is not AshAggregatedResults
        ):
            unrecorded.append(f"{model.__name__}: strips whitespace")
    assert unrecorded == []


def test_the_aggregated_results_name_every_own_str_field():
    own_strs = {
        name
        for name, field in AshAggregatedResults.model_fields.items()
        if field.annotation is str
    }
    validated = {
        field
        for decorator in AshAggregatedResults.__pydantic_decorators__.field_validators.values()
        if decorator.cls_var_name == "_names_as_recorded_before"
        for field in decorator.info.fields
    }
    assert own_strs and own_strs <= validated, (own_strs, validated)


class _PluginDetail(BaseModel):
    """A plugin's own model, as one might put in a property bag."""

    path: str


def _result(uri: str) -> Result:
    return Result(
        ruleId="R1",
        message=Message(text=f"A finding in '{uri}'"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri=uri)
                )
            )
        ],
        properties=PropertyBag(tags=[f"file::{uri}"], detail=_PluginDetail(path=uri)),
    )


def test_a_sarif_result_built_with_the_name_is_written_and_read_back():
    report = SarifReport(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="scripted")),
                invocations=[
                    Invocation(
                        commandLine=f"tool --exclude {ODD}",
                        arguments=["--exclude", ODD],
                        executionSuccessful=True,
                    )
                ],
                results=[_result(ODD)],
            )
        ]
    )

    written = report.model_dump_json(exclude_none=True)
    back = SarifReport.model_validate_json(written)

    result = back.runs[0].results[0]
    assert result.locations[0].physicalLocation.root.artifactLocation.uri == RECORDED
    assert result.message.root.text == f"A finding in '{RECORDED}'"
    assert result.properties.tags == [f"file::{RECORDED}"]
    assert result.properties.detail == {"path": RECORDED}
    assert back.runs[0].invocations[0].arguments == ["--exclude", RECORDED]
    assert back.runs[0].invocations[0].commandLine == f"tool --exclude {RECORDED}"
    # Read back, the record is the one that was written.
    assert back.model_dump_json(exclude_none=True) == written


def test_a_record_model_holds_the_name_in_its_record_form_and_reads_it_back():
    rows = {
        "converter": ConverterStatusInfo(
            converted_paths=[ODD], failure=f"OSError: {ODD}"
        ),
        "refusal": RefusedInputInfo(path=ODD, member=ODD, reason=f"a link: {ODD}"),
        "scanner": ScannerTargetStatusInfo(missing_reason=ODD, skipped_reason=ODD),
        "metadata": ReportMetadata(
            project_name=ODD, report_id="ASH-report", tool_version="v"
        ),
        "finding": FlatVulnerability(
            id="1",
            title="t",
            description=ODD,
            severity="HIGH",
            scanner="s",
            scanner_type="SAST",
            file_path=ODD,
        ),
    }

    dumped = {name: row.model_dump_json() for name, row in rows.items()}

    for name, text in dumped.items():
        assert RECORDED.replace("\\", "\\\\") in text, (name, text)
        assert type(rows[name]).model_validate_json(text).model_dump_json() == text


def test_one_scanner_naming_the_file_costs_no_scanner_its_findings(tmp_path: Path):
    """Scanner B's invocation names the file (a link exclusion); scanner A's finding
    elsewhere is in the results file, which reads back."""
    finding = _result("app.py")
    model = AshAggregatedResults(
        sarif=SarifReport(
            runs=[
                Run(tool=Tool(driver=ToolComponent(name="a")), results=[finding]),
                Run(
                    tool=Tool(driver=ToolComponent(name="b")),
                    invocations=[
                        Invocation(
                            arguments=["--exclude", ODD], executionSuccessful=True
                        )
                    ],
                    results=[],
                ),
            ]
        )
    )

    model.save_model(tmp_path)
    back = AshAggregatedResults.model_validate_json(
        (tmp_path / "ash_aggregated_results.json").read_bytes()
    )

    assert [r.ruleId for r in back.sarif.get_all_results()] == ["R1"]
    assert back.sarif.runs[1].invocations[0].arguments == ["--exclude", RECORDED]


@pytest.mark.parametrize(
    "name",
    ["app.py", "mödule.py", "名前.py", RECORDED, "tab\there.py"],
    ids=["ascii", "latin", "cjk", "spelled-escape", "control"],
)
def test_a_name_that_is_text_is_held_as_it_is(name):
    """The form changes lone surrogates only; it leaves text, the escape's own
    characters included, as it is, so applying it twice changes nothing."""
    uri = _result(name).locations[0].physicalLocation.root.artifactLocation.uri

    assert uri == name
    assert text_of_undecodable(uri) == uri
