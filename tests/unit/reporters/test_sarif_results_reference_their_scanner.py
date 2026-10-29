# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each result in ``ash.sarif`` says which scanner's rule it reports.

Why this exists
---------------
``ash.sarif`` is one run per project: ``tool.driver`` is ASH, and each scanner is a
``tool.extensions[]`` entry carrying its own name, version and rules. For a result
that names its rule only by ``ruleId``, with no ``rule.toolComponent``, a SARIF
reader looks the rule up in ``tool.driver.rules``, which is empty. SARIF 2.1.0
3.27.7: "If theDescriptor occurs in theTool.extensions (3.18.3), then rule
SHOULD be present", because "ruleIndex alone does not specify which extension
contains theDescriptor".

The sarif reporter gives each result whose rule is defined by its scanner's
extension a ``rule`` reference: ``id`` (equal to ``ruleId``), ``index`` (the
rule's position in that extension's ``rules``) and ``toolComponent`` (the
extension's ``name`` and its ``index`` in ``tool.extensions``). The reference adds
nothing else: the driver, the extensions, the rules, the ruleIds and the
locations stay as they are. A result whose rule no extension defines gets no
reference, since 3.27.7 says ``rule`` SHALL NOT be present without a descriptor.

The references are added to the reporter's output only; the results model and
``ash_aggregated_results.json`` are unchanged.
"""

import json
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
    SarifReporter,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.sarif_utils import attach_scanner_details

pytestmark = pytest.mark.unit

ASH_DRIVER = "AWS Labs - Automated Security Helper"
SCANNERS = [
    ("bandit", "1.8.6", ["a.py", "b.py"]),
    ("semgrep", "1.140.0", ["c.py"]),
    ("cfn-nag", "0.8.10", []),
]


def _scanner_report(name, version, uris):
    report = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": name,
                            # A rule no result uses, so indices are not trivially 0.
                            "rules": [{"id": f"{name}-unused"}]
                            + [{"id": f"{name}-{uri}"} for uri in uris],
                        }
                    },
                    "results": [
                        {
                            "ruleId": f"{name}-{uri}",
                            "level": "warning",
                            "message": {"text": f"{name} finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": uri},
                                        "region": {"startLine": 3},
                                    }
                                }
                            ],
                        }
                        for uri in uris
                    ],
                }
            ],
        }
    )
    return attach_scanner_details(report, scanner_name=name, scanner_version=version)


@pytest.fixture
def model(tmp_path):
    context = MagicMock()
    context.source_dir = tmp_path / "source"
    context.output_dir = tmp_path / "output"
    context.ignore_suppressions = True
    context.source_dir.mkdir()
    processor = ScanResultProcessor(
        plugin_context=context, validation_manager=MagicMock()
    )
    aggregated = AshAggregatedResults()
    for name, version, uris in SCANNERS:
        aggregated = processor.process_container(
            ScanResultsContainer(
                scanner_name=name,
                report_type="sarif",
                target=context.source_dir,
                target_type="source",
                raw_results=_scanner_report(name, version, uris),
            ),
            aggregated,
        )
    return aggregated


def _render(model, tmp_path) -> dict:
    context = PluginContext(source_dir=tmp_path, output_dir=tmp_path / "out")
    return json.loads(SarifReporter(context=context).report(model))


def _model_dump(model) -> dict:
    return json.loads(
        model.sarif.model_dump_json(
            by_alias=True, exclude_none=True, exclude_unset=True
        )
    )


def _without_rule(result: dict) -> dict:
    return {k: v for k, v in result.items() if k not in ("rule", "ruleIndex")}


def test_one_run_with_ash_as_driver_and_each_scanner_as_an_extension(model, tmp_path):
    document = _render(model, tmp_path)

    assert len(document["runs"]) == 1
    tool = document["runs"][0]["tool"]
    assert tool["driver"]["name"] == ASH_DRIVER
    assert tool["driver"]["version"] == get_ash_version()
    assert [(e["name"], e["version"]) for e in tool["extensions"]] == [
        (name, version) for name, version, _ in SCANNERS
    ]


def test_each_result_references_its_rule_in_its_scanners_extension(model, tmp_path):
    run = _render(model, tmp_path)["runs"][0]
    extensions = run["tool"]["extensions"]

    assert run["results"], "the fixture must produce results"
    for result in run["results"]:
        rule = result["rule"]
        component = rule["toolComponent"]
        extension = extensions[component["index"]]
        assert component["name"] == extension["name"]
        assert extension["name"] == result["properties"]["scanner_name"]
        assert extension["rules"][rule["index"]]["id"] == result["ruleId"]
        assert rule["id"] == result["ruleId"]
        # ruleIndex would have to equal rule.index (3.27.6); it is left out.
        assert "ruleIndex" not in result
    # The unused first rule makes every index non-zero.
    assert {r["rule"]["index"] for r in run["results"]} == {1, 2}


def test_nothing_but_the_references_changes(model, tmp_path):
    before = _model_dump(model)["runs"][0]
    after = _render(model, tmp_path)["runs"][0]

    assert after["tool"] == before["tool"]
    assert [_without_rule(r) for r in after["results"]] == [
        _without_rule(r) for r in before["results"]
    ]
    assert {k: v for k, v in after.items() if k != "results"} == {
        k: v for k, v in before.items() if k != "results"
    }


def test_github_relevant_fields_are_unchanged(model, tmp_path):
    before = _model_dump(model)["runs"][0]
    after = _render(model, tmp_path)["runs"][0]

    assert after["tool"]["driver"]["name"] == before["tool"]["driver"]["name"]
    assert [(r["ruleId"], r["locations"]) for r in after["results"]] == [
        (r["ruleId"], r["locations"]) for r in before["results"]
    ]


def test_a_result_without_a_descriptor_gets_no_reference(model, tmp_path):
    run = model.sarif.runs[0]
    orphan = run.results[0].model_copy(deep=True)
    orphan.ruleId = "NOT-A-RULE"
    unnamed = run.results[0].model_copy(deep=True)
    unnamed.ruleId = "ALSO-NOT-A-RULE"
    unnamed.properties = None
    run.results.extend([orphan, unnamed])

    results = {r["ruleId"]: r for r in _render(model, tmp_path)["runs"][0]["results"]}

    assert "rule" not in results["NOT-A-RULE"]
    assert "rule" not in results["ALSO-NOT-A-RULE"]


def test_two_extensions_with_one_name_resolve_by_rule(model, tmp_path):
    """The merge keeps same-named components apart when fullName differs."""
    tool = model.sarif.runs[0].tool
    twin = tool.extensions[0].model_copy(deep=True)
    twin.fullName = "another bandit"
    twin.rules = [twin.rules[0].model_copy(update={"id": "bandit-twin-only"})]
    tool.extensions.append(twin)
    result = model.sarif.runs[0].results[0].model_copy(deep=True)
    result.ruleId = "bandit-twin-only"
    model.sarif.runs[0].results.append(result)

    run = _render(model, tmp_path)["runs"][0]
    reference = next(r for r in run["results"] if r["ruleId"] == "bandit-twin-only")[
        "rule"
    ]

    assert reference["toolComponent"]["index"] == len(SCANNERS)
    assert reference["index"] == 0


def test_each_project_run_indexes_its_own_extensions(model, tmp_path):
    second = model.sarif.runs[0].model_copy(deep=True)
    second.tool.extensions = list(reversed(second.tool.extensions))
    model.sarif.runs.append(second)

    for run in _render(model, tmp_path)["runs"]:
        for result in run["results"]:
            extension = run["tool"]["extensions"][
                result["rule"]["toolComponent"]["index"]
            ]
            assert extension["name"] == result["properties"]["scanner_name"]


def test_the_results_model_is_not_changed(model, tmp_path):
    before = _model_dump(model)

    _render(model, tmp_path)

    assert _model_dump(model) == before


def test_the_document_is_dumped_once_and_not_validated_again(
    model, tmp_path, monkeypatch
):
    """One pass: re-validating 20,000 results took about 15 times as long."""

    def refuse(*args, **kwargs):
        raise AssertionError("the sarif reporter validated a document again")

    monkeypatch.setattr(SarifReport, "model_validate", refuse)
    monkeypatch.setattr(SarifReport, "model_validate_json", refuse)

    assert _render(model, tmp_path)["runs"][0]["results"][0]["rule"]


def test_a_results_own_rule_fields_are_kept(model, tmp_path):
    from automated_security_helper.schemas.sarif_schema_model import (
        ReportingDescriptorReference,
    )

    first = model.sarif.runs[0].results[0]
    first.rule = ReportingDescriptorReference.model_validate(
        {"id": first.ruleId, "guid": "8f7e3a2b-1c4d-4e5f-9a8b-7c6d5e4f3a2b"}
    )

    reference = _render(model, tmp_path)["runs"][0]["results"][0]["rule"]

    assert reference["guid"] == "8f7e3a2b-1c4d-4e5f-9a8b-7c6d5e4f3a2b"
    assert reference["toolComponent"]["name"] == "bandit"
    # And the model keeps the reference it had.
    assert first.rule.root.model_dump(exclude_unset=True) == {
        "id": first.ruleId,
        "guid": "8f7e3a2b-1c4d-4e5f-9a8b-7c6d5e4f3a2b",
    }
