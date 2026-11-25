# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cfn-nag results name the CloudFormation resource they are about.

cfn_nag's SARIF writer renders one result per logical resource id and names that
id in ``locations[0].logicalLocations[0].name`` (captured with cfn-nag 0.8.10,
tests/test_data/scanners/cfn_nag/captured/cfn_nag-0.8.10-two-buckets.sarif: two
buckets with one finding give two results that differ only in that name and the
line). ``attach_cfn_nag_resources`` copies it under ``ash_resource_id``, the key a
resource-scoped suppression matches.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    attach_cfn_nag_resources,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.scanner_names import SCANNER_TOOL_TYPES

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "cfn_nag"
    / "captured"
)


def _load(name: str) -> SarifReport:
    return SarifReport.model_validate(
        json.loads((CAPTURED / name).read_text(encoding="utf-8"))
    )


def _bag(result) -> dict:
    return result.properties.model_dump(exclude_none=True) if result.properties else {}


def test_each_captured_result_gets_its_own_resource() -> None:
    report = _load("cfn_nag-0.8.10-two-buckets.sarif")
    results = report.runs[0].results
    assert results, "the capture holds results (a FATAL capture would hold none)"
    assert attach_cfn_nag_resources(report) == len(results)
    by_line = {}
    for result in results:
        region = result.locations[0].physicalLocation.root.region
        by_line.setdefault(region.startLine, set()).add(_bag(result)["ash_resource_id"])
    # one bucket per line, and the two lines name two different resources
    assert by_line == {8: {"M0FixtureBucketA"}, 12: {"M0FixtureBucketB"}}


def test_a_scan_writes_the_resource_of_each_result(tmp_path) -> None:
    """The adapter's own path: stdout in, resource-named results out."""
    from unittest.mock import patch

    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
        CfnNagScanner,
        CfnNagScannerConfig,
    )

    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True)
    template = (CAPTURED.parent / "m0_fixture_two_buckets.yaml").read_text()
    (context.work_dir / "m0_fixture_two_buckets.yaml").write_text(template)
    scanner = CfnNagScanner(context=context, config=CfnNagScannerConfig())
    stdout = (CAPTURED / "cfn_nag-0.8.10-two-buckets.sarif").read_text()
    with (
        patch.object(
            CfnNagScanner,
            "validate_plugin_dependencies",
            autospec=True,
            return_value=True,
        ),
        patch.object(CfnNagScanner, "_run_subprocess", autospec=True) as double,
    ):
        double.return_value = {"stdout": stdout, "stderr": "", "returncode": 0}
        report = scanner.scan(target=context.work_dir, target_type="converted")
    results = [r for run in report.runs for r in run.results]
    assert len(results) == 6
    by_line: dict = {}
    for result in results:
        line = result.locations[0].physicalLocation.root.region.startLine
        by_line.setdefault(line, set()).add(_bag(result).get("ash_resource_id"))
    # each id on the result of its own bucket: a swap would still pass a set check
    assert by_line == {8: {"M0FixtureBucketA"}, 12: {"M0FixtureBucketB"}}


def test_the_resource_reaches_the_flat_row() -> None:
    report = _load("cfn_nag-0.8.10-two-buckets.sarif")
    attach_cfn_nag_resources(report)
    flats = [
        FlatVulnerability.from_sarif_result(
            result, "cfn-nag", SCANNER_TOOL_TYPES["cfn-nag"], report.runs[0]
        )
        for result in report.runs[0].results
    ]
    assert {flat.resource_id for flat in flats} == {
        "M0FixtureBucketA",
        "M0FixtureBucketB",
    }


def test_a_fatal_capture_names_nothing() -> None:
    """The portable-ruby FATAL renders no result, so there is nothing to name."""
    report = _load("cfn_nag-0.8.10-fatal-psych-portable-ruby-3.3.8.sarif")
    assert attach_cfn_nag_resources(report) == 0


def _report_with(locations: list) -> SarifReport:
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "cfn_nag"}},
                    "results": [
                        {
                            "ruleId": "CFN_NAG_W51",
                            "message": {"text": "a finding"},
                            "locations": locations,
                        }
                    ],
                }
            ],
        }
    )


def _location(*names: str) -> dict:
    return {
        "physicalLocation": {"artifactLocation": {"uri": "t.yaml"}},
        "logicalLocations": [{"name": name} for name in names],
    }


@pytest.mark.parametrize(
    "locations",
    [
        [_location()],
        [_location("")],
        [_location("A", "B")],
        [_location("A"), _location("B")],
        [{"physicalLocation": {"artifactLocation": {"uri": "t.yaml"}}}],
    ],
    ids=["none", "blank", "two-in-one", "two-locations", "no-logical-key"],
)
def test_a_result_with_no_single_resource_gets_none(locations: list) -> None:
    """Planted must-not-attach: a wrong id binds a suppression to the wrong finding."""
    report = _report_with(locations)
    assert attach_cfn_nag_resources(report) == 0
    assert "ash_resource_id" not in _bag(report.runs[0].results[0])


def test_the_same_name_twice_is_still_one_resource() -> None:
    report = _report_with([_location("A"), _location("A")])
    assert attach_cfn_nag_resources(report) == 1
    assert _bag(report.runs[0].results[0])["ash_resource_id"] == "A"
