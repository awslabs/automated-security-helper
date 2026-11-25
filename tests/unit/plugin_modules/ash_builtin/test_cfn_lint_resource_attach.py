# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cfn-lint results name the CloudFormation resource they are in.

cfn-lint's SARIF carries the rule, the file and the span and no resource; its JSON
report carries ``Location.Path``, whose second element is the logical id when the
first is ``Resources`` (M0 item c). The captured pair
tests/test_data/scanners/cfn_lint_guard/captured/cfn-lint-1.57.2-m0-two-bad-properties.*
is one template run in both formats: two buckets with the same rejected property
(their findings differ only in the resource and the line) and a parameter with two
findings that are in no resource.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
    CfnLintScanner,
    attach_cfn_lint_resources,
    cfn_lint_resources,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "cfn_lint_guard"
    / "captured"
)
STEM = "cfn-lint-1.57.2-m0-two-bad-properties"


def _json() -> list:
    return json.loads((CAPTURED / f"{STEM}.json").read_text(encoding="utf-8"))


def _sarif() -> SarifReport:
    return SarifReport.model_validate(
        json.loads((CAPTURED / f"{STEM}.sarif").read_text(encoding="utf-8"))
    )


def _bag(result) -> dict:
    return result.properties.model_dump(exclude_none=True) if result.properties else {}


def _by_line(report: SarifReport) -> dict:
    return {
        result.locations[0].physicalLocation.root.region.startLine: _bag(result).get(
            "ash_resource_id"
        )
        for result in report.runs[0].results
    }


def test_the_captured_pair_names_the_two_buckets_and_nothing_for_the_parameter() -> (
    None
):
    report = _sarif()
    assert attach_cfn_lint_resources(report, cfn_lint_resources(_json())) == 2
    assert _by_line(report) == {
        8: None,  # W2001, in Parameters
        9: None,  # E2002, in Parameters
        14: "M0FixtureBucketA",
        18: "M0FixtureBucketB",
    }


def test_the_resource_survives_the_scanners_normalization() -> None:
    """The scan attaches per batch, then normalize_report relocates the results."""
    report = _sarif()
    attach_cfn_lint_resources(report, cfn_lint_resources(_json()))
    CfnLintScanner.normalize_report(None, report)  # type: ignore[arg-type]
    named = {
        _bag(r)["ash_resource_id"]
        for r in report.runs[0].results
        if "ash_resource_id" in _bag(r)
    }
    assert named == {"M0FixtureBucketA", "M0FixtureBucketB"}


def test_every_captured_finding_is_matched_to_a_result_key() -> None:
    """The two reports are spelled alike: no JSON finding is orphaned from its result."""
    keys = set(cfn_lint_resources(_json()))
    report = _sarif()
    seen = set()
    for result in report.runs[0].results:
        root = result.locations[0].physicalLocation.root
        region = root.region
        seen.add(
            (
                result.ruleId,
                root.artifactLocation.uri,
                region.startLine,
                region.startColumn,
                region.endLine,
                region.endColumn,
                result.message.root.text,
            )
        )
    assert seen == keys


def test_a_key_that_names_two_resources_names_neither() -> None:
    """Planted must-not-attach: two findings the report cannot tell apart."""
    document = _json()
    twin = json.loads(json.dumps(document[2]))
    twin["Location"]["Path"] = ["Resources", "SomeOtherBucket", "Properties", "X"]
    resources = cfn_lint_resources([*document, twin])
    report = _sarif()
    assert attach_cfn_lint_resources(report, resources) == 1
    assert _by_line(report)[14] is None
    assert _by_line(report)[18] == "M0FixtureBucketB"


@pytest.mark.parametrize("document", [None, {}, ["x"], [{"Rule": 1}], [{"Rule": {}}]])
def test_a_report_of_another_shape_lists_nothing(document) -> None:
    assert cfn_lint_resources(document) == {}


@pytest.mark.parametrize(
    "path",
    [
        ["Parameters", "P", "Type"],
        ["Outputs", "O"],
        ["Resources"],
        ["Resources", 3],
        ["Resources", ""],
        [],
        None,
    ],
)
def test_a_finding_outside_a_resource_is_recorded_as_none(path) -> None:
    entry = json.loads(json.dumps(_json()[2]))
    entry["Location"]["Path"] = path
    (named,) = cfn_lint_resources([entry]).values()
    assert named == {None}


# --------------------------------------------------------------------------
# The second run, end to end.
# --------------------------------------------------------------------------


@pytest.fixture
def scanner(test_plugin_context, tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
        CfnLintScannerConfig,
    )

    scanner = CfnLintScanner(context=test_plugin_context, config=CfnLintScannerConfig())
    scanner.exit_code = 0
    return scanner


def _attach(scanner, tmp_path, fake):
    report = _sarif()
    batch_file = tmp_path / "cfn-lint.0.sarif"
    with patch.object(CfnLintScanner, "_run_subprocess", autospec=True) as double:
        double.side_effect = fake
        scanner._attach_resources(
            report,
            ["/src/t.yaml"],
            batch_file,
            ["--regions", "us-east-1"],
            tmp_path,
            tmp_path,
            {},
        )
    return report, double


def test_the_second_run_names_the_resources_and_leaves_the_record_alone(
    scanner, tmp_path
) -> None:
    def fake(self, command=None, **kwargs):
        target = [a for a in command if a.startswith("--output-file=")][0]
        Path(target.split("=", 1)[1]).write_text(
            (CAPTURED / f"{STEM}.json").read_text(encoding="utf-8")
        )
        self.exit_code = 6  # cfn-lint's own finding bits
        self.errors.append("a stderr line of the side run")
        return {"returncode": 6}

    report, double = _attach(scanner, tmp_path, fake)
    assert _by_line(report)[14] == "M0FixtureBucketA"
    assert scanner.exit_code == 0
    assert "a stderr line of the side run" not in scanner.errors
    command = double.call_args.args[1]
    assert command[:3] == ["cfn-lint", "--format", "json"]
    assert "--regions" in command and command[-2:] == ["--", "/src/t.yaml"]
    assert not list(tmp_path.glob("*.resources.json")), "the file is removed"


def test_a_run_that_writes_no_report_names_nothing_and_fails_nothing(
    scanner, tmp_path
) -> None:
    def fake(self, command=None, **kwargs):
        self.exit_code = 32
        return {"returncode": 32}

    report, _ = _attach(scanner, tmp_path, fake)
    assert set(_by_line(report).values()) == {None}
    assert scanner.exit_code == 0


def test_an_unreadable_report_names_nothing(scanner, tmp_path, caplog) -> None:
    def fake(self, command=None, **kwargs):
        target = [a for a in command if a.startswith("--output-file=")][0]
        Path(target.split("=", 1)[1]).write_text("{ not json")
        return {"returncode": 0}

    with caplog.at_level(logging.DEBUG):
        report, _ = _attach(scanner, tmp_path, fake)
    assert set(_by_line(report).values()) == {None}


def test_a_clean_report_costs_no_second_run(scanner, tmp_path) -> None:
    report = SarifReport.model_validate(
        {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "cfn-lint"}}}]}
    )
    with patch.object(CfnLintScanner, "_run_subprocess", autospec=True) as double:
        scanner._attach_resources(
            report, ["/src/t.yaml"], tmp_path / "b.sarif", [], tmp_path, tmp_path, {}
        )
    double.assert_not_called()
