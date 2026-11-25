"""cfn-nag: the Psych FATAL and the captured SARIF, read from real tool output.

The fixtures under ``tests/test_data/scanners/cfn_nag/captured/`` are the output
of ``cfn_nag_scan`` 0.8.10 over ``m0_fixture_bucket.yaml`` (recapture in
``tests/test_data/scanners/M0-FINDINGS.md``, item b):

* on a Homebrew portable-ruby build the scan FATALs: exit 1, a SARIF document
  with 0 results, an empty stderr, and the explanation only in the JSON format;
* on a source-built Ruby it renders three results whose logical resource id is
  the structured SARIF field ``locations[0].logicalLocations[0].name``.

Pinned here: the FATAL is a failed, unevaluated target (fail-closed) that names
a way forward, and a working run is unchanged by the hint.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScanner,
    CfnNagScannerConfig,
)

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "cfn_nag"
    / "captured"
)
FATAL_STEM = "cfn_nag-0.8.10-fatal-psych-portable-ruby-3.3.8"
TEMPLATE = (CAPTURED.parent / "m0_fixture_bucket.yaml").read_text()


@pytest.fixture
def scanner(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True)
    (context.work_dir / "m0_fixture_bucket.yaml").write_text(TEMPLATE)
    return CfnNagScanner(context=context, config=CfnNagScannerConfig())


@pytest.fixture
def run_with(scanner):
    """Scan the one template with the tool's stdout, stderr and exit code faked."""

    def _run(stdout: str, stderr: str, returncode: int):
        with (
            patch.object(
                CfnNagScanner,
                "validate_plugin_dependencies",
                autospec=True,
                return_value=True,
            ),
            patch.object(CfnNagScanner, "_run_subprocess", autospec=True) as double,
        ):
            double.return_value = {
                "stdout": stdout,
                "stderr": stderr,
                "returncode": returncode,
            }
            return scanner.scan(
                target=scanner.context.work_dir, target_type="converted"
            )

    return _run


def test_the_captured_fatal_json_names_the_psych_failure():
    violations = json.loads((CAPTURED / f"{FATAL_STEM}.json").read_text())[0][
        "file_results"
    ]["violations"]
    assert [v["id"] for v in violations] == ["FATAL"]
    assert "Psych::Parser" in violations[0]["message"]
    assert violations[0]["logical_resource_ids"] == []


def test_the_captured_fatal_sarif_has_no_results_and_no_explanation():
    """The shape the adapter sees: nothing in SARIF says why the run failed."""
    sarif = json.loads((CAPTURED / f"{FATAL_STEM}.sarif").read_text())
    assert [len(run["results"]) for run in sarif["runs"]] == [0]
    assert "Psych" not in json.dumps(sarif)


def test_the_psych_fatal_is_a_failed_unevaluated_target_with_a_way_forward(
    scanner, run_with
):
    stdout = (CAPTURED / f"{FATAL_STEM}.sarif").read_text()

    report = run_with(stdout, "", 1)

    assert [r for run in report.runs for r in run.results] == []
    assert scanner.targets_attempted == 1
    assert scanner.targets_failed == 1
    assert scanner.unevaluated_targets, "the template is not recorded as unevaluated"
    reason = " ".join(scanner.errors)
    assert "no rule was evaluated against this template" in reason
    assert "--output-format json" in reason
    assert "Psych::Parser" in reason
    assert "portable-ruby" in reason


def test_a_working_run_is_unchanged_and_the_logical_id_is_a_sarif_field(
    scanner, run_with
):
    stdout = (CAPTURED / "cfn_nag-0.8.10-m0.sarif").read_text()

    report = run_with(stdout, "", 0)

    results = [r for run in report.runs for r in run.results]
    assert sorted(r.ruleId for r in results) == [
        "CFN_NAG_W35",
        "CFN_NAG_W41",
        "CFN_NAG_W51",
    ]
    assert scanner.targets_failed == 0
    assert not scanner.errors
    names = [[loc.name for loc in r.locations[0].logicalLocations] for r in results]
    assert names == [["M0FixtureBucket"]] * 3


def test_two_resources_give_one_sarif_result_per_id():
    """Question (b): SARIF is one result per id, JSON is one violation with a list."""
    sarif = json.loads((CAPTURED / "cfn_nag-0.8.10-two-buckets.sarif").read_text())
    ids = [
        [loc["name"] for loc in r["locations"][0]["logicalLocations"]]
        for r in sarif["runs"][0]["results"]
    ]
    assert len(ids) == 6
    assert all(len(one) == 1 for one in ids)
    assert {one[0] for one in ids} == {"M0FixtureBucketA", "M0FixtureBucketB"}
    violations = json.loads((CAPTURED / "cfn_nag-0.8.10-two-buckets.json").read_text())[
        0
    ]["file_results"]["violations"]
    assert all(
        v["logical_resource_ids"] == ["M0FixtureBucketA", "M0FixtureBucketB"]
        for v in violations
    )
