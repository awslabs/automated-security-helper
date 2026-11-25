# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""trivy: the resource of a Terraform misconfiguration, and the fixed version.

Two facts trivy's SARIF leaves in message prose or leaves out, read at the bytes
(trivy 0.76.2, the captured pair in tests/test_data/scanners/trivy/captured/):

* A vulnerability message carries ``Fixed Version: <versions>`` on its fifth line
  (empty when no fix is known). ``fix_available`` is written True for a non-empty
  value, and nothing otherwise.
* A misconfiguration's resource (``CauseMetadata.Resource``) is in trivy's JSON
  report and not in its SARIF. A desk run over four sample inputs read it as
  ``aws_s3_bucket.m0_fixture_bucket`` for Terraform, as the file-and-line
  locator ``t.yaml:3-4`` for CloudFormation, and not at all for Kubernetes and
  Dockerfile, so only Terraform's is written as a resource id.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.plugin_modules.ash_builtin.scanners._trivy_scanner_base import (
    TrivyScannerBase,
    _misconfig_report_command,
    attach_trivy_resources,
    trivy_misconfig_resources,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "trivy"
    / "captured"
)
STEM = "trivy-0.76.2-misconfig-terraform"


def _bag(result) -> dict:
    return result.properties.model_dump(exclude_none=True) if result.properties else {}


def _captured_sarif() -> SarifReport:
    return SarifReport.model_validate(
        json.loads((CAPTURED / f"{STEM}.sarif").read_text(encoding="utf-8"))
    )


def _captured_json() -> dict:
    return json.loads((CAPTURED / f"{STEM}.json").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# Fixed version.
# --------------------------------------------------------------------------

VULN = (
    "Package: lodash\nInstalled Version: 4.17.20\nVulnerability CVE-2021-23337\n"
    "Severity: HIGH\nFixed Version: {fixed}\nLink: [CVE-2021-23337](https://avd)"
)


@pytest.mark.parametrize(
    ("fixed", "expected"),
    [("4.17.21", "4.17.21"), ("4.17.21, 5.0.0", "4.17.21, 5.0.0"), ("", None)],
    ids=["one", "several", "empty"],
)
def test_the_fixed_version_is_read_from_the_vulnerability_message(
    fixed: str, expected: str | None
) -> None:
    message = VULN.format(fixed=fixed)
    assert TrivyScannerBase._fixed_version_from_message(message) == expected


@pytest.mark.parametrize(
    "message",
    [
        None,
        "",
        "Artifact: main.tf\nType: terraform\nVulnerability AWS-0086\nSeverity: HIGH",
        # a Fixed Version line that is not under a Package: first line is prose
        "Message: x\nPackage: a\nInstalled Version: 1\nFixed Version: 2\n",
    ],
    ids=["none", "empty", "misconfiguration", "package-line-not-first"],
)
def test_a_message_that_is_not_a_vulnerability_names_no_fix(message) -> None:
    assert TrivyScannerBase._fixed_version_from_message(message) is None


def _vulnerability_report(fixed: str) -> SarifReport:
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Trivy"}},
                    "results": [
                        {
                            "ruleId": "CVE-2021-23337",
                            "message": {"text": VULN.format(fixed=fixed)},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "package-lock.json"
                                        },
                                        "region": {"startLine": 5},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )


def test_a_known_fix_is_written_as_fix_available(mock_plugin_context, tmp_path) -> None:
    scanner = TrivyRepoScanner(context=mock_plugin_context)
    out = scanner._attach_package_identity(_vulnerability_report("4.17.21"), tmp_path)
    bag = _bag(out.runs[0].results[0])
    assert bag["fix_available"] is True
    assert bag["package_name"] == "lodash"


def test_an_empty_fixed_version_writes_no_fix_state(
    mock_plugin_context, tmp_path
) -> None:
    """Empty cannot say that no fix will ever exist, so nothing is attached."""
    scanner = TrivyRepoScanner(context=mock_plugin_context)
    out = scanner._attach_package_identity(_vulnerability_report(""), tmp_path)
    assert "fix_available" not in _bag(out.runs[0].results[0])


# --------------------------------------------------------------------------
# Misconfiguration resources.
# --------------------------------------------------------------------------


def test_the_captured_terraform_pair_names_the_resource_of_every_result() -> None:
    report = _captured_sarif()
    results = report.runs[0].results
    resources = trivy_misconfig_resources(_captured_json())
    assert attach_trivy_resources(report, resources) == len(results) == 8
    assert {_bag(r)["ash_resource_id"] for r in results} == {
        "aws_s3_bucket.m0_fixture_bucket"
    }


def _json_report(result_type: str, resource, *, rule="AWS-0086", lines=(6, 8)) -> dict:
    return {
        "Results": [
            {
                "Target": "main.tf",
                "Type": result_type,
                "Misconfigurations": [
                    {
                        "ID": rule,
                        "Status": "FAIL",
                        "CauseMetadata": {
                            "Resource": resource,
                            "StartLine": lines[0],
                            "EndLine": lines[1],
                        },
                    }
                ],
            }
        ]
    }


def _sarif_for(rule="AWS-0086", lines=(6, 8), count=1) -> SarifReport:
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Trivy"}},
                    "results": [
                        {
                            "ruleId": rule,
                            "message": {"text": "Artifact: main.tf\nType: terraform"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "main.tf"},
                                        "region": {
                                            "startLine": lines[0],
                                            "endLine": lines[1],
                                        },
                                    }
                                }
                            ],
                        }
                    ]
                    * count,
                }
            ],
        }
    )


@pytest.mark.parametrize(
    "result_type", ["cloudformation", "kubernetes", "dockerfile", "helm", None]
)
def test_a_type_whose_resource_is_not_a_resource_address_is_never_written(
    result_type,
) -> None:
    """Planted must-not-attach: ``t.yaml:3-4`` is a position, not a resource."""
    resources = trivy_misconfig_resources(_json_report(result_type, "t.yaml:3-4"))
    report = _sarif_for()
    assert attach_trivy_resources(report, resources) == 0
    assert "ash_resource_id" not in _bag(report.runs[0].results[0])


def test_terraform_with_no_resource_writes_nothing() -> None:
    resources = trivy_misconfig_resources(_json_report("terraform", None))
    assert attach_trivy_resources(_sarif_for(), resources) == 0


def test_a_count_mismatch_between_the_two_reports_writes_nothing() -> None:
    """One JSON record, two SARIF results under the key: whose is whose is unknown."""
    resources = trivy_misconfig_resources(_json_report("terraform", "aws_s3_bucket.a"))
    assert attach_trivy_resources(_sarif_for(count=2), resources) == 0


def test_only_failed_records_are_listed() -> None:
    report = _json_report("terraform", "aws_s3_bucket.a")
    report["Results"][0]["Misconfigurations"][0]["Status"] = "PASS"
    assert trivy_misconfig_resources(report) == {}


@pytest.mark.parametrize("document", [None, [], {"Results": None}, {"Results": ["x"]}])
def test_a_report_of_another_shape_lists_nothing(document) -> None:
    assert trivy_misconfig_resources(document) == {}


# --------------------------------------------------------------------------
# The second run's command.
# --------------------------------------------------------------------------


def test_the_json_command_swaps_format_output_and_scanners(tmp_path) -> None:
    out = tmp_path / "x.json"
    command = [
        "/bin/trivy",
        "fs",
        "--format",
        "sarif",
        "--output",
        "/r/results_sarif.sarif",
        "--scanners",
        "vuln,misconfig",
        "--cache-dir=/c",
        "/src",
    ]
    assert _misconfig_report_command(command, out) == [
        "/bin/trivy",
        "fs",
        "--format",
        "json",
        "--output",
        out.as_posix(),
        "--scanners",
        "misconfig",
        "--cache-dir=/c",
        "/src",
    ]


def test_the_json_command_handles_the_glued_spellings_and_adds_scanners(
    tmp_path,
) -> None:
    out = tmp_path / "x.json"
    command = ["/bin/trivy", "repository", "--format=sarif", "-o", "/r/a.sarif", "/src"]
    assert _misconfig_report_command(command, out) == [
        "/bin/trivy",
        "repository",
        "--scanners=misconfig",
        "--format=json",
        "-o",
        out.as_posix(),
        "/src",
    ]


@pytest.mark.parametrize(
    "command",
    [
        ["/bin/trivy", "fs", "/src"],
        ["/bin/trivy", "fs", "--format", "sarif", "/src"],
        ["/bin/trivy", "fs", "--output", "/r/a", "/src"],
        ["/bin/trivy", "fs", "--format"],
    ],
    ids=["neither", "no-output", "no-format", "dangling-format"],
)
def test_a_command_with_nothing_to_turn_runs_nothing(command, tmp_path) -> None:
    assert _misconfig_report_command(command, tmp_path / "x.json") is None


# --------------------------------------------------------------------------
# The second run, end to end, and what it leaves on the scan's record.
# --------------------------------------------------------------------------


@pytest.fixture
def scanner(mock_plugin_context, tmp_path):
    scanner = TrivyRepoScanner(context=mock_plugin_context)
    scanner.results_dir = tmp_path / "results"
    scanner.results_dir.mkdir()
    scanner.exit_code = 0
    return scanner


def _run_side(scanner, final_args, fake):
    with (
        patch.object(
            TrivyRepoScanner, "_effective_scanners", return_value=["vuln", "misconfig"]
        ),
        patch.object(PluginBase, "_run_subprocess", autospec=True) as double,
    ):
        double.side_effect = fake
        report = scanner._attach_misconfig_resources(_captured_sarif(), final_args)
    return report, double


FINAL_ARGS = [
    "/bin/trivy",
    "repository",
    "--format",
    "sarif",
    "--output",
    "/r/results_sarif.sarif",
    "/src",
]


def test_the_second_run_names_the_resources_and_leaves_the_record_alone(
    scanner,
) -> None:
    def fake(self, command, **kwargs):
        target = Path(command[command.index("--output") + 1])
        target.write_text((CAPTURED / f"{STEM}.json").read_text(encoding="utf-8"))
        # what the real recorders do to a scan that ran this command
        self.exit_code = 9
        self.errors.append("a stderr line of the side run")
        self.output.append("a stdout line of the side run")
        self._scan_timed_out_after = 1.0
        return {"returncode": 0}

    report, double = _run_side(scanner, FINAL_ARGS, fake)
    assert {_bag(r)["ash_resource_id"] for r in report.runs[0].results} == {
        "aws_s3_bucket.m0_fixture_bucket"
    }
    assert scanner.exit_code == 0
    assert "a stderr line of the side run" not in scanner.errors
    assert "a stdout line of the side run" not in scanner.output
    assert getattr(scanner, "_scan_timed_out_after", None) is None
    # run once, as JSON, with only the misconfig scanner, and with no stdout read
    (call,) = double.call_args_list
    command = call.args[1]
    assert command[command.index("--format") + 1] == "json"
    assert "--scanners=misconfig" in command
    assert call.kwargs["stdout_preference"] == "none"
    assert not list(scanner.results_dir.glob("*misconfig.json")), "the file is removed"


@pytest.mark.parametrize("returncode", [1, 2])
def test_a_failed_second_run_names_nothing_and_fails_nothing(
    scanner, returncode
) -> None:
    def fake(self, command, **kwargs):
        self.exit_code = returncode
        return {"returncode": returncode}

    report, _ = _run_side(scanner, FINAL_ARGS, fake)
    assert all("ash_resource_id" not in _bag(r) for r in report.runs[0].results)
    assert scanner.exit_code == 0


def test_no_second_run_without_a_resource_naming_type(scanner) -> None:
    """A scan with no Terraform misconfiguration does not pay for another run."""
    with patch.object(PluginBase, "_run_subprocess", autospec=True) as double:
        with patch.object(
            TrivyRepoScanner, "_effective_scanners", return_value=["misconfig"]
        ):
            report = _vulnerability_report("1.0")
            scanner._attach_misconfig_resources(report, FINAL_ARGS)
    double.assert_not_called()


def test_no_second_run_without_the_misconfig_scanner(scanner) -> None:
    with patch.object(PluginBase, "_run_subprocess", autospec=True) as double:
        with patch.object(
            TrivyRepoScanner, "_effective_scanners", return_value=["vuln"]
        ):
            scanner._attach_misconfig_resources(_captured_sarif(), FINAL_ARGS)
    double.assert_not_called()
