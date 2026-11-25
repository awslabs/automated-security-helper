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
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.core.cancellation import ScanCancelled
from automated_security_helper.core.exceptions import ScannerError
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
    # A scan whose own run left a non-zero exit code and an error line, so a side
    # run that reset the record to a clean one is told from one that left it alone.
    scanner.exit_code = 6
    scanner.errors = ["earlier line"]
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
    written: list[Path] = []

    def fake(self, command, **kwargs):
        target = Path(command[command.index("--output") + 1])
        written.append(target)
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
    assert scanner.exit_code == 6
    assert scanner.errors == ["earlier line"]
    assert "a stdout line of the side run" not in scanner.output
    assert getattr(scanner, "_scan_timed_out_after", None) is None
    # run once, as JSON, with only the misconfig scanner, and with no stdout read
    (call,) = double.call_args_list
    command = call.args[1]
    assert command[command.index("--format") + 1] == "json"
    assert "--scanners=misconfig" in command
    assert call.kwargs["stdout_preference"] == "none"
    (target,) = written
    assert not target.exists(), "the file is removed"


@pytest.mark.parametrize("returncode", [1, 2, 32])
def test_a_failed_second_run_names_nothing_and_fails_nothing(
    scanner, returncode
) -> None:
    written: list[Path] = []

    def fake(self, command, **kwargs):
        written.append(Path(command[command.index("--output") + 1]))
        self.exit_code = returncode
        return {"returncode": returncode}

    report, _ = _run_side(scanner, FINAL_ARGS, fake)
    assert all("ash_resource_id" not in _bag(r) for r in report.runs[0].results)
    assert scanner.exit_code == 6
    assert scanner.errors == ["earlier line"]
    assert len(written) == 1, "the second run was made, so the checks above measured it"


def test_a_non_zero_exit_with_a_complete_report_names_nothing(scanner) -> None:
    """Pinned: the report of a run that did not exit 0 is not read."""
    written: list[Path] = []

    def fake(self, command, **kwargs):
        target = Path(command[command.index("--output") + 1])
        written.append(target)
        target.write_text((CAPTURED / f"{STEM}.json").read_text(encoding="utf-8"))
        return {"returncode": 5}

    report, _ = _run_side(scanner, FINAL_ARGS, fake)
    assert all("ash_resource_id" not in _bag(r) for r in report.runs[0].results)
    assert not written[0].exists()


def test_an_unreadable_report_names_nothing_and_is_removed(scanner) -> None:
    written: list[Path] = []

    def fake(self, command, **kwargs):
        target = Path(command[command.index("--output") + 1])
        written.append(target)
        target.write_text("{ not json")
        return {"returncode": 0}

    report, _ = _run_side(scanner, FINAL_ARGS, fake)
    assert all("ash_resource_id" not in _bag(r) for r in report.runs[0].results)
    assert not written[0].exists()
    assert scanner.exit_code == 6


def test_no_second_run_without_a_resource_naming_type(scanner) -> None:
    """A scan with no Terraform misconfiguration does not pay for another run."""
    with patch.object(PluginBase, "_run_subprocess", autospec=True) as double:
        with patch.object(
            TrivyRepoScanner, "_effective_scanners", return_value=["misconfig"]
        ):
            report = _vulnerability_report("1.0")
            scanner._attach_misconfig_resources(report, FINAL_ARGS)
    double.assert_not_called()


@pytest.mark.parametrize("kind", ["cloudformation", "kubernetes"])
def test_no_second_run_for_a_misconfiguration_type_that_names_no_resource(
    scanner, kind
) -> None:
    """The case the type check decides: a misconfiguration, of a type that is not
    a resource address."""
    report = _sarif_for()
    report.runs[0].results[0].message.root.text = f"Artifact: main.tf\nType: {kind}"
    with patch.object(PluginBase, "_run_subprocess", autospec=True) as double:
        with patch.object(
            TrivyRepoScanner, "_effective_scanners", return_value=["misconfig"]
        ):
            scanner._attach_misconfig_resources(report, FINAL_ARGS)
    double.assert_not_called()
    # control: the same report with a Terraform type does start the run
    report.runs[0].results[0].message.root.text = "Artifact: main.tf\nType: terraform"
    with patch.object(PluginBase, "_run_subprocess", autospec=True) as double:
        double.return_value = {"returncode": 1}
        with patch.object(
            TrivyRepoScanner, "_effective_scanners", return_value=["misconfig"]
        ):
            scanner._attach_misconfig_resources(report, FINAL_ARGS)
    double.assert_called_once()


def test_no_second_run_offline(scanner) -> None:
    """Trivy's Terraform checks fetch module sources; offline mode exists to stop
    that, so the side run is not made."""
    with (
        patch.object(TrivyRepoScanner, "_offline", return_value=True),
        patch.object(
            TrivyRepoScanner, "_effective_scanners", return_value=["misconfig"]
        ),
        patch.object(PluginBase, "_run_subprocess", autospec=True) as double,
    ):
        scanner._attach_misconfig_resources(_captured_sarif(), FINAL_ARGS)
    double.assert_not_called()


def test_the_scanner_set_is_read_from_the_command_as_it_ran(scanner) -> None:
    """ASH can take misconfig out of the --scanners token while the option still
    names it; the command decides."""
    args = [*FINAL_ARGS[:2], "--scanners=vuln", *FINAL_ARGS[2:]]
    with (
        patch.object(
            TrivyRepoScanner, "_effective_scanners", return_value=["misconfig"]
        ),
        patch.object(PluginBase, "_run_subprocess", autospec=True) as double,
    ):
        scanner._attach_misconfig_resources(_captured_sarif(), args)
    double.assert_not_called()
    # control: the same token naming misconfig does run
    args = [*FINAL_ARGS[:2], "--scanners", "vuln,misconfig", *FINAL_ARGS[2:]]
    with (
        patch.object(TrivyRepoScanner, "_effective_scanners", return_value=["vuln"]),
        patch.object(PluginBase, "_run_subprocess", autospec=True) as double,
    ):
        double.return_value = {"returncode": 1}
        scanner._attach_misconfig_resources(_captured_sarif(), args)
    double.assert_called_once()


@pytest.mark.parametrize(
    "failure",
    [RuntimeError("boom"), ScannerError("refused")],
    ids=["runtime-error", "scanner-error"],
)
def test_a_second_run_that_raises_returns_the_report_unchanged(
    scanner, failure
) -> None:
    """The enrichment is best effort: whatever it raises leaves the report read."""

    def fake(self, command, **kwargs):
        raise failure

    report, _ = _run_side(scanner, FINAL_ARGS, fake)
    assert all("ash_resource_id" not in _bag(r) for r in report.runs[0].results)
    assert len(report.runs[0].results) == 8
    assert scanner.exit_code == 6


def test_a_cancellation_during_the_second_run_propagates(scanner) -> None:
    def fake(self, command, **kwargs):
        raise ScanCancelled("cancelled")

    with pytest.raises(ScanCancelled):
        _run_side(scanner, FINAL_ARGS, fake)


def test_a_failed_second_run_is_warned_about_once_with_its_exit_code(scanner) -> None:
    def fake(self, command, **kwargs):
        return {"returncode": 32}

    with patch.object(TrivyRepoScanner, "_plugin_log", autospec=True) as log:
        _run_side(scanner, FINAL_ARGS, fake)
        _run_side(scanner, FINAL_ARGS, fake)
    warnings = [
        call
        for call in log.call_args_list
        if call.kwargs.get("level") == logging.WARNING
    ]
    assert len(warnings) == 1
    assert "32" in warnings[0].args[1]


# --------------------------------------------------------------------------
# Ties between records the two reports cannot tell apart.
# --------------------------------------------------------------------------


def _sarif_with_messages(*messages: str, rule="AWS-0086", lines=(6, 8)) -> SarifReport:
    report = _sarif_for(rule=rule, lines=lines, count=len(messages))
    for result, message in zip(report.runs[0].results, messages):
        result.message.root.text = (
            f"Artifact: main.tf\nType: terraform\nVulnerability {rule}\n"
            f"Severity: HIGH\nMessage: {message}\nLink: [{rule}](https://avd)"
        )
    return report


def _json_with(*records: tuple[str, str]) -> dict:
    """One FAIL record per (resource, message) pair, on one check and range."""
    return {
        "Results": [
            {
                "Target": "main.tf",
                "Type": "terraform",
                "Misconfigurations": [
                    {
                        "ID": "AWS-0086",
                        "Status": "FAIL",
                        "Message": message,
                        "CauseMetadata": {
                            "Resource": resource,
                            "StartLine": 6,
                            "EndLine": 8,
                        },
                    }
                    for resource, message in records
                ],
            }
        ]
    }


def test_a_positive_control_on_the_synthetic_data() -> None:
    """The negatives above and below use these builders; this one must attach."""
    resources = trivy_misconfig_resources(_json_report("terraform", "aws_s3_bucket.a"))
    assert attach_trivy_resources(_sarif_for(), resources) == 1


def test_two_instances_of_one_check_on_one_range_attach_nothing() -> None:
    """A module used twice, or the instances of a count: same check, file, range
    and message, so no order can say whose is whose."""
    sarif = _sarif_with_messages("same", "same")
    resources = trivy_misconfig_resources(
        _json_with(
            ("module.b.aws_s3_bucket.x", "same"), ("module.a.aws_s3_bucket.x", "same")
        )
    )
    assert attach_trivy_resources(sarif, resources) == 0
    assert all("ash_resource_id" not in _bag(r) for r in sarif.runs[0].results)


def test_the_tie_attaches_nothing_whichever_order_the_second_run_lists_them() -> None:
    for order in (("a", "b"), ("b", "a")):
        sarif = _sarif_with_messages("same", "same")
        resources = trivy_misconfig_resources(
            _json_with(*((f"aws_s3_bucket.{name}[0]", "same") for name in order))
        )
        assert attach_trivy_resources(sarif, resources) == 0


def test_a_tie_that_names_one_resource_throughout_still_attaches() -> None:
    sarif = _sarif_with_messages("same", "same")
    resources = trivy_misconfig_resources(
        _json_with(("aws_s3_bucket.a", "same"), ("aws_s3_bucket.a", "same"))
    )
    assert attach_trivy_resources(sarif, resources) == 2


def test_records_that_say_different_things_are_told_apart_by_their_message() -> None:
    """Listed in the other order than the SARIF's, and still attached right."""
    sarif = _sarif_with_messages("first message", "second message")
    resources = trivy_misconfig_resources(
        _json_with(
            ("aws_s3_bucket.second", "second message"),
            ("aws_s3_bucket.first", "first message"),
        )
    )
    assert attach_trivy_resources(sarif, resources) == 2
    assert [_bag(r)["ash_resource_id"] for r in sarif.runs[0].results] == [
        "aws_s3_bucket.first",
        "aws_s3_bucket.second",
    ]


# --------------------------------------------------------------------------
# The message is the repository's text: only the verified Artifact line opens it.
# --------------------------------------------------------------------------


def _result_with(uri: str, text: str):
    report = _sarif_for()
    result = report.runs[0].results[0]
    result.locations[0].physicalLocation.root.artifactLocation.uri = uri
    result.message.root.text = text
    return result


def test_the_type_is_read_when_the_artifact_line_names_the_results_location() -> None:
    result = _result_with("main.tf", "Artifact: main.tf\nType: terraform\nx")
    assert TrivyScannerBase._misconfig_type(result) == "terraform"


def test_an_encoded_location_is_compared_decoded() -> None:
    result = _result_with("a%20b.tf", "Artifact: a b.tf\nType: terraform\nx")
    assert TrivyScannerBase._misconfig_type(result) == "terraform"


def test_a_file_name_with_a_line_break_cannot_write_the_type_line() -> None:
    """The name ``x`` + newline + ``Type: terraform`` makes trivy write a line the
    repository chose; the real type, cloudformation, comes a line later."""
    name = "x\nType: terraform"
    result = _result_with(
        "x%0AType%3A%20terraform",
        f"Artifact: {name}\nType: cloudformation\nVulnerability AWS-0086",
    )
    assert TrivyScannerBase._misconfig_type(result) is None


def test_a_message_whose_artifact_line_names_another_file_is_not_read() -> None:
    result = _result_with("main.tf", "Artifact: other.tf\nType: terraform\nx")
    assert TrivyScannerBase._misconfig_type(result) is None


def test_no_second_run_without_the_misconfig_scanner(scanner) -> None:
    with patch.object(PluginBase, "_run_subprocess", autospec=True) as double:
        with patch.object(
            TrivyRepoScanner, "_effective_scanners", return_value=["vuln"]
        ):
            scanner._attach_misconfig_resources(_captured_sarif(), FINAL_ARGS)
    double.assert_not_called()
