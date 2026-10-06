# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cfn-lint scanner: severity mapping, argv, exit-code handling and opt-in defaults.

The SARIF these tests parse is real cfn-lint 1.57.1 output, captured from the fixture
repository under ``tests/test_data/scanners/cfn_lint_guard/repo`` with::

    cd tests/test_data/scanners/cfn_lint_guard/repo
    cfn-lint --format sarif -- templates/insecure.yaml \
        > ../captured/cfn-lint-1.57.1-insecure.sarif      # exit 6 (E|W)
    cfn-lint --format sarif -- templates/compliant.yaml \
        > ../captured/cfn-lint-1.57.1-compliant.sarif     # exit 0

Only the subprocess is faked, by writing those captured files to the ``--output-file``
cfn-lint was asked for; discovery, argv construction, parsing and the severity mapping
all run for real.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
    SEVERITY_BY_RULE_LETTER,
    CfnLintScanner,
    CfnLintScannerConfig,
    CfnLintScannerConfigOptions,
    _successful_exit,
    severity_for_rule,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

FIXTURES = (
    Path(__file__).resolve().parents[3] / "test_data" / "scanners" / "cfn_lint_guard"
)
CAPTURED_INSECURE = FIXTURES / "captured" / "cfn-lint-1.57.1-insecure.sarif"
CAPTURED_COMPLIANT = FIXTURES / "captured" / "cfn-lint-1.57.1-compliant.sarif"

#: What the captured insecure-template run must parse to: rule id, file, line,
#: ASH severity and SARIF level. Read off the template by hand, not off the parser.
EXPECTED_INSECURE = {
    ("W2001", "templates/insecure.yaml", 4, "LOW", "note"),
    ("E3002", "templates/insecure.yaml", 10, "MEDIUM", "warning"),
    ("E2533", "templates/insecure.yaml", 14, "MEDIUM", "warning"),
}


def _observed(report: SarifReport) -> set:
    out = set()
    for run in report.runs:
        for result in run.results or []:
            physical = result.locations[0].physicalLocation.root
            level = getattr(result.level, "value", result.level)
            out.add(
                (
                    result.ruleId,
                    physical.artifactLocation.uri,
                    physical.region.startLine,
                    result.properties.issue_severity,
                    level,
                )
            )
    return out


def _assert_parses_to(report: SarifReport, expected: set) -> None:
    observed = _observed(report)
    assert observed == expected, (
        f"missing {sorted(expected - observed)}, unexpected {sorted(observed - expected)}"
    )


def _load(path: Path) -> SarifReport:
    return SarifReport.model_validate(json.loads(path.read_text(encoding="utf-8")))


@pytest.fixture
def repo(ash_temp_path) -> Path:
    target = ash_temp_path / "repo"
    shutil.copytree(FIXTURES / "repo", target)
    return target


def _scanner(repo: Path, **options) -> CfnLintScanner:
    context = PluginContext(
        source_dir=repo,
        output_dir=repo / ".ash" / "ash_output",
        work_dir=repo / ".ash" / "ash_output" / "converted",
        config=get_default_config(),
    )
    scanner = CfnLintScanner(
        context=context,
        config=CfnLintScannerConfig(
            enabled=True, options=CfnLintScannerConfigOptions(**options)
        ),
    )
    return scanner


class FakeCfnLint:
    """Stands in for _run_subprocess: records argv and writes captured SARIF."""

    def __init__(self, captured_by_template: dict, returncode=6, extra=None):
        self.captured_by_template = captured_by_template
        self.returncode = returncode
        self.extra = extra or {}
        self.calls: list = []

    def __call__(self, command, **kwargs):
        self.calls.append(list(command))
        output = next(
            a.split("=", 1)[1] for a in command if a.startswith("--output-file=")
        )
        files = command[command.index("--") + 1 :]
        runs = []
        for name in files:
            source = self.captured_by_template.get(name)
            if source is not None:
                runs.extend(json.loads(Path(source).read_text())["runs"])
        # cfn-lint writes the file whenever it completes, findings or not (measured:
        # exit 0 on compliant.yaml still writes a 732-byte SARIF with no results).
        if self.returncode in (0, 2, 4, 6, 8, 10, 12, 14):
            merged = json.loads(CAPTURED_INSECURE.read_text())
            merged["runs"][0]["results"] = [
                r for run in runs for r in run.get("results", [])
            ]
            Path(output).write_text(json.dumps(merged), encoding="utf-8")
        response = {"stdout": "", "stderr": "", "returncode": self.returncode}
        response.update(self.extra)
        return response


class TestSeverityMapping:
    @pytest.mark.parametrize(
        "rule_id, expected",
        [
            ("E3002", ("MEDIUM", "warning")),
            ("W2001", ("LOW", "note")),
            ("I3011", ("INFO", "none")),
            ("e3002", ("MEDIUM", "warning")),
            # An unknown class fails a default scan rather than hiding under it.
            ("X9999", ("MEDIUM", "warning")),
            (None, ("MEDIUM", "warning")),
        ],
    )
    def test_rule_letter_mapping(self, rule_id, expected):
        assert severity_for_rule(rule_id) == expected

    def test_the_table_covers_exactly_the_three_cfn_lint_classes(self):
        assert set(SEVERITY_BY_RULE_LETTER) == {"E", "W", "I"}

    def test_captured_output_parses_to_the_expected_findings(self, repo):
        report = _scanner(repo).normalize_report(_load(CAPTURED_INSECURE))
        _assert_parses_to(report, EXPECTED_INSECURE)

    def test_compliant_template_has_no_findings(self, repo):
        report = _scanner(repo).normalize_report(_load(CAPTURED_COMPLIANT))
        assert _observed(report) == set()

    @pytest.mark.parametrize(
        "field, value",
        [
            ("ruleId", "E3003"),
            ("ruleId", "W3002"),  # same number, different class: severity must move
            ("startLine", 11),
            ("uri", "templates/compliant.yaml"),
        ],
    )
    def test_negative_control_a_mutated_finding_fails_the_assertion(
        self, repo, field, value
    ):
        """The assertion above bites: one changed field in one finding fails it."""
        raw = json.loads(CAPTURED_INSECURE.read_text())
        result = next(r for r in raw["runs"][0]["results"] if r["ruleId"] == "E3002")
        physical = result["locations"][0]["physicalLocation"]
        if field == "ruleId":
            result["ruleId"] = value
        elif field == "startLine":
            physical["region"]["startLine"] = value
        else:
            physical["artifactLocation"]["uri"] = value
        report = _scanner(repo).normalize_report(SarifReport.model_validate(raw))
        with pytest.raises(AssertionError):
            _assert_parses_to(report, EXPECTED_INSECURE)

    def test_driver_rules_are_sorted_for_reproducible_reports(self, repo):
        raw = json.loads(CAPTURED_INSECURE.read_text())
        rules = {r["id"]: r for r in raw["runs"][0]["tool"]["driver"]["rules"]}
        # Neither sorted nor reverse-sorted, so no accident of input order passes.
        raw["runs"][0]["tool"]["driver"]["rules"] = [
            rules["E3002"],
            rules["W2001"],
            rules["E2533"],
        ]
        report = _scanner(repo).normalize_report(SarifReport.model_validate(raw))
        ids = [r.id for r in report.runs[0].tool.driver.rules]
        assert ids == ["E2533", "E3002", "W2001"]


class TestExitCodes:
    @pytest.mark.parametrize("code", [0, 2, 4, 6, 8, 10, 12, 14])
    def test_level_bitmask_combinations_are_completed_runs(self, code):
        assert _successful_exit(code)

    @pytest.mark.parametrize("code", [1, 3, 16, 32, -9, None, "x"])
    def test_fatal_and_unknown_codes_are_failures(self, code):
        assert not _successful_exit(code)


class TestOptions:
    @pytest.mark.parametrize(
        "field, value",
        [
            ("regions", ["--update-specs"]),
            ("regions", ["us-east-1; rm -rf /"]),
            ("ignore_checks", ["--format=json"]),
            ("include_checks", ["E30 02"]),
        ],
    )
    def test_values_that_could_be_read_as_options_are_refused(self, field, value):
        with pytest.raises(ValidationError):
            CfnLintScannerConfigOptions(**{field: value})

    def test_valid_values_are_accepted(self):
        options = CfnLintScannerConfigOptions(
            regions=["us-east-1", "eu-west-2", "ALL_REGIONS"],
            ignore_checks=["W2001", "W3"],
            include_checks=["I"],
        )
        assert options.regions[-1] == "ALL_REGIONS"

    def test_default_version_constraint_has_a_floor_and_a_ceiling(self):
        constraint = CfnLintScannerConfigOptions().tool_version
        assert constraint == ">=1.43.3,<2.0.0"

    def test_missing_config_file_is_an_error_not_a_silent_default(self, repo):
        scanner = _scanner(repo, config_file="nope/.cfnlintrc")
        with pytest.raises(Exception, match="does not exist"):
            scanner._option_args(repo)

    def test_without_config_file_the_repository_cfnlintrc_is_not_read(self, repo):
        """A scanned repo's .cfnlintrc can load Python rules and disable checks."""
        (repo / ".cfnlintrc").write_text("ignore_checks: [E, W]\n")
        results = repo / "out"
        results.mkdir()
        args = _scanner(repo)._option_args(results)
        config_args = [a for a in args if a.startswith("--config-file=")]
        assert len(config_args) == 1
        named = Path(config_args[0].split("=", 1)[1])
        assert named == (results / "ash-empty.cfnlintrc").resolve()
        assert named.read_text() == "{}\n"

    @pytest.mark.skipif(
        __import__("sys").platform == "win32",
        reason="symlink creation needs privileges",
    )
    def test_the_empty_config_replaces_a_planted_symlink(self, repo):
        victim = repo / "victim.txt"
        victim.write_text("keep me\n")
        results = repo / "out"
        results.mkdir()
        (results / "ash-empty.cfnlintrc").symlink_to(victim)
        _scanner(repo)._option_args(results)
        assert victim.read_text() == "keep me\n"
        assert not (results / "ash-empty.cfnlintrc").is_symlink()


class TestOptIn:
    def test_scanner_is_opt_in_and_off_by_default(self):
        assert CfnLintScanner.OPT_IN is True
        assert CfnLintScannerConfig().enabled is False

    def test_sarif_extra_is_requested(self, repo):
        assert _scanner(repo)._get_tool_package_extras() == ["sarif"]


class TestBatching:
    def test_batches_respect_the_budget_and_keep_order(self):
        paths = [f"t/{i:03d}.yaml" for i in range(100)]
        batches = CfnLintScanner.batches(paths, budget=120)
        assert [p for b in batches for p in b] == paths
        assert all(sum(len(p) + 1 for p in b) <= 120 for b in batches)
        assert len(batches) > 1

    def test_an_oversized_path_gets_its_own_batch(self):
        long = "x" * 500
        assert CfnLintScanner.batches(["a", long, "b"], budget=100) == [
            ["a"],
            [long],
            ["b"],
        ]


class TestScan:
    def _run(self, scanner, fake):
        with (
            patch.object(
                CfnLintScanner, "validate_plugin_dependencies", return_value=True
            ),
            patch.object(CfnLintScanner, "_run_subprocess", side_effect=fake),
        ):
            return scanner.scan(
                target=Path(scanner.context.source_dir), target_type="source"
            )

    def test_scan_lints_exactly_the_cloudformation_templates(self, repo):
        fake = FakeCfnLint({"templates/insecure.yaml": CAPTURED_INSECURE})
        scanner = _scanner(repo)
        report = self._run(scanner, fake)
        assert len(fake.calls) == 1
        argv = fake.calls[0]
        files = argv[argv.index("--") + 1 :]
        # settings.yaml has no Resources and unparseable.yaml is not YAML; both are
        # skipped exactly as cfn-nag skips them.
        assert files == ["templates/compliant.yaml", "templates/insecure.yaml"]
        assert argv[:3] == ["cfn-lint", "--format", "sarif"]
        assert scanner.targets_attempted == 2 and scanner.targets_failed == 0
        _assert_parses_to(report, EXPECTED_INSECURE)

    def test_the_recorded_invocation_carries_no_host_path(self, repo):
        fake = FakeCfnLint({}, returncode=0)
        report = self._run(_scanner(repo), fake)
        recorded = report.runs[0].invocations[0].arguments
        assert "--config-file=ash-empty.cfnlintrc" in recorded
        assert not any(str(repo) in a for a in recorded), recorded
        # The tool itself still gets the absolute path.
        assert any(a.startswith("--config-file=/") or ":/" in a for a in fake.calls[0])

    def test_template_names_are_glob_escaped_and_cannot_be_options(self, repo):
        templates = repo / "templates"
        shutil.copy(templates / "compliant.yaml", templates / "g[1].yaml")
        shutil.copy(templates / "compliant.yaml", templates / "-dash.yaml")
        fake = FakeCfnLint({}, returncode=0)
        self._run(_scanner(repo), fake)
        argv = fake.calls[0]
        files = argv[argv.index("--") + 1 :]
        assert "templates/g[[]1].yaml" in files
        assert "templates/-dash.yaml" in files
        assert argv.index("--") < argv.index("templates/-dash.yaml")

    def test_config_options_reach_argv_as_single_tokens(self, repo):
        (repo / ".cfnlintrc").write_text("ignore_checks: []\n")
        fake = FakeCfnLint({}, returncode=0)
        self._run(
            _scanner(
                repo,
                config_file=".cfnlintrc",
                regions=["eu-west-1"],
                ignore_checks=["W2001"],
            ),
            fake,
        )
        argv = fake.calls[0]
        assert any(
            a.startswith("--config-file=") and a.endswith("/.cfnlintrc") for a in argv
        )
        assert argv[argv.index("--regions") + 1] == "eu-west-1"
        assert argv[argv.index("--ignore-checks") + 1] == "W2001"

    def test_a_fatal_exit_counts_every_template_in_the_batch_as_failed(self, repo):
        fake = FakeCfnLint({}, returncode=1)
        scanner = _scanner(repo)
        report = self._run(scanner, fake)
        assert scanner.targets_attempted == 2
        assert scanner.targets_failed == 2
        assert report.runs[0].results == []
        assert any("cfn-lint exited 1" in e for e in scanner.errors)

    def test_a_timeout_is_a_failed_batch(self, repo):
        fake = FakeCfnLint({}, returncode=-9, extra={"timed_out": True})
        scanner = _scanner(repo)
        self._run(scanner, fake)
        assert scanner.targets_failed == scanner.targets_attempted == 2
        assert any("timed out" in e for e in scanner.errors)

    def test_a_configuration_error_result_is_a_failure_not_a_finding(self, repo):
        raw = json.loads(CAPTURED_INSECURE.read_text())
        raw["runs"][0]["results"] = [
            {
                "ruleId": "E0003",
                "level": "error",
                "message": {
                    "text": "templates/x.yaml could not be processed by glob.glob"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uriBaseId": "EXECUTIONROOT"},
                            "region": {"startLine": 1, "startColumn": 1},
                        }
                    }
                ],
            }
        ]
        fake = FakeCfnLint({}, returncode=2)

        def writer(command, **kwargs):
            response = fake(command, **kwargs)
            output = next(
                a.split("=", 1)[1] for a in command if a.startswith("--output-file=")
            )
            Path(output).write_text(json.dumps(raw), encoding="utf-8")
            return response

        scanner = _scanner(repo)
        report = self._run(scanner, writer)
        assert report.runs[0].results == []
        assert scanner.targets_failed == 2
        assert any("configuration error" in e for e in scanner.errors)

    def test_a_cloudformation_file_the_model_rejects_is_a_failed_target(self, repo):
        (repo / "templates" / "custom.yaml").write_text(
            "Resources:\n  X:\n    Type: 'Not A Valid Type!'\n"
        )
        fake = FakeCfnLint({}, returncode=0)
        scanner = _scanner(repo)
        self._run(scanner, fake)
        assert scanner.targets_attempted == 3
        assert scanner.targets_failed == 1
        assert any("custom.yaml" in e for e in scanner.errors)

    def test_no_templates_attempts_nothing(self, ash_temp_path):
        empty = ash_temp_path / "empty"
        empty.mkdir()
        (empty / "readme.yaml").write_text("a: 1\n")
        fake = FakeCfnLint({})
        scanner = _scanner(empty)
        self._run(scanner, fake)
        assert fake.calls == []
        assert scanner.targets_attempted == 0

    def test_missing_dependencies_return_false_without_running(self, repo):
        scanner = _scanner(repo)
        with (
            patch.object(
                CfnLintScanner, "validate_plugin_dependencies", return_value=False
            ),
            patch.object(CfnLintScanner, "_run_subprocess") as run,
        ):
            assert scanner.scan(target=repo, target_type="source") is False
        run.assert_not_called()
