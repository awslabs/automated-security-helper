# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cfn-guard scanner: rule selection, result normalization, exit codes, opt-in defaults.

The SARIF parsed here is real cfn-guard 3.2.1 output against the registry's
``wa-Security-Pillar.guard`` (aws-guard-rules-registry 1.0.2), captured from the
fixture repository with the repository bind-mounted at ``/srv`` so no host path is
recorded in the file::

    unshare -rm sh -c 'mount --bind tests/test_data/scanners/cfn_lint_guard/repo /srv &&
      cfn-guard validate --rules=<rules>/wa-Security-Pillar.guard \
        --data=/srv/templates/insecure.yaml --output-format=sarif --structured \
        --show-summary=none' > captured/cfn-guard-3.2.1-wa-Security-Pillar-insecure.sarif
    # exit 19; the compliant template gives exit 0 and no results

That is also why the captured URIs read ``srv/templates/insecure.yaml``: cfn-guard
writes the absolute path minus its leading ``/``, which is what the scanner replaces.
"""

from __future__ import annotations

import collections
import json
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_guard_scanner import (
    DEFAULT_RULE_SET,
    VIOLATION_LEVEL,
    VIOLATION_SEVERITY,
    CfnGuardScanner,
    CfnGuardScannerConfig,
    CfnGuardScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils import rules_bundles
from automated_security_helper.utils.rules_bundles import (
    MANIFEST_NAME,
    RULES_DIR_ENV,
    RulesBundleUnavailable,
)
from automated_security_helper.utils.tool_downloads import get_rules_bundle

FIXTURES = (
    Path(__file__).resolve().parents[3] / "test_data" / "scanners" / "cfn_lint_guard"
)
CAPTURED_INSECURE = (
    FIXTURES / "captured" / "cfn-guard-3.2.1-wa-Security-Pillar-insecure.sarif"
)
CAPTURED_COMPLIANT = (
    FIXTURES / "captured" / "cfn-guard-3.2.1-wa-Security-Pillar-compliant.sarif"
)

#: The captured insecure run, as (rule id, start line) -> number of results: 24 in
#: all. Counted from the raw captured JSON with a separate ``json.load`` rather than
#: through the scanner. The S3 rules report on the bucket's Properties (line 9) and
#: LAMBDA_INSIDE_VPC on the function's (line 13). cfn-guard emits one result per
#: failing clause, which is why most rules appear more than once.
EXPECTED_INSECURE = collections.Counter(
    {
        ("LAMBDA_INSIDE_VPC", 13): 2,
        ("S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED", 9): 5,
        ("S3_BUCKET_LOGGING_ENABLED", 9): 1,
        ("S3_BUCKET_PUBLIC_READ_PROHIBITED", 9): 5,
        ("S3_BUCKET_PUBLIC_WRITE_PROHIBITED", 9): 5,
        ("S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED", 9): 2,
        ("S3_BUCKET_VERSIONING_ENABLED", 9): 2,
        ("S3_DEFAULT_ENCRYPTION_KMS", 9): 2,
    }
)


def _observed(results, uri="templates/insecure.yaml") -> collections.Counter:
    counts = collections.Counter()
    for result in results:
        physical = result.locations[0].physicalLocation.root
        assert physical.artifactLocation.uri == uri
        assert getattr(result.level, "value", result.level) == VIOLATION_LEVEL
        assert result.properties.issue_severity == VIOLATION_SEVERITY
        counts[(result.ruleId, physical.region.startLine)] += 1
    return counts


def _load(path: Path) -> SarifReport:
    return SarifReport.model_validate(json.loads(path.read_text(encoding="utf-8")))


def _fake_bundle(root: Path, names=("wa-Security-Pillar.guard", "custom-set.guard")):
    """An installed bundle under ``root`` whose manifest matches the real pin."""
    bundle = get_rules_bundle("aws-guard-rules-registry")
    directory = root / rules_bundles.bundle_dir_name(bundle)
    directory.mkdir(parents=True)
    files = {}
    for name in names:
        path = directory / name
        path.write_text(f"rule {name.split('.')[0].replace('-', '_')} {{ }}\n")
        files[name] = rules_bundles._sha256(path)
    (directory / MANIFEST_NAME).write_text(
        json.dumps(rules_bundles._manifest_for(bundle, files))
    )
    return directory


@pytest.fixture
def repo(ash_temp_path) -> Path:
    target = ash_temp_path / "repo"
    shutil.copytree(FIXTURES / "repo", target)
    return target


@pytest.fixture
def rules_root(ash_temp_path, monkeypatch) -> Path:
    root = ash_temp_path / "rules"
    monkeypatch.setenv(RULES_DIR_ENV, str(root))
    return root


def _scanner(repo: Path, **options) -> CfnGuardScanner:
    context = PluginContext(
        source_dir=repo,
        output_dir=repo / ".ash" / "ash_output",
        work_dir=repo / ".ash" / "ash_output" / "converted",
        config=get_default_config(),
    )
    return CfnGuardScanner(
        context=context,
        config=CfnGuardScannerConfig(
            enabled=True, options=CfnGuardScannerConfigOptions(**options)
        ),
    )


class TestNormalization:
    def test_captured_output_parses_to_the_expected_findings(self):
        results = CfnGuardScanner.normalize_results(
            _load(CAPTURED_INSECURE), "templates/insecure.yaml"
        )
        assert _observed(results) == EXPECTED_INSECURE

    def test_the_host_path_cfn_guard_writes_is_replaced(self):
        raw = CAPTURED_INSECURE.read_text()
        assert '"uri": "srv/templates/insecure.yaml"' in raw  # what cfn-guard wrote
        results = CfnGuardScanner.normalize_results(
            _load(CAPTURED_INSECURE), "templates/insecure.yaml"
        )
        assert {
            r.locations[0].physicalLocation.root.artifactLocation.uri for r in results
        } == {"templates/insecure.yaml"}

    def test_compliant_template_has_no_findings(self):
        assert CfnGuardScanner.normalize_results(_load(CAPTURED_COMPLIANT), "x") == []

    @pytest.mark.parametrize("field", ["ruleId", "startLine", "drop"])
    def test_negative_control_a_mutated_finding_fails_the_assertion(self, field):
        raw = json.loads(CAPTURED_INSECURE.read_text())
        results = raw["runs"][0]["results"]
        target = next(r for r in results if r["ruleId"] == "LAMBDA_INSIDE_VPC")
        if field == "ruleId":
            target["ruleId"] = "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED"
        elif field == "startLine":
            target["locations"][0]["physicalLocation"]["region"]["startLine"] = 14
        else:
            results.remove(target)
        normalized = CfnGuardScanner.normalize_results(
            SarifReport.model_validate(raw), "templates/insecure.yaml"
        )
        assert _observed(normalized) != EXPECTED_INSECURE


class TestParseResponse:
    def _stdout(self, path=CAPTURED_INSECURE):
        return path.read_text()

    def test_exit_19_with_results_is_a_completed_run(self):
        failure, report = CfnGuardScanner._parse_response(
            {"returncode": 19, "stdout": self._stdout(), "stderr": ""}
        )
        assert failure is None and report.runs[0].results

    def test_exit_0_with_no_results_is_a_completed_run(self):
        failure, report = CfnGuardScanner._parse_response(
            {"returncode": 0, "stdout": self._stdout(CAPTURED_COMPLIANT), "stderr": ""}
        )
        assert failure is None and not report.runs[0].results

    @pytest.mark.parametrize(
        "response, reason",
        [
            # Measured: an unparseable data file or a missing rules path.
            (
                {
                    "returncode": 255,
                    "stdout": "",
                    "stderr": "Error occurred Parser Error",
                },
                "exited 255: Error occurred Parser Error",
            ),
            ({"returncode": 19, "stdout": "", "stderr": ""}, "without writing SARIF"),
            ({"returncode": 0, "stdout": "{not json", "stderr": ""}, "not valid SARIF"),
            ({"returncode": -9, "timed_out": True}, "timed out"),
            ({"error": "No such file"}, "could not be started"),
        ],
    )
    def test_failures_are_named(self, response, reason):
        failure, report = CfnGuardScanner._parse_response(response)
        assert report is None and reason in failure

    def test_a_failing_exit_with_no_results_is_not_read_as_clean(self):
        failure, _ = CfnGuardScanner._parse_response(
            {"returncode": 19, "stdout": self._stdout(CAPTURED_COMPLIANT), "stderr": ""}
        )
        assert "no results" in failure


class TestRuleSelection:
    def test_default_rule_set_is_the_security_pillar(self):
        assert DEFAULT_RULE_SET == "wa-Security-Pillar"
        assert CfnGuardScannerConfigOptions().rule_sets == ["wa-Security-Pillar"]

    def test_default_resolves_to_the_verified_bundle_file(self, repo, rules_root):
        directory = _fake_bundle(rules_root)
        assert _scanner(repo).rule_files() == [directory / "wa-Security-Pillar.guard"]

    def test_missing_bundle_names_the_remedy(self, repo, rules_root):
        with pytest.raises(
            RulesBundleUnavailable, match="ash dependencies install --tool cfn-guard"
        ):
            _scanner(repo).rule_files()

    def test_an_unknown_rule_set_lists_what_is_available(self, repo, rules_root):
        _fake_bundle(rules_root)
        with pytest.raises(RulesBundleUnavailable, match="Available: custom-set.guard"):
            _scanner(repo, rule_sets=["no-such-set"]).rule_files()

    def test_a_modified_rules_file_is_refused(self, repo, rules_root):
        directory = _fake_bundle(rules_root)
        (directory / "wa-Security-Pillar.guard").write_text("rule weakened { }\n")
        with pytest.raises(RulesBundleUnavailable, match="no longer matches"):
            _scanner(repo).rule_files()

    def test_a_manifest_for_another_pin_is_refused(self, repo, rules_root):
        directory = _fake_bundle(rules_root)
        manifest = json.loads((directory / MANIFEST_NAME).read_text())
        manifest["sha256"] = "0" * 64
        (directory / MANIFEST_NAME).write_text(json.dumps(manifest))
        with pytest.raises(RulesBundleUnavailable, match="not the pinned"):
            _scanner(repo).rule_files()

    def test_own_rules_paths_are_resolved_against_the_source(self, repo, rules_root):
        (repo / "policy").mkdir()
        (repo / "policy" / "mine.guard").write_text("rule mine { }\n")
        scanner = _scanner(repo, rule_sets=[], rules_paths=["policy"])
        assert scanner.rule_files() == [repo / "policy"]

    def test_own_rules_paths_that_do_not_exist_are_refused(self, repo, rules_root):
        with pytest.raises(RulesBundleUnavailable, match="does not exist"):
            _scanner(repo, rule_sets=[], rules_paths=["policy"]).rule_files()

    def test_selecting_nothing_is_refused(self, repo, rules_root):
        with pytest.raises(
            RulesBundleUnavailable, match="no cfn-guard rules are selected"
        ):
            _scanner(repo, rule_sets=[]).rule_files()

    @pytest.mark.parametrize("name", ["wa-Security-Pillar.guard", "../x", "a/b", "-r"])
    def test_rule_set_names_must_be_bare_names(self, name):
        with pytest.raises(ValidationError):
            CfnGuardScannerConfigOptions(rule_sets=[name])


class TestDependencies:
    def test_missing_binary_is_missing_with_a_reason(self, repo, rules_root):
        _fake_bundle(rules_root)
        scanner = _scanner(repo)
        with patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners."
            "cfn_guard_scanner.find_executable",
            return_value=None,
        ):
            assert scanner.validate_plugin_dependencies() is False
        assert "cfn-guard is not on PATH" in scanner.dependency_unavailable_reason
        assert scanner.scan(target=repo, target_type="source") is False

    def test_missing_rules_are_missing_with_a_reason(self, repo, rules_root):
        scanner = _scanner(repo)
        with patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners."
            "cfn_guard_scanner.find_executable",
            return_value="/usr/local/bin/cfn-guard",
        ):
            assert scanner.validate_plugin_dependencies() is False
        assert "rules are not installed" in scanner.dependency_unavailable_reason
        assert scanner.dependency_unavailable_reason in scanner.errors

    def test_install_commands_install_the_binary_then_the_rules(self, repo):
        commands = _scanner(repo).custom_install_commands
        for target_platform in ("linux", "darwin", "windows"):
            for arch in ("amd64", "arm64"):
                steps = commands[target_platform][arch]
                assert len(steps) == 2
                assert "install_pinned_tool" in " ".join(steps[0].args)
                assert "cfn-guard" in steps[0].args
                assert "install_rules_bundle" in " ".join(steps[1].args)
                assert steps[1].args[-1] == "aws-guard-rules-registry"


class TestOptIn:
    def test_scanner_is_opt_in_and_off_by_default(self):
        assert CfnGuardScanner.OPT_IN is True
        assert CfnGuardScannerConfig().enabled is False


class TestScan:
    def _run(self, scanner, fake):
        with (
            patch.object(
                CfnGuardScanner, "validate_plugin_dependencies", return_value=True
            ),
            patch.object(CfnGuardScanner, "_run_subprocess", side_effect=fake),
        ):
            return scanner.scan(
                target=Path(scanner.context.source_dir), target_type="source"
            )

    def test_each_template_is_validated_once_with_the_selected_rules(
        self, repo, rules_root
    ):
        directory = _fake_bundle(rules_root)
        calls = []

        def fake(command, **kwargs):
            calls.append(command)
            data = next(a for a in command if a.startswith("--data="))
            insecure = data.endswith("/templates/insecure.yaml")
            source = CAPTURED_INSECURE if insecure else CAPTURED_COMPLIANT
            return {
                "returncode": 19 if insecure else 0,
                "stdout": source.read_text(),
                "stderr": "",
            }

        scanner = _scanner(repo)
        report = self._run(scanner, fake)
        assert len(calls) == 2
        for command in calls:
            assert command[:2] == ["cfn-guard", "validate"]
            assert (
                f"--rules={(directory / 'wa-Security-Pillar.guard').as_posix()}"
                in command
            )
            assert "--output-format=sarif" in command
            assert "--structured" in command and "--show-summary=none" in command
            data = next(a for a in command if a.startswith("--data="))
            assert Path(data.split("=", 1)[1]).is_absolute()
        assert scanner.targets_attempted == 2 and scanner.targets_failed == 0
        assert _observed(report.runs[0].results) == EXPECTED_INSECURE

    def test_one_failing_template_does_not_cost_the_others(self, repo, rules_root):
        _fake_bundle(rules_root)

        def fake(command, **kwargs):
            data = next(a for a in command if a.startswith("--data="))
            if data.endswith("/templates/compliant.yaml"):
                return {"returncode": 255, "stdout": "", "stderr": "Parser Error"}
            return {
                "returncode": 19,
                "stdout": CAPTURED_INSECURE.read_text(),
                "stderr": "",
            }

        scanner = _scanner(repo)
        report = self._run(scanner, fake)
        assert scanner.targets_attempted == 2
        assert scanner.targets_failed == 1
        assert any(
            "templates/compliant.yaml: cfn-guard exited 255" in e
            for e in scanner.errors
        )
        assert _observed(report.runs[0].results) == EXPECTED_INSECURE

    def test_rules_removed_between_validation_and_scan_raise(self, repo, rules_root):
        scanner = _scanner(repo)
        with (
            patch.object(
                CfnGuardScanner, "validate_plugin_dependencies", return_value=True
            ),
            pytest.raises(Exception, match="rules are not installed"),
        ):
            scanner.scan(target=repo, target_type="source")
