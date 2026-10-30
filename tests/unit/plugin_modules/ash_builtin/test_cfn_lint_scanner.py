# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cfn-lint scanner: severity mapping, argv, exit-code handling and defaults.

The SARIF these tests parse is real cfn-lint 1.57.1 output, captured from the fixture
repository under ``tests/test_data/scanners/cfn_lint_guard/repo`` with::

    cd tests/test_data/scanners/cfn_lint_guard/repo
    cfn-lint --format sarif -- templates/insecure.yaml \
        > ../captured/cfn-lint-1.57.1-insecure.sarif      # exit 6 (E|W)
    cfn-lint --format sarif -- templates/compliant.yaml \
        > ../captured/cfn-lint-1.57.1-compliant.sarif     # exit 0

cfn-lint 1.57.2, the release the image pins (its THIRD_PARTY_LICENSES entry), gives
the same results for both templates (rule ids, levels, messages and locations), and
the same exit codes; checked when the pin moved to 1.57.2.

Only the subprocess is faked, by writing those captured files to the ``--output-file``
cfn-lint was asked for; discovery, argv construction, parsing and the severity mapping
all run for real.
"""

from __future__ import annotations

import glob
import json
import os
import re
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
    SEVERITY_BY_RULE_LETTER,
    CfnLintScanner,
    CfnLintScannerConfig,
    CfnLintScannerConfigOptions,
    _successful_exit,
    severity_for_rule,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.tool_config_dir import TOOL_CONFIG_DIR_PREFIX

pytestmark = pytest.mark.unit


def _ashs_own(config: Path, repo: Path) -> bool:
    """Whether ``config`` is the empty config ASH writes for this run's cfn-lint.

    ``config/tool_config_trust.empty_tool_config`` writes it in a directory of the
    scanner run's own, outside the scanned tree.
    """
    return not config.resolve().is_relative_to(repo.resolve()) and any(
        parent.name.startswith(TOOL_CONFIG_DIR_PREFIX) for parent in config.parents
    )


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


def _scanner(
    repo: Path, *, operator: bool = False, overrides: tuple = (), **options
) -> CfnLintScanner:
    """A scanner whose config came from the scanned tree unless ``operator`` is set.

    ``operator=True`` records a config file outside the tree; ``overrides`` records
    --config-overrides keys.
    """
    config = get_default_config()
    # operator=True: built from no file in the scanned tree. Otherwise from the
    # tree's .ash/.ash.yaml, judged against the defaults plus ``overrides``.
    record_provenance(
        config,
        in_tree=[] if operator else [repo / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
        config_overrides=list(overrides),
    )
    context = PluginContext(
        source_dir=repo,
        output_dir=repo / ".ash" / "ash_output",
        work_dir=repo / ".ash" / "ash_output" / "converted",
        config=config,
    )
    scanner = CfnLintScanner(
        context=context,
        config=CfnLintScannerConfig(
            enabled=True, options=CfnLintScannerConfigOptions(**options)
        ),
    )
    return scanner


def _unescaped(argument: str) -> str:
    """A ``glob.escape``-d path as cfn-lint's ``glob.glob`` matches it."""
    return re.sub(r"\[(.)\]", r"\1", argument)


class FakeCfnLint:
    """Stands in for _run_subprocess: records argv and writes captured SARIF.

    ``captured_by_template`` is keyed by repository-relative template path. Each
    captured result is located at the path cfn-lint was given for that template,
    as cfn-lint locates it (measured with 1.57.2: an absolute argument gives an
    absolute URI).
    """

    def __init__(self, captured_by_template: dict, returncode=6, extra=None):
        self.captured_by_template = captured_by_template
        self.returncode = returncode
        self.extra = extra or {}
        self.calls: list = []
        self.cwds: list = []

    def __call__(self, command, **kwargs):
        self.calls.append(list(command))
        self.cwds.append(kwargs.get("cwd"))
        output = next(
            a.split("=", 1)[1] for a in command if a.startswith("--output-file=")
        )
        files = command[command.index("--") + 1 :]
        runs = []
        for argument in files:
            given = _unescaped(argument)
            for name, source in self.captured_by_template.items():
                if given == name or given.endswith("/" + name):
                    for run in json.loads(Path(source).read_text())["runs"]:
                        for result in run.get("results", []):
                            for location in result.get("locations", []):
                                artifact = location["physicalLocation"][
                                    "artifactLocation"
                                ]
                                artifact["uri"] = given
                        runs.append(run)
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

    def test_missing_config_file_is_an_error_not_a_silent_default(self, repo, tmp_path):
        # Outside the checkout: the repo fixture lives inside it.
        missing = tmp_path / "operator" / ".cfnlintrc"
        scanner = _scanner(repo, operator=True, config_file=str(missing))
        with pytest.raises(Exception, match="does not exist"):
            scanner._option_args()

    def test_without_config_file_the_repository_cfnlintrc_is_not_read(self, repo):
        """A scanned repo's .cfnlintrc can load Python rules and disable checks."""
        (repo / ".cfnlintrc").write_text("ignore_checks: [E, W]\n")
        args = _scanner(repo)._option_args()
        config_args = [a for a in args if a.startswith("--config-file=")]
        assert len(config_args) == 1
        named = Path(config_args[0].split("=", 1)[1])
        assert named.name == "ash-empty.cfnlintrc" and _ashs_own(named, repo)
        assert named.read_text() == "{}\n"

    @pytest.mark.skipif(
        __import__("sys").platform == "win32",
        reason="symlink creation needs privileges",
    )
    def test_a_link_where_the_empty_config_was_written_is_neither_followed_nor_used(
        self, repo
    ):
        """The results directory is inside the tree with the default output
        directory, so a link may already be at the name ASH used to write there."""
        kept = repo / "kept.txt"
        kept.write_text("keep me\n")
        results = repo / "out"
        results.mkdir()
        (results / "ash-empty.cfnlintrc").symlink_to(kept)
        (arg,) = [
            a for a in _scanner(repo)._option_args() if a.startswith("--config-file=")
        ]
        assert kept.read_text() == "keep me\n"
        assert _ashs_own(Path(arg.split("=", 1)[1]), repo)


class TestBuiltin:
    def test_scanner_is_on_by_default(self):
        assert CfnLintScannerConfig().enabled is True

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
        files = [_unescaped(a) for a in argv[argv.index("--") + 1 :]]
        # settings.yaml has no Resources and unparseable.yaml is not YAML; both are
        # skipped exactly as cfn-nag skips them.
        assert files == [
            (repo / "templates" / name).absolute().as_posix()
            for name in ("compliant.yaml", "insecure.yaml")
        ]
        assert argv[:3] == ["cfn-lint", "--format", "sarif"]
        assert scanner.targets_attempted == 2 and scanner.targets_failed == 0
        _assert_parses_to(report, EXPECTED_INSECURE)

    def test_no_location_refers_to_a_uri_base_the_report_does_not_define(self, repo):
        """cfn-lint tags every location with ``uriBaseId: EXECUTIONROOT``.

        Its own run declares that base (with a description and no uri), but ASH
        builds its own run and the merged ``ash.sarif`` never defines it, so the
        reference dangled. The URI is already relative to the source directory,
        where cfn-lint ran, which is what an ASH location without a base means.
        """
        captured = CAPTURED_INSECURE.read_text()
        assert captured.count('"uriBaseId": "EXECUTIONROOT"') == 3  # the control
        fake = FakeCfnLint({"templates/insecure.yaml": CAPTURED_INSECURE})
        report = self._run(_scanner(repo), fake)

        dumped = report.model_dump_json(exclude_none=True)
        assert "EXECUTIONROOT" not in dumped
        assert "uriBaseId" not in dumped
        _assert_parses_to(report, EXPECTED_INSECURE)

    def test_cfn_lint_runs_outside_the_scanned_tree_on_absolute_paths(self, repo):
        """cfn-lint resolves the relative paths in a config file (``append_rules``,
        ``custom_rules``, ``override_spec``) against its working directory, not
        against the file. Run in the source directory, an operator's
        ``append_rules: [rules]`` imported the scanned tree's ``rules/*.py``
        (measured with 1.57.2). So cfn-lint runs outside the tree, every path it
        is given is absolute, and its absolute URIs are reported
        repository-relative."""
        fake = FakeCfnLint({"templates/insecure.yaml": CAPTURED_INSECURE})
        report = self._run(_scanner(repo), fake)

        (cwd,) = fake.cwds
        assert cwd is not None, "cfn-lint ran in the source directory"
        assert not Path(cwd).absolute().is_relative_to(repo.absolute()), cwd
        argv = fake.calls[0]
        files = argv[argv.index("--") + 1 :]
        assert files and all(Path(_unescaped(f)).is_absolute() for f in files)
        for option in ("--output-file=", "--config-file="):
            (value,) = [a.split("=", 1)[1] for a in argv if a.startswith(option)]
            assert Path(value).is_absolute(), (option, value)
        _assert_parses_to(report, EXPECTED_INSECURE)

    def test_each_scan_runs_cfn_lint_in_a_new_empty_private_directory(self, repo):
        """From the filesystem root, a relative ``append_rules: [tmp/x]`` in the
        operator's .cfnlintrc named /tmp/x, which any local user can write to. So
        each scan runs cfn-lint in a directory of its own: new, empty, outside
        the scanned tree, only this user can enter it, and it is removed
        afterwards. A relative path then names nothing."""
        seen = []
        fake = FakeCfnLint({"templates/insecure.yaml": CAPTURED_INSECURE})

        def cfn_lint(command, **kwargs):
            cwd = Path(kwargs["cwd"])
            seen.append(
                (cwd, cwd.is_dir() and not any(cwd.iterdir()), cwd.stat().st_mode)
            )
            return fake(command, **kwargs)

        scanner = _scanner(repo)
        _assert_parses_to(self._run(scanner, cfn_lint), EXPECTED_INSECURE)
        self._run(scanner, cfn_lint)

        (first, first_empty, first_mode), (second, second_empty, _) = seen
        assert first != Path(first.anchor), "cfn-lint ran in the filesystem root"
        assert first_empty and second_empty
        assert first != second
        assert not first.absolute().is_relative_to(repo.absolute()), first
        if os.name != "nt":
            assert first_mode & 0o777 == 0o700, oct(first_mode)
        assert not first.exists() and not second.exists()

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
        templates_dir = glob.escape((repo / "templates").absolute().as_posix())
        assert f"{templates_dir}/g[[]1].yaml" in files
        assert f"{templates_dir}/-dash.yaml" in files
        assert argv.index("--") < argv.index(f"{templates_dir}/-dash.yaml")

    def test_config_options_reach_argv_as_single_tokens(self, repo, tmp_path):
        operator_rc = tmp_path / "operator" / ".cfnlintrc"
        operator_rc.parent.mkdir()
        operator_rc.write_text("ignore_checks: []\n")
        fake = FakeCfnLint({}, returncode=0)
        self._run(
            _scanner(
                repo,
                operator=True,
                config_file=str(operator_rc),
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

    def test_with_template_ignores_honored_each_template_gets_its_own_run(self, repo):
        """cfn-lint applies the last template's ignore_checks to the parse errors
        of the template it reads next. With template ignores honored no
        command-line list replaces them, so each template runs alone and its
        ignores reach only itself."""
        fake = FakeCfnLint({"templates/insecure.yaml": CAPTURED_INSECURE})
        scanner = _scanner(repo, operator=True, honor_inline_ignores=True)
        report = self._run(scanner, fake)
        files = [call[call.index("--") + 1 :] for call in fake.calls]
        assert [len(batch) for batch in files] == [1, 1], files
        assert scanner.targets_attempted == 2 and scanner.targets_failed == 0
        _assert_parses_to(report, EXPECTED_INSECURE)
        # By default the templates still share one run.
        default = FakeCfnLint({"templates/insecure.yaml": CAPTURED_INSECURE})
        self._run(_scanner(repo, operator=True), default)
        assert len(default.calls) == 1

    def test_with_template_ignores_honored_a_failed_run_costs_only_its_template(
        self, repo
    ):
        fake = FakeCfnLint({"templates/insecure.yaml": CAPTURED_INSECURE})

        def cfn_lint(command, **kwargs):
            if command[-1].endswith("/compliant.yaml"):
                return {"stdout": "", "stderr": "boom", "returncode": 1}
            return fake(command, **kwargs)

        scanner = _scanner(repo, operator=True, honor_inline_ignores=True)
        report = self._run(scanner, cfn_lint)
        assert scanner.targets_attempted == 2
        assert scanner.targets_failed == 1
        # The failure is recorded once, by the ERROR log line the base class appends
        # to self.errors; at an earlier tip a second, bare "<template>: <reason>"
        # line sat beside it, and this test looked for that exact element.
        recorded = [
            e
            for e in scanner.errors
            if "templates/compliant.yaml: cfn-lint exited 1: boom" in e
        ]
        assert len(recorded) == 1, scanner.errors
        assert not any("insecure.yaml" in e for e in scanner.errors), scanner.errors
        _assert_parses_to(report, EXPECTED_INSECURE)

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
        # No cfn-lint ran, so there is no exit code: None, as cfn-guard records it,
        # not the 0 an earlier tip's reset wrote and the executor read for a tool
        # that never ran.
        assert scanner.exit_code is None

    @pytest.mark.parametrize(
        "environment",
        [
            # What CI gets from `AWS_REGION: ${{ vars.UNSET }}`: set, but empty.
            {"AWS_REGION": ""},
            {"AWS_REGION": "af-south-1"},
            {"AWS_DEFAULT_REGION": "ap-southeast-4"},
        ],
    )
    def test_an_unset_regions_option_validates_against_us_east_1_whatever_the_host(
        self, repo, monkeypatch, environment
    ):
        """``regions: []`` means us-east-1, not whatever region the host is set to.

        cfn-lint 1.57.2 falls back to ``AWS_REGION``, then ``AWS_DEFAULT_REGION``,
        then us-east-1 when neither ``--regions``, the template's metadata nor a
        config file names a region (cfnlint/config.py, ``regions``). Measured:
        ``AWS_REGION=`` makes it exit 32, "Regions [''] are unsupported", for every
        template, and ``AWS_REGION=af-south-1`` reports an
        ``AWS::Bedrock::Agent`` as E3006, a resource type that region lacks.
        """
        for name in ("AWS_REGION", "AWS_DEFAULT_REGION"):
            monkeypatch.delenv(name, raising=False)
        for name, value in environment.items():
            monkeypatch.setenv(name, value)
        fake = FakeCfnLint({}, returncode=0)
        seen = []

        def cfn_lint(command, **kwargs):
            env = kwargs.get("env")
            child = dict(os.environ if env is None else env)
            if "--regions" in command:
                region = command[command.index("--regions") + 1]
            else:
                region = child.get(
                    "AWS_REGION", child.get("AWS_DEFAULT_REGION", "us-east-1")
                )
            seen.append(region)
            if region == "":
                return {
                    "stdout": "",
                    "stderr": "Regions [''] are unsupported.",
                    "returncode": 32,
                }
            return fake(command, **kwargs)

        scanner = _scanner(repo)
        self._run(scanner, cfn_lint)

        assert seen == ["us-east-1"]
        assert scanner.targets_failed == 0, scanner.errors
        # ASH's own environment is left as it was; only cfn-lint's is pinned.
        for name, value in environment.items():
            assert os.environ[name] == value

    def test_regions_set_by_the_operator_are_passed_as_given(self, repo, monkeypatch):
        monkeypatch.setenv("AWS_REGION", "af-south-1")
        fake = FakeCfnLint({}, returncode=0)
        self._run(
            _scanner(repo, operator=True, regions=["eu-west-1", "us-west-2"]), fake
        )
        argv = fake.calls[0]
        start = argv.index("--regions") + 1
        assert argv[start : start + 2] == ["eu-west-1", "us-west-2"]

    def test_regions_set_by_the_scanned_tree_are_not_passed(self, repo, monkeypatch):
        """--regions overrides a template's own regions and drops region-dependent
        findings, so it goes through the operator gate like ignore_checks."""
        monkeypatch.setenv("AWS_REGION", "af-south-1")
        fake = FakeCfnLint({}, returncode=0)
        self._run(_scanner(repo, regions=["eu-west-1", "us-west-2"]), fake)
        assert "--regions" not in fake.calls[0], fake.calls[0]

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


class TestTheScannedTreeCannotLoadRules:
    """A .cfnlintrc's append_rules makes cfn-lint import Python files as rules.

    ``config_file`` is honored only when the operator set it and it lies outside the
    scanned tree; anything else is ignored and ASH's empty configuration is passed.
    """

    @staticmethod
    def _plant(repo: Path) -> Path:
        rules = repo / "rules"
        rules.mkdir()
        (rules / "extra.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(repo / 'rules' / 'imported')!r}).touch()\n"
        )
        rc = repo / ".cfnlintrc"
        rc.write_text("append_rules:\n  - rules\n")
        return rc

    @staticmethod
    def _config_arg(scanner) -> str:
        (arg,) = [a for a in scanner._option_args() if a.startswith("--config-file=")]
        return arg

    @pytest.mark.parametrize("spelling", ["relative", "absolute"])
    def test_a_config_file_set_by_the_scanned_tree_is_ignored(
        self, repo, caplog, spelling
    ):
        rc = self._plant(repo)
        value = ".cfnlintrc" if spelling == "relative" else rc.as_posix()
        scanner = _scanner(repo, config_file=value)

        with caplog.at_level("WARNING"):
            arg = self._config_arg(scanner)

        assert arg.endswith("/ash-empty.cfnlintrc")
        assert "scanners.cfn-lint.options.config_file" in caplog.text

    def test_the_operator_cannot_name_a_config_file_inside_the_tree(self, repo):
        rc = self._plant(repo)
        scanner = _scanner(repo, operator=True, config_file=rc.as_posix())

        assert self._config_arg(scanner).endswith("/ash-empty.cfnlintrc")

    @pytest.mark.skipif(os.name == "nt", reason="symlinks")
    @pytest.mark.parametrize("shape", ["file", "directory"])
    def test_the_operator_cannot_name_a_path_in_the_tree_that_links_out_of_it(
        self, repo, tmp_path, caplog, shape
    ):
        """A path written in the tree goes where the tree's links send it, so the
        tree would choose which .cfnlintrc, and which append_rules, cfn-lint
        loads."""
        # tmp_path, not ash_temp_path: the repo fixture is inside this checkout.
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / ".cfnlintrc").write_text("append_rules:\n  - rules\n")
        if shape == "file":
            (repo / "ci").mkdir()
            (repo / "ci" / ".cfnlintrc").symlink_to(outside / ".cfnlintrc")
        else:
            (repo / "ci").symlink_to(outside, target_is_directory=True)
        scanner = _scanner(repo, operator=True, config_file="ci/.cfnlintrc")

        with caplog.at_level("WARNING"):
            arg = self._config_arg(scanner)

        assert arg.endswith("/ash-empty.cfnlintrc")
        assert "Ignoring scanners.cfn-lint.options.config_file" in caplog.text
        assert "symbolic link" in caplog.text

    def test_an_override_of_another_option_does_not_vouch_for_config_file(self, repo):
        rc = self._plant(repo)
        scanner = _scanner(
            repo,
            overrides=("scanners.cfn-lint.options.regions=[us-east-1]",),
            config_file=rc.as_posix(),
        )

        assert self._config_arg(scanner).endswith("/ash-empty.cfnlintrc")

    @pytest.mark.parametrize("key_spelling", ["cfn-lint", "cfn_lint"])
    def test_an_operator_override_outside_the_tree_is_used(
        self, repo, tmp_path, key_spelling
    ):
        operator_rc = tmp_path / "operator" / ".cfnlintrc"
        operator_rc.parent.mkdir()
        operator_rc.write_text("{}\n")
        scanner = _scanner(
            repo,
            overrides=(f"scanners.{key_spelling}.options.config_file={operator_rc}",),
            config_file=str(operator_rc),
        )

        arg = self._config_arg(scanner)

        assert arg == f"--config-file={operator_rc.resolve().as_posix()}"


class TestOptionsOnlyTheOperatorMaySet:
    """``ignore_checks`` drops findings before ASH sees them. Set by a config in the
    scanned tree (or an MCP client), it is ignored with a warning and its default is
    used, as ``config_file`` is. ``tool_version``, which chooses the cfn-lint release
    uv installs, is held to the operator's value when the config is resolved, as
    for every scanner (tests/unit/config/test_tool_version_is_the_operators.py)."""

    @staticmethod
    def _args(scanner, repo: Path) -> list:
        return scanner._option_args()

    def test_ignore_checks_from_the_scanned_tree_are_ignored(self, repo, caplog):
        scanner = _scanner(repo, ignore_checks=["E", "W"])
        with caplog.at_level("WARNING"):
            args = self._args(scanner, repo)
        # Only the placeholder that keeps a template's own list out (see
        # TestTemplateIgnoresAreOffByDefault).
        start = args.index("--ignore-checks") + 1
        assert args[start] == "W0000" and args[start + 1].startswith("--")
        assert "Ignoring scanners.cfn-lint.options.ignore_checks" in caplog.text

    @pytest.mark.parametrize("how", ["outside-config", "override"])
    def test_ignore_checks_set_by_the_operator_are_passed(self, repo, how):
        if how == "outside-config":
            scanner = _scanner(repo, operator=True, ignore_checks=["W2001"])
        else:
            scanner = _scanner(
                repo,
                overrides=("scanners.cfn-lint.options.ignore_checks=[W2001]",),
                ignore_checks=["W2001"],
            )
        args = self._args(scanner, repo)
        assert args[args.index("--ignore-checks") + 1] == "W2001"

    def test_the_scanner_reads_the_tool_version_it_is_given(self, repo):
        scanner = _scanner(repo, operator=True, tool_version="==1.57.2")
        assert scanner._get_tool_version_constraint() == "==1.57.2"
        assert all("==1.57.2" in c for c in scanner.uv_tool_install_commands)

    def test_each_refusal_is_logged_once_per_scanner(self, repo, caplog):
        with caplog.at_level("WARNING"):
            scanner = _scanner(repo, ignore_checks=["E"])
            for _ in range(3):
                self._args(scanner, repo)
        assert (
            caplog.text.count("Ignoring scanners.cfn-lint.options.ignore_checks") == 1
        )

    def test_a_tree_value_equal_to_the_default_is_not_warned_about(self, repo, caplog):
        with caplog.at_level("WARNING"):
            scanner = _scanner(repo, ignore_checks=[], tool_version=">=1.43.3,<2.0.0")
            self._args(scanner, repo)
        assert "Ignoring scanners.cfn-lint" not in caplog.text


def _mandatory(args: list) -> list:
    (value,) = [a.split("=", 1)[1] for a in args if a.startswith("--mandatory-checks=")]
    return value.split(",")


def _is_mandatory(rule_id: str, prefixes: list) -> bool:
    """cfn-lint's test (rules/_rule.py, ``_rule_is_enabled``): a prefix match."""
    return any(rule_id.startswith(prefix) for prefix in prefixes)


#: Rule ids to check coverage against: the built-in shape (a letter and four
#: digits), its neighbors around the ignored ones, and ids a custom rule could have.
_SAMPLE_IDS = [
    *(f"{letter}{n:04d}" for letter in "EWI" for n in range(0, 10000, 37)),
    "E0000",
    "E0003",
    "E3002",
    "E2533",
    "W2001",
    "W2000",
    "W2002",
    "W20010",
    "W200",
    "W3",
    "W",
    "I3011",
    "X9999",
    "e3002",
    "Custom1",
    "E9001",
]


class TestTemplateIgnoresAreOffByDefault:
    """A template's ``Metadata: cfn-lint: config: ignore_checks``, at the template or
    the resource level, drops findings before ASH sees them (measured with 1.57.2:
    ``[E, W]`` at the template level turned the fixture's 3 findings into 0). cfn-lint
    applies neither to a rule named in ``--mandatory-checks``, which also overrides
    ``--ignore-checks``, so ASH passes every rule id outside the operator's own
    ignores as mandatory."""

    @staticmethod
    def _args(scanner, repo: Path) -> list:
        return scanner._option_args()

    def test_with_no_ignores_every_rule_is_mandatory(self, repo):
        mandatory = _mandatory(self._args(_scanner(repo), repo))
        assert all(_is_mandatory(rule, mandatory) for rule in _SAMPLE_IDS)

    def test_with_no_ignores_a_placeholder_keeps_a_templates_list_out(self, repo):
        """cfn-lint reads the next template with the last decoded template's
        Metadata config still set, and drops its E0000 when that config's
        ignore_checks name E0000, without consulting --mandatory-checks (measured
        with 1.43.3 and 1.57.2). A command-line --ignore-checks replaces a
        template's list, so ASH always passes one: W0000 when there is nothing to
        ignore. It is not a prefix of E0000, and every rule is mandatory, so it
        ignores nothing."""
        args = self._args(_scanner(repo), repo)
        start = args.index("--ignore-checks") + 1
        assert args[start] == "W0000" and args[start + 1].startswith("--")
        assert not "E0000".startswith("W0000")
        mandatory = _mandatory(args)
        assert all(_is_mandatory(rule, mandatory) for rule in _SAMPLE_IDS)

    def test_the_placeholder_is_left_out_when_the_operator_ignores_something(
        self, repo
    ):
        args = self._args(_scanner(repo, operator=True, ignore_checks=["W2001"]), repo)
        start = args.index("--ignore-checks") + 1
        assert args[start] == "W2001" and args[start + 1].startswith("--")

    def test_with_template_ignores_on_no_placeholder_is_passed(self, repo):
        """It would replace the template-level ignore_checks the operator let in."""
        scanner = _scanner(repo, operator=True, honor_inline_ignores=True)
        assert "--ignore-checks" not in self._args(scanner, repo)

    @pytest.mark.parametrize(
        "ignores", [["W2001"], ["W"], ["W2001", "E30", "I"], ["W200", "W2001"]]
    )
    def test_exactly_the_operators_ignores_are_left_out(self, repo, ignores):
        scanner = _scanner(repo, operator=True, ignore_checks=ignores)
        args = self._args(scanner, repo)
        mandatory = _mandatory(args)
        for rule in _SAMPLE_IDS:
            if any(prefix != rule and prefix.startswith(rule) for prefix in ignores):
                # An id shorter than an ignored prefix it begins (W for an ignored
                # W2001) cannot be mandatory: every prefix of it is a prefix of
                # W2001 too. No built-in id is: they are all five characters.
                continue
            ignored = any(rule.startswith(prefix) for prefix in ignores)
            assert _is_mandatory(rule, mandatory) is not ignored, rule
        start = args.index("--ignore-checks") + 1
        assert args[start : start + len(ignores)] == ignores

    def test_the_operators_config_file_ignores_are_left_out_too(self, repo, tmp_path):
        """And passed as --ignore-checks, which cfn-lint ranks above a template's
        own ignore_checks, so they apply whatever the template says."""
        rc = tmp_path / "operator" / ".cfnlintrc"
        rc.parent.mkdir()
        rc.write_text("ignore_checks:\n  - W2001\n  - --update-specs\n")
        scanner = _scanner(repo, operator=True, config_file=str(rc))
        args = self._args(scanner, repo)
        mandatory = _mandatory(args)
        assert not _is_mandatory("W2001", mandatory)
        assert _is_mandatory("W2002", mandatory) and _is_mandatory("E3002", mandatory)
        start = args.index("--ignore-checks") + 1
        assert args[start] == "W2001"
        # A value that could be read as an option never reaches argv.
        assert "--update-specs" not in args

    def test_the_operator_can_turn_template_ignores_back_on(self, repo):
        scanner = _scanner(
            repo, operator=True, honor_inline_ignores=True, ignore_checks=["W2001"]
        )
        args = self._args(scanner, repo)
        assert not any(a.startswith("--mandatory-checks") for a in args)
        assert args[args.index("--ignore-checks") + 1] == "W2001"

    def test_the_scanned_tree_cannot_turn_them_back_on(self, repo, caplog):
        scanner = _scanner(repo, honor_inline_ignores=True)
        with caplog.at_level("WARNING"):
            args = self._args(scanner, repo)
            self._args(scanner, repo)
        assert all(_is_mandatory(rule, _mandatory(args)) for rule in _SAMPLE_IDS)
        assert caplog.text.count("scanners.cfn-lint.options.honor_inline_ignores") == 1

    def test_an_ignore_list_too_long_to_pass_is_refused_not_truncated(self, repo):
        """Prefixes that share nothing past their first letter grow the list most:
        each adds about 244 entries. 26 of them need about 28000 characters."""
        many = [
            f"{chr(ord('A') + i)}{i % 10}{i * 3 % 10}{i * 7 % 10}{i * 9 % 10}"
            for i in range(26)
        ]
        scanner = _scanner(repo, operator=True, ignore_checks=many)
        with pytest.raises(Exception, match="ignore_checks names too many rule ids"):
            self._args(scanner, repo)
        # The same list with template ignores honored passes no mandatory list.
        honored = _scanner(
            repo, operator=True, ignore_checks=many, honor_inline_ignores=True
        )
        assert not any(
            a.startswith("--mandatory-checks") for a in self._args(honored, repo)
        )

    def test_the_mandatory_list_shrinks_the_template_batches(self, repo):
        """cfn-lint is given at most _ARGV_CHAR_BUDGET characters of options and
        templates together, so a long ignore list means smaller batches."""
        fake = FakeCfnLint({}, returncode=0)
        many = [f"W{n}" for n in range(1000, 1012)]
        scanner = _scanner(repo, operator=True, ignore_checks=many)
        TestScan()._run(scanner, fake)
        for argv in fake.calls:
            assert sum(len(a) + 1 for a in argv[1:]) <= 24000


def _configured(args: list) -> list:
    return [a.split("=", 1)[1] for a in args if a.startswith("--configure-rule=")]


class TestTemplateRuleConfigurationIsOffByDefault:
    """A template's ``Metadata: cfn-lint: config: configure_rules`` changes what
    cfn-lint reports: E3031 ``exceptions`` and E1029 ``custom_excludes`` turned a
    template's E3031, E1029 and E1161 into E1161 alone (measured with 1.57.2 and,
    without E1161, 1.43.3). --mandatory-checks does not stop it. cfn-lint takes
    configure_rules from the first of the command line, the template and the config
    file that sets any, whole: one ``--configure-rule`` replaces both the template's
    and the config file's. So unless the operator turns template ignores on, ASH
    passes the operator's own configure_rules on the command line, or a value that
    changes nothing when there are none."""

    @staticmethod
    def _args(scanner, repo: Path) -> list:
        return scanner._option_args()

    @staticmethod
    def _rc(tmp_path: Path, text: str) -> Path:
        rc = tmp_path / "operator" / ".cfnlintrc"
        rc.parent.mkdir(exist_ok=True)
        rc.write_text(text, encoding="utf-8")
        return rc

    def test_without_operator_configure_rules_a_no_op_is_passed(self, repo):
        """E3012 ``strict`` is false by default; setting it to false changes no
        finding (measured on the fixture templates with 1.57.2) and keeps the
        template's configure_rules from applying."""
        assert _configured(self._args(_scanner(repo), repo)) == ["E3012:strict=false"]

    def test_an_operator_config_file_without_configure_rules_gets_the_no_op(
        self, repo, tmp_path
    ):
        rc = self._rc(tmp_path, "ignore_checks: [W2001]\n")
        scanner = _scanner(repo, operator=True, config_file=str(rc))
        assert _configured(self._args(scanner, repo)) == ["E3012:strict=false"]

    def test_the_operators_configure_rules_are_passed_on_the_command_line(
        self, repo, tmp_path
    ):
        rc = self._rc(
            tmp_path,
            "configure_rules:\n"
            "  E3031:\n    exceptions: ['Bad_.*']\n"
            "  E1029:\n    custom_excludes: '^Stage$'\n"
            "  I3042:\n    partition: false\n    region: true\n"
            "  E9001:\n    limit: 3\n",
        )
        scanner = _scanner(repo, operator=True, config_file=str(rc))
        assert _configured(self._args(scanner, repo)) == [
            "E3031:exceptions=Bad_.*",
            "E1029:custom_excludes=^Stage$",
            "I3042:partition=false",
            "I3042:region=true",
            "E9001:limit=3",
        ]

    @pytest.mark.parametrize(
        "rule, value",
        [
            # --configure-rule takes one value per key and splits on these.
            ("E3031:\n    exceptions: ['^a$', '^b$']", "two items"),
            ("E3031:\n    exceptions: ['^arn:aws:.*']", "a colon"),
            ("E1029:\n    custom_excludes: 'a{1,3}'", "a comma"),
            ("E1029:\n    custom_excludes: 'a=b'", "an equals sign"),
            ("E3031:\n    exceptions: []", "no items"),
            ("E3031:\n    exceptions: [{a: 1}]", "a mapping"),
            ("'--x':\n    exceptions: a", "a rule id that is not one"),
            ("E3031:\n    'a,b': c", "a key that is not one"),
        ],
    )
    def test_a_value_the_command_line_cannot_carry_is_left_out_with_a_warning(
        self, repo, tmp_path, caplog, rule, value
    ):
        """The rule then uses its default, which for every built-in rule reports
        at least as much. Nothing is passed that cfn-lint would read differently
        from the file."""
        rc = self._rc(
            tmp_path,
            f"configure_rules:\n  {rule}\n  I3042:\n    partition: false\n",
        )
        scanner = _scanner(repo, operator=True, config_file=str(rc))
        with caplog.at_level("WARNING"):
            configured = _configured(self._args(scanner, repo))
            self._args(scanner, repo)
        assert configured == ["I3042:partition=false"], value
        assert caplog.text.count("Not passing configure_rules") == 1, caplog.text

    def test_with_nothing_left_the_no_op_is_passed(self, repo, tmp_path):
        rc = self._rc(
            tmp_path, "configure_rules:\n  E3031:\n    exceptions: ['^a:b$']\n"
        )
        scanner = _scanner(repo, operator=True, config_file=str(rc))
        assert _configured(self._args(scanner, repo)) == ["E3012:strict=false"]

    def test_merge_configs_in_the_operators_file_is_refused(self, repo, tmp_path):
        """Under merge_configs cfn-lint merges the template's configure_rules into
        the command line's, rule by rule (measured: the template's E3031 and E1029
        settings applied again), so no command-line value can keep them out."""
        rc = self._rc(tmp_path, "merge_configs: true\n")
        scanner = _scanner(repo, operator=True, config_file=str(rc))
        with pytest.raises(Exception, match="merge_configs"):
            self._args(scanner, repo)
        # With template configuration honored, the file is used as written.
        honored = _scanner(
            repo, operator=True, config_file=str(rc), honor_inline_ignores=True
        )
        assert _configured(self._args(honored, repo)) == []

    def test_an_operators_file_that_uses_an_alias_is_refused(self, repo, tmp_path):
        """ASH reads the operator's file with YAML aliases refused, as it reads
        every YAML config. cfn-lint reads aliases, so a file ASH could not read
        could still set merge_configs or ignore_checks ASH never saw; the scan
        stops instead of running cfn-lint with it."""
        rc = self._rc(
            tmp_path,
            "x-strict: &strict\n  strict: false\nconfigure_rules:\n  E3012: *strict\n",
        )
        scanner = _scanner(repo, operator=True, config_file=str(rc))
        with pytest.raises(ScannerError, match="alias") as raised:
            self._args(scanner, repo)
        assert rc.as_posix() in str(raised.value)
        # With template configuration honored, ASH does not read the file.
        honored = _scanner(
            repo, operator=True, config_file=str(rc), honor_inline_ignores=True
        )
        assert _configured(self._args(honored, repo)) == []

    def test_the_operator_can_let_templates_configure_rules(self, repo, tmp_path):
        rc = self._rc(
            tmp_path, "configure_rules:\n  E3031:\n    exceptions: ['Bad_.*']\n"
        )
        scanner = _scanner(
            repo, operator=True, config_file=str(rc), honor_inline_ignores=True
        )
        # cfn-lint reads the config file as written, the template's settings first.
        assert _configured(self._args(scanner, repo)) == []

    def test_the_scanned_tree_cannot_let_them(self, repo):
        scanner = _scanner(repo, honor_inline_ignores=True)
        assert _configured(self._args(scanner, repo)) == ["E3012:strict=false"]

    def test_each_value_reaches_argv_as_one_token(self, repo, tmp_path):
        rc = self._rc(
            tmp_path, "configure_rules:\n  E1029:\n    custom_excludes: ' -x --y'\n"
        )
        fake = FakeCfnLint({}, returncode=0)
        TestScan()._run(_scanner(repo, operator=True, config_file=str(rc)), fake)
        argv = fake.calls[0]
        assert "--configure-rule=E1029:custom_excludes= -x --y" in argv
        assert argv.index("--configure-rule=E1029:custom_excludes= -x --y") < (
            argv.index("--")
        )


class TestToolVersionIsOnlyAVersionConstraint:
    """tool_version is appended to the package name for uv; it must stay a constraint."""

    @pytest.mark.parametrize(
        "value",
        [
            " @ file:///tmp/other",
            "@ git+https://example.invalid/other.git",
            "[extra]>=1",
            ">=1; sys_platform != 'x'",
            ">=1 --index-url https://example.invalid",
            "1.57.2",
        ],
    )
    def test_a_value_that_is_not_a_specifier_set_is_replaced_by_the_default(
        self, value
    ):
        """As for every uv-installed tool (tests/unit/config/test_tool_version_is_a_version_specifier.py)."""
        default = CfnLintScannerConfigOptions().tool_version
        assert CfnLintScannerConfigOptions(tool_version=value).tool_version == default

    @pytest.mark.parametrize(
        "value", [">=1.43.3,<2.0.0", "==1.57.2", "~=1.57", "==1.*", None, ""]
    )
    def test_specifier_sets_are_accepted(self, value):
        assert CfnLintScannerConfigOptions(tool_version=value).tool_version == value


def test_an_outside_cfnlintrc_set_by_the_scanned_tree_is_ignored(repo, tmp_path):
    """The operator rule on its own: outside the tree, but the tree's config chose it."""
    outside = tmp_path / "elsewhere" / ".cfnlintrc"
    outside.parent.mkdir()
    outside.write_text("{}\n")
    scanner = _scanner(repo, config_file=str(outside))

    (arg,) = [a for a in scanner._option_args() if a.startswith("--config-file=")]

    assert arg.endswith("/ash-empty.cfnlintrc")


def test_each_target_starts_from_a_clean_exit_code(repo, monkeypatch):
    """ScannerExecutor runs one instance over the source, then the converted target.

    The base class keeps the worst exit code across subprocess calls, and the
    invocation records it. A clean converted target after a source with errors
    and warnings (exit 6) must record its own 0. Only the process call is
    replaced, so ``_run_subprocess`` and that accumulation run for real.
    """
    converted = repo / ".ash" / "ash_output" / "converted" / "archive.zip"
    converted.mkdir(parents=True)
    shutil.copy(repo / "templates" / "compliant.yaml", converted / "t.yaml")
    runs = iter(
        [
            FakeCfnLint({"templates/insecure.yaml": CAPTURED_INSECURE}, returncode=6),
            FakeCfnLint({}, returncode=0),
        ]
    )
    monkeypatch.setattr(
        "automated_security_helper.utils.subprocess_utils."
        "run_command_with_output_handling",
        lambda command, **_: next(runs)(command),
    )
    scanner = _scanner(repo)
    scanner.use_uv_tool = False
    with patch.object(
        CfnLintScanner, "validate_plugin_dependencies", return_value=True
    ):
        source = scanner.scan(target=repo, target_type="source")
        assert source.runs[0].invocations[0].exitCode == 6
        assert scanner.exit_code == 6

        report = scanner.scan(target=converted.parent, target_type="converted")

    assert scanner.targets_attempted == 1 and scanner.targets_failed == 0
    assert report.runs[0].results == []
    assert scanner.exit_code == 0
    assert report.runs[0].invocations[0].exitCode == 0


def test_the_environment_is_copied_under_the_environ_lock(monkeypatch):
    """Other scanner threads change os.environ while cfn-lint's environment is
    built (cdk_nag_wrapper sets and removes variables around each template). A
    copy reads the keys and then each value, so it is taken under ENVIRON_LOCK,
    which every change also holds (utils/process_env.py). The copy is watched
    through a stand-in for os.environ that records whether the lock was held at
    each read."""
    from collections.abc import Mapping

    from automated_security_helper.utils import process_env

    class Lock:
        held = False

        def __enter__(self):
            self.held = True

        def __exit__(self, *exc_info):
            self.held = False

    lock = Lock()
    held_at_read: list = []

    class Environ(Mapping):
        def __init__(self, data):
            self._data = data

        def __getitem__(self, key):
            held_at_read.append(lock.held)
            return self._data[key]

        def __iter__(self):
            return iter(self._data)

        def __len__(self):
            return len(self._data)

    # Undone before the test returns: pytest itself writes to os.environ between
    # phases.
    with monkeypatch.context() as patched:
        patched.setattr(process_env, "ENVIRON_LOCK", lock)
        patched.setattr(os, "environ", Environ({"PATH": "/usr/bin", "LANG": "C"}))
        env = CfnLintScanner._child_env()

    assert env == {
        "PATH": "/usr/bin",
        "LANG": "C",
        "AWS_REGION": "us-east-1",
        "AWS_DEFAULT_REGION": "us-east-1",
    }
    assert held_at_read == [True, True]
