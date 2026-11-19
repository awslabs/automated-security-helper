# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""SpectralScanner: the invocation, the exit status, and the severity mapping.

The reports below are what Spectral 6.17.1 (the pinned version) wrote when it was
run as ``spectral lint --ruleset=<extends spectral:oas and spectral:asyncapi>
--format=sarif --output=<file> --fail-severity=hint --ignore-unknown-format --quiet
'**/*.{json,yaml,yml}'`` from the root of a two-file tree (``api.yaml`` with six
warnings, ``broken.yaml`` with one error) and from the root of a clean tree.
Spectral lists all 112 rules of its rulesets in ``tool.driver.rules``; here the list
is cut to the rules the results name and ``ruleIndex`` renumbered to match. Every
other field is as Spectral wrote it. The scan() tests replace the subprocess with a
fake that serves them, so they run on every platform without the binary.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_spectral_plugins
from automated_security_helper.plugin_modules.ash_spectral_plugins import (
    spectral_scanner as ss,
)
from automated_security_helper.plugin_modules.ash_spectral_plugins.spectral_scanner import (
    SpectralScanner,
    SpectralScannerConfig,
    SpectralScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit

HELP = "https://meta.stoplight.io/docs/spectral/docs/reference/openapi-rules.md#"

#: (rule id, description) in the order of ``tool.driver.rules`` below.
_RULES = [
    ("path-params", "Path parameters must be defined and valid."),
    ("info-contact", 'Info object must have "contact" object.'),
    ("info-description", 'Info "description" must be present and non-empty string.'),
    (
        "operation-description",
        'Operation "description" must be present and non-empty string.',
    ),
    ("operation-operationId", 'Operation must have "operationId".'),
    ("operation-tags", 'Operation must have non-empty "tags" array.'),
    ("oas3-api-servers", 'OpenAPI "servers" must be present and non-empty array.'),
]


def _driver() -> Dict[str, Any]:
    return {
        "name": "spectral",
        "rules": [
            {
                "id": rule_id,
                "shortDescription": {"text": text},
                "helpUri": f"{HELP}{rule_id}",
            }
            for rule_id, text in _RULES
        ],
        "version": "6.17.1",
        "informationUri": "https://github.com/stoplightio/spectral",
    }


def _result(
    rule_index: int,
    level: Optional[str],
    text: str,
    uri: str,
    artifact: int,
    region: tuple,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "message": {"text": text},
        "ruleId": _RULES[rule_index][0],
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "index": artifact},
                    "region": dict(
                        zip(
                            ("startLine", "startColumn", "endLine", "endColumn"), region
                        )
                    ),
                }
            }
        ],
        "ruleIndex": rule_index,
    }
    if level is not None:
        out["level"] = level
    return out


def _report(results: List[Dict[str, Any]], artifacts: List[str]) -> Dict[str, Any]:
    return {
        "$schema": "http://json.schemastore.org/sarif-2.1.0-rtm.6.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": _driver()},
                "results": results,
                "artifacts": [
                    {"sourceLanguage": "YAML", "location": {"uri": uri}}
                    for uri in artifacts
                ],
            }
        ],
    }


POSITIVE = _report(
    [
        _result(
            6,
            "warning",
            'OpenAPI "servers" must be present and non-empty array.',
            "api.yaml",
            0,
            (1, 1, 10, 26),
        ),
        _result(
            1,
            "warning",
            'Info object must have "contact" object.',
            "api.yaml",
            0,
            (2, 6, 4, 17),
        ),
        _result(
            2,
            "warning",
            'Info "description" must be present and non-empty string.',
            "api.yaml",
            0,
            (2, 6, 4, 17),
        ),
        _result(
            3,
            "warning",
            'Operation "description" must be present and non-empty string.',
            "api.yaml",
            0,
            (7, 9, 10, 26),
        ),
        _result(
            4,
            "warning",
            'Operation must have "operationId".',
            "api.yaml",
            0,
            (7, 9, 10, 26),
        ),
        _result(
            5,
            "warning",
            'Operation must have non-empty "tags" array.',
            "api.yaml",
            0,
            (7, 9, 10, 26),
        ),
        _result(
            0,
            "error",
            'Operation must define parameter "{petId}" as expected by path "/pets/{petId}".',
            "broken.yaml",
            1,
            (14, 9, 20, 26),
        ),
    ],
    ["api.yaml", "broken.yaml"],
)

#: What POSITIVE must produce, written out by hand from the run above, not derived from
#: the code under test: (ruleId, SARIF level, ASH severity, uri, start line).
POSITIVE_EXPECTED = [
    ("oas3-api-servers", "warning", "MEDIUM", "api.yaml", 1),
    ("info-contact", "warning", "MEDIUM", "api.yaml", 2),
    ("info-description", "warning", "MEDIUM", "api.yaml", 2),
    ("operation-description", "warning", "MEDIUM", "api.yaml", 7),
    ("operation-operationId", "warning", "MEDIUM", "api.yaml", 7),
    ("operation-tags", "warning", "MEDIUM", "api.yaml", 7),
    ("path-params", "error", "HIGH", "broken.yaml", 14),
]

#: A tree with nothing to report: Spectral still writes the report, with no results.
NEGATIVE = _report([], [])


def _findings(report: SarifReport) -> List[tuple]:
    """(ruleId, SARIF level, ASH severity, uri, line) for every result, in order."""
    out = []
    for r in report.get_all_results():
        loc = r.locations[0].physicalLocation.root
        out.append(
            (
                r.ruleId,
                getattr(r.level, "value", r.level),
                getattr(r.properties, "issue_severity", None),
                loc.artifactLocation.uri,
                loc.region.startLine,
            )
        )
    return out


class FakeSpectral:
    """Stands in for _run_subprocess: records argv, writes a report."""

    def __init__(
        self,
        report: Optional[Dict[str, Any]] = None,
        exit_code: int = 1,
        report_text: Optional[str] = None,
        stderr: str = "",
        timed_out: bool = False,
    ):
        self.report = POSITIVE if report is None else report
        self.exit_code, self.report_text = exit_code, report_text
        self.stderr, self.timed_out = stderr, timed_out
        self.write_report = True
        self.calls: List[Dict[str, Any]] = []

    def without_a_report(self) -> "FakeSpectral":
        self.write_report = False
        return self

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            if self.timed_out:
                scanner.exit_code = 0
                return {"timed_out": True}
            if self.write_report:
                path = Path(_flag(command, "--output="))
                text = self.report_text
                if text is None:
                    text = json.dumps(self.report)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            scanner.exit_code = self.exit_code
            return {"returncode": self.exit_code, "stdout": "", "stderr": self.stderr}

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _flag(argv: List[str], prefix: str) -> Optional[str]:
    """The value of the ``--flag=value`` token starting ``prefix``, or None."""
    for token in argv:
        if token.startswith(prefix):
            return token[len(prefix) :]
    return None


def _scanner(
    source: Path,
    tmp_path: Path,
    *,
    operator: bool = True,
    **options,
) -> SpectralScanner:
    """``operator``: the options came from the operator, or from the scanned tree."""
    config = get_default_config()
    record_provenance(
        config,
        in_tree=[] if operator else [source / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
    )
    output = tmp_path / "out"
    return SpectralScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=config,
        ),
        config=SpectralScannerConfig(
            enabled=True, options=SpectralScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "api").mkdir(parents=True)
    (src / "api" / "openapi.yaml").write_text("openapi: 3.0.3\n")
    (src / "app.py").write_text("print(1)\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ss, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(
    scanner: SpectralScanner,
    fake: FakeSpectral,
    monkeypatch,
    target: Optional[Path] = None,
    target_type: str = "source",
):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert SpectralScannerConfig().enabled is True
        assert SpectralScannerConfig().name == "spectral"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "spectral")

    def test_the_module_exports_the_scanner(self):
        assert ash_spectral_plugins.ASH_SCANNERS == [SpectralScanner]
        assert ash_spectral_plugins.ASH_REPORTERS == []

    def test_the_scanner_states_what_it_is(self):
        assert SpectralScanner.python_only is False
        assert SpectralScanner.success_exit_codes == {0, 1}

    def test_the_tree_may_not_choose_the_ruleset(self):
        assert SpectralScannerConfigOptions().ruleset_file is None

    def test_the_sandbox_requirements_are_the_strict_default(self):
        assert SpectralScanner.sandbox_requirements == SandboxRequirements()


class TestInvocation:
    def test_every_fixed_flag_and_the_documents(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSpectral()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[:2] == ["spectral", "lint"]
        for expected in (
            "--format=sarif",
            "--fail-severity=hint",
            "--ignore-unknown-format",
            "--quiet",
        ):
            assert expected in argv
        assert argv[-1] == "**/*.{json,yaml,yml}"
        assert fake.calls[0]["cwd"] is None, "the run starts in the source directory"

    def test_the_documents_are_not_given_after_a_double_dash(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """After ``--`` Spectral lints nothing and reads standard input."""
        scanner = _scanner(tree, tmp_path)
        fake = FakeSpectral()
        _run(scanner, fake, monkeypatch)
        assert "--" not in fake.argv

    def test_options_take_their_value_with_an_equals_sign(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSpectral()
        _run(scanner, fake, monkeypatch)
        for flag in ("--ruleset", "--output", "--format", "--fail-severity"):
            assert flag not in fake.argv

    def test_the_report_is_written_beside_the_results(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSpectral()
        _run(scanner, fake, monkeypatch)
        report = Path(_flag(fake.argv, "--output="))
        assert report.name == "spectral.sarif"
        assert report.is_absolute()

    @pytest.mark.parametrize(
        "forbidden", ["--stdin-filepath", "--resolver", "--fail-on-unmatched-globs"]
    )
    def test_flags_that_read_elsewhere_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, forbidden
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSpectral()
        _run(scanner, fake, monkeypatch)
        assert not any(
            a == forbidden or a.startswith(f"{forbidden}=") for a in fake.argv
        )

    def test_a_ruleset_is_always_passed_and_it_is_ashs_own_by_default(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / ".spectral.yaml").write_text("extends: []\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeSpectral()
        _run(scanner, fake, monkeypatch)
        ruleset = Path(_flag(fake.argv, "--ruleset="))
        assert ruleset.read_text(encoding="utf-8") == (
            'extends: ["spectral:oas", "spectral:asyncapi"]\n'
        )
        assert not ruleset.resolve().is_relative_to(tree.resolve())

    def test_the_converted_target_is_a_glob_under_an_absolute_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "spec.json").write_text("{}\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeSpectral(report=NEGATIVE, exit_code=0)
        _run(scanner, fake, monkeypatch, target=converted, target_type="converted")
        assert (
            fake.argv[-1] == f"{converted.absolute().as_posix()}/**/*.{{json,yaml,yml}}"
        )

    def test_a_tree_with_no_json_or_yaml_is_skipped_without_running_the_tool(
        self, tmp_path, on_path, monkeypatch
    ):
        """Spectral exits 2 and writes no report when its glob matches nothing."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text("print(1)\n")
        (src / ".hidden").mkdir()
        (src / ".hidden" / "spec.yaml").write_text("openapi: 3.0.3\n")
        scanner = _scanner(src, tmp_path)
        fake = FakeSpectral()
        assert _run(scanner, fake, monkeypatch) is True
        assert fake.calls == []

    def test_nothing_to_scan_reason_names_an_empty_selection(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text("print(1)\n")
        assert "no JSON or YAML" in _scanner(src, tmp_path).nothing_to_scan_reason()

    def test_nothing_to_scan_reason_is_none_when_a_document_exists(
        self, tree, tmp_path
    ):
        assert _scanner(tree, tmp_path).nothing_to_scan_reason() is None

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSpectral()
        _run(scanner, fake, monkeypatch, target=tmp_path / "gone")
        assert fake.calls == []


class TestRulesetOption:
    def test_the_operators_ruleset_is_passed_instead_of_ashs(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        mine = tmp_path / "mine.yaml"
        mine.write_text('extends: ["spectral:oas"]\n')
        scanner = _scanner(tree, tmp_path, ruleset_file=str(mine))
        fake = FakeSpectral()
        _run(scanner, fake, monkeypatch)
        assert Path(_flag(fake.argv, "--ruleset=")).resolve() == mine.resolve()

    def test_a_ruleset_set_by_the_tree_is_refused_with_a_warning(
        self, tree, tmp_path, on_path, monkeypatch, caplog
    ):
        mine = tree / "rules.yaml"
        mine.write_text("rules: {}\n")
        scanner = _scanner(tree, tmp_path, operator=False, ruleset_file=str(mine))
        fake = FakeSpectral()
        with caplog.at_level("WARNING"):
            _run(scanner, fake, monkeypatch)
        ruleset = Path(_flag(fake.argv, "--ruleset="))
        assert ruleset.resolve() != mine.resolve()
        assert "scanners.spectral.options.ruleset_file" in caplog.text

    def test_a_ruleset_that_is_not_a_file_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, ruleset_file=str(tmp_path / "missing.yaml"))
        fake = FakeSpectral()
        with pytest.raises(ScannerError):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []


class TestReport:
    def test_the_positive_run_is_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeSpectral(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_the_clean_run_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeSpectral(NEGATIVE, exit_code=0), monkeypatch)
        assert _findings(report) == []
        assert scanner._exit_code_accepted()

    def test_results_are_marked_as_lint_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeSpectral(), monkeypatch)
        for result in report.get_all_results():
            assert getattr(result.kind, "value", result.kind) == "fail"
            assert {"lint", "api-description"} <= set(result.properties.tags)

    @pytest.mark.parametrize(
        "level, severity, sarif_level",
        [
            ("error", "HIGH", "error"),
            ("warning", "MEDIUM", "warning"),
            # Spectral writes both its info and hint severities as note. The positive
            # run has no note result, so this row is a written-by-hand report.
            ("note", "LOW", "note"),
            # Spectral always writes a level. ASH's SARIF model reads a missing one
            # as the SARIF default, warning.
            (None, "MEDIUM", "warning"),
            ("none", "HIGH", "error"),
        ],
    )
    def test_every_level_is_rated_and_the_sarif_level_agrees(
        self, tree, tmp_path, on_path, monkeypatch, level, severity, sarif_level
    ):
        report_in = _report(
            [_result(1, level, "x", "api.yaml", 0, (2, 6, 4, 17))], ["api.yaml"]
        )
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeSpectral(report_in), monkeypatch)
        ((_, got_level, got_severity, _, _),) = _findings(report)
        assert (got_severity, got_level) == (severity, sarif_level)

    def test_an_unknown_level_is_high(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        # An unknown level is not valid SARIF, so exercise the mapping directly.
        result = SimpleNamespace(level="bogus", kind=None, properties=None)
        report = SimpleNamespace(get_all_results=lambda: [result])
        scanner._post_process_sarif(report, [], tree)
        assert result.properties.issue_severity == "HIGH"
        assert getattr(result.level, "value", result.level) == "error"

    def test_the_report_round_trips(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeSpectral(), monkeypatch)
        again = SarifReport.model_validate(json.loads(report.model_dump_json()))
        assert _findings(again) == POSITIVE_EXPECTED


class TestExitStatus:
    @pytest.mark.parametrize("code", [0, 1])
    def test_zero_and_one_succeed(self, tree, tmp_path, on_path, monkeypatch, code):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeSpectral(exit_code=code), monkeypatch)
        assert scanner._exit_code_accepted()

    @pytest.mark.parametrize("code", [2, 126, 137])
    def test_any_other_exit_fails_the_scan_even_with_a_report_on_disk(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        """Exit 2 is Spectral's own failure."""
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeSpectral(exit_code=code), monkeypatch)

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=5)
        fake = FakeSpectral(timed_out=True)
        with pytest.raises(ScannerError, match="timed out after 5"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 5

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "not json",
            "[]",
            "{}",
            '{"version": "2.1.0", "runs": []}',
            '{"runs": [{"tool": 1}]}',
        ],
        ids=[
            "empty",
            "not-json",
            "not-an-object",
            "no-runs-key",
            "empty-runs",
            "bad-run",
        ],
    )
    def test_malformed_output_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch, text
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeSpectral(report_text=text, exit_code=0), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeSpectral(exit_code=0).without_a_report(), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        first = FakeSpectral()
        _run(scanner, first, monkeypatch)
        report = Path(_flag(first.argv, "--output="))
        assert report.exists(), "the first run left its report"
        with pytest.raises(ScannerError):
            _run(scanner, FakeSpectral(exit_code=0).without_a_report(), monkeypatch)
        assert not report.exists()

    def test_the_tools_stderr_is_not_copied_into_the_scans_errors(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner._process_command_response(
            {"returncode": 2, "stdout": "", "stderr": "ENOENT: PLANTED-TEXT"}
        )
        assert not any("PLANTED-TEXT" in line for line in scanner.errors)

    def test_the_failure_message_names_the_log_and_does_not_quote_it(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.exit_code = 2
        results = tmp_path / "out" / "source" / "spectral.sarif"
        message = scanner._describe_scan_failure(ScannerError("boom"), results)
        assert "stderr.log" in message
        assert "exit code 2" in message
        assert "not quoted" in message

    def test_a_failure_before_the_tool_started_has_no_exit_code(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        message = scanner._describe_scan_failure(
            ScannerError("boom"), None, tool_started=False
        )
        assert "was not started" in message
        assert "exit code" not in message


class TestDependencyCheck:
    def test_a_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ss, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False

    def test_a_missing_binary_means_the_scan_does_not_run_the_tool(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ss, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        fake = FakeSpectral()
        assert _run(scanner, fake, monkeypatch) is False
        assert fake.calls == []

    def test_a_present_binary_satisfies_them(self, tree, tmp_path, on_path):
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is True

    def test_an_unavailable_reason_fails_the_check(self, tree, tmp_path, on_path):
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "not on this platform"
        assert scanner.validate_plugin_dependencies() is False


class TestInstall:
    def test_install_commands_cover_every_published_platform(self, tmp_path):
        """Needs the ``spectral`` rows of ``utils/tool_downloads.py``."""
        scanner = _scanner(tmp_path, tmp_path)
        for platform, arch in [
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
            ("windows", "amd64"),
        ]:
            commands = scanner.get_installation_commands(platform, arch)
            assert commands, f"no install command for {platform}/{arch}"
            assert "spectral" in commands[0]

    def test_windows_arm64_is_not_published(self, tmp_path):
        scanner = _scanner(tmp_path, tmp_path)
        assert not scanner.get_installation_commands("windows", "arm64")
