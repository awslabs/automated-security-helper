# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""BearerScanner: the invocation, the JSON-to-SARIF conversion and the exit status.

The scan() tests replace the subprocess with a fake that writes a Bearer JSON report,
so they run on every platform without the binary. The report below is written by hand
from the field list in Bearer's report types (pkg/report/output/security/types), not
captured from a binary: it is not a captured-output oracle.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_bearer_plugins
from automated_security_helper.plugin_modules.ash_bearer_plugins import (
    bearer_scanner as bs,
)
from automated_security_helper.plugin_modules.ash_bearer_plugins.bearer_scanner import (
    BEARER_SEVERITY_MAP,
    BearerScanner,
    BearerScannerConfig,
    BearerScannerConfigOptions,
    convert_bearer_report,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    build_scanner_policy,
)

pytestmark = pytest.mark.unit


def _finding(rule_id: str, filename: str, line: int, title: str = "A finding") -> dict:
    return {
        "cwe_ids": ["79"],
        "id": rule_id,
        "title": title,
        "description": "Why this matters.",
        "documentation_url": f"https://docs.bearer.com/reference/rules/{rule_id}",
        "line_number": line,
        "full_filename": f"/work/{filename}",
        "filename": filename,
        "source": {"start": line, "end": line, "column": {"start": 1, "end": 5}},
        "sink": {
            "start": line,
            "end": line,
            "column": {"start": 3, "end": 9},
            "content": "the sink",
        },
        "snippet": "the code",
        "fingerprint": f"fp-{rule_id}-{line}",
    }


#: One finding per severity, written out by hand: (rule, bearer severity, ASH
#: severity, SARIF level, file, line).
EXPECTED = [
    ("rule_critical", "critical", "CRITICAL", "error", "app.py", 1),
    ("rule_high", "high", "HIGH", "error", "src/a.js", 2),
    ("rule_medium", "medium", "MEDIUM", "warning", "src/b.rb", 3),
    ("rule_low", "low", "LOW", "note", "c.go", 4),
    ("rule_warning", "warning", "INFO", "none", "d.java", 5),
]
POSITIVE: Dict[str, Any] = {
    severity: [_finding(rule, filename, line)]
    for rule, severity, _a, _l, filename, line in EXPECTED
}


def _rows(report: SarifReport) -> List[tuple]:
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


class FakeBearer:
    """Stands in for _run_subprocess: records the call, writes a JSON report."""

    def __init__(
        self,
        document: Any = POSITIVE,
        exit_code: int = 2,
        text: Optional[str] = None,
        write: bool = True,
        flags: Optional[Dict[str, Any]] = None,
    ):
        self.document, self.exit_code, self.text = document, exit_code, text
        self.write, self.flags = write, flags or {}
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            if self.write:
                output = next(a for a in command if a.startswith("--output="))
                path = Path(output.split("=", 1)[1])
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    self.text if self.text is not None else json.dumps(self.document),
                    encoding="utf-8",
                )
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": "",
                "stderr": "QUOTED SOURCE LINE",
                **self.flags,
            }

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(source: Path, tmp_path: Path) -> BearerScanner:
    output = tmp_path / "out"
    return BearerScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=BearerScannerConfig(enabled=True),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("print(1)\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(bs, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch, target=None, target_type="source"):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


def _flag(argv: List[str], prefix: str) -> Optional[str]:
    for token in argv:
        if token.startswith(prefix):
            return token[len(prefix) :]
    return None


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert BearerScannerConfig().enabled is True
        assert BearerScannerConfig().name == "bearer"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "bearer")

    def test_the_module_exports_the_scanner(self):
        assert ash_bearer_plugins.ASH_SCANNERS == [BearerScanner]
        assert ash_bearer_plugins.ASH_REPORTERS == []

    def test_it_has_no_option_a_tree_could_use_to_hide_findings(self):
        assert set(BearerScannerConfigOptions.model_fields) <= {
            "severity_threshold",
            "scan_timeout",
            "offline",
        }


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBearer()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[:2] == ["bearer", "scan"]
        for token in (
            "--format=json",
            "--scanner=sast",
            "--exit-code=2",
            "--quiet",
            "--no-color",
            "--hide-progress-bar",
            "--force",
            "--disable-version-check",
        ):
            assert token in argv
        assert argv[-2:] == ["--", "."]
        assert _flag(argv, "--output=").endswith("/source/bearer.json")

    def test_the_working_directory_is_the_source_directory(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBearer()
        _run(scanner, fake, monkeypatch)
        assert fake.calls[0]["cwd"] is None or Path(fake.calls[0]["cwd"]) == tree

    def test_the_converted_target_is_an_absolute_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "nb.py").write_text("x = 1\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeBearer()
        _run(scanner, fake, monkeypatch, target=converted, target_type="converted")
        assert fake.argv[-2:] == ["--", converted.absolute().as_posix()]

    def test_every_option_is_one_flag_equals_value_token(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBearer()
        _run(scanner, fake, monkeypatch)
        before_path = fake.argv[: fake.argv.index("--")]
        for token in before_path[2:]:
            assert token.startswith("--"), token
        # No flag takes its value as a separate token.
        assert before_path[0] == "bearer"

    def test_the_tree_config_and_ignore_file_are_replaced_by_empty_ones(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "bearer.yml").write_text("rule:\n  skip-rule: [x]\n")
        (tree / "bearer.ignore").write_text("{}")
        scanner = _scanner(tree, tmp_path)
        fake = FakeBearer()
        _run(scanner, fake, monkeypatch)
        config = Path(_flag(fake.argv, "--config-file="))
        ignore = Path(_flag(fake.argv, "--ignore-file="))
        for path in (config, ignore):
            assert tree not in path.parents
            assert path.read_text(encoding="utf-8") == ""

    @pytest.mark.parametrize(
        "forbidden",
        [
            "--api-key",
            "--external-rule-dir",
            "--skip-rule",
            "--only-rule",
            "--scanner=secrets",
            "--exit-code=0",
            "--diff",
        ],
    )
    def test_flags_that_hide_findings_or_reach_out_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, forbidden
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBearer()
        _run(scanner, fake, monkeypatch)
        assert not any(
            t == forbidden or t.startswith(forbidden + "=") for t in fake.argv
        )

    def test_ashs_output_directory_inside_the_tree_is_skipped(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        output = tree / "ash-out"
        scanner = _scanner(tree, tmp_path)
        scanner.context.output_dir = output
        fake = FakeBearer()
        _run(scanner, fake, monkeypatch)
        assert _flag(fake.argv, "--skip-path=") is not None
        assert "ash-out" in _flag(fake.argv, "--skip-path=")

    def test_a_skip_path_with_a_comma_is_refused_before_the_tool_starts(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.context.output_dir = tree / "a,b"
        fake = FakeBearer()
        with pytest.raises(ScannerError):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBearer()
        _run(scanner, fake, monkeypatch, target=tmp_path / "does-not-exist")
        assert fake.calls == []


class TestReport:
    def test_happy_path_every_severity_is_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeBearer(), monkeypatch)
        assert isinstance(report, SarifReport)
        assert _rows(report) == [
            (rule, level, ash, uri, line)
            for rule, _b, ash, level, uri, line in EXPECTED
        ]

    @pytest.mark.parametrize("rule,severity,ash,level,uri,line", EXPECTED)
    def test_each_severity_row_agrees_between_level_and_issue_severity(
        self, rule, severity, ash, level, uri, line
    ):
        document = convert_bearer_report({severity: [_finding(rule, uri, line)]})
        result = document["runs"][0]["results"][0]
        assert result["level"] == level
        assert result["properties"]["issue_severity"] == ash
        assert BEARER_SEVERITY_MAP[severity] == (ash, level)

    def test_negative_control_an_empty_report_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeBearer(document={}, exit_code=0), monkeypatch)
        assert isinstance(report, SarifReport)
        assert report.get_all_results() == []

    def test_cwe_ids_fingerprints_and_regions_are_carried(self):
        document = convert_bearer_report({"high": [_finding("r", "./x/y.py", 7)]})
        run = document["runs"][0]
        result = run["results"][0]
        assert (
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            == "x/y.py"
        )
        assert result["locations"][0]["physicalLocation"]["region"] == {
            "startLine": 7,
            "endLine": 7,
            "startColumn": 3,
            "endColumn": 9,
        }
        assert "CWE-79" in result["properties"]["tags"]
        assert result["partialFingerprints"] == {"bearer/v1": "fp-r-7"}
        assert run["tool"]["driver"]["rules"][0]["id"] == "r"

    def test_code_snippets_are_not_copied_into_the_report(self):
        text = json.dumps(convert_bearer_report({"high": [_finding("r", "a", 1)]}))
        assert "the code" not in text
        assert "the sink" not in text

    def test_the_report_survives_a_sarif_round_trip(self):
        document = convert_bearer_report(POSITIVE)
        assert len(SarifReport.model_validate(document).get_all_results()) == 5

    def test_a_severity_the_plugin_does_not_rate_fails_instead_of_vanishing(self):
        with pytest.raises(ScannerError, match="severity"):
            convert_bearer_report(
                {"critical": [], "catastrophic": [_finding("r", "a", 1)]}
            )


REFERENCE_REPORT = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "bearer"
    / "reference"
    / "positive.json"
)


class TestReferenceReport:
    """Severity mapping over a committed report file (hand-written, see its README)."""

    def test_each_severity_maps_and_a_leading_dot_slash_is_stripped(self):
        sarif = convert_bearer_report(json.loads(REFERENCE_REPORT.read_text()))
        rows = [
            (
                r["ruleId"],
                r["level"],
                r["properties"]["issue_severity"],
                r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            )
            for r in sarif["runs"][0]["results"]
        ]
        assert rows == [
            ("javascript_lang_hardcoded_secret", "error", "CRITICAL", "src/app.js"),
            ("python_django_sql_injection", "error", "HIGH", "app.py"),
            ("ruby_lang_weak_hash_md5", "note", "LOW", "lib/h.rb"),
        ]

    def test_the_converted_reference_report_validates_as_sarif(self):
        sarif = convert_bearer_report(json.loads(REFERENCE_REPORT.read_text()))
        assert len(SarifReport.model_validate(sarif).get_all_results()) == 3


class TestExitStatus:
    @pytest.mark.parametrize("code", [0, 2])
    def test_zero_and_two_succeed(self, tree, tmp_path, on_path, monkeypatch, code):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeBearer(exit_code=code), monkeypatch)
        assert scanner._exit_code_accepted()

    @pytest.mark.parametrize("code", [1, 126, 137])
    def test_nonzero_exit_with_findings_on_disk_still_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeBearer(exit_code=code), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeBearer(write=False, exit_code=0), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        results = Path(scanner.results_dir) / "source" / "bearer.json"
        results.parent.mkdir(parents=True, exist_ok=True)
        results.write_text(json.dumps(POSITIVE))
        # The run writes nothing, so the stale report must be gone, not read.
        with pytest.raises(ScannerError):
            _run(scanner, FakeBearer(write=False, exit_code=0), monkeypatch)

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBearer(write=False, exit_code=124, flags={"timed_out": True})
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, fake, monkeypatch)
        timeout = fake.calls[0]["timeout"]
        assert timeout is None or 0 < timeout <= scanner.config.options.scan_timeout

    def test_stderr_is_not_copied_into_errors(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeBearer(), monkeypatch)
        assert "QUOTED SOURCE LINE" not in " ".join(scanner.errors)

    def test_stderr_guard_is_the_class_flag_with_a_positive_control(
        self, tree, tmp_path, monkeypatch
    ):
        # Positive control: with the base flag on, the same response copies the
        # stream into errors, so the absence above is the flag's doing.
        response = {"returncode": 1, "stdout": "", "stderr": "QUOTED SOURCE LINE"}
        assert BearerScanner.quote_tool_stderr is False
        guarded = _scanner(tree, tmp_path)
        guarded._process_command_response(dict(response))
        assert "QUOTED SOURCE LINE" not in " ".join(guarded.errors)
        monkeypatch.setattr(BearerScanner, "quote_tool_stderr", True)
        open_scanner = _scanner(tree, tmp_path)
        open_scanner._process_command_response(dict(response))
        assert "QUOTED SOURCE LINE" in " ".join(open_scanner.errors)

    def test_the_failure_message_names_the_log_without_quoting_it(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        message = scanner._describe_scan_failure(
            RuntimeError("boom"), tmp_path / "x" / "bearer.json"
        )
        assert "bearer.stderr.log" in message.lower() or "stderr.log" in message
        assert "not quoted" in message


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "text",
        [
            "not json at all",
            "[1, 2, 3]",
            '"a string"',
            '{"high": "not a list"}',
            '{"high": ["not an object"]}',
            '{"high": [{"filename": "a.py"}]}',
            '{"high": [{"id": "r"}]}',
            '{"unheard_of": []}',
        ],
    )
    def test_malformed_output_fails_the_scan_instead_of_reading_clean(
        self, tree, tmp_path, on_path, monkeypatch, text
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeBearer(text=text, exit_code=2), monkeypatch)

    def test_an_empty_report_file_is_not_a_clean_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeBearer(text="", exit_code=0), monkeypatch)


class TestToolAbsent:
    def test_a_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(bs, "find_executable", lambda cmd: None)
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is False

    def test_a_present_binary_satisfies_them(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_the_missing_binary_hint_names_the_license_and_not_ash_install(
        self, tree, tmp_path, monkeypatch, caplog
    ):
        messages: List[str] = []
        monkeypatch.setattr(bs, "find_executable", lambda cmd: None)
        monkeypatch.setattr(bs.ASH_LOGGER, "warning", messages.append)
        _scanner(tree, tmp_path).validate_plugin_dependencies()
        assert any("Elastic License 2.0" in m for m in messages)
        assert not any("ash dependencies install" in m for m in messages)


class TestLicenseGate:
    def test_ash_declares_no_install_command_for_an_elv2_tool(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        assert not scanner.custom_install_commands

    def test_the_module_docstring_names_the_license(self):
        assert "Elastic License 2.0" in bs.__doc__

    def test_the_class_vars_are_set_deliberately(self):
        assert BearerScanner.python_only is False
        assert BearerScanner.success_exit_codes == {0, 2}
        assert BearerScanner.sandbox_requirements == SandboxRequirements()


class TestSandbox:
    def _policy(self, tmp_path, monkeypatch, requirements):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        source = tmp_path / "src"
        source.mkdir()
        output = source / ".ash" / "ash_output"
        output.mkdir(parents=True)
        return build_scanner_policy(
            "bearer",
            requirements,
            argv0=sys.executable,
            source_dir=source,
            output_dir=output,
            results_dir=output / "scanners" / "bearer",
            scan_target=source,
            cwd=source,
            offline=False,
            network_scanners=None,
        )

    def test_bearer_declares_the_strict_default(self, tmp_path, monkeypatch):
        policy = self._policy(tmp_path, monkeypatch, BearerScanner.sandbox_requirements)
        assert policy.network is False

    def test_the_tools_environment_variables_are_not_passed_in(
        self, tmp_path, monkeypatch
    ):
        policy = self._policy(tmp_path, monkeypatch, BearerScanner.sandbox_requirements)
        passed = policy.filter_env(
            {
                "BEARER_SCANNER": "secrets,sast",
                "BEARER_CONFIG_FILE": "/etc/bearer.yml",
                "BEARER_API_KEY": "placeholder",
            }
        )
        assert passed.keys() == {"HOME"} | set(policy.extra_env)
