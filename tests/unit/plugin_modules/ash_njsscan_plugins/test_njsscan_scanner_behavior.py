# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""NjsscanScanner: argv, severity mapping, exit status and failure handling.

The SARIF the fake subprocess writes is built by ``_sarif`` below in the shape
njsscan's own formatter produces (``njsscan/formatters/sarif.py``: ``ruleId``,
``ruleIndex``, ``message``, ``level``, one location with a region and a snippet,
``properties`` with ``owasp-web`` and ``cwe``; a driver named ``nodejsscan``; an
invocation carrying ``executionSuccessful``). It is written from that source, not
captured from a run. ``TestCapturedReports`` below serves SARIF captured from a
real njsscan 1.0.2 run (tests/test_data/scanners/njsscan/captured) through the same
fake, so the shape the scanner reads is checked against the real tool's too. The
``scan()`` tests replace the subprocess with a fake, so they run on every platform
without the tool. Expected findings are written out by hand, not derived from the
code under test.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_njsscan_plugins
from automated_security_helper.plugin_modules.ash_njsscan_plugins import (
    njsscan_scanner as ns,
)
from automated_security_helper.plugin_modules.ash_njsscan_plugins.njsscan_scanner import (
    EMPTY_CONFIG,
    NJSSCAN_DEFAULT_VERSION_CONSTRAINT,
    NJSSCAN_PYTHON_REQUEST,
    NjsscanScanner,
    NjsscanScannerConfig,
    NjsscanScannerConfigOptions,
    source_relative_uri,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit

# (rule id, njsscan SARIF level, uri, start line) -> the only inputs a result needs.
Finding = Tuple[str, str, str, int]

POSITIVE: List[Finding] = [
    ("node_insecure_random_generator", "error", "app.js", 3),
    ("node_xss_mustache_escape", "warning", "views/page.hbs", 7),
    ("node_unsafe_pattern_in_comment", "note", "routes/user.js", 12),
    ("node_unknown_severity", "none", "lib/util.js", 1),
]

#: (ruleId, SARIF level, ASH severity, uri, start line), written out by hand.
POSITIVE_EXPECTED = [
    ("node_insecure_random_generator", "error", "HIGH", "app.js", 3),
    ("node_xss_mustache_escape", "warning", "MEDIUM", "views/page.hbs", 7),
    ("node_unsafe_pattern_in_comment", "note", "LOW", "routes/user.js", 12),
    ("node_unknown_severity", "none", "INFO", "lib/util.js", 1),
]


def _result(index: int, finding: Finding) -> Dict[str, Any]:
    rule_id, level, uri, line = finding
    return {
        "ruleId": rule_id,
        "ruleIndex": index,
        "message": {"text": f"description of {rule_id}"},
        "level": level,
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": line,
                        "endLine": line,
                        "startColumn": 1,
                        "endColumn": 20,
                        "snippet": {"text": "Math.random()"},
                    },
                }
            }
        ],
        "properties": {"owasp-web": "a3", "cwe": "CWE-330: weak randomness"},
    }


def _sarif(findings: List[Finding], *, successful: bool = True) -> Dict[str, Any]:
    """A SARIF log shaped like njsscan's formatter writes it."""
    seen: List[str] = []
    for finding in findings:
        if finding[0] not in seen:
            seen.append(finding[0])
    return {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "nodejsscan",
                        "informationUri": "https://github.com/ajinabraham/njsscan",
                        "semanticVersion": "1.0.2",
                        "version": "1.0.2",
                        "rules": [
                            {
                                "id": rule_id,
                                "name": rule_id.title().replace("_", ""),
                                "helpUri": "https://example.invalid/rules",
                                "properties": {"tags": ["security"]},
                            }
                            for rule_id in seen
                        ],
                    }
                },
                "invocations": [
                    {
                        "endTimeUtc": "2026-11-19T00:00:00Z",
                        "executionSuccessful": successful,
                    }
                ],
                "results": [_result(seen.index(f[0]), f) for f in findings],
            }
        ],
    }


def _text(findings: List[Finding], **kw: Any) -> str:
    return json.dumps(_sarif(findings, **kw))


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


class FakeNjsscan:
    """Stands in for _run_subprocess: records argv, writes the report named by argv."""

    def __init__(
        self,
        sarif_text: Optional[str] = None,
        exit_code: int = 1,
        timed_out: bool = False,
        stderr: str = "",
    ):
        self.sarif_text = _text(POSITIVE) if sarif_text is None else sarif_text
        self.write_report = sarif_text != ""
        self.exit_code, self.timed_out, self.stderr = exit_code, timed_out, stderr
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            output = next(a for a in command if a.startswith("--output="))
            config = next(a for a in command if a.startswith("--config="))
            config_path = Path(config.split("=", 1)[1])
            self.calls.append(
                {
                    "argv": list(command),
                    "env": env,
                    "timeout": timeout,
                    "cwd": cwd,
                    # Read now: the config is removed when the run ends.
                    "config_text": (
                        config_path.read_text(encoding="utf-8")
                        if config_path.exists()
                        else None
                    ),
                }
            )
            if self.timed_out:
                return {"timed_out": True, "returncode": None}
            if self.write_report:
                path = Path(output.split("=", 1)[1])
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(self.sarif_text, encoding="utf-8")
            scanner.exit_code = self.exit_code
            return {"returncode": self.exit_code, "stdout": "", "stderr": self.stderr}

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(
    source: Path,
    tmp_path: Path,
    *,
    output_dir: Optional[Path] = None,
    **options,
) -> NjsscanScanner:
    output = output_dir or tmp_path / "out"
    output.mkdir(parents=True, exist_ok=True)
    return NjsscanScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=AshConfig(),
        ),
        config=NjsscanScannerConfig(
            enabled=True, options=NjsscanScannerConfigOptions(**options)
        ),
    )


@pytest.fixture(autouse=True)
def linux_host(monkeypatch):
    """The scanner's view of the OS is Linux, whatever runs the tests."""
    monkeypatch.setattr(ns, "platform", SimpleNamespace(system=lambda: "Linux"))


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "routes").mkdir(parents=True)
    (src / "app.js").write_text("const r = Math.random();\n")
    (src / "routes" / "user.js").write_text("module.exports = {};\n")
    return src


@pytest.fixture
def deps_ok(monkeypatch):
    """The dependency check answers yes without starting uv."""
    monkeypatch.setattr(
        NjsscanScanner, "validate_plugin_dependencies", lambda self: True
    )


def _run(
    scanner: NjsscanScanner,
    fake: FakeNjsscan,
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
        assert NjsscanScannerConfig().enabled is True
        assert NjsscanScannerConfig().name == "njsscan"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "njsscan")

    def test_the_module_exports_the_scanner(self):
        assert ash_njsscan_plugins.ASH_SCANNERS == [NjsscanScanner]
        assert ash_njsscan_plugins.ASH_REPORTERS == []

    def test_the_plugin_offers_no_option_that_points_at_a_config_file(self):
        names = set(NjsscanScannerConfigOptions.model_fields)
        assert not {n for n in names if "config" in n or "ignore" in n}

    def test_the_class_states_what_the_inventory_reads(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        assert NjsscanScanner.python_only is False
        assert NjsscanScanner.offline_strategy.name == "BUNDLED"
        assert NjsscanScanner.success_exit_codes == {0, 1}
        assert NjsscanScanner.sandbox_requirements == SandboxRequirements()
        assert scanner.command == "njsscan"


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeNjsscan()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[0] == "njsscan"
        assert argv[1] == "--sarif"
        assert argv[2].startswith("--output=")
        assert argv[2].endswith("/source/njsscan.sarif")
        assert argv[3].startswith("--config=")
        # The scan path follows "--", and for the source it is ".": the tool runs
        # in the source directory (cwd None), so reported paths are source-relative.
        assert argv[4:] == ["--", "."]
        assert fake.calls[0]["cwd"] is None

    def test_the_config_is_an_empty_one_outside_the_tree(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        (tree / ".njsscan").write_text(
            "ignore-rules:\n  - node_insecure_random_generator\n"
        )
        scanner = _scanner(tree, tmp_path)
        fake = FakeNjsscan()
        _run(scanner, fake, monkeypatch)
        config = Path(fake.argv[3].split("=", 1)[1]).resolve()
        assert not config.is_relative_to(tree.resolve())
        assert fake.calls[0]["config_text"] == EMPTY_CONFIG
        assert "node_insecure_random_generator" not in EMPTY_CONFIG

    @pytest.mark.parametrize(
        "flag",
        [
            "-w",
            "--exit-warning",
            "--missing-controls",
            "--json",
            "--html",
            "--sonarqube",
            "--defectdojo",
            "--gitlab-sast",
        ],
    )
    def test_flags_that_change_the_exit_code_or_the_format_are_never_passed(
        self, flag, tree, tmp_path, deps_ok, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeNjsscan()
        _run(scanner, fake, monkeypatch)
        assert flag not in fake.argv

    def test_the_converted_target_is_passed_as_an_absolute_path(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "template.js").write_text("x\n")
        fake = FakeNjsscan()
        _run(scanner, fake, monkeypatch, target=converted, target_type="converted")
        assert fake.argv[-2:] == ["--", converted.absolute().as_posix()]
        assert fake.argv[2].endswith("/converted/njsscan.sarif")

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeNjsscan()
        _run(scanner, fake, monkeypatch, target=tmp_path / "does-not-exist")
        assert fake.calls == []


class TestReport:
    def test_the_positive_report_is_rated_and_located(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeNjsscan(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_a_clean_report_has_no_findings(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        fake = FakeNjsscan(sarif_text=_text([]), exit_code=0)
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert _findings(report) == []

    def test_a_dot_slash_and_a_file_uri_become_source_relative(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        absolute = (tree / "routes" / "user.js").absolute().as_uri()
        findings: List[Finding] = [
            ("rule_a", "error", "./app.js", 3),
            ("rule_b", "warning", absolute, 5),
        ]
        fake = FakeNjsscan(sarif_text=_text(findings))
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert [f[3] for f in _findings(report)] == ["app.js", "routes/user.js"]

    def test_results_under_ashs_own_output_directory_are_dropped(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        output = tree / ".ash" / "ash_output"
        findings: List[Finding] = [
            ("rule_a", "error", "app.js", 1),
            ("rule_a", "error", ".ash/ash_output/reports/report.js", 2),
        ]
        scanner = _scanner(tree, tmp_path, output_dir=output)
        report = _run(scanner, FakeNjsscan(sarif_text=_text(findings)), monkeypatch)
        assert [f[3] for f in _findings(report)] == ["app.js"]

    def test_the_tools_own_unsuccessful_invocation_is_carried_into_ashs(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        # Exit 1 is also what njsscan returns when semgrep could not read a file; the
        # SARIF says executionSuccessful false then, and the run must read as incomplete.
        fake = FakeNjsscan(sarif_text=_text(POSITIVE, successful=False))
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert report.runs[0].invocations[0].executionSuccessful is False

    def test_a_successful_run_reads_as_successful(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeNjsscan(), monkeypatch)
        assert report.runs[0].invocations[0].executionSuccessful is True


class TestSeverity:
    @staticmethod
    def _report(*levels: Optional[str]) -> SarifReport:
        findings: List[Finding] = [
            (f"rule_{i}", "warning", f"f{i}.js", i + 1) for i in range(len(levels))
        ]
        doc = _sarif(findings)
        for result, level in zip(doc["runs"][0]["results"], levels, strict=True):
            if level is None:
                del result["level"]
            else:
                result["level"] = level
        return SarifReport.model_validate(doc)

    @pytest.mark.parametrize(
        "njsscan_level, severity, sarif_level",
        [
            ("error", "HIGH", "error"),
            ("warning", "MEDIUM", "warning"),
            ("note", "LOW", "note"),
            ("none", "INFO", "none"),
        ],
    )
    def test_each_level_maps_to_one_severity_and_the_same_sarif_level(
        self, njsscan_level, severity, sarif_level
    ):
        report = NjsscanScanner.apply_severity_mapping(self._report(njsscan_level))
        assert _findings(report)[0][1:3] == (sarif_level, severity)

    def test_a_result_without_a_level_is_medium(self):
        report = NjsscanScanner.apply_severity_mapping(self._report(None))
        assert _findings(report)[0][1:3] == ("warning", "MEDIUM")

    def test_an_unknown_level_is_high(self):
        report = self._report("warning")
        report.runs[0].results[0].level = "bogus"
        NjsscanScanner.apply_severity_mapping(report)
        assert _findings(report)[0][1:3] == ("error", "HIGH")

    def test_negative_control_a_changed_level_changes_the_severity(self):
        low = NjsscanScanner.apply_severity_mapping(self._report("note"))
        high = NjsscanScanner.apply_severity_mapping(self._report("error"))
        assert _findings(low)[0][2] != _findings(high)[0][2]


class TestExitStatus:
    def test_exit_1_with_findings_succeeds(self, tree, tmp_path, deps_ok, monkeypatch):
        report = _run(_scanner(tree, tmp_path), FakeNjsscan(exit_code=1), monkeypatch)
        assert len(_findings(report)) == len(POSITIVE)

    def test_exit_0_succeeds(self, tree, tmp_path, deps_ok, monkeypatch):
        fake = FakeNjsscan(sarif_text=_text([]), exit_code=0)
        assert _findings(_run(_scanner(tree, tmp_path), fake, monkeypatch)) == []

    @pytest.mark.parametrize("code", [2, 126, 137])
    def test_any_other_exit_fails_even_with_a_report_on_disk(
        self, code, tree, tmp_path, deps_ok, monkeypatch
    ):
        with pytest.raises(ScannerError, match=f"exited with code {code}"):
            _run(_scanner(tree, tmp_path), FakeNjsscan(exit_code=code), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        with pytest.raises(ScannerError, match="scan failed"):
            _run(
                _scanner(tree, tmp_path),
                FakeNjsscan(sarif_text="", exit_code=0),
                monkeypatch,
            )

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeNjsscan(), monkeypatch)
        with pytest.raises(ScannerError, match="scan failed"):
            _run(scanner, FakeNjsscan(sarif_text="", exit_code=0), monkeypatch)

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=30)
        fake = FakeNjsscan(timed_out=True)
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 30

    @pytest.mark.parametrize(
        "text, message",
        [
            ("not json {", "scan failed"),
            ("[1, 2, 3]", "not SARIF"),
            ("{}", "no SARIF run"),
            ('{"version": "2.1.0", "runs": []}', "no SARIF run"),
        ],
    )
    def test_malformed_output_fails_the_scan(
        self, text, message, tree, tmp_path, deps_ok, monkeypatch
    ):
        fake = FakeNjsscan(sarif_text=text, exit_code=1)
        with pytest.raises(ScannerError, match=message):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)

    def test_the_tools_stderr_text_is_not_a_finding(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        fake = FakeNjsscan(sarif_text=_text([]), exit_code=0, stderr="warning: x")
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert _findings(report) == []


class TestDependencyCheck:
    def test_unsatisfied_dependencies_skip_the_scan_without_running_the_tool(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: False)
        fake = FakeNjsscan()
        assert _run(scanner, fake, monkeypatch) is False
        assert scanner.dependencies_satisfied is False
        assert fake.calls == []

    def test_without_uv_and_without_a_copy_on_path_the_check_fails(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(scanner, "resolve_deferred_tool_version", lambda: None)
        monkeypatch.setattr(scanner, "_validate_uv_tool_availability", lambda: False)
        monkeypatch.setattr(ns, "get_uv_tool_command", lambda command: None)
        assert scanner.validate_plugin_dependencies() is False

    def test_a_dependency_failure_reason_stops_the_check(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "not installed"
        assert scanner.validate_plugin_dependencies() is False


class TestInstall:
    def test_the_install_command_pins_version_and_interpreter(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        assert scanner.uv_tool_install_commands == [
            (
                f"uv tool install --python {NJSSCAN_PYTHON_REQUEST} "
                f"njsscan{NJSSCAN_DEFAULT_VERSION_CONSTRAINT}"
            )
        ]
        commands = scanner.get_installation_commands("linux", "amd64")
        assert [
            "uv",
            "tool",
            "install",
            "--python",
            NJSSCAN_PYTHON_REQUEST,
            "njsscan==1.0.2",
        ] in commands

    def test_the_pin_can_be_overridden_by_an_option(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path, tool_version=">=1.0.0,<2")
        assert scanner._get_tool_version_constraint() == ">=1.0.0,<2"

    def test_install_commands_cover_linux_and_macos_and_not_windows(
        self, tree, tmp_path
    ):
        scanner = _scanner(tree, tmp_path)
        for platform_name, arch in [
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
        ]:
            assert scanner.get_installation_commands(platform_name, arch), (
                f"no install command for {platform_name}/{arch}"
            )
        assert scanner.get_installation_commands("windows", "amd64") == []

    def test_windows_is_an_unsupported_platform(self, tree, tmp_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        assert scanner.unsupported_platform_reason() is None
        monkeypatch.setattr(ns, "platform", SimpleNamespace(system=lambda: "Windows"))
        assert "Mac and Linux" in scanner.unsupported_platform_reason()
        assert scanner.validate_plugin_dependencies() is False


class TestSourceRelativeUri:
    @pytest.mark.parametrize(
        "uri, expected",
        [
            ("app.js", "app.js"),
            ("./app.js", "app.js"),
            ("routes/user.js", "routes/user.js"),
            (None, None),
            ("", ""),
        ],
    )
    def test_relative_values(self, uri, expected, tmp_path):
        assert source_relative_uri(uri, tmp_path) == expected

    def test_a_file_uri_under_the_source_is_made_relative(self, tmp_path):
        uri = (tmp_path / "routes" / "user.js").absolute().as_uri()
        assert source_relative_uri(uri, tmp_path) == "routes/user.js"

    def test_a_file_uri_outside_the_source_is_left_as_written(self, tmp_path):
        outside = (tmp_path.parent / "elsewhere" / "x.js").absolute().as_uri()
        assert source_relative_uri(outside, tmp_path) == outside


#: SARIF a real njsscan 1.0.2 run wrote (see the README beside it).
CAPTURED = Path(__file__).resolve().parents[3] / ("test_data/scanners/njsscan/captured")


class TestCapturedReports:
    """The scanner over what the real tool wrote, not over a hand-built shape."""

    def test_the_positive_capture_is_rated_from_the_real_levels(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        # The WARNING result has no "level" key in the capture (njsscan omits the
        # SARIF default); the ERROR one has "error". Written out by hand.
        fake = FakeNjsscan(
            sarif_text=(CAPTURED / "positive.sarif").read_text(encoding="utf-8")
        )
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert _findings(report) == [
            ("node_insecure_random_generator", "warning", "MEDIUM", "app.js", 4),
            ("eval_nodejs", "error", "HIGH", "app.js", 8),
        ]
        first = report.get_all_results()[0]
        assert first.properties.njsscan_level == "warning"
        assert first.properties.model_extra["owasp-web"].startswith("A9")

    def test_the_capture_has_a_warning_result_with_no_level_key(self):
        document = json.loads((CAPTURED / "positive.sarif").read_text("utf-8"))
        levels = [r.get("level") for r in document["runs"][0]["results"]]
        assert levels == [None, "error"]

    def test_negative_control_the_clean_capture_has_no_findings(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        fake = FakeNjsscan(
            sarif_text=(CAPTURED / "negative.sarif").read_text(encoding="utf-8"),
            exit_code=0,
        )
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert _findings(report) == []
        assert report.runs[0].invocations[0].executionSuccessful is True

    def test_the_errored_capture_reads_as_an_unsuccessful_run(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        # A run whose semgrep could not start: exit 1, no results, and the
        # invocation says so. It must not read as a clean scan.
        fake = FakeNjsscan(
            sarif_text=(CAPTURED / "errored.sarif").read_text(encoding="utf-8"),
            exit_code=1,
        )
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert _findings(report) == []
        assert report.runs[0].invocations[0].executionSuccessful is False

    def test_the_drivers_name_is_not_the_plugins_name(self):
        document = json.loads((CAPTURED / "positive.sarif").read_text("utf-8"))
        assert document["runs"][0]["tool"]["driver"]["name"] == "nodejsscan"

    def test_every_capture_names_the_pinned_release(self):
        pin = NJSSCAN_DEFAULT_VERSION_CONSTRAINT.removeprefix("==")
        for name in ("positive", "negative", "errored"):
            document = json.loads((CAPTURED / f"{name}.sarif").read_text("utf-8"))
            assert document["runs"][0]["tool"]["driver"]["version"] == pin


class TestDirectExecutionFindsSemgrep:
    """A copy run directly gets its own environment's bin directory on PATH."""

    def test_under_uv_the_environment_is_inherited(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        assert scanner.use_uv_tool is True
        assert scanner._direct_exec_env() is None

    def test_a_direct_copy_puts_the_real_directory_of_the_executable_first(
        self, tree, tmp_path, monkeypatch
    ):
        env_bin = tmp_path / "tool-env" / "bin"
        env_bin.mkdir(parents=True)
        real = env_bin / "njsscan"
        real.write_text("#!/bin/sh\n")
        link_dir = tmp_path / "linked"
        link_dir.mkdir()
        (link_dir / "njsscan").symlink_to(real)
        monkeypatch.setattr(ns.shutil, "which", lambda name: str(link_dir / "njsscan"))
        monkeypatch.setenv("PATH", f"{link_dir}{os.pathsep}/usr/bin")
        scanner = _scanner(tree, tmp_path)
        scanner.use_uv_tool = False
        env = scanner._direct_exec_env()
        assert env is not None
        assert env["PATH"].split(os.pathsep)[0] == env_bin.resolve().as_posix()
        assert link_dir.as_posix() in env["PATH"].split(os.pathsep)

    def test_an_executable_that_cannot_be_found_leaves_the_environment_alone(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ns.shutil, "which", lambda name: None)
        scanner = _scanner(tree, tmp_path)
        scanner.use_uv_tool = False
        assert scanner._direct_exec_env() is None

    def test_the_scan_hands_that_environment_to_the_subprocess(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.use_uv_tool = False
        marker = {"PATH": "/marker/bin"}
        monkeypatch.setattr(scanner, "_direct_exec_env", lambda: marker)
        fake = FakeNjsscan()
        _run(scanner, fake, monkeypatch)
        assert fake.calls[0]["env"] == marker
