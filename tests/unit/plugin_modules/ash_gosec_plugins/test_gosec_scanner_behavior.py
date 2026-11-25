# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""GosecScanner: the invocation, exit status handling, severity and failure cases.

The report the scan() tests read is a capture of a real gosec v2.30.0 run
(``tests/test_data/scanners/gosec/captured/``; its README gives the argv, version and
inputs). Its expected findings are written out below by hand from that capture, not
derived from the code under test. The synthetic SARIF helpers build only the edge
cases a capture cannot hold (a rule whose tag cannot be read, a malformed report).
The scan() tests replace the subprocess with a fake, so they run on every platform
without gosec or the Go toolchain.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_gosec_plugins
from automated_security_helper.plugin_modules.ash_gosec_plugins import (
    gosec_scanner as gs,
)
from automated_security_helper.plugin_modules.ash_gosec_plugins.gosec_scanner import (
    GosecScanner,
    GosecScannerConfig,
    GosecScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.tool_downloads import downloadable_tools

pytestmark = pytest.mark.unit


def _rule(rule_id: str, severity: str) -> Dict[str, Any]:
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": f"{rule_id} description"},
        "properties": {"tags": ["security", severity], "precision": "high"},
    }


def _result(rule_id: str, level: str, uri: str, line: int) -> Dict[str, Any]:
    return {
        "ruleId": rule_id,
        "ruleIndex": 0,
        "level": level,
        "message": {"text": f"{rule_id} finding"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": line,
                        "endLine": line,
                        "startColumn": 1,
                        "endColumn": 10,
                        "snippet": {"text": "code"},
                    },
                }
            }
        ],
    }


def _sarif(rules: List[Dict[str, Any]], results: List[Dict[str, Any]]) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "gosec",
                            "version": "v2.30.0",
                            "semanticVersion": "2.30.0",
                            "informationUri": "https://github.com/securego/gosec/",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }
    )


FIXTURES = Path(__file__).resolve().parents[3] / "test_data" / "scanners" / "gosec"
CAPTURED = FIXTURES / "captured"

#: A real gosec v2.30.0 report over FIXTURES/positive: G402 TLS InsecureSkipVerify
#: (rule tag HIGH, native level error), G304 file inclusion via variable (MEDIUM,
#: error), G104 unhandled error (LOW, warning), in gosec's own result order.
POSITIVE = (CAPTURED / "positive.sarif").read_text(encoding="utf-8")
#: A real gosec v2.30.0 report over FIXTURES/negative: no results, exit 0.
NEGATIVE = (CAPTURED / "negative.sarif").read_text(encoding="utf-8")

#: What POSITIVE must produce: (ruleId, SARIF level, ASH severity, uri, line).
#: The ASH level is set from the severity, so G304 (error natively) becomes warning.
POSITIVE_EXPECTED = [
    ("G402", "error", "HIGH", "pkg/client.go", 12),
    ("G304", "warning", "MEDIUM", "pkg/util.go", 7),
    ("G104", "note", "LOW", "pkg/util.go", 14),
]

#: The native levels in the capture, written from reading it: what gosec itself says
#: before the adapter rates each result.
POSITIVE_NATIVE_LEVELS = {"G402": "error", "G304": "error", "G104": "warning"}


def _findings(report: SarifReport) -> List[tuple]:
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


class FakeGosec:
    """Stands in for _run_subprocess: records argv, writes the report where -out says."""

    def __init__(
        self,
        sarif_text: Optional[str] = POSITIVE,
        exit_code: int = 1,
        stderr: str = "",
        timed_out: bool = False,
    ):
        self.sarif_text, self.exit_code = sarif_text, exit_code
        self.stderr, self.timed_out = stderr, timed_out
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            if self.timed_out:
                scanner.exit_code = -9
                return {"returncode": -9, "stdout": "", "stderr": "", "timed_out": True}
            out_arg = next(a for a in command if a.startswith("-out="))
            path = Path(out_arg.split("=", 1)[1])
            if self.sarif_text is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(self.sarif_text, encoding="utf-8")
            scanner.exit_code = self.exit_code
            return {"returncode": self.exit_code, "stdout": "", "stderr": self.stderr}

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(source: Path, tmp_path: Path, **options) -> GosecScanner:
    output = tmp_path / "out"
    return GosecScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=GosecScannerConfig(
            enabled=True, options=GosecScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "pkg").mkdir(parents=True)
    (src / "go.mod").write_text("module example.com/demo\n\ngo 1.22\n")
    (src / "main.go").write_text("package main\n\nfunc main() {}\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(gs, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch, target=None, target_type="source"):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert GosecScannerConfig().enabled is True
        assert GosecScannerConfig().name == "gosec"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "gosec")

    def test_the_module_exports_the_scanner(self):
        assert ash_gosec_plugins.ASH_SCANNERS == [GosecScanner]
        assert ash_gosec_plugins.ASH_REPORTERS == []

    def test_declared_class_variables(self):
        assert GosecScanner.python_only is False
        assert GosecScanner.success_exit_codes == {0, 1}
        assert GosecScanner.sandbox_requirements == SandboxRequirements()


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeGosec()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[0] == "gosec"
        assert "-fmt=sarif" in argv
        assert "-nosec=true" in argv
        assert any(a.startswith("-out=") and a.endswith("gosec.sarif") for a in argv)
        # "--" ends flag parsing; the source target is ./... from the source dir.
        assert argv[-2:] == ["--", "./..."]

    def test_tests_are_scanned_only_when_asked(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        off = FakeGosec()
        _run(_scanner(tree, tmp_path), off, monkeypatch)
        assert not any(a.startswith("-tests") for a in off.argv)
        on = FakeGosec()
        _run(_scanner(tree, tmp_path, include_tests=True), on, monkeypatch)
        assert "-tests=true" in on.argv

    @pytest.mark.parametrize(
        "flag", ["-conf", "-no-fail", "-nosec=false", "-ai-api-key", "-ai-api-provider"]
    )
    def test_flags_that_read_config_hide_findings_or_reach_the_network_are_not_passed(
        self, tree, tmp_path, on_path, monkeypatch, flag
    ):
        fake = FakeGosec()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert not any(a == flag or a.startswith(flag + "=") for a in fake.argv)

    def test_the_converted_target_is_scanned_by_absolute_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "converted"
        converted.mkdir()
        (converted / "x.go").write_text("package x\n")
        fake = FakeGosec()
        _run(
            _scanner(tree, tmp_path),
            fake,
            monkeypatch,
            target=converted,
            target_type="converted",
        )
        assert fake.argv[-2:] == ["--", converted.absolute().as_posix() + "/..."]


class TestReport:
    def test_positive_report_is_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeGosec(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_is_clean(self, tree, tmp_path, on_path, monkeypatch):
        report = _run(
            _scanner(tree, tmp_path),
            FakeGosec(sarif_text=NEGATIVE, exit_code=0),
            monkeypatch,
        )
        assert _findings(report) == []

    def test_the_capture_holds_every_severity_the_mapping_names(self):
        """The oracle is not trivially one-sided: all three native tags are present."""
        run = json.loads(POSITIVE)["runs"][0]
        tags = {
            rule["id"]: [t for t in rule["properties"]["tags"] if t != "security"]
            for rule in run["tool"]["driver"]["rules"]
        }
        assert tags == {"G104": ["LOW"], "G304": ["MEDIUM"], "G402": ["HIGH"]}
        native = {r["ruleId"]: r["level"] for r in run["results"]}
        assert native == POSITIVE_NATIVE_LEVELS

    def test_severity_rows_over_the_captured_report(self):
        """Each captured result: native level and rule tag in, ASH severity out."""
        report = SarifReport.model_validate(json.loads(POSITIVE))
        rule_severities = gs._rule_severities(report)
        assert rule_severities == {"G104": "LOW", "G304": "MEDIUM", "G402": "HIGH"}
        rated = {
            str(r.ruleId): gs.severity_for(r.level, rule_severities.get(str(r.ruleId)))
            for r in report.get_all_results()
        }
        assert rated == {"G402": "HIGH", "G304": "MEDIUM", "G104": "LOW"}

    def test_an_error_whose_rule_tag_cannot_be_read_is_high(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        rule = _rule("G999", "UNRATED")
        sarif = _sarif([rule], [_result("G999", "error", "main.go", 3)])
        report = _run(
            _scanner(tree, tmp_path), FakeGosec(sarif_text=sarif), monkeypatch
        )
        assert _findings(report) == [("G999", "error", "HIGH", "main.go", 3)]

    def test_every_result_is_a_failure_tagged_security(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeGosec(), monkeypatch)
        for result in report.get_all_results():
            assert getattr(result.kind, "value", result.kind) == "fail"
            assert "security" in result.properties.tags

    @pytest.mark.parametrize(
        "level,rule_severity,expected",
        [
            ("warning", "LOW", "LOW"),
            ("error", "MEDIUM", "MEDIUM"),
            ("error", "HIGH", "HIGH"),
            # error with a rule tag that cannot say which: the more severe reading.
            ("error", "LOW", "HIGH"),
            ("error", None, "HIGH"),
            ("note", None, "LOW"),
        ],
    )
    def test_severity_rows(self, level, rule_severity, expected):
        assert gs.severity_for(level, rule_severity) == expected

    def test_level_and_severity_agree_for_every_result(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeGosec(), monkeypatch)
        for _, level, severity, _, _ in _findings(report):
            assert gs.GOSEC_LEVEL_MAP[severity].value == level

    def test_the_report_round_trips_as_sarif(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeGosec(), monkeypatch)
        assert SarifReport.model_validate(json.loads(report.model_dump_json()))


class TestExitStatus:
    def test_one_with_findings_is_a_success(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeGosec(exit_code=1), monkeypatch)
        assert scanner._exit_code_accepted()

    def test_zero_is_a_success(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeGosec(sarif_text=NEGATIVE, exit_code=0), monkeypatch)
        assert scanner._exit_code_accepted()

    def test_one_with_no_findings_is_a_processing_error_not_a_clean_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakeGosec(sarif_text=NEGATIVE, exit_code=1),
                monkeypatch,
            )

    @pytest.mark.parametrize("code", [2, 126, 137])
    def test_any_other_exit_fails_even_with_a_report_on_disk(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), FakeGosec(exit_code=code), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakeGosec(sarif_text=None, exit_code=0),
                monkeypatch,
            )

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        first = FakeGosec()
        _run(scanner, first, monkeypatch)
        report = Path(
            next(a for a in first.argv if a.startswith("-out=")).split("=", 1)[1]
        )
        assert report.exists()
        with pytest.raises(ScannerError):
            _run(scanner, FakeGosec(sarif_text=None, exit_code=0), monkeypatch)

    def test_a_timeout_fails_the_scan(self, tree, tmp_path, on_path, monkeypatch):
        fake = FakeGosec(timed_out=True)
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert len(fake.calls) == 1

    def test_the_scan_timeout_reaches_the_subprocess(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=321)
        fake = FakeGosec()
        _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 321

    def test_a_timeout_failure_names_the_timeout(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError, match="(?i)timed out"):
            _run(
                _scanner(tree, tmp_path, scan_timeout=321),
                FakeGosec(timed_out=True),
                monkeypatch,
            )

    def test_stderr_is_not_copied_into_errors(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeGosec(stderr="QUOTED-SOURCE-LINE"), monkeypatch)
        assert "QUOTED-SOURCE-LINE" not in " ".join(map(str, scanner.errors))


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "text",
        [
            "not json at all",
            "[1, 2, 3]",
            "{}",
            '{"version": "2.1.0", "runs": "nope"}',
        ],
    )
    def test_output_that_is_not_a_sarif_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch, text
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakeGosec(sarif_text=text, exit_code=1),
                monkeypatch,
            )

    def test_an_empty_report_file_does_not_pass_as_clean(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakeGosec(sarif_text="", exit_code=0),
                monkeypatch,
            )


class TestDependencyCheck:
    def test_a_missing_gosec_is_unsatisfied(self, tree, tmp_path, monkeypatch):
        monkeypatch.setattr(gs, "find_executable", lambda cmd: None)
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is False

    def test_gosec_without_the_go_toolchain_is_unsatisfied(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            gs, "find_executable", lambda cmd: "/fake/gosec" if cmd == "gosec" else None
        )
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is False

    def test_both_present_satisfies_them(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True


PLATFORMS = [
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("darwin", "amd64"),
    ("darwin", "arm64"),
    ("windows", "amd64"),
    ("windows", "arm64"),
]


class TestInstall:
    def test_without_a_registered_pin_the_scanner_still_constructs_and_installs_nothing(
        self, tmp_path, monkeypatch
    ):
        """The shared pin table may not know gosec yet; that must not raise."""
        monkeypatch.setattr(gs, "downloadable_tools", list)
        scanner = _scanner(tmp_path, tmp_path)
        for platform, arch in PLATFORMS:
            assert scanner.get_installation_commands(platform, arch) == []

    def test_a_registered_pin_gives_every_published_platform_a_command(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(gs, "downloadable_tools", lambda: ["gosec"])
        seen = []

        def fake_pinned(tool):
            seen.append(tool)
            table: dict = {}
            for p, a in PLATFORMS:
                table.setdefault(p, {})[a] = [
                    CustomCommand(args=["install", tool, p, a], shell=False)
                ]
            return table

        monkeypatch.setattr(gs, "pinned_tool_install_commands", fake_pinned)
        scanner = _scanner(tmp_path, tmp_path)
        assert seen == ["gosec"]
        for platform, arch in PLATFORMS:
            commands = scanner.get_installation_commands(platform, arch)
            assert commands, f"no install command for {platform}/{arch}"
            assert commands[0].args == ["install", "gosec", platform, arch]

    @pytest.mark.skipif(
        "gosec" not in downloadable_tools(),
        reason="the gosec pin in utils/tool_downloads.py is registered by the "
        "integration change; this row runs once it is",
    )
    def test_the_real_pin_installs_on_every_published_platform(self, tmp_path):
        scanner = _scanner(tmp_path, tmp_path)
        for platform, arch in PLATFORMS:
            commands = scanner.get_installation_commands(platform, arch)
            assert commands, f"no install command for {platform}/{arch}"
            assert "gosec" in commands[0].args

    def test_the_hint_when_gosec_is_missing_matches_the_pin_state(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(gs, "find_executable", lambda cmd: None)
        warnings = []
        monkeypatch.setattr(gs.ASH_LOGGER, "warning", warnings.append)
        monkeypatch.setattr(gs, "downloadable_tools", list)
        assert _scanner(tmp_path, tmp_path).validate_plugin_dependencies() is False
        assert "pins no gosec release" in warnings[-1]
        monkeypatch.setattr(gs, "downloadable_tools", lambda: ["gosec"])
        monkeypatch.setattr(gs, "pinned_tool_install_commands", lambda tool: {})
        assert _scanner(tmp_path, tmp_path).validate_plugin_dependencies() is False
        assert "ash dependencies install" in warnings[-1]


class TestDeclarations:
    def test_the_facet_rows_name_the_tool_the_scanner_runs(self):
        ops = vars(GosecScanner)["operational_facets"]
        assert ops.scanner_name == GosecScannerConfig().name == "gosec"
        assert ops.runtime.tool_versions_key == gs.GOSEC_TOOL_NAME
        assert ops.exit_codes.success_exit_codes == tuple(
            sorted(GosecScanner.success_exit_codes)
        )
        assert vars(GosecScanner)["facets"].rule_id.state.value == "mapped"

    def test_the_captured_native_report_is_sarif(self):
        document = json.loads(POSITIVE)
        assert document["version"].startswith("2.1") and "runs" in document
