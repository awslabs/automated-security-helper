# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""OsvScannerScanner: argv, severity mapping, the offline skip and failure handling.

The hand-written SARIF below has the shape the OSV-Scanner documentation shows (one
rule per advisory, one result per vulnerable package, ``level: warning``); it drives the
mapping cases a single real report cannot reach. The real OSV-Scanner v2.7.1 report in
``tests/test_data/scanners/osv-scanner/captured`` is read by ``TestCapturedReport``. The
scan() tests replace the subprocess with a fake, so they run on every platform without
the binary.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_osv_scanner_plugins
from automated_security_helper.plugin_modules.ash_osv_scanner_plugins import (
    osv_scanner_scanner as oss,
)
from automated_security_helper.plugin_modules.ash_osv_scanner_plugins.osv_scanner_scanner import (
    OFFLINE_SKIP_REASON,
    OsvScannerScanner,
    OsvScannerScannerConfig,
    OsvScannerScannerConfigOptions,
    severity_from_score,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    build_scanner_policy,
)

pytestmark = pytest.mark.unit


def _result(rule_id: str, level: Optional[str], uri: str = "package-lock.json") -> dict:
    result: Dict[str, Any] = {
        "ruleId": rule_id,
        "message": {"text": f"Package 'left-pad@1.0.0' is vulnerable to '{rule_id}'"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
    }
    if level is not None:
        result["level"] = level
    return result


def _rule(rule_id: str, score: Optional[str] = None) -> dict:
    rule: Dict[str, Any] = {
        "id": rule_id,
        "shortDescription": {"text": f"{rule_id}: an advisory"},
    }
    if score is not None:
        rule["properties"] = {"security-severity": score}
    return rule


def _sarif(rules: List[dict], results: List[dict]) -> dict:
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "osv-scanner",
                        "informationUri": "https://github.com/google/osv-scanner",
                        "version": "2.7.1",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


#: A warning with no score: the sample in the documentation.
POSITIVE = _sarif(
    [_rule("CVE-2022-24713")], [_result("CVE-2022-24713", "warning", "Cargo.lock")]
)

#: A run that read the lockfile and found nothing.
NEGATIVE = _sarif([], [])


def _findings(report: SarifReport) -> List[tuple]:
    """(ruleId, SARIF level, ASH severity, uri) for every result, in order."""
    out = []
    for r in report.get_all_results():
        loc = r.locations[0].physicalLocation.root
        out.append(
            (
                r.ruleId,
                getattr(r.level, "value", r.level),
                getattr(r.properties, "issue_severity", None),
                loc.artifactLocation.uri,
            )
        )
    return out


class FakeOsv:
    """Stands in for _run_subprocess: records argv, writes the report where argv says."""

    def __init__(
        self,
        report: Optional[Any] = POSITIVE,
        exit_code: int = 1,
        stderr: str = "",
        timed_out: bool = False,
        raw_text: Optional[str] = None,
    ):
        self.report, self.exit_code, self.stderr = report, exit_code, stderr
        self.timed_out, self.raw_text = timed_out, raw_text
        self.calls: List[dict] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            if self.timed_out:
                scanner.exit_code = -9
                return {"timed_out": True}
            out = next(a for a in command if a.startswith("--output-file="))
            path = Path(out.split("=", 1)[1])
            if self.raw_text is not None:
                path.write_text(self.raw_text)
            elif self.report is not None:
                path.write_text(json.dumps(self.report))
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": "",
                "stderr": self.stderr,
            }

        return run


def _scanner(source: Path, tmp_path: Path, **options) -> OsvScannerScanner:
    config = get_default_config()
    record_provenance(config, in_tree=[], trusted=AshConfig())
    return OsvScannerScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=OsvScannerScannerConfig(
            enabled=True, options=OsvScannerScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "package-lock.json").write_text("{}\n")
    return src


@pytest.fixture(autouse=True)
def online(monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(oss, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner: OsvScannerScanner, fake: FakeOsv, monkeypatch, **kw):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(scanner.context.source_dir), target_type="source", **kw
    )


class TestAlphaPlugin:
    def test_the_module_exports_the_scanner(self):
        assert ash_osv_scanner_plugins.ASH_SCANNERS == [OsvScannerScanner]
        assert ash_osv_scanner_plugins.ASH_REPORTERS == []

    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert OsvScannerScannerConfig().enabled is True
        assert OsvScannerScannerConfig().name == "osv-scanner"

    def test_class_declarations(self):
        from automated_security_helper.core.enums import OfflineStrategy

        assert OsvScannerScanner.python_only is False
        assert OsvScannerScanner.success_exit_codes == {0, 1, 128}
        assert OsvScannerScanner.sandbox_requirements == SandboxRequirements(
            network=True
        )
        assert OsvScannerScanner.offline_strategy is OfflineStrategy.SKIP_OFFLINE


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeOsv()
        _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        assert argv[:4] == ["osv-scanner", "scan", "source", "--recursive"]
        assert "--format=sarif" in argv
        out = [a for a in argv if a.startswith("--output-file=")]
        assert len(out) == 1
        assert out[0].endswith("/source/osv-scanner.sarif")
        assert argv[-1] == "."
        assert "--offline" not in argv

    def test_every_option_is_one_flag_equals_value_token(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeOsv()
        _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        for flag in ("--format", "--output-file", "--config"):
            assert flag not in argv, f"{flag} must be one --flag=value token"

    def test_an_empty_config_replaces_the_trees_osv_scanner_toml(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "osv-scanner.toml").write_text(
            '[[IgnoredVulns]]\nid = "CVE-2022-24713"\n'
        )
        scanner = _scanner(tree, tmp_path)
        fake = FakeOsv()
        _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        config = [a for a in argv if a.startswith("--config=")]
        assert len(config) == 1
        path = Path(config[0].split("=", 1)[1])
        assert not path.is_relative_to(tree)

    @pytest.mark.parametrize(
        "flag",
        [
            "--offline",
            "--offline-vulnerabilities",
            "--download-offline-databases",
            "--licenses",
            "--call-analysis",
            "--data-source=native",
            "--lockfile",
            "--experimental",
        ],
    )
    def test_flags_that_reach_the_network_or_widen_the_scan_are_never_passed(
        self, flag, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeOsv()
        _run(scanner, fake, monkeypatch)
        assert not any(a.startswith(flag) for a in fake.calls[0]["argv"])

    def test_the_offline_option_skips_the_scanner_before_the_tool_starts(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, offline=True)
        fake = FakeOsv()
        assert _run(scanner, fake, monkeypatch) is False
        assert fake.calls == []
        assert scanner.dependency_unavailable_reason == OFFLINE_SKIP_REASON

    def test_ash_offline_mode_skips_the_scanner_before_the_tool_starts(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        monkeypatch.setenv("ASH_OFFLINE", "true")
        scanner = _scanner(tree, tmp_path)
        fake = FakeOsv()
        assert _run(scanner, fake, monkeypatch) is False
        assert fake.calls == []
        assert scanner.dependency_unavailable_reason == OFFLINE_SKIP_REASON

    def test_online_the_same_scanner_reaches_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        # The control for the two skips above: the default options, ASH online.
        scanner = _scanner(tree, tmp_path)
        fake = FakeOsv()
        _run(scanner, fake, monkeypatch)
        assert len(fake.calls) == 1
        assert scanner.dependency_unavailable_reason is None

    def test_an_empty_target_never_reaches_the_tool(
        self, tmp_path, on_path, monkeypatch
    ):
        empty = tmp_path / "empty"
        empty.mkdir()
        scanner = _scanner(empty, tmp_path)
        fake = FakeOsv()
        monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
        scanner.scan(target=empty, target_type="source")
        assert fake.calls == []

    def test_the_timeout_reaches_the_subprocess(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=123)
        fake = FakeOsv()
        _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 123


class TestReport:
    def test_positive_capture_is_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeOsv(), monkeypatch)
        assert _findings(report) == [
            ("CVE-2022-24713", "warning", "MEDIUM", "Cargo.lock")
        ]
        result = report.get_all_results()[0]
        assert result.kind.value == "fail"
        assert {"sca", "security"} <= set(result.properties.tags)

    def test_negative_control_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path), FakeOsv(report=NEGATIVE, exit_code=0), monkeypatch
        )
        assert report.get_all_results() == []

    @pytest.mark.parametrize(
        "level, severity, written",
        [
            ("error", "HIGH", "error"),
            ("warning", "MEDIUM", "warning"),
            ("note", "LOW", "note"),
            ("none", "INFO", "none"),
            (None, "MEDIUM", "warning"),
        ],
    )
    def test_level_to_severity_and_the_level_agrees(
        self, level, severity, written, tree, tmp_path, on_path, monkeypatch
    ):
        data = _sarif([_rule("GHSA-aaaa")], [_result("GHSA-aaaa", level)])
        report = _run(_scanner(tree, tmp_path), FakeOsv(report=data), monkeypatch)
        (finding,) = _findings(report)
        assert finding[1:3] == (written, severity)

    def test_the_level_table_has_a_row_for_every_sarif_level(self):
        assert set(oss.LEVEL_SEVERITY) == {"error", "warning", "note", "none"}
        assert oss.DEFAULT_SEVERITY == ("MEDIUM", oss.Level.warning)

    @pytest.mark.parametrize(
        "score, severity, level",
        [
            (10.0, "CRITICAL", "error"),
            (9.0, "CRITICAL", "error"),
            (8.9, "HIGH", "error"),
            (7.0, "HIGH", "error"),
            (6.9, "MEDIUM", "warning"),
            (4.0, "MEDIUM", "warning"),
            (3.9, "LOW", "note"),
            (0.1, "LOW", "note"),
            (0.0, "INFO", "none"),
        ],
    )
    def test_score_boundaries(self, score, severity, level):
        got_severity, got_level = severity_from_score(score)
        assert (got_severity, got_level.value) == (severity, level)

    def test_a_rule_score_wins_over_the_results_level(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        data = _sarif(
            [_rule("CVE-2024-0001", "9.8")], [_result("CVE-2024-0001", "warning")]
        )
        report = _run(_scanner(tree, tmp_path), FakeOsv(report=data), monkeypatch)
        assert _findings(report)[0][1:3] == ("error", "CRITICAL")

    def test_an_unreadable_score_falls_back_to_the_level(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        data = _sarif(
            [_rule("CVE-2024-0002", "high")], [_result("CVE-2024-0002", "note")]
        )
        report = _run(_scanner(tree, tmp_path), FakeOsv(report=data), monkeypatch)
        assert _findings(report)[0][1:3] == ("note", "LOW")

    def test_each_result_uses_its_own_rule(self, tree, tmp_path, on_path, monkeypatch):
        data = _sarif(
            [_rule("CVE-A", "9.1"), _rule("CVE-B", "2.0")],
            [_result("CVE-A", "warning"), _result("CVE-B", "warning")],
        )
        report = _run(_scanner(tree, tmp_path), FakeOsv(report=data), monkeypatch)
        assert [f[2] for f in _findings(report)] == ["CRITICAL", "LOW"]


class TestExitStatus:
    @pytest.mark.parametrize("code", [0, 1])
    def test_zero_and_one_succeed(self, code, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeOsv(exit_code=code), monkeypatch)
        assert scanner.exit_code == code

    def test_no_packages_found_is_an_empty_scan_when_no_report_is_written(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeOsv(report=None, exit_code=128), monkeypatch)
        assert report.get_all_results() == []
        assert len(report.runs) == 1

    @pytest.mark.parametrize("code", [2, 126, 127, 129, 137])
    def test_other_codes_fail_even_with_a_report_on_disk(
        self, code, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeOsv(exit_code=code), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeOsv(report=None, exit_code=0), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeOsv(), monkeypatch)
        assert list((tmp_path / "out").rglob("osv-scanner.sarif"))
        # The second run writes nothing; the first run's report must not be read.
        with pytest.raises(ScannerError):
            _run(scanner, FakeOsv(report=None, exit_code=0), monkeypatch)

    def test_stderr_is_not_copied_into_errors_or_the_failure_message(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        secret_text = "path/to/tree/secret-name.lock"
        with pytest.raises(ScannerError) as err:
            _run(scanner, FakeOsv(exit_code=127, stderr=secret_text), monkeypatch)
        assert secret_text not in str(err.value)
        assert secret_text not in " ".join(scanner.errors or [])

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=5)
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, FakeOsv(timed_out=True), monkeypatch)


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "raw",
        [
            "not json",
            "[1, 2, 3]",
            '{"version": "2.1.0"}',
            '{"runs": "nope"}',
        ],
    )
    def test_unreadable_or_gradeless_reports_fail_the_scan(
        self, raw, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeOsv(raw_text=raw, exit_code=1), monkeypatch)

    def test_a_zero_byte_report_after_an_accepted_code_is_an_empty_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeOsv(raw_text="", exit_code=0), monkeypatch)
        assert report.get_all_results() == []


class TestDependencyCheck:
    def test_missing_binary(self, tmp_path, monkeypatch):
        monkeypatch.setattr(oss, "find_executable", lambda cmd: None)
        assert _scanner(tmp_path, tmp_path).validate_plugin_dependencies() is False

    def test_present_binary(self, tmp_path, monkeypatch):
        monkeypatch.setattr(oss, "find_executable", lambda cmd: "/fake/bin/osv-scanner")
        assert _scanner(tmp_path, tmp_path).validate_plugin_dependencies() is True

    def test_an_unavailable_dependency_wins_over_the_path(self, tmp_path, monkeypatch):
        monkeypatch.setattr(oss, "find_executable", lambda cmd: "/fake/bin/osv-scanner")
        scanner = _scanner(tmp_path, tmp_path)
        scanner.dependency_unavailable_reason = "unsupported platform"
        assert scanner.validate_plugin_dependencies() is False


def test_the_sample_report_is_valid_sarif():
    SarifReport.model_validate(copy.deepcopy(POSITIVE))


# ---------------------------------------------------------------------------
# A real OSV-Scanner 2.7.1 report (tests/test_data/scanners/osv-scanner/captured)
# ---------------------------------------------------------------------------

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "osv-scanner"
    / "captured"
    / "positive.sarif"
)
CAPTURED_ROOT = "/tmp/ash-osv-fixture-lane/pos"


class TestCapturedReport:
    def test_the_capture_is_what_the_readme_says(self):
        data = json.loads(CAPTURED.read_text(encoding="utf-8"))
        run = data["runs"][0]
        assert run["tool"]["driver"]["version"] == "2.7.1"
        assert len(run["results"]) == 5
        assert {r["level"] for r in run["results"]} == {"warning"}
        assert all("region" not in json.dumps(r["locations"]) for r in run["results"])

    def test_every_result_is_rated_from_its_rule_score_and_the_level_agrees(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        data = json.loads(CAPTURED.read_text(encoding="utf-8"))
        scores = {
            rule["id"]: float(rule["properties"]["security-severity"])
            for rule in data["runs"][0]["tool"]["driver"]["rules"]
        }
        fake = FakeOsv(raw_text=CAPTURED.read_text(encoding="utf-8"))
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        results = report.get_all_results()
        assert len(results) == 5
        for result in results:
            severity, level = severity_from_score(scores[result.ruleId])
            assert result.properties.issue_severity == severity
            assert result.level == level
            assert result.kind.value == "fail"

    def test_an_absolute_uri_under_the_target_becomes_target_relative(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        text = CAPTURED.read_text(encoding="utf-8").replace(CAPTURED_ROOT, str(tree))
        report = _run(_scanner(tree, tmp_path), FakeOsv(raw_text=text), monkeypatch)
        assert {f[3] for f in _findings(report)} == {"package-lock.json"}

    def test_an_absolute_uri_outside_the_target_is_left_as_written(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        text = CAPTURED.read_text(encoding="utf-8")
        report = _run(_scanner(tree, tmp_path), FakeOsv(raw_text=text), monkeypatch)
        assert {f[3] for f in _findings(report)} == {
            f"file://{CAPTURED_ROOT}/package-lock.json"
        }

    def test_no_packages_found_writes_no_report_and_is_an_empty_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        # The capture session: a lockfile with no dependencies exited 128 and the
        # tool wrote no report file.
        report = _run(
            _scanner(tree, tmp_path), FakeOsv(report=None, exit_code=128), monkeypatch
        )
        assert report.get_all_results() == []


class TestInstallCommands:
    def test_the_scanner_installs_from_the_module_local_pin(
        self, tmp_path, monkeypatch
    ):
        from automated_security_helper.plugin_modules.ash_osv_scanner_plugins import (
            osv_scanner_install,
        )
        from automated_security_helper.utils import tool_downloads

        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        scanner = _scanner(tmp_path, tmp_path)
        # The shared table has no osv-scanner row; the module's own table serves.
        assert "osv-scanner" not in tool_downloads.downloadable_tools()
        pairs = {
            (platform, arch)
            for platform, arches in scanner.custom_install_commands.items()
            for arch in arches
        }
        assert pairs == set(osv_scanner_install.ASSETS)
        for arches in scanner.custom_install_commands.values():
            for commands in arches.values():
                (command,) = commands
                assert command.shell is False
                assert "install_osv_scanner" in " ".join(command.args)

    def test_the_missing_binary_hint_names_the_install_command(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(oss, "find_executable", lambda cmd: None)
        seen: List[str] = []
        monkeypatch.setattr(
            oss.ASH_LOGGER, "warning", lambda msg, *a, **k: seen.append(msg)
        )
        scanner = _scanner(tmp_path, tmp_path)
        assert scanner.validate_plugin_dependencies() is False
        (message,) = seen
        assert "ash dependencies install" in message
        # --tool takes the scanner's name (here the executable's name too).
        assert "--tool osv-scanner`" in message


class TestSandboxPolicy:
    def test_the_declared_network_reaches_the_built_policy(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        source = tmp_path / "src"
        source.mkdir()
        output = source / ".ash" / "ash_output"
        output.mkdir(parents=True)

        def policy(requirements, offline):
            return build_scanner_policy(
                "osv-scanner",
                requirements,
                argv0=sys.executable,
                source_dir=source,
                output_dir=output,
                results_dir=output / "scanners" / "osv-scanner",
                scan_target=source,
                cwd=source,
                offline=offline,
                network_scanners=None,
            )

        declared = OsvScannerScanner.sandbox_requirements
        assert declared == SandboxRequirements(network=True)
        assert policy(declared, offline=False).network is True
        # The sandbox never grants a network under ASH's offline mode.
        assert policy(declared, offline=True).network is False
        assert policy(SandboxRequirements(), offline=False).network is False
