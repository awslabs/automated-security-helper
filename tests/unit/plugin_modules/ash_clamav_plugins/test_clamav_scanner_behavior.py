# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ClamAVScanner: the invocation, the log parser, severity and failure handling.

The log texts below follow the output ClamAV documents and implements
(clamscan/manager.c and clamscan/clamscan.c: ``<path>: <signature> FOUND``,
``<path>: <message> ERROR``, and the SCAN SUMMARY block). They were written from that
source, not captured from a clamscan binary, so they run on every platform. The scan()
tests replace the subprocess with a fake that writes the log where ``--log=`` says.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_clamav_plugins
from automated_security_helper.plugin_modules.ash_clamav_plugins import (
    clamav_scanner as cs,
)
from automated_security_helper.plugin_modules.ash_clamav_plugins.clamav_scanner import (
    ClamAVScanner,
    ClamAVScannerConfig,
    ClamAVScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

SUMMARY = """
----------- SCAN SUMMARY -----------
Known viruses: 8700000
Engine version: 1.4.2
Scanned directories: 2
Scanned files: 3
Infected files: {infected}
Data scanned: 0.00 MB
Time: 12.345 sec (0 m 12 s)
Start Date: 2026:11:18 10:00:00
End Date:   2026:11:18 10:00:12
"""

FIXTURES = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "clamav"
    / "documented"
)
# Two detections, one of them in a path that itself contains ": ".
POSITIVE = (FIXTURES / "positive.log").read_text(encoding="utf-8")
NEGATIVE = (FIXTURES / "negative.log").read_text(encoding="utf-8")

POSITIVE_EXPECTED = [
    ("Win.Test.EICAR_HDB-1", "error", "HIGH", "dropper/eicar.com", 1),
    ("Unix.Trojan.Agent-123", "error", "HIGH", "odd: name/payload.bin", 1),
]


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


class FakeClamscan:
    """Stands in for _run_subprocess: records argv, writes a log where --log= says."""

    def __init__(self, log: Optional[str] = POSITIVE, exit_code: int = 1):
        self.log, self.exit_code = log, exit_code
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            arg = next(a for a in command if a.startswith("--log="))
            path = Path(arg.split("=", 1)[1])
            if self.log is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(self.log, encoding="utf-8")
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": "",
                "stderr": "./secret-name.txt: Access denied ERROR",
            }

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(source: Path, tmp_path: Path) -> ClamAVScanner:
    output = tmp_path / "out"
    return ClamAVScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=ClamAVScannerConfig(enabled=True, options=ClamAVScannerConfigOptions()),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("print(1)\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(cs, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch, target=None, target_type="source"):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


class TestCommunityPlugin:
    def test_on_by_default_once_the_module_is_listed(self):
        assert ClamAVScannerConfig().enabled is True
        assert ClamAVScannerConfig().name == "clamav"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "clamav")

    def test_the_module_exports_the_scanner(self):
        assert ash_clamav_plugins.ASH_SCANNERS == [ClamAVScanner]
        assert ash_clamav_plugins.ASH_REPORTERS == []

    def test_class_declarations(self):
        assert ClamAVScanner.python_only is False
        assert ClamAVScanner.success_exit_codes == {0, 1}


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        fake = FakeClamscan()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        argv = fake.argv
        assert argv[0] == "clamscan"
        assert "--recursive" in argv
        assert "--follow-dir-symlinks=0" in argv
        assert "--follow-file-symlinks=0" in argv
        assert any(
            a.startswith("--log=") and a.endswith("/source/clamav.log") for a in argv
        )
        assert argv[-1] == "."
        assert "--" not in argv

    def test_the_subprocess_runs_in_the_source_directory(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        # cwd None means PluginBase._run_subprocess uses the source directory,
        # which is what makes the "." scan path report source-relative URIs.
        fake = FakeClamscan()
        scanner = _scanner(tree, tmp_path)
        _run(scanner, fake, monkeypatch)
        assert fake.calls[0]["cwd"] is None
        assert scanner._subprocess_cwd(tmp_path) is None

    @pytest.mark.parametrize(
        "flag",
        [
            "--database",
            "--move",
            "--copy",
            "--remove",
            "--file-list",
            "--include",
            "--exclude",
        ],
    )
    def test_flags_that_change_the_tree_or_choose_the_database_are_never_passed(
        self, flag, tree, tmp_path, monkeypatch, on_path
    ):
        fake = FakeClamscan()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert not any(a == flag or a.startswith(flag + "=") for a in fake.argv)

    def test_a_converted_target_is_an_absolute_path(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        converted = tmp_path / "conv"
        converted.mkdir()
        (converted / "a.txt").write_text("x\n")
        fake = FakeClamscan(log=NEGATIVE, exit_code=0)
        _run(_scanner(tree, tmp_path), fake, monkeypatch, converted, "converted")
        assert fake.argv[-1] == converted.absolute().as_posix()

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        fake = FakeClamscan()
        _run(_scanner(tree, tmp_path), fake, monkeypatch, tmp_path / "nope")
        assert fake.calls == []


class TestReport:
    def test_happy_path_findings_are_rated_and_located(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        report = _run(_scanner(tree, tmp_path), FakeClamscan(), monkeypatch)
        assert isinstance(report, SarifReport)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_is_clean(self, tree, tmp_path, monkeypatch, on_path):
        report = _run(_scanner(tree, tmp_path), FakeClamscan(NEGATIVE, 0), monkeypatch)
        assert isinstance(report, SarifReport)
        assert _findings(report) == []

    def test_tags_and_engine_version(self, tree, tmp_path, monkeypatch, on_path):
        report = _run(_scanner(tree, tmp_path), FakeClamscan(), monkeypatch)
        for r in report.get_all_results():
            assert {"malware", "security"} <= set(r.properties.tags)
        assert report.runs[0].tool.driver.name == "ClamAV"

    def test_results_under_ashs_output_directory_are_dropped(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        log = (
            "./.ash/ash_output/converted/x.py: Win.Test.EICAR_HDB-1 FOUND\n"
            "./real.bin: Win.Test.EICAR_HDB-1 FOUND\n"
        ) + SUMMARY.format(infected=2)
        scanner = _scanner(tree, tmp_path)
        scanner.context.output_dir = tree / ".ash" / "ash_output"
        report = _run(scanner, FakeClamscan(log), monkeypatch)
        assert [f[3] for f in _findings(report)] == ["real.bin"]

    @pytest.mark.parametrize(
        "level_text",
        ["Win.Test.EICAR_HDB-1", "PUA.Win.Packer.UPX-1", "Eicar-Signature"],
    )
    def test_every_signature_is_high_and_error(
        self, level_text, tree, tmp_path, monkeypatch, on_path
    ):
        log = f"./f: {level_text} FOUND\n" + SUMMARY.format(infected=1)
        report = _run(_scanner(tree, tmp_path), FakeClamscan(log), monkeypatch)
        assert _findings(report) == [(level_text, "error", "HIGH", "f", 1)]


class TestParser:
    def test_error_lines_are_counted_not_reported_as_findings(self):
        text = "./a: Access denied ERROR\n./b: OK\n" + SUMMARY.format(infected=0)
        parsed = cs.parse_clamscan_log(text)
        assert parsed["errors"] == 1
        assert parsed["detections"] == []
        assert parsed["engine"] == "1.4.2"

    @pytest.mark.parametrize(
        "text",
        [
            "./a: Sig FOUND\n",  # no summary: the scan did not finish
            "./a: OK\n----------- SCAN SUMMARY -----------\nKnown viruses: 1\n",
            "garbage that is not a clamscan log\n",
            "./a: Sig FOUND\n" + SUMMARY.format(infected=0),  # counts disagree
            "./a: OK\n" + SUMMARY.format(infected=3),  # counts disagree
        ],
    )
    def test_malformed_logs_raise(self, text):
        with pytest.raises(ScannerError):
            cs.parse_clamscan_log(text)

    def test_a_malformed_log_fails_the_scan(self, tree, tmp_path, monkeypatch, on_path):
        fake = FakeClamscan(log="not a clamscan log\n", exit_code=0)
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)

    def test_an_empty_log_fails_the_scan(self, tree, tmp_path, monkeypatch, on_path):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path), FakeClamscan(log="", exit_code=0), monkeypatch
            )


class TestExitStatus:
    def test_zero_and_one_succeed(self, tree, tmp_path, monkeypatch, on_path):
        for log, code in ((NEGATIVE, 0), (POSITIVE, 1)):
            report = _run(
                _scanner(tree, tmp_path), FakeClamscan(log, code), monkeypatch
            )
            assert isinstance(report, SarifReport)

    @pytest.mark.parametrize("code", [2, 126, 127, 137])
    def test_other_codes_fail_even_with_a_log_on_disk(
        self, code, tree, tmp_path, monkeypatch, on_path
    ):
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), FakeClamscan(POSITIVE, code), monkeypatch)

    def test_no_log_written_fails_the_scan(self, tree, tmp_path, monkeypatch, on_path):
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), FakeClamscan(None, 0), monkeypatch)

    def test_a_log_left_by_an_earlier_run_is_removed(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.results_dir = tmp_path / "results"
        stale = scanner.results_dir / "source" / "clamav.log"
        stale.parent.mkdir(parents=True)
        stale.write_text(POSITIVE)
        scanner._execute_scan(tree, "source", [])
        assert not stale.exists()

    def test_stderr_is_not_copied_into_errors(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        """Through the real fold, not through the fake subprocess.

        The fake replaces ``_run_subprocess`` wholesale, so the response the base
        class folds is built here by hand and passed to the method under test.
        """
        scanner = _scanner(tree, tmp_path)
        scanner._process_command_response(
            {"returncode": 2, "stdout": "", "stderr": "./secret-name.txt: denied ERROR"}
        )
        assert scanner.exit_code == 2
        assert not any("secret-name" in e for e in scanner.errors)

    def test_the_planted_control_quoting_does_copy_stderr(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        """The same call with quoting on does copy it, so the test above can fail."""
        monkeypatch.setattr(ClamAVScanner, "quote_tool_stderr", True)
        scanner = _scanner(tree, tmp_path)
        scanner._process_command_response(
            {"returncode": 2, "stdout": "", "stderr": "./secret-name.txt: denied ERROR"}
        )
        assert any("secret-name" in e for e in scanner.errors)

    def test_the_declaration_keeps_the_stream_out(self):
        assert ClamAVScanner.quote_tool_stderr is False


class TestTimeout:
    def test_the_timeout_reaches_the_subprocess(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        fake = FakeClamscan()
        scanner = _scanner(tree, tmp_path)
        _run(scanner, fake, monkeypatch)
        timeout = fake.calls[0]["timeout"]
        assert (
            timeout is not None and 0 < timeout <= scanner.config.options.scan_timeout
        )

    def test_a_timed_out_run_fails_the_scan(self, tree, tmp_path, monkeypatch, on_path):
        scanner = _scanner(tree, tmp_path)

        def timed_out(command, **_):
            scanner.exit_code = 124
            return {"returncode": 124, "stdout": "", "stderr": "", "timed_out": True}

        monkeypatch.setattr(scanner, "_run_subprocess", timed_out)
        with pytest.raises(ScannerError):
            scanner.scan(target=tree, target_type="source")


class TestDependencyCheck:
    def test_tool_absent_is_reported_with_the_install_hint(self, monkeypatch, caplog):
        monkeypatch.setattr(cs, "find_executable", lambda cmd: None)
        warnings: List[str] = []
        monkeypatch.setattr(
            cs.ASH_LOGGER, "warning", lambda m, *a, **k: warnings.append(m)
        )
        scanner = ClamAVScanner()
        assert scanner.validate_plugin_dependencies() is False
        assert any("freshclam" in w and "clamscan" in w for w in warnings)

    def test_tool_present(self, monkeypatch):
        monkeypatch.setattr(cs, "find_executable", lambda cmd: "/usr/bin/" + cmd)
        assert ClamAVScanner().validate_plugin_dependencies() is True

    def test_an_unavailable_reason_wins(self, monkeypatch):
        monkeypatch.setattr(cs, "find_executable", lambda cmd: "/usr/bin/" + cmd)
        scanner = ClamAVScanner()
        scanner.dependency_unavailable_reason = "refused"
        assert scanner.validate_plugin_dependencies() is False

    def test_a_missing_tool_never_runs_the_scan(self, tree, tmp_path, monkeypatch):
        monkeypatch.setattr(cs, "find_executable", lambda cmd: None)
        fake = FakeClamscan()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert fake.calls == []


class TestDatabaseAge:
    def test_no_database_is_none(self, tmp_path):
        assert cs.database_age_days((str(tmp_path),)) is None

    def test_age_of_the_newest_daily_file(self, tmp_path):
        import os
        import time

        f = tmp_path / "daily.cvd"
        f.write_text("x")
        old = time.time() - 10 * 86400
        os.utime(f, (old, old))
        age = cs.database_age_days((str(tmp_path),))
        assert age is not None and 9.9 < age < 10.1

    def test_a_stale_database_is_noted_at_info_and_scan_goes_on(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        monkeypatch.setattr(cs, "database_age_days", lambda: 30.0)
        scanner = _scanner(tree, tmp_path)
        notes: List[str] = []
        monkeypatch.setattr(
            scanner,
            "_plugin_log",
            lambda msg, *a, **k: notes.append(msg),
        )
        report = _run(scanner, FakeClamscan(NEGATIVE, 0), monkeypatch)
        assert isinstance(report, SarifReport)
        assert any("30 days old" in n for n in notes)


class TestSandboxDeclaration:
    def test_strict_default(self):
        from automated_security_helper.utils.sandbox.policy import SandboxRequirements

        assert ClamAVScanner.sandbox_requirements == SandboxRequirements()


class TestRegisterRows:
    def test_both_register_rows_are_declared_on_the_class_itself(self):
        assert "facets" in vars(ClamAVScanner)
        assert "operational_facets" in vars(ClamAVScanner)

    def test_the_operational_row_mirrors_the_class(self):
        ops = ClamAVScanner.operational_facets
        assert ops.scanner_name == ClamAVScannerConfig().name
        assert ops.exit_codes.success_exit_codes == tuple(
            sorted(ClamAVScanner.success_exit_codes)
        )
        assert ops.network.offline_strategy is ClamAVScanner.offline_strategy
        assert ops.runtime.external_programs == ("clamscan",)
        assert ops.runtime.python_only is bool(ClamAVScanner.python_only)
        assert ops.runtime.use_uv_tool is False
        assert ops.targets.tool_type is ScannerToolType.CUSTOM
        # The tool is user-installed and never redistributed (GPL-2.0 plus a
        # separate signature database): nothing is provisioned by ASH.
        assert ops.platforms.provisionable == ()
        assert ops.provenance.source is opsf.ProvenanceSource.USER_INSTALLED

    def test_the_instance_matches_the_declared_tool_type(self):
        assert ClamAVScanner().tool_type is ScannerToolType.CUSTOM
