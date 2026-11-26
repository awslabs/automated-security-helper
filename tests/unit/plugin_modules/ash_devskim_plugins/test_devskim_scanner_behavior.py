# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""DevSkimScanner: invocation, severity mapping, exit status and failure handling.

The SARIF the fake tool writes here is built from the shape DevSkim 1.0.103 writes (read
from the real capture in tests/test_data/scanners/devskim/captured/: ruleId, level,
message, one physical location with a region and a matched-text snippet, and the
``tags`` / ``DevSkimSeverity`` / ``DevSkimConfidence`` properties), so the edge cases a
real run does not produce (no ``DevSkimSeverity``, no level, a broken report) can be
driven one at a time. The captured run itself is read in
test_devskim_install_and_captured.py. The expected findings are written out by hand
below, not derived from the code under test. The subprocess is replaced by a fake, so
the tests run on every platform without DevSkim or .NET.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_devskim_plugins
from automated_security_helper.plugin_modules.ash_devskim_plugins import (
    devskim_scanner as ds,
)
from automated_security_helper.plugin_modules.ash_devskim_plugins.devskim_scanner import (
    DEVSKIM_SEVERITY_MAP,
    DevSkimScanner,
    DevSkimScannerConfig,
    DevSkimScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import Level, SarifReport
from automated_security_helper.utils.severity_ladder import _SARIF_LEVEL_TO_SEVERITY
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    build_scanner_policy,
)

pytestmark = pytest.mark.unit


def _result(
    rule: str, uri: str, line: int, severity: Optional[str], level: Optional[str]
) -> Dict[str, Any]:
    item: Dict[str, Any] = {
        "ruleId": rule,
        "message": {"text": f"{rule} finding"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": line,
                        "startColumn": 1,
                        "endLine": line,
                        "endColumn": 9,
                        "snippet": {"text": "md5()"},
                    },
                }
            }
        ],
        "properties": {"tags": ["Cryptography"], "DevSkimConfidence": "High"},
    }
    if severity is not None:
        item["properties"]["DevSkimSeverity"] = severity
    if level is not None:
        item["level"] = level
    return item


def _sarif(results: List[Dict[str, Any]]) -> str:
    return json.dumps(
        {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.6.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "devskim", "rules": []}},
                    "results": results,
                    "columnKind": "utf16CodeUnits",
                }
            ],
        }
    )


#: One result per DevSkim severity: (ruleId, uri, line, DevSkimSeverity, the SARIF
#: level DevSkim writes for that severity). Expected ASH rows are in
#: ``POSITIVE_EXPECTED``, written by hand.
POSITIVE = [
    _result("DS126858", "app.py", 4, "Critical", "error"),
    _result("DS185832", "lib/copy.c", 9, "Important", "error"),
    _result("DS137138", "web/page.js", 2, "Moderate", "warning"),
    _result("DS140021", "main.c", 7, "BestPractice", "note"),
    _result("DS176209", "notes.py", 1, "ManualReview", "note"),
]
POSITIVE_EXPECTED = [
    ("DS126858", "error", "CRITICAL", "app.py", 4),
    ("DS185832", "error", "HIGH", "lib/copy.c", 9),
    ("DS137138", "warning", "MEDIUM", "web/page.js", 2),
    ("DS140021", "note", "LOW", "main.c", 7),
    ("DS176209", "none", "INFO", "notes.py", 1),
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


class FakeDevSkim:
    """Stands in for _run_subprocess: records argv, writes a report."""

    def __init__(
        self,
        results: Optional[List[Dict[str, Any]]] = None,
        exit_code: int = 0,
        text: Optional[str] = None,
        write: bool = True,
        timed_out: bool = False,
    ):
        self.text = text if text is not None else _sarif(results or [])
        self.exit_code, self.write, self.timed_out = exit_code, write, timed_out
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            out = next(a for a in command if a.startswith("--output-file="))
            path = Path(out.split("=", 1)[1])
            if self.write and not self.timed_out:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(self.text, encoding="utf-8")
            scanner.exit_code = 124 if self.timed_out else self.exit_code
            return {
                "returncode": scanner.exit_code,
                "stdout": "",
                "stderr": "",
                "timed_out": self.timed_out,
            }

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(source: Path, tmp_path: Path, **options) -> DevSkimScanner:
    config = get_default_config()
    output = tmp_path / "out"
    return DevSkimScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=config,
        ),
        config=DevSkimScannerConfig(
            enabled=True, options=DevSkimScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("print(1)\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ds, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch, target=None, target_type="source"):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


class TestAlphaPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert DevSkimScannerConfig().enabled is True
        assert DevSkimScannerConfig().name == "devskim"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "devskim")

    def test_the_module_exports_the_scanner(self):
        assert ash_devskim_plugins.ASH_SCANNERS == [DevSkimScanner]
        assert ash_devskim_plugins.ASH_REPORTERS == []

    def test_class_vars_are_set_deliberately(self):
        assert DevSkimScanner.python_only is False
        assert DevSkimScanner.success_exit_codes == {0}
        assert DevSkimScanner.offline_strategy.value != "unknown"
        assert DevSkimScanner.external_executables == ("dotnet",)


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDevSkim()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[:2] == ["devskim", "analyze"]
        assert "--source-code=." in argv
        assert "--file-format=sarif" in argv
        assert "--disable-supression" in argv
        out = next(a for a in argv if a.startswith("--output-file="))
        assert out.endswith("/source/devskim.sarif")
        assert fake.calls[0]["cwd"] is None, "the run starts in the source directory"

    @pytest.mark.parametrize(
        "forbidden",
        [
            "--options-json",
            "--ignore-default-rules",
            "-i",
            "-r",
            "--rule-ids",
            "--ignore-rule-ids",
            "--crawl-archives",
            "-E",
            "--skip-excerpts",
        ],
    )
    def test_flags_that_change_rules_or_read_extra_input_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, forbidden
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDevSkim()
        _run(scanner, fake, monkeypatch)
        assert not any(
            a == forbidden or a.startswith(f"{forbidden}=") for a in fake.argv
        )

    def test_the_converted_target_is_an_absolute_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "x.py").write_text("print(1)\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeDevSkim()
        _run(scanner, fake, monkeypatch, target=converted, target_type="converted")
        assert f"--source-code={converted.absolute().as_posix()}" in fake.argv

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDevSkim()
        _run(scanner, fake, monkeypatch, target=tmp_path / "gone")
        assert fake.calls == []


class TestSeverity:
    def test_every_devskim_severity_is_rated_and_leveled_consistently(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeDevSkim(POSITIVE), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_the_clean_report_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeDevSkim([]), monkeypatch)
        assert _findings(report) == []

    @pytest.mark.parametrize(
        "level,expected",
        [
            ("error", ("HIGH", "error")),
            ("warning", ("MEDIUM", "warning")),
            ("note", ("LOW", "note")),
            ("none", ("MEDIUM", "warning")),
            (None, ("MEDIUM", "warning")),
        ],
    )
    def test_without_a_devskim_severity_the_sarif_level_decides(
        self, tree, tmp_path, on_path, monkeypatch, level, expected
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(
            scanner,
            FakeDevSkim([_result("DS1", "app.py", 1, None, level)]),
            monkeypatch,
        )
        (row,) = _findings(report)
        assert (row[2], row[1]) == expected

    def test_an_unknown_devskim_severity_falls_back_to_the_level(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(
            scanner,
            FakeDevSkim([_result("DS1", "app.py", 1, "Unheard", "warning")]),
            monkeypatch,
        )
        (row,) = _findings(report)
        assert (row[2], row[1]) == ("MEDIUM", "warning")

    def test_the_table_has_a_row_per_documented_severity(self):
        assert set(DEVSKIM_SEVERITY_MAP) == {
            "critical",
            "important",
            "moderate",
            "bestpractice",
            "manualreview",
        }

    def test_level_and_severity_agree_under_the_repo_severity_ladder(self):
        """Where the ladder maps a level to one severity (warning, note, none), the
        table's row for that level carries the same severity: ManualReview is INFO,
        so its level is ``none`` (``note`` is LOW on the ladder)."""
        ladder = {
            "warning": "MEDIUM",
            "note": "LOW",
            "none": "INFO",
        }
        for name, (severity, level) in DEVSKIM_SEVERITY_MAP.items():
            if level.value in ladder:
                assert ladder[level.value] == severity, (name, severity, level)
        assert DEVSKIM_SEVERITY_MAP["manualreview"] == ("INFO", Level.none)
        # And the ladder module itself still rates those levels this way.
        for level_name, expected in ladder.items():
            assert _SARIF_LEVEL_TO_SEVERITY[level_name] == expected

    def test_results_are_marked_as_failures_with_a_security_tag(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeDevSkim(POSITIVE), monkeypatch)
        for result in report.get_all_results():
            assert getattr(result.kind, "value", result.kind) == "fail"
            assert "security" in result.properties.tags
            assert "Cryptography" in result.properties.tags


class TestExitStatusAndFailures:
    def test_zero_with_findings_is_a_success(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeDevSkim(POSITIVE, exit_code=0), monkeypatch)
        assert scanner._exit_code_accepted()

    @pytest.mark.parametrize("code", [1, 5, 126, 137, 150])
    def test_nonzero_exit_fails_even_with_findings_on_disk(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeDevSkim(POSITIVE, exit_code=code), monkeypatch)

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=5)
        fake = FakeDevSkim(timed_out=True)
        with pytest.raises(ScannerError, match=r"timed out after '?5'? s"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 5

    @pytest.mark.parametrize(
        "text",
        ["{not json", "[]", "null", "", '{"version": "2.1.0", "runs": "x"}'],
    )
    def test_malformed_or_empty_output_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch, text
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(Exception):
            _run(scanner, FakeDevSkim(text=text), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeDevSkim(write=False), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeDevSkim(POSITIVE), monkeypatch)
        with pytest.raises(ScannerError):
            _run(scanner, FakeDevSkim(write=False), monkeypatch)


class TestToolAbsent:
    def test_a_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            ds,
            "find_executable",
            lambda cmd: "/fake/bin/dotnet" if cmd == "dotnet" else None,
        )
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False

    def test_a_missing_dotnet_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            ds,
            "find_executable",
            lambda cmd: None if cmd == "dotnet" else f"/fake/bin/{cmd}",
        )
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False

    def test_a_present_binary_and_runtime_satisfy_them(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_an_unavailable_dependency_reason_wins(self, tree, tmp_path, on_path):
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "no install path"
        assert scanner.validate_plugin_dependencies() is False


class TestInstall:
    def test_the_pin_is_a_stable_release(self):
        assert ds.DEVSKIM_VERSION == "1.0.103"
        assert "-" not in ds.DEVSKIM_VERSION
        assert ds.DEVSKIM_PACKAGE == "Microsoft.CST.DevSkim.CLI"

    def test_install_commands_cover_linux_and_darwin(self, tmp_path, monkeypatch):
        bin_dir = tmp_path / "bin"
        monkeypatch.setenv("ASH_BIN_PATH", str(bin_dir))
        scanner = _scanner(tmp_path, tmp_path)
        for platform in ("linux", "darwin"):
            for arch in ("amd64", "arm64"):
                commands = scanner.get_installation_commands(platform, arch)
                assert len(commands) == 1, f"{platform}/{arch}: {commands}"
                args = list(commands[0])
                assert args[1] == "-c"
                assert "install_devskim" in args[2]
                assert args[3] == str(bin_dir.absolute())

    def test_windows_is_not_installed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        scanner = _scanner(tmp_path, tmp_path)
        for arch in ("amd64", "arm64"):
            assert scanner.get_installation_commands("windows", arch) == []


class TestSandboxRequirements:
    def test_devskim_declares_the_strict_default(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        source = tmp_path / "src"
        source.mkdir()
        output = source / ".ash" / "ash_output"
        output.mkdir(parents=True)
        layout = SimpleNamespace(source=source, output=output)

        def policy(requirements):
            return build_scanner_policy(
                "devskim",
                requirements,
                argv0=sys.executable,
                source_dir=layout.source,
                output_dir=layout.output,
                results_dir=layout.output / "scanners" / "devskim",
                scan_target=layout.source,
                cwd=layout.source,
                offline=False,
                network_scanners=None,
            )

        declared = DevSkimScanner.sandbox_requirements
        assert declared == SandboxRequirements()
        assert policy(declared).network is False
