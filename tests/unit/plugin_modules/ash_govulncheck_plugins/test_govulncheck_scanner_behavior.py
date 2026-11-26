# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""GovulncheckScanner: severity mapping, invocation and failure handling.

The SARIF below is written by hand from govulncheck's SARIF shape (rule id is the
OSV id, one result per finding, level error / warning / note by scan precision,
one location that is the module's go.mod), so each case controls exactly one
field. It is not a capture from the real tool: the captured v1.9.0 runs are read
in test_govulncheck_install_and_captured.py. The subprocess is replaced with a
fake that serves the SARIF, so these tests run on every platform without Go or
govulncheck installed.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_base import (
    CustomCommand,
    declaring_install_story,
)
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules import ash_govulncheck_plugins as pkg
from automated_security_helper.plugin_modules.ash_govulncheck_plugins import (
    govulncheck_install as gi,
)
from automated_security_helper.plugin_modules.ash_govulncheck_plugins import (
    govulncheck_scanner as gs,
)
from automated_security_helper.plugin_modules.ash_govulncheck_plugins.govulncheck_scanner import (
    GovulncheckScanner,
    GovulncheckScannerConfig,
    GovulncheckScannerConfigOptions,
)
from automated_security_helper.utils.config_trust import record_provenance

pytestmark = pytest.mark.unit

#: (rule id, govulncheck level) in report order. Three vulnerabilities, one per level.
RESULTS = [
    ("GO-2023-0001", "error"),
    ("GO-2023-0002", "warning"),
    ("GO-2023-0003", "note"),
]
#: What ASH must report for each, written out here and not derived from the code.
EXPECTED = [
    ("GO-2023-0001", "error", "HIGH"),
    ("GO-2023-0002", "warning", "MEDIUM"),
    ("GO-2023-0003", "note", "LOW"),
]


def _sarif(results: List[tuple] | None = None, *, version: str = "v1.9.0") -> str:
    results = RESULTS if results is None else results
    document: Dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "govulncheck",
                        "semanticVersion": version,
                        "informationUri": "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck",
                        "rules": [
                            {"id": rule_id, "shortDescription": {"text": rule_id}}
                            for rule_id, _ in results
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": rule_id,
                        "level": level,
                        "message": {
                            "text": f"Vulnerability {rule_id} affects the module"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "go.mod",
                                        "uriBaseId": "%SRCROOT%",
                                    },
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                    for rule_id, level in results
                ],
            }
        ],
    }
    return json.dumps(document)


class FakeGovulncheck:
    """Stands in for _run_subprocess: records argv, cwd and timeout, serves stdout."""

    def __init__(
        self,
        stdout: Optional[str] = None,
        exit_code: int = 0,
        stderr: str = "",
        timed_out: bool = False,
    ):
        self.stdout = _sarif() if stdout is None else stdout
        self.exit_code, self.stderr, self.timed_out = exit_code, stderr, timed_out
        self.calls: List[dict] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, cwd=None, timeout=None, **_):
            self.calls.append(
                {"argv": list(command), "cwd": Path(cwd), "timeout": timeout}
            )
            if self.timed_out:
                scanner.exit_code = -9
                return {"timed_out": True}
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": self.stdout,
                "stderr": self.stderr,
            }

        return run


def _scanner(source: Path, tmp_path: Path, **options) -> GovulncheckScanner:
    config = get_default_config()
    record_provenance(config, in_tree=[], trusted=AshConfig())
    return GovulncheckScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=GovulncheckScannerConfig(
            enabled=True, options=GovulncheckScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "go.mod").write_text("module example.com/app\n\ngo 1.22\n")
    (src / "main.go").write_text("package main\n\nfunc main() {}\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(gs, "find_executable", lambda cmd: f"/fake/bin/{cmd}")
    monkeypatch.setattr(GovulncheckScanner, "_scanner_offline", lambda self: False)


@pytest.fixture
def no_go(monkeypatch):
    """govulncheck on PATH, the Go toolchain it runs not."""
    monkeypatch.setattr(
        gs, "find_executable", lambda cmd: None if cmd == "go" else f"/fake/bin/{cmd}"
    )


def _run(scanner: GovulncheckScanner, fake: FakeGovulncheck, monkeypatch, **kw):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(scanner.context.source_dir), target_type="source", **kw
    )


def _findings(report) -> List[tuple]:
    return [
        (
            r.ruleId,
            getattr(r.level, "value", r.level),
            getattr(r.properties, "issue_severity", None),
        )
        for r in report.get_all_results()
    ]


class TestAlphaPlugin:
    def test_the_module_exports_the_scanner(self):
        assert pkg.ASH_SCANNERS == [GovulncheckScanner]
        assert pkg.ASH_REPORTERS == []

    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert GovulncheckScannerConfig().enabled is True
        assert GovulncheckScannerConfig().name == "govulncheck"

    def test_declarations(self):
        assert GovulncheckScanner.python_only is False
        assert GovulncheckScanner.success_exit_codes == {0}
        assert GovulncheckScanner.offline_strategy is OfflineStrategy.SKIP_OFFLINE
        assert GovulncheckScanner.sandbox_requirements.network is True
        assert GovulncheckScanner.external_executables == ("go",)


class TestInvocation:
    def test_every_fixed_flag_and_the_pattern_after_double_dash(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeGovulncheck()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        (call,) = fake.calls
        assert call["argv"] == [
            "govulncheck",
            "-format=sarif",
            "-scan=symbol",
            "--",
            "./...",
        ]
        assert call["cwd"] == tree.absolute()

    def test_test_files_are_opt_in(self, tree, tmp_path, on_path, monkeypatch):
        fake = FakeGovulncheck()
        _run(_scanner(tree, tmp_path, include_tests=True), fake, monkeypatch)
        assert "-test=true" in fake.calls[0]["argv"]

    def test_module_level_scan_passes_no_pattern(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeGovulncheck()
        _run(_scanner(tree, tmp_path, scan_level="module"), fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        assert "-scan=module" in argv
        assert "./..." not in argv and "--" not in argv

    @pytest.mark.parametrize("flag", ["-db", "-show", "-mode", "-C", "-json"])
    def test_flags_that_reach_elsewhere_are_never_passed(
        self, flag, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeGovulncheck()
        _run(_scanner(tree, tmp_path, include_tests=True), fake, monkeypatch)
        assert not any(
            a == flag or a.startswith(flag + "=") for a in fake.calls[0]["argv"]
        )

    def test_one_run_per_module_with_the_module_as_working_directory(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "svc" / "api").mkdir(parents=True)
        (tree / "svc" / "api" / "go.mod").write_text("module example.com/api\n")
        (tree / "vendor" / "dep").mkdir(parents=True)
        (tree / "vendor" / "dep" / "go.mod").write_text("module example.com/dep\n")
        fake = FakeGovulncheck()
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert [c["cwd"] for c in fake.calls] == [
            tree.absolute(),
            (tree / "svc" / "api").absolute(),
        ]
        uris = sorted(
            r.locations[0].physicalLocation.root.artifactLocation.uri
            for r in report.get_all_results()
        )
        assert uris == ["go.mod"] * 3 + ["svc/api/go.mod"] * 3

    def test_ignored_module_is_not_scanned(self, tree, tmp_path, on_path, monkeypatch):
        (tree / "svc").mkdir()
        (tree / "svc" / "go.mod").write_text("module example.com/svc\n")
        fake = FakeGovulncheck()
        _run(
            _scanner(tree, tmp_path),
            fake,
            monkeypatch,
            global_ignore_paths=[IgnorePathWithReason(path="svc/**", reason="test")],
        )
        assert [c["cwd"] for c in fake.calls] == [tree.absolute()]

    def test_a_tree_with_no_go_mod_never_reaches_the_tool(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text("print(1)\n")
        fake = FakeGovulncheck()
        report = _run(_scanner(src, tmp_path), fake, monkeypatch)
        assert fake.calls == []
        assert report.get_all_results() == []

    def test_offline_mode_skips_the_scan(self, tree, tmp_path, on_path, monkeypatch):
        monkeypatch.setattr(GovulncheckScanner, "_scanner_offline", lambda self: True)
        fake = FakeGovulncheck()
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert fake.calls == []
        assert report.get_all_results() == []

    def test_timeout_reaches_the_subprocess(self, tree, tmp_path, on_path, monkeypatch):
        fake = FakeGovulncheck()
        _run(_scanner(tree, tmp_path, scan_timeout=120), fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 120


class TestReport:
    def test_findings_are_rated_and_the_level_agrees(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeGovulncheck(), monkeypatch)
        assert _findings(report) == EXPECTED

    def test_negative_control_clean_report_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeGovulncheck(stdout=_sarif([]))
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert report.get_all_results() == []

    def test_a_result_without_a_level_is_medium(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        document = json.loads(_sarif([("GO-2023-0009", "error")]))
        del document["runs"][0]["results"][0]["level"]
        report = _run(
            _scanner(tree, tmp_path),
            FakeGovulncheck(stdout=json.dumps(document)),
            monkeypatch,
        )
        assert _findings(report) == [("GO-2023-0009", "warning", "MEDIUM")]

    def test_tool_version_is_read_from_semantic_version(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        before = scanner.tool_version
        _run(scanner, FakeGovulncheck(stdout=_sarif(version="v9.8.7")), monkeypatch)
        assert scanner.tool_version == "v9.8.7"
        assert scanner.tool_version != before

    def test_tool_version_falls_back_to_driver_version(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        document = json.loads(_sarif())
        driver = document["runs"][0]["tool"]["driver"]
        del driver["semanticVersion"]
        driver["version"] = "v6.5.4"
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeGovulncheck(stdout=json.dumps(document)), monkeypatch)
        assert scanner.tool_version == "v6.5.4"

    def test_the_report_is_written_to_the_results_directory(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeGovulncheck(), monkeypatch)
        written = Path(scanner.results_dir) / "source" / "govulncheck.sarif"
        assert len(json.loads(written.read_text())["runs"][0]["results"]) == 3


class TestFailures:
    @pytest.mark.parametrize("code", [1, 2, 3, 126, 137])
    def test_any_nonzero_exit_fails_even_with_a_report_on_stdout(
        self, code, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeGovulncheck(exit_code=code, stderr="govulncheck: loading packages")
        with pytest.raises(ScannerError, match=f"exited {code}"):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError, match="timed out"):
            _run(_scanner(tree, tmp_path), FakeGovulncheck(timed_out=True), monkeypatch)

    @pytest.mark.parametrize(
        "stdout, message",
        [
            ("", "wrote no report"),
            ("   \n", "wrote no report"),
            ("not json at all", "not JSON"),
            ("[1, 2]", "not a SARIF document"),
            ('{"version": "2.1.0", "runs": []}', "no runs"),
            ('{"version": "2.1.0", "runs": "x"}', "not valid SARIF"),
        ],
    )
    def test_malformed_output_fails_the_scan(
        self, stdout, message, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError, match=message):
            _run(_scanner(tree, tmp_path), FakeGovulncheck(stdout=stdout), monkeypatch)

    def test_a_missing_tool_is_reported_unavailable(self, tree, tmp_path, monkeypatch):
        monkeypatch.setattr(gs, "find_executable", lambda cmd: None)
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is False

    def test_a_present_tool_is_available(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True


class TestGoToolchain:
    """govulncheck runs ``go`` to load packages; without it v1.9.0 misreports the
    module as missing, so the scanner names the missing program itself."""

    def test_a_missing_go_is_reported_with_its_reason(self, tree, tmp_path, no_go):
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False
        assert scanner.dependency_unavailable_reason == gs.GO_TOOLCHAIN_MISSING
        assert scanner.missing_dependency_reason() == gs.GO_TOOLCHAIN_MISSING
        assert "go.mod" in gs.GO_TOOLCHAIN_MISSING

    def test_a_forced_binary_cannot_outvote_a_missing_go(self, tree, tmp_path, no_go):
        assert (
            _scanner(tree, tmp_path)._forced_binary_precluded_reason()
            == gs.GO_TOOLCHAIN_MISSING
        )

    def test_with_go_present_nothing_is_precluded(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path)._forced_binary_precluded_reason() is None


class TestInstall:
    def test_the_install_is_declared_for_every_platform_go_runs_on(self):
        # Written out here, not read from the code: Windows included.
        assert sorted(gs.INSTALL_PLATFORMS) == [
            ("darwin", "amd64"),
            ("darwin", "arm64"),
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("windows", "amd64"),
            ("windows", "arm64"),
        ]

    def test_every_platform_gets_the_same_argv_with_no_shell(self, tmp_path):
        """An argv, not a shell line, so nothing in it needs a POSIX shell."""
        with declaring_install_story():
            scanner = _scanner(tmp_path, tmp_path)
        declared = set()
        for platform, arch in gs.INSTALL_PLATFORMS:
            commands = scanner.get_installation_commands(platform, arch)
            assert len(commands) == 1, f"{platform}/{arch}: {commands}"
            (command,) = commands
            assert isinstance(command, CustomCommand)
            assert command.shell is False, f"{platform}/{arch} runs through a shell"
            words = list(command)
            assert words[:3] == [sys.executable, "-c", gi.INSTALL_SCRIPT]
            assert words[-1] == f"{gs.GOVULNCHECK_PACKAGE}@{gs.GOVULNCHECK_VERSION}"
            assert not any(word.startswith("GOBIN=") for word in words), words
            declared.add(tuple(words))
        assert len(declared) == 1, "the platforms were given different commands"

    def test_the_command_installs_into_ash_s_bin_directory(
        self, tmp_path, on_path, monkeypatch
    ):
        bin_dir = tmp_path / "ash-bin"
        monkeypatch.setenv("ASH_BIN_PATH", str(bin_dir))
        scanner = _scanner(tmp_path, tmp_path)
        (command,) = scanner.get_installation_commands("windows", "amd64")
        assert list(command)[3] == os.path.abspath(str(bin_dir))

    def test_without_go_no_install_command_is_declared(self, tmp_path, monkeypatch):
        monkeypatch.setattr(gs, "find_executable", lambda cmd: None)
        scanner = _scanner(tmp_path, tmp_path)
        assert scanner.get_installation_commands("linux", "amd64") == []

    def test_the_pin_is_a_stable_release(self):
        assert gs.GOVULNCHECK_VERSION.startswith("v1.")
        assert "-" not in gs.GOVULNCHECK_VERSION
