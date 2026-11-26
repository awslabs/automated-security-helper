# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""DotnetVulnerableScanner: invocation, report conversion and failure handling.

``dotnet`` is not run. The reports below are written out by hand in the shape
NuGet's ``ListPackageJsonRenderer`` produces (property names read from its
source, NuGet.Client ``ListPackageJsonRenderer.cs``), and the scan() tests
replace the subprocess with a fake that serves them. They run on every
platform without the .NET SDK. They are not captures of a real run; the
real-SDK check is test_dotnet_vulnerable_captured.py, over a run of SDK 10.0.404.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules import ash_dotnet_vulnerable_plugins
from automated_security_helper.plugin_modules.ash_dotnet_vulnerable_plugins import (
    dotnet_vulnerable_scanner as ds,
)
from automated_security_helper.plugin_modules.ash_dotnet_vulnerable_plugins.dotnet_vulnerable_scanner import (
    DotnetVulnerableScanner,
    DotnetVulnerableScannerConfig,
    DotnetVulnerableScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit

ADVISORY = "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"
ADVISORY_2 = "https://github.com/advisories/GHSA-dddd-eeee-ffff"


def _package(pkg_id: str, version: str, vulns: Optional[List[dict]] = None) -> dict:
    out: Dict[str, Any] = {
        "id": pkg_id,
        "requestedVersion": version,
        "resolvedVersion": version,
    }
    if vulns is not None:
        out["vulnerabilities"] = vulns
    return out


def _vuln(severity: str, url: str = ADVISORY) -> dict:
    return {"severity": severity, "advisoryurl": url}


def _report(frameworks: List[dict], problems: Optional[List[dict]] = None) -> dict:
    document: Dict[str, Any] = {
        "version": 1,
        "parameters": "--vulnerable --include-transitive",
    }
    if problems:
        document["problems"] = problems
    document["sources"] = ["https://api.nuget.org/v3/index.json"]
    document["projects"] = [
        {"path": "/work/src/App/App.csproj", "frameworks": frameworks}
    ]
    return document


#: Two target frameworks, every NuGet severity name, a vulnerable transitive
#: package, a package seen under both frameworks, and one with no advisory url.
POSITIVE = _report(
    [
        {
            "framework": "net8.0",
            "topLevelPackages": [
                _package("Newtonsoft.Json", "12.0.1", [_vuln("High")]),
                _package("Example.Critical", "1.0.0", [_vuln("Critical", ADVISORY_2)]),
                _package("Example.Moderate", "2.0.0", [_vuln("Moderate")]),
                _package("Example.Low", "3.0.0", [_vuln("Low")]),
            ],
            "transitivePackages": [
                _package("Example.Transitive", "4.0.0", [_vuln("High")]),
            ],
        },
        {
            "framework": "net6.0",
            "topLevelPackages": [
                _package("Newtonsoft.Json", "12.0.1", [_vuln("High")]),
                _package("Example.NoUrl", "5.0.0", [_vuln("Low", "")]),
            ],
        },
    ]
)

#: (ruleId, SARIF level, ASH severity, package, version), in report order, written
#: out by hand. Results are ordered by the dedup key (package id first).
POSITIVE_EXPECTED = [
    ("GHSA-dddd-eeee-ffff", "error", "CRITICAL", "Example.Critical", "1.0.0"),
    ("GHSA-aaaa-bbbb-cccc", "note", "LOW", "Example.Low", "3.0.0"),
    ("GHSA-aaaa-bbbb-cccc", "warning", "MEDIUM", "Example.Moderate", "2.0.0"),
    ("NUGET-VULNERABLE-PACKAGE", "note", "LOW", "Example.NoUrl", "5.0.0"),
    ("GHSA-aaaa-bbbb-cccc", "error", "HIGH", "Example.Transitive", "4.0.0"),
    ("GHSA-aaaa-bbbb-cccc", "error", "HIGH", "Newtonsoft.Json", "12.0.1"),
]

#: A project whose packages have no known vulnerability: the renderer lists no
#: ``vulnerabilities`` key and, for a clean project, no packages at all.
NEGATIVE = _report([{"framework": "net8.0"}])
NEGATIVE_WITH_PACKAGES = _report(
    [{"framework": "net8.0", "topLevelPackages": [_package("Clean.Package", "1.0.0")]}]
)

NOT_RESTORED = _report(
    [],
    problems=[
        {
            "project": "/work/src/App/App.csproj",
            "level": "error",
            "text": "No assets file was found for `/work/src/App/App.csproj`. "
            "Please run restore before running this command.",
        }
    ],
)


def _findings(report: SarifReport) -> List[tuple]:
    out = []
    for r in report.get_all_results():
        props = r.properties
        out.append(
            (
                r.ruleId,
                getattr(r.level, "value", r.level),
                getattr(props, "issue_severity", None),
                getattr(props, "package_name", None),
                getattr(props, "package_version", None),
            )
        )
    return out


# ---------------------------------------------------------------------------
# scan() with the subprocess replaced
# ---------------------------------------------------------------------------


class FakeDotnet:
    """Stands in for _run_subprocess: records argv, env, timeout and cwd, serves
    a report per project (the argv's project path), or a default one."""

    def __init__(
        self,
        default: Optional[dict] = POSITIVE,
        by_project: Optional[Dict[str, dict]] = None,
        exit_code: int = 0,
        exit_by_project: Optional[Dict[str, int]] = None,
        raw_stdout: Optional[str] = None,
        stderr: str = "",
        timed_out: bool = False,
    ):
        self.default = default
        self.by_project = by_project or {}
        self.exit_code = exit_code
        self.exit_by_project = exit_by_project or {}
        self.raw_stdout = raw_stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.calls: List[dict] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **kw):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            if self.timed_out:
                scanner.exit_code = -9
                return {"timed_out": True}
            project = command[2]
            code = self.exit_by_project.get(project, self.exit_code)
            scanner.exit_code = code
            if self.raw_stdout is not None:
                stdout = self.raw_stdout
            else:
                document = self.by_project.get(project, self.default)
                stdout = json.dumps(document) if document is not None else ""
            return {"returncode": code, "stdout": stdout, "stderr": self.stderr}

        return run


def _scanner(source: Path, tmp_path: Path, **options) -> DotnetVulnerableScanner:
    config = get_default_config()
    record_provenance(config, in_tree=[], trusted=AshConfig())
    return DotnetVulnerableScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=DotnetVulnerableScannerConfig(
            enabled=True, options=DotnetVulnerableScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "App").mkdir(parents=True)
    (src / "App" / "App.csproj").write_text("<Project />\n")
    (src / "App" / "Program.cs").write_text("class P {}\n")
    (src / "App.sln").write_text("\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ds, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake: FakeDotnet, monkeypatch, **kw):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(scanner.context.source_dir), target_type="source", **kw
    )


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert DotnetVulnerableScannerConfig().enabled is True
        assert DotnetVulnerableScannerConfig().name == "dotnet-vulnerable"

    def test_the_module_exports_the_scanner(self):
        assert ash_dotnet_vulnerable_plugins.ASH_SCANNERS == [DotnetVulnerableScanner]
        assert ash_dotnet_vulnerable_plugins.ASH_REPORTERS == []

    def test_declarations(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        assert scanner.command == "dotnet"
        assert scanner.tool_type == ScannerToolType.SCA
        assert DotnetVulnerableScanner.python_only is False
        assert DotnetVulnerableScanner.offline_strategy is OfflineStrategy.SKIP_OFFLINE
        assert DotnetVulnerableScanner.success_exit_codes == {0}

    def test_sandbox_grants_a_network_and_the_sdks_own_variables_only(self):
        req = DotnetVulnerableScanner.sandbox_requirements
        assert isinstance(req, SandboxRequirements)
        assert req.network is True
        assert set(req.env_prefixes) == {"DOTNET_", "NUGET_"}
        assert req.env_names == ()
        assert req.read_paths == ()


class TestInvocation:
    def test_every_fixed_flag_and_the_project_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDotnet()
        _run(scanner, fake, monkeypatch)
        assert [c["argv"] for c in fake.calls] == [
            [
                "dotnet",
                "list",
                "App/App.csproj",
                "package",
                "--vulnerable",
                "--include-transitive",
                "--format",
                "json",
                "--output-version",
                "1",
            ]
        ]
        # None runs the tool in the source directory, so the project path above is
        # the one the report is keyed on.
        assert fake.calls[0]["cwd"] is None

    def test_the_solution_file_is_not_passed(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDotnet()
        _run(scanner, fake, monkeypatch)
        assert all("App.sln" not in " ".join(c["argv"]) for c in fake.calls)

    @pytest.mark.parametrize(
        "flag",
        [
            # SDK 10 only: SDK 7 to 9 reject it as an unrecognized option and fail
            # every project, and the scanner documents and gates on SDK 7.0.200.
            "--no-restore",
            "--outdated",
            "--deprecated",
            "--source",
            "-s",
            "--config",
            "--interactive",
            "--framework",
            "--include-prerelease",
            "--verbosity",
        ],
    )
    def test_flags_that_restore_reach_other_sources_or_prompt_are_never_passed(
        self, flag, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDotnet()
        _run(scanner, fake, monkeypatch)
        assert all(flag not in c["argv"] for c in fake.calls)

    def test_a_project_name_starting_with_a_dash_is_not_read_as_an_option(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "src"
        src.mkdir()
        (src / "-odd.csproj").write_text("<Project />\n")
        scanner = _scanner(src, tmp_path)
        fake = FakeDotnet()
        _run(scanner, fake, monkeypatch)
        assert fake.calls[0]["argv"][2] == "./-odd.csproj"

    def test_every_project_kind_is_scanned_once_in_sorted_order(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "src"
        for name in ("b/B.fsproj", "a/A.csproj", "c/C.vbproj", "d/D.txt", "e/e.CSPROJ"):
            (src / name).parent.mkdir(parents=True, exist_ok=True)
            (src / name).write_text("<Project />\n")
        scanner = _scanner(src, tmp_path)
        fake = FakeDotnet(default=NEGATIVE)
        _run(scanner, fake, monkeypatch)
        assert [c["argv"][2] for c in fake.calls] == [
            "a/A.csproj",
            "b/B.fsproj",
            "c/C.vbproj",
            "e/e.CSPROJ",
        ]
        assert scanner.targets_attempted == 4

    def test_the_run_is_quiet_and_keeps_the_callers_environment(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        monkeypatch.setenv("NUGET_PACKAGES", "/cache/nuget")
        scanner = _scanner(tree, tmp_path)
        fake = FakeDotnet()
        _run(scanner, fake, monkeypatch)
        env = fake.calls[0]["env"]
        assert env["DOTNET_NOLOGO"] == "1"
        assert env["DOTNET_CLI_TELEMETRY_OPTOUT"] == "1"
        assert env["NUGET_PACKAGES"] == "/cache/nuget"

    def test_a_link_leaving_the_tree_is_not_passed_to_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "Evil.csproj").write_text("<Project />\n")
        (tree / "Evil.csproj").symlink_to(outside / "Evil.csproj")
        scanner = _scanner(tree, tmp_path)
        fake = FakeDotnet()
        _run(scanner, fake, monkeypatch)
        assert [c["argv"][2] for c in fake.calls] == ["App/App.csproj"]

    def test_ignore_paths_leave_a_project_out(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "Other").mkdir()
        (tree / "Other" / "Other.csproj").write_text("<Project />\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeDotnet()
        _run(
            scanner,
            fake,
            monkeypatch,
            global_ignore_paths=[
                IgnorePathWithReason(path="Other/**", reason="vendored")
            ],
        )
        assert [c["argv"][2] for c in fake.calls] == ["App/App.csproj"]

    def test_no_project_file_is_a_clean_skip_and_never_starts_the_tool(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "src"
        src.mkdir()
        (src / "README.md").write_text("x\n")
        scanner = _scanner(src, tmp_path)
        fake = FakeDotnet()
        report = _run(scanner, fake, monkeypatch)
        assert fake.calls == []
        assert scanner.targets_attempted == 0
        assert _findings(report) == []

    def test_a_missing_or_empty_target_never_reaches_the_tool(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "empty"
        src.mkdir()
        scanner = _scanner(src, tmp_path)
        fake = FakeDotnet()
        report = _run(scanner, fake, monkeypatch)
        assert fake.calls == []
        assert _findings(report) == []


class TestReport:
    def test_the_positive_report_is_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeDotnet(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED
        for result in report.get_all_results():
            loc = result.locations[0].physicalLocation.root
            assert loc.artifactLocation.uri == "App/App.csproj"
            assert loc.region.startLine == 1
            assert getattr(result.kind, "value", result.kind) == "fail"
        assert scanner.targets_failed == 0
        assert scanner.errors == []

    def test_negative_control_a_project_without_vulnerabilities_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        for clean in (NEGATIVE, NEGATIVE_WITH_PACKAGES):
            scanner = _scanner(tree, tmp_path)
            report = _run(scanner, FakeDotnet(default=clean), monkeypatch)
            assert _findings(report) == []
            assert scanner.targets_failed == 0

    def test_a_package_under_two_frameworks_is_one_result_naming_both(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeDotnet(), monkeypatch)
        newtonsoft = next(
            r
            for r in report.get_all_results()
            if r.properties.package_name == "Newtonsoft.Json"
        )
        assert newtonsoft.properties.target_frameworks == ["net6.0", "net8.0"]
        assert newtonsoft.properties.dependency_kind == "top-level"

    def test_a_transitive_package_says_so(self, tree, tmp_path, on_path, monkeypatch):
        report = _run(_scanner(tree, tmp_path), FakeDotnet(), monkeypatch)
        transitive = next(
            r
            for r in report.get_all_results()
            if r.properties.package_name == "Example.Transitive"
        )
        assert transitive.properties.dependency_kind == "transitive"
        assert "transitive package" in transitive.message.root.text

    def test_two_advisories_on_one_package_are_two_results(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        document = _report(
            [
                {
                    "framework": "net8.0",
                    "topLevelPackages": [
                        _package(
                            "Two.Advisories",
                            "1.0.0",
                            [_vuln("High", ADVISORY), _vuln("High", ADVISORY_2)],
                        )
                    ],
                }
            ]
        )
        report = _run(
            _scanner(tree, tmp_path), FakeDotnet(default=document), monkeypatch
        )
        assert sorted(f[0] for f in _findings(report)) == [
            "GHSA-aaaa-bbbb-cccc",
            "GHSA-dddd-eeee-ffff",
        ]

    def test_the_message_names_the_package_severity_and_advisory(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeDotnet(), monkeypatch)
        text = report.get_all_results()[-1].message.root.text
        assert text == (
            "Newtonsoft.Json 12.0.1 (top-level package) has a known High severity "
            f"vulnerability: {ADVISORY}"
        )

    def test_a_result_survives_a_sarif_round_trip(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeDotnet(), monkeypatch)
        again = SarifReport.model_validate_json(
            report.model_dump_json(exclude_none=True, by_alias=True)
        )
        assert _findings(again) == POSITIVE_EXPECTED

    def test_a_second_project_is_reported_under_its_own_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "Lib").mkdir()
        (tree / "Lib" / "Lib.csproj").write_text("<Project />\n")
        fake = FakeDotnet(
            default=NEGATIVE,
            by_project={
                "Lib/Lib.csproj": _report(
                    [
                        {
                            "framework": "net8.0",
                            "topLevelPackages": [
                                _package("Lib.Dep", "1.0.0", [_vuln("Low")])
                            ],
                        }
                    ]
                )
            },
        )
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        (result,) = report.get_all_results()
        uri = result.locations[0].physicalLocation.root.artifactLocation.uri
        assert uri == "Lib/Lib.csproj"


class TestSeverity:
    @pytest.mark.parametrize(
        ("name", "ash", "sarif"),
        [
            ("Critical", "CRITICAL", "error"),
            ("High", "HIGH", "error"),
            ("Moderate", "MEDIUM", "warning"),
            ("Low", "LOW", "note"),
            ("critical", "CRITICAL", "error"),
            ("  High ", "HIGH", "error"),
        ],
    )
    def test_each_nuget_severity_has_one_ash_severity_and_one_level(
        self, name, ash, sarif
    ):
        severity, level = ds.severity_for(name)
        assert (severity, level.value) == (ash, sarif)

    @pytest.mark.parametrize("name", ["", "   ", None])
    def test_a_result_without_a_severity_is_medium(self, name):
        severity, level = ds.severity_for(name)
        assert (severity, level.value) == ("MEDIUM", "warning")

    def test_an_unknown_severity_name_is_high(self):
        severity, level = ds.severity_for("Catastrophic")
        assert (severity, level.value) == ("HIGH", "error")

    def test_every_mapped_level_agrees_with_its_severity(self):
        for severity, level in ds.NUGET_SEVERITY_MAP.values():
            assert (
                level.value
                == {
                    "CRITICAL": "error",
                    "HIGH": "error",
                    "MEDIUM": "warning",
                    "LOW": "note",
                }[severity]
            )

    @pytest.mark.parametrize(
        ("url", "rule"),
        [
            (ADVISORY, "GHSA-aaaa-bbbb-cccc"),
            (
                "https://github.com/advisories/GHSA-AAAA-BBBB-CCCC/",
                "GHSA-aaaa-bbbb-cccc",
            ),
            ("https://example.test/advisory/42", "NUGET-VULNERABLE-PACKAGE"),
            ("", "NUGET-VULNERABLE-PACKAGE"),
            (None, "NUGET-VULNERABLE-PACKAGE"),
            ("https://github.com/advisories/GHSA-", "NUGET-VULNERABLE-PACKAGE"),
        ],
    )
    def test_the_rule_id_is_the_ghsa_id_or_the_generic_one(self, url, rule):
        assert ds.rule_id_for(url) == rule


class TestExitStatusAndFailures:
    def test_a_nonzero_exit_fails_the_project_even_with_findings_on_stdout(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeDotnet(exit_code=1), monkeypatch)
        assert _findings(report) == []
        assert scanner.targets_failed == 1
        assert any("App/App.csproj" in e and "exited 1" in e for e in scanner.errors)
        assert scanner.exit_code == 1

    def test_a_nonzero_exit_with_no_report_names_it(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeDotnet(default=None, exit_code=134), monkeypatch)
        assert scanner.targets_failed == 1
        assert any("exited 134 and wrote no report" in e for e in scanner.errors)

    def test_a_project_that_was_not_restored_is_a_failed_target_not_a_clean_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeDotnet(default=NOT_RESTORED), monkeypatch)
        assert _findings(report) == []
        assert scanner.targets_failed == 1
        assert scanner.targets_attempted == 1
        (error,) = scanner.errors
        assert "App/App.csproj" in error
        assert "No assets file was found" in error
        assert "dotnet restore" in error

    def test_a_warning_problem_does_not_fail_the_project(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        document = copy.deepcopy(NEGATIVE)
        document["problems"] = [{"level": "warning", "text": "a source is down"}]
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeDotnet(default=document), monkeypatch)
        assert scanner.targets_failed == 0

    def test_one_failed_project_does_not_hide_another_ones_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "Lib").mkdir()
        (tree / "Lib" / "Lib.csproj").write_text("<Project />\n")
        fake = FakeDotnet(by_project={"Lib/Lib.csproj": NOT_RESTORED})
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, fake, monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED
        assert scanner.targets_failed == 1
        assert scanner.targets_attempted == 2

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=5)
        fake = FakeDotnet(timed_out=True)
        with pytest.raises(ScannerError, match="timed out after 5"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 5

    def test_the_timeout_is_one_budget_for_every_project(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "Lib").mkdir()
        (tree / "Lib" / "Lib.csproj").write_text("<Project />\n")
        scanner = _scanner(tree, tmp_path, scan_timeout=100)
        ticks = iter([0.0, 10.0, 200.0, 300.0])
        monkeypatch.setattr(ds, "_now", lambda: next(ticks))
        fake = FakeDotnet(default=NEGATIVE)
        with pytest.raises(ScannerError, match="timed out after 100"):
            _run(scanner, fake, monkeypatch)
        assert len(fake.calls) == 1
        assert fake.calls[0]["timeout"] == 90.0

    @pytest.mark.parametrize(
        "stdout",
        [
            "",
            "   \n",
            "not json at all",
            "{ truncated",
            "[]",
            '"a string"',
            "{}",
            '{"projects": "no"}',
        ],
    )
    def test_malformed_output_fails_the_project_and_reports_nothing(
        self, stdout, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeDotnet(raw_stdout=stdout), monkeypatch)
        assert _findings(report) == []
        assert scanner.targets_failed == 1
        assert any("App/App.csproj" in e for e in scanner.errors)

    def test_lines_before_the_report_are_skipped(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        stdout = "Restore complete (0.4s)\n" + json.dumps(POSITIVE)
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeDotnet(raw_stdout=stdout), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_stderr_is_never_copied_into_the_errors(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDotnet(
            default=None, exit_code=1, stderr="quoted text from the scanned tree"
        )
        _run(scanner, fake, monkeypatch)
        assert scanner.targets_failed == 1
        assert not any("quoted text" in e for e in scanner.errors)

    def test_a_very_long_problem_text_is_shortened(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        document = _report([], problems=[{"level": "error", "text": "x" * 5000}])
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeDotnet(default=document), monkeypatch)
        assert len(scanner.errors[0]) < 1000


class TestDependencyGate:
    def test_a_missing_dotnet_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ds, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        fake = FakeDotnet()
        assert _run(scanner, fake, monkeypatch) is False
        assert scanner.dependencies_satisfied is False
        assert fake.calls == []

    def test_dotnet_on_the_path_satisfies_the_check(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(scanner, "_is_offline_mode", lambda: False)
        assert scanner.validate_plugin_dependencies() is True

    def test_offline_mode_skips_the_scanner_without_looking_for_dotnet(
        self, tree, tmp_path, monkeypatch
    ):
        def must_not_look(cmd):
            raise AssertionError("looked for the executable under --offline")

        monkeypatch.setattr(ds, "find_executable", must_not_look)
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(scanner, "_is_offline_mode", lambda: True)
        assert scanner.validate_plugin_dependencies() is False

    def test_a_scanner_whose_tool_is_unavailable_stays_unsatisfied(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "not available on this platform"
        assert scanner.validate_plugin_dependencies() is False

    def test_there_is_no_install_command_because_the_sdk_is_the_users_own(
        self, tree, tmp_path
    ):
        assert _scanner(tree, tmp_path).custom_install_commands == {}


class TestHelpers:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("App.csproj", True),
            ("App.fsproj", True),
            ("App.vbproj", True),
            ("APP.CSPROJ", True),
            (".csproj", False),
            ("App.sln", False),
            ("App.csproj.user", False),
            ("App.props", False),
        ],
    )
    def test_project_names(self, name, expected):
        assert ds.is_project_name(name) is expected

    def test_the_clean_report_converts_to_no_results(self):
        assert ds.convert_report(NEGATIVE, project_uri="a.csproj") == []

    def test_a_report_without_vulnerabilities_keys_converts_to_no_results(self):
        document = copy.deepcopy(NEGATIVE_WITH_PACKAGES)
        assert ds.convert_report(document, project_uri="a.csproj") == []
