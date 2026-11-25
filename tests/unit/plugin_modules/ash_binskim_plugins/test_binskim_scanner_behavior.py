# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""BinskimScanner: the invocation, the exit status, and the SARIF it grades.

The SARIF below is written by hand in the shape sarif-sdk gives BinSkim logs (rule ids
``BA####``, ``file://`` artifact URIs, levels error/warning/note, kind fail/pass). It is
NOT a capture of a real run: BinSkim was not available when the tests were written.
Replace it with a captured log when one exists. The scan() tests replace the subprocess
with a fake, so they run on every platform without the binary.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_binskim_plugins
from automated_security_helper.plugin_modules.ash_binskim_plugins import (
    binskim_scanner as bs,
)
from automated_security_helper.plugin_modules.ash_binskim_plugins.binskim_scanner import (
    BinskimScanner,
    BinskimScannerConfig,
    BinskimScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

ELF_HEAD = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8


def _result(rule: str, level: Optional[str], uri: str, kind: str = "fail") -> dict:
    result: Dict[str, Any] = {
        "ruleId": rule,
        "kind": kind,
        "message": {"text": f"{rule} message"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": uri}}},
        ],
    }
    if level is not None:
        result["level"] = level
    return result


def _sarif(results: List[dict]) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {"driver": {"name": "BinSkim", "rules": []}},
                    "results": results,
                }
            ],
        }
    )


class FakeBinskim:
    """Stands in for _run_subprocess: records argv, writes the report it is given."""

    def __init__(
        self,
        results: Optional[List[dict]] = None,
        exit_code: int = 0,
        sarif_text: Optional[str] = None,
        write_report: bool = True,
        timed_out: bool = False,
        stderr: str = "",
    ):
        self.results = results or []
        self.exit_code = exit_code
        self.sarif_text = sarif_text
        self.write_report = write_report
        self.timed_out = timed_out
        self.stderr = stderr
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            if self.write_report and not self.timed_out:
                out = next(a for a in command if a.startswith("--output="))
                path = Path(out.split("=", 1)[1])
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    self.sarif_text
                    if self.sarif_text is not None
                    else _sarif(self.results),
                    encoding="utf-8",
                )
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": "",
                "stderr": self.stderr,
                "timed_out": self.timed_out,
            }

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(source: Path, tmp_path: Path, **options) -> BinskimScanner:
    output = tmp_path / "out"
    return BinskimScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=BinskimScannerConfig(
            enabled=True, options=BinskimScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "bin").mkdir(parents=True)
    (src / "bin" / "app").write_bytes(ELF_HEAD)
    (src / "README.txt").write_text("hello\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(bs, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch, target: Optional[Path] = None):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type="source"
    )


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
            )
        )
    return out


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert BinskimScannerConfig().enabled is True
        assert BinskimScannerConfig().name == "binskim"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "binskim")

    def test_the_module_exports_the_scanner(self):
        assert ash_binskim_plugins.ASH_SCANNERS == [BinskimScanner]
        assert ash_binskim_plugins.ASH_REPORTERS == []

    def test_declared_class_vars(self):
        assert BinskimScanner.python_only is False
        assert BinskimScanner.success_exit_codes == {0}


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeBinskim()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        argv = fake.argv
        assert argv[:2] == ["BinSkim", "analyze"]
        assert argv[-2:] == ["--", tree.absolute().as_posix()]
        for flag in (
            "--recurse=true",
            "--level=Error;Warning;Note",
            "--kind=Fail",
            "--quiet=true",
            "--disable-telemetry=true",
            "--ignorePdbLoadError=true",
        ):
            assert flag in argv
        assert any(
            a.startswith("--output=") and a.endswith("binskim.sarif") for a in argv
        )

    @pytest.mark.parametrize(
        "prefix", ["--config", "--sympath", "--plugin", "--post-uri", "--baseline"]
    )
    def test_flags_that_read_the_tree_or_reach_the_network_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, prefix
    ):
        fake = FakeBinskim()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert not [a for a in fake.argv if a.startswith(prefix)]

    def test_scan_timeout_reaches_the_subprocess(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeBinskim()
        _run(_scanner(tree, tmp_path, scan_timeout=77), fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 77


class TestReport:
    def test_levels_map_to_matching_severity_and_level(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        root = tree.absolute().as_posix()
        results = [
            _result("BA2001", "error", f"file://{root}/bin/app"),
            _result("BA2002", "warning", f"file://{root}/bin/app"),
            _result("BA2003", "note", f"file://{root}/bin/app"),
            _result("BA2004", None, "bin/app"),
        ]
        report = _run(_scanner(tree, tmp_path), FakeBinskim(results), monkeypatch)
        assert _findings(report) == [
            ("BA2001", "error", "HIGH", "bin/app"),
            ("BA2002", "warning", "MEDIUM", "bin/app"),
            ("BA2003", "note", "LOW", "bin/app"),
            ("BA2004", "warning", "MEDIUM", "bin/app"),
        ]

    def test_severity_mapping_over_the_committed_reference_log(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """The mapping read over a committed log file rather than inline dicts.

        The log is hand-written, not captured (tests/test_data/scanners/binskim/
        README.md says so); this row's job is the file-to-severity path.
        """
        text = (
            Path(__file__).resolve().parents[3]
            / "test_data"
            / "scanners"
            / "binskim"
            / "reference.sarif"
        ).read_text(encoding="utf-8")
        report = _run(
            _scanner(tree, tmp_path), FakeBinskim(sarif_text=text), monkeypatch
        )
        assert _findings(report) == [
            ("BA2008", "error", "HIGH", "bin/app.exe"),
            ("BA3010", "warning", "MEDIUM", "bin/tool"),
            ("BA3003", "note", "LOW", "bin/tool"),
        ]

    def test_non_failure_results_are_dropped(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        results = [
            _result("BA2001", "none", "bin/app", kind="pass"),
            _result("BA2002", "none", "bin/app", kind="notApplicable"),
        ]
        report = _run(_scanner(tree, tmp_path), FakeBinskim(results), monkeypatch)
        assert _findings(report) == []

    def test_negative_control_clean_log_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeBinskim([]), monkeypatch)
        assert _findings(report) == []

    def test_a_uri_outside_the_target_is_left_alone(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        results = [_result("BA2001", "error", "file:///elsewhere/x.dll")]
        report = _run(_scanner(tree, tmp_path), FakeBinskim(results), monkeypatch)
        assert _findings(report)[0][3] == "file:///elsewhere/x.dll"


class TestExitStatus:
    @pytest.mark.parametrize("code", [1, 2, 126, 137])
    def test_any_nonzero_exit_fails_even_with_a_report_on_disk(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        results = [_result("BA2001", "error", "bin/app")]
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakeBinskim(results, exit_code=code),
                monkeypatch,
            )

    def test_findings_do_not_fail_the_run(self, tree, tmp_path, on_path, monkeypatch):
        results = [_result("BA2001", "error", "bin/app")]
        report = _run(_scanner(tree, tmp_path), FakeBinskim(results), monkeypatch)
        assert len(_findings(report)) == 1

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeBinskim(timed_out=True, exit_code=124)
        # The base words the limit through a redacting token, so the number is
        # not asserted; the scan_timeout option it points the operator at is.
        with pytest.raises(ScannerError, match=r"timed out.*options\.scan_timeout"):
            _run(_scanner(tree, tmp_path, scan_timeout=5), fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 5

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakeBinskim(write_report=False),
                monkeypatch,
            )

    def test_a_report_left_by_an_earlier_run_is_removed_first(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.results_dir = tmp_path / "results"
        stale = scanner.results_dir / "source" / "binskim.sarif"
        stale.parent.mkdir(parents=True)
        stale.write_text("stale")
        _, results_file, _ = scanner._execute_scan(tree, "source", [])
        assert results_file == stale
        assert not stale.exists()

    def test_stderr_is_not_copied_into_errors(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeBinskim(stderr="quoted tree text SENTINEL"), monkeypatch)
        assert "SENTINEL" not in " ".join(str(e) for e in scanner.errors)


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "text", ["not json", "{", "[]", '{"version": "2.1.0"}'], ids=str
    )
    def test_unusable_output_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch, text
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakeBinskim(sarif_text=text),
                monkeypatch,
            )

    def test_an_empty_report_file_is_not_a_clean_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakeBinskim(sarif_text=""),
                monkeypatch,
            )


class TestToolAbsent:
    def test_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(bs, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False

    def test_present_binary_satisfies_the_check(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_an_unavailable_dependency_reason_wins(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        # on_path makes the PATH probe answer True, so only the recorded reason
        # (a pydantic field, set on the instance) can make this False.
        assert scanner.validate_plugin_dependencies() is True
        scanner.dependency_unavailable_reason = "no platform build"
        assert scanner.validate_plugin_dependencies() is False


class TestNothingToScan:
    def test_a_tree_with_no_binary_has_a_reason(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "a.py").write_text("print(1)\n")
        assert (
            "no PE, ELF or Mach-O" in _scanner(src, tmp_path).nothing_to_scan_reason()
        )

    @pytest.mark.parametrize(
        "head",
        [b"MZ\x90\x00", ELF_HEAD, b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"],
        ids=["pe", "elf", "macho64", "fat"],
    )
    def test_a_tree_with_a_binary_has_none(self, tmp_path, head):
        src = tmp_path / "src"
        src.mkdir()
        (src / "x.bin").write_bytes(head)
        assert _scanner(src, tmp_path).nothing_to_scan_reason() is None

    def test_a_binary_under_git_is_not_counted(self, tmp_path):
        src = tmp_path / "src"
        (src / ".git").mkdir(parents=True)
        (src / ".git" / "obj").write_bytes(ELF_HEAD)
        assert _scanner(src, tmp_path).nothing_to_scan_reason() is not None


class TestInstall:
    def test_an_unpinned_tool_constructs_with_no_install_commands(self, tree, tmp_path):
        """Without a pin in utils/tool_downloads.py the scanner must still
        construct (it raised ToolNotProvisionableError before), and it offers no
        install: the tool is reported missing rather than half-provisioned."""
        from automated_security_helper.utils.tool_downloads import (
            downloadable_tools,
        )

        scanner = _scanner(tree, tmp_path)
        if "binskim" in downloadable_tools():
            pytest.skip(
                "pinned centrally; see test_pinned_commands_cover_every_platform"
            )
        assert not scanner.custom_install_commands

    def test_pinned_commands_cover_every_platform(self, tree, tmp_path):
        """Takes effect when the integration lane adds the pin."""
        from automated_security_helper.utils.tool_downloads import (
            downloadable_tools,
            supported_platforms,
        )

        if "binskim" not in downloadable_tools():
            pytest.skip("no binskim pin in utils/tool_downloads.py yet")
        commands = _scanner(tree, tmp_path).custom_install_commands
        for platform_name, arch in supported_platforms("binskim"):
            assert commands[platform_name][arch]


class TestSandboxRequirements:
    def test_the_strict_default_grants_nothing(self):
        from automated_security_helper.utils.sandbox.policy import SandboxRequirements

        requirements = BinskimScanner.sandbox_requirements
        assert requirements == SandboxRequirements()
        assert not requirements.network
        assert not requirements.network_requires_grant
        assert not requirements.env_prefixes

    def test_no_flag_that_needs_the_network_is_passed(self, tree, tmp_path):
        """The strict sandbox is only right while the argv reaches nothing."""
        argv = _scanner(tree, tmp_path)._build_arguments(tree, tmp_path / "r.sarif")
        assert not [a for a in argv if a.startswith(("--sympath", "--post-uri"))]


class TestFacetsRegister:
    def test_the_register_row_is_declared_on_the_class_itself(self):
        from automated_security_helper.base.scanner_facets import (
            SCANNER_FACETS_ATTR,
            FacetState,
            ScannerFacets,
        )

        declared = vars(BinskimScanner).get(SCANNER_FACETS_ATTR)
        assert isinstance(declared, ScannerFacets)
        assert declared.rule_id.state is FacetState.MAPPED
        assert declared.resource_id.state is FacetState.NA

    def test_the_operational_row_mirrors_the_class(self, tree, tmp_path):
        from automated_security_helper.base.scanner_operational_facets import (
            OPERATIONAL_FACETS_ATTR,
        )

        row = vars(BinskimScanner)[OPERATIONAL_FACETS_ATTR]
        scanner = _scanner(tree, tmp_path)
        assert row.scanner_name == scanner.config.name
        assert row.network.offline_strategy is BinskimScanner.offline_strategy
        assert row.exit_codes.success_exit_codes == tuple(
            sorted(BinskimScanner.success_exit_codes)
        )
        assert row.targets.tool_type is scanner.tool_type
        assert row.runtime.python_only is bool(scanner.is_python_only())
        assert row.runtime.use_uv_tool is bool(scanner.use_uv_tool)
