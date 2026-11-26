# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""BinskimScanner: the invocation, the exit status, and the SARIF it grades.

The inline SARIF below is written by hand (rule ids ``BA####``, levels
error/warning/note, kind fail/pass) to reach each branch of the grading. The shape of
a real log (id-and-arguments messages, percent-encoded absolute ``file://`` URIs, no
``kind``) is pinned by the captured logs in tests/test_data/scanners/binskim/captured,
which the ``TestCapturedLog`` rows read. The scan() tests replace the subprocess with
a fake, so they run on every platform without the binary.
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


def _sarif(results: List[dict], rules: Optional[List[dict]] = None) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {"driver": {"name": "BinSkim", "rules": rules or []}},
                    "results": results,
                }
            ],
        }
    )


def _id_message_result(rule: str, arguments: List[str]) -> dict:
    """A result whose message names a message string, as BinSkim writes them."""
    return {
        "ruleId": rule,
        "ruleIndex": 0,
        "level": "error",
        "message": {"id": "Error", "arguments": arguments},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "bin/app"}}}],
    }


def _rule(rule: str, error_text: str) -> dict:
    return {"id": rule, "messageStrings": {"Error": {"text": error_text}}}


#: The captured runs were written on Linux, so their file URIs carry no drive; on
#: Windows no target lies under a drive-less path and they stay as written.
posix_paths_only = pytest.mark.skipif(
    sys.platform == "win32", reason="the captured URIs are POSIX paths with no drive"
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


class TestAlphaPlugin:
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

    def test_every_run_gets_invariant_globalization(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """Without ICU the .NET runtime aborts before BinSkim starts (exit 134)."""
        monkeypatch.setenv("ASH_TEST_SENTINEL_VARIABLE", "kept")
        monkeypatch.setenv(bs.GLOBALIZATION_INVARIANT_ENV, "0")
        fake = FakeBinskim()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        env = fake.calls[0]["env"]
        assert env[bs.GLOBALIZATION_INVARIANT_ENV] == "1"
        assert env["ASH_TEST_SENTINEL_VARIABLE"] == "kept"


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


class TestMessages:
    """The message text every report reads, resolved once from the rule."""

    def test_an_id_message_gets_the_rule_text_with_its_arguments(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeBinskim(
            sarif_text=_sarif(
                [_id_message_result("BA2001", ["app"])],
                rules=[_rule("BA2001", "'{0}' was linked without it.")],
            )
        )
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        (result,) = report.get_all_results()
        body = result.message.root
        assert body.text == "'app' was linked without it."
        assert body.id == "Error"
        assert not body.arguments

    def test_a_placeholder_inside_an_argument_is_not_filled_again(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """The arguments are folded into the text and dropped, so a reader that fills
        a message's arguments into its text has nothing left to fill."""
        from automated_security_helper.utils.sarif_rule_descriptors import (
            rule_descriptors_by_result,
        )
        from automated_security_helper.utils.sarif_utils import result_message_text

        fake = FakeBinskim(
            sarif_text=_sarif(
                [_id_message_result("BA2001", ["lib{0}.so", "x"])],
                rules=[_rule("BA2001", "'{0}' and {1}.")],
            )
        )
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        (result,) = report.get_all_results()
        assert result.message.root.text == "'lib{0}.so' and x."
        (descriptor,) = rule_descriptors_by_result(report)
        assert result_message_text(result, descriptor) == "'lib{0}.so' and x."

    def test_a_message_with_text_is_left_as_written(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeBinskim(
            sarif_text=_sarif(
                [_result("BA2001", "error", "bin/app")],
                rules=[_rule("BA2001", "the rule's own text")],
            )
        )
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        (result,) = report.get_all_results()
        assert result.message.root.text == "BA2001 message"

    def test_a_rule_the_run_does_not_declare_leaves_the_id_form(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """No string to resolve, so the id and arguments stay for the readers that
        resolve them; nothing is invented."""
        fake = FakeBinskim(sarif_text=_sarif([_id_message_result("BA2001", ["app"])]))
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        (result,) = report.get_all_results()
        body = result.message.root
        assert body.text is None
        assert (body.id, body.arguments) == ("Error", ["app"])


CAPTURED = Path(__file__).resolve().parents[3] / "test_data/scanners/binskim/captured"

#: The directories the captured runs scanned (see captured/README.md).
CAPTURE_TARGETS = {
    "positive": Path("/tmp/binskim-capture/positive"),
    "negative": Path("/tmp/binskim-capture/negative"),
}


def _grade_capture(name: str, tree: Path, tmp_path: Path) -> SarifReport:
    """The captured log of run *name*, graded as the scanner grades a run's log."""
    report = SarifReport.model_validate_json(
        (CAPTURED / f"{name}.sarif").read_text(encoding="utf-8")
    )
    return _scanner(tree, tmp_path)._post_process_sarif(
        report, [], CAPTURE_TARGETS[name]
    )


class TestCapturedLog:
    """The adapter over BinSkim 4.4.9.14's own output, not a guess at its shape."""

    @posix_paths_only
    def test_the_positive_log_grades_to_one_finding_per_rule_and_file(
        self, tree, tmp_path
    ):
        report = _grade_capture("positive", tree, tmp_path)
        assert _findings(report) == [
            (rule, "error", "HIGH", path)
            for path in ("bin/app", "sp ace/app 2")
            for rule in ("BA3001", "BA3003", "BA3010", "BA3011")
        ]

    def test_the_positive_log_grades_every_result_high_on_any_host(
        self, tree, tmp_path
    ):
        report = _grade_capture("positive", tree, tmp_path)
        assert [
            (rule, level, severity) for rule, level, severity, _ in _findings(report)
        ] == [
            (rule, "error", "HIGH")
            for _path in range(2)
            for rule in ("BA3001", "BA3003", "BA3010", "BA3011")
        ]

    @posix_paths_only
    def test_a_percent_encoded_uri_is_decoded_to_the_real_path(self, tree, tmp_path):
        """BinSkim writes ``sp%20ace/app%202``; the path on disk has spaces."""
        uris = {u for *_, u in _findings(_grade_capture("positive", tree, tmp_path))}
        assert "sp ace/app 2" in uris
        assert not [u for u in uris if "%" in u]

    def test_the_message_text_is_resolved_through_the_rule_message_strings(
        self, tree, tmp_path
    ):
        """The log gives ``{"id": "Error", "arguments": [...]}`` and no text; the graded
        result carries the rule's sentence with the arguments filled in."""
        from automated_security_helper.utils.sarif_rule_descriptors import (
            rule_descriptors_by_result,
        )
        from automated_security_helper.utils.sarif_utils import result_message_text

        raw = json.loads((CAPTURED / "positive.sarif").read_text(encoding="utf-8"))
        assert {
            json.dumps(result["message"], sort_keys=True)
            for result in raw["runs"][0]["results"]
            if result["ruleId"] == "BA3003"
        } == {
            '{"arguments": ["app", "app"], "id": "Error"}',
            '{"arguments": ["app%202", "app%202"], "id": "Error"}',
        }
        report = _grade_capture("positive", tree, tmp_path)
        results = report.get_all_results()
        descriptors = rule_descriptors_by_result(report)
        stack = next(r for r in results if r.ruleId == "BA3003")
        body = stack.message.root
        assert body.id == "Error" and not body.arguments
        assert body.text.startswith(
            "The stack protector was not found in 'app'. This may be because"
        )
        assert body.text.endswith("Modules did not meet the criteria: app")
        for result, descriptor in zip(results, descriptors):
            text = result.message.root.text
            assert text and "{0}" not in text and "{1}" not in text
            assert result_message_text(result, descriptor) == text

    def test_the_negative_log_has_no_findings(self, tree, tmp_path):
        assert _findings(_grade_capture("negative", tree, tmp_path)) == []

    @pytest.mark.parametrize(
        ("uri", "expected"),
        [
            pytest.param(uri, expected, marks=posix_paths_only)
            for uri, expected in (
                ("file:///t/x/sp%20ace/a%2Bb", "sp ace/a+b"),
                ("file://localhost/t/x/a", "a"),
                ("file:///t/x/a", "a"),
                ("file:///t/elsewhere/a", "file:///t/elsewhere/a"),
            )
        ]
        + [("bin/app", "bin/app")],
    )
    def test_relative_uri(self, uri, expected):
        assert BinskimScanner._relative_uri(uri, Path("/t/x")) == expected

    @pytest.mark.skipif(sys.platform != "win32", reason="a Windows drive path")
    @pytest.mark.parametrize(
        ("uri", "expected"),
        [
            ("file:///C:/t/x/sp%20ace/a.dll", "sp ace/a.dll"),
            ("file:///C:/t/elsewhere/a.dll", "file:///C:/t/elsewhere/a.dll"),
        ],
    )
    def test_relative_uri_with_a_drive(self, uri, expected):
        assert BinskimScanner._relative_uri(uri, Path("C:/t/x")) == expected


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
        monkeypatch.setattr(bs, "installed_executable", lambda: None)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False

    def test_the_missing_tool_warning_names_the_pinned_install(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(bs, "find_executable", lambda cmd: None)
        monkeypatch.setattr(bs, "installed_executable", lambda: None)
        seen: List[str] = []
        monkeypatch.setattr(
            bs.ASH_LOGGER, "warning", lambda msg, *a, **k: seen.append(msg)
        )
        _scanner(tree, tmp_path).validate_plugin_dependencies()
        assert len(seen) == 1
        assert "--tool binskim" in seen[0]
        assert "ash_binskim_plugins" in seen[0]

    def test_present_binary_satisfies_the_check(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_the_build_ash_installed_is_found_without_a_link(
        self, tree, tmp_path, monkeypatch
    ):
        """Windows gets no ``BinSkim`` link, so the build's own directory is read."""
        installed = tmp_path / "bin" / "binskim-4.4.9.14-win-x64" / "BinSkim.exe"
        monkeypatch.setattr(bs, "find_executable", lambda cmd: None)
        monkeypatch.setattr(bs, "installed_executable", lambda: installed)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is True
        assert scanner.command == str(installed)
        argv = scanner._build_arguments(tree, tmp_path / "r.sarif")
        assert argv[:2] == [str(installed), "analyze"]

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
        [
            b"MZ\x90\x00",
            ELF_HEAD,
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe\x00\x00\x00\x02",
        ],
        ids=["pe", "elf", "macho64", "fat"],
    )
    def test_a_tree_with_a_binary_has_none(self, tmp_path, head):
        src = tmp_path / "src"
        src.mkdir()
        (src / "x.bin").write_bytes(head)
        assert _scanner(src, tmp_path).nothing_to_scan_reason() is None

    @pytest.mark.parametrize(
        "head",
        [
            b"\xca\xfe\xba\xbe\x00\x00\x00\x34",  # Java 8 class file
            b"\xca\xfe\xba\xbe\x00\x00\x00\x2d",  # Java 1.1, the first major
            b"\xca\xfe\xba\xbe\x00\x03\x00\x2d",  # Java 1.0.2, minor 3
            b"\xca\xfe\xba\xbe",  # too short to be either
        ],
        ids=["java8", "java1.1", "java1.0.2", "truncated"],
    )
    def test_a_java_class_file_is_not_a_binary_for_binskim(self, tmp_path, head):
        """A class file shares the fat Mach-O magic number; a tree of them is SKIPPED."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "A.class").write_bytes(head)
        assert _scanner(src, tmp_path).nothing_to_scan_reason() is not None

    def test_a_binary_under_git_is_not_counted(self, tmp_path):
        src = tmp_path / "src"
        (src / ".git").mkdir(parents=True)
        (src / ".git" / "obj").write_bytes(ELF_HEAD)
        assert _scanner(src, tmp_path).nothing_to_scan_reason() is not None


class TestInstall:
    def test_the_scanner_offers_the_module_local_install_for_every_build(
        self, tree, tmp_path, monkeypatch
    ):
        """The pin is binskim_install.py's, not the shared tool_downloads table's."""
        from automated_security_helper.plugin_modules.ash_binskim_plugins import (
            binskim_install,
        )
        from automated_security_helper.utils.tool_downloads import (
            downloadable_tools,
        )

        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        assert "binskim" not in downloadable_tools()
        commands = _scanner(tree, tmp_path).custom_install_commands
        for platform_name, arch in binskim_install.RIDS:
            (command,) = commands[platform_name][arch]
            assert "install_binskim" in " ".join(command.args)
        assert "arm64" not in commands.get("darwin", {})


class TestSandboxRequirements:
    def test_only_the_invariant_variable_is_granted(self):
        from automated_security_helper.utils.sandbox.policy import SandboxRequirements

        requirements = BinskimScanner.sandbox_requirements
        assert requirements == SandboxRequirements(
            env_names=(bs.GLOBALIZATION_INVARIANT_ENV,)
        )
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
        # The captured run (tests/test_data/scanners/binskim/captured) is the corpus
        # the register's consistency gate reads these against.
        for cell in (
            declared.rule_id,
            declared.severity,
            declared.file_path,
            declared.message,
            declared.references,
            declared.tags,
            declared.extras,
        ):
            assert cell.state is FacetState.MAPPED
        assert declared.remediation_text.state is FacetState.DROPPED
        assert declared.resource_id.state is FacetState.NA
        assert declared.line_range.state is FacetState.NA

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
