# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""PmdScanner: the invocation, the exit status, and the report.

The report tests read SARIF that PMD 7.29.0 (the pinned version) actually wrote.
It was produced with::

    pmd check --no-progress --no-cache --rulesets=category/java/security.xml \
        --format=sarif --report-file=<file> --dir=<dir>

over a file with a hard-coded AES key (line 7) and a hard-coded initialization vector
(line 10), and over a clean file. Only the directory in each ``file://`` URI differs
from the capture: the tests put the tree's own path there, as PMD would. The scan()
tests replace the subprocess with a fake that serves these captures, so they run on
every platform without PMD or a JVM.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_pmd_plugins
from automated_security_helper.plugin_modules.ash_pmd_plugins import (
    pmd_scanner as ps,
)
from automated_security_helper.plugin_modules.ash_pmd_plugins.pmd_scanner import (
    PMD_ARCHIVE_SHA256,
    PmdScanner,
    PmdScannerConfig,
    PmdScannerConfigOptions,
    severity_for_level,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit

#: The directory the capture was made in; replaced by the tree under test.
CAPTURE_ROOT = "file:///work/src"

_CAPTURED = (
    Path(__file__).resolve().parents[3] / "test_data" / "scanners" / "pmd" / "captured"
)

#: PMD 7.29.0 over a tree holding Crypto.java (a hard-coded key and a hard-coded IV);
#: tests/test_data/scanners/pmd/captured/positive.sarif.
POSITIVE_CAPTURE = (_CAPTURED / "positive.sarif").read_text(encoding="utf-8")

#: PMD 7.29.0 over a tree with nothing to report (exit 0);
#: tests/test_data/scanners/pmd/captured/negative.sarif.
NEGATIVE_CAPTURE = (_CAPTURED / "negative.sarif").read_text(encoding="utf-8")

#: What the positive capture must produce, written out by hand from the fixture it
#: was captured over, not derived from the code under test.
POSITIVE_EXPECTED = [
    ("HardCodedCryptoKey", "warning", "MEDIUM", "Crypto.java", 7),
    ("InsecureCryptoIv", "warning", "MEDIUM", "Crypto.java", 10),
]


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


class FakePmd:
    """Stands in for _run_subprocess: records argv, writes a captured report."""

    def __init__(
        self,
        capture: Optional[str] = POSITIVE_CAPTURE,
        exit_code: int = 4,
        timed_out: bool = False,
        stderr: str = "",
    ):
        self.capture, self.exit_code = capture, exit_code
        self.timed_out, self.stderr = timed_out, stderr
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            report_arg = next(a for a in command if a.startswith("--report-file="))
            path = Path(report_arg.split("=", 1)[1])
            if self.capture is not None and not self.timed_out:
                text = self.capture.replace(
                    CAPTURE_ROOT, Path(scanner.context.source_dir).resolve().as_uri()
                )
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            scanner.exit_code = self.exit_code
            response: Dict[str, Any] = {
                "returncode": self.exit_code,
                "stdout": "",
                "stderr": self.stderr,
            }
            if self.timed_out:
                response["timed_out"] = True
            return response

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(
    source: Path,
    tmp_path: Path,
    **options,
) -> PmdScanner:
    config = get_default_config()
    record_provenance(config, in_tree=[], trusted=AshConfig())
    output = tmp_path / "out"
    return PmdScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=config,
        ),
        config=PmdScannerConfig(
            enabled=True, options=PmdScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "Crypto.java").write_text("public class Crypto {}\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ps, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(
    scanner: PmdScanner,
    fake: FakePmd,
    monkeypatch,
    target: Optional[Path] = None,
    target_type: str = "source",
):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


def _flag(argv: List[str], prefix: str) -> Optional[str]:
    """The value of the ``--flag=value`` token starting ``prefix``, or None."""
    for token in argv:
        if token.startswith(prefix):
            return token[len(prefix) :]
    return None


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert PmdScannerConfig().enabled is True
        assert PmdScannerConfig().name == "pmd"

    def test_the_module_exports_the_scanner(self):
        assert ash_pmd_plugins.ASH_SCANNERS == [PmdScanner]
        assert ash_pmd_plugins.ASH_REPORTERS == []

    def test_class_variables_are_set_deliberately(self):
        assert PmdScanner.python_only is False
        assert PmdScanner.success_exit_codes == {0, 4}
        assert PmdScanner.sandbox_requirements == SandboxRequirements()


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakePmd()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[:2] == ["pmd", "check"]
        for expected in (
            "--no-progress",
            "--no-cache",
            "--format=sarif",
            "--rulesets=category/java/security.xml",
            "--minimum-priority=5",
            "--suppress-marker=ASH_PMD_NO_INLINE_SUPPRESSION",
        ):
            assert expected in argv
        # The source target is "." from the source dir (the subprocess's cwd).
        assert argv[-1] == "--dir=."
        assert fake.calls[0]["cwd"] is None, "the run starts in the source directory"

    def test_every_value_is_one_equals_token(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """A separate value token would be read as a path or an unknown option."""
        scanner = _scanner(tree, tmp_path)
        fake = FakePmd()
        _run(scanner, fake, monkeypatch)
        assert all(a.startswith("--") or a in ("pmd", "check") for a in fake.argv)

    def test_the_inline_suppression_marker_is_one_no_source_file_uses(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """PMD hides a violation on a ``NOPMD`` line; that comment is the tree's."""
        scanner = _scanner(tree, tmp_path)
        fake = FakePmd()
        _run(scanner, fake, monkeypatch)
        marker = _flag(fake.argv, "--suppress-marker=")
        assert marker and marker != "NOPMD"

    def test_the_report_goes_to_a_file_under_the_results_directory(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakePmd()
        _run(scanner, fake, monkeypatch)
        report = Path(_flag(fake.argv, "--report-file="))
        assert report.name == "pmd.sarif"
        assert report.parent.name == "source"

    @pytest.mark.parametrize(
        "forbidden",
        [
            "--cache",
            "--aux-classpath",
            "--uri",
            "--file-list",
            "--ignore-list",
            "--property",
        ],
    )
    def test_flags_that_read_the_tree_or_reach_outside_it_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, forbidden
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakePmd()
        _run(scanner, fake, monkeypatch)
        assert not any(
            a == forbidden or a.startswith(f"{forbidden}=") for a in fake.argv
        )

    def test_the_converted_target_is_an_absolute_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "X.java").write_text("class X {}\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakePmd(capture=NEGATIVE_CAPTURE, exit_code=0)
        _run(scanner, fake, monkeypatch, target=converted, target_type="converted")
        assert fake.argv[-1] == f"--dir={converted.absolute().as_posix()}"

    def test_options_choose_the_rulesets_and_priority(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(
            tree,
            tmp_path,
            rulesets=["category/java/security.xml", "category/apex/security.xml"],
            minimum_priority=3,
        )
        fake = FakePmd()
        _run(scanner, fake, monkeypatch)
        assert (
            "--rulesets=category/java/security.xml,category/apex/security.xml"
            in fake.argv
        )
        assert "--minimum-priority=3" in fake.argv

    @pytest.mark.parametrize(
        "bad",
        [
            "my-rules.xml",
            "/etc/pmd/rules.xml",
            "../rules.xml",
            "https://example.com/rules.xml",
            "category/java/security.xml,/etc/x.xml",
            "category/java/../../x.xml",
        ],
    )
    def test_a_ruleset_that_is_not_a_builtin_category_is_refused(self, bad):
        """The scanned repository would choose the rules with a path or URL."""
        with pytest.raises(ValueError):
            PmdScannerConfigOptions(rulesets=[bad])

    def test_an_empty_ruleset_list_is_refused(self):
        with pytest.raises(ValueError):
            PmdScannerConfigOptions(rulesets=[])

    def test_ash_output_directories_inside_the_target_are_excluded(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(
            scanner, "_ash_output_dirs_inside", lambda target: [Path(".ash/ash_output")]
        )
        fake = FakePmd()
        _run(scanner, fake, monkeypatch)
        assert f"--exclude={tree.absolute().as_posix()}/.ash/ash_output" in fake.argv

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakePmd()
        _run(scanner, fake, monkeypatch, target=tmp_path / "gone")
        assert fake.calls == []


class TestReport:
    def test_the_positive_capture_is_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakePmd(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_the_clean_capture_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(
            scanner, FakePmd(capture=NEGATIVE_CAPTURE, exit_code=0), monkeypatch
        )
        assert _findings(report) == []

    def test_results_are_marked_as_failures_and_tagged(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakePmd(), monkeypatch)
        for result in report.get_all_results():
            assert getattr(result.kind, "value", result.kind) == "fail"
            assert {"pmd", "sast"} <= set(result.properties.tags)

    @pytest.mark.parametrize(
        "level,severity",
        [("error", "HIGH"), ("warning", "MEDIUM"), ("note", "LOW")],
    )
    def test_each_level_maps_to_one_severity_over_the_real_capture(
        self, tree, tmp_path, on_path, monkeypatch, level, severity
    ):
        """The capture's result level rewritten to each level PMD can write."""
        text = POSITIVE_CAPTURE.replace(
            '          "level": "warning",', f'          "level": "{level}",'
        )
        assert text.count(f'"level": "{level}"') >= 2
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakePmd(capture=text), monkeypatch)
        rows = _findings(report)
        assert [(r[1], r[2]) for r in rows] == [(level, severity)] * 2

    def test_a_result_without_a_level_is_medium(self):
        assert severity_for_level(None) == "MEDIUM"

    def test_a_result_without_a_level_gets_a_warning_level(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        text = POSITIVE_CAPTURE.replace('          "level": "warning",\n', "")
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakePmd(capture=text), monkeypatch)
        assert [(r[1], r[2]) for r in _findings(report)] == [("warning", "MEDIUM")] * 2

    def test_a_uri_outside_the_target_is_left_as_it_is(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        text = POSITIVE_CAPTURE.replace(
            "file:///work/src/Crypto.java", "file:///elsewhere/Crypto.java"
        )
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakePmd(capture=text), monkeypatch)
        assert {r[3] for r in _findings(report)} == {"file:///elsewhere/Crypto.java"}

    def test_a_uri_with_escaped_characters_is_decoded(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        text = POSITIVE_CAPTURE.replace(
            "file:///work/src/Crypto.java", "file:///work/src/my%20dir/Crypto.java"
        )
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakePmd(capture=text), monkeypatch)
        assert {r[3] for r in _findings(report)} == {"my dir/Crypto.java"}


class TestExitStatus:
    def test_four_means_violations_and_is_a_success(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakePmd(exit_code=4), monkeypatch)
        assert scanner.exit_code == 4
        assert scanner._exit_code_accepted()

    def test_zero_means_clean_and_is_a_success(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakePmd(capture=NEGATIVE_CAPTURE, exit_code=0), monkeypatch)
        assert scanner._exit_code_accepted()

    @pytest.mark.parametrize("code", [1, 2, 5, 126, 137])
    def test_any_other_exit_fails_the_scan_even_with_a_report_on_disk(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        """Exit 5 is a file PMD could not analyze: the report is partial."""
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakePmd(exit_code=code), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakePmd(capture=None, exit_code=0), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        first = FakePmd()
        _run(scanner, first, monkeypatch)
        report = Path(_flag(first.argv, "--report-file="))
        assert report.exists(), "the first run left its report"
        with pytest.raises(ScannerError):
            _run(scanner, FakePmd(capture=None, exit_code=0), monkeypatch)
        assert not report.exists()

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=5)
        fake = FakePmd(timed_out=True, exit_code=0)
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 5

    def test_the_tools_stderr_is_not_copied_into_the_scans_errors(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner._process_command_response(
            {
                "returncode": 0,
                "stdout": "",
                "stderr": "ParseException: Encountered PLANTED-TOKEN",
            }
        )
        assert not any("PLANTED-TOKEN" in line for line in scanner.errors)

    def test_the_failure_message_names_the_log_and_does_not_quote_it(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.exit_code = 5
        results = tmp_path / "out" / "source" / "pmd.sarif"
        message = scanner._describe_scan_failure(ScannerError("boom"), results)
        assert "stderr.log" in message
        assert "exit code 5" in message
        assert "not quoted" in message

    def test_a_failure_before_the_tool_started_has_no_exit_code(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        message = scanner._describe_scan_failure(
            ScannerError("boom"), None, tool_started=False
        )
        assert "was not started" in message
        assert "exit code" not in message


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "text",
        [
            "",
            "not json at all",
            "[1, 2, 3]",
            '{"unexpected": "shape"}',
            '{"version": "2.1.0", "runs": "none"}',
        ],
    )
    def test_a_report_that_is_not_sarif_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch, text
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakePmd(capture=text, exit_code=4), monkeypatch)


class TestDependencyCheck:
    def test_a_missing_pmd_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ps, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False

    def test_a_missing_java_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            ps, "find_executable", lambda cmd: None if cmd == "java" else "/fake/pmd"
        )
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False

    def test_pmd_and_java_present_satisfy_them(self, tree, tmp_path, on_path):
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is True

    def test_missing_pmd_never_reaches_the_tool(self, tree, tmp_path, monkeypatch):
        monkeypatch.setattr(ps, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        fake = FakePmd()
        assert _run(scanner, fake, monkeypatch) is False
        assert scanner.dependencies_satisfied is False
        assert fake.calls == []


class TestInstall:
    @pytest.mark.parametrize("platform", ["linux", "darwin", "windows"])
    @pytest.mark.parametrize("arch", ["amd64", "arm64"])
    def test_install_commands_cover_every_platform(self, tmp_path, platform, arch):
        """The PMD archive is portable, so every pair has the same pinned install."""
        scanner = _scanner(tmp_path, tmp_path)
        commands = scanner.get_installation_commands(platform, arch)
        assert commands, f"no install command for {platform}/{arch}"
        assert PMD_ARCHIVE_SHA256 in str(commands[0])

    def test_the_pinned_release_is_a_stable_release_with_a_full_digest(self):
        assert ps.PMD_VERSION.count(".") == 2
        assert all(part.isdigit() for part in ps.PMD_VERSION.split("."))
        assert len(PMD_ARCHIVE_SHA256) == 64
        assert ps.PMD_ARCHIVE_URL.startswith("https://github.com/pmd/pmd/releases/")
        assert ps.PMD_VERSION in ps.PMD_ARCHIVE_URL
