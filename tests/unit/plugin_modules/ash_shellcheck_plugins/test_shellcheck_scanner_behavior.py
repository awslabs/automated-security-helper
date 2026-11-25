# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ShellCheckScanner: target selection, json1 conversion, severity, failures.

The conversion tests read json1 that ShellCheck 0.11.0 (the pinned version)
actually printed for a three-line script (``bad.sh``, below) and for a clean one;
the argv was ``shellcheck --norc --format=json1 -- <file>``. The scan() tests
replace the subprocess with a fake that serves that output, so they run on every
platform without the binary.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules import ash_shellcheck_plugins
from automated_security_helper.plugin_modules.ash_shellcheck_plugins import (
    shellcheck_scanner as ss,
)
from automated_security_helper.plugin_modules.ash_shellcheck_plugins.shellcheck_scanner import (
    SHELLCHECK_LEVEL_MAP,
    ShellCheckScanner,
    ShellCheckScannerConfig,
    ShellCheckScannerConfigOptions,
    convert_json1_comments,
    shebang_interpreter,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance

pytestmark = pytest.mark.unit

#: The script the capture below was made from:
#:   #!/bin/bash
#:   echo $1
#:   for f in $(ls); do cat $f; done
#:   x=`date`
BAD_SH_JSON1 = (
    r'{"comments":[{"file":"bad.sh","line":2,"endLine":2,"column":6,"endColumn":8,'
    r'"level":"info","code":2086,"message":"Double quote to prevent globbing and '
    r'word splitting.","fix":{"replacements":[{"column":6,"endColumn":6,"endLine":2,'
    r'"insertionPoint":"afterEnd","line":2,"precedence":7,"replacement":"\""},'
    r'{"column":8,"endColumn":8,"endLine":2,"insertionPoint":"beforeStart","line":2,'
    r'"precedence":7,"replacement":"\""}]}},{"file":"bad.sh","line":3,"endLine":3,'
    r'"column":10,"endColumn":15,"level":"error","code":2045,"message":"Iterating '
    r'over ls output is fragile. Use globs.","fix":null},{"file":"bad.sh","line":3,'
    r'"endLine":3,"column":24,"endColumn":26,"level":"info","code":2086,"message":'
    r'"Double quote to prevent globbing and word splitting.","fix":{"replacements":'
    r'[{"column":24,"endColumn":24,"endLine":3,"insertionPoint":"afterEnd","line":3,'
    r'"precedence":10,"replacement":"\""},{"column":26,"endColumn":26,"endLine":3,'
    r'"insertionPoint":"beforeStart","line":3,"precedence":10,"replacement":"\""}]}},'
    r'{"file":"bad.sh","line":4,"endLine":4,"column":1,"endColumn":2,"level":"warning",'
    r'"code":2034,"message":"x appears unused. Verify use (or export if used '
    r'externally).","fix":null},{"file":"bad.sh","line":4,"endLine":4,"column":3,'
    r'"endColumn":9,"level":"style","code":2006,"message":"Use $(...) notation '
    r'instead of legacy backticks `...`.","fix":{"replacements":[{"column":3,'
    r'"endColumn":4,"endLine":4,"insertionPoint":"afterEnd","line":4,"precedence":8,'
    r'"replacement":"$("},{"column":8,"endColumn":9,"endLine":4,"insertionPoint":'
    r'"beforeStart","line":4,"precedence":8,"replacement":")"}]}}]}'
)

#: What ShellCheck printed for a clean script (status 0).
CLEAN_JSON1 = '{"comments":[]}'

#: (ruleId, SARIF level, ASH severity, uri, startLine, startColumn), written out
#: by hand from the capture's script, not derived from the converter under test.
BAD_SH_EXPECTED = [
    ("SC2086", "note", "LOW", "bad.sh", 2, 6),
    ("SC2045", "error", "HIGH", "bad.sh", 3, 10),
    ("SC2086", "note", "LOW", "bad.sh", 3, 24),
    ("SC2034", "warning", "MEDIUM", "bad.sh", 4, 1),
    ("SC2006", "none", "INFO", "bad.sh", 4, 3),
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
                loc.region.startColumn,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Conversion and severity
# ---------------------------------------------------------------------------


class TestConversion:
    def test_the_captured_report_is_rated_and_located(self):
        comments = json.loads(BAD_SH_JSON1)["comments"]
        report = convert_json1_comments(comments)
        assert _findings(report) == BAD_SH_EXPECTED

    def test_negative_control_a_clean_capture_has_no_findings(self):
        report = convert_json1_comments(json.loads(CLEAN_JSON1)["comments"])
        assert report.get_all_results() == []
        assert report.runs[0].tool.driver.name == "ShellCheck"

    def test_each_rule_is_declared_once_with_a_help_link(self):
        report = convert_json1_comments(json.loads(BAD_SH_JSON1)["comments"])
        rules = report.runs[0].tool.driver.rules
        assert [r.id for r in rules] == ["SC2006", "SC2034", "SC2045", "SC2086"]
        assert str(rules[3].helpUri) == "https://www.shellcheck.net/wiki/SC2086"

    def test_the_report_round_trips_through_the_sarif_model(self):
        report = convert_json1_comments(json.loads(BAD_SH_JSON1)["comments"])
        text = report.model_dump_json(exclude_none=True, exclude_unset=True)
        again = SarifReport.model_validate(json.loads(text))
        assert _findings(again) == BAD_SH_EXPECTED

    @pytest.mark.parametrize(
        ("level", "severity", "sarif_level"),
        [
            ("error", "HIGH", "error"),
            ("warning", "MEDIUM", "warning"),
            ("info", "LOW", "note"),
            ("style", "INFO", "none"),
            # A level ShellCheck did not state, or one this table lacks, is the
            # more severe choice rather than under-reported.
            ("critical", "HIGH", "error"),
            (None, "HIGH", "error"),
        ],
    )
    def test_severity_and_sarif_level_agree_for_every_level(
        self, level, severity, sarif_level
    ):
        comment = {"file": "a.sh", "line": 1, "code": 2086, "message": "m"}
        if level is not None:
            comment["level"] = level
        (result,) = convert_json1_comments([comment]).get_all_results()
        assert result.properties.issue_severity == severity
        assert getattr(result.level, "value", result.level) == sarif_level

    def test_the_table_has_exactly_the_four_shellcheck_levels(self):
        assert set(SHELLCHECK_LEVEL_MAP) == {"error", "warning", "info", "style"}


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------


class TestShebang:
    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("#!/bin/bash", "bash"),
            ("#!/bin/sh -e", "sh"),
            ("#!/usr/bin/env bash", "bash"),
            ("#!/usr/bin/env -S bash -eu", "bash"),
            ("#!/usr/bin/env FOO=1 dash", "dash"),
            ("#!/usr/bin/zsh", "zsh"),
            ("#!/usr/bin/env", None),
            ("#!", None),
            ("echo hi", None),
            ("", None),
        ],
    )
    def test_interpreter_name(self, line, expected):
        assert shebang_interpreter(line) == expected


# ---------------------------------------------------------------------------
# scan() with the subprocess replaced
# ---------------------------------------------------------------------------


class FakeShellCheck:
    """Stands in for _run_subprocess: records argv/env/timeout, serves output."""

    def __init__(
        self,
        stdout: str = BAD_SH_JSON1,
        exit_code: int = 1,
        stderr: str = "",
        timed_out: bool = False,
    ):
        self.stdout, self.exit_code, self.stderr = stdout, exit_code, stderr
        self.timed_out = timed_out
        self.calls: List[dict] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, **_):
            self.calls.append({"argv": list(command), "env": env, "timeout": timeout})
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


def _scanner(
    source: Path, tmp_path: Path, output_dir: Optional[Path] = None, **options
) -> ShellCheckScanner:
    config = get_default_config()
    record_provenance(config, in_tree=[], trusted=AshConfig())
    return ShellCheckScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output_dir or tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=ShellCheckScannerConfig(
            enabled=True, options=ShellCheckScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "bin").mkdir()
    (src / "bad.sh").write_text("#!/bin/bash\necho $1\n")
    (src / "sub" / "run.sh").write_text("echo no shebang\n")
    (src / "bin" / "tool").write_text("#!/usr/bin/env bash\necho hi\n")
    # Not passed: a zsh script (ShellCheck does not support zsh), another
    # interpreter, an extensionless file with no shebang, and a non-shell name.
    (src / "z.sh").write_text("#!/usr/bin/zsh\nprint hi\n")
    (src / "bin" / "py").write_text("#!/usr/bin/env python3\nprint(1)\n")
    (src / "bin" / "plain").write_text("just text\n")
    (src / "notes.txt").write_text("#!/bin/bash\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ss, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner: ShellCheckScanner, fake: FakeShellCheck, monkeypatch, **kw):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(scanner.context.source_dir), target_type="source", **kw
    )


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert ShellCheckScannerConfig().enabled is True
        assert ShellCheckScannerConfig().name == "shellcheck"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "shellcheck")

    def test_the_module_exports_the_scanner(self):
        assert ash_shellcheck_plugins.ASH_SCANNERS == [ShellCheckScanner]
        assert ash_shellcheck_plugins.ASH_REPORTERS == []

    def test_the_scanner_declares_how_it_runs(self):
        assert ShellCheckScanner.success_exit_codes == {0, 1}
        assert ShellCheckScanner.python_only is False


class TestInvocation:
    def test_every_fixed_flag_and_the_script_paths_after_double_dash(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeShellCheck()
        report = _run(scanner, fake, monkeypatch)
        assert fake.calls[0]["argv"] == [
            "shellcheck",
            "--norc",
            "--format=json1",
            "--severity=style",
            "--",
            "bad.sh",
            "bin/tool",
            "sub/run.sh",
        ]
        assert scanner.targets_attempted == 3
        assert _findings(report) == BAD_SH_EXPECTED

    def test_the_subprocess_starts_in_the_source_directory(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        # Report paths are source-relative because argv paths are, and the base
        # starts the child in context.source_dir when no cwd is passed.
        scanner = _scanner(tree, tmp_path)
        seen: dict = {}

        def run(command, **kwargs):
            seen.update(kwargs)
            scanner.exit_code = 0
            return {"returncode": 0, "stdout": CLEAN_JSON1, "stderr": ""}

        monkeypatch.setattr(scanner, "_run_subprocess", run)
        scanner.scan(target=tree, target_type="source")
        assert "cwd" not in seen or Path(seen["cwd"]) == tree

    @pytest.mark.parametrize(
        "flag",
        [
            "-x",
            "--external-sources",
            "-a",
            "--check-sourced",
            "-e",
            "--exclude",
            "-o",
            "--enable",
            "-P",
            "--source-path",
            "-s",
            "--shell",
            "--rcfile",
        ],
    )
    def test_flags_that_follow_files_or_change_the_rules_are_never_passed(
        self, flag, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeShellCheck()
        _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        before_files = argv[: argv.index("--")]
        assert not any(a == flag or a.startswith(flag + "=") for a in before_files)

    def test_shellcheck_opts_is_removed_from_the_environment(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        monkeypatch.setenv("SHELLCHECK_OPTS", "--exclude=SC2086")
        monkeypatch.setenv("SHELLCHECK_TEST_KEPT", "1")
        scanner = _scanner(tree, tmp_path)
        fake = FakeShellCheck()
        _run(scanner, fake, monkeypatch)
        # Names narrowed into a local first, so a failure prints names only.
        names = set(fake.calls[0]["env"])
        assert "SHELLCHECK_OPTS" not in names
        assert "SHELLCHECK_TEST_KEPT" in names

    def test_global_ignore_paths_remove_a_script(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeShellCheck()
        _run(
            scanner,
            fake,
            monkeypatch,
            global_ignore_paths=[IgnorePathWithReason(path="sub/**", reason="test")],
        )
        argv = fake.calls[0]["argv"]
        assert argv[argv.index("--") + 1 :] == ["bad.sh", "bin/tool"]

    def test_output_directory_inside_the_source_is_not_scanned(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        out = tree / ".ash" / "ash_output"
        out.mkdir(parents=True)
        (out / "leftover.sh").write_text("#!/bin/sh\n")
        scanner = _scanner(tree, tmp_path, output_dir=out)
        fake = FakeShellCheck()
        _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        assert not any("leftover.sh" in a for a in argv)

    def test_a_symlink_that_leaves_the_tree_is_not_passed(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        outside = tmp_path / "outside.sh"
        outside.write_text("#!/bin/sh\necho $x\n")
        (tree / "link.sh").symlink_to(outside)
        scanner = _scanner(tree, tmp_path)
        fake = FakeShellCheck()
        _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        assert "link.sh" not in argv

    def test_no_shell_scripts_is_an_empty_report_with_zero_targets(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text("print(1)\n")
        scanner = _scanner(src, tmp_path)
        fake = FakeShellCheck()
        report = _run(scanner, fake, monkeypatch)
        assert fake.calls == []
        assert scanner.targets_attempted == 0
        assert report.runs and report.runs[0].results == []

    def test_a_missing_target_never_reaches_the_tool(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "src"
        src.mkdir()
        scanner = _scanner(src, tmp_path)
        fake = FakeShellCheck()
        monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
        report = scanner.scan(target=tmp_path / "absent", target_type="source")
        assert fake.calls == []
        assert report.runs[0].results == []

    def test_a_long_script_list_is_split_into_several_runs(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "src"
        src.mkdir()
        for i in range(30):
            (src / f"script_{i:02d}.sh").write_text("echo hi\n")
        monkeypatch.setattr(ss, "_MAX_COMMAND_LINE_CHARS", 200)
        scanner = _scanner(src, tmp_path)
        fake = FakeShellCheck(stdout=CLEAN_JSON1, exit_code=0)
        _run(scanner, fake, monkeypatch)
        assert len(fake.calls) > 1
        passed: List[str] = []
        for call in fake.calls:
            argv = call["argv"]
            assert argv[:4] == [
                "shellcheck",
                "--norc",
                "--format=json1",
                "--severity=style",
            ]
            passed.extend(argv[argv.index("--") + 1 :])
        assert passed == [f"script_{i:02d}.sh" for i in range(30)]

    def test_findings_of_every_run_are_merged(self, tmp_path, on_path, monkeypatch):
        src = tmp_path / "src"
        src.mkdir()
        for i in range(10):
            (src / f"s{i}.sh").write_text("echo hi\n")
        monkeypatch.setattr(ss, "_MAX_COMMAND_LINE_CHARS", 120)
        scanner = _scanner(src, tmp_path)
        fake = FakeShellCheck()
        report = _run(scanner, fake, monkeypatch)
        assert len(fake.calls) > 1
        assert len(report.get_all_results()) == 5 * len(fake.calls)


class TestExitStatus:
    @pytest.mark.parametrize("code", [0, 1])
    def test_zero_and_one_complete_the_scan(
        self, code, tree, tmp_path, on_path, monkeypatch
    ):
        stdout = CLEAN_JSON1 if code == 0 else BAD_SH_JSON1
        scanner = _scanner(tree, tmp_path)
        report = _run(
            scanner, FakeShellCheck(stdout=stdout, exit_code=code), monkeypatch
        )
        assert len(report.get_all_results()) == (0 if code == 0 else 5)

    @pytest.mark.parametrize("code", [2, 3, 4, 126, 137])
    def test_any_other_status_fails_even_with_a_report_printed(
        self, code, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeShellCheck(stdout=BAD_SH_JSON1, exit_code=code)
        with pytest.raises(ScannerError, match=f"exited {code}"):
            _run(scanner, fake, monkeypatch)

    def test_status_two_names_the_unreadable_file_from_stderr(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeShellCheck(
            stdout=CLEAN_JSON1,
            exit_code=2,
            stderr="nope.sh: openBinaryFile: does not exist",
        )
        with pytest.raises(ScannerError, match="nope.sh"):
            _run(scanner, fake, monkeypatch)

    def test_a_failing_run_stops_the_remaining_runs(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "src"
        src.mkdir()
        for i in range(10):
            (src / f"s{i}.sh").write_text("echo hi\n")
        monkeypatch.setattr(ss, "_MAX_COMMAND_LINE_CHARS", 120)
        scanner = _scanner(src, tmp_path)
        fake = FakeShellCheck(exit_code=3)
        with pytest.raises(ScannerError):
            _run(scanner, fake, monkeypatch)
        assert len(fake.calls) == 1

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=5)
        fake = FakeShellCheck(timed_out=True)
        with pytest.raises(ScannerError, match="timed out after 5"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 5

    def test_the_scan_timeout_is_one_budget_for_all_runs(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "src"
        src.mkdir()
        for i in range(30):
            (src / f"s{i}.sh").write_text("echo hi\n")
        monkeypatch.setattr(ss, "_MAX_COMMAND_LINE_CHARS", 120)
        clock = {"now": 100.0}
        monkeypatch.setattr(ss, "_now", lambda: clock["now"])
        scanner = _scanner(src, tmp_path, scan_timeout=10)
        fake = FakeShellCheck(stdout=CLEAN_JSON1, exit_code=0)
        inner = fake(scanner)

        def run(command, **kw):
            clock["now"] += 4
            return inner(command, **kw)

        monkeypatch.setattr(scanner, "_run_subprocess", run)
        with pytest.raises(ScannerError, match="timed out"):
            scanner.scan(target=src, target_type="source")
        timeouts = [c["timeout"] for c in fake.calls]
        assert timeouts == sorted(timeouts, reverse=True)
        assert all(t <= 10 for t in timeouts)


class TestMalformedOutput:
    @pytest.mark.parametrize(
        ("stdout", "match"),
        [
            ("", "without writing a json1 report"),
            ("   \n", "without writing a json1 report"),
            ("not json at all", "not JSON"),
            ('{"comments": ', "not JSON"),
            ("[]", "not a json1 document"),
            ('{"comments": 3}', "not a json1 document"),
            ('{"other": []}', "not a json1 document"),
        ],
    )
    def test_output_that_is_not_json1_fails_the_scan(
        self, stdout, match, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeShellCheck(stdout=stdout, exit_code=1)
        with pytest.raises(ScannerError, match=match):
            _run(scanner, fake, monkeypatch)

    def test_a_comment_that_is_not_an_object_is_dropped(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        stdout = json.dumps(
            {
                "comments": [
                    "junk",
                    {
                        "file": "bad.sh",
                        "line": 2,
                        "column": 1,
                        "level": "error",
                        "code": 1,
                        "message": "m",
                    },
                ]
            }
        )
        report = _run(scanner, FakeShellCheck(stdout=stdout), monkeypatch)
        assert [r.ruleId for r in report.get_all_results()] == ["SC1"]


class TestDependencyCheck:
    def test_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ss, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        fake = FakeShellCheck()
        assert _run(scanner, fake, monkeypatch) is False
        assert scanner.dependencies_satisfied is False
        assert fake.calls == []

    def test_present_binary_satisfies_the_check(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_an_unavailable_dependency_short_circuits_the_check(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "not available here"
        assert scanner.validate_plugin_dependencies() is False


class TestInstall:
    def test_the_scanner_constructs_and_declares_no_install_commands(self, tmp_path):
        # ShellCheck is GPL-3.0 and has no utils/tool_downloads.py pin: ASH does not
        # download it, so no platform has an install command and construction does
        # not depend on a pin that does not exist.
        scanner = _scanner(tmp_path, tmp_path)
        for platform, arch in [
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
            ("windows", "amd64"),
            ("windows", "arm64"),
        ]:
            assert scanner.get_installation_commands(platform, arch) == []
        assert not scanner.custom_install_commands

    def test_the_tool_is_not_in_the_download_table(self):
        from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS

        assert "shellcheck" not in TOOL_VERSIONS

    def test_a_missing_binary_names_how_to_install_it(
        self, tmp_path, monkeypatch, caplog
    ):
        monkeypatch.setattr(ss, "find_executable", lambda cmd: None)
        scanner = _scanner(tmp_path, tmp_path)
        seen = []
        monkeypatch.setattr(
            ss.ASH_LOGGER, "warning", lambda msg, *a, **k: seen.append(msg)
        )
        assert scanner.validate_plugin_dependencies() is False
        assert seen and "package manager" in seen[0]
        assert "ash dependencies install" not in seen[0]


class TestCapturedFixtures:
    ROOT = (
        Path(__file__).resolve().parents[3]
        / "test_data"
        / "scanners"
        / "shellcheck"
        / "captured"
    )

    def test_the_positive_capture_is_the_oracle_for_the_conversion(self):
        text = (self.ROOT / "positive.json1").read_text(encoding="utf-8")
        assert json.loads(text) == json.loads(BAD_SH_JSON1)
        report = convert_json1_comments(json.loads(text)["comments"])
        assert _findings(report) == BAD_SH_EXPECTED

    def test_the_negative_capture_has_no_findings(self):
        text = (self.ROOT / "negative.json1").read_text(encoding="utf-8")
        assert not convert_json1_comments(
            json.loads(text)["comments"]
        ).get_all_results()

    def test_the_readme_records_the_argv_and_version(self):
        text = (self.ROOT / "README.md").read_text(encoding="utf-8")
        assert "0.11.0" in text and "--format=json1" in text
