# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""TruffleHogScanner: the invocation, what the tree may configure, and the report.

The report tests read SARIF that TruffleHog 3.100.0 actually wrote;
tests/test_data/scanners/trufflehog/captured/README.md has the argv. The scan()
tests replace the subprocess with a fake that serves those captures, so they run on
every platform without the binary.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from pydantic import ValidationError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_trufflehog_plugins
from automated_security_helper.plugin_modules.ash_trufflehog_plugins import (
    trufflehog_scanner as ts,
)
from automated_security_helper.plugin_modules.ash_trufflehog_plugins.trufflehog_scanner import (
    TruffleHogScanner,
    TruffleHogScannerConfig,
    TruffleHogScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "trufflehog"
    / "captured"
)

#: What the positive capture must produce, written out by hand from the fixture it
#: was captured over, not derived from the code under test: three fabricated GitHub
#: tokens, one in src/app.py at line 4, one in a URL in src/remote.cfg at line 2
#: (which the URI detector reports as well) and one in src/services/settings.py at
#: line 3, on a line that carries a trufflehog:ignore comment.
POSITIVE_EXPECTED = [
    ("Github", "warning", "HIGH", "src/app.py", 4),
    ("Github", "warning", "HIGH", "src/remote.cfg", 2),
    ("Github", "warning", "HIGH", "src/services/settings.py", 3),
]

STDOUT_LOG = "TruffleHogScanner.stdout.log"
STDERR_LOG = "TruffleHogScanner.stderr.log"


def _findings(report: SarifReport) -> List[tuple]:
    """(ruleId, SARIF level, ASH severity, uri, line) for every result, sorted."""
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
    return sorted(out, key=lambda f: (f[3], f[4], f[0]))


def _captured(name: str) -> Dict[str, Any]:
    return json.loads((CAPTURED / name).read_text(encoding="utf-8"))


def _result(rule: str, level: str, uri: str, line: int) -> Dict[str, Any]:
    return {
        "ruleId": rule,
        "level": level,
        "message": {"text": f"Found result for detector {rule}."},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }


def _report_of(*results: Dict[str, Any]) -> str:
    """The negative capture with ``results`` put in its one run."""
    report = _captured("negative.sarif")
    report["runs"][0]["results"] = list(results)
    return json.dumps(report)


class FakeTruffleHog:
    """Stands in for _run_subprocess: records argv, writes a captured report.

    TruffleHog writes its SARIF to stdout, which ASH writes to the stdout log in
    the run's results directory; the fake writes the capture there.
    """

    def __init__(
        self,
        sarif: Optional[str] = "positive.sarif",
        exit_code: int = 0,
        sarif_text: Optional[str] = None,
        stderr: str = "",
    ):
        self.sarif, self.exit_code = sarif, exit_code
        self.sarif_text, self.stderr = sarif_text, stderr
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            text = self.sarif_text
            if text is None and self.sarif is not None:
                text = (CAPTURED / self.sarif).read_text(encoding="utf-8")
            if text is not None:
                Path(results_dir).mkdir(parents=True, exist_ok=True)
                (Path(results_dir) / STDOUT_LOG).write_text(text, encoding="utf-8")
            scanner.exit_code = self.exit_code
            return {"returncode": self.exit_code, "stdout": "", "stderr": self.stderr}

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(
    source: Path,
    tmp_path: Path,
    *,
    operator: bool = True,
    output_dir: Optional[Path] = None,
    **options,
) -> TruffleHogScanner:
    """``operator``: the options came from the operator, or from the scanned tree."""
    config = get_default_config()
    record_provenance(
        config,
        in_tree=[] if operator else [source / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
    )
    output = output_dir or tmp_path / "out"
    return TruffleHogScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=config,
        ),
        config=TruffleHogScannerConfig(
            enabled=True, options=TruffleHogScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "services").mkdir(parents=True)
    (src / "app.py").write_text("print(1)\n")
    (src / "services" / "settings.py").write_text("DEBUG = False\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ts, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


@pytest.fixture(autouse=True)
def online(monkeypatch):
    """No test depends on the offline setting of the machine that runs it."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)


def _run(
    scanner: TruffleHogScanner,
    fake: FakeTruffleHog,
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


def _warnings(scanner: TruffleHogScanner, monkeypatch) -> List[str]:
    """Collects what the scanner logs at WARNING from here on."""
    import logging

    seen: List[str] = []
    original = scanner._plugin_log

    def record(message, *args, level=logging.INFO, **kwargs):
        if level == logging.WARNING:
            seen.append(str(message))
        return original(message, *args, level=level, **kwargs)

    monkeypatch.setattr(scanner, "_plugin_log", record)
    return seen


class TestAlphaPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert TruffleHogScannerConfig().enabled is True
        assert TruffleHogScannerConfig().name == "trufflehog"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "trufflehog")

    def test_the_module_exports_the_scanner(self):
        assert ash_trufflehog_plugins.ASH_SCANNERS == [TruffleHogScanner]
        assert ash_trufflehog_plugins.ASH_REPORTERS == []

    def test_nothing_is_sent_and_nothing_is_hidden_by_default(self):
        options = TruffleHogScannerConfigOptions()
        assert options.verify is False
        assert options.honor_inline_ignores is False
        assert options.results == "verified,unknown"


class TestResultsOption:
    @pytest.mark.parametrize(
        "given, kept",
        [
            ("verified", "verified"),
            ("unknown, verified", "verified,unknown"),
            ("unverified,verified,unknown,verified", "verified,unknown,unverified"),
        ],
    )
    def test_it_is_kept_in_one_spelling(self, given, kept):
        assert TruffleHogScannerConfigOptions(results=given).results == kept

    @pytest.mark.parametrize(
        "given", ["", " , ", "all", "verified,filtered_unverified", "verified;unknown"]
    )
    def test_anything_else_is_refused(self, given):
        with pytest.raises(ValidationError):
            TruffleHogScannerConfigOptions(results=given)


class TestInvocation:
    def test_the_whole_default_command_line(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        fake = FakeTruffleHog()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        exclude = _flag(argv, "--exclude-paths=")
        assert argv == [
            "trufflehog",
            "filesystem",
            "--sarif",
            "--no-update",
            "--no-color",
            "--fail-on-scan-errors",
            "--no-verification",
            "--no-ignore-tag",
            f"--exclude-paths={exclude}",
            "--",
            ".",
        ]

    def test_flags_that_expose_the_secret_or_load_a_config_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, verify=True, honor_inline_ignores=True)
        fake = FakeTruffleHog()
        _run(scanner, fake, monkeypatch)
        for token in fake.argv:
            assert token not in ("--json", "-j", "--json-legacy", "--fail")
            assert not token.startswith(("--config", "--verifier"))

    def test_the_exclusion_file_names_git_directories_and_nothing_else(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        import re

        scanner = _scanner(tree, tmp_path)
        fake = FakeTruffleHog()
        _run(scanner, fake, monkeypatch)
        exclude = Path(_flag(fake.argv, "--exclude-paths="))
        assert exclude.is_absolute()
        assert not exclude.is_relative_to(tree)
        lines = exclude.read_text(encoding="utf-8").splitlines()
        assert lines == [ts.GIT_DIR_PATTERN]
        pattern = re.compile(lines[0])
        for excluded in (".git/config", "vendor/lib/.git/HEAD", "a\\.git\\index"):
            assert pattern.search(excluded), excluded
        for scanned in (".github/workflows/ci.yml", "src/git/app.py", ".gitignore"):
            assert not pattern.search(scanned), scanned

    def test_the_converted_target_is_an_absolute_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "notebook.py").write_text("print(1)\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeTruffleHog(sarif="negative.sarif")
        _run(scanner, fake, monkeypatch, target=converted, target_type="converted")
        assert fake.argv[-2:] == ["--", converted.absolute().as_posix()]

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeTruffleHog()
        assert _run(scanner, fake, monkeypatch, target=tmp_path / "absent") is True
        assert fake.calls == []


class TestVerification:
    def test_the_operator_turns_it_on(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path, verify=True)
        fake = FakeTruffleHog()
        _run(scanner, fake, monkeypatch)
        assert "--no-verification" not in fake.argv
        assert _flag(fake.argv, "--results=") == "verified,unknown"

    def test_the_operator_chooses_the_results(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, verify=True, results="verified")
        fake = FakeTruffleHog()
        _run(scanner, fake, monkeypatch)
        assert _flag(fake.argv, "--results=") == "verified"

    def test_the_tree_may_not_narrow_the_results_the_operator_asked_for(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """The operator's verify stands; the tree's results does not."""
        config = get_default_config()
        record_provenance(
            config, in_tree=[tree / ".ash" / ".ash.yaml"], trusted=AshConfig()
        )
        scanner = _scanner(tree, tmp_path, verify=True, results="verified")
        scanner.context.config = config
        monkeypatch.setattr(scanner, "_verify", lambda: True)
        warnings = _warnings(scanner, monkeypatch)
        fake = FakeTruffleHog()
        _run(scanner, fake, monkeypatch)
        assert _flag(fake.argv, "--results=") == "verified,unknown"
        assert len(warnings) == 1
        assert "scanners.trufflehog.options.results" in warnings[0]

    def test_from_the_tree_it_is_refused_with_a_warning(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, operator=False, verify=True)
        warnings = _warnings(scanner, monkeypatch)
        fake = FakeTruffleHog()
        _run(scanner, fake, monkeypatch)
        assert "--no-verification" in fake.argv
        assert _flag(fake.argv, "--results=") is None
        assert len(warnings) == 1
        assert "scanners.trufflehog.options.verify" in warnings[0]

    def test_offline_nothing_is_verified_and_that_is_said(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        monkeypatch.setenv("ASH_OFFLINE", "true")
        scanner = _scanner(tree, tmp_path, verify=True)
        warnings = _warnings(scanner, monkeypatch)
        fake = FakeTruffleHog()
        _run(scanner, fake, monkeypatch)
        assert "--no-verification" in fake.argv
        assert _flag(fake.argv, "--results=") is None
        assert len(warnings) == 1 and "offline" in warnings[0]

    def test_the_scanners_own_offline_option_keeps_it_off(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, verify=True, offline=True)
        fake = FakeTruffleHog()
        _run(scanner, fake, monkeypatch)
        assert "--no-verification" in fake.argv

    def test_without_it_the_results_option_changes_nothing(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, results="verified")
        fake = FakeTruffleHog()
        _run(scanner, fake, monkeypatch)
        assert "--no-verification" in fake.argv
        assert _flag(fake.argv, "--results=") is None

    def test_no_network_is_declared_for_the_sandbox(self):
        from automated_security_helper.utils.sandbox.policy import SandboxRequirements

        assert TruffleHogScanner.sandbox_requirements == SandboxRequirements()


class TestInlineIgnores:
    def test_ignore_comments_hide_nothing_unless_the_operator_says_otherwise(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, honor_inline_ignores=True)
        fake = FakeTruffleHog()
        _run(scanner, fake, monkeypatch)
        assert "--no-ignore-tag" not in fake.argv

    def test_from_the_tree_the_option_is_refused_with_a_warning(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, operator=False, honor_inline_ignores=True)
        warnings = _warnings(scanner, monkeypatch)
        fake = FakeTruffleHog()
        _run(scanner, fake, monkeypatch)
        assert "--no-ignore-tag" in fake.argv
        assert len(warnings) == 1
        assert "honor_inline_ignores" in warnings[0]

    def test_a_refusal_is_logged_once_per_option_through_the_base_class(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(
            tree,
            tmp_path,
            operator=False,
            verify=True,
            honor_inline_ignores=True,
        )
        warnings = _warnings(scanner, monkeypatch)
        for _ in range(3):
            assert scanner._honor_inline_ignores() is False
            assert scanner._verify() is False
        assert len(warnings) == 2
        assert scanner._operator_refusals_logged == {
            "scanners.trufflehog.options.verify",
            "scanners.trufflehog.options.honor_inline_ignores",
        }


class TestReport:
    def test_the_positive_capture_is_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeTruffleHog(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_the_capture_holds_the_duplicate_the_scanner_drops(self):
        """Negative control: the URI result is in what TruffleHog wrote."""
        raw = _captured("positive.sarif")["runs"][0]["results"]
        assert sorted(r["ruleId"] for r in raw) == ["Github", "Github", "Github", "URI"]

    def test_negative_control_the_clean_capture_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeTruffleHog(sarif="negative.sarif"), monkeypatch)
        assert isinstance(report, SarifReport)
        assert _findings(report) == []

    def test_results_are_marked_as_unverified_secret_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeTruffleHog(), monkeypatch)
        for result in report.get_all_results():
            assert {"secret", "security"} <= set(result.properties.tags)
            assert result.properties.verification == "not verified"
            assert getattr(result.kind, "value", result.kind) == "fail"

    def test_a_credential_the_provider_confirmed_is_critical(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """TruffleHog writes level error for a verified result (pkg/output/sarif.go).

        No capture holds one: a verified result needs a live credential.
        """
        scanner = _scanner(tree, tmp_path, verify=True)
        text = _report_of(
            _result("Github", "error", "src/app.py", 4),
            _result("Github", "warning", "src/old.py", 9),
        )
        report = _run(scanner, FakeTruffleHog(sarif_text=text), monkeypatch)
        assert _findings(report) == [
            ("Github", "error", "CRITICAL", "src/app.py", 4),
            ("Github", "warning", "HIGH", "src/old.py", 9),
        ]
        states = {
            r.locations[0].physicalLocation.root.artifactLocation.uri: (
                r.properties.verification
            )
            for r in report.get_all_results()
        }
        assert states == {"src/app.py": "verified", "src/old.py": "not verified"}

    def test_the_capture_holds_no_secret_and_the_report_adds_none(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeTruffleHog(), monkeypatch)
        for text in (
            (CAPTURED / "positive.sarif").read_text(encoding="utf-8"),
            report.model_dump_json(),
        ):
            assert "ghp_" not in text

    def test_results_under_ashs_own_output_directory_are_dropped(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        output = tree / ".ash" / "ash_output"
        output.mkdir(parents=True)
        scanner = _scanner(tree, tmp_path, output_dir=output)
        text = _report_of(
            _result("Github", "warning", "src/app.py", 4),
            _result("Github", "warning", ".ash/ash_output/converted/copy.py", 4),
        )
        report = _run(scanner, FakeTruffleHog(sarif_text=text), monkeypatch)
        assert [f[3] for f in _findings(report)] == ["src/app.py"]

    def test_the_report_survives_a_round_trip_through_the_sarif_model(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeTruffleHog(), monkeypatch)
        again = SarifReport.model_validate_json(report.model_dump_json())
        assert _findings(again) == POSITIVE_EXPECTED


class TestGenericDuplicates:
    def _kept(self, tree, tmp_path, monkeypatch, *results) -> List[tuple]:
        scanner = _scanner(tree, tmp_path)
        fake = FakeTruffleHog(sarif_text=_report_of(*results))
        return [
            (f[0], f[1], f[3], f[4])
            for f in _findings(_run(scanner, fake, monkeypatch))
        ]

    def test_a_generic_result_alone_on_its_line_is_kept(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        kept = self._kept(
            tree,
            tmp_path,
            monkeypatch,
            _result("URI", "warning", "db.cfg", 2),
            _result("Github", "warning", "db.cfg", 3),
        )
        assert kept == [
            ("URI", "warning", "db.cfg", 2),
            ("Github", "warning", "db.cfg", 3),
        ]

    def test_the_same_line_in_another_file_is_another_place(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        kept = self._kept(
            tree,
            tmp_path,
            monkeypatch,
            _result("URI", "warning", "a.cfg", 2),
            _result("Github", "warning", "b.cfg", 2),
        )
        assert len(kept) == 2

    def test_a_verified_generic_result_outranks_an_unverified_provider_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        kept = self._kept(
            tree,
            tmp_path,
            monkeypatch,
            _result("URI", "error", "db.cfg", 2),
            _result("Github", "warning", "db.cfg", 2),
        )
        assert kept == [
            ("Github", "warning", "db.cfg", 2),
            ("URI", "error", "db.cfg", 2),
        ]

    def test_two_provider_detectors_on_one_line_are_both_kept(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        kept = self._kept(
            tree,
            tmp_path,
            monkeypatch,
            _result("Github", "warning", "ci.env", 1),
            _result("Gitlab", "warning", "ci.env", 1),
        )
        assert len(kept) == 2


class TestExitCodesAndOutput:
    def test_zero_is_a_success_with_or_without_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        for capture in ("positive.sarif", "negative.sarif"):
            scanner = _scanner(tree, tmp_path)
            report = _run(scanner, FakeTruffleHog(sarif=capture), monkeypatch)
            assert isinstance(report, SarifReport)

    @pytest.mark.parametrize("code", [1, 183])
    def test_any_other_exit_fails_the_scan_even_with_a_report_on_disk(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeTruffleHog(exit_code=code), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeTruffleHog(sarif=None), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeTruffleHog(), monkeypatch)
        stale = Path(scanner.results_dir) / "source" / STDOUT_LOG
        assert stale.is_file()
        with pytest.raises(ScannerError):
            _run(scanner, FakeTruffleHog(sarif=None), monkeypatch)
        assert not stale.exists()

    def test_the_tools_stderr_is_not_copied_into_the_scans_errors(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        said = "verification error: provider answered 401 for hunter2"
        _run(scanner, FakeTruffleHog(stderr=said), monkeypatch)
        scanner._process_command_response(
            {"returncode": 0, "stdout": "", "stderr": said}
        )
        assert not any("hunter2" in line for line in scanner.errors)

    def test_the_failure_message_names_the_log_and_does_not_quote_it(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeTruffleHog(exit_code=1, stderr="fatal: hunter2")
        with pytest.raises(ScannerError) as raised:
            _run(scanner, fake, monkeypatch)
        message = str(raised.value)
        assert STDERR_LOG in message
        assert "exit code 1" in message
        assert "hunter2" not in message

    def test_a_failure_before_the_tool_started_has_no_exit_code(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)

        def refuse(*args, **kwargs):
            raise ScannerError("refused")

        monkeypatch.setattr(scanner, "_build_arguments", refuse)
        with pytest.raises(ScannerError) as raised:
            _run(scanner, FakeTruffleHog(), monkeypatch)
        assert "trufflehog was not started" in str(raised.value)


class TestUnreadFiles:
    LINE = (
        '2026-11-23T20:55:07Z\terror\ttrufflehog\terror scanning file\t{"path": "%s"}\n'
    )

    def test_each_file_the_log_says_was_not_read_is_counted_and_not_named(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        warnings = _warnings(scanner, monkeypatch)
        log = tmp_path / STDERR_LOG
        log.write_text(
            self.LINE % "src/private.pem"
            + "info-0\ttrufflehog\tfinished scanning\n"
            + self.LINE % "src/keys/id_rsa",
            encoding="utf-8",
        )
        scanner._warn_of_unread_files(log)
        assert len(warnings) == 1
        assert "2 file(s)" in warnings[0]
        assert log.as_posix() in warnings[0]
        assert "private.pem" not in warnings[0] and "id_rsa" not in warnings[0]

    def test_negative_control_a_log_with_no_such_line_says_nothing(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        warnings = _warnings(scanner, monkeypatch)
        log = tmp_path / STDERR_LOG
        log.write_text("info-0\ttrufflehog\tfinished scanning\n", encoding="utf-8")
        scanner._warn_of_unread_files(log)
        assert warnings == []

    def test_a_missing_log_is_not_an_error(self, tree, tmp_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        warnings = _warnings(scanner, monkeypatch)
        scanner._warn_of_unread_files(tmp_path / "absent.log")
        assert warnings == []


class TestDependencies:
    def test_a_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ts, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False

    def test_a_present_binary_satisfies_them(self, tree, tmp_path, on_path):
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is True

    def test_ash_declares_no_install_for_it(self, tree, tmp_path, on_path):
        """TruffleHog is AGPL-3.0: ASH runs the one on PATH and installs none."""
        from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS

        assert "trufflehog" not in TOOL_VERSIONS
        assert not _scanner(tree, tmp_path).custom_install_commands
