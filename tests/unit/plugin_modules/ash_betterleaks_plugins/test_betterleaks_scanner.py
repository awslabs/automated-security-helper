# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""BetterleaksScanner: the invocation, what the tree may configure, and the report.

The report tests read SARIF that Betterleaks 1.10.1 (the pinned version) actually
wrote; tests/test_data/scanners/betterleaks/captured/README.md has the argv. The scan()
tests replace the subprocess with a fake that serves those captures, so they run on
every platform without the binary.
"""

from __future__ import annotations

import json
import ntpath
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config import tool_config_trust
from automated_security_helper.core import constants
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_betterleaks_plugins
from automated_security_helper.plugin_modules.ash_betterleaks_plugins import (
    betterleaks_scanner as bs,
)
from automated_security_helper.plugin_modules.ash_betterleaks_plugins.betterleaks_scanner import (
    BetterleaksScanner,
    BetterleaksScannerConfig,
    BetterleaksScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance

pytestmark = pytest.mark.unit

FIXTURES = (
    Path(__file__).resolve().parents[3] / "test_data" / "scanners" / "betterleaks"
)
CAPTURED = FIXTURES / "captured"

#: What the positive capture must produce, written out by hand from the fixture
#: it was captured over, not derived from the code under test: two fabricated
#: GitHub tokens, one in app.py at line 4 and one in services/settings.py at line 3.
POSITIVE_EXPECTED = [
    ("github-pat", "error", "CRITICAL", "app.py", 4),
    ("github-pat", "error", "CRITICAL", "services/settings.py", 3),
]

ENV_NAMES = (
    "BETTERLEAKS_CONFIG",
    "BETTERLEAKS_CONFIG_TOML",
    "GITLEAKS_CONFIG",
    "GITLEAKS_CONFIG_TOML",
)


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


class FakeBetterleaks:
    """Stands in for _run_subprocess: records argv, writes a captured report."""

    def __init__(
        self,
        sarif: Optional[str] = "positive.sarif",
        exit_code: int = 2,
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
            report_arg = next(a for a in command if a.startswith("--report-path="))
            path = Path(report_arg.split("=", 1)[1])
            text = self.sarif_text
            if text is None and self.sarif is not None:
                text = (CAPTURED / self.sarif).read_text(encoding="utf-8")
            if text is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
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
) -> BetterleaksScanner:
    """``operator``: the options came from the operator, or from the scanned tree."""
    config = get_default_config()
    record_provenance(
        config,
        in_tree=[] if operator else [source / ".ash.yaml"],
        trusted=AshConfig(),
    )
    output = output_dir or tmp_path / "out"
    return BetterleaksScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=config,
        ),
        config=BetterleaksScannerConfig(
            enabled=True, options=BetterleaksScannerConfigOptions(**options)
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
    monkeypatch.setattr(bs, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


@pytest.fixture(autouse=True)
def no_config_env(monkeypatch):
    """No test depends on the config variables of the machine that runs it."""
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)


def _run(
    scanner: BetterleaksScanner,
    fake: FakeBetterleaks,
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


def _run_from_a_directory_holding(tmp_path: Path, monkeypatch, *names: str) -> Path:
    """Work from a scratch directory holding a config file at each of ``names``.

    A relative config variable is anchored to the directory ASH runs in, and ASH
    reads the file there to check its ``[extend]`` path.
    """
    run = tmp_path / "run"
    run.mkdir()
    for name in names:
        (run / name).write_text("title = 'operator'\n")
    monkeypatch.chdir(run)
    return run


class TestAlphaPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert BetterleaksScannerConfig().enabled is True
        assert BetterleaksScannerConfig().name == "betterleaks"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "betterleaks")

    def test_the_module_exports_the_scanner(self):
        assert ash_betterleaks_plugins.ASH_SCANNERS == [BetterleaksScanner]
        assert ash_betterleaks_plugins.ASH_REPORTERS == []

    def test_the_tree_may_not_turn_on_what_hides_findings(self):
        options = BetterleaksScannerConfigOptions()
        assert options.config_file is None
        assert options.honor_inline_ignores is False
        assert options.honor_tree_ignore_files is False


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBetterleaks()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[:2] == ["betterleaks", "dir"]
        for expected in (
            "--report-format=sarif",
            "--redact=100",
            "--exit-code=2",
            "--no-banner",
            "--no-color",
            "--ignore-gitleaks-allow",
        ):
            assert expected in argv
        # "--" ends option parsing; the source target is "." from the source dir.
        assert argv[-2:] == ["--", "."]
        assert fake.calls[0]["cwd"] is None, "the run starts in the source directory"

    def test_redact_takes_its_value_with_an_equals_sign(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """``--redact 100`` would make ``100`` the scan path."""
        scanner = _scanner(tree, tmp_path)
        fake = FakeBetterleaks()
        _run(scanner, fake, monkeypatch)
        assert "--redact" not in fake.argv
        assert "100" not in fake.argv

    @pytest.mark.parametrize(
        "forbidden",
        [
            "--unsafe-auto-load-config",
            "--validation",
            "--baseline-path",
            "--diagnostics",
        ],
    )
    def test_flags_that_read_the_tree_or_reach_the_network_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, forbidden
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBetterleaks()
        _run(scanner, fake, monkeypatch)
        assert not any(
            a == forbidden or a.startswith(f"{forbidden}=") for a in fake.argv
        )

    def test_the_ignore_path_is_an_empty_directory_outside_the_tree(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBetterleaks()
        _run(scanner, fake, monkeypatch)
        empty = Path(_flag(fake.argv, "--gitleaks-ignore-path="))
        assert empty.is_dir() or not empty.exists()
        assert not empty.resolve().is_relative_to(tree.resolve())
        if empty.exists():
            assert list(empty.iterdir()) == []

    def test_the_converted_target_is_an_absolute_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "x.py").write_text("print(1)\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeBetterleaks(sarif="negative.sarif", exit_code=0)
        _run(scanner, fake, monkeypatch, target=converted, target_type="converted")
        assert fake.argv[-2:] == ["--", converted.absolute().as_posix()]

    def test_inline_allow_comments_are_ignored_unless_the_operator_says_otherwise(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, honor_inline_ignores=True)
        fake = FakeBetterleaks()
        _run(scanner, fake, monkeypatch)
        assert "--ignore-gitleaks-allow" not in fake.argv

    def test_inline_allow_from_the_tree_is_refused_with_a_warning(
        self, tree, tmp_path, on_path, monkeypatch, caplog
    ):
        scanner = _scanner(tree, tmp_path, operator=False, honor_inline_ignores=True)
        fake = FakeBetterleaks()
        with caplog.at_level("WARNING"):
            _run(scanner, fake, monkeypatch)
        assert "--ignore-gitleaks-allow" in fake.argv
        assert "scanners.betterleaks.options.honor_inline_ignores" in caplog.text

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """Betterleaks exits 0 for a path that does not exist, so ASH must not ask."""
        scanner = _scanner(tree, tmp_path)
        fake = FakeBetterleaks()
        _run(scanner, fake, monkeypatch, target=tmp_path / "gone")
        assert fake.calls == []


class TestReport:
    def test_the_positive_capture_is_rated_critical_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeBetterleaks(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_the_clean_capture_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(
            scanner, FakeBetterleaks(sarif="negative.sarif", exit_code=0), monkeypatch
        )
        assert _findings(report) == []

    def test_results_are_marked_as_secret_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeBetterleaks(), monkeypatch)
        for result in report.get_all_results():
            assert getattr(result.kind, "value", result.kind) == "fail"
            assert {"secret", "security"} <= set(result.properties.tags)

    def test_empty_fingerprints_and_the_wrong_driver_version_are_dropped(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeBetterleaks(), monkeypatch)
        assert all(r.partialFingerprints is None for r in report.get_all_results())
        driver = report.runs[0].tool.driver
        assert driver.name == "betterleaks"
        assert driver.semanticVersion is None

    def test_a_snippet_that_is_not_redacted_is_overwritten(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """A future Betterleaks that put the match in its SARIF still leaks nothing."""
        raw = json.loads((CAPTURED / "positive.sarif").read_text(encoding="utf-8"))
        for result in raw["runs"][0]["results"]:
            region = result["locations"][0]["physicalLocation"]["region"]
            region["snippet"]["text"] = "not-a-redaction"
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeBetterleaks(sarif_text=json.dumps(raw)), monkeypatch)
        texts = {
            r.locations[0].physicalLocation.root.region.snippet.text
            for r in report.get_all_results()
        }
        assert texts == {"REDACTED"}

    def test_results_under_ashs_own_output_directory_are_dropped(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """Betterleaks has no exclude flag, so it reads ASH's output inside the tree."""
        raw = json.loads((CAPTURED / "positive.sarif").read_text(encoding="utf-8"))
        template = raw["runs"][0]["results"][0]
        copy = json.loads(json.dumps(template))
        copy["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = (
            ".ash/ash_output/converted/notebook.py"
        )
        raw["runs"][0]["results"].append(copy)
        scanner = _scanner(tree, tmp_path, output_dir=tree / ".ash" / "ash_output")
        report = _run(scanner, FakeBetterleaks(sarif_text=json.dumps(raw)), monkeypatch)
        assert [f[3] for f in _findings(report)] == [
            "app.py",
            "services/settings.py",
        ]

    def test_the_report_survives_a_round_trip_through_the_sarif_model(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeBetterleaks(), monkeypatch)
        again = SarifReport.model_validate_json(
            report.model_dump_json(exclude_none=True, by_alias=True)
        )
        assert _findings(again) == POSITIVE_EXPECTED


class TestExitStatus:
    def test_two_means_leaks_and_is_a_success(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeBetterleaks(exit_code=2), monkeypatch)
        assert scanner.exit_code == 2
        assert scanner._exit_code_accepted()

    def test_zero_means_clean_and_is_a_success(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeBetterleaks(sarif="negative.sarif", exit_code=0), monkeypatch)
        assert scanner._exit_code_accepted()

    @pytest.mark.parametrize("code", [1, 126, 137])
    def test_any_other_exit_fails_the_scan_even_with_a_report_on_disk(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        """Exit 1 is a Betterleaks failure (--exit-code moved the leaks code to 2)."""
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeBetterleaks(exit_code=code), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeBetterleaks(sarif=None, exit_code=0), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """A tool that fails writes no report; the template reads what is at the path."""
        scanner = _scanner(tree, tmp_path)
        first = FakeBetterleaks()
        _run(scanner, first, monkeypatch)
        report = Path(_flag(first.argv, "--report-path="))
        assert report.exists(), "the first run left its report"
        second = FakeBetterleaks(sarif=None, exit_code=0)
        with pytest.raises(ScannerError):
            _run(scanner, second, monkeypatch)
        assert not report.exists()

    def test_the_tools_stderr_is_not_copied_into_the_scans_errors(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner._process_command_response(
            {
                "returncode": 0,
                "stdout": "",
                "stderr": "WRN Invalid .gitleaksignore entry fingerprint=PLANTED-LINE",
            }
        )
        assert not any("PLANTED-LINE" in line for line in scanner.errors)

    def test_the_failure_message_names_the_log_and_does_not_quote_it(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.exit_code = 1
        results = tmp_path / "out" / "source" / "betterleaks.sarif"
        message = scanner._describe_scan_failure(ScannerError("boom"), results)
        assert "stderr.log" in message
        assert "exit code 1" in message
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


class TestMaskedLog:
    def test_the_quoted_entry_is_cut_and_the_rest_of_the_log_kept(self, tmp_path):
        log = tmp_path / "BetterleaksScanner.stderr.log"
        log.write_text(
            "8:00PM INF scanned ~10 bytes\n"
            "8:00PM WRN Invalid .gitleaksignore entry fingerprint=PLANTED-LINE\n"
            "8:00PM WRN leaks found: 1\n",
            encoding="utf-8",
        )
        bs._mask_quoted_ignore_entries(log)
        text = log.read_text(encoding="utf-8")
        assert "PLANTED-LINE" not in text
        assert "Invalid .gitleaksignore entry" in text
        assert "scanned ~10 bytes" in text
        assert "leaks found: 1" in text

    def test_negative_control_a_log_with_no_such_line_is_untouched(self, tmp_path):
        log = tmp_path / "BetterleaksScanner.stderr.log"
        body = "8:00PM INF scanned ~10 bytes\n8:00PM WRN leaks found: 1\n"
        log.write_text(body, encoding="utf-8")
        bs._mask_quoted_ignore_entries(log)
        assert log.read_text(encoding="utf-8") == body

    def test_a_missing_log_is_not_an_error(self, tmp_path):
        bs._mask_quoted_ignore_entries(tmp_path / "absent.log")


class TestConfigurationTheTreeMayNotChoose:
    def test_without_an_operator_config_none_is_passed_and_the_tree_file_is_noted(
        self, tree, tmp_path, on_path, monkeypatch, caplog
    ):
        (tree / ".betterleaks.toml").write_text("title = 'planted'\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeBetterleaks()
        with caplog.at_level("INFO"):
            _run(scanner, fake, monkeypatch)
        assert _flag(fake.argv, "--config=") is None
        assert "--unsafe-auto-load-config" not in fake.argv
        assert ".betterleaks.toml" in caplog.text
        assert "is not read" in caplog.text

    def test_a_config_outside_the_tree_set_by_the_operator_is_passed(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        chosen = tmp_path / "shared" / "betterleaks.toml"
        chosen.parent.mkdir()
        chosen.write_text("title = 'operator'\n")
        scanner = _scanner(tree, tmp_path, config_file=str(chosen))
        fake = FakeBetterleaks()
        _run(scanner, fake, monkeypatch)
        assert _flag(fake.argv, "--config=") == chosen.resolve().as_posix()

    def test_a_config_set_by_the_tree_is_not_used(
        self, tree, tmp_path, on_path, monkeypatch, caplog
    ):
        chosen = tmp_path / "shared" / "betterleaks.toml"
        chosen.parent.mkdir()
        chosen.write_text("title = 'tree'\n")
        scanner = _scanner(tree, tmp_path, operator=False, config_file=str(chosen))
        fake = FakeBetterleaks()
        with caplog.at_level("WARNING"):
            _run(scanner, fake, monkeypatch)
        assert _flag(fake.argv, "--config=") is None
        assert "scanners.betterleaks.options.config_file" in caplog.text

    def test_a_config_the_operator_names_that_does_not_exist_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(
            tree, tmp_path, config_file=str(tmp_path / "shared" / "absent.toml")
        )
        fake = FakeBetterleaks()
        with pytest.raises(ScannerError, match="config_file"):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
    def test_an_operator_config_in_the_tree_that_links_out_of_it_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        outside = tmp_path / "shared" / "betterleaks.toml"
        outside.parent.mkdir()
        outside.write_text("title = 'elsewhere'\n")
        (tree / "lint").mkdir()
        (tree / "lint" / "betterleaks.toml").symlink_to(outside)
        scanner = _scanner(tree, tmp_path, config_file="lint/betterleaks.toml")
        fake = FakeBetterleaks()
        with pytest.raises(ScannerError, match="symbolic link"):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    def test_a_relative_config_variable_is_anchored_where_the_operator_set_it(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """Betterleaks would resolve it against the scanned tree, its working directory."""
        _run_from_a_directory_holding(tmp_path, monkeypatch, "rules.toml")
        monkeypatch.setenv("BETTERLEAKS_CONFIG", "rules.toml")
        scanner = _scanner(tree, tmp_path)
        fake = FakeBetterleaks()
        _run(scanner, fake, monkeypatch)
        passed = _flag(fake.argv, "--config=")
        assert passed == Path(os.path.abspath("rules.toml")).as_posix()
        assert not Path(passed).is_relative_to(tree.resolve())

    def test_the_gitleaks_named_variable_is_the_fallback(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        _run_from_a_directory_holding(tmp_path, monkeypatch, "legacy.toml")
        monkeypatch.setenv("GITLEAKS_CONFIG", "legacy.toml")
        scanner = _scanner(tree, tmp_path)
        fake = FakeBetterleaks()
        _run(scanner, fake, monkeypatch)
        assert (
            _flag(fake.argv, "--config=")
            == Path(os.path.abspath("legacy.toml")).as_posix()
        )

    def test_the_betterleaks_variable_wins_over_the_gitleaks_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        _run_from_a_directory_holding(tmp_path, monkeypatch, "new.toml", "legacy.toml")
        monkeypatch.setenv("BETTERLEAKS_CONFIG", "new.toml")
        monkeypatch.setenv("GITLEAKS_CONFIG", "legacy.toml")
        scanner = _scanner(tree, tmp_path)
        fake = FakeBetterleaks()
        _run(scanner, fake, monkeypatch)
        assert (
            _flag(fake.argv, "--config=")
            == Path(os.path.abspath("new.toml")).as_posix()
        )

    def test_an_absolute_config_variable_and_the_toml_variable_are_left_to_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        absolute = (tmp_path / "rules.toml").as_posix()
        # ASH reads the file the variable names to check its [extend] path.
        (tmp_path / "rules.toml").write_text("title = 'operator'\n")
        monkeypatch.setenv("BETTERLEAKS_CONFIG", absolute)
        scanner = _scanner(tree, tmp_path)
        fake = FakeBetterleaks()
        _run(scanner, fake, monkeypatch)
        assert _flag(fake.argv, "--config=") is None
        monkeypatch.delenv("BETTERLEAKS_CONFIG")
        monkeypatch.setenv("BETTERLEAKS_CONFIG_TOML", "title = 'inline'")
        fake = FakeBetterleaks()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert _flag(fake.argv, "--config=") is None

    def test_under_a_sandbox_the_variables_are_not_passed_in_and_that_is_said(
        self, tree, tmp_path, on_path, monkeypatch, caplog
    ):
        monkeypatch.setenv("BETTERLEAKS_CONFIG", "rules.toml")
        monkeypatch.setattr(bs, "active_scope", lambda: object())
        scanner = _scanner(tree, tmp_path)
        fake = FakeBetterleaks()
        with caplog.at_level("WARNING"):
            _run(scanner, fake, monkeypatch)
        assert _flag(fake.argv, "--config=") is None
        assert (
            "BETTERLEAKS_CONFIG is not passed into the scanner sandbox" in caplog.text
        )

    def test_the_operators_option_beats_the_environment(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        chosen = tmp_path / "shared" / "betterleaks.toml"
        chosen.parent.mkdir()
        chosen.write_text("title = 'operator'\n")
        monkeypatch.setenv("BETTERLEAKS_CONFIG", "rules.toml")
        scanner = _scanner(tree, tmp_path, config_file=str(chosen))
        fake = FakeBetterleaks()
        _run(scanner, fake, monkeypatch)
        assert _flag(fake.argv, "--config=") == chosen.resolve().as_posix()


class TestIgnoreFilesInTheTree:
    """Betterleaks reads them whatever ASH passes and drops what they list."""

    @pytest.mark.parametrize("name", [".betterleaksignore", ".gitleaksignore"])
    def test_a_tree_holding_one_fails_before_the_tool_runs(
        self, tree, tmp_path, on_path, monkeypatch, name
    ):
        (tree / name).write_text("app.py:github-pat:4\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeBetterleaks()
        with pytest.raises(ScannerError) as raised:
            _run(scanner, fake, monkeypatch)
        assert name in str(raised.value)
        assert "honor_tree_ignore_files" in str(raised.value)
        assert fake.calls == []

    def test_both_files_are_named(self, tree, tmp_path, on_path, monkeypatch):
        (tree / ".betterleaksignore").write_text("a:b:1\n")
        (tree / ".gitleaksignore").write_text("a:b:1\n")
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError) as raised:
            _run(scanner, FakeBetterleaks(), monkeypatch)
        assert ".betterleaksignore" in str(raised.value)
        assert ".gitleaksignore" in str(raised.value)

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
    def test_a_link_with_the_name_counts_even_when_it_leads_nowhere(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / ".gitleaksignore").symlink_to(tmp_path / "nowhere")
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeBetterleaks(), monkeypatch)

    def test_the_operator_may_accept_the_file(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / ".betterleaksignore").write_text("app.py:github-pat:4\n")
        scanner = _scanner(tree, tmp_path, honor_tree_ignore_files=True)
        fake = FakeBetterleaks()
        report = _run(scanner, fake, monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED
        assert _flag(fake.argv, "--gitleaks-ignore-path=")

    def test_the_tree_may_not_accept_its_own_file(
        self, tree, tmp_path, on_path, monkeypatch, caplog
    ):
        (tree / ".betterleaksignore").write_text("app.py:github-pat:4\n")
        scanner = _scanner(tree, tmp_path, operator=False, honor_tree_ignore_files=True)
        fake = FakeBetterleaks()
        with caplog.at_level("WARNING"):
            with pytest.raises(ScannerError):
                _run(scanner, fake, monkeypatch)
        assert "scanners.betterleaks.options.honor_tree_ignore_files" in caplog.text
        assert fake.calls == []

    def test_negative_control_a_tree_without_one_runs(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBetterleaks()
        _run(scanner, fake, monkeypatch)
        assert len(fake.calls) == 1

    def test_a_directory_of_that_name_below_the_root_is_not_the_roots_file(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "services" / ".gitleaksignore").write_text("x:y:1\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeBetterleaks()
        _run(scanner, fake, monkeypatch)
        assert len(fake.calls) == 1


class TestDependencyCheck:
    def test_a_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(bs, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False

    def test_a_present_binary_satisfies_them(self, tree, tmp_path, on_path):
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is True


class TestInstall:
    def test_install_commands_cover_every_published_platform(self, tmp_path):
        scanner = _scanner(tmp_path, tmp_path)
        for platform, arch in [
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
            ("windows", "amd64"),
            ("windows", "arm64"),
        ]:
            commands = scanner.get_installation_commands(platform, arch)
            assert commands, f"no install command for {platform}/{arch}"
            assert "betterleaks" in commands[0]


class TestPinnedRelease:
    """The pin is the 1.x release the tests were captured against, and the image has it."""

    REPO = Path(__file__).resolve().parents[4]
    # Tag v1.10.1 of github.com/betterleaks/betterleaks.
    COMMIT = "39d5bdcf34db54e944facac5cf6e8b03db5e2b99"  # pragma: allowlist secret

    def _dockerfile(self) -> str:
        return (self.REPO / "Dockerfile").read_text(encoding="utf-8")

    def test_the_pin_is_a_stable_release_not_a_candidate(self):
        from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS

        version = TOOL_VERSIONS["betterleaks"]
        assert version == "v1.10.1"
        assert "rc" not in version and "-" not in version

    @pytest.mark.parametrize(
        "platform,arch,archive,member",
        [
            ("linux", "amd64", "betterleaks_1.10.1_linux_x64.tar.gz", "betterleaks"),
            ("linux", "arm64", "betterleaks_1.10.1_linux_arm64.tar.gz", "betterleaks"),
            ("darwin", "amd64", "betterleaks_1.10.1_darwin_x64.tar.gz", "betterleaks"),
            (
                "darwin",
                "arm64",
                "betterleaks_1.10.1_darwin_arm64.tar.gz",
                "betterleaks",
            ),
            (
                "windows",
                "amd64",
                "betterleaks_1.10.1_windows_x64.zip",
                "betterleaks.exe",
            ),
            (
                "windows",
                "arm64",
                "betterleaks_1.10.1_windows_arm64.zip",
                "betterleaks.exe",
            ),
        ],
    )
    def test_each_platform_resolves_to_a_verified_archive(
        self, platform, arch, archive, member
    ):
        from automated_security_helper.utils.tool_downloads import get_tool_asset

        asset = get_tool_asset("betterleaks", platform, arch)
        assert asset.url == (
            "https://github.com/betterleaks/betterleaks/releases/download/"
            f"v1.10.1/{archive}"
        )
        assert asset.archive is True
        assert asset.member_name == member
        assert len(asset.sha256) == 64
        # A second digest, of the executable inside, so an installed copy is checked.
        assert asset.executable_digest and asset.executable_digest != asset.sha256

    def test_the_license_entry_is_mit_at_the_release_commit(self):
        from automated_security_helper.utils.tool_downloads import (
            THIRD_PARTY_LICENSES,
            TOOL_VERSIONS,
        )

        entry = THIRD_PARTY_LICENSES["betterleaks"]
        assert entry.version == TOOL_VERSIONS["betterleaks"]
        assert entry.commit == self.COMMIT
        assert entry.license == "MIT"
        assert not entry.copyleft
        assert [f.name for f in entry.files] == ["LICENSE"]

    def test_the_image_installs_it_through_the_pinned_tool_installer(self):
        dockerfile = self._dockerfile()
        assert "RUN with-retry 'install-pinned-tool betterleaks -b /usr/local/bin'" in (
            dockerfile
        )

    def test_the_dockerfile_pins_the_same_version_as_the_tool_table(self):
        from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS

        assert (
            f'ARG BETTERLEAKS_VERSION="{TOOL_VERSIONS["betterleaks"]}"'
            in self._dockerfile()
        )

    def test_the_image_loads_the_module_for_its_tool_install(self):
        assert (
            "automated_security_helper.plugin_modules.ash_betterleaks_plugins"
            in self._dockerfile()
        )


# --- a config's [extend] path reads nothing from the scanned tree -----------------

_RELATIVE_EXTEND = "[extend]\npath = 'common.toml'\n"
_TREE_COMMON = "[[allowlists]]\npaths = ['''.*''']\n"

_EXTEND_SOURCES = [
    "config_file",
    "BETTERLEAKS_CONFIG",
    "GITLEAKS_CONFIG",
    "BETTERLEAKS_CONFIG_TOML",
    "GITLEAKS_CONFIG_TOML",
    "chain",
]


def _extend_scanner(tree, tmp_path, monkeypatch, how: str, extend_text: str):
    """A scanner whose config is chosen as ``how``, holding ``extend_text``.

    The scanned tree holds ``common.toml``: the file a relative extend path
    would open from Betterleaks' working directory. The results directory is
    inside the tree, as in ASH's default layout.
    """
    operator_dir = tmp_path / "op"
    operator_dir.mkdir()
    options = {}
    if how == "config_file":
        (operator_dir / "betterleaks.toml").write_text(extend_text)
        options["config_file"] = str(operator_dir / "betterleaks.toml")
    elif how.endswith("_TOML"):
        monkeypatch.setenv(how, extend_text)
    elif how == "chain":
        (operator_dir / "mid.toml").write_text(extend_text)
        (operator_dir / "betterleaks.toml").write_text(
            f"[extend]\npath = '{(operator_dir / 'mid.toml').as_posix()}'\n"
        )
        options["config_file"] = str(operator_dir / "betterleaks.toml")
    else:
        (operator_dir / "betterleaks.toml").write_text(extend_text)
        monkeypatch.setenv(how, str(operator_dir / "betterleaks.toml"))
    (tree / "common.toml").write_text(_TREE_COMMON)
    return _scanner(tree, tmp_path, output_dir=tree / ".ash" / "ash_output", **options)


@pytest.mark.parametrize("how", _EXTEND_SOURCES)
def test_a_relative_extend_path_is_refused(tree, tmp_path, monkeypatch, how):
    """Matched on the refusal's own words, not on "extend", which a refusal for
    another reason can hold too: the refusal of a config ASH cannot parse names
    ``[extend]``, and the refusal of a file names it under pytest's ``tmp_path``,
    whose directory carries this test's name."""
    scanner = _extend_scanner(tree, tmp_path, monkeypatch, how, _RELATIVE_EXTEND)
    with pytest.raises(ScannerError, match=_RELATIVE_REFUSAL):
        scanner._build_arguments(tree, tmp_path / "o.sarif")


@pytest.mark.parametrize("how", _EXTEND_SOURCES)
def test_an_absolute_extend_path_builds_an_argv(tree, tmp_path, monkeypatch, how):
    """The control: the same shape with an absolute extend path builds an argv.

    ASH passes the operator's file as ``--config``, and nothing for a variable,
    which Betterleaks reads itself, so the exact argument is compared.
    """
    common = tmp_path / "op" / "common.toml"
    absolute = f"[extend]\npath = '{common.as_posix()}'\n"
    scanner = _extend_scanner(tree, tmp_path, monkeypatch, how, absolute)
    common.write_text(_TREE_COMMON)
    args = scanner._build_arguments(tree, tmp_path / "o.sarif")
    configs = [a for a in args if a.startswith("--config")]
    if how in ("config_file", "chain"):
        operator = (tmp_path / "op" / "betterleaks.toml").resolve()
        assert configs == [f"--config={operator.as_posix()}"]
    else:
        assert configs == []


# --- the keys, as Betterleaks reads them -------------------------------------------

#: The refusal of a relative ``common.toml``, in the words every route gives it.
_RELATIVE_REFUSAL = re.escape("'common.toml', which is not an absolute path")

#: Spellings Betterleaks reads as ``extend.path``: its TOML decoder matches a key
#: to the field of the same name in any case.
_RELATIVE_SPELLINGS = {
    "mixed-case-table": "[Extend]\nPath = 'common.toml'\n",
    "upper-case-key": "[extend]\nPATH = 'common.toml'\n",
    "upper-case-table": "[EXTEND]\npath = 'common.toml'\n",
}


@pytest.mark.parametrize("how", ["config_file", "BETTERLEAKS_CONFIG_TOML"])
@pytest.mark.parametrize("spelling", sorted(_RELATIVE_SPELLINGS))
def test_a_relative_extend_path_in_any_key_spelling_is_refused(
    tree, tmp_path, monkeypatch, spelling, how
):
    """Each spelling has Betterleaks open ``common.toml`` from the scanned tree."""
    scanner = _extend_scanner(
        tree, tmp_path, monkeypatch, how, _RELATIVE_SPELLINGS[spelling]
    )
    with pytest.raises(ScannerError, match=_RELATIVE_REFUSAL):
        scanner._build_arguments(tree, tmp_path / "o.sarif")


#: The UTF-8 byte order mark some editors save at the start of a file.
_BYTE_ORDER_MARK = chr(0xFEFF)


def _with_config_text(tree, tmp_path, monkeypatch, how: str, text: str):
    """``_extend_scanner`` with the config ``how`` names holding ``text`` as written.

    For ``chain`` the text is the extended file's, which ASH reads the same way.
    Files are written as UTF-8 bytes: ``write_text`` uses the locale's encoding,
    which on Windows cannot encode a byte order mark.
    """
    scanner = _extend_scanner(tree, tmp_path, monkeypatch, how, "")
    if how.endswith("_TOML"):
        monkeypatch.setenv(how, text)
    else:
        name = "mid.toml" if how == "chain" else "betterleaks.toml"
        (tmp_path / "op" / name).write_bytes(text.encode("utf-8"))
    return scanner


def _with_byte_order_mark(tree, tmp_path, monkeypatch, how: str, text: str):
    """``_with_config_text`` with ``text`` saved behind a byte order mark."""
    return _with_config_text(tree, tmp_path, monkeypatch, how, _BYTE_ORDER_MARK + text)


#: The words of the refusal of a config that starts with the mark.
_MARK_REFUSAL = re.escape(
    "starts with a UTF-8 byte order mark, which Betterleaks cannot read"
)


def _marked(tmp_path, how: str) -> str:
    """How the refusal names the config of ``how`` that starts with the mark: the
    file (for ``chain``, the extended one), or the variable that holds the text."""
    if how.endswith("_TOML"):
        return f"the config text in {how}"
    return repr(
        str(tmp_path / "op" / ("mid.toml" if how == "chain" else "betterleaks.toml"))
    )


#: What the ``[extend]`` of the texts the mark tests save holds.
_EXTEND_SHAPES = ["relative", "absolute", "empty", "none"]


def _extend_text(tmp_path, extend: str) -> str:
    """The config text for ``extend``: a relative path, an absolute one to the
    operator's ``common.toml``, an empty one, or no ``[extend]`` at all."""
    if extend == "relative":
        return _RELATIVE_EXTEND
    if extend == "absolute":
        return f"[extend]\npath = '{(tmp_path / 'op' / 'common.toml').as_posix()}'\n"
    if extend == "empty":
        return "[extend]\npath = ''\n"
    return "title = 'operator'\n"


@pytest.mark.parametrize("extend", _EXTEND_SHAPES)
@pytest.mark.parametrize("how", _EXTEND_SOURCES)
def test_a_config_behind_a_byte_order_mark_is_refused_for_the_mark(
    tree, tmp_path, monkeypatch, how, extend
):
    """Betterleaks 1.10.1 cannot read a config that starts with a UTF-8 byte order
    mark. Given one by any route it reads a config from (a file with ``--config``,
    the file or the text a variable holds, a file a config extends), it stops at the
    mark ("toml: invalid character at start of key") and exits 1, and it reads the
    same text without the mark. So ASH refuses a config Betterleaks reads before it
    runs, naming it, whatever its ``[extend]`` holds: a relative path, an absolute or an
    empty one, or none, so the refusal does not wait for an extend path. The same
    texts without the mark are the controls: the relative one is refused for its
    path and the others build an argv."""
    scanner = _with_byte_order_mark(
        tree, tmp_path, monkeypatch, how, _extend_text(tmp_path, extend)
    )
    (tmp_path / "op" / "common.toml").write_text(_TREE_COMMON)
    with pytest.raises(ScannerError, match=_MARK_REFUSAL) as refused:
        scanner._build_arguments(tree, tmp_path / "o.sarif")
    assert _marked(tmp_path, how) in str(refused.value)


@pytest.mark.parametrize("extend", ["empty", "none"])
@pytest.mark.parametrize("how", _EXTEND_SOURCES)
def test_a_config_with_no_extend_path_builds_an_argv(
    tree, tmp_path, monkeypatch, how, extend
):
    """The control for the marked configs with an empty extend path or none: the
    same text without the mark builds an argv, as the absolute one does."""
    scanner = _with_config_text(
        tree, tmp_path, monkeypatch, how, _extend_text(tmp_path, extend)
    )
    args = scanner._build_arguments(tree, tmp_path / "o.sarif")
    configs = [a for a in args if a.startswith("--config")]
    if how in ("config_file", "chain"):
        operator = (tmp_path / "op" / "betterleaks.toml").resolve()
        assert configs == [f"--config={operator.as_posix()}"]
    else:
        assert configs == []


@pytest.mark.parametrize("how", _EXTEND_SOURCES)
def test_a_byte_order_mark_inside_an_extend_path_is_part_of_the_path(
    tree, tmp_path, monkeypatch, how
):
    """A mark at the start of the path value, not of the text, is part of the path,
    which then does not start at a root, so Betterleaks would open it from the
    scanned tree. It is refused as written, although the path with the mark removed
    names a file outside the tree."""
    common = tmp_path / "op" / "common.toml"
    value = _BYTE_ORDER_MARK + common.as_posix()
    scanner = _with_config_text(
        tree, tmp_path, monkeypatch, how, f"[extend]\npath = '{value}'\n"
    )
    common.write_text(_TREE_COMMON)
    with pytest.raises(
        ScannerError, match=re.escape(f"{value!r}, which is not an absolute path")
    ):
        scanner._build_arguments(tree, tmp_path / "o.sarif")


# --- only the config Betterleaks reads is refused for the mark ---------------------

#: Two config variables set together, the one Betterleaks reads first: a path
#: variable before a TOML one, and each ``BETTERLEAKS_`` name before its
#: ``GITLEAKS_`` fallback. That is the order the scanner module's docstring gives,
#: and the one Betterleaks 1.10.1 read in each pair, run on its own with both set.
_READ_OVER_UNREAD = [
    ("BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG"),
    ("BETTERLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML"),
    ("BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML"),
    ("GITLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML"),
    ("GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML"),
    ("BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG_TOML"),
]


def _set_config(tmp_path, monkeypatch, name: str, text: str) -> str:
    """Set the config variable ``name`` to ``text``, or to an absolute file holding
    it written as UTF-8 bytes, and return how a refusal names that config."""
    if name.endswith("_TOML"):
        monkeypatch.setenv(name, text)
        return f"the config text in {name}"
    config = tmp_path / "op" / f"{name.lower()}.toml"
    config.parent.mkdir(exist_ok=True)
    config.write_bytes(text.encode("utf-8"))
    monkeypatch.setenv(name, str(config))
    return repr(str(config))


def _with_two_configs(tree, tmp_path, monkeypatch, read, unread, texts):
    """A scanner with the variables ``read`` and ``unread`` set to the two ``texts``,
    and how a refusal names each config. The scanned tree holds ``common.toml``."""
    named = (
        _set_config(tmp_path, monkeypatch, read, texts[0]),
        _set_config(tmp_path, monkeypatch, unread, texts[1]),
    )
    (tree / "common.toml").write_text(_TREE_COMMON)
    return _scanner(tree, tmp_path, output_dir=tree / ".ash" / "ash_output"), named


@pytest.mark.parametrize(("read", "unread"), _READ_OVER_UNREAD)
def test_a_mark_in_a_config_betterleaks_does_not_read_is_skipped(
    tree, tmp_path, monkeypatch, read, unread
):
    """Betterleaks opens only the config it reads by that order, so a mark in another
    variable that is set cannot stop it. ASH checks that one past the mark, and the
    scan runs on the config Betterleaks reads."""
    scanner, _ = _with_two_configs(
        tree,
        tmp_path,
        monkeypatch,
        read,
        unread,
        ("title = 'read'\n", _BYTE_ORDER_MARK + "title = 'unread'\n"),
    )
    args = scanner._build_arguments(tree, tmp_path / "o.sarif")
    assert [a for a in args if a.startswith("--config")] == []


@pytest.mark.parametrize(("read", "unread"), _READ_OVER_UNREAD)
def test_a_mark_in_the_config_betterleaks_reads_is_refused_naming_it(
    tree, tmp_path, monkeypatch, read, unread
):
    """The control: the mark in the config Betterleaks reads, next to the other one
    unmarked, is refused, naming the one it reads."""
    scanner, (named, _) = _with_two_configs(
        tree,
        tmp_path,
        monkeypatch,
        read,
        unread,
        (_BYTE_ORDER_MARK + "title = 'read'\n", "title = 'unread'\n"),
    )
    with pytest.raises(ScannerError, match=_MARK_REFUSAL) as refused:
        scanner._build_arguments(tree, tmp_path / "o.sarif")
    assert f"{read}: {named} starts with" in str(refused.value)


@pytest.mark.parametrize(("read", "unread"), _READ_OVER_UNREAD)
def test_a_config_betterleaks_does_not_read_is_still_checked_past_the_mark(
    tree, tmp_path, monkeypatch, read, unread
):
    """ASH checks every config variable that is set, in case Betterleaks reads one
    ASH does not expect it to. Only the mark is skipped in a config Betterleaks
    does not read: a relative extend path behind it is refused, naming that
    variable, as it is in the config Betterleaks reads."""
    scanner, _ = _with_two_configs(
        tree,
        tmp_path,
        monkeypatch,
        read,
        unread,
        ("title = 'read'\n", _BYTE_ORDER_MARK + _RELATIVE_EXTEND),
    )
    with pytest.raises(ScannerError, match=_RELATIVE_REFUSAL) as refused:
        scanner._build_arguments(tree, tmp_path / "o.sarif")
    assert f"{unread} sets [extend] path = 'common.toml'" in str(refused.value)


@pytest.mark.parametrize(("read", "unread"), _READ_OVER_UNREAD)
def test_a_file_a_config_betterleaks_does_not_read_extends_is_checked_past_the_mark(
    tree, tmp_path, monkeypatch, read, unread
):
    """The config Betterleaks does not read extends a file that starts with the mark.
    Betterleaks never opens that file either, so the mark is skipped there too, and
    the relative extend path behind it is refused, naming the extended file."""
    mid = tmp_path / "op" / "mid.toml"
    mid.parent.mkdir()
    mid.write_bytes((_BYTE_ORDER_MARK + _RELATIVE_EXTEND).encode("utf-8"))
    scanner, _ = _with_two_configs(
        tree,
        tmp_path,
        monkeypatch,
        read,
        unread,
        ("title = 'read'\n", f"[extend]\npath = '{mid.as_posix()}'\n"),
    )
    with pytest.raises(ScannerError, match=_RELATIVE_REFUSAL) as refused:
        scanner._build_arguments(tree, tmp_path / "o.sarif")
    assert f"{mid.as_posix()} sets [extend] path = 'common.toml'" in str(refused.value)


#: The variables that name a file, each set below to a relative path.
_PATH_VARIABLES = ["BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG"]


def _relative_config(tmp_path, monkeypatch, name: str, text: str) -> Path:
    """Set ``name`` to ``rules.toml``, a file holding ``text`` as UTF-8 bytes in the
    directory ASH runs in, and return the file ASH anchors the value to."""
    run = _run_from_a_directory_holding(tmp_path, monkeypatch)
    (run / "rules.toml").write_bytes(text.encode("utf-8"))
    monkeypatch.setenv(name, "rules.toml")
    return Path(os.path.abspath("rules.toml"))


@pytest.mark.parametrize("name", _PATH_VARIABLES)
def test_a_mark_in_a_relative_config_variable_is_refused_naming_the_anchored_file(
    tree, tmp_path, monkeypatch, name
):
    """ASH passes a relative path variable to Betterleaks as ``--config``, anchored
    where ASH runs, so that file is the config Betterleaks reads. A mark at its start
    is refused, naming the variable and the anchored file. The same file without the
    mark is passed: the relative-variable tests in
    ``TestConfigurationTheTreeMayNotChoose`` are the controls."""
    anchored = _relative_config(
        tmp_path, monkeypatch, name, _BYTE_ORDER_MARK + "title = 'operator'\n"
    )
    scanner = _scanner(tree, tmp_path)
    with pytest.raises(ScannerError, match=_MARK_REFUSAL) as refused:
        scanner._build_arguments(tree, tmp_path / "o.sarif")
    assert f"{name}: {str(anchored)!r} starts with" in str(refused.value)


@pytest.mark.parametrize("toml", ["BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG_TOML"])
@pytest.mark.parametrize("name", _PATH_VARIABLES)
def test_a_mark_in_a_toml_variable_beside_a_relative_one_is_skipped(
    tree, tmp_path, monkeypatch, name, toml
):
    """Betterleaks reads the ``--config`` ASH passes for the relative variable, not
    the TOML variable set beside it, so a mark in the TOML one is skipped and the
    anchored file is passed."""
    anchored = _relative_config(tmp_path, monkeypatch, name, "title = 'operator'\n")
    monkeypatch.setenv(toml, _BYTE_ORDER_MARK + "title = 'unread'\n")
    scanner = _scanner(tree, tmp_path)
    args = scanner._build_arguments(tree, tmp_path / "o.sarif")
    assert _flag(args, "--config=") == anchored.as_posix()


# --- the check called directly, as the scanner calls it -----------------------------


def test_a_config_the_tool_does_not_read_is_checked_past_the_mark():
    """A config another one takes precedence over is never opened by the tool, so
    the mark cannot stop it, and the config is not refused for it. The rest of the
    config is still checked: a relative extend path behind the mark is refused."""
    with pytest.raises(ScannerError, match=_RELATIVE_REFUSAL):
        tool_config_trust.refuse_relative_extend_path(
            "Betterleaks",
            "GITLEAKS_CONFIG_TOML",
            text=_BYTE_ORDER_MARK + _RELATIVE_EXTEND,
            read_by_tool=False,
        )
    tool_config_trust.refuse_relative_extend_path(
        "Betterleaks",
        "GITLEAKS_CONFIG_TOML",
        text=_BYTE_ORDER_MARK + "title = 'operator'\n",
        read_by_tool=False,
    )


@pytest.mark.parametrize("read_by_tool", [True, False])
def test_a_file_a_config_extends_is_read_as_the_config_is(tmp_path, read_by_tool):
    """The tool opens the file a config extends only when it reads the config. A
    mark at the start of that file is refused when it does, naming the file, and
    skipped when it does not, where the relative extend path behind it is refused."""
    extended = tmp_path / "mid.toml"
    extended.write_bytes((_BYTE_ORDER_MARK + _RELATIVE_EXTEND).encode("utf-8"))
    text = f"[extend]\npath = '{extended.as_posix()}'\n"
    words = _MARK_REFUSAL if read_by_tool else _RELATIVE_REFUSAL
    with pytest.raises(ScannerError, match=words) as refused:
        tool_config_trust.refuse_relative_extend_path(
            "Betterleaks", "GITLEAKS_CONFIG_TOML", text=text, read_by_tool=read_by_tool
        )
    named = repr(str(extended)) if read_by_tool else f"{extended.as_posix()} sets"
    assert named in str(refused.value)


#: Values under ``extend`` that ASH cannot read the way the tools do, with the
#: words of the refusal.
_UNREADABLE_EXTEND = {
    "path-is-an-integer": ("[extend]\npath = 42\n", "not a string"),
    "path-is-an-array": ("[extend]\npath = ['common.toml']\n", "not a string"),
    "path-is-a-table": ("[extend.path]\nfile = 'common.toml'\n", "not a string"),
    "extend-is-a-string": ("extend = 'common.toml'\n", "not a table"),
    "extend-is-an-array-of-tables": (
        "[[extend]]\npath = 'common.toml'\n",
        "not a table",
    ),
}


@pytest.mark.parametrize("shape", sorted(_UNREADABLE_EXTEND))
def test_an_extend_value_ash_cannot_read_as_the_tools_do_is_refused(
    tree, tmp_path, monkeypatch, shape
):
    text, words = _UNREADABLE_EXTEND[shape]
    scanner = _extend_scanner(tree, tmp_path, monkeypatch, "config_file", text)
    with pytest.raises(ScannerError, match=words):
        scanner._build_arguments(tree, tmp_path / "o.sarif")


#: Two keys that fold to one setting, both absolute and outside the tree. The
#: decoder writes both into one field in document order, so which one Betterleaks
#: uses is not ASH's to guess. Two tables that fold together are refused even when
#: only one of them sets the path.
_DUPLICATE_EXTEND = {
    "two-tables": "[extend]\npath = '<common>'\n[Extend]\nPath = '<other>'\n",
    "two-tables-one-path": "[extend]\npath = '<common>'\n[Extend]\nuseDefault = true\n",
    "two-keys": "[extend]\npath = '<common>'\nPath = '<other>'\n",
}


@pytest.mark.parametrize("shape", sorted(_DUPLICATE_EXTEND))
def test_an_extend_path_set_twice_once_keys_are_folded_is_refused(
    tree, tmp_path, monkeypatch, shape
):
    common = tmp_path / "op" / "common.toml"
    other = tmp_path / "op" / "other.toml"
    text = (
        _DUPLICATE_EXTEND[shape]
        .replace("<common>", common.as_posix())
        .replace("<other>", other.as_posix())
    )
    scanner = _extend_scanner(tree, tmp_path, monkeypatch, "config_file", text)
    common.write_text("title = 'common'\n")
    other.write_text("title = 'other'\n")
    with pytest.raises(ScannerError, match="more than once"):
        scanner._build_arguments(tree, tmp_path / "o.sarif")


def test_a_mixed_case_extend_path_is_followed_into_the_file_it_names(
    tree, tmp_path, monkeypatch
):
    mid = tmp_path / "op" / "mid.toml"
    scanner = _extend_scanner(
        tree,
        tmp_path,
        monkeypatch,
        "config_file",
        f"[Extend]\nPath = '{mid.as_posix()}'\n",
    )
    mid.write_text(_RELATIVE_EXTEND)
    with pytest.raises(ScannerError, match=_RELATIVE_REFUSAL):
        scanner._build_arguments(tree, tmp_path / "o.sarif")


#: The same setting, absolute, in the spellings a config may use.
_ABSOLUTE_SPELLINGS = {
    "mixed-case-table": "[Extend]\nPath = '<common>'\n",
    "inline-table": "extend = { path = '<common>' }\n",
    "dotted-key": "extend.path = '<common>'\n",
}


@pytest.mark.parametrize("spelling", sorted(_ABSOLUTE_SPELLINGS))
def test_an_absolute_extend_path_in_any_key_spelling_is_passed(
    tree, tmp_path, monkeypatch, spelling
):
    """The control for the spellings: an absolute path outside the tree passes the
    operator's config, however its keys are spelled."""
    common = tmp_path / "op" / "common.toml"
    text = _ABSOLUTE_SPELLINGS[spelling].replace("<common>", common.as_posix())
    scanner = _extend_scanner(tree, tmp_path, monkeypatch, "config_file", text)
    common.write_text("title = 'common'\n")
    args = scanner._build_arguments(tree, tmp_path / "o.sarif")
    operator = (tmp_path / "op" / "betterleaks.toml").resolve()
    assert _flag(args, "--config=") == operator.as_posix()


# --- the path Betterleaks opens -----------------------------------------------------


def _home(tmp_path: Path, monkeypatch) -> Path:
    """A home directory for ``~`` to expand to, on every platform's spelling."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


def test_a_home_relative_extend_path_is_refused(tree, tmp_path, monkeypatch):
    """Betterleaks does not expand ``~`` in an extend path, so ``~/common.toml``
    names ``<tree>/~/common.toml``. It is refused although the operator's home
    holds a file of that name."""
    home = _home(tmp_path, monkeypatch)
    (home / "common.toml").write_text("title = 'home'\n")
    scanner = _extend_scanner(
        tree,
        tmp_path,
        monkeypatch,
        "config_file",
        "[extend]\npath = '~/common.toml'\n",
    )
    (tree / "~").mkdir()
    (tree / "~" / "common.toml").write_text(_TREE_COMMON)
    with pytest.raises(
        ScannerError, match=re.escape("'~/common.toml', which is not an absolute path")
    ):
        scanner._build_arguments(tree, tmp_path / "o.sarif")


def test_a_home_relative_config_variable_is_checked_where_betterleaks_reads_it(
    tree, tmp_path, monkeypatch
):
    """ASH anchors ``~/betterleaks.toml`` to the operator's home and passes that
    file, so that is the file it checks: the home's extends a relative path and is
    refused, although a file of the literal spelling under the directory ASH runs
    in extends nothing."""
    home = _home(tmp_path, monkeypatch)
    (home / "betterleaks.toml").write_text(_RELATIVE_EXTEND)
    run = _run_from_a_directory_holding(tmp_path, monkeypatch)
    (run / "~").mkdir()
    (run / "~" / "betterleaks.toml").write_text("title = 'literal'\n")
    monkeypatch.setenv("BETTERLEAKS_CONFIG", "~/betterleaks.toml")
    (tree / "common.toml").write_text(_TREE_COMMON)
    scanner = _scanner(tree, tmp_path, output_dir=tree / ".ash" / "ash_output")
    with pytest.raises(ScannerError, match=_RELATIVE_REFUSAL):
        scanner._build_arguments(tree, tmp_path / "o.sarif")


def test_a_home_relative_config_variable_extending_an_absolute_path_is_passed(
    tree, tmp_path, monkeypatch
):
    """The control: the home's file extends an absolute path outside the tree, so
    it is passed as ``--config``, and the file passed is the home's."""
    home = _home(tmp_path, monkeypatch)
    common = tmp_path / "op" / "common.toml"
    common.parent.mkdir()
    common.write_text("title = 'common'\n")
    (home / "betterleaks.toml").write_text(f"[extend]\npath = '{common.as_posix()}'\n")
    run = _run_from_a_directory_holding(tmp_path, monkeypatch)
    (run / "~").mkdir()
    monkeypatch.setenv("BETTERLEAKS_CONFIG", "~/betterleaks.toml")
    scanner = _scanner(tree, tmp_path, output_dir=tree / ".ash" / "ash_output")
    args = scanner._build_arguments(tree, tmp_path / "o.sarif")
    assert _flag(args, "--config=") == (home / "betterleaks.toml").as_posix()


def test_the_windows_rule_is_built_from_the_function_the_scanner_calls():
    """``core.constants`` names ``utils.path_stat.is_anchored`` again for the modules
    that import it from there, and the test below builds its patch from that name.
    A second definition in ``core.constants`` would have the patch run a copy the
    scanner does not call, so both names are pinned to the one function."""
    from automated_security_helper.utils import path_stat

    assert constants.is_anchored is path_stat.is_anchored
    assert bs.is_anchored is path_stat.is_anchored


def test_a_rooted_config_variable_with_no_drive_is_anchored_where_windows_reads_it(
    tree, tmp_path, monkeypatch
):
    """On Windows a value with a root and no drive (``\\op\\betterleaks.toml``)
    names a file on the drive of Betterleaks' working directory, the scanned
    tree's, while ASH would check it on its own. ASH anchors such a value where it
    runs and passes it as ``--config``. Measured on every platform under Windows'
    rule for an anchored path (``core.constants.is_anchored`` with ``ntpath``),
    under which a POSIX absolute path has no drive either."""
    real = constants.is_anchored
    monkeypatch.setattr(
        bs, "is_anchored", lambda path, pathmod=None: real(path, ntpath), raising=False
    )
    chosen = tmp_path / "op" / "betterleaks.toml"
    chosen.parent.mkdir()
    chosen.write_text("title = 'operator'\n")
    if os.name == "nt":
        monkeypatch.chdir(tmp_path)
        value = ntpath.splitdrive(str(chosen))[1]
    else:
        value = chosen.as_posix()
    monkeypatch.setenv("BETTERLEAKS_CONFIG", value)
    scanner = _scanner(tree, tmp_path, output_dir=tree / ".ash" / "ash_output")
    args = scanner._build_arguments(tree, tmp_path / "o.sarif")
    assert _flag(args, "--config=") == Path(os.path.abspath(value)).as_posix()


#: Windows removes ``..`` from a path before it follows a link in it, so a path
#: there names the same file whichever way ``..`` is read.
_LINKS_BEFORE_DOT_DOT = pytest.mark.skipif(
    os.name == "nt", reason="Windows removes .. before it follows a link"
)


def _a_value_through_a_link(tmp_path: Path) -> str:
    """An absolute config value holding ``..`` after a symbolic link.

    The kernel follows ``op/link`` to ``real/sub`` before it reads ``..``, so the
    value opens ``real/betterleaks.toml``, as Betterleaks' own open of it does. Read
    with ``..`` removed by hand it names ``op/betterleaks.toml``.
    """
    (tmp_path / "real" / "sub").mkdir(parents=True)
    (tmp_path / "op").mkdir()
    (tmp_path / "op" / "link").symlink_to(
        tmp_path / "real" / "sub", target_is_directory=True
    )
    return f"{(tmp_path / 'op' / 'link').as_posix()}/../betterleaks.toml"


@_LINKS_BEFORE_DOT_DOT
@pytest.mark.parametrize("name", ["BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG"])
def test_a_linked_config_variable_is_checked_where_betterleaks_opens_it(
    tree, tmp_path, monkeypatch, name
):
    """ASH leaves an absolute value to Betterleaks, so the file it checks is the
    one the value opens: here one that extends a relative path, refused, although
    the file the value names with ``..`` removed extends nothing."""
    value = _a_value_through_a_link(tmp_path)
    (tmp_path / "real" / "betterleaks.toml").write_text(_RELATIVE_EXTEND)
    (tmp_path / "op" / "betterleaks.toml").write_text("title = 'collapsed'\n")
    (tree / "common.toml").write_text(_TREE_COMMON)
    monkeypatch.setenv(name, value)
    scanner = _scanner(tree, tmp_path, output_dir=tree / ".ash" / "ash_output")
    with pytest.raises(ScannerError, match=_RELATIVE_REFUSAL):
        scanner._build_arguments(tree, tmp_path / "o.sarif")


@_LINKS_BEFORE_DOT_DOT
@pytest.mark.parametrize("name", ["BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG"])
def test_a_linked_config_variable_extending_an_absolute_path_is_left_to_betterleaks(
    tree, tmp_path, monkeypatch, name
):
    """The control: the file the value opens extends an absolute path outside the
    tree, so the value is left to Betterleaks, though nothing is at the path it
    names with ``..`` removed."""
    value = _a_value_through_a_link(tmp_path)
    common = tmp_path / "op" / "common.toml"
    common.write_text("title = 'common'\n")
    (tmp_path / "real" / "betterleaks.toml").write_text(
        f"[extend]\npath = '{common.as_posix()}'\n"
    )
    monkeypatch.setenv(name, value)
    scanner = _scanner(tree, tmp_path, output_dir=tree / ".ash" / "ash_output")
    args = scanner._build_arguments(tree, tmp_path / "o.sarif")
    assert _flag(args, "--config=") is None


def _a_relative_value_through_a_link(tmp_path: Path, monkeypatch) -> tuple[Path, str]:
    """The directory ASH runs in, and a config value relative to it holding ``..``
    after a symbolic link there.

    ASH anchors the value where it runs with ``..`` removed by hand, so it names
    ``op/betterleaks.toml``, and passes that file. Opened as written, the value
    would be ``real/betterleaks.toml``, through the link.
    """
    run = _run_from_a_directory_holding(tmp_path, monkeypatch)
    (run / "real" / "sub").mkdir(parents=True)
    (run / "op").mkdir()
    (run / "op" / "link").symlink_to(run / "real" / "sub", target_is_directory=True)
    return run, "op/link/../betterleaks.toml"


@_LINKS_BEFORE_DOT_DOT
@pytest.mark.parametrize("name", ["BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG"])
def test_a_relative_linked_config_variable_is_checked_where_ash_anchors_it(
    tree, tmp_path, monkeypatch, name
):
    """ASH passes a relative value anchored where it runs, ``..`` removed, so that
    file is the one it checks: here one that extends a relative path, refused,
    although the file the value opens through the link extends nothing."""
    run, value = _a_relative_value_through_a_link(tmp_path, monkeypatch)
    (run / "op" / "betterleaks.toml").write_text(_RELATIVE_EXTEND)
    (run / "real" / "betterleaks.toml").write_text("title = 'linked'\n")
    (tree / "common.toml").write_text(_TREE_COMMON)
    monkeypatch.setenv(name, value)
    scanner = _scanner(tree, tmp_path, output_dir=tree / ".ash" / "ash_output")
    with pytest.raises(ScannerError, match=_RELATIVE_REFUSAL):
        scanner._build_arguments(tree, tmp_path / "o.sarif")


@_LINKS_BEFORE_DOT_DOT
@pytest.mark.parametrize("name", ["BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG"])
def test_a_relative_linked_config_variable_extending_an_absolute_path_is_passed(
    tree, tmp_path, monkeypatch, name
):
    """The control: the file ASH anchors extends an absolute path outside the tree,
    so it is passed as ``--config``, spelled without ``..``, although the file the
    value opens through the link extends a relative path."""
    run, value = _a_relative_value_through_a_link(tmp_path, monkeypatch)
    common = tmp_path / "common.toml"
    common.write_text("title = 'common'\n")
    (run / "op" / "betterleaks.toml").write_text(
        f"[extend]\npath = '{common.as_posix()}'\n"
    )
    (run / "real" / "betterleaks.toml").write_text(_RELATIVE_EXTEND)
    monkeypatch.setenv(name, value)
    scanner = _scanner(tree, tmp_path, output_dir=tree / ".ash" / "ash_output")
    args = scanner._build_arguments(tree, tmp_path / "o.sarif")
    anchored = Path(os.getcwd(), "op", "betterleaks.toml")
    assert _flag(args, "--config=") == anchored.as_posix()
