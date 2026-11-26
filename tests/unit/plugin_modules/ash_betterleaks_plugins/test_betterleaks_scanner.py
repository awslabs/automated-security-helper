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
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
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
