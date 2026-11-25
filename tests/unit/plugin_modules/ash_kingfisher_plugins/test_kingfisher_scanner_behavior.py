# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""KingfisherScanner: the invocation, the exit status and the report.

The report tests read the SARIF committed under
``tests/test_data/scanners/kingfisher/captured/`` (see its README for how it was
captured and what was replaced). The scan() tests replace the subprocess with a fake
that serves those captures, so they run on every platform without the binary.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_kingfisher_plugins
from automated_security_helper.plugin_modules.ash_kingfisher_plugins import (
    kingfisher_scanner as ks,
)
from automated_security_helper.plugin_modules.ash_kingfisher_plugins.kingfisher_scanner import (
    KingfisherScanner,
    KingfisherScannerConfig,
    KingfisherScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit

#: The flags every run carries, as the pinned version documents them.
EXPECTED_FLAGS = (
    "--no-validate",
    "--no-update-check",
    "--quiet",
    "--redact",
    "--no-ignore",
    "--git-history=none",
    "--format=sarif",
)

#: What the positive capture must produce, written out by hand from the directory it
#: was captured over: one fabricated GitHub token in creds.txt at line 1.
POSITIVE_EXPECTED = [
    ("betterleaks.github-pat", "error", "CRITICAL", "creds.txt", 1),
]

#: The committed captures (tests/test_data/scanners/kingfisher/captured/README.md).
CAPTURED = Path(__file__).resolve().parents[3] / (
    "test_data/scanners/kingfisher/captured"
)
POSITIVE = (CAPTURED / "positive.sarif").read_text(encoding="utf-8")
#: A clean directory: Kingfisher writes the run with an empty results list.
NEGATIVE = (CAPTURED / "negative.sarif").read_text(encoding="utf-8")


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


class FakeKingfisher:
    """Stands in for _run_subprocess: records argv, writes a captured report."""

    def __init__(
        self,
        sarif_text: Optional[str] = POSITIVE,
        exit_code: int = 200,
        extra: Optional[Dict[str, Any]] = None,
        stderr: str = "",
    ):
        self.sarif_text, self.exit_code = sarif_text, exit_code
        self.extra, self.stderr = extra or {}, stderr
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            output_arg = next(a for a in command if a.startswith("--output="))
            path = Path(output_arg.split("=", 1)[1])
            if self.sarif_text is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(self.sarif_text, encoding="utf-8")
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": "",
                "stderr": self.stderr,
                **self.extra,
            }

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
) -> KingfisherScanner:
    """``operator``: the options came from the operator, or from the scanned tree."""
    config = get_default_config()
    record_provenance(
        config,
        in_tree=[] if operator else [source / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
    )
    output = output_dir or tmp_path / "out"
    return KingfisherScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=config,
        ),
        config=KingfisherScannerConfig(
            enabled=True, options=KingfisherScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "creds.txt").write_text("nothing to see\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ks, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(
    scanner: KingfisherScanner,
    fake: FakeKingfisher,
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
        assert KingfisherScannerConfig().enabled is True
        assert KingfisherScannerConfig().name == "kingfisher"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "kingfisher")

    def test_the_module_exports_the_scanner(self):
        assert ash_kingfisher_plugins.ASH_SCANNERS == [KingfisherScanner]
        assert ash_kingfisher_plugins.ASH_REPORTERS == []

    def test_live_validation_is_off_by_default(self):
        assert KingfisherScannerConfigOptions().validate_credentials is False

    def test_the_sandbox_requirements_are_the_strict_default(self):
        assert KingfisherScanner.sandbox_requirements == SandboxRequirements()

    def test_the_success_exit_codes_are_the_three_kingfisher_documents(self):
        assert KingfisherScanner.success_exit_codes == {0, 200, 205}


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeKingfisher()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[:2] == ["kingfisher", "scan"]
        for expected in EXPECTED_FLAGS:
            assert expected in argv
        assert _flag(argv, "--output=").endswith("source/kingfisher.sarif")
        # "--" ends option parsing; the source target is "." from the source dir.
        assert argv[-2:] == ["--", "."]
        assert fake.calls[0]["cwd"] is None, "the run starts in the source directory"

    def test_the_scan_path_is_not_read_as_a_flag(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeKingfisher()
        _run(scanner, fake, monkeypatch)
        before_separator = fake.argv[: fake.argv.index("--")]
        assert "." not in before_separator

    @pytest.mark.parametrize(
        "forbidden",
        [
            "--config",
            "--baseline-file",
            "--manage-baseline",
            "--blast-radius",
            "--access-map",
            "--self-update",
            "--alert-webhook",
            "--rules-path",
            "--allow-internal-ips",
        ],
    )
    def test_flags_that_read_the_tree_or_reach_the_network_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, forbidden
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeKingfisher()
        _run(scanner, fake, monkeypatch)
        assert not any(
            a == forbidden or a.startswith(f"{forbidden}=") for a in fake.argv
        )

    def test_validation_is_refused_unless_the_operator_turned_it_on(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeKingfisher()
        _run(scanner, fake, monkeypatch)
        assert "--no-validate" in fake.argv

    def test_the_operator_can_turn_validation_on(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, validate_credentials=True)
        fake = FakeKingfisher()
        _run(scanner, fake, monkeypatch)
        assert "--no-validate" not in fake.argv

    def test_validation_switched_on_by_the_tree_is_refused_with_a_warning(
        self, tree, tmp_path, on_path, monkeypatch, caplog
    ):
        scanner = _scanner(tree, tmp_path, operator=False, validate_credentials=True)
        fake = FakeKingfisher()
        with caplog.at_level("WARNING"):
            _run(scanner, fake, monkeypatch)
        assert "--no-validate" in fake.argv
        assert "scanners.kingfisher.options.validate_credentials" in caplog.text

    def test_the_converted_target_is_an_absolute_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "x.py").write_text("print(1)\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeKingfisher(sarif_text=NEGATIVE, exit_code=0)
        _run(scanner, fake, monkeypatch, target=converted, target_type="converted")
        assert fake.argv[-2:] == ["--", converted.absolute().as_posix()]

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeKingfisher()
        _run(scanner, fake, monkeypatch, target=tmp_path / "gone")
        assert fake.calls == []


class TestReport:
    def test_the_positive_capture_is_rated_critical_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeKingfisher(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_the_clean_capture_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(
            scanner, FakeKingfisher(sarif_text=NEGATIVE, exit_code=0), monkeypatch
        )
        assert _findings(report) == []

    def test_a_low_confidence_level_does_not_lower_the_rating(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """Kingfisher writes note for low confidence; ASH rates every secret alike."""
        for level in ("note", "warning", "error"):
            raw = json.loads(POSITIVE)
            raw["runs"][0]["results"][0]["level"] = level
            scanner = _scanner(tree, tmp_path)
            report = _run(
                scanner, FakeKingfisher(sarif_text=json.dumps(raw)), monkeypatch
            )
            assert _findings(report) == POSITIVE_EXPECTED, level

    def test_results_are_marked_as_secret_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeKingfisher(), monkeypatch)
        for result in report.get_all_results():
            assert getattr(result.kind, "value", result.kind) == "fail"
            assert {"secret", "security"} <= set(result.properties.tags)

    def test_the_run_properties_with_the_scanned_path_are_dropped(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeKingfisher(), monkeypatch)
        assert report.runs[0].properties is None
        assert "/scanned/dir" not in report.model_dump_json()

    def test_the_real_driver_version_is_kept(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeKingfisher(), monkeypatch)
        driver = report.runs[0].tool.driver
        assert driver.name == "kingfisher"
        assert driver.semanticVersion == "2.19.1"

    def test_a_redacted_snippet_is_kept_as_kingfisher_wrote_it(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeKingfisher(), monkeypatch)
        region = report.get_all_results()[0].locations[0].physicalLocation.root.region
        assert region.snippet.text == "[REDACTED:a11dff19]"

    def test_a_snippet_that_is_not_redacted_is_overwritten(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """A run without --redact's effect still leaks nothing into the report."""
        raw = json.loads(POSITIVE)
        region = raw["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "region"
        ]
        region["snippet"]["text"] = "not-a-redaction"
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeKingfisher(sarif_text=json.dumps(raw)), monkeypatch)
        texts = {
            r.locations[0].physicalLocation.root.region.snippet.text
            for r in report.get_all_results()
        }
        assert texts == {"REDACTED"}

    def test_results_under_ashs_own_output_directory_are_dropped(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """Kingfisher has no exclude flag ASH passes, so it reads ASH's output."""
        raw = json.loads(POSITIVE)
        copy = json.loads(json.dumps(raw["runs"][0]["results"][0]))
        copy["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = (
            "./.ash/ash_output/converted/notebook.py"
        )
        raw["runs"][0]["results"].append(copy)
        scanner = _scanner(tree, tmp_path, output_dir=tree / ".ash" / "ash_output")
        report = _run(scanner, FakeKingfisher(sarif_text=json.dumps(raw)), monkeypatch)
        assert [f[3] for f in _findings(report)] == ["creds.txt"]

    def test_the_report_survives_a_round_trip_through_the_sarif_model(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeKingfisher(), monkeypatch)
        again = SarifReport.model_validate_json(
            report.model_dump_json(exclude_none=True, by_alias=True)
        )
        assert _findings(again) == POSITIVE_EXPECTED


class TestExitStatus:
    @pytest.mark.parametrize("code", [200, 205])
    def test_finding_secrets_is_a_success(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeKingfisher(exit_code=code), monkeypatch)
        assert scanner.exit_code == code
        assert scanner._exit_code_accepted()

    def test_zero_means_clean_and_is_a_success(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeKingfisher(sarif_text=NEGATIVE, exit_code=0), monkeypatch)
        assert scanner._exit_code_accepted()

    @pytest.mark.parametrize("code", [1, 2, 3, 126, 137])
    def test_nonzero_exit_with_findings_on_disk_fails_unless_it_is_a_documented_one(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        """Exit 3 is "nothing to scan"; a report on disk decides nothing then."""
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeKingfisher(exit_code=code), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeKingfisher(sarif_text=None, exit_code=0), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        first = FakeKingfisher()
        _run(scanner, first, monkeypatch)
        report = Path(_flag(first.argv, "--output="))
        assert report.exists(), "the first run left its report"
        second = FakeKingfisher(sarif_text=None, exit_code=0)
        with pytest.raises(ScannerError):
            _run(scanner, second, monkeypatch)
        assert not report.exists()

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=60)
        fake = FakeKingfisher(sarif_text=None, exit_code=124, extra={"timed_out": True})
        with pytest.raises(ScannerError, match="timed out after"):
            _run(scanner, fake, monkeypatch)
        timeout = fake.calls[0]["timeout"]
        assert timeout is not None and 0 < timeout <= 60

    @pytest.mark.parametrize(
        "text",
        [
            "not json at all",
            "{",
            "[]",
            "{}",
            json.dumps({"version": "2.1.0", "runs": []}),
            json.dumps({"version": "2.1.0", "runs": [{"tool": 3}]}),
        ],
        ids=["prose", "truncated", "array", "no-run-object", "no-runs", "bad-run"],
    )
    def test_malformed_output_fails_the_scan_instead_of_reading_as_clean(
        self, tree, tmp_path, on_path, monkeypatch, text
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeKingfisher(sarif_text=text, exit_code=0), monkeypatch)

    def test_an_empty_report_file_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeKingfisher(sarif_text="", exit_code=0), monkeypatch)

    def test_the_tools_stderr_is_not_copied_into_the_scans_errors(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner._process_command_response(
            {"returncode": 0, "stdout": "", "stderr": "WARN PLANTED-LINE from a file"}
        )
        assert not any("PLANTED-LINE" in line for line in scanner.errors)

    def test_the_failure_message_names_the_log_and_does_not_quote_it(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.exit_code = 1
        results = tmp_path / "out" / "source" / "kingfisher.sarif"
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


class TestDependencyCheck:
    def test_a_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ks, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False

    def test_a_present_binary_satisfies_them(self, tree, tmp_path, on_path):
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is True


class TestInstall:
    def test_install_commands_cover_every_published_platform(self, tmp_path):
        from automated_security_helper.utils.tool_downloads import downloadable_tools

        if "kingfisher" not in downloadable_tools():
            pytest.skip("the pinned release table has no kingfisher rows yet")
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
            assert "kingfisher" in str(commands[0])
