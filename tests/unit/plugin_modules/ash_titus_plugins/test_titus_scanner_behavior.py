# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""TitusScanner: the invocation, the exit status, and the report.

The synthetic SARIF below has the shape Titus v1.3.0 prints for ``titus scan
--format sarif`` (pkg/sarif/sarif.go: result fields, ``security-severity``, the
``titusLocation/v1`` fingerprint, and a score-banded level), with one result per
severity band so every band is covered. The REAL output the binary printed is the
captured fixture under tests/test_data/scanners/titus/captured/ (see its README), and
``TestCapturedReport`` drives the adapter over it. The scan() tests replace the layer
under ``_run_subprocess`` with a fake that returns the SARIF as stdout, so they run
on every platform without the binary and exercise the stdout-to-results-file step of
the plugin.

The matched text in the fixtures is an obviously fake value, never a real credential.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_titus_plugins
from automated_security_helper.plugin_modules.ash_titus_plugins import (
    titus_install as ti,
)
from automated_security_helper.plugin_modules.ash_titus_plugins import (
    titus_scanner as ts,
)
from automated_security_helper.plugin_modules.ash_titus_plugins.titus_scanner import (
    TitusScanner,
    TitusScannerConfig,
    TitusScannerConfigOptions,
    severity_for,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

FAKE_MATCH = "FAKE-NOT-A-REAL-SECRET-0000"


def _result(rule_id: str, uri: str, line: int, score: Optional[int]) -> Dict[str, Any]:
    """One result as pkg/sarif/sarif.go writes it; ``score`` None means unscored."""
    result: Dict[str, Any] = {
        "ruleId": rule_id,
        "level": "warning",
        "message": {"text": f"Rule {rule_id}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": line,
                        "startColumn": 7,
                        "endLine": line,
                        "endColumn": 33,
                        "snippet": {"text": FAKE_MATCH},
                    },
                }
            }
        ],
        "partialFingerprints": {"titusLocation/v1": "ab" * 32},
    }
    if score is not None:
        level = (
            "none"
            if score < 20
            else "note"
            if score < 40
            else "warning"
            if score < 60
            else "error"
        )
        result["level"] = level
        result["properties"] = {"security-severity": f"{score / 10:.1f}"}
    return result


def _report(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "titus",
                        "version": "0.1.0",
                        "rules": [
                            {
                                "id": "np.aws.1",
                                "name": "AWS API Key",
                                "shortDescription": {"text": ""},
                            }
                        ],
                    }
                },
                "results": results,
            }
        ],
    }


#: Four scored results, one per band, and the findings expected from them, written out
#: by hand: (ruleId, SARIF level, ASH severity, uri, line).
POSITIVE = _report(
    [
        _result("np.aws.1", "app.py", 4, 85),
        _result("np.github.1", "services/settings.py", 3, 65),
        _result("np.generic.1", "notes.txt", 9, 45),
        _result("np.generic.2", "notes.txt", 12, 25),
        _result("np.generic.3", "notes.txt", 15, 5),
    ]
)
POSITIVE_EXPECTED = [
    ("np.aws.1", "error", "CRITICAL", "app.py", 4),
    ("np.github.1", "error", "HIGH", "services/settings.py", 3),
    ("np.generic.1", "warning", "MEDIUM", "notes.txt", 9),
    ("np.generic.2", "note", "LOW", "notes.txt", 12),
    ("np.generic.3", "none", "INFO", "notes.txt", 15),
]
NEGATIVE = _report([])


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
            )
        )
    return out


def _base_run_subprocess():
    """The class whose ``_run_subprocess`` TitusScanner's override calls."""
    return next(
        cls for cls in TitusScanner.__mro__[1:] if "_run_subprocess" in cls.__dict__
    )


class FakeTitus:
    """Stands in for the base ``_run_subprocess``: records the call, prints SARIF."""

    def __init__(
        self,
        document: Optional[Any] = POSITIVE,
        exit_code: int = 0,
        stdout_text: Optional[str] = None,
        stderr: str = "",
        timed_out: bool = False,
    ):
        self.document, self.exit_code = document, exit_code
        self.stdout_text, self.stderr = stdout_text, stderr
        self.timed_out = timed_out
        self.calls: List[Dict[str, Any]] = []

    def install(self, monkeypatch, scanner: TitusScanner) -> None:
        fake = self

        def run(_self, command, results_dir=None, **kwargs):
            fake.calls.append(
                {"argv": list(command), "kwargs": dict(kwargs), "dir": results_dir}
            )
            if fake.timed_out:
                _self.exit_code = -9
                return {"timed_out": True}
            _self.exit_code = fake.exit_code
            text = fake.stdout_text
            if text is None and fake.document is not None:
                text = json.dumps(fake.document)
            response: Dict[str, Any] = {
                "returncode": fake.exit_code,
                "stderr": fake.stderr,
            }
            if kwargs.get("stdout_preference") == "return":
                response["stdout"] = text or ""
            return response

        monkeypatch.setattr(_base_run_subprocess(), "_run_subprocess", run)

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(
    source: Path, tmp_path: Path, output_dir: Optional[Path] = None, **options
) -> TitusScanner:
    config = get_default_config()
    output = output_dir or tmp_path / "out"
    return TitusScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=config,
        ),
        config=TitusScannerConfig(
            enabled=True, options=TitusScannerConfigOptions(**options)
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


def _run(scanner, fake, monkeypatch, target=None, target_type="source"):
    fake.install(monkeypatch, scanner)
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert TitusScannerConfig().enabled is True
        assert TitusScannerConfig().name == "titus"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "titus")

    def test_the_module_exports_the_scanner(self):
        assert ash_titus_plugins.ASH_SCANNERS == [TitusScanner]
        assert ash_titus_plugins.ASH_REPORTERS == []

    def test_class_vars_are_set_deliberately(self):
        assert TitusScanner.python_only is False
        assert TitusScanner.success_exit_codes == {0}


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeTitus()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[:2] == ["titus", "scan"]
        for expected in (
            "--format=sarif",
            "--output=:memory:",
            "--accessibility=private",
            "--context-lines=0",
        ):
            assert expected in argv
        assert argv[-2:] == ["--", "."], "the source is '.' from the source dir"
        assert fake.calls[0]["kwargs"].get("cwd") is None

    def test_stdout_is_asked_for_so_it_can_become_the_results_file(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeTitus()
        _run(scanner, fake, monkeypatch)
        assert fake.calls[0]["kwargs"]["stdout_preference"] == "return"
        written = Path(scanner.results_dir) / "source" / "titus.sarif"
        assert json.loads(written.read_text(encoding="utf-8"))["version"] == "2.1.0"

    def test_options_take_their_value_with_an_equals_sign(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """A separate value token would be read as the scan path."""
        scanner = _scanner(tree, tmp_path)
        fake = FakeTitus()
        _run(scanner, fake, monkeypatch)
        for bare in ("--format", "--output", "--accessibility", "--context-lines"):
            assert bare not in fake.argv
        assert "sarif" not in fake.argv and "private" not in fake.argv

    @pytest.mark.parametrize(
        "flag",
        [
            "--validate",
            "--score-scope",
            "--rules",
            "--ruleset",
            "--ignore",
            "--include-noisy",
            "--git",
            "--docker",
            "--token",
        ],
    )
    def test_flags_that_reach_the_network_or_read_the_tree_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, flag
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeTitus()
        _run(scanner, fake, monkeypatch)
        assert not [a for a in fake.argv if a == flag or a.startswith(flag + "=")]

    def test_a_converted_target_is_an_absolute_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "x.py").write_text("x = 1\n")
        fake = FakeTitus(document=NEGATIVE)
        _run(scanner, fake, monkeypatch, target=converted, target_type="converted")
        assert fake.argv[-2:] == ["--", converted.absolute().as_posix()]

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeTitus()
        _run(scanner, fake, monkeypatch, target=tmp_path / "gone")
        assert fake.calls == []


class TestReport:
    def test_the_positive_report_is_rated_by_score_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeTitus(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_the_clean_report_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path), FakeTitus(document=NEGATIVE), monkeypatch
        )
        assert _findings(report) == []

    def test_level_and_severity_agree_on_every_result(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeTitus(), monkeypatch)
        for result in report.get_all_results():
            severity = result.properties.issue_severity
            assert result.level == ts.SEVERITY_LEVEL[severity]

    def test_every_snippet_is_redacted(self, tree, tmp_path, on_path, monkeypatch):
        report = _run(_scanner(tree, tmp_path), FakeTitus(), monkeypatch)
        dumped = report.model_dump_json()
        assert FAKE_MATCH not in dumped
        for result in report.get_all_results():
            region = result.locations[0].physicalLocation.root.region
            assert region.snippet.text == ts.REDACTED

    def test_results_are_marked_as_secret_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeTitus(), monkeypatch)
        for result in report.get_all_results():
            assert {"secret", "security"} <= set(result.properties.tags)
        for result in report.get_all_results():
            if result.properties.issue_severity != "INFO":
                assert getattr(result.kind, "value", result.kind) == "fail"

    def test_the_wrong_driver_version_is_dropped(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeTitus(), monkeypatch)
        assert report.runs[0].tool.driver.version is None

    def test_a_file_uri_under_the_target_becomes_source_relative(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        document = copy.deepcopy(POSITIVE)
        absolute = (tree / "app.py").absolute().as_posix()
        document["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"] = f"file://{absolute}"
        report = _run(
            _scanner(tree, tmp_path), FakeTitus(document=document), monkeypatch
        )
        assert _findings(report)[0][3] == "app.py"

    def test_results_under_ashs_own_output_directory_are_dropped(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, output_dir=tree / ".ash-out")
        document = copy.deepcopy(POSITIVE)
        document["runs"][0]["results"][1]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"] = ".ash-out/reports/prior.sarif"
        report = _run(scanner, FakeTitus(document=document), monkeypatch)
        assert [f[3] for f in _findings(report)].count(
            ".ash-out/reports/prior.sarif"
        ) == 0
        assert len(_findings(report)) == 4

    def test_the_report_round_trips_through_the_sarif_model(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeTitus(), monkeypatch)
        assert len(SarifReport.model_validate(report.model_dump(mode="json")).runs) == 1


class TestSeverity:
    @pytest.mark.parametrize(
        "score, level, expected",
        [
            ("10.0", "error", "CRITICAL"),
            ("8.0", "error", "CRITICAL"),
            ("7.9", "error", "HIGH"),
            ("6.0", "error", "HIGH"),
            ("5.9", "warning", "MEDIUM"),
            ("4.0", "warning", "MEDIUM"),
            ("3.9", "note", "LOW"),
            ("2.0", "note", "LOW"),
            ("1.9", "none", "INFO"),
            ("0.0", "none", "INFO"),
        ],
    )
    def test_each_score_band(self, score, level, expected):
        assert severity_for(level, score) == expected
        assert ts.SEVERITY_LEVEL[expected].value == level

    @pytest.mark.parametrize(
        "level, expected",
        [("error", "HIGH"), ("warning", "MEDIUM"), ("note", "LOW"), ("none", "INFO")],
    )
    def test_an_unscored_result_is_rated_by_its_level(self, level, expected):
        assert severity_for(level, None) == expected

    def test_a_result_without_a_level_is_medium(self):
        assert severity_for(None, None) == "MEDIUM"

    def test_an_unknown_level_is_high(self):
        assert severity_for("catastrophic", None) == "HIGH"

    def test_an_unreadable_score_falls_back_to_the_level(self):
        assert severity_for("note", "not-a-number") == "LOW"

    def test_an_unscored_warning_in_a_report_is_medium(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        document = _report([_result("np.x.1", "app.py", 1, None)])
        report = _run(
            _scanner(tree, tmp_path), FakeTitus(document=document), monkeypatch
        )
        assert _findings(report) == [("np.x.1", "warning", "MEDIUM", "app.py", 1)]


class TestExitStatus:
    def test_zero_is_a_success_with_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeTitus(exit_code=0), monkeypatch)
        assert scanner.exit_code == 0
        assert scanner._exit_code_accepted()

    @pytest.mark.parametrize("code", [1, 2, 126, 137])
    def test_any_other_exit_fails_the_scan_even_with_a_report_on_disk(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeTitus(exit_code=code), monkeypatch)

    def test_a_run_that_printed_nothing_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeTitus(document=None, stdout_text=""), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeTitus(), monkeypatch)
        with pytest.raises(ScannerError):
            _run(scanner, FakeTitus(document=None, stdout_text=""), monkeypatch)

    def test_stderr_is_not_copied_into_the_scanners_errors(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeTitus(stderr="reading /src/secret-named-file"), monkeypatch)
        assert not any("secret-named-file" in str(e) for e in scanner.errors)

    def test_the_stderr_filter_is_the_flag_not_an_accident(
        self, tree, tmp_path, monkeypatch
    ):
        """Control for the test above: the same response through a scanner that
        quotes stderr does put the stream into ``errors`` when the tool failed, so
        the absence above comes from ``quote_tool_stderr = False``."""
        assert TitusScanner.quote_tool_stderr is False
        response = {"returncode": 1, "stderr": "reading /src/secret-named-file"}
        quiet = _scanner(tree, tmp_path)
        quiet._process_command_response(dict(response))
        assert not any("secret-named-file" in str(e) for e in quiet.errors)
        monkeypatch.setattr(TitusScanner, "quote_tool_stderr", True)
        loud = _scanner(tree, tmp_path)
        loud._process_command_response(dict(response))
        assert any("secret-named-file" in str(e) for e in loud.errors)

    def test_failure_before_start_has_no_exit_code_and_names_the_tool(
        self, tree, tmp_path
    ):
        message = _scanner(tree, tmp_path)._describe_scan_failure(
            RuntimeError("boom"), None, tool_started=False
        )
        assert "titus was not started" in message
        assert "exit code" not in message


class TestTimeout:
    def test_a_timeout_fails_the_scan_and_the_limit_reaches_the_subprocess(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=5)
        fake = FakeTitus(timed_out=True)
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["kwargs"]["timeout"] <= 5


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "text",
        [
            "not json at all",
            "[1, 2, 3]",
            '{"version": "2.1.0"}',
            '{"version": "2.1.0", "runs": []}',
            '{"version": "2.1.0", "runs": [{"results": "nope"}]}',
        ],
    )
    def test_output_that_is_not_a_usable_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch, text
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeTitus(stdout_text=text), monkeypatch)


class TestDependencyCheck:
    def test_a_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ts, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False

    def test_a_missing_binary_never_reaches_the_tool(self, tree, tmp_path, monkeypatch):
        monkeypatch.setattr(ts, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        fake = FakeTitus()
        assert _run(scanner, fake, monkeypatch) is False
        assert scanner.dependencies_satisfied is False
        assert fake.calls == []

    def test_a_present_binary_satisfies_them(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_an_unavailable_dependency_reason_wins_over_a_binary_on_path(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "not published for this platform"
        assert scanner.validate_plugin_dependencies() is False


CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "titus"
    / "captured"
)

#: What the captured positive report must come out as: (ruleId, SARIF level, ASH
#: severity, uri, line). Written from the scores in the capture: 5.0 is MEDIUM, 2.5
#: is LOW (the bands are in the module docstring).
CAPTURED_EXPECTED = [
    ("np.slack.2", "warning", "MEDIUM", "notes.txt", 1),
    ("np.generic.2", "note", "LOW", "services/settings.py", 2),
    ("np.github.1", "warning", "MEDIUM", "ci.env", 1),
]


class TestCapturedReport:
    """The adapter over what the binary really printed (captured/README.md)."""

    def _doc(self, name: str) -> Dict[str, Any]:
        return json.loads((CAPTURED / name).read_text(encoding="utf-8"))

    def test_the_captured_positive_is_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path),
            FakeTitus(document=self._doc("positive.sarif")),
            monkeypatch,
        )
        assert _findings(report) == CAPTURED_EXPECTED

    def test_the_captured_negative_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path),
            FakeTitus(document=self._doc("negative.sarif")),
            monkeypatch,
        )
        assert _findings(report) == []

    def test_the_captured_matched_text_never_reaches_the_report(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        document = self._doc("positive.sarif")
        assert "FIXTURE-PLACEHOLDER-FOR-MATCHED-TEXT" in json.dumps(document)
        report = _run(
            _scanner(tree, tmp_path), FakeTitus(document=document), monkeypatch
        )
        assert "FIXTURE-PLACEHOLDER-FOR-MATCHED-TEXT" not in report.model_dump_json()

    def test_the_hosts_absolute_path_is_dropped(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        document = self._doc("positive.sarif")
        assert "absolute_path" in json.dumps(document)
        report = _run(
            _scanner(tree, tmp_path), FakeTitus(document=document), monkeypatch
        )
        results = report.get_all_results()
        assert len(results) == 3
        for result in results:
            assert "absolute_path" not in (result.properties.model_extra or {})
            assert "titus_score" in result.properties.model_extra
        assert "/lane/src" not in report.model_dump_json()

    def test_the_captured_fingerprint_and_score_survive(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path),
            FakeTitus(document=self._doc("positive.sarif")),
            monkeypatch,
        )
        first = report.get_all_results()[0]
        assert first.partialFingerprints["titusLocation/v1"].startswith("a49f36e0")
        assert first.properties.model_extra["security-severity"] == "5.0"


class TestInstall:
    """Install commands come from the plugin's own pin, titus_install.py."""

    def test_construction_builds_a_command_for_every_published_platform(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        scanner = _scanner(tmp_path, tmp_path)
        table = scanner.custom_install_commands
        assert {(p, a) for p, arches in table.items() for a in arches} == set(ti.ASSETS)
        for arches in table.values():
            for commands in arches.values():
                (command,) = commands
                assert command.shell is False
                assert "install_titus" in " ".join(command.args)
        assert "arm64" not in table["windows"], "titus publishes no windows/arm64"

    def test_construction_does_not_raise_without_a_bin_directory(
        self, tmp_path, monkeypatch
    ):
        from automated_security_helper.utils import download_utils as du

        monkeypatch.setattr(du, "current_bin_path", lambda: None)
        scanner = _scanner(tmp_path, tmp_path)
        (command,) = scanner.custom_install_commands["linux"]["amd64"]
        assert "install_titus" not in " ".join(command.args)
