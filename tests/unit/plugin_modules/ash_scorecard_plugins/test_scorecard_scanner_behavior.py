# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ScorecardScanner: opt-in gate, argv, JSON-to-SARIF conversion, failure handling.

The JSON below follows ``JSONScorecardResultV2`` (ossf/scorecard
``pkg/scorecard/json.go``) as written from its documented fields; it is not a
capture from a running scorecard binary. The scan() tests replace the subprocess
with a fake, so they run on every platform without the binary.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_scorecard_plugins
from automated_security_helper.plugin_modules.ash_scorecard_plugins import (
    scorecard_scanner as ss,
)
from automated_security_helper.plugin_modules.ash_scorecard_plugins.scorecard_scanner import (
    ScorecardScanner,
    ScorecardScannerConfig,
    ScorecardScannerConfigOptions,
    convert_scorecard_result,
    normalize_repo,
    origin_url_from_git_config,
    severity_for_score,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance

pytestmark = pytest.mark.unit

REPO = "github.com/example-org/example-repo"


def _check(name: str, score: int, reason: str = "reason", details=None) -> dict:
    return {
        "name": name,
        "score": score,
        "reason": reason,
        "details": details,
        "documentation": {
            "url": f"https://github.com/ossf/scorecard/blob/abc/docs/checks.md#{name.lower()}",
            "short": f"{name} short description",
        },
    }


DOCUMENT: Dict[str, Any] = {
    "date": "2026-11-19T00:00:00Z",
    "repo": {"name": REPO, "commit": "0" * 40},
    "scorecard": {"version": "v5.7.0", "commit": "1" * 40},
    "score": 5.4,
    "checks": [
        _check("Branch-Protection", 0, "branch protection not enabled", ["Warn: x"]),
        _check("Code-Review", 3),
        _check("SAST", 5),
        _check("Pinned-Dependencies", 6),
        _check("Token-Permissions", 9),
        _check("License", 10, "license file detected"),
        _check("Fuzzing", -1, "internal error"),
    ],
    "metadata": [],
}


def _findings(report: SarifReport) -> List[tuple]:
    return [
        (
            r.ruleId,
            getattr(r.level, "value", r.level),
            getattr(r.properties, "issue_severity", None),
        )
        for r in report.get_all_results()
    ]


class TestAlphaPlugin:
    def test_the_module_exports_the_scanner(self):
        assert ash_scorecard_plugins.ASH_SCANNERS == [ScorecardScanner]
        assert ash_scorecard_plugins.ASH_REPORTERS == []

    def test_scanner_is_off_by_default(self):
        assert ScorecardScannerConfig().enabled is False
        assert ScorecardScannerConfig().name == "scorecard"

    def test_class_declarations(self):
        assert ScorecardScanner.python_only is False
        assert ScorecardScanner.success_exit_codes == {0}
        assert ScorecardScanner.sandbox_requirements.network is True
        assert set(ScorecardScanner.sandbox_requirements.env_names) == set(
            ss.TOKEN_ENV_NAMES
        )


class TestSeverity:
    @pytest.mark.parametrize(
        "score,severity,level",
        [
            (0, "HIGH", "error"),
            (2, "HIGH", "error"),
            (3, "MEDIUM", "warning"),
            (5, "MEDIUM", "warning"),
            (6, "LOW", "note"),
            (9, "LOW", "note"),
        ],
    )
    def test_each_band(self, score, severity, level):
        assert severity_for_score(score) == (severity, level)

    @pytest.mark.parametrize("score", [10, -1, 11])
    def test_scores_that_are_not_findings_raise(self, score):
        with pytest.raises(ValueError):
            severity_for_score(score)

    def test_report_rows_and_negative_controls(self):
        report = convert_scorecard_result(DOCUMENT, repo=REPO)
        assert _findings(report) == [
            ("Branch-Protection", "error", "HIGH"),
            ("Code-Review", "warning", "MEDIUM"),
            ("SAST", "warning", "MEDIUM"),
            ("Pinned-Dependencies", "note", "LOW"),
            ("Token-Permissions", "note", "LOW"),
        ]
        names = {f[0] for f in _findings(report)}
        # 10 is a pass and -1 is inconclusive: neither is a finding.
        assert "License" not in names and "Fuzzing" not in names

    def test_a_clean_result_has_no_findings(self):
        doc = copy.deepcopy(DOCUMENT)
        doc["checks"] = [_check("License", 10), _check("SAST", 10)]
        assert convert_scorecard_result(doc, repo=REPO).get_all_results() == []

    def test_message_says_it_scores_the_origin_repository(self):
        report = convert_scorecard_result(DOCUMENT, repo=REPO)
        first = report.get_all_results()[0]
        assert "origin repository as hosted on GitHub" in first.message.root.text
        assert "scored 0/10" in first.message.root.text
        physical = first.locations[0].physicalLocation.root
        assert physical.artifactLocation.uri == REPO
        # A check names no line of a file, so no region is written.
        assert physical.region is None

    def test_driver_version_and_aggregate_score(self):
        report = convert_scorecard_result(DOCUMENT, repo=REPO)
        assert report.runs[0].tool.driver.version == "v5.7.0"
        assert report.runs[0].tool.driver.name == "OpenSSF Scorecard"

    def test_round_trip(self):
        report = convert_scorecard_result(DOCUMENT, repo=REPO)
        again = SarifReport.model_validate_json(
            report.model_dump_json(exclude_none=True, by_alias=True)
        )
        assert _findings(again) == _findings(report)


class TestMalformedChecks:
    @pytest.mark.parametrize(
        "check",
        [
            "not an object",
            {"score": 3, "reason": "no name"},
            {"name": "", "score": 3},
            {"name": "X", "score": 11},
            {"name": "X", "score": -2},
            {"name": "X", "score": "3"},
            {"name": "X", "score": True},
            {"name": "X", "score": 3.5},
            {"name": "X"},
        ],
    )
    def test_bad_check_fails_the_conversion(self, check):
        doc = copy.deepcopy(DOCUMENT)
        doc["checks"] = [check]
        with pytest.raises(ScannerError):
            convert_scorecard_result(doc, repo=REPO)


class TestRepoResolution:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("o/r", "github.com/o/r"),
            ("github.com/o/r", "github.com/o/r"),
            ("https://github.com/o/r.git", "github.com/o/r"),
            ("https://github.com/o/r/", "github.com/o/r"),
            ("git@github.com:o/r.git", "github.com/o/r"),
            ("ssh://git@github.com/o/r.git", "github.com/o/r"),
            ("https://gitlab.com/o/r", None),
            ("github.com/o", None),
            ("--repo=x/y", None),
            ("github.com/../r", None),
            ("", None),
        ],
    )
    def test_normalize(self, value, expected):
        assert normalize_repo(value) == expected

    def test_origin_url_is_read_from_the_origin_section_only(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text(
            '[remote "upstream"]\n\turl = https://github.com/other/other\n'
            '[remote "origin"]\n\turl = https://github.com/o/r\n'
        )
        assert origin_url_from_git_config(tmp_path) == "https://github.com/o/r"

    def test_no_git_config_is_none(self, tmp_path):
        assert origin_url_from_git_config(tmp_path) is None


# ---------------------------------------------------------------------------
# scan() with the subprocess replaced
# ---------------------------------------------------------------------------


class FakeScorecard:
    def __init__(
        self,
        stdout: Optional[str] = None,
        exit_code: int = 0,
        stderr: str = "",
        timed_out: bool = False,
    ):
        self.stdout = json.dumps(DOCUMENT) if stdout is None else stdout
        self.exit_code, self.stderr, self.timed_out = exit_code, stderr, timed_out
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


def _scanner(source: Path, tmp_path: Path, **options) -> ScorecardScanner:
    config = get_default_config()
    record_provenance(config, in_tree=[], trusted=AshConfig())
    return ScorecardScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=ScorecardScannerConfig(
            enabled=True, options=ScorecardScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / ".git").mkdir(parents=True)
    (src / ".git" / "config").write_text(
        '[remote "origin"]\n\turl = https://github.com/example-org/example-repo.git\n'
    )
    (src / "app.py").write_text("print(1)\n")
    return src


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (*ss.TOKEN_ENV_NAMES, "GH_HOST", "SCORECARD_EXPERIMENTAL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "not-a-real-token")


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ss, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner: ScorecardScanner, fake: FakeScorecard, monkeypatch):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(target=Path(scanner.context.source_dir), target_type="source")


class TestScan:
    def test_happy_path_argv_and_findings(
        self, tree, tmp_path, token, on_path, monkeypatch
    ):
        fake = FakeScorecard()
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert len(fake.calls) == 1
        assert fake.calls[0]["argv"] == [
            "scorecard",
            f"--repo={REPO}",
            "--format=json",
            "--show-details",
        ]
        assert [f[0] for f in _findings(report)][0] == "Branch-Protection"
        assert len(_findings(report)) == 5

    def test_repo_option_beats_the_origin_remote(
        self, tree, tmp_path, token, on_path, monkeypatch
    ):
        fake = FakeScorecard()
        _run(_scanner(tree, tmp_path, repo="other/thing"), fake, monkeypatch)
        assert "--repo=github.com/other/thing" in fake.calls[0]["argv"]

    @pytest.mark.parametrize(
        "flag", ["--local", "--token", "--output", "--format=sarif"]
    )
    def test_flags_that_change_what_is_scored_are_never_passed(
        self, flag, tree, tmp_path, token, on_path, monkeypatch
    ):
        fake = FakeScorecard()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert not any(a.startswith(flag) for a in fake.calls[0]["argv"])

    def test_redirecting_environment_is_removed(
        self, tree, tmp_path, token, on_path, monkeypatch
    ):
        monkeypatch.setenv("GH_HOST", "ghe.example.invalid")
        monkeypatch.setenv("SCORECARD_EXPERIMENTAL", "1")
        fake = FakeScorecard()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        env = fake.calls[0]["env"]
        assert "GH_HOST" not in env and "SCORECARD_EXPERIMENTAL" not in env
        assert env["GITHUB_AUTH_TOKEN"] == "not-a-real-token"

    def test_the_converted_target_is_not_rescored(
        self, tree, tmp_path, token, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeScorecard()
        monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
        report = scanner.scan(target=tree, target_type="converted")
        assert fake.calls == []
        assert report.get_all_results() == []

    def test_nonzero_exit_fails_even_with_findings_on_stdout(
        self, tree, tmp_path, token, on_path, monkeypatch
    ):
        fake = FakeScorecard(exit_code=1, stderr="rate limited")
        with pytest.raises(ScannerError, match="exited 1"):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, token, on_path, monkeypatch
    ):
        fake = FakeScorecard(timed_out=True)
        with pytest.raises(ScannerError, match="timed out"):
            _run(_scanner(tree, tmp_path, scan_timeout=30), fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 30

    @pytest.mark.parametrize(
        "stdout,message",
        [
            ("", "wrote no report"),
            ("   \n", "wrote no report"),
            ("not json", "not JSON"),
            ("[1, 2]", "not a Scorecard result object"),
            ('{"score": 1}', "not a Scorecard result object"),
            ('{"checks": [{"name": "X", "score": 99}]}', "score"),
        ],
    )
    def test_malformed_output_fails_the_scan(
        self, stdout, message, tree, tmp_path, token, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError, match=message):
            _run(_scanner(tree, tmp_path), FakeScorecard(stdout=stdout), monkeypatch)

    def test_stderr_is_not_copied_into_errors(
        self, tree, tmp_path, token, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeScorecard(stderr="line quoted from somewhere"), monkeypatch)
        assert not any("quoted from somewhere" in e for e in scanner.errors)


class TestOptInGate:
    def test_no_token_fails_closed_naming_the_variables(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeScorecard()
        with pytest.raises(ScannerError, match="GITHUB_TOKEN"):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert fake.calls == []

    def test_no_remote_fails_closed(self, tmp_path, token, on_path, monkeypatch):
        src = tmp_path / "plain"
        src.mkdir()
        (src / "a.py").write_text("x = 1\n")
        fake = FakeScorecard()
        with pytest.raises(ScannerError, match="origin"):
            _run(_scanner(src, tmp_path), fake, monkeypatch)
        assert fake.calls == []

    def test_non_github_remote_fails_closed(
        self, tmp_path, token, on_path, monkeypatch
    ):
        src = tmp_path / "gl"
        (src / ".git").mkdir(parents=True)
        (src / ".git" / "config").write_text(
            '[remote "origin"]\n\turl = https://gitlab.com/o/r\n'
        )
        (src / "a.py").write_text("x = 1\n")
        with pytest.raises(ScannerError, match="github.com"):
            _run(_scanner(src, tmp_path), FakeScorecard(), monkeypatch)

    def test_offline_fails_closed(self, tree, tmp_path, token, on_path, monkeypatch):
        monkeypatch.setattr(ScorecardScanner, "_is_offline_mode", lambda self: True)
        fake = FakeScorecard()
        with pytest.raises(ScannerError, match="offline"):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert fake.calls == []

    @pytest.mark.parametrize("name", ss.TOKEN_ENV_NAMES)
    def test_each_documented_token_variable_opens_the_gate(
        self, name, tree, tmp_path, on_path, monkeypatch
    ):
        monkeypatch.setenv(name, "not-a-real-token")
        assert _scanner(tree, tmp_path)._gate_refusal() is None


class TestDependencyCheck:
    def test_missing_binary(self, tree, tmp_path, token, monkeypatch):
        monkeypatch.setattr(ss, "find_executable", lambda cmd: None)
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is False

    def test_present_binary(self, tree, tmp_path, token, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_gate_refusal_is_recorded_as_the_reason(self, tree, tmp_path, on_path):
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False
        assert "GITHUB_TOKEN" in scanner.dependency_unavailable_reason
