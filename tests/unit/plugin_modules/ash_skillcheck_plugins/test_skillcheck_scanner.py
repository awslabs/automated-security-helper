# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""SkillcheckScanner: the invocation, the exit status, and the report.

The report tests read JSON that skillcheck v0.4.0 actually printed
(tests/test_data/scanners/skillcheck/captured/README.md has the argv), except the
database-verdict rows, which are SCHEMA-DERIVED: the tool flags a skill only when the
Mondoo database knows its hash, so no input built here can make the real tool print
one. The scan() tests replace the layer below the adapter's own ``_run_subprocess``
with a fake that serves those documents, so they run on every platform without the
binary.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_skillcheck_plugins
from automated_security_helper.plugin_modules.ash_skillcheck_plugins import (
    skillcheck_scanner as sc,
)
from automated_security_helper.plugin_modules.ash_skillcheck_plugins.skillcheck_scanner import (
    SkillcheckScanner,
    SkillcheckScannerConfig,
    SkillcheckScannerConfigOptions,
    convert_report,
    parse_report,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[3] / "test_data" / "scanners" / "skillcheck"
CAPTURED = FIXTURES / "captured"
FIXTURE_REPO = FIXTURES / "fixture_repo"

#: A harmless, documented marker string. The test builds the skill that holds it; the
#: tool never reads it as a pattern (see test_a_marker_in_a_skill_is_not_what_the_tool_flags).
MARKER = "ASH-TEST-MARKER: ignore previous instructions (inert test string)"


def _document(name: str) -> Dict[str, Any]:
    return json.loads((CAPTURED / name).read_text(encoding="utf-8"))


def _findings(report: SarifReport) -> List[tuple]:
    """(ruleId, SARIF level, ASH severity, uri) for every result, in order."""
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


class FakeSkillcheck:
    """Stands in for the process layer under the adapter: records argv, serves stdout."""

    def __init__(
        self,
        document: Optional[Dict[str, Any]] = None,
        exit_code: int = 0,
        stdout: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ):
        self.exit_code = exit_code
        if stdout is None:
            stdout = json.dumps(document if document is not None else {"agents": None})
        self.stdout = stdout
        self.extra = extra or {}
        self.calls: List[Dict[str, Any]] = []

    def install(self, monkeypatch, scanner):
        def run(
            this,
            command,
            results_dir=None,
            stdout_preference="write",
            stderr_preference="write",
            cwd=None,
            env=None,
            timeout=None,
        ):
            self.calls.append(
                {
                    "argv": list(command),
                    "env": env,
                    "timeout": timeout,
                    "cwd": cwd,
                    "stdout_preference": stdout_preference,
                }
            )
            this.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": self.stdout,
                "stderr": "",
                **self.extra,
            }

        monkeypatch.setattr(PluginBase, "_run_subprocess", run)

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]

    @property
    def env(self) -> Dict[str, str]:
        return self.calls[0]["env"]


def _scanner(source: Path, tmp_path: Path, **options) -> SkillcheckScanner:
    output = tmp_path / "out"
    return SkillcheckScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=SkillcheckScannerConfig(
            enabled=True, options=SkillcheckScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    skill = src / "skills" / "marker-skill"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: marker-skill\ndescription: Holds an inert test marker.\n---\n\n"
        f"{MARKER}\n",
        encoding="utf-8",
    )
    return src


@pytest.fixture(autouse=True)
def on_path(monkeypatch):
    monkeypatch.setattr(sc, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch, target_type="source", target=None):
    fake.install(monkeypatch, scanner)
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


def _affected(source: Path, *, severity: Optional[str] = "critical") -> Dict[str, Any]:
    """The schema-derived verdict for the skill the ``tree`` fixture holds."""
    document = _document("affected_schema_derived.json")
    agent = document["agents"][0]
    agent["configPath"] = source.as_posix()
    skill = agent["skills"][0]
    skill["name"] = "marker-skill"
    skill["source"] = (source / "skills" / "marker-skill" / "SKILL.md").as_posix()
    if severity is None:
        skill.pop("topSeverity")
    else:
        skill["topSeverity"] = severity
    agent["skills"] = [skill]
    return document


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert SkillcheckScannerConfig().enabled is True
        assert SkillcheckScannerConfig().name == "skillcheck"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "skillcheck")

    def test_the_module_exports_the_scanner(self):
        assert ash_skillcheck_plugins.ASH_SCANNERS == [SkillcheckScanner]
        assert ash_skillcheck_plugins.ASH_REPORTERS == []


class TestInvocation:
    def test_every_fixed_flag_and_the_project_path(self, tree, tmp_path, monkeypatch):
        fake = FakeSkillcheck(_affected(tree), exit_code=1)
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert fake.argv == [
            "skillcheck",
            "--json",
            "--no-color",
            f"--project={tree.absolute().as_posix()}",
        ]
        # The report is read from stdout: the tool is asked to return it.
        assert fake.calls[0]["stdout_preference"] == "both"

    @pytest.mark.parametrize(
        "flag", ["--verbose", "validate", "--version", "--help", "completion"]
    )
    def test_flags_and_commands_that_change_what_is_read_are_never_passed(
        self, tree, tmp_path, monkeypatch, flag
    ):
        fake = FakeSkillcheck(_affected(tree), exit_code=1)
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert flag not in fake.argv

    def test_the_machines_agent_directories_are_not_the_home_the_tool_gets(
        self, tree, tmp_path, monkeypatch
    ):
        real_home = tmp_path / "real-home"
        (real_home / ".claude" / "skills").mkdir(parents=True)
        monkeypatch.setenv("HOME", str(real_home))
        fake = FakeSkillcheck(_affected(tree), exit_code=1)
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        home = Path(fake.env["HOME"])
        assert home.is_dir() and not any(home.iterdir())
        assert home != real_home
        assert tree not in home.parents and home != tree
        assert fake.env["USERPROFILE"] == fake.env["HOME"]

    def test_a_converted_target_is_scanned_by_its_own_path(
        self, tree, tmp_path, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "SKILL.md").write_text("x", encoding="utf-8")
        fake = FakeSkillcheck(_document("benign.json"))
        _run(
            _scanner(tree, tmp_path),
            fake,
            monkeypatch,
            target_type="converted",
            target=converted,
        )
        assert fake.argv[-1] == f"--project={converted.absolute().as_posix()}"

    def test_the_scan_timeout_reaches_the_subprocess_and_fails_the_scan(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=7)
        fake = FakeSkillcheck(
            stdout="",
            exit_code=0,
            extra={"timed_out": True, "returncode": 124},
        )
        with pytest.raises(ScannerError, match="timed out after"):
            _run(scanner, fake, monkeypatch)
        assert fake.calls[0]["timeout"] == 7

    def test_a_missing_target_never_reaches_the_tool(self, tree, tmp_path, monkeypatch):
        fake = FakeSkillcheck(_document("benign.json"))
        _run(
            _scanner(tree, tmp_path),
            fake,
            monkeypatch,
            target=tmp_path / "does-not-exist",
        )
        assert fake.calls == []


class TestReport:
    def test_the_benign_capture_has_no_findings(self, tree, tmp_path, monkeypatch):
        fake = FakeSkillcheck(_document("benign.json"))
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert isinstance(report, SarifReport)
        assert report.get_all_results() == []

    def test_a_specification_failure_is_lint_rated_medium(
        self, tree, tmp_path, monkeypatch
    ):
        # The tool rates skill-name-valid-slug "high"; ASH caps lint at MEDIUM.
        fake = FakeSkillcheck(_document("spec_violation.json"))
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert _findings(report) == [
            (
                "skillcheck.spec.skill-name-valid-slug",
                "warning",
                "MEDIUM",
                "skills/MySkill/SKILL.md",
            )
        ]

    def test_a_seeded_marker_skill_the_database_knows_is_flagged(
        self, tree, tmp_path, monkeypatch
    ):
        fake = FakeSkillcheck(_affected(tree), exit_code=1)
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert _findings(report) == [
            (
                "skillcheck.database-verdict",
                "error",
                "CRITICAL",
                "skills/marker-skill/SKILL.md",
            )
        ]
        props = report.get_all_results()[0].properties
        assert props.skill_name == "marker-skill"
        assert props.risk_score == 91.5

    def test_a_marker_in_a_skill_is_not_what_the_tool_flags(
        self, tree, tmp_path, monkeypatch
    ):
        """Must-not-flag: the same seeded skill, database answer ``unknown``.

        skillcheck matches no content pattern. The marker file exists on disk
        and the tool, as captured, reports the skill without a verdict.
        """
        assert MARKER in (tree / "skills" / "marker-skill" / "SKILL.md").read_text()
        document = _affected(tree)
        skill = document["agents"][0]["skills"][0]
        for key in ("riskScore", "topSeverity", "summary", "purl"):
            skill.pop(key)
        skill["status"] = "unknown"
        fake = FakeSkillcheck(document)
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert report.get_all_results() == []

    def test_findings_are_relative_to_the_scanned_directory(self):
        sarif, skills, dropped = convert_report(_document("spec_violation.json"))
        uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"]
        assert uri == "skills/MySkill/SKILL.md"
        assert (skills, dropped) == (1, 0)

    def test_a_path_outside_the_scanned_directory_is_not_a_location(self):
        document = _document("spec_violation.json")
        document["agents"][0]["skills"][0]["source"] = "/elsewhere/SKILL.md"
        sarif, _, _ = convert_report(document)
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "."

    def test_agents_from_the_home_directory_are_dropped(self):
        """The capture is a run with a home that held a Claude Code skill."""
        sarif, skills, dropped = convert_report(_document("home_leak.json"))
        assert sarif["runs"][0]["results"] == []
        assert (skills, dropped) == (1, 1)

    def test_a_dropped_home_agent_is_warned_about(self, tree, tmp_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        logged: List[str] = []
        monkeypatch.setattr(
            scanner, "_plugin_log", lambda msg, *a, **k: logged.append(str(msg))
        )
        _run(scanner, FakeSkillcheck(_document("home_leak.json")), monkeypatch)
        assert any("not the scanned project" in m for m in logged)

    @pytest.mark.parametrize(
        ("top", "expected"),
        [
            ("critical", ("CRITICAL", "error")),
            ("high", ("HIGH", "error")),
            ("medium", ("MEDIUM", "warning")),
            ("low", ("LOW", "note")),
            (None, ("HIGH", "error")),
            ("catastrophic", ("HIGH", "error")),
        ],
    )
    def test_database_verdict_severity_mapping(self, top, expected):
        document = _document("affected_schema_derived.json")
        skill = document["agents"][0]["skills"][0]
        document["agents"][0]["skills"] = [skill]
        if top is None:
            skill.pop("topSeverity")
        else:
            skill["topSeverity"] = top
        sarif, _, _ = convert_report(document)
        result = sarif["runs"][0]["results"][0]
        assert (result["properties"]["issue_severity"], result["level"]) == expected

    @pytest.mark.parametrize(
        ("tool", "expected"),
        [
            ("critical", ("MEDIUM", "warning")),
            ("high", ("MEDIUM", "warning")),
            ("medium", ("LOW", "note")),
            ("low", ("INFO", "none")),
            ("surprising", ("HIGH", "error")),
        ],
    )
    def test_specification_severity_mapping(self, tool, expected):
        document = _document("spec_violation.json")
        document["agents"][0]["skills"][0]["spec"][0]["severity"] = tool
        sarif, _, _ = convert_report(document)
        result = sarif["runs"][0]["results"][0]
        assert (result["properties"]["issue_severity"], result["level"]) == expected

    def test_a_clean_or_unknown_verdict_is_not_a_finding(self):
        document = _document("affected_schema_derived.json")
        results = convert_report(document)[0]["runs"][0]["results"]
        # Three skills in the document; the clean one is the only one left out.
        assert [r["properties"]["skill_name"] for r in results] == [
            "synthetic-affected-skill",
            "synthetic-medium-skill",
        ]

    def test_a_verdict_at_high_severity_counts_even_when_status_is_not_affected(self):
        document = _document("affected_schema_derived.json")
        skill = document["agents"][0]["skills"][2]
        skill.update({"status": "queued", "topSeverity": "high"})
        document["agents"][0]["skills"] = [skill]
        results = convert_report(document)[0]["runs"][0]["results"]
        assert len(results) == 1

    def test_instruction_files_are_inventory_not_findings(self):
        document = _document("benign.json")
        document["agents"][0]["rules"] = [
            {"name": "AGENTS.md", "source": "/x/AGENTS.md", "hash": "ab"}
        ]
        assert convert_report(document)[0]["runs"][0]["results"] == []

    def test_the_sarif_round_trips(self):
        sarif, _, _ = convert_report(_document("affected_schema_derived.json"))
        report = SarifReport.model_validate(sarif)
        again = SarifReport.model_validate(
            json.loads(report.model_dump_json(by_alias=True, exclude_none=True))
        )
        assert len(again.get_all_results()) == 2

    def test_the_fingerprint_survives_an_edit_of_the_skill(self):
        a = _document("affected_schema_derived.json")
        b = copy.deepcopy(a)
        b["agents"][0]["skills"][0]["hash"] = "f" * 64
        key = lambda d: convert_report(d)[0]["runs"][0]["results"][0][  # noqa: E731
            "partialFingerprints"
        ]
        assert key(a) == key(b)

    def test_a_target_with_no_skill_reports_that_nothing_was_scanned(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeSkillcheck({"agents": None}), monkeypatch)
        assert report.get_all_results() == []
        assert scanner._nothing_scanned_reason == (
            "skillcheck found no agent skill in the target"
        )


class TestExitStatus:
    def test_one_with_a_blocking_verdict_is_a_success(
        self, tree, tmp_path, monkeypatch
    ):
        fake = FakeSkillcheck(_affected(tree, severity="high"), exit_code=1)
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert len(report.get_all_results()) == 1

    def test_one_with_a_report_that_holds_no_blocking_verdict_fails(
        self, tree, tmp_path, monkeypatch
    ):
        fake = FakeSkillcheck(_document("benign.json"), exit_code=1)
        with pytest.raises(ScannerError, match="without printing a critical or high"):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)

    def test_one_with_nothing_on_stdout_is_the_failure_it_is(
        self, tree, tmp_path, monkeypatch
    ):
        """``--project`` at a path that is not a directory: exit 1, empty stdout."""
        fake = FakeSkillcheck(stdout="", exit_code=1)
        with pytest.raises(ScannerError, match="did not print a JSON report"):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)

    @pytest.mark.parametrize("code", [2, 126, 137])
    def test_any_other_code_fails_even_with_a_report_on_stdout(
        self, tree, tmp_path, monkeypatch, code
    ):
        fake = FakeSkillcheck(_affected(tree), exit_code=code)
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)

    def test_a_previous_runs_report_is_not_read_again(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeSkillcheck(_affected(tree), exit_code=1), monkeypatch)
        with pytest.raises(ScannerError, match="did not print a JSON report"):
            _run(scanner, FakeSkillcheck(stdout="", exit_code=0), monkeypatch)

    @pytest.mark.parametrize(
        "stdout",
        [
            "",
            "not json",
            "[]",
            "{}",
            '{"agents": 5}',
            '{"agents": [{"platform": 1, "configPath": "/x"}]}',
            '{"agents": [{"platform": "Project"}]}',
            '{"agents": [{"platform": "Project", "configPath": "/x", "skills": 3}]}',
            (
                '{"agents": [{"platform": "Project", "configPath": "/x", '
                '"skills": [{"hash": "ab"}]}]}'
            ),
        ],
    )
    def test_output_that_is_not_the_report_fails_closed(
        self, tree, tmp_path, monkeypatch, stdout
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakeSkillcheck(stdout=stdout, exit_code=0),
                monkeypatch,
            )

    def test_the_tools_output_is_not_quoted_in_the_error(self):
        with pytest.raises(ScannerError) as raised:
            parse_report("SECRET-TREE-TEXT is not json")
        assert "SECRET-TREE-TEXT" not in str(raised.value)

    def test_a_null_agents_member_is_an_empty_report(self):
        assert parse_report('{"agents": null}')["agents"] == []


class TestNetworkAndOfflinePosture:
    def test_offline_defaults_to_false(self):
        assert SkillcheckScannerConfigOptions().offline is False

    def test_an_offline_scan_skips_the_scanner(self):
        assert SkillcheckScanner.offline_strategy is OfflineStrategy.SKIP_OFFLINE

    def test_the_sandbox_grants_a_network_and_nothing_else(self):
        required = SkillcheckScanner.sandbox_requirements
        assert required.network is True
        assert required.network_requires_grant is False
        assert not required.read_paths and not required.env_names
        assert not required.env_prefixes and not required.cache_paths

    def test_there_are_no_options_a_tree_could_set_to_hide_findings(self):
        extra = set(SkillcheckScannerConfigOptions.model_fields) - {
            "severity_threshold",
            "scan_timeout",
            "offline",
        }
        assert extra == set()


class TestInstallStory:
    def test_ash_provisions_nothing_and_never_the_pypi_namesake(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        assert scanner.use_uv_tool is False
        assert not scanner.custom_install_commands
        assert not scanner.uv_tool_install_commands
        assert not scanner.dependencies
        source = Path(sc.__file__).read_text(encoding="utf-8")
        for forbidden in ("pip install", "uv tool", "uvx", "pipx", "npx", "npm i"):
            assert forbidden not in source

    def test_the_tested_release_is_a_stable_tag_named_in_the_hint(self):
        assert sc.SKILLCHECK_TESTED_VERSION == "0.4.0"

    def test_a_missing_binary_is_reported_with_the_release_page(
        self, tree, tmp_path, monkeypatch, caplog
    ):
        monkeypatch.setattr(sc, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False

    def test_a_present_binary_passes(self, tree, tmp_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True


class TestDeclarations:
    def test_the_operational_row_agrees_with_the_class(self):
        ops = SkillcheckScanner.operational_facets
        assert ops.scanner_name == SkillcheckScannerConfig().name
        assert ops.network.offline_strategy is SkillcheckScanner.offline_strategy
        assert ops.exit_codes.success_exit_codes == tuple(
            sorted(SkillcheckScanner.success_exit_codes)
        )
        assert ops.runtime.python_only is False

    def test_the_facets_row_is_the_classes_own(self):
        assert "facets" in vars(SkillcheckScanner)
        assert "operational_facets" in vars(SkillcheckScanner)


def test_the_fixture_inputs_the_captures_were_made_over_exist():
    for name in ("benign", "spec_violation"):
        assert list((FIXTURE_REPO / name).rglob("SKILL.md"))
