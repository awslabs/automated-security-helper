# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Snyk Agent Scan scanner: conversion, discovery, argv, failure handling.

What the oracle is
------------------
The service's answers are the two documents the pinned ``snyk-agent-scan==0.7.1``
printed under ``tests/test_data/scanners/agent-scan/captured/`` (see its README: the
tool's real ``--json`` envelope, over a local stub analysis service, so the risk
values are the stub's). The scanner tests drive the real ``scan()`` over trees built
in ``tmp_path`` and replace only ``_run_subprocess``: a fake that records argv, cwd,
timeout and the files that were staged, and answers with the captured document that
matches what the staged ``SKILL.md`` holds. The marked skill is built here from the
documented marker string, never from real attack content.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules import ash_agent_scan_plugins
from automated_security_helper.plugin_modules.ash_agent_scan_plugins import (
    agent_scan_scanner as module,
)
from automated_security_helper.plugin_modules.ash_agent_scan_plugins.agent_scan_scanner import (
    AGENT_SCAN_DEFAULT_VERSION_CONSTRAINT,
    AGENT_SCAN_PARSER_VERSION,
    FAILURE_CATEGORY_TO_CODE,
    SCORE_BANDS,
    SKILL_RISK_NAMES,
    AgentScanSchemaError,
    AgentScanScanner,
    AgentScanScannerConfig,
    AgentScanScannerConfigOptions,
    convert_agent_scan_document,
    parse_agent_scan_document,
    risk_severity,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "agent-scan"
    / "captured"
)
MARKED_DOC: Dict[str, Any] = json.loads(
    (CAPTURED / "scan-skill-marked-0.7.1.json").read_text(encoding="utf-8")
)
CLEAN_DOC: Dict[str, Any] = json.loads(
    (CAPTURED / "scan-skill-clean-0.7.1.json").read_text(encoding="utf-8")
)

#: The documented detection marker the seeded skill carries (also the stub's).
MARKER = "ASH-FIXTURE-MARKER-agent-scan-mild"
MARKED_SKILL = (
    "---\nname: marked-skill\ndescription: Summarizes meeting notes.\n---\n\n"
    "# Marked skill\n\nSummarize the notes the user pastes.\n\n"
    f"<!-- {MARKER}: a documented detection marker used by ASH tests. -->\n"
)
BENIGN_SKILL = (
    "---\nname: benign-skill\ndescription: Formats a short greeting.\n---\n\n"
    "# Benign skill\n\nReply with a short friendly greeting.\n"
)
OUTSIDE_TEXT = "OUTSIDE-TEXT-THAT-MUST-NOT-BE-STAGED"

# Hand-written from the captured marked document: (rule, severity, level, line).
MARKED_EXPECTED = sorted(
    [
        ("prompt_injection_skill_instructions", "HIGH", "error", 10),
        ("suspicious_download_url", "HIGH", "error", None),
        ("malicious_code", "CRITICAL", "error", 10),
        ("secret_detection", "MEDIUM", "warning", None),
        ("third_party_content_exposure", "LOW", "note", None),
        ("unverifiable_dependencies", "LOW", "note", None),
    ],
    key=lambda row: (row[0], row[3] or 0),
)


def _level(result) -> str:
    return result.level.value if hasattr(result.level, "value") else result.level


def _rows(results) -> List[tuple]:
    rows = []
    for result in results:
        region = result.locations[0].physicalLocation.root.region
        rows.append(
            (
                result.ruleId,
                result.properties.issue_severity,
                _level(result),
                region.startLine if region else None,
            )
        )
    return sorted(rows, key=lambda row: (row[0], row[3] or 0))


def _doc(risk_indexes: Dict[str, Any], **skill: Any) -> Dict[str, Any]:
    entry = {
        "name": "a-skill",
        "files": [{"name": "SKILL.md", "type": "instruction"}],
        "risk_indexes": risk_indexes,
        **skill,
    }
    return {
        "scan_path_responses": [
            {
                "client": "/stage/0000",
                "path": "/stage",
                "server_risks": [],
                "skill_risks": [entry],
            }
        ]
    }


# --------------------------------------------------------------------------- #
# Severity bands
# --------------------------------------------------------------------------- #


class TestSeverity:
    @pytest.mark.parametrize(
        "score,severity,level",
        [
            (0, "LOW", "note"),
            (299, "LOW", "note"),
            (300, "MEDIUM", "warning"),
            (599, "MEDIUM", "warning"),
            (600, "HIGH", "error"),
            (999, "HIGH", "error"),
            (1000, "CRITICAL", "error"),
        ],
    )
    def test_the_tools_four_score_bands(self, score, severity, level):
        assert risk_severity(score) == (severity, level)

    def test_the_band_table_is_the_four_edges_of_the_pinned_printer(self):
        assert [upper for upper, _, _ in SCORE_BANDS] == [299, 599, 999, 1000]

    def test_a_score_above_the_maximum_is_refused(self):
        with pytest.raises(AgentScanSchemaError):
            risk_severity(1001)

    @pytest.mark.parametrize("score", [-1, 1001])
    def test_an_out_of_range_score_in_a_document_is_refused(self, score):
        document = _doc({"malicious_code": {"score": score, "evidence": "x"}})
        with pytest.raises(AgentScanSchemaError):
            convert_agent_scan_document(document, skill_label="s")

    def test_every_converted_result_carries_severity_and_level_that_agree(self):
        converted = convert_agent_scan_document(MARKED_DOC, skill_label="s")
        assert converted.results
        for result in converted.results:
            assert (result.properties.issue_severity, _level(result)) == risk_severity(
                result.properties.agent_scan_score
            )


# --------------------------------------------------------------------------- #
# Conversion
# --------------------------------------------------------------------------- #


class TestConversion:
    def test_the_marked_capture_is_rated_and_located(self):
        converted = convert_agent_scan_document(MARKED_DOC, skill_label="skills/marked")
        assert _rows(converted.results) == MARKED_EXPECTED
        assert converted.problems == []
        assert set(converted.rules) == {
            "prompt_injection_skill_instructions",
            "suspicious_download_url",
            "malicious_code",
            "secret_detection",
            "third_party_content_exposure",
            "unverifiable_dependencies",
        }
        uris = {
            r.locations[0].physicalLocation.root.artifactLocation.uri
            for r in converted.results
        }
        assert uris == {"skills/marked/SKILL.md"}

    def test_negative_control_the_clean_capture_has_no_findings(self):
        converted = convert_agent_scan_document(CLEAN_DOC, skill_label="skills/clean")
        assert (converted.results, converted.rules, converted.problems) == ([], {}, [])

    def test_a_changed_score_changes_the_rows(self):
        mutated = json.loads(json.dumps(MARKED_DOC))
        mutated["scan_path_responses"][0]["skill_risks"][0]["risk_indexes"][
            "secret_detection"
        ]["score"] = 650
        converted = convert_agent_scan_document(mutated, skill_label="skills/marked")
        assert _rows(converted.results) != MARKED_EXPECTED

    def test_the_region_end_line_and_url_lists_are_carried(self):
        document = _doc(
            {
                "suspicious_download_url": {
                    "score": 700,
                    "evidence": "e",
                    "malicious_urls": ["https://example.invalid/a"],
                    "locations": [
                        {
                            "start": {"path": "scripts/run.sh", "line": 3},
                            "end": {"path": "scripts/run.sh", "line": 5},
                        }
                    ],
                }
            }
        )
        (result,) = convert_agent_scan_document(document, skill_label="").results
        physical = result.locations[0].physicalLocation.root
        assert physical.artifactLocation.uri == "scripts/run.sh"
        assert (physical.region.startLine, physical.region.endLine) == (3, 5)
        assert result.properties.malicious_urls == ["https://example.invalid/a"]

    def test_a_risk_with_no_location_sits_on_the_skill_file(self):
        document = _doc({"secret_detection": {"score": 400, "evidence": "e"}})
        (result,) = convert_agent_scan_document(document, skill_label="a/b").results
        physical = result.locations[0].physicalLocation.root
        assert physical.artifactLocation.uri == "a/b/SKILL.md"
        assert physical.region is None

    def test_fingerprints_are_unique_and_ignore_the_services_wording(self):
        converted = convert_agent_scan_document(MARKED_DOC, skill_label="s")
        prints = [r.partialFingerprints["agent-scan/v1"] for r in converted.results]
        assert len(prints) == len(set(prints))
        reworded = json.loads(json.dumps(MARKED_DOC))
        for risk in reworded["scan_path_responses"][0]["skill_risks"][0][
            "risk_indexes"
        ].values():
            risk["evidence"] = "different words"
        again = convert_agent_scan_document(reworded, skill_label="s")
        assert [r.partialFingerprints["agent-scan/v1"] for r in again.results] == prints

    def test_every_risk_name_the_models_know_has_a_display_name(self):
        from automated_security_helper.plugin_modules.ash_agent_scan_plugins.agent_scan_scanner import (
            _RiskIndexes,
        )

        assert set(_RiskIndexes.model_fields) == set(SKILL_RISK_NAMES)


class TestSchemaIsLocked:
    """Fail closed on anything the 0.7.1 models do not describe."""

    def test_the_parser_is_locked_to_the_pinned_release(self):
        assert AGENT_SCAN_PARSER_VERSION == "0.7.1"
        assert AGENT_SCAN_DEFAULT_VERSION_CONSTRAINT == "==0.7.1"

    def test_the_captures_parse(self):
        assert parse_agent_scan_document(MARKED_DOC)
        assert parse_agent_scan_document(CLEAN_DOC)

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda d: d.update({"version": "2"}),
            lambda d: d["scan_path_responses"][0].update({"issues": []}),
            lambda d: d["scan_path_responses"][0]["skill_risks"][0].update({"x": 1}),
            lambda d: d["scan_path_responses"][0]["skill_risks"][0][
                "risk_indexes"
            ].update({"a_future_risk": {"score": 1, "evidence": "e"}}),
            lambda d: d["scan_path_responses"][0]["skill_risks"][0]["risk_indexes"][
                "malicious_code"
            ].update({"severity": "high"}),
            lambda d: d["scan_path_responses"][0]["skill_risks"][0]["risk_indexes"][
                "malicious_code"
            ].update({"score": "1000"}),
            lambda d: d["scan_path_responses"][0]["skill_risks"][0]["risk_indexes"][
                "malicious_code"
            ].update({"score": True}),
            lambda d: d["scan_path_responses"][0]["skill_risks"][0]["risk_indexes"][
                "malicious_code"
            ].pop("evidence"),
            lambda d: d["scan_path_responses"][0]["skill_risks"][0]["files"][0].update(
                {"type": "binary"}
            ),
            lambda d: d["scan_path_responses"][0]["skill_risks"][0].update(
                {"error": {"category": "a_new_category"}}
            ),
            lambda d: d["scan_path_responses"][0].update(
                {"server_risks": [{"name": "srv"}]}
            ),
            lambda d: d["scan_path_responses"][0]["skill_risks"][0]["risk_indexes"][
                "malicious_code"
            ]["locations"][0]["start"].update({"path": "/etc/passwd"}),
            lambda d: d["scan_path_responses"][0]["skill_risks"][0]["risk_indexes"][
                "malicious_code"
            ]["locations"][0]["start"].update({"path": "../escape"}),
            lambda d: d["scan_path_responses"][0]["skill_risks"][0]["risk_indexes"][
                "secret_detection"
            ].update({"malicious_urls": ["https://example.invalid/x"]}),
            lambda d: d["scan_path_responses"][0]["skill_risks"][0]["risk_indexes"][
                "suspicious_download_url"
            ].update({"unverifiable_urls": ["https://example.invalid/x"]}),
        ],
        ids=[
            "top-level key",
            "path key",
            "skill key",
            "unknown risk name",
            "unknown risk key",
            "score as string",
            "score as bool",
            "missing evidence",
            "unknown file type",
            "unknown error category",
            "server risks present",
            "absolute location path",
            "dotdot location path",
            "malicious urls on the wrong risk",
            "unverifiable urls on the wrong risk",
        ],
    )
    def test_an_unrecognized_document_is_refused(self, mutate):
        document = json.loads(json.dumps(MARKED_DOC))
        mutate(document)
        with pytest.raises(AgentScanSchemaError):
            convert_agent_scan_document(document, skill_label="s")

    @pytest.mark.parametrize(
        "document", [[], "text", None, 3, {}, {"scan_path_responses": "x"}]
    )
    def test_a_document_that_is_not_the_object_is_refused(self, document):
        with pytest.raises(AgentScanSchemaError):
            parse_agent_scan_document(document)

    def test_the_refusal_names_where_and_never_the_value(self):
        document = _doc(
            {"malicious_code": {"score": "VALUE-FROM-THE-SKILL", "evidence": "e"}}
        )
        with pytest.raises(AgentScanSchemaError) as raised:
            parse_agent_scan_document(document)
        assert "malicious_code" in str(raised.value)
        assert "VALUE-FROM-THE-SKILL" not in str(raised.value)


class TestCompleteness:
    def test_no_skill_analyzed_is_not_a_clean_answer(self):
        document = _doc({})
        document["scan_path_responses"][0]["skill_risks"] = []
        converted = convert_agent_scan_document(document, skill_label="s")
        assert converted.results == []
        assert any("not 1" in p for p in converted.problems)

    def test_two_skills_in_one_answer_is_not_the_answer_asked_for(self):
        document = _doc({})
        skills = document["scan_path_responses"][0]["skill_risks"]
        skills.append(dict(skills[0]))
        converted = convert_agent_scan_document(document, skill_label="s")
        assert any("not 1" in p for p in converted.problems)

    def test_two_paths_in_one_answer_is_not_the_answer_asked_for(self):
        document = _doc({})
        document["scan_path_responses"].append(document["scan_path_responses"][0])
        converted = convert_agent_scan_document(document, skill_label="s")
        assert any("not 1" in p for p in converted.problems)

    @pytest.mark.parametrize(
        "category,code",
        [
            ("analysis_error", "X007"),
            ("skill_scan_error", "X002"),
            ("server_http_error", "X006"),
        ],
    )
    def test_a_failure_the_tool_reports_is_a_problem_naming_its_code_not_its_text(
        self, category, code
    ):
        document = _doc(
            {},
            error={
                "message": "TEXT-THE-TOOL-QUOTED-FROM-A-FILE",
                "is_failure": True,
                "category": category,
            },
        )
        converted = convert_agent_scan_document(document, skill_label="s")
        assert [code in p for p in converted.problems] == [True]
        assert all("TEXT-THE-TOOL-QUOTED" not in p for p in converted.problems)

    def test_an_error_the_tool_says_is_not_a_failure_is_not_one(self):
        document = _doc({}, error={"is_failure": False, "category": "file_not_found"})
        assert convert_agent_scan_document(document, skill_label="s").problems == []

    def test_an_error_with_no_flag_counts_as_a_failure(self):
        document = _doc({}, error={"category": "skill_scan_error"})
        assert convert_agent_scan_document(document, skill_label="s").problems

    def test_the_code_table_is_the_tools(self):
        assert FAILURE_CATEGORY_TO_CODE["analysis_error"] == "X007"
        assert FAILURE_CATEGORY_TO_CODE[None] == "X008"


# --------------------------------------------------------------------------- #
# Config and class declarations
# --------------------------------------------------------------------------- #


class TestCommunityPlugin:
    def test_on_by_default_once_its_module_is_listed(self):
        assert AgentScanScannerConfig().enabled is True

    def test_the_module_exports_the_scanner(self):
        assert ash_agent_scan_plugins.ASH_SCANNERS == [AgentScanScanner]
        assert ash_agent_scan_plugins.ASH_REPORTERS == []

    def test_declarations(self):
        assert AgentScanScannerConfig().name == "agent-scan"
        assert AgentScanScanner.python_only is True
        assert AgentScanScanner.offline_strategy is OfflineStrategy.SKIP_OFFLINE
        assert AgentScanScanner.success_exit_codes == {0}
        assert AgentScanScanner.sandbox_requirements == SandboxRequirements(
            network=True, env_names=("SNYK_TOKEN",)
        )

    def test_the_options_hold_no_pointer_a_scanned_tree_could_aim(self):
        """No analysis URL, config file, push key or control server: nothing the
        scanned repository writes can choose where skill content is sent, so no
        operator-only option rows are owed."""
        own = set(AgentScanScannerConfigOptions.model_fields) - set(
            ScannerOptionsBase.model_fields
        )
        assert own == {"tool_version"}

    def test_the_declared_facets_are_the_scanners_own(self):
        assert "facets" in vars(AgentScanScanner)
        assert "operational_facets" in vars(AgentScanScanner)
        assert AgentScanScanner.operational_facets.scanner_name == "agent-scan"


# --------------------------------------------------------------------------- #
# The scanner, with snyk-agent-scan replaced by a fake
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _token_and_uv(monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setenv("SNYK_TOKEN", "snyk-token-for-tests")
    monkeypatch.setattr(module, "find_uv_or_none", lambda: "/opt/uv/bin/uv")


def _tree(tmp_path: Path) -> Path:
    repo = tmp_path / "src"
    (repo / "skills" / "marked" / "scripts").mkdir(parents=True)
    (repo / "skills" / "benign").mkdir(parents=True)
    (repo / "skills" / "benign" / "node_modules" / "x").mkdir(parents=True)
    (repo / "docs").mkdir()
    (repo / "skills" / "marked" / "SKILL.md").write_text(MARKED_SKILL)
    (repo / "skills" / "marked" / "scripts" / "run.sh").write_text("echo hello\n")
    (repo / "skills" / "benign" / "SKILL.md").write_text(BENIGN_SKILL)
    (repo / "skills" / "benign" / "node_modules" / "x" / "SKILL.md").write_text(
        MARKED_SKILL
    )
    (repo / "docs" / "skill.md").write_text(MARKED_SKILL)
    (repo / "README.md").write_text("# demo\n")
    return repo


def _scanner(repo: Path, tmp_path: Path, **options) -> AgentScanScanner:
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    context = PluginContext(
        source_dir=repo,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    return AgentScanScanner(
        context=context,
        config=AgentScanScannerConfig(
            enabled=True, options=AgentScanScannerConfigOptions(**options)
        ),
    )


class FakeAgentScan:
    """Stands in for ``_run_subprocess``: prints the captured document that matches
    what the staged ``SKILL.md`` holds, as the real tool prints its answer."""

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []
        #: staged directory name ("0000", ...) -> spec. A spec is {"returncode",
        #: "stdout" (str verbatim, or a dict dumped as JSON), "stderr", "timed_out"}.
        self.specs: Dict[str, Dict[str, Any]] = {}

    def __call__(
        self,
        scanner,
        command,
        results_dir=None,
        stdout_preference="write",
        stderr_preference="write",
        cwd=None,
        env=None,
        timeout=None,
    ):
        staged = Path(command[-1])
        skill_md = staged / "SKILL.md"
        marked = skill_md.is_file() and MARKER in skill_md.read_text()
        staged_files = sorted(
            p.relative_to(staged).as_posix() for p in staged.rglob("*") if p.is_file()
        )
        self.calls.append(
            {
                "command": list(command),
                "cwd": Path(cwd) if cwd else None,
                "timeout": timeout,
                "env": env,
                "staged_name": staged.name,
                "staged_files": staged_files,
                "staged_links": [p.name for p in staged.rglob("*") if p.is_symlink()],
                "log_existed": (
                    Path(results_dir) / "AgentScanScanner.stdout.log"
                ).exists(),
            }
        )
        spec = self.specs.get(
            staged.name,
            {"returncode": 0, "stdout": MARKED_DOC if marked else CLEAN_DOC},
        )
        body = spec.get("stdout")
        if body is not None:
            (Path(results_dir) / "AgentScanScanner.stdout.log").write_text(
                body if isinstance(body, str) else json.dumps(body)
            )
        if spec.get("stderr"):
            (Path(results_dir) / "AgentScanScanner.stderr.log").write_text(
                spec["stderr"]
            )
        response: Dict[str, Any] = {"returncode": spec.get("returncode", 0)}
        if spec.get("timed_out"):
            response["timed_out"] = True
        scanner.exit_code = max(scanner.exit_code, response["returncode"])
        return response


@pytest.fixture
def fake(monkeypatch):
    fake = FakeAgentScan()
    monkeypatch.setattr(
        AgentScanScanner, "_run_subprocess", lambda self, **kw: fake(self, **kw)
    )
    return fake


class TestInvocation:
    def test_one_run_per_skill_with_every_fixed_flag_and_the_path_after_dashes(
        self, tmp_path, fake
    ):
        repo = _tree(tmp_path)
        scanner = _scanner(repo, tmp_path)
        scanner.scan(target=repo, target_type="source")

        # node_modules and a lowercase skill.md are not skill roots.
        assert [c["staged_name"] for c in fake.calls] == ["0000", "0001"]
        for call in fake.calls:
            command = call["command"]
            storage = command[command.index("--") - 1]
            assert command[:9] == [
                "/opt/uv/bin/uv",
                "tool",
                "run",
                "--from",
                "snyk-agent-scan==0.7.1",
                "snyk-agent-scan",
                "scan",
                "--json",
                "--skills",
            ]
            assert storage.startswith("--storage-file=")
            assert command[-2] == "--"
            assert command[-1] != str(repo)
            # The storage file and every invocation sit under ASH's results dir.
            assert call["cwd"].is_relative_to(tmp_path / "out")
            assert storage.removeprefix("--storage-file=").startswith(str(call["cwd"]))
            assert len(command) == 12

    @pytest.mark.parametrize(
        "forbidden",
        [
            "--dangerously-run-mcp-servers",
            "--ci",
            "--analysis-url",
            "--control-server",
            "--control-identifier",
            "--push-key",
            "--machine-id",
            "--config-file",
            "--verification-H",
            "--skip-ssl-verify",
            "--scan-all-users",
            "--mcp-oauth-tokens-path",
            "--no-skills",
            "--ignore-risks",
            "--ignore-failure-codes",
        ],
    )
    def test_flags_that_start_servers_aim_the_upload_or_read_elsewhere_are_never_passed(
        self, tmp_path, fake, forbidden
    ):
        repo = _tree(tmp_path)
        _scanner(repo, tmp_path).scan(target=repo, target_type="source")
        assert fake.calls
        for call in fake.calls:
            assert not any(
                c == forbidden or c.startswith(f"{forbidden}=") for c in call["command"]
            )

    def test_the_install_name_is_the_snyk_package_never_the_redirect_name(
        self, tmp_path, fake
    ):
        repo = _tree(tmp_path)
        scanner = _scanner(repo, tmp_path)
        scanner.scan(target=repo, target_type="source")
        for call in fake.calls:
            assert "mcp-scan" not in " ".join(call["command"])

    def test_the_skill_is_staged_as_a_copy_that_holds_only_scanned_files(
        self, tmp_path, fake
    ):
        repo = _tree(tmp_path)
        _scanner(repo, tmp_path).scan(target=repo, target_type="source")
        by_name = {c["staged_name"]: c["staged_files"] for c in fake.calls}
        assert by_name["0000"] == ["SKILL.md"]
        assert by_name["0001"] == ["SKILL.md", "scripts/run.sh"]

    def test_a_link_in_the_tree_is_never_staged(self, tmp_path, fake):
        repo = _tree(tmp_path)
        outside = tmp_path / "outside.txt"
        outside.write_text(OUTSIDE_TEXT)
        outside_dir = tmp_path / "outside_dir"
        outside_dir.mkdir()
        (outside_dir / "SKILL.md").write_text(MARKED_SKILL)
        (outside_dir / "notes.txt").write_text(OUTSIDE_TEXT)
        (repo / "skills" / "benign" / "leak.txt").symlink_to(outside)
        (repo / "skills" / "benign" / "linked-dir").symlink_to(outside_dir)
        _scanner(repo, tmp_path).scan(target=repo, target_type="source")
        # Two roots only: the linked directory's SKILL.md is not a third.
        assert [c["staged_name"] for c in fake.calls] == ["0000", "0001"]
        benign = next(c for c in fake.calls if c["staged_name"] == "0000")
        assert benign["staged_files"] == ["SKILL.md"]
        assert benign["staged_links"] == []

    def test_a_nested_skill_is_scanned_on_its_own_and_not_staged_into_its_parent(
        self, tmp_path, fake
    ):
        repo = tmp_path / "src"
        (repo / "skills" / "outer" / "inner").mkdir(parents=True)
        (repo / "skills" / "outer" / "SKILL.md").write_text(BENIGN_SKILL)
        (repo / "skills" / "outer" / "inner" / "SKILL.md").write_text(MARKED_SKILL)
        report = _scanner(repo, tmp_path).scan(target=repo, target_type="source")
        assert [c["staged_files"] for c in fake.calls] == [["SKILL.md"], ["SKILL.md"]]
        assert isinstance(report, SarifReport)
        uris = {
            r.locations[0].physicalLocation.root.artifactLocation.uri
            for r in report.runs[0].results
        }
        assert uris == {"skills/outer/inner/SKILL.md"}

    def test_the_source_directory_itself_may_be_the_skill(self, tmp_path, fake):
        repo = tmp_path / "src"
        repo.mkdir()
        (repo / "SKILL.md").write_text(MARKED_SKILL)
        report = _scanner(repo, tmp_path).scan(target=repo, target_type="source")
        assert isinstance(report, SarifReport)
        uris = {
            r.locations[0].physicalLocation.root.artifactLocation.uri
            for r in report.runs[0].results
        }
        assert uris == {"SKILL.md"}

    def test_global_ignore_paths_leave_a_skill_out(self, tmp_path, fake):
        repo = _tree(tmp_path)
        _scanner(repo, tmp_path).scan(
            target=repo,
            target_type="source",
            global_ignore_paths=[
                IgnorePathWithReason(path="skills/marked/**", reason="not shipped")
            ],
        )
        assert [c["staged_files"] for c in fake.calls] == [["SKILL.md"]]

    def test_a_tree_with_no_skills_attempts_nothing(self, tmp_path, fake):
        repo = tmp_path / "src"
        repo.mkdir()
        (repo / "main.py").write_text("print(1)\n")
        scanner = _scanner(repo, tmp_path)
        report = scanner.scan(target=repo, target_type="source")
        assert fake.calls == []
        assert scanner.targets_attempted == 0
        assert isinstance(report, SarifReport) and report.runs[0].results == []

    def test_the_staging_tree_is_removed_after_the_scan(self, tmp_path, fake):
        repo = _tree(tmp_path)
        _scanner(repo, tmp_path).scan(target=repo, target_type="source")
        for call in fake.calls:
            assert not Path(call["command"][-1]).exists()


class TestReport:
    def test_the_marked_skill_is_flagged_and_the_benign_skill_is_not(
        self, tmp_path, fake
    ):
        repo = _tree(tmp_path)
        scanner = _scanner(repo, tmp_path)
        report = scanner.scan(target=repo, target_type="source")
        assert isinstance(report, SarifReport)
        assert _rows(report.runs[0].results) == MARKED_EXPECTED
        uris = {
            r.locations[0].physicalLocation.root.artifactLocation.uri
            for r in report.runs[0].results
        }
        assert uris == {"skills/marked/SKILL.md"}
        assert scanner.targets_attempted == 2 and scanner.targets_failed == 0

    def test_negative_control_a_tree_of_benign_skills_is_clean(self, tmp_path, fake):
        repo = tmp_path / "src"
        (repo / "skills" / "a").mkdir(parents=True)
        (repo / "skills" / "a" / "SKILL.md").write_text(BENIGN_SKILL)
        report = _scanner(repo, tmp_path).scan(target=repo, target_type="source")
        assert isinstance(report, SarifReport)
        assert report.runs[0].results == []
        assert len(fake.calls) == 1

    def test_the_driver_names_the_pinned_version(self, tmp_path, fake):
        repo = _tree(tmp_path)
        report = _scanner(repo, tmp_path).scan(target=repo, target_type="source")
        assert isinstance(report, SarifReport)
        assert report.runs[0].tool.driver.version == "0.7.1"

    def test_the_sarif_file_is_written_and_round_trips(self, tmp_path, fake):
        repo = _tree(tmp_path)
        report = _scanner(repo, tmp_path).scan(target=repo, target_type="source")
        assert isinstance(report, SarifReport)
        written = list((tmp_path / "out").rglob("agent-scan.sarif"))
        assert len(written) == 1
        again = SarifReport.model_validate_json(written[0].read_text())
        assert len(again.runs[0].results) == len(report.runs[0].results) == 6


class TestExitStatus:
    def test_exit_0_with_the_document_succeeds(self, tmp_path, fake):
        repo = _tree(tmp_path)
        report = _scanner(repo, tmp_path).scan(target=repo, target_type="source")
        assert isinstance(report, SarifReport)

    def test_exit_1_with_nothing_on_stdout_fails_and_does_not_quote_stderr(
        self, tmp_path, fake
    ):
        repo = _tree(tmp_path)
        fake.specs["0001"] = {
            "returncode": 1,
            "stdout": None,
            "stderr": "Traceback: SECRET-LINE-FROM-THE-SKILL",
        }
        scanner = _scanner(repo, tmp_path)
        with pytest.raises(ScannerError) as raised:
            scanner.scan(target=repo, target_type="source")
        message = str(raised.value)
        assert "exited 1" in message and "AgentScanScanner.stderr.log" in message
        assert "SNYK_TOKEN" in message
        assert "SECRET-LINE-FROM-THE-SKILL" not in message
        assert all("SECRET-LINE-FROM-THE-SKILL" not in e for e in scanner.errors)

    @pytest.mark.parametrize("code", [1, 2, 126, 137])
    def test_any_other_code_fails_even_with_the_document_on_disk(
        self, tmp_path, fake, code
    ):
        repo = _tree(tmp_path)
        for name in ("0000", "0001"):
            fake.specs[name] = {"returncode": code, "stdout": MARKED_DOC}
        with pytest.raises(ScannerError, match=f"exited {code}"):
            _scanner(repo, tmp_path).scan(target=repo, target_type="source")

    def test_exit_0_with_an_empty_stdout_fails(self, tmp_path, fake):
        repo = _tree(tmp_path)
        fake.specs["0000"] = {"returncode": 0, "stdout": ""}
        with pytest.raises(ScannerError, match="printed no result"):
            _scanner(repo, tmp_path).scan(target=repo, target_type="source")

    def test_a_log_left_by_an_earlier_run_is_removed_first(self, tmp_path, fake):
        repo = _tree(tmp_path)
        scanner = _scanner(repo, tmp_path)
        scanner.scan(target=repo, target_type="source")
        scanner.scan(target=repo, target_type="source")
        assert [c["log_existed"] for c in fake.calls] == [False] * len(fake.calls)

    def test_a_failure_in_one_skill_keeps_the_findings_of_the_others(
        self, tmp_path, fake
    ):
        repo = _tree(tmp_path)
        fake.specs["0000"] = {"returncode": 2, "stdout": None}
        scanner = _scanner(repo, tmp_path)
        with pytest.raises(ScannerError, match="1 of 2 skill"):
            scanner.scan(target=repo, target_type="source")
        written = list((tmp_path / "out").rglob("agent-scan.sarif"))
        assert len(written) == 1
        kept = SarifReport.model_validate_json(written[0].read_text())
        assert _rows(kept.runs[0].results) == MARKED_EXPECTED

    def test_a_skill_the_tool_reports_failed_makes_the_run_not_clean(
        self, tmp_path, fake
    ):
        repo = _tree(tmp_path)
        failed = json.loads(json.dumps(CLEAN_DOC))
        failed["scan_path_responses"][0]["skill_risks"][0]["error"] = {
            "message": "MESSAGE-FROM-THE-TOOL",
            "is_failure": True,
            "category": "analysis_error",
        }
        fake.specs["0000"] = {"returncode": 0, "stdout": failed}
        with pytest.raises(ScannerError, match="X007") as raised:
            _scanner(repo, tmp_path).scan(target=repo, target_type="source")
        assert "MESSAGE-FROM-THE-TOOL" not in str(raised.value)


class TestTimeout:
    def test_the_scan_timeout_reaches_the_subprocess(self, tmp_path, fake):
        repo = _tree(tmp_path)
        _scanner(repo, tmp_path, scan_timeout=77).scan(
            target=repo, target_type="source"
        )
        assert {c["timeout"] for c in fake.calls} == {77.0}

    def test_a_timeout_fails_the_scan_and_says_so(self, tmp_path, fake):
        repo = _tree(tmp_path)
        fake.specs["0000"] = {"returncode": 124, "stdout": None, "timed_out": True}
        with pytest.raises(ScannerError, match="timed out after 5.0s"):
            _scanner(repo, tmp_path, scan_timeout=5).scan(
                target=repo, target_type="source"
            )


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "body,fragment",
        [
            ("not json at all", "not JSON"),
            ("{", "not JSON"),
            ("[]", "cannot read"),
            ('{"scan_path_responses": "x"}', "cannot read"),
            ('{"scan_path_responses": [], "version": "2"}', "cannot read"),
            (
                '{"scan_path_responses": [{"path": "p", "issues": []}]}',
                "cannot read",
            ),
        ],
    )
    def test_an_unreadable_document_fails_the_scan(
        self, tmp_path, fake, body, fragment
    ):
        repo = tmp_path / "src"
        (repo / "s").mkdir(parents=True)
        (repo / "s" / "SKILL.md").write_text(BENIGN_SKILL)
        fake.specs["0000"] = {"returncode": 0, "stdout": body}
        with pytest.raises(ScannerError, match=fragment):
            _scanner(repo, tmp_path).scan(target=repo, target_type="source")

    def test_a_document_from_another_schema_is_a_failed_skill_not_a_clean_one(
        self, tmp_path, fake
    ):
        """The 0.5-style shape (issue codes), which a floating install could print."""
        repo = tmp_path / "src"
        (repo / "s").mkdir(parents=True)
        (repo / "s" / "SKILL.md").write_text(BENIGN_SKILL)
        fake.specs["0000"] = {
            "returncode": 0,
            "stdout": {
                "/stage": {
                    "client": "x",
                    "path": "/stage",
                    "servers": [],
                    "issues": [{"code": "E001", "message": "m"}],
                }
            },
        }
        scanner = _scanner(repo, tmp_path)
        with pytest.raises(ScannerError, match="cannot read"):
            scanner.scan(target=repo, target_type="source")
        assert scanner.targets_failed == 1


class TestDependencyCheck:
    def test_with_a_token_and_uv_the_scanner_is_available_at_the_pinned_version(
        self, tmp_path
    ):
        repo = _tree(tmp_path)
        scanner = _scanner(repo, tmp_path)
        assert scanner.validate_plugin_dependencies() is True
        assert scanner.dependencies_satisfied is True
        assert scanner.tool_version == "0.7.1"

    def test_a_range_override_leaves_the_version_unnamed(self, tmp_path):
        repo = _tree(tmp_path)
        scanner = _scanner(repo, tmp_path, tool_version=">=0.7,<0.8")
        assert scanner.validate_plugin_dependencies() is True
        assert scanner.tool_version is None

    def test_without_a_token_it_is_unavailable_and_names_the_variable_only(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.delenv("SNYK_TOKEN")
        repo = _tree(tmp_path)
        scanner = _scanner(repo, tmp_path)
        assert scanner.validate_plugin_dependencies() is False
        reason = scanner.dependency_unavailable_reason
        assert "SNYK_TOKEN is not set" in reason
        assert "analysis API" in reason

    def test_a_blank_token_counts_as_no_token(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SNYK_TOKEN", "   ")
        scanner = _scanner(_tree(tmp_path), tmp_path)
        assert scanner.validate_plugin_dependencies() is False

    def test_the_token_value_is_never_in_the_reason_or_the_log(
        self, tmp_path, monkeypatch, caplog
    ):
        monkeypatch.setattr(module, "find_uv_or_none", lambda: None)
        scanner = _scanner(_tree(tmp_path), tmp_path)
        with caplog.at_level(logging.DEBUG):
            assert scanner.validate_plugin_dependencies() is False
        assert "snyk-token-for-tests" not in scanner.dependency_unavailable_reason
        assert "snyk-token-for-tests" not in caplog.text

    def test_without_uv_it_is_unavailable_and_names_the_install(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(module, "find_uv_or_none", lambda: None)
        scanner = _scanner(_tree(tmp_path), tmp_path)
        assert scanner.validate_plugin_dependencies() is False
        reason = scanner.dependency_unavailable_reason
        assert "uv tool install 'snyk-agent-scan==0.7.1'" in reason
        assert "--tool agent-scan" in reason
        assert "ash_agent_scan_plugins" in reason

    def test_offline_is_refused_with_the_reason(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASH_OFFLINE", "true")
        scanner = _scanner(_tree(tmp_path), tmp_path)
        assert scanner.validate_plugin_dependencies() is False
        assert "has no offline mode" in scanner.dependency_unavailable_reason

    def test_a_missing_token_skips_the_scan_without_running_anything(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.delenv("SNYK_TOKEN")
        repo = _tree(tmp_path)
        calls: List[Any] = []
        monkeypatch.setattr(
            AgentScanScanner, "_run_subprocess", lambda self, **kw: calls.append(kw)
        )
        assert _scanner(repo, tmp_path).scan(target=repo, target_type="source") is False
        assert calls == []

    def test_a_reason_already_recorded_is_honored(self, tmp_path):
        scanner = _scanner(_tree(tmp_path), tmp_path)
        scanner.dependency_unavailable_reason = "recorded earlier"
        assert scanner.validate_plugin_dependencies() is False

    def test_the_run_before_the_check_is_refused(self, tmp_path):
        repo = _tree(tmp_path)
        scanner = _scanner(repo, tmp_path)
        with pytest.raises(ScannerError, match="before its dependency check"):
            scanner._argv(tmp_path, tmp_path / "storage.json")


class TestInstall:
    def test_the_install_command_pins_the_snyk_package(self, tmp_path):
        repo = tmp_path / "src"
        repo.mkdir()
        scanner = _scanner(repo, tmp_path)
        assert scanner.uv_tool_install_commands == [
            f"uv tool install snyk-agent-scan{AGENT_SCAN_DEFAULT_VERSION_CONSTRAINT}"
        ]

    @pytest.mark.parametrize(
        "platform,arch",
        [
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
            ("windows", "amd64"),
            ("windows", "arm64"),
        ],
    )
    def test_install_commands_cover_every_platform(self, tmp_path, platform, arch):
        repo = tmp_path / "src"
        repo.mkdir()
        commands = _scanner(repo, tmp_path).get_installation_commands(platform, arch)
        assert ["uv", "tool", "install", "snyk-agent-scan==0.7.1"] in commands
        assert not any("mcp-scan" in " ".join(map(str, c)) for c in commands)

    def test_a_tool_version_option_overrides_the_default(self, tmp_path):
        repo = tmp_path / "src"
        repo.mkdir()
        scanner = _scanner(repo, tmp_path, tool_version=">=0.7,<0.8")
        assert scanner._get_tool_version_constraint() == ">=0.7,<0.8"
