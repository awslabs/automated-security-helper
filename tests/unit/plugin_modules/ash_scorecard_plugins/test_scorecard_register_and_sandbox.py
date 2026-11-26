# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Scorecard: the facets declarations, the sandbox policy, the severity table over
the sample result, and the stderr and repository-name fixes.

The sample result in ``data/`` is schema-derived, not captured (see its README): it
holds a check at every band edge. The real capture is under
``tests/test_data/scanners/scorecard/captured/`` and is read by
test_scorecard_install_and_captured.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_facets import FacetState, ScannerFacets
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_scorecard_plugins import (
    scorecard_scanner as ss,
)
from automated_security_helper.plugin_modules.ash_scorecard_plugins.scorecard_scanner import (
    SCORE_BANDS,
    ScorecardScanner,
    ScorecardScannerConfig,
    convert_scorecard_result,
    normalize_repo,
)
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    build_scanner_policy,
)

pytestmark = pytest.mark.unit

DATA = Path(__file__).parent / "data"
REPO = "github.com/example-org/example-repo"


# ---------------------------------------------------------------------------
# The facets declarations
# ---------------------------------------------------------------------------


class TestDeclarations:
    def test_the_scanner_owns_both_declarations(self):
        assert isinstance(vars(ScorecardScanner).get("facets"), ScannerFacets)
        assert isinstance(
            vars(ScorecardScanner).get("operational_facets"),
            opsf.ScannerOperationalFacets,
        )

    def test_the_result_register_row_is_decided_per_facet(self):
        facets = vars(ScorecardScanner)["facets"]
        # Resource identity: a hosted repository locator is not a resource id.
        assert facets.resource_id.state is FacetState.NA
        assert facets.resource_type.state is FacetState.NA
        assert facets.rule_id.state is FacetState.MAPPED
        assert facets.severity.state is FacetState.MAPPED
        # The repository is written as the artifact URI (a suppression's path
        # matches it), so file_path is mapped; a result has no lines.
        assert facets.file_path.state is FacetState.MAPPED
        assert facets.line_range.state is FacetState.NA

    def test_the_operational_row_mirrors_the_class(self):
        row = vars(ScorecardScanner)["operational_facets"]
        assert row.scanner_name == ScorecardScannerConfig().name == "scorecard"
        assert row.network.offline_strategy is ScorecardScanner.offline_strategy
        assert ScorecardScanner.offline_strategy is OfflineStrategy.SKIP_OFFLINE
        assert row.network.offline_outcome is opsf.OfflineOutcome.NOT_RUN
        assert row.network.sandbox_network is opsf.SandboxNetwork.ONLINE
        assert ScorecardScanner.sandbox_requirements.network is True
        assert row.exit_codes.success_exit_codes == tuple(
            sorted(ScorecardScanner.success_exit_codes)
        )
        assert row.runtime.python_only is ScorecardScanner.python_only is False

    def test_tool_type_is_one_story(self, tmp_path):
        row = vars(ScorecardScanner)["operational_facets"]
        scanner = _construct(tmp_path)
        assert scanner.tool_type is row.targets.tool_type is ScannerToolType.SCA
        assert set(row.targets.kinds) & opsf.TOOL_TYPE_SERVED_BY[scanner.tool_type]

    def test_the_license_cites_the_pinned_read(self):
        row = vars(ScorecardScanner)["operational_facets"]
        citation = row.provenance.upstream_license
        assert citation.startswith("Apache-2.0 (source: the LICENSE file inside the ")
        assert "v5.7.0" in citation
        assert row.provenance.source is opsf.ProvenanceSource.USER_INSTALLED
        # The tier is the manifest's, not the register row's.
        assert "tier" not in type(row.provenance).model_fields

    def test_the_runtime_compat_row_is_declared_and_empty(self):
        row = vars(ScorecardScanner)["operational_facets"]
        assert row.runtime_compat.rows == ()

    def test_the_platforms_row_names_the_module_local_installer(self):
        row = vars(ScorecardScanner)["operational_facets"]
        assert row.platforms.provisionable == ()
        assert "scorecard_install.py" in row.platforms.note


def _construct(tmp_path) -> ScorecardScanner:
    config = get_default_config()
    AshConfig.model_rebuild()
    record_provenance(config, in_tree=[], trusted=AshConfig())
    return ScorecardScanner(
        context=PluginContext(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=ScorecardScannerConfig(enabled=True),
    )


# ---------------------------------------------------------------------------
# Sandbox requirements (checklist row 25)
# ---------------------------------------------------------------------------


@pytest.fixture
def layout(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    source = tmp_path / "src"
    source.mkdir()
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    return SimpleNamespace(source=source, output=output)


def _policy(layout, requirements, *, offline=False):
    return build_scanner_policy(
        "scorecard",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "scorecard",
        scan_target=layout.source,
        cwd=layout.source,
        offline=offline,
        network_scanners=None,
    )


class TestSandboxRequirements:
    def test_the_declaration_is_the_network_and_the_four_token_names(self):
        declared = ScorecardScanner.sandbox_requirements
        assert declared.network is True
        assert declared.network_requires_grant is False
        assert set(declared.env_names) == set(ss.TOKEN_ENV_NAMES)
        assert declared.env_prefixes == ()
        assert declared.read_paths == () and declared.cache_paths == ()

    def test_online_the_policy_grants_the_network(self, layout):
        policy = _policy(layout, ScorecardScanner.sandbox_requirements)
        assert policy.network is True

    def test_offline_the_policy_never_grants_it(self, layout):
        policy = _policy(layout, ScorecardScanner.sandbox_requirements, offline=True)
        assert policy.network is False

    @pytest.mark.parametrize("name", ss.TOKEN_ENV_NAMES)
    def test_each_token_variable_passes_through(self, layout, name):
        policy = _policy(layout, ScorecardScanner.sandbox_requirements)
        kept = policy.filter_env({name: "not-a-real-token"})
        assert kept[name] == "not-a-real-token"

    def test_a_policy_without_the_declaration_drops_the_token(self, layout):
        # The negative control: the pass-through comes from the declaration.
        policy = _policy(layout, SandboxRequirements())
        assert "GITHUB_TOKEN" not in policy.filter_env({"GITHUB_TOKEN": "x"})

    def test_a_redirecting_variable_is_not_passed(self, layout):
        policy = _policy(layout, ScorecardScanner.sandbox_requirements)
        kept = policy.filter_env({"GH_HOST": "ghe.example.invalid"})
        assert "GH_HOST" not in kept


# ---------------------------------------------------------------------------
# The severity mapping over the sample result (checklist row 18)
# ---------------------------------------------------------------------------


class TestSeverityOverTheSampleResult:
    def _document(self):
        return json.loads((DATA / "scorecard_result.json").read_text())

    def test_every_band_edge_in_the_sample_maps_as_the_table_says(self):
        report = convert_scorecard_result(self._document(), repo=REPO)
        got = {
            r.ruleId: (
                getattr(r.level, "value", r.level),
                r.properties.issue_severity,
            )
            for r in report.get_all_results()
        }
        assert got == {
            "Branch-Protection": ("error", "HIGH"),
            "Code-Review": ("warning", "MEDIUM"),
            "SAST": ("warning", "MEDIUM"),
            "Pinned-Dependencies": ("note", "LOW"),
            "Token-Permissions": ("note", "LOW"),
        }

    def test_the_table_and_the_sample_agree_on_every_band(self):
        by_score = {
            c["score"]: c["name"] for c in self._document()["checks"] if c["score"] >= 0
        }
        for low, high, severity, level in SCORE_BANDS:
            # The sample holds at least one check inside each band.
            assert any(low <= s <= high for s in by_score), (low, high)
            report = convert_scorecard_result(self._document(), repo=REPO)
            for r in report.get_all_results():
                score = r.properties.scorecard_score
                if low <= score <= high:
                    assert r.properties.issue_severity == severity
                    assert getattr(r.level, "value", r.level) == level

    def test_the_driver_carries_the_scorecard_version_and_the_aggregate(self):
        report = convert_scorecard_result(self._document(), repo=REPO)
        assert report.runs[0].tool.driver.version == "v5.7.0"
        assert (
            report.runs[0].properties.model_dump()["scorecard_aggregate_score"] == 5.4
        )

    def test_the_rule_carries_the_documentation_link(self):
        report = convert_scorecard_result(self._document(), repo=REPO)
        rules = {
            getattr(r.id, "root", r.id): r for r in report.runs[0].tool.driver.rules
        }
        assert str(rules["Branch-Protection"].helpUri).endswith("#branch-protection")


# ---------------------------------------------------------------------------
# The repository name (a dotted first segment is a host, not an owner)
# ---------------------------------------------------------------------------


class TestRepositoryNames:
    @pytest.mark.parametrize(
        "value",
        [
            "github.com/o",
            "https://github.com/github.com/o",
            "github.com/github.com/o",
            "gitlab.com/o",
            "example.org/r",
            "o_x/r",
            "o.x/r",
        ],
    )
    def test_a_dotted_or_underscored_owner_is_refused(self, value):
        assert normalize_repo(value) is None

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("o/r.js", "github.com/o/r.js"),
            ("o-x/r_y", "github.com/o-x/r_y"),
            ("github.com/o-x/r.y", "github.com/o-x/r.y"),
            ("git@github.com:o/r.git", "github.com/o/r"),
        ],
    )
    def test_names_may_carry_dots_and_underscores_owners_hyphens(self, value, expected):
        assert normalize_repo(value) == expected


# ---------------------------------------------------------------------------
# Stderr stays out of the errors and the failure text
# ---------------------------------------------------------------------------

CANARY = "CANARY-quoted-from-the-tree-or-github"


@pytest.fixture
def _env(monkeypatch):
    for name in (*ss.TOKEN_ENV_NAMES, "GH_HOST", "SCORECARD_EXPERIMENTAL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "not-a-real-token")
    monkeypatch.setattr(ss, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / ".git").mkdir(parents=True)
    (src / ".git" / "config").write_text(
        '[remote "origin"]\n\turl = https://github.com/example-org/example-repo.git\n'
    )
    (src / "app.py").write_text("print(1)\n")
    return src


class TestStderr:
    def test_the_class_does_not_quote_the_tools_stderr(self):
        assert ScorecardScanner.quote_tool_stderr is False
        assert ScorecardScanner.unquoted_failure_tool_name == "scorecard"

    def test_a_failed_run_does_not_quote_stderr_in_the_error_or_the_errors(
        self, tree, tmp_path, _env, monkeypatch
    ):
        scanner = _construct_for(tree, tmp_path)

        def run(command, results_dir=None, **_):
            scanner.exit_code = 1
            return {"returncode": 1, "stdout": "", "stderr": CANARY}

        monkeypatch.setattr(scanner, "_run_subprocess", run)
        with pytest.raises(ScannerError) as raised:
            scanner.scan(target=tree, target_type="source")
        assert CANARY not in str(raised.value)
        assert not any(CANARY in line for line in scanner.errors)

    def test_stderr_is_written_to_the_log_not_returned(
        self, tree, tmp_path, _env, monkeypatch
    ):
        scanner = _construct_for(tree, tmp_path)
        seen = {}

        def run(command, results_dir=None, stderr_preference=None, **_):
            seen["stderr_preference"] = stderr_preference
            scanner.exit_code = 0
            return {"returncode": 0, "stdout": "{}", "stderr": ""}

        monkeypatch.setattr(scanner, "_run_subprocess", run)
        with pytest.raises(ScannerError):  # "{}" is not a Scorecard result object
            scanner.scan(target=tree, target_type="source")
        assert seen["stderr_preference"] == "write"


def _construct_for(source: Path, tmp_path: Path) -> ScorecardScanner:
    config = get_default_config()
    AshConfig.model_rebuild()
    record_provenance(config, in_tree=[], trusted=AshConfig())
    return ScorecardScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=ScorecardScannerConfig(enabled=True),
    )


# ---------------------------------------------------------------------------
# Installation (checklist rows 11 and 21): the module-local pinned installer
# ---------------------------------------------------------------------------


class TestInstallation:
    def test_every_published_pair_has_an_install_command(self, tmp_path, monkeypatch):
        from automated_security_helper.plugin_modules.ash_scorecard_plugins import (
            scorecard_install as si,
        )

        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        scanner = _construct(tmp_path)
        pairs = {
            (platform, arch)
            for platform, arches in scanner.custom_install_commands.items()
            for arch in arches
        }
        assert pairs == set(si.ASSETS)
        for arches in scanner.custom_install_commands.values():
            for commands in arches.values():
                (command,) = commands
                assert command.shell is False
                assert "install_scorecard" in " ".join(command.args)

    def test_a_missing_binary_names_the_pinned_install_command(
        self, tree, tmp_path, _env, monkeypatch
    ):
        monkeypatch.setattr(ss, "find_executable", lambda cmd: None)
        scanner = _construct_for(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False
        reason = scanner.dependency_unavailable_reason
        assert "ash dependencies install" in reason
        assert "--tool scorecard" in reason
        assert "ash_scorecard_plugins" in reason
