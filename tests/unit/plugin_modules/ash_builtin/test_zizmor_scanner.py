# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the zizmor scanner.

The SARIF these tests parse is real zizmor 1.30.1 output, committed at
tests/test_data/scanners/zizmor/zizmor-1.30.1.sarif (see the README beside it).
Only the subprocess is faked: input collection, argv and environment
construction, URI rebasing, the severity mapping and the per-target counters
all run for real.
"""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path, PurePosixPath

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    zizmor_scanner as zizmor_module,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
    GITHUB_TOKEN_ENV_VARS,
    ZIZMOR_DEFAULT_VERSION_CONSTRAINT,
    ZizmorScanner,
    ZizmorScannerConfig,
    ZizmorScannerConfigOptions,
    is_zizmor_input,
    map_zizmor_severity,
    version_satisfies,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance

FIXTURE_ROOT = Path(__file__).parents[3] / "test_data" / "scanners" / "zizmor"
CAPTURED_SARIF = FIXTURE_ROOT / "zizmor-1.30.1.sarif"

#: What ASH must report for the captured output: (rule, uri, line, ASH
#: severity, SARIF level). Derived by hand from the mapping table, not from the
#: code under test.
EXPECTED_FINDINGS = sorted(
    [
        # Medium severity, Low confidence -> one band down.
        ("zizmor/artipacked", ".github/workflows/vulnerable.yml", 10, "LOW", "note"),
        (
            "zizmor/dangerous-triggers",
            ".github/workflows/vulnerable.yml",
            2,
            "HIGH",
            "error",
        ),
        (
            "zizmor/excessive-permissions",
            ".github/workflows/vulnerable.yml",
            7,
            "MEDIUM",
            "warning",
        ),
        (
            "zizmor/template-injection",
            ".github/workflows/vulnerable.yml",
            14,
            "HIGH",
            "error",
        ),
        (
            "zizmor/unpinned-uses",
            ".github/workflows/vulnerable.yml",
            10,
            "HIGH",
            "error",
        ),
        ("zizmor/template-injection", "actions/greet/action.yml", 11, "HIGH", "error"),
        ("zizmor/template-injection", "actions/greet/action.yml", 11, "HIGH", "error"),
    ]
)

#: The files ASH should hand zizmor from repo/, relative to its root.
EXPECTED_INPUTS = [
    ".github/workflows/clean.yml",
    ".github/workflows/vulnerable.yml",
    "actions/clean/action.yaml",
    "actions/greet/action.yml",
    "other/action.yml",
]


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _no_version_probe(monkeypatch):
    """Construction must not shell out to uv in a unit test."""
    monkeypatch.setattr(
        ZizmorScanner, "_get_uv_tool_version", lambda self, *_: "1.30.1"
    )


@pytest.fixture
def repo(tmp_path) -> Path:
    """A copy of the fixture repository, outside any git checkout's influence."""
    target = tmp_path / "src"
    shutil.copytree(FIXTURE_ROOT / "repo", target)
    return target


def _scanner(
    source_dir: Path, *, operator: bool | None = None, **options
) -> ZizmorScanner:
    """``operator``: the options came from the operator (True), the scanned tree
    (False), or a config with no recorded provenance (None, counted as the tree's)."""
    output_dir = source_dir / ".ash" / "ash_output"
    config = get_default_config()
    if operator is not None:
        record_provenance(
            config,
            in_tree=[] if operator else [source_dir / ".ash" / ".ash.yaml"],
            trusted=AshConfig(),
        )
    context = PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=output_dir / "converted",
        config=config,
    )
    return ZizmorScanner(
        context=context,
        config=ZizmorScannerConfig(
            enabled=True, options=ZizmorScannerConfigOptions(**options)
        ),
    )


def _fake_run(scanner, *, stdout=None, stderr="", returncode=0, calls=None):
    """Replace _run_subprocess with one that writes logs the way the real one does."""

    def run(command, results_dir=None, env=None, timeout=None, **_):
        if calls is not None:
            calls.append({"command": list(command), "env": env, "timeout": timeout})
        name = scanner.__class__.__name__
        if stdout is not None:
            Path(results_dir, f"{name}.stdout.log").write_text(stdout)
        if stderr:
            Path(results_dir, f"{name}.stderr.log").write_text(stderr)
        response = {"returncode": returncode}
        scanner._process_command_response(response)
        return response

    object.__setattr__(scanner, "_run_subprocess", run)
    object.__setattr__(scanner, "validate_plugin_dependencies", lambda: True)


def _summarize(report: SarifReport):
    rows = []
    for run in report.runs:
        for result in run.results or []:
            physical = result.locations[0].physicalLocation.root
            rows.append(
                (
                    result.ruleId,
                    physical.artifactLocation.uri,
                    physical.region.startLine,
                    result.properties.issue_severity,
                    getattr(result.level, "value", result.level),
                )
            )
    return sorted(rows)


# --------------------------------------------------------------------------- #
# Configuration defaults
# --------------------------------------------------------------------------- #


def test_zizmor_is_on_by_default():
    assert ZizmorScannerConfig().enabled is True
    assert ZizmorScanner.offline_strategy == OfflineStrategy.BUNDLED
    options = ZizmorScannerConfigOptions()
    assert options.online_audits is False
    assert options.persona == "regular"
    assert options.tool_version == ZIZMOR_DEFAULT_VERSION_CONSTRAINT


def test_install_command_carries_the_version_constraint(repo):
    scanner = _scanner(repo)
    assert scanner.uv_tool_install_commands == [
        f"uv tool install zizmor{ZIZMOR_DEFAULT_VERSION_CONSTRAINT}"
    ]


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "version, constraint, expected",
    [
        ("1.30.1", ">=1.29.0,<2.0.0", True),
        ("1.29.0", ">=1.29.0,<2.0.0", True),
        ("1.28.9", ">=1.29.0,<2.0.0", False),
        ("2.0.0", ">=1.29.0,<2.0.0", False),
        ("1.30.1", "==1.30.1", True),
        ("1.30", "==1.30.0", True),
        ("1.30.2", "==1.30.1", False),
        ("1.30.2", "!=1.30.1", True),
        ("1.30.2", "~=1.30.0", True),
        ("1.31.0", "~=1.30.0", False),
        ("1.31.0", "~=1.30", True),
        ("1.30.7", "==1.30.*", True),
        ("1.31.0", "==1.30.*", False),
        ("1.30.1", None, True),
        ("1.30.1", "", True),
        # Unverifiable, not guessed.
        (None, ">=1.0", None),
        ("1.30.1rc1", ">=1.0", None),
        ("1.30.1", ">=1.0a1", None),
        ("1.30.1", "~=1", None),
        ("1.30.1", ">=1.*", None),
        ("1.30.1", "===1.30.1", None),
    ],
)
def test_version_satisfies(version, constraint, expected):
    assert version_satisfies(version, constraint) is expected


@pytest.mark.parametrize(
    "severity, confidence, level, expected",
    [
        ("High", "High", "error", "HIGH"),
        ("High", "Medium", "error", "HIGH"),
        ("High", "Low", "error", "MEDIUM"),
        ("Medium", "High", "warning", "MEDIUM"),
        ("Medium", "Medium", "warning", "MEDIUM"),
        ("Medium", "Low", "warning", "LOW"),
        ("Low", "High", "note", "LOW"),
        ("Low", "Low", "note", "INFO"),
        ("Informational", "High", "note", "INFO"),
        ("Informational", "Low", "note", "INFO"),
        # Missing confidence: no adjustment.
        ("High", None, "error", "HIGH"),
        ("High", "Unknown", "error", "HIGH"),
        # Missing or unknown severity: zizmor's level, read the ASH way.
        (None, "Low", "error", "HIGH"),
        ("Unknown", "High", "warning", "MEDIUM"),
        (None, None, "note", "LOW"),
        (None, None, None, "MEDIUM"),
    ],
)
def test_map_zizmor_severity(severity, confidence, level, expected):
    assert map_zizmor_severity(severity, confidence, level) == expected


@pytest.mark.parametrize(
    "path, expected",
    [
        (".github/workflows/ci.yml", True),
        (".github/workflows/ci.yaml", True),
        ("sub/project/.github/workflows/ci.yml", True),
        ("action.yml", True),
        ("actions/x/action.yaml", True),
        (".github/workflows/nested/ci.yml", False),
        (".github/workflows/README.md", False),
        ("workflows/ci.yml", False),
        ("github/workflows/ci.yml", False),
        ("actions/x/my-action.yml", False),
    ],
)
def test_is_zizmor_input(path, expected):
    assert is_zizmor_input(PurePosixPath(path)) is expected


# --------------------------------------------------------------------------- #
# Input collection
# --------------------------------------------------------------------------- #


def _relative(paths, root):
    return [p.relative_to(root.absolute()).as_posix() for p in paths]


def test_collects_workflows_and_actions_and_nothing_else(repo):
    scanner = _scanner(repo)
    inputs = scanner._collect_inputs(repo, "source", [])
    # node_modules/ and the nested non-workflow are absent.
    assert _relative(inputs, repo) == EXPECTED_INPUTS


def test_global_ignore_paths_remove_inputs(repo):
    scanner = _scanner(repo)
    inputs = scanner._collect_inputs(
        repo,
        "source",
        [IgnorePathWithReason(path="actions/**", reason="test")],
    )
    assert _relative(inputs, repo) == [
        p for p in EXPECTED_INPUTS if not p.startswith("actions/")
    ]


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")


@pytest.mark.parametrize(
    "link, points_at",
    [
        (".github/workflows/leak.yml", "leak.yml"),
        ("actions/linked", "greet"),
    ],
    ids=["workflow-file", "action-directory"],
)
def test_an_input_that_resolves_outside_the_target_is_not_passed(
    repo, tmp_path, caplog, link, points_at
):
    """zizmor reads a symlinked input where it points; one outside is skipped."""
    outside = tmp_path / "outside"
    (outside / "greet").mkdir(parents=True)
    (outside / "leak.yml").write_text(
        (repo / ".github" / "workflows" / "clean.yml").read_text()
    )
    (outside / "greet" / "action.yml").write_text(
        (repo / "actions" / "greet" / "action.yml").read_text()
    )
    _symlink_or_skip(repo / link, outside / points_at)
    scanner = _scanner(repo)
    with caplog.at_level("WARNING"):
        inputs = _relative(scanner._collect_inputs(repo, "source", []), repo)
    assert inputs == EXPECTED_INPUTS
    if link.endswith(".yml"):
        assert "resolves outside the scan root" in caplog.text
    # A symlinked directory is not descended into by the scan set, so its action
    # never becomes a candidate; held here so a change there cannot let it through.


def test_a_symlink_inside_the_target_is_still_an_input(repo):
    """Only where a link points matters: one into the tree stays an input."""
    real = repo / ".github" / "workflows"
    target = next(p for p in sorted(real.iterdir()) if p.suffix in (".yml", ".yaml"))
    link = real / f"linked-{target.name}"
    _symlink_or_skip(link, target)
    inputs = _relative(_scanner(repo)._collect_inputs(repo, "source", []), repo)
    assert link.relative_to(repo).as_posix() in inputs


def test_gitignored_and_output_dir_files_are_not_inputs(repo):
    (repo / ".gitignore").write_text("other/\n")
    copy_in_output = repo / ".ash" / "ash_output" / "x" / "action.yml"
    copy_in_output.parent.mkdir(parents=True)
    copy_in_output.write_text((repo / "actions/greet/action.yml").read_text())
    scanner = _scanner(repo)
    inputs = scanner._collect_inputs(repo, "source", [])
    assert _relative(inputs, repo) == [
        p for p in EXPECTED_INPUTS if not p.startswith("other/")
    ]


# --------------------------------------------------------------------------- #
# argv and environment
# --------------------------------------------------------------------------- #


def _argv_and_env(scanner, repo):
    scanner._inputs = scanner._collect_inputs(repo, "source", [])
    scanner.results_dir.mkdir(parents=True, exist_ok=True)
    final_args, results_file, env = scanner._execute_scan(repo, "source", [])
    return final_args, results_file, env


def test_default_argv_is_offline_sarif_with_inputs_after_double_dash(repo):
    scanner = _scanner(repo)
    final_args, results_file, _ = _argv_and_env(scanner, repo)
    assert final_args[0] == "zizmor"
    assert "--offline" in final_args
    for flag in ("--no-exit-codes", "--no-progress"):
        assert flag in final_args
    assert final_args[final_args.index("--format") + 1] == "sarif"
    assert final_args[final_args.index("--persona") + 1] == "regular"
    separator = final_args.index("--")
    # Inputs are relative to source_dir, the subprocess cwd.
    assert final_args[separator + 1 :] == EXPECTED_INPUTS
    assert results_file.name == "ZizmorScanner.stdout.log"
    assert scanner.targets_attempted == len(EXPECTED_INPUTS)


def test_tokens_and_zizmor_env_never_reach_zizmor_offline(repo, monkeypatch):
    for name in (*GITHUB_TOKEN_ENV_VARS, "ZIZMOR_CONFIG", "ZIZMOR_OFFLINE"):
        monkeypatch.setenv(name, "value-that-must-not-leak")
    monkeypatch.setenv("UNRELATED_VARIABLE", "kept")
    _, _, env = _argv_and_env(_scanner(repo), repo)
    for name in (*GITHUB_TOKEN_ENV_VARS, "ZIZMOR_CONFIG", "ZIZMOR_OFFLINE"):
        assert name not in env
    assert env["UNRELATED_VARIABLE"] == "kept"


def test_token_variables_are_stripped_whatever_their_case(repo, monkeypatch):
    """Windows environment names are case-insensitive, so ``Gh_Token`` is GH_TOKEN."""
    monkeypatch.setenv("Gh_Token", "value-that-must-not-leak")
    _, _, env = _argv_and_env(_scanner(repo), repo)
    assert not any(key.upper() == "GH_TOKEN" for key in env)


def test_online_audits_drops_offline_and_passes_the_token_through(repo, monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setenv("GH_TOKEN", "token-value")
    monkeypatch.setenv("ZIZMOR_CONFIG", "/elsewhere.yml")
    final_args, _, env = _argv_and_env(
        _scanner(repo, operator=True, online_audits=True), repo
    )
    assert "--offline" not in final_args
    assert env["GH_TOKEN"] == "token-value"
    # Never on the command line, where it would be logged.
    assert not any("token-value" in arg for arg in final_args)
    assert "ZIZMOR_CONFIG" not in env


@pytest.mark.parametrize("operator", [False, None])
def test_online_audits_from_the_scanned_tree_stay_offline_without_a_token(
    repo, monkeypatch, caplog, operator
):
    """A repository's own config cannot turn on the network or hand zizmor a token.

    ``operator=None`` is a config with no recorded provenance, counted as the
    tree's.
    """
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    for name in GITHUB_TOKEN_ENV_VARS:
        monkeypatch.setenv(name, "token-value")
    with caplog.at_level("WARNING"):
        final_args, _, env = _argv_and_env(
            _scanner(repo, operator=operator, online_audits=True), repo
        )
    assert "--offline" in final_args
    for name in GITHUB_TOKEN_ENV_VARS:
        assert name not in env
    assert "scanners.zizmor.options.online_audits" in caplog.text


def test_ash_offline_mode_overrides_online_audits(repo, monkeypatch):
    monkeypatch.setenv("ASH_OFFLINE", "true")
    monkeypatch.setenv("GITHUB_TOKEN", "token-value")
    final_args, _, env = _argv_and_env(
        _scanner(repo, operator=True, online_audits=True), repo
    )
    assert "--offline" in final_args
    assert "GITHUB_TOKEN" not in env


def test_an_operator_config_file_is_passed_resolved_and_a_missing_one_fails(repo):
    (repo / "zizmor-ci.yml").write_text("rules: {}\n")
    final_args, _, _ = _argv_and_env(
        _scanner(repo, operator=True, config_file="zizmor-ci.yml"), repo
    )
    config = f"--config={(repo / 'zizmor-ci.yml').resolve().as_posix()}"
    assert config in final_args
    assert final_args.index(config) < final_args.index("--")
    assert "--no-config" not in final_args
    with pytest.raises(FileNotFoundError, match="does-not-exist.yml"):
        _argv_and_env(
            _scanner(repo, operator=True, config_file="does-not-exist.yml"), repo
        )


@pytest.mark.parametrize("operator", [False, None])
def test_a_config_file_from_the_scanned_tree_is_ignored(repo, caplog, operator):
    (repo / "zizmor-ci.yml").write_text("rules: {}\n")
    with caplog.at_level("WARNING"):
        final_args, _, _ = _argv_and_env(
            _scanner(repo, operator=operator, config_file="zizmor-ci.yml"), repo
        )
    separator = final_args.index("--")
    assert "--no-config" in final_args[:separator]
    assert not any(a.startswith("--config") for a in final_args[:separator])
    assert "scanners.zizmor.options.config_file" in caplog.text


@pytest.mark.parametrize("name", ["zizmor.yml", ".github/zizmor.yml"])
def test_without_an_operator_config_zizmor_reads_none(repo, caplog, name):
    """zizmor would discover the tree's own config next to its inputs."""
    (repo / name).parent.mkdir(parents=True, exist_ok=True)
    (repo / name).write_text("rules:\n  template-injection:\n    disable: true\n")
    with caplog.at_level("INFO"):
        final_args, _, _ = _argv_and_env(_scanner(repo), repo)
    assert "--no-config" in final_args[: final_args.index("--")]
    assert f"{name} in the scanned tree is not read" in caplog.text


def test_a_path_that_looks_like_a_flag_stays_an_input(repo):
    hostile = repo / "--config=evil" / "action.yml"
    hostile.parent.mkdir()
    hostile.write_text((repo / "actions/clean/action.yaml").read_text())
    final_args, _, _ = _argv_and_env(_scanner(repo), repo)
    separator = final_args.index("--")
    assert "--config=evil/action.yml" in final_args[separator + 1 :]
    assert not any(a.startswith("--config") for a in final_args[:separator])


# --------------------------------------------------------------------------- #
# Parsing real zizmor output
# --------------------------------------------------------------------------- #


def _scan_with_output(repo, sarif_text, **run_kwargs):
    scanner = _scanner(repo)
    _fake_run(scanner, stdout=sarif_text, **run_kwargs)
    return scanner, scanner.scan(repo, "source", [])


def test_captured_output_parses_into_the_expected_findings(repo):
    scanner, report = _scan_with_output(repo, CAPTURED_SARIF.read_text())
    assert isinstance(report, SarifReport)
    assert _summarize(report) == EXPECTED_FINDINGS
    assert scanner.targets_attempted == len(EXPECTED_INPUTS)
    assert scanner.targets_failed == 0
    invocation = report.runs[0].invocations[0]
    assert invocation.executionSuccessful is True


def _mutated(mutate):
    data = json.loads(CAPTURED_SARIF.read_text())
    first = data["runs"][0]["results"][0]
    mutate(first)
    return json.dumps(data)


@pytest.mark.parametrize(
    "description, mutate",
    [
        ("rule id", lambda r: r.update(ruleId="zizmor/something-else")),
        # zizmor's own rating is what the mapping reads, so changing it must move
        # the ASH severity and level.
        (
            "severity",
            lambda r: r["properties"].update({"zizmor/severity": "High"}),
        ),
        (
            "confidence",
            lambda r: r["properties"].update({"zizmor/confidence": "High"}),
        ),
        (
            "location",
            lambda r: r["locations"][0]["physicalLocation"]["region"].update(
                startLine=99
            ),
        ),
        (
            "file",
            lambda r: r["locations"][0]["physicalLocation"]["artifactLocation"].update(
                uri="actions/clean/action.yaml"
            ),
        ),
    ],
)
def test_negative_control_a_mutated_finding_does_not_match(repo, description, mutate):
    """The assertion above bites: each single-field mutation must change the summary."""
    _, report = _scan_with_output(repo, _mutated(mutate))
    assert _summarize(report) != EXPECTED_FINDINGS, description


def test_uris_relative_to_an_enclosing_repository_are_rebased(repo):
    """zizmor writes URIs relative to the git root, not to the scanned directory.

    Simulated here as a scan of ``src`` inside a repository whose root is its
    parent, which is what zizmor 1.30.1 emits (``src/.github/...``).
    """
    data = json.loads(CAPTURED_SARIF.read_text())
    text = json.dumps(data).replace('"uri": "', '"uri": "src/')
    _, report = _scan_with_output(repo, text)
    assert _summarize(report) == EXPECTED_FINDINGS
    for run in report.runs:
        for result in run.results:
            for step in result.codeFlows[0].threadFlows[0].locations:
                uri = step.location.physicalLocation.root.artifactLocation.uri
                assert not uri.startswith("src/")


def test_an_ambiguous_or_unknown_uri_is_left_alone(repo):
    scanner = _scanner(repo)
    scanner._last_inputs = [
        repo.absolute() / "a/action.yml",
        repo.absolute() / "b/action.yml",
    ]
    assert scanner._rebased_uri("action.yml") == "action.yml"
    assert scanner._rebased_uri("c/action.yml") == "c/action.yml"
    assert scanner._rebased_uri("x/a/action.yml") == "x/a/action.yml"
    assert scanner._rebased_uri("a/action.yml") == "a/action.yml"
    assert scanner._rebased_uri("repo/a/action.yml") == "repo/a/action.yml"


def test_verbatim_path_separates_a_nested_repository_from_the_outer_one(repo):
    """zizmor writes the same URI for ``ci.yml`` in an outer and a nested repository.

    Its URI is relative to each file's own git root, so a vendored checkout's
    workflow and the outer one at the same relative path both come back as
    ``.github/workflows/ci.yml``. The input path zizmor records beside each
    location tells them apart.
    """
    scanner = _scanner(repo)
    outer = repo.absolute() / ".github/workflows/ci.yml"
    nested = repo.absolute() / "vendor/lib/.github/workflows/ci.yml"
    scanner._last_inputs = [outer, nested]
    uri = ".github/workflows/ci.yml"
    assert scanner._rebased_uri(uri) == uri  # ambiguous by suffix alone
    assert (
        scanner._rebased_uri(uri, "vendor/lib/.github/workflows/ci.yml")
        == "vendor/lib/.github/workflows/ci.yml"
    )
    assert scanner._rebased_uri(uri, ".github/workflows/ci.yml") == uri
    # A recorded path that is not one of this scan's inputs is not trusted.
    assert scanner._rebased_uri(uri, "elsewhere/.github/workflows/ci.yml") == uri
    # Nor is one naming a different file.
    assert scanner._rebased_uri(uri, "vendor/lib/.github/workflows/other.yml") == uri


def test_verbatim_path_is_read_from_the_sarif(repo):
    """End to end through _post_process_sarif: the vendored copy keeps its path."""
    data = json.loads(CAPTURED_SARIF.read_text())
    vendored = "vendor/lib/.github/workflows/vulnerable.yml"
    (repo / vendored).parent.mkdir(parents=True)
    shutil.copy(repo / ".github/workflows/vulnerable.yml", repo / vendored)
    text = json.dumps(data).replace(
        '"verbatim_path": ".github/workflows/vulnerable.yml"',
        f'"verbatim_path": "{vendored}"',
    )
    _, report = _scan_with_output(repo, text)
    uris = {row[1] for row in _summarize(report)}
    assert uris == {vendored, "actions/greet/action.yml"}


# --------------------------------------------------------------------------- #
# No inputs, rejected inputs, failures
# --------------------------------------------------------------------------- #


def test_no_workflows_or_actions_completes_with_zero_findings_without_zizmor(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n")
    scanner = _scanner(source)
    calls = []
    _fake_run(scanner, stdout="never read", calls=calls)
    report = scanner.scan(source, "source", [])
    assert calls == []
    assert isinstance(report, SarifReport)
    assert report.runs[0].results == []
    assert report.runs[0].tool.driver.name == "zizmor"
    # 0 attempted is how ASH says "nothing to evaluate": SKIPPED, not PASSED.
    assert scanner.targets_attempted == 0


NOT_AN_ACTION = (
    " WARN collect_inputs: zizmor::registry::input: failed to validate "
    "file://other/action.yml as action: input does not match expected "
    "validation schema\n"
)
PARSE_FAILURE = (
    " WARN collect_inputs: zizmor::registry::input: failed to parse input: did "
    "not find expected ',' or ']' at line 2 column 5\n"
)
NO_INPUTS = "fatal: no audit was performed\nerror: no inputs collected\n"


def test_a_file_that_is_not_an_action_is_not_counted(repo):
    scanner, report = _scan_with_output(
        repo, CAPTURED_SARIF.read_text(), stderr=NOT_AN_ACTION
    )
    assert _summarize(report) == EXPECTED_FINDINGS
    assert scanner.targets_attempted == len(EXPECTED_INPUTS) - 1
    assert scanner.targets_failed == 0


def test_an_unparseable_input_is_a_failed_target(repo):
    scanner, _ = _scan_with_output(
        repo, CAPTURED_SARIF.read_text(), stderr=NOT_AN_ACTION + PARSE_FAILURE
    )
    assert scanner.targets_attempted == len(EXPECTED_INPUTS) - 1
    assert scanner.targets_failed == 1


def test_failed_targets_never_exceed_attempted_targets(repo):
    scanner, _ = _scan_with_output(
        repo, CAPTURED_SARIF.read_text(), stderr=PARSE_FAILURE * 9
    )
    assert scanner.targets_attempted == len(EXPECTED_INPUTS)
    assert scanner.targets_failed == len(EXPECTED_INPUTS)


def test_network_warnings_are_not_counted_as_rejected_inputs(repo):
    scanner, _ = _scan_with_output(
        repo,
        CAPTURED_SARIF.read_text(),
        stderr=" WARN audit: zizmor: failed to fetch https://api.github.com/x\n",
    )
    assert scanner.targets_failed == 0
    assert scanner.targets_attempted == len(EXPECTED_INPUTS)


def test_exit_3_with_every_input_rejected_is_zero_findings(repo):
    scanner, report = _scan_with_output(
        repo,
        None,
        returncode=3,
        stderr=NOT_AN_ACTION * 1 + PARSE_FAILURE * 4 + NO_INPUTS,
    )
    assert isinstance(report, SarifReport)
    assert report.runs[0].results == []
    # Every real input failed to load: failed == attempted, which ASH reports ERROR.
    assert scanner.targets_attempted == len(EXPECTED_INPUTS) - 1
    assert scanner.targets_failed == scanner.targets_attempted


def test_exit_3_with_only_non_actions_attempts_nothing(tmp_path):
    source = tmp_path / "src"
    (source / "x").mkdir(parents=True)
    (source / "x" / "action.yml").write_text("tool: other\n")
    scanner = _scanner(source)
    _fake_run(scanner, stdout=None, returncode=3, stderr=NOT_AN_ACTION + NO_INPUTS)
    report = scanner.scan(source, "source", [])
    assert report.runs[0].results == []
    assert scanner.targets_attempted == 0


@pytest.mark.parametrize("returncode", [1, 2, 3])
def test_a_tool_failure_without_output_is_an_error_not_a_clean_scan(repo, returncode):
    scanner = _scanner(repo)
    _fake_run(scanner, stdout=None, returncode=returncode, stderr="fatal: boom\n")
    with pytest.raises(ScannerError, match="boom"):
        scanner.scan(repo, "source", [])


def test_a_previous_runs_sarif_is_never_read_as_this_runs(repo):
    scanner = _scanner(repo)
    stale = scanner.results_dir / "source" / "ZizmorScanner.stdout.log"
    stale.parent.mkdir(parents=True)
    stale.write_text(CAPTURED_SARIF.read_text())
    _fake_run(scanner, stdout=None, returncode=1, stderr="fatal: boom\n")
    with pytest.raises(ScannerError):
        scanner.scan(repo, "source", [])


def test_a_timeout_reports_the_timeout(repo):
    scanner = _scanner(repo, scan_timeout=5)

    def run(command, results_dir=None, env=None, timeout=None, **_):
        assert timeout == 5
        response = {"returncode": 124, "timed_out": True}
        scanner._process_command_response(response)
        return response

    object.__setattr__(scanner, "_run_subprocess", run)
    object.__setattr__(scanner, "validate_plugin_dependencies", lambda: True)
    with pytest.raises(ScannerError, match="timed out after 5"):
        scanner.scan(repo, "source", [])


def test_each_target_starts_from_a_clean_exit_code(repo):
    """The base class keeps the maximum exit code; one target's 3 must not leak."""
    scanner = _scanner(repo)
    scanner.exit_code = 3
    _fake_run(scanner, stdout=None, returncode=1, stderr="fatal: boom\n" + NO_INPUTS)
    with pytest.raises(ScannerError):
        scanner.scan(repo, "source", [])


# --------------------------------------------------------------------------- #
# Dependency resolution
# --------------------------------------------------------------------------- #


class _Completed:
    def __init__(self, stdout, returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def _with_executable(monkeypatch, version_output, returncode=0, seen=None):
    monkeypatch.setattr(zizmor_module, "find_executable", lambda _: "/opt/bin/zizmor")

    def fake_run_command(args, env=None, **_):
        if seen is not None:
            seen.append((list(args), env))
        return _Completed(version_output, returncode)

    monkeypatch.setattr(zizmor_module, "run_command", fake_run_command)


def test_a_satisfying_binary_on_path_runs_directly(repo, monkeypatch):
    seen = []
    monkeypatch.setenv("GH_TOKEN", "token-value")
    _with_executable(monkeypatch, "zizmor 1.29.0\n", seen=seen)
    scanner = _scanner(repo)
    assert scanner.validate_plugin_dependencies() is True
    assert scanner.use_uv_tool is False
    assert scanner.tool_version == "1.29.0"
    assert seen[0][0] == ["/opt/bin/zizmor", "--version"]
    assert "GH_TOKEN" not in seen[0][1]


@pytest.mark.parametrize("output", ["zizmor 1.28.0\n", "zizmor 2.0.0\n", "garbage\n"])
def test_an_unsatisfying_binary_offline_is_missing_with_a_reason(
    repo, monkeypatch, output
):
    monkeypatch.setenv("ASH_OFFLINE", "true")
    _with_executable(monkeypatch, output)
    scanner = _scanner(repo)
    object.__setattr__(scanner, "_resolve_through_uv", lambda: False)
    assert scanner.validate_plugin_dependencies() is False
    assert scanner.dependencies_satisfied is False
    reason = scanner.dependency_unavailable_reason
    assert "zizmor at /opt/bin/zizmor" in reason
    assert "while offline" in reason
    assert ZIZMOR_DEFAULT_VERSION_CONSTRAINT in reason
    # Once recorded, the verdict stands.
    assert scanner.validate_plugin_dependencies() is False


def test_no_binary_falls_back_to_uv(repo, monkeypatch):
    monkeypatch.setattr(zizmor_module, "find_executable", lambda _: None)
    scanner = _scanner(repo)
    object.__setattr__(scanner, "_resolve_through_uv", lambda: True)
    assert scanner.validate_plugin_dependencies() is True


def test_offline_without_any_zizmor_does_not_try_to_install(repo, monkeypatch):
    monkeypatch.setenv("ASH_OFFLINE", "true")
    monkeypatch.setattr(zizmor_module, "find_executable", lambda _: None)
    scanner = _scanner(repo)
    object.__setattr__(scanner, "_validate_uv_tool_availability", lambda: True)
    object.__setattr__(
        scanner, "_get_tool_installation_info", lambda: {"available": False}
    )

    def refuse(**_):
        raise AssertionError("must not install offline")

    object.__setattr__(scanner, "_install_uv_tool", refuse)
    assert scanner.validate_plugin_dependencies() is False
    assert "no zizmor executable was found" in scanner.dependency_unavailable_reason


def test_post_process_leaves_the_input_report_intact_for_other_runs(repo):
    """Guards _summarize against reading a shared object: two scans, two results."""
    _, first = _scan_with_output(repo, CAPTURED_SARIF.read_text())
    _, second = _scan_with_output(repo, _mutated(lambda r: r.update(ruleId="z/x")))
    assert _summarize(first) == EXPECTED_FINDINGS
    assert _summarize(second) != _summarize(copy.deepcopy(first))


# tool_version is appended to the package name for uv, so it must stay a version
# constraint: a direct reference would let the config choose what uv installs.
@pytest.mark.parametrize(
    "value",
    [
        " @ file:///tmp/evil",
        "@ git+https://example.invalid/evil.git",
        "[evil]>=1",
        ">=1; sys_platform != 'x'",
        "1.30.1",
    ],
)
def test_a_tool_version_that_is_not_a_specifier_set_is_replaced_by_the_default(value):
    """As for every uv-installed tool (tests/unit/config/test_tool_version_is_a_version_specifier.py)."""
    default = ZizmorScannerConfigOptions().tool_version
    assert ZizmorScannerConfigOptions(tool_version=value).tool_version == default


@pytest.mark.parametrize("value", [">=1.29.0,<2.0.0", "==1.30.1", None])
def test_a_specifier_set_tool_version_is_accepted(value):
    assert ZizmorScannerConfigOptions(tool_version=value).tool_version == value
