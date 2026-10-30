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
import logging
import os
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import pytest
from packaging.specifiers import SpecifierSet

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
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

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


# Which tool_version applies is decided when the config is resolved, for every
# scanner alike: tests/unit/config/test_tool_version_is_the_operators.py runs zizmor
# through a repository config, an operator config and a workspace project.


def test_the_scanner_reads_the_tool_version_it_is_given(repo):
    """The constraint the install and the PATH check get is the option as given."""
    scanner = _scanner(repo, operator=True, tool_version="==1.29.0")
    assert scanner._get_tool_version_constraint() == "==1.29.0"
    assert scanner.uv_tool_install_commands == ["uv tool install zizmor==1.29.0"]


def test_install_command_carries_the_version_constraint(repo):
    """The stored command carries the default constraint. Its clauses are
    compared as a specifier set: the command builder spells the requirement the
    way packaging prints it, which orders the clauses, not as the constant does."""
    (command,) = scanner_commands = _scanner(repo).uv_tool_install_commands
    assert len(scanner_commands) == 1
    prefix = "uv tool install zizmor"
    assert command.startswith(prefix)
    assert SpecifierSet(command[len(prefix) :]) == SpecifierSet(
        ZIZMOR_DEFAULT_VERSION_CONSTRAINT
    )


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
        # A shorter version is zero-padded for the prefix too: "1" is 1.0.0.
        ("1", "~=1.0.0", True),
        ("1.0", "~=1.0.0", True),
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
        # GitHub and zizmor key on the exact spellings; handed these, zizmor
        # rejected them and they read as failed targets.
        ("Action.yml", False),
        ("actions/x/ACTION.YAML", False),
        (".github/workflows/ci.YAML", False),
        (".github/workflows/ci.YML", False),
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


@pytest.mark.parametrize(
    ("source_dir", "expected"),
    [
        (".github", ["workflows/clean.yml", "workflows/vulnerable.yml"]),
        (".github/workflows", ["clean.yml", "vulnerable.yml"]),
    ],
)
def test_a_source_dir_that_is_a_github_or_workflows_dir_is_audited(
    repo, source_dir, expected
):
    """Its files sit directly inside a ``.github/workflows`` directory."""
    source = repo / source_dir
    inputs = _scanner(source)._collect_inputs(source, "source", [])
    assert _relative(inputs, source) == expected


@pytest.mark.parametrize(
    ("relative", "scan_root", "expected"),
    [
        ("workflows/ci.yml", "/r/.github", True),
        ("ci.yml", "/r/.github/workflows", True),
        ("sub/ci.yml", "/r/.github/workflows", False),
        ("ci.yml", "/r/.github", False),
        ("workflows/ci.yml", None, False),
        ("action.yml", "/r/anything", True),
    ],
)
def test_is_zizmor_input_counts_the_scan_roots_own_name(relative, scan_root, expected):
    root = None if scan_root is None else Path(scan_root)
    assert is_zizmor_input(PurePosixPath(relative), scan_root=root) is expected


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


@pytest.mark.parametrize(
    "pattern, removed",
    [
        ("actions/", ("actions/",)),
        ("**/greet/", ("actions/greet/",)),
        (".github/", (".github/",)),
    ],
)
def test_an_ignore_path_ending_in_a_slash_removes_what_is_inside(
    repo, pattern, removed
):
    """An ignore path ending in ``/`` names what is inside that directory, as every
    other place ASH matches an ignore path reads it (``ignore_path_matches``)."""
    scanner = _scanner(repo)
    inputs = scanner._collect_inputs(
        repo, "source", [IgnorePathWithReason(path=pattern, reason="test")]
    )
    assert _relative(inputs, repo) == [
        p for p in EXPECTED_INPUTS if not p.startswith(removed)
    ]


def test_an_ignore_path_ending_in_a_slash_keeps_a_file_of_that_name(repo):
    """``other/action.yml/`` names a directory, so the file other/action.yml is kept."""
    scanner = _scanner(repo)
    inputs = scanner._collect_inputs(
        repo,
        "source",
        [IgnorePathWithReason(path="other/action.yml/", reason="test")],
    )
    assert _relative(inputs, repo) == EXPECTED_INPUTS


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
        # The scan set zizmor reads leaves a file link out of the tree out before
        # zizmor's own check sees it, and names the link, not its target.
        assert f"Not scanning {link!r}: link leaves the scanned tree" in caplog.text
        assert outside.as_posix() not in caplog.text
    # A symlinked directory is not descended into by the scan set, so its action
    # never becomes a candidate; held here so a change there cannot let it through.


def test_a_converted_input_that_resolves_outside_the_target_is_not_passed(
    repo, tmp_path, caplog
):
    """The converted target is not read through the scan set, so zizmor's own
    check is what keeps a link out of the tree from reaching zizmor."""
    outside = tmp_path / "outside" / "leak.yml"
    outside.parent.mkdir(parents=True)
    outside.write_text((repo / ".github" / "workflows" / "clean.yml").read_text())
    scanner = _scanner(repo)
    converted = Path(scanner._plugin_context.work_dir)
    workflows = converted / ".github" / "workflows"
    workflows.mkdir(parents=True)
    _symlink_or_skip(workflows / "leak.yml", outside)
    (workflows / "clean.yml").write_text(outside.read_text())

    with caplog.at_level("WARNING"):
        inputs = _relative(
            scanner._collect_inputs(converted, "converted", []), converted
        )

    assert inputs == [".github/workflows/clean.yml"]
    assert (
        "Not auditing .github/workflows/leak.yml: it resolves outside the scan root."
        in caplog.text
    )


@pytest.mark.parametrize(
    "links",
    [
        [(".github/workflows/broken.yml", "missing.yml")],
        [("actions/broken/action.yml", "missing.yml")],
        [
            (".github/workflows/broken.yml", "loop.yml"),
            (".github/workflows/loop.yml", "broken.yml"),
        ],
    ],
    ids=["dangling-workflow", "dangling-action", "looping-workflow"],
)
def test_an_input_link_that_resolves_to_no_file_is_skipped_with_a_warning(
    repo, caplog, links
):
    """zizmor cannot open such an input and fails the whole run, so it is skipped
    with a warning, as a link pointing outside the scan root is."""
    for link, points_at in links:
        (repo / link).parent.mkdir(parents=True, exist_ok=True)
        _symlink_or_skip(repo / link, Path(points_at))
    scanner = _scanner(repo)
    with caplog.at_level("WARNING"):
        inputs = _relative(scanner._collect_inputs(repo, "source", []), repo)
    assert inputs == EXPECTED_INPUTS
    assert f"Not auditing {links[0][0]}" in caplog.text


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


def test_the_workspace_output_directory_is_named_to_the_scan_set(repo, monkeypatch):
    """In a workspace scan the workspace's output directory holds every project's
    output. The scan set leaves it out only when it is named; a project at the
    workspace root otherwise audits other projects' output as its own source."""
    seen: list = []
    monkeypatch.setattr(
        zizmor_module, "scan_set", lambda **kwargs: seen.append(kwargs) or []
    )
    workspace_output = repo.parent / "workspace-out"
    scanner = ZizmorScanner(
        context=PluginContext(
            source_dir=repo,
            output_dir=workspace_output / "src",
            work_dir=workspace_output / "src" / "converted",
            workspace_output_dir=workspace_output,
            config=get_default_config(),
        ),
        config=ZizmorScannerConfig(),
    )

    scanner._collect_inputs(repo, "source", [])

    assert [call["workspace_output_dir"] for call in seen] == [str(workspace_output)]


def test_an_action_git_tracks_under_the_output_directory_is_an_input(repo, monkeypatch):
    """The scan set leaves ASH's output directory out but keeps the files git
    tracks there, since a repository can commit a composite action at that
    path. The scanner must not drop them a second time."""
    committed = repo / ".ash" / "ash_output" / "sample" / "action.yml"
    committed.parent.mkdir(parents=True)
    committed.write_text((repo / "actions/greet/action.yml").read_text())
    kept_by_the_scan_set = [str(repo / "actions/greet/action.yml"), str(committed)]
    monkeypatch.setattr(
        zizmor_module, "scan_set", lambda **_: list(kept_by_the_scan_set)
    )
    scanner = _scanner(repo)
    inputs = scanner._collect_inputs(repo, "source", [])
    assert _relative(inputs, repo) == [
        ".ash/ash_output/sample/action.yml",
        "actions/greet/action.yml",
    ]


@pytest.mark.parametrize("honor", [True, False])
def test_the_gitignore_applies_as_the_config_says(repo, honor):
    """A scan set zizmor computes itself follows ``honor_ignore_files``."""
    (repo / ".gitignore").write_text("other/\n")
    scanner = _scanner(repo)
    scanner._plugin_context.config.honor_ignore_files = honor

    inputs = _relative(scanner._collect_inputs(repo, "source", []), repo)

    ignored = [p for p in EXPECTED_INPUTS if p.startswith("other/")]
    assert ignored, "the fixture has no input under other/"
    assert inputs == (
        [p for p in EXPECTED_INPUTS if p not in ignored] if honor else EXPECTED_INPUTS
    )


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
    # The SARIF on stdout is parsed as JSON: a colored run would put escape
    # sequences into it, so the flag that turns color off is part of the argv.
    assert final_args[final_args.index("--color") + 1] == "never"
    separator = final_args.index("--")
    # Inputs are relative to source_dir, the subprocess cwd.
    assert final_args[separator + 1 :] == EXPECTED_INPUTS
    assert results_file.name == "ZizmorScanner.stdout.log"
    assert scanner.targets_attempted == len(EXPECTED_INPUTS)


#: The variables zizmor reads a GitHub token from, spelled out here rather than
#: read from the scanner, so a name dropped from its list fails these tests.
TOKEN_VARIABLES = ["GH_TOKEN", "GITHUB_TOKEN", "ZIZMOR_GITHUB_TOKEN"]
#: The variables that change zizmor's behavior, removed whatever online_audits is.
#: RUST_LOG is zizmor's log filter: one from the caller's shell that hides WARN
#: lines hides the rejected-input warnings the per-target counters are read from.
BEHAVIOR_VARIABLES = [
    "ZIZMOR_CONFIG",
    "ZIZMOR_OFFLINE",
    "ZIZMOR_NO_ONLINE_AUDITS",
    "RUST_LOG",
]


def test_the_scanner_strips_exactly_the_documented_variables():
    assert sorted(GITHUB_TOKEN_ENV_VARS) == sorted(TOKEN_VARIABLES)
    assert sorted(zizmor_module.ZIZMOR_BEHAVIOR_ENV_VARS) == sorted(BEHAVIOR_VARIABLES)


@pytest.mark.parametrize("name", TOKEN_VARIABLES + BEHAVIOR_VARIABLES)
def test_tokens_and_zizmor_env_never_reach_zizmor_offline(repo, monkeypatch, name):
    monkeypatch.setenv(name, "value-that-must-not-leak")
    monkeypatch.setenv("UNRELATED_VARIABLE", "kept")
    _, _, env = _argv_and_env(_scanner(repo), repo)
    assert name not in env
    assert env["UNRELATED_VARIABLE"] == "kept"


@pytest.mark.parametrize("name", TOKEN_VARIABLES)
def test_token_variables_are_stripped_whatever_their_case(repo, monkeypatch, name):
    """Windows environment names are case-insensitive, so ``Gh_Token`` is GH_TOKEN."""
    mixed = "_".join(part.capitalize() for part in name.split("_"))
    monkeypatch.setenv(mixed, "value-that-must-not-leak")
    _, _, env = _argv_and_env(_scanner(repo), repo)
    assert not any(key.upper() == name for key in env)


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
    for name in TOKEN_VARIABLES:
        monkeypatch.setenv(name, "token-value")
    with caplog.at_level("WARNING"):
        final_args, _, env = _argv_and_env(
            _scanner(repo, operator=operator, online_audits=True), repo
        )
    assert "--offline" in final_args
    for name in TOKEN_VARIABLES:
        assert name not in env
    assert "scanners.zizmor.options.online_audits" in caplog.text


def test_inline_ignore_comments_are_off_by_default(repo):
    """``# zizmor: ignore[...]`` in the scanned tree would drop a finding before ASH
    sees it, so it would be neither reported nor counted as suppressed."""
    final_args, _, _ = _argv_and_env(_scanner(repo), repo)
    assert "--no-ignores" in final_args[: final_args.index("--")]


def test_the_operator_may_honor_inline_ignore_comments(repo):
    final_args, _, _ = _argv_and_env(
        _scanner(repo, operator=True, honor_inline_ignores=True), repo
    )
    assert "--no-ignores" not in final_args


@pytest.mark.parametrize("operator", [False, None])
def test_inline_ignores_turned_on_from_the_scanned_tree_stay_off(
    repo, caplog, operator
):
    with caplog.at_level("WARNING"):
        final_args, _, _ = _argv_and_env(
            _scanner(repo, operator=operator, honor_inline_ignores=True), repo
        )
    assert "--no-ignores" in final_args[: final_args.index("--")]
    assert "scanners.zizmor.options.honor_inline_ignores" in caplog.text


def test_ash_offline_mode_overrides_online_audits(repo, monkeypatch):
    monkeypatch.setenv("ASH_OFFLINE", "true")
    monkeypatch.setenv("GITHUB_TOKEN", "token-value")
    final_args, _, env = _argv_and_env(
        _scanner(repo, operator=True, online_audits=True), repo
    )
    assert "--offline" in final_args
    assert "GITHUB_TOKEN" not in env


def test_the_scanners_own_offline_option_keeps_zizmor_offline(repo, monkeypatch):
    """options.offline is the per-scanner switch every scanner honors through the
    base class. zizmor consulted only ASH's global mode, so an operator who set
    online_audits and offline on this scanner got online audits and the token.
    ASH's global mode is cleared first: set in the shell, it alone would produce
    --offline and strip the token, and the scanner's own option would stay
    untested."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setenv("GH_TOKEN", "token-value")
    scanner = _scanner(repo, operator=True, online_audits=True, offline=True)
    final_args, _, env = _argv_and_env(scanner, repo)
    assert "--offline" in final_args
    assert "GH_TOKEN" not in env


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


_OUTSIDE_LINE = "first-line-of-a-file-outside-the-tree: ["


def _config_linked_out(repo: Path, shape: str) -> str:
    """A config_file value in the tree that leads to a file outside it."""
    outside = repo.parent / "outside"
    outside.mkdir()
    (outside / "creds").write_text(f"{_OUTSIDE_LINE}\n")
    if shape == "file":
        _symlink_or_skip(repo / "zizmor-ci.yml", outside / "creds")
        return "zizmor-ci.yml"
    if shape == "chain":
        _symlink_or_skip(repo / "second.yml", outside / "creds")
        _symlink_or_skip(repo / "zizmor-ci.yml", repo / "second.yml")
        return "zizmor-ci.yml"
    if shape == "dangling":
        _symlink_or_skip(repo / "zizmor-ci.yml", outside / "missing.yml")
        return "zizmor-ci.yml"
    if shape == "directory":
        _symlink_or_skip(repo / "ci", outside)
        return "ci/creds"
    (repo / "deep").mkdir()
    _symlink_or_skip(repo / "deep" / "up", outside)
    return "deep/up/creds"


@pytest.mark.parametrize(
    "shape", ["file", "chain", "dangling", "directory", "nested directory"]
)
def test_an_operator_config_file_in_the_tree_cannot_link_out_of_it(repo, shape):
    """The operator may name a config inside the scanned tree, but the tree decides
    what is at that path. zizmor quotes a config it cannot parse in its error
    (1.30.1: the first key), so a link there to a file outside the tree put a
    line of that file into ash.log and the aggregated results. zizmor is not
    run, and the scan is an error."""
    value = _config_linked_out(repo, shape)
    scanner = _scanner(repo, operator=True, config_file=value)
    with pytest.raises(ScannerError) as excinfo:
        _argv_and_env(scanner, repo)
    message = str(excinfo.value)
    assert "scanners.zizmor.options.config_file" in message
    assert "symbolic link" in message and "zizmor is not run" in message
    assert _OUTSIDE_LINE not in message
    assert (repo.parent / "outside").as_posix() not in message


def test_an_operator_config_file_in_the_tree_may_link_inside_it(repo):
    (repo / "ci").mkdir()
    (repo / "ci" / "zizmor.yml").write_text("rules: {}\n")
    _symlink_or_skip(repo / "zizmor-ci.yml", Path("ci") / "zizmor.yml")
    final_args, _, _ = _argv_and_env(
        _scanner(repo, operator=True, config_file="zizmor-ci.yml"), repo
    )
    assert f"--config={(repo / 'ci' / 'zizmor.yml').resolve().as_posix()}" in (
        final_args
    )


def test_an_operator_config_file_outside_the_tree_may_be_a_link(repo):
    """Outside the tree the operator controls both the path and the link."""
    shared = repo.parent / "shared"
    shared.mkdir()
    (shared / "zizmor.yml").write_text("rules: {}\n")
    _symlink_or_skip(repo.parent / "zizmor.yml", shared / "zizmor.yml")
    final_args, _, _ = _argv_and_env(
        _scanner(repo, operator=True, config_file="../zizmor.yml"), repo
    )
    assert f"--config={(shared / 'zizmor.yml').resolve().as_posix()}" in final_args


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
    dashed = repo / "--config=other" / "action.yml"
    dashed.parent.mkdir()
    dashed.write_text((repo / "actions/clean/action.yaml").read_text())
    final_args, _, _ = _argv_and_env(_scanner(repo), repo)
    separator = final_args.index("--")
    assert "--config=other/action.yml" in final_args[separator + 1 :]
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
    # zizmor was skipped by design, which the invocation record reads as a 0;
    # a declined run, where the tool did not run, leaves None instead.
    assert scanner.exit_code == 0


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
    # The file is the one zizmor's rejection line quotes (other/action.yml), so
    # the probe reads it and finds another tool's file, not a path it cannot
    # open (which counts as a failed target).
    source = tmp_path / "src"
    (source / "other").mkdir(parents=True)
    (source / "other" / "action.yml").write_text("tool: other\n")
    scanner = _scanner(source)
    _fake_run(scanner, stdout=None, returncode=3, stderr=NOT_AN_ACTION + NO_INPUTS)
    report = scanner.scan(source, "source", [])
    assert report.runs[0].results == []
    assert scanner.targets_attempted == 0


def test_a_non_action_whose_path_holds_a_space_is_not_counted(repo):
    """zizmor quotes the path as given; a space in it must not turn an
    inapplicable file into a failed target. The quoted file is in the tree (a
    sixth input, another tool's action.yml), so the count it leaves is the five
    real inputs, not one of them dropped for a file zizmor was never given."""
    other = repo / "my tools" / "other" / "action.yml"
    other.parent.mkdir(parents=True)
    other.write_text("tool: some-other-tool\nsteps:\n  - build\n")
    rejected = (
        " WARN collect_inputs: zizmor::registry::input: failed to validate "
        "file://my tools/other/action.yml as action: input does not match "
        "expected validation schema\n"
    )
    scanner, _ = _scan_with_output(repo, CAPTURED_SARIF.read_text(), stderr=rejected)
    assert scanner.targets_attempted == len(EXPECTED_INPUTS)
    assert scanner.targets_failed == 0


@pytest.mark.parametrize(
    "quoted",
    [".github/workflows/action.yml", "file://sub/.github/workflows/action.yaml"],
)
def test_a_workflow_rejected_as_not_an_action_is_a_failed_target(repo, quoted):
    """A file directly in .github/workflows is a workflow GitHub runs whatever its
    name. One named action.yml is handed to zizmor as a composite action and
    rejected as not an action: that is a target ASH meant to audit and could
    not, never an inapplicable file to drop from the counts. The quoted file is
    in the tree, a sixth input, so the counts include it."""
    workflow = repo / quoted.removeprefix("file://")
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text("on: push\n")
    rejected = (
        " WARN collect_inputs: zizmor::registry::input: failed to validate "
        f"{quoted} as action: input does not match expected validation schema\n"
    )
    scanner, _ = _scan_with_output(repo, CAPTURED_SARIF.read_text(), stderr=rejected)
    assert scanner.targets_attempted == len(EXPECTED_INPUTS) + 1
    assert scanner.targets_failed == 1


def test_a_rejected_workflow_is_counted_when_the_source_dir_is_the_workflows_dir(
    repo,
):
    """The source dir may itself be ``.github/workflows`` (a supported shape).
    zizmor then quotes a rejected file by its bare name, relative to that cwd:
    the name alone says nothing about where it sits, so the quoted path is read
    against the source dir, and the file counts as a failed workflow rather than
    being dropped as an inapplicable action."""
    source = repo / ".github" / "workflows"
    (source / "action.yml").write_text("on: push\n")
    rejected = (
        " WARN collect_inputs: zizmor::registry::input: failed to validate "
        "action.yml as action: input does not match expected validation schema\n"
    )
    empty_sarif = json.dumps(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "zizmor"}}, "results": []}],
        }
    )
    scanner = _scanner(source)
    _fake_run(scanner, stdout=empty_sarif, stderr=rejected)
    scanner.scan(source, "source", [])
    # clean.yml, vulnerable.yml and action.yml were collected; the rejected
    # workflow is one of the three attempted targets, and it failed, rather than
    # a target removed from the count.
    assert scanner.targets_attempted == 3
    assert scanner.targets_failed == 1


def test_exit_3_counts_every_remaining_input_as_failed(repo):
    """Exit 3 says zizmor audited nothing. When its rejection lines use words the
    parser does not read, the inputs must still count as not audited, never as
    audited with zero findings."""
    unread_wording = (
        " WARN collect_inputs: zizmor::registry::input: skipping x.yml: not a "
        "workflow\n"
    )
    scanner, report = _scan_with_output(
        repo, None, returncode=3, stderr=unread_wording + NO_INPUTS
    )
    assert report.runs[0].results == []
    assert scanner.targets_attempted == len(EXPECTED_INPUTS)
    assert scanner.targets_failed == scanner.targets_attempted


@pytest.mark.parametrize("returncode", [1, 2, 3])
def test_a_tool_failure_without_output_is_an_error_not_a_clean_scan(repo, returncode):
    """The error names the code the tool exited with. Whether the tool's own text
    is quoted depends on the code: see the two tests below."""
    scanner = _scanner(repo)
    _fake_run(scanner, stdout=None, returncode=returncode, stderr="fatal: boom\n")
    with pytest.raises(ScannerError, match=rf"\(exit code {returncode}: "):
        scanner.scan(repo, "source", [])


def test_a_tool_failure_with_an_accepted_code_quotes_the_tools_text(repo):
    """Exit 3 is in the scanner's success set, so the failure that follows it (no
    results file) is described with the tool's stderr log read."""
    scanner = _scanner(repo)
    _fake_run(scanner, stdout=None, returncode=3, stderr="fatal: boom\n")
    with pytest.raises(ScannerError) as raised:
        scanner.scan(repo, "source", [])
    message = str(raised.value)
    assert "an accepted exit code for this scanner" in message, message
    assert "boom" in message, message


@pytest.mark.parametrize("returncode", [1, 2])
def test_a_tool_failure_with_a_refused_code_names_the_log_it_did_not_read(
    repo, returncode
):
    """Exits 1 and 2 are outside the success set: the result is refused, so the
    stderr log is named in the message and not quoted."""
    scanner = _scanner(repo)
    _fake_run(scanner, stdout=None, returncode=returncode, stderr="fatal: boom\n")
    with pytest.raises(ScannerError) as raised:
        scanner.scan(repo, "source", [])
    message = str(raised.value)
    assert "not an accepted exit code" in message, message
    assert "Stderr not read" in message, message
    assert "boom" not in message, message


def test_a_previous_runs_sarif_is_never_read_as_this_runs(repo):
    scanner = _scanner(repo)
    stale = scanner.results_dir / "source" / "ZizmorScanner.stdout.log"
    stale.parent.mkdir(parents=True)
    stale.write_text(CAPTURED_SARIF.read_text())
    _fake_run(scanner, stdout=None, returncode=1, stderr="fatal: boom\n")
    with pytest.raises(ScannerError):
        scanner.scan(repo, "source", [])


def test_a_timeout_reports_the_timeout(repo):
    """The error names the scanner and the limit as the configuration guide shows
    it, ``<scanner> timed out after '1800' s``: the limit is its own quoted token,
    never ``after 5s``."""
    scanner = _scanner(repo, scan_timeout=5)

    def run(command, results_dir=None, env=None, timeout=None, **_):
        assert timeout == 5
        response = {"returncode": 124, "timed_out": True}
        scanner._process_command_response(response)
        return response

    object.__setattr__(scanner, "_run_subprocess", run)
    object.__setattr__(scanner, "validate_plugin_dependencies", lambda: True)
    with pytest.raises(ScannerError) as raised:
        scanner.scan(repo, "source", [])
    message = str(raised.value)
    assert "ZizmorScanner timed out after '5' s" in message, message
    assert "scanners.zizmor.options.scan_timeout" in message, message


def test_a_tool_that_finishes_under_the_limit_is_not_reported_as_timed_out(repo):
    """The timeout test's control: the same scanner and limit, with a tool that
    exits in time. It is handed the limit, and its report is read."""
    scanner = _scanner(repo, scan_timeout=5)
    calls = []
    _fake_run(scanner, stdout=CAPTURED_SARIF.read_text(), calls=calls)
    report = scanner.scan(repo, "source", [])
    assert _summarize(report) == EXPECTED_FINDINGS
    assert [call["timeout"] for call in calls] == [5.0]


def test_each_target_starts_from_a_clean_exit_code(repo):
    """The base class keeps the maximum exit code; one target's 3 must not leak."""
    scanner = _scanner(repo)
    scanner.exit_code = 3
    _fake_run(scanner, stdout=None, returncode=1, stderr="fatal: boom\n" + NO_INPUTS)
    with pytest.raises(ScannerError):
        scanner.scan(repo, "source", [])


def test_a_target_with_nothing_to_audit_does_not_inherit_the_previous_exit_code(
    tmp_path,
):
    """The converted target follows the source target on one instance. When it
    holds nothing zizmor audits, scan() returns before _execute_scan resets the
    exit code, so the source target's code read as the converted target's."""
    converted = tmp_path / "converted"
    (converted / "archive.zip").mkdir(parents=True)
    (converted / "archive.zip" / "app.py").write_text("print(1)\n")
    source = tmp_path / "src"
    source.mkdir()
    scanner = _scanner(source)
    _fake_run(scanner, stdout="never read")
    scanner.exit_code = 3

    report = scanner.scan(converted, "converted", [])

    assert report.runs[0].results == []
    assert scanner.targets_attempted == 0
    assert scanner.exit_code == 0


def test_a_target_with_nothing_to_audit_does_not_inherit_the_previous_timing(
    tmp_path,
):
    """The same early return skips the template's per-target reset of the
    times and the stream lines: the source target's start paired with the
    converted target's end, and its stderr lines led this target's record."""
    converted = tmp_path / "converted"
    converted.mkdir()
    (converted / "app.py").write_text("print(1)\n")
    source = tmp_path / "src"
    source.mkdir()
    scanner = _scanner(source)
    _fake_run(scanner, stdout="never read")
    earlier = datetime(2000, 1, 1, tzinfo=timezone.utc)
    scanner.start_time = earlier
    scanner.end_time = earlier
    scanner.errors = ["the source target's stderr"]
    scanner.output = ["the source target's stdout"]

    scanner.scan(converted, "converted", [])

    assert scanner.start_time is not None and scanner.start_time != earlier
    assert scanner.end_time is not None and scanner.end_time >= scanner.start_time
    assert "the source target's stderr" not in scanner.errors
    assert scanner.output == []


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


def test_a_satisfying_binary_on_path_clears_a_stale_unavailable_reason(
    repo, monkeypatch
):
    """An earlier check recorded why zizmor was unavailable; a satisfying binary
    on PATH now answers the check, and the stale reason goes with it, so the
    scanner never reads as satisfied and unavailable at once."""
    _with_executable(monkeypatch, "zizmor 1.29.0\n")
    scanner = _scanner(repo)
    scanner.dependency_unavailable_reason = "zizmor is not available: none was found"

    assert scanner.validate_plugin_dependencies() is True

    assert scanner.dependencies_satisfied is True
    assert scanner.dependency_unavailable_reason is None


def test_a_satisfying_binary_on_path_is_checked_before_the_uv_probe(repo, monkeypatch):
    """The docstring's order: a zizmor on PATH that satisfies the constraint runs
    directly, and the uv probe the construction deferred is not owed then. Sent
    first, the probe started uv for nothing, and a probe that is refused or
    fails could decide the check before PATH was ever looked at."""
    _with_executable(monkeypatch, "zizmor 1.29.0\n")

    def must_not_run(self, *_):
        raise AssertionError("the uv probe ran although PATH satisfies")

    monkeypatch.setattr(ZizmorScanner, "_get_uv_tool_version", must_not_run)
    scanner = _scanner(repo)
    assert scanner._deferred_tool_version_probe is not None

    assert scanner.validate_plugin_dependencies() is True

    assert scanner.tool_version == "1.29.0"
    assert scanner._deferred_tool_version_probe is None
    # Nothing left for the SARIF step or the inventory to run, so the version the
    # binary reported stands.
    scanner.resolve_deferred_tool_version()
    assert scanner.tool_version == "1.29.0"


def test_without_a_binary_on_path_the_deferred_probe_runs_for_the_uv_route(
    repo, monkeypatch
):
    monkeypatch.setattr(zizmor_module, "find_executable", lambda _: None)
    probed = []
    monkeypatch.setattr(
        ZizmorScanner,
        "_get_uv_tool_version",
        lambda self, *args: probed.append(args) or "1.30.1",
    )
    scanner = _scanner(repo)
    object.__setattr__(scanner, "_resolve_through_uv", lambda *_: True)

    assert scanner.validate_plugin_dependencies() is True

    assert len(probed) == 1
    assert scanner.tool_version == "1.30.1"
    assert scanner._deferred_tool_version_probe is None


def test_a_scanner_already_missing_does_not_start_the_uv_probe(repo, monkeypatch):
    """A scanner whose dependency check already recorded MISSING keeps that
    answer without a uv call: probed first, the deferred version probe started uv
    for a tool the check was about to refuse anyway."""
    monkeypatch.setattr(zizmor_module, "find_executable", lambda _: None)

    def must_not_run(self, *_):
        raise AssertionError("the uv probe ran for a scanner already MISSING")

    monkeypatch.setattr(ZizmorScanner, "_get_uv_tool_version", must_not_run)
    scanner = _scanner(repo)
    assert scanner._deferred_tool_version_probe is not None
    scanner.dependency_unavailable_reason = "zizmor is not available: uv refused"

    def must_not_resolve():
        raise AssertionError("the uv route ran for a scanner already MISSING")

    object.__setattr__(scanner, "_resolve_through_uv", must_not_resolve)

    assert scanner.validate_plugin_dependencies() is False

    assert scanner.dependency_unavailable_reason == (
        "zizmor is not available: uv refused"
    )


@pytest.mark.parametrize("output", ["zizmor 1.28.0\n", "zizmor 2.0.0\n", "garbage\n"])
def test_an_unsatisfying_binary_offline_is_missing_with_a_reason(
    repo, monkeypatch, output
):
    monkeypatch.setenv("ASH_OFFLINE", "true")
    _with_executable(monkeypatch, output)
    scanner = _scanner(repo)
    object.__setattr__(scanner, "_resolve_through_uv", lambda *_: False)
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
    object.__setattr__(scanner, "_resolve_through_uv", lambda *_: True)
    assert scanner.validate_plugin_dependencies() is True


def test_offline_without_any_zizmor_does_not_try_to_install(repo, monkeypatch):
    monkeypatch.setenv("ASH_OFFLINE", "true")
    monkeypatch.setattr(zizmor_module, "find_executable", lambda _: None)
    scanner = _scanner(repo)
    _constrained_probe_answers(scanner, None)
    object.__setattr__(scanner, "_validate_uv_tool_availability", lambda: True)
    object.__setattr__(
        scanner, "_get_tool_installation_info", lambda: {"available": False}
    )

    def refuse(**_):
        raise AssertionError("must not install offline")

    object.__setattr__(scanner, "_install_uv_tool", refuse)
    assert scanner.validate_plugin_dependencies() is False
    assert "no zizmor executable was found" in scanner.dependency_unavailable_reason


def test_the_scanners_own_offline_option_does_not_install_either(repo, monkeypatch):
    """One offline reading for the class, the scanner's own (_scanner_offline):
    ASH online, this scanner's options.offline true. The uv route installs
    nothing and the MISSING reason says "while offline", as under ASH_OFFLINE."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setattr(zizmor_module, "find_executable", lambda _: None)
    scanner = _scanner(repo, operator=True, offline=True)
    _constrained_probe_answers(scanner, None)
    object.__setattr__(scanner, "_validate_uv_tool_availability", lambda: True)
    object.__setattr__(
        scanner, "_get_tool_installation_info", lambda: {"available": False}
    )

    def refuse(**_):
        raise AssertionError("must not install when the scanner is offline")

    object.__setattr__(scanner, "_install_uv_tool", refuse)
    assert scanner.validate_plugin_dependencies() is False
    assert "while offline" in scanner.dependency_unavailable_reason


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
        " @ file:///tmp/other",
        "@ git+https://example.invalid/other.git",
        "[extra]>=1",
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


# --------------------------------------------------------------------------- #
# The version probe, the uv route, the inputs and the report's logical paths
# --------------------------------------------------------------------------- #


def test_the_version_probe_keeps_a_prerelease_suffix(repo, monkeypatch):
    """A pre-release zizmor is not the release it precedes: the probe keeps the
    suffix, and version_satisfies then answers "cannot verify" rather than
    accepting 1.30.0-rc.1 as 1.30.0."""
    _with_executable(monkeypatch, "zizmor 1.30.0-rc.1\n")
    scanner = _scanner(repo)

    version = scanner._probe_executable_version("/opt/bin/zizmor")

    assert version == "1.30.0-rc.1"
    assert version_satisfies(version, ZIZMOR_DEFAULT_VERSION_CONSTRAINT) is None


def _constrained_probe_answers(scanner, version):
    """What the constrained version probe (``uv tool run --from <requirement>
    zizmor --version``) answers for this scanner: a version, or None when uv
    resolved nothing. The autouse fixture answers 1.30.1 for every scanner."""
    object.__setattr__(scanner, "_get_uv_tool_version", lambda *_, **__: version)


def _rejected_on_path_with_uv_available(repo, monkeypatch, source):
    """A zizmor on PATH the version check rejects, and a uv runner that reports
    the tool available from *source*; selecting that answer unprobed is a test
    failure, since the runner's answer may be the rejected binary itself."""
    _with_executable(monkeypatch, "zizmor 1.28.0\n")
    scanner = _scanner(repo)
    object.__setattr__(scanner, "_validate_uv_tool_availability", lambda: True)
    object.__setattr__(
        scanner,
        "_get_tool_installation_info",
        lambda: {
            "available": True,
            "preferred_source": source,
            "pre_installed_path": "/opt/bin/zizmor",
        },
    )

    def must_not_select(info):
        raise AssertionError("the runner's answer was selected unprobed")

    def must_not_install(**_):
        raise AssertionError("uv installed although the probe's release satisfies")

    object.__setattr__(scanner, "_select_tool_execution", must_not_select)
    object.__setattr__(scanner, "_install_uv_tool", must_not_install)
    return scanner


@pytest.mark.parametrize("offline", [True, False], ids=["offline", "online"])
@pytest.mark.parametrize("source", ["pre_installed", "uv"])
def test_a_satisfying_release_the_probe_resolved_runs_through_uv(
    repo, monkeypatch, offline, source
):
    """An old zizmor earlier on PATH and the right release installed through uv:
    the constrained probe resolves the right one, so the uv route is accepted
    and runs it, offline and online alike, with nothing installed. Refusing
    every uv answer once the PATH binary was rejected read this machine as
    MISSING offline and installed on every check online."""
    if offline:
        monkeypatch.setenv("ASH_OFFLINE", "true")
    else:
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
    scanner = _rejected_on_path_with_uv_available(repo, monkeypatch, source)
    _constrained_probe_answers(scanner, "1.30.1")

    assert scanner.validate_plugin_dependencies() is True

    assert scanner.dependencies_satisfied is True
    assert scanner.use_uv_tool is True
    assert scanner.tool_version == "1.30.1"
    assert scanner.dependency_unavailable_reason is None


def test_a_release_the_probe_resolved_that_does_not_satisfy_is_not_accepted(
    repo, monkeypatch
):
    """The probe's own answer is held to the constraint too: a uv route that
    resolves an old release is no better than the rejected binary."""
    monkeypatch.setenv("ASH_OFFLINE", "true")
    scanner = _rejected_on_path_with_uv_available(repo, monkeypatch, "uv")
    _constrained_probe_answers(scanner, "1.28.0")

    assert scanner.validate_plugin_dependencies() is False
    assert scanner.dependencies_satisfied is False
    assert "does not satisfy" in scanner.dependency_unavailable_reason


def test_a_probe_that_resolves_a_release_spares_the_install(repo, monkeypatch):
    """No zizmor on PATH and none the runner lists, but the constrained probe
    resolves the release from uv's cache: that is the uv route, and installing
    first would spend a network round trip on what uv already has."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setattr(zizmor_module, "find_executable", lambda _: None)
    scanner = _scanner(repo)
    _constrained_probe_answers(scanner, "1.30.1")
    object.__setattr__(scanner, "_validate_uv_tool_availability", lambda: True)
    object.__setattr__(
        scanner,
        "_get_tool_installation_info",
        lambda: {"available": False, "preferred_source": "none"},
    )

    def must_not_install(**_):
        raise AssertionError("uv installed although the probe's release satisfies")

    object.__setattr__(scanner, "_install_uv_tool", must_not_install)

    assert scanner.validate_plugin_dependencies() is True
    assert scanner.use_uv_tool is True


def test_an_earlier_checks_path_version_is_not_read_as_the_probes_answer(
    repo, monkeypatch
):
    """The first check found a satisfying zizmor on PATH and recorded its version;
    by the second check that binary reports an old release and the probe
    resolves nothing. The version the first check recorded is not the probe's
    answer, so the second check is MISSING, not satisfied by a stale number."""
    monkeypatch.setenv("ASH_OFFLINE", "true")
    _with_executable(monkeypatch, "zizmor 1.29.0\n")
    scanner = _scanner(repo)
    _constrained_probe_answers(scanner, None)
    assert scanner.validate_plugin_dependencies() is True
    assert scanner.tool_version == "1.29.0"

    _with_executable(monkeypatch, "zizmor 1.28.0\n")
    object.__setattr__(scanner, "_validate_uv_tool_availability", lambda: True)
    object.__setattr__(
        scanner,
        "_get_tool_installation_info",
        lambda: {"available": False, "preferred_source": "none"},
    )

    assert scanner.validate_plugin_dependencies() is False
    assert scanner.dependencies_satisfied is False
    assert "does not satisfy" in scanner.dependency_unavailable_reason


@pytest.mark.parametrize("source", ["pre_installed", "uv"])
def test_a_rejected_path_binary_is_not_handed_back_through_uv_offline(
    repo, monkeypatch, source
):
    """Offline, the only zizmor the uv runner sees on PATH is the one the version
    probe just rejected, and the constrained probe resolves nothing, so the
    scanner is MISSING with the probe's reason, never run to fail later. The
    runner may report that binary as pre-installed or, when it is a uv tool
    install's own shim, as the uv source; whatever the source, a rejected
    zizmor is never selected unprobed."""
    monkeypatch.setenv("ASH_OFFLINE", "true")
    scanner = _rejected_on_path_with_uv_available(repo, monkeypatch, source)
    _constrained_probe_answers(scanner, None)

    assert scanner.validate_plugin_dependencies() is False
    assert scanner.dependencies_satisfied is False
    assert "does not satisfy" in scanner.dependency_unavailable_reason


@pytest.mark.parametrize(
    ("resolved", "satisfies"),
    [
        (["/opt/bin/zizmor"], False),
        (["uv", "tool", "run", "zizmor"], True),
        (["/opt/uv/bin/uv", "tool", "run", "zizmor"], True),
        (["C:\\Users\\me\\.local\\bin\\uv.exe", "tool", "run", "zizmor"], True),
        (["UV.EXE", "tool", "run", "zizmor"], True),
    ],
    ids=["bare-binary", "uv-bare", "uv-absolute", "uv-windows", "uv-upper-case"],
)
def test_after_a_failed_install_only_a_uv_route_the_probe_resolves_satisfies(
    repo, monkeypatch, resolved, satisfies
):
    """After the constrained install fails, a zizmor the resolver finds by name
    would be the PATH binary the probe rejected: the dependency is MISSING,
    not satisfied. The one answer that still counts is uv's own route (the
    release resolved from uv's cache), whatever name the resolver found uv
    under: a bare word, an absolute path, or uv.exe. Comparing the argv text
    with the bare word refused the others."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    _with_executable(monkeypatch, "zizmor 1.28.0\n")
    scanner = _scanner(repo)
    _constrained_probe_answers(scanner, None)
    object.__setattr__(scanner, "_validate_uv_tool_availability", lambda: True)
    object.__setattr__(
        scanner,
        "_get_tool_installation_info",
        lambda: {"available": False, "preferred_source": "none"},
    )
    object.__setattr__(scanner, "_install_uv_tool", lambda **_: False)
    monkeypatch.setattr(
        zizmor_module, "get_uv_tool_command", lambda *args, **kwargs: resolved
    )

    assert scanner.validate_plugin_dependencies() is satisfies
    assert scanner.dependencies_satisfied is satisfies
    if not satisfies:
        assert "could not provide" in scanner.dependency_unavailable_reason


@pytest.mark.parametrize(
    "command",
    [
        ["/opt/bin/zizmor"],
        ["/opt/uv/bin/uv", "tool", "install", "zizmor"],
        ["/opt/uv/bin/uv", "tool"],
        ["/opt/tools/uv-wrapper", "tool", "run", "zizmor"],
        [],
        None,
    ],
    ids=["bare-binary", "other-verb", "short", "other-name", "empty", "none"],
)
def test_a_command_that_is_not_a_uv_route_is_read_as_none(command):
    assert zizmor_module._is_a_uv_route(command) is False


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX named pipes")
def test_a_named_pipe_named_like_an_action_is_skipped_without_blocking(repo, caplog):
    """Reading a FIFO blocks until a writer appears, outside any scan timeout,
    for ASH's own probes and for zizmor. Only a regular file is an input. The
    writer thread makes a read that does happen return instead of hanging the
    test: a collection that reads the pipe then lists it, which the assertion
    catches."""
    pipe = repo / "pipes" / "action.yml"
    pipe.parent.mkdir()
    os.mkfifo(pipe)
    done = threading.Event()

    def feed():
        # Serve every open for reading until released: a collection that opens
        # the pipe twice (a sniff, then a content read) then fails on the
        # listing instead of hanging the run on the second open.
        while not done.is_set():
            with open(pipe, "w") as writer:
                writer.write("name: x\nruns:\n  using: composite\n  steps: []\n")

    writer_thread = threading.Thread(target=feed, daemon=True)
    writer_thread.start()
    try:
        scanner = _scanner(repo)

        with caplog.at_level(logging.WARNING):
            inputs = _relative(scanner._collect_inputs(repo, "source", []), repo)

        assert inputs == EXPECTED_INPUTS
        assert "Not auditing pipes/action.yml" in caplog.text
        assert "not a regular file" in caplog.text
    finally:
        # Release the writer: when the collection behaves it never opens the
        # pipe, and the thread would otherwise stay blocked in open() for the
        # rest of the session.
        done.set()
        reader = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK)
        try:
            writer_thread.join(timeout=5)
        finally:
            os.close(reader)
        assert not writer_thread.is_alive()


def test_a_link_whose_target_cannot_be_stated_is_skipped_not_raised(
    repo, monkeypatch, caplog
):
    """A link whose target sits in a directory this user cannot search cannot be
    stat'ed through: before Python 3.13 Path.is_file() raises PermissionError
    there instead of answering. One such input must not end the collection.
    The denial is real (the target directory is made unsearchable), so the
    test holds whichever stat call the probe makes."""
    if os.name == "nt" or getattr(os, "geteuid", lambda: 1)() == 0:
        pytest.skip("directory modes do not deny this user")
    link = repo / "linked" / "action.yml"
    link.parent.mkdir()
    target_dir = repo / "actions" / "greet"
    _symlink_or_skip(link, target_dir / "action.yml")
    kept = repo / "actions" / "clean" / "action.yaml"
    monkeypatch.setattr(
        zizmor_module, "scan_set", lambda **kwargs: [str(link), str(kept)]
    )
    scanner = _scanner(repo)
    target_dir.chmod(0o000)
    try:
        with caplog.at_level(logging.WARNING):
            inputs = _relative(scanner._collect_inputs(repo, "source", []), repo)
    finally:
        target_dir.chmod(0o755)

    assert inputs == ["actions/clean/action.yaml"]
    assert "Not auditing linked/action.yml" in caplog.text


def test_an_action_under_a_vendored_directory_is_named_in_the_debug_log(repo, caplog):
    scanner = _scanner(repo)

    with caplog.at_level(logging.DEBUG, logger=ASH_LOGGER.name):
        inputs = _relative(scanner._collect_inputs(repo, "source", []), repo)

    assert "node_modules/vendored-action/action.yml" not in inputs
    assert "node_modules/vendored-action/action.yml" in caplog.text


def test_a_file_written_as_an_action_that_zizmor_rejects_is_a_failed_target(repo):
    """zizmor words a schema rejection of a real composite action like the
    rejection of another tool's action.yml; the file itself tells them apart
    (an action has a top-level ``runs`` key), and a real action ASH meant to
    audit and could not is a failed target, not an inapplicable file."""
    broken = repo / "broken" / "action.yml"
    broken.parent.mkdir()
    broken.write_text("name: broken\nruns:\n  using: nothing-zizmor-knows\n")
    rejected = (
        " WARN collect_inputs: zizmor::registry::input: failed to validate "
        "file://broken/action.yml as action: input does not match expected "
        "validation schema\n"
    )

    scanner, _ = _scan_with_output(repo, CAPTURED_SARIF.read_text(), stderr=rejected)

    assert scanner.targets_attempted == len(EXPECTED_INPUTS) + 1
    assert scanner.targets_failed == 1


_REJECTED_BROKEN_ACTION = (
    " WARN collect_inputs: zizmor::registry::input: failed to validate "
    "file://broken/action.yml as action: input does not match expected "
    "validation schema\n"
)


def _rejected_action_counts(repo, monkeypatch, body: bytes, limit=None):
    """zizmor rejected ``broken/action.yml`` holding *body*; what the counters say."""
    broken = repo / "broken" / "action.yml"
    broken.parent.mkdir()
    broken.write_bytes(body)
    if limit is not None:
        monkeypatch.setattr(zizmor_module, "_ACTION_PROBE_LIMIT", limit)
    scanner, _ = _scan_with_output(
        repo, CAPTURED_SARIF.read_text(), stderr=_REJECTED_BROKEN_ACTION
    )
    return scanner.targets_attempted, scanner.targets_failed


def test_an_action_longer_than_the_probe_reads_is_a_failed_target(repo, monkeypatch):
    """A real action whose "runs" key sits past the read limit: the partial
    text parses as a mapping without it, or does not parse at all. Either way
    the file was not read whole, so it is not written off as inapplicable."""
    body = b"name: broken\ndescription: " + b"x" * 64 + b"\nruns:\n  using: node20\n"

    attempted, failed = _rejected_action_counts(repo, monkeypatch, body, limit=48)

    assert (attempted, failed) == (len(EXPECTED_INPUTS) + 1, 1)


def test_a_cut_off_action_whose_runs_key_was_read_is_a_failed_target(repo, monkeypatch):
    """The read stopped inside the document, but the "runs" key is in the part
    that was read: an action, and a failed target."""
    body = b"runs:\n  using: composite\n  steps:\n" + b"    - run: echo\n" * 40

    attempted, failed = _rejected_action_counts(repo, monkeypatch, body, limit=48)

    assert (attempted, failed) == (len(EXPECTED_INPUTS) + 1, 1)


def test_an_action_the_safe_loader_refuses_is_a_failed_target(repo, monkeypatch):
    """PyYAML's safe loader refuses an unknown tag that zizmor's parser read; the
    raw text still shows the action's "runs" key, so the file is an action ASH
    meant to audit and could not, not another tool's file."""
    body = b"name: !custom broken\nruns:\n  using: composite\n  steps: []\n"

    attempted, failed = _rejected_action_counts(repo, monkeypatch, body)

    assert (attempted, failed) == (len(EXPECTED_INPUTS) + 1, 1)


def test_a_rejected_file_that_cannot_be_read_is_a_failed_target(repo, monkeypatch):
    """A rejection line that names no input of the run (here, the quoted path
    names no file zizmor was given) is not known to be another tool's file: fail
    closed, one failed target, and nothing is opened on its account. The
    attempted count stays the inputs zizmor was given; a quoted path that was
    never an input adds nothing to it."""
    scanner, _ = _scan_with_output(
        repo, CAPTURED_SARIF.read_text(), stderr=_REJECTED_BROKEN_ACTION
    )

    assert scanner.targets_attempted == len(EXPECTED_INPUTS)
    assert scanner.targets_failed == 1


def test_a_rejection_line_is_matched_to_an_input_never_read_as_a_path(
    repo, monkeypatch
):
    """zizmor rejected an action under a directory whose name holds the words
    " as action ", so a lazy read of the path out of the line ended at `x` and
    opened <source>/x, whatever that was (a committed link to a FIFO blocked the
    scan). The line is matched against the run's inputs instead: the action
    under that directory is the input it names, read whole as another tool's
    file and dropped from the attempted count, and <source>/x is never opened."""
    other = repo / "x as action y" / "action.yml"
    other.parent.mkdir()
    other.write_text("tool: other\n")
    decoy = repo / "x"
    decoy.write_text("never read\n")
    opened: list = []
    real_read = zizmor_module.read_bytes_at_most

    def recording_read(path, limit):
        opened.append(Path(path))
        return real_read(path, limit)

    monkeypatch.setattr(zizmor_module, "read_bytes_at_most", recording_read)
    rejected = (
        " WARN collect_inputs: zizmor::registry::input: failed to validate "
        "file://x as action y/action.yml as action: input does not match "
        "expected validation schema\n"
    )

    scanner, _ = _scan_with_output(repo, CAPTURED_SARIF.read_text(), stderr=rejected)

    assert scanner.targets_attempted == len(EXPECTED_INPUTS)
    assert scanner.targets_failed == 0
    assert decoy.resolve() not in {path.resolve() for path in opened}
    assert other.resolve() in {path.resolve() for path in opened}


def test_the_rejected_input_is_the_longest_argument_the_line_names(repo):
    """Matched against the run's arguments spelled with and without the file://
    prefix, the longest first; a line that names none is None."""
    scanner = _scanner(repo)
    short = repo / "x"
    long = repo / "x as action y" / "action.yml"
    scanner._last_inputs = [short, long]
    line = "failed to validate file://x as action y/action.yml as action: schema"

    assert scanner._rejected_input_named(line) == long
    assert scanner._rejected_input_named("failed to validate x as action: s") == short
    assert scanner._rejected_input_named("failed to validate x as actions") is None
    assert scanner._rejected_input_named("failed to validate other as action") is None


def test_another_tools_file_read_whole_is_still_inapplicable(repo, monkeypatch):
    """The decision the probe exists for: a file named action.yml that parses
    whole as something without a top-level "runs" key is dropped from the
    attempted count, not counted as failed."""
    body = b"name: broken\nversion: 2\nsteps:\n  - run: echo\n"

    attempted, failed = _rejected_action_counts(repo, monkeypatch, body)

    assert (attempted, failed) == (len(EXPECTED_INPUTS), 0)


@pytest.mark.parametrize(
    ("body", "answer"),
    [
        (b"name: x\nruns:\n  using: composite\n", True),
        (b"name: x\nsteps: []\n", False),
        (b"- a\n- b\n", False),
        (b"name: !custom x\nruns:\n  using: composite\n", True),
        (b"name: !custom x\nsteps: []\n", None),
        (b"", False),
    ],
    ids=[
        "action",
        "other-mapping",
        "sequence",
        "tagged-action",
        "tagged-other",
        "empty",
    ],
)
def test_the_action_probe_answers_in_three_ways(tmp_path, body, answer):
    path = tmp_path / "action.yml"
    path.write_bytes(body)
    assert zizmor_module._declares_a_github_action(path) is answer


def test_the_action_probe_cannot_decide_what_it_could_not_read(tmp_path):
    assert zizmor_module._declares_a_github_action(tmp_path / "missing.yml") is None
    assert zizmor_module._declares_a_github_action(tmp_path) is None


def test_a_converted_inputs_absolute_path_does_not_stay_in_the_logical_location(
    repo,
):
    """A converted input is passed by absolute path, which zizmor copies into
    the logical-location properties ASH's sanitizer does not rewrite; after the
    URI is rebased the property is made relative to the target."""
    scanner = _scanner(repo)
    converted = repo / ".ash" / "ash_output" / "converted"
    action = converted / "x" / "action.yml"
    action.parent.mkdir(parents=True)
    action.write_text("name: x\nruns:\n  using: composite\n  steps: []\n")
    scanner._last_inputs = [action]
    report = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "zizmor"}},
                    "results": [
                        {
                            "ruleId": "zizmor/x",
                            "level": "warning",
                            "message": {"text": "m"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "x/action.yml"},
                                        "region": {"startLine": 1},
                                    },
                                    "logicalLocations": [
                                        {
                                            "properties": {
                                                "symbolic": {
                                                    "key": {
                                                        "Local": {
                                                            "verbatim_path": str(action)
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )

    out = scanner._post_process_sarif(report, [], converted)

    logical = out.runs[0].results[0].locations[0].logicalLocations[0]
    local = logical.properties.model_extra["symbolic"]["key"]["Local"]
    assert local["verbatim_path"] == "x/action.yml"
    assert str(repo) not in json.dumps(local)


def test_many_inputs_are_audited_in_several_runs_and_one_report(repo, monkeypatch):
    """A tree with more inputs than one command line holds is audited in several
    zizmor runs; the counters are summed and the findings joined. Each run
    answers with the findings of its own inputs only, so the joined report must
    hold every expected finding exactly once, rebased and joined per batch."""
    monkeypatch.setattr(zizmor_module, "_INPUT_ARGV_BUDGET", _ONE_INPUT_PER_BATCH)
    scanner = _scanner(repo)
    calls = _fake_runs_per_batch(scanner, CAPTURED_SARIF.read_text())

    report = scanner.scan(repo, "source", [])

    inputs_per_call = [
        call["command"][call["command"].index("--") + 1 :] for call in calls
    ]
    assert inputs_per_call == [[path] for path in EXPECTED_INPUTS]
    assert scanner.targets_attempted == len(EXPECTED_INPUTS)
    assert scanner.targets_failed == 0
    assert sorted(_summarize(report)) == EXPECTED_FINDINGS


#: An argv budget that puts one input per batch for every fixture input, clear of
#: the 24+16 boundary two adjacent inputs' lengths add up to, whether or not a
#: separator byte is counted.
_ONE_INPUT_PER_BATCH = 36


def _fake_runs_per_batch(scanner, sarif_text: str) -> list:
    """Like ``_fake_run``, answering each run with the captured SARIF reduced to
    the results whose file is among that run's inputs (the arguments after
    ``--``); returns the recorded calls."""
    calls: list = []
    whole = json.loads(sarif_text)

    def run(command, results_dir=None, env=None, timeout=None, **_):
        calls.append({"command": list(command), "env": env, "timeout": timeout})
        inputs = set(command[command.index("--") + 1 :])
        part = copy.deepcopy(whole)
        part["runs"][0]["results"] = [
            result
            for result in whole["runs"][0]["results"]
            if result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            in inputs
        ]
        name = scanner.__class__.__name__
        Path(results_dir, f"{name}.stdout.log").write_text(json.dumps(part))
        response = {"returncode": 0}
        scanner._process_command_response(response)
        return response

    object.__setattr__(scanner, "_run_subprocess", run)
    object.__setattr__(scanner, "validate_plugin_dependencies", lambda: True)
    return calls


def _fake_runs(scanner, stdouts: list) -> list:
    """Like ``_fake_run``, with one stdout per run (the last one repeats);
    returns the recorded calls."""
    calls: list = []
    remaining = list(stdouts)

    def run(command, results_dir=None, env=None, timeout=None, **_):
        calls.append({"command": list(command), "env": env, "timeout": timeout})
        stdout = remaining.pop(0) if len(remaining) > 1 else remaining[0]
        name = scanner.__class__.__name__
        Path(results_dir, f"{name}.stdout.log").write_text(stdout)
        response = {"returncode": 0}
        scanner._process_command_response(response)
        return response

    object.__setattr__(scanner, "_run_subprocess", run)
    object.__setattr__(scanner, "validate_plugin_dependencies", lambda: True)
    return calls


def _later_batch_sarif() -> str:
    """The captured SARIF with one rule renamed, so it fires only in a later
    batch, every result carrying its rule's index in THIS report's rules array,
    and an invocation that names the batch."""
    data = json.loads(CAPTURED_SARIF.read_text())
    run = data["runs"][0]
    renamed = "zizmor/only-in-a-later-batch"
    for rule in run["tool"]["driver"]["rules"]:
        if rule["id"] == "zizmor/artipacked":
            rule["id"] = renamed
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    for result in run["results"]:
        if result["ruleId"] == "zizmor/artipacked":
            result["ruleId"] = renamed
        result["ruleIndex"] = rule_ids.index(result["ruleId"])
    run["invocations"] = [{"executionSuccessful": True, "commandLine": "later"}]
    return json.dumps(data)


def test_a_joined_report_carries_every_batchs_rules_and_invocations(repo, monkeypatch):
    """A rule that fires only in a later batch keeps its descriptor (help URI,
    description) in the joined report, each rule id appears once, the
    invocations of every run are kept in order (one per batch: the base class
    records each run's own argv as that run's invocation, replacing whatever
    the tool wrote), and a result's ruleIndex points at its rule in the merged
    list, not into the batch's own array."""
    monkeypatch.setattr(zizmor_module, "_INPUT_ARGV_BUDGET", _ONE_INPUT_PER_BATCH)
    scanner = _scanner(repo)
    calls = _fake_runs(scanner, [CAPTURED_SARIF.read_text(), _later_batch_sarif()])

    report = scanner.scan(repo, "source", [])

    run = report.runs[0]
    assert len(calls) == len(EXPECTED_INPUTS) >= 2
    rule_ids = [rule.id for rule in run.tool.driver.rules]
    assert len(rule_ids) == len(set(rule_ids))
    assert "zizmor/artipacked" in rule_ids
    assert "zizmor/only-in-a-later-batch" in rule_ids
    assert {result.ruleId for result in run.results} <= set(rule_ids)
    indexed = [result for result in run.results if result.ruleIndex >= 0]
    assert indexed, "the later batch's results carried a ruleIndex"
    for result in indexed:
        assert run.tool.driver.rules[result.ruleIndex].id == result.ruleId
    assert len(run.invocations) == len(calls)
    assert [
        invocation.commandLine.rsplit(" -- ", 1)[-1] for invocation in run.invocations
    ] == EXPECTED_INPUTS
    assert len(run.results) == len(EXPECTED_INPUTS) * len(EXPECTED_FINDINGS)


def test_a_run_declined_after_earlier_batches_keeps_their_counters(repo, monkeypatch):
    """When the template declines a later batch (its dependency check says no),
    the scan's answer is that refusal, and the counters account for every
    input: the two the earlier batches audited, and the three the declined
    batch and the ones after it never ran, counted as attempted and failed so
    no reader sees "two audited, nothing found" beside the refusal."""
    monkeypatch.setattr(zizmor_module, "_INPUT_ARGV_BUDGET", _ONE_INPUT_PER_BATCH)
    scanner = _scanner(repo)
    _fake_run(scanner, stdout=CAPTURED_SARIF.read_text())
    checks: list = []

    def dependencies_until_the_third_batch() -> bool:
        checks.append(len(checks))
        return len(checks) < 3

    object.__setattr__(
        scanner, "validate_plugin_dependencies", dependencies_until_the_third_batch
    )

    result = scanner.scan(repo, "source", [])

    assert result is False
    assert len(checks) == 3
    assert scanner.targets_attempted == len(EXPECTED_INPUTS)
    assert scanner.targets_failed == len(EXPECTED_INPUTS) - 2
    assert scanner.exit_code == 0


def test_batches_that_all_declined_leave_no_exit_code(repo, monkeypatch):
    """The template declined the first batch, so zizmor never ran: the exit
    code stays None, the base class's "the tool did not run", not a 0 that
    reads as a clean run, and every input counts as attempted and failed."""
    monkeypatch.setattr(zizmor_module, "_INPUT_ARGV_BUDGET", _ONE_INPUT_PER_BATCH)
    scanner = _scanner(repo)
    _fake_run(scanner, stdout=CAPTURED_SARIF.read_text())
    object.__setattr__(scanner, "validate_plugin_dependencies", lambda: False)

    result = scanner.scan(repo, "source", [])

    assert result is False
    assert scanner.targets_attempted == len(EXPECTED_INPUTS)
    assert scanner.targets_failed == len(EXPECTED_INPUTS)
    assert scanner.exit_code is None


def _fake_runs_with_codes(scanner, stdout: str, returncodes: list, stderrs=None):
    """Like ``_fake_runs``, one return code (and stderr text) per run in order,
    the last repeating, every run answered with *stdout*; the response carries
    the stderr text too, so it reaches the scanner's own record as the real
    runner's does. Returns the recorded calls and the start_time the template
    had set when each run began."""
    calls: list = []
    starts: list = []
    codes = list(returncodes)
    texts = list(stderrs or [""])

    def run(command, results_dir=None, env=None, timeout=None, **_):
        calls.append({"command": list(command), "env": env, "timeout": timeout})
        starts.append(scanner.start_time)
        code = codes.pop(0) if len(codes) > 1 else codes[0]
        text = texts.pop(0) if len(texts) > 1 else texts[0]
        name = scanner.__class__.__name__
        Path(results_dir, f"{name}.stdout.log").write_text(stdout)
        if text:
            Path(results_dir, f"{name}.stderr.log").write_text(text)
        response = {"returncode": code, "stderr": text}
        scanner._process_command_response(response)
        return response

    object.__setattr__(scanner, "_run_subprocess", run)
    object.__setattr__(scanner, "validate_plugin_dependencies", lambda: True)
    return calls, starts


def test_batch_exit_codes_are_folded_by_the_scanners_own_ranking(repo, monkeypatch):
    """The fold is the scanner's _worse_exit_code, which ranks by its accepted
    codes {0, 3}: a code outside the set outranks an accepted one in either
    order, a signal death outranks every code and is recorded as the shell
    reports it, and None leaves the fold alone. The module-level fold, a plain
    max, read 3 above 1. Only accepted codes reach the fold today (the template
    refuses a batch outside the set before its report is read), so the scan
    below proves the mechanism: every batch's code is folded through the
    scanner's own hook, with the codes the batches returned."""
    scanner = _scanner(repo)
    assert scanner._worse_exit_code(None, 3) == 3
    assert scanner._worse_exit_code(0, 3) == 3
    assert scanner._worse_exit_code(3, 1) == 1
    assert scanner._worse_exit_code(1, 3) == 1
    assert scanner._worse_exit_code(1, -11) == 139
    assert scanner._worse_exit_code(139, 3) == 139

    monkeypatch.setattr(zizmor_module, "_INPUT_ARGV_BUDGET", _ONE_INPUT_PER_BATCH)
    calls, _ = _fake_runs_with_codes(scanner, CAPTURED_SARIF.read_text(), [3, 0, 3])
    folded: list = []

    def recording_fold(current, new):
        folded.append((current, new))
        return ZizmorScanner._worse_exit_code(scanner, current, new)

    object.__setattr__(scanner, "_worse_exit_code", recording_fold)

    report = scanner.scan(repo, "source", [])

    assert isinstance(report, SarifReport)
    assert len(calls) == len(EXPECTED_INPUTS) >= 3
    assert [new for _, new in folded] == [3, 0] + [3] * (len(calls) - 2)
    assert folded[0][0] is None
    assert scanner.exit_code == 3


def test_a_multi_batch_scan_keeps_every_batchs_record(repo, monkeypatch):
    """The template resets start_time, output and errors at the top of each of
    its runs, so a target audited in several batches kept only the last batch's:
    a duration covering one batch and the earlier batches' stderr lines, which
    feed the reports, gone. The record now spans the batches: the first batch's
    start, and every batch's stderr lines in run order."""
    monkeypatch.setattr(zizmor_module, "_INPUT_ARGV_BUDGET", _ONE_INPUT_PER_BATCH)
    scanner = _scanner(repo)
    markers = [f"batch-{index}-marker" for index in range(len(EXPECTED_INPUTS))]
    calls, starts = _fake_runs_with_codes(
        scanner, CAPTURED_SARIF.read_text(), [0], stderrs=markers
    )

    report = scanner.scan(repo, "source", [])

    assert isinstance(report, SarifReport)
    assert len(calls) == len(markers)
    assert scanner.start_time == starts[0]
    assert scanner.end_time is not None and scanner.end_time >= starts[-1]
    recorded = "\n".join(str(line) for line in scanner.errors)
    assert [marker for marker in markers if marker in recorded] == markers


def test_a_declined_single_batch_target_leaves_no_exit_code(repo):
    """The template declined the one batch (its dependency check said no), so
    zizmor never ran: the exit code is None, as it is when a multi-batch target
    is declined, not the 0 a per-target reset left for a single batch, which
    read as a clean run."""
    scanner = _scanner(repo)
    _fake_run(scanner, stdout=CAPTURED_SARIF.read_text())
    object.__setattr__(scanner, "validate_plugin_dependencies", lambda: False)

    result = scanner.scan(repo, "source", [])

    assert result is False
    assert scanner.exit_code is None
