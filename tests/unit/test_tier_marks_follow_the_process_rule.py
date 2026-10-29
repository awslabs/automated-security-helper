# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The tier marks of named tests follow tests/NAMING_CONVENTIONS.md.

A tier is read from what a test can do on any path it takes: a test that starts a
child process (a scan that reaches a real or stand-in tool, git, a child Python)
is integration whatever outcome it asserts, a test that drives whole child scans
as an operator would is e2e, and a test that stays in-process is unit. These tests
read the marks statically, with ``ast``, so a re-mark that puts a process-starting
test back into the unit tier fails here before the unit job runs it.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
TIERS = {"unit", "integration", "e2e"}


def _tier_names(node: ast.AST) -> set[str]:
    """The tier names in a mark expression: ``pytest.mark.<tier>``, a call of
    one, or a list or tuple of those."""
    if isinstance(node, (ast.List, ast.Tuple)):
        return set().union(*(_tier_names(element) for element in node.elts))
    if isinstance(node, ast.Call):
        return _tier_names(node.func)
    if (
        isinstance(node, ast.Attribute)
        and node.attr in TIERS
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "mark"
    ):
        return {node.attr}
    return set()


def _marks_of(body: list[ast.stmt]) -> set[str]:
    """The tiers of a ``pytestmark = ...`` assignment in *body*, if any."""
    found: set[str] = set()
    for statement in body:
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "pytestmark"
            for target in statement.targets
        ):
            found |= _tier_names(statement.value)
    return found


def _parse(relative: str) -> ast.Module:
    return ast.parse((REPO_ROOT / relative).read_text(encoding="utf-8"))


def _tiers(relative: str, qualname: str) -> set[str]:
    """The union of tiers an item carries from its module, its class and itself."""
    module = _parse(relative)
    tiers = _marks_of(module.body)
    scope: list[ast.stmt] = module.body
    for name in qualname.split("."):
        node = next(
            statement
            for statement in scope
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            )
            and statement.name == name
        )
        tiers |= set().union(*(_tier_names(d) for d in node.decorator_list))
        if isinstance(node, ast.ClassDef):
            tiers |= _marks_of(node.body)
            scope = node.body
    return tiers


MCP = "tests/unit/cli/mcp/"
PLUGINS = "tests/unit/plugin_modules/"
JUPYTER = PLUGINS + "ash_builtin/converters/test_jupyter_converter_sandbox.py"
SNYK = PLUGINS + "ash_snyk_plugins/test_snyk_ignored_files_never_reach_snyk.py"
CLOUD = PLUGINS + "ash_aws_plugins/test_cloud_reporters_require_operator_config.py"
STAND_INS = "TestTheStandInsCanBeStartedOnWindows."


@pytest.mark.parametrize(
    "relative, qualname, expected",
    [
        # git init and git add run in a child process for this one test; the rest
        # of its module drives the CLI and the MCP tool in-process.
        (
            MCP + "test_scan_refusal_text_reaches_the_client.py",
            "test_files_in_the_way_of_the_output",
            "integration",
        ),
        (
            MCP + "test_scan_refusal_text_reaches_the_client.py",
            "test_a_config_that_does_not_validate",
            "unit",
        ),
        # The leak check runs after the thirteen integration tests it guards.
        (
            "tests/unit/core/test_inventory_installs_nothing.py",
            "test_the_sandbox_reaches_nothing_real",
            "integration",
        ),
        # The stand-in backend runs every planned nbconvert command unchanged.
        (JUPYTER, "TestNoInstallUnderASandbox", "integration"),
        (JUPYTER, "TestNbconvertRunsUnderTheSandbox", "integration"),
        (JUPYTER, "TestAFailedConversionIsLostCoverageInEitherMode", "integration"),
        (
            JUPYTER,
            STAND_INS + "test_a_script_logs_under_the_name_of_the_tool_it_stands_for",
            "integration",
        ),
        (
            JUPYTER,
            STAND_INS + "test_removing_a_stand_in_removes_every_file_it_is_made_of",
            "unit",
        ),
        (
            JUPYTER,
            STAND_INS
            + "test_a_launcher_is_asked_for_a_version_with_no_character_cmd_reads",
            "unit",
        ),
        # A pre-filter that empties the scan set is still a path into scanner.scan().
        (
            PLUGINS + "test_detect_secrets_lockfile_split.py",
            "test_generated_lockfile_is_still_skipped",
            "integration",
        ),
        # A refusal is one outcome of a path that starts the stand-in snyk.
        (
            SNYK,
            "TestTheSourceTarget.test_a_source_target_holding_an_ignored_file_never_starts_snyk",
            "integration",
        ),
        (
            SNYK,
            "TestTheSourceTarget.test_a_source_target_holding_the_output_dir_is_refused",
            "integration",
        ),
        (
            SNYK,
            "TestTheConvertedTarget.test_an_ignored_member_of_a_work_dir_outside_the_source_is_refused",
            "integration",
        ),
        # A rerender goes through run_ash_scan.
        (
            CLOUD,
            "TestCloudReportersNeedTheOperator.test_rerendering_stored_results_contacts_nothing",
            "integration",
        ),
        (
            CLOUD,
            "TestCloudReportersNeedTheOperator.test_rerendering_results_that_hold_no_scan_is_refused",
            "integration",
        ),
        # Two child Python processes through _run_isolated.
        (
            "tests/unit/test_docs_ci_runner_tools.py",
            "test_the_allowlist_check_runs_standalone_and_fails_the_step",
            "integration",
        ),
    ],
)
def test_a_process_starting_test_carries_the_tier_of_what_it_starts(
    relative, qualname, expected
):
    assert _tiers(relative, qualname) == {expected}


def test_whole_child_scans_are_e2e():
    """Module-scoped child scans with 900- and 600-second timeouts are the whole
    product driven as an operator would drive it."""
    module = _parse(MCP + "test_session_plugins_stay_in_their_session.py")
    assert _marks_of(module.body) == {"e2e"}


@pytest.mark.parametrize(
    "relative",
    [
        PLUGINS + "ash_aws_plugins/test_bedrock_markdown_text_escapes_once.py",
        PLUGINS + "ash_aws_plugins/test_reporter_retry_caps_in_the_report_phase.py",
        PLUGINS + "ash_aws_plugins/test_tree_config_cannot_route_off_host_reporters.py",
        PLUGINS + "test_cdk_nag_extra_requirements.py",
        PLUGINS + "test_converters_and_reporters_launch_no_tool.py",
        PLUGINS + "ash_aws_plugins/test_enabled_reporter_missing_setting_is_named.py",
        PLUGINS + "ash_aws_plugins/test_reporter_retry_config_is_honored.py",
        PLUGINS + "test_cdk_nag_container_deps.py",
    ],
)
def test_the_module_mark_does_not_sit_between_a_comment_and_what_it_documents(
    relative,
):
    """A ``#:`` or plain comment above a constant documents that constant, so
    the tier line goes above the comment, not between the two."""
    lines = (REPO_ROOT / relative).read_text(encoding="utf-8").splitlines()
    (index,) = [i for i, line in enumerate(lines) if line.startswith("pytestmark =")]
    assert not lines[index - 1].startswith("#"), (relative, lines[index - 1])


def test_the_scope_probes_get_their_tier_from_one_place():
    """The leaked-scope probes are marked by _run_probe, not inside each source."""
    relative = "tests/unit/test_a_leaked_run_scope_fails_its_test.py"
    text = (REPO_ROOT / relative).read_text(encoding="utf-8")
    module = _parse(relative)
    assert text.count("pytestmark = pytest.mark.unit") == 1
    assert any(
        isinstance(node, ast.FunctionDef) and node.name == "_with_a_tier"
        for node in module.body
    )


def test_the_database_cases_name_their_tier_once():
    """The subset TestTheOfflineImageDefault parametrizes over is built from
    CASE_TIERS, not written as a second list of marks."""
    relative = "tests/unit/utils/test_content_db_staleness.py"
    module = _parse(relative)
    (cls,) = [
        node
        for node in module.body
        if isinstance(node, ast.ClassDef) and node.name == "TestTheOfflineImageDefault"
    ]
    (function,) = [
        node
        for node in cls.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "test_every_other_database_still_fails"
    ]
    (parametrize,) = [
        d
        for d in function.decorator_list
        if isinstance(d, ast.Call)
        and isinstance(d.func, ast.Attribute)
        and d.func.attr == "parametrize"
    ]
    assert isinstance(parametrize.args[1], ast.Name), ast.dump(parametrize.args[1])
