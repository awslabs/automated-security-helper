# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ashx results {report, diff, trend, merge, inspect}``, and the spellings 4.0 removed.

The five commands that read, compare and combine saved results moved under one
noun in 3.9. The old top-level spellings (``ash report`` and the rest) were
deprecated then, with one DeprecationWarning per run naming the replacement, and
are removed in 4.0: the root has no such command, so each is a usage error, and
the new spelling is the only one.
"""

import typer.main
import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

pytestmark = pytest.mark.unit

VERBS = ("report", "diff", "trend", "merge", "inspect")


def _argv(verb: str, tmp_path) -> list[str]:
    """A cheap, deterministic invocation of *verb* that needs no scan results.

    Each one fails the same way under either spelling (a missing input, or a
    bare group), so the exit code and the command's own message can be compared.
    """
    missing = str(tmp_path / "absent.json")
    return {
        "report": [verb, "--output-dir", str(tmp_path / "no-such-output")],
        "diff": [verb, missing, missing],
        "trend": [verb, missing, missing],
        "merge": [verb, "--results", str(tmp_path / "no-such-shard")],
        "inspect": [verb],
    }[verb]


def _run(argv: list[str]):
    return CliRunner().invoke(app, argv, prog_name="ashx")


def _warnings(stderr: str) -> list[str]:
    return [
        line for line in stderr.splitlines() if line.startswith("DeprecationWarning")
    ]


def test_results_group_holds_exactly_the_five_verbs():
    root = typer.main.get_command(app)
    assert set(root.commands["results"].commands) == set(VERBS)


@pytest.mark.parametrize("verb", VERBS)
def test_the_old_spelling_is_not_a_root_command(verb):
    root = typer.main.get_command(app)
    assert verb not in root.commands


@pytest.mark.parametrize("verb", VERBS)
def test_the_new_spelling_runs_and_does_not_warn(verb, tmp_path):
    result = _run(["results", *_argv(verb, tmp_path)])
    assert "No such command" not in result.output
    assert _warnings(result.stderr) == []


@pytest.mark.parametrize("verb", VERBS)
def test_the_removed_spelling_is_a_usage_error(verb, tmp_path):
    result = _run(_argv(verb, tmp_path))
    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert f"No such command '{verb}'" in result.stderr
    assert _warnings(result.stderr) == []


@pytest.mark.parametrize("verb", VERBS)
def test_asking_for_help_on_the_new_spelling_does_not_warn(verb):
    result = _run(["results", verb, "--help"])
    assert result.exit_code == 0
    assert _warnings(result.stderr) == []


def test_root_help_lists_results_and_not_the_removed_spellings():
    result = _run(["--help"])
    assert result.exit_code == 0
    names = {
        line[1:].split()[0]
        for line in result.stdout.splitlines()
        if line.startswith("│ ") and line[2:3].isalpha()
    }
    assert "results" in names
    assert not names & set(VERBS)


def test_a_bare_results_group_prints_its_help_and_exits_with_the_usage_code():
    result = _run(["results"])
    assert result.exit_code == 5
    for verb in VERBS:
        assert verb in result.stdout
