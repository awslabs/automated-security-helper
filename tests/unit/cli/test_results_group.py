# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash results {report, diff, trend, merge, inspect}`` and the deprecated spellings.

The five commands that read, compare and combine saved results live under one
noun. Three of them, ``report``, ``merge`` and ``inspect``, were top-level commands
in 3.8: each new spelling runs the same implementation as the old one; each old
spelling keeps working through 3.9, prints one DeprecationWarning on stderr naming
its replacement, and is removed in 4.0. ``diff`` and ``trend`` are new in 3.9, so
they have no old spelling: ``ash diff`` and ``ash trend`` are unknown commands.
"""

import typer.main
import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import (
    DEPRECATED_RESULTS_SPELLINGS,
    app,
)
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

pytestmark = pytest.mark.unit

VERBS = ("report", "diff", "trend", "merge", "inspect")

#: The verbs that were top-level commands in 3.8, so the ones with an old spelling.
MOVED = ("report", "merge", "inspect")


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
    return CliRunner().invoke(app, argv, prog_name="ash")


def _warnings(stderr: str) -> list[str]:
    return [
        line for line in stderr.splitlines() if line.startswith("DeprecationWarning")
    ]


def _options(command) -> set[str]:
    return {opt for param in command.params for opt in getattr(param, "opts", [])}


def test_the_deprecated_set_is_the_three_verbs_that_had_a_top_level_spelling():
    assert DEPRECATED_RESULTS_SPELLINGS == set(MOVED)


def test_results_group_holds_exactly_the_five_verbs():
    root = typer.main.get_command(app)
    assert set(root.commands["results"].commands) == set(VERBS)


@pytest.mark.parametrize("verb", ["diff", "trend"])
def test_diff_and_trend_have_no_top_level_spelling(verb, tmp_path):
    """No release had ``ash diff`` or ``ash trend``: they are new in 3.9 and live
    under ``ash results`` only, so there is no old spelling to keep, to warn about
    or to remove in 4.0, and the top-level word is an unknown command."""
    missing = str(tmp_path / "absent.json")

    result = _run([verb, missing, missing])

    assert verb not in typer.main.get_command(app).commands
    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert f"No such command '{verb}'" in result.output, result.output
    assert _warnings(result.stderr) == []


@pytest.mark.parametrize("verb", MOVED)
def test_the_new_spelling_runs_the_same_command_as_the_old(verb):
    root = typer.main.get_command(app)
    old, new = root.commands[verb], root.commands["results"].commands[verb]
    assert _options(new) == _options(old)
    assert type(new) is type(old)
    assert new.help == old.help


@pytest.mark.parametrize("verb", VERBS)
def test_the_new_spelling_does_not_warn(verb, tmp_path):
    result = _run(["results", *_argv(verb, tmp_path)])
    assert _warnings(result.stderr) == []


@pytest.mark.parametrize("verb", MOVED)
def test_the_old_spelling_warns_once_and_still_works(verb, tmp_path):
    new = _run(["results", *_argv(verb, tmp_path)])
    old = _run(_argv(verb, tmp_path))
    warned = _warnings(old.stderr)
    assert len(warned) == 1
    assert f"'ash {verb}' is deprecated" in warned[0]
    assert "removed in 4.0" in warned[0]
    assert f"'ash results {verb}'" in warned[0]
    # Same behavior as the new spelling: same verdict, and the command's own
    # message, when it prints one a spelling-free way, is unchanged.
    assert old.exit_code == new.exit_code
    assert old.stdout == new.stdout


@pytest.mark.parametrize("verb", MOVED)
def test_asking_for_help_does_not_warn(verb):
    result = _run([verb, "--help"])
    assert result.exit_code == 0
    assert _warnings(result.stderr) == []


@pytest.mark.parametrize("verb", ["report", "merge"])
def test_printing_the_json_skeleton_does_not_warn(verb):
    # The skeleton only prints what the command takes; it is not a use of the
    # deprecated spelling, and the snapshots of it stay the same under both.
    old = _run([verb, "--generate-cli-skeleton"])
    new = _run(["results", verb, "--generate-cli-skeleton"])
    assert old.exit_code == new.exit_code == 0
    assert _warnings(old.stderr) == []
    assert old.stdout == new.stdout


def test_root_help_lists_results_and_hides_the_old_spellings():
    result = _run(["--help"])
    assert result.exit_code == 0
    names = {
        line[1:].split()[0]
        for line in result.stdout.splitlines()
        if line.startswith("│ ") and line[2:3].isalpha()
    }
    assert "results" in names
    assert not names & DEPRECATED_RESULTS_SPELLINGS


def test_the_old_spellings_stay_in_the_command_mapping():
    # Hidden from --help, not removed: the docs, the wrapper tables and the help
    # snapshots walk the mapping, and 4.0 is when the entries go.
    root = typer.main.get_command(app)
    for verb in MOVED:
        assert verb in root.commands
        assert root.commands[verb].hidden is True


def test_a_bare_results_group_prints_its_help_and_exits_with_the_usage_code():
    result = _run(["results"])
    assert result.exit_code == 5
    for verb in VERBS:
        assert verb in result.stdout
