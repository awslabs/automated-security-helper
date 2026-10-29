# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A whole ``ash scan`` does not start tools that live inside the tree it scans.

``uv run ash scan .`` puts the repository's ``.venv/bin`` first on PATH, and
``npm run`` does the same with ``node_modules/.bin``. A bandit or semgrep there is
repository content. This runs the real command, in a child process, over a tree
holding a stand-in ``.venv/bin/bandit`` and ``node_modules/.bin/semgrep``, each of
which leaves a file behind when it is started, and with both directories on PATH.

Offline, the scanners' tool check runs a PATH copy of the tool with ``--version`` to
see whether it can stand in for the uv-managed one, which is how a tool on PATH is
started before any scan. By default neither stand-in may be started, and the log
names each one and the opt-in. With ``ASH_ALLOW_IN_TREE_TOOLS=1`` or
``--allow-in-tree-tools`` they are started, with a warning naming them. A setting of
that name in the repository's own ``.ash.yaml`` changes nothing.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests.utils.tool_guard import CHILD_TOOL_PROBE_STUBS

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform == "win32", reason="the stand-in tools are POSIX shell scripts"
    ),
]

# The ASH the parent test imported, ahead of whatever the interpreter has installed,
# so the child runs the code under test. Its tool probes are answered first
# (CHILD_TOOL_PROBE_STUBS, after the path insert it imports through): the child
# finds the uv installed with ASH beside its interpreter whatever PATH it is given,
# and ran it, which left uv's cache in the test's HOME.
DRIVER = (
    textwrap.dedent(
        """
        import os
        import sys

        sys.path.insert(0, os.environ["ASH_TEST_CODE_ROOT"])
        """
    )
    + CHILD_TOOL_PROBE_STUBS
    + textwrap.dedent(
        """
        from automated_security_helper.cli.main import app

        sys.argv = ["ash", "scan", *sys.argv[1:]]
        app()
        """
    )
)


def stand_in(directory: Path, name: str, ran: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    tool = directory / name
    tool.write_text(f"#!/bin/sh\n: > '{ran}'\necho '{name} 1.0.0'\n")
    tool.chmod(0o755)
    return tool


@pytest.fixture
def tree(tmp_path):
    tree = tmp_path / "repo"
    tree.mkdir()
    (tree / "app.py").write_text("print('hello')\n")
    marks = tmp_path / "marks"
    marks.mkdir()
    tools = {
        "bandit": stand_in(tree / ".venv" / "bin", "bandit", marks / "bandit-ran"),
        "semgrep": stand_in(
            tree / "node_modules" / ".bin", "semgrep", marks / "semgrep-ran"
        ),
    }
    # The "other copy" a run may find once the in-tree one is refused: the test's
    # own, outside the tree (``scan`` puts it on PATH ahead of the host's). Without
    # it the child found the unit tests' tool guard stand-in there (the parent's
    # PATH, inherited) and the guard recorded the scan's bandit as a start. Their
    # marks are kept apart from ``marks``, which the tests read as "an in-tree
    # tool ran".
    other_marks = tmp_path / "outside-marks"
    other_marks.mkdir()
    for name in tools:
        stand_in(tmp_path / "outside-bin", name, other_marks / f"{name}-ran")
    return tree, marks, tools


def scan(tree: Path, tools: dict, *extra: str, env_extra=None) -> str:
    import automated_security_helper

    output = tree.parent / "out"
    # Offline, semgrep needs a rule cache before it looks for its tool at all.
    rules = tree.parent / "semgrep-rules"
    rules.mkdir(exist_ok=True)
    (rules / "rule.yaml").write_text(
        "rules:\n- id: ash-test\n  pattern: eval(...)\n  message: m\n"
        "  languages: [python]\n  severity: WARNING\n"
    )
    env = dict(os.environ)
    env.pop("ASH_ALLOW_IN_TREE_TOOLS", None)
    env.update(
        {
            "ASH_OFFLINE": "YES",
            "NO_COLOR": "1",
            "COLUMNS": "200",
            "SEMGREP_RULES_CACHE_DIR": str(rules),
            "ASH_TEST_CODE_ROOT": str(
                Path(automated_security_helper.__file__).parents[1]
            ),
            "PATH": os.pathsep.join(
                [
                    str(tools["bandit"].parent),
                    str(tools["semgrep"].parent),
                    str(tree.parent / "outside-bin"),
                    # A run that must find no other copy gets the system directories
                    # only, not the host's whole PATH.
                    "/usr/bin:/bin"
                    if (env_extra or {}).get("PATH_SUFFIX_ONLY")
                    else env["PATH"],
                ]
            ),
        }
    )
    env.update(env_extra or {})
    completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [
            sys.executable,
            "-I",
            "-c",
            DRIVER,
            "--source-dir",
            str(tree),
            "--output-dir",
            str(output),
            "--mode",
            "local",
            *(() if "--scanners" in extra else ("--scanners", "bandit,semgrep")),
            "--phases",
            "scan",
            "--no-progress",
            "--no-fail-on-findings",
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=600,
        env=env,
        cwd=tree,
    )
    # The console, for what the scan prints rather than logs: styles stripped (rich
    # still emits bold under NO_COLOR) and whitespace collapsed (it wraps lines).
    console = re.sub(r"\x1b\[[0-9;]*m", "", completed.stdout)
    (tree.parent / "console.txt").write_text(" ".join(console.split()))
    return (output / "ash.log").read_text()


def test_tools_inside_the_tree_are_not_started(tree):
    root, marks, tools = tree

    log = scan(root, tools)

    assert sorted(p.name for p in marks.iterdir()) == []
    for name, tool in tools.items():
        refusals = [
            line
            for line in log.splitlines()
            if f"Not running {name} from inside the scanned tree" in line
        ]
        assert refusals, log[-4000:]
        assert str(tool) in refusals[0]
        assert "ASH_ALLOW_IN_TREE_TOOLS" in refusals[0]


@pytest.mark.parametrize(
    "how",
    [
        {"env_extra": {"ASH_ALLOW_IN_TREE_TOOLS": "1"}},
        {"extra": ("--allow-in-tree-tools",)},
    ],
    ids=["environment", "flag"],
)
def test_the_operators_opt_in_starts_them_with_a_warning(tree, how):
    root, marks, tools = tree

    log = scan(root, tools, *how.get("extra", ()), env_extra=how.get("env_extra"))

    assert (marks / "bandit-ran").exists(), log[-4000:]
    assert (marks / "semgrep-ran").exists(), log[-4000:]
    assert any(
        "Running bandit from inside the scanned tree" in line
        and str(tools["bandit"]) in line
        for line in log.splitlines()
    ), log[-4000:]


@pytest.mark.parametrize(
    "location, config",
    [
        (".ash/.ash.yaml", "allow_in_tree_tools: true\n"),
        (".ash.yaml", "allow_in_tree_tools: true\n"),
        (".ash/.ash.yaml", "ASH_ALLOW_IN_TREE_TOOLS: '1'\n"),
    ],
    ids=["dot-ash-dir", "repository-root", "env-name"],
)
def test_the_repositorys_config_cannot_turn_it_on(tree, location, config):
    """Keys the config schema ignores, so the scan runs with the config read."""
    root, marks, tools = tree
    (root / location).parent.mkdir(parents=True, exist_ok=True)
    (root / location).write_text(config)

    log = scan(root, tools)

    assert sorted(p.name for p in marks.iterdir()) == [], log[-4000:]
    # The scan got as far as looking the tools up, so the config was read and the
    # refusal is what kept them from running.
    assert "Not running bandit from inside the scanned tree" in log, log[-4000:]


def test_a_scanner_whose_only_tool_is_in_the_tree_is_missing_and_says_why(tmp_path):
    """cfn-nag's cfn_nag_scan, from the tree alone: MISSING, with path and remedy."""
    tree = tmp_path / "repo"
    tree.mkdir()
    (tree / "template.yaml").write_text("Resources: {}\n")
    marks = tmp_path / "marks"
    marks.mkdir()
    tool = stand_in(tree / ".venv" / "bin", "cfn_nag_scan", marks / "cfn-nag-ran")
    empty_bin = tmp_path / "ash-bin"
    empty_bin.mkdir()

    log = scan(
        tree,
        {"bandit": tool, "semgrep": tool},
        "--scanners",
        "cfn-nag",
        env_extra={"ASH_BIN_PATH": str(empty_bin), "PATH_SUFFIX_ONLY": "1"},
    )

    assert not (marks / "cfn-nag-ran").exists()
    missing = [
        line
        for line in log.splitlines()
        if "Scanner cfn-nag dependencies are not satisfied, marking as MISSING" in line
    ]
    assert missing, log[-4000:]
    assert "found only inside the scanned tree" in missing[0]
    assert str(tool) in missing[0]
    results = (tmp_path / "out" / "ash_aggregated_results.json").read_text()
    assert "found only inside the scanned tree" in results
    console = (tmp_path / "console.txt").read_text()
    assert f"Found only inside the scanned tree, so not run: cfn_nag_scan ({tool})" in (
        console
    ), console[-4000:]


def test_the_incomplete_scan_message_names_each_refused_tool(tmp_path, monkeypatch):
    """ "Install the missing tools" is the wrong advice for one the repository has."""
    from automated_security_helper.interactions import run_ash_scan
    from automated_security_helper.utils import subprocess_utils
    from automated_security_helper.utils.subprocess_utils import (
        find_executable,
        scanning_tree,
    )

    tree = tmp_path / "repo"
    bandit = stand_in(tree / ".venv" / "bin", "bandit", tmp_path / "bandit-ran")
    monkeypatch.setenv("PATH", str(bandit.parent))
    monkeypatch.delenv("ASH_ALLOW_IN_TREE_TOOLS", raising=False)
    monkeypatch.setattr(
        subprocess_utils, "path_independent_dirs", lambda: [tmp_path / "ash-bin"]
    )
    printed: list = []
    monkeypatch.setattr(
        run_ash_scan, "print", lambda *args, **_: printed.append(" ".join(args))
    )
    subprocess_utils.clear_find_executable_cache()
    try:
        # run_ash_scan's scope, and inside it the orchestrator's own, where the
        # scanners look their tools up.
        with scanning_tree(tree):
            with scanning_tree(tree):
                assert find_executable("bandit") is None
            run_ash_scan._print_in_tree_refusals()
    finally:
        subprocess_utils.clear_find_executable_cache()

    assert len(printed) == 1, printed
    assert f"bandit ({bandit})" in printed[0]
    assert "--allow-in-tree-tools" in printed[0]
