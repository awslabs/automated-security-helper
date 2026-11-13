# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A runnable block must not read a shell variable that only another session set.

WHY THIS EXISTS
---------------
The docs-example runner runs a page's blocks in sessions. A shell block hands its
variables to the next block of the same session, but a block on another fixture, or a
fresh one, starts a new session that holds only the runner's own environment. One page
set OPERATOR_CONFIG in a block on the empty fixture and read it in blocks on the default
fixture, so its "operator config" scans ran as `ash scan --config ""`. ASH read an empty
path as no config, the scans exited 2 as the page expected, and every check passed. It
surfaced only when ASH began refusing an empty --config path.

check_session_variables reports that shape: a read of $NAME or ${NAME} in a runnable
shell block, where no earlier block of the same session sets NAME and an earlier block
of another session does. A variable the runner's session environment provides, or one
the reading block sets itself, is not reported. The sessions and that environment come
from the runner (tests/integration/docs/docs_runner.py), not from a copy here.

Like test_docs_checks_can_fail.py, nothing here runs a docs command: every page lives
in tmp_path and the check reads it statically.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKS_PATH = REPO_ROOT / "scripts" / "docs_checks.py"
FENCE = "```"


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


dc = _load("_ash_docs_checks", CHECKS_PATH)


def _check(tmp_path: Path, text: str):
    page = tmp_path / "page.md"
    page.write_text(text, encoding="utf-8")
    return dc.check_session_variables([page], tmp_path)


def _block(body: str, marker: str = "", lang: str = "bash") -> str:
    head = f"<!-- doctest: {marker} -->\n" if marker else ""
    return f"{head}{FENCE}{lang}\n{body}\n{FENCE}\n"


def _page(*blocks: str) -> str:
    return "# Page\n\n" + "\nProse.\n\n".join(blocks)


def _lines_of(text: str, needle: str) -> list[int]:
    return [n for n, line in enumerate(text.split("\n"), start=1) if needle in line]


# The shape the platform-teams tutorial had: the operator config is written in a
# session on the empty fixture, and read by scans on the default fixture.
SET_ON_EMPTY = _block(
    'OPERATOR_CONFIG="$HOME/ash-operator/ash.yaml"\n'
    'mkdir -p "$(dirname "$OPERATOR_CONFIG")"\n'
    "printf 'fail_on_findings: true\\n' > \"$OPERATOR_CONFIG\"",
    "run fixture=empty",
)
SCAN = 'ash scan --config "$OPERATOR_CONFIG" --scanners detect-secrets'
CHECK_LOG = (
    "head -n 1 .ash/ash_output/ash.log | "
    'grep -F "Using config file specified at: $OPERATOR_CONFIG"'
)
BEFORE_THE_FIX = _page(
    SET_ON_EMPTY,
    _block("mkdir ash-gate-demo\ncd ash-gate-demo"),
    _block(SCAN, "run expect-exit=2"),
    _block(CHECK_LOG),
)
AFTER_THE_FIX = _page(
    SET_ON_EMPTY,
    _block("mkdir ash-gate-demo\ncd ash-gate-demo", "run fixture=empty"),
    _block(SCAN, "run fixture=empty expect-exit=2"),
    _block(CHECK_LOG, "run fixture=empty"),
)


def test_a_variable_set_on_another_fixture_is_reported_where_it_is_read(tmp_path):
    findings = _check(tmp_path, BEFORE_THE_FIX)
    reads = _lines_of(BEFORE_THE_FIX, "$OPERATOR_CONFIG")
    # The setting block's own reads are not reported, and both later reads are.
    assert [f.line for f in findings] == reads[-2:], [str(f) for f in findings]
    set_at = _lines_of(BEFORE_THE_FIX, f"{FENCE}bash")[0]
    for finding in findings:
        assert finding.check == "session"
        assert "$OPERATOR_CONFIG" in finding.message
        assert f"fixture '{dc.DEFAULT_FIXTURE}'" in finding.message
        assert f"line {set_at}" in finding.message
        assert "fixture 'empty'" in finding.message
        assert "the fixture changes" in finding.message


def test_the_page_after_the_fix_passes(tmp_path):
    assert _check(tmp_path, AFTER_THE_FIX) == []


def test_a_variable_set_and_read_in_one_session_passes(tmp_path):
    """Control: the same blocks on one fixture, set in one block and read in a later one."""
    text = _page(
        _block('OPERATOR_CONFIG="$HOME/ash.yaml"\ntouch "$OPERATOR_CONFIG"'),
        _block(SCAN, "run expect-exit=2"),
        _block(CHECK_LOG),
    )
    assert _check(tmp_path, text) == []


def test_a_fresh_block_starts_a_session_the_variable_does_not_reach(tmp_path):
    text = _page(
        _block("REPORT_DIR=reports"),
        _block('ls "$REPORT_DIR"', "run fresh"),
    )
    (finding,) = _check(tmp_path, text)
    assert "$REPORT_DIR" in finding.message
    assert "fresh" in finding.message


def test_a_save_block_on_another_fixture_splits_the_sessions_too(tmp_path):
    """The runner follows every block it handles: a block that only saves a file on
    another fixture starts a session, and the next block on the default fixture starts
    yet another, so a variable set before the save is gone after it."""
    text = _page(
        _block("REPORT_DIR=reports"),
        _block("project_name: x", "save-as=.ash/ash.yaml fixture=empty", "yaml"),
        _block('ls "$REPORT_DIR"'),
    )
    (finding,) = _check(tmp_path, text)
    assert "$REPORT_DIR" in finding.message
    assert f"fixture '{dc.DEFAULT_FIXTURE}'" in finding.message


def test_a_block_that_sets_the_variable_itself_passes(tmp_path):
    text = _page(
        _block("REPORT_DIR=reports", "run fixture=empty"),
        _block('REPORT_DIR=out\nls "$REPORT_DIR"'),
        _block('export REPORT_DIR=out\nls "$REPORT_DIR"'),
        _block('for REPORT_DIR in a b; do ls "$REPORT_DIR"; done'),
        _block('read -r REPORT_DIR < name.txt\nls "${REPORT_DIR}"'),
        _block('declare REPORT_DIR=out\nls "$REPORT_DIR"'),
        _block('ls "$REPORT_DIR"', 'run env="REPORT_DIR=out"'),
    )
    assert _check(tmp_path, text) == []


def test_only_real_reads_count(tmp_path):
    """Text that looks like a read but is not one: single quotes, an escaped dollar, a
    comment, a default or an error for the unset case, and a quoted here-document."""
    text = _page(
        _block("REPORT_DIR=reports", "run fixture=empty"),
        _block(
            "echo '$REPORT_DIR'\n"
            "echo \\$REPORT_DIR\n"
            "# ls $REPORT_DIR\n"
            'ls "${REPORT_DIR:-reports}"\n'
            'ls "${REPORT_DIR-reports}"\n'
            'ls "${REPORT_DIR:?set REPORT_DIR first}"\n'
            "cat <<'EOF'\n$REPORT_DIR\nEOF"
        ),
    )
    assert _check(tmp_path, text) == []


def test_every_form_of_a_read_counts(tmp_path):
    reading = (
        "ls $REPORT_DIR\n"
        'ls "${REPORT_DIR}"\n'
        "echo ${#REPORT_DIR}\n"
        'echo "$(basename "$REPORT_DIR")"\n'
        "cat <<EOF\n$REPORT_DIR\nEOF"
    )
    text = _page(_block("REPORT_DIR=reports", "run fixture=empty"), _block(reading))
    findings = _check(tmp_path, text)
    first = _lines_of(text, "ls $REPORT_DIR")[0]
    expected = [first + offset for offset in (0, 1, 2, 3, 5)]
    assert [f.line for f in findings] == expected


def test_a_console_block_reads_only_its_commands(tmp_path):
    text = _page(
        _block("REPORT_DIR=reports", "run fixture=empty"),
        _block("$ ls reports\nfiles in $REPORT_DIR:", lang="console"),
        _block('$ ls "$REPORT_DIR"', lang="console"),
    )
    (finding,) = _check(tmp_path, text)
    assert finding.line == _lines_of(text, '$ ls "$REPORT_DIR"')[0]


def test_only_blocks_the_runner_runs_count(tmp_path):
    """An illustrative block neither sets a variable nor reads one, and a python block
    reads the environment, not $NAME."""
    text = _page(
        _block("REPORT_DIR=reports", "run fixture=empty"),
        _block('ls "$REPORT_DIR"', 'illustrative reason="needs a scan first"'),
        _block('print("$REPORT_DIR")', lang="python"),
    )
    assert _check(tmp_path, text) == []
    text = _page(
        _block("REPORT_DIR=reports", 'illustrative reason="needs a scan first"'),
        _block('ls "$REPORT_DIR"', "run fixture=empty"),
    )
    assert _check(tmp_path, text) == []


def test_the_runners_own_environment_is_read_from_the_runner(tmp_path, monkeypatch):
    """HOME is set in every session by the runner, so a page that also sets it on
    another fixture is not reported. Taking HOME out of the runner's environment makes
    the same page a finding, so the list is the runner's, not a copy."""
    text = _page(
        _block("HOME=/srv/ash", "run fixture=empty"),
        _block('ls "$HOME"'),
    )
    assert _check(tmp_path, text) == []

    runner = dc._docs_runner()
    real = runner.session_environment

    def without_home(*args, **kwargs):
        env = real(*args, **kwargs)
        env.pop("HOME")
        return env

    monkeypatch.setattr(runner, "session_environment", without_home)
    (finding,) = _check(tmp_path, text)
    assert "$HOME" in finding.message


def test_the_sessions_are_the_runners(tmp_path, monkeypatch):
    """The check follows the runner's own session rule: with a runner that never starts
    a second session, the page before the fix has nothing to report."""
    assert _check(tmp_path, BEFORE_THE_FIX)
    runner = dc._docs_runner()
    monkeypatch.setattr(
        runner, "starts_session", lambda block, fixture_in_use: fixture_in_use is None
    )
    assert _check(tmp_path, BEFORE_THE_FIX) == []
