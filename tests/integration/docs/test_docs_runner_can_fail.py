# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The docs-example runner reports every way a block can fail, and passes a clean page.

A runner that cannot fail is worse than none: test_docs_examples.py would be green
over docs whose commands do not work. So each failure the runner exists to catch is
planted here in a synthetic page, with a clean control beside it, using trivial
commands (echo, false, exit) so the whole file runs in a few seconds:

* a failing command, reported with page, line, command, exit code and output tail;
* an exit code other than the marker's expect-exit, in both directions;
* a block that runs past its timeout;
* a python block that raises;
* an illustrative block, which must not run at all.

It also pins the session semantics the docs rely on (files, directory and variables
carry between blocks; env= applies to one block; fixture= and fresh start over) and
the isolation the job relies on (private HOME, the venv's ash, downloads refused at
once).
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

HERE = Path(__file__).resolve().parent


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runner = _load("_ash_docs_runner", HERE / "docs_runner.py")
checks = runner.load_docs_checks()


def _page(tmp_path: Path, text: str):
    path = tmp_path / "page.md"
    path.write_text(text, encoding="utf-8")
    return checks.parse_page(path, tmp_path)


def _run(tmp_path: Path, text: str):
    scratch = tmp_path / "sessions"
    scratch.mkdir()
    return runner.PageRunner(_page(tmp_path, text), scratch).run()


FENCE = "```"


def _assert_all_ok(results, count: int) -> None:
    """Every block passed, and as many ran as the page has: all([]) is true, so a
    runner that ran nothing would otherwise pass every clean control."""
    assert len(results) == count, (
        f"expected {count} blocks to run, got {len(results)}: "
        + runner.failure_report(results)
    )
    assert all(r.ok for r in results), runner.failure_report(results)


def test_a_clean_page_passes_and_carries_its_session(tmp_path):
    """Control: files, the directory and variables carry from block to block."""
    results = _run(
        tmp_path,
        f"""# Tutorial

{FENCE}bash
echo hello > greeting.txt
mkdir -p sub
cd sub
GREETING=hi
export TARGET=world
{FENCE}

Prose between blocks.

{FENCE}console
$ test "$(cat ../greeting.txt)" = hello && test "$GREETING" = hi && echo carried
carried
{FENCE}

{FENCE}python
import os
from pathlib import Path

assert Path.cwd().name == "sub", Path.cwd()
assert os.environ["TARGET"] == "world"
assert Path("../greeting.txt").read_text(encoding="utf-8").strip() == "hello"
{FENCE}
""",
    )
    assert [r.lang for r in results] == ["bash", "console", "python"]
    _assert_all_ok(results, 3)


def test_a_failing_command_is_reported_with_its_context(tmp_path):
    results = _run(
        tmp_path,
        f"""# Page

{FENCE}bash
echo before-the-failure
false
echo never-printed
{FENCE}
""",
    )
    (result,) = results
    assert not result.ok
    assert result.exit_code == 1
    report = runner.failure_report(results)
    assert "page.md:3:" in report, report
    assert "false" in report and "exit code 1, expected 0" in report, report
    assert "before-the-failure" in report, report
    # set -e stopped the block at the failure.
    assert "never-printed" not in result.output


def test_a_wrong_expect_exit_fails_in_both_directions(tmp_path):
    results = _run(
        tmp_path,
        f"""<!-- doctest: run expect-exit=3 -->
{FENCE}bash
exit 3
{FENCE}

<!-- doctest: run expect-exit=3 -->
{FENCE}bash
exit 0
{FENCE}

{FENCE}bash
exit 3
{FENCE}

<!-- doctest: run expect-exit=nonzero -->
{FENCE}bash
exit 2
{FENCE}

<!-- doctest: run expect-exit=nonzero -->
{FENCE}bash
true
{FENCE}

<!-- doctest: run expect-exit=any -->
{FENCE}bash
exit 9
{FENCE}
""",
    )
    assert [r.ok for r in results] == [True, False, False, True, False, True]
    assert "exit code 0, expected 3" in results[1].report()


#: How long a block that should time out runs when the runner's timeout is broken. The
#: block ends by itself after this, so the regression fails its test within a minute;
#: a block that never ends would hang until something outside killed the job. Nothing
#: outside the runner stops the block, so a broken timeout cannot be hidden by a
#: wrapper's own one.
TIMEOUT_GUARD_S = 60


def test_a_block_past_its_timeout_is_stopped_and_reported(tmp_path):
    started = time.monotonic()
    results = _run(
        tmp_path,
        f"""<!-- doctest: run timeout=1 -->
{FENCE}bash
sleep {TIMEOUT_GUARD_S}
{FENCE}
""",
    )
    (result,) = results
    assert result.timed_out and not result.ok, result.report()
    assert "timed out after" in result.report()
    assert time.monotonic() - started < 30, "the timeout did not stop the block"


def test_the_runners_default_timeout_stops_an_unmarked_block(tmp_path):
    """A block without timeout= gets the runner's default, set small here."""
    scratch = tmp_path / "sessions"
    scratch.mkdir()
    page = _page(tmp_path, f"{FENCE}bash\nsleep {TIMEOUT_GUARD_S}\n{FENCE}\n")
    started = time.monotonic()
    (result,) = runner.PageRunner(page, scratch, default_timeout=1).run()
    assert result.timed_out and not result.ok, result.report()
    assert time.monotonic() - started < 30, "the default timeout did not stop the block"


def test_a_python_block_that_raises_fails(tmp_path):
    results = _run(
        tmp_path,
        f"""{FENCE}python
raise RuntimeError("planted failure")
{FENCE}
""",
    )
    (result,) = results
    assert not result.ok and result.exit_code != 0
    assert "planted failure" in result.report()


def test_expect_exit_nonzero_does_not_accept_a_missing_command(tmp_path):
    """126 and 127 mean the command could not run at all (not executable, not
    found): a broken example, not the failure the marker says the block shows."""
    results = _run(
        tmp_path,
        f"""<!-- doctest: run expect-exit=nonzero -->
{FENCE}bash
false
{FENCE}

<!-- doctest: run expect-exit=nonzero -->
{FENCE}bash
no-such-command-in-the-docs
{FENCE}

<!-- doctest: run expect-exit=nonzero -->
{FENCE}bash
printf 'echo hi\\n' > not-executable.sh
./not-executable.sh
{FENCE}
""",
    )
    assert [r.exit_code for r in results] == [1, 127, 126], runner.failure_report(
        results
    )
    assert [r.ok for r in results] == [True, False, False]
    assert "not found or not executable" in results[1].report()


def test_an_illustrative_block_is_not_run(tmp_path):
    results = _run(
        tmp_path,
        f"""<!-- doctest: illustrative reason="needs AWS credentials" -->
{FENCE}bash
false
{FENCE}

{FENCE}text
false
{FENCE}

<!-- doctest: illustrative reason="Windows only" -->
{FENCE}powershell
exit 1
{FENCE}
""",
    )
    assert results == []


def test_env_applies_to_its_block_only(tmp_path):
    results = _run(
        tmp_path,
        f"""<!-- doctest: run env="ONLY_HERE=1" -->
{FENCE}bash
test "$ONLY_HERE" = 1
{FENCE}

{FENCE}bash
test -z "${{ONLY_HERE:-}}"
{FENCE}
""",
    )
    _assert_all_ok(results, 2)


def test_fixture_and_fresh_start_a_new_session(tmp_path):
    results = _run(
        tmp_path,
        f"""{FENCE}bash
test -f app.py
touch leftover.txt
LEFTOVER=1
{FENCE}

<!-- doctest: run fresh -->
{FENCE}bash
test -f app.py && test ! -e leftover.txt && test -z "${{LEFTOVER:-}}"
{FENCE}

<!-- doctest: run fixture=empty -->
{FENCE}bash
test -z "$(ls -A | grep -v '^.git$')"
{FENCE}
""",
    )
    _assert_all_ok(results, 3)


def test_the_session_is_isolated_and_offline(tmp_path):
    """Private HOME, the venv's ash, and a network that refuses at once."""
    results = _run(
        tmp_path,
        f"""{FENCE}bash
test "$HOME" != "{Path.home()}"
case "$HOME" in "{tmp_path}"*) ;; *) exit 10;; esac
test "$(command -v ash)" = "{Path(sys.executable).parent / "ash"}"
{FENCE}

{FENCE}python
import time
import urllib.request

started = time.monotonic()
try:
    urllib.request.urlopen("https://example.com/", timeout=30)
except OSError as exc:
    print("refused:", exc)
else:
    raise SystemExit("the network was reachable")
assert time.monotonic() - started < 5, "the network failed slowly"
{FENCE}
""",
    )
    _assert_all_ok(results, 2)


def test_a_tool_on_the_host_path_is_not_on_the_session_path(tmp_path, monkeypatch):
    """A session does not find a tool that is only on the invoking user's PATH.

    With the host PATH appended to a session's, a block that runs a tool found only
    there passes on one machine and fails on another. The tool below is put first on
    this process's PATH; a session must not see it, and must still see the venv's ash
    and the system's git. The block exits explicitly: a session runs under set -e,
    which ignores a failing `! command`.
    """
    host_bin = tmp_path / "host-bin"
    host_bin.mkdir()
    tool = host_bin / "ash-docs-host-only-tool"
    tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", f"{host_bin}{os.pathsep}{os.environ.get('PATH', '')}")
    assert shutil.which(tool.name), "the planted tool is not on this process's PATH"
    results = _run(
        tmp_path,
        f"""{FENCE}bash
if command -v {tool.name}; then exit 11; fi
! command -v {tool.name} || exit 12
test "$(command -v ash)" = "{Path(sys.executable).parent / "ash"}"
command -v git
case ":$PATH:" in *":{host_bin}:"*) exit 10;; esac
{FENCE}
""",
    )
    _assert_all_ok(results, 1)


def _planted_tool(directory: Path, name: str) -> Path:
    directory.mkdir(parents=True)
    tool = directory / name
    tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    tool.chmod(0o755)
    return tool


def test_the_tools_ash_installed_are_on_the_session_path(tmp_path, monkeypatch):
    """A session finds what `ash dependencies install` put in place for this user.

    ASH installs a binary into its bin directory (ASH_BIN_PATH, else ~/.ash/bin)
    and a Python tool with `uv tool install`, into uv's tool bin directory. A
    session's HOME is private, so ASH inside it would look in the session's own,
    empty copies of both; the invoking user's are on the session's PATH instead,
    resolved as ASH and uv resolve them. Each is planted here in a directory named
    by the variable that moves it, beside a tool on the host PATH that must stay
    out of reach. The test session removes UV_TOOL_BIN_DIR from the process, so uv's
    directory is named in the record tests/conftest.py exports, not in the process.
    """
    ash_tool = _planted_tool(tmp_path / "ash-bin", "ash-docs-ash-bin-tool")
    uv_tool = _planted_tool(tmp_path / "uv-tool-bin", "ash-docs-uv-tool")
    host_tool = _planted_tool(tmp_path / "host-bin", "ash-docs-host-only-tool")
    monkeypatch.setenv("ASH_BIN_PATH", str(ash_tool.parent))
    monkeypatch.delenv("UV_TOOL_BIN_DIR", raising=False)
    monkeypatch.setenv(
        "ASH_TEST_DEVELOPER_HOME",
        json.dumps({"env": {"UV_TOOL_BIN_DIR": str(uv_tool.parent)}, "home": ""}),
    )
    monkeypatch.setenv(
        "PATH", f"{host_tool.parent}{os.pathsep}{os.environ.get('PATH', '')}"
    )
    assert runner.ash_tool_dirs() == [ash_tool.parent, uv_tool.parent]
    results = _run(
        tmp_path,
        f"""{FENCE}bash
test "$(command -v {ash_tool.name})" = "{ash_tool}"
test "$(command -v {uv_tool.name})" = "{uv_tool}"
if command -v {host_tool.name}; then exit 11; fi
{FENCE}
""",
    )
    _assert_all_ok(results, 1)


def test_the_tools_in_the_home_the_test_session_replaced_are_on_the_session_path(
    tmp_path, monkeypatch
):
    """The tools of the user's own home are found though the test session moved HOME.

    tests/conftest.py points HOME at a private directory for the whole pytest run and
    records the values it replaced in ASH_TEST_DEVELOPER_HOME. `ash dependencies
    install` ran as the user, outside the run, so its tools are under the recorded
    home, not under Path.home(). Planted here: a tool in each of the recorded home's
    two default tool directories, an empty private home, and none of the variables
    that would name those directories directly.
    """
    real_home = tmp_path / "real-home"
    ash_tool = _planted_tool(real_home / ".ash" / "bin", "ash-docs-real-ash-tool")
    uv_tool = _planted_tool(real_home / ".local" / "bin", "ash-docs-real-uv-tool")
    private_home = tmp_path / "private-home"
    private_home.mkdir()
    for name in ("ASH_BIN_PATH", "UV_TOOL_BIN_DIR", "XDG_BIN_HOME", "XDG_DATA_HOME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(
        "ASH_TEST_DEVELOPER_HOME",
        json.dumps({"env": {"HOME": str(real_home)}, "home": str(real_home)}),
    )
    monkeypatch.setenv("HOME", str(private_home))
    found = [directory.resolve() for directory in runner.ash_tool_dirs()]
    assert found == [ash_tool.parent.resolve(), uv_tool.parent.resolve()]


def test_a_shell_session_block_runs_like_a_console_block(tmp_path):
    """shell-session and bash-session are console blocks: prompts run, output does not."""
    results = _run(
        tmp_path,
        f"""{FENCE}shell-session
$ echo from-a-prompt > out.txt
this-output-line-is-not-a-command
{FENCE}

{FENCE}bash-session
$ test "$(cat out.txt)" = from-a-prompt
{FENCE}

<!-- doctest: run expect-exit=1 -->
{FENCE}shell-session
$ false
{FENCE}
""",
    )
    assert [r.lang for r in results] == [
        "shell-session",
        "bash-session",
        "shell-session",
    ]
    _assert_all_ok(results, 3)


def test_fixtures_come_from_the_docs_root(tmp_path):
    """With --docs-root, a page starts in that tree's fixture, not this checkout's.

    The docs tree is a git repository, as a docs root is: the runner copies a fixture
    from git's listing of it.
    """
    docs_root = tmp_path / "docs-tree"
    docs_root.mkdir()
    subprocess.run(
        ["git", "init", "-q", str(docs_root)], check=True, capture_output=True
    )
    fixture = docs_root / checks.DOC_FIXTURES_DIR / checks.DEFAULT_FIXTURE
    fixture.mkdir(parents=True)
    (fixture / "only-in-the-docs-tree.txt").write_text("x\n", encoding="utf-8")
    scratch = tmp_path / "sessions"
    scratch.mkdir()
    page = _page(tmp_path, f"{FENCE}bash\ntest -f only-in-the-docs-tree.txt\n{FENCE}\n")
    results = runner.PageRunner(page, scratch, docs_root=docs_root).run()
    _assert_all_ok(results, 1)


SAVED_PAGE = f"""# A plugin tutorial

<!-- doctest: save-as=my_plugins/greeting.py -->
{FENCE}python
def hello():
    return "hi"
{FENCE}

<!-- doctest: config kind=other reason="a settings file for the example" save-as=.ash/settings.yaml -->
{FENCE}yaml
greeting: hi
{FENCE}

<!-- doctest: run save-as=tools/where.py -->
{FENCE}python
from pathlib import Path

assert Path(__file__).as_posix().endswith("tools/where.py"), __file__
{FENCE}

{FENCE}python
from my_plugins.greeting import hello

assert hello() == "hi"
{FENCE}

{FENCE}bash
PYTHONPATH=. python -c "from my_plugins.greeting import hello; assert hello() == 'hi'"
test -f .ash/settings.yaml
{FENCE}
"""


def test_saved_files_are_there_for_later_blocks(tmp_path):
    results = _run(tmp_path, SAVED_PAGE)
    assert [r.command.split("\n")[0] for r in results][:2] == [
        "save-as=my_plugins/greeting.py",
        "save-as=.ash/settings.yaml",
    ]
    _assert_all_ok(results, 5)


def test_a_later_block_fails_when_the_save_as_is_dropped(tmp_path):
    """The proof that save-as is what made the module importable."""
    page = SAVED_PAGE.replace("<!-- doctest: save-as=my_plugins/greeting.py -->\n", "")
    results = _run(tmp_path, page)
    *_, python_import, shell_import = results
    for result in (python_import, shell_import):
        assert not result.ok and "No module named 'my_plugins'" in result.output, (
            runner.failure_report(results)
        )


def test_a_save_as_that_leaves_the_project_is_refused(tmp_path):
    results = _run(
        tmp_path,
        f"""<!-- doctest: save-as=../outside.py -->
{FENCE}python
x = 1
{FENCE}

<!-- doctest: save-as=/tmp/absolute.py -->
{FENCE}python
x = 1
{FENCE}

{FENCE}bash
mkdir -p elsewhere && ln -s "$PWD/elsewhere" linked
{FENCE}

<!-- doctest: save-as=linked/through-a-link.py -->
{FENCE}python
x = 1
{FENCE}

<!-- doctest: save-as=elsewhere -->
{FENCE}text
a directory is in the way
{FENCE}
""",
    )
    refused = [r for r in results if r.refused]
    assert [r.command for r in refused] == [
        "save-as=../outside.py",
        "save-as=/tmp/absolute.py",
        "save-as=linked/through-a-link.py",
        "save-as=elsewhere",
    ], runner.failure_report(results)
    assert "goes through a link" in refused[2].report()
    assert "is a directory" in refused[3].report()
    assert not (tmp_path / "sessions" / "outside.py").exists()
    assert not any((tmp_path / "sessions").rglob("through-a-link.py"))


def test_the_save_backstop_refuses_an_escape_the_path_check_misses(
    tmp_path, monkeypatch
):
    """The runner resolves the target and refuses it outside the project even when
    save_as_problem lets the path through, so one missed case cannot write outside."""
    monkeypatch.setattr(
        runner.load_docs_checks(), "save_as_problem", lambda value: None
    )
    results = _run(
        tmp_path,
        f"""<!-- doctest: save-as=../outside.py -->
{FENCE}python
x = 1
{FENCE}
""",
    )
    assert [r.refused for r in results] == [
        "save-as refused: ../outside.py leaves the page's project"
    ], runner.failure_report(results)
    assert not any(tmp_path.rglob("outside.py"))


def test_a_page_with_only_saved_blocks_is_run(tmp_path):
    """The examples test selects pages by the blocks a session handles, so a page that
    only saves files is run too, and a save the runner refuses is reported."""
    examples = _load("_ash_docs_examples", HERE / "test_docs_examples.py")
    saved_only = tmp_path / "saved.md"
    saved_only.write_text(
        f"<!-- doctest: save-as=settings.yaml -->\n{FENCE}yaml\nproject_name: x\n{FENCE}\n",
        encoding="utf-8",
    )
    nothing = tmp_path / "prose.md"
    nothing.write_text(f"# Prose\n\n{FENCE}text\nhello\n{FENCE}\n", encoding="utf-8")
    selected = examples.pages_to_run([saved_only, nothing], tmp_path)
    assert [page.rel for page in selected] == ["saved.md"]
