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
the isolation the job relies on (private HOME, the venv's ash, no network).
"""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path

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
assert Path("../greeting.txt").read_text().strip() == "hello"
{FENCE}
""",
    )
    assert [r.lang for r in results] == ["bash", "console", "python"]
    assert all(r.ok for r in results), runner.failure_report(results)


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


def test_a_block_past_its_timeout_is_stopped_and_reported(tmp_path):
    started = time.monotonic()
    results = _run(
        tmp_path,
        f"""<!-- doctest: run timeout=1 -->
{FENCE}bash
tail -f /dev/null
{FENCE}
""",
    )
    (result,) = results
    assert result.timed_out and not result.ok
    assert "timed out after" in result.report()
    assert time.monotonic() - started < 30, "the timeout did not stop the block"


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
    assert all(r.ok for r in results), runner.failure_report(results)


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
    assert all(r.ok for r in results), runner.failure_report(results)


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
    assert all(r.ok for r in results), runner.failure_report(results)


def test_fixtures_come_from_the_docs_root(tmp_path):
    """With --docs-root, a page starts in that tree's fixture, not this checkout's."""
    docs_root = tmp_path / "docs-tree"
    fixture = docs_root / checks.DOC_FIXTURES_DIR / checks.DEFAULT_FIXTURE
    fixture.mkdir(parents=True)
    (fixture / "only-in-the-docs-tree.txt").write_text("x\n", encoding="utf-8")
    scratch = tmp_path / "sessions"
    scratch.mkdir()
    page = _page(tmp_path, f"{FENCE}bash\ntest -f only-in-the-docs-tree.txt\n{FENCE}\n")
    results = runner.PageRunner(page, scratch, docs_root=docs_root).run()
    assert all(r.ok for r in results), runner.failure_report(results)
