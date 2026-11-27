"""The docs feature coverage gate fails on a feature no example reaches, and passes
once an example reaches it, with the real docs runner and real coverage.

A gate that cannot fail is worse than none: the docs feature coverage check would be
green over examples that exercise nothing. So a planted feature, one ASH function, is
measured end to end here: synthetic pages run through ``PageRunner`` with a coverage
directory of their own (``DocsCoverage``), coverage.py starts in every Python process
of each block through ``COVERAGE_PROCESS_START`` and the rc file the runner writes
into that directory, and ``scripts/docs_feature_coverage.py check`` reads the data
and the runner's records:

* a page whose block does not call the planted function fails the gate, naming it;
* a python block that calls it passes;
* a shell block's python grandchild carries the block's coverage context;
* a forked child that ends in ``os._exit`` saves no coverage data, so no pool's
  shutdown can cut a save off and leave a file the check cannot read;
* a block that leaves a process running fails, naming it, and counts for nothing,
  while one that waits for the process it started counts;
* a block that reaches the function and then fails its expected exit does not count;
* nor does a block that reaches it while it shows ASH refusing something (its marker
  expects the usage-error exit), nor one whose output sample no longer matches;
* a call that the function's leading guard answers does not reach its region.

It also pins what the runner records (every block it ran or saved, with its session
and the exit it expects, and nothing for a page whose run raised) and that a block's
context is its own: given to that block only, never carried to the next one, and
nothing at all without coverage.

Each test builds its own coverage directory and never reads ASH_DOCS_COVERAGE_DIR: the
docs examples job sets that variable for this whole directory, and these pages must
not reach its data.

Skipped on Windows, which the docs runner does not support (see docs_runner.py).
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import inspect
import json
import os
import re
import sys
from pathlib import Path

import pytest
from coverage import CoverageData

from automated_security_helper.core.enums import AshExitCode

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.name == "nt",
        reason="POSIX shell and process groups; the docs job has no Windows runner",
    ),
]

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
FENCE = "```"

#: The planted feature's id. Its kind is measured by code reach alone, like the MCP
#: tools and the plugins, so a passing block that runs its region covers it.
PLANTED_ID = "mcp-tool:planted"

#: A path the planted function reads past its leading guard (it is not blank, so the
#: guard does not answer it), and a blank one the guard answers at once.
REACHES_THE_REGION = "/opt/ash/bin"
ANSWERED_EARLY = "   "


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    return module


runner = _load("_ash_docs_runner", HERE / "docs_runner.py")
checks = runner.load_docs_checks()


def _cov():
    """scripts/docs_feature_coverage.py, loaded by path like the other scripts."""
    return _load(
        "_ash_docs_feature_coverage", REPO_ROOT / "scripts" / "docs_feature_coverage.py"
    )


def _planted_function():
    from automated_security_helper.core import constants

    return constants.is_blank_bin_path


def _planted():
    """The planted feature: ``is_blank_bin_path``, a pure function of
    automated_security_helper.core.constants.

    Chosen because importing that module runs none of its body: measured on this
    tree, no statement of it runs at ``import automated_security_helper.core.constants``,
    while the module's import-time lines do. So a block that imports the module puts
    its own context in the data (the check then has a passing block it can read) and
    reaches this function only if it calls it. A function whose body ran at import
    would make the uncovered page below cover it; that test says so if it happens.

    Its region starts past its leading guard, the ``return True`` for a blank path,
    which is the first statement of its body: the region rule measures past the
    guards a function opens with, and only those. So the pages that must reach it call
    it with a path that is not blank, and one page calls it with a path that guard
    answers.
    """
    return _cov().code_feature(PLANTED_ID, _planted_function())


def _run_page(tmp_path: Path, text: str, coverage=None):
    """Run a synthetic page; with ``coverage``, through the runner's coverage hook."""
    docs = tmp_path / "docs"
    docs.mkdir(exist_ok=True)
    path = docs / "page.md"
    path.write_text(text, encoding="utf-8")
    page = checks.parse_page(path, docs)
    scratch = tmp_path / "sessions"
    scratch.mkdir()
    if coverage is None:
        results = runner.PageRunner(page, scratch).run()
    else:
        results = runner.PageRunner(page, scratch, coverage=coverage).run()
    return page, results


def _coverage(tmp_path: Path):
    return runner.DocsCoverage(directory=tmp_path / "coverage")


def _check(tmp_path: Path, coverage, page):
    """Run the gate over this page's run alone, with an empty baseline."""
    baseline = tmp_path / "baseline.txt"
    baseline.write_text("# This file may only shrink.\n", encoding="utf-8")
    out = tmp_path / "out"
    code = _cov().run_check(
        data=coverage.directory,
        baseline=baseline,
        docs_root=page.path.parent,
        out=out,
        features=[_planted()],
        corpus=[page.path],
    )
    report = json.loads(
        (out / "docs-feature-coverage.json").read_text(encoding="utf-8")
    )
    (feature,) = [entry for entry in report["features"] if entry["id"] == PLANTED_ID]
    markdown = (out / "docs-feature-coverage.md").read_text(encoding="utf-8")
    return code, report, feature, markdown


def _contexts_on(path: str, lines, directory: Path) -> set[str]:
    """The contexts the data files record on any of ``lines`` of ``path``, read with
    coverage.py's own API and nothing of the module under test."""
    found: set[str] = set()
    parts = sorted((directory / "data").glob(".coverage.*"))
    assert parts, f"no coverage data file was written under {directory / 'data'}"
    for part in parts:
        data = CoverageData(basename=str(part))
        data.read()
        try:
            for measured in data.measured_files():
                if not measured.replace("\\", "/").endswith("/" + path):
                    continue
                for line, contexts in data.contexts_by_lineno(measured).items():
                    if line in lines:
                        found.update(contexts)
        finally:
            data.close()
    return found


def _region_contexts(directory: Path) -> set[str]:
    (region,) = _planted().regions
    return _contexts_on(region.path, region.lines, directory)


def _lines_before_the_region() -> set[int]:
    """The lines of the planted function's body statements before its region: the
    statements up to and through its early exit. Not its def, decorator or docstring
    lines: the def line runs when the module is imported, so a block that only
    imports the module puts its context there."""
    function = _planted_function()
    (region,) = _planted().regions
    tree = ast.parse(Path(inspect.getsourcefile(function)).read_text(encoding="utf-8"))
    (node,) = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == function.__name__
        and function.__code__.co_firstlineno
        in (node.lineno, *(decorator.lineno for decorator in node.decorator_list))
    ]
    body = node.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    first = min(region.lines)
    lines = {
        line
        for statement in body
        if statement.end_lineno < first
        for line in range(statement.lineno, statement.end_lineno + 1)
    }
    assert lines and not lines & region.lines, (
        "the planted function has no statement before its region, so no call that its "
        "early exit answers can be told from a call that does not run it at all"
    )
    assert node.lineno not in lines
    return lines


def _fence_lines(page) -> list[int]:
    return [block.fence_line for block in page.blocks]


def _record(coverage) -> dict:
    """The runner's record of page.md."""
    name = hashlib.sha256(b"page.md").hexdigest()[:16] + ".json"
    return json.loads(
        (coverage.directory / "blocks" / name).read_text(encoding="utf-8")
    )


def _calls(name: str) -> str:
    return f"""{FENCE}python
import automated_security_helper.core.constants as constants

print(constants.is_blank_bin_path("{name}"))
{FENCE}
"""


IMPORTS_THE_MODULE = f"""{FENCE}python
import automated_security_helper.core.constants as constants

print(constants.ASH_DOCS_URL)
{FENCE}
"""

CALLS_THE_FUNCTION = _calls(REACHES_THE_REGION)


def test_a_page_whose_block_does_not_call_the_planted_function_fails_the_gate(tmp_path):
    coverage = _coverage(tmp_path)
    page, results = _run_page(tmp_path, IMPORTS_THE_MODULE, coverage)

    assert [r.ok for r in results] == [True], runner.failure_report(results)
    assert not _region_contexts(coverage.directory), (
        "the planted function's body ran without the block calling it, so this page "
        "cannot show the gate failing; plant a function whose body does not run when "
        "its module is imported"
    )
    (region,) = _planted().regions
    assert not _contexts_on(
        region.path, _lines_before_the_region(), coverage.directory
    ), (
        "importing the planted function's module ran the statements before its "
        "region, so the early-exit test cannot tell a call its early exit answers "
        "from an import"
    )
    code, report, feature, markdown = _check(tmp_path, coverage, page)

    assert code == 1
    assert feature["covered"] is False
    assert report["gate"]["failures"]["F1"] == [PLANTED_ID]
    assert PLANTED_ID in markdown
    # The block's own context reached the data: this is a gate failure over a sound
    # measurement, not a measurement that measured nothing.
    assert report["denominators"]["blocks_passed"] == 1
    assert report["denominators"]["contexts"] >= 1


def test_a_python_block_that_calls_the_planted_function_passes_the_gate(tmp_path):
    coverage = _coverage(tmp_path)
    page, results = _run_page(tmp_path, CALLS_THE_FUNCTION, coverage)

    assert [r.ok for r in results] == [True], runner.failure_report(results)
    (line,) = _fence_lines(page)
    assert _region_contexts(coverage.directory) == {f"page.md::{line}"}
    code, _report, feature, _markdown = _check(tmp_path, coverage, page)

    assert code == 0
    assert feature["covered"] is True
    assert feature["pages"] == ["page.md"]


def test_a_shell_blocks_python_grandchild_carries_the_blocks_context(tmp_path):
    """ASH runs in children of a block's shell (``ash``, ``python``), not in the shell
    and not in the pytest process: the context and the rc file reach them through the
    session's environment."""
    coverage = _coverage(tmp_path)
    page, results = _run_page(
        tmp_path,
        f"""{FENCE}bash
python -c "import automated_security_helper.core.constants as c; c.is_blank_bin_path('{REACHES_THE_REGION}')"
{FENCE}
""",
        coverage,
    )

    assert [r.ok for r in results] == [True], runner.failure_report(results)
    (line,) = _fence_lines(page)
    assert _region_contexts(coverage.directory) == {f"page.md::{line}"}
    code, _report, feature, _markdown = _check(tmp_path, coverage, page)

    assert code == 0
    assert feature["covered"] is True


def test_a_forked_child_that_ends_in_os_exit_writes_no_coverage_data(tmp_path):
    """No measured process saves its coverage data inside ``os._exit``.

    multiprocessing's fork workers end in ``os._exit``, and a pool shut down by its
    ``with`` block sends SIGTERM to every worker still alive, one inside that save
    included: the save is cut off and the data file it leaves cannot be read, which
    stops the check with exit 2. So a forked child that ends in ``os._exit`` leaves no
    data file, while the block's own process still leaves its own."""
    coverage = _coverage(tmp_path)
    _page, results = _run_page(
        tmp_path,
        f"""{FENCE}python
import os

import automated_security_helper.core.constants as constants

child = os.fork()
if child == 0:
    constants.is_blank_bin_path("{REACHES_THE_REGION}")
    os._exit(0)
os.waitpid(child, 0)
print("pids", os.getpid(), child)
{FENCE}
""",
        coverage,
    )

    assert [r.ok for r in results] == [True], runner.failure_report(results)
    (line,) = [
        text for text in results[0].output.splitlines() if text.startswith("pids ")
    ]
    parent, child = (int(word) for word in line.split()[1:])
    names = [part.name for part in (coverage.directory / "data").glob(".coverage.*")]
    assert any(f".pid{parent}." in name for name in names), names
    assert not [name for name in names if f".pid{child}." in name], names


def _starts_in_the_background(seconds: int) -> str:
    """A shell line that starts a measured python process in the background, its
    output sent away from the block's: after ``seconds`` it reaches the planted
    function's region."""
    return (
        f'python -c "import time; time.sleep({seconds}); '
        "import automated_security_helper.core.constants as c; "
        f"c.is_blank_bin_path('{REACHES_THE_REGION}')\" > /dev/null 2>&1 &"
    )


def test_a_block_that_leaves_a_process_running_fails_names_it_and_counts_for_nothing(
    tmp_path,
):
    """A process a block leaves running keeps the block's coverage context: it read
    the context from its environment when coverage started in it, so what it runs
    after the block ended would count for that block, though nothing of the block
    shows it. So once a block's shell has exited, the block's process group must hold
    no process: a block that leaves one fails, the runner names the process it left,
    and the block is no evidence. The process here reaches the planted function only
    after its block ended."""
    pid_file = tmp_path / "left-running.pid"
    coverage = _coverage(tmp_path)
    page, results = _run_page(
        tmp_path,
        IMPORTS_THE_MODULE
        + f"""
{FENCE}bash
{_starts_in_the_background(30)}
echo "$!" > "{pid_file}"
{FENCE}
""",
        coverage,
    )

    assert [r.ok for r in results] == [True, False], runner.failure_report(results)
    left = pid_file.read_text(encoding="utf-8").strip()
    assert left.isdigit(), left
    # The pid is named by the runner, not by a line of the block's own text.
    shown = {text.strip() for text in results[1].command.splitlines()}
    named = [
        text
        for text in results[1].report().splitlines()
        if text.strip() not in shown and re.search(rf"(?<!\d){left}(?!\d)", text)
    ]
    assert named, results[1].report()
    code, report, feature, _markdown = _check(tmp_path, coverage, page)

    assert code == 1
    assert feature["covered"] is False
    assert report["gate"]["failures"]["F1"] == [PLANTED_ID]


def test_a_block_that_waits_for_the_process_it_started_counts(tmp_path):
    """The control: a block that starts a process in the background and waits for it
    leaves nothing running, passes, and counts for what that process reached."""
    coverage = _coverage(tmp_path)
    page, results = _run_page(
        tmp_path,
        f"""{FENCE}bash
{_starts_in_the_background(1)}
wait
{FENCE}
""",
        coverage,
    )

    assert [r.ok for r in results] == [True], runner.failure_report(results)
    (line,) = _fence_lines(page)
    assert _region_contexts(coverage.directory) == {f"page.md::{line}"}
    code, _report, feature, _markdown = _check(tmp_path, coverage, page)

    assert code == 0
    assert feature["covered"] is True


def test_a_block_that_reaches_the_planted_function_and_then_fails_does_not_count(
    tmp_path,
):
    """An example that does not end the way its marker says demonstrates nothing,
    even when its code ran."""
    coverage = _coverage(tmp_path)
    page, results = _run_page(
        tmp_path,
        IMPORTS_THE_MODULE
        + f"""
{FENCE}python
import automated_security_helper.core.constants as constants

constants.is_blank_bin_path("{REACHES_THE_REGION}")
raise SystemExit(3)
{FENCE}
""",
        coverage,
    )

    assert [r.ok for r in results] == [True, False], runner.failure_report(results)
    _first, second = _fence_lines(page)
    assert _region_contexts(coverage.directory) == {f"page.md::{second}"}, (
        "the failing block did not reach the planted function, so this test would "
        "pass for the wrong reason"
    )
    code, report, feature, _markdown = _check(tmp_path, coverage, page)

    assert code == 1
    assert feature["covered"] is False
    assert report["gate"]["failures"]["F1"] == [PLANTED_ID]


def test_a_block_that_shows_a_refusal_does_not_count_though_it_reached_the_function(
    tmp_path,
):
    """A block whose marker expects ASH's usage-error exit passes when ASH refuses
    what it was given: it shows the refusal, not the work of the code it reached."""
    refused = int(AshExitCode.USAGE_ERROR)
    coverage = _coverage(tmp_path)
    page, results = _run_page(
        tmp_path,
        IMPORTS_THE_MODULE
        + f"""
<!-- doctest: run expect-exit={refused} -->
{FENCE}python
import automated_security_helper.core.constants as constants

constants.is_blank_bin_path("{REACHES_THE_REGION}")
raise SystemExit({refused})
{FENCE}
""",
        coverage,
    )

    assert [r.ok for r in results] == [True, True], runner.failure_report(results)
    first, second = _fence_lines(page)
    assert _region_contexts(coverage.directory) == {f"page.md::{second}"}, (
        "the refusal block did not reach the planted function, so this test would "
        "pass for the wrong reason"
    )
    assert [
        (block["line"], block["expected"], block["ok"])
        for block in _record(coverage)["blocks"]
    ] == [(first, "0", True), (second, str(refused), True)]
    code, report, feature, _markdown = _check(tmp_path, coverage, page)

    assert code == 1
    assert feature["covered"] is False
    assert report["gate"]["failures"]["F1"] == [PLANTED_ID]


def test_a_block_whose_output_sample_no_longer_matches_does_not_count(tmp_path):
    """An output sample is part of what its example claims: the record's verdict for
    the block it shows is the block's and the sample's together."""
    coverage = _coverage(tmp_path)
    page, results = _run_page(
        tmp_path,
        IMPORTS_THE_MODULE
        + "\n"
        + CALLS_THE_FUNCTION
        + f"""
<!-- doctest: output -->
{FENCE}text
a line the block does not print
{FENCE}
""",
        coverage,
    )

    assert [r.ok for r in results] == [True, True, False], runner.failure_report(
        results
    )
    first, shown, _sample = _fence_lines(page)
    assert _region_contexts(coverage.directory) == {f"page.md::{shown}"}
    assert [(block["line"], block["ok"]) for block in _record(coverage)["blocks"]] == [
        (first, True),
        (shown, False),
    ]
    code, report, feature, _markdown = _check(tmp_path, coverage, page)

    assert code == 1
    assert feature["covered"] is False
    assert report["gate"]["failures"]["F1"] == [PLANTED_ID]


def test_a_call_that_the_functions_leading_guard_answers_does_not_reach_its_region(
    tmp_path,
):
    """The guards a function opens with run on calls that do none of the work past
    them, so they are not its region: the function ran, and the gate still finds it
    uncovered."""
    coverage = _coverage(tmp_path)
    page, results = _run_page(tmp_path, _calls(ANSWERED_EARLY), coverage)

    assert [r.ok for r in results] == [True], runner.failure_report(results)
    (line,) = _fence_lines(page)
    (region,) = _planted().regions
    assert f"page.md::{line}" in _contexts_on(
        region.path, _lines_before_the_region(), coverage.directory
    ), (
        "the block did not run the planted function's statements before its region, "
        "so it never called the function and this test would pass for the wrong "
        "reason"
    )
    assert not _region_contexts(coverage.directory)
    code, report, feature, _markdown = _check(tmp_path, coverage, page)

    assert code == 1
    assert feature["covered"] is False
    assert report["gate"]["failures"]["F1"] == [PLANTED_ID]


def test_the_runner_records_every_block_it_ran_or_saved_with_its_session(tmp_path):
    """One record per page: each block run or saved, with its context, the session it
    ran in, whether the runner runs it, its save-as path, the exit it expects and its
    verdict (with its output sample's). An output sample is compared, not run, and is
    not in the record."""
    coverage = _coverage(tmp_path)
    page, results = _run_page(
        tmp_path,
        f"""{FENCE}python
print("first")
{FENCE}

<!-- doctest: save-as=notes/settings.yaml -->
{FENCE}yaml
project_name: example
{FENCE}

<!-- doctest: run fresh -->
{FENCE}bash
echo second
{FENCE}

<!-- doctest: output -->
{FENCE}text
second
{FENCE}
""",
        coverage,
    )

    assert all(r.ok for r in results), runner.failure_report(results)
    first, saved, fresh, _sample = _fence_lines(page)

    assert _record(coverage) == {
        "schema": 1,
        "page": "page.md",
        "blocks": [
            {
                "line": first,
                "context": f"page.md::{first}",
                "session": 1,
                "runs": True,
                "save_as": None,
                "expected": "0",
                "ok": True,
            },
            {
                "line": saved,
                "context": f"page.md::{saved}",
                "session": 1,
                "runs": False,
                "save_as": "notes/settings.yaml",
                "expected": "0",
                "ok": True,
            },
            {
                "line": fresh,
                "context": f"page.md::{fresh}",
                "session": 2,
                "runs": True,
                "save_as": None,
                "expected": "0",
                "ok": True,
            },
        ],
    }


def test_a_page_whose_run_raised_leaves_no_record(tmp_path):
    """A record gives each block's verdict, and a run that raised part way has none
    for the blocks it never reached: it writes no record, so the page gives no
    evidence (the examples test fails on the error itself). Here the second save
    needs a directory where the first save left a file."""
    coverage = _coverage(tmp_path)
    docs = tmp_path / "docs"
    docs.mkdir()
    path = docs / "page.md"
    path.write_text(
        f"""<!-- doctest: save-as=notes.txt -->
{FENCE}text
some notes
{FENCE}

<!-- doctest: save-as=notes.txt/inner.yaml -->
{FENCE}yaml
project_name: example
{FENCE}
""",
        encoding="utf-8",
    )
    page = checks.parse_page(path, docs)
    scratch = tmp_path / "sessions"
    scratch.mkdir()

    with pytest.raises(OSError):
        runner.PageRunner(page, scratch, coverage=coverage).run()

    blocks = coverage.directory / "blocks"
    assert blocks.is_dir(), (
        "the page's session never started, so this test would pass for the wrong reason"
    )
    assert list(blocks.iterdir()) == []


def test_each_block_gets_its_own_context_and_cannot_carry_one_forward(tmp_path):
    """The context is the block's own variable, like a marker's env=: a block that
    exports another value does not hand it to the next block. A session carries one
    coverage variable, the rc file the runner wrote into the coverage directory, and
    a fresh session gets it again; the directory itself reaches no session."""
    coverage = _coverage(tmp_path)
    rcfile = coverage.directory / "coverage.rc"
    text = f"""{FENCE}bash
test "$DOCS_COVERAGE_CONTEXT" = "page.md::1"
test "$COVERAGE_PROCESS_START" = "{rcfile}"
test -z "${{ASH_DOCS_COVERAGE_DIR:-}}"
export DOCS_COVERAGE_CONTEXT=carried-forward
{FENCE}

{FENCE}bash
test "$DOCS_COVERAGE_CONTEXT" = "page.md::8"
{FENCE}

<!-- doctest: run fresh -->
{FENCE}bash
test "$DOCS_COVERAGE_CONTEXT" = "page.md::13"
test "$COVERAGE_PROCESS_START" = "{rcfile}"
test -z "${{ASH_DOCS_COVERAGE_DIR:-}}"
{FENCE}
"""
    page, results = _run_page(tmp_path, text, coverage)

    assert _fence_lines(page) == [1, 8, 13], "the expected contexts above are stale"
    assert [r.ok for r in results] == [True, True, True], runner.failure_report(results)
    assert rcfile.is_file()


def test_without_coverage_a_session_sees_no_coverage_variable_and_nothing_is_recorded(
    tmp_path, monkeypatch
):
    """A runner built without coverage changes nothing, even in a process whose own
    environment names a coverage directory and a context: the twins and the runner's
    own failure proofs never reach the docs examples' data."""
    from_the_environment = tmp_path / "from-the-environment"
    monkeypatch.setenv("ASH_DOCS_COVERAGE_DIR", str(from_the_environment))
    monkeypatch.setenv("DOCS_COVERAGE_CONTEXT", "from-the-environment")

    _page, results = _run_page(
        tmp_path,
        f"""{FENCE}bash
test -z "${{ASH_DOCS_COVERAGE_DIR:-}}"
test -z "${{DOCS_COVERAGE_CONTEXT:-}}"
test -z "${{COVERAGE_PROCESS_START:-}}"
{FENCE}
""",
    )

    assert [r.ok for r in results] == [True], runner.failure_report(results)
    assert not from_the_environment.exists()
