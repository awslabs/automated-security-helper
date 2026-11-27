"""Docs feature coverage: which product features the executed docs examples reach.

scripts/docs_feature_coverage.py enumerates the product's features from code (the
commands and options of the click tree, the plugins the plugin modules register, the
rows of the configuration reference, the MCP tools), reads the coverage data the docs
examples job collects (one coverage context per executed block, ``<page>::<fence
line>``) together with the runner's record of every block it ran or saved, and says
which features a passing executed example, one expected to succeed or to report
findings (or a scan expected to end with scanner errors that wrote its results),
reached. ``check`` fails on an uncovered feature missing from a
shrink-only baseline (F1) and on a baseline line that names no feature (F2); given
the base branch's baseline it also fails on a line for a covered feature (F3) and on
a line the pull request added (F4). It exits 2 when the measurement measured nothing.

These tests hold that contract without running anything: the coverage data is
written with coverage.py's own CoverageData API and the runner's records as the JSON
the runner writes, so each rule is shown on input whose answer is known. The runner's
side of the collection (tests/integration/docs/docs_runner.py, ``DocsCoverage``) is
held here where it runs in this process; the end-to-end proof with the real runner and
real coverage is tests/integration/docs/test_docs_feature_coverage_can_fail.py.

Paths in a feature's region are repository-relative POSIX paths from
``automated_security_helper/``, so the tests read the same on every OS the unit tier
runs on.
"""

from __future__ import annotations

import ast
import configparser
import functools
import hashlib
import importlib
import importlib.util
import inspect
import json
import os
import re
import sys
import uuid
from collections import defaultdict
from pathlib import Path

import pytest
import yaml
from coverage import CoverageData

from automated_security_helper.core.enums import AshExitCode

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "scripts" / "docs_feature_coverage.py"
RUNNER = REPO_ROOT / "tests" / "integration" / "docs" / "docs_runner.py"
COMMITTED_BASELINE = REPO_ROOT / "scripts" / "docs_feature_coverage_baseline.txt"
FENCE = "```"

#: Every kind of feature the inventory holds.
KINDS = ("command", "option", "scanner", "reporter", "converter", "config", "mcp-tool")
#: What the report directory holds after a run.
REPORT_JSON = "docs-feature-coverage.json"
REPORT_MD = "docs-feature-coverage.md"
BASELINE_OUT = "docs_feature_coverage_baseline.txt"
#: What the baseline's header must keep saying.
RATCHET_SENTENCE = "may only shrink"
DENOMINATORS = (
    "pages_recorded",
    "pages_selected",
    "blocks_run",
    "blocks_passed",
    "data_files",
    "contexts",
)

#: The file the runner writes into its coverage directory for every measured process.
RCFILE_NAME = "coverage.rc"
#: The exit codes a block may expect and still be evidence (AshExitCode names):
#: success and actionable findings. Every other expectation shows ASH refusing
#: something or being stopped, and the code it names never ran its work.
COUNTING_EXITS = ("SUCCESS", "ACTIONABLE_FINDINGS")
#: An exit that counts only when the block's scan also wrote its results (it reached
#: ASHScanOrchestrator._write_results_file past its early exits): ASH exits 1 for a
#: scan with scanner errors and for many refusals alike (``--use-existing`` with no
#: results, ``ash config init`` refusing a second source), and a refusal never ran the
#: work its feature names.
COUNTING_ONCE_A_SCAN_WROTE_ITS_RESULTS = ("SCAN_ERRORS",)
#: The workflow that runs the docs examples and the docs feature coverage check.
UNIFIED_CI = REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml"

#: A planted feature's code. The file need not exist: the evaluation reads only the
#: coverage data and the feature's own region.
PLANTED_PATH = "automated_security_helper/planted_for_the_gate.py"
PLANTED_LINES = frozenset({10, 11, 12})
#: Code that a block reaches when it must reach something other than the feature.
OTHER_PATH = "automated_security_helper/somewhere_else.py"


# --------------------------------------------------------------------------- #
# Loading the modules under test
# --------------------------------------------------------------------------- #


def _load(name: str, path: Path):
    """A module loaded by path, the way the docs tests load scripts/ (not a package)."""
    if name in sys.modules:
        return sys.modules[name]
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        # A module that failed half way is not left for the next test to find.
        del sys.modules[name]
        raise
    return module


def _cov():
    """scripts/docs_feature_coverage.py."""
    return _load("_ash_docs_feature_coverage", SCRIPT)


def _runner():
    """tests/integration/docs/docs_runner.py, under the name the other docs tests use."""
    return _load("_ash_docs_runner", RUNNER)


def _checks():
    return _runner().load_docs_checks()


@functools.lru_cache(maxsize=1)
def _inventory() -> tuple:
    return tuple(_cov().inventory())


def _by_id() -> dict:
    return {feature.id: feature for feature in _inventory()}


# --------------------------------------------------------------------------- #
# A synthetic run: the docs tree, the runner's records, the coverage data
# --------------------------------------------------------------------------- #


class Run:
    """What a docs examples run leaves behind, built by hand for one test.

    ``data`` is the coverage directory with the runner's layout: coverage data files
    under ``data/`` (``.coverage.<suffix>``) and one record per page under
    ``blocks/<sha256(page)[:16]>.json``. The data says the code ran in another
    checkout, as data from a CI runner does.
    """

    def __init__(self, tmp_path: Path):
        self.root = tmp_path
        self.docs = tmp_path / "docs"
        self.data = tmp_path / "coverage"
        self.out = tmp_path / "out"
        self.checkout = tmp_path / "elsewhere" / "checkout"
        self.docs.mkdir()
        (self.data / "data").mkdir(parents=True)
        (self.data / "blocks").mkdir(parents=True)
        self.corpus: list[Path] = []
        self._data_files = 0

    def page(self, rel: str, text: str) -> list[int]:
        """Write a page into the docs tree and the corpus; the fence lines of its blocks."""
        path = self.docs / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        self.corpus.append(path)
        page = _checks().parse_page(path, self.docs)
        return [block.fence_line for block in page.blocks]

    def real_page(self, rel: str):
        """A page of this repository's docs, copied into the docs tree under its own
        path, parsed: the test reads the page as it is now, never a copy of its
        lines."""
        self.page(rel, (REPO_ROOT / rel).read_text(encoding="utf-8"))
        return _checks().parse_page(self.docs / rel, self.docs)

    def record(self, rel: str, *blocks: dict) -> None:
        """The runner's record of a page: every block it ran or saved."""
        name = hashlib.sha256(rel.encode("utf-8")).hexdigest()[:16] + ".json"
        (self.data / "blocks" / name).write_text(
            json.dumps({"schema": 1, "page": rel, "blocks": list(blocks)}),
            encoding="utf-8",
        )

    def measured(self, region_path: str) -> str:
        return str(self.checkout.joinpath(*region_path.split("/")))

    def hit(
        self, context: str, region_path: str, lines, *, measured: str | None = None
    ) -> None:
        """One data file in which ``context`` ran ``lines`` of ``region_path``."""
        self._data_files += 1
        data = CoverageData(
            basename=str(self.data / "data" / ".coverage"),
            suffix=f"synthetic.{self._data_files}",
        )
        data.set_context(context)
        data.add_lines({measured or self.measured(region_path): sorted(lines)})
        data.write()
        data.close()


def _block(
    rel: str,
    line: int,
    *,
    session: int = 1,
    runs: bool = True,
    ok: bool = True,
    save_as: str | None = None,
    expected: str = "0",
) -> dict:
    """One block of a record, as the runner writes it: ``expected`` is the exit its
    marker names (``0`` when it names none), as the runner reads it, and ``ok`` is
    the block's verdict together with its output sample's."""
    return {
        "line": line,
        "context": f"{rel}::{line}",
        "session": session,
        "runs": runs,
        "save_as": save_as,
        "expected": expected,
        "ok": ok,
    }


def _baseline(path: Path, ids) -> Path:
    path.write_text(
        f"# This file {RATCHET_SENTENCE}.\n#\n" + "".join(f"{i}\n" for i in ids),
        encoding="utf-8",
    )
    return path


def _planted(
    feature_id: str = "scanner:planted", path: str = PLANTED_PATH, lines=PLANTED_LINES
):
    """A feature of a kind measured by code reach alone, with a region of its own."""
    cov = _cov()
    return cov.Feature(
        id=feature_id,
        regions=(cov.Region(path=path, lines=frozenset(lines)),),
        location=f"{path}:9",
    )


def _check(run: Run, features, baseline_ids=(), **kwargs) -> int:
    return _cov().run_check(
        data=run.data,
        baseline=_baseline(run.root / "baseline.txt", baseline_ids),
        docs_root=run.docs,
        out=run.out,
        features=list(features),
        corpus=list(run.corpus),
        **kwargs,
    )


def _report(run: Run) -> dict:
    return json.loads((run.out / REPORT_JSON).read_text(encoding="utf-8"))


def _markdown(run: Run) -> str:
    return (run.out / REPORT_MD).read_text(encoding="utf-8")


def _evaluate(run: Run, features):
    return _cov().evaluate(list(features), run.data, run.docs, list(run.corpus))


def _covered(run: Run, features) -> frozenset:
    return _evaluate(run, features).covered


def _join(*blocks: str) -> str:
    return "\n\n".join(blocks) + "\n"


def _the_block(page, *needles: str):
    """The one block of a page whose text holds every needle: found by its content,
    so a case on a real page follows the page when its lines move."""
    found = [block for block in page.blocks if all(n in block.body for n in needles)]
    assert len(found) == 1, (page.rel, needles, [block.fence_line for block in found])
    return found[0]


def _expected_exit(block) -> str:
    """The exit a block's marker expects, as the runner reads it (``0`` by default)."""
    if block.marker is None:
        return "0"
    return str(block.marker.keys.get("expect-exit", "0"))


def _record_as_the_runner_does(run: Run, rel: str):
    """Record every block of a page that the runner runs or saves, each in the
    session the runner gives it and expecting what its marker says, every one
    passing: the record a run of the page leaves. The parsed page."""
    checks = _checks()
    page = checks.parse_page(run.docs / rel, run.docs)
    blocks = []
    for number, _fixture, block in _runner().page_sessions(page):
        runs = checks.runner_runs(block)
        blocks.append(
            _block(
                rel,
                block.fence_line,
                session=number,
                runs=runs,
                save_as=block.save_as or None,
                expected=_expected_exit(block) if runs else "0",
            )
        )
    run.record(rel, *blocks)
    return page


ONE_BLOCK = f"""# A page

{FENCE}python
print("an example")
{FENCE}
"""

TWO_BLOCKS = f"""# Two blocks

{FENCE}python
print("first")
{FENCE}

{FENCE}python
print("second")
{FENCE}
"""


def _valid_run(tmp_path: Path) -> tuple[Run, int]:
    """One passing block that reached the planted feature."""
    run = Run(tmp_path)
    (line,) = run.page("page.md", ONE_BLOCK)
    run.record("page.md", _block("page.md", line))
    run.hit(f"page.md::{line}", PLANTED_PATH, {11})
    return run, line


def _outputs_run(tmp_path: Path):
    """A run with one covered and one uncovered planted feature, and a failing block."""
    run = Run(tmp_path)
    first, second = run.page("page.md", TWO_BLOCKS)
    run.record("page.md", _block("page.md", first), _block("page.md", second, ok=False))
    run.hit(f"page.md::{first}", PLANTED_PATH, {11})
    run.hit(f"page.md::{second}", OTHER_PATH, {3})
    features = [
        _planted("scanner:planted"),
        _planted("reporter:planted", path=OTHER_PATH, lines={20}),
    ]
    return run, features


# --------------------------------------------------------------------------- #
# Reading code the way the inventory must, as an oracle independent of it
# --------------------------------------------------------------------------- #


def _function_node(
    path: str, name: str | None = None, *, cls: str | None = None, lineno=None
):
    """A function of a repository file, from its syntax tree: by class and name, or
    by the line its def is on."""
    tree = ast.parse((REPO_ROOT / path).read_text(encoding="utf-8"))
    if lineno is not None:
        scope = list(ast.walk(tree))
    elif cls is not None:
        (klass,) = [
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == cls
        ]
        scope = klass.body
    else:
        scope = tree.body
    found = [
        node
        for node in scope
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and (name is None or node.name == name)
        and (lineno is None or node.lineno == lineno)
    ]
    assert len(found) == 1, (path, name, cls, lineno, [n.lineno for n in found])
    return found[0]


def _without_docstring(body: list) -> list:
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


def _is_guard(statement) -> bool:
    """An early exit: a top-level ``if`` with no ``else`` whose body ends in
    ``return`` or ``raise``."""
    return (
        isinstance(statement, ast.If)
        and not statement.orelse
        and isinstance(statement.body[-1], (ast.Return, ast.Raise))
    )


def _region_oracle(node) -> frozenset:
    """The region rule, read from the syntax tree on its own: the body without its
    docstring, past its last early exit (all of it when it has none, or when nothing
    follows the last one), each statement as its full span of lines."""
    body = _without_docstring(node.body)
    guards = [index for index, statement in enumerate(body) if _is_guard(statement)]
    if guards and guards[-1] + 1 < len(body):
        body = body[guards[-1] + 1 :]
    return frozenset(
        line
        for statement in body
        for line in range(statement.lineno, statement.end_lineno + 1)
    )


def _calls_super_scan(node) -> bool:
    """Whether a function calls ``super().scan(...)``."""
    return any(
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "scan"
        and isinstance(call.func.value, ast.Call)
        and isinstance(call.func.value.func, ast.Name)
        and call.func.value.func.id == "super"
        for call in ast.walk(node)
    )


def _is_not_implemented_stub(node) -> bool:
    """Whether a function does nothing but raise NotImplementedError."""
    body = _without_docstring(node.body)
    if len(body) != 1 or not isinstance(body[0], ast.Raise) or body[0].exc is None:
        return False
    exc = body[0].exc
    target = exc.func if isinstance(exc, ast.Call) else exc
    return isinstance(target, ast.Name) and target.id == "NotImplementedError"


def _innermost_function(path: str, line: int):
    tree = ast.parse((REPO_ROOT / path).read_text(encoding="utf-8"))
    around = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno < line <= node.end_lineno
    ]
    assert around, f"{path}:{line} is in no function"
    return max(around, key=lambda node: node.lineno)


def _assert_region(region, node) -> None:
    """``region`` is ``node``'s region under the rule, line for line."""
    expected = _region_oracle(node)
    assert expected, f"{region.path}: {node.name} has no statement to measure"
    assert region.lines == expected, (
        f"{region.path}: the region of {node.name} (def at {node.lineno}) differs from "
        f"its statements past its last early exit; lines in only one of them: "
        f"{sorted(region.lines ^ expected)[:20]}"
    )


def _source_path(obj) -> str:
    """Where ``obj`` is defined, repository-relative POSIX from
    ``automated_security_helper/``."""
    text = Path(inspect.getsourcefile(obj)).resolve().as_posix()
    return text[text.rindex("automated_security_helper/") :]


def _branch_lines(node, name: str) -> frozenset:
    """The lines of the bodies of every ``if`` in ``node``, at any depth, whose test
    reads ``name``: each body statement as its full span, never the test line or the
    ``else``. An oracle for an option's own branch, read from the syntax tree."""
    lines: set[int] = set()
    for statement in ast.walk(node):
        if isinstance(statement, ast.If) and any(
            isinstance(word, ast.Name)
            and isinstance(word.ctx, ast.Load)
            and word.id == name
            for word in ast.walk(statement.test)
        ):
            for inner in statement.body:
                lines.update(range(inner.lineno, inner.end_lineno + 1))
    return frozenset(lines)


def _line_of(source: str, text: str) -> int:
    """The number of the one line of ``source`` that holds ``text``."""
    (number,) = [
        number
        for number, line in enumerate(source.splitlines(), start=1)
        if text in line
    ]
    return number


def _self_calls(node) -> set[str]:
    """The names a function calls on ``self``: ``self.<name>(...)``."""
    return {
        call.func.attr
        for call in ast.walk(node)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "self"
    }


# --------------------------------------------------------------------------- #
# The runner's coverage hook
# --------------------------------------------------------------------------- #


def test_the_runner_names_its_coverage_variables_and_record_schema():
    """The pytest process is switched on by ASH_DOCS_COVERAGE_DIR; each block's
    context reaches its processes as DOCS_COVERAGE_CONTEXT, a name outside ASH's own
    ``ASH_`` namespace, which the scanner sandbox passes on. The rc file is written
    per run into the coverage directory, so none is committed beside the runner."""
    runner = _runner()

    assert runner.COVERAGE_DIR_VARIABLE == "ASH_DOCS_COVERAGE_DIR"
    assert runner.COVERAGE_CONTEXT_VARIABLE == "DOCS_COVERAGE_CONTEXT"
    assert runner.RECORD_SCHEMA == 1
    assert not (RUNNER.parent / "feature_coverage.coveragerc").exists()


def test_the_rc_file_measures_the_package_per_block_into_the_coverage_directory(
    tmp_path,
):
    """Every measured process reads this file: it must measure the package (by name,
    not a directory relative to the page's fixture), write parallel data files to an
    absolute path in the coverage directory (a process that lost a variable must not
    write to ``/data``), label them with the block's context, and keep the sysmon
    core (branch, concurrency and dynamic_context would each make coverage fall back
    from it). Its warnings stay off: a measured process's stderr is its block's
    output, which an output sample is compared against, and on Python 3.11, which
    has no sysmon core, every measured process would print the no-sysmon warning."""
    directory = tmp_path / "coverage"
    coverage = _runner().DocsCoverage(directory=directory)
    coverage.session_environment()
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(coverage.rcfile.read_text(encoding="utf-8"))
    run = parser["run"]

    assert coverage.rcfile == directory / RCFILE_NAME
    assert run["source_pkgs"].split() == ["automated_security_helper"]
    assert "source" not in run
    data_file = run["data_file"].strip()
    assert "$" not in data_file
    assert Path(data_file).is_absolute()
    assert Path(data_file) == directory / "data" / ".coverage"
    assert run["context"].strip() == "${DOCS_COVERAGE_CONTEXT-unattributed}"
    assert run["parallel"].strip().lower() == "true"
    assert {"_exit", "fork"} <= set(re.split(r"[,\s]+", run["patch"].strip()))
    for falls_back in ("branch", "concurrency", "dynamic_context"):
        assert falls_back not in run, falls_back
    assert "identifiers" not in run.get("omit", "")
    assert set(re.split(r"[,\s]+", run["disable_warnings"].strip())) == {
        "no-data-collected",
        "module-not-imported",
        "module-not-measured",
        "no-sysmon",
        "already-imported",
        "couldnt-parse",
    }


@pytest.mark.parametrize("value", [None, "", "   "], ids=["unset", "empty", "blank"])
def test_coverage_is_off_when_the_directory_variable_is_unset_or_blank(value):
    """Without the variable the runner changes nothing for any page."""
    environ = {} if value is None else {"ASH_DOCS_COVERAGE_DIR": value}

    assert _runner().DocsCoverage.from_environment(environ) is None


def test_coverage_refuses_a_relative_directory():
    """A relative directory would be resolved in every session's own directory."""
    with pytest.raises(ValueError):
        _runner().DocsCoverage.from_environment(
            {"ASH_DOCS_COVERAGE_DIR": "relative/coverage"}
        )


def test_coverage_reads_an_absolute_directory_and_keeps_its_rc_file_there(tmp_path):
    runner = _runner()
    directory = tmp_path / "coverage"

    coverage = runner.DocsCoverage.from_environment(
        {"ASH_DOCS_COVERAGE_DIR": str(directory)}
    )

    assert coverage == runner.DocsCoverage(directory=directory)
    assert coverage.rcfile == directory / RCFILE_NAME


def test_a_session_gets_one_coverage_variable_the_rc_file_and_both_subdirectories(
    tmp_path,
):
    """The rc file names the data directory itself, so a session carries only the
    variable that starts coverage; the per-block context is added block by block."""
    runner = _runner()
    directory = tmp_path / "coverage"
    coverage = runner.DocsCoverage(directory=directory)

    env = coverage.session_environment()

    assert env == {"COVERAGE_PROCESS_START": str(directory / RCFILE_NAME)}
    assert (directory / RCFILE_NAME).is_file()
    assert (directory / "data").is_dir() and (directory / "blocks").is_dir()


def test_a_blocks_context_is_its_page_and_fence_line():
    assert (
        _runner().DocsCoverage.context("how-to/configure.md", 12)
        == "how-to/configure.md::12"
    )


def test_a_pages_record_is_written_whole_under_a_name_from_the_page(
    tmp_path, monkeypatch
):
    """One file per page, named from the page so parallel workers never share one,
    written to a temporary name beside it and renamed, so a reader never sees half."""
    runner = _runner()
    coverage = runner.DocsCoverage(directory=tmp_path / "coverage")
    coverage.session_environment()
    blocks = [_block("how-to/configure.md", 3), _block("how-to/configure.md", 9)]
    replaced = []
    real_replace = os.replace

    def recording_replace(src, dst, *args, **kwargs):
        replaced.append((Path(src), Path(dst)))
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", recording_replace)

    path = coverage.write_record("how-to/configure.md", blocks)

    name = hashlib.sha256(b"how-to/configure.md").hexdigest()[:16] + ".json"
    assert path == tmp_path / "coverage" / "blocks" / name
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "schema": 1,
        "page": "how-to/configure.md",
        "blocks": blocks,
    }
    assert [p.name for p in path.parent.iterdir()] == [name]
    assert len(replaced) == 1
    source, target = replaced[0]
    assert target == path and source.parent == path.parent and source != path


def _recording_replace(monkeypatch) -> list:
    """os.replace, recording each (source, target) it is called with."""
    replaced = []
    real_replace = os.replace

    def recording_replace(src, dst, *args, **kwargs):
        replaced.append((Path(src), Path(dst)))
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", recording_replace)
    return replaced


def test_the_rc_file_is_written_whole_beside_itself_and_renamed_into_place(
    tmp_path, monkeypatch
):
    """Every measured process reads the rc file as it starts, while the sessions of
    every worker ask for it again. A write in place truncates the file first, and a
    process that reads it then runs coverage with its defaults: its lines are lost
    and a stray ``.coverage`` lands in the page's project. So the text goes to a
    temporary name in the same directory, renamed over the file, both when there is
    no file yet and when the file holds other text."""
    runner = _runner()
    directory = tmp_path / "coverage"
    replaced = _recording_replace(monkeypatch)
    coverage = runner.DocsCoverage(directory=directory)

    coverage.session_environment()
    text = coverage.rcfile.read_text(encoding="utf-8")
    coverage.rcfile.write_text("[run]\nparallel = False\n", encoding="utf-8")
    runner.DocsCoverage(directory=directory).session_environment()

    assert coverage.rcfile.read_text(encoding="utf-8") == text
    assert len(replaced) == 2, replaced
    for source, target in replaced:
        assert target == coverage.rcfile
        assert source.parent == target.parent and source != target
    assert sorted(p.name for p in directory.iterdir()) == [
        "blocks",
        RCFILE_NAME,
        "data",
    ]


def test_asking_again_for_an_rc_file_that_holds_its_text_leaves_it_untouched(
    tmp_path, monkeypatch
):
    """Each session of each worker asks for the same rc file; when it already holds
    the text, nothing is written, so a process that starts meanwhile reads it whole."""
    runner = _runner()
    directory = tmp_path / "coverage"
    first = runner.DocsCoverage(directory=directory)
    first.session_environment()
    text = first.rcfile.read_text(encoding="utf-8")
    # An old time stamp, so that a rewrite shows even within one tick of the clock.
    os.utime(first.rcfile, ns=(1_000_000_000, 1_000_000_000))
    before = first.rcfile.stat()
    replaced = _recording_replace(monkeypatch)

    env = runner.DocsCoverage(directory=directory).session_environment()

    after = first.rcfile.stat()
    assert env == {"COVERAGE_PROCESS_START": str(first.rcfile)}
    assert first.rcfile.read_text(encoding="utf-8") == text
    assert (after.st_ino, after.st_size, after.st_mtime_ns) == (
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    assert replaced == []


# --------------------------------------------------------------------------- #
# Reading a command line: docs_checks.invocation_usage
# --------------------------------------------------------------------------- #


def _cli_node(cli, path: tuple[str, ...]):
    command = cli
    for word in path[1:]:
        command = command.subcommands[word]
    return command


def _expected_uses(cli, uses):
    """(owner, names, value) for (owner, a name the option is spelled with, value)."""
    return [
        (owner, _cli_node(cli, owner).options[name].names, value)
        for owner, name, value in uses
    ]


def _usage(args, cli=None):
    checks = _checks()
    cli = cli if cli is not None else checks.load_cli()
    path, uses = checks.invocation_usage(args, cli)
    return tuple(path), [(tuple(u.command), tuple(u.names), u.value) for u in uses]


SCAN = ("ash", "scan")


@pytest.mark.parametrize(
    ("args", "path", "uses"),
    [
        pytest.param(
            ["scan", "--scanners", "bandit"],
            SCAN,
            [(SCAN, "--scanners", "bandit")],
            id="after-the-subcommand-the-subcommands",
        ),
        pytest.param(
            ["--scanners", "bandit", "scan"],
            SCAN,
            [(SCAN, "--scanners", "bandit")],
            id="before-the-subcommand-passed-on-to-it",
        ),
        pytest.param(
            ["--output-dir", "out", "report"],
            ("ash", "report"),
            [(("ash", "report"), "--output-dir", "out")],
            id="before-another-subcommand-that-takes-it",
        ),
        pytest.param(
            ["--format", "text", "report"],
            ("ash", "report"),
            [(("ash", "report"), "--format", "text")],
            id="passed-on-by-a-long-spelling-they-share",
        ),
        pytest.param(
            [
                "--config-overrides",
                "global_settings.severity_threshold=HIGH",
                "config",
                "validate",
            ],
            ("ash", "config", "validate"),
            [
                (
                    ("ash", "config", "validate"),
                    "--config-overrides",
                    "global_settings.severity_threshold=HIGH",
                )
            ],
            id="passed-on-to-the-leaf-of-a-group",
        ),
        pytest.param(
            ["--scanners", "bandit"],
            ("ash",),
            [(("ash",), "--scanners", "bandit")],
            id="no-subcommand",
        ),
        pytest.param(
            ["config", "validate", "--config", ".ash/.ash.yaml"],
            ("ash", "config", "validate"),
            [(("ash", "config", "validate"), "--config", ".ash/.ash.yaml")],
            id="a-nested-subcommand",
        ),
        pytest.param(
            ["report", "--format", "sarif"],
            ("ash", "report"),
            [(("ash", "report"), "--format", "sarif")],
            id="a-hidden-spelling",
        ),
        pytest.param(
            ["scan", "--config-overrides=global_settings.severity_threshold=HIGH"],
            SCAN,
            [(SCAN, "--config-overrides", "global_settings.severity_threshold=HIGH")],
            id="an-inline-value",
        ),
        pytest.param(
            ["scan", "--no-progress", "--offline"],
            SCAN,
            [(SCAN, "--no-progress", None), (SCAN, "--offline", None)],
            id="flags-and-a-secondary-name",
        ),
        pytest.param(
            ["scan", "-vd", "-f", "sarif", "-fhtml"],
            SCAN,
            [
                (SCAN, "-v", None),
                (SCAN, "-d", None),
                (SCAN, "-f", "sarif"),
                (SCAN, "-f", "html"),
            ],
            id="short-options-clustered-and-attached",
        ),
        pytest.param(
            ["scan", "--source-dir", "$SOURCE"],
            SCAN,
            [(SCAN, "--source-dir", "$SOURCE")],
            id="a-value-the-shell-fills-in",
        ),
        pytest.param(
            ["scan", "<path>", "$EXTRA_ARGS", "--offline"],
            SCAN,
            [(SCAN, "--offline", None)],
            id="placeholders-and-dollar-words-are-skipped",
        ),
        pytest.param(
            ["scan", "--offline", "--", "--scanners", "bandit"],
            SCAN,
            [(SCAN, "--offline", None)],
            id="nothing-after-a-double-dash",
        ),
    ],
)
def test_invocation_usage_gives_each_option_to_the_command_ash_args_problems_accepts_it_on(
    args, path, uses
):
    """invocation_usage walks the arguments the way ash_args_problems judges them: an
    argument list ash_args_problems accepts has each option attributed, with the value
    given, to the command that receives it. That is the command it follows, except a
    root option typed before a subcommand that takes it (by its name or a long
    spelling they share), which ASH passes on to that subcommand
    (AshTyperGroup._options_for_subcommand in cli/main.py); the uses then carry the
    subcommand's own spellings of it."""
    checks = _checks()
    cli = checks.load_cli()

    assert checks.ash_args_problems(args, cli, check_values=False) == []
    assert _usage(args) == (path, _expected_uses(cli, uses))


@pytest.mark.parametrize(
    ("args", "path", "uses", "refused"),
    [
        pytest.param(
            ["scan", "--bogus", "value", "--offline"],
            SCAN,
            [(SCAN, "--offline", None)],
            "--bogus is not an option of 'ash scan'",
            id="an-unknown-option-and-its-value",
        ),
        pytest.param(
            ["config", "validate", "--scanners", "bandit"],
            ("ash", "config", "validate"),
            [],
            "--scanners is not an option of 'ash config validate'",
            id="another-commands-option",
        ),
    ],
)
def test_invocation_usage_gives_no_command_an_option_ash_args_problems_refuses(
    args, path, uses, refused
):
    """An option no command takes at its position is used by nothing: it is not
    evidence for the root's option of the same name either."""
    checks = _checks()
    cli = checks.load_cli()

    assert any(
        refused in problem
        for problem in checks.ash_args_problems(args, cli, check_values=False)
    )
    assert _usage(args) == (path, _expected_uses(cli, uses))


def test_invocation_usage_gives_a_forwarding_commands_unknown_option_to_the_root():
    """A command that forwards options it does not own (as scan and build-image once
    did to the ASH inside a container) hands them to the root, so the root owns them;
    a command that does not forward refuses them."""
    checks = _checks()
    root = checks.CliCommand(
        path=("ash",),
        options={
            "--verbose": checks.CliOption(names=("--verbose",), takes_value=False)
        },
        max_args=0,
        subcommands={},
    )
    forwards = checks.CliCommand(
        path=("ash", "run"),
        options={"--target": checks.CliOption(names=("--target",), takes_value=True)},
        max_args=0,
        subcommands={},
        forwards_unknown=True,
    )
    keeps = checks.CliCommand(
        path=("ash", "plain"), options={}, max_args=0, subcommands={}
    )
    root.subcommands = {"run": forwards, "plain": keeps}

    forwarded = ["run", "--verbose", "--target", "t"]
    assert checks.ash_args_problems(forwarded, root, check_values=False) == []
    assert _usage(forwarded, root) == (
        ("ash", "run"),
        [(("ash",), ("--verbose",), None), (("ash", "run"), ("--target",), "t")],
    )

    refused = ["plain", "--verbose"]
    assert checks.ash_args_problems(refused, root, check_values=False)
    assert _usage(refused, root) == (("ash", "plain"), [])


# --------------------------------------------------------------------------- #
# Regions: a function's statements past its early exits
# --------------------------------------------------------------------------- #

#: Line numbers matter here: each expected set below counts them.
REGION_SOURCE = '''\
import functools


def plain(a, b):
    """A docstring
    on two lines."""
    total = a + b
    if total:
        return total
    return 0


@functools.lru_cache(
    maxsize=None,
)
def decorated(
    value,
):
    """Doc."""
    result = [
        value,
    ]
    for item in result:
        print(item)
    return result


class Holder:
    def method(self):
        return 1

    def other(self):
        def inner():
            return 2

        return inner()


def plain():
    return "a second definition"


def raises_early(value):
    if value is None:
        raise ValueError("no value")
    checked = value
    return checked


def guard_with_else(value):
    if value:
        return 1
    else:
        value = 2
    return value


def if_that_does_not_exit(value):
    if value:
        value = value + 1
    return value


def only_a_guard(value):
    if value:
        return value


def two_guards(ctx, value):
    if ctx is None:
        return None
    prepared = ctx
    if value:
        prepared = None
        return prepared
    result = (
        prepared,
        value,
    )
    return result


def exits_inside_a_loop(values):
    for value in values:
        if value:
            return value
    return None


def documented_only():
    """Nothing but this docstring."""
'''


@pytest.mark.parametrize(
    ("name", "firstlineno", "lines"),
    [
        pytest.param("plain", 4, {10}, id="past-its-early-exit"),
        pytest.param(
            "decorated", 13, {20, 21, 22, 23, 24, 25}, id="by-its-first-decorator"
        ),
        pytest.param("decorated", 16, {20, 21, 22, 23, 24, 25}, id="by-its-def-line"),
        pytest.param("method", 29, {30}, id="a-method"),
        pytest.param("other", 32, {33, 34, 36}, id="a-nested-function"),
        pytest.param("plain", 39, {40}, id="the-second-of-two-names"),
        pytest.param("raises_early", 43, {46, 47}, id="a-raise-is-an-early-exit"),
        pytest.param(
            "guard_with_else",
            50,
            {51, 52, 53, 54, 55},
            id="an-if-with-an-else-is-not-an-early-exit",
        ),
        pytest.param(
            "if_that_does_not_exit",
            58,
            {59, 60, 61},
            id="an-if-that-does-not-return-or-raise-is-not-one",
        ),
        pytest.param(
            "only_a_guard",
            64,
            {65, 66},
            id="nothing-after-the-early-exit-keeps-the-body",
        ),
        pytest.param("two_guards", 69, {76, 77, 78, 79, 80}, id="past-the-last-of-two"),
        pytest.param(
            "exits_inside_a_loop",
            83,
            {84, 85, 86, 87},
            id="an-exit-inside-a-loop-is-not-one",
        ),
    ],
)
def test_a_region_is_the_functions_statements_past_its_last_early_exit(
    name, firstlineno, lines
):
    """Importing a module runs its def lines, decorators and default values, so they
    can never show that a feature ran, and a docstring is not executed. The
    statements up to a function's last early exit (a top-level ``if`` with no
    ``else`` whose body ends in ``return`` or ``raise``) run on calls that do none of
    its work: the scan callback's ``ctx.invoked_subcommand`` exit runs before every
    subcommand. So the region is the statements after the last early exit, each as
    its whole span of lines (coverage can record a continuation line), and all of the
    body when nothing follows the last one. The function is the one whose def line or
    first decorator is on ``firstlineno``."""
    assert _cov().region_lines(REGION_SOURCE, name, firstlineno) == frozenset(lines)


@pytest.mark.parametrize(
    ("name", "firstlineno"),
    [("plain", 5), ("missing", 4), ("documented_only", 90)],
    ids=["no-def-on-that-line", "no-such-name", "a-docstring-and-nothing-else"],
)
def test_a_region_of_a_function_that_is_not_there_is_an_inventory_error(
    name, firstlineno
):
    """A feature with no line to reach could never be covered; the inventory refuses
    it instead of listing it."""
    cov = _cov()

    with pytest.raises(cov.InventoryError):
        cov.region_lines(REGION_SOURCE, name, firstlineno)


@pytest.fixture
def synthetic_module(tmp_path):
    """Write a module under a directory named ``automated_security_helper`` and import
    it under a name of its own, so its functions have package-relative regions
    without touching the real package."""
    names: list[str] = []

    def make(filename: str, text: str):
        directory = tmp_path / "checkout" / "automated_security_helper"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / filename
        path.write_text(text, encoding="utf-8")
        name = f"_synthetic_{path.stem}_{uuid.uuid4().hex}"
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        names.append(name)
        spec.loader.exec_module(module)
        return module

    yield make
    for name in names:
        sys.modules.pop(name, None)


def test_a_functions_region_is_named_from_the_package_directory(synthetic_module):
    """The path is repository-relative POSIX from ``automated_security_helper/``,
    found through any wrapper (lru_cache here), so it reads the same wherever the
    checkout is and on every OS."""
    cov = _cov()
    module = synthetic_module("region_probe.py", REGION_SOURCE)

    region = cov.function_region(module.decorated)

    assert region == cov.Region(
        path="automated_security_helper/region_probe.py",
        lines=frozenset({20, 21, 22, 23, 24, 25}),
    )


def test_a_code_feature_is_its_functions_region_and_location(synthetic_module):
    cov = _cov()
    module = synthetic_module("region_probe.py", REGION_SOURCE)

    feature = cov.code_feature("scanner:probe", module.decorated)

    assert feature.id == "scanner:probe"
    assert (feature.kind, feature.name) == ("scanner", "probe")
    assert feature.regions == (cov.function_region(module.decorated),)
    path, _, line = feature.location.rpartition(":")
    assert path == "automated_security_helper/region_probe.py" and int(line) > 0


# --------------------------------------------------------------------------- #
# The command tree: commands that share code are one feature
# --------------------------------------------------------------------------- #

#: A small Typer app shaped like ASH's: the root's callback is the same function as
#: the ``run`` subcommand (as bare ``ash`` is ``ash scan``), a hidden alias registers
#: it a third time, ``tools`` is a group with no callback of its own, and ``run``'s
#: command class adds an option the function never receives, as ASH's
#: CliJsonInputCommand adds --cli-json-input (cli/json_input.py).
FAKE_CLI = """\
import typer
from typer.core import TyperCommand, TyperOption

app = typer.Typer()
tools = typer.Typer()
app.add_typer(tools, name="tools")


class TakesAFile(TyperCommand):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params.append(
            TyperOption(param_decls=["--from-file"], metavar="PATH", expose_value=False)
        )


def _check_level(value: str) -> str:
    if value not in ("low", "high"):
        raise typer.BadParameter("low or high")
    return value


def run(
    level: str = typer.Option("low", "--level", callback=_check_level),
    quiet: bool = typer.Option(False, "--quiet/--no-quiet"),
    secret: str = typer.Option("", "--secret", hidden=True),
):
    print(level, quiet, secret)


app.callback(invoke_without_command=True)(run)
app.command("run", cls=TakesAFile)(run)
app.command("old-run", hidden=True)(run)


@tools.command("list")
def list_tools():
    print("tools")
"""

#: A command tree that yields no option at all.
FAKE_CLI_WITHOUT_OPTIONS = """\
import typer

app = typer.Typer(add_completion=False)


@app.command("first")
def first():
    print("first")


@app.command("second")
def second():
    print("second")
"""


def test_commands_sharing_a_callback_are_one_feature_named_by_the_longest_visible_path(
    synthetic_module,
):
    """Line coverage cannot tell apart two commands that run one function, so they
    are one feature, named by the longest path that is not hidden, with the options of
    every member merged by canonical name. A group with no callback runs no code of
    its own and is no feature. Hidden options are not features, nor are Typer's
    completion options (left out by name: like an option the function never receives,
    they have expose_value false); --help is not a parameter of the command. An
    option the function never receives is a feature, as ASH documents its own. An
    option's own callback is part of its code."""
    import typer

    cov = _cov()
    module = synthetic_module("fake_cli.py", FAKE_CLI)

    features = {
        feature.id: feature
        for feature in cov.cli_features(typer.main.get_command(module.app))
    }

    run = cov.function_region(module.run)
    assert set(features) == {
        "command:ash run",
        "command:ash tools list",
        "option:ash run --level",
        "option:ash run --quiet",
        "option:ash run --from-file",
    }
    assert features["command:ash run"].regions == (run,)
    assert features["command:ash tools list"].regions == (
        cov.function_region(module.list_tools),
    )
    assert set(features["option:ash run --level"].regions) == {
        run,
        cov.function_region(module._check_level),
    }
    assert features["option:ash run --quiet"].regions == (run,)
    assert features["option:ash run --from-file"].regions == (run,)


def test_a_command_tree_that_yields_no_option_is_an_inventory_error(synthetic_module):
    """ASH's tree holds hundreds of options, so a walk that finds none read the tree
    wrong (typer builds it from its own vendored click, whose classes are not the
    installed click's) and would leave every option ungated without a word."""
    import typer

    cov = _cov()
    module = synthetic_module("fake_cli_without_options.py", FAKE_CLI_WITHOUT_OPTIONS)

    with pytest.raises(cov.InventoryError):
        cov.cli_features(typer.main.get_command(module.app))


def test_a_command_whose_callback_is_typers_own_is_an_inventory_error(synthetic_module):
    """Such a callback holds no ASH code, so the command could never be covered; the
    inventory refuses rather than list a feature nothing can reach."""
    import typer

    cov = _cov()
    module = synthetic_module("fake_cli.py", FAKE_CLI)
    root = typer.main.get_command(module.app)
    root.commands["tools"].commands["list"].callback = typer.main.get_command

    with pytest.raises(cov.InventoryError):
        cov.cli_features(root)


#: A command tree shaped like ASH's scan, for the options a branch of the callback
#: reads: the root's callback is the scan (bare ``ash`` is ``ash scan``), it ends at a
#: version exit as ASH's does, and its options carry ASH's own spellings, so the docs
#: parser reads a block's command line here as it reads one for ASH. ``--offline``'s
#: branch sits inside a loop and spans three lines; ``--source-dir``'s is an ``elif``
#: and the ``else`` below it belongs to no option; nothing branches on ``--output-dir``.
FAKE_SCAN_CLI = """\
import typer

app = typer.Typer(add_completion=False)


def scan(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version"),
    quiet: bool = typer.Option(False, "--quiet/--no-quiet"),
    offline: bool = typer.Option(False, "--offline/--no-offline"),
    source_dir: str = typer.Option(".", "--source-dir"),
    output_dir: str = typer.Option("out", "--output-dir"),
):
    if ctx.invoked_subcommand is not None:
        return
    if version:
        print("version 1")
        raise typer.Exit
    if not quiet:
        print("not quiet")
    for item in [source_dir]:
        if offline and item:
            print(
                item,
            )
        elif source_dir:
            print("a source directory")
        else:
            print("neither")
    print(output_dir)


app.callback(invoke_without_command=True)(scan)
app.command("scan")(scan)
"""


def _fake_scan_node():
    """The fake scan callback's syntax tree."""
    (node,) = [
        node
        for node in ast.parse(FAKE_SCAN_CLI).body
        if isinstance(node, ast.FunctionDef) and node.name == "scan"
    ]
    return node


def test_an_option_a_branch_of_the_callback_reads_is_measured_in_that_branch_too(
    synthetic_module,
):
    """An option whose work is an early exit (``ash --version`` prints and exits
    before the command's own code) could never reach the command's region. So an
    option is also measured in the bodies of every ``if`` of the callback, at any
    depth, whose test reads its parameter, early exits included: one more region,
    the union of those bodies, never the test line or an ``else``. The command's
    region stays the option's first. An option no branch reads gets no more."""
    import typer

    cov = _cov()
    module = synthetic_module("fake_scan_cli.py", FAKE_SCAN_CLI)
    node = _fake_scan_node()

    features = {
        feature.id: feature
        for feature in cov.cli_features(typer.main.get_command(module.app))
    }

    command = cov.function_region(module.scan)
    assert features["command:ash scan"].regions == (command,)

    def branch(parameter: str):
        return cov.Region(path=command.path, lines=_branch_lines(node, parameter))

    for option, parameter in (
        ("--version", "version"),
        ("--quiet", "quiet"),
        ("--offline", "offline"),
        ("--source-dir", "source_dir"),
    ):
        feature = features[f"option:ash scan {option}"]
        assert feature.regions[0] == command, option
        assert set(feature.regions) == {command, branch(parameter)}, option
        assert len(feature.regions) == 2, option
    assert features["option:ash scan --output-dir"].regions == (command,)

    assert branch("version").lines == {
        _line_of(FAKE_SCAN_CLI, 'print("version 1")'),
        _line_of(FAKE_SCAN_CLI, "raise typer.Exit"),
    }
    assert not branch("version").lines & command.lines
    assert _line_of(FAKE_SCAN_CLI, "if version:") not in branch("version").lines
    assert branch("quiet").lines == {_line_of(FAKE_SCAN_CLI, 'print("not quiet")')}
    middle = _line_of(FAKE_SCAN_CLI, "item,")
    assert branch("offline").lines == {middle - 1, middle, middle + 1}
    assert branch("source_dir").lines == {
        _line_of(FAKE_SCAN_CLI, 'print("a source directory")')
    }
    neither = _line_of(FAKE_SCAN_CLI, 'print("neither")')
    assert not [
        feature.id
        for feature in features.values()
        if feature.kind == "option"
        and any(neither in region.lines for region in feature.regions[1:])
    ]


@pytest.mark.parametrize(
    ("command_line", "parameter", "covered", "uncovered"),
    [
        pytest.param(
            "ash --version",
            "version",
            {"option:ash scan --version"},
            {"command:ash scan"},
            id="the-version-exit-shows-the-version-option-and-not-the-scan",
        ),
        pytest.param(
            "ash scan --offline",
            "quiet",
            {"command:ash scan", "option:ash scan --offline"},
            {"option:ash scan --quiet"},
            id="a-branch-run-because-an-option-was-not-given-does-not-show-it",
        ),
    ],
)
def test_a_block_that_reaches_a_branch_of_the_callback_covers_only_options_it_gives(
    tmp_path, synthetic_module, command_line, parameter, covered, uncovered
):
    """An option's own branch is evidence only beside a command line that gives the
    option: ``if not quiet:`` runs when ``--quiet`` is not given, so a block that
    reached it shows the scan, and any option it gave, but never ``--quiet``."""
    import typer

    cov = _cov()
    module = synthetic_module("fake_scan_cli.py", FAKE_SCAN_CLI)
    features = cov.cli_features(typer.main.get_command(module.app))
    path = cov.function_region(module.scan).path
    run = Run(tmp_path)
    line = _one_command(run, command_line)
    run.record("page.md", _block("page.md", line))
    run.hit(f"page.md::{line}", path, _branch_lines(_fake_scan_node(), parameter))

    result = _covered(run, features)

    assert covered <= result, sorted(covered - result)
    assert not uncovered & result, sorted(uncovered & result)


# --------------------------------------------------------------------------- #
# Plugins: each measured in the work the framework leaves to it
# --------------------------------------------------------------------------- #

SYNTHETIC_SCANNERS = '''\
from automated_security_helper.base.scanner_plugin import ScannerPluginBase


class SyntheticScanner(ScannerPluginBase):
    def _execute_scan(self, target, target_type, global_ignore_paths):
        args = ["synthetic", str(target)]
        return args, target, None


class _SharedTemplate(ScannerPluginBase):
    def _execute_scan(self, target, target_type, global_ignore_paths):
        args = self._arguments(target)
        return args, target, None


class FirstShared(_SharedTemplate):
    def _arguments(self, target):
        found = ["first", str(target)]
        return found


class SecondShared(_SharedTemplate):
    def _arguments(self, target):
        found = ["second", str(target)]
        return found


class OverridesScan(ScannerPluginBase):
    def _execute_scan(self, target, target_type, global_ignore_paths):
        """Unreachable: this scanner overrides scan() directly."""
        raise NotImplementedError("OverridesScan overrides scan()")

    def scan(self, target, target_type, global_ignore_paths=None, config=None, *a, **k):
        if not self.dependencies_satisfied:
            return None
        findings = []
        return findings


class DelegatesScan(ScannerPluginBase):
    def scan(self, target, target_type, global_ignore_paths=None, config=None, *a, **k):
        self.started = True
        return super().scan(target, target_type, global_ignore_paths, config, *a, **k)

    def _execute_scan(self, target, target_type, global_ignore_paths):
        args = ["delegates", str(target)]
        return args, target, None


ASH_SCANNERS = [SyntheticScanner, FirstShared, SecondShared, OverridesScan, DelegatesScan]
'''

SYNTHETIC_LISTED_AGAIN = """\
from .scanners import SyntheticScanner

ASH_SCANNERS = [SyntheticScanner]
"""

SYNTHETIC_REPORTERS = """\
from automated_security_helper.base.reporter_plugin import ReporterPluginBase


class SyntheticReporter(ReporterPluginBase):
    def report(self, model):
        text = "a report"
        return text


ASH_REPORTERS = [SyntheticReporter]
"""

SYNTHETIC_CONVERTERS = """\
from automated_security_helper.base.converter_plugin import ConverterPluginBase


class SyntheticConverter(ConverterPluginBase):
    def convert(self):
        converted = []
        return converted


ASH_CONVERTERS = [SyntheticConverter]
"""


@pytest.fixture
def synthetic_package(tmp_path):
    """A plugin package under a directory named ``automated_security_helper``,
    importable under a name of its own, for plugin_features to walk."""
    names: list[str] = []

    def make(files: dict[str, str]):
        directory = (
            tmp_path / "checkout" / "automated_security_helper" / "synthetic_plugins"
        )
        directory.mkdir(parents=True)
        (directory / "__init__.py").write_text("", encoding="utf-8")
        for stem, text in files.items():
            (directory / f"{stem}.py").write_text(text, encoding="utf-8")
        name = f"_synthetic_plugins_{uuid.uuid4().hex}"
        spec = importlib.util.spec_from_file_location(
            name, directory / "__init__.py", submodule_search_locations=[str(directory)]
        )
        assert spec and spec.loader
        package = importlib.util.module_from_spec(spec)
        sys.modules[name] = package
        names.append(name)
        spec.loader.exec_module(package)
        return package

    yield make
    for key in [
        key
        for key in sys.modules
        if any(key == name or key.startswith(name + ".") for name in names)
    ]:
        del sys.modules[key]


def test_each_plugin_is_measured_in_its_own_work_method(synthetic_package):
    """A scanner in its _execute_scan, also when its own scan() only adds to the
    framework's template and calls super().scan(...); a scanner whose scan() replaces
    the template (and leaves _execute_scan a stub that only raises
    NotImplementedError, which never runs and so could never show the scanner ran)
    in that scan(); a reporter in report; a converter in convert. A class listed by
    two modules is one feature."""
    cov = _cov()
    checks = _checks()
    package = synthetic_package(
        {
            "scanners": SYNTHETIC_SCANNERS,
            "listed_again": SYNTHETIC_LISTED_AGAIN,
            "reporters": SYNTHETIC_REPORTERS,
            "converters": SYNTHETIC_CONVERTERS,
        }
    )

    features = {feature.id: feature for feature in cov.plugin_features(package)}

    scanners = sys.modules[f"{package.__name__}.scanners"]
    reporters = sys.modules[f"{package.__name__}.reporters"]
    converters = sys.modules[f"{package.__name__}.converters"]

    def fid(kind, plugin):
        return f"{kind}:{checks._declared_plugin_name(plugin)}"

    assert set(features) == {
        fid("scanner", scanners.SyntheticScanner),
        fid("scanner", scanners.FirstShared),
        fid("scanner", scanners.SecondShared),
        fid("scanner", scanners.OverridesScan),
        fid("scanner", scanners.DelegatesScan),
        fid("reporter", reporters.SyntheticReporter),
        fid("converter", converters.SyntheticConverter),
    }
    region = cov.function_region
    assert features[fid("scanner", scanners.SyntheticScanner)].regions == (
        region(scanners.SyntheticScanner._execute_scan),
    )
    assert features[fid("scanner", scanners.OverridesScan)].regions == (
        region(scanners.OverridesScan.scan),
    )
    assert features[fid("scanner", scanners.DelegatesScan)].regions == (
        region(scanners.DelegatesScan._execute_scan),
    )
    assert features[fid("reporter", reporters.SyntheticReporter)].regions == (
        region(reporters.SyntheticReporter.report),
    )
    assert features[fid("converter", converters.SyntheticConverter)].regions == (
        region(converters.SyntheticConverter.convert),
    )


def test_plugins_that_share_one_work_method_say_so(synthetic_package):
    """Covering the shared code covers each of them, and line coverage cannot say
    which ran; the note tells a reader of the report."""
    cov = _cov()
    checks = _checks()
    package = synthetic_package({"scanners": SYNTHETIC_SCANNERS})

    # plugin_features imports the package's modules; the fixture runs only its __init__.
    features = {feature.id: feature for feature in cov.plugin_features(package)}
    scanners = sys.modules[f"{package.__name__}.scanners"]

    first = f"scanner:{checks._declared_plugin_name(scanners.FirstShared)}"
    second = f"scanner:{checks._declared_plugin_name(scanners.SecondShared)}"
    alone = f"scanner:{checks._declared_plugin_name(scanners.SyntheticScanner)}"
    assert features[first].regions == features[second].regions
    assert "shares its code with" in features[first].note
    assert second in features[first].note and first in features[second].note
    assert "shares its code with" not in features[alone].note


def test_plugins_that_share_a_work_method_each_need_a_method_of_their_own(
    synthetic_package,
):
    """Reaching the shared code shows that one of them ran, not which. Each also needs
    the methods it defines in its own class body that the shared method calls on
    ``self``, so that its own code tells it apart; a plugin with a work method of its
    own needs nothing more."""
    cov = _cov()
    checks = _checks()
    package = synthetic_package({"scanners": SYNTHETIC_SCANNERS})

    features = {feature.id: feature for feature in cov.plugin_features(package)}

    scanners = sys.modules[f"{package.__name__}.scanners"]

    def fid(plugin):
        return f"scanner:{checks._declared_plugin_name(plugin)}"

    assert features[fid(scanners.FirstShared)].requires == (
        cov.function_region(scanners.FirstShared._arguments),
    )
    assert features[fid(scanners.SecondShared)].requires == (
        cov.function_region(scanners.SecondShared._arguments),
    )
    for plugin in (
        scanners.SyntheticScanner,
        scanners.OverridesScan,
        scanners.DelegatesScan,
    ):
        assert features[fid(plugin)].requires == (), plugin.__name__


@pytest.mark.parametrize(
    ("reached", "covered"),
    [
        pytest.param(("shared",), set(), id="the-shared-method-alone-covers-neither"),
        pytest.param(("shared", "first"), {"first"}, id="with-the-first-ones-own"),
        pytest.param(("shared", "second"), {"second"}, id="with-the-second-ones-own"),
        pytest.param(("first",), set(), id="its-own-method-alone-covers-nothing"),
    ],
)
def test_a_plugin_that_shares_its_work_method_is_covered_where_its_own_method_ran_too(
    tmp_path, synthetic_package, reached, covered
):
    """A plugin that shares its work method is covered when a passing block reached
    the shared method and one of the methods it needs of its own."""
    cov = _cov()
    checks = _checks()
    package = synthetic_package({"scanners": SYNTHETIC_SCANNERS})
    features = {feature.id: feature for feature in cov.plugin_features(package)}
    scanners = sys.modules[f"{package.__name__}.scanners"]
    ids = {
        "first": f"scanner:{checks._declared_plugin_name(scanners.FirstShared)}",
        "second": f"scanner:{checks._declared_plugin_name(scanners.SecondShared)}",
    }
    regions = {
        "shared": cov.function_region(scanners.FirstShared._execute_scan),
        "first": cov.function_region(scanners.FirstShared._arguments),
        "second": cov.function_region(scanners.SecondShared._arguments),
    }
    run = Run(tmp_path)
    (line,) = run.page("page.md", ONE_BLOCK)
    run.record("page.md", _block("page.md", line))
    for name in reached:
        run.hit(f"page.md::{line}", regions[name].path, {min(regions[name].lines)})

    result = _covered(run, [features[ids["first"]], features[ids["second"]]])

    assert result == {ids[name] for name in covered}


#: Two scanners that share a work method, one of which defines none of the methods
#: that work method calls on ``self``: it inherits the template's.
SHARED_WITHOUT_A_METHOD_OF_ITS_OWN = """\
from automated_security_helper.base.scanner_plugin import ScannerPluginBase


class _SharedTemplate(ScannerPluginBase):
    def _execute_scan(self, target, target_type, global_ignore_paths):
        args = self._arguments(target)
        return args, target, None

    def _arguments(self, target):
        found = ["shared", str(target)]
        return found


class FirstShared(_SharedTemplate):
    def _arguments(self, target):
        found = ["first", str(target)]
        return found


class SecondShared(_SharedTemplate):
    pass


ASH_SCANNERS = [FirstShared, SecondShared]
"""


def test_a_plugin_that_shares_its_work_method_and_owns_nothing_it_calls_is_an_inventory_error(
    synthetic_package,
):
    """Line coverage could never tell such a plugin from the one it shares with, so
    the inventory refuses it at the change that creates it, naming it, rather than
    read the other plugin's run as its own."""
    cov = _cov()
    package = synthetic_package({"scanners": SHARED_WITHOUT_A_METHOD_OF_ITS_OWN})

    with pytest.raises(cov.InventoryError) as raised:
        cov.plugin_features(package)

    assert "secondshared" in str(raised.value).lower(), str(raised.value)


def test_a_plugin_module_that_does_not_import_is_an_inventory_error(synthetic_package):
    """A module that imports here and not on the CI runner would make the inventory
    differ between them, and the baseline read stale; the inventory refuses instead."""
    cov = _cov()
    package = synthetic_package(
        {
            "scanners": SYNTHETIC_SCANNERS,
            "broken": 'raise ImportError("a dependency this module needs is missing")\n',
        }
    )

    with pytest.raises(cov.InventoryError, match="broken"):
        cov.plugin_features(package)


def test_a_plugin_group_its_package_recorded_as_not_loaded_is_an_inventory_error(
    synthetic_package,
):
    """ASH's builtin plugin package catches an ImportError per plugin group, leaves
    that group's list empty and records it in ASH_PLUGIN_LOAD_ERRORS, and the package
    still imports (plugin_modules/ash_builtin/__init__.py). The inventory refuses a
    module whose record is not empty, rather than come out short."""
    cov = _cov()
    package = synthetic_package(
        {
            "scanners": SYNTHETIC_SCANNERS,
            "loader": "ASH_PLUGIN_LOAD_ERRORS = {\n"
            '    "synthetic_plugins.reporters": "ImportError: a dependency is missing",\n'
            "}\n",
        }
    )

    with pytest.raises(
        cov.InventoryError, match=re.escape("synthetic_plugins.reporters")
    ):
        cov.plugin_features(package)


#: A scanner whose scan() calls the template, which calls an _execute_scan stub.
DELEGATES_TO_A_STUB = """\
from automated_security_helper.base.scanner_plugin import ScannerPluginBase


class DelegatesToAStub(ScannerPluginBase):
    def scan(self, target, target_type, global_ignore_paths=None, config=None, *a, **k):
        return super().scan(target, target_type, global_ignore_paths, config, *a, **k)

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("nothing does the work")


ASH_SCANNERS = [DelegatesToAStub]
"""

#: A scanner whose scan() replaces the template and itself only raises.
REPLACES_SCAN_WITH_A_STUB = '''\
from automated_security_helper.base.scanner_plugin import ScannerPluginBase


class ReplacesScanWithAStub(ScannerPluginBase):
    def scan(self, target, target_type, global_ignore_paths=None, config=None, *a, **k):
        """Not written yet."""
        raise NotImplementedError("not written yet")


ASH_SCANNERS = [ReplacesScanWithAStub]
'''


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            "from automated_security_helper.base.scanner_plugin import ScannerPluginBase\n"
            "\n\nclass InheritsTheTemplate(ScannerPluginBase):\n    pass\n\n\n"
            "ASH_SCANNERS = [InheritsTheTemplate]\n",
            id="a-scanner",
        ),
        pytest.param(
            DELEGATES_TO_A_STUB, id="a-scanner-whose-execute-scan-only-raises"
        ),
        pytest.param(
            REPLACES_SCAN_WITH_A_STUB, id="a-scanner-whose-own-scan-only-raises"
        ),
        pytest.param(
            "from automated_security_helper.base.reporter_plugin import ReporterPluginBase\n"
            "\n\nclass ReportsNothing(ReporterPluginBase):\n    pass\n\n\n"
            "ASH_REPORTERS = [ReportsNothing]\n",
            id="a-reporter",
        ),
        pytest.param(
            "from automated_security_helper.base.converter_plugin import ConverterPluginBase\n"
            "\n\nclass ConvertsNothing(ConverterPluginBase):\n    pass\n\n\n"
            "ASH_CONVERTERS = [ConvertsNothing]\n",
            id="a-converter",
        ),
    ],
)
def test_a_plugin_whose_work_code_is_the_frameworks_or_only_raises_is_an_inventory_error(
    synthetic_package, text
):
    """The framework's own method holds no line of the plugin's work, and a function
    that only raises NotImplementedError never runs."""
    cov = _cov()
    package = synthetic_package({"plugin": text})

    with pytest.raises(cov.InventoryError):
        cov.plugin_features(package)


# --------------------------------------------------------------------------- #
# The inventory of this package
# --------------------------------------------------------------------------- #


def test_the_inventory_ids_are_unique_sorted_and_of_every_kind():
    ids = [feature.id for feature in _inventory()]

    assert ids == sorted(ids), "the inventory is not in id order"
    assert len(ids) == len(set(ids)), "an id is listed twice"
    assert {feature.kind for feature in _inventory()} == set(KINDS)
    for feature in _inventory():
        assert feature.id == f"{feature.kind}:{feature.name}", feature.id
        assert feature.name and feature.name == feature.name.strip(), feature.id


def _scan_callback():
    path = "automated_security_helper/cli/scan.py"
    return path, _function_node(path, "run_ash_scan_cli_command")


def _scan_early_exit(node, *, mentions: str):
    """The scan callback's early exit whose condition names ``mentions``."""
    (guard,) = [
        statement
        for statement in _without_docstring(node.body)
        if _is_guard(statement) and mentions in ast.unparse(statement.test)
    ]
    return guard


def test_the_scan_command_is_one_feature_that_bare_ash_belongs_to():
    """Bare ``ash`` runs the scan through the same callback as ``ash scan``, so there
    is one feature, ``command:ash scan``, and the root's options are its options. Its
    code starts past the callback's early exits: the return taken when a subcommand
    follows, which click runs before every subcommand, and the --version exit."""
    by_id = _by_id()
    path, node = _scan_callback()

    scan = by_id["command:ash scan"]
    (region,) = scan.regions
    assert region.path == path
    _assert_region(region, node)
    for mentions in ("invoked_subcommand", "version"):
        guard = _scan_early_exit(node, mentions=mentions)
        assert not region.lines & set(range(guard.lineno, guard.end_lineno + 1)), (
            mentions
        )
    assert "command:ash" not in by_id
    assert "option:ash scan --scanners" in by_id
    assert not [fid for fid in by_id if fid.startswith("option:ash --")]


def test_the_version_option_is_measured_in_the_scan_callbacks_version_branch():
    """``ash --version`` prints and exits at the scan callback's version exit, before
    the scan's own code: that branch's body is the option's code. The region is read
    from the callback's syntax tree and the option's parameter name, never a line
    number."""
    import typer

    from automated_security_helper.cli.main import app

    path, node = _scan_callback()
    (parameter,) = [
        param
        for param in typer.main.get_command(app).params
        if "--version" in param.opts
    ]
    guard = _scan_early_exit(node, mentions="version")
    body = {
        line
        for statement in guard.body
        for line in range(statement.lineno, statement.end_lineno + 1)
    }
    expected = _branch_lines(node, parameter.name)
    by_id = _by_id()

    feature = by_id["option:ash scan --version"]

    assert body and body <= expected
    assert guard.lineno not in expected
    assert _cov().Region(path=path, lines=expected) in feature.regions
    assert feature.regions[0] == by_id["command:ash scan"].regions[0]


@pytest.mark.parametrize(
    "absent",
    [
        "command:ash",
        "command:ash report",
        "command:ash build-image",
        "command:ash diff",
        "command:ash merge",
        "command:ash trend",
        "command:ash inspect",
        "command:ash inspect findings",
        "command:ash inspect sarif-fields",
    ],
)
def test_hidden_spellings_are_not_features(absent):
    """A hidden spelling is the same callback as a visible command, which carries the
    feature; ``ash inspect`` is also a group with no callback."""
    assert absent not in _by_id()


#: The visible groups of ASH's command tree that have no callback of their own.
GROUPS_WITHOUT_A_CALLBACK = (
    "config",
    "container",
    "dependencies",
    "express",
    "plugin",
    "results",
    "results inspect",
    "suppress",
)


@pytest.mark.parametrize("group", GROUPS_WITHOUT_A_CALLBACK)
def test_a_group_without_a_callback_is_not_a_feature_and_its_subcommands_are(group):
    """A group with no callback runs no code of its own, so nothing could cover it;
    each subcommand it holds is a feature of its own. Pinned so that a group that
    gains a callback is a visible change."""
    import typer

    from automated_security_helper.cli.main import app

    command = typer.main.get_command(app)
    for word in group.split():
        command = command.commands[word]
    by_id = _by_id()

    assert command.callback is None, f"ash {group} has a callback now"
    assert f"command:ash {group}" not in by_id
    visible = sorted(
        name
        for name, sub in command.commands.items()
        if not sub.hidden and sub.callback is not None
    )
    assert visible, f"ash {group} has no visible subcommand with a callback"
    for name in visible:
        assert f"command:ash {group} {name}" in by_id, name


@pytest.mark.parametrize(
    "present",
    [
        "command:ash results report",
        "command:ash results diff",
        "command:ash results merge",
        "command:ash results trend",
        "command:ash results inspect findings",
        "command:ash container build",
        "command:ash config validate",
        "command:ash dependencies install",
        "command:ash mcp",
        "option:ash results report --format",
        "option:ash config validate --config-overrides",
        "option:ash scan --cli-json-input",
        "option:ash scan --generate-cli-skeleton",
    ],
)
def test_the_visible_command_of_each_callback_is_a_feature(present):
    """--cli-json-input and --generate-cli-skeleton never reach the function
    (expose_value is false), but ASH documents them as options of the command."""
    assert present in _by_id()


def test_help_and_completion_options_are_not_features():
    """--help prints and exits before any handler runs; the completion options are
    Typer's, not ASH's."""
    names = {fid.rpartition(" ")[2] for fid in _by_id() if fid.startswith("option:")}

    assert names, "the inventory holds no option"
    assert not names & {"--help", "--install-completion", "--show-completion"}


def test_every_option_belongs_to_a_command_feature_and_carries_its_code():
    by_id = _by_id()

    for fid, feature in by_id.items():
        if feature.kind != "option":
            continue
        command, _, name = feature.name.rpartition(" ")
        assert name.startswith("-"), fid
        assert f"command:{command}" in by_id, fid
        assert set(by_id[f"command:{command}"].regions) <= set(feature.regions), fid


@functools.lru_cache(maxsize=1)
def _scanner_classes() -> dict:
    """Every scanner class the plugin modules list, by its declared name, read the
    way docs_checks.plugin_names reads them: an oracle beside the inventory."""
    import pkgutil

    from automated_security_helper import plugin_modules

    checks = _checks()
    found = {}
    for info in pkgutil.walk_packages(
        plugin_modules.__path__, plugin_modules.__name__ + "."
    ):
        module = importlib.import_module(info.name)
        for plugin in getattr(module, "ASH_SCANNERS", None) or []:
            found[checks._declared_plugin_name(plugin)] = plugin
    return found


def _replaces_the_scan_template(plugin) -> bool:
    """Whether a scanner's own scan() does its work instead of calling
    super().scan(...), the framework's template, which calls _execute_scan."""
    if "scan" not in plugin.__dict__:
        return False
    node = _function_node(_source_path(plugin), "scan", cls=plugin.__name__)
    return not _calls_super_scan(node)


#: The scanners whose own scan() replaces the framework's template, leaving
#: _execute_scan a stub that only raises NotImplementedError
#: (base/scanner_plugin.py's scan() docstring invites bespoke scanners to do this).
SCANNERS_THAT_REPLACE_SCAN = (
    "actionlint",
    "cdk-nag",
    "cfn-guard",
    "cfn-lint",
    "cfn-nag",
    "detect-secrets",
    "ferret-scan",
    "guarddog",
    "hadolint",
    "mcp-config",
    "npm-audit",
    "snyk-code",
    "syft",
    "trivy-repo",
)


def test_exactly_these_scanners_replace_the_scan_template():
    """Pinned, so that a scanner that starts or stops replacing scan() is a visible
    change: its work code moves between scan() and _execute_scan()."""
    replacing = {
        name
        for name, plugin in _scanner_classes().items()
        if _replaces_the_scan_template(plugin)
    }

    assert replacing == set(SCANNERS_THAT_REPLACE_SCAN)


@pytest.mark.parametrize("name", SCANNERS_THAT_REPLACE_SCAN)
def test_a_scanner_that_replaces_the_scan_template_is_measured_in_its_own_scan(name):
    """Its _execute_scan is a stub that raises NotImplementedError and never runs, so
    measured there it could never be covered; detect-secrets, which the default scan
    runs, is one of these. Its region is its scan() past the skip checks it opens
    with."""
    plugin = _scanner_classes()[name]
    path = _source_path(plugin)
    stub = _function_node(path, "_execute_scan", cls=plugin.__name__)
    assert _is_not_implemented_stub(stub), f"{name}'s _execute_scan is not a stub now"

    (region,) = _by_id()[f"scanner:{name}"].regions

    assert region.path == path
    _assert_region(region, _function_node(path, "scan", cls=plugin.__name__))
    assert not any(stub.lineno <= line <= stub.end_lineno for line in region.lines)


def test_bandit_is_measured_in_its_own_execute_scan():
    """bandit's scan() adds to the template and calls super().scan(...), so its work
    is its _execute_scan."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
    )

    feature = _by_id()[f"scanner:{_checks()._declared_plugin_name(BanditScanner)}"]

    (region,) = feature.regions
    assert region.path == (
        "automated_security_helper/plugin_modules/ash_builtin/scanners/bandit_scanner.py"
    )
    assert not _replaces_the_scan_template(BanditScanner)
    _assert_region(
        region, _function_node(region.path, "_execute_scan", cls="BanditScanner")
    )


def test_opengrep_and_semgrep_share_the_grep_bases_execute_scan_and_say_so():
    """GrepScannerBase.scan only calls the template, so both scanners are measured in
    GrepScannerBase._execute_scan, which line coverage cannot tell apart by scanner."""
    classes = _scanner_classes()
    by_id = _by_id()
    owners = {
        name: next(c for c in classes[name].__mro__ if "_execute_scan" in c.__dict__)
        for name in ("opengrep", "semgrep")
    }
    (owner,) = set(owners.values())
    scan_owner = next(c for c in classes["opengrep"].__mro__ if "scan" in c.__dict__)
    assert scan_owner is owner and not _replaces_the_scan_template(owner)
    path = _source_path(owner)

    for name, other in (("opengrep", "semgrep"), ("semgrep", "opengrep")):
        feature = by_id[f"scanner:{name}"]
        (region,) = feature.regions
        assert region.path == path
        _assert_region(
            region, _function_node(path, "_execute_scan", cls=owner.__name__)
        )
        assert (
            "shares its code with" in feature.note
            and f"scanner:{other}" in feature.note
        )


def _grep_base():
    """The class whose _execute_scan opengrep and semgrep share."""
    return next(
        klass
        for klass in _scanner_classes()["opengrep"].__mro__
        if "_execute_scan" in klass.__dict__
    )


def _own_regions_the_shared_method_calls(plugin) -> set:
    """The regions of the methods ``plugin`` defines in its own class body that the
    grep base's _execute_scan calls on ``self``: an oracle, read from the syntax
    trees on their own."""
    cov = _cov()
    owner = _grep_base()
    shared = _function_node(_source_path(owner), "_execute_scan", cls=owner.__name__)
    path = _source_path(plugin)
    return {
        cov.Region(
            path=path,
            lines=_region_oracle(_function_node(path, name, cls=plugin.__name__)),
        )
        for name in sorted(_self_calls(shared))
        if name in plugin.__dict__
    }


def test_opengrep_and_semgrep_each_need_a_method_of_their_own_beside_the_shared_one():
    """semgrep runs in the docs job and opengrep does not, so the shared method alone
    would cover opengrep whenever semgrep ran. Each needs a method it defines itself
    that the shared method calls; every plugin with a work method of its own, and
    every other feature, needs nothing more."""
    classes = _scanner_classes()
    by_id = _by_id()

    for name in ("opengrep", "semgrep"):
        expected = _own_regions_the_shared_method_calls(classes[name])
        requires = by_id[f"scanner:{name}"].requires
        assert expected, f"{name} defines no method the shared one calls"
        assert set(requires) == expected and len(requires) == len(expected), name
    assert not set(by_id["scanner:opengrep"].requires) & set(
        by_id["scanner:semgrep"].requires
    )
    for feature in _inventory():
        if feature.id not in ("scanner:opengrep", "scanner:semgrep"):
            assert feature.requires == (), feature.id


@pytest.mark.parametrize(
    ("own", "covered", "uncovered"),
    [
        pytest.param(
            None,
            set(),
            {"scanner:opengrep", "scanner:semgrep"},
            id="the-shared-method-alone",
        ),
        pytest.param(
            "semgrep",
            {"scanner:semgrep"},
            {"scanner:opengrep"},
            id="semgreps-own-method-ran-too",
        ),
        pytest.param(
            "opengrep",
            {"scanner:opengrep"},
            {"scanner:semgrep"},
            id="opengreps-own-method-ran-too",
        ),
    ],
)
def test_reaching_the_grep_bases_work_method_covers_the_grep_scanner_whose_own_code_ran(
    tmp_path, own, covered, uncovered
):
    by_id = _by_id()
    run = Run(tmp_path)
    (line,) = run.page("page.md", ONE_BLOCK)
    run.record("page.md", _block("page.md", line))
    (shared,) = by_id["scanner:semgrep"].regions
    run.hit(f"page.md::{line}", shared.path, {min(shared.lines)})
    if own is not None:
        for region in _own_regions_the_shared_method_calls(_scanner_classes()[own]):
            run.hit(f"page.md::{line}", region.path, {min(region.lines)})

    result = _covered(run, [by_id["scanner:opengrep"], by_id["scanner:semgrep"]])

    assert covered <= result, sorted(covered - result)
    assert not uncovered & result, sorted(uncovered & result)


def test_no_plugin_is_measured_in_a_stub_that_only_raises_not_implemented():
    plugins = [
        f for f in _inventory() if f.kind in ("scanner", "reporter", "converter")
    ]

    assert plugins, "the inventory holds no plugin"
    for feature in plugins:
        for region in feature.regions:
            function = _innermost_function(region.path, min(region.lines))
            assert not _is_not_implemented_stub(function), (
                f"{feature.id} is measured in {function.name} "
                f"({region.path}:{function.lineno}), which only raises "
                "NotImplementedError and so never runs"
            )


def test_a_reporter_and_a_converter_are_measured_in_report_and_convert():
    from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
        ArchiveConverter,
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
        SarifReporter,
    )

    checks = _checks()
    by_id = _by_id()
    builtin = "automated_security_helper/plugin_modules/ash_builtin"
    for kind, plugin, method, path in (
        ("reporter", SarifReporter, "report", f"{builtin}/reporters/sarif_reporter.py"),
        (
            "converter",
            ArchiveConverter,
            "convert",
            f"{builtin}/converters/archive_converter.py",
        ),
    ):
        feature = by_id[f"{kind}:{checks._declared_plugin_name(plugin)}"]
        (region,) = feature.regions
        assert region.path == path
        _assert_region(region, _function_node(path, method, cls=plugin.__name__))


def test_plugins_here_that_share_one_work_method_name_each_other():
    """opengrep and semgrep are the only plugins that share one, pinned so that a new
    shared base is a visible change."""
    by_id = _by_id()
    plugins = [
        f for f in _inventory() if f.kind in ("scanner", "reporter", "converter")
    ]
    by_region = defaultdict(list)
    for feature in plugins:
        by_region[feature.regions].append(feature.id)
    shared = [ids for ids in by_region.values() if len(ids) > 1]

    assert sorted(sorted(ids) for ids in shared) == [
        ["scanner:opengrep", "scanner:semgrep"]
    ]
    for ids in by_region.values():
        for fid in ids:
            others = [other for other in ids if other != fid]
            if others:
                assert "shares its code with" in by_id[fid].note, fid
                assert all(other in by_id[fid].note for other in others), fid
            else:
                assert "shares its code with" not in by_id[fid].note, fid


def test_the_config_features_are_the_rows_of_the_configuration_reference():
    """The reference's own walk of the AshConfig model: a list item's keys after
    ``[]``, a field's alias where it declares one, every section row too, and the
    plugin sections by name only (each plugin's options are on its own page)."""
    from automated_security_helper.config.ash_config import AshConfig

    generator = _load(
        "_ash_generate_config_reference_for_coverage",
        REPO_ROOT / "scripts" / "generate_config_reference.py",
    )
    sections, _missing = generator.walk_config(AshConfig)
    rows = {f"config:{row['full']}" for section in sections for row in section.rows}
    config = {f.id: f for f in _inventory() if f.kind == "config"}

    assert set(config) == rows
    for fid in (
        "config:global_settings",
        "config:global_settings.severity_threshold",
        "config:global_settings.ignore_paths[].path",
        "config:mcp-resource-management.max_concurrent_scans",
        "config:scanners.cdk-nag",
    ):
        assert fid in config, fid
    assert not [fid for fid in config if "*" in fid]
    assert "config:mcp_resource_management" not in config
    assert "config:scanners.bandit.enabled" not in config
    assert all(feature.regions == () for feature in config.values())
    # build.custom_scanners holds scanner objects, whose fields are their runtime state
    # (context.config is an AshConfig again): the walk stops at the list.
    assert "config:build.custom_scanners" in config
    assert not [
        fid
        for fid in config
        if fid.startswith(
            ("config:build.custom_scanners.", "config:build.custom_scanners[]")
        )
    ]


def test_the_mcp_tool_features_are_the_registered_tools_measured_in_their_bodies():
    gate = _load(
        "_ash_docs_gate_for_feature_coverage",
        REPO_ROOT / "scripts" / "verify_docs_freshness.py",
    )
    tools = gate.mcp_tool_names()
    by_id = _by_id()

    assert {fid for fid in by_id if fid.startswith("mcp-tool:")} == {
        f"mcp-tool:{name}" for name in tools
    }
    (region,) = by_id["mcp-tool:run_ash_scan"].regions
    assert region.path == "automated_security_helper/cli/mcp_server.py"
    lineno = int(tools["run_ash_scan"].rpartition(":")[2])
    _assert_region(region, _function_node(region.path, lineno=lineno))


def test_every_code_feature_is_measured_in_a_file_of_this_package():
    for feature in _inventory():
        if feature.kind == "config":
            continue
        assert feature.regions, f"{feature.id} has no code to reach"
        for region in feature.regions:
            assert region.path.startswith("automated_security_helper/"), feature.id
            assert (REPO_ROOT / region.path).is_file(), feature.id
            assert region.lines and min(region.lines) > 0, feature.id
        path, _, line = feature.location.rpartition(":")
        assert path == feature.regions[0].path and int(line) > 0, feature.id


def test_the_corpus_is_the_markdown_the_docs_examples_test_reads():
    """pages_selected and the presented column read the same pages the examples
    test parametrizes over: the docs freshness corpus, templates left out."""
    gate = _load(
        "_ash_docs_gate_for_feature_coverage",
        REPO_ROOT / "scripts" / "verify_docs_freshness.py",
    )
    expected = sorted(p.resolve() for p in gate.collect_md_files() if p.suffix == ".md")

    assert sorted(p.resolve() for p in _cov().corpus_pages(REPO_ROOT)) == expected


# --------------------------------------------------------------------------- #
# Evidence: code reach by a passing executed block
# --------------------------------------------------------------------------- #


def test_an_uncovered_planted_feature_fails_the_gate_as_f1_and_exits_1(tmp_path):
    """The red half of the gate: a feature no passing block reached, not in the
    baseline. The block's context is in the data (it ran other code), so this is a
    gate failure, not a measurement that measured nothing."""
    run = Run(tmp_path)
    (line,) = run.page("page.md", ONE_BLOCK)
    run.record("page.md", _block("page.md", line))
    run.hit(f"page.md::{line}", OTHER_PATH, {5})
    planted = _planted()

    assert _check(run, [planted]) == 1
    report = _report(run)
    assert report["gate"]["failures"]["F1"] == [planted.id]
    (entry,) = report["features"]
    assert entry["covered"] is False and entry["pages"] == []
    assert planted.id in _markdown(run)


def test_a_passing_block_that_reaches_the_planted_feature_passes_the_gate(tmp_path):
    run, line = _valid_run(tmp_path)
    planted = _planted()

    assert _check(run, [planted]) == 0
    (entry,) = _report(run)["features"]
    assert entry["covered"] is True and entry["pages"] == ["page.md"]


def test_a_failing_block_that_reaches_the_planted_feature_does_not_cover_it(tmp_path):
    """An example that does not end the way its marker says demonstrates nothing."""
    run = Run(tmp_path)
    first, second = run.page("page.md", TWO_BLOCKS)
    run.record("page.md", _block("page.md", first), _block("page.md", second, ok=False))
    run.hit(f"page.md::{first}", OTHER_PATH, {5})
    run.hit(f"page.md::{second}", PLANTED_PATH, PLANTED_LINES)
    planted = _planted()

    assert planted.id not in _covered(run, [planted])
    assert _check(run, [planted]) == 1


def _an_exit_no_member_names() -> str:
    codes = {int(member) for member in AshExitCode}
    return str(next(code for code in range(256) if code not in codes))


#: Every exit a block can expect, with its AshExitCode name where it has one.
EXPECTED_EXITS = [
    pytest.param(str(int(member)), member.name, id=member.name)
    for member in AshExitCode
] + [
    pytest.param("nonzero", None, id="nonzero"),
    pytest.param("any", None, id="any"),
    pytest.param(_an_exit_no_member_names(), None, id="an-exit-ash-does-not-use"),
]
#: How far a block's processes got with a scan's results write.
RESULTS_WRITES = ["no-results-write", "an-early-exit-of-the-write", "wrote-its-results"]


def _results_write():
    """ASHScanOrchestrator._write_results_file, which a scan runs once its phases
    have run, to write the results it found."""
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    return ASHScanOrchestrator._write_results_file


def _scan_wrote_its_results(run: Run, context: str) -> None:
    """Coverage data in which ``context`` ran the results write past its early exits."""
    region = _cov().function_region(_results_write())
    run.hit(context, region.path, {min(region.lines)})


def _scan_left_the_results_write_at_an_early_exit(run: Run, context: str) -> None:
    """Coverage data in which ``context`` ran the results write up to its last early
    exit and no further."""
    path = "automated_security_helper/core/orchestrator.py"
    node = _function_node(path, "_write_results_file", cls="ASHScanOrchestrator")
    body = _without_docstring(node.body)
    guards = [statement for statement in body if _is_guard(statement)]
    run.hit(context, path, set(range(body[0].lineno, guards[-1].end_lineno + 1)))


@pytest.mark.parametrize("results", RESULTS_WRITES)
@pytest.mark.parametrize(("expected", "name"), EXPECTED_EXITS)
def test_only_a_block_expected_to_succeed_or_to_report_findings_is_evidence(
    tmp_path, expected, name, results
):
    """A passing block that expects ASH to refuse something (an invalid configuration,
    a workspace error, a usage error) shows the refusal: the code it reaches stops
    before doing the work its feature names. So do a block that expects to be
    stopped, one that expects any nonzero exit, and one that expects anything. ASH
    exits 1 both for a scan whose scanners failed and for many refusals, so a block
    that expects 1 is evidence only when its scan also wrote its results: it reached
    the results write past its early exits (no results file for this run; the engine
    returned something else). The codes are read from AshExitCode."""
    run = Run(tmp_path)
    (line,) = run.page(
        "page.md",
        f"<!-- doctest: run expect-exit={expected} -->\n"
        f'{FENCE}python\nprint("an example")\n{FENCE}\n',
    )
    run.record("page.md", _block("page.md", line, expected=expected))
    run.hit(f"page.md::{line}", PLANTED_PATH, {11})
    if results == "wrote-its-results":
        _scan_wrote_its_results(run, f"page.md::{line}")
    elif results == "an-early-exit-of-the-write":
        _scan_left_the_results_write_at_an_early_exit(run, f"page.md::{line}")
    # A block expected to succeed passes too, so the measurement itself is sound.
    run.page("other.md", ONE_BLOCK)
    run.record("other.md", _block("other.md", 3))
    run.hit("other.md::3", OTHER_PATH, {5})
    planted = _planted()
    counts = name in COUNTING_EXITS or (
        name in COUNTING_ONCE_A_SCAN_WROTE_ITS_RESULTS
        and results == "wrote-its-results"
    )

    assert (planted.id in _covered(run, [planted])) is counts


def test_a_scan_wrote_its_results_once_it_passed_both_early_exits_of_the_results_write():
    """The code that tells a scan with scanner errors from a refusal, both exit 1: the
    results write past its two early exits, the return for a run that writes no
    results file and the return for an engine that gave something other than
    results. Pinned, so that a change to either exit, or a third one, is a visible
    change to what an exit-1 example must reach."""
    path = "automated_security_helper/core/orchestrator.py"
    node = _function_node(path, "_write_results_file", cls="ASHScanOrchestrator")
    guards = [
        statement for statement in _without_docstring(node.body) if _is_guard(statement)
    ]

    region = _cov().function_region(_results_write())

    assert len(guards) == 2, [ast.unparse(guard.test) for guard in guards]
    assert "_writes_results_file" in ast.unparse(guards[0].test)
    assert "AshAggregatedResults" in ast.unparse(guards[1].test)
    assert region.path == path
    _assert_region(region, node)
    for guard in guards:
        assert not region.lines & set(range(guard.lineno, guard.end_lineno + 1))


@pytest.mark.parametrize(
    ("rel", "needles", "reached", "wrote_results", "covered", "uncovered"),
    [
        pytest.param(
            "docs/content/reference/exit-codes.md",
            ("--use-existing",),
            "command:ash scan",
            False,
            set(),
            {
                "command:ash scan",
                "option:ash scan --use-existing",
                "option:ash scan --output-dir",
                "option:ash scan --source-dir",
            },
            id="use-existing-with-no-results-to-use",
        ),
        pytest.param(
            "docs/content/reference/exit-codes.md",
            ("ash config init",),
            "command:ash config init",
            False,
            set(),
            {"command:ash config init"},
            id="config-init-refusing-a-second-config-source",
        ),
        pytest.param(
            "docs/content/faq.md",
            ("npm-audit,detect-secrets",),
            "command:ash scan",
            True,
            {
                "command:ash scan",
                "option:ash scan --offline",
                "option:ash scan --scanners",
            },
            set(),
            id="an-offline-scan-with-npm-audit-missing",
        ),
        pytest.param(
            "docs/content/faq.md",
            ("npm-audit,detect-secrets",),
            "command:ash scan",
            False,
            set(),
            {"command:ash scan", "option:ash scan --offline"},
            id="the-same-scan-had-it-written-no-results",
        ),
        pytest.param(
            "docs/content/how-to/run-offline.md",
            ("js-app-results",),
            "command:ash scan",
            True,
            {
                "command:ash scan",
                "option:ash scan --offline",
                "option:ash scan --source-dir",
                "option:ash scan --output-dir",
            },
            set(),
            id="an-offline-scan-of-a-project-with-a-lockfile",
        ),
    ],
)
def test_an_exit_1_example_on_these_pages_counts_only_when_its_scan_wrote_its_results(
    tmp_path, rel, needles, reached, wrote_results, covered, uncovered
):
    """``--use-existing`` with an output directory that holds no results exits 1 well
    past the scan callback's early exits, and ``ash config init`` exits 1 refusing a
    second config source: they show a refusal, not the features their command lines
    name. An offline scan that reports npm-audit MISSING exits 1 too, after it wrote
    its results, and shows the scan."""
    run = Run(tmp_path)
    block = _the_block(run.real_page(rel), *needles)
    assert _expected_exit(block) == str(int(AshExitCode.SCAN_ERRORS)), (
        f"{rel}:{block.fence_line} no longer expects exit 1; this case is stale"
    )
    context = f"{rel}::{block.fence_line}"
    run.record(rel, _block(rel, block.fence_line, expected=_expected_exit(block)))
    _reach(run, context, reached)
    if wrote_results:
        _scan_wrote_its_results(run, context)

    result = _covered(run, _cli_features())

    assert covered <= result, sorted(covered - result)
    assert not uncovered & result, sorted(uncovered & result)


def test_check_exits_2_when_the_results_write_it_reads_exit_1_by_is_gone(
    tmp_path, monkeypatch, capsys
):
    """A rename of the results write must fail the check loudly, naming it, never
    leave every exit-1 example silently uncovered (or covered)."""
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    cov = _cov()
    run = Run(tmp_path)
    (line,) = run.page(
        "page.md",
        f"<!-- doctest: run expect-exit=1 -->\n{FENCE}python\nprint(1)\n{FENCE}\n",
    )
    run.record("page.md", _block("page.md", line, expected="1"))
    run.hit(f"page.md::{line}", PLANTED_PATH, {11})
    planted = _planted()
    monkeypatch.setattr(cov, "inventory", lambda: [planted])
    monkeypatch.setattr(cov, "corpus_pages", lambda docs_root: list(run.corpus))
    monkeypatch.delattr(ASHScanOrchestrator, "_write_results_file")

    code = cov.main(
        [
            "check",
            "--data",
            str(run.data),
            "--baseline",
            str(_baseline(tmp_path / "baseline.txt", [])),
            "--docs-root",
            str(run.docs),
            "--out",
            str(run.out),
        ]
    )

    assert code == 2
    assert "_write_results_file" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("command_line", "counts"),
    [
        pytest.param(
            "ash dependencies install --tool not-a-tool",
            False,
            id="a-refused-tool-selection-of-dependencies-install",
        ),
        pytest.param(
            "ash scan --offline",
            True,
            id="a-scan-whose-exit-is-the-findings-code",
        ),
    ],
)
def test_a_block_that_shows_dependencies_install_refusing_a_selection_is_no_evidence(
    tmp_path, command_line, counts
):
    """The bad-selection exit of ``ash dependencies install --tool <unknown>`` is the
    number of the scan's actionable-findings code, which counts as evidence; but that
    command never scans, so such a block shows a refusal. The same code on a scan is
    findings."""
    selection = str(_checks().bad_selection_exit())
    run = Run(tmp_path)
    (line,) = run.page(
        "page.md",
        f"<!-- doctest: run expect-exit={selection} -->\n"
        f"{FENCE}bash\n{command_line}\n{FENCE}\n",
    )
    run.record("page.md", _block("page.md", line, expected=selection))
    run.hit(f"page.md::{line}", PLANTED_PATH, {11})
    # A block expected to succeed passes too, so the measurement itself is sound.
    run.page("other.md", ONE_BLOCK)
    run.record("other.md", _block("other.md", 3))
    run.hit("other.md::3", OTHER_PATH, {5})
    planted = _planted()

    assert (planted.id in _covered(run, [planted])) is counts


def test_a_saved_blocks_context_is_no_evidence(tmp_path):
    """Only a block the runner ran can have reached code; a record that says a block
    was saved and not run counts for nothing whatever the data holds."""
    run = Run(tmp_path)
    first, second = run.page(
        "page.md",
        _join(
            f'{FENCE}python\nprint("run")\n{FENCE}',
            f'<!-- doctest: save-as=example.py -->\n{FENCE}python\nprint("saved")\n{FENCE}',
        ),
    )
    run.record(
        "page.md",
        _block("page.md", first),
        _block("page.md", second, runs=False, save_as="example.py"),
    )
    run.hit(f"page.md::{first}", OTHER_PATH, {5})
    run.hit(f"page.md::{second}", PLANTED_PATH, PLANTED_LINES)
    planted = _planted()

    assert planted.id not in _covered(run, [planted])


@pytest.mark.parametrize(
    "spelling",
    ["another-checkout", "a-checkout-named-like-the-package", "windows-separators"],
)
def test_code_recorded_in_another_checkout_still_matches_its_region(tmp_path, spelling):
    run = Run(tmp_path)
    (line,) = run.page("page.md", ONE_BLOCK)
    run.record("page.md", _block("page.md", line))
    parts = PLANTED_PATH.split("/")
    measured = {
        "another-checkout": str(tmp_path.joinpath("elsewhere", "checkout", *parts)),
        "a-checkout-named-like-the-package": str(
            tmp_path.joinpath("automated_security_helper", *parts)
        ),
        "windows-separators": "C:\\work\\" + PLANTED_PATH.replace("/", "\\"),
    }[spelling]
    run.hit(f"page.md::{line}", PLANTED_PATH, {11}, measured=measured)
    planted = _planted()

    assert planted.id in _covered(run, [planted])


def test_a_file_whose_name_only_ends_like_the_region_does_not_match(tmp_path):
    run = Run(tmp_path)
    (line,) = run.page("page.md", ONE_BLOCK)
    run.record("page.md", _block("page.md", line))
    run.hit(
        f"page.md::{line}",
        PLANTED_PATH,
        {11},
        measured=str(tmp_path / ("not" + PLANTED_PATH)),
    )
    planted = _planted()

    assert planted.id not in _covered(run, [planted])


# --------------------------------------------------------------------------- #
# Evidence: commands and options are invoked and reached
# --------------------------------------------------------------------------- #


def _cli_features():
    return [f for f in _inventory() if f.kind in ("command", "option")]


def _reach(run: Run, context: str, feature_id: str) -> None:
    """Coverage data in which ``context`` ran the first line of a real feature's code."""
    region = _by_id()[feature_id].regions[0]
    run.hit(context, region.path, {min(region.lines)})


def _one_command(run: Run, command_line: str, *, marker: str = "") -> int:
    (line,) = run.page(
        "page.md",
        (f"{marker}\n" if marker else "") + f"{FENCE}bash\n{command_line}\n{FENCE}\n",
    )
    return line


@pytest.mark.parametrize(
    ("command_line", "reached", "covered", "uncovered"),
    [
        pytest.param(
            "ash scan --scanners bandit --offline",
            "command:ash scan",
            {
                "command:ash scan",
                "option:ash scan --scanners",
                "option:ash scan --offline",
            },
            {"option:ash scan --source-dir"},
            id="options-after-the-subcommand",
        ),
        pytest.param(
            "ash --scanners bandit",
            "command:ash scan",
            {"command:ash scan", "option:ash scan --scanners"},
            set(),
            id="bare-ash-is-the-scan",
        ),
        pytest.param(
            "ash scan --no-progress",
            "command:ash scan",
            {"option:ash scan --progress"},
            set(),
            id="a-secondary-name",
        ),
        pytest.param(
            "ash report --format sarif",
            "command:ash results report",
            {"command:ash results report", "option:ash results report --format"},
            set(),
            id="a-hidden-spelling-is-evidence",
        ),
        pytest.param(
            "ash --output-dir out report",
            "command:ash results report",
            {"command:ash results report", "option:ash results report --output-dir"},
            {"option:ash scan --output-dir"},
            id="an-option-before-the-subcommand-is-the-subcommands",
        ),
    ],
)
def test_a_passing_block_covers_the_command_it_invokes_and_the_options_it_gives(
    tmp_path, command_line, reached, covered, uncovered
):
    """An option is read on every invocation, with its default, so reaching the
    command's code alone would cover every option; the block must also give it. ASH
    passes a root option typed before a subcommand on to the subcommand, so it is the
    subcommand's option that is shown."""
    run = Run(tmp_path)
    line = _one_command(run, command_line)
    run.record("page.md", _block("page.md", line))
    _reach(run, f"page.md::{line}", reached)

    result = _covered(run, _cli_features())

    assert covered <= result, sorted(covered - result)
    assert not uncovered & result, sorted(uncovered & result)


@pytest.mark.parametrize(
    ("command_line", "stops_at", "covered", "uncovered"),
    [
        pytest.param(
            "ash config validate --config .ash/.ash.yaml",
            "invoked_subcommand",
            set(),
            {"command:ash scan", "option:ash scan --config"},
            id="another-subcommand-runs-the-callback-up-to-its-return",
        ),
        pytest.param(
            "ash --version",
            "version",
            {"option:ash scan --version"},
            {"command:ash scan"},
            id="the-version-exit-is-the-version-options-own-work",
        ),
        pytest.param(
            "ash scan --config .ash/.ash.yaml",
            None,
            {"command:ash scan", "option:ash scan --config"},
            set(),
            id="the-scan-reaches-its-own-code",
        ),
    ],
)
def test_only_the_scan_callbacks_code_past_its_early_exits_shows_the_scan(
    tmp_path, command_line, stops_at, covered, uncovered
):
    """click runs the root group's callback, the scan's own function, before every
    subcommand, and the function returns at once there; ``ash --version`` prints and
    exits a few lines further on. The lines up to those exits run for invocations
    that scan nothing, so a block that reached only them covers neither the scan nor
    an option it gives, except the one option whose own work that exit is:
    ``ash --version`` shows ``--version``, never the scan. A block that reached the
    scan's own code covers the scan and the options it gives."""
    path, node = _scan_callback()
    run = Run(tmp_path)
    line = _one_command(run, command_line)
    run.record("page.md", _block("page.md", line))
    if stops_at is None:
        _reach(run, f"page.md::{line}", "command:ash scan")
    else:
        first = _without_docstring(node.body)[0].lineno
        guard = _scan_early_exit(node, mentions=stops_at)
        run.hit(f"page.md::{line}", path, set(range(first, guard.end_lineno + 1)))

    result = _covered(run, _cli_features())

    assert covered <= result, sorted(covered - result)
    assert not uncovered & result, sorted(uncovered & result)


@pytest.mark.parametrize(
    "rel",
    [
        "docs/content/getting-started/local.md",
        "docs/content/getting-started/agents.md",
    ],
)
def test_ash_version_on_these_pages_covers_the_version_option_and_not_the_scan(
    tmp_path, rel
):
    """These pages run ``ash --version``, which prints the version and exits at the
    scan callback's version exit."""
    path, node = _scan_callback()
    run = Run(tmp_path)
    page = run.real_page(rel)
    (block,) = [block for block in page.blocks if block.body.strip() == "ash --version"]
    context = f"{rel}::{block.fence_line}"
    run.record(rel, _block(rel, block.fence_line, expected=_expected_exit(block)))
    first = _without_docstring(node.body)[0].lineno
    guard = _scan_early_exit(node, mentions="version")
    run.hit(context, path, set(range(first, guard.end_lineno + 1)))

    result = _covered(run, _cli_features())

    assert "option:ash scan --version" in result
    assert "command:ash scan" not in result


def test_a_python_block_that_reaches_a_commands_code_covers_it_and_none_of_its_options(
    tmp_path,
):
    """A command is covered by reaching its code, as a plugin is. An option needs a
    command line that gives it, and command lines are read from shell blocks, so a
    python block that runs ASH (through subprocess, say) shows no option."""
    run = Run(tmp_path)
    (line,) = run.page(
        "page.md",
        f"{FENCE}python\nimport subprocess\n\n"
        'subprocess.run(["ash", "scan", "--scanners", "bandit"], check=True)\n'
        f"{FENCE}\n",
    )
    run.record("page.md", _block("page.md", line))
    _reach(run, f"page.md::{line}", "command:ash scan")

    result = _covered(run, _cli_features())

    assert "command:ash scan" in result
    assert "option:ash scan --scanners" not in result


def test_a_block_that_shows_a_refusal_covers_nothing_it_names(tmp_path):
    """ASH refuses the value before the code that would use it runs; the block's
    marker says so. It shows the refusal, not the command, the options or the keys on
    its command line, even where it reached their code."""
    refused = str(int(AshExitCode.USAGE_ERROR))
    run = Run(tmp_path)
    line = _one_command(
        run,
        "ash scan --scanners bandit "
        "--config-overrides 'global_settings.severity_threshold=HIGH'",
        marker=f"<!-- doctest: run expect-exit={refused} -->",
    )
    run.record("page.md", _block("page.md", line, expected=refused))
    _reach(run, f"page.md::{line}", "command:ash scan")
    overrides = _anchor("apply_config_overrides")
    run.hit(f"page.md::{line}", overrides.path, {min(overrides.lines)})
    # A block expected to succeed passes too, so the measurement itself is sound.
    run.page("other.md", ONE_BLOCK)
    run.record("other.md", _block("other.md", 3))
    run.hit("other.md::3", OTHER_PATH, {5})

    result = _covered(run, _cli_features() + _config_features())

    assert not result & {
        "command:ash scan",
        "option:ash scan --scanners",
        "option:ash scan --config-overrides",
        "config:global_settings",
        "config:global_settings.severity_threshold",
    }, sorted(result)


@pytest.mark.parametrize(
    ("ok", "reach"), [(True, False), (False, True)], ids=["not-reached", "failed"]
)
def test_an_option_is_not_covered_by_a_block_that_did_not_pass_and_reach(
    tmp_path, ok, reach
):
    run = Run(tmp_path)
    line = _one_command(run, "ash scan --scanners bandit")
    run.record("page.md", _block("page.md", line, ok=ok))
    if reach:
        _reach(run, f"page.md::{line}", "command:ash scan")
    else:
        run.hit(f"page.md::{line}", OTHER_PATH, {5})
    if not ok:
        # Another block passes, so the measurement itself is sound.
        run.page("other.md", ONE_BLOCK)
        run.record("other.md", _block("other.md", 3))
        run.hit("other.md::3", OTHER_PATH, {5})

    result = _covered(run, _cli_features())

    assert not result & {"command:ash scan", "option:ash scan --scanners"}


# --------------------------------------------------------------------------- #
# Evidence: configuration keys are in effect and the code that consumes them ran
# --------------------------------------------------------------------------- #


def _config_features():
    return [f for f in _inventory() if f.kind == "config"]


def _anchor(name: str):
    """The code that consumes a configuration: load_config_file for a saved document,
    apply_config_overrides for --config-overrides."""
    from automated_security_helper.config import resolve_config

    return _cov().function_region(getattr(resolve_config, name))


def _saved_config(
    body: str,
    *,
    kind: str = "kind=ash",
    save_as: str = ".ash/.ash.yaml",
    lang: str = "yaml",
) -> str:
    return f"<!-- doctest: config {kind} save-as={save_as} -->\n{FENCE}{lang}\n{body}\n{FENCE}"


def _scan_block(
    command_line: str = "ash scan --offline", *, fresh: bool = False
) -> str:
    marker = "<!-- doctest: run fresh -->\n" if fresh else ""
    return f"{marker}{FENCE}bash\n{command_line}\n{FENCE}"


SEVERITY = "global_settings:\n  severity_threshold: HIGH"


def _overrides(value: str) -> str:
    """A scan command line that gives ``value`` to --config-overrides, quoted."""
    return f"ash scan --config-overrides '{value}'"


def _config_run(
    tmp_path: Path,
    *,
    page: str,
    config_at: int = 0,
    block_at: int = 1,
    saved: bool = True,
    save_as: str = ".ash/.ash.yaml",
    saved_ok: bool = True,
    block_ok: bool = True,
    block_session: int = 1,
    anchor: str = "load_config_file",
) -> Run:
    """A page with a configuration block and a block that may load it, recorded and
    measured: the block reached ``anchor``."""
    run = Run(tmp_path)
    lines = run.page("page.md", page)
    config_line, block_line = lines[config_at], lines[block_at]
    records = [_block("page.md", block_line, ok=block_ok, session=block_session)]
    if saved:
        records.append(
            _block("page.md", config_line, runs=False, ok=saved_ok, save_as=save_as)
        )
    run.record("page.md", *sorted(records, key=lambda record: record["line"]))
    region = _anchor(anchor)
    run.hit(f"page.md::{block_line}", region.path, {min(region.lines)})
    if not block_ok:
        run.page("other.md", ONE_BLOCK)
        run.record("other.md", _block("other.md", 3))
        run.hit("other.md::3", OTHER_PATH, {5})
    return run


@pytest.mark.parametrize(
    ("variant", "covered", "uncovered"),
    [
        pytest.param(
            {"page": _join(_saved_config(SEVERITY), _scan_block())},
            {"config:global_settings", "config:global_settings.severity_threshold"},
            {"config:fail_on_findings"},
            id="a-saved-ash-config",
        ),
        pytest.param(
            {
                "page": _join(
                    "<!-- doctest: config kind=pyproject save-as=pyproject.toml -->\n"
                    f'{FENCE}toml\n[project]\nname = "example"\n\n[tool.ash]\n'
                    f"fail_on_findings = false\n{FENCE}",
                    _scan_block(),
                ),
                "save_as": "pyproject.toml",
            },
            {"config:fail_on_findings"},
            {"config:project_name"},
            id="pyproject-under-tool-ash",
        ),
        pytest.param(
            {
                "page": _join(
                    _saved_config(
                        "global_settings:\n  ignore_paths:\n"
                        '    - path: "build/**"\n      reason: generated output'
                    ),
                    _scan_block(),
                )
            },
            {
                "config:global_settings",
                "config:global_settings.ignore_paths",
                "config:global_settings.ignore_paths[].path",
                "config:global_settings.ignore_paths[].reason",
            },
            {"config:global_settings.ignore_paths[].expires"},
            id="a-list-of-mappings",
        ),
        pytest.param(
            {
                "page": _join(
                    _saved_config(
                        "mcp-resource-management:\n  max_concurrent_scans: 2"
                    ),
                    _scan_block(),
                )
            },
            {
                "config:mcp-resource-management",
                "config:mcp-resource-management.max_concurrent_scans",
            },
            set(),
            id="written-by-its-alias",
        ),
        pytest.param(
            {
                "page": _join(
                    _saved_config(
                        "mcp_resource_management:\n  max_concurrent_scans: 2"
                    ),
                    _scan_block(),
                )
            },
            {
                "config:mcp-resource-management",
                "config:mcp-resource-management.max_concurrent_scans",
            },
            set(),
            id="written-by-its-field-name",
        ),
        pytest.param(
            {
                "page": _join(
                    _saved_config("scanners:\n  cdk_nag:\n    enabled: false"),
                    _scan_block(),
                )
            },
            {"config:scanners", "config:scanners.cdk-nag"},
            {"config:scanners.bandit"},
            id="a-plugin-section",
        ),
    ],
)
def test_a_saved_config_covers_the_rows_it_sets_when_a_later_block_loads_it(
    tmp_path, variant, covered, uncovered
):
    """Setting a.b.c sets a and a.b too; a written key matches a row by its alias or
    its field name; the id is always the row's own path."""
    run = _config_run(tmp_path, **variant)

    result = _covered(run, _config_features())

    assert covered <= result, sorted(covered - result)
    assert not uncovered & result, sorted(uncovered & result)


@pytest.mark.parametrize(
    "variant",
    [
        pytest.param(
            {
                "page": _join(
                    _saved_config(
                        SEVERITY,
                        kind='kind=ash-invalid reason="shows the refusal of a bad value"',
                    ),
                    _scan_block(),
                )
            },
            id="an-ash-invalid-config-never-counts",
        ),
        pytest.param(
            {
                "page": _join(
                    _saved_config(
                        SEVERITY,
                        kind='kind=other reason="a settings file of another program"',
                    ),
                    _scan_block(),
                )
            },
            id="another-programs-file",
        ),
        pytest.param(
            {"page": _join(_saved_config(SEVERITY), _scan_block()), "saved_ok": False},
            id="a-refused-save",
        ),
        pytest.param(
            {"page": _join(_saved_config(SEVERITY), _scan_block()), "block_ok": False},
            id="a-failing-block",
        ),
        pytest.param(
            {
                "page": _join(_saved_config(SEVERITY), _scan_block()),
                "anchor": "apply_config_overrides",
            },
            id="a-block-that-loaded-no-config-file",
        ),
        pytest.param(
            {
                "page": _join(_saved_config(SEVERITY), _scan_block(fresh=True)),
                "block_session": 2,
            },
            id="saved-in-an-earlier-session",
        ),
        pytest.param(
            {
                "page": _join(_scan_block(), _saved_config(SEVERITY)),
                "config_at": 1,
                "block_at": 0,
            },
            id="saved-after-the-block",
        ),
        pytest.param(
            {
                "page": _join(f"{FENCE}yaml\n{SEVERITY}\n{FENCE}", _scan_block()),
                "saved": False,
            },
            id="shown-and-not-saved",
        ),
    ],
)
def test_a_config_key_is_not_covered_unless_a_passing_block_loaded_a_saved_ash_config_holding_it(
    tmp_path, variant
):
    run = _config_run(tmp_path, **variant)

    assert "config:global_settings.severity_threshold" not in _covered(
        run, _config_features()
    )


def _loading_run(tmp_path: Path, *, text: str, loading: int = -1) -> Run:
    """A page recorded as the runner records it, whose ``loading``-th runnable block
    reached load_config_file."""
    run = Run(tmp_path)
    run.page("page.md", text)
    page = _record_as_the_runner_does(run, "page.md")
    block = [block for block in page.blocks if _checks().runner_runs(block)][loading]
    region = _anchor("load_config_file")
    run.hit(f"page.md::{block.fence_line}", region.path, {min(region.lines)})
    return run


def _discovered_names() -> list[str]:
    """Every name config discovery reads in the directory it searches, from the lists
    core/constants.py gives it (config/config_sources.py): the canonical file, each
    dedicated name at the top and in ``.ash/``, then each rc name at the top."""
    from automated_security_helper.core import constants

    names = [constants.ASH_CANONICAL_CONFIG_FILE_NAME]
    for name in constants.ASH_CONFIG_FILE_NAMES:
        names += [name, f".ash/{name}"]
    names += constants.ASH_RC_FILE_NAMES
    return list(dict.fromkeys(names))


#: A configuration that sets project_name, in the language of each config file name.
PROJECT_NAME = {
    "yaml": "project_name: demo",
    "json": '{"project_name": "demo"}',
    "toml": 'project_name = "demo"',
}


@pytest.mark.parametrize("name", _discovered_names())
def test_a_config_saved_under_a_name_discovery_reads_counts_for_a_scan_of_its_directory(
    tmp_path, name
):
    """A scan that names no configuration loads the first config source discovery
    finds in the directory it scans, the working directory when no --source-dir is
    given; a saved configuration under any of discovery's names is one it can have
    loaded. The names are read from the code."""
    suffix = name.rpartition(".")[2]
    lang = {"yml": "yaml"}.get(suffix, suffix)
    run = _loading_run(
        tmp_path,
        text=_join(
            _saved_config(PROJECT_NAME[lang], save_as=name, lang=lang), _scan_block()
        ),
    )

    assert "config:project_name" in _covered(run, _config_features())


#: The rows SEVERITY sets.
SEVERITY_ROWS = {"config:global_settings", "config:global_settings.severity_threshold"}
#: A configuration file under a name discovery never reads.
TEAM = "configs/team.yaml"
#: A fragment holding a key of global_settings at its root.
FRAGMENT = "severity_threshold: HIGH"
FRAGMENT_KIND = "kind=ash-fragment at=global_settings"


@pytest.mark.parametrize(
    ("variant", "covered", "uncovered"),
    [
        pytest.param(
            {
                "text": _join(
                    _saved_config("fail_on_findings: false", save_as=".ash.yaml"),
                    _saved_config("project_name: demo", save_as=".ash.yaml"),
                    _scan_block(),
                )
            },
            {"config:project_name"},
            {"config:fail_on_findings"},
            id="a-later-save-of-the-same-name-replaced-it",
        ),
        pytest.param(
            {
                "text": _join(
                    _saved_config("fail_on_findings: false", save_as=".ash.yaml"),
                    _scan_block(),
                    _saved_config("project_name: demo", save_as=".ash.yaml"),
                ),
                "loading": 0,
            },
            {"config:fail_on_findings"},
            {"config:project_name"},
            id="replaced-only-after-the-block-that-loaded-it",
        ),
        pytest.param(
            {
                "text": _join(
                    _saved_config("project_name: demo", save_as=".ash.yaml"),
                    _saved_config(SEVERITY, save_as="notes/team.yaml"),
                    _scan_block(),
                )
            },
            {"config:project_name"},
            SEVERITY_ROWS,
            id="a-name-discovery-does-not-read",
        ),
        pytest.param(
            {
                "text": _join(
                    _saved_config(SEVERITY, save_as=".ash/.ashrc.yaml"), _scan_block()
                )
            },
            set(),
            SEVERITY_ROWS,
            id="an-rc-name-in-the-ash-directory",
        ),
        pytest.param(
            {
                "text": _join(
                    _saved_config(
                        FRAGMENT, kind=FRAGMENT_KIND, save_as=".ash/fragment.yaml"
                    ),
                    _scan_block(),
                )
            },
            set(),
            SEVERITY_ROWS,
            id="a-fragment-under-its-at-prefix",
        ),
        pytest.param(
            {
                "text": _join(
                    _saved_config(FRAGMENT, kind=FRAGMENT_KIND, save_as=".ash.yaml"),
                    _scan_block(),
                )
            },
            set(),
            SEVERITY_ROWS,
            id="a-fragment-under-a-name-discovery-reads",
        ),
        pytest.param(
            {
                "text": _join(
                    _saved_config(SEVERITY, save_as=TEAM),
                    _scan_block(f"ash scan --config {TEAM} --offline"),
                )
            },
            SEVERITY_ROWS,
            set(),
            id="named-by-config",
        ),
        pytest.param(
            {
                "text": _join(
                    _saved_config(SEVERITY, save_as=TEAM),
                    _scan_block(f"ash scan --config={TEAM} --offline"),
                )
            },
            SEVERITY_ROWS,
            set(),
            id="named-by-config-inline",
        ),
        pytest.param(
            {
                "text": _join(
                    _saved_config(SEVERITY, save_as=TEAM),
                    _scan_block(f"ash scan -c {TEAM} --offline"),
                )
            },
            SEVERITY_ROWS,
            set(),
            id="named-by-the-short-spelling-of-config",
        ),
        pytest.param(
            {
                "text": _join(
                    _saved_config(SEVERITY, save_as=TEAM),
                    _scan_block(f"ASH_CONFIG={TEAM} ash scan --offline"),
                )
            },
            SEVERITY_ROWS,
            set(),
            id="named-by-ash-config-on-the-command",
        ),
        pytest.param(
            {
                "text": _join(
                    _saved_config(SEVERITY, save_as=TEAM),
                    _scan_block(f"export ASH_CONFIG={TEAM}\nash scan --offline"),
                )
            },
            SEVERITY_ROWS,
            set(),
            id="named-by-ash-config-exported-in-the-block",
        ),
        pytest.param(
            {
                "text": _join(
                    _saved_config(SEVERITY, save_as=TEAM),
                    _scan_block("ash scan --config configs/other.yaml --offline"),
                )
            },
            set(),
            SEVERITY_ROWS,
            id="config-names-another-file",
        ),
        pytest.param(
            {
                "text": _join(
                    _saved_config(SEVERITY, save_as=TEAM),
                    _scan_block('ASH_CONFIG="$TEAM_CONFIG" ash scan --offline'),
                )
            },
            set(),
            SEVERITY_ROWS,
            id="ash-config-from-a-variable",
        ),
        pytest.param(
            {
                "text": _join(
                    _saved_config(SEVERITY, save_as=TEAM),
                    _scan_block(f"export ASH_CONFIG={TEAM}"),
                    _scan_block(),
                )
            },
            set(),
            SEVERITY_ROWS,
            id="ash-config-exported-by-an-earlier-block",
        ),
        pytest.param(
            {
                "text": _join(
                    _saved_config(SEVERITY, save_as="sub/.ash.yaml"),
                    _scan_block("ash --source-dir sub --offline"),
                )
            },
            SEVERITY_ROWS,
            set(),
            id="in-the-directory-source-dir-names",
        ),
        pytest.param(
            {
                "text": _join(
                    _saved_config(SEVERITY, save_as=".ash.yaml"),
                    _scan_block("ash --source-dir . --offline"),
                )
            },
            SEVERITY_ROWS,
            set(),
            id="source-dir-names-the-working-directory",
        ),
        pytest.param(
            {
                "text": _join(
                    _saved_config(SEVERITY, save_as=".ash.yaml"),
                    _scan_block("ash --source-dir sub --offline"),
                )
            },
            set(),
            SEVERITY_ROWS,
            id="in-the-working-directory-while-source-dir-names-another",
        ),
        pytest.param(
            {
                "text": _join(
                    _saved_config(SEVERITY, save_as="sub/.ash.yaml"),
                    _scan_block(),
                )
            },
            set(),
            SEVERITY_ROWS,
            id="in-a-subdirectory-and-no-source-dir",
        ),
    ],
)
def test_a_saved_config_counts_only_where_the_loading_block_can_have_loaded_it(
    tmp_path, variant, covered, uncovered
):
    """A block that reached load_config_file loaded one configuration, not every one
    the page saved. A saved one counts when the block can have loaded it: the latest
    save of its name before the block, under a name discovery reads in the directory
    the block scans (--source-dir, else the working directory), or the name the
    block's own command line gives --config, or a literal ASH_CONFIG=<name> the block
    itself assigns. A fragment never counts: loaded on its own, its keys sit at the
    root, not under its at= prefix. Anything that cannot be shown loaded does not
    count."""
    run = _loading_run(tmp_path, **variant)

    result = _covered(run, _config_features())

    assert covered <= result, sorted(covered - result)
    assert not uncovered & result, sorted(uncovered & result)


#: A workflow a page saves for another program: its step changes directory in the
#: shell of a CI runner, never in a shell of the page's session.
SAVED_WORKFLOW_THAT_CHANGES_DIRECTORY = _saved_config(
    "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
    "      - run: |\n          cd sub\n          make test",
    kind="kind=github-actions",
    save_as=".github/workflows/test.yml",
)


def _changes_directory_before_the_scan(moves: str) -> str:
    """A page that saves SEVERITY under a name discovery reads, runs ``moves`` in a
    shell block of its own, then scans the working directory."""
    return _join(
        _saved_config(SEVERITY, save_as=".ash.yaml"),
        _scan_block(moves),
        _scan_block(),
    )


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            _changes_directory_before_the_scan("cd sub"), id="cd-in-an-earlier-block"
        ),
        pytest.param(
            _join(
                _scan_block("cd sub"),
                _saved_config(SEVERITY, save_as=".ash.yaml"),
                _scan_block(),
            ),
            id="cd-before-the-save",
        ),
        pytest.param(
            _join(
                _saved_config(SEVERITY, save_as=TEAM),
                _scan_block("cd sub"),
                _scan_block(f"ash scan --config {TEAM} --offline"),
            ),
            id="cd-before-a-scan-that-names-the-config",
        ),
        pytest.param(
            _join(
                _saved_config(SEVERITY, save_as=TEAM),
                _scan_block("cd sub"),
                _scan_block(f"ASH_CONFIG={TEAM} ash scan --offline"),
            ),
            id="cd-before-a-scan-whose-ash-config-names-it",
        ),
        pytest.param(
            _join(
                _saved_config(SEVERITY, save_as="sub/.ash.yaml"),
                _scan_block("cd sub"),
                _scan_block("ash --source-dir sub --offline"),
            ),
            id="cd-before-a-scan-of-the-directory-source-dir-names",
        ),
        pytest.param(
            _join(
                _saved_config(SEVERITY, save_as=".ash.yaml"),
                _scan_block("cd sub && ash scan --offline"),
            ),
            id="cd-in-the-loading-block",
        ),
        pytest.param(
            _join(
                _saved_config(SEVERITY, save_as=TEAM),
                _scan_block(f"cd sub && ash scan --config {TEAM} --offline"),
            ),
            id="cd-in-the-loading-block-that-names-the-config",
        ),
        pytest.param(
            _join(
                _saved_config(SEVERITY, save_as=TEAM),
                _scan_block(f"cd sub && ASH_CONFIG={TEAM} ash scan --offline"),
            ),
            id="cd-in-the-loading-block-whose-ash-config-names-it",
        ),
        pytest.param(
            _changes_directory_before_the_scan("mkdir -p sub\ncd sub"),
            id="cd-on-a-later-line",
        ),
        pytest.param(
            _changes_directory_before_the_scan("if [ -d sub ]; then\n  cd sub\nfi"),
            id="cd-on-an-indented-line",
        ),
        pytest.param(
            _changes_directory_before_the_scan("cd"), id="cd-with-no-argument"
        ),
        pytest.param(
            _changes_directory_before_the_scan("mkdir -p sub; cd sub"),
            id="cd-after-a-semicolon",
        ),
        pytest.param(
            _changes_directory_before_the_scan("mkdir -p sub && cd sub"),
            id="cd-after-and",
        ),
        pytest.param(
            _changes_directory_before_the_scan("mkdir sub 2>/dev/null || cd sub"),
            id="cd-after-or",
        ),
        pytest.param(
            _changes_directory_before_the_scan("ls | cd sub"), id="cd-after-a-pipe"
        ),
        pytest.param(
            _changes_directory_before_the_scan("(cd sub && ls)"),
            id="cd-right-after-an-opening-parenthesis",
        ),
        pytest.param(
            _changes_directory_before_the_scan("( cd sub && ls )"),
            id="cd-in-a-subshell",
        ),
        pytest.param(
            _changes_directory_before_the_scan("{ cd sub; ls; }"),
            id="cd-after-an-opening-brace",
        ),
        pytest.param(
            _changes_directory_before_the_scan("pushd sub"),
            id="pushd-in-an-earlier-block",
        ),
        pytest.param(
            _join(
                _saved_config(SEVERITY, save_as=".ash.yaml"),
                _scan_block("pushd sub\nash scan --offline\npopd"),
            ),
            id="pushd-and-popd-around-the-loading-scan",
        ),
        pytest.param(
            _join(
                _saved_config(SEVERITY, save_as=".ash.yaml"),
                f"{FENCE}console\n$ mkdir -p sub\n$ cd sub\n{FENCE}",
                _scan_block(),
            ),
            id="cd-after-the-prompt-of-a-console-block",
        ),
    ],
)
def test_after_a_shell_block_of_the_session_changes_directory_no_saved_config_counts(
    tmp_path, text
):
    """The runner carries the directory a shell block ends in into the next block of
    its session (docs_runner.py, ``_carry_state``), while every save stays anchored at
    the page's project (``_save``). So once a shell block of the session, at or before
    the block that loaded a configuration, holds cd, pushd or popd in command position
    (at the start of a line, after its indentation, or after ;, &&, ||, |, ( or {),
    nothing shows which file the scan read, and no saved configuration counts under any
    name: one discovery reads, one --config names, or one ASH_CONFIG names. A console
    block is read as the commands the runner runs from it, its prompts taken off. A cd
    in a subshell, which moves nothing after it, stops the credit too: the reading is
    static, and an uncovered feature is the safe side of a doubt."""
    run = _loading_run(tmp_path, text=text)

    result = _covered(run, _config_features())

    assert not SEVERITY_ROWS & result, sorted(SEVERITY_ROWS & result)


def test_a_shell_block_that_changed_directory_stops_the_credit_though_it_failed(
    tmp_path,
):
    """The shell's exit trap writes the directory a block ended in whatever the block's
    exit, so a failing block that changed directory moved the blocks of the session
    after it as much as a passing one would."""
    run = Run(tmp_path)
    save, moves, scan = run.page(
        "page.md",
        _join(
            _saved_config(SEVERITY, save_as=".ash.yaml"),
            _scan_block("cd sub && false"),
            _scan_block(),
        ),
    )
    run.record(
        "page.md",
        _block("page.md", save, runs=False, save_as=".ash.yaml"),
        _block("page.md", moves, ok=False),
        _block("page.md", scan),
    )
    region = _anchor("load_config_file")
    run.hit(f"page.md::{scan}", region.path, {min(region.lines)})

    result = _covered(run, _config_features())

    assert not SEVERITY_ROWS & result, sorted(SEVERITY_ROWS & result)


@pytest.mark.parametrize(
    ("text", "loading"),
    [
        pytest.param(
            _changes_directory_before_the_scan("echo cd"),
            -1,
            id="the-word-as-an-argument",
        ),
        pytest.param(
            _changes_directory_before_the_scan("ls cd-notes"),
            -1,
            id="an-argument-that-starts-with-the-word",
        ),
        pytest.param(
            _changes_directory_before_the_scan('echo "cd sub"'),
            -1,
            id="the-word-inside-a-string",
        ),
        pytest.param(
            _join(
                _saved_config(SEVERITY, save_as=".ash.yaml"),
                _scan_block("echo cd && ash scan --offline"),
            ),
            -1,
            id="the-word-as-an-argument-in-the-loading-block",
        ),
        pytest.param(
            _join(
                _scan_block("cd sub"),
                _scan_block("ls", fresh=True),
                _saved_config(SEVERITY, save_as=".ash.yaml"),
                _scan_block(),
            ),
            -1,
            id="cd-in-an-earlier-session",
        ),
        pytest.param(
            _join(
                _saved_config(SEVERITY, save_as=".ash.yaml"),
                _scan_block(),
                _scan_block("cd sub"),
            ),
            0,
            id="cd-after-the-loading-block",
        ),
        pytest.param(
            _join(
                SAVED_WORKFLOW_THAT_CHANGES_DIRECTORY,
                _saved_config(SEVERITY, save_as=".ash.yaml"),
                _scan_block(),
            ),
            -1,
            id="cd-in-a-saved-file-of-another-program",
        ),
    ],
)
def test_a_saved_config_still_counts_where_no_shell_of_its_session_changed_directory_before_the_load(
    tmp_path, text, loading
):
    """The word alone stops nothing. As an argument or inside a string it is not a
    command; a cd in an earlier session moved nothing in this one, which starts in a
    fresh copy of its fixture; a cd after the loading block moved nothing that block
    ran; and a file saved for another program is not a shell block of the session."""
    run = _loading_run(tmp_path, text=text, loading=loading)

    result = _covered(run, _config_features())

    assert SEVERITY_ROWS <= result, sorted(SEVERITY_ROWS - result)


def _discovery_order(tmp_path: Path, names) -> list[str]:
    """``names`` in the order config discovery ranks them, taken from discovery itself:
    each is written into a new directory and discover_config_source runs on it, so the
    order is the product's (config/config_sources.py), never restated here. The first
    is the one discovery picks when all of them are there. A pyproject.toml is written
    with a [tool.ash] table, without which it is no config source."""
    from automated_security_helper.config.config_sources import discover_config_source
    from automated_security_helper.core import constants

    directory = tmp_path / "discovery" / uuid.uuid4().hex
    for name in names:
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        text = "[tool.ash]\n" if name == constants.ASH_PYPROJECT_FILE_NAME else ""
        target.write_text(text, encoding="utf-8")
    found = discover_config_source(directory)
    assert found.selected is not None, names
    return [
        source.path.relative_to(directory).as_posix()
        for source in (found.selected, *found.ignored)
    ]


#: Configurations that each set one top-level row of their own, so the rows covered
#: show which saved configuration counted.
SETTING = {
    "config:project_name": {"project_name": "demo"},
    "config:fail_on_findings": {"fail_on_findings": False},
    "config:honor_ignore_files": {"honor_ignore_files": False},
}


def _saved_under(name: str, document: dict, *, kind: str = "") -> str:
    """A block that saves ``document``, a mapping of top-level scalars, as ``name``: in
    that file's language, as the [tool.ash] table of a pyproject.toml, and of the kind
    that file is unless ``kind`` names another."""
    from automated_security_helper.core import constants

    suffix = name.rpartition(".")[2]
    lang = {"yml": "yaml"}.get(suffix, suffix)
    pyproject = name.rpartition("/")[2] == constants.ASH_PYPROJECT_FILE_NAME
    if lang == "json":
        text = json.dumps(document)
    else:
        separator = " = " if lang == "toml" else ": "
        lines = [
            f"{key}{separator}{json.dumps(value)}" for key, value in document.items()
        ]
        text = "\n".join(["[tool.ash]", *lines] if pyproject else lines)
    kind = kind or ("kind=pyproject" if pyproject else "kind=ash")
    return _saved_config(text, kind=kind, save_as=name, lang=lang)


def _rival_run(
    tmp_path: Path, names: dict[str, str], steps, *, scan: str = "ash scan --offline"
) -> Run:
    """A page that saves, in order, the SETTING of each (role, row) step under the
    name ``names`` gives its role, and runs ``scan`` at the step "scan": the block
    that reached load_config_file."""
    blocks = [
        _scan_block(scan)
        if step == "scan"
        else _saved_under(names[step[0]], SETTING[step[1]])
        for step in steps
    ]
    return _loading_run(tmp_path, text=_join(*blocks))


#: Where the page saves the configuration discovery picks: before the other one, or
#: after it.
PICKED_FIRST = [
    pytest.param(True, id="the-one-it-picks-saved-first"),
    pytest.param(False, id="the-one-it-picks-saved-last"),
]


def _two_saves_and_the_scan(picked_first: bool) -> list:
    saves = [
        ("picked", "config:project_name"),
        ("outranked", "config:fail_on_findings"),
    ]
    return [*(saves if picked_first else saves[::-1]), "scan"]


@pytest.mark.parametrize("picked_first", PICKED_FIRST)
@pytest.mark.parametrize(
    "rank",
    [
        pytest.param(rank, id=f"discovery-ranks-{rank}-and-{rank + 1}")
        for rank in range(len(_discovered_names()))
    ],
)
def test_of_two_saved_configs_discovery_could_read_only_the_one_it_picks_counts(
    tmp_path, rank, picked_first
):
    """Discovery picks exactly one config source and never merges two
    (config/config_sources.py), so of two configurations saved under names it reads,
    the scan loaded one: the first in discovery's order, wherever the page saved it.
    Each pair is two names next to each other in that order, read from discovery over
    every name it reads, so every step of the order is held."""
    from automated_security_helper.core import constants

    every = [*_discovered_names(), constants.ASH_PYPROJECT_FILE_NAME]
    order = _discovery_order(tmp_path, every)
    assert sorted(order) == sorted(every), "discovery reads every one of these names"
    picked, outranked = _discovery_order(tmp_path, order[rank : rank + 2])
    run = _rival_run(
        tmp_path,
        {"picked": picked, "outranked": outranked},
        _two_saves_and_the_scan(picked_first),
    )

    result = _covered(run, _config_features())

    assert "config:project_name" in result, (picked, outranked)
    assert "config:fail_on_findings" not in result, (picked, outranked)


@pytest.mark.parametrize(
    ("steps", "covered", "uncovered"),
    [
        pytest.param(
            [
                ("picked", "config:project_name"),
                ("outranked", "config:fail_on_findings"),
                ("picked", "config:honor_ignore_files"),
                "scan",
            ],
            {"config:honor_ignore_files"},
            {"config:project_name", "config:fail_on_findings"},
            id="saved-again-after-the-one-it-outranks",
        ),
        pytest.param(
            [
                ("picked", "config:project_name"),
                ("picked", "config:honor_ignore_files"),
                ("outranked", "config:fail_on_findings"),
                "scan",
            ],
            {"config:honor_ignore_files"},
            {"config:project_name", "config:fail_on_findings"},
            id="saved-again-before-the-one-it-outranks",
        ),
        pytest.param(
            [
                ("picked", "config:project_name"),
                ("outranked", "config:fail_on_findings"),
                "scan",
                ("picked", "config:honor_ignore_files"),
            ],
            {"config:project_name"},
            {"config:fail_on_findings", "config:honor_ignore_files"},
            id="saved-again-only-after-the-block-that-loaded-it",
        ),
    ],
)
def test_the_config_discovery_picks_counts_by_its_latest_save_before_the_load(
    tmp_path, steps, covered, uncovered
):
    """A later save of the name discovery picks replaces the file the scan reads, so
    the replacing save's rows count and the replaced one's do not, and the name it
    outranks never counts. A save after the loading block replaced nothing that block
    read. The two names are the two that discovery ranks first, read from discovery."""
    picked, outranked = _discovery_order(tmp_path, _discovered_names())[:2]
    run = _rival_run(tmp_path, {"picked": picked, "outranked": outranked}, steps)

    result = _covered(run, _config_features())

    assert covered <= result, (sorted(covered - result), picked, outranked)
    assert not uncovered & result, (sorted(uncovered & result), picked, outranked)


def test_a_file_discovery_picks_hides_the_ones_it_outranks_even_when_it_never_counts(
    tmp_path,
):
    """Discovery reads files, not the kind a page gives a block: a fragment saved under
    the name it picks is the file the scan loads, so a full configuration saved under
    a name it ranks lower was never loaded. Neither counts, since a fragment never does
    (loaded on its own, its keys sit at the root, not under its at= prefix)."""
    picked, outranked = _discovery_order(tmp_path, _discovered_names())[:2]
    run = _loading_run(
        tmp_path,
        text=_join(
            _saved_under(picked, {"severity_threshold": "HIGH"}, kind=FRAGMENT_KIND),
            _saved_under(outranked, SETTING["config:project_name"]),
            _scan_block(),
        ),
    )

    result = _covered(run, _config_features())

    shown = (SEVERITY_ROWS | {"config:project_name"}) & result
    assert not shown, (sorted(shown), picked, outranked)


@pytest.mark.parametrize("picked_first", PICKED_FIRST)
def test_of_two_saved_configs_in_the_directory_source_dir_names_only_the_one_discovery_picks_counts(
    tmp_path, picked_first
):
    """Discovery ranks the names in the directory it searches, the one --source-dir
    names, as it ranks them in the working directory."""
    picked, outranked = _discovery_order(tmp_path, _discovered_names())[:2]
    run = _rival_run(
        tmp_path,
        {"picked": f"sub/{picked}", "outranked": f"sub/{outranked}"},
        _two_saves_and_the_scan(picked_first),
        scan="ash --source-dir sub --offline",
    )

    result = _covered(run, _config_features())

    assert "config:project_name" in result, (picked, outranked)
    assert "config:fail_on_findings" not in result, (picked, outranked)


@pytest.mark.parametrize(
    ("command_line", "anchor", "covered", "uncovered"),
    [
        pytest.param(
            "ash scan --config-overrides 'global_settings.severity_threshold=HIGH'",
            "apply_config_overrides",
            {"config:global_settings.severity_threshold", "config:global_settings"},
            {"config:fail_on_findings"},
            id="a-key-and-its-section",
        ),
        pytest.param(
            "ash scan --config-overrides='global_settings.severity_threshold=HIGH'",
            "apply_config_overrides",
            {"config:global_settings.severity_threshold"},
            set(),
            id="an-inline-value",
        ),
        pytest.param(
            "ash scan --config-overrides 'external_reports_to_include+=[\"extra.sarif\"]'",
            "apply_config_overrides",
            {"config:external_reports_to_include"},
            set(),
            id="an-append",
        ),
        pytest.param(
            "ash scan --config-overrides 'mcp_resource_management.max_concurrent_scans=2'",
            "apply_config_overrides",
            {"config:mcp-resource-management.max_concurrent_scans"},
            set(),
            id="a-field-name-where-the-row-has-an-alias",
        ),
        pytest.param(
            "ash scan --config-overrides 'global_settings.severity_threshold=HIGH'",
            "load_config_file",
            set(),
            {"config:global_settings.severity_threshold"},
            id="the-overrides-code-did-not-run",
        ),
        pytest.param(
            _overrides(
                'global_settings.ignore_paths+=[{"path": "app.py", '
                '"reason": "generated", "expires": "2020-01-01"}]'
            ),
            "apply_config_overrides",
            {
                "config:global_settings",
                "config:global_settings.ignore_paths",
                "config:global_settings.ignore_paths[].path",
                "config:global_settings.ignore_paths[].reason",
                "config:global_settings.ignore_paths[].expires",
            },
            {"config:global_settings.suppressions"},
            id="the-keys-of-mappings-appended-to-a-list",
        ),
        pytest.param(
            _overrides(
                'global_settings.ignore_paths+={"path": "build/", "reason": "generated"}'
            ),
            "apply_config_overrides",
            {
                "config:global_settings.ignore_paths[].path",
                "config:global_settings.ignore_paths[].reason",
            },
            {"config:global_settings.ignore_paths[].expires"},
            id="the-keys-of-one-mapping-appended-to-a-list",
        ),
        pytest.param(
            _overrides(
                'global_settings.suppressions=[{"rule_id": "B101", '
                '"path": "tests/**", "reason": "asserts in tests"}]'
            ),
            "apply_config_overrides",
            {
                "config:global_settings.suppressions",
                "config:global_settings.suppressions[].rule_id",
                "config:global_settings.suppressions[].path",
                "config:global_settings.suppressions[].reason",
            },
            {"config:global_settings.suppressions[].expires"},
            id="the-keys-of-mappings-that-replace-a-list",
        ),
        pytest.param(
            _overrides('global_settings={"severity_threshold": "HIGH"}'),
            "apply_config_overrides",
            {"config:global_settings", "config:global_settings.severity_threshold"},
            {"config:global_settings.ignore_paths"},
            id="the-keys-of-a-mapping-set-on-a-section",
        ),
        pytest.param(
            _overrides(
                'global_settings.suppressions+=[{"path": "app.py", "ruleId": "B101"}]'
            ),
            "apply_config_overrides",
            {
                "config:global_settings.suppressions",
                "config:global_settings.suppressions[].path",
            },
            {"config:global_settings.suppressions[].rule_id"},
            id="a-key-inside-the-value-that-names-no-row-sets-nothing",
        ),
        pytest.param(
            _overrides("global_settings={severity_threshold: HIGH}"),
            "apply_config_overrides",
            {"config:global_settings"},
            {"config:global_settings.severity_threshold"},
            id="a-value-that-does-not-parse-sets-only-its-key",
        ),
        pytest.param(
            _overrides(
                'global_settings.ignore_paths+=[{"path": "app.py", "reason": "x"}]'
            ),
            "load_config_file",
            set(),
            {
                "config:global_settings.ignore_paths",
                "config:global_settings.ignore_paths[].path",
            },
            id="keys-inside-a-value-the-overrides-code-never-read",
        ),
    ],
)
def test_a_config_override_covers_its_key_when_the_overrides_code_ran(
    tmp_path, command_line, anchor, covered, uncovered
):
    """An override's value sets keys too: it is parsed the way apply_config_overrides
    parses it (a JSON list or object, a bracketed list), and each key inside it is a
    row under the override's key, under its ``[]`` when the value is a list or the
    override appends to a list. A key that names no row sets nothing, and a value
    that does not parse sets only the key the override names."""
    run = Run(tmp_path)
    line = _one_command(run, command_line)
    run.record("page.md", _block("page.md", line))
    region = _anchor(anchor)
    run.hit(f"page.md::{line}", region.path, {min(region.lines)})

    result = _covered(run, _config_features())

    assert covered <= result, sorted(covered - result)
    assert not uncovered & result, sorted(uncovered & result)


SUPPRESS_FINDINGS = "docs/content/how-to/suppress-findings.md"


@pytest.mark.parametrize(
    ("needles", "covered", "uncovered"),
    [
        pytest.param(
            ("ignore_paths+=", '"expires"'),
            {
                "config:global_settings.ignore_paths",
                "config:global_settings.ignore_paths[].path",
                "config:global_settings.ignore_paths[].reason",
                "config:global_settings.ignore_paths[].expires",
            },
            {"config:global_settings.suppressions"},
            id="an-ignore-path-that-has-expired",
        ),
        pytest.param(
            ("suppressions+=", '"rule_id"', '"expires"'),
            {
                "config:global_settings.suppressions",
                "config:global_settings.suppressions[].path",
                "config:global_settings.suppressions[].rule_id",
                "config:global_settings.suppressions[].reason",
                "config:global_settings.suppressions[].expires",
            },
            {"config:global_settings.ignore_paths"},
            id="a-suppression-that-has-expired",
        ),
        pytest.param(
            ("suppressions+=", '"ruleId"'),
            {
                "config:global_settings.suppressions",
                "config:global_settings.suppressions[].path",
                "config:global_settings.suppressions[].reason",
            },
            {
                "config:global_settings.suppressions[].rule_id",
                "config:global_settings.suppressions[].expires",
            },
            id="a-suppression-whose-rule-key-is-misspelled",
        ),
    ],
)
def test_the_keys_suppress_findings_gives_inside_an_override_value_are_covered(
    tmp_path, needles, covered, uncovered
):
    """The page demonstrates suppressions and ignore paths end to end through
    --config-overrides, one run per entry, each expected to report the finding the
    entry no longer covers."""
    run = Run(tmp_path)
    block = _the_block(run.real_page(SUPPRESS_FINDINGS), *needles)
    run.record(
        SUPPRESS_FINDINGS,
        _block(SUPPRESS_FINDINGS, block.fence_line, expected=_expected_exit(block)),
    )
    region = _anchor("apply_config_overrides")
    run.hit(
        f"{SUPPRESS_FINDINGS}::{block.fence_line}", region.path, {min(region.lines)}
    )

    result = _covered(run, _config_features())

    assert covered <= result, sorted(covered - result)
    assert not uncovered & result, sorted(uncovered & result)


# --------------------------------------------------------------------------- #
# Presented, and the denominators
# --------------------------------------------------------------------------- #

PRESENTED = _join(
    '<!-- doctest: illustrative reason="needs AWS credentials, which a docs run '
    'does not have" -->\n'
    f"{FENCE}bash\nash scan --scanners bandit,checkov "
    f"--config-overrides 'global_settings.severity_threshold=HIGH'\n{FENCE}",
    f"{FENCE}yaml\nscanners:\n  semgrep:\n    enabled: true\n{FENCE}",
)


def test_a_feature_any_block_shows_is_presented_whether_or_not_it_ran(tmp_path):
    """Report only: a gap with a presented feature needs its example executed, a gap
    with none needs documentation first."""
    run = Run(tmp_path)
    run.page("presented.md", PRESENTED)
    (line,) = run.page("page.md", ONE_BLOCK)
    run.record("page.md", _block("page.md", line))
    run.hit(f"page.md::{line}", OTHER_PATH, {5})

    evaluation = _evaluate(run, _inventory())

    shown = {
        "command:ash scan",
        "option:ash scan --scanners",
        "option:ash scan --config-overrides",
        "scanner:bandit",
        "scanner:checkov",
        "scanner:semgrep",
        "config:global_settings.severity_threshold",
        "config:scanners.semgrep",
    }
    assert shown <= evaluation.presented, sorted(shown - evaluation.presented)
    assert not {"reporter:sarif", "option:ash scan --source-dir"} & evaluation.presented
    assert not shown & evaluation.covered


def test_the_denominators_count_what_the_measurement_read(tmp_path):
    """pages_selected counts the corpus pages the runner selects (a block to run or to
    save), so a selected page that left no record shows as a gap."""
    run = Run(tmp_path)
    first, second = run.page("run.md", TWO_BLOCKS)
    run.page("prose.md", "# Prose only\n\nNo block here.\n")
    run.page(
        "saved.md",
        f"<!-- doctest: save-as=settings.yaml -->\n{FENCE}yaml\nproject_name: x\n{FENCE}\n",
    )
    run.record("run.md", _block("run.md", first), _block("run.md", second, ok=False))
    run.hit(f"run.md::{first}", PLANTED_PATH, {11})
    run.hit(f"run.md::{second}", OTHER_PATH, {3})

    evaluation = _evaluate(run, [_planted()])

    assert dict(evaluation.denominators) == {
        "pages_recorded": 1,
        "pages_selected": 2,
        "blocks_run": 2,
        "blocks_passed": 1,
        "data_files": 2,
        "contexts": 2,
    }


# --------------------------------------------------------------------------- #
# The baseline and the gate
# --------------------------------------------------------------------------- #


def test_reading_a_baseline_returns_its_ids_and_skips_comments_and_blank_lines(
    tmp_path,
):
    path = tmp_path / "baseline.txt"
    path.write_text(
        "# This file may only shrink.\n#\n\ncommand:ash results trend\n"
        "config:global_settings\n",
        encoding="utf-8",
    )

    assert _cov().read_baseline(path) == [
        "command:ash results trend",
        "config:global_settings",
    ]


MALFORMED_BASELINES = [
    pytest.param("scanner:b\nscanner:a\n", id="unsorted"),
    pytest.param("scanner:a\nscanner:a\n", id="a-duplicate"),
    pytest.param("widget:planted\n", id="an-unknown-kind"),
    pytest.param("planted\n", id="no-kind"),
    pytest.param("scanner:\n", id="no-name"),
    pytest.param("scanner: planted\n", id="a-blank-after-the-kind"),
]


@pytest.mark.parametrize("text", MALFORMED_BASELINES)
def test_a_malformed_baseline_is_a_measurement_error(tmp_path, text):
    cov = _cov()
    path = tmp_path / "baseline.txt"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(cov.MeasurementError):
        cov.read_baseline(path)


def test_the_gate_classes_each_way_the_baseline_and_the_measurement_disagree():
    """F1 an uncovered feature the baseline lacks; F2 a line naming no feature; and,
    given the base branch's baseline, F3 a line for a covered feature and F4 a line
    the base branch's baseline lacks."""
    failures = _cov().gate_failures(
        feature_ids=["command:a", "command:b", "command:c", "scanner:d"],
        covered=["command:a", "scanner:d"],
        baseline=["command:c", "command:gone", "scanner:d"],
        base_baseline=["command:c", "scanner:d"],
    )

    assert failures == {
        "F1": ["command:b"],
        "F2": ["command:gone"],
        "F3": ["scanner:d"],
        "F4": ["command:gone"],
    }


def test_f3_and_f4_are_not_checked_without_a_base_baseline():
    """Without the base branch's baseline (a push, or the pull request that adds the
    file) a covered feature that is still listed is not a failure: the CI runner can
    reach code the measurement the file was written from did not. F1 and F2 still
    apply."""
    failures = _cov().gate_failures(
        feature_ids=["command:a", "command:b", "command:c"],
        covered=["command:a", "command:c"],
        baseline=["command:b", "command:c"],
        base_baseline=None,
    )

    assert failures == {"F1": [], "F2": [], "F3": [], "F4": []}


@pytest.mark.parametrize(
    ("covered", "baseline", "base", "failing"),
    [
        pytest.param(True, ["scanner:gone"], None, ("F2", ["scanner:gone"]), id="F2"),
        pytest.param(
            True,
            ["scanner:planted"],
            ["scanner:planted"],
            ("F3", ["scanner:planted"]),
            id="F3",
        ),
        pytest.param(
            False, ["scanner:planted"], [], ("F4", ["scanner:planted"]), id="F4"
        ),
    ],
)
def test_check_exits_1_on_each_baseline_failure_and_names_the_line(
    tmp_path, covered, baseline, base, failing
):
    run = Run(tmp_path)
    (line,) = run.page("page.md", ONE_BLOCK)
    run.record("page.md", _block("page.md", line))
    run.hit(f"page.md::{line}", PLANTED_PATH if covered else OTHER_PATH, {11})
    kwargs = {}
    if base is not None:
        kwargs["base_baseline"] = _baseline(tmp_path / "base.txt", base)

    assert _check(run, [_planted()], baseline, **kwargs) == 1
    name, ids = failing
    assert _report(run)["gate"]["failures"][name] == ids
    markdown = _markdown(run)
    assert name in markdown and all(i in markdown for i in ids)


def test_an_uncovered_feature_on_the_baseline_passes(tmp_path):
    run = Run(tmp_path)
    (line,) = run.page("page.md", ONE_BLOCK)
    run.record("page.md", _block("page.md", line))
    run.hit(f"page.md::{line}", OTHER_PATH, {5})

    assert _check(run, [_planted()], ["scanner:planted"]) == 0


def test_without_a_base_baseline_a_covered_listed_feature_is_a_warning_naming_the_line(
    tmp_path, capsys
):
    """The run passes, and says which line to delete: in the report's warnings, in
    the markdown section and in what it prints."""
    run, _line = _valid_run(tmp_path)
    planted = _planted()

    assert _check(run, [planted], [planted.id]) == 0

    gate = _report(run)["gate"]
    assert gate["exit_code"] == 0
    assert gate["failures"]["F3"] == []
    assert gate["warnings"] == {"F3": [planted.id]}
    assert planted.id in _markdown(run)
    printed = capsys.readouterr()
    assert planted.id in printed.out + printed.err


# --------------------------------------------------------------------------- #
# Exit 2: the measurement measured nothing, or does not fit the docs tree
# --------------------------------------------------------------------------- #


def _no_records(run: Run, line: int) -> None:
    run.hit(f"page.md::{line}", PLANTED_PATH, {11})


def _no_data_files(run: Run, line: int) -> None:
    run.record("page.md", _block("page.md", line))


def _no_passing_block(run: Run, line: int) -> None:
    run.record("page.md", _block("page.md", line, ok=False))
    run.hit(f"page.md::{line}", PLANTED_PATH, {11})


def _no_passing_context_in_the_data(run: Run, line: int) -> None:
    run.record("page.md", _block("page.md", line))
    run.hit("unattributed", PLANTED_PATH, {11})


def _a_recorded_page_the_docs_tree_lacks(run: Run, line: int) -> None:
    run.record("gone.md", _block("gone.md", 3))
    run.hit("gone.md::3", PLANTED_PATH, {11})


def _a_recorded_block_the_page_lacks(run: Run, line: int) -> None:
    run.record("page.md", _block("page.md", line + 40))
    run.hit(f"page.md::{line + 40}", PLANTED_PATH, {11})


def _a_recorded_block_without_its_expected_exit(run: Run, line: int) -> None:
    block = _block("page.md", line)
    del block["expected"]
    run.record("page.md", block)
    run.hit(f"page.md::{line}", PLANTED_PATH, {11})


@pytest.mark.parametrize(
    "breaks",
    [
        _no_records,
        _no_data_files,
        _no_passing_block,
        _no_passing_context_in_the_data,
        _a_recorded_page_the_docs_tree_lacks,
        _a_recorded_block_the_page_lacks,
        _a_recorded_block_without_its_expected_exit,
    ],
    ids=lambda breaks: breaks.__name__.strip("_").replace("_", "-"),
)
def test_a_measurement_that_measured_nothing_or_came_from_another_tree_exits_2(
    tmp_path, breaks
):
    """A zero must never read as a result: each of these is an error, not a pass and
    not a list of uncovered features. A record that does not say what its block
    expected cannot be judged, so it is not read as expecting success."""
    run = Run(tmp_path)
    (line,) = run.page("page.md", ONE_BLOCK)
    breaks(run, line)

    assert _check(run, [_planted()]) == 2


@pytest.mark.parametrize("damage", ["garbage", "truncated"])
def test_a_coverage_data_file_that_cannot_be_read_exits_2_naming_it(
    tmp_path, capsys, damage
):
    """coverage.py's combine skips a data file it cannot read and says so only to a
    warning callback, so the lines of a process killed while it saved its data (a
    truncated file) would drop out without a word, and the features only that
    process reached would read as uncovered: a flaky gate failure. Every data file
    must read, or the measurement cannot be trusted."""
    run, line = _valid_run(tmp_path)
    damaged = run.data / "data" / ".coverage.damaged.4242"
    if damage == "garbage":
        damaged.write_bytes(b"not a coverage data file\n" * 64)
    else:
        data = CoverageData(
            basename=str(run.data / "data" / ".coverage"), suffix="damaged.4242"
        )
        data.set_context(f"page.md::{line}")
        data.add_lines({run.measured(OTHER_PATH): [3]})
        data.write()
        data.close()
        damaged.write_bytes(damaged.read_bytes()[:1024])

    assert _check(run, [_planted()]) == 2
    assert damaged.name in capsys.readouterr().err


@pytest.mark.parametrize("text", MALFORMED_BASELINES)
def test_check_exits_2_on_a_malformed_baseline(tmp_path, text):
    run, _line = _valid_run(tmp_path)
    path = tmp_path / "malformed.txt"
    path.write_text(text, encoding="utf-8")

    assert (
        _cov().run_check(
            data=run.data,
            baseline=path,
            docs_root=run.docs,
            out=run.out,
            features=[_planted()],
            corpus=run.corpus,
        )
        == 2
    )


@pytest.mark.parametrize("which", ["baseline", "base_baseline"])
def test_check_exits_2_on_a_baseline_it_cannot_read(tmp_path, which):
    run, _line = _valid_run(tmp_path)
    kwargs = {
        "baseline": _baseline(tmp_path / "baseline.txt", []),
        "base_baseline": None,
    }
    kwargs[which] = tmp_path / "no-such-baseline.txt"

    assert (
        _cov().run_check(
            data=run.data,
            docs_root=run.docs,
            out=run.out,
            features=[_planted()],
            corpus=run.corpus,
            **kwargs,
        )
        == 2
    )


def test_check_exits_2_when_the_inventory_fails_closed(tmp_path, monkeypatch):
    cov = _cov()
    run, _line = _valid_run(tmp_path)

    def refuse():
        raise cov.InventoryError("a plugin module does not import")

    monkeypatch.setattr(cov, "inventory", refuse)

    assert issubclass(cov.InventoryError, cov.MeasurementError)
    assert (
        cov.run_check(
            data=run.data,
            baseline=_baseline(tmp_path / "baseline.txt", []),
            docs_root=run.docs,
            out=run.out,
            features=None,
            corpus=run.corpus,
        )
        == 2
    )


def test_main_exits_2_with_the_traceback_on_an_error_nothing_expected(
    tmp_path, monkeypatch, capsys
):
    """Python exits 1 on an uncaught exception, which is the gate-failure code; a
    bug or a recursion in the inventory is a measurement error, and says where."""
    cov = _cov()
    run, _line = _valid_run(tmp_path)

    def recurse():
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(cov, "inventory", recurse)
    monkeypatch.setattr(cov, "corpus_pages", lambda docs_root: list(run.corpus))

    code = cov.main(
        [
            "check",
            "--data",
            str(run.data),
            "--baseline",
            str(_baseline(tmp_path / "baseline.txt", [])),
            "--docs-root",
            str(run.docs),
            "--out",
            str(run.out),
        ]
    )

    assert code == 2
    printed = capsys.readouterr()
    assert "Traceback" in printed.err and "RecursionError" in printed.err


def test_report_and_write_baseline_exit_2_on_a_measurement_that_measured_nothing(
    tmp_path,
):
    cov = _cov()
    run = Run(tmp_path)
    (line,) = run.page("page.md", ONE_BLOCK)
    _no_data_files(run, line)

    assert (
        cov.run_report(
            data=run.data,
            docs_root=run.docs,
            out=run.out,
            features=[_planted()],
            corpus=run.corpus,
        )
        == 2
    )
    assert (
        cov.run_write_baseline(
            data=run.data,
            baseline=tmp_path / "written.txt",
            docs_root=run.docs,
            features=[_planted()],
            corpus=run.corpus,
        )
        == 2
    )
    assert not (tmp_path / "written.txt").exists()


# --------------------------------------------------------------------------- #
# What a run writes
# --------------------------------------------------------------------------- #


def _table_rows(markdown: str) -> list[list[str]]:
    rows = []
    for line in markdown.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if all(re.fullmatch(r":?-+:?", cell) for cell in cells):
            continue
        rows.append(cells)
    return rows


def test_check_writes_the_json_report_with_the_figure_denominators_and_failing_ids(
    tmp_path,
):
    run, features = _outputs_run(tmp_path)

    assert _check(run, features) == 1
    report = _report(run)

    assert report["schema"] == 1
    assert report["overall"] == {"covered": 1, "total": 2, "percent": 50.0}
    assert report["totals"]["scanner"] == {"covered": 1, "total": 1}
    assert report["totals"]["reporter"] == {"covered": 0, "total": 1}
    assert report["denominators"] == {
        "pages_recorded": 1,
        "pages_selected": 1,
        "blocks_run": 2,
        "blocks_passed": 1,
        "data_files": 2,
        "contexts": 2,
    }
    assert [entry["id"] for entry in report["features"]] == [
        "reporter:planted",
        "scanner:planted",
    ]
    covered, uncovered = report["features"][1], report["features"][0]
    assert covered == {
        "id": "scanner:planted",
        "kind": "scanner",
        "covered": True,
        "presented": False,
        "pages": ["page.md"],
        "location": f"{PLANTED_PATH}:9",
        "note": "",
    }
    assert uncovered["covered"] is False and uncovered["pages"] == []
    assert report["gate"]["exit_code"] == 1
    assert report["gate"]["failures"] == {
        "F1": ["reporter:planted"],
        "F2": [],
        "F3": [],
        "F4": [],
    }
    assert report["gate"]["warnings"] == {"F3": []}


def test_check_writes_the_markdown_section_with_the_figure_kinds_denominators_and_failures(
    tmp_path,
):
    run, features = _outputs_run(tmp_path)
    _check(run, features)

    markdown = _markdown(run)
    report = _report(run)

    figure = re.search(
        r"(\d+) of (\d+) features \((\d+(?:\.\d+)?)%\) reached by an executed docs "
        r"example",
        markdown,
    )
    assert figure, markdown
    assert figure.group(1, 2) == ("1", "2") and float(figure.group(3)) == 50.0
    rows = [row[:3] for row in _table_rows(markdown)]
    assert ["scanner", "1", "1"] in rows and ["reporter", "0", "1"] in rows, rows
    for name, value in report["denominators"].items():
        assert any(
            name in line and str(value) in line for line in markdown.splitlines()
        ), name
    assert "F1" in markdown and "reporter:planted" in markdown
    assert "presented" in markdown


def test_check_prints_the_figure_with_its_denominators(tmp_path, capsys):
    run, features = _outputs_run(tmp_path)
    _check(run, features)

    printed = capsys.readouterr().out

    assert "1 of 2 features" in printed
    assert all(name in printed for name in DENOMINATORS), printed


def test_the_markdown_lists_fifty_ids_per_failing_class_and_counts_the_rest(tmp_path):
    run = Run(tmp_path)
    (line,) = run.page("page.md", ONE_BLOCK)
    run.record("page.md", _block("page.md", line))
    run.hit(f"page.md::{line}", OTHER_PATH, {3})
    uncovered = [_planted(f"scanner:planted-{n:02d}") for n in range(51)]

    assert _check(run, uncovered) == 1

    markdown = _markdown(run)
    assert all(f"scanner:planted-{n:02d}" in markdown for n in range(50))
    assert "scanner:planted-50" not in markdown
    assert "1 more" in markdown
    assert len(_report(run)["gate"]["failures"]["F1"]) == 51


def test_check_appends_its_section_to_the_summary_file(tmp_path):
    run, features = _outputs_run(tmp_path)
    summary = tmp_path / "summary.md"
    summary.write_text("## An earlier step\n", encoding="utf-8")

    _check(run, features, summary=summary)

    text = summary.read_text(encoding="utf-8")
    assert text.startswith("## An earlier step\n")
    assert _markdown(run) in text


def test_check_writes_the_baseline_the_run_would_need(tmp_path):
    """A failing pull request downloads the corrected file instead of editing it."""
    run, features = _outputs_run(tmp_path)
    _check(run, features)

    written = run.out / BASELINE_OUT

    assert _cov().read_baseline(written) == ["reporter:planted"]
    assert RATCHET_SENTENCE in written.read_text(encoding="utf-8")


def test_report_writes_the_outputs_and_never_fails_the_gate(tmp_path):
    run, features = _outputs_run(tmp_path)

    assert (
        _cov().run_report(
            data=run.data,
            docs_root=run.docs,
            out=run.out,
            features=features,
            corpus=run.corpus,
        )
        == 0
    )
    report = _report(run)
    assert report["gate"] is None
    assert {entry["id"]: entry["covered"] for entry in report["features"]} == {
        "reporter:planted": False,
        "scanner:planted": True,
    }
    assert (run.out / REPORT_MD).is_file()


def test_write_baseline_records_the_uncovered_features_and_the_check_then_passes(
    tmp_path,
):
    cov = _cov()
    run, features = _outputs_run(tmp_path)
    path = tmp_path / "written-baseline.txt"

    assert (
        cov.run_write_baseline(
            data=run.data,
            baseline=path,
            docs_root=run.docs,
            features=features,
            corpus=run.corpus,
        )
        == 0
    )

    assert cov.read_baseline(path) == ["reporter:planted"]
    header = " ".join(
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith("#")
    )
    assert RATCHET_SENTENCE in header and "Never add a feature" in header
    assert (
        cov.run_check(
            data=run.data,
            baseline=path,
            docs_root=run.docs,
            out=run.out,
            features=features,
            corpus=run.corpus,
        )
        == 0
    )


def test_check_leaves_the_coverage_directory_as_it_was_and_reads_it_again_alike(
    tmp_path,
):
    """Combining keeps its inputs (coverage deletes them by default), so a second
    reading of the same run, or the upload after it, finds the same data."""
    run, features = _outputs_run(tmp_path)

    def snapshot() -> dict:
        return {
            path.relative_to(run.data).as_posix(): path.read_bytes()
            for path in sorted(run.data.rglob("*"))
            if path.is_file()
        }

    before = snapshot()
    assert _check(run, features) == 1
    first = _report(run)

    assert snapshot() == before
    assert _check(run, features) == 1
    assert _report(run) == first
    assert snapshot() == before


# --------------------------------------------------------------------------- #
# The command line, and the committed baseline
# --------------------------------------------------------------------------- #


def test_main_runs_the_check_from_its_command_line(tmp_path, monkeypatch):
    cov = _cov()
    run, _line = _valid_run(tmp_path)
    planted = _planted()
    monkeypatch.setattr(cov, "inventory", lambda: [planted])
    monkeypatch.setattr(cov, "corpus_pages", lambda docs_root: list(run.corpus))
    baseline = _baseline(tmp_path / "baseline.txt", [])

    code = cov.main(
        [
            "check",
            "--data",
            str(run.data),
            "--baseline",
            str(baseline),
            "--docs-root",
            str(run.docs),
            "--out",
            str(run.out),
        ]
    )

    assert code == 0
    assert [entry["id"] for entry in _report(run)["features"]] == [planted.id]


def test_the_default_baseline_is_the_file_beside_the_script(tmp_path, monkeypatch):
    """CI names no path under tests/integration/docs outside the examples step, so the
    baseline lives in scripts/ and check reads it when no --baseline is given."""
    cov = _cov()
    assert cov.DEFAULT_BASELINE == COMMITTED_BASELINE

    run = Run(tmp_path)
    (line,) = run.page("page.md", ONE_BLOCK)
    run.record("page.md", _block("page.md", line))
    run.hit(f"page.md::{line}", OTHER_PATH, {5})
    planted = _planted()
    monkeypatch.setattr(
        cov, "DEFAULT_BASELINE", _baseline(tmp_path / "default.txt", [planted.id])
    )
    monkeypatch.setattr(cov, "inventory", lambda: [planted])
    monkeypatch.setattr(cov, "corpus_pages", lambda docs_root: list(run.corpus))

    code = cov.main(
        [
            "check",
            "--data",
            str(run.data),
            "--docs-root",
            str(run.docs),
            "--out",
            str(run.out),
        ]
    )

    assert code == 0


def test_the_committed_baseline_is_sorted_unique_and_names_only_features():
    if not COMMITTED_BASELINE.is_file():
        pytest.skip(
            "scripts/docs_feature_coverage_baseline.txt does not exist yet: the first "
            "full docs examples run writes it (write-baseline), and this checks it once "
            "it is committed"
        )
    ids = _cov().read_baseline(COMMITTED_BASELINE)
    header = " ".join(
        line
        for line in COMMITTED_BASELINE.read_text(encoding="utf-8").splitlines()
        if line.startswith("#")
    )

    assert RATCHET_SENTENCE in header
    unknown = sorted(set(ids) - set(_by_id()))
    assert not unknown, (
        "the committed baseline names features the inventory does not have (renamed "
        f"or removed: delete their lines): {unknown}"
    )


# --------------------------------------------------------------------------- #
# The workflow: the check gets the base branch's baseline on a pull request
# --------------------------------------------------------------------------- #

CHECK_STEP = "Check the docs feature coverage"
BASE_STEP = "Read the base branch's docs feature coverage baseline"


def _docs_examples_step(name: str) -> dict:
    jobs = yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))["jobs"]
    (step,) = [
        step for step in jobs["docs-examples"]["steps"] if step.get("name") == name
    ]
    return step


def _base_baseline_file() -> str:
    """The file the base step writes the base branch's baseline into."""
    written = re.findall(r'>\s*"([^"]+)"', _docs_examples_step(BASE_STEP)["run"])
    assert len(written) == 1, written
    return written[0]


def _check_run() -> str:
    """The check step's script, its continuation lines joined."""
    return re.sub(r"\\\n", " ", _docs_examples_step(CHECK_STEP)["run"])


def test_the_check_step_reports_after_a_red_examples_step_and_only_a_cancel_skips_it():
    condition = re.sub(r"\s+", "", str(_docs_examples_step(CHECK_STEP).get("if", "")))

    assert condition == "${{!cancelled()}}", condition


def test_on_a_pull_request_and_in_the_merge_queue_the_check_gets_the_base_baseline():
    """Without the base branch's baseline the check applies neither F3 nor F4, and the
    baseline would stop being shrink-only. The base step runs on exactly these two
    events, and the check passes on the file that step writes."""
    condition = re.sub(r"\s+", "", str(_docs_examples_step(BASE_STEP).get("if", "")))
    base_file = _base_baseline_file()
    run = _check_run()
    (command,) = [
        line
        for line in run.splitlines()
        if "scripts/docs_feature_coverage.py check" in line
    ]
    passed = f'--base-baseline "{base_file}"'

    assert condition.startswith("${{!cancelled()&&("), condition
    assert set(re.findall(r"github\.event_name==['\"](\w+)['\"]", condition)) == {
        "pull_request",
        "merge_group",
    }, condition
    if passed not in command:
        arrays = re.findall(r'"\$\{(\w+)\[@\]\}"', command)
        assert any(f"{array}=({passed})" in run for array in arrays), (
            f"the check is not given {passed}: {command!r}"
        )


def test_a_base_baseline_that_lists_no_feature_still_reaches_the_check():
    """The base step writes the file only when the base branch has one, and a base
    baseline that lists no feature still means every listed line is new (F4) and
    every covered one is to delete (F3): the check is given the file when it exists,
    not only when it is not empty."""
    base_file = _base_baseline_file()

    tests = re.findall(
        r'\[\s+(-\w)\s+"' + re.escape(base_file) + r'"\s+\]', _check_run()
    )

    assert tests == ["-f"], tests
