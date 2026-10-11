# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No walk the test run performs may enter a per-run directory.

Why this file exists
--------------------
``tests/pytest-temp/<uuid>/`` is the tests' own scratch area, inside the
repository and gitignored, and the ``ash_temp_path`` fixture ``shutil.rmtree``s a
subtree of it on teardown. Under ``-n auto`` that teardown runs while other
workers are mid-walk, so any test that walks the repository root races it.

There are two distinct races, and that distinction is why this is a guard rather
than a third individual fix:

1. **Read after enumerate.** ``sorted(root.rglob("*.py"))`` is materialised in
   full, then each file is read. A file listed at the start can be gone by the
   time it is read. Fixed once, in ``test_project_isolation.py``, by filtering the
   walk's output.
2. **Scandir during descent.** ``rglob`` raises from *inside* its own traversal,
   before it yields anything, when a directory it listed is removed before it
   descends into it. Measured on macos-14 py3.11, in a different walker::

       _candidate_files -> REPO_ROOT.rglob("*")
         pathlib.py:397 _iterate_directories   (recursive)
         pathlib.py:386   with scandir(parent_path) as scandir_it:
         -> os.scandir(self)
         FileNotFoundError: .../tests/pytest-temp/<uuid>/test_output_dir

   No filter on the output can prevent that, because there is no output.

   Seen on one leg of a run whose other legs passed. An attempt to reproduce it
   by racing a real teardown failed to hit the window on 3.11 and 3.13. Measured
   since, deterministically: removing the directory at the moment ``rglob`` lists it, through an audit hook
   on ``os.scandir``, raises FileNotFoundError on 3.10 and 3.11, and on 3.12, 3.13
   and 3.14 the directory is skipped without an error. A newer interpreter still
   descends into the scratch tree and returns whatever is there, so the race is not
   gone there, only quieter. The fix is not scoped
   to an interpreter.

Fixing (1) does not fix (2). That is not a hypothetical: the first fix landed and
a second walker failed the same way three hours later, on a leg that had just been
added to the matrix. So the rule is structural -- walk with
``tests.utils.helpers.iter_repo_files``, which prunes ``dirnames`` in place so
``os.walk`` never descends into the scratch tree. Pruning removes the race;
filtering and exception-catching only narrow it.

Why this is an AST check and not a grep
---------------------------------------
A regex over source lines flags the traceback quoted above, which lives in a
docstring in ``helpers.py``. The cheapest way to make a text-matching guard green
is then to delete the explanation, which is precisely backwards -- the same
failure ``test_prose_about_the_hazard_is_not_counted_as_the_hazard`` documents in
``test_project_isolation.py``. Matching ``ast.Call`` nodes makes prose invisible
by construction, so the explanation can stay.

Two walks this guard could not see
----------------------------------
The first version matched ``REPO_ROOT.glob`` and ``REPO_ROOT.rglob`` by name, in
tests/ only. Two walks raced past it: one bound the root to ``REPO``, and two lived
in scripts the tests run on the real checkout (``collect_md_files`` in
scripts/verify_docs_freshness.py walked ``REPO_ROOT.rglob("*.md")``, and
``find_orphans`` in .github/scripts/check-snapshot-trailers.py walked
``(root / "tests").rglob`` with the root arriving as a parameter). So the sweep now
lives in ``tests.utils.walk_guard``, which evaluates what each walk's receiver is,
follows the scripts the tests load or run, and fails closed on a receiver it cannot
resolve. Its module docstring says exactly what it follows.

A receiver that only exists at run time (a path a call returns, an awaited result)
cannot be resolved, so the walk is flagged. Each such walk that is in fact safe is
named in ``_EXEMPT`` below by file, function and receiver, with the reason, and
``test_every_exemption_still_names_a_flagged_walk`` fails when an entry no longer
matches anything, so the list cannot rot into blanket permission.

It deliberately does not flag a walk of a subtree no per-run directory is under.
Walking ``automated_security_helper/`` or ``.github/`` is safe; there is nothing to
race.
"""

from __future__ import annotations

import importlib.util
import textwrap
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath
from types import ModuleType

import pytest

from automated_security_helper.utils.version_management import _load_toml
from tests.utils.helpers import (
    ASH_TEST_TEMP_ROOT,
    is_under_test_scratch,
    iter_repo_files,
)
from tests.utils.walk_guard import (
    PER_RUN_DIRS,
    Evaluator,
    InRepo,
    Private,
    Source,
    Sweep,
    node_modules_dirs,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = REPO_ROOT / "tests"

#: Walks the guard cannot resolve that are safe, by (file, function, receiver), with
#: the reason. Every entry must still name a flagged walk; see
#: test_every_exemption_still_names_a_flagged_walk.
_EXEMPT = {
    ("tests/utils/helpers.py", "iter_repo_files", "root"): (
        "The sanctioned walker: it removes the scratch tree from dirnames before "
        "os.walk descends. TestIterRepoFilesPrunesTheScratchTree covers it."
    ),
    (".github/scripts/check-snapshot-trailers.py", "_snapshot_dirs", "root / entry"): (
        "Walks only directories git reports as untracked and not ignored, pruning "
        "every directory git reports as ignored. "
        "TestScriptWalkersStayOutOfTheScratchTree removes a scratch directory at the "
        "moment the walk lists it and shows it is never entered."
    ),
    (".github/scripts/check-snapshot-trailers.py", "find_orphans", "entry"): (
        "One per-module directory inside a __snapshots__ directory that "
        "_snapshot_dirs returned, so never an ignored one."
    ),
    (
        "scripts/verify_multi_project_attribution.py",
        "find_scanner_error_logs",
        "scanner_dir",
    ): (
        "A fixed-depth pattern with no ** of its own; its one substitution is a "
        "scanner name taken from the scan's results, and it is applied to the "
        "scan's own output directory."
    ),
    ("tests/snapshot/mcp/test_snapshot_mcp_session_tools.py", "_files_under", "root"): (
        "The source an MCP session extracted, under the workspace root that the "
        "isolated_mcp_state fixture points at tmp_path."
    ),
    (
        "tests/unit/converters/test_converter_scanned_tree.py",
        "test_a_regular_archive_beside_a_symlinked_one_still_extracts",
        "extracted",
    ): (
        "What the converter extracted, under the work directory of "
        "test_plugin_context, which is inside this test's ash_temp_path."
    ),
    (
        "tests/unit/test_agent_plugin_ash_version.py",
        "test_every_version_files_path_exists",
        "REPO_ROOT",
    ): (
        "Globs commitizen's version_files entries, which are literal paths with "
        "no wildcard, so the glob resolves one path and never descends. "
        "test_the_version_files_exemption_is_still_sound asserts that."
    ),
    (
        "tests/unit/utils/test_cdk_nag_unevaluated_rule.py",
        "test_the_prefix_appears_verbatim_in_the_installed_distribution",
        "root",
    ): (
        "The installed cdk-nag distribution, found through importlib.util.find_spec; "
        "no test creates or removes anything in it."
    ),
}


@pytest.fixture(scope="module")
def sweep() -> Sweep:
    return Sweep.of_checkout()


@pytest.fixture(scope="module")
def offenders(sweep) -> dict:
    return sweep.offenders()


class TestNoWalkTheTestsRunEntersAPerRunDirectory:
    def test_the_sweep_reads_the_tests_and_the_scripts_they_reach(self, sweep):
        """Anti-vacuity: an empty sweep would make every assertion below pass."""
        names = {source.rel.name for source in sweep.tests}
        assert len(sweep.tests) > 500, f"only {len(sweep.tests)} test modules read"
        assert {"test_project_isolation.py", "helpers.py", "conftest.py"} <= names
        reached = {rel.as_posix(): reach.called for rel, reach in sweep.reached.items()}
        assert "collect_md_files" in reached["scripts/verify_docs_freshness.py"]
        assert "find_orphans" in reached[".github/scripts/check-snapshot-trailers.py"]
        assert sum(1 for _ in sweep.walks()) > 50, "the sweep found almost no walks"

    def test_no_walk_the_tests_run_can_enter_a_per_run_directory(self, offenders):
        unexempted = {
            key: lines for key, lines in offenders.items() if key not in _EXEMPT
        }
        assert unexempted == {}, (
            "these walks can enter a per-run directory (tests/pytest-temp, which "
            "other xdist workers create and remove, .ash/ash_output, .venv, "
            "node_modules), or walk something the guard cannot resolve. List files "
            "with git ls-files, or walk with tests.utils.helpers.iter_repo_files, "
            "which never enters the scratch tree. A receiver that only exists at run "
            "time and is safe goes in _EXEMPT with the reason:\n"
            + "\n".join(line for lines in unexempted.values() for line in lines)
        )

    def test_every_exemption_still_names_a_flagged_walk(self, offenders):
        """An exemption that matches nothing is either stale or misspelled."""
        stale = sorted(set(_EXEMPT) - set(offenders))
        assert stale == [], f"remove these from _EXEMPT: {stale}"

    def test_the_version_files_exemption_is_still_sound(self):
        """The one exemption holds only while no entry carries a wildcard.

        ``REPO_ROOT.glob("a/b.md")`` resolves one path. ``REPO_ROOT.glob("**/b.md")``
        walks the whole tree and would race exactly like the rest. So the exemption
        is conditional, and this is the condition.

        Read through the package's own ``_load_toml`` rather than ``tomllib``.
        ``tomllib`` is standard library only from 3.11 while ``requires-python``
        floors at 3.10, and a module-level ``import tomllib`` took out this whole
        file -- and therefore the guard itself -- on all three 3.10 legs.
        """
        settings = _load_toml(REPO_ROOT / "pyproject.toml")["tool"]["commitizen"]

        entries = settings["version_files"]
        assert entries, "version_files is empty, so the exemption guards nothing"
        wildcarded = [entry for entry in entries if "*" in entry or "?" in entry]
        assert wildcarded == [], (
            "a version_files entry now carries a wildcard, so "
            "test_every_version_files_path_exists globs recursively and races the "
            "scratch tree. Either drop the wildcard or convert that test to "
            "iter_repo_files and remove its exemption here: " + repr(wildcarded)
        )


def _source(rel: str, text: str) -> Source:
    return Source(PurePosixPath(rel), textwrap.dedent(text))


def _values(expression: str, bindings: str = "", rel: str = "tests/unit/test_x.py"):
    """What ``expression`` evaluates to after ``bindings``, in a synthetic module."""
    source = _source(rel, textwrap.dedent(bindings) + f"\n_PROBE = {expression}\n")
    return Evaluator([source]).lookup("_PROBE", source, None)


_PER_RUN = tuple(PurePosixPath(d) for d in PER_RUN_DIRS)


def _flagged(*sources: Source, scripts: tuple = ()) -> dict:
    """``(function, receiver)`` -> reasons, for a synthetic tree."""
    found = Sweep(sources, scripts).offenders(_PER_RUN)
    return {(fn, receiver): lines for (_, fn, receiver), lines in found.items()}


class TestTheEvaluator:
    """What a receiver can be, read from the AST; nothing is imported or run."""

    def test_path_arithmetic_on_the_file_resolves_to_the_checkout(self):
        assert _values("Path(__file__).resolve().parents[2]") == {
            InRepo(PurePosixPath("."))
        }
        assert _values("Path(__file__).parent.parent") == {
            InRepo(PurePosixPath("tests"))
        }
        assert _values(
            "ROOT / 'tests' / 'unit'", "ROOT = Path(__file__).parents[2]"
        ) == {InRepo(PurePosixPath("tests/unit"))}
        assert _values("Path(f'{ROOT}/docs')", "ROOT = Path(__file__).parents[2]") == {
            InRepo(PurePosixPath("docs"))
        }

    def test_private_directories_are_recognized(self):
        source = """
            def f(tmp_path, tmp_path_factory, ash_temp_path):
                a = tmp_path / "x"
                b = tmp_path_factory.mktemp("y")
                c = Path(f"{ash_temp_path}/z")
                d = Path.home() / ".cache"
                return a, b, c, d
        """
        module = _source("tests/unit/test_x.py", source)
        evaluator = Evaluator([module])
        func = module.functions["f"][0]
        for name in "abcd":
            values = evaluator.lookup(name, module, func)
            assert values and all(isinstance(v, Private) for v in values), (
                name,
                values,
            )

    def test_loops_tuples_dicts_and_constructor_keywords_are_followed(self):
        bindings = """
            ROOT = Path(__file__).parents[2]
            DIRS = (ROOT / ".github", ROOT / "scripts")
            BY_NAME = {"a": ROOT / "docs"}
            context = PluginContext(output_dir=ROOT / "out")
        """
        assert _values(
            "LAST", textwrap.dedent(bindings) + "for d in DIRS:\n    LAST = d\n"
        ) == {
            InRepo(PurePosixPath(".github")),
            InRepo(PurePosixPath("scripts")),
        }
        assert _values("BY_NAME['a']", bindings) == {InRepo(PurePosixPath("docs"))}
        assert _values("context.output_dir", bindings) == {InRepo(PurePosixPath("out"))}

    def test_the_working_directory_is_the_checkout(self):
        """pytest runs from the repository root, so a walk of the cwd walks it."""
        root = {InRepo(PurePosixPath("."))}
        assert _values("Path.cwd()") == root
        assert _values("os.getcwd()", "import os") == root
        assert _values("Path('tests')") == {InRepo(PurePosixPath("tests"))}

    def test_anything_else_is_unknown_and_nothing_is_executed(self):
        for expression in (
            "__import__('subprocess').run(['false'])",
            "open('/etc/passwd').read()",
            "Path(__file__).with_name('x')",
            "UNBOUND / 'tests'",
            "Path(__file__).parents[UNBOUND]",
        ):
            values = _values(expression)
            assert values and not any(
                isinstance(v, (InRepo, Private)) for v in values
            ), (
                expression,
                values,
            )


class TestTheDetector:
    """Synthetic trees: what is flagged, and what is not."""

    def test_walks_of_a_tree_holding_the_scratch_directory_are_flagged(self):
        test = _source(
            "tests/unit/test_x.py",
            """
            import ast, os, shutil
            from pathlib import Path
            REPO = Path(__file__).resolve().parents[2]
            REPO_ROOT = Path(__file__).resolve().parents[2]
            TESTS = REPO / "tests"
            PKG = REPO / "automated_security_helper"

            def a(): return REPO.rglob("*.yml")
            def b(): return TESTS.rglob("*.py")
            def c(): return list(os.walk(REPO))
            def d(dst): shutil.copytree(REPO, dst)
            def e(): return REPO.glob("**/x.yml")
            def f(): return PKG.rglob("*.py")
            def g(): return REPO.glob("*.yml")
            def h(): return REPO.glob(".github/**/*.yml")
            def i(tmp_path): return tmp_path.rglob("*")
            def j(ash_temp_path): return ash_temp_path.rglob("*")
            def k(tree): return ast.walk(tree)
            def m(where): return where.rglob("*")
            def n(): return _helper(REPO)
            def o(tmp_path): return _helper(tmp_path)
            def _helper(root): return list(root.rglob("*"))
            def p(): return REPO_ROOT.rglob("*")
            """,
        )
        flagged = _flagged(test)
        assert set(flagged) == {
            ("a", "REPO"),
            ("b", "TESTS"),
            ("c", "REPO"),
            ("d", "REPO"),
            ("e", "REPO"),
            ("m", "where"),
            ("_helper", "root"),
            ("p", "REPO_ROOT"),
        }, flagged
        assert "holds tests/pytest-temp/" in flagged[("b", "TESTS")][0]
        assert "cannot be resolved" in flagged[("m", "where")][0]

    def test_a_script_walk_is_flagged_only_when_a_test_runs_it_on_the_checkout(self):
        """The two shapes the first guard missed, in scripts the tests load."""
        docs = _source(
            "scripts/docs_gate.py",
            """
            from pathlib import Path
            REPO_ROOT = Path(__file__).resolve().parent.parent
            def collect_md_files():
                return sorted(REPO_ROOT.rglob("*.md"))
            def never_called():
                return sorted(REPO_ROOT.rglob("*.txt"))
            """,
        )
        orphans = _source(
            ".github/scripts/orphans.py",
            """
            def find_orphans(root):
                return sorted((root / "tests").rglob("__snapshots__"))
            """,
        )
        on_checkout = _source(
            "tests/unit/test_on_checkout.py",
            """
            import importlib.util
            from pathlib import Path
            REPO_ROOT = Path(__file__).resolve().parents[2]

            def gate():
                spec = importlib.util.spec_from_file_location(
                    "g", REPO_ROOT / "scripts" / "docs_gate.py"
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return module

            def trailers():
                spec = importlib.util.spec_from_file_location(
                    "t", REPO_ROOT / ".github/scripts/orphans.py"
                )
                return importlib.util.module_from_spec(spec)

            def test_docs(gate):
                assert gate.collect_md_files()

            def test_orphans(trailers):
                assert trailers.find_orphans(REPO_ROOT) == []
            """,
        )
        flagged = _flagged(on_checkout, scripts=(docs, orphans))
        assert set(flagged) == {
            ("collect_md_files", "REPO_ROOT"),
            ("find_orphans", "root / 'tests'"),
        }, flagged

        on_tmp_only = _source(
            "tests/unit/test_on_tmp.py",
            textwrap.dedent(
                """
                import importlib.util
                from pathlib import Path
                REPO_ROOT = Path(__file__).resolve().parents[2]

                def trailers():
                    spec = importlib.util.spec_from_file_location(
                        "t", REPO_ROOT / ".github/scripts/orphans.py"
                    )
                    return importlib.util.module_from_spec(spec)

                def test_orphans(trailers, tmp_path):
                    assert trailers.find_orphans(tmp_path) == []
                """
            ),
        )
        assert _flagged(on_tmp_only, scripts=(docs, orphans)) == {}

    def test_node_modules_is_per_run_only_beside_a_package_json_outside_tests(self):
        """npm installs beside a project's package.json; a fixture's is test data."""
        found = node_modules_dirs(
            [
                "package.json",
                "deploy/cdk/package.json",
                "tests/test_data/scanners/guarddog/fixture_repo/npm_clean/package.json",
                "docs/not-a-package.json",
            ]
        )
        assert found == {
            PurePosixPath("node_modules"),
            PurePosixPath("deploy/cdk/node_modules"),
        }

    def test_prose_about_the_hazard_is_not_counted_as_the_hazard(self):
        """``helpers.py`` quotes the traceback; an AST check must not see it.

        Stated as a test because a future maintainer hitting a false positive here
        would reasonably reach for the delete key on the explanation, and the
        explanation is the most useful thing in that module.
        """
        helpers = (TESTS_ROOT / "utils" / "helpers.py").read_text(encoding="utf-8")
        assert "REPO_ROOT.rglob" in helpers, (
            "helpers.py no longer quotes the traceback, so this test is checking "
            "nothing about how the detector treats prose"
        )
        flagged = _flagged(_source("tests/utils/helpers.py", helpers))
        assert set(flagged) == {("iter_repo_files", "root")}, flagged


class TestIterRepoFilesPrunesTheScratchTree:
    """The helper's own behavior, since five call sites now depend on it."""

    def test_a_scratch_file_is_not_yielded(self, ash_temp_path):
        planted = ash_temp_path / "planted_probe.py"
        planted.write_text("x = 1\n", encoding="utf-8")

        assert planted.exists(), "the fixture did not write the probe"
        yielded = {p.resolve() for p in iter_repo_files(REPO_ROOT)}
        assert planted.resolve() not in yielded

    def test_it_yields_real_source(self):
        """The companion: pruning must not have emptied the walk."""
        yielded = {p.name for p in iter_repo_files(REPO_ROOT)}
        assert "pyproject.toml" in yielded
        assert "helpers.py" in yielded

    def test_prune_scratch_false_does_yield_the_scratch_file(self, ash_temp_path):
        """The opt-out has to opt out, or the control that uses it proves nothing."""
        planted = ash_temp_path / "planted_probe.py"
        planted.write_text("x = 1\n", encoding="utf-8")

        yielded = {p.resolve() for p in iter_repo_files(REPO_ROOT, prune_scratch=False)}
        assert planted.resolve() in yielded

    def test_skip_dirs_is_honored(self):
        yielded = set(iter_repo_files(REPO_ROOT, skip_dirs=frozenset({"tests"})))
        assert not any("tests" in p.relative_to(REPO_ROOT).parts for p in yielded)
        assert yielded, "skipping tests/ emptied the whole walk"

    def test_a_vanishing_path_outside_the_scratch_tree_is_not_silently_skipped(
        self, tmp_path
    ):
        """The tolerance must be narrow, or blindness reads as cleanliness.

        ``os.walk`` ignores errors by default. If ``iter_repo_files`` inherited
        that, a walk that failed for any reason would return a short list and every
        sweep built on it would report a clean repository. Only the scratch tree is
        silently skipped; this pins that a path outside it is not classified as
        scratch, which is what routes it to the re-raising branch.
        """
        outside = tmp_path / "not-scratch"
        outside.mkdir()

        assert not is_under_test_scratch(outside)
        assert is_under_test_scratch(ASH_TEST_TEMP_ROOT / "whatever")

    def test_the_scratch_root_is_inside_the_repository(self):
        """If it were not, pruning it would be a no-op and this is all theatre."""
        assert ASH_TEST_TEMP_ROOT.resolve().is_relative_to(REPO_ROOT.resolve())


#: Walkers outside tests/ that tests run against the real checkout. The AST sweep
#: above reads tests/ only, so it cannot see them.
_SCRIPT_WALKERS = {
    "docs-corpus": REPO_ROOT / "scripts" / "verify_docs_freshness.py",
    "snapshot-orphans": REPO_ROOT
    / ".github"
    / "scripts"
    / "check-snapshot-trailers.py",
}


def _load_script(which: str) -> ModuleType:
    path = _SCRIPT_WALKERS[which]
    name = f"_walker_under_test_{which.replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    # check-snapshot-trailers declares dataclasses, which resolve through sys.modules.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _run_walker(which: str) -> list[str]:
    """The walker's output as strings: collected files, or orphan problems."""
    module = _load_script(which)
    if which == "docs-corpus":
        return [str(path) for path in module.collect_md_files()]
    return list(module.find_orphans(REPO_ROOT))


def _plant(scratch: Path) -> Path:
    """A directory in the scratch tree holding what each walker would pick up."""
    planted = scratch / "planted"
    (planted / "inner" / "__snapshots__").mkdir(parents=True)
    (planted / "inner" / "planted_probe.md").write_text("# probe\n", encoding="utf-8")
    return planted


# Runs in a child interpreter, because an audit hook cannot be removed and a test
# worker should not keep one. The hook watches every directory listing. The first
# listing of the planted directory, or of anything under it, removes the planted
# directory before the listing proceeds: what another worker's ash_temp_path teardown
# does mid-walk, made deterministic. ``entered`` records every such listing.
_MID_WALK_REMOVAL = r"""
import importlib.util, json, os, shutil, sys
from pathlib import Path

repo, planted, script, which = sys.argv[1:5]
planted = os.path.realpath(planted)
sys.path.insert(0, repo)
state = {"armed": False, "entered": [], "removed": False}


def hook(event, args):
    if not state["armed"] or event not in ("os.scandir", "os.listdir"):
        return
    target = args[0] if args else None
    if target is None or isinstance(target, int):
        return
    path = os.path.realpath(os.fsdecode(target))
    if path != planted and not path.startswith(planted + os.sep):
        return
    state["entered"].append(path)
    if not state["removed"]:
        state["removed"] = True
        state["armed"] = False
        shutil.rmtree(planted)
        state["armed"] = True


sys.addaudithook(hook)
spec = importlib.util.spec_from_file_location("walker", script)
module = importlib.util.module_from_spec(spec)
sys.modules["walker"] = module
spec.loader.exec_module(module)
state["armed"] = True
try:
    if which == "docs-corpus":
        result = [str(p) for p in module.collect_md_files()]
    else:
        result = list(module.find_orphans(Path(repo)))
    error = None
except Exception as exc:
    result, error = None, f"{type(exc).__name__}: {exc}"
state["armed"] = False
print(json.dumps({"error": error, "entered": state["entered"],
                  "removed": state["removed"],
                  "returned": None if result is None else len(result)}))
"""


@pytest.mark.parametrize("which", sorted(_SCRIPT_WALKERS))
class TestScriptWalkersStayOutOfTheScratchTree:
    """Two walkers in scripts that tests run on the real checkout, under xdist.

    ``scripts/verify_docs_freshness.py``'s ``collect_md_files`` walked
    ``REPO_ROOT.rglob("*.md")``, and ``test_docs_freshness_gate_can_fail`` runs it.
    ``.github/scripts/check-snapshot-trailers.py``'s ``find_orphans`` walked
    ``(root / "tests").rglob("__snapshots__")``, and ``test_snapshot_policy`` runs it
    on the repository. Both descended into ``tests/pytest-temp`` while other workers
    created and removed directories there: the scandir-during-descent race described
    at the top of this file, from code the AST sweep does not read.

    Each walker now takes its file list from git, which does not enter an ignored
    directory, and the scratch tree is ignored. The first test shows nothing in the
    scratch tree reaches a walker's output; the second removes a scratch directory at
    the moment a walker lists it and shows the walker never got there.
    """

    def test_nothing_in_the_scratch_tree_reaches_the_output(self, which, ash_temp_path):
        planted = _plant(ash_temp_path)

        output = _run_walker(which)

        assert planted.exists(), "the walker removed the planted directory"
        leaked = [entry for entry in output if "pytest-temp" in entry]
        assert leaked == [], f"{which} read the scratch tree: {leaked}"

    def test_a_scratch_directory_removed_mid_walk_is_never_entered(
        self, which, ash_temp_path
    ):
        planted = _plant(ash_temp_path)

        child = subprocess.run(
            [
                sys.executable,
                "-c",
                _MID_WALK_REMOVAL,
                str(REPO_ROOT),
                str(planted),
                str(_SCRIPT_WALKERS[which]),
                which,
            ],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=REPO_ROOT,
        )
        assert child.returncode == 0, child.stdout + child.stderr
        report = json.loads(child.stdout.strip().splitlines()[-1])

        assert report["error"] is None, (
            f"{which} raised when a scratch directory vanished mid-walk: "
            f"{report['error']}"
        )
        assert report["entered"] == [], (
            f"{which} listed a scratch directory, so it races any worker removing "
            f"one: {report['entered']}"
        )
        assert report["returned"] is not None
        if which == "docs-corpus":
            assert report["returned"] > 100, "the corpus came back nearly empty"
        assert planted.exists()


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
