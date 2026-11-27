"""The hand matrix expanders scripts/_ci_matrix.py does not read yet, held against it.

Three places expand a workflow matrix by hand: ``_effective_cells`` in
tests/unit/test_pre_commit_hooks_manifest.py, ``matrix_entries`` in
tests/integration/docs/ci_runners/reports.py and the overlay check in
tests/unit/test_unit_test_shards.py. Verbatim copies of each are compared with the
reader, and with the adapter each place is re-pointed to, over every workflow in
.github/workflows on every event, with controls that show the comparison can fail.
"""

from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
READER = REPO_ROOT / "scripts" / "_ci_matrix.py"


def _load_ci_matrix() -> Any:
    """scripts/_ci_matrix.py, loaded by path: scripts/ is not a package."""
    name = "_ash_ci_matrix"
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, READER)
        assert spec and spec.loader, f"cannot load {READER}"
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


ci = _load_ci_matrix()

#: The events on which the pull-request overlay is void. Each of the three expanders
#: compared an overlay entry as text, which never matches a cell, so each read the
#: matrix as one of these events does.
STATIC_EVENTS = ("push", "merge_group", "workflow_dispatch")
STATIC_EVENT = "workflow_dispatch"


# ---------------------------------------------------------------------------
# The three expanders as they were, verbatim.
# ---------------------------------------------------------------------------


def _old_effective_cells(job, method):
    """tests/unit/test_pre_commit_hooks_manifest.py _effective_cells."""
    matrix = job["strategy"]["matrix"]
    excludes = matrix.get("exclude") or []
    cells = set()
    for os_name in matrix["os"]:
        for python in matrix["python-version"]:
            cell = {"os": os_name, "python-version": python, "method": method}
            if not any(all(cell.get(k) == v for k, v in ex.items()) for ex in excludes):
                cells.add((os_name, python))
    return cells


def _old_matrix_entries(matrix):
    """tests/integration/docs/ci_runners/reports.py matrix_entries."""
    keys = [key for key in matrix if key not in ("include", "exclude")]
    for key in keys:
        if not isinstance(matrix[key], list):
            raise ValueError(
                f"matrix key {key} is {matrix[key]!r}, not a list; its runs cannot be "
                "counted before the run"
            )
    runs = [{}] if keys else []
    for key in keys:
        runs = [{**run, key: value} for run in runs for value in matrix[key]]
    for name in ("exclude", "include"):
        if not isinstance(matrix.get(name) or [], list):
            raise ValueError(f"matrix {name} is {matrix[name]!r}, not a list")
    for exclude in matrix.get("exclude") or []:
        runs = [
            run
            for run in runs
            if not all(run.get(key) == value for key, value in exclude.items())
        ]
    for include in matrix.get("include") or []:
        matched = False
        for run in runs:
            if all(run[key] == value for key, value in include.items() if key in keys):
                run.update({k: v for k, v in include.items() if k not in keys})
                matched = True
        if not matched:
            runs.append(dict(include))
    return runs


_OLD_COVER_PREFIX = "${{ github.event_name == 'pull_request' && '"
_OLD_COVER_SUFFIX = "' || '' }}"


def _old_is_cover(value):
    """tests/unit/test_unit_test_shards.py _assert_only_the_pull_request_cover."""
    return (
        isinstance(value, str)
        and value.startswith(_OLD_COVER_PREFIX)
        and value.endswith(_OLD_COVER_SUFFIX)
    )


# ---------------------------------------------------------------------------
# What each place is re-pointed to, written out here so the comparison holds the
# adapter and not only the reader.
# ---------------------------------------------------------------------------


def _adapted_cells(matrix, method, event):
    """_effective_cells over the reader: the axes' product less the excludes."""
    legs = ci.axis_cells(matrix, event)
    return {
        (leg["os"], leg["python-version"])
        for leg in legs
        if leg.get("method") == method
    }


def _adapted_entries(matrix, event=STATIC_EVENT):
    """matrix_entries over the reader: the cells of a job that holds only the matrix."""
    return ci.cells({"strategy": {"matrix": matrix}}, event)


def _adapted_is_cover(value):
    """The cover check over the reader's one definition of the overlay."""
    return isinstance(value, str) and bool(ci.PULL_REQUEST_OVERLAY.match(value))


def _overlay(value):
    return "${{ github.event_name == 'pull_request' && '" + value + "' || '' }}"


def _workflow(name):
    """The workflow as the old expanders read it (yaml.safe_load) and as the reader."""
    path = WORKFLOWS / name
    return yaml.safe_load(path.read_text(encoding="utf-8")), ci.load_workflow(path)


def _matrix_of(job):
    return (job.get("strategy") or {}).get("matrix") or {}


def _shown(name):
    """A name as the report shows it. The suite's output redaction masks any twelve
    characters of the running test's id wherever they are printed, so the dashes and
    the extension of a workflow name, which the id holds, would print as <value>."""
    return name.replace(".yml", "").replace("-", " ")


ALL_WORKFLOWS = sorted(WORKFLOWS.glob("*.yml"))

# ---------------------------------------------------------------------------
# tests/unit/test_pre_commit_hooks_manifest.py: _effective_cells
# ---------------------------------------------------------------------------

SURFACES = (
    ("ash-unified-ci.yml", "install-validation"),
    ("ash-install-methods.yml", "validate"),
)


@pytest.mark.parametrize("name, job_id", SURFACES)
def test_the_effective_cells_equal_the_old_ones_on_every_event_the_cover_is_void_on(
    name, job_id, record_property
):
    old, new = _workflow(name)
    matrix = new["jobs"][job_id]["strategy"]["matrix"]
    methods = matrix["method"]
    assert len(methods) >= 5, methods
    for event in STATIC_EVENTS:
        per_method = {}
        for method in methods:
            before = _old_effective_cells(old["jobs"][job_id], method)
            after = _adapted_cells(matrix, method, event)
            assert before == after, (name, job_id, event, method)
            per_method[method] = len(before)
        record_property(
            "counts",
            f"site1 {_shown(name)} {_shown(job_id)} {event}: "
            f"methods={len(methods)} cells={sum(per_method.values())} {per_method}",
        )


@pytest.mark.parametrize("name, job_id", SURFACES)
def test_a_pull_request_reads_fewer_cells_than_the_old_expander_did(
    name, job_id, record_property
):
    """The event matters: the cover takes cells off a pull request and nowhere else."""
    old, new = _workflow(name)
    matrix = new["jobs"][job_id]["strategy"]["matrix"]
    static = pull_request = 0
    for method in matrix["method"]:
        before = _old_effective_cells(old["jobs"][job_id], method)
        after = _adapted_cells(matrix, method, "pull_request")
        assert after <= before, (name, job_id, method)
        static += len(before)
        pull_request += len(after)
    assert pull_request < static, (static, pull_request)
    record_property(
        "counts",
        f"site1 {_shown(name)} {_shown(job_id)} pull_request: "
        f"cells={pull_request} (the old expander read {static})",
    )


def test_the_effective_cells_comparison_can_fail():
    """Controls: equality above is a finding about these workflows, not a property of
    the comparison."""
    old, new = _workflow("ash-install-methods.yml")
    matrix = new["jobs"]["validate"]["strategy"]["matrix"]
    before = _old_effective_cells(old["jobs"]["validate"], "pre-commit")
    after = _adapted_cells(matrix, "pre-commit", STATIC_EVENT)
    assert before == after
    assert len(before) >= 10, before
    # A dropped cell is a difference.
    assert before != after - {sorted(after)[0]}
    # So is the cover: a pull request has no ubuntu-latest or macos-latest hook cell.
    on_pull_request = _adapted_cells(matrix, "pre-commit", "pull_request")
    assert before != on_pull_request
    assert {("ubuntu-latest", "3.12"), ("macos-latest", "3.12")} <= before
    assert not {("ubuntu-latest", "3.12"), ("macos-latest", "3.12")} & on_pull_request


# ---------------------------------------------------------------------------
# tests/integration/docs/ci_runners/reports.py: matrix_entries
# ---------------------------------------------------------------------------


def _includes_only(matrix):
    """A matrix with no axis and several includes. GitHub adds an include to the
    original combinations only (a combination an earlier include created is not one),
    and such a matrix has none, so each include is a run of its own."""
    axes = [key for key in matrix if key not in ("include", "exclude")]
    return not axes and len(matrix.get("include") or []) > 1


@pytest.mark.parametrize("path", ALL_WORKFLOWS, ids=lambda path: path.name)
def test_the_matrix_entries_equal_the_old_ones_but_for_the_include_only_matrices(
    path, record_property
):
    old = yaml.safe_load(path.read_text(encoding="utf-8"))
    new = ci.load_workflow(path)
    compared = 0
    include_only = []
    totals = dict.fromkeys(ci.EVENTS, 0)
    old_total = 0
    for job_id, job in new["jobs"].items():
        matrix = _matrix_of(old["jobs"][job_id])
        if not matrix:
            continue
        assert isinstance(matrix, dict), (path.name, job_id, matrix)
        before = _old_matrix_entries(copy.deepcopy(matrix))
        for event in STATIC_EVENTS:
            after = _adapted_entries(copy.deepcopy(matrix), event)
            if _includes_only(matrix):
                assert after == [dict(entry) for entry in matrix["include"]]
                assert len(before) == 1 < len(after), (path.name, job_id, event)
            else:
                assert after == before, (path.name, job_id, event)
        if _includes_only(matrix):
            include_only.append(_shown(job_id))
        for event in ci.EVENTS:
            totals[event] += len(ci.cells(job, event))
        old_total += len(before)
        compared += 1
    shown = " ".join(f"{event}={count}" for event, count in totals.items())
    record_property(
        "counts",
        f"site2 {_shown(path.name)}: jobs={len(new['jobs'])} "
        f"matrices={compared} {shown} old_expander={old_total} "
        f"include_only={len(include_only)} {include_only}",
    )


def test_every_matrix_the_workflows_hold_is_compared(record_property):
    """The denominator: the comparison above reads matrices, not an empty list."""
    count = 0
    for path in ALL_WORKFLOWS:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        count += sum(1 for job in document["jobs"].values() if _matrix_of(job))
    assert count >= 20, count
    record_property(
        "counts", f"site2 matrices in {len(ALL_WORKFLOWS)} workflows: {count}"
    )


PLANTED_MATRICES = {
    "the sharded docs matrix": {"shard": [0, 1, 2, 3]},
    "a product": {"a": [1, 2], "b": [1, 2, 3]},
    "an exclude": {
        "os": ["a", "b"],
        "py": [1, 2],
        "exclude": [{"os": "a", "py": 1}],
    },
    "an include merging into a matching cell": {
        "os": ["a"],
        "include": [{"os": "a", "extra": 1}],
    },
    "an include adding a cell no cell matches": {
        "os": ["a"],
        "include": [{"os": "b", "extra": 1}],
    },
    "a single include": {"include": [{"x": 1}]},
    "an exclude only": {"exclude": [{"os": "a"}]},
    "an empty axis": {"os": []},
    "a later include overwriting an earlier one": {
        "os": ["a"],
        "include": [{"os": "a", "n": 1}, {"os": "a", "n": 2}],
    },
    "an include keyed on a value an earlier include added": {
        "os": ["a"],
        "include": [{"os": "a", "extra": 1}, {"os": "a", "extra": 2, "more": 3}],
    },
}


@pytest.mark.parametrize(
    "matrix", list(PLANTED_MATRICES.values()), ids=list(PLANTED_MATRICES)
)
def test_the_planted_matrices_count_as_the_old_expander_counted_them(matrix):
    assert _adapted_entries(copy.deepcopy(matrix)) == _old_matrix_entries(
        copy.deepcopy(matrix)
    )


def test_an_overlay_exclude_is_void_when_static_and_applies_on_a_pull_request():
    matrix = {"os": ["a", "b"], "exclude": [{"os": _overlay("a")}]}
    assert _old_matrix_entries(matrix) == [{"os": "a"}, {"os": "b"}]
    assert _adapted_entries(matrix, STATIC_EVENT) == [{"os": "a"}, {"os": "b"}]
    assert _adapted_entries(matrix, "pull_request") == [{"os": "b"}]


def test_an_include_never_joins_a_run_an_earlier_include_added():
    """The one difference on a live matrix. GitHub adds an include entry to the
    original combinations only ("the {fruit: banana, animal: cat} entry does not add to
    the {fruit: banana} matrix combination because that combination was not one of the
    original"). The old expander matched a later include against the runs an earlier one
    had appended, so it merged them: two includes and no axis counted as one run."""
    only = {"include": [{"x": 1}, {"x": 2}]}
    assert _old_matrix_entries(only) == [{"x": 2}]
    assert _adapted_entries(only) == [{"x": 1}, {"x": 2}]
    later = {"os": ["a"], "include": [{"os": "b", "x": 1}, {"os": "b", "y": 2}]}
    assert _old_matrix_entries(later) == [{"os": "a"}, {"os": "b", "x": 1, "y": 2}]
    assert _adapted_entries(later) == [
        {"os": "a"},
        {"os": "b", "x": 1},
        {"os": "b", "y": 2},
    ]


def test_the_matrix_entries_comparison_can_fail():
    matrix = PLANTED_MATRICES["a product"]
    assert _adapted_entries(matrix) == _old_matrix_entries(matrix)
    assert _adapted_entries(matrix)[:-1] != _old_matrix_entries(matrix)
    assert len(_adapted_entries(matrix)) == 6


def test_the_empty_matrix_is_the_one_accepted_input_the_answers_differ_on():
    """matrix_runs answers 1 for an empty matrix before it asks for the entries."""
    assert _old_matrix_entries({}) == []
    assert _adapted_entries({}) == [{}]


def test_an_expression_the_reader_does_not_read_is_refused_where_it_was_counted():
    matrix = {"os": ["a"], "include": [{"os": "a", "label": "${{ github.sha }}"}]}
    assert _old_matrix_entries(matrix) == [{"os": "a", "label": "${{ github.sha }}"}]
    with pytest.raises(ci.UnsupportedExpression):
        _adapted_entries(matrix)


@pytest.mark.parametrize(
    "matrix",
    [
        {"os": "${{ fromJSON(inputs.os) }}"},
        {"os": "ubuntu-latest"},
        {"os": ["a"], "exclude": "x"},
    ],
    ids=["an expression axis", "a string axis", "an exclude that is not a list"],
)
def test_a_matrix_neither_side_can_count_is_a_value_error_on_both(matrix):
    with pytest.raises(ValueError):
        _old_matrix_entries(matrix)
    with pytest.raises(ValueError):
        _adapted_entries(matrix)


# ---------------------------------------------------------------------------
# tests/unit/test_unit_test_shards.py: the pull-request cover
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ALL_WORKFLOWS, ids=lambda path: path.name)
def test_the_cover_check_equals_the_old_one_on_every_exclude_value(
    path, record_property
):
    document = ci.load_workflow(path)
    values = 0
    covers = 0
    for job_id, job in document["jobs"].items():
        for entry in _matrix_of(job).get("exclude") or []:
            for key, value in entry.items():
                values += 1
                assert _adapted_is_cover(value) == _old_is_cover(value), (
                    path.name,
                    job_id,
                    key,
                    value,
                )
                if not _adapted_is_cover(value):
                    continue
                covers += 1
                quoted = value[len(_OLD_COVER_PREFIX) : -len(_OLD_COVER_SUFFIX)]
                assert ci.resolve_overlay(value, "pull_request") == quoted
                for event in STATIC_EVENTS:
                    assert ci.resolve_overlay(value, event) is None
    record_property(
        "counts",
        f"site3 {_shown(path.name)}: excludes={values} covers={covers} "
        f"static={values - covers}",
    )


def test_the_tier_jobs_carry_the_covers_the_comparison_reads(record_property):
    """The denominator: the tier jobs of the unified CI have cover entries to compare."""
    document = ci.load_workflow(WORKFLOWS / "ash-unified-ci.yml")
    covers = {
        job_id: len(_matrix_of(job).get("exclude") or [])
        for job_id, job in document["jobs"].items()
        if job_id.startswith(("unit-test-", "integration-test-", "e2e-test-"))
    }
    assert sum(covers.values()) >= 15, covers
    record_property("counts", f"site3 tier jobs of the unified CI: {covers}")


def test_the_cover_check_comparison_can_fail():
    """The two checks differ on exactly the strings the old one read too loosely: it
    asked only for the prefix and the suffix, so a second quoted value passed."""
    malformed = "${{ github.event_name == 'pull_request' && 'a' && 'b' || '' }}"
    assert _old_is_cover(malformed) is True
    assert _adapted_is_cover(malformed) is False
    for value in (_overlay("ubuntu-latest"), _overlay("")):
        assert _old_is_cover(value) is True
        assert _adapted_is_cover(value) is True
    for value in (
        "ubuntu-latest",
        None,
        3,
        "${{ github.event_name == 'push' && 'a' || '' }}",
        "${{ github.event_name == 'pull_request' && 'a' }}",
    ):
        assert _old_is_cover(value) is False
        assert _adapted_is_cover(value) is False


# ---------------------------------------------------------------------------
# The three places as they are now, held against the copies above.
# ---------------------------------------------------------------------------

CI_RUNNERS = REPO_ROOT / "tests" / "integration" / "docs" / "ci_runners"
UNIFIED_CI = WORKFLOWS / "ash-unified-ci.yml"
PRE_COMMIT_MANIFEST_TEST = (
    REPO_ROOT / "tests" / "unit" / "test_pre_commit_hooks_manifest.py"
)
SHARDS_TEST = REPO_ROOT / "tests" / "unit" / "test_unit_test_shards.py"


def _load_module(name, path):
    """A file of the repository loaded by path under a name of its own."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _reports():
    """tests/integration/docs/ci_runners/reports.py, loaded inside its package."""
    package = "_f2b_ci_runners"
    if package not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            package,
            CI_RUNNERS / "__init__.py",
            submodule_search_locations=[str(CI_RUNNERS)],
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[package] = module
        spec.loader.exec_module(module)
    return importlib.import_module(f"{package}.reports")


def test_the_re_pointed_effective_cells_equal_the_old_ones(record_property):
    manifest = _load_module("_f2b_pre_commit_hooks_manifest", PRE_COMMIT_MANIFEST_TEST)
    assert manifest.ci_matrix is ci
    compared = 0
    for name, job_id in SURFACES:
        job = _workflow(name)[0]["jobs"][job_id]
        for method in job["strategy"]["matrix"]["method"]:
            got = manifest._effective_cells(job, method)
            assert got == _old_effective_cells(job, method), (name, job_id, method)
            compared += 1
    assert compared >= 15, compared
    record_property("counts", f"site1 re-pointed function: methods compared={compared}")


def test_the_re_pointed_matrix_entries_equal_the_old_ones(record_property):
    reports = _reports()
    assert sys.modules["_ash_ci_matrix"] is ci
    compared = 0
    for path in ALL_WORKFLOWS:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_id, job in document["jobs"].items():
            matrix = _matrix_of(job)
            if not isinstance(matrix, dict) or not matrix or _includes_only(matrix):
                continue
            got = reports.matrix_entries(copy.deepcopy(matrix))
            expected = _old_matrix_entries(copy.deepcopy(matrix))
            assert got == expected, (path.name, job_id)
            assert reports.matrix_runs(job) == len(got), (path.name, job_id)
            compared += 1
    assert compared >= 15, compared
    for matrix in PLANTED_MATRICES.values():
        got = reports.matrix_entries(copy.deepcopy(matrix))
        assert got == _old_matrix_entries(copy.deepcopy(matrix))
    only = {"include": [{"x": 1}, {"x": 2}]}
    assert reports.matrix_entries(only) == [{"x": 1}, {"x": 2}]
    assert reports.matrix_runs({"strategy": {"matrix": only}}) == 2
    record_property(
        "counts", f"site2 re-pointed function: matrices compared={compared}"
    )


def test_the_re_pointed_matrix_runs_refuse_what_they_refused():
    reports = _reports()
    for matrix in (
        {"os": "${{ fromJSON(inputs.os) }}"},
        {"os": "ubuntu-latest"},
        {"os": ["a"], "exclude": "x"},
    ):
        with pytest.raises(ValueError):
            reports.matrix_entries(matrix)
    with pytest.raises(ValueError, match="cannot be counted before the run"):
        reports.matrix_runs(
            {"strategy": {"matrix": "${{ fromJSON(needs.x.outputs.m) }}"}}
        )
    assert reports.matrix_runs({"runs-on": "x"}) == 1
    assert reports.matrix_runs({"strategy": {"matrix": {}}}) == 1


def test_the_re_pointed_cover_assertion_flags_what_is_not_a_cover(record_property):
    shards = _load_module("_f2b_unit_test_shards", SHARDS_TEST)
    assert shards.ci_matrix is ci
    check = shards._assert_only_the_pull_request_cover
    document = yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))
    checked = 0
    for job_id in (*shards.SHARDED_TIER_JOB_IDS, *shards.E2E_TEST_JOB_IDS):
        matrix = document["jobs"][job_id]["strategy"]["matrix"]
        for entry in matrix.get("exclude") or []:
            assert all(_old_is_cover(value) for value in entry.values())
            checked += len(entry)
        check(job_id, matrix)
    assert checked >= 15, checked
    check("planted", {"exclude": [{"os": _overlay("ubuntu-latest")}]})
    check("planted", {"os": ["a"]})
    for exclude in (
        {"os": "windows-latest"},
        {"os": None},
        {"python-version": 3.11},
        {"os": "${{ github.event_name == 'push' && 'a' || '' }}"},
        {"os": "${{ github.event_name == 'pull_request' && 'a' && 'b' || '' }}"},
    ):
        with pytest.raises(AssertionError, match="static exclude"):
            check("planted", {"exclude": [exclude]})
    record_property("counts", f"site3 re-pointed assertion: cover entries={checked}")
