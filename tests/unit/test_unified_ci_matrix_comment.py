"""The Unified CI matrix comment shows every cell, and nothing from a run can act as markup.

Why this file exists
--------------------
.github/scripts/unified-ci-matrix-comment.py keeps one comment on a pull request that
shows every cell of every matrix in ash-unified-ci.yml with the result of the job that
ran for it. Four small jobs at the end of that workflow run its ``publish`` command,
chained by ``needs``, and rewrite the comment as the run reaches each stage. They run
with a token that can write pull-request comments, and job names come from the pull
request's own copy of the workflow. So the properties that matter more than the layout
are: no cell may go missing (a cell the matrix leaves out has to read as excluded, and a
cell that should have run and did not has to read as not in the run); no text from the
run may become a link, an image, a mention or a table cell of its own; the publishing
jobs never fail a run and never write where the token cannot; and the four jobs stay
chained, least-privileged and free of pull-request code.

These tests run the script's functions in-process on responses captured from real runs,
and read the real workflow file for the shape of the four jobs.

The fixtures
------------
tests/test_data/unified_ci_matrix_comment/ holds, captured read-only with ``gh api``
(all pages, the latest attempt, re-indented the way pretty-format-json writes JSON,
nothing removed):

* run-45866848235.json and jobs-45866848235.json: a pull-request run that had finished,
  with a failure conclusion, 160 jobs.
* run-45876264325.json and jobs-45876264325.json: a pull-request run read while it was in
  progress: 79 jobs running, and unit-coverage and required-checks not yet created
  because the jobs they need had not finished.
* job-<id>-log-head.txt: four of those jobs' logs up to their first step, which is all
  the script reads of a log.
* workflow-c15148192f4c.json: ash-unified-ci.yml at the commit the two runs were built
  on, parsed with yaml.safe_load, with each job's ``steps`` left out (the script reads
  none) and the job order kept in ``job_order``, because the file's keys are sorted.

Controls
--------
A check that cannot fail proves nothing, so the census of the rendered cells and the
markup check each have a test that hands them a body with one cell removed, one cell
drawn twice in place of another of the same state, or rendered with the escaping
switched off, and asserts that they fail.
"""

from __future__ import annotations

import base64
import copy
import http.client
import importlib.util
import itertools
import json
import re
import ssl
import sys
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / ".github" / "scripts" / "unified-ci-matrix-comment.py"
REQUIREMENTS = (
    REPO_ROOT / ".github" / "scripts" / "unified-ci-matrix-comment.requirements.txt"
)
UNIFIED_CI = REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml"
DATA = REPO_ROOT / "tests" / "test_data" / "unified_ci_matrix_comment"
REPO = "awslabs/automated-security-helper"
COMPLETED = 45866848235
IN_PROGRESS = 45876264325


def _load():
    spec = importlib.util.spec_from_file_location("_unified_ci_matrix_comment", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    # dataclasses look the module up by name while the classes are built.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


m = _load()


def _json(name: str):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def _fixture_workflow() -> dict:
    data = _json("workflow-c15148192f4c.json")
    workflow = dict(data["workflow"])
    workflow["jobs"] = {
        job_id: workflow["jobs"][job_id] for job_id in data["job_order"]
    }
    return workflow


def _jobs(run_id: int) -> list[dict]:
    return [job for page in _json(f"jobs-{run_id}.json") for job in page["jobs"]]


def _run(run_id: int) -> dict:
    return _json(f"run-{run_id}.json")


def _pull(run: dict) -> dict:
    return {
        "number": 1209,
        "base": {"ref": "main"},
        "head": {
            "ref": run["head_branch"],
            "sha": run["head_sha"],
            "repo": {"full_name": run["head_repository"]["full_name"]},
        },
    }


def _model(workflow: dict | None = None, event: str = "pull_request"):
    pull = _pull(_run(COMPLETED))
    return m.build_model(
        workflow if workflow is not None else _fixture_workflow(),
        path=".github/workflows/ash-unified-ci.yml",
        event=event,
        contexts_for=lambda e: m.github_context(
            e, repository=REPO, default_branch="main", pull=pull
        ),
    )


def _render(
    run_id: int, jobs: list[dict] | None = None, facts=None, mode: str = "all"
) -> str:
    return m.render_comment(
        _model(),
        _run(run_id),
        _jobs(run_id) if jobs is None else jobs,
        facts or {},
        source="`c151481` on the default branch",
        mode=mode,
    )


def _expected_icons(model, jobs: list[dict], run: dict) -> Counter:
    placement = m.place_jobs(model, jobs, run_completed=run["status"] == "completed")
    states = [placement.state(cell) for cell in model.cells()]
    states += [m.job_state(job) for job in placement.others]
    return Counter(state.icon for state in states)


_ICON = re.compile("|".join(re.escape(state.icon) for state in m.STATES))


def _table_icons(body: str) -> Counter:
    """Every state icon drawn in a table row; summaries and the legend are not tables."""
    found: Counter = Counter()
    for line in body.splitlines():
        if line.startswith("|"):
            found.update(_ICON.findall(line))
    return found


def _assert_census(body: str, expected: Counter) -> None:
    found = _table_icons(body)
    assert found == expected, f"drawn {dict(found)}, expected {dict(expected)}"


def _cells_with_a_job_of_their_name(model, jobs: list[dict]) -> list[tuple]:
    """(group, cell, job) for each cell the matrices run whose job the run lists under
    the cell's own name. The pairing is by name alone, so it does not rest on
    place_jobs, the code the rendered body is checked against."""
    by_name = {job["name"]: job for job in jobs}
    return [
        (group, cell, by_name[cell.name])
        for group in model.groups
        for cell in group.cells
        if cell.excluded is None and cell.name in by_name
    ]


def _section_of(body: str, group) -> str:
    """The part of ``body`` that draws ``group``: its own table when its jobs have a
    matrix, else the one table of the jobs that have none."""
    heading = (
        f"<b>{m.html_code(group.title)}</b>"
        if group.has_matrix
        else "<b>Jobs without a matrix</b>"
    )
    return body.split(heading, 1)[1].split("</details>", 1)[0]


def _link_of(group, cell, job: dict) -> str:
    """The link the renderer draws for ``cell``: the icon of its job's state, the job's
    address, and the hover text that names the cell's leg in its table."""
    fold = next((axis for axis in m.FOLD_AXES if axis in group.dims), None)
    column = next((axis for axis in m.COLUMN_AXES if axis in group.dims), None)
    leg = ", ".join(
        f"{axis} {m.to_string(cell.values[axis])}"
        for axis in (fold, column)
        if axis and axis in cell.values
    )
    return m._icon(m.job_state(job), job, leg or cell.name or cell.job_id, True)


def _assert_each_cell_drawn_once(body: str, named: list[tuple]) -> None:
    """Each cell of ``named`` is drawn once, as its own job's link, in its own table.

    The icon census cannot see a cell drawn twice while another cell of the same state
    is dropped, because the icons still add up. A link names its job, so counting each
    cell's own link can."""
    for group, cell, job in named:
        drawn = _section_of(body, group).count(_link_of(group, cell, job))
        assert drawn == 1, f"{cell.name!r} is drawn {drawn} times in {group.title!r}"


def _outside_code(text: str) -> str:
    """``text`` with its code spans replaced by a placeholder, as CommonMark reads them."""
    out = []
    i = 0
    while i < len(text):
        if text[i] != "`":
            out.append(text[i])
            i += 1
            continue
        j = i
        while j < len(text) and text[j] == "`":
            j += 1
        size = j - i
        k = j
        close = -1
        while k < len(text):
            if text[k] == "`":
                end = k
                while end < len(text) and text[end] == "`":
                    end += 1
                if end - k == size:
                    close = k
                    break
                k = end
            else:
                k += 1
        if close < 0:
            out.append(text[i:j])
            i = j
            continue
        out.append("\x00")
        i = close + size
    return "".join(out)


def _cells_of(row: str) -> int:
    """The number of cells a table row holds: its unescaped pipes, less one."""
    return len(re.findall(r"(?<!\\)\|", row)) - 1


#: Written as code points: a literal right-to-left override in the source would reorder
#: what a reader of this file sees.
RLO = chr(0x202E)
ZWSP = chr(0x200B)
HOSTILE = (
    "x`` | ![img](https://example.invalid/p.png) <img src=x onerror=y> @someone "
    "org/repo#2 #1 [link](javascript:alert(1)) a\\|b\r::warning::injected\n"
    f"##[error]x {RLO}reversed{ZWSP}joined"
)
_ACTIVE = ("<img", "![", "@someone", "](javascript", "#2", "#1", RLO, ZWSP)


def _assert_inert(row: str, columns: int) -> None:
    assert _cells_of(row) == columns, f"{row!r} is not {columns} cells"
    outside = _outside_code(row)
    for marker in _ACTIVE:
        assert marker not in outside, f"{marker!r} outside a code span in {row!r}"
    assert "\r" not in row and "\n" not in row


def _hostile_job() -> dict:
    job = copy.deepcopy(_jobs(COMPLETED)[0])
    job.update(id=1, name=HOSTILE, labels=["label | @someone"])
    return job


def _other_rows(body: str) -> list[str]:
    section = body.split("Other jobs in this run", 1)[1].split("</details>", 1)[0]
    return [
        line
        for line in section.splitlines()
        if line.startswith("| ") and not line.startswith("| job ") and "---" not in line
    ]


# ---------------------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------------------


class TestExpressions:
    def test_the_pull_request_overlay_is_its_value_on_a_pull_request_only(self):
        text = "${{ github.event_name == 'pull_request' && 'ubuntu-latest' || '' }}"
        on_pr = {"github": {"event_name": "pull_request"}}
        on_push = {"github": {"event_name": "push"}}
        assert m.evaluate_value(text, on_pr) == "ubuntu-latest"
        assert m.evaluate_value(text, on_push) == ""

    def test_strings_compare_without_case_and_operators_return_operands(self):
        assert m.evaluate("'Docker' == 'docker'", {}) is True
        assert m.evaluate("null && 'x'", {}) is None
        assert m.evaluate("'' || 0 || 'last'", {}) == "last"
        assert m.evaluate("!matrix.offline", {"matrix": {}}) is True
        assert m.evaluate("1 == '1'", {}) is True
        assert m.evaluate("-1 < 0", {}) is True

    def test_format_fills_its_arguments_and_reads_doubled_braces(self):
        assert m.evaluate("format(' [{0}]', 'podman')", {}) == " [podman]"
        assert m.evaluate("format('{{0}} {0}', 'a')", {}) == "{0} a"
        with pytest.raises(m.ExpressionError):
            m.evaluate("format('{1}', 'a')", {})

    def test_a_template_keeps_its_type_alone_and_interpolates_with_text(self):
        assert m.evaluate_value("${{ 45 }}", {}) == 45
        assert (
            m.evaluate_value("py${{ matrix.v }}", {"matrix": {"v": "3.12"}}) == "py3.12"
        )
        assert m.evaluate_value("${{ format('}}{0}', 'x') }}", {}) == "}x"

    def test_a_context_unknown_outside_the_run_is_refused_not_read_as_empty(self):
        with pytest.raises(m.UnknownContext):
            m.evaluate("vars.RUNNER", {})
        with pytest.raises(m.UnknownContext):
            m.evaluate("needs.setup.outputs.matrix", {})

    def test_truthiness_is_githubs(self):
        for value in (False, 0, 0.0, "", None, float("nan")):
            assert not m.truthy(value), value
        for value in (True, 1, "0", "false", [], {}):
            assert m.truthy(value), value

    def test_the_scan_names_evaluate_to_the_names_github_gave_the_jobs(self):
        """Every scan-validation include entry, through the real name template, is a real
        job name of the finished run, and the other way round."""
        workflow = _fixture_workflow()
        job = workflow["jobs"]["scan-validation"]
        names = {
            m.to_string(m.evaluate_value(job["name"], {"matrix": entry, "github": {}}))
            for entry in job["strategy"]["matrix"]["include"]
        }
        ran = {j["name"] for j in _jobs(COMPLETED) if j["name"].startswith("scan (")}
        assert names == ran
        assert "scan (python-container, ubuntu-latest) [offline]" in names
        assert "scan (bash, ubuntu-latest) [finch]" in names


# ---------------------------------------------------------------------------------------
# Matrix expansion
# ---------------------------------------------------------------------------------------


class TestMatrixExpansion:
    def test_includes_merge_or_append_as_githubs_documented_example(self):
        """The fruit and animal example of GitHub's matrix reference, result for result."""
        matrix = {
            "fruit": ["apple", "pear"],
            "animal": ["cat", "dog"],
            "include": [
                {"color": "green"},
                {"color": "pink", "animal": "cat"},
                {"fruit": "apple", "shape": "circle"},
                {"fruit": "banana"},
                {"fruit": "banana", "animal": "cat"},
            ],
        }
        assert m.expand_matrix(matrix, {}).active == [
            {"fruit": "apple", "animal": "cat", "color": "pink", "shape": "circle"},
            {"fruit": "apple", "animal": "dog", "color": "green", "shape": "circle"},
            {"fruit": "pear", "animal": "cat", "color": "pink"},
            {"fruit": "pear", "animal": "dog", "color": "green"},
            {"fruit": "banana"},
            {"fruit": "banana", "animal": "cat"},
        ]

    def test_an_exclude_matches_on_every_key_it_names(self):
        matrix = {
            "os": ["macos-latest", "windows-latest"],
            "version": [12, 14, 16],
            "environment": ["staging", "production"],
            "exclude": [
                {"os": "macos-latest", "version": 12, "environment": "production"},
                {"os": "windows-latest", "version": 16},
            ],
        }
        expansion = m.expand_matrix(matrix, {})
        assert len(expansion.active) == 12 - 1 - 2
        assert sum(1 for _, out in expansion.display if out) == 3

    def test_an_include_that_re_adds_an_excluded_cell_shows_it_once_and_running(self):
        matrix = {
            "os": ["a", "b"],
            "exclude": [{"os": "a"}],
            "include": [{"os": "a", "x": 1}],
        }
        expansion = m.expand_matrix(matrix, {})
        assert expansion.display == [({"os": "b"}, False), ({"os": "a", "x": 1}, False)]

    def test_a_product_past_the_cap_is_refused(self):
        with pytest.raises(m.ExpressionError):
            m.expand_matrix({"a": list(range(100)), "b": list(range(100))}, {})

    def test_the_cover_and_the_static_exclusions_read_differently(self):
        model = _model()
        unit = next(g for g in model.groups if "unit-test-linux" in g.job_ids)
        cover = [c for c in unit.cells if c.values["os"] == "ubuntu-latest"]
        assert cover and all(c.excluded is m.EXCLUDED_HERE for c in cover)
        assert set(cover[0].runs_on_events) == {
            "push",
            "merge_group",
            "workflow_dispatch",
        }
        install = next(g for g in model.groups if g.job_ids == ["install-validation"])
        static = [
            c
            for c in install.cells
            if c.values["os"] == "windows-latest" and c.values["method"] == "homebrew"
        ]
        assert len(static) == 4 and all(c.excluded is m.EXCLUDED_ALWAYS for c in static)


# ---------------------------------------------------------------------------------------
# The model against a real run
# ---------------------------------------------------------------------------------------


def _independent_cell_count(workflow: dict) -> int:
    """Cells counted straight from the file: product, include-only list, or one job."""
    total = 0
    for job in workflow["jobs"].values():
        matrix = (job.get("strategy") or {}).get("matrix")
        if matrix is None:
            total += 1
            continue
        axes = [v for k, v in matrix.items() if k not in ("include", "exclude")]
        assert not (axes and matrix.get("include")), (
            "this count has no rule for that mix"
        )
        total += (
            len(list(itertools.product(*axes)))
            if axes
            else len(matrix.get("include") or [])
        )
    return total


class TestTheModelOfARealRun:
    def test_every_cell_of_every_matrix_is_in_the_model(self):
        model = _model()
        assert len(model.cells()) == _independent_cell_count(_fixture_workflow()) == 456
        job_ids = [job_id for group in model.groups for job_id in group.job_ids]
        assert sorted(job_ids) == sorted(_fixture_workflow()["jobs"])
        assert not [g.problems for g in model.groups if g.problems]

    def test_jobs_named_by_one_template_share_one_table(self):
        model = _model()
        unit = next(g for g in model.groups if "unit-test-linux" in g.job_ids)
        assert unit.job_ids == [
            "unit-test-linux",
            "unit-test-macos",
            "unit-test-windows",
        ]
        assert unit.dims == ["os", "python-version", "shard"]
        assert len(unit.cells) == 2 * 4 * 6 + 2 * 4 * 8 + 1 * 4 * 8
        titles = [g.title for g in model.groups]
        assert len(titles) == len(set(titles)), titles

    def test_every_job_the_run_listed_has_a_cell_and_no_cell_is_left_without_one(self):
        model = _model()
        jobs = _jobs(COMPLETED)
        placement = m.place_jobs(model, jobs, run_completed=True)
        assert placement.others == []
        assert {id(job) for job in placement.jobs.values()} == {id(job) for job in jobs}
        running = [c for c in model.cells() if c.excluded is None]
        assert all(c.id in placement.jobs for c in running)
        # What GitHub created is exactly what the model does not exclude: 160 jobs, one of
        # them the never-expanded warm-image-layers entry standing for its two cells.
        assert len(running) == len(jobs) + 1
        assert len(placement.collapsed) == 2

    def test_a_job_missing_from_a_finished_run_reads_as_not_in_the_run(self):
        model = _model()
        jobs = [j for j in _jobs(COMPLETED) if j["name"] != "e2e-test (windows-latest)"]
        placement = m.place_jobs(model, jobs, run_completed=True)
        states = Counter(placement.state(c) for c in model.cells())
        assert states[m.NOT_IN_RUN] == 1
        body = _render(COMPLETED, jobs=jobs)
        assert f"| `windows-latest` | {m.NOT_IN_RUN.icon} |" in body

    def test_a_job_no_cell_names_is_listed_not_dropped(self):
        jobs = _jobs(COMPLETED)
        renamed = copy.deepcopy(jobs[0])
        renamed.update(id=2, name="lint (a leg a pull request adds)")
        body = _render(COMPLETED, jobs=[*jobs, renamed])
        rows = _other_rows(body)
        assert len(rows) == 1 and "a leg a pull request adds" in rows[0]

    def test_a_never_expanded_job_goes_to_a_job_with_nothing_placed_yet(self):
        """Two workflow jobs share one name template. GitHub made one of the first
        job's two legs, and listed the second job, whose condition was false, once under
        the raw template. That entry is the second job's. The first job's other leg is
        missing from the run, and before this change it took the entry."""
        template = "t (${{ matrix.os }})"
        workflow = {
            "name": "w",
            "on": {"pull_request": {}},
            "jobs": {
                job_id: {
                    "name": template,
                    "runs-on": "${{ matrix.os }}",
                    "strategy": {"matrix": {"os": legs}},
                }
                for job_id, legs in (("first", ["a", "b"]), ("second", ["c"]))
            },
        }
        model = _model(workflow)
        made = {
            "id": 1,
            "name": "t (a)",
            "status": "completed",
            "conclusion": "success",
        }
        raw = {
            "id": 2,
            "name": template,
            "status": "completed",
            "conclusion": "skipped",
        }
        placement = m.place_jobs(model, [made, raw], run_completed=True)
        cells = {(cell.job_id, cell.values["os"]): cell for cell in model.cells()}
        assert placement.jobs.get(cells["first", "a"].id) is made
        assert placement.jobs.get(cells["second", "c"].id) is raw
        assert cells["first", "b"].id not in placement.jobs
        assert placement.state(cells["first", "b"]) is m.NOT_IN_RUN
        assert placement.collapsed == {cells["second", "c"].id}
        assert placement.others == []


# ---------------------------------------------------------------------------------------
# The rendered comment
# ---------------------------------------------------------------------------------------


class TestTheComment:
    def test_it_opens_with_the_marker_and_counts_every_cell(self):
        body = _render(COMPLETED)
        assert body.splitlines()[0] == m.MARKER
        assert (
            "❌ 129 failed · ✅ 30 passed · ⏭️ 2 skipped · ➖ 222 excluded on this event"
            " · ⛔ 73 excluded on every trigger"
        ) in body
        assert len(body) <= m.BODY_BUDGET

    def test_every_cell_is_drawn_once(self):
        model = _model()
        for run_id in (COMPLETED, IN_PROGRESS):
            body = _render(run_id)
            jobs = _jobs(run_id)
            named = _cells_with_a_job_of_their_name(model, jobs)
            # Every job but the never-expanded entry that stands for two cells.
            assert len(named) == len(jobs) - 1
            _assert_each_cell_drawn_once(body, named)
            _assert_census(body, _expected_icons(model, jobs, _run(run_id)))

    def test_control_the_census_fails_when_one_cell_is_not_drawn(self):
        body = _render(COMPLETED)
        expected = _expected_icons(_model(), _jobs(COMPLETED), _run(COMPLETED))
        first_link = re.search(r"\[❌\]\([^)]*\)", body).group(0)
        with pytest.raises(AssertionError):
            _assert_census(body.replace(first_link, "", 1), expected)

    def test_control_the_check_fails_when_one_cell_is_drawn_twice_in_place_of_another(
        self,
    ):
        """Two failed cells, the second's link replaced by the first's: the icons add up
        as before, so the census cannot tell, and each cell's own link can."""
        model, jobs = _model(), _jobs(COMPLETED)
        body = _render(COMPLETED)
        named = _cells_with_a_job_of_their_name(model, jobs)
        _assert_each_cell_drawn_once(body, named)
        icon = re.escape(m.FAILED.icon)
        links = re.findall(rf'\[{icon}\]\(https://github\.com/[^ )]+ "[^"]*"\)', body)
        first, second = links[:2]
        twice = body.replace(second, first, 1)
        assert first != second and twice != body
        _assert_census(twice, _expected_icons(model, jobs, _run(COMPLETED)))
        with pytest.raises(AssertionError):
            _assert_each_cell_drawn_once(twice, named)

    def test_the_shards_of_one_os_and_version_sit_in_one_cell_in_order(self):
        body = _render(COMPLETED)
        row = next(
            line
            for line in body.split("unit-test (…, py…, shard …)", 1)[1].splitlines()
            if line.startswith("| `ubuntu-24.04-arm` |")
        )
        cells = re.split(r"(?<!\\)\|", row)[1:-1]
        assert [c.strip() for c in cells][1] == "➖" * 6
        shards = re.findall(r'"shard (\dof6), python-version 3\.12: failed"', cells[2])
        assert shards == [f"{i}of6" for i in range(1, 7)]

    def test_an_in_progress_run_shows_running_and_not_yet_created_jobs(self):
        body = _render(IN_PROGRESS)
        assert "⏳ 79 running · 🕒 2 pending" in body
        assert "| `unit-coverage` | `ubuntu-24.04-arm` | 🕒 pending |" in body
        assert "| `required-checks` | `ubuntu-24.04-arm` | 🕒 pending |" in body

    def test_a_requested_run_starts_with_every_cell_pending(self):
        run = dict(_run(COMPLETED), status="queued", conclusion=None)
        body = m.render_comment(_model(), run, [], {}, source="x")
        assert "🕒 161 pending · ➖ 222 excluded on this event" in body

    def test_runner_environments_come_from_the_log_headers(self):
        facts = {
            "ubuntu-24.04-arm": m.parse_runner_header(
                (DATA / "job-140071768606-log-head.txt").read_bytes()
            )
        }
        body = _render(COMPLETED, facts=facts)
        assert (
            "| `ubuntu-24.04-arm` | `ubuntu-24.04-arm` `20261116.188.1` "
            "| `Ubuntu 24.04.5 LTS` | `arm64` | 49 |"
        ) in body
        assert "| `macos-latest` | – | – | – | 5 |" in body

    def test_a_label_only_excluded_cells_use_says_so(self):
        workflow = {
            "name": "w",
            "on": {"pull_request": {}, "push": {}},
            "jobs": {
                "t": {
                    "name": "t (${{ matrix.os }})",
                    "runs-on": "${{ matrix.os }}",
                    "strategy": {
                        "matrix": {
                            "os": ["a", "b"],
                            "exclude": [
                                {
                                    "os": "${{ github.event_name == 'pull_request' && 'b' || '' }}"
                                }
                            ],
                        }
                    },
                }
            },
        }
        run = dict(_run(COMPLETED), status="in_progress", conclusion=None)
        body = m.render_comment(_model(workflow), run, [], {}, source="x")
        assert "| `a` | – | – | – | 0 so far |" in body
        assert "| `b` | – | – | – | 0, excluded on this event |" in body

    def test_the_body_fits_by_dropping_links_first(self, monkeypatch):
        full = _render(COMPLETED)
        monkeypatch.setattr(m, "BODY_BUDGET", 20000)
        body = m.render_within_limit(
            _model(), _run(COMPLETED), _jobs(COMPLETED), {}, source="x"
        )
        assert len(body) <= 20000
        assert body.count("](https://github.com/") < full.count("](https://github.com/")
        monkeypatch.setattr(m, "BODY_BUDGET", 3000)
        cut = m.render_within_limit(
            _model(), _run(COMPLETED), _jobs(COMPLETED), {}, source="x"
        )
        assert len(cut) <= 3000 and cut.rstrip().endswith("see the run for the rest._")

    def test_a_body_cut_for_size_ends_at_a_line_with_its_blocks_closed(
        self, monkeypatch
    ):
        """A body too large for one comment is cut between two lines, whatever the
        budget: no code span is left open, the ``<details>`` block the cut passes is
        closed, and the note ends the body. Before this change the cut fell on a
        character, so a code span or a block could be left open above the note."""
        rows = [
            f"| {m.code(f'row {i}')} | {m.code(f'a`b {i}')} | x |" for i in range(80)
        ]
        body = "\n".join(
            [
                m.MARKER,
                "",
                "<details open><summary><b>t</b> 80 cells</summary>",
                "",
                *rows,
                "",
                "</details>",
                "",
                "<details><summary>Legend</summary>",
                "",
                "some text",
                "",
                "</details>",
                "",
            ]
        )
        monkeypatch.setattr(m, "render_comment", lambda *args, **kwargs: body)
        whole_lines = set(body.splitlines())
        for budget in range(300, len(body), 23):
            monkeypatch.setattr(m, "BODY_BUDGET", budget)
            cut = m.render_within_limit(None, {}, [], {}, source="x")
            lines = cut.splitlines()
            assert len(cut) <= budget, budget
            assert cut.startswith(m.MARKER), budget
            assert cut.rstrip().endswith("see the run for the rest._"), budget
            for line in lines:
                whole = line in whole_lines or line.endswith("for the rest._")
                assert whole, (budget, line)
                assert "`" not in _outside_code(line), (budget, line)
            opened = sum(line.startswith("<details") for line in lines)
            assert opened == lines.count("</details>"), budget


# ---------------------------------------------------------------------------------------
# What came from the run cannot act as markup
# ---------------------------------------------------------------------------------------


class TestEscaping:
    def test_a_hostile_job_name_stays_one_inert_cell(self):
        body = _render(COMPLETED, jobs=[*_jobs(COMPLETED), _hostile_job()])
        rows = _other_rows(body)
        assert len(rows) == 1
        _assert_inert(rows[0], columns=3)
        assert not any(line.lstrip().startswith("::") for line in body.splitlines())
        assert "##[error]" not in _outside_code(body)

    def test_control_the_check_fails_when_escaping_is_off(self, monkeypatch):
        monkeypatch.setattr(m, "code", lambda value, table=True, limit=100: str(value))
        body = _render(COMPLETED, jobs=[*_jobs(COMPLETED), _hostile_job()])
        with pytest.raises(AssertionError):
            for row in _other_rows(body):
                _assert_inert(row, columns=3)

    @pytest.mark.parametrize(
        "value",
        [
            "`",
            "``x``",
            "a`b",
            "x |y",
            "\\|",
            "@user",
            "<b>",
            "#3",
            f"x{RLO}y",
            "\r\n::x::",
        ],
    )
    def test_any_value_is_one_code_span(self, value):
        span = m.code(value)
        assert _outside_code(span) == "\x00", span
        assert _cells_of(f"| {span} |") == 1, span

    def test_the_log_line_cannot_start_a_workflow_command(self):
        assert (
            m.one_line("x\r::warning::y\n##[error]z") == "x : :warning: :y # #[error]z"
        )


# ---------------------------------------------------------------------------------------
# What a runner says about itself
# ---------------------------------------------------------------------------------------


class TestRunnerHeader:
    @pytest.mark.parametrize(
        ("job_id", "image", "version", "system", "arch"),
        [
            (
                140071768606,
                "ubuntu-24.04-arm",
                "20261116.188.1",
                "Ubuntu 24.04.5 LTS",
                "arm64",
            ),
            (
                140071770604,
                "ubuntu-24.04",
                "20261122.23.1",
                "Ubuntu 24.04.5 LTS",
                "x64",
            ),
            (
                140071769147,
                "macos-15-arm64",
                "20261123.0558.1",
                "macOS 15.8.2 24H232",
                "arm64",
            ),
            (
                140071768755,
                "windows-2025-vs2026",
                "20261116.315.1",
                "Microsoft Windows Server 2025 10.0.26100 Datacenter",
                "x64",
            ),
        ],
    )
    def test_the_header_names_the_image_system_and_arch(
        self, job_id, image, version, system, arch
    ):
        facts = m.parse_runner_header(
            (DATA / f"job-{job_id}-log-head.txt").read_bytes()
        )
        assert facts == m.RunnerFacts(
            image=image, version=version, os=system, arch=arch
        )

    def test_a_windows_log_with_crlf_line_endings_reads_the_same(self):
        """A Windows runner's log arrives with CRLF line endings. The fixture is stored
        with LF, as the repository stores every text file, so the CRLF form is built
        here from it."""
        raw = (DATA / "job-140071768755-log-head.txt").read_bytes()
        crlf = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        assert crlf.count(b"\r\n") > 10
        assert m.parse_runner_header(crlf) == m.RunnerFacts(
            image="windows-2025-vs2026",
            version="20261116.315.1",
            os="Microsoft Windows Server 2025 10.0.26100 Datacenter",
            arch="x64",
        )

    def test_a_group_a_step_prints_is_not_read(self):
        text = (
            "2026-11-26T17:20:16.1Z Current runner version: '2.338.2'\n"
            "2026-11-26T17:20:16.2Z ##[group]Run something\n"
            "2026-11-26T17:20:16.3Z ##[group]Runner Image\n"
            "2026-11-26T17:20:16.4Z Image: spoofed\n"
            "2026-11-26T17:20:16.5Z ##[endgroup]\n"
        )
        assert m.parse_runner_header(text.encode()) is None

    def test_a_value_with_markup_is_dropped(self):
        text = (
            "##[group]Operating System\nUbuntu <b>\n##[endgroup]\n"
            "##[group]Runner Image\nImage: `x` | y\n##[endgroup]\n"
        )
        assert m.parse_runner_header(text.encode()) is None


# ---------------------------------------------------------------------------------------
# The API client and the comment, over a recording transport
# ---------------------------------------------------------------------------------------


class FakeAPI:
    """A transport that answers by method and path and records every exchange."""

    def __init__(self):
        self.routes: dict[tuple[str, str], list] = {}
        self.calls: list[tuple[str, str, dict, bytes | None]] = []

    def on(self, method: str, path: str, *responses) -> None:
        self.routes[(method, path)] = list(responses)

    def __call__(self, method, url, headers, body, max_bytes):
        self.calls.append((method, url, dict(headers), body))
        parts = urllib.parse.urlsplit(url)
        key = (method, parts.path if parts.netloc == "api.github.com" else parts.netloc)
        answers = self.routes[key]
        answer = answers.pop(0) if len(answers) > 1 else answers[0]
        return answer(url, headers, body) if callable(answer) else answer

    def count(self, method: str, path: str) -> int:
        return sum(
            1
            for call_method, url, _, _ in self.calls
            if call_method == method and urllib.parse.urlsplit(url).path == path
        )


def _ok(data, status: int = 200, headers: dict | None = None):
    return m.Response(status, headers or {}, json.dumps(data).encode())


def _client(api: FakeAPI, sleeps: list | None = None):
    return m.GitHubClient(
        "t0ken", transport=api, sleep=(sleeps if sleeps is not None else []).append
    )


class _Reply:
    """What ``opener.open`` gives back: a context manager with a status and headers,
    whose body reads as the answer's, or fails the way a dropped connection does."""

    def __init__(self, answer: m.Response, make_error=None):
        self.status = answer.status
        self.headers = answer.headers
        self._body = answer.body
        self._make_error = make_error

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def read(self, size=None):
        if self._make_error is not None:
            raise self._make_error()
        return self._body[:size] if size else self._body


class _Opener:
    """Stands in for the opener ``urllib_transport`` builds: it answers from a FakeAPI,
    and the body of every answer from one host fails when it is read."""

    def __init__(self, api: FakeAPI, failing_host: str, make_error):
        self._api = api
        self._failing_host = failing_host
        self._make_error = make_error

    def open(self, request, timeout=None):
        url = request.full_url
        answer = self._api(request.get_method(), url, {}, request.data, None)
        failing = urllib.parse.urlsplit(url).netloc == self._failing_host
        return _Reply(answer, self._make_error if failing else None)


class TestTheClient:
    def test_a_log_is_fetched_from_its_redirect_without_the_token(self):
        api = FakeAPI()
        path = f"/repos/{REPO}/actions/jobs/7/logs"
        api.on(
            "GET",
            path,
            m.Response(302, {"location": "https://logs.example.invalid/x?sig=1"}, b""),
        )
        api.on("GET", "logs.example.invalid", m.Response(206, {}, b"header"))
        assert _client(api).log_head(path) == b"header"
        first, second = api.calls
        assert first[2]["Authorization"] == "Bearer t0ken"
        assert "Authorization" not in second[2] and second[2]["Range"].startswith(
            "bytes=0-"
        )

    def test_a_redirect_that_is_not_https_is_refused(self):
        api = FakeAPI()
        path = f"/repos/{REPO}/actions/jobs/7/logs"
        api.on(
            "GET",
            path,
            m.Response(302, {"location": "http://logs.example.invalid/x"}, b""),
        )
        with pytest.raises(m.GitHubError):
            _client(api).log_head(path)
        assert len(api.calls) == 1

    def test_the_handler_follows_no_redirect(self):
        assert (
            m._NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://x")
            is None
        )

    def test_pages_are_followed_on_the_api_host_only(self):
        api = FakeAPI()
        path = f"/repos/{REPO}/actions/runs/1/jobs"
        api.on(
            "GET",
            path,
            _ok(
                {"jobs": [1]},
                headers={"link": f'<https://api.github.com{path}?page=2>; rel="next"'},
            ),
            _ok({"jobs": [2]}),
        )
        assert _client(api).paginate(path, {"per_page": "100"}, key="jobs") == [1, 2]
        api.on(
            "GET",
            path,
            _ok(
                {"jobs": [1]},
                headers={"link": '<https://elsewhere.invalid/p?page=2>; rel="next"'},
            ),
        )
        with pytest.raises(m.GitHubError):
            _client(api).paginate(path, key="jobs")

    def test_a_server_error_is_retried_and_a_rate_limit_waits(self):
        api = FakeAPI()
        sleeps: list = []
        path = f"/repos/{REPO}/actions/runs/1"
        api.on("GET", path, m.Response(502, {}, b""), _ok({"id": 1}))
        assert _client(api, sleeps).get_json(path) == {"id": 1}
        api.on("GET", path, m.Response(403, {"retry-after": "7"}, b""), _ok({"id": 1}))
        assert _client(api, sleeps).get_json(path) == {"id": 1}
        assert sleeps == [2.0, 7.0]

    def test_a_403_without_a_rate_limit_header_is_not_retried(self):
        """A refusal for want of permission answers at once; only a rate limit waits."""
        api = FakeAPI()
        sleeps: list = []
        path = f"/repos/{REPO}/issues/5/comments"
        api.on("POST", path, m.Response(403, {}, b"{}"))
        with pytest.raises(m.GitHubError) as raised:
            _client(api, sleeps).send_json("POST", path, {"body": "x"})
        assert raised.value.status == 403
        assert len(api.calls) == 1 and sleeps == []


class TestTheOneComment:
    PATH = f"/repos/{REPO}/issues/5/comments"

    def _comments(self, *bodies_and_users):
        return [
            {"id": 10 + i, "body": body, "user": {"login": login, "type": kind}}
            for i, (body, login, kind) in enumerate(bodies_and_users)
        ]

    def test_only_the_bots_marked_comment_is_edited(self):
        api = FakeAPI()
        api.on(
            "GET",
            self.PATH,
            _ok(
                self._comments(
                    (m.MARKER + " a person quoting it", "someone", "User"),
                    (m.MARKER + "\nold", m.BOT_LOGIN, "Bot"),
                )
            ),
        )
        api.on("PATCH", f"/repos/{REPO}/issues/comments/11", _ok({}))
        posted = m.Posted()
        assert (
            m.upsert_comment(_client(api), REPO, 5, m.MARKER + "\nnew", posted)
            == "updated"
        )
        assert posted.comment_id == 11
        assert (
            m.upsert_comment(_client(api), REPO, 5, m.MARKER + "\nnew", posted)
            == "unchanged"
        )
        assert api.count("PATCH", f"/repos/{REPO}/issues/comments/11") == 1

    def test_a_missing_comment_is_created_and_a_deleted_one_recreated(self):
        api = FakeAPI()
        api.on("GET", self.PATH, _ok([]))
        api.on("POST", self.PATH, _ok({"id": 99}, status=201))
        api.on("PATCH", f"/repos/{REPO}/issues/comments/99", m.Response(404, {}, b"{}"))
        posted = m.Posted()
        assert (
            m.upsert_comment(_client(api), REPO, 5, m.MARKER + "\none", posted)
            == "created"
        )
        assert (
            m.upsert_comment(_client(api), REPO, 5, m.MARKER + "\ntwo", posted)
            == "created"
        )
        assert api.count("POST", self.PATH) == 2


LINKS = [
    "matrix-comment-checks",
    "matrix-comment-scans",
    "matrix-comment-tiers",
    "matrix-comment",
]
#: The names GitHub lists two of the publishing jobs under, for the publish tests.
POST_JOB_NAMES = {
    "matrix-comment-checks": "matrix comment (checks)",
    "matrix-comment": "matrix comment",
}
SHA = "1" * 40
PUBLISH_COMMAND = ".github/scripts/unified-ci-matrix-comment.py publish"


def _publish_workflow() -> dict:
    """The captured workflow plus two publishing jobs, as the real file has four."""
    workflow = _fixture_workflow()
    for job_id, name in POST_JOB_NAMES.items():
        final = " --final" if job_id == "matrix-comment" else ""
        workflow["jobs"][job_id] = {
            "name": name,
            "runs-on": "ubuntu-slim",
            "steps": [{"run": f"python {PUBLISH_COMMAND}{final}"}],
        }
    return workflow


def _post_jobs(run_id: int) -> list[dict]:
    """The job entries GitHub lists for the publishing jobs themselves."""
    template = _jobs(run_id)[0]
    return [
        dict(
            copy.deepcopy(template),
            id=9_000_000 + index,
            name=name,
            status="in_progress",
            conclusion=None,
        )
        for index, name in enumerate(POST_JOB_NAMES.values())
    ]


def _event(*, number: int = 1209, head_repo: str = REPO, author: str = "someone"):
    return {
        "pull_request": {
            "number": number,
            "user": {"login": author},
            "base": {"ref": "main"},
            "head": {
                "ref": "feature",
                "sha": "a" * 40,
                "repo": {"full_name": head_repo},
            },
        },
        "repository": {"default_branch": "main"},
    }


def _contents(workflow: dict) -> dict:
    text = yaml.safe_dump(workflow, sort_keys=False)
    return {
        "encoding": "base64",
        "size": len(text),
        "content": base64.encodebytes(text.encode()).decode(),
    }


class _Publish:
    """A fake API for one ``publish`` call, and the call itself."""

    def __init__(self, tmp_path, *, run=None, reads=None, comments=None):
        self.run = run or dict(_run(COMPLETED), status="in_progress", conclusion=None)
        self.summary = tmp_path / "summary.md"
        self.api = FakeAPI()
        self.sleeps: list = []
        self.logs: list = []
        self.warnings: list = []
        path = self.run["path"]
        self.api.on("GET", f"/repos/{REPO}/actions/runs/{COMPLETED}", _ok(self.run))
        self.api.on(
            "GET", f"/repos/{REPO}/contents/{path}", _ok(_contents(_publish_workflow()))
        )
        jobs = _jobs(COMPLETED) + _post_jobs(COMPLETED)
        self.api.on(
            "GET",
            f"/repos/{REPO}/actions/runs/{COMPLETED}/jobs",
            *[_ok({"jobs": read}) for read in (reads or [jobs])],
        )
        self.api.on("GET", f"/repos/{REPO}/issues/1209/comments", _ok(comments or []))
        self.api.on(
            "POST", f"/repos/{REPO}/issues/1209/comments", _ok({"id": 77}, status=201)
        )
        self.api.on("PATCH", f"/repos/{REPO}/issues/comments/77", _ok({}))
        header = (DATA / "job-140071768606-log-head.txt").read_bytes()
        self.api.routes[("GET", "logs.example.invalid")] = [m.Response(206, {}, header)]
        for job in _jobs(COMPLETED):
            self.api.on(
                "GET",
                f"/repos/{REPO}/actions/jobs/{job['id']}/logs",
                m.Response(302, {"location": "https://logs.example.invalid/l"}, b""),
            )

    def publish(
        self,
        *,
        final,
        event=None,
        event_name="pull_request",
        client=None,
        budget_seconds=m.PUBLISH_BUDGET_SECONDS,
    ):
        return m.publish(
            client or _client(self.api, []),
            repo=REPO,
            run_id=COMPLETED,
            event_name=event_name,
            event=_event() if event is None else event,
            workflow_sha=SHA,
            final=final,
            summary_path=str(self.summary),
            log=self.logs.append,
            warn=self.warnings.append,
            sleep=self.sleeps.append,
            budget_seconds=budget_seconds,
        )

    def requests_under(self, fragment: str) -> list:
        return [
            c for c in self.api.calls if fragment in urllib.parse.urlsplit(c[1]).path
        ]

    def summary_text(self) -> str:
        return self.summary.read_text(encoding="utf-8") if self.summary.exists() else ""

    def posted_body(self) -> str:
        (call,) = [c for c in self.api.calls if c[0] in ("POST", "PATCH")]
        return json.loads(call[3])["body"]


def _marked(number: int, attempt: int, comment_id: int = 77) -> dict:
    body = (
        f"{m.MARKER}\n"
        f"<!-- ash-unified-ci-matrix-run: run_number={number} run_attempt={attempt} -->\n"
        "old table\n"
    )
    return {
        "id": comment_id,
        "body": body,
        "user": {"login": m.BOT_LOGIN, "type": "Bot"},
    }


class TestThePublish:
    def test_the_publishing_jobs_are_found_by_their_command_and_left_out(self):
        workflow = _publish_workflow()
        assert m.post_job_ids(workflow) == list(POST_JOB_NAMES)
        shown, ids = m.without_post_jobs(workflow)
        assert ids == list(POST_JOB_NAMES)
        assert not set(ids) & set(shown["jobs"])
        assert len(shown["jobs"]) == len(workflow["jobs"]) - 2

    def test_an_intermediate_link_creates_the_one_comment(self, tmp_path):
        api = _Publish(tmp_path)
        run = api.run
        assert api.publish(final=False) == 0
        assert len(api.requests_under("/issues/1209/comments")) == 2  # list, create
        body = api.posted_body()
        lines = body.splitlines()
        assert lines[0] == m.MARKER
        assert lines[1] == (
            f"<!-- ash-unified-ci-matrix-run: run_number={run['run_number']} "
            f"run_attempt={run['run_attempt']} -->"
        )
        assert "**`in_progress`**" in body
        for name in POST_JOB_NAMES.values():
            assert name not in body
        assert api.summary_text() == ""
        assert api.requests_under("/logs") == []
        assert api.warnings == []

    def test_the_final_link_edits_the_comment_and_writes_the_summary_first(
        self, tmp_path
    ):
        api = _Publish(tmp_path, comments=[_marked(1, 1)])
        seen: list[bool] = []

        def patch(url, headers, body):
            seen.append(api.summary_text() != "")
            return _ok({})

        api.api.on("PATCH", f"/repos/{REPO}/issues/comments/77", patch)
        assert api.publish(final=True) == 0
        assert api.api.count("POST", f"/repos/{REPO}/issues/1209/comments") == 0
        assert len(api.requests_under("/issues/comments/77")) == 1
        body = api.posted_body()
        assert seen == [True]
        assert api.summary_text() == body
        assert "**`completed: failure`**" in body
        for name in POST_JOB_NAMES.values():
            assert name not in body
        assert "| `ubuntu-24.04-arm` | `ubuntu-24.04-arm` `20261116.188.1` " in body
        _assert_census(
            body, _expected_icons(_model(), _jobs(COMPLETED), _run(COMPLETED))
        )

    def test_a_fork_pull_request_gets_the_summary_and_no_comment_request(
        self, tmp_path
    ):
        api = _Publish(tmp_path)
        assert api.publish(final=True, event=_event(head_repo="someone/fork")) == 0
        assert api.requests_under("/issues/") == []
        assert api.summary_text().startswith(m.MARKER)
        assert any("fork" in line and "read-only" in line for line in api.logs)
        assert api.warnings == []

    def test_a_dependabot_pull_request_gets_the_comment(self, tmp_path):
        """GitHub gives a Dependabot run a read-only token only by default; these jobs
        ask for pull-requests: write, so the comment is written like any other. Before
        this change the script skipped a pull request by dependabot[bot] and wrote no
        comment."""
        api = _Publish(tmp_path)
        assert api.publish(final=True, event=_event(author="dependabot[bot]")) == 0
        assert api.api.count("POST", f"/repos/{REPO}/issues/1209/comments") == 1
        assert api.posted_body().startswith(m.MARKER)
        assert api.warnings == []

    def test_a_403_on_the_comment_write_is_one_warning_naming_the_status(
        self, tmp_path
    ):
        """Before this change a 403 on the write was only logged, with no warning."""
        api = _Publish(tmp_path)
        api.api.on(
            "POST", f"/repos/{REPO}/issues/1209/comments", m.Response(403, {}, b"{}")
        )
        assert api.publish(final=True) == 0
        assert len(api.warnings) == 1 and "403" in api.warnings[0]
        assert api.summary_text().startswith(m.MARKER)

    def test_another_failure_on_the_comment_write_is_a_warning_and_exit_0(
        self, tmp_path
    ):
        api = _Publish(tmp_path)
        api.api.on(
            "POST", f"/repos/{REPO}/issues/1209/comments", m.Response(422, {}, b"{}")
        )
        assert api.publish(final=True) == 0
        assert len(api.warnings) == 1 and "422" in api.warnings[0]

    @pytest.mark.parametrize(
        ("existing", "attempt", "patched"),
        [
            ((3481, 1), 1, False),  # a later run is left alone
            ((3480, 2), 1, False),  # the same run, a later attempt, too
            ((3480, 1), 1, True),  # the same run and attempt is this run's own table
            ((3480, 1), 2, True),  # the same run, an earlier attempt, is replaced
            ((3479, 9), 1, True),  # an earlier run is replaced whatever its attempt
        ],
    )
    def test_a_comment_that_shows_a_later_run_is_left_alone(
        self, tmp_path, existing, attempt, patched
    ):
        """The fixture run is number 3480, attempt 1 unless the case says otherwise."""
        run = dict(
            _run(COMPLETED), status="in_progress", conclusion=None, run_attempt=attempt
        )
        api = _Publish(tmp_path, run=run, comments=[_marked(*existing)])
        assert api.publish(final=False) == 0
        assert len(api.requests_under("/issues/comments/77")) == int(patched)
        assert any("later than this run" in line for line in api.logs) is (not patched)

    def test_a_comment_with_no_run_line_counts_as_older(self, tmp_path):
        bare = _marked(9999, 9)
        bare["body"] = m.MARKER + "\nold table\n"
        api = _Publish(tmp_path, comments=[bare])
        assert api.publish(final=False) == 0
        assert len(api.requests_under("/issues/comments/77")) == 1

    def test_with_two_marked_comments_the_oldest_is_edited_and_the_count_logged(
        self, tmp_path
    ):
        api = _Publish(tmp_path, comments=[_marked(1, 1, 90), _marked(1, 1, 77)])
        assert api.publish(final=False) == 0
        assert len(api.requests_under("/issues/comments/77")) == 1
        assert api.requests_under("/issues/comments/90") == []
        assert any("2 comments" in line for line in api.logs)

    @pytest.mark.parametrize("event_name", ["push", "merge_group"])
    def test_a_run_with_no_pull_request_writes_only_the_summary(
        self, tmp_path, event_name
    ):
        run = dict(
            _run(COMPLETED), status="in_progress", conclusion=None, event=event_name
        )
        api = _Publish(tmp_path, run=run)
        assert api.publish(final=True, event={}, event_name=event_name) == 0
        assert api.requests_under("/issues/") == []
        assert api.summary_text().startswith(m.MARKER)
        assert any("no pull request" in line for line in api.logs)

    def test_the_workflow_is_read_from_the_runs_own_commit(self, tmp_path):
        api = _Publish(tmp_path)
        assert api.publish(final=False) == 0
        (call,) = api.requests_under("/contents/")
        parts = urllib.parse.urlsplit(call[1])
        assert parts.path == (
            f"/repos/{REPO}/contents/.github/workflows/ash-unified-ci.yml"
        )
        assert urllib.parse.parse_qs(parts.query) == {"ref": [SHA]}

    @pytest.mark.parametrize(
        "path",
        ["../x.yml", ".github/workflows/a/b.yml", "x.yml", ".github/workflows/a.txt"],
    )
    def test_a_workflow_path_outside_the_workflows_directory_is_refused(
        self, tmp_path, path
    ):
        api = _Publish(tmp_path)
        with pytest.raises(ValueError):
            m.fetch_workflow(_client(api.api), REPO, path, SHA)
        assert api.requests_under("/contents/") == []

    def test_a_job_still_running_when_the_final_link_starts_is_read_again(
        self, tmp_path
    ):
        done = _jobs(COMPLETED) + _post_jobs(COMPLETED)
        early = [
            dict(j, status="in_progress", conclusion=None)
            if j["id"] == done[0]["id"]
            else j
            for j in done
        ]
        api = _Publish(tmp_path, reads=[early, done])
        assert api.publish(final=True) == 0
        assert api.sleeps == [m.SETTLE_SECONDS]
        assert len(api.requests_under(f"/actions/runs/{COMPLETED}/jobs")) == 2
        _assert_census(
            api.posted_body(),
            _expected_icons(_model(), _jobs(COMPLETED), _run(COMPLETED)),
        )

    def test_a_job_that_never_finishes_stops_the_settle_and_is_drawn_running(
        self, tmp_path
    ):
        done = _jobs(COMPLETED) + _post_jobs(COMPLETED)
        stuck = [
            dict(j, status="in_progress", conclusion=None)
            if j["id"] == done[0]["id"]
            else j
            for j in done
        ]
        api = _Publish(tmp_path, reads=[stuck])
        assert api.publish(final=True) == 0
        assert api.sleeps == [m.SETTLE_SECONDS] * m.SETTLE_READS
        assert (
            len(api.requests_under(f"/actions/runs/{COMPLETED}/jobs"))
            == 1 + m.SETTLE_READS
        )
        assert _table_icons(api.posted_body())[m.RUNNING.icon] >= 1

    @pytest.mark.parametrize(
        ("other", "shown"),
        [("success", "unknown"), ("failure", "failure"), ("cancelled", "cancelled")],
    )
    def test_a_job_that_never_finishes_leaves_only_a_success_unknown(
        self, tmp_path, other, shown
    ):
        """A job still unfinished at the last read could end any way, so the header does
        not call the run a success; a failed or cancelled job elsewhere still decides
        the conclusion, and a note says why. Before this change the first case read
        ``completed: success`` while that job's cell was drawn running."""
        jobs = [
            dict(j, status="completed", conclusion="success") for j in _jobs(COMPLETED)
        ]
        jobs[0] = dict(jobs[0], status="in_progress", conclusion=None)
        jobs[1] = dict(jobs[1], conclusion=other)
        api = _Publish(tmp_path, reads=[jobs + _post_jobs(COMPLETED)])
        assert api.publish(final=True) == 0
        body = api.posted_body()
        assert f"**`completed: {shown}`**" in body
        assert "completed: success" not in body
        assert api.sleeps == [m.SETTLE_SECONDS] * m.SETTLE_READS
        assert any("still read unfinished" in warning for warning in api.warnings)

    def test_an_intermediate_link_does_not_wait_for_a_running_job(self, tmp_path):
        done = _jobs(COMPLETED) + _post_jobs(COMPLETED)
        stuck = [
            dict(j, status="in_progress", conclusion=None)
            if j["id"] == done[0]["id"]
            else j
            for j in done
        ]
        api = _Publish(tmp_path, reads=[stuck])
        assert api.publish(final=False) == 0
        assert api.sleeps == []
        assert len(api.requests_under(f"/actions/runs/{COMPLETED}/jobs")) == 1

    def test_reads_that_keep_failing_warn_and_never_fail_the_run(
        self, tmp_path, capsys
    ):
        api = _Publish(tmp_path)
        api.api.on(
            "GET", f"/repos/{REPO}/actions/runs/{COMPLETED}", m.Response(500, {}, b"")
        )
        code = m.publish(
            _client(api.api, []),
            repo=REPO,
            run_id=COMPLETED,
            event_name="pull_request",
            event=_event(),
            workflow_sha=SHA,
            final=True,
            summary_path=str(api.summary),
            log=api.logs.append,
            sleep=api.sleeps.append,
        )
        assert code == 0
        out = capsys.readouterr().out
        assert out.startswith("::warning title=Unified CI matrix comment::")
        assert "could not be built" in api.summary_text()
        assert api.requests_under("/issues/") == []

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(
                lambda: http.client.IncompleteRead(b"half a header"),
                id="IncompleteRead",
            ),
            pytest.param(lambda: ssl.SSLError("bad record mac"), id="SSLError"),
        ],
    )
    def test_a_log_read_that_breaks_mid_response_costs_only_the_runner_headers(
        self, tmp_path, monkeypatch, make_error
    ):
        """``read()`` raises IncompleteRead when a body ends early and SSLError when the
        TLS stream breaks. Neither was a TransientError, so one such log read ended the
        publish before any table was written. Now the transport turns both into one, and
        the publish skips that label's header, says so in the log, and writes the rest."""
        api = _Publish(tmp_path)
        opener = _Opener(api.api, "logs.example.invalid", make_error)
        monkeypatch.setattr(m.urllib.request, "build_opener", lambda *handlers: opener)
        client = m.GitHubClient(
            "t0ken", transport=m.urllib_transport, sleep=lambda seconds: None
        )
        assert api.publish(final=True, client=client) == 0
        assert api.api.count("POST", f"/repos/{REPO}/issues/1209/comments") == 1
        assert api.summary_text().startswith(m.MARKER)
        assert any("could not read the runner header" in line for line in api.logs)
        assert api.warnings == []

    def test_a_write_to_the_summary_that_fails_is_a_warning_too(self, tmp_path):
        api = _Publish(tmp_path)
        api.summary = tmp_path / "missing-directory" / "summary.md"
        assert api.publish(final=True) == 0
        assert any("job summary" in w for w in api.warnings)

    def test_control_without_the_discovery_a_publishing_job_lands_under_other_jobs(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(m, "post_job_ids", lambda workflow: [])
        api = _Publish(tmp_path)
        assert api.publish(final=False) == 0
        # With the discovery off, the job is a cell of the model like any other, and the
        # table names it: the check that no publishing job is drawn can therefore fail.
        assert "matrix comment (checks)" in api.posted_body()

    @pytest.mark.parametrize(
        ("conclusions", "expected"),
        [
            (["success", "skipped"], "success"),
            (["success", "cancelled"], "cancelled"),
            # A cancelled job outranks a failed one, as on two push runs of main (the
            # note on the matrix-comment jobs). Before this change the order was failure
            # first, and this case read failure.
            (["success", "failure", "cancelled"], "cancelled"),
            (["success", "failure"], "failure"),
            (["timed_out"], "failure"),
            (["startup_failure", "success"], "failure"),
            ([None, "success"], "success"),
        ],
    )
    def test_the_run_conclusion_is_derived_from_its_jobs(self, conclusions, expected):
        jobs = [{"conclusion": c} for c in conclusions]
        assert m.derived_conclusion(jobs) == expected

    def test_a_publishing_job_that_failed_does_not_count_toward_the_conclusion(
        self, tmp_path
    ):
        """The four jobs carry continue-on-error, so one that failed leaves the run
        green; the table must not read it as a failure either."""
        ok = [
            dict(j, status="completed", conclusion="success") for j in _jobs(COMPLETED)
        ]
        failed_posts = [
            dict(j, status="completed", conclusion="failure")
            for j in _post_jobs(COMPLETED)
        ]
        api = _Publish(tmp_path, reads=[ok + failed_posts])
        assert api.publish(final=True) == 0
        assert "**`completed: success`**" in api.posted_body()

    def test_a_missing_variable_is_a_warning_and_exit_0(self, capsys):
        assert m.main(["publish", "--final"], {}) == 0
        out = capsys.readouterr().out
        assert out.startswith("::warning title=Unified CI matrix comment::")
        assert "GITHUB_TOKEN" in out

    def test_an_error_text_cannot_start_a_workflow_command(
        self, capsys, tmp_path, monkeypatch
    ):
        def hostile(*args, **kwargs):
            raise ValueError("::error::x\n::warning::y")

        monkeypatch.setattr(m, "fetch_workflow", hostile)
        api = _Publish(tmp_path)
        m.publish(
            _client(api.api, []),
            repo=REPO,
            run_id=COMPLETED,
            event_name="pull_request",
            event=_event(),
            workflow_sha=SHA,
            final=False,
            log=api.logs.append,
        )
        lines = capsys.readouterr().out.splitlines()
        assert len(lines) == 1 and lines[0].startswith(m.WARNING_PREFIX)
        assert "::" not in lines[0][len(m.WARNING_PREFIX) :]


class _Clock:
    """A clock the test moves by hand, in place of time.monotonic."""

    def __init__(self, now: float = 0.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


class TestTheTimeBudget:
    """A job that reaches its timeout is cancelled, and one cancelled job turns the run's
    conclusion to cancelled, so one publish run keeps to a wall-clock budget."""

    PATH = f"/repos/{REPO}/actions/runs/1"

    def _client(self, api, sleeps, clock):
        return m.GitHubClient("t0ken", transport=api, sleep=sleeps.append, clock=clock)

    def test_a_retry_that_would_end_past_the_budget_raises_at_once_and_sleeps_not_at_all(
        self,
    ):
        """Without a budget the client slept the whole retry-after (up to 120 s), however
        little time the job had left."""
        api = FakeAPI()
        api.on("GET", self.PATH, m.Response(429, {"retry-after": "90"}, b""), _ok({}))
        sleeps: list = []
        client = self._client(api, sleeps, _Clock())
        client.start_budget(60)
        with pytest.raises(m.TransientError, match="time budget"):
            client.get_json(self.PATH)
        assert sleeps == [] and len(api.calls) == 1

    def test_control_the_same_wait_is_slept_inside_a_budget_that_holds_it(self):
        api = FakeAPI()
        api.on("GET", self.PATH, m.Response(429, {"retry-after": "90"}, b""), _ok({}))
        sleeps: list = []
        client = self._client(api, sleeps, _Clock())
        client.start_budget(120)
        assert client.get_json(self.PATH) == {}
        assert sleeps == [90.0]

    def test_a_request_after_the_deadline_is_refused_before_it_is_sent(self):
        """The client has a deadline: past it no request is sent. Without one it would
        send every request however late."""
        api = FakeAPI()
        api.on("GET", self.PATH, _ok({}))
        clock = _Clock()
        client = self._client(api, [], clock)
        client.start_budget(60)
        clock.now = 61.0
        with pytest.raises(m.TransientError, match="time budget"):
            client.get_json(self.PATH)
        assert api.calls == []

    def test_with_the_budget_spent_the_runner_log_heads_are_not_read(self, tmp_path):
        """With no time left the reads stop. Without the check the loop read a log head
        per label whatever the time."""
        api = _Publish(tmp_path)
        client = _client(api.api, [])
        client.start_budget(0)
        assert m.read_runner_facts(client, REPO, _jobs(COMPLETED), {}, {}, []) is False
        assert api.requests_under("/logs") == []

    def test_control_with_time_left_the_runner_log_heads_are_read(self, tmp_path):
        api = _Publish(tmp_path)
        client = _client(api.api, [])
        client.start_budget(300)
        facts: dict = {}
        assert (
            m.read_runner_facts(client, REPO, _jobs(COMPLETED), facts, {}, []) is True
        )
        assert api.requests_under("/logs") and facts

    def test_publish_with_the_budget_spent_prints_one_warning_and_returns_0(
        self, tmp_path
    ):
        """A budget of nothing ends the run at its first request, with one warning.
        Without a budget publish went on to read the run and the workflow."""
        api = _Publish(tmp_path)
        assert api.publish(final=True, budget_seconds=0) == 0
        assert len(api.warnings) == 1 and "time budget" in api.warnings[0]
        assert api.api.calls == []
        assert "could not be built" in api.summary_text()

    def test_the_settle_stops_when_less_time_is_left_than_one_wait_and_says_so_once(
        self, tmp_path
    ):
        """Without the check the settle slept three times whatever the time left."""
        done = _jobs(COMPLETED) + _post_jobs(COMPLETED)
        stuck = [
            dict(j, status="in_progress", conclusion=None)
            if j["id"] == done[0]["id"]
            else j
            for j in done
        ]
        api = _Publish(tmp_path, reads=[stuck])
        assert api.publish(final=True, budget_seconds=m.SETTLE_SECONDS - 2) == 0
        assert api.sleeps == []
        assert len(api.requests_under(f"/actions/runs/{COMPLETED}/jobs")) == 1
        assert len(api.warnings) == 1 and "job list" in api.warnings[0]

    def _timed(self, api, clock, step=0.0, jump_on_logs=0.0):
        """A client on ``clock`` whose every transport call moves the clock by ``step``,
        and whose log reads move it a further ``jump_on_logs``."""

        def transport(method, url, headers, body, max_bytes):
            clock.now += step
            if urllib.parse.urlsplit(url).path.endswith("/logs"):
                clock.now += jump_on_logs
            return api.api(method, url, headers, body, max_bytes)

        return m.GitHubClient(
            "t0ken", transport=transport, sleep=lambda seconds: None, clock=clock
        )

    @staticmethod
    def _labels() -> int:
        return len(
            {
                m.label_of(job)
                for job in _jobs(COMPLETED)
                if m.label_of(job)
                and job.get("status") == "completed"
                and job.get("runner_name")
                and job.get("steps")
            }
        )

    def test_the_header_reads_stop_with_the_reserve_left_and_the_write_still_goes_out(
        self, tmp_path
    ):
        """The clock moves 10 s per request. The run, the workflow and the job list take
        30 s of a 100 s budget, one runner header takes 20 more, and the next label finds
        50 s left, which is under the reserve: the reads stop, one warning says so, and
        the comment is still written. Before the reserve existed the loop went on until
        the budget was spent, the comment's own request was then refused, and the run
        printed two warnings and wrote nothing."""
        api = _Publish(tmp_path)
        client = self._timed(api, _Clock(), step=10.0)
        assert api.publish(final=True, client=client, budget_seconds=100) == 0
        assert len(api.requests_under("/logs")) == 1 < self._labels()
        assert api.api.count("POST", f"/repos/{REPO}/issues/1209/comments") == 1
        assert len(api.warnings) == 1
        assert "too little of the time budget was left" in api.warnings[0]
        assert "runner headers" in api.warnings[0]

    def test_a_deadline_passed_before_the_comment_step_skips_it_with_one_warning(
        self, tmp_path
    ):
        """The first log read jumps the clock 1,000 s, past the deadline. The reads then
        stop, and the comment step sends no request at all, so the run prints one
        warning. Before this change the comment's first request was refused by the
        client and raised a second warning."""
        api = _Publish(tmp_path)
        client = self._timed(api, _Clock(), jump_on_logs=1000.0)
        assert api.publish(final=True, client=client) == 0
        assert api.requests_under("/issues/") == []
        assert len(api.warnings) == 1
        assert "the comment was not written" in api.warnings[0]
        assert api.summary_text().startswith(m.MARKER)

    def test_control_with_enough_time_every_header_is_read_the_comment_is_written_and_nothing_warns(
        self, tmp_path
    ):
        api = _Publish(tmp_path)
        client = self._timed(api, _Clock())
        assert api.publish(final=True, client=client) == 0
        assert len(api.requests_under("/logs")) == self._labels()
        assert api.api.count("POST", f"/repos/{REPO}/issues/1209/comments") == 1
        assert api.warnings == []


# ---------------------------------------------------------------------------------------
# The live files
# ---------------------------------------------------------------------------------------


def _unified() -> dict:
    return yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))


def _needs_of(job: dict) -> list[str]:
    needs = job.get("needs") or []
    return [needs] if isinstance(needs, str) else list(needs)


def _squash(text: Any) -> str:
    return re.sub(r"\s+", "", str(text))


class TestTheLiveFiles:
    def test_the_current_unified_ci_matrix_expands_without_a_problem(self):
        workflow = _unified()
        model = _model(workflow)
        assert not [g.problems for g in model.groups if g.problems]
        assert sorted(j for g in model.groups for j in g.job_ids) == sorted(
            workflow["jobs"]
        )
        assert all(c.name for c in model.cells())
        assert len(model.cells()) == _independent_cell_count(workflow)

    def test_the_requirement_is_pinned_by_hash(self):
        lines = [
            line
            for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        assert len(lines) == 1
        assert re.match(r"pyyaml==[\d.]+ (--hash=sha256:[0-9a-f]{64} ?)+", lines[0])


#: The `if:` of the three links before the last, and of the last, with no whitespace.
_PULL_REQUEST_ONLY_IF = _squash(
    "${{ !cancelled() && github.event_name == 'pull_request' && "
    "github.event.pull_request.head.repo.full_name == github.repository }}"
)
#: The one job no link names: only the gate may wait for it, so that no test or scan job
#: has a serial link behind it. TestEnsureCache in test_unified_ci_job_counts.py pins it.
ENSURE_CACHE = "ensure-cache"
_EVERY_EVENT_IF = _squash("${{ !cancelled() }}")
_PUBLISH_STEP_ENV_VALUE = "${{ github.token }}"
_CHECKOUT_REF = (
    "${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha "
    "|| github.sha }}"
)


class TestTheLiveLinks:
    """The four publishing jobs, as ash-unified-ci.yml really declares them."""

    def test_the_script_finds_exactly_the_four_jobs_by_their_command(self):
        assert m.post_job_ids(_unified()) == LINKS

    def test_the_first_link_needs_no_link_and_each_other_needs_the_one_before(self):
        jobs = _unified()["jobs"]
        assert not set(_needs_of(jobs[LINKS[0]])) & set(LINKS)
        for previous, link in zip(LINKS, LINKS[1:]):
            assert previous in _needs_of(jobs[link]), link
            assert not set(_needs_of(jobs[link])) & (set(LINKS) - {previous}), link

    def test_the_last_link_reaches_every_other_job_through_needs(self):
        jobs = _unified()["jobs"]
        reached: set[str] = set()
        pending = list(_needs_of(jobs[LINKS[-1]]))
        while pending:
            job_id = pending.pop()
            if job_id not in reached:
                reached.add(job_id)
                pending.extend(_needs_of(jobs[job_id]))
        assert reached == set(jobs) - {LINKS[-1]}

    def test_the_needs_of_the_four_that_are_not_links_split_the_other_jobs(self):
        jobs = _unified()["jobs"]
        listed = [
            job_id
            for link in LINKS
            for job_id in _needs_of(jobs[link])
            if job_id not in LINKS
        ]
        # ensure-cache is the one job no link names (the constant says why); every other
        # job sits in exactly one link's needs.
        assert sorted(listed) == sorted(set(jobs) - set(LINKS) - {ENSURE_CACHE})

    def test_ensure_cache_is_in_no_links_needs_and_the_last_link_reaches_it_by_the_gate(
        self,
    ):
        """The first link used to list ensure-cache, which put a serial link under every
        job that waits for it; only the gate may wait for it."""
        jobs = _unified()["jobs"]
        for link in LINKS:
            assert ENSURE_CACHE not in _needs_of(jobs[link]), link
        assert ENSURE_CACHE in _needs_of(jobs["required-checks"])
        assert "required-checks" in _needs_of(jobs[LINKS[-1]])

    def test_every_link_carries_job_level_continue_on_error(self):
        """The steps around the script (checkout, interpreter, install) must not turn a
        run red. The links first had no continue-on-error, so a failed install failed the
        run."""
        jobs = _unified()["jobs"]
        for link in LINKS:
            assert jobs[link].get("continue-on-error") is True, link

    def test_every_step_has_its_own_limit_and_the_longest_path_fits_the_job(self):
        """A hung step must end before the job reaches its limit, because a job that
        reaches it is cancelled and one cancelled job turns the run's conclusion to
        cancelled. The say-so step runs only when the renderer is absent, which skips
        setup, install and publish, so the longest path is the larger of the two."""
        jobs = _unified()["jobs"]
        for link in LINKS:
            steps = jobs[link]["steps"]
            for step in steps:
                assert isinstance(step.get("timeout-minutes"), int), (link, step)
            say_so = [s for s in steps if "== ''" in str(s.get("if", ""))]
            main_path = [s for s in steps if s not in say_so]
            checkout = steps[0]["timeout-minutes"]
            longest = max(
                sum(s["timeout-minutes"] for s in main_path),
                checkout + sum(s["timeout-minutes"] for s in say_so),
            )
            assert longest < jobs[link]["timeout-minutes"], link

    def test_the_publish_step_limit_covers_the_budget_plus_a_minute(self):
        jobs = _unified()["jobs"]
        for link in LINKS:
            publish_step = jobs[link]["steps"][-1]
            assert PUBLISH_COMMAND in publish_step["run"], link
            assert (
                publish_step["timeout-minutes"] * 60 >= m.PUBLISH_BUDGET_SECONDS + 60
            ), link
        assert m.WRITE_RESERVE_SECONDS < m.PUBLISH_BUDGET_SECONDS

    def test_the_conditions_are_the_two_exact_strings(self):
        jobs = _unified()["jobs"]
        for link in LINKS[:-1]:
            assert _squash(jobs[link]["if"]) == _PULL_REQUEST_ONLY_IF, link
        assert _squash(jobs[LINKS[-1]]["if"]) == _EVERY_EVENT_IF
        # The gate keeps its own condition and does not wait for any link.
        assert not set(_needs_of(jobs["required-checks"])) & set(LINKS)

    def test_the_links_are_small_least_privileged_and_never_queue(self):
        jobs = _unified()["jobs"]
        for link in LINKS:
            job = jobs[link]
            assert job["runs-on"] == "ubuntu-slim", link
            assert job["timeout-minutes"] <= 10, link
            assert job["permissions"] == {
                "actions": "read",
                "contents": "read",
                "pull-requests": "write",
            }, link
            assert "concurrency" not in job, link

    def test_the_renderer_is_checked_out_from_the_base_branch_without_credentials(self):
        jobs = _unified()["jobs"]
        for link in LINKS:
            checkout = jobs[link]["steps"][0]
            assert checkout["uses"].startswith("actions/checkout@"), link
            assert checkout["with"]["ref"] == _CHECKOUT_REF, link
            assert checkout["with"]["persist-credentials"] is False, link
            assert checkout["with"]["sparse-checkout-cone-mode"] is False, link
            assert checkout["with"]["sparse-checkout"].split() == [
                ".github/scripts/unified-ci-matrix-comment.py",
                ".github/scripts/unified-ci-matrix-comment.requirements.txt",
            ], link

    def test_the_token_reaches_only_the_publish_step_and_no_run_reads_an_expression(
        self,
    ):
        jobs = _unified()["jobs"]
        for link in LINKS:
            job = jobs[link]
            assert "env" not in job and "secrets" not in str(job), link
            *others, publish_step = job["steps"]
            assert set(publish_step["env"]) == {"GITHUB_TOKEN"}, link
            assert publish_step["env"]["GITHUB_TOKEN"] == _PUBLISH_STEP_ENV_VALUE, link
            assert PUBLISH_COMMAND in publish_step["run"], link
            for step in others:
                assert "GITHUB_TOKEN" not in str(step), link
                assert "github.token" not in str(step), link
            for step in job["steps"]:
                assert "${{" not in str(step.get("run", "")), link

    def test_no_workflow_level_env_or_default_hands_the_token_or_a_secret_to_a_link(
        self,
    ):
        """A workflow-level ``env`` reaches every step of every job, the links' checkout
        and install steps included, and ``defaults`` shapes every ``run`` step. The token
        belongs to the publish step alone, as the test above pins for each job, so it
        and the secrets stay out of both. The names are read as a set and each value on
        its own, so a failure prints no whole mapping."""
        workflow = _unified()
        env = workflow.get("env") or {}
        names = set(env)
        assert "GITHUB_TOKEN" not in names
        for name in sorted(names):
            value = str(env[name])
            assert "github.token" not in value, name
            assert "secrets." not in value, name
        defaults = str(workflow.get("defaults") or {})
        assert "github.token" not in defaults
        assert "secrets." not in defaults

    def test_every_action_is_pinned_to_a_full_commit_sha(self):
        jobs = _unified()["jobs"]
        for link in LINKS:
            for step in jobs[link]["steps"]:
                if "uses" in step:
                    assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", step["uses"]), step[
                        "uses"
                    ]

    def test_only_the_last_link_passes_final(self):
        jobs = _unified()["jobs"]
        for link in LINKS:
            run = jobs[link]["steps"][-1]["run"].split()
            assert ("--final" in run) is (link == LINKS[-1]), link

    def test_the_workflow_is_not_started_by_workflow_run_or_pull_request_target(self):
        workflow = _unified()
        # PyYAML reads the bare key `on` as the boolean True.
        triggers = workflow.get(True, workflow.get("on"))
        assert triggers, "the workflow has no triggers"
        assert "workflow_run" not in triggers
        assert "pull_request_target" not in triggers

    def test_the_publishing_jobs_are_named_in_the_censuss_ungated_list(self):
        spec = importlib.util.spec_from_file_location(
            "_census",
            REPO_ROOT / ".github" / "scripts" / "assert-required-checks-census.py",
        )
        census = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(census)
        assert set(LINKS) <= set(census._UNGATED)
