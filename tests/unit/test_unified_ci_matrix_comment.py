"""The Unified CI matrix comment shows every cell, and nothing from a run can act as markup.

Why this file exists
--------------------
.github/scripts/unified-ci-matrix-comment.py keeps one comment on a pull request that
shows every cell of every matrix in ash-unified-ci.yml with the result of the job that
ran for it, and rewrites it while the run is in progress. Its job runs with a token that
can write pull-request comments, also for a pull request from a fork, and job names come
from the pull request's own copy of the workflow. So two properties matter more than the
layout: no cell may go missing (a cell the matrix leaves out has to read as excluded,
and a cell that should have run and did not has to read as not in the run), and no text
from the run may become a link, an image, a mention or a table cell of its own.

These tests run the script's functions in-process on responses captured from real runs.

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
markup check each have a test that hands them a body with one cell removed, or rendered
with the escaping switched off, and asserts that they fail.
"""

from __future__ import annotations

import copy
import importlib.util
import itertools
import json
import re
import sys
import urllib.parse
from collections import Counter
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / ".github" / "scripts" / "unified-ci-matrix-comment.py"
REQUIREMENTS = (
    REPO_ROOT / ".github" / "scripts" / "unified-ci-matrix-comment.requirements.txt"
)
UNIFIED_CI = REPO_ROOT / ".github" / "workflows" / "ash-unified-ci.yml"
COMMENT_WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "ash-unified-ci-matrix-comment.yml"
)
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
            _assert_census(body, _expected_icons(model, _jobs(run_id), _run(run_id)))

    def test_control_the_census_fails_when_one_cell_is_not_drawn(self):
        body = _render(COMPLETED)
        expected = _expected_icons(_model(), _jobs(COMPLETED), _run(COMPLETED))
        first_link = re.search(r"\[❌\]\([^)]*\)", body).group(0)
        with pytest.raises(AssertionError):
            _assert_census(body.replace(first_link, "", 1), expected)

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
# The API client, the comment and the watch loop, over a recording transport
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


def _budget(remaining: str, limit: str = "1000") -> dict:
    return {"x-ratelimit-limit": limit, "x-ratelimit-remaining": remaining}


def _client(api: FakeAPI, sleeps: list | None = None):
    return m.GitHubClient(
        "t0ken", transport=api, sleep=(sleeps if sleeps is not None else []).append
    )


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

    def test_the_last_api_response_says_how_much_budget_is_left(self):
        api = FakeAPI()
        path = f"/repos/{REPO}/actions/runs/1"
        api.on(
            "GET",
            path,
            _ok({}, headers=_budget("900")),
            _ok({}, headers=_budget("?")),
            _ok({}, headers=_budget("0", limit="0")),
            _ok({}, headers=_budget("100")),
        )
        client = _client(api)
        assert client.budget_share() is None
        client.get_json(path)
        assert client.budget_share() == 0.9
        # An unreadable header, or a limit of nothing, leaves the last reading.
        client.get_json(path)
        client.get_json(path)
        assert client.budget_share() == 0.9
        client.get_json(path)
        assert client.budget_share() == 0.1


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


class TestThePullRequest:
    def test_a_fork_pull_request_is_found_by_its_head(self):
        run = {"head_branch": "main", "head_repository": {"full_name": "someone/fork"}}
        api = FakeAPI()
        api.on(
            "GET",
            f"/repos/{REPO}/pulls",
            _ok(
                [
                    {
                        "number": 3,
                        "head": {"ref": "main", "repo": {"full_name": "someone/fork"}},
                    },
                    {
                        "number": 4,
                        "head": {"ref": "main", "repo": {"full_name": "other/fork"}},
                    },
                ]
            ),
        )
        assert [p["number"] for p in m.pull_requests_for(_client(api), REPO, run)] == [
            3
        ]
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(api.calls[0][1]).query)
        assert query["head"] == ["someone:main"] and query["state"] == ["open"]

    def test_the_newest_run_of_the_head_is_the_one_shown(self):
        run = {"id": 1, "run_number": 5, "head_sha": "a" * 40, "workflow_id": 9}
        api = FakeAPI()
        api.on(
            "GET",
            f"/repos/{REPO}/actions/workflows/9/runs",
            _ok({"workflow_runs": [{"id": 2, "run_number": 6, "head_sha": "b" * 40}]}),
        )
        assert m.latest_run(_client(api), REPO, run, "b" * 40)["id"] == 2
        assert m.latest_run(_client(api), REPO, run, "a" * 40)["id"] == 1


class TestTheWatch:
    def _api(self, runs, job_pages):
        completed = _run(COMPLETED)
        api = FakeAPI()
        api.on("GET", f"/repos/{REPO}/pulls", _ok([_pull(completed)]))
        api.on(
            "GET",
            f"/repos/{REPO}/actions/workflows/{completed['workflow_id']}/runs",
            _ok({"workflow_runs": [completed]}),
        )
        api.on(
            "GET", f"/repos/{REPO}/actions/runs/{COMPLETED}", *[_ok(r) for r in runs]
        )
        api.on(
            "GET",
            f"/repos/{REPO}/actions/runs/{COMPLETED}/jobs",
            *[_ok(p) for p in job_pages],
        )
        api.on("GET", f"/repos/{REPO}/issues/1209/comments", _ok([]))
        api.on(
            "POST", f"/repos/{REPO}/issues/1209/comments", _ok({"id": 77}, status=201)
        )
        api.on("PATCH", f"/repos/{REPO}/issues/comments/77", _ok({}))
        header = (DATA / "job-140071768606-log-head.txt").read_bytes()
        api.routes[("GET", "logs.example.invalid")] = [m.Response(206, {}, header)]
        for job in _jobs(COMPLETED):
            api.on(
                "GET",
                f"/repos/{REPO}/actions/jobs/{job['id']}/logs",
                m.Response(302, {"location": "https://logs.example.invalid/l"}, b""),
            )
        return api

    def _watch(self, api, sleeps, event_run=None, max_failures=5):
        clock = itertools.count(0, 45)
        return m.watch(
            _client(api, []),
            repo=REPO,
            event_run=event_run or _run(COMPLETED),
            workflow=_fixture_workflow(),
            workflow_path=".github/workflows/ash-unified-ci.yml",
            default_branch="main",
            source="x",
            poll_seconds=45,
            deadline_seconds=3600,
            log=lambda line: None,
            sleep=sleeps.append,
            now=lambda: next(clock),
            max_failures=max_failures,
        )

    def test_the_comment_follows_the_run_to_its_end(self):
        final = _jobs(COMPLETED)
        middle = [
            dict(j, status="in_progress", conclusion=None)
            if j["name"].startswith("unit-test")
            else j
            for j in final
        ]
        running = dict(_run(COMPLETED), status="in_progress", conclusion=None)
        api = self._api([running, _run(COMPLETED)], [{"jobs": middle}, {"jobs": final}])
        sleeps: list = []
        assert self._watch(api, sleeps) == 0
        assert sleeps == [45]
        assert api.count("POST", f"/repos/{REPO}/issues/1209/comments") == 1
        patches = [c for c in api.calls if c[0] == "PATCH"]
        assert len(patches) == 1
        last = json.loads(patches[0][3])["body"]
        assert "**`completed: failure`**" in last
        _assert_census(last, _expected_icons(_model(), final, _run(COMPLETED)))
        assert "| `ubuntu-24.04-arm` | `ubuntu-24.04-arm` `20261116.188.1` " in last

    @pytest.mark.parametrize(
        ("remaining", "wait"), [("249", 180), ("250", 45), ("900", 45)]
    )
    def test_a_low_request_budget_slows_the_poll(self, remaining, wait):
        """The token's hourly budget is the whole repository's: under a quarter of it
        left, the watcher reads four times less often so other workflows keep theirs."""
        running = dict(_run(COMPLETED), status="in_progress", conclusion=None)
        api = self._api([running, _run(COMPLETED)], [{"jobs": _jobs(COMPLETED)}])
        api.on(
            "GET",
            f"/repos/{REPO}/actions/runs/{COMPLETED}",
            _ok(running, headers=_budget(remaining)),
            _ok(_run(COMPLETED), headers=_budget(remaining)),
        )
        sleeps: list = []
        assert self._watch(api, sleeps) == 0
        assert sleeps == [wait]

    def test_a_run_that_is_not_for_a_pull_request_reads_nothing(self):
        api = FakeAPI()
        assert self._watch(api, [], event_run=dict(_run(COMPLETED), event="push")) == 0
        assert api.calls == []

    def test_a_stale_head_with_no_run_of_its_own_writes_nothing(self):
        api = self._api([_run(COMPLETED)], [{"jobs": []}])
        api.on(
            "GET",
            f"/repos/{REPO}/pulls",
            _ok(
                [
                    dict(
                        _pull(_run(COMPLETED)),
                        head={
                            "ref": _run(COMPLETED)["head_branch"],
                            "sha": "c" * 40,
                            "repo": {"full_name": REPO},
                        },
                    )
                ]
            ),
        )
        api.on(
            "GET",
            f"/repos/{REPO}/actions/workflows/{_run(COMPLETED)['workflow_id']}/runs",
            _ok({"workflow_runs": []}),
        )
        assert self._watch(api, []) == 0
        assert api.count("POST", f"/repos/{REPO}/issues/1209/comments") == 0

    def test_reads_that_keep_failing_end_the_job_red(self):
        api = self._api([_run(COMPLETED)], [{"jobs": []}])
        api.on(
            "GET", f"/repos/{REPO}/actions/runs/{COMPLETED}", m.Response(500, {}, b"")
        )
        sleeps: list = []
        assert self._watch(api, sleeps, max_failures=2) == 1
        assert len(sleeps) == 1


# ---------------------------------------------------------------------------------------
# The live files
# ---------------------------------------------------------------------------------------


class TestTheLiveFiles:
    def test_the_current_unified_ci_matrix_expands_without_a_problem(self):
        workflow = yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))
        model = _model(workflow)
        assert not [g.problems for g in model.groups if g.problems]
        assert sorted(j for g in model.groups for j in g.job_ids) == sorted(
            workflow["jobs"]
        )
        assert all(c.name for c in model.cells())
        assert len(model.cells()) == _independent_cell_count(workflow)

    def test_the_comment_workflow_listens_to_the_unified_ci_workflow_by_its_name(self):
        unified = yaml.safe_load(UNIFIED_CI.read_text(encoding="utf-8"))
        comment = yaml.safe_load(COMMENT_WORKFLOW.read_text(encoding="utf-8"))
        trigger = comment[True]["workflow_run"]
        assert trigger["workflows"] == [unified["name"]]
        assert trigger["types"] == ["requested", "completed"]

    def test_the_comment_workflow_runs_nothing_from_the_pull_request(self):
        comment = yaml.safe_load(COMMENT_WORKFLOW.read_text(encoding="utf-8"))
        assert set(comment[True]) == {"workflow_run"}
        assert comment["permissions"] == {}
        (job,) = comment["jobs"].values()
        assert job["permissions"] == {
            "actions": "read",
            "contents": "read",
            "pull-requests": "write",
        }
        for clause in (
            "github.repository == 'awslabs/automated-security-helper'",
            "github.event.workflow_run.event == 'pull_request'",
            "github.event.workflow_run.path == '.github/workflows/ash-unified-ci.yml'",
        ):
            assert clause in job["if"]
        checkout = job["steps"][0]
        assert checkout["uses"].startswith("actions/checkout@")
        assert checkout["with"]["ref"] == "${{ github.sha }}"
        assert checkout["with"]["persist-credentials"] is False
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", step["uses"]), step[
                    "uses"
                ]
            assert "${{" not in str(step.get("run", "")), (
                "a run script reads no expression"
            )

    def test_the_requirement_is_pinned_by_hash(self):
        lines = [
            line
            for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        assert len(lines) == 1
        assert re.match(r"pyyaml==[\d.]+ (--hash=sha256:[0-9a-f]{64} ?)+", lines[0])
