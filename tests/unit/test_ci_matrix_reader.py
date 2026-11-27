"""The shared CI matrix reader (scripts/_ci_matrix.py) reads a workflow the way GitHub does.

Four test modules used to expand a job's matrix each their own way. These tests hold the
one reader they now share to GitHub's rules on planted workflows, so a change to the
reader fails here and not as a moved leg count in some other module. They also hold what
the reader refuses to a named error: an expression it does not know, a condition it
cannot evaluate and a runner label that is not in its table are never read as a match,
as true, or as a known runner.
"""

from __future__ import annotations

import ast
import copy
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
MODULE = REPO_ROOT / "scripts" / "_ci_matrix.py"


def _workflow_files(directory: Path) -> list[Path]:
    """The workflow files directly under ``directory``: GitHub reads both extensions."""
    found = [*directory.glob("*.yml"), *directory.glob("*.yaml")]
    return sorted(path for path in found if path.is_file())


WORKFLOW_FILES = _workflow_files(WORKFLOWS)


def _load() -> Any:
    """scripts/_ci_matrix.py, loaded by path under a name of its own for this file, so the
    modules that share the reader under another name do not share this copy.

    The helper is imported here and not at the top, so a broken helper fails the tests
    that use it with its own error and not this whole file at collection."""
    from tests.utils.ci_matrix_loader import load_by_path

    return load_by_path("_ash_ci_matrix_under_test", MODULE)


class _Reader:
    """The module under test, loaded on first use, so a missing or broken module fails
    each test with its own error and not once at collection."""

    def __getattr__(self, name: str) -> Any:
        return getattr(_load(), name)


ci = _Reader()


def _job(matrix: dict[str, Any] | None = None, **fields: Any) -> dict[str, Any]:
    job: dict[str, Any] = {"runs-on": "ubuntu-latest", **fields}
    if matrix is not None:
        job["strategy"] = {"matrix": matrix}
    return job


def _overlay(value: str) -> str:
    """The one event-conditioned matrix entry the workflows use."""
    return "${{ github.event_name == 'pull_request' && '" + value + "' || '' }}"


PLANTED = """\
name: planted
on:
  pull_request:
    paths:
      - "docs/**"
  workflow_dispatch:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""


class TestLoadingAWorkflow:
    def test_a_plain_on_key_reads_as_on_and_not_true(self):
        workflow = ci.parse_workflow(PLANTED)
        assert "on" in workflow
        assert True not in workflow
        # The control: the loader a test would otherwise reach for reads it as True.
        assert True in yaml.safe_load(PLANTED)

    def test_the_events_and_the_path_filter_are_read(self):
        found = ci.triggers(ci.parse_workflow(PLANTED))
        assert set(found) == {"pull_request", "workflow_dispatch"}
        assert found["pull_request"].path_filtered is True
        assert found["workflow_dispatch"].path_filtered is False

    @pytest.mark.parametrize(
        "on, events",
        [
            ("push", {"push"}),
            ("[push, pull_request]", {"push", "pull_request"}),
        ],
    )
    def test_the_short_forms_of_on_name_their_events(self, on, events):
        text = f"on: {on}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
        found = ci.triggers(ci.parse_workflow(text))
        assert set(found) == events
        assert not [t for t in found.values() if t.path_filtered]

    def test_paths_ignore_filters_and_an_empty_filter_does_not(self):
        text = (
            "on:\n  push:\n    paths-ignore: ['docs/**']\n  pull_request:\n"
            "    paths: []\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
        )
        found = ci.triggers(ci.parse_workflow(text))
        assert found["push"].path_filtered is True
        assert found["pull_request"].path_filtered is False

    def test_a_document_read_with_yaml_safe_load_is_refused_by_triggers(self):
        with pytest.raises(ci.WorkflowError, match="load_workflow"):
            ci.triggers(yaml.safe_load(PLANTED))

    @pytest.mark.parametrize(
        "text, why",
        [
            ("jobs: [unclosed\n", "does not parse"),
            ("name: no jobs\non: push\n", "no jobs mapping"),
            ("", "not one YAML mapping"),
            ("on: push\njobs: {}\n---\non: push\njobs: {}\n", "not one YAML mapping"),
            ("- a\n- b\n", "not one YAML mapping"),
        ],
    )
    def test_a_workflow_that_is_not_one_mapping_with_jobs_is_refused(self, text, why):
        with pytest.raises(ci.WorkflowError, match=why) as caught:
            ci.parse_workflow(text, source="the planted file")
        assert "the planted file" in str(caught.value)

    def test_load_workflow_reads_a_file_and_names_it_in_a_refusal(self, tmp_path):
        good = tmp_path / "good.yml"
        good.write_text(PLANTED, encoding="utf-8")
        assert ci.load_workflow(good) == ci.parse_workflow(PLANTED)
        bad = tmp_path / "bad.yml"
        bad.write_text("jobs: [unclosed\n", encoding="utf-8")
        with pytest.raises(ci.WorkflowError, match="bad.yml"):
            ci.load_workflow(bad)


class TestExpansion:
    def test_a_job_without_a_matrix_is_one_empty_leg(self):
        assert ci.cells({"runs-on": "ubuntu-latest"}) == [{}]
        assert ci.cells(_job({})) == [{}]

    def test_the_axes_multiply_in_the_order_written(self):
        job = _job({"os": ["a", "b"], "py": ["1", "2"]})
        assert ci.cells(job) == [
            {"os": "a", "py": "1"},
            {"os": "a", "py": "2"},
            {"os": "b", "py": "1"},
            {"os": "b", "py": "2"},
        ]

    def test_an_exclude_drops_the_cells_it_matches(self):
        matrix = {"os": ["a", "b"], "py": ["1", "2"]}
        whole = _job({**matrix, "exclude": [{"os": "a", "py": "2"}]})
        assert ci.cells(whole) == [
            {"os": "a", "py": "1"},
            {"os": "b", "py": "1"},
            {"os": "b", "py": "2"},
        ]
        partial = _job({**matrix, "exclude": [{"os": "b"}]})
        assert ci.cells(partial) == [{"os": "a", "py": "1"}, {"os": "a", "py": "2"}]

    def test_one_flipped_exclude_changes_the_count(self):
        """The must-flag control: an exclude that stops matching puts its cell back."""
        matrix = {"os": ["a", "b", "c"], "py": ["1", "2"]}
        base = _job({**matrix, "exclude": [{"os": "a", "py": "1"}]})
        flipped = _job({**matrix, "exclude": [{"os": "z", "py": "1"}]})
        assert len(ci.cells(base)) == 5
        assert len(ci.cells(flipped)) == 6
        back = [cell for cell in ci.cells(flipped) if cell not in ci.cells(base)]
        assert back == [{"os": "a", "py": "1"}]

    @pytest.mark.parametrize(
        "event, legs",
        [
            ("push", 2),
            ("merge_group", 2),
            ("workflow_dispatch", 2),
            ("pull_request", 1),
        ],
    )
    def test_an_overlay_drops_a_cell_only_on_a_pull_request(self, event, legs):
        job = _job({"os": ["a", "b"], "exclude": [{"os": _overlay("a")}]})
        assert len(ci.cells(job, event)) == legs
        if event == "pull_request":
            assert ci.cells(job, event) == [{"os": "b"}]

    def test_an_entry_with_one_void_value_matches_nothing(self):
        matrix = {
            "os": ["a", "b"],
            "py": ["1", "2"],
            "exclude": [{"os": _overlay("a"), "py": "1"}],
        }
        job = _job(matrix)
        # Off a pull request the os value is void, so the entry drops nothing at all,
        # not even the cells its py value alone would match.
        assert len(ci.cells(job, "push")) == 4
        assert ci.cells(job, "pull_request") == [
            {"os": "a", "py": "2"},
            {"os": "b", "py": "1"},
            {"os": "b", "py": "2"},
        ]

    def test_resolve_overlay_reads_the_one_shape_and_leaves_the_rest(self):
        expression = _overlay("ubuntu-latest")
        assert ci.resolve_overlay(expression, "pull_request") == "ubuntu-latest"
        assert ci.resolve_overlay(expression, "push") is None
        assert ci.resolve_overlay(expression, "merge_group") is None
        assert ci.resolve_overlay("ubuntu-latest", "push") == "ubuntu-latest"
        assert ci.resolve_overlay(3, "pull_request") == 3
        assert ci.PULL_REQUEST_OVERLAY.match(expression)

    def test_an_include_merges_into_every_cell_it_matches(self):
        job = _job(
            {
                "os": ["a", "b"],
                "py": ["1", "2"],
                "include": [{"os": "a", "extra": True}],
            }
        )
        assert ci.cells(job) == [
            {"os": "a", "py": "1", "extra": True},
            {"os": "a", "py": "2", "extra": True},
            {"os": "b", "py": "1"},
            {"os": "b", "py": "2"},
        ]

    def test_an_include_that_matches_no_cell_is_a_cell_of_its_own(self):
        job = _job(
            {
                "os": ["a", "b"],
                "include": [{"os": "a", "extra": 1}, {"os": "c"}],
            }
        )
        assert ci.cells(job) == [
            {"os": "a", "extra": 1},
            {"os": "b"},
            {"os": "c"},
        ]

    def test_an_include_cannot_overwrite_an_axis_value(self):
        job = _job({"os": ["a"], "py": ["1"], "include": [{"os": "a", "py": "9"}]})
        assert ci.cells(job) == [{"os": "a", "py": "1"}, {"os": "a", "py": "9"}]

    def test_a_later_include_overwrites_a_value_an_earlier_one_added(self):
        job = _job(
            {
                "os": ["a"],
                "include": [{"os": "a", "extra": 1}, {"os": "a", "extra": 2}],
            }
        )
        assert ci.cells(job) == [{"os": "a", "extra": 2}]

    def test_an_exclude_runs_before_an_include(self):
        job = _job(
            {
                "os": ["a", "b"],
                "exclude": [{"os": "a"}],
                "include": [{"os": "a", "extra": 1}],
            }
        )
        assert ci.cells(job) == [{"os": "b"}, {"os": "a", "extra": 1}]

    def test_a_matrix_of_includes_alone_is_those_entries(self):
        job = _job({"include": [{"os": "a"}, {"os": "b", "x": 1}]})
        assert ci.cells(job) == [{"os": "a"}, {"os": "b", "x": 1}]

    def test_expanding_changes_nothing_it_was_given(self):
        job = _job(
            {
                "os": ["a", "b"],
                "exclude": [{"os": _overlay("a")}],
                "include": [{"os": "a", "extra": 1}, {"os": "c"}],
            }
        )
        before = copy.deepcopy(job)
        for event in ("push", "pull_request"):
            for cell in ci.cells(job, event):
                cell["touched"] = True
        assert job == before

    def test_an_unknown_event_is_refused_and_not_read_as_the_static_matrix(self):
        job = _job({"os": ["a", "b"], "exclude": [{"os": _overlay("a")}]})
        with pytest.raises(ValueError, match="pull-request"):
            ci.cells(job, "pull-request")
        with pytest.raises(ValueError, match="schedule"):
            ci.resolve_overlay(_overlay("a"), "schedule")

    def test_axis_cells_is_the_product_less_the_excludes_and_nothing_more(self):
        matrix = {
            "os": ["a", "b"],
            "exclude": [{"os": _overlay("a")}],
            "include": [{"os": "c"}],
        }
        assert ci.axis_cells(matrix, "push") == [{"os": "a"}, {"os": "b"}]
        assert ci.axis_cells(matrix, "pull_request") == [{"os": "b"}]
        assert ci.axis_cells({"include": [{"os": "c"}]}) == []
        assert ci.axis_cells({}) == []

    def test_a_planted_workflow_text_expands_per_event(self):
        text = (
            "on: [push, pull_request]\n"
            "jobs:\n"
            "  legs:\n"
            "    runs-on: ${{ matrix.os }}\n"
            "    strategy:\n"
            "      matrix:\n"
            "        os: [ubuntu-latest, macos-15]\n"
            '        python-version: ["3.11", "3.12"]\n'
            "        exclude:\n"
            "          - os: ${{ github.event_name == 'pull_request' && 'macos-15' || '' }}\n"
            "          - python-version: ${{ github.event_name == 'pull_request' && '3.11' || '' }}\n"
            "    steps:\n"
            "      - run: echo hi\n"
        )
        job = ci.parse_workflow(text)["jobs"]["legs"]
        assert len(ci.cells(job, "push")) == 4
        assert ci.cells(job, "pull_request") == [
            {"os": "ubuntu-latest", "python-version": "3.12"}
        ]

    @pytest.mark.parametrize("where", ["axis", "exclude", "include"])
    def test_an_expression_it_does_not_read_is_refused_and_not_matched(self, where):
        expression = "${{ github.event_name == 'push' && 'a' || '' }}"
        matrix: dict[str, Any] = {"os": ["a", "b"]}
        if where == "axis":
            matrix["os"] = [expression, "b"]
        elif where == "exclude":
            matrix["exclude"] = [{"os": expression}]
        else:
            matrix["include"] = [{"os": "a", "extra": expression}]
        with pytest.raises(ci.UnsupportedExpression) as caught:
            ci.cells(_job(matrix))
        assert caught.value.shape == "matrix expression"
        assert "github.event_name == 'push'" in str(caught.value)

    def test_the_overlay_is_read_in_an_exclude_and_refused_anywhere_else(self):
        matrix = {"os": ["a"], "include": [{"os": "a", "extra": _overlay("x")}]}
        with pytest.raises(ci.UnsupportedExpression):
            ci.cells(_job(matrix))
        with pytest.raises(ci.UnsupportedExpression):
            ci.cells(_job({"os": [_overlay("a"), "b"]}))

    def test_an_overlay_with_text_around_it_is_not_the_overlay(self):
        around = "x " + _overlay("a")
        with pytest.raises(ci.UnsupportedExpression):
            ci.cells(_job({"os": ["a"], "exclude": [{"os": around}]}))

    def test_a_matrix_it_cannot_expand_is_refused(self):
        dynamic = _job("${{ fromJSON(needs.plan.outputs.matrix) }}")
        with pytest.raises(ci.UnsupportedExpression) as caught:
            ci.cells(dynamic)
        assert caught.value.shape == "matrix expression"
        with pytest.raises(ci.UnsupportedMatrix, match="axis os is not a list"):
            ci.cells(_job({"os": "ubuntu-latest"}))
        with pytest.raises(ci.UnsupportedMatrix, match="exclude is not a list"):
            ci.cells(_job({"os": ["a"], "exclude": ["a"]}))
        with pytest.raises(ci.UnsupportedMatrix, match="include is not a list"):
            ci.cells(_job({"os": ["a"], "include": {"os": "a"}}))
        with pytest.raises(ci.UnsupportedMatrix, match="not a mapping"):
            ci.cells({"strategy": ["a"]})
        with pytest.raises(ci.UnsupportedMatrix, match="not a mapping"):
            ci.cells({"strategy": {"matrix": ["a"]}})

    def test_an_exclude_key_that_names_no_axis_is_refused_and_not_ignored(self):
        """GitHub rejects the workflow. An entry that matched nothing would leave the leg
        count looking right for a typo in a key."""
        matrix = {"os": ["a", "b"], "python-version": ["1"]}
        typo = _job({**matrix, "exclude": [{"python_version": "1"}]})
        with pytest.raises(ci.UnsupportedMatrix, match="'python_version'") as caught:
            ci.cells(typo)
        assert "the axes are os, python-version" in str(caught.value)
        with pytest.raises(ci.UnsupportedMatrix, match="'python_version'"):
            ci.axis_cells(typo["strategy"]["matrix"])
        # The key is judged with the entry's other keys, not only when it is the first.
        second = _job({**matrix, "exclude": [{"os": "a", "python_version": "1"}]})
        with pytest.raises(ci.UnsupportedMatrix, match="'python_version'"):
            ci.cells(second)

    @pytest.mark.parametrize("event", ["push", "pull_request"])
    def test_an_exclude_key_that_names_no_axis_is_refused_on_every_event(self, event):
        """An entry with a void value matches nothing, and GitHub reads its key anyway."""
        job = _job({"os": ["a", "b"], "exclude": [{"oss": _overlay("a")}]})
        with pytest.raises(ci.UnsupportedMatrix, match="'oss'"):
            ci.cells(job, event)

    def test_a_key_only_an_include_adds_is_not_an_axis_to_exclude_on(self):
        matrix = {
            "os": ["a"],
            "include": [{"os": "a", "extra": 1}],
            "exclude": [{"extra": 1}],
        }
        with pytest.raises(ci.UnsupportedMatrix, match="'extra'"):
            ci.cells(_job(matrix))

    def test_an_exclude_in_a_matrix_with_no_axis_is_refused(self):
        with pytest.raises(ci.UnsupportedMatrix, match="'os'"):
            ci.axis_cells({"include": [{"os": "a"}], "exclude": [{"os": "a"}]})

    @pytest.mark.parametrize(
        "excludes",
        [[{}], [{}, {"os": "a"}], [{"os": "a"}, {}]],
        ids=["alone", "first", "last"],
    )
    def test_an_empty_exclude_entry_is_refused_wherever_it_stands(self, excludes):
        """An entry with no key names no axis. Asking whether every key of an entry
        matches a leg holds for every leg when there is no key, so reading the entry
        as a match drops all of them and the job's count reads zero, with no error."""
        matrix = {"os": ["a", "b"], "python-version": ["1"]}
        job = _job({**matrix, "exclude": excludes})
        with pytest.raises(ci.UnsupportedMatrix, match="empty") as caught:
            ci.cells(job)
        assert "the axes are os, python-version" in str(caught.value)
        with pytest.raises(ci.UnsupportedMatrix, match="empty"):
            ci.axis_cells(job["strategy"]["matrix"])

    @pytest.mark.parametrize("event", ["push", "pull_request"])
    def test_an_empty_exclude_entry_is_refused_on_every_event(self, event):
        job = _job({"os": ["a", "b"], "exclude": [{}]})
        with pytest.raises(ci.UnsupportedMatrix, match="empty"):
            ci.cells(job, event)

    def test_an_empty_exclude_entry_is_refused_in_a_matrix_with_no_axis(self):
        with pytest.raises(ci.UnsupportedMatrix, match="the axes are none"):
            ci.axis_cells({"include": [{"os": "a"}], "exclude": [{}]})

    def test_an_exclude_with_no_entry_is_not_an_empty_entry(self):
        """The control: no exclude, and an exclude of no entries, drop nothing."""
        matrix = {"os": ["a", "b"]}
        legs = [{"os": "a"}, {"os": "b"}]
        assert ci.cells(_job(matrix)) == legs
        assert ci.cells(_job({**matrix, "exclude": []})) == legs

    def test_matrix_values_name_what_the_matrix_names_whether_or_not_a_leg_runs_it(
        self,
    ):
        job = _job(
            {
                "os": ["a", "b"],
                "exclude": [{"os": "b"}],
                "include": [{"os": "c"}, {"py": "1"}],
            }
        )
        assert ci.matrix_values(job, "os") == ["a", "b", "c"]
        assert ci.matrix_values(job, "py") == ["1"]
        assert ci.matrix_values(job, "absent") == []
        assert ci.matrix_values({"runs-on": "x"}, "os") == []


#: The conditions the validator steps of install-validation carry, in their two spellings:
#: wrapped in ${{ }} with a status function, and bare.
UVX_ONLY_ON_3_12 = "${{ !cancelled() && matrix.method == 'bundle' && matrix.python-version == '3.12' }}"
ANY_CONTAINER_RUNTIME = "matrix.method == 'podman' || matrix.method == 'finch' || matrix.method == 'nerdctl'"

#: Condition shapes the evaluator refuses, with the name it must refuse them by.
REFUSED = [
    ("matrix.method != 'uvx'", "the != operator"),
    ("github.event_name == 'push'", "the github context (github.event_name)"),
    ("inputs.legs == 'all'", "the inputs context (inputs.legs)"),
    ("env.ACT == 'x'", "the env context (env.ACT)"),
    (
        "steps.install.outcome == 'success'",
        "the steps context (steps.install.outcome)",
    ),
    ("!env.ACT", "negation (!) of anything but cancelled()"),
    ("!(matrix.a == 'x')", "negation (!) of anything but cancelled()"),
    ("!matrix.a == 'x'", "negation (!) of anything but cancelled()"),
    ("startsWith(matrix.runner, 'jenkinsfile-')", "a call to startsWith()"),
    ("contains(fromJSON('[\"a\"]'), matrix.os)", "a call to contains()"),
    ("format('{0}', matrix.os) == 'x'", "a call to format()"),
    ("always()", "a call to always()"),
    ("success()", "a call to success()"),
    ("failure()", "a call to failure()"),
    ("cancelled()", "a call to cancelled()"),
    ("matrix.flag", "a value that is not compared with =="),
    ("'a'", "a value that is not compared with =="),
    (
        "matrix.a == 'x' && matrix.b == 'y' || matrix.c == 'z'",
        "&& and || mixed without parentheses",
    ),
    (
        "matrix.a == 'x' || matrix.b == 'y' && matrix.c == 'z'",
        "&& and || mixed without parentheses",
    ),
    ("matrix.shard == 1", "a non-string literal"),
    ("matrix.flag == true", "a non-string literal"),
    ("matrix.flag == null", "a non-string literal"),
    ("matrix['method'] == 'x'", "index access ([ ])"),
    ("matrix.a.b == 'x'", "a nested matrix property (matrix.a.b)"),
    ("matrix == 'x'", "a matrix reference that is not matrix.<key>"),
    ("", "an empty condition"),
    ("   ", "an empty condition"),
    ("${{ }}", "an empty condition"),
    ("matrix.a == 'x", "an unterminated string literal"),
    ('matrix.a == "x"', "the character '\"'"),
    (
        "matrix.a == 'x' matrix.b == 'y'",
        "two operands with no && or || between them",
    ),
    ("(matrix.a == 'x'", "an unclosed parenthesis"),
    ("matrix.a == 'x')", "an unmatched closing parenthesis"),
    (
        "${{ matrix.a == 'x' }} && ${{ matrix.b == 'y' }}",
        "a ${{ }} wrapper inside the expression",
    ),
    ("matrix.a == 'x' &&", "an incomplete condition"),
    ("&& matrix.a == 'x'", "the operator '&&'"),
]


class TestTheConditionEvaluator:
    @pytest.mark.parametrize(
        "expression, cell, expected",
        [
            ("matrix.method == 'bundle'", {"method": "bundle"}, True),
            ("matrix.method == 'bundle'", {"method": "pip"}, False),
            ("${{ matrix.method == 'bundle' }}", {"method": "bundle"}, True),
            ("${{matrix.method=='bundle'}}", {"method": "bundle"}, True),
            ("'bundle' == matrix.method", {"method": "bundle"}, True),
            ("matrix.a == matrix.b", {"a": "x", "b": "x"}, True),
            ("matrix.a == matrix.b", {"a": "x", "b": "y"}, False),
            ("matrix.python-version == '3.12'", {"python-version": "3.12"}, True),
            ("matrix.method == 'it''s'", {"method": "it's"}, True),
            ("${{ !cancelled() }}", {}, True),
            ("!cancelled() && matrix.a == 'x'", {"a": "y"}, False),
            (UVX_ONLY_ON_3_12, {"method": "bundle", "python-version": "3.12"}, True),
            (UVX_ONLY_ON_3_12, {"method": "bundle", "python-version": "3.11"}, False),
            (UVX_ONLY_ON_3_12, {"method": "homebrew", "python-version": "3.12"}, False),
            (ANY_CONTAINER_RUNTIME, {"method": "podman"}, True),
            (ANY_CONTAINER_RUNTIME, {"method": "nerdctl"}, True),
            (ANY_CONTAINER_RUNTIME, {"method": "bundle"}, False),
            (
                "(matrix.a == 'x' && matrix.b == 'y') || matrix.c == 'z'",
                {"a": "x", "b": "y", "c": "n"},
                True,
            ),
            (
                "(matrix.a == 'x' && matrix.b == 'y') || matrix.c == 'z'",
                {"a": "x", "b": "n", "c": "z"},
                True,
            ),
            (
                "(matrix.a == 'x' && matrix.b == 'y') || matrix.c == 'z'",
                {"a": "x", "b": "n", "c": "n"},
                False,
            ),
            (
                "matrix.a == 'x' && (matrix.b == 'y' || matrix.c == 'z')",
                {"a": "n", "b": "y", "c": "z"},
                False,
            ),
            (
                "matrix.a == 'x' && (matrix.b == 'y' || matrix.c == 'z')",
                {"a": "x", "b": "n", "c": "z"},
                True,
            ),
        ],
    )
    def test_the_shapes_it_reads_evaluate_over_the_cell(
        self, expression, cell, expected
    ):
        assert ci.evaluate_condition(expression, cell) is expected

    @pytest.mark.parametrize(
        "expression, cell, expected",
        [
            # GitHub ignores case when it compares strings.
            ("matrix.os == 'Ubuntu-Latest'", {"os": "ubuntu-latest"}, True),
            # Operands of different types are compared as numbers.
            ("matrix.shard == '1'", {"shard": 1}, True),
            ("matrix.shard == '2'", {"shard": 1}, False),
            # An unquoted 3.10 is the number 3.1 in YAML, which '3.10' also reads as.
            ("matrix.python-version == '3.10'", {"python-version": 3.1}, True),
            # The same value written as a string is not.
            ("matrix.python-version == '3.10'", {"python-version": "3.1"}, False),
            # A boolean is 1 or 0, and 'true' is not a number.
            ("matrix.flag == 'true'", {"flag": True}, False),
            ("matrix.flag == '1'", {"flag": True}, True),
            # A key the cell does not carry is null: 0 as a number, so '' matches it.
            ("matrix.absent == 'x'", {}, False),
            ("matrix.absent == ''", {}, True),
        ],
    )
    def test_equality_is_githubs_loose_equality(self, expression, cell, expected):
        assert ci.evaluate_condition(expression, cell) is expected

    @pytest.mark.parametrize("expression, shape", REFUSED)
    def test_every_other_shape_is_refused_by_name(self, expression, shape):
        with pytest.raises(ci.UnsupportedExpression) as caught:
            ci.evaluate_condition(expression, {"a": "x", "b": "y", "method": "bundle"})
        assert caught.value.shape == shape
        assert shape in str(caught.value)

    @pytest.mark.parametrize("expression, shape", REFUSED)
    def test_a_refused_shape_is_never_read_as_true_or_false(self, expression, shape):
        """Whatever the cell holds, the answer is a refusal and never a boolean."""
        for cell in ({}, {"a": "x", "b": "y", "c": "z", "method": "bundle"}):
            with pytest.raises(ci.UnsupportedExpression):
                ci.evaluate_condition(expression, cell)

    def test_a_refusal_is_not_hidden_by_an_operand_that_is_already_decided(self):
        cell = {"method": "bundle"}
        with pytest.raises(ci.UnsupportedExpression, match="github context"):
            ci.evaluate_condition(
                "matrix.method == 'nope' && github.event_name == 'push'", cell
            )
        with pytest.raises(ci.UnsupportedExpression, match="startsWith"):
            ci.evaluate_condition(
                "matrix.method == 'bundle' || startsWith(matrix.os, 'u')", cell
            )

    def test_a_step_without_an_if_runs_and_a_step_with_one_follows_it(self):
        cell = {"method": "bundle", "python-version": "3.12"}
        assert ci.step_runs({"run": "echo"}, cell) is True
        assert ci.step_runs({"if": None}, cell) is True
        assert ci.step_runs({"if": "matrix.method == 'pip'"}, cell) is False
        assert ci.step_runs({"if": UVX_ONLY_ON_3_12}, cell) is True
        with pytest.raises(ci.UnsupportedExpression, match="not a string"):
            ci.step_runs({"if": True}, cell)
        with pytest.raises(ci.UnsupportedExpression, match="env context"):
            ci.step_runs({"if": "${{ !cancelled() && env.ACT == 'x' }}"}, cell)


#: The rows of RUNNER_LABELS as GitHub's runner reference gives them for these labels:
#: (OS family, architecture, image version or None where the label names none).
LABEL_FACTS = {
    "ubuntu-latest": ("linux", "x86_64", None),
    "ubuntu-24.04": ("linux", "x86_64", "24.04"),
    "ubuntu-24.04-arm": ("linux", "arm64", "24.04"),
    "ubuntu-slim": ("linux", "x86_64", None),
    "macos-latest": ("macos", "arm64", None),
    "macos-15": ("macos", "arm64", "15"),
    "windows-latest": ("windows", "x86_64", None),
}

FINCH_OVERRIDE = (
    "${{ (matrix.method == 'finch' && matrix.os == 'ubuntu-latest') "
    "&& 'ubuntu-24.04' || matrix.os }}"
)


def _planted(job_lines: str, header: str = "on: push\n") -> dict[str, Any]:
    return ci.parse_workflow(f"{header}jobs:\n  j:\n{job_lines}")


CALLEE_USES = "./.github/workflows/callee.yml"

#: A reusable workflow whose one job runs on the runner label its caller gives it.
CALLEE = """\
on:
  workflow_call:
    inputs:
      runner:
        type: string
        default: ubuntu-latest
      note:
        type: string
        default: plain text
jobs:
  work:
    runs-on: ${{ inputs.runner }}
    steps:
      - run: echo hi
"""


#: The same workflow with the runner declared required and given no default, so its
#: label is the one each call passes.
CALLEE_REQUIRING_A_RUNNER = CALLEE.replace(
    "        default: ubuntu-latest\n", "        required: true\n"
)


def _caller(with_text: str = "") -> dict[str, Any]:
    """A workflow whose job ``call`` calls CALLEE, with the ``with:`` block it is given."""
    return ci.parse_workflow(
        f"on: push\njobs:\n  call:\n    uses: {CALLEE_USES}\n{with_text}"
    )


def _called(workflow: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The reusable workflows of this repository that ``workflow`` calls, by ``uses:``."""
    return {
        job["uses"]: ci.load_workflow(REPO_ROOT / job["uses"])
        for job in workflow["jobs"].values()
        if str(job.get("uses", "")).startswith("./")
    }


class TestRunnerLabels:
    def test_the_table_holds_the_rows_the_runner_reference_gives(self):
        found = {
            label: (row.os_family, row.architecture, row.image_version)
            for label, row in ci.RUNNER_LABELS.items()
        }
        assert found == LABEL_FACTS

    def test_every_row_is_keyed_by_its_label_and_names_a_version_only_when_the_label_does(
        self,
    ):
        assert ci.RUNNER_LABELS
        for label, row in ci.RUNNER_LABELS.items():
            assert row.label == label
            assert row.os_family in {"linux", "macos", "windows"}, row
            assert row.architecture in {"x86_64", "arm64"}, row
            assert label.startswith(
                {"linux": "ubuntu", "macos": "macos", "windows": "windows"}[
                    row.os_family
                ]
            ), row
            names_a_version = any(char.isdigit() for char in label)
            assert (row.image_version is not None) is names_a_version, row
            if row.image_version is not None:
                assert row.image_version in label, row
            if label.endswith("-arm"):
                assert row.architecture == "arm64", row

    def test_a_known_label_resolves_and_an_unknown_one_is_named(self):
        row = ci.runner_label("ubuntu-24.04-arm")
        assert (row.os_family, row.architecture, row.image_version) == (
            "linux",
            "arm64",
            "24.04",
        )
        with pytest.raises(ci.UnknownRunnerLabel, match="ubuntu-18.04"):
            ci.runner_label("ubuntu-18.04")

    def test_a_literal_label_in_the_table_passes_and_is_reported_as_checked(self):
        workflow = _planted("    runs-on: ubuntu-latest\n")
        assert ci.check_runner_labels(workflow) == {"ubuntu-latest"}

    def test_a_literal_label_not_in_the_table_is_refused_by_job_and_label(self):
        workflow = _planted("    runs-on: windows-2019\n")
        with pytest.raises(ci.UnknownRunnerLabel, match=r"j \(runs-on\): windows-2019"):
            ci.check_runner_labels(workflow)

    def test_the_matrix_os_values_are_checked_whether_or_not_a_leg_runs_them(self):
        lines = (
            "    runs-on: ${{ matrix.os }}\n"
            "    strategy:\n"
            "      matrix:\n"
            "        os: [ubuntu-latest, solaris-11]\n"
            "        exclude:\n"
            "          - os: solaris-11\n"
        )
        with pytest.raises(ci.UnknownRunnerLabel, match="solaris-11"):
            ci.check_runner_labels(_planted(lines))

    def test_a_matrix_os_value_is_checked_when_runs_on_is_a_literal(self):
        lines = (
            "    runs-on: ubuntu-latest\n"
            "    strategy:\n"
            "      matrix:\n"
            "        os: [ubuntu-latest, beos-5]\n"
        )
        with pytest.raises(ci.UnknownRunnerLabel, match=r"j \(matrix os\): beos-5"):
            ci.check_runner_labels(_planted(lines))

    def test_an_include_row_os_value_is_checked_too(self):
        lines = (
            "    runs-on: ${{ matrix.os }}\n"
            "    strategy:\n"
            "      matrix:\n"
            "        include:\n"
            "          - os: ubuntu-latest\n"
            "          - os: amiga-3\n"
        )
        with pytest.raises(ci.UnknownRunnerLabel, match="amiga-3"):
            ci.check_runner_labels(_planted(lines))

    def test_every_label_in_a_matrix_is_reported_when_all_are_known(self):
        lines = (
            "    runs-on: ${{ matrix.os }}\n"
            "    strategy:\n"
            "      matrix:\n"
            "        os: [ubuntu-latest, macos-15, windows-latest]\n"
        )
        assert ci.check_runner_labels(_planted(lines)) == {
            "ubuntu-latest",
            "macos-15",
            "windows-latest",
        }

    def test_the_label_an_override_names_is_checked_and_the_axis_labels_stay_in(self):
        known = f"    runs-on: {FINCH_OVERRIDE}\n    strategy:\n      matrix:\n"
        axes = "        os: [ubuntu-latest]\n        method: [finch, pip]\n"
        assert ci.check_runner_labels(_planted(known + axes)) == {
            "ubuntu-latest",
            "ubuntu-24.04",
        }
        unknown = known.replace("'ubuntu-24.04'", "'ubuntu-23.04'")
        with pytest.raises(ci.UnknownRunnerLabel, match="ubuntu-23.04"):
            ci.check_runner_labels(_planted(unknown + axes))

    def test_a_reusable_workflow_takes_the_default_of_the_input_it_names(self):
        header = (
            "on:\n  workflow_call:\n    inputs:\n      runner:\n        type: string\n"
            "        default: {default}\n"
        )
        lines = "    runs-on: ${{ inputs.runner }}\n"
        ok = _planted(lines, header.format(default="ubuntu-latest"))
        assert ci.check_runner_labels(ok) == {"ubuntu-latest"}
        bad = _planted(lines, header.format(default="plan9"))
        with pytest.raises(ci.UnknownRunnerLabel, match="plan9"):
            ci.check_runner_labels(bad)
        none = _planted(lines, "on:\n  workflow_call: {}\n")
        with pytest.raises(ci.UnsupportedExpression, match="no string default"):
            ci.check_runner_labels(none)

    @pytest.mark.parametrize(
        "runs_on, shape",
        [
            ("${{ matrix.os == 'a' && 'b' || 'c' }}", "runs-on expression"),
            ("${{ github.event_name }}", "runs-on expression"),
            ("[self-hosted, linux]", "a runs-on that is not a string"),
        ],
    )
    def test_a_runs_on_it_does_not_read_is_refused_by_name(self, runs_on, shape):
        workflow = _planted(f"    runs-on: {runs_on}\n")
        with pytest.raises(ci.UnsupportedExpression) as caught:
            ci.check_runner_labels(workflow)
        assert caught.value.shape == shape

    def test_a_job_that_calls_a_reusable_workflow_names_no_runner(self):
        workflow = _planted("    uses: ./.github/workflows/other.yml\n")
        assert ci.check_runner_labels(workflow) == set()

    def test_runs_on_resolves_each_leg_to_the_label_it_runs_on(self):
        matrix = {"os": ["ubuntu-latest", "macos-15"], "method": ["finch", "pip"]}
        job = _job(matrix, **{"runs-on": FINCH_OVERRIDE})
        assert ci.runs_on(job, {"os": "ubuntu-latest", "method": "finch"}) == (
            "ubuntu-24.04"
        )
        assert ci.runs_on(job, {"os": "ubuntu-latest", "method": "pip"}) == (
            "ubuntu-latest"
        )
        assert ci.runs_on(job, {"os": "macos-15", "method": "finch"}) == "macos-15"
        by_axis = _job(matrix, **{"runs-on": "${{ matrix.os }}"})
        assert ci.runs_on(by_axis, {"os": "macos-15"}) == "macos-15"
        assert ci.runs_on(_job(), {}) == "ubuntu-latest"
        with pytest.raises(ci.CiMatrixError, match="no runner"):
            ci.runs_on({"uses": "./.github/workflows/other.yml"}, {})
        with pytest.raises(ci.CiMatrixError, match="os"):
            ci.runs_on(by_axis, {})

    @pytest.mark.parametrize(
        "cell, label",
        [
            ({"os": "ubuntu-latest", "method": "Finch"}, "ubuntu-24.04"),
            ({"os": "ubuntu-latest", "method": "FINCH"}, "ubuntu-24.04"),
            ({"os": "Ubuntu-Latest", "method": "finch"}, "ubuntu-24.04"),
            # The controls: another method, and another image, are not overridden.
            ({"os": "ubuntu-latest", "method": "pip"}, "ubuntu-latest"),
            ({"os": "macos-15", "method": "Finch"}, "macos-15"),
        ],
    )
    def test_the_override_compares_strings_the_way_github_does(self, cell, label):
        """GitHub's == ignores case, so a leg whose method or image differs from the
        override's text only in case is still overridden."""
        job = _job(**{"runs-on": FINCH_OVERRIDE})
        assert ci.runs_on(job, cell) == label

    def test_a_matrix_key_the_matrix_does_not_define_is_refused(self):
        """Without this a typo in the key names no label, and the empty set passes."""
        lines = (
            "    runs-on: ${{ matrix.runner }}\n"
            "    strategy:\n"
            "      matrix:\n"
            "        os: [ubuntu-latest]\n"
        )
        workflow = _planted(lines)
        with pytest.raises(ci.CiMatrixError, match=r"matrix\.runner"):
            ci.check_runner_labels(workflow)
        with pytest.raises(ci.CiMatrixError, match=r"matrix\.runner"):
            ci.runs_on_labels(workflow["jobs"]["j"])

    def test_a_runs_on_that_reads_a_matrix_the_job_does_not_have_is_refused(self):
        with pytest.raises(ci.CiMatrixError, match=r"matrix\.os"):
            ci.check_runner_labels(_planted("    runs-on: ${{ matrix.os }}\n"))

    @pytest.mark.parametrize(
        "matrix_lines", ["        os: []\n", "        include: []\n"]
    )
    def test_a_matrix_with_no_legs_has_no_runner_to_read_and_is_refused(
        self, matrix_lines
    ):
        """No leg lacks the key when there is no leg, so the key has to be named."""
        head = "    runs-on: ${{ matrix.os }}\n    strategy:\n      matrix:\n"
        lines = head + matrix_lines
        job = _planted(lines)["jobs"]["j"]
        assert ci.cells(job, "push") == []
        with pytest.raises(ci.CiMatrixError, match=r"matrix\.os"):
            ci.check_runner_labels(_planted(lines))

    def test_a_leg_with_no_value_for_the_key_runs_on_nothing_and_is_refused(self):
        lines = (
            "    runs-on: ${{ matrix.runner }}\n"
            "    strategy:\n"
            "      matrix:\n"
            "        os: [a, b]\n"
            "        include:\n"
            "          - os: c\n"
            "            runner: ubuntu-latest\n"
        )
        with pytest.raises(ci.CiMatrixError, match="no value for it") as caught:
            ci.check_runner_labels(_planted(lines))
        assert "'os': 'a'" in str(caught.value)

    def test_a_leg_that_lacks_the_key_on_a_pull_request_only_is_refused(self):
        """The overlay drops the leg an include merged into, so on a pull request that
        include is a leg of its own, and it has no runner."""
        lines = (
            "    runs-on: ${{ matrix.runner }}\n"
            "    strategy:\n"
            "      matrix:\n"
            "        os: [a, b]\n"
            "        runner: [ubuntu-latest]\n"
            "        exclude:\n"
            f"          - os: {_overlay('a')}\n"
            "        include:\n"
            "          - os: a\n"
            "            extra: 1\n"
        )
        job = _planted(lines)["jobs"]["j"]
        assert all("runner" in leg for leg in ci.cells(job, "push"))
        with pytest.raises(ci.CiMatrixError, match="on pull_request") as caught:
            ci.check_runner_labels(_planted(lines))
        assert "'extra': 1" in str(caught.value)

    def test_the_override_needs_the_axis_it_compares_and_an_os_in_every_leg(self):
        head = f"    runs-on: {FINCH_OVERRIDE}\n    strategy:\n      matrix:\n"
        no_os = _planted(head + "        method: [finch, pip]\n")
        with pytest.raises(ci.CiMatrixError, match=r"matrix\.os"):
            ci.check_runner_labels(no_os)
        no_axis = _planted(head + "        os: [ubuntu-latest]\n")
        with pytest.raises(ci.CiMatrixError, match=r"matrix\.method"):
            ci.check_runner_labels(no_axis)
        lines = head + (
            "        os: [ubuntu-latest]\n"
            "        method: [finch]\n"
            "        include:\n"
            "          - method: pip\n"
        )
        with pytest.raises(ci.CiMatrixError, match="no value for it"):
            ci.check_runner_labels(_planted(lines))

    def test_an_axis_only_some_legs_carry_is_not_refused(self):
        """The override compares matrix.method, and a leg with no method is not a finch
        leg: it falls through to its os. The scan-validation job is built this way."""
        lines = (
            f"    runs-on: {FINCH_OVERRIDE}\n"
            "    strategy:\n"
            "      matrix:\n"
            "        include:\n"
            "          - { os: ubuntu-latest, method: finch }\n"
            "          - { os: macos-15 }\n"
        )
        assert ci.check_runner_labels(_planted(lines)) == {
            "ubuntu-latest",
            "ubuntu-24.04",
            "macos-15",
        }

    @pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda path: path.name)
    def test_every_label_a_workflow_names_is_in_the_table(self, path):
        workflow = ci.load_workflow(path)
        labels = ci.check_runner_labels(workflow, called=_called(workflow))
        assert labels <= set(ci.RUNNER_LABELS)

    def test_the_workflows_were_actually_read(self):
        """The denominator for the test above: it read many workflows and many labels."""
        assert len(WORKFLOW_FILES) >= 20, WORKFLOW_FILES
        seen: set[str] = set()
        for path in WORKFLOW_FILES:
            workflow = ci.load_workflow(path)
            seen |= ci.check_runner_labels(workflow, called=_called(workflow))
        assert {
            "ubuntu-latest",
            "ubuntu-24.04-arm",
            "macos-15",
            "windows-latest",
        } <= seen

    def test_a_workflow_file_with_the_yaml_extension_is_listed_and_checked(
        self, tmp_path
    ):
        """GitHub runs a .yaml workflow as it runs a .yml one, so the listing has to name
        it, and the check has to refuse what it names."""
        text = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
        odd = text.replace("ubuntu-latest", "plan9")
        (tmp_path / "ok.yml").write_text(text, encoding="utf-8")
        (tmp_path / "odd.yaml").write_text(odd, encoding="utf-8")
        (tmp_path / "notes.txt").write_text(text, encoding="utf-8")
        (tmp_path / "ok.yml.bak").write_text(text, encoding="utf-8")
        (tmp_path / "nested.yml").mkdir()
        by_name = {path.name: path for path in _workflow_files(tmp_path)}
        assert list(by_name) == ["odd.yaml", "ok.yml"]
        ok = ci.load_workflow(by_name["ok.yml"])
        assert ci.check_runner_labels(ok) == {"ubuntu-latest"}
        with pytest.raises(ci.UnknownRunnerLabel, match="plan9"):
            ci.check_runner_labels(ci.load_workflow(by_name["odd.yaml"]))


class TestACallToAReusableWorkflow:
    """What a caller passes in ``with:`` reaches the ``runs-on`` of the workflow it calls,
    so it is held to the same table as a runs-on written in the workflow itself."""

    def test_a_label_the_caller_passes_is_checked_against_the_table(self):
        called = {CALLEE_USES: ci.parse_workflow(CALLEE)}
        ok = _caller("    with:\n      runner: ubuntu-24.04-arm\n")
        assert ci.check_runner_labels(ok, called=called) == {"ubuntu-24.04-arm"}
        bad = _caller("    with:\n      runner: windows-2019\n")
        with pytest.raises(
            ci.UnknownRunnerLabel, match=r"call \(with runner\): windows-2019"
        ):
            ci.check_runner_labels(bad, called=called)

    def test_an_input_that_does_not_feed_a_runs_on_is_not_read_as_a_label(self):
        called = {CALLEE_USES: ci.parse_workflow(CALLEE)}
        caller = _caller("    with:\n      note: plan9\n      runner: ubuntu-latest\n")
        assert ci.check_runner_labels(caller, called=called) == {"ubuntu-latest"}

    def test_an_input_the_caller_leaves_out_names_no_label_here(self):
        """The called workflow's own default is read when that workflow is checked."""
        called = {CALLEE_USES: ci.parse_workflow(CALLEE)}
        caller = _caller("    with:\n      note: plan9\n")
        assert ci.check_runner_labels(caller, called=called) == set()
        assert ci.check_runner_labels(ci.parse_workflow(CALLEE)) == {"ubuntu-latest"}

    def test_an_input_with_no_default_is_read_from_the_caller(self):
        assert "required: true" in CALLEE_REQUIRING_A_RUNNER
        called = {CALLEE_USES: ci.parse_workflow(CALLEE_REQUIRING_A_RUNNER)}
        ok = _caller("    with:\n      runner: macos-15\n")
        assert ci.check_runner_labels(ok, called=called) == {"macos-15"}
        bad = _caller("    with:\n      runner: plan9\n")
        with pytest.raises(ci.UnknownRunnerLabel, match="plan9"):
            ci.check_runner_labels(bad, called=called)

    def test_a_required_input_is_checked_at_each_call_and_not_in_the_callee(self):
        """A required input with no default is read from the calls, and the check of
        each call reads what it passes. Read on its own, the called workflow names no
        label from it and is not refused for having no default."""
        called = {CALLEE_USES: ci.parse_workflow(CALLEE_REQUIRING_A_RUNNER)}
        callee = called[CALLEE_USES]
        assert ci.check_runner_labels(callee) == set()
        assert ci.runs_on_labels(callee["jobs"]["work"], callee) == set()
        # The calls carry the check: a known label passes and an unknown one is named.
        ok = _caller("    with:\n      runner: macos-15\n")
        assert ci.check_runner_labels(ok, called=called) == {"macos-15"}
        bad = _caller("    with:\n      runner: plan9\n")
        with pytest.raises(ci.UnknownRunnerLabel, match="plan9"):
            ci.check_runner_labels(bad, called=called)

    @pytest.mark.parametrize(
        "declared",
        ["        required: false\n", ""],
        ids=["not_required", "no_required_key"],
    )
    def test_an_input_a_caller_may_leave_out_is_still_read_for_its_default(
        self, declared
    ):
        """GitHub's reference gives a string input with no default the value "", so a
        runs-on that reads one a call leaves out would be empty, and no call passes a
        label for the check to read. Only an input declared required, with no default,
        is read from the calls."""
        optional = CALLEE.replace("        default: ubuntu-latest\n", declared)
        assert "required: true" not in optional
        with pytest.raises(ci.UnsupportedExpression, match="no string default"):
            ci.check_runner_labels(ci.parse_workflow(optional))

    def test_runs_on_names_no_label_for_an_input_only_the_caller_gives(self):
        """runs_on names the label of one leg, and the callee holds none for it."""
        callee = ci.parse_workflow(CALLEE_REQUIRING_A_RUNNER)
        with pytest.raises(ci.UnsupportedExpression, match="no string default"):
            ci.runs_on(callee["jobs"]["work"], {}, callee)

    @pytest.mark.parametrize(
        "with_text, shape",
        [
            (
                "    with:\n      runner: ${{ matrix.runner }}\n",
                "a runner input given as an expression",
            ),
            ("    with:\n      runner: 3\n", "a runner input that is not a string"),
            (
                "    with:\n      runner: [a, b]\n",
                "a runner input that is not a string",
            ),
            ("    with:\n      - runner\n", "a with: that is not a mapping"),
        ],
    )
    def test_a_value_it_cannot_read_is_refused_by_name(self, with_text, shape):
        called = {CALLEE_USES: ci.parse_workflow(CALLEE)}
        with pytest.raises(ci.UnsupportedExpression) as caught:
            ci.check_runner_labels(_caller(with_text), called=called)
        assert caught.value.shape == shape

    def test_a_call_whose_workflow_was_not_given_is_refused_when_it_passes_inputs(self):
        shape = "a call that passes inputs to a reusable workflow that was not given"
        caller = _caller("    with:\n      runner: ubuntu-latest\n")
        other = {"./.github/workflows/other.yml": ci.parse_workflow(CALLEE)}
        for kwargs in ({}, {"called": {}}, {"called": other}):
            with pytest.raises(ci.UnsupportedExpression) as caught:
                ci.check_runner_labels(caller, **kwargs)
            assert caught.value.shape == shape
            assert CALLEE_USES in str(caught.value)

    def test_a_call_that_passes_no_input_has_nothing_to_look_up(self):
        assert ci.check_runner_labels(_caller()) == set()
        assert ci.check_runner_labels(_caller("    with: {}\n")) == set()

    def test_the_called_workflows_runs_on_is_read_with_the_same_refusals(self):
        callee = CALLEE.replace("${{ inputs.runner }}", "${{ inputs.runner || 'x' }}")
        called = {CALLEE_USES: ci.parse_workflow(callee)}
        caller = _caller("    with:\n      runner: ubuntu-latest\n")
        with pytest.raises(ci.UnsupportedExpression) as caught:
            ci.check_runner_labels(caller, called=called)
        assert caught.value.shape == "runs-on expression"

    def test_the_real_calls_are_read_and_a_wrong_label_in_one_is_refused(self):
        workflow = ci.load_workflow(WORKFLOWS / "ash-repo-scan.yml")
        called = _called(workflow)
        assert called, "ash-repo-scan.yml calls reusable workflows"
        labels = ci.check_runner_labels(workflow, called=called)
        passing = [
            job_id
            for job_id, job in workflow["jobs"].items()
            if "runner" in (job.get("with") or {})
        ]
        assert passing, "ash-repo-scan.yml passes a runner to a called workflow"
        for job_id in passing:
            assert workflow["jobs"][job_id]["with"]["runner"] in labels
            planted = copy.deepcopy(workflow)
            planted["jobs"][job_id]["with"]["runner"] = "windows-2019"
            with pytest.raises(
                ci.UnknownRunnerLabel, match=rf"{job_id} \(with runner\): windows-2019"
            ):
                ci.check_runner_labels(planted, called=called)


CONSUMERS = [
    "tests/unit/test_unified_ci_job_counts.py",
    "tests/unit/test_ci_matrix_agreement.py",
    "tests/unit/test_oci_runner_ci_coverage.py",
    "tests/unit/docs/test_page_claims.py",
]

#: The one place a test loads the reader, and this file, which holds the loaders the
#: scan below is tried on. Neither is read for a loader of its own.
LOADER_HELPER = "tests/utils/ci_matrix_loader.py"
THIS_FILE = Path(__file__).resolve().relative_to(REPO_ROOT).as_posix()

#: The test modules that load the reader with a loader of their own today. A new one
#: fails the scan below, and each leaves this set when it moves to load_ci_matrix(). A
#: module named here that no longer has a loader of its own fails the scan too, so the
#: set only shrinks.
OWN_LOADERS = {
    "tests/integration/docs/ci_runners/reports.py",
    "tests/unit/test_pre_commit_hooks_manifest.py",
    "tests/unit/test_unit_test_shards.py",
}


#: The two spellings by which a module names the reader: its file, and the module name
#: the shared helper registers it under.
READER_FILE = "_ci_matrix.py"
READER_NAME = "_ash_ci_matrix"


def _docstring_values(tree: ast.AST) -> set[int]:
    """The ids of the string nodes that are a docstring: prose, never a name."""
    found: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            first = node.body[0] if node.body else None
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                found.add(id(first.value))
    return found


def _own_loader_lines(source: bytes | str, filename: str) -> list[int]:
    """The lines where a test module loads the reader with its own loader.

    A module has one when it calls ``spec_from_file_location`` and also writes the
    reader's file name or its module name as a string, outside a docstring. Its calls
    are the lines. The call need not hold the name: a loader that takes the path or the
    name from a constant, as ``MODULE`` or ``name`` here, is still one. ``filename``
    names the module in a SyntaxError.
    """
    tree = ast.parse(source, filename=filename)
    prose = _docstring_values(tree)
    names_the_reader = any(
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in prose
        and (
            node.value == READER_NAME
            or node.value == READER_FILE
            or node.value.endswith("/" + READER_FILE)
        )
        for node in ast.walk(tree)
    )
    if not names_the_reader:
        return []
    return sorted(
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and getattr(node.func, "attr", getattr(node.func, "id", ""))
        == "spec_from_file_location"
    )


def _own_loaders(root: Path, modules: Iterable[Path]) -> dict[str, list[int]]:
    """The modules among ``modules`` that load the reader with their own loader, by
    path below ``root``, each with the lines of its loader calls.

    The loader helper and this file are not read. A module whose bytes name no loader
    or no reader is not parsed, so a fixture that is not Python does not stop the scan
    until it names both."""
    found: dict[str, list[int]] = {}
    for path in modules:
        name = path.relative_to(root).as_posix()
        if name in (LOADER_HELPER, THIS_FILE):
            continue
        data = path.read_bytes()
        if b"spec_from_file_location" not in data or b"_ci_matrix" not in data:
            continue
        lines = _own_loader_lines(data, name)
        if lines:
            found[name] = lines
    return found


def _test_modules() -> list[Path]:
    """Every ``tests/**/*.py`` file of the checkout, in path order.

    Walked with the repository's own walker, which leaves the tests' scratch tree out
    before it descends: ``rglob`` over tests/ races the directories other workers make
    there (tests/unit/test_repo_walkers_skip_scratch.py). It asks git nothing, so the
    scan runs in the unit tier, on a tree that is not a checkout too.
    """
    from tests.utils.helpers import iter_repo_files

    walked = iter_repo_files(
        REPO_ROOT / "tests", skip_dirs=frozenset({"__pycache__", "node_modules"})
    )
    return sorted(path for path in walked if path.suffix == ".py" and path.is_file())


def _plant(root: Path, sources: dict[str, str]) -> list[Path]:
    """Write each module of ``sources`` below ``root``, at the path it is keyed by."""
    paths: list[Path] = []
    for name, source in sources.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        paths.append(path)
    return paths


#: Test modules that load the reader with a loader of their own, by the shape of it.
#: They are parsed and never run, so ROOT and where name nothing.
PLANTED_LOADERS = {
    "path_in_the_call": (
        "import importlib.util\n"
        "spec = importlib.util.spec_from_file_location(\n"
        "    'reader', ROOT / 'scripts' / '_ci_matrix.py'\n"
        ")\n"
    ),
    "module_name_in_the_call": (
        "import importlib.util\n"
        "spec = importlib.util.spec_from_file_location('_ash_ci_matrix', where)\n"
    ),
    "path_and_name_in_constants": (
        "import importlib.util\n"
        "READER = ROOT / 'scripts' / '_ci_matrix.py'\n"
        "def load():\n"
        "    name = '_ash_ci_matrix'\n"
        "    return importlib.util.spec_from_file_location(name, READER)\n"
    ),
    "the_function_imported_bare": (
        "from importlib.util import spec_from_file_location\n"
        "spec = spec_from_file_location('_ash_ci_matrix', where)\n"
    ),
    "inside_a_class": (
        "import importlib.util\n"
        "class Loader:\n"
        "    def load(self):\n"
        "        return importlib.util.spec_from_file_location(\n"
        "            'x', 'scripts/_ci_matrix.py'\n"
        "        )\n"
    ),
}

#: Test modules that do not load the reader by themselves: one that loads another
#: script, one that uses the helper, and two that only name the reader in prose.
PLANTED_FINE = {
    "loads_another_script": (
        "import importlib.util\n"
        "spec = importlib.util.spec_from_file_location('other', where)\n"
    ),
    "uses_the_helper": (
        '"""Reads scripts/_ci_matrix.py through the helper."""\n'
        "from tests.utils.ci_matrix_loader import load_ci_matrix\n"
        "ci = load_ci_matrix()\n"
    ),
    "names_the_reader_in_a_docstring_and_a_comment": (
        '"""Compares scripts/_ci_matrix.py (_ash_ci_matrix) with other.py."""\n'
        "import importlib.util\n"
        "# scripts/_ci_matrix.py is loaded by the helper, not here.\n"
        "spec = importlib.util.spec_from_file_location('other', where)\n"
    ),
    "names_the_reader_in_a_function_docstring": (
        "import importlib.util\n"
        "def load():\n"
        "    '''Loads scripts/_ci_matrix.py.'''\n"
        "    return importlib.util.spec_from_file_location('other', where)\n"
    ),
}


@pytest.fixture(scope="module")
def checkout_loaders() -> dict[str, list[int]]:
    """The test modules of this checkout that load the reader with their own loader."""
    return _own_loaders(REPO_ROOT, _test_modules())


class TestTheByPathLoader:
    """tests/utils/ci_matrix_loader.py is the one place a test loads the reader."""

    def test_a_module_that_fails_to_load_is_not_left_in_sys_modules(self, tmp_path):
        from tests.utils.ci_matrix_loader import load_by_path

        broken = tmp_path / "broken.py"
        broken.write_text("READY = True\nraise RuntimeError('boom')\n", "utf-8")
        name = "_ash_ci_matrix_loader_probe_broken"
        try:
            with pytest.raises(RuntimeError, match="boom"):
                load_by_path(name, broken)
            assert name not in sys.modules
            # Asked again it fails again, and does not hand out a half-built module.
            with pytest.raises(RuntimeError, match="boom"):
                load_by_path(name, broken)
        finally:
            sys.modules.pop(name, None)

    def test_a_module_that_loads_is_registered_and_loaded_once(self, tmp_path):
        from tests.utils.ci_matrix_loader import load_by_path

        good = tmp_path / "good.py"
        good.write_text("LOADS = []\nLOADS.append(1)\n", encoding="utf-8")
        name = "_ash_ci_matrix_loader_probe_good"
        try:
            first = load_by_path(name, good)
            assert sys.modules[name] is first
            assert load_by_path(name, good) is first
            assert first.LOADS == [1]
        finally:
            sys.modules.pop(name, None)

    def test_a_module_that_defines_a_dataclass_loads(self, tmp_path):
        """The module is registered before it runs: a frozen dataclass reads its own
        module's namespace to resolve its annotations, as the reader's do."""
        from tests.utils.ci_matrix_loader import load_by_path

        text = (
            "from __future__ import annotations\n"
            "from dataclasses import dataclass\n"
            "\n"
            "@dataclass(frozen=True)\n"
            "class Row:\n"
            "    label: str\n"
        )
        source = tmp_path / "rows.py"
        source.write_text(text, encoding="utf-8")
        name = "_ash_ci_matrix_loader_probe_rows"
        try:
            assert load_by_path(name, source).Row("x").label == "x"
        finally:
            sys.modules.pop(name, None)

    def test_the_reader_is_loaded_once_under_the_name_the_test_modules_share(self):
        from tests.utils.ci_matrix_loader import load_ci_matrix

        reader = load_ci_matrix()
        assert load_ci_matrix() is reader
        assert sys.modules["_ash_ci_matrix"] is reader
        assert reader.__file__ is not None
        assert Path(reader.__file__).resolve() == MODULE
        assert reader.cells({"runs-on": "ubuntu-latest"}) == [{}]

    @pytest.mark.parametrize("relative", CONSUMERS)
    def test_a_test_module_that_reads_the_reader_loads_it_through_the_helper(
        self, relative
    ):
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        assert "from tests.utils.ci_matrix_loader import load_ci_matrix" in text
        assert not _own_loader_lines(text, relative)

    @pytest.mark.parametrize(
        "source", list(PLANTED_LOADERS.values()), ids=list(PLANTED_LOADERS)
    )
    def test_a_loader_of_the_reader_is_found_whatever_its_shape(self, source):
        assert _own_loader_lines(source, "planted.py"), source

    @pytest.mark.parametrize(
        "source", list(PLANTED_FINE.values()), ids=list(PLANTED_FINE)
    )
    def test_a_module_that_does_not_load_the_reader_by_itself_is_not_found(
        self, source
    ):
        assert _own_loader_lines(source, "planted.py") == []

    def test_the_scan_finds_a_loader_in_any_directory_and_skips_the_exempt_files(
        self, tmp_path
    ):
        own = PLANTED_LOADERS["path_in_the_call"]
        paths = _plant(
            tmp_path,
            {
                "tests/unit/test_new.py": own,
                "tests/integration/deeper/still/test_nested.py": own,
                "tests/unit/test_fine.py": PLANTED_FINE["uses_the_helper"],
                LOADER_HELPER: own,
                THIS_FILE: own,
            },
        )
        assert _own_loaders(tmp_path, paths) == {
            "tests/unit/test_new.py": [2],
            "tests/integration/deeper/still/test_nested.py": [2],
        }

    def test_a_module_that_is_not_python_is_skipped_unless_it_names_both(
        self, tmp_path
    ):
        """A fixture that is not Python does not matter to the scan until its text
        names a loader and the reader. Then it cannot be said to hold no loader, and
        the scan stops and names it."""
        quiet = _plant(tmp_path, {"tests/data/not_python.py": "def (:\n"})
        assert _own_loaders(tmp_path, quiet) == {}
        text = "spec_from_file_location('_ash_ci_matrix', where\n"
        broken = _plant(tmp_path, {"tests/test_broken.py": text})
        with pytest.raises(SyntaxError) as caught:
            _own_loaders(tmp_path, broken)
        # str() of a SyntaxError holds the file's base name only, so the path is read
        # from the error.
        assert caught.value.filename == "tests/test_broken.py"

    def test_the_scan_reads_the_test_modules_of_the_checkout(self):
        """The denominator: a walk that found none would find no loader."""
        modules = {path.relative_to(REPO_ROOT).as_posix() for path in _test_modules()}
        assert len(modules) > 1000, len(modules)
        assert {THIS_FILE, LOADER_HELPER} <= modules
        assert OWN_LOADERS <= modules

    def test_no_test_module_loads_the_reader_with_a_loader_of_its_own(
        self, checkout_loaders
    ):
        new = {
            name: lines
            for name, lines in checkout_loaders.items()
            if name not in OWN_LOADERS
        }
        assert not new, (
            f"{new} load scripts/_ci_matrix.py with a loader of their own: use "
            "load_ci_matrix() from tests/utils/ci_matrix_loader.py"
        )

    def test_a_module_named_as_having_a_loader_of_its_own_still_has_one(
        self, checkout_loaders
    ):
        gone = sorted(OWN_LOADERS - set(checkout_loaders))
        assert not gone, (
            f"{gone} no longer load the reader with a loader of their own: take "
            "them out of OWN_LOADERS"
        )


VALIDATOR = "./.github/actions/validate-"


def _validator_steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        step for step in job["steps"] if str(step.get("uses", "")).startswith(VALIDATOR)
    ]


class TestTheRealWorkflows:
    def test_unified_ci_runs_on_every_event_with_no_path_filter(self):
        found = ci.triggers(ci.load_workflow(WORKFLOWS / "ash-unified-ci.yml"))
        assert {event: t.path_filtered for event, t in found.items()} == {
            "push": False,
            "pull_request": False,
            "merge_group": False,
            "workflow_dispatch": False,
        }

    @pytest.mark.parametrize(
        "name", ["ash-install-methods.yml", "ash-docs-ci-runners.yml"]
    )
    def test_a_path_filtered_workflow_runs_on_a_filtered_pull_request_and_a_dispatch(
        self, name
    ):
        """No push or merge-queue run backs these up, so a cell they drop on a pull
        request has no later run (the note on the install-methods cover)."""
        found = ci.triggers(ci.load_workflow(WORKFLOWS / name))
        assert {event: t.path_filtered for event, t in found.items()} == {
            "pull_request": True,
            "workflow_dispatch": False,
        }

    @pytest.mark.parametrize(
        "name",
        ["ash-unified-ci.yml", "ash-install-methods.yml", "ash-docs-ci-runners.yml"],
    )
    @pytest.mark.parametrize(
        "event", ["push", "pull_request", "merge_group", "workflow_dispatch"]
    )
    def test_every_job_of_the_matrix_workflows_expands_on_every_event(
        self, name, event
    ):
        jobs = ci.load_workflow(WORKFLOWS / name)["jobs"]
        legs = {job_id: len(ci.cells(job, event)) for job_id, job in jobs.items()}
        assert legs
        assert all(count >= 1 for count in legs.values()), legs

    def test_every_leg_of_install_methods_runs_exactly_one_validator_step(self):
        job = ci.load_workflow(WORKFLOWS / "ash-install-methods.yml")["jobs"][
            "validate"
        ]
        legs = ci.cells(job, "workflow_dispatch")
        assert len(legs) >= 50, len(legs)
        for leg in legs:
            running = [
                s.get("uses") for s in _validator_steps(job) if ci.step_runs(s, leg)
            ]
            assert len(running) == 1, (leg, running)

    def test_the_bundle_leg_runs_uvx_on_python_3_12_only(self):
        job = ci.load_workflow(WORKFLOWS / "ash-unified-ci.yml")["jobs"][
            "install-validation"
        ]
        legs = ci.cells(job, "push")
        bundle = [leg for leg in legs if leg["method"] == "bundle"]
        assert len(bundle) >= 10, len(bundle)
        for leg in bundle:
            running = {
                step["id"]
                for step in _validator_steps(job)
                if "id" in step and ci.step_runs(step, leg)
            }
            expected = {"pipx", "pip", "mcp", "precommit"}
            if leg["python-version"] == "3.12":
                expected = expected | {"uvx"}
            assert running == expected, (leg, running)
        # Every other leg is one validator: Homebrew, or a container runtime.
        others = [leg for leg in legs if leg["method"] != "bundle"]
        assert others
        for leg in others:
            running = [
                s.get("uses") for s in _validator_steps(job) if ci.step_runs(s, leg)
            ]
            assert len(running) == 1, (leg, running)
