"""The e2e's required-node list, held to the suite without a cluster.

The kind job runs tests/e2e/require_nodes.py on its log, which only proves that what
the list names passed. This file proves the list is worth requiring:

- every id in it is still collected, so a renamed or deleted e2e test fails here, in
  the unit job, instead of when somebody next reads the e2e log;
- every test marked ``negative_control`` is in it, and a new negative control cannot be
  added without being required. Two rules back that: every test named like one must be
  marked, and every test in a class (or module) that holds a negative control must be
  marked ``negative_control`` or ``positive_control``, so naming cannot dodge it;
- the check itself rejects a log that lacks one required pass, or has it only as a
  FAILED line or inside a longer id.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.e2e.require_nodes import (
    REQUIRED_FILE,
    main,
    missing_from_log,
    required_nodes,
)

OPERATOR_DIR = Path(__file__).resolve().parents[1]
WORKFLOW = OPERATOR_DIR.parents[1] / ".github" / "workflows" / "ash-kubernetes-operator.yml"
# What a negative control is called in this suite. A test whose id matches is required
# to carry the marker, so the census does not depend on remembering it. "not_refused" is
# the positive assertion that a good run was accepted.
NEGATIVE_NAME = re.compile(
    r"Refus|(?<!not_)refus(?:e|es|ed|al)|reject|NegativeControl|CanFail|Tampered|tampered"
    r"|Incomplete|detects_a_removed|cannot_take"
)


def group_of(node: str) -> str:
    """The class a test belongs to, or its module for a test outside any class."""
    path, _, rest = node.partition("::")
    parts = rest.split("::")
    return f"{path}::{parts[0]}" if len(parts) > 1 else path


def unclassified(collected: list[str], negative: list[str], positive: list[str]) -> list[str]:
    """Tests sharing a class (or module) with a negative control that are neither kind.

    The name rule can be dodged by naming; this cannot. Once a class holds a negative
    control, every test added to it must say which it is, with
    @pytest.mark.negative_control or @pytest.mark.positive_control.
    """
    negative_set, positive_set = set(negative), set(positive)
    groups = {group_of(node) for node in negative_set}
    return sorted(
        node
        for node in collected
        if group_of(node) in groups and node not in negative_set and node not in positive_set
    )


def collect(*args: str) -> list[str]:
    env = {k: v for k, v in os.environ.items() if k != "ASH_OPERATOR_E2E"}
    env["PYTHONPATH"] = str(OPERATOR_DIR)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-o",
            "addopts=",
            "--color=no",
            "-p",
            "no:cacheprovider",
            *args,
            "tests/e2e",
        ],
        cwd=OPERATOR_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:]
    nodes = [line for line in result.stdout.splitlines() if "::" in line]
    assert nodes, f"collected nothing from tests/e2e:\n{result.stdout[-2000:]}"
    return nodes


@pytest.fixture(scope="module")
def collected() -> list[str]:
    return collect()


@pytest.fixture(scope="module")
def marked() -> list[str]:
    return collect("-m", "negative_control")


@pytest.fixture(scope="module")
def declared_positive() -> list[str]:
    return collect("-m", "positive_control")


class TestTheListMatchesTheSuite:
    def test_every_required_node_is_collected(self, collected):
        missing = sorted(set(required_nodes()) - set(collected))
        assert not missing, (
            f"{REQUIRED_FILE.name} names tests that no longer exist: {missing}. Re-point "
            f"the list deliberately; the e2e job would otherwise fail on them."
        )

    def test_every_negative_control_is_required(self, marked):
        missing = sorted(set(marked) - set(required_nodes()))
        assert not missing, f"negative controls not in {REQUIRED_FILE.name}: {missing}"

    def test_every_test_named_as_a_negative_control_is_marked(self, collected, marked):
        unmarked = sorted(n for n in collected if NEGATIVE_NAME.search(n) and n not in marked)
        assert not unmarked, f"named like negative controls but not marked: {unmarked}"

    def test_every_test_beside_a_negative_control_is_classified(
        self, collected, marked, declared_positive
    ):
        loose = unclassified(collected, marked, declared_positive)
        assert not loose, (
            f"tests in a class that holds negative controls, marked as neither: {loose}. "
            f"Mark each @pytest.mark.negative_control (and list it in {REQUIRED_FILE.name}) "
            f"or @pytest.mark.positive_control."
        )

    def test_no_test_is_both(self, marked, declared_positive):
        assert not set(marked) & set(declared_positive)

    def test_every_marked_control_matches_the_name_rule_or_its_class_does(self, marked):
        # The name rule is the backstop for a control added to a class with none; check
        # it would have seen every control there is today, by its own name or its class's.
        missed = sorted(n for n in marked if not NEGATIVE_NAME.search(n))
        assert not missed, f"the name rule misses these marked controls: {missed}"

    def test_the_census_is_not_vacuous(self, collected, marked):
        # The name rule above would pass over a suite where nothing matched it.
        assert len([n for n in collected if NEGATIVE_NAME.search(n)]) >= 10
        assert len(marked) >= 10, marked

    def test_the_eks_applier_and_the_image_locks_are_required(self):
        nodes = required_nodes()
        for module in ("test_e2e_eks_applier.py", "test_e2e_image_locks.py"):
            assert any(n.startswith(f"tests/e2e/{module}::") for n in nodes), module


class TestTheCensusCanFail:
    COLLECTED = [
        "tests/e2e/m.py::TestTheVerdictCanFail::test_one_rejected",
        "tests/e2e/m.py::TestTheVerdictCanFail::test_quietly_added",
        "tests/e2e/m.py::TestMixed::test_detects_a_removed_field",
        "tests/e2e/m.py::TestMixed::test_the_positive_half",
        "tests/e2e/m.py::TestPositiveOnly::test_anything",
        "tests/e2e/m.py::test_module_level_refusal",
        "tests/e2e/m.py::test_module_level_other",
    ]

    def test_an_unmarked_test_beside_a_control_is_reported(self):
        negative = [self.COLLECTED[0], self.COLLECTED[2], self.COLLECTED[5]]
        positive = [self.COLLECTED[3]]
        assert unclassified(self.COLLECTED, negative, positive) == [
            "tests/e2e/m.py::TestTheVerdictCanFail::test_quietly_added",
            "tests/e2e/m.py::test_module_level_other",
        ]

    def test_a_fully_classified_suite_passes(self):
        negative = [self.COLLECTED[i] for i in (0, 1, 2, 5)]
        positive = [self.COLLECTED[i] for i in (3, 6)]
        assert unclassified(self.COLLECTED, negative, positive) == []

    @pytest.mark.parametrize(
        "node",
        [
            "tests/e2e/x.py::TestAPartialScanIsIncomplete::test_ash_merge_exited_one",
            "tests/e2e/x.py::TestCrdUpgrade::test_the_api_server_refuses_dropping_it",
            "tests/e2e/x.py::T::test_a_refusal_is_recorded",
            "tests/e2e/x.py::T::test_it_is_refused",
            "tests/e2e/x.py::T::test_the_bad_one_is_rejected",
            "tests/e2e/x.py::T::test_without_the_crd_it_cannot_take_a_scan",
        ],
    )
    def test_the_name_rule_sees_each_spelling(self, node):
        assert NEGATIVE_NAME.search(node), node

    def test_the_name_rule_spares_the_positive_spelling(self):
        assert not NEGATIVE_NAME.search("tests/e2e/x.py::T::test_it_is_not_refused")


ALL = ["tests/e2e/a.py::T::test_one", "tests/e2e/a.py::T::test_two[x-y z]"]


def log_of(*lines: str) -> str:
    return "\n".join(["===== short test summary info =====", *lines, "== 2 passed =="])


class TestTheCheckCanFail:
    def test_a_log_with_every_pass_is_accepted(self):
        assert missing_from_log(log_of(*(f"PASSED {n}" for n in ALL)), ALL) == []

    def test_a_missing_pass_is_reported(self):
        assert missing_from_log(log_of(f"PASSED {ALL[0]}"), ALL) == [ALL[1]]

    def test_a_failed_line_is_not_a_pass(self):
        log = log_of(f"PASSED {ALL[0]}", f"FAILED {ALL[1]} - AssertionError")
        assert missing_from_log(log, ALL) == [ALL[1]]

    def test_a_longer_id_is_not_a_pass(self):
        log = log_of(f"PASSED {ALL[0]}", f"PASSED {ALL[1]}_extra")
        assert missing_from_log(log, ALL) == [ALL[1]]

    def test_an_empty_list_is_refused(self, tmp_path):
        empty = tmp_path / "nodes.txt"
        empty.write_text("# nothing\n\n")
        with pytest.raises(ValueError, match="no node ids"):
            required_nodes(empty)

    def test_a_duplicate_is_refused(self, tmp_path):
        twice = tmp_path / "nodes.txt"
        twice.write_text(f"{ALL[0]}\n{ALL[0]}\n")
        with pytest.raises(ValueError, match="more than once"):
            required_nodes(twice)

    def test_the_command_fails_on_the_real_list_when_one_pass_is_dropped(self, tmp_path):
        nodes = required_nodes()
        full = tmp_path / "full.log"
        full.write_text(log_of(*(f"PASSED {n}" for n in nodes)))
        assert main([str(full)]) == 0
        dropped = tmp_path / "dropped.log"
        dropped.write_text(log_of(*(f"PASSED {n}" for n in nodes[1:])))
        assert main([str(dropped)]) == 1

    def test_a_log_without_summary_lines_fails(self, tmp_path, capsys):
        bare = tmp_path / "bare.log"
        bare.write_text("collected 98 items\n98 passed\n")
        assert main([str(bare)]) == 1
        assert "-rp" in capsys.readouterr().out


class TestTheWorkflowRunsIt:
    def e2e_script(self) -> str:
        workflow = yaml.safe_load(WORKFLOW.read_text())
        steps = workflow["jobs"]["e2e-kind"]["steps"]
        (step,) = [s for s in steps if s.get("name") == "End to end against kind"]
        return step["run"]

    def test_the_suite_prints_a_pass_line_per_test(self):
        script = self.e2e_script()
        assert re.search(r"python -m pytest tests/e2e .*-rp", script), script

    def test_the_check_runs_on_the_log_after_the_suite(self):
        script = self.e2e_script()
        suite = script.index("tee e2e.log")
        check = script.index("python -m tests.e2e.require_nodes e2e.log")
        assert check > suite, script

    def test_the_list_is_not_also_inlined_in_the_workflow(self):
        # One list. A second copy in the workflow is the one nobody updates.
        assert "tests/e2e/test_e2e_" not in self.e2e_script()
