"""Unit tests for .github/scripts/assert-pytest-required-nodes.py.

The script's own --self-test feeds it synthetic logs. These tests run a real pytest
in a subprocess and judge what it printed, so the parser is held to pytest's actual
output format rather than to a copy of it written by the same hand. The job in
ash-iac-drift.yml that uses the script also runs this file, so these negative
controls run on every push that job covers.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / ".github" / "scripts" / "assert-pytest-required-nodes.py"
WORKFLOW = REPO / ".github" / "workflows" / "ash-iac-drift.yml"

SUITE = """
import pytest

def test_alpha():
    pass

@pytest.mark.parametrize("case", ["one", "two"])
def test_beta(case):
    pass

class TestGamma:
    def test_delta(self):
        pass
"""

NODES = [
    "test_suite.py::test_alpha",
    "test_suite.py::test_beta[one]",
    "test_suite.py::test_beta[two]",
    "test_suite.py::TestGamma::test_delta",
]


@pytest.fixture(scope="module")
def guard() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "assert_pytest_required_nodes", SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_pytest(directory: Path, source: str, color: str = "no") -> str:
    """Run a real pytest over one generated module, isolated from this repo's config."""
    (directory / "test_suite.py").write_text(source, encoding="utf-8")
    # An empty ini of its own, so this repository's pytest.ini (coverage, xdist,
    # live logging) does not apply to the inner run.
    (directory / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "test_suite.py",
            "-c",
            "pytest.ini",
            "-p",
            "no:cacheprovider",
            "-p",
            "no:randomly",
            "-v",
            "-rpfEsxX",
            f"--color={color}",
        ],
        cwd=directory,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout + result.stderr


def test_self_test_passes(guard: ModuleType) -> None:
    assert guard.self_test() == 0


def test_a_real_complete_run_is_accepted(guard: ModuleType, tmp_path: Path) -> None:
    log = run_pytest(tmp_path, SUITE)
    verdict = guard.check(log, NODES, len(NODES))
    assert verdict.problems == []
    assert verdict.passed == len(NODES)


def test_a_real_colored_run_is_judged_like_a_plain_one(
    guard: ModuleType, tmp_path: Path
) -> None:
    log = run_pytest(tmp_path, SUITE, color="yes")
    assert "\x1b[" in log, "the inner run printed no color, so this test checks nothing"
    assert guard.check(log, NODES, len(NODES)).problems == []
    missing = guard.check(log, [*NODES, "test_suite.py::test_absent"], len(NODES))
    assert missing.problems == [
        "required test did not pass: test_suite.py::test_absent"
    ]


def test_a_renamed_test_is_rejected(guard: ModuleType, tmp_path: Path) -> None:
    log = run_pytest(
        tmp_path, SUITE.replace("def test_delta", "def test_delta_renamed")
    )
    verdict = guard.check(log, NODES, len(NODES))
    assert (
        "required test did not pass: test_suite.py::TestGamma::test_delta"
        in verdict.problems
    )
    # The count is unchanged by a rename, so only the node-id check catches it.
    assert verdict.passed == len(NODES)


def test_a_dropped_test_lowers_the_count_below_the_floor(
    guard: ModuleType, tmp_path: Path
) -> None:
    source = SUITE.replace('["one", "two"]', '["one"]')
    log = run_pytest(tmp_path, source)
    verdict = guard.check(
        log, [n for n in NODES if n != "test_suite.py::test_beta[two]"], len(NODES)
    )
    assert verdict.passed == len(NODES) - 1
    assert any("below the floor" in problem for problem in verdict.problems)


def test_a_skipped_test_is_rejected(guard: ModuleType, tmp_path: Path) -> None:
    source = (
        SUITE
        + '\n\ndef test_skipped():\n    pytest.skip("optional dependency absent")\n'
    )
    log = run_pytest(tmp_path, source)
    verdict = guard.check(log, NODES, len(NODES))
    assert any("1 skipped" in problem for problem in verdict.problems)


def test_a_failing_test_is_rejected(guard: ModuleType, tmp_path: Path) -> None:
    source = SUITE + "\n\ndef test_fails():\n    assert False\n"
    log = run_pytest(tmp_path, source)
    verdict = guard.check(log, NODES, len(NODES))
    assert any("1 failed" in problem for problem in verdict.problems)


def test_a_collection_error_is_rejected(guard: ModuleType, tmp_path: Path) -> None:
    log = run_pytest(tmp_path, "import a_module_that_does_not_exist\n" + SUITE)
    verdict = guard.check(log, NODES, len(NODES))
    assert any("1 error" in problem for problem in verdict.problems)
    assert any("below the floor" in problem for problem in verdict.problems)


def test_a_run_without_rp_is_rejected(guard: ModuleType, tmp_path: Path) -> None:
    (tmp_path / "test_suite.py").write_text(SUITE, encoding="utf-8")
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    log = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "test_suite.py",
            "-c",
            "pytest.ini",
            "-p",
            "no:cacheprovider",
            "-v",
            "--color=no",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    verdict = guard.check(log, NODES, len(NODES))
    assert verdict.passed == len(NODES)
    assert any("run pytest with -rp" in problem for problem in verdict.problems)


def test_main_exits_non_zero_on_a_missing_node(
    guard: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log_path = tmp_path / "run.log"
    log_path.write_text(run_pytest(tmp_path, SUITE), encoding="utf-8")
    nodes_path = tmp_path / "nodes.txt"
    nodes_path.write_text(
        "\n".join([*NODES, "test_suite.py::test_never_written"]) + "\n",
        encoding="utf-8",
    )
    assert (
        guard.main(
            ["--log", str(log_path), "--nodes", str(nodes_path), "--min-passed", "4"]
        )
        == 1
    )
    assert (
        "required test did not pass: test_suite.py::test_never_written"
        in capsys.readouterr().out
    )
    nodes_path.write_text("\n".join(NODES) + "\n", encoding="utf-8")
    assert (
        guard.main(
            ["--log", str(log_path), "--nodes", str(nodes_path), "--min-passed", "4"]
        )
        == 0
    )


def _job_block(text: str, job: str) -> str:
    match = re.search(
        rf"^  {re.escape(job)}:\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert match, f"job {job} not found in {WORKFLOW.name}"
    return match.group(1)


def test_the_workflow_job_gates_on_this_guard() -> None:
    """The job exists, runs this guard and this file, and the gate job needs it."""
    text = WORKFLOW.read_text(encoding="utf-8")
    job = _job_block(text, "planted-defect-suites")
    assert "assert-pytest-required-nodes.py --self-test" in job
    assert "tests/unit/test_assert_pytest_required_nodes.py" in job
    assert "-rpfEsxX" in job
    gate = _job_block(text, "iac-drift")
    assert re.search(r"^\s+- planted-defect-suites$", gate, re.MULTILINE)


def test_every_required_node_belongs_to_a_suite_the_job_runs() -> None:
    """A required node from a file the job does not run could never pass, and would
    fail the job for the wrong reason; one from a file nobody lists would be dead."""
    job = _job_block(WORKFLOW.read_text(encoding="utf-8"), "planted-defect-suites")
    suites = set(re.findall(r"^\s+(tests/unit/\S+\.py)(?: \\)?$", job, re.MULTILINE))
    nodes_block = re.search(
        r"<<'NODES'\n(.*?)^\s+NODES$", job, re.MULTILINE | re.DOTALL
    )
    assert nodes_block, "the NODES heredoc is missing"
    nodes = [line.strip() for line in nodes_block.group(1).splitlines() if line.strip()]
    assert nodes
    assert {node.split("::", 1)[0] for node in nodes} == suites
