# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The docs-freshness gate's parallel run gives the serial run's answers.

WHY THIS EXISTS
---------------
`scripts/verify_docs_freshness.py` runs its registry in forked worker processes,
grouped by the expensive cache each check builds, and prints the report in the
registry's order. Two properties carry the whole change and are pinned here:

- EQUIVALENCE: the parallel mode and the ``--serial`` escape hatch print the same
  report and exit with the same code, on the real tree and on synthetic
  registries. Without this pin, a grouping edit could drop a check, reorder the
  report, or lose a check's printed notes, and the lint gate would go quietly
  different from the path everyone debugs with.

- FAIL-CLOSED: a check that kills its worker (os._exit, a SystemExit, a segfault)
  is reported as ERROR -- the check did not run -- and the gate exits 2, exactly
  as a raising check always has. A worker crash must never read as a pass, and
  the checks the worker finished before dying must keep their verdicts.

The synthetic-registry tests go through ``run_gate``, the same function ``main()``
hands its literal check list to, so they exercise the real grouping, worker,
collection and printing code with planted checks instead of the 26 real ones.
"""

from __future__ import annotations

import ast
import importlib.util
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "verify_docs_freshness.py"


def _registered_check_count() -> int:
    """How many checks main() registers, read from the syntax tree.

    Parsed, not run, the way test_docs_freshness_gate_can_fail.py reads the same
    list, so the whole-registry assertion below tracks the registry instead of
    pinning today's count.
    """
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    main_fn = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    for node in ast.walk(main_fn):
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "checks" for t in node.targets)
            and isinstance(node.value, ast.List)
        ):
            return len(node.value.elts)
    raise AssertionError("could not find the `checks` list in main()")


@pytest.fixture(scope="module")
def gate():
    """Import the gate script as a module, by path, as the other gate tests do."""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    spec = importlib.util.spec_from_file_location("_ash_docs_gate_parallel", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _needs_fork(gate) -> None:
    if gate._fork_context() is None:  # pragma: no cover - Linux CI always has fork
        pytest.skip("this platform's multiprocessing has no fork start method")


def _passing() -> list[str]:
    return []


def _failing() -> list[str]:
    return ["the docs drifted", "and a second line"]


def _raising() -> list[str]:
    raise ValueError("boom")


def _printing() -> list[str]:
    # The shape check functions use for their skipped/note lines: printed while
    # the check runs, before its verdict line.
    print("        note: printed by the check itself")
    return []


def _crashing() -> list[str]:  # pragma: no cover - runs only in a worker it kills
    os._exit(13)
    return []


@pytest.mark.integration
def test_a_synthetic_registry_reports_identically_in_both_modes(gate, capsys):
    """Byte-identical reports: verdict lines, failure lines, a raising check's
    ERROR, a check's own printed notes, the summary, and the exit code."""
    _needs_fork(gate)
    checks = [
        ("a check that passes", _passing),
        ("a check that prints a note", _printing),
        ("a check that fails", _failing),
        ("a check that raises", _raising),
    ]

    serial_code = gate.run_gate(checks, serial=True)
    serial_out = capsys.readouterr().out
    parallel_code = gate.run_gate(checks, serial=False)
    parallel_out = capsys.readouterr().out

    assert serial_code == parallel_code == 2
    assert parallel_out == serial_out
    assert "PASS  a check that passes" in serial_out
    assert "        note: printed by the check itself" in serial_out
    assert "FAIL  a check that fails" in serial_out
    assert "        - the docs drifted" in serial_out
    assert "ERROR a check that raises" in serial_out
    assert "        - the check did not run: ValueError: boom" in serial_out


@pytest.mark.integration
def test_exit_codes_zero_and_one_survive_the_parallel_path(gate, capsys):
    _needs_fork(gate)
    assert gate.run_gate([("all good", _passing)], serial=False) == 0
    assert "All documentation freshness checks passed." in capsys.readouterr().out
    assert gate.run_gate([("drifted", _failing)], serial=False) == 1
    assert "Documentation is out of sync with source code." in capsys.readouterr().out


@pytest.mark.integration
def test_a_crashing_check_reports_error_and_the_gate_exits_2(gate, capsys):
    """A planted check that kills its worker outright: the checks the worker
    finished keep their verdicts, the dead one is ERROR with the worker's exit
    code, and the gate exits 2 -- never a silent pass."""
    _needs_fork(gate)
    checks = [
        ("reported before the crash", _passing),
        ("planted crash", _crashing),
    ]

    code = gate.run_gate(checks, serial=False)
    out = capsys.readouterr().out

    assert code == 2
    assert "PASS  reported before the crash" in out
    assert "ERROR planted crash" in out
    assert (
        "the worker process running this check exited with code 13 "
        "before reporting a result"
    ) in out
    assert "1 passed, 0 failed, 1 did not run, 2 total" in out


@pytest.mark.integration
@pytest.mark.slow
def test_parallel_and_serial_runs_agree_on_the_real_tree(gate, capsys):
    """main() both ways over this checkout: the same stdout, byte for byte, and
    the same exit code. Serial runs first so the parallel run's workers fork from
    a warmed parent; the cold-cache timing story is the measurement's, not this
    test's, which pins only that the two modes give one answer."""
    serial_code = gate.main(["--serial"])
    serial_out = capsys.readouterr().out
    parallel_code = gate.main([])
    parallel_out = capsys.readouterr().out

    assert serial_code == parallel_code
    assert parallel_out == serial_out
    # The report covered the whole registry, not a subset that happened to agree.
    verdicts = sum(
        line.startswith(("PASS ", "FAIL ", "ERROR "))
        for line in serial_out.splitlines()
    )
    assert verdicts == _registered_check_count()
