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
import multiprocessing
import os
import re
import sys
import time
import threading
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


@pytest.fixture(autouse=True)
def _one_thread(gate, monkeypatch):
    """Let the gate fork from this test process.

    The gate forks only from a single-threaded process, and a pytest-xdist worker
    has execnet's receiver thread, so under xdist the gate would otherwise take the
    serial path and every fork test below would skip. The gate reads its platform
    and thread count through one small function, ``_fork_environment``; this
    reports the real platform with a count of one, on the gate module only, so
    ``threading`` and ``sys`` stay untouched for everything else in the process.
    The tests that pin the guard set their own answer after this.
    """
    monkeypatch.setattr(gate, "_fork_environment", lambda: (sys.platform, 1))


def _needs_fork(gate) -> None:
    if gate._fork_context() is None:  # pragma: no cover - Linux CI always has fork
        pytest.skip("this platform cannot fork the gate's workers")


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
def test_parallel_and_serial_runs_agree_on_the_real_tree():
    """The script both ways over this checkout, each in its own fresh process: the
    same stdout, byte for byte, and the same exit code.

    Fresh processes, parallel first. A check that reads process state (an import
    an earlier check left in sys.modules, a warmed lru_cache) answers from a cold
    worker differently from the way it answers in a warm serial run; an in-process
    comparison that ran serial first forked its workers from a parent that held
    every cache, so a cold worker's different answer could not show.
    """
    import subprocess

    from tests.utils.helpers import checkout_env

    if not sys.platform.startswith("linux"):  # pragma: no cover - Linux CI
        pytest.skip("the gate forks only on Linux, so there is no parallel run here")

    def run(*extra: str) -> tuple[int, str, str]:
        done = subprocess.run(
            [sys.executable, str(SCRIPT), *extra],
            cwd=REPO_ROOT,
            env=checkout_env(),
            capture_output=True,
            text=True,
            check=False,
        )
        return done.returncode, done.stdout, done.stderr

    parallel_code, parallel_out, parallel_err = run()
    serial_code, serial_out, serial_err = run("--serial")

    # The comparison means something only if the first run really forked: the gate
    # says which mode ran on stderr, and a serial run of both would agree trivially.
    assert re.search(r"running \d+ checks in \d+ workers", parallel_err), parallel_err
    assert "running serially: --serial" in serial_err, serial_err
    assert serial_code == parallel_code
    assert parallel_out == serial_out
    # The report covered the whole registry, not a subset that happened to agree.
    verdicts = sum(
        line.startswith(("PASS ", "FAIL ", "ERROR "))
        for line in serial_out.splitlines()
    )
    assert verdicts == _registered_check_count()


def _hang_after_closing_the_pipe(checks, indices, sender) -> None:
    """A worker body that sends nothing, closes its pipe, and then does not exit."""
    import time

    sender.close()
    time.sleep(120)


def _sleeps_a_long_time() -> list[str]:
    import time

    time.sleep(120)
    return []


def _live_workers() -> list[str]:
    return [
        p.name
        for p in multiprocessing.active_children()
        if p.name.startswith("docs-freshness-")
    ]


@pytest.mark.integration
def test_a_worker_that_will_not_exit_is_terminated_and_reported(
    gate, monkeypatch, capsys
):
    """join() has a timeout: a worker that closed its pipe and hung is terminated,
    its unreported check is ERROR (exit 2), and the gate returns instead of
    blocking in join() forever."""
    _needs_fork(gate)
    monkeypatch.setattr(gate, "_run_group", _hang_after_closing_the_pipe)
    monkeypatch.setattr(gate, "_WORKER_EXIT_TIMEOUT_S", 0.5)
    monkeypatch.setattr(gate, "_WORKER_KILL_GRACE_S", 0.5)

    code = gate.run_gate([("never reports", _passing)], serial=False)
    out = capsys.readouterr().out

    assert code == 2
    assert "ERROR never reports" in out
    assert "did not exit within 0.5s of closing its pipe and was terminated" in out
    assert _live_workers() == []


@pytest.mark.integration
def test_dropping_the_generator_stops_every_live_worker(gate, monkeypatch):
    """A consumer that stops early (run_gate raising while it prints, a closed
    pipe under `| head`) must not leave workers behind: they are not daemons, so
    the interpreter would wait for the slow one at exit."""
    _needs_fork(gate)
    monkeypatch.setattr(gate, "_check_groups", lambda: {_sleeps_a_long_time: "slow"})
    checks = [("fast", _passing), ("slow", _sleeps_a_long_time)]

    results = gate._iter_parallel(checks, gate._fork_context())
    try:
        first = next(results)
        assert first[0] == "fast"
        # The fast worker may still be tearing down; the slow one is certainly up.
        assert "docs-freshness-slow" in _live_workers()
        results.close()
        assert _live_workers() == []
    finally:
        for process in multiprocessing.active_children():
            if process.name.startswith("docs-freshness-"):
                process.kill()
                process.join()


def _records_its_process() -> list[str]:
    return [str(os.getpid())]


@pytest.mark.integration
@pytest.mark.parametrize(
    "unsafe",
    ["thread", "platform"],
)
def test_the_gate_runs_serially_where_forking_is_not_safe(
    gate, monkeypatch, capsys, unsafe
):
    """Another thread alive, or a platform other than Linux: no fork, the checks
    run in this process, and stderr says so and why."""
    if unsafe == "thread":
        monkeypatch.setattr(gate, "_fork_environment", lambda: ("linux", 2))
    else:
        monkeypatch.setattr(gate, "_fork_environment", lambda: ("darwin", 1))
    assert gate._fork_context() is None

    gate.run_gate([("which process", _records_its_process)], serial=False)
    captured = capsys.readouterr()

    # The check reports its own pid as its failure line: it ran in this process.
    assert f"        - {os.getpid()}" in captured.out
    assert "running serially: " in captured.err
    assert ("2 threads" if unsafe == "thread" else "darwin") in captured.err


@pytest.mark.integration
def test_the_gate_says_which_mode_ran(gate, capsys):
    """The mode goes to stderr (stdout is the report the two modes must share), so
    a run that silently fell back to serial cannot be taken for a parallel one."""
    _needs_fork(gate)
    checks = [("one", _passing), ("two", _passing)]

    gate.run_gate(checks, serial=False)
    err = capsys.readouterr().err
    assert "running 2 checks in 1 workers" in err

    gate.run_gate(checks, serial=True)
    err = capsys.readouterr().err
    assert "running serially: --serial" in err
    assert "workers" not in err


@pytest.mark.integration
def test_a_fork_decision_that_flips_between_calls_cannot_turn_into_exit_1(
    gate, monkeypatch, capsys
):
    """The decision is taken once and handed to the parallel runner. If a second
    read of the environment would now say "not safe" (a thread started in between),
    the run must still finish with the verdicts, never die on a missing context
    (a traceback is exit 1, which the gate reports as "docs drifted")."""
    _needs_fork(gate)
    answers = iter([(sys.platform, 1)] + [("darwin", 9)] * 50)
    monkeypatch.setattr(gate, "_fork_environment", lambda: next(answers))

    code = gate.run_gate([("steady", _passing)], serial=False)
    out = capsys.readouterr().out

    assert code == 0
    assert "PASS  steady" in out


@pytest.mark.integration
def test_the_parallel_runner_without_a_context_falls_back_to_serial(gate):
    """None is what the decision returns where forking is unsafe: the runner must
    give the serial answers, not raise AttributeError on ``None.Pipe``."""
    results = list(gate._iter_parallel([("one", _passing)], None))

    assert results == [("one", "", "ok", [])]


@pytest.mark.integration
@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="reads /proc/self/task"
)
def test_the_thread_guard_counts_os_threads_not_python_threads(gate, monkeypatch):
    """On Linux the count is the process's real thread count, which sees a thread
    the threading module never heard of (a native library's, or one started with
    ``_thread``) -- the count CPython's own fork warning uses."""
    import _thread

    monkeypatch.undo()  # the autouse fixture's one-thread answer is not under test
    release = threading.Event()
    started = threading.Event()

    def _park() -> None:
        started.set()
        release.wait(30)

    before_python = threading.active_count()
    before_os = gate._fork_environment()[1]
    _thread.start_new_thread(_park, ())
    try:
        assert started.wait(10)
        platform, count = gate._fork_environment()
        assert platform == sys.platform
        assert threading.active_count() == before_python  # invisible to threading
        assert count == before_os + 1  # visible to the OS count
        assert len(os.listdir("/proc/self/task")) == count
    finally:
        release.set()


@pytest.mark.integration
def test_a_hung_teardown_after_every_result_does_not_stall_the_others(
    gate, monkeypatch, capsys
):
    """A worker that has sent everything and closed its pipe but will not exit is
    reaped at the end, not waited for in the middle: the other group's results are
    collected at once, the run is not slowed by the join bound, and nothing is
    reported against a group that had already reported."""
    _needs_fork(gate)
    real_run_group = gate._run_group

    def _slow_exit(checks, indices, sender) -> None:
        real_run_group(checks, indices, sender)
        time.sleep(120)

    monkeypatch.setattr(gate, "_run_group", _slow_exit)
    monkeypatch.setattr(gate, "_check_groups", lambda: {_passing: "a", _failing: "b"})
    monkeypatch.setattr(gate, "_WORKER_EXIT_TIMEOUT_S", 8.0)
    monkeypatch.setattr(gate, "_WORKER_EXIT_GRACE_S", 0.2)
    monkeypatch.setattr(gate, "_WORKER_KILL_GRACE_S", 0.5)

    started = time.monotonic()
    code = gate.run_gate([("quiet", _passing), ("loud", _failing)], serial=False)
    elapsed = time.monotonic() - started
    out = capsys.readouterr().out

    assert code == 1
    assert "PASS  quiet" in out
    assert "FAIL  loud" in out
    assert "ERROR" not in out
    assert elapsed < 4.0
    assert _live_workers() == []


@pytest.mark.integration
def test_a_worker_that_is_exiting_cleanly_gets_a_grace_before_terminate(
    gate, monkeypatch
):
    """The end-of-run reap joins briefly before it terminates, so a worker in the
    middle of a normal exit finishes with its own exit code, not SIGTERM's."""
    _needs_fork(gate)
    real_run_group = gate._run_group

    def _short_exit(checks, indices, sender) -> None:
        real_run_group(checks, indices, sender)
        time.sleep(0.5)

    exit_codes: list[int | None] = []
    real_stop = gate._stop_worker

    def _spy(process, grace=0.0) -> None:
        real_stop(process, grace)
        exit_codes.append(process.exitcode)

    monkeypatch.setattr(gate, "_run_group", _short_exit)
    monkeypatch.setattr(gate, "_stop_worker", _spy)
    monkeypatch.setattr(gate, "_WORKER_EXIT_GRACE_S", 5.0)

    assert list(gate._iter_parallel([("one", _passing)], gate._fork_context()))
    assert exit_codes == [0]


@pytest.mark.integration
def test_a_silent_worker_is_named_and_reported_when_nothing_arrives(
    gate, monkeypatch, capsys
):
    """connection_wait has a bound: a worker that holds its pipe open and sends
    nothing (a deadlock on a lock inherited through fork) is terminated and its
    checks are ERROR naming the worker, instead of the run waiting forever."""
    _needs_fork(gate)

    def _deadlocked(checks, indices, sender) -> None:
        time.sleep(120)

    monkeypatch.setattr(gate, "_run_group", _deadlocked)
    monkeypatch.setattr(gate, "_WORKER_IDLE_TIMEOUT_S", 0.5)
    monkeypatch.setattr(gate, "_WORKER_KILL_GRACE_S", 0.5)

    code = gate.run_gate([("never answers", _passing)], serial=False)
    out = capsys.readouterr().out

    assert code == 2
    assert "ERROR never answers" in out
    assert "docs-freshness-misc" in out
    assert "no result for 0.5s" in out
    assert _live_workers() == []


@pytest.mark.unit
def test_the_serial_help_matches_when_the_gate_runs_serially(gate, capsys):
    with pytest.raises(SystemExit):
        gate.main(["--help"])
    flat = " ".join(capsys.readouterr().out.split())

    assert "Platforms without fork always run serially" not in flat
    assert "non-Linux" in flat
    assert "more than one thread" in flat


@pytest.mark.integration
@pytest.mark.parametrize("serial", [True, False])
def test_a_check_that_returns_none_did_not_run(gate, capsys, serial):
    """The conversion of a check's result is inside the try: a check returning
    None is an ERROR for that check in both modes (exit 2), not a traceback and
    not a worker that dies and blames the checks after it."""
    if not serial:
        _needs_fork(gate)

    def _returns_none():
        return None

    checks = [
        ("returns none", _returns_none),
        ("after it", _passing),
    ]
    assert gate._execute_check(_returns_none)[0] == "error"
    code = gate.run_gate(checks, serial=serial)
    out = capsys.readouterr().out

    assert code == 2
    assert "ERROR returns none" in out
    assert "the check did not run: TypeError" in out
    assert "PASS  after it" in out


@pytest.mark.unit
def test_main_leaves_the_collector_as_it_found_it(gate, monkeypatch):
    """main() is called in-process by the gate's own suites. It must not freeze
    the caller's heap or switch the collector: both are process-wide."""
    import gc

    monkeypatch.setattr(gate, "run_gate", lambda checks, serial=False: 0)
    was_enabled = gc.isenabled()
    frozen_before = gc.get_freeze_count()
    try:
        assert gate.main(["--serial"]) == 0
        assert gc.isenabled() is was_enabled
        assert gc.get_freeze_count() == frozen_before
    finally:
        if not was_enabled:
            gc.disable()


@pytest.mark.unit
def test_the_script_entry_point_turns_the_collector_off(gate):
    """The collector is switched off, and the heap frozen at exit, only where the
    process is about to end: the __main__ block hands main() to _run_as_script."""
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    entry = next(
        node
        for node in tree.body
        if isinstance(node, ast.If) and "__main__" in ast.dump(node.test)
    )
    assert "_run_as_script" in ast.dump(entry)
    runner = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_run_as_script"
    )
    called = {
        node.func.attr
        for node in ast.walk(runner)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert {"disable", "freeze"} <= called
