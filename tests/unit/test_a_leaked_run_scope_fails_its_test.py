# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A test that leaks a run log scope fails, by name, instead of passing.

The suite's guard closes a leaked scope so the next test is not poisoned. A
guard that closed it silently let the leaking test pass, so the defect -- a
scope that would hold back every line no run owns for the rest of a real
server process -- never surfaced. The leaking test runs in a child pytest, so
this suite itself stays green while the failure is measured.
"""

import ast
from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple

import pytest

from tests.utils.helpers import run_a_child_pytest_under_this_suite

# The child pytest runs under the suite's own conftest, whose collection hook
# refuses any test without exactly one tier marker. The probes measure scope
# leaks, not tiers, so the marker is appended here once instead of being written
# into each probe's source; a probe that marks itself is left as written, and a
# probe whose own pytestmark names no tier (usefixtures, filterwarnings, skipif)
# keeps those marks: the tier is added to them, never written over them.
_A_TIER_FOR_THE_PROBE = """

import pytest

pytestmark = pytest.mark.unit
"""

_A_TIER_ADDED_TO_THE_PROBES_MARKS = """

import pytest

pytestmark = [
    *(pytestmark if isinstance(pytestmark, (list, tuple)) else [pytestmark]),
    pytest.mark.unit,
]
"""


_TIERS = {"unit", "integration", "e2e"}


def _pytestmark_assignments(source: str) -> list | None:
    """The module-level ``pytestmark = ...`` statements of *source*, or ``None``
    when *source* does not parse: the child's own collection then reports the
    syntax error, which a probe may exist to measure."""
    try:
        module = ast.parse(source)
    except SyntaxError:
        return None
    return [
        statement
        for statement in module.body
        if isinstance(statement, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "pytestmark"
            for target in statement.targets
        )
    ]


def _names_a_tier(assignments: list) -> bool:
    """Whether one of the ``pytestmark`` *assignments* carries a tier mark.

    Read with ``ast``: a ``pytestmark = pytest.mark.usefixtures(...)`` line, or
    the word in a comment or docstring, is not a tier.
    """
    for statement in assignments:
        for node in ast.walk(statement.value):
            if (
                isinstance(node, ast.Attribute)
                and node.attr in _TIERS
                and isinstance(node.value, ast.Attribute)
                and node.value.attr == "mark"
            ):
                return True
    return False


def _with_a_tier(source: str) -> str:
    """*source* with the collection hook's one-tier requirement satisfied.

    A source with no ``pytestmark`` gets ``pytestmark = pytest.mark.unit``; one
    whose ``pytestmark`` names no tier gets the tier added to its own marks (a
    second plain assignment would replace them silently); one that names a tier,
    or does not parse, is left as written.
    """
    assignments = _pytestmark_assignments(source)
    if assignments is None or _names_a_tier(assignments):
        return source
    if assignments:
        return source + _A_TIER_ADDED_TO_THE_PROBES_MARKS
    return source + _A_TIER_FOR_THE_PROBE


def _run_probe(
    tmp_path: Path,
    kind: str,
    source: str,
    options: Sequence[str] = (),
    extra_files: Optional[Dict[str, str]] = None,
) -> Tuple[int, str]:
    """Run *source* as a test module in a child pytest under the suite's own
    conftest, in definition order, and give its exit code and output. The
    child's environment is the helper's own, not this run's: the guards'
    failure text these cells assert passes through the report backstop, which
    redacts every environment value from it. *extra_files* (holder-relative
    paths to contents) build a probe of more than one module, such as a real
    package; the child then collects them in name order before *source*'s
    ``test_zz`` module."""
    if extra_files is not None:
        extra_files = {
            path: _with_a_tier(text) if Path(path).name.startswith("test_") else text
            for path, text in extra_files.items()
        }
    completed = run_a_child_pytest_under_this_suite(
        _with_a_tier(source),
        tmp_path,
        prefix=f"{kind}check-",
        # Definition order is the measurement where a probe's later test
        # reads what an earlier one left.
        options=("-q", "-p", "no:randomly", *options),
        extra_files=extra_files,
    )
    return completed.returncode, completed.stdout + completed.stderr


@pytest.mark.unit
def test_a_probe_without_a_tier_is_given_one():
    source = "def test_zz():\n    pass\n"

    tiered = _with_a_tier(source)

    assert tiered.startswith(source)
    assert tiered.count("pytestmark = pytest.mark.unit") == 1


def _marks_in_effect(source: str) -> list:
    """The names of the marks the module-level ``pytestmark`` of *source* holds
    once Python has run it, in the order pytest reads them."""
    namespace: dict = {}
    exec(compile(source, "<probe>", "exec"), namespace)  # noqa: S102 - the probe's own text
    marks = namespace["pytestmark"]
    if not isinstance(marks, (list, tuple)):
        marks = [marks]
    return [mark.name for mark in marks]


@pytest.mark.unit
def test_a_probe_whose_pytestmark_is_not_a_tier_keeps_its_marks_and_gains_one():
    """``pytestmark = pytest.mark.usefixtures(...)`` names no tier, so the child
    would refuse to collect the probe. The tier is added to the probe's own
    marks: a second plain ``pytestmark =`` would replace them and the
    ``usefixtures`` would be gone without any error."""
    source = (
        "import pytest\n\n"
        'pytestmark = pytest.mark.usefixtures("tmp_path")\n\n\n'
        "def test_zz():\n    pass\n"
    )

    tiered = _with_a_tier(source)

    assert tiered.startswith(source)
    assert _marks_in_effect(tiered) == ["usefixtures", "unit"]


@pytest.mark.unit
def test_a_probe_whose_pytestmark_is_a_list_keeps_every_mark_and_gains_one():
    source = (
        "import pytest\n\n"
        "pytestmark = [\n"
        '    pytest.mark.usefixtures("tmp_path"),\n'
        '    pytest.mark.filterwarnings("ignore"),\n'
        "]\n\n\n"
        "def test_zz():\n    pass\n"
    )

    tiered = _with_a_tier(source)

    assert tiered.startswith(source)
    assert _marks_in_effect(tiered) == ["usefixtures", "filterwarnings", "unit"]


@pytest.mark.unit
@pytest.mark.parametrize("tier", ["unit", "integration", "e2e"])
def test_a_probe_that_marks_its_own_tier_is_left_as_written(tier):
    source = f"import pytest\n\npytestmark = pytest.mark.{tier}\n\n\ndef test_zz():\n    pass\n"

    assert _with_a_tier(source) == source


@pytest.mark.unit
def test_a_probe_that_does_not_parse_is_left_for_the_child_to_report():
    """A probe written to fail at collection keeps its syntax error for the
    child; the helper neither raises nor marks it."""
    source = "def test_zz(:\n    pass\n"

    assert _with_a_tier(source) == source


_LEAKING_TEST = """\
from automated_security_helper.utils.log import open_run_log_scope


def test_that_leaks_a_scope():
    open_run_log_scope()
"""


@pytest.mark.integration
def test_a_test_that_leaks_a_scope_fails_and_the_failure_names_it(
    tmp_path: Path,
) -> None:
    returncode, output = _run_probe(tmp_path, "leak", _LEAKING_TEST)
    if "1 passed" not in output and "1 failed" not in output:
        raise RuntimeError(("control: the probe did not run", output[-2000:]))
    assert returncode != 0, (
        "a test that leaked a run log scope passed",
        output[-2000:],
    )
    assert "a run log scope outlived this test" in output, (
        "the failure does not name the leak",
        output[-2000:],
    )


_POISONING_TEST = """\
from automated_security_helper.utils.log import (
    close_run_log_scope,
    current_run_log_scope,
    open_run_log_scope,
)


def test_aa_closes_its_own_scope_by_value():
    scope, _token = open_run_log_scope()
    # By value, on the test's own thread: no scope is left open, so the
    # suite's guard sees nothing leaked, but the context variable stays set.
    close_run_log_scope(scope)


def test_zz_the_following_test_runs_in_no_scope():
    assert current_run_log_scope() is None
"""


@pytest.mark.integration
def test_a_scope_closed_by_value_does_not_poison_the_following_test(
    tmp_path: Path,
) -> None:
    """A test that closes its own scope by value leaves no scope open, so the
    guard's leak check has nothing to close -- but the context variable still
    names the closed scope on that worker. The guard puts the variable back
    whether or not anything leaked; while the restore sat behind the
    nothing-leaked early return, the next test on the worker ran inside a
    closed scope (the order-dependent class)."""
    # The by-value close runs before the test that reads the variable.
    returncode, output = _run_probe(tmp_path, "poison", _POISONING_TEST)
    if "2 passed" not in output and "failed" not in output:
        raise RuntimeError(("control: the probes did not run", output[-2000:]))
    assert returncode == 0 and "2 passed" in output, (
        "the test after a scope closed by value ran inside that scope",
        output[-2000:],
    )


_MODULE_FIXTURE_LEAK = """\
import pytest

from automated_security_helper.utils.log import open_run_log_scope


@pytest.fixture(scope="module")
def _a_scope_for_the_module():
    open_run_log_scope()
    yield


def test_aa_uses_the_module_fixture(_a_scope_for_the_module):
    pass


def test_zz_uses_nothing():
    pass
"""


@pytest.mark.integration
def test_a_scope_a_module_fixture_leaks_is_not_blamed_on_the_last_test(
    tmp_path: Path,
) -> None:
    """A module-scoped fixture's scope is caught when the module ends, and
    pytest shows that failure on the module's last test, which here never
    touched it: the failure names the module's fixtures, not that test."""
    returncode, output = _run_probe(tmp_path, "module", _MODULE_FIXTURE_LEAK)
    if "2 passed" not in output:
        raise RuntimeError(("control: the probes did not run", output[-2000:]))
    assert returncode != 0 and "1 error" in output, (
        "a scope a module fixture leaked did not fail the module",
        output[-2000:],
    )
    assert "a run log scope outlived this test" not in output, (
        "the module's leak is blamed on its last test",
        output[-2000:],
    )
    assert "outlived the module- and class-scoped fixtures of" in output, (
        "the failure does not name the module's fixtures",
        output[-2000:],
    )


_CLOSE_THAT_RAISES_ONCE = """\
from automated_security_helper.utils import log

_real_close = log.close_run_log_scope
_raised_for = []


def _close_raising_the_first_time(scope):
    if not _raised_for:
        _raised_for.append(scope)
        raise RuntimeError("this close fails")
    _real_close(scope)


def test_aa_leaks_two_scopes():
    log.close_run_log_scope = _close_raising_the_first_time
    log.open_run_log_scope()
    log.open_run_log_scope()


def test_zz_only_the_scope_whose_close_raised_is_left():
    log.close_run_log_scope = _real_close
    left = set(log._ACTIVE_RUN_LOG_SCOPES)
    for scope in left:
        _real_close(scope)
    assert left == set(_raised_for)
"""


@pytest.mark.integration
def test_a_close_that_raises_leaves_the_other_scopes_closed_and_fails_once(
    tmp_path: Path,
) -> None:
    """Each leaked scope is closed on its own: a close that raises does not
    leave the scopes after it open, and the test fails once, naming the
    scopes it closed and the one it could not, rather than with the close's
    error."""
    returncode, output = _run_probe(tmp_path, "close", _CLOSE_THAT_RAISES_ONCE)
    if "passed" not in output and "failed" not in output:
        raise RuntimeError(("control: the probes did not run", output[-2000:]))
    assert returncode != 0 and "2 passed, 1 error" in output, (
        "the leak did not fail exactly once, or a scope was left open",
        output[-2000:],
    )
    assert "could not be closed" in output and "this close fails" not in output, (
        "the failure is the close's error, not the guard's",
        output[-2000:],
    )


_WIDE_FIXTURE_LEAK = """\
import pytest

from automated_security_helper.utils.log import open_run_log_scope


@pytest.fixture(scope={scope!r})
def _a_scope_for_the_run():
    open_run_log_scope()
    yield


def test_aa_uses_the_wide_fixture(_a_scope_for_the_run):
    pass


def test_zz_uses_nothing():
    pass
"""


@pytest.mark.integration
def test_a_scope_a_session_fixture_leaks_fails_the_run(tmp_path: Path) -> None:
    """A session-scoped fixture is set up before the module's guard takes its
    count, and torn down after it, so neither the test's nor the module's
    guard sees its scope: the session-end check does, after pytest tears the
    session's fixtures down, and fails the run naming the scope."""
    returncode, output = _run_probe(
        tmp_path, "session", _WIDE_FIXTURE_LEAK.format(scope="session")
    )
    if "2 passed" not in output:
        raise RuntimeError(("control: the probes did not run", output[-2000:]))
    assert returncode != 0, (
        "a scope a wide fixture leaked did not fail the run",
        output[-2000:],
    )
    assert "a run log scope was still open when the session ended" in output, (
        "the failure does not name the leak",
        output[-2000:],
    )


_LEAK_THEN_A_FAILURE = """\
import pytest

from automated_security_helper.utils.log import open_run_log_scope


@pytest.fixture(scope="session")
def _a_scope_for_the_run():
    open_run_log_scope()
    yield


def test_aa_fails(_a_scope_for_the_run):
    assert False


def test_zz_would_run_next():
    pass
"""


@pytest.mark.integration
def test_a_leak_is_reported_when_the_run_is_stopped_early(tmp_path: Path) -> None:
    """``-x`` ends the run after the first failure, while a next test still
    exists: the session's fixtures are then torn down in pytest's own
    sessionfinish, outside every test's protocol. A guard that raised there
    crashed the run with a bare traceback, printed no summary, and skipped
    ``pytest_unconfigure``. The leak is reported with the run's own summary
    instead, and the run fails."""
    returncode, output = _run_probe(
        tmp_path, "stopped", _LEAK_THEN_A_FAILURE, options=("-x",)
    )
    if "1 failed" not in output:
        raise RuntimeError(("control: the probe did not fail under -x", output[-3000:]))
    assert returncode != 0
    assert "a run log scope was still open when the session ended" in output, (
        "the stopped run does not report the leak",
        output[-3000:],
    )
    assert "Traceback" not in output and "INTERNALERROR" not in output, (
        "the guard crashed the stopped run instead of reporting",
        output[-3000:],
    )


_LEAK_AT_IMPORT_THEN_A_COLLECTION_ERROR = """\
from automated_security_helper.utils.log import open_run_log_scope

open_run_log_scope()

raise ImportError("this module does not collect")
"""


@pytest.mark.integration
def test_a_leak_is_reported_when_no_test_ran(tmp_path: Path) -> None:
    """A module that opens a scope at import and then fails to collect runs no
    test, so no fixture -- the guards included -- is ever set up: the leak
    went unreported, named by nothing in the output. The session-end check
    runs whether or not a test did, and reports it."""
    returncode, output = _run_probe(
        tmp_path, "notests", _LEAK_AT_IMPORT_THEN_A_COLLECTION_ERROR
    )
    if "this module does not collect" not in output:
        raise RuntimeError(("control: the collect error is missing", output[-3000:]))
    assert returncode != 0
    assert "a run log scope was still open when the session ended" in output, (
        "a leak with no test run went unreported",
        output[-3000:],
    )


_LEAK_THEN_AN_INTERRUPT = """\
import pytest

from automated_security_helper.utils.log import open_run_log_scope


@pytest.fixture(scope="session")
def _a_scope_for_the_run():
    open_run_log_scope()
    yield


def test_aa_interrupts_the_run(_a_scope_for_the_run):
    raise KeyboardInterrupt


def test_zz_would_run_next():
    pass
"""


@pytest.mark.integration
def test_a_leak_is_reported_when_the_run_is_interrupted(tmp_path: Path) -> None:
    """An interrupt ends the run outside every test's protocol: the session's
    fixtures are torn down in pytest's own sessionfinish, and a guard that
    raised there crashed the run with a bare error instead of reporting. The
    leak is reported with the interrupted run's own summary."""
    returncode, output = _run_probe(tmp_path, "intr", _LEAK_THEN_AN_INTERRUPT)
    if "KeyboardInterrupt" not in output:
        raise RuntimeError(("control: the probe was not interrupted", output[-3000:]))
    assert returncode != 0
    assert "a run log scope was still open when the session ended" in output, (
        "the interrupted run does not report the leak",
        output[-3000:],
    )
    assert "INTERNALERROR" not in output, (
        "the guard crashed the interrupted run instead of reporting",
        output[-3000:],
    )


_COLLECTION_LEAK = """\
from automated_security_helper.utils.log import open_run_log_scope

open_run_log_scope()


def test_aa_runs_after_the_module_opened_a_scope():
    pass


def test_zz_uses_nothing():
    pass
"""


@pytest.mark.integration
def test_a_scope_opened_while_tests_are_collected_fails_the_run(
    tmp_path: Path,
) -> None:
    """A scope opened at import, while the module is collected, is open before
    any guard takes its count: the session-end check counts every scope still
    open, so it fails the run too, and its message names code run at import
    or collection rather than blaming only fixtures."""
    returncode, output = _run_probe(tmp_path, "collect", _COLLECTION_LEAK)
    if "2 passed" not in output:
        raise RuntimeError(("control: the probes did not run", output[-2000:]))
    assert returncode != 0, (
        "a scope opened at collection did not fail the run",
        output[-2000:],
    )
    assert "a run log scope was still open when the session ended" in output, (
        "the failure does not name the leak",
        output[-2000:],
    )
    assert "code run at import or collection" in output, (
        "the message does not name collection-time code as a source",
        output[-2000:],
    )


_SCOPES_RENAMED = """\
from automated_security_helper.utils import log


def test_aa_renames_the_open_scopes():
    # As a rename in utils/log.py would leave the guards: the set they read
    # is gone.
    log._RENAMED_ACTIVE_RUN_LOG_SCOPES = log.__dict__.pop("_ACTIVE_RUN_LOG_SCOPES")


def test_zz_uses_nothing():
    pass
"""


@pytest.mark.integration
def test_a_guard_whose_scope_set_is_renamed_fails_the_run(tmp_path: Path) -> None:
    """The guards read utils/log.py's set of open scopes by its name, with no
    fallback: if it is renamed they error, rather than read an empty set and
    pass every leak from then on. The test that renamed it passes its own
    call and errors at its teardown, with the missing name -- not with the
    probe's own KeyError or a source line echoed for some other failure."""
    returncode, output = _run_probe(
        tmp_path, "renamed", _SCOPES_RENAMED, options=("-rA",)
    )
    passed_lines = [
        line
        for line in output.splitlines()
        if "PASSED" in line and "test_aa_renames_the_open_scopes" in line
    ]
    if not passed_lines:
        raise RuntimeError(
            ("control: the renaming test did not run and pass", output[-2000:])
        )
    assert returncode != 0, (
        "the guards passed with the set of open scopes gone",
        output[-2000:],
    )
    assert "has no attribute '_ACTIVE_RUN_LOG_SCOPES'" in output, (
        "no guard read the renamed set by its name",
        output[-2000:],
    )
    assert "ERROR at teardown of test_aa_renames_the_open_scopes" in output, (
        "the rename did not error the renaming test's own teardown",
        output[-2000:],
    )


@pytest.mark.integration
@pytest.mark.parametrize("workers", ["2", "0"], ids=["with workers", "one process"])
def test_a_scope_a_session_fixture_leaks_fails_the_run_in_a_worker_too(
    tmp_path: Path, workers: str
) -> None:
    """An xdist worker's session end is not the run's: the worker sends the
    scopes still open to the controller, which reports them with its own and
    fails the run."""
    returncode, output = _run_probe(
        tmp_path,
        "worker",
        _WIDE_FIXTURE_LEAK.format(scope="session"),
        options=("-n", workers),
    )
    if "2 passed" not in output:
        raise RuntimeError(("control: the probes did not run", output[-2000:]))
    assert returncode != 0, (
        "a scope a session fixture leaked did not fail the run",
        output[-2000:],
    )
    assert "a run log scope was still open when the session ended" in output, (
        "the failure does not name the leak",
        output[-2000:],
    )


_CLOSE_THAT_ALWAYS_RAISES = """\
from automated_security_helper.utils import log

_real_close = log.close_run_log_scope


def _close_refusing(scope):
    raise RuntimeError("this close fails")


def test_aa_leaks_an_unclosable_scope():
    log.close_run_log_scope = _close_refusing
    log.open_run_log_scope()


def test_zz_runs_after_the_leak():
    log.close_run_log_scope = _real_close
"""


@pytest.mark.integration
def test_an_unclosable_scope_is_reported_once(tmp_path: Path) -> None:
    """A scope no guard can close fails the test that leaked it, once: the
    module's and the session's guards see the same open scope at their own
    ends, and without a record of what was already reported they would blame
    it a second time on the module's fixtures and a third on the session's --
    the misattribution the guards exist to avoid."""
    returncode, output = _run_probe(tmp_path, "unclosable", _CLOSE_THAT_ALWAYS_RAISES)
    if "could not be closed" not in output:
        raise RuntimeError(("control: the first report is missing", output[-2000:]))
    assert returncode != 0 and "2 passed, 1 error" in output, (
        "the leak did not fail exactly once",
        output[-2000:],
    )
    blamed_again = [
        phrase
        for phrase in (
            "outlived the module- and class-scoped fixtures",
            "a run log scope was still open when the session ended",
        )
        if phrase in output
    ]
    assert blamed_again == [], (
        "an unclosable scope was blamed on a later guard too",
        output[-2000:],
    )


@pytest.mark.unit
def test_the_gate_restore_restores_a_level_a_test_left(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The lazy gate read's PRESENT branch: with utils.log imported, the
    fixture snapshots the last resort's level at setup and puts it back at
    teardown. A misspelled sys.modules key would turn the guard off
    silently -- the absent branch yields and does nothing -- so the restore
    itself is pinned, not only the import discipline."""
    import sys

    import tests.conftest as root_conftest

    log_module = sys.modules.get("automated_security_helper.utils.log")
    assert log_module is not None, "the suite conftest imports ASH at load"
    fixture_function = root_conftest._the_last_resorts_gate_is_restored.__wrapped__
    before = log_module._LAST_RESORT.level
    guard = fixture_function()
    next(guard)
    log_module._LAST_RESORT.setLevel(before + 7)
    with pytest.raises(StopIteration):
        next(guard)
    assert log_module._LAST_RESORT.level == before, (
        "the gate restore did not put a left-behind level back"
    )


@pytest.mark.unit
def test_the_gate_restore_reads_the_module_through_sys_modules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The last-resort gate restore reads ``utils.log`` through
    ``sys.modules`` like the neighboring guards, importing nothing: with the
    module absent, its setup and teardown do nothing. An eager import put
    the module back on every test's setup -- redundant while the root
    conftest imports ASH at load, and a per-test import statement all the
    same."""
    import sys

    import automated_security_helper.utils as utils_package
    import tests.conftest as root_conftest

    fixture_function = root_conftest._the_last_resorts_gate_is_restored.__wrapped__
    monkeypatch.delitem(sys.modules, "automated_security_helper.utils.log")
    # The parent package's attribute goes too: ``from ... import log`` is
    # satisfied from it without touching sys.modules, so leaving it bound
    # would let an eager import through this probe unseen.
    monkeypatch.delattr(utils_package, "log")
    guard = fixture_function()
    next(guard)
    assert "automated_security_helper.utils.log" not in sys.modules, (
        "the gate restore imported utils.log at setup"
    )
    with pytest.raises(StopIteration):
        next(guard)
    assert "automated_security_helper.utils.log" not in sys.modules, (
        "the gate restore imported utils.log at teardown"
    )


_WIDE_FIXTURE_ENDS_ITS_SCOPE = """\
import pytest

from automated_security_helper.utils.log import end_run_log_scope, open_run_log_scope


@pytest.fixture(scope={scope!r})
def _a_scope_for_the_run():
    scope, token = open_run_log_scope()
    yield
    end_run_log_scope(scope, token)


def test_aa_uses_the_wide_fixture(_a_scope_for_the_run):
    pass


def test_zz_uses_nothing():
    pass
"""


@pytest.mark.integration
def test_control_a_session_fixture_that_ends_its_scope_passes(tmp_path: Path) -> None:
    """A session fixture that ends the scope it opened leaves the run green."""
    returncode, output = _run_probe(
        tmp_path, "session-ends", _WIDE_FIXTURE_ENDS_ITS_SCOPE.format(scope="session")
    )
    assert returncode == 0 and "2 passed" in output, (
        "a wide fixture that ended its scope failed the run",
        output[-2000:],
    )


#: A real package: ``__init__.py`` beside a ``conftest.py``, so pytest builds
#: a Package node and the package-scoped fixture ends when the package does --
#: one defined inside a lone test module has no Package node to bind to and
#: falls back to the session, which would re-measure the session case.
_PACKAGE_CONFTEST_THAT_LEAKS = """\
import pytest

from automated_security_helper.utils.log import open_run_log_scope


@pytest.fixture(scope="package", autouse=True)
def _a_scope_for_the_package():
    open_run_log_scope()
    yield
"""

_PACKAGE_CONFTEST_THAT_ENDS_ITS_SCOPE = """\
import os
import pathlib

import pytest

from automated_security_helper.utils.log import end_run_log_scope, open_run_log_scope


@pytest.fixture(scope="package", autouse=True)
def _a_scope_for_the_package():
    scope, token = open_run_log_scope()
    yield
    end_run_log_scope(scope, token)
    pathlib.Path(os.environ["TMPDIR"], "package-torn-down").write_text("done")
"""

_PACKAGE_TEST = """\
def test_aa_inside_the_package():
    pass
"""

_TEST_AFTER_THE_PACKAGE = """\
import os
import pathlib

from automated_security_helper.utils.log import current_run_log_scope


def test_zz_runs_after_the_package_ended():
    # The marker proves the package fixture tore down before this module ran,
    # so the probe measured a real Package node: a fixture that fell back to
    # the session would tear down after this test, with no marker yet.
    assert pathlib.Path(os.environ["TMPDIR"], "package-torn-down").exists()
    assert current_run_log_scope() is None
"""


@pytest.mark.integration
def test_a_scope_a_package_fixture_leaks_fails_the_run(tmp_path: Path) -> None:
    """A package-scoped fixture in a real package's conftest tears down when
    the package ends, before later modules run; a scope it leaked is seen by
    no narrower guard and fails the run at the session's end, by name."""
    returncode, output = _run_probe(
        tmp_path,
        "pkg",
        "def test_zz_outside_the_package():\n    pass\n",
        extra_files={
            "aa_pkg/__init__.py": "",
            "aa_pkg/conftest.py": _PACKAGE_CONFTEST_THAT_LEAKS,
            "aa_pkg/test_aa_inside.py": _PACKAGE_TEST,
        },
    )
    if "2 passed" not in output:
        raise RuntimeError(("control: the probes did not run", output[-2000:]))
    assert returncode != 0, (
        "a scope a package fixture leaked did not fail the run",
        output[-2000:],
    )
    assert "a run log scope was still open when the session ended" in output, (
        "the failure does not name the leak",
        output[-2000:],
    )


@pytest.mark.integration
def test_control_a_package_fixture_that_ends_its_scope_passes(tmp_path: Path) -> None:
    """A package fixture that ends its scope at the package's own end leaves
    the run green, and the module after the package runs outside any scope --
    which also proves the probe built a real Package node, since a session
    fallback would still hold the scope open there."""
    returncode, output = _run_probe(
        tmp_path,
        "pkg-ends",
        _TEST_AFTER_THE_PACKAGE,
        extra_files={
            "aa_pkg/__init__.py": "",
            "aa_pkg/conftest.py": _PACKAGE_CONFTEST_THAT_ENDS_ITS_SCOPE,
            "aa_pkg/test_aa_inside.py": _PACKAGE_TEST,
        },
    )
    assert returncode == 0 and "2 passed" in output, (
        "the package fixture did not tear down at the package's end",
        output[-2000:],
    )


def _a_stub_session() -> object:
    """The two attributes the sessionfinish wrapper reads: a config with an
    empty stash (no junit plugin), which the suite-property paths treat as
    nothing stored."""
    import types

    return types.SimpleNamespace(config=types.SimpleNamespace(stash=pytest.Stash()))


@pytest.mark.unit
def test_the_end_of_run_reporters_survive_a_raising_redaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The sessionfinish wrapper's first half redacts the suite properties
    before the junit plugin writes them; a raise there must not abort the
    hook, because that skips the junit file AND both end-of-run reporters (a
    planted leaked scope went unreported that way). The redaction failure's
    own rule stays the module's: a property set that cannot be redacted is
    not shown."""
    import tests.conftest as root_conftest

    reporters: list[str] = []

    def raising(config: object) -> None:
        raise RuntimeError("probe: the redaction failed")

    monkeypatch.setattr(root_conftest, "_redact_suite_properties", raising)
    monkeypatch.setattr(
        root_conftest, "_report_real_home_writes", lambda s: reporters.append("writes")
    )
    monkeypatch.setattr(
        root_conftest,
        "_report_run_log_scopes_still_open",
        lambda s: reporters.append("scopes"),
    )
    gen = root_conftest.pytest_sessionfinish(session=_a_stub_session(), exitstatus=0)
    next(gen)
    with pytest.raises(StopIteration):
        gen.send(None)
    assert reporters == ["writes", "scopes"], reporters


@pytest.mark.unit
def test_the_writes_reporter_hides_an_environment_value_in_a_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The end-of-run writes reporter prints each refused write's full path
    outside every report, and in a plain run the real HOME's prefix is an
    environment value: the printed message passes through the backstop's
    redaction like every other channel's text, and the event with the rest
    of the path still locates the stray write."""
    import secrets
    import types

    import tests.conftest as root_conftest

    value = "canary-" + secrets.token_hex(16)
    monkeypatch.setenv("ASH_TEST_BACKSTOP_WRITES_PATH", value)
    monkeypatch.setattr(
        root_conftest.real_home_guard,
        "drain",
        lambda: [("open", f"/somewhere/{value}/planted")],
    )
    lines: list[str] = []

    class _Reporter:
        def write_line(self, message: str, **kwargs: object) -> None:
            lines.append(message)

    pm = types.SimpleNamespace(get_plugin=lambda name: _Reporter())
    session = types.SimpleNamespace(
        config=types.SimpleNamespace(pluginmanager=pm), exitstatus=0
    )
    root_conftest._report_real_home_writes(session)
    assert len(lines) == 1, lines
    shown = {
        "the value": value in lines[0],
        "the marker": "<value>" in lines[0],
        "the event and the path's tail": "open" in lines[0] and "/planted" in lines[0],
    }
    assert shown == {
        "the value": False,
        "the marker": True,
        "the event and the path's tail": True,
    }, lines
    assert session.exitstatus == pytest.ExitCode.TESTS_FAILED


@pytest.mark.unit
def test_the_writes_reporter_replaces_a_message_it_cannot_redact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The module's not-shown rule, pinned on this reporter: with the
    redaction refusing, the count-only notice prints and no path does, and
    the session still fails for the write."""
    import types

    import tests.conftest as root_conftest

    def refusing(text: str) -> str:
        raise RuntimeError("probe: the redaction failed")

    monkeypatch.setattr(root_conftest, "redacted_environment_values", refusing)
    monkeypatch.setattr(
        root_conftest.real_home_guard,
        "drain",
        lambda: [("open", "/somewhere/secret-tail/planted")],
    )
    lines: list[str] = []

    class _Reporter:
        def write_line(self, message: str, **kwargs: object) -> None:
            lines.append(message)

    pm = types.SimpleNamespace(get_plugin=lambda name: _Reporter())
    session = types.SimpleNamespace(
        config=types.SimpleNamespace(pluginmanager=pm), exitstatus=0
    )
    root_conftest._report_real_home_writes(session)
    assert len(lines) == 1, lines
    shown = {
        "the notice": "could not be redacted, so they are not shown" in lines[0],
        "any path piece": "/somewhere" in lines[0] or "planted" in lines[0],
    }
    assert shown == {"the notice": True, "any path piece": False}, lines
    assert session.exitstatus == pytest.ExitCode.TESTS_FAILED


_A_CONFTEST_WHOSE_SESSIONFINISH_RAISES = """\
def pytest_sessionfinish(session, exitstatus):
    raise RuntimeError("a plain sessionfinish impl failed")
"""


@pytest.mark.integration
def test_the_end_of_run_reporters_survive_a_raising_inner_impl(
    tmp_path: Path,
) -> None:
    """A real inner impl of pytest_sessionfinish that raises (a plugin's own
    session teardown failing) must not take the end-of-run reporters with
    it: the child leaks a session-scoped run log scope AND registers a
    conftest whose plain sessionfinish impl raises, and the leak is still
    reported beside the surfaced raise. This pins the behavior, not a
    mechanism: pluggy's old-style wrapper protocol hands an inner raise back
    as the call outcome rather than throwing it into the wrapper generator,
    so the wrapper's own finally would bear load only after a move to the
    new-style wrapper form."""
    returncode, output = _run_probe(
        tmp_path,
        "innerraise",
        _WIDE_FIXTURE_LEAK.format(scope="session"),
        extra_files={"conftest.py": _A_CONFTEST_WHOSE_SESSIONFINISH_RAISES},
    )
    if "a plain sessionfinish impl failed" not in output:
        raise RuntimeError(
            ("control: the inner impl's raise did not surface", output[-2000:])
        )
    assert returncode != 0, output[-2000:]
    assert "a run log scope was still open when the session ended" in output, (
        "a raising inner impl took the end-of-run reporters with it",
        output[-2000:],
    )


@pytest.mark.unit
def test_the_worker_sends_a_notice_for_a_path_it_cannot_redact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The worker branch's not-shown fallback, pinned: a raising redaction
    sends the per-path notice, never the raw path, and the worker's hook
    neither raises nor loses the event."""
    import secrets
    import types

    import tests.conftest as root_conftest

    value = "canary-" + secrets.token_hex(16)
    monkeypatch.setenv("ASH_TEST_BACKSTOP_WFALL", value)
    calls: list[int] = []

    def raising(text: str) -> str:
        calls.append(1)
        raise RuntimeError("probe: the worker's redaction raised")

    monkeypatch.setattr(root_conftest, "redacted_environment_values", raising)
    monkeypatch.setattr(
        root_conftest.real_home_guard,
        "drain",
        lambda: [("open", f"/somewhere/{value}/planted")],
    )
    workeroutput: dict = {}
    session = types.SimpleNamespace(
        config=types.SimpleNamespace(workeroutput=workeroutput), exitstatus=0
    )
    root_conftest._report_real_home_writes(session)
    assert calls == [1], "the worker's redaction was not reached"
    sent = workeroutput.get(root_conftest._WORKER_WRITES_KEY)
    shown = {
        "one entry with the event kept": isinstance(sent, list)
        and len(sent) == 1
        and sent[0][0] == "open",
        "the value or a path piece sent": value in str(sent)
        or "/somewhere" in str(sent),
        "the notice sent": bool(sent) and "could not be redacted" in str(sent[0][1]),
    }
    assert shown == {
        "one entry with the event kept": True,
        "the value or a path piece sent": False,
        "the notice sent": True,
    }, sent


@pytest.mark.unit
def test_the_controller_pass_hides_a_value_a_worker_sent_raw(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The second layer, pinned: a line a worker sent raw -- holding a value
    the worker did not know -- prints with the controller's values hidden."""
    import secrets
    import types

    import tests.conftest as root_conftest

    value = "canary-" + secrets.token_hex(16)
    monkeypatch.setenv("ASH_TEST_BACKSTOP_CPASS", value)
    monkeypatch.setattr(
        root_conftest,
        "_writes_from_workers",
        [("gw7", "open", f"/elsewhere/{value}/planted")],
    )
    monkeypatch.setattr(root_conftest.real_home_guard, "drain", list)
    lines: list[str] = []

    class _Reporter:
        def write_line(self, message: str, **kwargs: object) -> None:
            lines.append(message)

    pm = types.SimpleNamespace(get_plugin=lambda name: _Reporter())
    session = types.SimpleNamespace(
        config=types.SimpleNamespace(pluginmanager=pm), exitstatus=0
    )
    root_conftest._report_real_home_writes(session)
    assert len(lines) == 1, lines
    shown = {
        "the value": value in lines[0],
        "the masked worker line": "gw7: open: /elsewhere/<value>/planted" in lines[0],
    }
    assert shown == {"the value": False, "the masked worker line": True}, lines
    assert session.exitstatus == pytest.ExitCode.TESTS_FAILED


@pytest.mark.unit
def test_the_scopes_reporters_composed_message_hides_a_value_in_a_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The non-raising half of the composed message's redaction, pinned: a
    scope label is whatever name the opening code chose, so one can hold
    an environment value, and the composed message is redacted once more
    before it is written. The guard-failed branch's cell covers the
    raising read; this one covers the ordinary path, where the labels
    themselves are the text that has to pass through the redaction."""
    import secrets
    import sys
    import types

    import automated_security_helper.utils.log  # noqa: F401 - the branch needs it loaded
    import tests.conftest as root_conftest

    value = "canary-" + secrets.token_hex(16)
    monkeypatch.setenv("ASH_TEST_BACKSTOP_LABEL", value)
    log_module = sys.modules["automated_security_helper.utils.log"]
    monkeypatch.setattr(root_conftest, "_open_run_log_scopes", lambda: {f"run-{value}"})
    monkeypatch.setattr(log_module, "close_run_log_scope", lambda scope: None)
    lines: list[str] = []

    class _Reporter:
        def write_line(self, message: str, **kwargs: object) -> None:
            lines.append(message)

    pm = types.SimpleNamespace(get_plugin=lambda name: _Reporter())
    session = types.SimpleNamespace(
        config=types.SimpleNamespace(pluginmanager=pm), exitstatus=0
    )
    root_conftest._report_run_log_scopes_still_open(session)
    assert len(lines) == 1, lines
    shown = {
        "the value": value in lines[0],
        "the masked label": "run-<value>" in lines[0],
        "the leak named": "a run log scope was still open" in lines[0],
    }
    assert shown == {
        "the value": False,
        "the masked label": True,
        "the leak named": True,
    }, lines
    assert session.exitstatus == pytest.ExitCode.TESTS_FAILED


@pytest.mark.unit
def test_the_scopes_reporters_unreadable_notice_hides_a_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The guard-failed branch prints one exception's text, the only piece
    of the scopes reporter's output this module does not write itself: a
    value inside it is redacted like the writes reporter's paths, while the
    exception's type name stays readable and the session still fails."""
    import secrets
    import types

    import automated_security_helper.utils.log  # noqa: F401 - the branch needs it loaded
    import tests.conftest as root_conftest

    value = "canary-" + secrets.token_hex(16)
    monkeypatch.setenv("ASH_TEST_BACKSTOP_SCOPES", value)

    def raising() -> set:
        raise RuntimeError(f"boom {value}")

    monkeypatch.setattr(root_conftest, "_open_run_log_scopes", raising)
    lines: list[str] = []

    class _Reporter:
        def write_line(self, message: str, **kwargs: object) -> None:
            lines.append(message)

    pm = types.SimpleNamespace(get_plugin=lambda name: _Reporter())
    session = types.SimpleNamespace(
        config=types.SimpleNamespace(pluginmanager=pm), exitstatus=0
    )
    root_conftest._report_run_log_scopes_still_open(session)
    assert len(lines) == 1, lines
    shown = {
        "the value": value in lines[0],
        "the marker": "<value>" in lines[0],
        "the type name and the notice": "RuntimeError" in lines[0]
        and "could not be read" in lines[0],
    }
    assert shown == {
        "the value": False,
        "the marker": True,
        "the type name and the notice": True,
    }, lines
    assert session.exitstatus == pytest.ExitCode.TESTS_FAILED
