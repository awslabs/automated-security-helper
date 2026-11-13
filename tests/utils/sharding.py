# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run one shard of the suite: ignore the test modules another shard owns.

CI splits the integration-test jobs into shards (``ASH_TEST_SHARD=3of8``) because the
tests that start real tools do not finish inside one job; the unit tier is not sharded.
The split is made here, in ``pytest_ignore_collect``, rather than by handing pytest a
list of files:

* A file named on the command line skips pytest's ignore machinery, so ``norecursedirs``,
  ``--ignore``, ``collect_ignore`` and the ``python_files`` match would stop applying to
  it, and a list built outside pytest would have to copy ``testpaths`` and ``python_files``
  and keep them in step.
* Here pytest collects exactly as it does for an unsharded run, with its own ``testpaths``,
  ``python_files`` and ignore rules, and this hook only removes the modules another shard
  owns. A module that is ignored is never imported.

A module belongs to shard ``crc32(path) % count + 1``, where ``path`` is its POSIX path
relative to the rootdir. That depends on the module alone, so every xdist worker and every
shard agree without sharing a list, and each module lands in exactly one shard of a given
count. Only paths that match the ``python_files`` patterns pytest was configured with are
filtered; everything else is left to pytest.

A shard that collects nothing makes pytest exit 5 (no tests collected). A malformed
``ASH_TEST_SHARD`` is a usage error.

One case is admitted: a shard that owns modules and holds no test of the tier. A shard
owns modules, not tiers, so with ``-m integration`` a shard whose modules hold only unit
tests collects every item and then deselects every one, and exit 5 there would read as a
failure of a leg that has nothing to run. The tier's other shards carry the rest.
``admit_empty_shard`` turns ``NO_TESTS_COLLECTED`` into ``OK`` only when this run has a
shard configured, was given a ``-m`` expression, and deselected at least one item; it
prints one line naming the shard and the expression. A shard that collected nothing at
all (it owns no module, or the shard count is larger than the suite) deselected nothing
and keeps exit 5, and so does an empty shard of a run with no ``-m`` expression. A tier
that is empty as a whole is not caught here: every leg of it would be admitted.

The other side of the same coin is a leg that collected tests and ran none of them. A
tier leg whose every selected test is skipped (a tool is absent, a gate is off) exits 0
and reads green while it measured nothing. ``fail_a_tier_run_that_executed_no_test``
turns that into ``TESTS_FAILED`` and prints one line, but only for a CI tier run: a
``-m`` expression was given AND the run opted in with ``ASH_TEST_TIER_FLOOR=1``. The
opt-in is the only trigger; a shard alone does not turn the floor on, so a developer who
reproduces a CI shard by hand is not failed for the gate skips of a missing
``--run-integration``. The run-unit-tests action sets the variable on its pytest step;
``configure`` reads it once and removes it from ``os.environ``, as it does the shard
variable, so a pytest that a test starts does not inherit it and the floor does not
differ between a CI runner and a developer's machine. ``GITHUB_ACTIONS`` is not
consulted: ``act`` and any other pytest under Actions would have set it too. The floor
acts only when pytest is
about to exit
``OK``, at least one item was collected and selected, and none of them executed. An
item executed when its call phase ran and did not skip, or when its setup failed (an
error is a result). A run that collected nothing is left to ``admit_empty_shard`` and
exit 5, so an admitted empty shard stays ``OK``. A plain local ``pytest`` is unaffected,
and so are ``--collect-only``, ``--setup-plan``, ``--setup-only``, ``--fixtures`` and
``--fixtures-per-test``, which run no test by design. Under xdist only the controller applies the floor: a worker whose share of
the tests was all skips says nothing, because the controller counts every worker's
reports.

The deselected items are counted by a ``pytest_deselected`` hook on a plugin object that
``configure`` registers. Under xdist the controller never collects, so each worker counts
its own and hands the number back in ``workeroutput`` when it finishes; the controller
keeps the largest in ``pytest_testnodedown``. Every worker collects and deselects the
same modules, so the counts agree, and adding them up would print a multiple of the
worker count in the admitted line (``-n 2`` read "(86 deselected)" for 43 tests) while
the admission itself, which asks only whether the count is above zero, would be the
same either way. The executed and skipped counts are not sent
that way: xdist hands every worker's test report to the controller through
``pytest_runtest_logreport`` (xdist/dsession.py ``worker_testreport``), so the
controller counts them from the reports it already receives, and summing the workers'
own counts as well would count each test twice. The plugin is an object, and not a module-level
``pytest_sessionfinish`` imported by tests/conftest.py, because that conftest already
defines its own ``pytest_sessionfinish``. The owner rule is unchanged.

The setting belongs to the run it was given to. ``configure`` reads ASH_TEST_SHARD once,
at ``pytest_configure``, and removes it from ``os.environ``: a variable left there would
reach every pytest a test starts, and a child that loaded tests/conftest.py and collected
a directory would drop the modules other shards own. The hook reads the setting from the
config, never from the environment. xdist workers are started after the removal and get
the setting through ``workerinput`` (``pytest_configure_node``).

The executed-test floor, continued. A leg whose every skip comes from an explicit
``skipif`` marker whose condition held is admitted: the test code declared that it does
not apply on this runner (a class that is ``skipif(os.name == "nt")`` on a Windows
shard), and the leg has nothing else to run. The line the floor prints then says so and
names the skip reasons with their counts. Every other skip still fails the floor: the
root conftest's ``--run-integration`` and ``--run-slow`` gates, a ``pytest.skip`` in a
test or a fixture (a missing tool), an unconditional ``skip`` mark.
:func:`skipif_reason` tells the two apart from what a report carries, because an xdist
controller receives reports and no items: the skip happened in setup, ``skipif`` is
among ``report.keywords`` and ``skip`` is not, the report points at the item's own line
(a mark skips at the item; a skip raised in a fixture or a test body points at the line
that raised it), and the reason is not one of the gate texts that
:data:`GATE_SKIP_REASONS` copies from tests/conftest.py (a unit test fails if the two
drift apart). The ``skip`` keyword is excluded because pytest checks every ``skipif``
first and then falls through to the ``skip`` marks, and both report the item's own line:
an item that carries a ``skipif`` whose condition did not hold and also a ``skip`` mark
would otherwise read as a held ``skipif``. A ``skipif`` with no condition is an
unconditional skip as well, but it carries no ``skip`` keyword, so it is still admitted
(a limit of reading reports and not items). The alternative not taken is to tag each
skip where the item exists, with a ``pytest_runtest_makereport`` hookwrapper that
re-evaluates the item's ``skipif`` marks (``_pytest.skipping.evaluate_skip_marks``, a
private function) or adds a user property to the report. The property would be
published in the JUnit XML, for the reason given at ``LEG_ASSERTION_MARKER``, and the
private call can change between pytest releases. Known limits: a test that carries a
``skipif`` whose condition did not hold and is skipped by a gate shows the gate's text
and is not admitted, which is the safe direction; a test that carries a held ``skipif``
and is also gated (a developer's run without ``--run-integration``) is not admitted
either, because the gate's ``skip`` mark is among its keywords; and a ``skipif`` whose
condition is a missing tool (``skipif(shutil.which("x") is None)``) is admitted like
any other, because it is declared, where a ``pytest.skip`` found at run time is not.
That last case is the floor's main one on an integration leg, which has no leg
assertion for its tools. Two things answer it: the admitted line is also written as a
``::notice`` annotation titled "tier run admitted on skipif skips" (a ``::warning`` with
that title in warn mode, see below), so an admitted leg shows on the run page and is not
silently green; and the fuller shape, not taken here,
is an allowlist of admitted reasons or a dedicated marker for "does not apply on this
runner", which would change every test module that declares such a ``skipif``.

One more limit, from reading ``report.keywords`` for both ``leg_assertion`` and
``skipif``: the keywords also hold node names and, for a parametrized test, its
callspec id, so a parametrize id equal to ``leg_assertion``, ``skipif`` or ``skip``
changes how that case is counted or read. tests/conftest.py reads markers and not
``item.keywords`` for the tier markers for the same reason, but its collection hook does
not reject such an id, so the rule is only this note: do not name a parametrize id after
one of these markers. The fuller shape, not taken, sends the node ids of the leg
assertions back from each xdist worker through ``workeroutput`` and uses
``get_closest_marker`` where xdist is not running.

``ASH_TEST_TIER_FLOOR=warn`` opts in like ``1`` and reports instead of failing: the
same line is printed with a warning prefix, followed by a GitHub warning annotation
(``::warning title=tier run executed no test::<the line>``), and the exit status is left
alone. The annotation puts the report on the workflow run's page, so a reader can see
whether any e2e leg still executed no test without opening each step log. A leg admitted
on its ``skipif`` skips also executed no test, so in warn mode its admitted line is
followed by ``::warning title=tier run admitted on skipif skips::<the line>`` and not by
the notice that ``1`` mode writes: one annotation per leg, and leaving warn mode is one
search of the run page for either of the two warning titles. The e2e legs
run in warn mode until a hosted run shows every one of them executing a real test with
its scanners installed. An empty value leaves the floor off, and so do ``0``, ``false``
and ``off`` in any letter case with blanks around them, which are the ways a developer
says "no floor" for a whole-suite run. Any other value is a usage error, as a malformed
``ASH_TEST_SHARD`` is, so that a mistyped ``WARN`` does not turn the floor off without a
word.

The failure line counts the leg assertions apart from the skips, so its numbers add up
(``2 collected, 1 skipped, 1 leg assertion not counted, 0 executed``); the clause is
left out when there are none. A failing floor under ``1`` also prints a GitHub error
annotation line, ``::error title=tier run executed no test::<the line>``, which puts the
reason on the workflow run's page and not only at the end of the step log.

Where a failed floor is recorded: the step log line and that annotation, and nowhere in
the JUnit XML. The file for such a run lists no failed testcase, so the "PyTest - ..."
check run that action-junit-report publishes can read green while the job exits 1. No
test report is added, because pytest's junitxml plugin has no public hook for a plugin to
add a testcase: ``LogXML.add_global_property`` (and the ``record_testsuite_property``
fixture over it) writes a ``<property>`` of the testsuite and no testcase, and feeding a
synthetic failed ``TestReport`` through ``pytest_runtest_logreport`` at session end would
also reach the terminal summary and every other reporter, and depends on junitxml's own
``pytest_sessionfinish`` running after ours. A reader of the check run follows the
annotation.
"""

from __future__ import annotations

import fnmatch
import os
import re
import zlib
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

import pytest

#: The variable the run-unit-tests action sets for a shard; unset means the whole suite.
ENV_VAR = "ASH_TEST_SHARD"

_SHARD = re.compile(r"^([1-9][0-9]*)of([1-9][0-9]*)$")


def parse_shard(text: str) -> Tuple[int, int]:
    """``'3of8'`` -> ``(3, 8)``. Refuses anything else, and an index past the count."""
    match = _SHARD.fullmatch(text)
    if match is None:
        raise ValueError(f"shard {text!r} is not <index>of<count>, for example 3of8")
    index, count = int(match.group(1)), int(match.group(2))
    if index > count:
        raise ValueError(f"shard {text!r} has an index past its count")
    return index, count


def shard_from_env(
    environ: Mapping[str, str] = os.environ,
) -> Optional[Tuple[int, int]]:
    """The shard this run is, or None for the whole suite. Raises ValueError if malformed."""
    text = environ.get(ENV_VAR)
    return None if not text else parse_shard(text)


def owner(relative_posix_path: str, count: int) -> int:
    """The 1-based shard, of ``count``, that owns a module."""
    return zlib.crc32(relative_posix_path.encode("utf-8")) % count + 1


def matches_python_files(path: Path, patterns: Sequence[str]) -> bool:
    """Whether pytest would take this file as a test module under its ``python_files``."""
    posix = path.as_posix()
    for pattern in patterns:
        if "/" in pattern:
            if fnmatch.fnmatch(posix, pattern) or fnmatch.fnmatch(
                posix, "*/" + pattern
            ):
                return True
        elif fnmatch.fnmatch(path.name, pattern):
            return True
    return False


def ignored_by_shard(
    path: Path, rootpath: Path, patterns: Sequence[str], shard: Tuple[int, int]
) -> bool:
    """Whether ``path`` is a test module that a different shard owns."""
    if not matches_python_files(path, patterns):
        return False
    try:
        relative = path.resolve().relative_to(rootpath.resolve())
    except ValueError:
        return False
    index, count = shard
    return owner(relative.as_posix(), count) != index


#: The parsed shard of this run, ``(index, count)``, or None for the whole suite.
_SHARD_KEY = pytest.StashKey[Optional[Tuple[int, int]]]()
#: The setting's text, kept so the controller can hand it to its xdist workers.
_TEXT_KEY = pytest.StashKey[str]()
#: The ``workerinput`` key the controller hands the text to a worker under.
WORKERINPUT_KEY = "ash_test_shard"
#: The opt-in the run-unit-tests action sets for a CI tier run; ``1`` turns the
#: executed-test floor on and ``warn`` turns it on in report-only mode. Read once by
#: ``configure`` and removed from the environment.
FLOOR_ENV_VAR = "ASH_TEST_TIER_FLOOR"
#: The value of the opt-in that reports a floor failure and leaves the exit status alone.
FLOOR_WARN_VALUE = "warn"
#: The values, compared after stripping blanks and lower-casing, that say the floor is
#: off, the same as an unset or empty variable. A developer who exports ``0`` to turn a
#: check off would otherwise get a usage error that ends the whole run.
FLOOR_OFF_VALUES = ("0", "false", "off")
#: The title of the GitHub error annotation a failing floor prints after its line.
FAILURE_TITLE = "tier run executed no test"
#: The title of the GitHub notice annotation a leg admitted on its ``skipif`` skips prints,
#: so that an admitted leg is visible on the run page and not only in the step log.
ADMITTED_TITLE = "tier run admitted on skipif skips"
#: What the floor line starts with in warn mode, so a reader knows it did not fail the run.
WARN_PREFIX = "warning (ASH_TEST_TIER_FLOOR=warn, exit status unchanged): "
#: Whether this run opted in to the floor, in either mode.
_FLOOR_KEY = pytest.StashKey[bool]()
#: Whether this run opted in with ``warn``: the floor reports and does not fail.
_FLOOR_WARN_KEY = pytest.StashKey[bool]()
#: The reasons of the two skips tests/conftest.py adds to a run that was not given
#: ``--run-slow`` or ``--run-integration``. They are gate skips and not ``skipif`` skips,
#: and the floor fails on them. A unit test checks that each text is still in that file.
GATE_SKIP_REASONS = (
    "Need --run-slow option to run",
    "Need --run-integration option to run",
)
#: The ``workerinput`` key the controller hands the opt-in to a worker under.
WORKERINPUT_FLOOR_KEY = "ash_test_tier_floor"


def configure(config: pytest.Config) -> None:
    """Take the shard setting for this run, once, and keep it out of the environment.

    The controller (or a plain run) reads ASH_TEST_SHARD and REMOVES it from
    ``os.environ``, so no process a test starts inherits it: a child pytest that loaded
    tests/conftest.py and collected a directory would otherwise drop the modules other
    shards own, and pass or fail by which shard it ran in. An xdist worker is started
    after this, from an environment without the variable, and is handed the setting
    through ``workerinput`` by :func:`pytest_configure_node`. Calling it twice is
    harmless, so a run that registers the module both ways reads the variable once.

    Raises ``pytest.UsageError`` for a shard value that is not ``<index>of<count>``, and
    for a floor value that is not empty, ``1``, ``warn`` or one of
    :data:`FLOOR_OFF_VALUES` (``0``, ``false``, ``off``, in any letter case).
    """
    if _SHARD_KEY in config.stash:
        return
    workerinput = getattr(config, "workerinput", None)
    if workerinput is not None:
        text = workerinput.get(WORKERINPUT_KEY) or ""
        floor = bool(workerinput.get(WORKERINPUT_FLOOR_KEY))
        # A worker never applies the floor, so it does not need the mode.
        warn = False
    else:
        text = os.environ.pop(ENV_VAR, "")
        floor_value = os.environ.pop(FLOOR_ENV_VAR, "")
        if floor_value.strip().lower() in FLOOR_OFF_VALUES:
            floor_value = ""
        if floor_value not in ("", "1", FLOOR_WARN_VALUE):
            raise pytest.UsageError(
                f"{FLOOR_ENV_VAR}: {floor_value!r} is not accepted; "
                f"use 1, {FLOOR_WARN_VALUE}, or 0 (off), or leave it empty"
            )
        floor = floor_value in ("1", FLOOR_WARN_VALUE)
        warn = floor_value == FLOOR_WARN_VALUE
    try:
        shard = parse_shard(text) if text else None
    except ValueError as error:
        raise pytest.UsageError(f"{ENV_VAR}: {error}") from None
    config.stash[_SHARD_KEY] = shard
    config.stash[_TEXT_KEY] = text
    config.stash[_FLOOR_KEY] = floor
    config.stash[_FLOOR_WARN_KEY] = warn
    # A stand-in config without a plugin manager (the unit tests of this module use one)
    # registers nothing. The early return above is what keeps this to once per config.
    # A run with a shard needs the plugin for the empty-shard admission, and a run that
    # opted in needs it for the executed-test floor, sharded or not.
    plugins = getattr(config, "pluginmanager", None)
    if (shard is not None or floor) and plugins is not None:
        plugins.register(_TierRunOutcome(), _TIER_RUN_PLUGIN)


def admit_empty_shard(session: Any, exitstatus: Any, deselected: int) -> bool:
    """Turn "no tests collected" into success for a shard whose tests ``-m`` deselected.

    True when it changed the exit status. It acts only when all four hold: the run has a
    shard configured, it was given a ``-m`` expression, pytest is about to exit with
    ``NO_TESTS_COLLECTED``, and ``deselected`` (the items the run deselected, counted by
    the plugin) is above zero. Why: a shard owns modules, not tiers, so with
    ``-m integration`` a shard can hold only unit tests, and exit 5 would fail a leg that
    has nothing to run while the tier's other shards carry the rest. A shard that
    collected nothing at all deselected nothing and keeps exit 5, which is what tells a
    shard count larger than the suite from a pass.
    """
    config = session.config
    text = config.stash.get(_TEXT_KEY, "")
    expression = config.getoption("markexpr", default="")
    if not text or not expression:
        return False
    if exitstatus != pytest.ExitCode.NO_TESTS_COLLECTED:
        return False
    if deselected <= 0:
        return False
    session.exitstatus = pytest.ExitCode.OK
    line = (
        f"shard {text} holds no test selected by -m {expression!r} ({deselected} "
        "deselected); admitted, the other shards of the run carry the rest"
    )
    reporter = config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_line(line)
    else:
        print(line)
    return True


def is_ci_tier_run(config: Any) -> bool:
    """Whether this is a CI tier run: a ``-m`` expression was given AND the run opted in
    with ``ASH_TEST_TIER_FLOOR`` (as ``configure`` read it).

    The opt-in is the only trigger. A shard does not turn the floor on: it drives the
    sharding and the empty-shard admission, and nothing else. A developer who reproduces
    a CI shard with ``ASH_TEST_SHARD=3of4 pytest -m integration`` and leaves out
    ``--run-integration`` gets every test skipped by the conftest gate, and must not be
    told by exit 1 that "a leg that runs nothing is not green".

    The one definition the floor and the tests that assert what a CI leg is provisioned
    with both use, so they cannot drift apart. It reads the config, not the environment:
    ``configure`` has already removed the variable from ``os.environ``.
    """
    if not config.getoption("markexpr", default=""):
        return False
    return bool(config.stash.get(_FLOOR_KEY, False))


def _write_line(config: Any, text: str) -> None:
    """Print one line through the terminal reporter, or to stdout without one."""
    reporter = config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_line(text)
    else:
        print(text)


def _is_the_items_own_location(path: Any, line: Any, location: Any) -> bool:
    """Whether a skip's ``(path, line)`` is the item's own place, as a mark skip reports.

    ``location`` is the report's ``(relative path, 0-based line, domain)``. A skip from a
    mark is reported at the item (path and line + 1); a skip raised in a fixture or in the
    test body is reported at the line that raised it. An absolute ``path`` ends with the
    relative one.
    """
    if not isinstance(location, (tuple, list)) or len(location) < 2:
        return False
    if location[1] is None or line != location[1] + 1:
        return False
    absolute = str(path).replace("\\", "/")
    relative = str(location[0]).replace("\\", "/")
    return absolute == relative or absolute.endswith("/" + relative)


def skipif_reason(report: Any) -> Optional[str]:
    """The reason of a skipped report that came from a ``skipif`` marker, else None.

    It reads only what the report carries (an xdist controller receives no item). All of
    these hold for a ``skipif`` skip: the report is a skip in the ``setup`` phase and not
    an expected failure; ``skipif`` is among ``report.keywords``; ``report.longrepr`` is
    the ``(path, line, reason)`` tuple of a skip and its place is the item's own
    (:func:`_is_the_items_own_location`); and the reason, once pytest's ``Skipped: ``
    prefix is removed, is not one of :data:`GATE_SKIP_REASONS`. Anything else, such as a
    gate skip, an unconditional ``skip`` mark, a ``pytest.skip`` in a fixture or in the
    test body, is None.

    ``skip`` must not be among ``report.keywords`` either. pytest's
    ``evaluate_skip_marks`` checks every ``skipif`` and then falls through to the
    ``skip`` marks, and a skip from either reports the item's own line, so an item with
    a ``skipif`` that did not fire and a ``skip`` mark would otherwise read as a held
    ``skipif``. A ``skipif`` with no condition is an unconditional skip too, but it
    carries no ``skip`` keyword and its report reads exactly like a held ``skipif``, so
    it is still admitted: a limit of reading reports, not items.

    Another limit of the same kind: ``report.keywords`` holds node names and, for a
    parametrized test, its callspec id, so a parametrize id of ``skipif`` or ``skip``
    changes the answer. See the note at :data:`LEG_ASSERTION_MARKER`.
    """
    if getattr(report, "when", None) != "setup":
        return None
    if not getattr(report, "skipped", False) or hasattr(report, "wasxfail"):
        return None
    keywords = getattr(report, "keywords", None) or {}
    if "skipif" not in keywords or "skip" in keywords:
        return None
    longrepr = getattr(report, "longrepr", None)
    if not isinstance(longrepr, (tuple, list)) or len(longrepr) != 3:
        return None
    path, line, text = longrepr
    if not _is_the_items_own_location(path, line, getattr(report, "location", None)):
        return None
    reason = str(text)
    reason = reason.removeprefix("Skipped: ")
    if reason in GATE_SKIP_REASONS:
        return None
    return reason


def fail_a_tier_run_that_executed_no_test(
    session: Any,
    executed: int,
    skipped: int,
    skipif_reasons: Optional[Mapping[str, int]] = None,
    leg_assertions: int = 0,
) -> bool:
    """Fail a CI tier run that selected tests and executed none of them.

    True when it changed the exit status. Why: a leg whose every selected test is
    skipped (a tool is absent, a gate is off) exits 0 and reads green while it measured
    nothing. It acts only when all of these hold: the run was given a ``-m``
    expression; it is a CI tier run (:func:`is_ci_tier_run`); it is not a ``--collect-only``, ``--setup-plan``,
    ``--setup-only``, ``--fixtures`` or ``--fixtures-per-test`` run, which run no test
    by design; pytest is about to exit ``OK``;
    at least one item was collected and selected (``session.testscollected``); and
    ``executed`` is zero. ``admit_empty_shard`` is not touched: a shard that collected
    nothing selected nothing, so an admitted empty shard stays ``OK`` here.

    ``skipif_reasons`` maps each reason of a ``skipif`` skip (:func:`skipif_reason`) to
    how many tests were skipped for it. When they account for every skip, the leg is
    admitted: it stays ``OK``, one line names the reasons and their counts and is
    followed by a GitHub notice annotation (``::notice title=...::<the line>``) so that
    an admitted leg is visible on the run page, and this returns False. In warn mode the
    annotation is a ``::warning`` with the same title and text instead, because an
    admitted leg executed no test either and the warn mode is only left when no leg
    reports one. A gate skip, a ``pytest.skip`` or a ``skip`` mark among the skips keeps
    the failure.

    Any reason is admitted, a missing tool included. The fuller shape, not taken here,
    admits only the reasons of an explicit allowlist, or only a skip from a dedicated
    marker that means "does not apply on this runner"; it needs every test module that
    declares such a ``skipif`` to be changed together with this module. The notice is
    the cheaper cure: an integration leg (which has no leg assertion for its tools,
    unlike e2e) admitted on ``skipif(shutil.which("x") is None)`` shows on the run
    page, and a reader can open it.

    The status becomes ``TESTS_FAILED`` and one line says what the run did, counting the
    ``leg_assertions`` (tests marked ``leg_assertion``, which are in neither count)
    apart so that the numbers add up. The line is followed by a GitHub error annotation
    carrying the same text. In warn mode (``ASH_TEST_TIER_FLOOR=warn``) the same line is
    printed with :data:`WARN_PREFIX`, followed by a GitHub warning annotation
    (``::warning title=...::<the line>``) so that the run page shows which legs still
    executed no test, and the status is left alone, so this returns False. It does
    nothing in an xdist worker,
    whose share of the tests may be all skips while the run executed hundreds; the
    controller counts every worker's reports and decides.
    """
    config = session.config
    # Only the controller decides. A worker has ``workerinput``; the controller does not.
    if hasattr(config, "workerinput"):
        return False
    if not is_ci_tier_run(config):
        return False
    if any(
        config.getoption(name, default=False)
        for name in (
            "collectonly",
            "setupplan",
            "setuponly",
            "showfixtures",
            "show_fixtures_per_test",
        )
    ):
        return False
    if session.exitstatus != pytest.ExitCode.OK:
        return False
    selected = session.testscollected
    if selected <= 0 or executed > 0:
        return False
    reasons = dict(skipif_reasons or {})
    if skipped > 0 and sum(reasons.values()) == skipped:
        listed = ", ".join(
            f"{count} x {reason!r}"
            for reason, count in sorted(reasons.items(), key=lambda r: (-r[1], r[0]))
        )
        admitted = (
            "tier run executed no test; admitted, because every skip is a skipif "
            f"condition that held: {skipped} skipped ({listed})"
        )
        _write_line(config, admitted)
        # One annotation per leg. In warn mode it is a warning, so that the run page
        # shows every e2e leg that still executed no test, admitted or not.
        level = "warning" if config.stash.get(_FLOOR_WARN_KEY, False) else "notice"
        _write_line(config, f"::{level} title={ADMITTED_TITLE}::{admitted}")
        return False
    counted = ""
    if leg_assertions > 0:
        plural = "" if leg_assertions == 1 else "s"
        counted = f", {leg_assertions} leg assertion{plural} not counted"
    line = (
        f"tier run executed no test: {selected} collected, {skipped} skipped{counted}, "
        "0 executed; a leg that runs nothing is not green"
    )
    if config.stash.get(_FLOOR_WARN_KEY, False):
        _write_line(config, WARN_PREFIX + line)
        _write_line(config, f"::warning title={FAILURE_TITLE}::{line}")
        return False
    session.exitstatus = pytest.ExitCode.TESTS_FAILED
    _write_line(config, line)
    _write_line(config, f"::error title={FAILURE_TITLE}::{line}")
    return True


#: The ``workeroutput`` key a worker hands its deselected count back under.
WORKEROUTPUT_KEY = "ash_shard_deselected"
#: The marker of a leg assertion: a test that checks what a CI leg is provisioned with.
#: It carries the tier of the leg it asserts, and the floor does not count it as a test
#: that executed, because a pass there says nothing about the product. The controller
#: of an xdist run receives reports and never items, and pytest puts the item's marker
#: names in ``TestReport.keywords``, which xdist sends along with the rest of the
#: report, so the name is read from there. Nothing is added to the report: a user
#: property would be published in the JUnit XML as a ``<property>`` inside the
#: ``<testcase>``, which pytest's documentation says breaks validation against the
#: xunit2 schema.
#:
#: Known limit: ``report.keywords`` also holds the item's node names and, for a
#: parametrized test, its callspec id, so a parametrize id equal to this name reads as the
#: marker and that case drops out of both counts; an id equal to ``skipif`` or ``skip``
#: misleads :func:`skipif_reason` the same way. tests/conftest.py draws the same line
#: between markers and ``item.keywords`` for the tier markers (the comment above
#: ``_TEST_TIERS`` in tests/conftest.py), but its collection hook only checks the tier
#: markers and does not reject a marker-named id, so nothing enforces it here: do not
#: give a parametrize id one of these names. The effect is small, since a leg has to
#: hinge on that one test. The fuller shape, not taken, has each xdist worker send the
#: node ids of its leg assertions back through ``workeroutput`` (as it does the
#: deselected count) and reads ``get_closest_marker`` where xdist is not running.
LEG_ASSERTION_MARKER = "leg_assertion"


class _TierRunOutcome:
    """The outcome of a tier run: the empty-shard admission and the executed-test floor.

    ``configure`` registers it for a run with a shard or under CI. A class because tests/conftest.py already defines the module-level
    ``pytest_sessionfinish`` that a hook imported by name would have to share, and
    because it holds the counts of the run: the items it deselected, the tests it
    executed and skipped, how many of the skips came from a ``skipif`` marker (by
    reason), and the leg assertions, which are in neither count.
    """

    def __init__(self) -> None:
        self.deselected = 0
        self.executed = 0
        self.skipped = 0
        self.skipif_reasons: Dict[str, int] = {}
        self.leg_assertions = 0

    def pytest_deselected(self, items: Sequence[Any]) -> None:
        self.deselected += len(items)

    def pytest_runtest_logreport(self, report: Any) -> None:
        """Count executed and skipped tests from the reports this process receives.

        A plain run gets its own reports and an xdist controller gets every worker's
        (``pytest_runtest_logreport`` is called for each, xdist/dsession.py), so the
        count is the same either way. A test is executed when its call phase ran
        without skipping, or when its setup failed (an error is a result). A skip
        in setup, or ``pytest.skip`` in the body, is skipped; an expected failure
        (``wasxfail``) ran its body and is executed. A leg assertion is neither: it
        is left out of both counts, though it is counted on its own so that the floor
        line can say so. It is recognized by its marker name in
        ``report.keywords``, which reaches an xdist controller with the report. A
        setup skip that :func:`skipif_reason` reads as a ``skipif`` skip is also tallied
        by its reason.
        """
        if LEG_ASSERTION_MARKER in (getattr(report, "keywords", None) or {}):
            # Every test has one setup report, so counting there counts each once.
            if report.when == "setup":
                self.leg_assertions += 1
            return
        if report.when == "setup":
            if report.failed:
                self.executed += 1
            elif report.skipped:
                self.skipped += 1
                reason = skipif_reason(report)
                if reason is not None:
                    self.skipif_reasons[reason] = self.skipif_reasons.get(reason, 0) + 1
        elif report.when == "call":
            if report.skipped and not hasattr(report, "wasxfail"):
                self.skipped += 1
            else:
                self.executed += 1

    @pytest.hookimpl(optionalhook=True)
    def pytest_testnodedown(self, node: Any, error: Any) -> None:
        """Controller side of xdist: keep the largest count a finished worker reported.

        Each worker collects and deselects the same modules, so the counts are the
        same number seen once per worker; their sum would be that number times the
        worker count. The admission asks only whether the count is above zero.
        """
        output = getattr(node, "workeroutput", None) or {}
        self.deselected = max(self.deselected, int(output.get(WORKEROUTPUT_KEY, 0)))

    def pytest_sessionfinish(self, session: Any, exitstatus: Any) -> None:
        workeroutput = getattr(session.config, "workeroutput", None)
        if workeroutput is not None:
            # An xdist worker reports its count and leaves the run's exit status to the
            # controller. xdist sends `workeroutput` after every sessionfinish hook ran.
            workeroutput[WORKEROUTPUT_KEY] = self.deselected
            return
        admit_empty_shard(session, exitstatus, self.deselected)
        fail_a_tier_run_that_executed_no_test(
            session,
            self.executed,
            self.skipped,
            self.skipif_reasons,
            self.leg_assertions,
        )


#: The name the plugin object is registered under, once per config.
_TIER_RUN_PLUGIN = "ash-tier-run-outcome"


def pytest_configure(config: pytest.Config) -> None:
    """The hook form of :func:`configure`, for a run that loads this module as a plugin.

    tests/conftest.py does not import this name; it calls :func:`configure` from its own
    ``pytest_configure``.
    """
    configure(config)


@pytest.hookimpl(optionalhook=True)
def pytest_configure_node(node: Any) -> None:
    """Hand the controller's shard setting and floor opt-in to an xdist worker.

    Not called without xdist. A worker never applies the floor, but the tests it runs
    ask :func:`is_ci_tier_run`, which reads the same stash.
    """
    node.workerinput[WORKERINPUT_KEY] = node.config.stash.get(_TEXT_KEY, "")
    node.workerinput[WORKERINPUT_FLOOR_KEY] = node.config.stash.get(_FLOOR_KEY, False)


def pytest_ignore_collect(
    collection_path: Path, config: pytest.Config
) -> Optional[bool]:
    """Ignore the test modules another shard owns. None leaves pytest's own decision."""
    shard = config.stash.get(_SHARD_KEY, None)
    if shard is None:
        return None
    patterns = config.getini("python_files")
    if ignored_by_shard(collection_path, config.rootpath, patterns, shard):
        return True
    return None
