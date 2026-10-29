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
adds them up in ``pytest_testnodedown``. The executed and skipped counts are not sent
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
"""

from __future__ import annotations

import fnmatch
import os
import re
import zlib
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence, Tuple

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
#: executed-test floor on. Read once by ``configure`` and removed from the environment.
FLOOR_ENV_VAR = "ASH_TEST_TIER_FLOOR"
#: Whether this run opted in to the floor.
_FLOOR_KEY = pytest.StashKey[bool]()
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

    Raises ``pytest.UsageError`` for a value that is not ``<index>of<count>``.
    """
    if _SHARD_KEY in config.stash:
        return
    workerinput = getattr(config, "workerinput", None)
    if workerinput is not None:
        text = workerinput.get(WORKERINPUT_KEY) or ""
        floor = bool(workerinput.get(WORKERINPUT_FLOOR_KEY))
    else:
        text = os.environ.pop(ENV_VAR, "")
        floor = os.environ.pop(FLOOR_ENV_VAR, "") == "1"
    try:
        shard = parse_shard(text) if text else None
    except ValueError as error:
        raise pytest.UsageError(f"{ENV_VAR}: {error}") from None
    config.stash[_SHARD_KEY] = shard
    config.stash[_TEXT_KEY] = text
    config.stash[_FLOOR_KEY] = floor
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


def fail_a_tier_run_that_executed_no_test(
    session: Any, executed: int, skipped: int
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

    The status becomes ``TESTS_FAILED`` and one line says what the run did. It does
    nothing in an xdist worker, whose share of the tests may be all skips while the run
    executed hundreds; the controller counts every worker's reports and decides.
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
    session.exitstatus = pytest.ExitCode.TESTS_FAILED
    line = (
        f"tier run executed no test: {selected} collected, {skipped} skipped, "
        "0 executed; a leg that runs nothing is not green"
    )
    reporter = config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_line(line)
    else:
        print(line)
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
LEG_ASSERTION_MARKER = "leg_assertion"


class _TierRunOutcome:
    """The outcome of a tier run: the empty-shard admission and the executed-test floor.

    ``configure`` registers it for a run with a shard or under CI. A class because tests/conftest.py already defines the module-level
    ``pytest_sessionfinish`` that a hook imported by name would have to share, and
    because it holds the counts of the run: the items it deselected, and the tests it
    executed and skipped.
    """

    def __init__(self) -> None:
        self.deselected = 0
        self.executed = 0
        self.skipped = 0

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
        is left out of both counts, and it is recognized by its marker name in
        ``report.keywords``, which reaches an xdist controller with the report.
        """
        if LEG_ASSERTION_MARKER in (getattr(report, "keywords", None) or {}):
            return
        if report.when == "setup":
            if report.failed:
                self.executed += 1
            elif report.skipped:
                self.skipped += 1
        elif report.when == "call":
            if report.skipped and not hasattr(report, "wasxfail"):
                self.skipped += 1
            else:
                self.executed += 1

    @pytest.hookimpl(optionalhook=True)
    def pytest_testnodedown(self, node: Any, error: Any) -> None:
        """Controller side of xdist: add up what a finished worker counted."""
        output = getattr(node, "workeroutput", None) or {}
        self.deselected += int(output.get(WORKEROUTPUT_KEY, 0))

    def pytest_sessionfinish(self, session: Any, exitstatus: Any) -> None:
        workeroutput = getattr(session.config, "workeroutput", None)
        if workeroutput is not None:
            # An xdist worker reports its count and leaves the run's exit status to the
            # controller. xdist sends `workeroutput` after every sessionfinish hook ran.
            workeroutput[WORKEROUTPUT_KEY] = self.deselected
            return
        admit_empty_shard(session, exitstatus, self.deselected)
        fail_a_tier_run_that_executed_no_test(session, self.executed, self.skipped)


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
