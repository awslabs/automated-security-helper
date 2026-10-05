# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures every snapshot test uses. Read DEVELOPMENT.md "Snapshot tests" first.

A snapshot here is a statement of what a user sees. Changing one is a decision, so:

- a snapshot only changes when someone runs ``pytest --snapshot-update`` and commits
  the result with a ``Snapshot-Update: <reason>`` trailer (checked in CI by
  .github/scripts/check-snapshot-trailers.py);
- CI never passes ``--snapshot-update`` (asserted by
  tests/snapshot/test_snapshot_policy.py, and refused at configure time below);
- a missing snapshot fails, and a snapshot nothing asserts any more fails the session
  as unused.

Use ``snapshot`` for structured data and ``text_snapshot(ext)`` for rendered text. Both
apply the one shared :class:`SnapshotNormalizer`; never normalize inside a test.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import rich
import rich.console
from rich._log_render import LogRender
from rich.text import Text
from syrupy.assertion import SnapshotAssertion

from tests.snapshot.support.extensions import (
    NormalizingAmberExtension,
    NormalizingTextFileExtension,
    bind,
)
from tests.snapshot.support.normalize import (
    SnapshotNormalizer,
    default_normalizer,
    pinned_terminal_env,
)

#: Environment that changes what ASH prints. Unset for every snapshot test, so a
#: snapshot taken on a laptop matches the one CI takes: ASH switches its console
#: output on CI and CODEBUILD_BUILD_ID, and the colour variables override NO_COLOR.
_UNSET_FOR_SNAPSHOTS = (
    "CI",
    "ISCI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "CODEBUILD_BUILD_ID",
    "FORCE_COLOR",
    "CLICOLOR_FORCE",
    "PY_COLORS",
    "ASH_DEBUG",
    "ASH_VERBOSE",
    "ASH_LOG_TO_STDERR",
    "ASH_ACTUAL_OUTPUT_DIR",
    "ASH_CONFIG",
    "ASH_DEFAULT_SEVERITY_LEVEL",
    "ASH_PROJECT_NAME",
    "ASH_IN_CONTAINER",
    "ASH_OFFLINE",
)


#: Normalizer switches a test or module may turn off with
#: ``@pytest.mark.snapshot_masking(...)``. See the module docstring of
#: tests/snapshot/support/normalize.py for what each one masks.
_MASKING_SWITCHES = frozenset({"mask_durations", "mask_duration_keys"})


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "snapshot_masking(mask_durations=..., mask_duration_keys=...): turn off a "
        "SnapshotNormalizer rule for a test whose inputs pin what it masks.",
    )
    # Belt and braces with test_snapshot_policy.py, which reads the workflow files: a
    # CI job that somehow passes --snapshot-update would turn every intended diff into
    # a silent rewrite, so the session refuses to start.
    if config.getoption("--snapshot-update", default=False) and (
        os.environ.get("GITHUB_ACTIONS") == "true" or os.environ.get("CI") == "true"
    ):
        raise pytest.UsageError(
            "--snapshot-update is refused under CI. Update snapshots locally, review "
            "the diff, and commit it with a 'Snapshot-Update: <reason>' trailer."
        )


@pytest.fixture(autouse=True)
def _pinned_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Render every snapshot for the same terminal: 100 columns, no colour, no TTY."""
    for name in _UNSET_FOR_SNAPSHOTS:
        monkeypatch.delenv(name, raising=False)
    for name, value in pinned_terminal_env().items():
        monkeypatch.setenv(name, value)
    # rich.print() renders through one process-wide Console, created on first use and
    # keeping the width it saw then. Another test in the same worker can create it
    # under a different COLUMNS, so it is discarded and rebuilt under the pinned env.
    monkeypatch.setattr(rich, "_console", None)
    # The same for the Consoles ASH modules build at import time (cli/dependencies.py
    # has one). A Console that read COLUMNS when it was constructed keeps that width,
    # and the import happened at collection, under the developer's shell. Clearing the
    # stored size makes it read the pinned COLUMNS when it renders.
    for console in _module_level_consoles():
        monkeypatch.setattr(console, "_width", None)
        monkeypatch.setattr(console, "_height", None)
    # On Windows, a console whose stream is not a real console counts as "legacy
    # Windows", and rich then subtracts one from COLUMNS: every rich.print line would
    # wrap at 99 there and 100 everywhere else. The streams under test are capture
    # buffers on every OS, so the legacy renderer never runs; only the width differs.
    monkeypatch.setattr(rich.console, "detect_legacy_windows", lambda: False)
    # ASH's log handler builds its Console with an empty environment, so COLUMNS does
    # not reach it and its width is whatever os.get_terminal_size reports: a
    # developer's terminal under `-n 0 -s`, rich's fallback of 80 under xdist. Log
    # lines carry absolute paths (the scanned directory, report locations), and rich
    # folds a long path wherever the column ends, so at any realistic width the fold
    # point depends on how long the machine's temp dir is, and a folded path cannot be
    # masked. The log console is therefore given a width no log line reaches, which
    # leaves every path whole. rich.print and typer's error boxes read COLUMNS, which
    # takes precedence over this, so they stay at the pinned 100.
    monkeypatch.setattr(os, "get_terminal_size", _wide_log_terminal)
    # rich's log handler prints the wall-clock time on a line, then leaves the column
    # blank on every following line until the second changes. Whether a slow line
    # shows a new time is a race with the clock, so the time column renders one
    # constant token: the first line of each handler shows it, and no later one does.
    monkeypatch.setattr(LogRender, "__call__", _log_render_without_clock)


@pytest.fixture(autouse=True)
def _fresh_ash_loggers() -> Iterator[None]:
    """Give every snapshot the logging state of a freshly started ``ash`` process.

    ``get_logger`` attaches a handler to the ``ash`` logger (and to named children
    such as ``ash.cli.config.lint``) that lives for the rest of the process, at the
    level the command that called it chose. A command that logs before it calls
    ``get_logger`` itself would otherwise print through whichever handler, at
    whichever level, the previous test in the same xdist worker left behind -- so
    its snapshot would depend on test order. A fresh process has no handler on
    ``ash`` (propagation is off), so such a record goes to logging's last-resort
    handler: stderr, WARNING and above, message text only. That is restored here,
    and the previous state is put back afterwards for the rest of the suite.
    """
    saved = []
    for logger in _ash_loggers():
        saved.append((logger, logger.handlers, logger.level, logger.propagate))
        logger.handlers = []
        logger.setLevel(logging.NOTSET)
        # Only the root of ASH's hierarchy has propagation off at import time.
        logger.propagate = logger.name != "ash"
    try:
        yield
    finally:
        for logger in _ash_loggers():
            # Handlers the test's command attached, typically a file handler on a log
            # in tmp_path. Closed so Windows can delete the temp dir. pytest's own
            # capture handlers are attached for this teardown phase and are left to
            # pytest.
            ours = [h for h in logger.handlers if not _is_pytest_handler(h)]
            for handler in ours:
                handler.close()
            logger.handlers = [h for h in logger.handlers if _is_pytest_handler(h)]
        for logger, handlers, level, propagate in saved:
            logger.handlers = handlers
            logger.setLevel(level)
            logger.propagate = propagate


@pytest.hookimpl(wrapper=True, trylast=True)
def pytest_runtest_call(item: pytest.Item) -> Iterator[None]:
    """Run the test body with no logging handler that a real ``ash`` would not have.

    pytest's logging plugin attaches its capture handlers to the root logger, and to
    the non-propagating ``ash`` logger, when the call phase starts -- after every
    fixture, so :func:`_fresh_ash_loggers` cannot see them. Left in place they take
    the records a real process prints through logging's last-resort handler
    (stderr, WARNING and above): ASH logging before it has configured its own
    handler, and every module logger that propagates to the root. Those lines are
    part of what an operator sees, so they are detached for the test body and put
    back before the logging plugin's own teardown removes them. ``trylast`` makes
    this wrapper the innermost, so it runs after the plugin attached them.
    """
    detached = []
    for logger in (logging.getLogger(), *_ash_loggers()):
        if logger.handlers:
            detached.append((logger, logger.handlers))
            logger.handlers = []
    try:
        return (yield)
    finally:
        for logger, handlers in detached:
            # The test may have configured its own handlers on the same logger;
            # _fresh_ash_loggers closes those afterwards.
            logger.handlers = [*handlers, *logger.handlers]


def _is_pytest_handler(handler: logging.Handler) -> bool:
    return type(handler).__module__.startswith("_pytest")


def _ash_loggers() -> list[logging.Logger]:
    names = [
        name
        for name in logging.root.manager.loggerDict
        if name == "ash" or name.startswith("ash.")
    ]
    return [
        logger
        for logger in (logging.getLogger(name) for name in names)
        if isinstance(logger, logging.Logger)
    ]


def _module_level_consoles() -> list[rich.console.Console]:
    """Every rich Console held at module scope by an imported ASH module."""
    found: dict[int, rich.console.Console] = {}
    for name, module in list(sys.modules.items()):
        if module is None or not name.startswith("automated_security_helper"):
            continue
        for value in list(vars(module).values()):
            if isinstance(value, rich.console.Console):
                found[id(value)] = value
    return list(found.values())


_LOG_CONSOLE_COLUMNS = 1000


def _wide_log_terminal(*_args: object) -> os.terminal_size:
    return os.terminal_size((_LOG_CONSOLE_COLUMNS, 50))


_real_log_render = LogRender.__call__


def _log_render_without_clock(self: LogRender, *args: Any, **kwargs: Any) -> Any:
    kwargs["time_format"] = lambda _when: Text("[<LOG_TIME>]")
    return _real_log_render(self, *args, **kwargs)


@pytest.fixture
def snapshot_normalizer(
    request: pytest.FixtureRequest,
    tmp_path: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> SnapshotNormalizer:
    """The shared normalizer, with this test's temp dirs registered.

    A test that creates paths elsewhere registers them with ``add_root`` before it
    asserts; a test that learns an id it cannot choose (a scan id) uses ``add_literal``.
    A test whose inputs pin time fully opts out of duration masking with
    ``@pytest.mark.snapshot_masking(mask_durations=False, mask_duration_keys=False)``
    (or a module ``pytestmark``), so a wrong duration shows up as a diff.
    """
    normalizer = default_normalizer(
        tmp_paths=[tmp_path, tmp_path_factory.getbasetemp()]
    )
    # Closest marker wins, so a test can override its module's ``pytestmark``.
    for mark in reversed(list(request.node.iter_markers("snapshot_masking"))):
        if mark.args:
            raise pytest.UsageError("snapshot_masking takes keyword arguments only")
        unknown = set(mark.kwargs) - _MASKING_SWITCHES
        if unknown:
            raise pytest.UsageError(
                f"snapshot_masking: unknown switch(es) {sorted(unknown)}; "
                f"expected {sorted(_MASKING_SWITCHES)}"
            )
        for name, value in mark.kwargs.items():
            if not isinstance(value, bool):
                raise pytest.UsageError(f"snapshot_masking: {name} must be a bool")
            setattr(normalizer, name, value)
    return normalizer


@pytest.fixture
def snapshot(
    snapshot: SnapshotAssertion, snapshot_normalizer: SnapshotNormalizer
) -> SnapshotAssertion:
    """syrupy's ``snapshot``, normalized. For dicts, lists and short strings."""
    return snapshot.use_extension(bind(NormalizingAmberExtension, snapshot_normalizer))


@pytest.fixture
def text_snapshot(
    snapshot: SnapshotAssertion, snapshot_normalizer: SnapshotNormalizer
) -> Callable[[str], SnapshotAssertion]:
    """``text_snapshot("md")`` -> an assertion storing one ``.md`` file per snapshot.

    The file lands in ``__snapshots__/<test module>/<test name>.<ext>``. Pass
    ``name=`` through syrupy as usual (``text_snapshot("md")(name="narrow")``) when one
    test asserts more than one document.
    """

    def _for(extension: str) -> SnapshotAssertion:
        return snapshot.use_extension(
            bind(
                NormalizingTextFileExtension,
                snapshot_normalizer,
                file_extension=extension,
            )
        )

    return _for


# --------------------------------------------------------------------------- #
# The canonical fixture scan. Built by tests/snapshot/support/fixture_model.py
# through ASH's own aggregation; its findings and scanner statuses are listed in
# tests/test_data/snapshot_fixture/README.md. Imports are local so this section
# stays an append to the fixtures above.
# --------------------------------------------------------------------------- #


@pytest.fixture
def pinned_clock(monkeypatch: pytest.MonkeyPatch):
    """Pin datetime.now() and uuid4 in every module that stamps them into output.

    Returns the clock; the fixture-model builders advance it from scan start to
    report time themselves.
    """
    from tests.snapshot.support.fixture_model import pin_clock

    return pin_clock(monkeypatch)


@pytest.fixture
def fixture_context(tmp_path: Path):
    """The PluginContext of the single-directory fixture scan."""
    from tests.snapshot.support.fixture_model import fixture_plugin_context

    return fixture_plugin_context(tmp_path)


@pytest.fixture
def fixture_model(pinned_clock, fixture_context, tmp_path: Path):
    """The single-directory fixture scan, as reporters receive it."""
    from tests.snapshot.support.fixture_model import build_fixture_model

    return build_fixture_model(tmp_path, fixture_context)


@pytest.fixture
def fixture_workspace_model(
    pinned_clock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The two-project workspace fixture scan, as merged reporters receive it."""
    from tests.snapshot.support.fixture_model import build_fixture_workspace_model

    return build_fixture_workspace_model(tmp_path, monkeypatch)


@pytest.fixture
def fixture_skipped_workspace_model(
    pinned_clock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The workspace fixture scan with a third, skipped project (``docs``)."""
    from tests.snapshot.support.fixture_model import build_fixture_workspace_model

    return build_fixture_workspace_model(
        tmp_path, monkeypatch, with_skipped_project=True
    )


@pytest.fixture
def fixture_variant(request: pytest.FixtureRequest, tmp_path: Path):
    """``fixture_variant("single" | "workspace" | "skipped-workspace")`` -> (model, context).

    The context is the one ASH gives reporters for that shape: the fixture
    repository's own config for a single scan, and the workspace-level default
    config ``emit_workspace_reports`` uses for the two workspace shapes.
    """
    from tests.snapshot.support.fixture_model import workspace_reporter_context

    def _for(variant: str):
        if variant == "single":
            return (
                request.getfixturevalue("fixture_model"),
                request.getfixturevalue("fixture_context"),
            )
        name = {
            "workspace": "fixture_workspace_model",
            "skipped-workspace": "fixture_skipped_workspace_model",
        }[variant]
        model = request.getfixturevalue(name)
        return model, workspace_reporter_context(model, tmp_path)

    return _for
