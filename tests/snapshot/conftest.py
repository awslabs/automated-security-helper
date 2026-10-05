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

import contextlib
import importlib
import logging
import os
import platform
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

from tests.snapshot.support.cli import LINUX_AMD64, pin_host
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
#: output on CI and CODEBUILD_BUILD_ID, and the color variables override NO_COLOR.
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


#: Normalizer switches a test or module may turn on with
#: ``@pytest.mark.snapshot_masking(...)``. All are off by default; see "Time" in the
#: module docstring of tests/snapshot/support/normalize.py for what each one masks
#: and when opting in is justified.
_MASKING_SWITCHES = frozenset({"mask_instants", "mask_durations", "mask_duration_keys"})


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "snapshot_masking(mask_instants=..., mask_durations=..., "
        "mask_duration_keys=...): turn on a SnapshotNormalizer time rule (all are off "
        "by default) for a test that renders wall-clock time it cannot pin.",
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
    """Render every snapshot for the same terminal: 100 columns, no color, no TTY."""
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
        # Fixed when the Console was built, by the detect_legacy_windows() pinned just
        # below, which an import at collection ran unpinned. cli/dependencies.py's
        # console is built that way, and on windows-latest it drew the installer panel
        # with square corners in some workers and rounded ones in others.
        monkeypatch.setattr(console, "legacy_windows", False)
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
    # shows a new time is a race with the clock, and the column's width follows the
    # locale's %x %X, so the time column renders one constant token instead: the
    # first line of each handler shows it, and every later one shows as many blanks.
    # Handlers are built per get_logger() call and _fresh_ash_loggers drops them
    # between tests, so "first line" is a property of the command, not of test order.
    monkeypatch.setattr(LogRender, "__call__", _log_render_without_clock)


@pytest.fixture(autouse=True)
def _pinned_host(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Render every snapshot as linux-amd64 unless the test simulates another host.

    ASH reads ``platform.system()`` to decide what it prints, so without this a
    snapshot showed the OS the suite ran on. Measured on windows-latest, where 18 of
    the 26 snapshot failures came from it: ASH's log console is built with
    ``legacy_windows=True`` and ``safe_box=True`` on Windows (utils/log.py), which
    draws panels with square corners and wraps one column early; semgrep and opengrep
    default to disabled there, which every rendered config and scanner list shows;
    and cfn-nag's install probe asks for a Ruby DevKit instead of a C compiler. A
    test that renders a Windows variant says so with ``simulated_host``, which nests
    inside this one, and then renders it on every OS.

    The patch goes on the test's own ``monkeypatch``, not on a context of its own.
    With a separate context, a test that patched ``platform.system`` directly
    (test_snapshot_console_metrics_table.py does) recorded the pinned function as the
    original, and its ``monkeypatch``, torn down after this fixture, put the pin back
    after this fixture had removed it. Every later test in that xdist worker then ran
    as Linux: on windows-latest the unit tests that write a ``.cmd`` launcher wrote a
    shebang script instead and failed with WinError 193. One ``monkeypatch`` undoes
    in LIFO order, so the test's patch comes off before this one does.
    """
    restore_defaults = pin_host(monkeypatch, LINUX_AMD64)
    yield
    restore_defaults()


#: The host lookups as this process found them, before any snapshot test patched them.
_REAL_HOST_LOOKUPS = (platform.system, platform.machine)


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_teardown(item: pytest.Item) -> Iterator[None]:
    """Fail a snapshot test that leaves ``platform.system``/``machine`` patched.

    Runs after every fixture of the test is torn down. A leaked host answer changes
    what every later test in the worker runs as, snapshot or not, and on the host it
    names it is invisible: the leak described in ``_pinned_host`` answered "Linux" on
    Linux like the real function, and was found only as unrelated unit-test failures
    on Windows. Compared by identity, so it is caught on every OS. The real functions
    are put back first, so the failure stays with the test that caused it.
    """
    try:
        return (yield)
    finally:
        leaked = (platform.system, platform.machine) != _REAL_HOST_LOOKUPS
        if leaked:
            platform.system, platform.machine = _REAL_HOST_LOOKUPS
            raise AssertionError(
                f"{item.nodeid} left platform.system/platform.machine patched after "
                "teardown. Patch them through the test's own monkeypatch, or with "
                "tests.snapshot.support.cli.simulated_host."
            )


#: Where ASH's own plugins live. A fresh ``ash`` process registers these and nothing
#: else unless its config names more (no snapshot test's config does).
_BUILTIN_PLUGIN_PACKAGE = "automated_security_helper.plugin_modules.ash_builtin"


def _is_builtin_plugin_module(module_path: str) -> bool:
    if module_path == _BUILTIN_PLUGIN_PACKAGE or module_path.startswith(
        _BUILTIN_PLUGIN_PACKAGE + "."
    ):
        return True
    # Core modules may subscribe handlers too; the other plugin packages
    # (ash_aws_plugins, ash_ferret_plugins, ...) are what a config opts into.
    return module_path.startswith(
        "automated_security_helper."
    ) and not module_path.startswith("automated_security_helper.plugin_modules.")


@pytest.fixture(autouse=True)
def _builtin_plugins_only(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Give every snapshot the plugin registry of a fresh process; see below."""
    with builtin_plugin_registry(monkeypatch):
        yield


@contextlib.contextmanager
def builtin_plugin_registry(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Give every snapshot the plugin registry of a freshly started ``ash`` process.

    Plugins register into one module-level ``ash_plugin_manager`` when their module is
    first imported, and ``plugin_modules()`` memoises what it resolved. So once any
    test in an xdist worker imports ``ash_aws_plugins`` (the pinned clock does, to
    patch two AWS reporters' ``datetime``) or ``ash_ferret_plugins``, every later
    snapshot in that worker lists ferret-scan, trivy-repo and the AWS reporters,
    installs their dependencies, and runs aws-security-hub's validation against
    whatever AWS credentials the machine has. Measured: the full suite failed 31
    snapshots this way, and ``-n 0`` with the AWS reporter tests first reproduced
    it inside tests/snapshot alone.

    For the test, the registry keeps only ASH's built-in registrations (in their
    original order), the event handlers keep only ASH's own, and the resolution
    cache starts empty; all three are put back afterwards for the rest of the
    suite. A built-in that an earlier test unregistered is not quietly re-added:
    the fixture fails, because a fresh process would have it.

    Used as the autouse fixture ``_builtin_plugins_only``; a context manager so
    tests/snapshot/test_snapshot_plugin_registry.py can drive it directly.

    A plugin module imported for the first time during the test registered into the
    test's copy, and Python will not run that module's registration again: it stays
    in ``sys.modules``. Its registrations are therefore merged back into the real
    registry on teardown (keys the real registry already has are left alone), so the
    rest of the suite sees the same registry it would have seen without this fixture.
    """
    from automated_security_helper.plugin_modules import ash_builtin
    from automated_security_helper.plugins import ash_plugin_manager
    from tests.snapshot.support.fixture_model import CLOCK_PINNED_MODULES

    # ``pinned_clock`` imports these to patch them, and two are AWS reporters: their
    # package registers its plugins on first import. Imported inside the test, those
    # registrations would land in the test's copy and the first test in a worker to
    # pin the clock would list the AWS reporters (measured: `ash report --format
    # dict` did, under xdist only). Importing them first puts them in the real
    # registry, where the filter below leaves them out of every test alike.
    for module_name in CLOCK_PINNED_MODULES:
        importlib.import_module(module_name)

    library = ash_plugin_manager.plugin_library
    imported_before = set(sys.modules)
    real: dict[str, dict[str, Any]] = {}
    for kind, declared in (
        ("converters", ash_builtin.ASH_CONVERTERS),
        ("scanners", ash_builtin.ASH_SCANNERS),
        ("reporters", ash_builtin.ASH_REPORTERS),
    ):
        real[kind] = getattr(library, kind)
        builtin = {
            name: registration
            for name, registration in real[kind].items()
            if _is_builtin_plugin_module(registration.plugin_module_path)
        }
        missing = sorted(
            cls.__name__ for cls in declared if cls.__name__ not in builtin
        )
        if missing:
            raise RuntimeError(
                f"built-in {kind} missing from the plugin registry before this "
                f"snapshot test (an earlier test removed them): {missing}"
            )
        monkeypatch.setattr(library, kind, builtin)
    real_handlers = library.event_handlers
    monkeypatch.setattr(
        library,
        "event_handlers",
        {
            event: [
                callback
                for callback in callbacks
                if _is_builtin_plugin_module(getattr(callback, "__module__", "") or "")
            ]
            for event, callbacks in real_handlers.items()
        },
    )
    monkeypatch.setattr(ash_plugin_manager, "_resolved_plugins", {})
    try:
        yield
    finally:
        # Runs before monkeypatch puts the real dicts back, so the copies are still
        # installed and readable here.
        _merge_new_registrations(library, real, real_handlers, imported_before)


def _merge_new_registrations(
    library: Any,
    real: dict[str, dict[str, Any]],
    real_handlers: dict[Any, list[Callable[..., Any]]],
    imported_before: set[str],
) -> None:
    """Copy into the real registry what modules first imported during the test added."""

    def first_imported_now(module_path: str) -> bool:
        return module_path in sys.modules and module_path not in imported_before

    for kind, registry in real.items():
        for name, registration in getattr(library, kind).items():
            if name not in registry and first_imported_now(
                registration.plugin_module_path
            ):
                registry[name] = registration
    for event, callbacks in library.event_handlers.items():
        for callback in callbacks:
            module_path = getattr(callback, "__module__", "") or ""
            if first_imported_now(module_path) and callback not in real_handlers.get(
                event, []
            ):
                real_handlers.setdefault(event, []).append(callback)


@pytest.fixture(autouse=True)
def _no_real_aws(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """No snapshot may reach AWS with the machine's credentials.

    The AWS reporter tests stub every client call; this is the floor under them and
    under any other test: placeholder keys, no profile, no config or credentials
    file, no instance metadata. A call that slips past a stub fails to authenticate
    instead of acting on a real account (one did, with an expired token, before
    _builtin_plugins_only existed).
    """
    for name in (
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN",
        "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    ):
        monkeypatch.delenv(name, raising=False)
    missing = str(tmp_path / "no-aws-config")
    monkeypatch.setenv("AWS_CONFIG_FILE", missing)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", missing)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "snapshot-test-not-a-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "snapshot-test-not-a-secret")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


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
    Instants and durations are not masked. A test that renders wall-clock time it
    cannot pin opts in with, for example,
    ``@pytest.mark.snapshot_masking(mask_instants=True, mask_durations=True)`` (or a
    module ``pytestmark``). Prefer pinning the clock (``pinned_clock``).
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
