# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Driving the ``ash`` CLI for snapshot tests, and pretending to be another host.

Nothing here normalizes output; the ``snapshot`` and ``text_snapshot`` fixtures still
do all of that. What lives here pins the *inputs* that would otherwise differ between
machines.

:func:`run_cli` invokes the real Typer ``app`` in-process with ``CliRunner`` and returns
one document per invocation: the command line, everything the user saw on the terminal
(stdout and stderr interleaved, as click 8.2+ records them), and the exit code. Each
run happens inside :func:`pinned_console`, which says what it pins and why.

:func:`displayed_cwd` fixes the cwd that ``Path.absolute()`` reports, for the few
outputs that draw a box around an absolute path.

:func:`simulated_host` makes this process answer as another OS and CPU. Patching
``platform.system`` alone is not enough, because two scanner configs read it while
their class body runs, at import:

- ``SemgrepScannerConfig.enabled = platform.system().lower() != "windows"``
- ``OpengrepScannerConfig.enabled = platform.system().lower() != "windows"``

pydantic copies those defaults into the core schema of every model that nests the
config (``ScannerConfigSegment``, ``AshConfig``) and into the default instances those
models hold, so each of those is patched and its schema rebuilt, then all of it is put
back afterwards. ``tests/snapshot/config/test_snapshot_config_hosts.py`` asserts every
path that reads the default sees the simulated value, so a change to how these
defaults are built fails there rather than as a confusing snapshot diff on Windows.
"""

from __future__ import annotations

import contextlib
import os
import platform
import shlex
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from types import ModuleType

import pytest
from typer.testing import CliRunner


@dataclass(frozen=True)
class Host:
    """An OS and CPU as ``platform.system()`` and ``platform.machine()`` report them."""

    id: str
    system: str
    machine: str

    @property
    def is_windows(self) -> bool:
        return self.system.lower() == "windows"


LINUX_AMD64 = Host("linux-amd64", "Linux", "x86_64")
LINUX_ARM64 = Host("linux-arm64", "Linux", "aarch64")
DARWIN_AMD64 = Host("darwin-amd64", "Darwin", "x86_64")
DARWIN_ARM64 = Host("darwin-arm64", "Darwin", "arm64")
WINDOWS_AMD64 = Host("windows-amd64", "Windows", "AMD64")
WINDOWS_ARM64 = Host("windows-arm64", "Windows", "ARM64")
#: Neither a platform nor an architecture ASH knows, so both resolve to "unknown".
UNKNOWN_HOST = Host("freebsd-riscv64", "FreeBSD", "riscv64")

#: Every host ASH distinguishes, for surfaces that read the platform and the arch.
ALL_HOSTS = (
    LINUX_AMD64,
    LINUX_ARM64,
    DARWIN_AMD64,
    DARWIN_ARM64,
    WINDOWS_AMD64,
    WINDOWS_ARM64,
    UNKNOWN_HOST,
)

#: For surfaces that only differ between Windows and everything else (the semgrep and
#: opengrep defaults above).
CONFIG_HOSTS = (LINUX_AMD64, WINDOWS_AMD64)


def _windows_dependent_defaults():
    """(config class, segment field name) for each default evaluated at import."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
        OpengrepScannerConfig,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
        SemgrepScannerConfig,
    )

    return ((SemgrepScannerConfig, "semgrep"), (OpengrepScannerConfig, "opengrep"))


def _set_import_time_defaults(enabled: bool) -> None:
    from automated_security_helper.config.ash_config import (
        AshConfig,
        ScannerConfigSegment,
    )

    ash_config_scanners = AshConfig.model_fields["scanners"].default
    for config_cls, segment_field in _windows_dependent_defaults():
        config_cls.model_fields["enabled"].default = enabled
        config_cls.model_rebuild(force=True)
        # Default instances: object.__setattr__ skips validate_assignment, which is
        # the point; this is the value the class body would have produced.
        object.__setattr__(
            ScannerConfigSegment.model_fields[segment_field].default, "enabled", enabled
        )
        object.__setattr__(
            getattr(ash_config_scanners, segment_field), "enabled", enabled
        )
    ScannerConfigSegment.model_rebuild(force=True)
    AshConfig.model_rebuild(force=True)


@contextlib.contextmanager
def simulated_host(monkeypatch: pytest.MonkeyPatch, host: Host) -> Iterator[Host]:
    """Run the body as if on ``host``; restores the real host's defaults on exit.

    "Real" is whatever ``platform.system()`` answers on entry, so this nests: inside
    the linux-amd64 host tests/snapshot/conftest.py pins for every snapshot test, a
    test's own ``simulated_host`` restores linux-amd64, and the conftest pin restores
    the machine's own host. The import-time defaults are rebuilt only when the
    simulated host flips them, which on a Linux or macOS machine running a non-Windows
    host is never.
    """
    real_enabled = platform.system().lower() != "windows"
    simulated_enabled = not host.is_windows
    flips_defaults = simulated_enabled != real_enabled
    with monkeypatch.context() as mp:
        mp.setattr(platform, "system", lambda: host.system)
        mp.setattr(platform, "machine", lambda: host.machine)
        if flips_defaults:
            _set_import_time_defaults(simulated_enabled)
        try:
            yield host
        finally:
            if flips_defaults:
                _set_import_time_defaults(real_enabled)


#: What ``Path.absolute()`` reports under :func:`displayed_cwd`. Same length in its
#: POSIX and Windows spellings, which is the property that matters (see below).
DISPLAYED_CWD = "/workspace/demo-project"


@contextlib.contextmanager
def displayed_cwd(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Make ``Path.absolute()`` report :data:`DISPLAYED_CWD`; the real cwd is unchanged.

    For output that draws a rich box around an absolute path. The normalizer masks
    the path, but the box was padded to the real path's length first, so the border
    lands in a different column on every machine. A display-only cwd of fixed length
    keeps the geometry the same everywhere. Relative file access still goes to the
    real working directory, because only ``os.getcwd`` is replaced. Register
    DISPLAYED_CWD with ``snapshot_normalizer.add_root`` so its Windows spelling
    (backslashes) snapshots like the POSIX one.

    ``os.getcwd`` returns the native spelling (``\\workspace\\demo-project`` on
    Windows), as the real one does. From Python 3.13 ``Path.absolute()`` relies on
    that: it splits the cwd on the native separator only, so a POSIX-spelled cwd on
    Windows became one component, ``/workspace/demo-project\\probe``, which compares
    unequal to the same path parsed normally and failed the probe below.
    """
    import pathlib

    native_cwd = str(pathlib.PurePath(DISPLAYED_CWD))
    with monkeypatch.context() as mp:
        mp.setattr(os, "getcwd", lambda: native_cwd)
        accessor = getattr(pathlib, "_NormalAccessor", None)  # Python 3.10 only
        if accessor is not None and hasattr(accessor, "getcwd"):
            mp.setattr(accessor, "getcwd", staticmethod(lambda: native_cwd))
        probe = pathlib.Path("probe").absolute()
        if pathlib.PurePath(DISPLAYED_CWD, "probe") != probe:
            raise AssertionError(
                f"displayed_cwd did not take effect on this Python: {probe}"
            )
        yield


@dataclass(frozen=True)
class CliRun:
    args: tuple[str, ...]
    exit_code: int
    output: str
    exception: BaseException | None

    @property
    def document(self) -> str:
        """What a user typing the command would see, plus how it exited."""
        return (
            f"$ ash {shlex.join(self.args)}\n"
            f"{self.output.rstrip()}\n"
            f"[exit code: {self.exit_code}]\n"
        )


#: Every log record a CLI run creates is stamped with this instant (2030-03-17 UTC).
FROZEN_LOG_CLOCK = 1_900_000_000


class _FrozenLogClock:
    """Stands in for the ``time`` module inside ``logging`` only."""

    def __init__(self, real: ModuleType) -> None:
        self._real = real

    def time(self) -> float:
        return float(FROZEN_LOG_CLOCK)

    def time_ns(self) -> int:
        return FROZEN_LOG_CLOCK * 1_000_000_000

    def __getattr__(self, name: str):
        return getattr(self._real, name)


@contextlib.contextmanager
def pinned_console() -> Iterator[None]:
    """Make every rich console a CLI run builds render the same on every OS.

    - rich.print and rich.get_console share one lazily-built Console. It is dropped so
      the next one reads the pinned COLUMNS/NO_COLOR/TERM, not whatever terminal an
      earlier import saw.
    - ASH's log console passes ``_environ={}``, so it never reads COLUMNS and asks the
      process's real stdin/stdout/stderr for a size instead: 80 columns under xdist,
      the developer's terminal width under ``-n0``. The terminal is pinned to the same
      100x50 the environment advertises.
    - On real Windows rich treats any console whose stdout is not a VT-capable console
      as legacy and renders one column narrower. CliRunner's stream never is, so that
      is turned off; a simulated Windows host still gets ASH's own explicit
      ``legacy_windows=True`` log console, because that is ASH's choice, not rich's.
    - Log records are stamped with a frozen clock, so a log file a run writes into its
      tmp dir carries one instant. The console's time column does not depend on it:
      tests/snapshot/conftest.py draws that column as the constant ``[<LOG_TIME>]``
      for every snapshot test (normalize.py's docstring says why a text rule cannot).
    """
    import logging

    import rich.console

    with pytest.MonkeyPatch.context() as mp:
        # pytest's live-logging handler (log_cli = True in pytest.ini) suspends and
        # resumes capture around each record, and resuming reassigns sys.stdout,
        # undoing CliRunner's redirection for the rest of the run: everything after
        # the first propagating record (a DeprecationWarning routed through
        # py.warnings, on the first import of a module) lands in pytest's capture
        # instead of the result. tests/conftest.py detaches it from the ash logger
        # for the same reason; during a CLI run it is detached everywhere.
        loggers = [logging.getLogger()] + [
            obj
            for obj in logging.Logger.manager.loggerDict.values()
            if isinstance(obj, logging.Logger)
        ]
        for logger in loggers:
            kept = [
                h
                for h in logger.handlers
                if not type(h).__name__.startswith("_LiveLogging")
            ]
            if len(kept) != len(logger.handlers):
                mp.setattr(logger, "handlers", kept)
        mp.setattr(rich, "_console", None)
        mp.setattr(rich.console, "detect_legacy_windows", lambda: False)
        mp.setattr(os, "get_terminal_size", lambda *_: os.terminal_size((100, 50)))
        mp.setattr(logging, "time", _FrozenLogClock(time))
        yield


def run_cli(args: Sequence[str], *, stdin: str | None = None) -> CliRun:
    """Invoke ``ash <args>`` in-process. Uncaught exceptions propagate to the test."""
    from automated_security_helper.cli.main import app

    with pinned_console():
        result = CliRunner().invoke(app, list(args), input=stdin, catch_exceptions=True)
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        raise result.exception
    return CliRun(
        args=tuple(args),
        exit_code=result.exit_code,
        output=result.output,
        exception=result.exception,
    )


__all__ = [
    "ALL_HOSTS",
    "CONFIG_HOSTS",
    "CliRun",
    "Host",
    "LINUX_AMD64",
    "WINDOWS_AMD64",
    "run_cli",
    "simulated_host",
]
