# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures for the characterization tests. Read the docstring of ``_harness`` first.

Every test in this package runs with the launch guards installed (``_launch_guards``,
autouse), with or without a harness: no process starts or is signaled, no socket
opens, no C library is called, nothing is written outside pytest's basetemp, and
anything undeclared fails the test. ``char`` gives a test its harness, with a
hermetic environment, and ``snapshot`` writes its golden through the harness's
normalizer. Imports at collection, which those guards do not cover, are watched
instead (``_harness.watched_imports``): a test module whose import starts a
process, sends a signal or opens a socket fails to collect.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Iterator

import pytest
from syrupy.assertion import SnapshotAssertion

from tests.unit.characterization import _harness

# Third-party modules that a test module here imports at module level, imported
# once under the import watch. urllib3 checks for IPv6 when first imported by
# binding a socket to ("::1", 0) and closing it; that is the one import-time
# effect allowed, and only from there. Add a module here, with the narrowest
# allowance it needs, rather than importing it unwatched.
with _harness.watched_imports(
    "the characterization conftest's pre-imports",
    allowed=[_harness.urllib3_ipv6_probe],
):
    import detect_secrets  # noqa: E402, F401
    import requests  # noqa: E402, F401
    import urllib3  # noqa: E402, F401

# The harness models POSIX exec semantics, and test_harness_confinement.py imports
# posix and pty and names POSIX-only functions of os and signal at module level, so on
# Windows the package's test modules are kept out of collection: a module that fails
# to import there is a collection error, which ends the whole run with exit 2 rather
# than skipping anything. _launch_guards below skips every test that reaches it on
# any other path.
if sys.platform == "win32":
    collect_ignore_glob = ["test_*.py"]


@pytest.hookimpl(wrapper=True)
def pytest_make_collect_report(collector: pytest.Collector) -> Iterator[Any]:
    """Import each test module here under the import watch, with nothing allowed."""
    if not isinstance(collector, pytest.Module):
        return (yield)
    with _harness.watched_imports(collector.nodeid) as refused:
        report = yield
    if refused and report.passed:
        # Something on the way swallowed the LaunchViolation.
        report.outcome = "failed"
        report.longrepr = "\n".join(refused)
    return report


@pytest.fixture(autouse=True)
def _launch_guards(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[None]:
    if sys.platform == "win32":
        pytest.skip("the characterization harness models POSIX exec semantics")
    with _harness.guarded(monkeypatch, tmp_path_factory.getbasetemp()):
        yield


@pytest.fixture
def char_factory(_launch_guards: None):
    """Build a harness in a directory of the caller's choosing (for self-tests)."""

    def make(directory: Path) -> _harness.Harness:
        return _harness.Harness(directory)

    return make


@pytest.fixture(scope="session", autouse=True)
def _sweep_stale_short_roots() -> None:
    """Once per worker, remove the harness roots a killed run left behind."""
    if sys.platform != "win32":
        _harness.sweep_stale_short_roots()


@pytest.fixture
def char(char_factory) -> Iterator[_harness.Harness]:
    """A harness in a fresh ``<TMPDIR>/char-<8 hex digits>``, at most 96 characters
    long (see ``_harness.short_root``)."""
    with _harness.short_root() as root:
        harness = char_factory(root)
        with harness.active():
            yield harness


@pytest.fixture
def snapshot(snapshot: SnapshotAssertion, char: _harness.Harness) -> SnapshotAssertion:
    return snapshot.use_extension(char.snapshot_extension)
