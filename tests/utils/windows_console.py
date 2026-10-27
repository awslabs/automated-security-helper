# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Windows as ASH sees it, for tests that run on any platform.

The real checks need Windows, and no CI leg here runs these tests on a console, so
the platform and the console are both stood in for.
"""

from __future__ import annotations

import locale
import os

import pytest


class WindowsOs:
    """``os`` with the name "nt" and no process groups.

    Patched in as one module's ``os`` rather than by setting ``os.name``, which
    pathlib reads on every ``Path()``: with ``os.name`` "nt", a path built anywhere in
    the test would be a ``WindowsPath``.
    """

    name = "nt"

    def __getattr__(self, attribute: str):
        if attribute in ("tcgetpgrp", "getpgrp", "getpgid", "killpg", "setsid"):
            raise AttributeError(attribute)
        return getattr(os, attribute)


def as_windows(monkeypatch: pytest.MonkeyPatch, *, console: bool) -> None:
    """Run subprocess_utils as on Windows, attached to a console or not."""
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(subprocess_utils, "os", WindowsOs())
    # raising=False so the same test runs against code that predates the check: there
    # it has no effect, and the test fails on what that code does.
    monkeypatch.setattr(
        subprocess_utils, "_has_a_console", lambda: console, raising=False
    )


def windows_logging_kept_in_the_test(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let ``configure_windows_safe_logging`` take its Windows branch, undone afterwards.

    get_logger calls it every time. Once ``platform.system()`` answers "Windows" and
    a CI variable is set (as on every GitHub runner) or the console can't encode, it
    sets the process locale with ``locale.setlocale(LC_ALL, "en_US.UTF-8")`` and adds
    ``PYTHONIOENCODING`` to the environment. Patching the platform undoes neither,
    so without the stand-ins every later test on the same worker runs in
    en_US.UTF-8: Rich's log time column (``[%x %X]``) grows by five characters,
    the 80-column console wraps each message five characters sooner, and a test
    that looks for a phrase in a log line fails where the phrase wraps
    (test_report_errors_quote_no_input, test_recorded_config_quotes_no_env_value).

    The locale is set through a stand-in that changes nothing and answers with the
    locale the process has, as a query would. ``PYTHONIOENCODING`` is given to this
    ``monkeypatch``, so whatever the code sets is put back when it is undone.
    """
    query = locale.setlocale

    def setlocale(category: int, value: str | None = None) -> str:
        return query(category)

    monkeypatch.setattr(locale, "setlocale", setlocale)
    if "PYTHONIOENCODING" in os.environ:
        monkeypatch.setenv("PYTHONIOENCODING", os.environ["PYTHONIOENCODING"])
    else:
        # monkeypatch undoes only what it changed, so set it and take it away: the
        # test runs without it, as the code under test expects, and the value the
        # code adds is removed again when the patches are undone.
        monkeypatch.setenv("PYTHONIOENCODING", "")
        monkeypatch.delenv("PYTHONIOENCODING")
