# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""configure_windows_safe_logging sets the process locale once a process.

get_logger calls it for every logger it sets up, and the MCP server sets up
loggers from scan threads. The locale belongs to the whole process and
setlocale is not safe to call from several threads at once, so a second call,
and a call from another thread, leave the locale as the first one set it.
"""

import sys
import threading
import time
from unittest.mock import patch

import pytest

from automated_security_helper.utils import log as log_module

pytestmark = pytest.mark.unit


class _Console:
    """A console that cannot encode ASH's emoji and takes a reconfigure."""

    encoding = "cp1252"

    def reconfigure(self, **kwargs) -> None:
        return None

    def write(self, text: str) -> int:
        return len(text)

    def flush(self) -> None:
        return None


@pytest.fixture
def windows_console(monkeypatch):
    """Windows with a narrow console, and a process that has not set its locale.

    The environment variable the function also sets is stubbed out, so nothing
    the call does outlives the test.
    """
    monkeypatch.setattr(log_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(sys, "stdout", _Console())
    monkeypatch.setattr(sys, "stderr", _Console())
    monkeypatch.setattr(log_module, "setdefault_environ", lambda *args: None)
    # raising=False: the attribute is what the fix adds, and the test must fail
    # on the assertion below, not on a missing name, against the code without it.
    monkeypatch.setattr(log_module, "_locale_step_done", False, raising=False)


def test_a_second_call_leaves_the_locale_as_the_first_set_it(windows_console):
    with patch("locale.setlocale") as setlocale:
        log_module.configure_windows_safe_logging()
        log_module.configure_windows_safe_logging()

    assert setlocale.call_count == 1


def test_a_first_call_that_found_no_utf8_locale_does_not_try_again(windows_console):
    import locale

    with patch("locale.setlocale", side_effect=locale.Error("none")) as setlocale:
        log_module.configure_windows_safe_logging()
        log_module.configure_windows_safe_logging()

    # The two candidate names, tried once.
    assert setlocale.call_count == 2


def test_threads_that_arrive_together_set_the_locale_once(windows_console):
    threads = 8
    arrive_together = threading.Barrier(threads)
    errors: list[BaseException] = []
    calls: list[tuple] = []

    def slow_setlocale(*args):
        calls.append(args)
        # Long enough that a second thread is inside the step before the first
        # has left it, when nothing keeps the step to one thread.
        time.sleep(0.05)

    def reach_the_function() -> None:
        try:
            arrive_together.wait(timeout=30)
            log_module.configure_windows_safe_logging()
        except BaseException as exc:  # noqa: BLE001 -- reported by the assertion
            errors.append(exc)

    with patch("locale.setlocale", side_effect=slow_setlocale):
        workers = [threading.Thread(target=reach_the_function) for _ in range(threads)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(60)

    assert errors == []
    assert len(calls) == 1


def test_a_call_the_gate_turns_away_does_not_use_up_the_attempt(
    windows_console, monkeypatch
):
    with patch("locale.setlocale") as setlocale:
        monkeypatch.setattr(log_module.platform, "system", lambda: "Linux")
        log_module.configure_windows_safe_logging()
        monkeypatch.setattr(log_module.platform, "system", lambda: "Windows")
        log_module.configure_windows_safe_logging()

    assert setlocale.call_count == 1
