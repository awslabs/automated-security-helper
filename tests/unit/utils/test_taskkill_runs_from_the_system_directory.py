# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""On Windows, a scanner's process tree is ended by the system's own taskkill.

taskkill is run by its absolute path in the system directory, never by a bare
name the search path resolves, because on Windows that search starts in the
current directory, which for a scan is the scanned repository. The path comes
from GetSystemDirectoryW, else from
%SystemRoot%\\System32. With neither, it is not run, and the child alone is killed.

These run on any platform: the module's ``os`` is replaced by one that reports
Windows, and no real taskkill is run. The last one runs only on Windows, where
it reads the real system directory with nothing patched.
"""

from __future__ import annotations

import ctypes
import ntpath
import os
import subprocess
import sys
from typing import Any, List

import pytest

from automated_security_helper.utils import subprocess_utils


class _WindowsOs:
    """The os module, reporting Windows."""

    name = "nt"

    def __getattr__(self, attribute: str) -> Any:
        return getattr(os, attribute)


class _Child:
    """A child process that is running until it is killed."""

    pid = 4242

    def __init__(self) -> None:
        self.killed = False

    def poll(self):
        return -9 if self.killed else None

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout=None):
        return -9


@pytest.fixture
def ran(monkeypatch) -> List[List[str]]:
    calls: List[List[str]] = []

    def run(argv, **kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess_utils, "os", _WindowsOs())
    monkeypatch.setattr(subprocess_utils.subprocess, "run", run)
    monkeypatch.delattr(ctypes, "windll", raising=False)
    for name in ("SystemRoot", "SYSTEMROOT"):
        monkeypatch.delenv(name, raising=False)
    return calls


def test_taskkill_runs_by_its_path_under_systemroot(ran, monkeypatch):
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    child = _Child()

    subprocess_utils._stop_tree(child, 0.0)

    assert ran, "taskkill was not run"
    assert ran[0][0] == "C:\\Windows\\System32\\taskkill.exe", ran
    assert ran[0][1:] == ["/T", "/F", "/PID", "4242"], ran


def test_the_system_directory_comes_from_windows_first(ran, monkeypatch):
    monkeypatch.setenv("SystemRoot", "C:\\Elsewhere")

    class _Kernel32:
        @staticmethod
        def GetSystemDirectoryW(buffer, size):
            buffer.value = "D:\\Win\\System32"
            return len(buffer.value)

    class _WinDLL:
        kernel32 = _Kernel32()

    monkeypatch.setattr(ctypes, "windll", _WinDLL(), raising=False)

    subprocess_utils._stop_tree(_Child(), 0.0)

    assert ran and ran[0][0] == "D:\\Win\\System32\\taskkill.exe", ran


def test_with_no_system_directory_taskkill_is_not_run_by_bare_name(ran):
    child = _Child()

    subprocess_utils._stop_tree(child, 0.0)

    assert ran == [], f"taskkill ran without a system directory: {ran}"
    assert child.killed, "the child was not killed when taskkill could not run"


class _Unkillable(_Child):
    """A child that does not exit when it is killed, and records every wait."""

    def __init__(self) -> None:
        super().__init__()
        self.waits: List[Any] = []

    def poll(self):
        return None

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if timeout is None:
            raise AssertionError("waited for the child with no bound")
        raise subprocess.TimeoutExpired("child", timeout)


def test_the_wait_after_the_kill_is_bounded(ran, monkeypatch):
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    child = _Unkillable()

    subprocess_utils._stop_tree(child, 0.0)

    assert child.waits and None not in child.waits, child.waits


@pytest.mark.skipif(
    sys.platform != "win32", reason="reads the real Windows system directory"
)
def test_the_real_system_directory_holds_taskkill():
    """Unpatched, on Windows: the path taskkill is run from exists."""
    system = subprocess_utils._windows_system_directory()
    taskkill = subprocess_utils._taskkill_path()

    assert system and ntpath.isabs(system), system
    assert taskkill and ntpath.isabs(taskkill), taskkill
    assert taskkill.lower().endswith("\\system32\\taskkill.exe"), taskkill
    assert os.path.isfile(taskkill), taskkill
