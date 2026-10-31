# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures shared by the interaction tests.

The host's user and group IDs
-----------------------------
Container mode reads the host's UID and GID (``subprocess_utils.get_host_uid`` and
``get_host_gid``, which run ``id -u`` and ``id -g``) and refuses a ``non-root`` image
build as UID or GID 0 before it starts anything: exit 3, "ASH is running as root".
That refusal is intended, and ``test_container_non_root_stage_uid.py`` and
``test_container_refused_inputs_keep_prior_output.py`` pin the IDs to 0 to test it.

Every other test that reaches container mode asserts something else, such as the
command that would run, how a refusal in the inner run is carried out, or how stale
results are cleared. Left to read the real IDs, each of them passes for a non-root
user and exits 3 for root, so a suite run as root (a container with no ``USER``, a
CI job that does not drop privileges) reports dozens of failures that are about the
account running the tests and not about the code. The sibling test files pin the IDs
one by one; this does it once for the directory.

An individual test or fixture that sets the IDs itself, or patches
``subprocess_utils.get_host_uid``, runs after this fixture and wins.
"""

import io
import os
import tempfile

import pytest

from automated_security_helper.utils import subprocess_utils


class _Pipe:
    def __init__(self, text: str = "") -> None:
        self._stream = io.StringIO(text)

    def readline(self) -> str:
        return self._stream.readline()


class _RuntimeStandIn:
    """A container runtime that runs until stopped; its second poll calls ``on_poll``.

    Bounded: it raises past 300 polls, so a planted signal that never took effect
    fails loudly. Its pid is this process's own, so a die-now record that a test
    never arms could not reach a process the test does not own.
    """

    def __init__(self, on_poll=None, stdout: str = "", stderr: str = "") -> None:
        self.stdout = _Pipe(stdout)
        self.stderr = _Pipe(stderr)
        self.returncode = None
        self.pid = os.getpid()
        self.polls = 0
        self.on_poll = on_poll
        self.killed = False

    def kill(self):
        self.killed = True

    def poll(self):
        self.polls += 1
        if self.polls > 300:
            raise RuntimeError(
                "polled past the bound: the planted signal never took effect"
            )
        if self.polls == 2 and self.on_poll is not None:
            self.on_poll()
        return self.returncode


@pytest.fixture
def tempfile_reads_this_tests_tmpdir(monkeypatch):
    """Keep the sweep of stranded private directories inside the test's own TMPDIR.

    The sweep searches TEMP, TMP and tempfile's own answer beside TMPDIR. A test
    that stays inside ``tmp_path`` sets TMPDIR (and empties the fixed parents), so
    the other two variables are unset and tempfile's cached answer is dropped for
    the test: a cached real temp directory would be searched too, and a stale
    private directory of this user there could be deleted by a test. A test that
    points TMPDIR at a directory that is not there must also give tempfile an
    answer of its own, since a TMPDIR it cannot use makes tempfile fall back to
    the host's /tmp.
    """
    monkeypatch.delenv("TEMP", raising=False)
    monkeypatch.delenv("TMP", raising=False)
    monkeypatch.setattr(tempfile, "tempdir", None)


@pytest.fixture
def runtime_stand_in():
    """The stand-in runtime class, shared by the tests that run the wait loop."""
    return _RuntimeStandIn


@pytest.fixture(autouse=True)
def _host_is_not_root(monkeypatch):
    """Report an ordinary user and group, whoever is running the tests."""
    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
