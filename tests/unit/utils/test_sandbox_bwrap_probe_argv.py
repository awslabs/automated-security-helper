# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every bwrap probe runs the sandbox's own ``true``, found by path, never by name.

bwrap resolves a bare command name through the PATH it is given, and the probe runs
with the operator's PATH. A PATH entry that is empty or ``.`` answers from the working
directory, which is usually the tree being scanned, so a bare ``true`` could start a
program from that tree, outside the Unix-socket filter the other probe applies. The
module already has ``_true()`` for this: it looks the program up through the sandbox's
own anchored-path lookup. These tests stand in for bwrap with a recording
``_probe_run`` and assert that every probe argv carries that path and no bare name.
"""

import tempfile
from typing import List, Optional, Sequence

import pytest

from automated_security_helper.utils.sandbox import backends
from automated_security_helper.utils.sandbox.backends import BwrapBackend
from tests.utils.fake_tool_paths import fake_tool_path

pytestmark = pytest.mark.unit

#: Where the fake host keeps the programs the probe looks up. Nothing is created or
#: started at these paths; only their spelling matters (see fake_tool_paths).
FAKE_PROGRAMS = {
    "bwrap": fake_tool_path("/usr/bin/bwrap"),
    "true": fake_tool_path("/usr/bin/true"),
}


def _probe_argvs(monkeypatch, tmp_path, programs=None) -> List[List[str]]:
    """Run BwrapBackend._probe with a bwrap that always succeeds; return every argv.

    ``programs`` is what the fake host's lookup finds (FAKE_PROGRAMS by default); a
    name it does not hold is not found."""
    recorded: List[List[str]] = []
    found = FAKE_PROGRAMS if programs is None else programs

    def fake_probe_run(argv: Sequence[str], env=None) -> Optional[str]:
        recorded.append(list(argv))
        return None

    monkeypatch.setattr(backends, "_probe_run", fake_probe_run)
    monkeypatch.setattr(backends, "_sandbox_program", lambda name: found.get(name))
    # The overlay probe makes a throwaway directory; keep it under tmp_path.
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    backend = BwrapBackend()
    assert backend._probe() is None
    return recorded


def test_the_probe_runs_three_commands(monkeypatch, tmp_path):
    argvs = _probe_argvs(monkeypatch, tmp_path)
    assert len(argvs) == 3
    assert all(argv[0] == FAKE_PROGRAMS["bwrap"] for argv in argvs)


def test_no_probe_argv_carries_a_bare_true(monkeypatch, tmp_path):
    # At the base the first and the overlay probe ended in the literal "true".
    for argv in _probe_argvs(monkeypatch, tmp_path):
        assert "true" not in argv, argv


def test_every_probe_argv_carries_the_shared_helpers_path(monkeypatch, tmp_path):
    for argv in _probe_argvs(monkeypatch, tmp_path):
        assert FAKE_PROGRAMS["true"] in argv, argv


def test_a_lookup_that_finds_no_true_falls_back_to_an_absolute_path(
    monkeypatch, tmp_path
):
    """The sandbox's lookup finds no ``true`` (an unusual PATH): every probe still
    ends in an absolute path, ``/bin/true``, and never the bare name."""
    argvs = _probe_argvs(monkeypatch, tmp_path, {"bwrap": FAKE_PROGRAMS["bwrap"]})

    assert len(argvs) == 3
    for argv in argvs:
        assert "true" not in argv, argv
        assert argv[-1] == "/bin/true", argv


def test_the_plain_and_overlay_probes_end_in_the_helpers_path(monkeypatch, tmp_path):
    plain, _filtered, overlay = _probe_argvs(monkeypatch, tmp_path)
    assert plain[-1] == FAKE_PROGRAMS["true"]
    assert overlay[-1] == FAKE_PROGRAMS["true"]
    assert overlay[-5] == "--overlay-src"
    assert overlay[-3] == "--tmp-overlay"
    assert overlay[-4] == overlay[-2]
