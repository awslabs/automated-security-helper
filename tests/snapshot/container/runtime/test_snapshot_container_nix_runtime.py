# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ``ash scan --mode nix`` prints and exits with when Nix really runs.

Deselected by default (tests/conftest.py). The Nix legs of ash-install-methods.yml
run it with ``--run-nix-snapshots`` after their own scan, through
.github/actions/validate-nix, so the flake under review supplies the scanner. The
first entry into the shell seeds the grype and rule caches, which that scan has
already done.

The host CLI runs in-process, as tests/snapshot/container/test_snapshot_container_nix.py
does, with ``sys.argv`` set the way a real ``ash`` process would have it, because Nix
mode forwards argv into the shell verbatim. ``nix develop`` is real, and so is the
inner ``ash`` it starts: the one on PATH, which under ``uv run`` is this checkout's.
The inner scan writes to the process's own stdout and stderr, which the in-process
runner does not capture, so the snapshot holds exactly what the outer ASH prints
around it. Only bandit is selected: the flake pins its version, and the fixture's
bandit findings do not depend on the platform.
"""

from __future__ import annotations

import sys

import pytest

pytestmark = [
    pytest.mark.nix_runtime,
    # The host prints "ASH Scan Completed in <duration>" from its own wall clock.
    pytest.mark.snapshot_masking(mask_durations=True),
]


def test_nix_scan_of_the_fixture(run_cli, snapshot, fixture_repo, monkeypatch):
    # The summary prints absolute host paths, whose length is the machine's.
    monkeypatch.setenv("COLUMNS", "1000")
    monkeypatch.delenv("ASH_NIX_FLAKE_REF", raising=False)
    monkeypatch.delenv("ASH_IN_NIX", raising=False)
    args = [
        "scan",
        "--mode",
        "nix",
        "--no-progress",
        "--source-dir",
        "src",
        "--output-dir",
        "out",
        "--scanners",
        "bandit",
    ]
    monkeypatch.setattr(sys, "argv", ["ash", *args])
    assert run_cli(args) == snapshot
