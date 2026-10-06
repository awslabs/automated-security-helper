# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How container mode turns the container's exit status into ASH's own.

The container runs this same CLI, so 0, 1 and 2 are verdicts it reached from a
results file, and the host recomputes its verdict from that file. Every other
status means the scan did not finish, and the host exits with it unchanged. Each
case here is one status the fake runner returns, with or without a results file
left in the mounted output directory; what the host then prints and exits with is
ASH's real behavior.
"""

from __future__ import annotations

import pytest

from tests.snapshot.container.conftest import FakeStep

SCAN = [
    "scan",
    "--mode",
    "container",
    "--no-build",
    "--no-progress",
    "--source-dir",
    "src",
    "--output-dir",
    "out",
]

#: The host prints "ASH Scan Completed in <duration>" from its own wall clock.
pytestmark = pytest.mark.snapshot_masking(mask_durations=True)


@pytest.fixture(autouse=True)
def _src(in_tmp, local_checkout, monkeypatch):
    (in_tmp / "src").mkdir()
    # The summary prints the absolute output directory, whose length is the
    # machine's, so at 100 columns rich would fold each path at a different place.
    # tests/snapshot/console pins that layout at a fixed width; here it is unfolded.
    monkeypatch.setenv("COLUMNS", "1000")


@pytest.fixture
def results_json(fixture_model) -> str:
    """The canonical fixture scan, as the container would leave it in ``/out``."""
    return fixture_model.model_dump_json()


@pytest.mark.parametrize("returncode", [0, 1, 2])
def test_verdict_status_with_results(
    returncode, run_cli, snapshot, fake_docker, results_json
):
    # Whatever the container said, the host's exit code comes from the results.
    fake_docker.run = FakeStep(returncode=returncode, results_json=results_json)
    assert run_cli(SCAN) == snapshot
    assert fake_docker.calls == ["run"]


def test_success_status_without_results(run_cli, snapshot, fake_docker):
    fake_docker.run = FakeStep(returncode=0, stdout="container wrote nothing\n")
    assert run_cli(SCAN) == snapshot


def test_unparseable_results(run_cli, snapshot, fake_docker):
    fake_docker.run = FakeStep(returncode=0, results_json="{not json")
    assert run_cli(SCAN) == snapshot


@pytest.mark.parametrize(
    "returncode",
    [
        pytest.param(3, id="3-invalid-config"),
        pytest.param(4, id="4-workspace-error"),
        pytest.param(125, id="125-runner-failed-before-entrypoint"),
        pytest.param(137, id="137-killed"),
    ],
)
def test_non_verdict_status(returncode, run_cli, snapshot, fake_docker, results_json):
    # A results file is left behind on purpose: a non-verdict status must not be
    # turned into a verdict by reading it.
    fake_docker.run = FakeStep(
        returncode=returncode,
        stderr=f"container exited with {returncode}\n",
        results_json=results_json,
    )
    assert run_cli(SCAN) == snapshot


def test_host_recomputes_the_verdict(run_cli, snapshot, fake_docker, results_json):
    # The container said 0, but the host applies its own options to the results it
    # reads back: with the incomplete-scanner gate off, the fixture's actionable
    # findings make it 2.
    fake_docker.run = FakeStep(returncode=0, results_json=results_json)
    assert run_cli([*SCAN, "--no-fail-on-incomplete-scanners"]) == snapshot
