# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``_relocate_colliding_output_dir`` ends when a link folds its step back.

The relocation moves a colliding ``--output-dir`` to ``<given>/.ash/ash_output``
and checks again, because a working directory inside the relocated path still
has it as an ancestor. The check assumed each step lands strictly inside the
previous one, which holds only without symbolic links: a repository can commit
``.ash/ash_output -> ..``, and then ``ash merge --output-dir .`` resolved every
step back to the working directory, the loop never ended, and the path grew by
two components per pass. Repository content hung the merge where it should have
been refused.

The relocation now stops when the resolved step is not strictly deeper than the
previous one and returns the relocated path as it stands; the link is then
``refuse_linked_output_dir``'s to refuse, as it refuses any link at the output
directory.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from automated_security_helper.cli.merge import _relocate_colliding_output_dir

pytestmark = pytest.mark.unit


def _relocate_within(seconds: float, output_dir: Path):
    """The relocation's answer, or None when it has not returned in *seconds*.

    Run on a daemon thread: before the fix the call never returns, and a test
    that waited on it would hang the whole run instead of failing. An exception
    the call raises on the thread is re-raised here, so a crash reads as a
    crash and not as the timeout.
    """
    answer: list = []
    failure: list = []

    def run() -> None:
        try:
            answer.append(_relocate_colliding_output_dir(output_dir))
        except BaseException as exc:  # noqa: BLE001 - re-raised on the test thread
            failure.append(exc)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    if failure:
        raise failure[0]
    return answer[0] if answer else None


def _link_or_skip(link: Path, target: str) -> None:
    """Create the directory link, or skip where this process may not."""
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover
        pytest.skip(f"symlinks are unavailable here: {exc}")


def test_a_link_folding_the_step_back_ends_the_relocation(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / ".ash").mkdir(parents=True)
    _link_or_skip(repo / ".ash" / "ash_output", "..")
    monkeypatch.chdir(repo)

    relocated = _relocate_within(5.0, Path("."))

    assert relocated is not None, "the relocation did not return within 5 s"
    # One step, as the plain case takes; the link at it is the refusal's business.
    assert relocated == Path(".").joinpath(".ash", "ash_output")


def test_a_working_directory_inside_the_relocated_path_still_steps_again(
    tmp_path, monkeypatch
):
    """The control: without a link the loop still takes its second step."""
    collector = tmp_path / "collector"
    inside = collector / ".ash" / "ash_output"
    inside.mkdir(parents=True)
    monkeypatch.chdir(inside)

    relocated = _relocate_within(5.0, Path("..", ".."))

    assert relocated == Path("..", "..").joinpath(
        ".ash", "ash_output", ".ash", "ash_output"
    )
