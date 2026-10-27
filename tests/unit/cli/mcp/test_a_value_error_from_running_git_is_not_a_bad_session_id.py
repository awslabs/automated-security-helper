# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ValueError from running git is a failed clone, not a bad session id.

``mcp_set_source_git`` answered every ``ValueError`` from ``set_source_git`` as
``invalid_session_id``: the url, the ref and the depth had passed their checks,
so the session id was taken to be what was left. Running git can raise one too,
before any process starts: ``subprocess.Popen`` refuses an argument that holds a
NUL character, and on POSIX one the file system encoding cannot write. A client
was then told its session id was wrong when git could not be started for the ref
or the url it gave.

The session id has a refusal of its own: ``set_source_git`` checks it before the
session is taken, and the check raises ``source_delivery.InvalidSessionIdError``,
a ``ValueError``. Only that is ``invalid_session_id``. A ``ValueError`` raised while
a git step is started is answered with that step's own type (``git_clone_failed``
for the clone and the fetch, ``git_checkout_failed`` for the checkout), as an
``OSError`` from starting git is, and a git that is not on PATH is ``git_clone_failed``.
A ``ValueError`` from anywhere else is not a failed clone and is not answered here:
``test_an_unexpected_value_error_from_set_source_git_is_logged.py`` covers it.

Where git would run, it is a stand-in run by this interpreter (named in
``_GIT_ARGV``), or ``_run_git`` is replaced. Nothing reaches the network.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterator, List

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.sessions import reset_default_registry_for_tests
from automated_security_helper.cli.mcp_tools import mcp_set_source_git

URL = "https://git.example.invalid/team/repo.git"
SESSION = "session-giterror"

#: The session ids the workspace cannot be made for: a path, the id of a caller
#: the server could not identify, and none at all.
REFUSED_SESSION_IDS = [
    pytest.param("../escape", id="a-path"),
    pytest.param("__unidentified__", id="unidentified-caller"),
    pytest.param("", id="empty"),
]

_STAND_IN_GIT = """\
import sys
from pathlib import Path

RUNS = Path({runs!r})
argv = sys.argv[1:]
step = next((arg for arg in argv if arg in ("clone", "fetch", "checkout")), None)
with RUNS.open("a", encoding="utf-8") as runs:
    runs.write(str(step) + "\\n")
if step == "clone":
    Path(argv[-1]).mkdir(parents=True, exist_ok=True)
sys.exit(0)
"""


@pytest.fixture
def delivery(tmp_path, monkeypatch) -> Iterator[Dict[str, Any]]:
    """A listed host, a workspace, and a stand-in git that succeeds at every step."""
    workspace = tmp_path / "workspaces"
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.invalid")
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    # The record of a delivered tree is kept per process; each test starts empty.
    monkeypatch.setattr(sd, "_SESSION_SOURCE_DIRS", {})
    reset_default_registry_for_tests()
    script = tmp_path / "stand-in-git.py"
    runs = tmp_path / "runs.txt"
    script.write_text(_STAND_IN_GIT.format(runs=str(runs)), encoding="utf-8")
    monkeypatch.setattr(sd, "_GIT_ARGV", (sys.executable, str(script)))
    yield {"workspace": workspace, "runs": runs}
    reset_default_registry_for_tests()


def _steps_run(delivery: Dict[str, Any]) -> List[str]:
    runs = delivery["runs"]
    return runs.read_text(encoding="utf-8").split() if runs.exists() else []


def _deliver(url: str = URL, **arguments: Any) -> Dict[str, Any]:
    return mcp_set_source_git(url=url, session_id=SESSION, **arguments)


def _source_tree(delivery: Dict[str, Any]) -> Path:
    """Where the session's clone lives while a delivery is in flight or done."""
    return delivery["workspace"] / SESSION / "source"


def _subcommand(cmd: List[str]) -> str:
    return next(part for part in cmd if part in ("clone", "fetch", "checkout"))


@pytest.mark.parametrize("step", ["clone", "fetch", "checkout"])
def test_a_value_error_from_a_git_step_is_a_git_failure(
    delivery, monkeypatch, step
) -> None:
    def run_git(cmd, *, env):
        if _subcommand(cmd) == step:
            raise ValueError("embedded null byte")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(sd, "_run_git", run_git)

    result = _deliver(ref="release")

    assert result.get("success") is False, result
    assert result.get("error_type") != "invalid_session_id", result
    # The step's own type, as the OSError route answers it: the checkout is
    # git_checkout_failed, the clone and the fetch git_clone_failed.
    expected = "git_checkout_failed" if step == "checkout" else "git_clone_failed"
    assert result.get("error_type") == expected, result
    assert "embedded null byte" in result["error"], result
    assert not _source_tree(delivery).exists(), "the failed step left its tree"


def test_a_nul_character_in_the_ref_is_refused_before_git_runs(delivery) -> None:
    """The ref is refused with the other refs git would read as something else, before
    the session's workspace is made: Popen never has to refuse the fetch's argv."""
    result = _deliver(ref="release" + chr(0) + "x")

    assert result.get("success") is False, result
    assert result.get("error_type") == "clone_ref_not_permitted", result
    assert _steps_run(delivery) == []
    assert not _source_tree(delivery).exists(), "a refused ref made a tree"


def test_a_url_the_file_system_encoding_cannot_write_is_refused_before_git_runs(
    delivery,
) -> None:
    """A lone surrogate after the host passes the url checks is refused with the other
    urls git would be started with, before the session's workspace is made. Popen
    could not encode it, so without the check the delivery would have made its
    workspace first and failed at the clone."""
    result = _deliver(url="https://git.example.invalid/team/repo" + chr(0xD800))

    assert result.get("success") is False, result
    assert result.get("error_type") == "clone_url_not_permitted", result
    assert _steps_run(delivery) == []
    assert not _source_tree(delivery).exists(), "a refused url made a tree"


def test_a_second_delivery_git_cannot_run_for_leaves_the_first_tree_to_scan(
    delivery, monkeypatch
) -> None:
    """The first delivery is kept, not replaced: the second one is cloned beside it,
    so when it fails the session still resolves to the tree it delivered, and nothing
    of the failed clone is left beside it.

    The second delivery fails at the fetch, where git cannot be started for the ref
    (the backstop in ``_run_git_step``; a ref that cannot be passed to git is
    refused before this point, and ``test_set_source_git_refuses_unprintable_url_and_ref_up_front.py``
    covers that)."""
    first = _deliver(ref="release")
    assert first.get("success") is True, first

    real_run_git = sd._run_git

    def run_git(cmd, *, env):
        if _subcommand(cmd) == "fetch":
            raise ValueError("embedded null byte")
        return real_run_git(cmd, env=env)

    monkeypatch.setattr(sd, "_run_git", run_git)

    result = _deliver(ref="release")

    assert result.get("success") is False, result
    assert result.get("error_type") == "git_clone_failed", result
    assert _source_tree(delivery).is_dir(), "the failed delivery took the first tree"
    assert sd.get_session_source_dir(SESSION) == _source_tree(delivery)
    session_dir = _source_tree(delivery).parent
    left = [p.name for p in session_dir.iterdir() if p.name.startswith(".source.")]
    assert left == [], f"the failed delivery left {left} beside source/"


@pytest.mark.parametrize("session_id", REFUSED_SESSION_IDS)
def test_a_session_id_the_workspace_cannot_be_made_for_is_still_invalid_session_id(
    delivery, session_id
) -> None:
    result = mcp_set_source_git(url=URL, ref="release", session_id=session_id)

    assert result.get("success") is False, result
    assert result.get("error_type") == "invalid_session_id", result
    assert _steps_run(delivery) == [], "git ran for a session id that was refused"


@pytest.mark.parametrize("session_id", REFUSED_SESSION_IDS)
def test_set_source_git_refuses_the_session_id_with_its_own_error(
    delivery, session_id
) -> None:
    """Raised before the session is taken, so nothing is created for it."""
    with pytest.raises(sd.InvalidSessionIdError) as refused:
        sd.set_source_git(url=URL, session_id=session_id)

    assert isinstance(refused.value, ValueError)
    assert _steps_run(delivery) == []
    assert not delivery["workspace"].exists(), "a refused session id made a workspace"


def test_a_runtime_error_from_set_source_git_is_still_a_failed_clone(
    delivery, monkeypatch
) -> None:
    """The control for the other arms: what set_source_git documents for a git
    that is not on PATH keeps its answer."""

    def no_git(**_arguments):
        raise RuntimeError(
            "git was not found on PATH, so the repository cannot be cloned"
        )

    monkeypatch.setattr(sd, "set_source_git", no_git)

    result = _deliver()

    assert result.get("error_type") == "git_clone_failed", result
    assert "git was not found on PATH" in result["error"], result


def test_a_delivery_git_can_run_for_is_delivered(delivery) -> None:
    """The control for the stand-in: nothing raised, the tree is delivered."""
    result = _deliver(ref="release")

    assert result.get("success") is True, result
    assert _steps_run(delivery) == ["clone", "fetch", "checkout"]
    assert sd.get_session_source_dir(SESSION) is not None
