# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""git output that is not valid text is decided by git's exit status.

``source_delivery._run_git`` reads git's stdout and stderr as text. A clone, a
fetch or a checkout can write bytes that are not valid in that encoding: a path
written in another encoding, a remote's message. Decoded strictly, they raise
``UnicodeDecodeError``, a ``ValueError``, before git's exit status is read, and
``mcp_set_source_git`` answered it as ``invalid_session_id``, with the clone left
on disk. Decoded so that no byte raises, git's exit status decides, as it does for
any other output:

- a clone or a checkout that git fails is ``git_clone_failed`` or
  ``git_checkout_failed``, with git's message in ``error`` and the tree removed;
- a fetch that git fails is tolerated, as before, and the checkout of the ref
  decides;
- a step that git completes delivers, whatever it wrote.

A byte that cannot be decoded is written as its ``\\xNN`` escape, so the message
keeps it. The bytes used here are invalid as UTF-8 and undefined in Windows code
page 1252, so they cannot be decoded on either. git's output is read in the
locale's encoding, so the escape is expected only where that encoding is UTF-8
(``_keeps_the_bytes``): in a Latin-1 locale every byte decodes, and in a Japanese
Windows locale some of these bytes pair into characters. The other checks do not
depend on the locale.

A failed clone has put part of a tree on disk before git exits, so the stand-in
writes a file into the clone target whatever its status is, and the tests check
that nothing of it stays beside ``source/``.

git is a stand-in run by this interpreter, named in ``_GIT_ARGV`` as
``test_set_source_git_times_out.py`` names its own: for each subcommand it writes
the bytes the test gives it and exits with the test's status. Nothing reaches the
network.
"""

from __future__ import annotations

import codecs
import json
import locale
import sys
from pathlib import Path
from typing import Any, Dict, Iterator, List

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.sessions import reset_default_registry_for_tests
from automated_security_helper.cli.mcp_tools import mcp_set_source_git

URL = "https://git.example.invalid/team/repo.git"
SESSION = "session-gitdecode"

#: Invalid as UTF-8 (each is a continuation byte with no lead byte) and undefined
#: in code page 1252.
NOT_UTF8 = b"\x81\x8d\x8f\x90\x9d"
#: How the delivery writes NOT_UTF8 in a message in a UTF-8 locale.
ESCAPED = "\\x81\\x8d\\x8f\\x90\\x9d"


def _keeps_the_bytes(result: Dict[str, Any]) -> None:
    """The message keeps the undecodable bytes as their escapes, where the locale's
    encoding is UTF-8, which is the encoding they are invalid in."""
    if codecs.lookup(locale.getpreferredencoding(False)).name == "utf-8":
        assert ESCAPED in result["error"], result


_STAND_IN_GIT = """\
import json
import sys
from pathlib import Path

RUNS = Path({runs!r})
BEHAVIOR = {behavior!r}
argv = sys.argv[1:]
step = next((arg for arg in argv if arg in ("clone", "fetch", "checkout")), None)
with RUNS.open("a", encoding="utf-8") as runs:
    runs.write(json.dumps([step, argv[-1]]) + "\\n")
status, out, err = BEHAVIOR.get(step, (0, b"", b""))
if step == "clone":
    # Whatever the status, a clone has written part of a tree when it exits.
    Path(argv[-1]).mkdir(parents=True, exist_ok=True)
    (Path(argv[-1]) / "a.py").write_text("a = 1\\n", encoding="utf-8")
sys.stdout.buffer.write(out)
sys.stderr.buffer.write(err)
sys.stdout.flush()
sys.stderr.flush()
sys.exit(status)
"""


@pytest.fixture
def stand_in_git(tmp_path, monkeypatch) -> Iterator[Dict[str, Any]]:
    """A git that writes, per subcommand, what ``install`` is given."""
    workspace = tmp_path / "workspaces"
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", "git.example.invalid")
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    # The record of a delivered tree is kept per process; each test starts empty.
    monkeypatch.setattr(sd, "_SESSION_SOURCE_DIRS", {})
    reset_default_registry_for_tests()
    script = tmp_path / "stand-in-git.py"
    runs = tmp_path / "runs.jsonl"

    def install(**behavior: Any) -> None:
        script.write_text(
            _STAND_IN_GIT.format(runs=str(runs), behavior=behavior), encoding="utf-8"
        )
        monkeypatch.setattr(sd, "_GIT_ARGV", (sys.executable, str(script)))

    yield {"install": install, "source": workspace / SESSION / "source", "runs": runs}
    reset_default_registry_for_tests()


def _ran(git: Dict[str, Any]) -> List[List[str]]:
    """Each subcommand the stand-in ran, with its last argument."""
    if not git["runs"].exists():
        return []
    return [
        json.loads(line)
        for line in git["runs"].read_text(encoding="utf-8").splitlines()
    ]


def _deliver(**arguments: Any) -> Dict[str, Any]:
    return mcp_set_source_git(url=URL, session_id=SESSION, **arguments)


def _nothing_of_the_clone_is_left(git: Dict[str, Any], what: str) -> None:
    """Neither ``source/`` nor a staging directory beside it holds the failed clone.
    The stand-in writes a file into the clone target before it exits, so the second
    check reads a delete that really had something to remove."""
    assert not git["source"].exists(), f"{what} left its tree"
    left = [
        p.name for p in git["source"].parent.iterdir() if p.name.startswith(".source.")
    ]
    assert left == [], f"{what} left {left} beside source/"


def test_a_clone_git_fails_with_output_that_is_not_utf8_is_a_failed_clone(
    stand_in_git,
) -> None:
    stand_in_git["install"](
        clone=(128, b"", b"fatal: unable to read '" + NOT_UTF8 + b"': no such file\n")
    )

    result = _deliver()

    assert result.get("success") is False, result
    assert result.get("error_type") == "git_clone_failed", result
    assert "git clone failed (exit 128)" in result["error"], result
    assert "fatal: unable to read" in result["error"], result
    _keeps_the_bytes(result)
    _nothing_of_the_clone_is_left(stand_in_git, "the failed clone")
    assert sd.get_session_source_dir(SESSION) is None


def test_a_fetch_git_fails_with_output_that_is_not_utf8_is_still_tolerated(
    stand_in_git,
) -> None:
    stand_in_git["install"](
        fetch=(128, b"", b"fatal: couldn't find remote ref " + NOT_UTF8 + b"\n")
    )

    result = _deliver(ref="release")

    assert result.get("success") is True, result
    ran = _ran(stand_in_git)
    assert [step for step, _last in ran] == ["clone", "fetch", "checkout"], ran
    # The fetch failed, so the checkout looks for the ref in the clone itself.
    assert ran[2][1] == "release", ran
    assert Path(result["source_dir"]) == stand_in_git["source"]
    assert sd.get_session_source_dir(SESSION) == stand_in_git["source"]


def test_a_checkout_git_fails_with_output_that_is_not_utf8_is_a_failed_checkout(
    stand_in_git,
) -> None:
    stand_in_git["install"](
        checkout=(1, b"", b"error: pathspec '" + NOT_UTF8 + b"' did not match\n")
    )

    result = _deliver(ref="release")

    assert result.get("success") is False, result
    assert result.get("error_type") == "git_checkout_failed", result
    assert "git checkout 'release' failed (exit 1)" in result["error"], result
    assert "did not match" in result["error"], result
    _keeps_the_bytes(result)
    _nothing_of_the_clone_is_left(stand_in_git, "the failed checkout")
    assert sd.get_session_source_dir(SESSION) is None


@pytest.mark.parametrize("step", ["clone", "fetch", "checkout"])
def test_a_step_git_completes_with_output_that_is_not_utf8_delivers(
    stand_in_git, step
) -> None:
    """git's exit status decides, so output that cannot be read as text changes
    nothing for a step that succeeded."""
    stand_in_git["install"](
        **{
            step: (
                0,
                b"wrote " + NOT_UTF8 + b"\n",
                b"remote: " + NOT_UTF8 + b"\n",
            )
        }
    )

    result = _deliver(ref="release")

    assert result.get("success") is True, result
    ran = _ran(stand_in_git)
    assert [name for name, _last in ran] == ["clone", "fetch", "checkout"], ran
    # The fetch succeeded, so the checkout takes what it fetched.
    assert ran[2][1] == "FETCH_HEAD", ran
    assert sd.get_session_source_dir(SESSION) == stand_in_git["source"]


def test_a_clone_git_fails_with_a_utf8_message_is_unchanged(stand_in_git) -> None:
    """The control: output that decodes was reported this way before the change."""
    stand_in_git["install"](clone=(128, b"", b"fatal: repository not found\n"))

    result = _deliver()

    assert result.get("error_type") == "git_clone_failed", result
    assert (
        "git clone failed (exit 128): fatal: repository not found" in result["error"]
    ), result
    _nothing_of_the_clone_is_left(stand_in_git, "the failed clone")


def test_a_session_id_the_workspace_cannot_be_made_for_is_still_refused(
    stand_in_git,
) -> None:
    """The control for the session id: refused before git starts, as before."""
    stand_in_git["install"]()

    result = mcp_set_source_git(url=URL, session_id="../escape")

    assert result.get("error_type") == "invalid_session_id", result
    assert _ran(stand_in_git) == [], "git ran for a session id that was refused"
