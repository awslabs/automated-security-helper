# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A url or ref holding a NUL, a control character or a lone surrogate is refused first.

``mcp_set_source_git`` documents that "every refusal is decided before anything is
created or cloned". The checks on ``ref`` read only a leading ``-``, so a ref such as
``release\\x00x`` passed them, the clone ran (git is allowed ten minutes for it), and
only ``subprocess.Popen`` refusing the fetch's argument ended the delivery, as a
failed clone. A lone surrogate in the url took the same road. Neither reaches git
now: the value is refused as ``clone_ref_not_permitted`` or ``clone_url_not_permitted``,
the session's workspace is not made, and git does not run.

The tests go through ``mcp_set_source_git`` (what a client sees) and through
``source_delivery.set_source_git`` (the function the tool calls), once per kind of
character. A url already had NUL, the other C0 controls and white space refused by
``remote_clone_host``; those tests are controls that stay refused. The ``ValueError``
catch in ``_run_git_step`` stays as a backstop for what no check anticipates, and
``test_a_value_error_from_running_git_is_not_a_bad_session_id.py`` keeps it covered.

git is a stand-in run by this interpreter (named in ``_GIT_ARGV``) that records each
step it is started for. Nothing reaches the network.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, Iterator, List

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.sessions import reset_default_registry_for_tests
from automated_security_helper.cli.mcp_tools import mcp_set_source_git

HOST = "git.example.invalid"
URL = f"https://{HOST}/team/repo.git"
SESSION = "session-unprintable"

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

#: One value per kind of character, each placed inside an otherwise plain ref.
REFS = [
    pytest.param("release\x00x", id="nul"),
    pytest.param("release\x01x", id="c0-start-of-heading"),
    pytest.param("release\nx", id="newline"),
    pytest.param("release\tx", id="tab"),
    pytest.param("release\x1bx", id="escape"),
    pytest.param("release\x7fx", id="delete"),
    pytest.param("release\x80x", id="c1-first"),
    pytest.param("release\x85x", id="c1-next-line"),
    pytest.param("release\x9fx", id="c1-last"),
    pytest.param("release" + chr(0xD800) + "x", id="high-surrogate"),
    pytest.param("release" + chr(0xDFFF) + "x", id="low-surrogate"),
    pytest.param("\x00", id="nul-alone"),
]

#: Characters ``remote_clone_host`` did not refuse before: DEL, the C1 controls that are
#: not white space, and a lone surrogate. The delivery got as far as running git.
URLS_NOT_REFUSED_BEFORE = [
    pytest.param(URL + "\x7f", id="delete"),
    pytest.param(URL + "\x80", id="c1-first"),
    pytest.param(URL + "\x9f", id="c1-last"),
    pytest.param(URL + chr(0xD800), id="high-surrogate"),
    pytest.param(URL + chr(0xDFFF), id="low-surrogate"),
    pytest.param(
        "https://" + HOST + "/te" + chr(0xD800) + "am/repo.git", id="mid-path"
    ),
]

#: Refused before this change as well; the tests keep them refused.
URLS_ALREADY_REFUSED = [
    pytest.param(URL + "\x00", id="nul"),
    pytest.param(URL + "\x01", id="c0-start-of-heading"),
    pytest.param(URL + "\n", id="newline"),
    pytest.param(URL + "\t", id="tab"),
    pytest.param(URL + "\x1b", id="escape"),
]


@pytest.fixture
def delivery(tmp_path, monkeypatch) -> Iterator[Dict[str, Any]]:
    """A listed host, a workspace that does not exist yet, and a recording git."""
    workspace = tmp_path / "workspaces"
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("ASH_MCP_GIT_ALLOWED_HOSTS", HOST)
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
    runs: Path = delivery["runs"]
    return runs.read_text(encoding="utf-8").split() if runs.exists() else []


def _nothing_was_started(delivery: Dict[str, Any]) -> None:
    assert _steps_run(delivery) == [], "git ran for a value that had to be refused"
    assert not delivery["workspace"].exists(), "a refused request made a workspace"
    assert sd.get_session_source_dir(SESSION) is None


@pytest.mark.parametrize("ref", REFS)
def test_a_ref_with_an_unprintable_character_is_refused_before_anything_runs(
    delivery, ref
) -> None:
    result = mcp_set_source_git(url=URL, ref=ref, session_id=SESSION)

    assert result.get("success") is False, result
    assert result.get("error_type") == "clone_ref_not_permitted", result
    assert "ref" in result["error"], result
    _nothing_was_started(delivery)


@pytest.mark.parametrize("ref", REFS)
def test_set_source_git_refuses_the_same_ref_before_it_makes_the_session(
    delivery, ref
) -> None:
    with pytest.raises(ValueError, match="ref"):
        sd.set_source_git(url=URL, ref=ref, session_id=SESSION)

    _nothing_was_started(delivery)


@pytest.mark.parametrize("url", URLS_NOT_REFUSED_BEFORE)
def test_a_url_with_an_unprintable_character_is_refused_before_anything_runs(
    delivery, url
) -> None:
    result = mcp_set_source_git(url=url, session_id=SESSION)

    assert result.get("success") is False, result
    assert result.get("error_type") == "clone_url_not_permitted", result
    _nothing_was_started(delivery)


@pytest.mark.parametrize("url", URLS_NOT_REFUSED_BEFORE)
def test_set_source_git_refuses_the_same_url_before_it_makes_the_session(
    delivery, url
) -> None:
    with pytest.raises(ValueError, match="url"):
        sd.set_source_git(url=url, session_id=SESSION)

    _nothing_was_started(delivery)


@pytest.mark.parametrize("url", URLS_ALREADY_REFUSED)
def test_a_url_with_a_nul_or_a_c0_control_stays_refused(delivery, url) -> None:
    """Control: ``remote_clone_host`` refused these before. They stay refused, and
    git does not run for them."""
    result = mcp_set_source_git(url=url, session_id=SESSION)

    assert result.get("success") is False, result
    assert result.get("error_type") == "clone_url_not_permitted", result
    _nothing_was_started(delivery)


def test_the_refusal_does_not_quote_the_value(delivery) -> None:
    """The text names the parameter and the kind of character, not the value, so a
    control character or a surrogate does not reach the client's terminal or log."""
    result = mcp_set_source_git(url=URL, ref="release\x1b[31mx", session_id=SESSION)

    assert result.get("error_type") == "clone_ref_not_permitted", result
    assert "\x1b" not in result["error"], result
    assert "[31m" not in result["error"], result


def test_a_plain_ref_is_still_delivered(delivery) -> None:
    """Control for the stand-in and for the new check: a ref with the characters git
    accepts in a name (a slash, a plus, an at sign, a dot) is cloned and checked out."""
    result = mcp_set_source_git(url=URL, ref="release/v1.0+build@2", session_id=SESSION)

    assert result.get("success") is True, result
    assert _steps_run(delivery) == ["clone", "fetch", "checkout"]
    assert sd.get_session_source_dir(SESSION) is not None


@pytest.mark.parametrize(
    "refused",
    [
        pytest.param({"ref": "release\x00x"}, id="ref-with-a-nul"),
        pytest.param({"url": URL + "\x7f"}, id="url-with-a-delete-character"),
    ],
)
def test_a_refused_value_leaves_the_previous_clone_delivered(delivery, refused) -> None:
    """The refusal comes before anything is created, so a clone that was delivered
    earlier keeps its tree and its record. ``_nothing_was_started`` cannot say so: it
    reads a session that never delivered anything."""
    first = mcp_set_source_git(url=URL, session_id=SESSION)
    assert first["success"] is True, first
    source = Path(first["source_dir"])
    (source / "kept.txt").write_text("kept\n", encoding="utf-8")
    steps_before = _steps_run(delivery)

    result = mcp_set_source_git(**{"url": URL, **refused}, session_id=SESSION)

    assert result.get("success") is False, result
    assert _steps_run(delivery) == steps_before, "git ran for a refused value"
    assert (source / "kept.txt").read_text(encoding="utf-8") == "kept\n"
    assert sd.get_session_source_dir(SESSION) == source
