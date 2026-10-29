"""The sandbox docs state which link targets each backend hides, and the hard-link limit.

tests/integration/sandbox/test_sandbox_escape.py scores bwrap and Landlock on reading
a link committed in the tree to a file outside the read list, inside $HOME and
outside it. Under firejail and sandbox-exec, whether the file outside $HOME is hidden
depends on where it is, so that integration test does not score it there; the limit
is pinned here instead, in the page operators read.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

PAGE = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "content"
    / "docs"
    / "scanner-sandbox.md"
)


def _words() -> str:
    return " ".join(PAGE.read_text(encoding="utf-8").split())


def test_sandbox_docs_state_the_link_target_limits():
    words = _words()

    assert (
        "Under bwrap and Landlock a link to a file outside the read list, in `$HOME` "
        "or anywhere else, cannot be read." in words
    )
    assert "firejail shows everything outside `$HOME` and `/tmp`" in words
    assert (
        "sandbox-exec reads everywhere except `$HOME` and the shared temporary "
        "directories" in words
    )
    # The backend sections the summary repeats.
    assert "Paths outside `$HOME` that your user can read remain readable" in words
    assert (
        "read everywhere except the home directory and the shared temporary "
        "directories" in words
    )


def test_sandbox_docs_state_the_hard_link_limit():
    words = _words()

    assert "nothing tells it apart from an ordinary file" in words
    assert "ASH does not try to detect one" in words
    assert "What contains a scanner that reads one is the sandbox" in words
