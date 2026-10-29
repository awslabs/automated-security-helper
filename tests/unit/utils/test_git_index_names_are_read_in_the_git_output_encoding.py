# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``git_index_below`` reads the names git lists in ``GIT_OUTPUT_ENCODING``.

It decoded git's output with ``os.fsdecode``. Under
``PYTHONLEGACYWINDOWSFSENCODING=1`` that is ``mbcs``, a code page, although git for
Windows prints UTF-8, so a committed file with a non-ASCII name was read back
mangled and left the scan set. The names now go through ``decode_git_output``
(``utils/git_command.py``), the decode every other read of git's output uses: the
git output encoding with ``surrogateescape``, so a byte that does not decode is
kept as a surrogate, as Python keeps it in a file name, and the call does not
fail.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.utils import git_command, subprocess_utils
from automated_security_helper.utils.scan_output_dirs import git_index_below

# Built with chr() so the source file stays ASCII.
CAFE = f"caf{chr(0xE9)}.py"


def _listing(monkeypatch: pytest.MonkeyPatch, tmp_path, stdout: bytes):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    monkeypatch.setattr(
        subprocess_utils,
        "spawn_run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=stdout, stderr=b""
        ),
    )
    return git_index_below(repo)


def test_a_utf8_name_is_read_whatever_the_filesystem_encoding(monkeypatch, tmp_path):
    monkeypatch.setattr(git_command, "GIT_OUTPUT_ENCODING", "utf-8")

    answer = _listing(monkeypatch, tmp_path, CAFE.encode("utf-8") + b"\0plain.py\0")

    assert answer.error is None
    assert answer.names == [CAFE, "plain.py"]


def test_a_name_in_the_output_encoding_is_read_in_it(monkeypatch, tmp_path):
    monkeypatch.setattr(git_command, "GIT_OUTPUT_ENCODING", "iso-8859-1")

    answer = _listing(monkeypatch, tmp_path, CAFE.encode("iso-8859-1") + b"\0")

    assert answer.error is None
    assert answer.names == [CAFE]


def test_a_byte_that_does_not_decode_is_kept_and_the_call_does_not_fail(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(git_command, "GIT_OUTPUT_ENCODING", "utf-8")

    answer = _listing(monkeypatch, tmp_path, b"w\xff.py\0ok.py\0")

    assert answer.error is None
    assert answer.names == ["w" + chr(0xDC00 + 0xFF) + ".py", "ok.py"]
