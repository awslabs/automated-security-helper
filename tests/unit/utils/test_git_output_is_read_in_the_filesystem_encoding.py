# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The git lookups in ``get_scan_set`` read git's output as Python reads a file name.

git prints a path as the bytes of its name, and on Windows always in UTF-8. Each
lookup captures the bytes and hands them to ``_git_text``, which decodes them with
``_git_output_codec`` (git's stderr, which is only quoted in a message, goes
through ``_git_message_text`` instead, with the same encoding and a handler that
never raises). That is the host's filesystem encoding on POSIX, the
encoding ``os.walk`` decodes names with, which a legacy locale makes ISO-8859-1 or
EUC-JP (UTF-8 there would not match the names on disk). On Windows it is UTF-8
whatever ``sys.getfilesystemencoding()`` says: ``PYTHONLEGACYWINDOWSFSENCODING=1``
(the PEP 529 opt-out) makes that ``mbcs``, a code page, and a changed file named
``caf`` plus U+00E9 then came back spelled with two other characters, matched no
file, and the findings in it were dropped.

Measured without git: ``subprocess.run`` in the module is replaced by a stand-in
that answers each lookup with the bytes git would have printed. The platform and
the filesystem encoding are patched for the cells that need another host's.
Nothing is created on disk.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

import pytest

from automated_security_helper.utils import get_scan_set

pytestmark = pytest.mark.unit

# Built with chr() so the source file stays ASCII.
NAME = f"caf{chr(0xE9)}"
#: What git for Windows prints for NAME, and git on a UTF-8 host.
RAW = NAME.encode("utf-8")

#: The repository root git prints, absolute on the platform the test runs on. A
#: rootless ``/repo`` is not absolute on Windows from Python 3.13 (``ntpath.isabs``
#: wants a drive), and ``_rev_parse_toplevel`` refuses a root that is not absolute.
REPO = Path(os.path.abspath(os.sep + "repo"))
#: How git prints it, as the platform spells a path name.
REPO_RAW = os.fsencode(str(REPO)) + os.fsencode(os.sep)


class _GitStandIn:
    """``subprocess.run`` for one git lookup: git printed ``stdout`` and ``stderr``
    and exited with ``returncode`` (0 unless the cell says otherwise)."""

    def __init__(
        self, stdout: bytes, *, returncode: int = 0, stderr: bytes = b""
    ) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr
        self.calls: List[Tuple[List[str], Dict[str, Any]]] = []

    def __call__(self, argv: Any, **kwargs: Any) -> "subprocess.CompletedProcess[Any]":
        self.calls.append((list(argv), kwargs))
        return subprocess.CompletedProcess(
            list(argv), self.returncode, stdout=self.stdout, stderr=self.stderr
        )


def _run(
    monkeypatch,
    stdout: bytes,
    lookup: Callable[[], Any],
    *,
    returncode: int = 0,
    stderr: bytes = b"",
) -> Tuple[Any, _GitStandIn]:
    git = _GitStandIn(stdout, returncode=returncode, stderr=stderr)
    monkeypatch.setattr(get_scan_set.subprocess, "run", git)
    # The lookups that resolve git themselves find a program; none is started.
    monkeypatch.setattr(get_scan_set, "_git_executable", lambda: "git")
    return lookup(), git


#: Each lookup: what git printed, the call, and what the lookup must return.
LOOKUPS: Dict[str, Tuple[bytes, Callable[[Path], Any], Callable[[], Any]]] = {
    "rev-parse --show-toplevel": (
        REPO_RAW + RAW + b"\n",
        lambda cwd: get_scan_set._rev_parse_toplevel(cwd, values=()),
        lambda: (Path(REPO / NAME).resolve(), None),
    ),
    "rev-parse --git-common-dir": (
        REPO_RAW + RAW + os.fsencode(os.sep) + b".git\n",
        get_scan_set.git_common_dir,
        lambda: Path(REPO / NAME / ".git").resolve(),
    ),
    "rev-parse --absolute-git-dir": (
        REPO_RAW + RAW + os.fsencode(os.sep) + b".git\n",
        get_scan_set.git_absolute_git_dir,
        lambda: Path(REPO / NAME / ".git").resolve(),
    ),
    "worktree list": (
        b"worktree " + REPO_RAW + RAW + b"\0HEAD " + b"0" * 40 + b"\0\0",
        get_scan_set.git_worktree_paths,
        lambda: {Path(REPO / NAME)},
    ),
    "ls-files": (
        b"src/" + RAW + b".py\0",
        lambda cwd: get_scan_set.git_index_paths_below(cwd, "src"),
        lambda: [f"src/{NAME}.py"],
    ),
    "ls-files --others": (
        b"src/" + RAW + b"/\0",
        lambda cwd: get_scan_set.git_untracked_paths_below(cwd, "src"),
        lambda: [f"src/{NAME}/"],
    ),
    "diff --name-only": (
        RAW + b".py\0",
        lambda cwd: get_scan_set.get_changed_files("main", cwd=cwd),
        lambda: [Path(f"{NAME}.py")],
    ),
}


def _decoding_as_the_code_page_does(code_page: str) -> Callable[[Any], str]:
    """``os.fsdecode`` as Windows has it under the legacy opt-in: with a code page."""

    def fsdecode(name: Any) -> str:
        return name.decode(code_page) if isinstance(name, bytes) else os.fspath(name)

    return fsdecode


@pytest.mark.parametrize(
    ("filesystem_encoding", "code_page"), [("utf-8", "utf-8"), ("mbcs", "cp1252")]
)
def test_git_output_is_read_as_utf8_on_windows_whatever_the_filesystem_encoding(
    monkeypatch, filesystem_encoding, code_page
):
    """git for Windows prints UTF-8. ``PYTHONLEGACYWINDOWSFSENCODING=1`` makes the
    filesystem encoding ``mbcs``, a code page, so the codec must not follow it there.

    ``os.fsdecode`` is replaced by what it does under each setting; reading the
    bytes through it spells NAME wrong under the code page.
    """
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "getfilesystemencoding", lambda: filesystem_encoding)
    monkeypatch.setattr(os, "fsdecode", _decoding_as_the_code_page_does(code_page))

    encoding, _errors = get_scan_set._git_output_codec()
    text = get_scan_set._git_text(RAW)

    assert encoding == "utf-8"
    assert text == NAME


def test_output_that_is_not_utf8_raises_on_windows(monkeypatch):
    """The Windows codec is strict, as ``os.fsdecode`` was there: a byte that is not
    UTF-8 is not kept. The listing lookups answer None for it (the cell below)."""
    monkeypatch.setattr(sys, "platform", "win32")

    with pytest.raises(UnicodeDecodeError):
        get_scan_set._git_text(NAME.encode("iso-8859-1"))


#: The lookups that decode inside their ``try`` and answer None for output that is
#: not UTF-8 (``_rev_parse_toplevel`` and ``get_changed_files`` do not catch it).
ANSWERS_NONE_FOR_UNDECODABLE = (
    "rev-parse --git-common-dir",
    "rev-parse --absolute-git-dir",
    "worktree list",
    "ls-files",
    "ls-files --others",
)


@pytest.mark.parametrize("lookup", ANSWERS_NONE_FOR_UNDECODABLE)
def test_a_lookup_whose_output_is_not_utf8_answers_none_under_the_windows_codec(
    monkeypatch, tmp_path, lookup
):
    monkeypatch.setattr(
        get_scan_set, "_git_output_codec", lambda: ("utf-8", "surrogatepass")
    )
    stdout, call, _expected = LOOKUPS[lookup]
    stdout = stdout.replace(RAW, NAME.encode("iso-8859-1"))

    answer, git = _run(monkeypatch, stdout, lambda: call(tmp_path))

    assert len(git.calls) == 1, git.calls
    assert answer is None, answer


def test_a_failed_toplevel_lookup_quotes_stderr_that_is_not_utf8_without_raising(
    monkeypatch, tmp_path
):
    """git's message is quoted, not matched against a file name, so a byte in it that
    is not UTF-8 must not raise out of the root lookup. Under
    ``PYTHONLEGACYWINDOWSFSENCODING=1`` the old decode used a code page with the
    ``replace`` handler and could not fail."""
    monkeypatch.setattr(
        get_scan_set, "_git_output_codec", lambda: ("utf-8", "surrogatepass")
    )
    stderr = b"fatal: " + NAME.encode("iso-8859-1") + b": not a git repository\n"

    answer, git = _run(
        monkeypatch,
        b"",
        lambda: get_scan_set._rev_parse_toplevel(tmp_path, values=()),
        returncode=128,
        stderr=stderr,
    )

    root, problem = answer
    assert len(git.calls) == 1, git.calls
    assert root is None
    assert problem is not None and "is not inside a git repository" in problem


@pytest.mark.parametrize(
    ("codec", "expected"),
    [
        (("utf-8", "surrogateescape"), f"fatal: caf{chr(0xDCE9)}"),
        (("utf-8", "surrogatepass"), f"fatal: caf{chr(0xFFFD)}"),
        (("utf-8", "strict"), f"fatal: caf{chr(0xFFFD)}"),
    ],
    ids=["posix-handler-kept", "windows-handler-replaced", "strict-replaced"],
)
def test_a_message_keeps_the_codecs_handler_unless_it_would_raise(
    monkeypatch, codec, expected
):
    """On POSIX a byte that is not UTF-8 stays a surrogate, so a redaction that looks
    for a value holding that byte still finds it; where the handler would raise,
    the byte becomes a replacement character."""
    monkeypatch.setattr(get_scan_set, "_git_output_codec", lambda: codec)

    assert get_scan_set._git_message_text(b"fatal: caf\xe9") == expected
    assert get_scan_set._git_message_text("already text") == "already text"


def test_a_str_is_returned_as_it_is():
    """``_git_path_line`` is handed text by callers that substitute the lookup."""
    assert get_scan_set._git_text(NAME) == NAME


def test_git_output_is_read_in_the_filesystem_encoding_of_a_legacy_locale(
    monkeypatch,
):
    """A POSIX host whose filesystem encoding is ISO-8859-1 names the file with the
    byte 0xE9; Python reads that file name so, and git's output is read the same."""
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(sys, "getfilesystemencoding", lambda: "iso-8859-1")
    monkeypatch.setattr(sys, "getfilesystemencodeerrors", lambda: "surrogateescape")

    assert get_scan_set._git_output_codec() == ("iso-8859-1", "surrogateescape")
    assert get_scan_set._git_text(NAME.encode("iso-8859-1")) == NAME


@pytest.mark.skipif(
    sys.platform == "win32", reason="Windows reads git's output as UTF-8, not as a name"
)
@pytest.mark.parametrize("output", [b"plain.py", RAW + b".py", b"caf\xe9.py", b"\xff"])
def test_on_posix_git_output_is_read_as_os_fsdecode_reads_a_name(output):
    """Control: where the codec is the filesystem's own, nothing changes for a name
    that is UTF-8 and nothing for one that is not (kept as surrogates)."""
    assert get_scan_set._git_text(output) == os.fsdecode(output)


def test_the_fixture_repository_root_is_absolute_on_this_platform():
    """Control for the platform pair (POSIX; Windows on Python 3.13 and later).

    ``_rev_parse_toplevel`` answers only a root that ``os.path.isabs`` accepts, so a
    fixture root spelled ``/repo`` reads as no root on Windows from 3.13, where a
    path with no drive is not absolute. The root built here is absolute wherever
    the test runs, and the lookup returns it.
    """
    assert os.path.isabs(str(REPO)), REPO
    assert os.path.isabs(os.fsdecode(REPO_RAW)), REPO_RAW


@pytest.mark.parametrize("lookup", sorted(LOOKUPS))
def test_a_non_ascii_name_git_prints_is_read_as_its_name(monkeypatch, tmp_path, lookup):
    stdout, call, expected = LOOKUPS[lookup]
    encoding, _errors = get_scan_set._git_output_codec()
    # git's bytes for the name in the encoding the lookup reads them in.
    try:
        in_lookup_encoding = NAME.encode(encoding)
    except UnicodeEncodeError:
        pytest.skip(
            f"{NAME!r} has no spelling in {encoding}, the filesystem encoding of "
            "this host"
        )
    stdout = stdout.replace(RAW, in_lookup_encoding)

    answer, git = _run(monkeypatch, stdout, lambda: call(tmp_path))

    assert len(git.calls) == 1, git.calls
    assert answer == expected(), answer


@pytest.mark.parametrize("lookup", sorted(LOOKUPS))
def test_every_lookup_captures_bytes_and_decodes_them_itself(
    monkeypatch, tmp_path, lookup
):
    """No lookup asks ``subprocess`` for text, whose decoding would use the locale's
    encoding (a code page such as cp1252 on Windows) instead of the codec."""
    stdout, call, _expected = LOOKUPS[lookup]

    _answer, git = _run(monkeypatch, stdout, lambda: call(tmp_path))

    (_argv, kwargs) = git.calls[0]
    assert not kwargs.get("text"), kwargs
    assert not kwargs.get("universal_newlines"), kwargs
    assert not kwargs.get("encoding"), kwargs
    assert not kwargs.get("errors"), kwargs


#: Lookups whose answer is a plain name, so the same cell runs on every platform.
LEGACY_LOOKUPS = (
    "ls-files",
    "ls-files --others",
    "diff --name-only",
    "worktree list",
)


@pytest.mark.parametrize("lookup", LEGACY_LOOKUPS)
def test_every_lookup_decodes_with_the_codec(monkeypatch, tmp_path, lookup):
    """The codec is asked for by each lookup: with it set to ISO-8859-1 the bytes
    0xE9 come back as the name, where UTF-8 would keep a surrogate."""
    monkeypatch.setattr(
        get_scan_set,
        "_git_output_codec",
        lambda: ("iso-8859-1", "surrogateescape"),
    )
    legacy_raw = NAME.encode("iso-8859-1")
    stdout, call, expected = LOOKUPS[lookup]
    stdout = stdout.replace(RAW, legacy_raw)
    assert legacy_raw != RAW and legacy_raw in stdout

    answer, git = _run(monkeypatch, stdout, lambda: call(tmp_path))

    assert len(git.calls) == 1, git.calls
    assert answer == expected(), answer
