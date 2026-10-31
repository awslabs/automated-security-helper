# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ``newline`` argument of both guarded writers reaches the bytes on disk.

open_for_write and open_for_atomic_write each take open()'s ``newline`` and hand
it to the text layer they build. The CSV writers (sarif_field_analysis) pass
``newline=""`` through open_for_write so csv's own line endings are kept. These pin
the argument where it runs, by the bytes each spelling produces, so a refactor of
the text layer is measured rather than assumed.

The two writers that take complete content from a caller, ``write_text_atomically``
and ``replace_without_following``, default ``newline`` to ``""``: nothing is
translated, so a ``\\r\\n`` already in the content (a CSV report) is not turned into
``\\r\\r\\n`` on Windows. The last tests below pin the value handed to the text
layer, which is what differs from the old ``None`` default on a platform whose line
ending is ``\\n`` as well as on Windows.
"""

import os

import pytest

from automated_security_helper.utils.atomic_write import write_text_atomically
from automated_security_helper.utils.sandbox import fs_guard

pytestmark = pytest.mark.unit

TEXT = "a\nb\n"

WRITERS = ["open_for_write", "open_for_atomic_write"]


def _write(writer: str, path, **text_options) -> None:
    with getattr(fs_guard, writer)(path, **text_options) as handle:
        handle.write(TEXT)


@pytest.mark.parametrize("writer", WRITERS)
def test_the_default_newline_writes_the_platform_line_ending(tmp_path, writer):
    target = tmp_path / "default.txt"
    _write(writer, target)
    assert target.read_bytes() == TEXT.replace("\n", os.linesep).encode()


@pytest.mark.parametrize("writer", WRITERS)
def test_an_empty_newline_writes_the_text_as_given(tmp_path, writer):
    """The CSV writers' spelling: no translation, whatever the platform."""
    target = tmp_path / "untranslated.csv"
    _write(writer, target, newline="")
    assert target.read_bytes() == b"a\nb\n"


@pytest.mark.parametrize("writer", WRITERS)
def test_a_crlf_newline_changes_the_bytes_on_every_platform(tmp_path, writer):
    target = tmp_path / "crlf.txt"
    _write(writer, target, newline="\r\n")
    assert target.read_bytes() == b"a\r\nb\r\n"


@pytest.mark.parametrize("writer", WRITERS)
@pytest.mark.parametrize("newline", ["", "\n", "\r\n"])
def test_newline_with_a_binary_handle_is_refused_as_open_refuses_it(
    tmp_path, writer, newline
):
    """Built-in open() raises ValueError for ``newline`` with a binary mode. The
    writers raise it too, before anything is created, rather than dropping the
    argument and writing bytes the caller did not expect."""
    target = tmp_path / "binary.bin"
    with pytest.raises(ValueError, match="newline"):
        with getattr(fs_guard, writer)(target, binary=True, newline=newline):
            pass
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("writer", WRITERS)
def test_a_binary_handle_without_a_newline_is_written_as_given(tmp_path, writer):
    target = tmp_path / "binary.bin"
    with getattr(fs_guard, writer)(target, binary=True) as handle:
        handle.write(b"a\nb\r\n")
    assert target.read_bytes() == b"a\nb\r\n"


def _record_newline_of_the_atomic_writer(monkeypatch):
    """Wrap fs_guard.open_for_atomic_write; return the list of ``newline`` values."""
    seen = []
    real = fs_guard.open_for_atomic_write

    def recording(*args, **kwargs):
        seen.append(kwargs.get("newline", "<not passed>"))
        return real(*args, **kwargs)

    monkeypatch.setattr(fs_guard, "open_for_atomic_write", recording)
    return seen


def test_write_text_atomically_hands_the_guarded_writer_an_empty_newline_by_default(
    tmp_path, monkeypatch
):
    """The default is ``""``, not ``None``: with ``None`` the text layer turns each
    ``\\n`` of content into ``\\r\\n`` on Windows, and a CSV report's own ``\\r\\n``
    into ``\\r\\r\\n``."""
    seen = _record_newline_of_the_atomic_writer(monkeypatch)

    write_text_atomically(tmp_path / "report.csv", "a,b\r\n1,2\r\n")

    assert seen == [""]


def test_write_text_atomically_writes_content_that_holds_crlf_as_given(tmp_path):
    """The bytes a Windows run must produce too: one ``\\r\\n`` per CSV row."""
    target = tmp_path / "report.csv"
    write_text_atomically(target, "a,b\r\n1,2\r\n")
    assert target.read_bytes() == b"a,b\r\n1,2\r\n"


def test_write_text_atomically_still_passes_an_explicit_newline_on(
    tmp_path, monkeypatch
):
    """A caller that wants the platform's line ending passes ``newline=None``."""
    seen = _record_newline_of_the_atomic_writer(monkeypatch)

    write_text_atomically(tmp_path / "plain.txt", "a\nb\n", newline=None)

    assert seen == [None]
    assert (tmp_path / "plain.txt").read_bytes() == "a\nb\n".replace(
        "\n", os.linesep
    ).encode()


def test_replace_without_following_hands_the_text_layer_an_empty_newline_by_default(
    tmp_path, monkeypatch
):
    """The guide writer: LF content stays LF on every platform."""
    seen = []
    real = os.fdopen

    def recording(fd, *args, **kwargs):
        seen.append(kwargs.get("newline", "<not passed>"))
        return real(fd, *args, **kwargs)

    monkeypatch.setattr(fs_guard.os, "fdopen", recording)
    target = tmp_path / "guide.md"

    fs_guard.replace_without_following(target, "a\nb\n")

    assert seen == [""]
    assert target.read_bytes() == b"a\nb\n"
