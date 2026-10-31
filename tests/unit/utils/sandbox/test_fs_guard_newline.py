# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ``newline`` argument of both guarded writers reaches the bytes on disk.

open_for_write and open_for_atomic_write each take open()'s ``newline`` and hand
it to the text layer they build. The CSV writers (sarif_field_analysis) pass
``newline=""`` through open_for_write so csv's own line endings are kept; nothing
passes it through open_for_atomic_write yet. These pin the argument where it runs,
by the bytes each spelling produces, so a writer that starts passing it, or a
refactor of the text layer, is measured rather than assumed.
"""

import os

import pytest

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
def test_newline_is_dropped_for_a_binary_handle(tmp_path, writer):
    """The text options are built only for a text handle: a binary writer gets
    none of them, so a ``newline`` passed with ``binary=True`` is dropped rather
    than handed to a bytes layer that would refuse it. Pinned so the drop stays
    a decision, not an accident."""
    target = tmp_path / "binary.bin"
    with getattr(fs_guard, writer)(target, binary=True, newline="\r\n") as handle:
        handle.write(b"a\nb\n")
    assert target.read_bytes() == b"a\nb\n"
