# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config text that carries CRLF is written as it is, not translated again.

Why this file exists
--------------------
``open()`` in text mode turns each line feed it writes into the platform's line
ending when ``newline`` is None, which is CR LF on Windows. A config that
``ash config lint --fix`` rewrites keeps the file's own line endings, so its text
already carries CR LF, and the translation made every line end CR CR LF. The
writers pass ``newline=""`` so the text reaches the file as it was given.

The tests run on any platform: the handles the write guard hands back are
wrapped so they translate as a Windows handle does, and the file's bytes are read
back. What decides the bytes is the ``newline`` the writer asks the guard for.
"""

from __future__ import annotations

import errno
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.cli.config import _write_config_text
from automated_security_helper.utils.sandbox import fs_guard

pytestmark = pytest.mark.unit

CRLF_TEXT = "project_name: after\r\nfail_on_findings: false\r\n"


class _AsOnWindows:
    """A text handle that writes as ``open()`` does on Windows: with ``newline``
    None each line feed becomes CR LF, and with ``newline=""`` the text goes to
    the file as it is."""

    def __init__(self, inner: Any, newline: str | None) -> None:
        self._inner = inner
        self._translate = newline is None

    def write(self, text: Any) -> int:
        if self._translate and isinstance(text, str):
            text = text.replace("\n", "\r\n")
        return self._inner.write(text)

    def __enter__(self):
        self._inner.__enter__()
        return self

    def __exit__(self, *exc):
        return self._inner.__exit__(*exc)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _windows_line_endings(
    monkeypatch: pytest.MonkeyPatch, *, staging_refused: bool = False
) -> None:
    """Hand the config writers handles that translate line feeds as Windows does.

    With ``staging_refused`` the staged write is refused at its staging file, so
    the writer makes the in-place write."""
    real_atomic = fs_guard.open_for_atomic_write
    real_plain = fs_guard.open_for_write

    @contextmanager
    def atomic(path, *args, **kwargs):
        if staging_refused:
            raise PermissionError(
                errno.EACCES, os.strerror(errno.EACCES), os.fspath(path)
            )
        with real_atomic(path, *args, **kwargs) as handle:
            yield _AsOnWindows(handle, kwargs.get("newline"))

    def plain(path, *args, **kwargs):
        return _AsOnWindows(real_plain(path, *args, **kwargs), kwargs.get("newline"))

    monkeypatch.setattr(fs_guard, "open_for_atomic_write", atomic)
    monkeypatch.setattr(fs_guard, "open_for_write", plain)


def test_the_in_place_write_keeps_the_line_endings_of_the_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red at the base: the in-place write opened the file without ``newline``, so
    a text with CR LF in it came out with CR CR LF."""
    config = tmp_path / ".ash.yaml"
    config.write_bytes(b"project_name: before\r\n")
    _windows_line_endings(monkeypatch, staging_refused=True)

    _write_config_text(config, CRLF_TEXT)

    assert config.read_bytes() == CRLF_TEXT.encode("utf-8")
