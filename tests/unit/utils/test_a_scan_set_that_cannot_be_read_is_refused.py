# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan set that cannot be read stops the scanner reading it; it is never empty.

scan_output_dirs.scan_set_of gives a scanner the run's scan set. Turning an
OSError or a ValueError from get_scan_set.scan_set into an empty list would tell a
scanner that asked for it that nothing is in scope, and checkov, for
one, would then have no names to rewrite its paths by; an ignore file the locale
cannot decode is one such ValueError (UnicodeDecodeError). Ignore files are read
with surrogateescape, as git reads any bytes; for every other error the scanner
stops with ScanSetUnreadableError, which names the error, and the scan exits 1
with that scanner incomplete.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.core import exceptions
from automated_security_helper.utils import get_scan_set
from automated_security_helper.utils.scan_output_dirs import scan_set_of

pytestmark = pytest.mark.unit


def _context(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n")
    return SimpleNamespace(
        source_dir=source,
        output_dir=tmp_path / "out",
        run_id="r1",
        workspace_output_dir=None,
    )


@pytest.mark.parametrize(
    "error",
    [
        OSError(13, "Permission denied", ".gitignore"),
        UnicodeDecodeError("utf-8", b"\xe9", 0, 1, "invalid continuation byte"),
        ValueError("a list that does not parse"),
    ],
    ids=["oserror", "decode", "value"],
)
def test_an_error_reading_the_scan_set_is_raised_not_turned_into_nothing(
    tmp_path, monkeypatch, error
):
    def unreadable(**kwargs):
        raise error

    monkeypatch.setattr(get_scan_set, "scan_set", unreadable)

    with pytest.raises(Exception) as refused:
        scan_set_of(_context(tmp_path))

    assert type(refused.value).__name__ == "ScanSetUnreadableError", refused.value
    assert isinstance(refused.value, exceptions.ASHValidationError)
    # Not one the scanners' own handlers turn into "nothing to exclude".
    assert not isinstance(refused.value, (OSError, TypeError, ValueError))
    assert "scan set" in str(refused.value), refused.value
    assert type(error).__name__ in str(refused.value), refused.value
    assert refused.value.__cause__ is error


def test_the_scan_set_is_read(tmp_path):
    context = _context(tmp_path)

    assert [
        name.replace("\\", "/").rsplit("/", 1)[-1] for name in scan_set_of(context)
    ] == ["app.py"]


def test_no_output_dir_is_no_scan_set(tmp_path):
    """A context with nothing to read the list from is not an error."""
    assert scan_set_of(SimpleNamespace(source_dir=tmp_path, output_dir=None)) == []
