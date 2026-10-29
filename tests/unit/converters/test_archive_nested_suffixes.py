# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A member named as any common archive format is recorded as not scanned.

The converter selects archives in the tree by a last suffix of zip, tar or gz, and a
member with one of those suffixes was already recorded as a nested archive. A member
named ``.tgz``, ``.tar.bz2``, ``.jar``, ``.whl`` or ``.7z`` was still left out
without a record, because none of those is a scannable extension either. The nested
check now uses its own suffix list, kept apart from the selection list.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    NESTED_ARCHIVE_SUFFIXES,
    ArchiveConverter,
    _is_archive_name,
)
from tests.utils.archive_builders import zip_bytes

ARCHIVE_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter"
)

NESTED = [
    "in.tgz",
    "in.TGZ",
    "in.tar.bz2",
    "in.tar.xz",
    "in.tbz2",
    "in.txz",
    "lib/in.jar",
    "dist/in.whl",
    "in.war",
    "in.ear",
    "in.egg",
    "in.7z",
    "in.RAR",
    "in.zip",
    "in.Tar",
    "in.tar.gz",
    "in.tar.Z",
    "in.tz",
    "in.lz",
    "in.lz4",
    "in.tzst",
    "in.apk",
    "in.aar",
    "in.nupkg",
    "in.deb",
    "in.rpm",
    "in.cpio",
    "in.zip.",
]


@pytest.fixture
def converter(test_plugin_context, monkeypatch):
    tree = Path(test_plugin_context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    members = {
        "top.py": b"print(1)\n",
        "data.json": b"{}\n",
        "x.zip.py": b"x = 1\n",
        # Deliberate semantics, not accidents: a member's extension is read
        # through _archive_suffix (lowercased, trailing dots and spaces
        # stripped), so an upper-cased or trailing-dot name is scannable.
        "APP.PY": b"X = 1\n",
        "trail.py.": b"y = 2\n",
    }
    members.update(dict.fromkeys(NESTED, b"not scanned"))
    archive = tree / "outer.zip"
    archive.write_bytes(zip_bytes(members))
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(archive)])
    # More names than one archive lists one by one; listed here so each is checked.
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.MEMBER_REFUSALS_LISTED", 100, raising=True)
    return ArchiveConverter(
        context=test_plugin_context,
        config=test_plugin_context.config.converters.archive,
    )


def test_every_nested_archive_suffix_is_recorded_as_not_scanned(converter):
    (extracted,) = converter.convert()

    assert sorted(r.member for r in converter.refused_inputs) == sorted(NESTED)
    assert all(r.limit is None for r in converter.refused_inputs)
    assert converter.failed_inputs == []
    assert (extracted / "top.py").is_file()
    assert (extracted / "x.zip.py").is_file(), "a .py member is not an archive"
    assert (extracted / "APP.PY").is_file(), (
        "an upper-cased extension is scannable: the member extension is read "
        "through _archive_suffix, which lowercases, by design"
    )
    assert (extracted / "trail.py.").is_file(), (
        "a trailing dot does not hide a scannable member: _archive_suffix "
        "strips trailing dots and spaces, by design"
    )


@pytest.mark.parametrize("suffix", NESTED_ARCHIVE_SUFFIXES)
def test_each_suffix_in_the_list_marks_a_member_as_an_archive(suffix):
    """Read from the constant, so a suffix dropped from it fails here."""
    assert _is_archive_name(f"in.{suffix}")
    assert _is_archive_name(f"dir/in.{suffix.upper()}")
    assert _is_archive_name(f"in.{suffix}.")


def test_nested_archive_suffixes_do_not_select_archives_in_the_tree():
    from automated_security_helper.plugin_modules.ash_builtin.converters import (
        archive_converter,
    )

    assert archive_converter.ARCHIVE_SUFFIXES == ("zip", "tar", "gz")
