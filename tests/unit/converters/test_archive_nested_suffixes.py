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
    ArchiveConverter,
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
]


@pytest.fixture
def converter(test_plugin_context, monkeypatch):
    tree = Path(test_plugin_context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    members = {"top.py": b"print(1)\n", "data.json": b"{}\n", "x.zip.py": b"x = 1\n"}
    members.update(dict.fromkeys(NESTED, b"not scanned"))
    archive = tree / "outer.zip"
    archive.write_bytes(zip_bytes(members))
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(archive)])
    return ArchiveConverter(
        context=test_plugin_context,
        config=test_plugin_context.config.converters.archive,
    )


def test_every_nested_archive_suffix_is_recorded_as_not_scanned(converter):
    (extracted,) = converter.convert()

    assert sorted(r.member for r in converter.refused_inputs) == sorted(NESTED)
    assert all(not r.scan_incomplete for r in converter.refused_inputs)
    assert (extracted / "top.py").is_file()
    assert (extracted / "x.zip.py").is_file(), "a .py member is not an archive"


def test_nested_archive_suffixes_do_not_select_archives_in_the_tree():
    from automated_security_helper.plugin_modules.ash_builtin.converters import (
        archive_converter,
    )

    assert archive_converter.ARCHIVE_SUFFIXES == ("zip", "tar", "gz")
