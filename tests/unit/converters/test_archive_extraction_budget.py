# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the archive converter's extraction limits count, beyond the limit tests.

``test_archive_converter_limits.py`` covers each limit at and over its value. This
pins the choices underneath: every member counts, extracted or not (a compressed
tar is decompressed member by member to reach the next header, whatever is
extracted), directory entries count as members, a refused archive leaves no
directory behind, a sparse member whose map stays inside its size still extracts
with its holes, and a converter built without a config gets the default limits.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfig,
    ArchiveConverterConfigOptions,
)
from tests.utils.archive_builders import GENEROUS_LIMITS, TEBIBYTE, zip_bytes

ARCHIVE_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter"
)


@pytest.fixture
def tree(test_plugin_context) -> Path:
    source = Path(test_plugin_context.source_dir)
    source.mkdir(parents=True, exist_ok=True)
    return source


def converter_for(
    context,
    monkeypatch,
    archives: List[Path],
    limits: Dict[str, int] | None = None,
    without_data_filter: bool = False,
) -> ArchiveConverter:
    monkeypatch.setattr(
        f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(p) for p in archives]
    )
    if without_data_filter:
        monkeypatch.setattr(f"{ARCHIVE_MODULE}._TAR_HAS_DATA_FILTER", False)
    config = ArchiveConverterConfig(
        options=ArchiveConverterConfigOptions(**{**GENEROUS_LIMITS, **(limits or {})})
    )
    context.config.converters.archive = config
    return ArchiveConverter(context=context, config=config)


def tar_with(entries: List[tarfile.TarInfo], data: Dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for info in entries:
            payload = data.get(info.name)
            archive.addfile(info, io.BytesIO(payload) if payload is not None else None)
    return buffer.getvalue()


def file_entry(name: str, data: bytes) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info


def dir_entry(name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    return info


def test_a_member_that_would_not_be_extracted_still_counts(
    tree, test_plugin_context, monkeypatch
):
    archive = tree / "data.zip"
    archive.write_bytes(zip_bytes({"ok.py": "print(1)\n", "blob.bin": bytes(2000)}))
    converter = converter_for(
        test_plugin_context, monkeypatch, [archive], {"max_member_bytes": 1000}
    )

    assert converter.convert() == []
    assert [(r.path, r.limit) for r in converter.refused_inputs] == [
        ("data.zip", "max_member_bytes")
    ]


def test_directory_entries_count_as_members(tree, test_plugin_context, monkeypatch):
    archive = tree / "dirs.tar"
    archive.write_bytes(
        tar_with(
            [dir_entry("a"), dir_entry("a/b"), file_entry("a/b/x.py", b"x = 1\n")],
            {"a/b/x.py": b"x = 1\n"},
        )
    )
    converter = converter_for(
        test_plugin_context, monkeypatch, [archive], {"max_members": 2}
    )

    assert converter.convert() == []
    assert [(r.path, r.limit) for r in converter.refused_inputs] == [
        ("dirs.tar", "max_members")
    ]


def test_a_refused_archive_leaves_no_directory(tree, test_plugin_context, monkeypatch):
    archive = tree / "declared.zip"
    archive.write_bytes(
        zip_bytes({"d.py": "print(1)\n"}, declared_sizes={"d.py": TEBIBYTE})
    )
    converter = converter_for(test_plugin_context, monkeypatch, [archive])

    assert converter.convert() == []
    results_dir = Path(converter.results_dir)
    assert not results_dir.exists() or list(results_dir.iterdir()) == []


def test_only_the_archive_refusal_is_recorded_not_its_members(
    tree, test_plugin_context, monkeypatch
):
    """Over a limit, the members are not inspected, so none is refused on its own."""
    archive = tree / "many.zip"
    archive.write_bytes(
        zip_bytes({"inner.zip": b"PK", "a.py": "a = 1\n", "b.py": "b = 1\n"})
    )
    converter = converter_for(
        test_plugin_context, monkeypatch, [archive], {"max_members": 2}
    )

    converter.convert()

    assert [(r.path, r.member, r.limit) for r in converter.refused_inputs] == [
        ("many.zip", None, "max_members")
    ]


def test_a_nested_archive_refusal_names_no_limit(
    tree, test_plugin_context, monkeypatch
):
    archive = tree / "outer.zip"
    archive.write_bytes(zip_bytes({"top.py": "t = 1\n", "inner.zip": b"PK"}))
    converter = converter_for(test_plugin_context, monkeypatch, [archive])

    (extracted,) = converter.convert()

    assert (extracted / "top.py").is_file()
    assert [(r.member, r.limit) for r in converter.refused_inputs] == [
        ("inner.zip", None)
    ]


@pytest.mark.parametrize(
    "without_data_filter",
    [pytest.param(False, id="data-filter"), pytest.param(True, id="copy")],
)
def test_a_sparse_member_within_its_size_extracts_with_its_holes(
    tree, test_plugin_context, monkeypatch, without_data_filter
):
    """GNU sparse 0.1: 5 stored bytes mapped at offset 3 of a 10-byte file."""
    info = tarfile.TarInfo("sparse.py")
    info.size = 5
    info.pax_headers = {"GNU.sparse.map": "3,5", "GNU.sparse.size": "10"}
    archive = tree / "sparse.tar"
    archive.write_bytes(tar_with([info], {"sparse.py": b"hello"}))
    converter = converter_for(
        test_plugin_context,
        monkeypatch,
        [archive],
        {"max_member_bytes": 10},
        without_data_filter=without_data_filter,
    )

    (extracted,) = converter.convert()

    assert (extracted / "sparse.py").read_bytes() == b"\0\0\0hello\0\0"
    assert converter.refused_inputs == []


def test_a_converter_without_a_config_has_the_default_limits(
    tree, test_plugin_context, monkeypatch
):
    archive = tree / "declared.zip"
    archive.write_bytes(
        zip_bytes({"d.py": "print(1)\n"}, declared_sizes={"d.py": TEBIBYTE})
    )
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(archive)])
    converter = ArchiveConverter(context=test_plugin_context)

    assert converter.convert() == []
    assert [(r.path, r.limit) for r in converter.refused_inputs] == [
        ("declared.zip", "max_member_bytes")
    ]


def test_the_defaults_are_the_documented_ones():
    """The values docs/content/docs/plugins/builtin/converters.md states."""
    assert ArchiveConverterConfigOptions().model_dump() == {
        "max_members": 100_000,
        "max_member_bytes": 256 * 1024 * 1024,
        "max_total_bytes": 1024 * 1024 * 1024,
        "max_compression_ratio": 100,
    }
