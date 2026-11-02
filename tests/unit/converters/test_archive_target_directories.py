# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each archive is extracted into a directory of its own.

The target directory is named from the archive's path, and the name folds ``/``
and ``.`` to ``__`` and other runs of non-word characters to ``-``, so ``a b.zip``
and ``a-b.zip`` named the same directory. The second archive found it already
there, so when it failed part way nothing it wrote was removed, and the scanners
read a partial extraction as its content; when both succeeded, a member of one
overwrote the same-named member of the other. The second now gets a directory
with a counter appended.
"""

from __future__ import annotations

import gzip
import io
import struct
import zipfile
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
)
from automated_security_helper.utils.scan_output_dirs import (
    CONVERTED_SOURCES_FILE_NAME,
)

pytestmark = pytest.mark.unit

ARCHIVE_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter"
)


def zip_of(members: Dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def zip_failing_on_its_second_member() -> bytes:
    raw = bytearray(
        zip_of({"second_ok.py": "print(1)\n", "second_bad.py": "print(2)\n"})
    )
    second = raw.rfind(b"PK\x01\x02")
    struct.pack_into("<I", raw, second + 16, 0xDEADBEEF)
    return bytes(raw)


def convert(context, monkeypatch, archives: List[Tuple[str, bytes]]):
    """Convert ``archives`` in the order given; returns the converter and results."""
    tree = Path(context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, data in archives:
        path = tree / name
        path.write_bytes(data)
        paths.append(str(path))
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: list(paths))
    converter = ArchiveConverter(
        context=context, config=context.config.converters.archive
    )
    return converter, converter.convert()


def written(converter) -> List[str]:
    """Every member file the converter wrote, less its own record of their sources
    (converted-sources.json), which is not extracted content."""
    root = Path(converter.results_dir)
    return sorted(
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() and p != root / CONVERTED_SOURCES_FILE_NAME
    )


@pytest.mark.parametrize(
    "first, second",
    [
        pytest.param("a b.zip", "a-b.zip", id="space-and-hyphen"),
        pytest.param("a/b.c.zip", "a__b/c.zip", id="slash-dot-and-underscores"),
    ],
)
def test_a_failing_archive_leaves_nothing_where_another_was_extracted(
    first, second, test_plugin_context, monkeypatch
):
    for name in (first, second):
        Path(test_plugin_context.source_dir, name).parent.mkdir(
            parents=True, exist_ok=True
        )
    converter, results = convert(
        test_plugin_context,
        monkeypatch,
        [
            (first, zip_of({"first.py": "x = 1\n"})),
            (second, zip_failing_on_its_second_member()),
        ],
    )

    assert [f.path for f in converter.failed_inputs] == [second]
    assert [p.name for p in Path(converter.results_dir).rglob("second*")] == []
    # The first archive is still listed as converted, so its files must remain:
    # cleaning up after the second must not remove a directory the first wrote.
    (extracted,) = results
    assert sorted(p.name for p in extracted.iterdir()) == ["first.py"]


def test_a_gzip_over_a_limit_leaves_nothing_where_another_was_extracted(
    test_plugin_context, monkeypatch
):
    options = test_plugin_context.config.converters.archive.options
    monkeypatch.setattr(options, "max_member_bytes", 1000)
    converter, results = convert(
        test_plugin_context,
        monkeypatch,
        [
            ("x y.json.gz", gzip.compress(b'{"a": 1}\n')),
            ("x-y.json.gz", gzip.compress(b'{"a": 1}\n' * 50_000)),
        ],
    )

    assert [(r.path, r.limit) for r in converter.refused_inputs] == [
        ("x-y.json.gz", "max_member_bytes")
    ]
    (extracted,) = results
    assert [p.name for p in extracted.iterdir()] == ["x y.json"]
    assert len(written(converter)) == 1, written(converter)


def test_archives_whose_names_fold_together_are_extracted_side_by_side(
    test_plugin_context, monkeypatch
):
    converter, results = convert(
        test_plugin_context,
        monkeypatch,
        [
            ("a b.zip", zip_of({"app.py": "first = 1\n"})),
            ("a-b.zip", zip_of({"app.py": "second = 2\n"})),
        ],
    )

    assert len(results) == 2
    assert len(set(results)) == 2
    assert sorted((p / "app.py").read_text() for p in results) == [
        "first = 1\n",
        "second = 2\n",
    ]
    assert converter.failed_inputs == []
