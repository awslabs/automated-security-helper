# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An archive in the tree that the converter does not extract is recorded, not dropped.

The converter extracts files whose last suffix is zip, tar or gz. A ``.tgz``,
``.tar.bz2``, ``.tar.xz``, ``.7z``, ``.jar`` or ``.whl`` in the scanned tree was
neither extracted nor recorded, so a tree whose only archive was ``release.tgz``
reported "No archive files", while the same names inside an archive were recorded
as not scanned. Each is now a refused input that says it was not extracted. It does
not fail the completeness gate.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from typing import Dict

from automated_security_helper.interactions.run_ash_scan import incomplete_converters
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
)
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
)

ARCHIVE_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter"
)

NOT_EXTRACTED = [
    "release.tgz",
    "dist/app.tar.bz2",
    "dist/app.tar.xz",
    "tools.7z",
    "lib/vendor.jar",
    "wheels/pkg-1.0-py3-none-any.whl",
    "odd.zip.",
]


def zip_of(members: Dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def convert(context, monkeypatch, files: Dict[str, bytes]):
    tree = Path(context.source_dir)
    paths = []
    for name, data in files.items():
        path = tree / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        paths.append(str(path))
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: list(paths))
    converter = ArchiveConverter(
        context=context, config=context.config.converters.archive
    )
    return converter, converter.convert()


def gate(converter):
    model = AshAggregatedResults()
    model.converter_results["archive"] = ConverterStatusInfo(
        refused_inputs=list(converter.refused_inputs),
        failed_inputs=list(converter.failed_inputs),
    )
    return incomplete_converters(model)


def test_an_archive_format_that_is_not_extracted_is_recorded(
    test_plugin_context, monkeypatch
):
    files = dict.fromkeys(NOT_EXTRACTED, b"not read")
    files["notes.txt"] = b"not an archive\n"
    files["app.zip"] = zip_of({"app.py": "x = 1\n"})

    converter, results = convert(test_plugin_context, monkeypatch, files)

    assert sorted(r.path for r in converter.refused_inputs) == sorted(NOT_EXTRACTED)
    for refusal in converter.refused_inputs:
        assert refusal.member is None and refusal.limit is None
        assert "not extracted" in refusal.reason
    assert converter.failed_inputs == []
    assert gate(converter) == []
    (extracted,) = results
    assert (extracted / "app.py").is_file()


def test_a_tree_whose_only_archive_is_a_tgz_records_it(
    test_plugin_context, monkeypatch
):
    converter, results = convert(
        test_plugin_context, monkeypatch, {"release.tgz": b"not read"}
    )

    assert results == []
    assert [r.path for r in converter.refused_inputs] == ["release.tgz"]


def test_an_ignored_archive_format_is_not_recorded(test_plugin_context, monkeypatch):
    monkeypatch.setattr(
        test_plugin_context.config.global_settings,
        "ignore_paths",
        [IgnorePathWithReason(path="lib/**", reason="vendored")],
    )

    converter, _ = convert(
        test_plugin_context,
        monkeypatch,
        {"lib/vendor.jar": b"not read", "release.tgz": b"not read"},
    )

    assert [r.path for r in converter.refused_inputs] == ["release.tgz"]
