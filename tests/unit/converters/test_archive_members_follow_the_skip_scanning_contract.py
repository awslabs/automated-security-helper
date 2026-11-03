# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Archive members are kept out of the scan by the same ignore paths as every
other input: the operator's, and none under --ignore-suppressions.

``ignore_paths_that_skip_scanning`` (models/core.py) is the contract every
pre-scan filter reads: an entry a delivered tree's own config supplied
(``client_supplied``) skips nothing before the scan, and ``--ignore-suppressions``
lifts every entry for every scanner. For a file in the tree the SARIF step marks a
finding under a client's entry suppressed; for an archive member it has no way to
(the finding sits at the member's extracted path under the work directory, and
nothing maps that back to ``lib/b.zip/vendor/m.js``), so the member's finding is
reported as an ordinary result: the safe side, and a recorded gap. The converter
read that contract for the archive itself and
then filtered the archive's members by every active entry, so a client's ignore
path dropped members before any scanner saw them, and the flag that is meant to
lift every suppression left them out all the same. A single-file .gz was
decompressed without consulting the member form at all, so an entry naming its
content in that form did not keep it out.

tests/unit/converters/test_archive_members_ignored_in_source_terms.py holds the
member naming; this file holds who may skip a member, and the .gz.
"""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.converters import (
    archive_converter,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfig,
)

pytestmark = pytest.mark.unit

ARCHIVE_MODULE = archive_converter.__name__

MEMBERS = {"vendor/m.js": "m = 1\n", "ok.js": "ok = 1\n"}


def _archive(path: Path, kind: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "zip":
        with zipfile.ZipFile(path, "w") as archive:
            for name, text in MEMBERS.items():
                archive.writestr(name, text)
        return path
    with tarfile.open(path, "w") as archive:
        for name, text in MEMBERS.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def _convert(
    context,
    monkeypatch,
    archive: Path,
    ignore_paths: List[IgnorePathWithReason],
    ignore_suppressions: bool = False,
):
    context.config.global_settings.ignore_paths = ignore_paths
    context.ignore_suppressions = ignore_suppressions
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(archive)])
    converter = ArchiveConverter(context=context, config=ArchiveConverterConfig())
    results = converter.convert()
    files = sorted(
        p.relative_to(extracted).as_posix()
        for extracted in results
        for p in extracted.rglob("*")
        if p.is_file()
    )
    return converter, results, files


@pytest.mark.parametrize("kind", ["zip", "tar"])
def test_an_operator_ignore_path_keeps_a_member_out(
    test_plugin_context, monkeypatch, kind
):
    """The control: an entry the operator wrote still skips the member."""
    archive = _archive(Path(test_plugin_context.source_dir) / "lib" / f"b.{kind}", kind)

    converter, _, files = _convert(
        test_plugin_context,
        monkeypatch,
        archive,
        [IgnorePathWithReason(path=f"lib/b.{kind}/vendor/m.js", reason="vendored")],
    )

    assert files == ["ok.js"]
    assert converter.refused_inputs == []


@pytest.mark.parametrize("kind", ["zip", "tar"])
def test_a_client_supplied_ignore_path_does_not_keep_a_member_out(
    test_plugin_context, monkeypatch, kind
):
    """A client's entry hides findings in the results; the member is extracted
    and scanned, as a notebook under the same entry is converted."""
    archive = _archive(Path(test_plugin_context.source_dir) / "lib" / f"b.{kind}", kind)

    converter, _, files = _convert(
        test_plugin_context,
        monkeypatch,
        archive,
        [
            IgnorePathWithReason(
                path=f"lib/b.{kind}/vendor/m.js", reason="client", client_supplied=True
            )
        ],
    )

    assert files == ["ok.js", "vendor/m.js"]
    assert converter.refused_inputs == []


@pytest.mark.parametrize("kind", ["zip", "tar"])
def test_ignore_suppressions_extracts_a_member_under_an_ignore_path(
    test_plugin_context, monkeypatch, kind
):
    """With --ignore-suppressions an ignore path skips nothing, members included."""
    archive = _archive(Path(test_plugin_context.source_dir) / "lib" / f"b.{kind}", kind)

    converter, _, files = _convert(
        test_plugin_context,
        monkeypatch,
        archive,
        [IgnorePathWithReason(path=f"lib/b.{kind}/vendor/m.js", reason="vendored")],
        ignore_suppressions=True,
    )

    assert files == ["ok.js", "vendor/m.js"]
    assert converter.refused_inputs == []


def _plain_gzip(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(gzip.compress(b'{"token": "x"}\n', mtime=0))
    return path


def test_an_ignore_path_naming_a_gzipped_files_content_keeps_it_out(
    test_plugin_context, monkeypatch
):
    """``lib/data.json.gz/data.json`` names what the .gz decompresses to, in the
    member form every archive member is named by; nothing is written for it."""
    archive = _plain_gzip(Path(test_plugin_context.source_dir) / "lib" / "data.json.gz")

    converter, results, files = _convert(
        test_plugin_context,
        monkeypatch,
        archive,
        [IgnorePathWithReason(path="lib/data.json.gz/data.json", reason="vendored")],
    )

    assert results == []
    assert files == []
    assert converter.refused_inputs == []
    assert converter.failed_inputs == []


def test_a_gzipped_file_no_ignore_path_names_is_decompressed(
    test_plugin_context, monkeypatch
):
    """The control: an entry for another file leaves the .gz in."""
    archive = _plain_gzip(Path(test_plugin_context.source_dir) / "lib" / "data.json.gz")

    _, results, files = _convert(
        test_plugin_context,
        monkeypatch,
        archive,
        [IgnorePathWithReason(path="lib/other.json.gz/other.json", reason="vendored")],
    )

    assert len(results) == 1
    assert files == ["data.json"]
