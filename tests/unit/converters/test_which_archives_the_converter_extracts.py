# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which files the archive converter extracts (archive_kind), and which archives a
run extracted whole (archives_extracted_whole).

convert() extracts a .zip that is a zip file, or a .zip, .tar or .gz that is a tar
file, compressed or not; a .gz that is no tar, or a file that only has an archive's
name, is not extracted. snyk-code's copy of the source leaves out exactly the
archives this run recorded as extracted whole, since their members reach Snyk with
the converted files, where ignore paths apply to them member by member. Every other
archive stays in the copy.
"""

from __future__ import annotations

import gzip
import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters import (
    archive_converter,
)

pytestmark = pytest.mark.unit


def _zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("a.js", "a = 1\n")
    return buffer.getvalue()


def _tar_bytes(mode: str = "w") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as archive:
        data = b"a = 1\n"
        info = tarfile.TarInfo("a.js")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


@pytest.mark.parametrize(
    ("name", "content", "kind"),
    [
        pytest.param("lib/b.zip", _zip_bytes(), "zip", id="zip"),
        pytest.param("lib/B.ZIP", _zip_bytes(), "zip", id="zip-upper-case"),
        pytest.param("lib/b.tar", _tar_bytes(), "tar", id="tar"),
        pytest.param("lib/b.tar.gz", _tar_bytes("w:gz"), "tar", id="tar-gz"),
        pytest.param("lib/b.zip", _tar_bytes(), "tar", id="tar-named-zip"),
        pytest.param("lib/b.gz", gzip.compress(b"{}\n"), None, id="gz-of-no-tar"),
        pytest.param("lib/b.zip", b"not an archive\n", None, id="zip-name-only"),
        pytest.param("lib/b.tar", b"", None, id="empty-tar-name"),
        pytest.param("lib/b.js", _zip_bytes(), None, id="zip-without-its-name"),
    ],
)
def test_the_converter_extracts_an_archive_by_its_name_and_its_format(
    name, content, kind
):
    handle = io.BytesIO(content)
    handle.seek(3)

    assert archive_converter.archive_kind(name, handle) == kind
    # Left at its start, for the caller that reads the file next.
    assert handle.tell() == 0


@pytest.mark.parametrize(
    ("name", "listed"),
    [
        ("a.zip", True),
        ("a.TAR", True),
        ("a.tar.gz", True),
        ("a.gz ", True),
        ("a.tgz", False),
        ("a.zip.js", False),
    ],
)
def test_the_converter_lists_an_archive_by_its_extension(name, listed):
    assert archive_converter.is_archive_name(name) is listed


def test_the_run_records_only_the_archives_it_extracted_whole(
    test_plugin_context, monkeypatch
):
    """What snyk-code's source copy leaves out: an archive this run extracted with
    no member refused. An ignored member still counts as extracted (it is left out
    on purpose); a refused member, an archive that is not one, and an ignored
    archive do not, so those stay in the copy."""
    from automated_security_helper.models.core import IgnorePathWithReason

    source = Path(test_plugin_context.source_dir)
    (source / "lib").mkdir(parents=True, exist_ok=True)
    (source / "lib" / "b.tar").write_bytes(_tar_bytes())
    link = zipfile.ZipInfo("link.js")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(source / "c.zip", "w") as archive:
        archive.writestr("z.js", "z = 1\n")
        archive.writestr(link, "/etc/passwd")
    (source / "d.json.gz").write_bytes(gzip.compress(b"{}\n"))
    (source / "vendor").mkdir(exist_ok=True)
    (source / "vendor" / "v.zip").write_bytes(_zip_bytes())
    names = ["lib/b.tar", "c.zip", "d.json.gz", "vendor/v.zip"]
    monkeypatch.setattr(
        f"{archive_converter.__name__}.scan_set",
        lambda **kwargs: [str(source / name) for name in names],
    )
    test_plugin_context.config.global_settings.ignore_paths = [
        IgnorePathWithReason(path="vendor/**", reason="vendored"),
        IgnorePathWithReason(path="lib/b.tar/a.js", reason="vendored"),
    ]
    converter = archive_converter.ArchiveConverter(
        context=test_plugin_context, config=archive_converter.ArchiveConverterConfig()
    )
    assert archive_converter.archives_extracted_whole(test_plugin_context) == set()

    converter.convert()

    assert archive_converter.archives_extracted_whole(test_plugin_context) == {
        "lib/b.tar"
    }
    assert [(r.path, r.member) for r in converter.refused_inputs] == [
        ("c.zip", "link.js")
    ]


def test_an_archive_with_a_member_no_scanner_reads_is_not_recorded_whole(
    test_plugin_context, monkeypatch
):
    """The converter does not extract a member no scanner reads (an image, a
    font), so that archive was not extracted whole: it stays in snyk-code's copy,
    which holds every member. Such a member is not refused. One that an ignore
    path names is left out on purpose, so its archive still counts."""
    from automated_security_helper.models.core import IgnorePathWithReason

    source = Path(test_plugin_context.source_dir)
    source.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(source / "f.zip", "w") as archive:
        archive.writestr("assets/logo.png", b"\x89PNG\r\n\x1a\n")
        archive.writestr("fonts/a.woff", b"wOFF")
        archive.writestr("ok.js", "ok = 1\n")
    with zipfile.ZipFile(source / "g.zip", "w") as archive:
        archive.writestr("vendor/x.png", b"\x89PNG\r\n\x1a\n")
        archive.writestr("ok.js", "ok = 1\n")
    names = ["f.zip", "g.zip"]
    monkeypatch.setattr(
        f"{archive_converter.__name__}.scan_set",
        lambda **kwargs: [str(source / name) for name in names],
    )
    test_plugin_context.config.global_settings.ignore_paths = [
        IgnorePathWithReason(path="g.zip/vendor/x.png", reason="vendored"),
    ]
    converter = archive_converter.ArchiveConverter(
        context=test_plugin_context, config=archive_converter.ArchiveConverterConfig()
    )

    converter.convert()

    assert archive_converter.archives_extracted_whole(test_plugin_context) == {"g.zip"}
    assert converter.refused_inputs == []


def test_an_archive_that_fails_to_extract_leaves_nothing_and_is_refused(
    test_plugin_context, monkeypatch
):
    """Extraction fails partway: the second member's bytes no longer match its CRC.
    What was written before the error is removed, the corrupt member included, so no
    scanner reads part of an archive as if it were all of it, and the archive is
    recorded as one failed input, which the completeness gate counts."""
    source = Path(test_plugin_context.source_dir)
    source.mkdir(parents=True, exist_ok=True)
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("z.js", "z = 1\n")
        archive.writestr("y.js", "y = 2\n")
    data = zipped.getvalue()
    assert data.count(b"y = 2") == 1
    (source / "c.zip").write_bytes(data.replace(b"y = 2", b"y = 3"))
    monkeypatch.setattr(
        f"{archive_converter.__name__}.scan_set",
        lambda **kwargs: [str(source / "c.zip")],
    )
    converter = archive_converter.ArchiveConverter(
        context=test_plugin_context, config=archive_converter.ArchiveConverterConfig()
    )

    assert converter.convert() == []

    assert not [p for p in Path(converter.results_dir).rglob("*") if p.is_file()]
    assert converter.refused_inputs == []
    assert [r.path for r in converter.failed_inputs] == ["c.zip"]
    assert converter.failed_inputs[0].reason
    assert archive_converter.archives_extracted_whole(test_plugin_context) == set()
