# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The archive converter does not extract a member an ignore path names in the
scanned tree's terms.

A member is extracted to ``archive/<the archive's folded name>/<member>`` below
ASH's work directory, and the folded name follows the directory ASH runs from, so
an ignore path written against it matches from one directory and not another. An
ignore path may instead name the member by the archive's path and then the
member's, as if the archive were a directory (``lib/b.tar/vendor/m.js``,
``**/vendor/**``). Such a member is never extracted: no scanner reads it,
snyk-code included, which would upload it.

A path in the tree names no member. An ignore path written for the file
``lib/vendor/m.js``, or a tree pattern such as ``vendor/**``, leaves the archive's
own ``vendor/m.js`` in: an ignore path must not silently drop a different file
from the scan. tests/integration/scanners/test_snyk_code_copy_leaves_out_ignore_paths.py
runs the same forms through a whole scan, from two working directories.
"""

from __future__ import annotations

import io
import logging
import os
import tarfile
import zipfile
from pathlib import Path

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


@pytest.mark.parametrize(
    ("archive", "member", "kind", "path"),
    [
        ("bundle.zip", "vendor/m.js", "zip", "bundle.zip/vendor/m.js"),
        ("lib/b.tar", "./vendor/m.js", "tar", "lib/b.tar/vendor/m.js"),
        # The file the extraction writes: empty and "." parts collapse, and a
        # leading "/" goes.
        ("lib/b.tar", "vendor//m.js", "tar", "lib/b.tar/vendor/m.js"),
        ("lib/b.zip", "vendor/./m.js", "zip", "lib/b.zip/vendor/m.js"),
        ("lib/b.tar", "/vendor/m.js", "tar", "lib/b.tar/vendor/m.js"),
        # zipfile drops ".." parts when it extracts; a tar keeps them, and the
        # converter refuses either before extracting it.
        ("lib/b.zip", "../vendor/m.js", "zip", "lib/b.zip/vendor/m.js"),
        ("lib/b.zip", "a/../vendor/m.js", "zip", "lib/b.zip/a/vendor/m.js"),
        ("lib/b.tar", "a/../vendor/m.js", "tar", "lib/b.tar/a/../vendor/m.js"),
        # A backslash separates where the host's separator is one; elsewhere it is
        # part of the name, as in the tree.
        (
            "a.zip",
            "dir\\w.js",
            "zip",
            "a.zip/dir/w.js" if os.sep == "\\" else "a.zip/dir\\w.js",
        ),
    ],
)
def test_a_member_is_named_by_its_archive_s_path_and_then_its_own(
    archive, member, kind, path
):
    assert archive_converter.member_source_path(archive, member, kind) == path


def _tar(path: Path, members: dict[str, str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w") as archive:
        for name, text in members.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def _zip(path: Path, members: dict[str, str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for name, text in members.items():
            archive.writestr(name, text)
    return path


def _with_a_name_that_is_not_utf_8(path: Path, kind: str) -> Path:
    """lib/b.<kind> holding secrét/m.js beside ok.js, the member's name not read as
    UTF-8: latin-1 bytes in the tar, which tarfile reads as "secr\\udce9t", and the
    UTF-8 flag clear in the zip, which zipfile reads as cp437, "secrΘt"."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "tar":
        with tarfile.open(
            path, "w", format=tarfile.GNU_FORMAT, encoding="latin-1"
        ) as archive:
            for name, text in (("secrét/m.js", "m = 1\n"), ("ok.js", "ok = 1\n")):
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return path
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w") as archive:
        archive.writestr("secrQt/m.js", "m = 1\n")
        archive.writestr("ok.js", "ok = 1\n")
    data = zipped.getvalue()
    assert data.count(b"secrQt/m.js") == 2  # its local and central headers
    path.write_bytes(data.replace(b"secrQt/m.js", "secrét/m.js".encode("latin-1")))
    return path


@pytest.fixture
def ash_records():
    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collector(level=logging.WARNING)
    logger = logging.getLogger("ash")
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


def _convert(context, monkeypatch, archive: Path, ignore_paths: list[str]):
    context.config.global_settings.ignore_paths = [
        IgnorePathWithReason(path=path, reason="vendored") for path in ignore_paths
    ]
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(archive)])
    converter = ArchiveConverter(context=context, config=ArchiveConverterConfig())
    (extracted,) = converter.convert()
    return converter, sorted(
        p.relative_to(extracted).as_posix() for p in extracted.rglob("*") if p.is_file()
    )


BOTH = ["ok.js", "vendor/m.js"]


@pytest.mark.parametrize("kind", ["zip", "tar"])
@pytest.mark.parametrize(
    ("ignore_path", "extracted"),
    [
        pytest.param("lib/b.KIND/vendor/m.js", ["ok.js"], id="archive-then-member"),
        pytest.param("lib/b.KIND/vendor/**", ["ok.js"], id="a-glob-into-the-archive"),
        pytest.param("**/vendor/**", ["ok.js"], id="at-any-depth"),
        pytest.param("lib/b.KIND/ok.js", ["vendor/m.js"], id="the-other-member"),
        # A single * spans "/", as everywhere in ASH's patterns.
        pytest.param("*.js", [], id="star-spans-the-archive"),
        pytest.param("lib/*.js", [], id="star-below-the-archive-s-directory"),
        pytest.param("*/vendor/*", ["ok.js"], id="star-on-both-sides"),
        pytest.param("lib/**/*.js", [], id="double-star"),
        # A path in the tree names no member: each leaves vendor/m.js in.
        pytest.param("lib/vendor/m.js", BOTH, id="a-file-where-the-archive-is"),
        pytest.param("lib/vendor/**", BOTH, id="a-directory-where-the-archive-is"),
        pytest.param("vendor/m.js", BOTH, id="a-file-at-the-root"),
    ],
)
def test_an_ignored_member_is_not_extracted(
    test_plugin_context, monkeypatch, ash_records, kind, ignore_path, extracted
):
    source = Path(test_plugin_context.source_dir)
    maker = _zip if kind == "zip" else _tar
    archive = maker(
        source / "lib" / f"b.{kind}",
        {"./vendor/m.js": "m = 1\n", "ok.js": "ok = 1\n"}
        if kind == "tar"
        else {"vendor/m.js": "m = 1\n", "ok.js": "ok = 1\n"},
    )

    converter, files = _convert(
        test_plugin_context, monkeypatch, archive, [ignore_path.replace("KIND", kind)]
    )

    assert files == extracted
    # Left out because it was asked for: no warning, no refusal.
    assert [r.getMessage() for r in ash_records] == []
    assert list(converter.refused_inputs) == []


@pytest.mark.parametrize("kind", ["zip", "tar"])
@pytest.mark.parametrize("member", ["vendor//m.js", "vendor/./m.js"])
def test_a_member_is_matched_by_the_file_its_extraction_writes(
    test_plugin_context, monkeypatch, ash_records, kind, member
):
    """zipfile and tarfile both write vendor//m.js and vendor/./m.js to
    vendor/m.js, so the ignore path written for that file leaves the member out."""
    source = Path(test_plugin_context.source_dir)
    maker = _zip if kind == "zip" else _tar
    archive = maker(
        source / "lib" / f"b.{kind}", {member: "m = 1\n", "ok.js": "ok = 1\n"}
    )

    converter, files = _convert(
        test_plugin_context, monkeypatch, archive, [f"lib/b.{kind}/vendor/m.js"]
    )

    assert files == ["ok.js"]
    assert [r.getMessage() for r in ash_records] == []
    assert list(converter.refused_inputs) == []


@pytest.mark.parametrize("kind", ["zip", "tar"])
def test_a_member_whose_name_is_not_utf_8_is_refused_when_ignore_paths_are_set(
    test_plugin_context, monkeypatch, ash_records, kind
):
    """An ignore path is written in UTF-8, so it cannot be compared with a name that
    was not read as UTF-8: with ignore paths set, such a member is refused. Its name
    is recorded, and logged, as text: tarfile's surrogate becomes its escape."""
    source = Path(test_plugin_context.source_dir)
    archive = _with_a_name_that_is_not_utf_8(source / "lib" / f"b.{kind}", kind)

    converter, files = _convert(
        test_plugin_context, monkeypatch, archive, [f"lib/b.{kind}/secrét/m.js"]
    )

    assert files == ["ok.js"]
    (refused,) = converter.refused_inputs
    assert "not UTF-8" in refused.reason
    assert refused.member == ("secr\\udce9t/m.js" if kind == "tar" else "secrΘt/m.js")
    messages = [r.getMessage() for r in ash_records]
    assert len(messages) == 1
    messages[0].encode("utf-8")


@pytest.mark.skipif(os.name == "nt", reason="a POSIX file name of latin-1 bytes")
def test_an_archive_whose_own_name_is_not_utf_8_is_refused_member_by_member(
    test_plugin_context, monkeypatch, ash_records
):
    """os.listdir reads a latin-1 byte in a file's name as a surrogate. A member of
    such an archive refused for its own name (../x.js) is recorded with the
    archive's path as text, and the rest of the archive is extracted."""
    source = Path(test_plugin_context.source_dir)
    archive = _tar(
        source / "lib" / os.fsdecode(b"b\xe9.tar"),
        {"../x.js": "x = 1\n", "ok.js": "ok = 1\n"},
    )

    converter, files = _convert(test_plugin_context, monkeypatch, archive, [])

    assert files == ["ok.js"]
    (refused,) = converter.refused_inputs
    assert refused.path == "lib/b\\udce9.tar"
    assert refused.member == "../x.js"
    for record in ash_records:
        record.getMessage().encode("utf-8")


@pytest.mark.parametrize("kind", ["zip", "tar"])
def test_with_no_ignore_path_a_member_whose_name_is_not_utf_8_is_extracted(
    test_plugin_context, monkeypatch, ash_records, kind
):
    """The control: with no ignore path there is nothing to compare the name with."""
    source = Path(test_plugin_context.source_dir)
    archive = _with_a_name_that_is_not_utf_8(source / "lib" / f"b.{kind}", kind)

    converter, files = _convert(test_plugin_context, monkeypatch, archive, [])

    assert len(files) == 2 and "ok.js" in files
    assert list(converter.refused_inputs) == []
    assert [r.getMessage() for r in ash_records] == []


@pytest.mark.skipif(os.sep != "/", reason="where os.sep is a backslash, it separates")
@pytest.mark.parametrize("kind", ["zip", "tar"])
def test_a_backslash_in_a_member_s_name_reaches_the_matcher_as_written(
    test_plugin_context, monkeypatch, kind
):
    """On POSIX the extraction writes a\\b.js as one file of that name at the
    archive's top, so the matcher is asked about that path, not about a/b.js. The
    matcher's answer is fixed here: yes only for the name read with the backslash
    as a separator, so the member is extracted exactly when it is asked as written.
    """
    asked: list[str] = []

    def matcher(path, pattern):
        asked.append(path)
        return path == f"lib/b.{kind}/a/b.js"

    monkeypatch.setattr(f"{ARCHIVE_MODULE}.path_matches_pattern", matcher)
    source = Path(test_plugin_context.source_dir)
    maker = _zip if kind == "zip" else _tar
    archive = maker(
        source / "lib" / f"b.{kind}", {"a\\b.js": "b = 1\n", "ok.js": "ok = 1\n"}
    )

    converter, files = _convert(
        test_plugin_context, monkeypatch, archive, [f"lib/b.{kind}/a/**"]
    )

    assert f"lib/b.{kind}/a\\b.js" in asked
    assert files == ["a\\b.js", "ok.js"]
    assert list(converter.refused_inputs) == []


@pytest.mark.parametrize("kind", ["zip", "tar"])
@pytest.mark.parametrize("ignore_path", ["vendor/**", "vendor/m.js", "vendor/deep/**"])
def test_a_tree_pattern_leaves_the_members_of_an_archive_at_the_root_in(
    test_plugin_context, monkeypatch, ash_records, kind, ignore_path
):
    """The archive's own vendor/ is not the tree's: ``vendor/**`` leaves out the
    tree's vendor/ files (the scan set's job) and no member of bundle.<kind>."""
    source = Path(test_plugin_context.source_dir)
    maker = _zip if kind == "zip" else _tar
    members = {"vendor/m.js": "m = 1\n", "vendor/deep/d.js": "d = 1\n", "ok.js": "1\n"}
    archive = maker(source / f"bundle.{kind}", members)

    converter, files = _convert(
        test_plugin_context, monkeypatch, archive, [ignore_path]
    )

    assert files == sorted(members)
    assert [r.getMessage() for r in ash_records] == []
    assert list(converter.refused_inputs) == []
