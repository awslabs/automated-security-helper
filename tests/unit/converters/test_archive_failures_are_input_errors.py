# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An archive the converter cannot read is an input error, recorded by its path
in the scanned tree.

The archive converter runs no tool, so every failure it records is about the
file: damaged, truncated, or named as an archive it cannot read as one. Those
records used to carry the default kind, "tool", which told the operator to make
the converter's tool able to run and let no ``ash-unconverted-input`` suppression
accept the archive, since a tool failure is never accepted. They are input
errors now, so a reviewed suppression on the archive's path waives the gate for
it, as it does for a notebook that is not one.

Two of the records were made from the archive's display name rather than the
path the scan set gave. ``record_failed_input`` relativizes its path against the
tree, and a path that is already relative resolves against the working
directory first, so a scan run from inside the tree recorded a different path.
"""

from __future__ import annotations

import contextlib
import errno
import gzip
import io
import lzma
import os
import tarfile
import zipfile
import zlib
from pathlib import Path

import pytest

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.plugin_modules.ash_builtin.converters import (
    archive_converter,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfig,
)

pytestmark = pytest.mark.unit

ARCHIVE_MODULE = archive_converter.__name__


def _damaged_zip() -> bytes:
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("z.js", "z = 1\n")
        archive.writestr("y.js", "y = 2\n")
    data = zipped.getvalue()
    assert data.count(b"y = 2") == 1
    return data.replace(b"y = 2", b"y = 3")


def _corrupted_deflate_zip() -> bytes:
    """A zip whose central directory is sound and whose one deflated member's
    compressed bytes are damaged, so the failure comes from the decompressor
    (zlib.error) or the CRC check (BadZipFile) at extraction, not at open."""
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        # Varied enough that the compressed data runs to hundreds of bytes, so
        # the damage below lands inside it and not in the central directory.
        archive.writestr(
            "z.js", "".join(f"z{i} = {i * 7919 % 1009}\n" for i in range(200))
        )
    data = bytearray(zipped.getvalue())
    # The local file header's name comes first; its compressed data follows it.
    start = data.find(b"z.js") + len(b"z.js")
    assert data.find(b"PK\x01\x02") > start + 100
    data[start + 10 : start + 18] = b"\xff" * 8
    return bytes(data)


def _cut_tar_bz2() -> bytes:
    """A bz2-compressed tar whose stream is damaged inside its first block."""
    packed = io.BytesIO()
    with tarfile.open(fileobj=packed, mode="w:bz2") as archive:
        info = tarfile.TarInfo("z.js")
        content = b"z = 1\n" * 200
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    data = bytearray(packed.getvalue())
    assert data[:3] == b"BZh"
    data[20:28] = b"\x00" * 8
    return bytes(data)


def _converter(context, monkeypatch, archive: Path) -> ArchiveConverter:
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(archive)])
    return ArchiveConverter(context=context, config=ArchiveConverterConfig())


@pytest.mark.parametrize(
    ("name", "content"),
    [
        pytest.param("lib/b.tar", b"not a tar at all\n", id="named-as-a-tar"),
        pytest.param("c.zip", _damaged_zip(), id="damaged-zip"),
        pytest.param("d.zip", _corrupted_deflate_zip(), id="corrupted-deflate"),
        # Named .tar: the converter sniffs bzip2 by content and never extracts a
        # file named .tar.bz2 (that suffix is refused by name, not read).
        pytest.param("lib/t.tar", _cut_tar_bz2(), id="damaged-bz2-stream"),
    ],
)
def test_an_archive_that_cannot_be_read_is_an_input_error(
    test_plugin_context, monkeypatch, name, content
):
    """Whatever the reader raises for a damaged archive (a CRC mismatch, a
    decompressor's error, a stream that is not a tar), the record is an input
    error: this converter runs no tool, so only the run's own errno values make a
    tool error (test_the_kind_of_a_failure_follows_the_error)."""
    source = Path(test_plugin_context.source_dir)
    archive = source / name
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(content)

    converter = _converter(test_plugin_context, monkeypatch, archive)
    assert converter.convert() == []

    (failed,) = converter.failed_inputs
    assert failed.path == name
    assert failed.kind == "input"
    assert failed.accepted is False


def test_a_suppression_on_the_archives_path_accepts_the_failure(
    test_plugin_context, monkeypatch
):
    """The suppression a reviewed, unreadable archive takes: the record stays,
    accepted, and the completeness gate leaves it out (waives_gate)."""
    from automated_security_helper.models.asharp_model import waives_gate

    source = Path(test_plugin_context.source_dir)
    archive = source / "lib" / "b.tar"
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(b"not a tar at all\n")
    test_plugin_context.config.global_settings.suppressions = [
        AshSuppression(
            rule_id="ash-unconverted-input",
            path="lib/b.tar",
            reason="a fixture that only looks like a tar",
        )
    ]

    converter = _converter(test_plugin_context, monkeypatch, archive)
    converter.convert()

    (failed,) = converter.failed_inputs
    assert failed.accepted is True
    assert failed.accepted_reason == "a fixture that only looks like a tar"
    assert waives_gate(failed)


def test_a_failure_of_the_run_is_a_tool_error_that_no_suppression_accepts(
    test_plugin_context, monkeypatch
):
    """The archive is sound; the work directory refuses the write. That is the
    run's failure, so the record says "tool" and the suppression on the
    archive's path does not waive the gate for it."""
    from automated_security_helper.models.asharp_model import waives_gate

    source = Path(test_plugin_context.source_dir)
    archive = source / "lib" / "b.zip"
    archive.parent.mkdir(parents=True, exist_ok=True)
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w") as sound:
        sound.writestr("z.js", "z = 1\n")
    archive.write_bytes(zipped.getvalue())
    test_plugin_context.config.global_settings.suppressions = [
        AshSuppression(
            rule_id="ash-unconverted-input",
            path="lib/b.zip",
            reason="a fixture kept on purpose",
        )
    ]

    def refusing_extractall(self, path=None, members=None, pwd=None):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(zipfile.ZipFile, "extractall", refusing_extractall)
    converter = _converter(test_plugin_context, monkeypatch, archive)

    results = converter.convert()

    assert results == []
    (failed,) = converter.failed_inputs
    assert failed.kind == "tool"
    assert failed.accepted is False
    assert not waives_gate(failed)
    assert "PermissionError" in failed.reason


@pytest.mark.parametrize(
    ("error", "kind"),
    [
        pytest.param(zipfile.BadZipFile("bad"), "input", id="bad-zip"),
        pytest.param(archive_converter._UnreadableArchive("cut"), "input", id="cut"),
        pytest.param(EOFError(), "input", id="eof"),
        pytest.param(tarfile.ReadError("unexpected end of data"), "input", id="tar"),
        pytest.param(
            tarfile.CompressionError("bz2 module is not available"),
            "input",
            id="tar-compression",
        ),
        pytest.param(gzip.BadGzipFile("Not a gzipped file"), "input", id="gzip"),
        pytest.param(
            zlib.error("Error -3 while decompressing data"), "input", id="zlib"
        ),
        pytest.param(lzma.LZMAError("Corrupt input data"), "input", id="lzma"),
        pytest.param(OSError("Invalid data stream"), "input", id="bz2-stream-no-errno"),
        pytest.param(OSError(errno.EISDIR, "Is a directory"), "input", id="over-a-dir"),
        pytest.param(OSError(errno.EEXIST, "File exists"), "input", id="exists"),
        # The run's: the work directory gone from under it, a link a guard refused,
        # a network filesystem that stopped answering, a file the filesystem
        # cannot hold. None of these is the archive's doing, and the old list,
        # which named the run's numbers and read every other one as the
        # archive's, let each of them be waived by a suppression.
        pytest.param(
            FileNotFoundError(errno.ENOENT, "No such file or directory"),
            "tool",
            id="work-dir-gone",
        ),
        pytest.param(
            OSError(errno.ELOOP, "Too many levels of symbolic links"),
            "tool",
            id="link-refused",
        ),
        pytest.param(OSError(errno.ESTALE, "Stale file handle"), "tool", id="stale"),
        pytest.param(
            OSError(errno.ETIMEDOUT, "Connection timed out"), "tool", id="nfs"
        ),
        pytest.param(OSError(errno.EFBIG, "File too large"), "tool", id="too-big"),
        pytest.param(OSError(errno.EXDEV, "Cross-device link"), "tool", id="xdev"),
        pytest.param(
            NotImplementedError("That compression method is not supported"),
            "input",
            id="zip-compression-method",
        ),
        pytest.param(
            NotADirectoryError(errno.ENOTDIR, "Not a directory"),
            "input",
            id="member-under-a-file",
        ),
        pytest.param(
            OSError(errno.ENAMETOOLONG, "File name too long"),
            "input",
            id="member-name-too-long",
        ),
        pytest.param(
            OSError(errno.EILSEQ, "Illegal byte sequence"), "input", id="member-name"
        ),
        pytest.param(
            OSError(errno.EINVAL, "Invalid data stream"), "input", id="bz2-stream"
        ),
        pytest.param(PermissionError(errno.EACCES, "denied"), "tool", id="permission"),
        pytest.param(OSError(errno.EPERM, "not permitted"), "tool", id="eperm"),
        pytest.param(
            OSError(errno.ENOSPC, "No space left on device"), "tool", id="enospc"
        ),
        pytest.param(OSError(errno.EDQUOT, "Disk quota exceeded"), "tool", id="quota"),
        pytest.param(OSError(errno.EROFS, "Read-only file system"), "tool", id="rofs"),
        pytest.param(OSError(errno.EMFILE, "Too many open files"), "tool", id="emfile"),
        pytest.param(
            OSError(errno.ENFILE, "Too many open files in system"), "tool", id="enfile"
        ),
        pytest.param(OSError(errno.EIO, "Input/output error"), "tool", id="eio"),
        pytest.param(
            OSError(errno.ENOMEM, "Cannot allocate memory"), "tool", id="enomem"
        ),
        pytest.param(
            OSError(errno.EBUSY, "Device or resource busy"), "tool", id="ebusy"
        ),
        pytest.param(MemoryError(), "tool", id="memory"),
        pytest.param(AttributeError("defect"), "tool", id="defect"),
        pytest.param(RuntimeError("defect"), "tool", id="runtime-defect"),
    ],
)
def test_the_kind_of_a_failure_follows_the_error(error, kind):
    assert archive_converter._failure_kind(error) == kind


def _tar_stream_raising(monkeypatch, error: BaseException) -> None:
    @contextlib.contextmanager
    def failing(handle):
        raise error
        yield  # pragma: no cover

    monkeypatch.setattr(archive_converter, "_tar_stream", failing)


@pytest.mark.parametrize(
    ("error", "raised"),
    [
        pytest.param(zlib.error("Error -3 while decompressing"), False, id="damaged"),
        pytest.param(EOFError("Compressed file ended"), False, id="cut"),
        pytest.param(
            OSError(errno.EINVAL, "Invalid data stream"), False, id="bz2-stream"
        ),
        pytest.param(PermissionError(errno.EACCES, "denied"), True, id="permission"),
        pytest.param(OSError(errno.EIO, "Input/output error"), True, id="eio"),
        pytest.param(MemoryError(), True, id="memory"),
        pytest.param(AttributeError("defect in the stream"), True, id="defect"),
    ],
)
def test_the_tar_probe_answers_not_a_tar_only_for_the_archives_own_errors(
    monkeypatch, error, raised
):
    """Reading the first block through the decompressor, the probe caught every
    error and answered "not a tar", so a permission refusal, a device error or a
    defect in the stream classes was recorded as an input error on the archive,
    which a suppression waives. Only the archive's own errors are that answer;
    the run's are raised, for convert() to grade as a tool failure."""
    _tar_stream_raising(monkeypatch, error)
    handle = io.BytesIO(b"x" * 1024)

    if raised:
        with pytest.raises(type(error)):
            archive_converter._holds_a_tar(handle)
    else:
        assert archive_converter._holds_a_tar(handle) is False
    assert handle.tell() == 0


@pytest.mark.parametrize(
    ("error", "raised"),
    [
        pytest.param(zlib.error("Error -3 while decompressing"), False, id="damaged"),
        pytest.param(EOFError("Compressed file ended"), False, id="cut"),
        pytest.param(PermissionError(errno.EACCES, "denied"), True, id="permission"),
        pytest.param(MemoryError(), True, id="memory"),
        pytest.param(AttributeError("defect in the stream"), True, id="defect"),
    ],
)
def test_the_order_probe_keeps_the_archives_errors_apart_from_the_runs(
    monkeypatch, error, raised
):
    """Where a stream carries gzip's magic and its first block also spells a tar
    header, the decompressor is asked first. Its own refusal (damaged or cut
    data) sends the stream to the plain tar reading, whose first block here is
    gzip bytes and no header, so the probe answers "not a tar"; an error of the
    run is raised, as every tar probe raises it, for convert() to grade."""

    class Failing(io.RawIOBase):
        def __init__(self, raw):
            super().__init__()

        def readable(self):
            return True

        def read(self, size=-1):
            raise error

    monkeypatch.setattr(archive_converter, "_GzipMembersStream", Failing)
    monkeypatch.setattr(archive_converter, "_spells_a_tar_header", lambda block: True)
    handle = io.BytesIO(gzip.compress(b"x" * 1024))

    if raised:
        with pytest.raises(type(error)):
            archive_converter._holds_a_tar(handle)
    else:
        assert archive_converter._holds_a_tar(handle) is False
    assert handle.tell() == 0


def test_a_run_error_while_probing_a_tar_is_a_tool_error_no_suppression_accepts(
    test_plugin_context, monkeypatch
):
    from automated_security_helper.models.asharp_model import waives_gate

    source = Path(test_plugin_context.source_dir)
    archive = source / "lib" / "b.tar"
    archive.parent.mkdir(parents=True, exist_ok=True)
    packed = io.BytesIO()
    with tarfile.open(fileobj=packed, mode="w") as sound:
        info = tarfile.TarInfo("z.js")
        info.size = 6
        sound.addfile(info, io.BytesIO(b"z = 1\n"))
    archive.write_bytes(packed.getvalue())
    test_plugin_context.config.global_settings.suppressions = [
        AshSuppression(
            rule_id="ash-unconverted-input",
            path="lib/b.tar",
            reason="a fixture kept on purpose",
        )
    ]
    _tar_stream_raising(monkeypatch, PermissionError(errno.EACCES, "denied"))
    converter = _converter(test_plugin_context, monkeypatch, archive)

    results = converter.convert()

    assert results == []
    (failed,) = converter.failed_inputs
    assert failed.kind == "tool"
    assert failed.accepted is False
    assert not waives_gate(failed)
    assert "PermissionError" in failed.reason


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows raises its own errors for a member under a file; the fallback "
    "is read where the extractor raises the two errors it catches",
)
def test_a_member_pair_the_admission_check_misses_is_the_archives_own_input_error(
    test_plugin_context, monkeypatch
):
    """The extraction-time fallback: a member the extractor cannot write because
    an earlier member made a file where its directory should be (NotADirectoryError),
    or a directory where its file should be (IsADirectoryError), is the archive's
    layout, recorded as an input error on the whole archive that a reviewed
    suppression accepts and that waives the gate. The admission check refuses such
    a pair before anything is written now, so the branch is reached here with that
    check switched off: it is kept as defense in depth for a pair the check's
    reading of the names misses, and this is the one test that drives it. The
    reason's exception name is not pinned (it differs by platform)."""
    from automated_security_helper.models.asharp_model import waives_gate

    monkeypatch.setattr(
        archive_converter, "_written_prefix_keys", lambda member_name, kind: []
    )
    source = Path(test_plugin_context.source_dir)
    archive = source / "under.zip"
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w", compression=zipfile.ZIP_STORED) as sound:
        sound.writestr(zipfile.ZipInfo("x.js"), b"x\n")
        sound.writestr(zipfile.ZipInfo("x.js/y.js"), b"y\n")
    archive.write_bytes(zipped.getvalue())
    test_plugin_context.config.global_settings.suppressions = [
        AshSuppression(
            rule_id="ash-unconverted-input",
            path="under.zip",
            reason="a reviewed fixture",
        )
    ]
    converter = _converter(test_plugin_context, monkeypatch, archive)

    results = converter.convert()

    assert results == []
    # Nothing was refused by name: the pair reached the extractor, which raised.
    assert converter.refused_inputs == []
    (failed,) = converter.failed_inputs
    assert failed.path == "under.zip"
    assert failed.kind == "input"
    assert failed.accepted is True
    assert failed.accepted_reason == "a reviewed fixture"
    assert waives_gate(failed)


def test_a_scan_set_path_outside_the_tree_is_not_skipped_and_does_not_raise(
    test_plugin_context, monkeypatch
):
    """With ignore paths set, the archive converter resolved every scan-set path
    against the source directory before matching, so a path not lexically under
    the tree raised ValueError into the conversion and the sound archive was
    recorded as a failure of the run's kind. No ignore path, written relative to
    the tree, names such a path."""
    from automated_security_helper.models.core import IgnorePathWithReason

    test_plugin_context.config.global_settings.ignore_paths = [
        IgnorePathWithReason(path="vendor/*", reason="third-party")
    ]
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )

    assert converter._skipped("/elsewhere/vendor/a.zip") is False
    # The control: a path under the tree that the entry names is skipped.
    inside = Path(test_plugin_context.source_dir) / "vendor" / "a.zip"
    assert converter._skipped(str(inside)) is True


def test_the_record_names_the_archive_by_its_path_in_the_tree_wherever_ash_runs(
    test_plugin_context, monkeypatch
):
    """Run from a directory inside the tree, the record still says lib/b.tar: a
    display name relativized a second time resolved against that directory."""
    source = Path(test_plugin_context.source_dir)
    archive = source / "lib" / "b.tar"
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(b"not a tar at all\n")
    inside = source / "sub"
    inside.mkdir()
    monkeypatch.chdir(inside)

    converter = _converter(test_plugin_context, monkeypatch, archive)
    converter.convert()

    assert [failed.path for failed in converter.failed_inputs] == ["lib/b.tar"]
