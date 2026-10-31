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

import errno
import io
import zipfile
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


def _converter(context, monkeypatch, archive: Path) -> ArchiveConverter:
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(archive)])
    return ArchiveConverter(context=context, config=ArchiveConverterConfig())


@pytest.mark.parametrize(
    ("name", "content"),
    [
        pytest.param("lib/b.tar", b"not a tar at all\n", id="named-as-a-tar"),
        pytest.param("c.zip", _damaged_zip(), id="damaged-zip"),
    ],
)
def test_an_archive_that_cannot_be_read_is_an_input_error(
    test_plugin_context, monkeypatch, name, content
):
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
