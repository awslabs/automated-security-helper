# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which archive members are extracted, and what the archive is recorded as.

The converter extracts a member only when some scanner would read it. That used
to be decided by the member's extension alone, against KNOWN_SCANNABLE_EXTENSIONS,
so a member with no extension (a Dockerfile, a Pipfile, an SSH private key), a
key or certificate file, a credential settings file, a lockfile or an ES module
was never extracted and never scanned, and the skip was logged at debug only.
Those names are admitted now (SCANNABLE_MEMBER_NAMES, SCANNABLE_MEMBER_SUFFIXES).

Two readings of "extracted whole" change with it. A notebook member is extracted
as it is, but the jupyter converter reads the scan set and not this converter's
output, so the notebook's code reaches no scanner as code: its archive is not
recorded whole. And two members written to one path (``vendor//m.js`` after
``vendor/m.js``, or a tar's repeated name) no longer overwrite each other
silently: the later one is refused, the earlier one's content is what is scanned,
and the refusal keeps the archive out of the whole set.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from automated_security_helper.plugin_modules.ash_builtin.converters import (
    archive_converter,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfig,
)

pytestmark = pytest.mark.unit

ARCHIVE_MODULE = archive_converter.__name__


def _zip(path: Path, members: List[Tuple[str, bytes]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members:
            archive.writestr(name, data)
    return path


def _tar(path: Path, members: List[Tuple[str, bytes]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w") as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def _convert(context, monkeypatch, archive: Path):
    monkeypatch.setattr(f"{ARCHIVE_MODULE}.scan_set", lambda **kwargs: [str(archive)])
    converter = ArchiveConverter(context=context, config=ArchiveConverterConfig())
    results = converter.convert()
    files: Dict[str, bytes] = {
        p.relative_to(extracted).as_posix(): p.read_bytes()
        for extracted in results
        for p in extracted.rglob("*")
        if p.is_file()
    }
    return converter, results, files


SCANNED_BY_NAME = [
    "Dockerfile",
    "Dockerfile.prod",
    "deploy/Containerfile",
    "Pipfile",
    "Pipfile.lock",
    "go.mod",
    "go.sum",
    ".npmrc",
    ".netrc",
    "keys/id_rsa",
    "certs/server.key",
    "certs/cert.pem",
    "src/app.mjs",
    "src/comp.vue",
    "src/main.cc",
]


def test_members_scanners_read_by_name_or_an_unlisted_extension_are_extracted(
    test_plugin_context, monkeypatch
):
    members = [(name, b"content\n") for name in SCANNED_BY_NAME]
    members.append(("assets/logo.png", b"\x89PNG\r\n\x1a\n"))
    archive = _zip(Path(test_plugin_context.source_dir) / "a.zip", members)

    converter, _, files = _convert(test_plugin_context, monkeypatch, archive)

    assert sorted(files) == sorted(SCANNED_BY_NAME)
    assert converter.refused_inputs == []
    # The image was left out, so the archive is not recorded as extracted whole.
    assert archive_converter.archives_extracted_whole(test_plugin_context) == set()


@pytest.mark.parametrize(
    "name",
    ["Dockerfile", "Dockerfile.prod", ".npmrc", "id_rsa", "go.mod", "a.lock", "x.mjs"],
)
def test_the_admission_test_names_what_scanners_read(name):
    assert archive_converter._member_is_scannable(name) is True


@pytest.mark.parametrize("name", ["logo.png", "a.woff", "README", "Dockerfiles"])
def test_the_admission_test_leaves_out_what_no_scanner_reads(name):
    assert archive_converter._member_is_scannable(name) is False


def test_a_notebook_member_is_extracted_but_its_archive_is_not_recorded_whole(
    test_plugin_context, monkeypatch
):
    """The jupyter converter never sees it, so its code is not scanned as code."""
    archive = _zip(
        Path(test_plugin_context.source_dir) / "a.zip",
        [("nb.ipynb", b'{"cells": []}\n'), ("ok.js", b"ok = 1\n")],
    )

    converter, _, files = _convert(test_plugin_context, monkeypatch, archive)

    assert sorted(files) == ["nb.ipynb", "ok.js"]
    assert converter.refused_inputs == []
    assert archive_converter.archives_extracted_whole(test_plugin_context) == set()


@pytest.mark.parametrize(
    ("kind", "first", "second"),
    [
        pytest.param("zip", "vendor//m.js", "vendor/m.js", id="zip-spellings"),
        pytest.param("tar", "./vendor/m.js", "vendor/m.js", id="tar-spellings"),
        pytest.param("tar", "vendor/m.js", "vendor/m.js", id="tar-repeated-name"),
    ],
)
def test_two_members_written_to_one_path_keep_the_first_and_refuse_the_second(
    test_plugin_context, monkeypatch, kind, first, second
):
    maker = _zip if kind == "zip" else _tar
    archive = maker(
        Path(test_plugin_context.source_dir) / f"a.{kind}",
        [(first, b"m = 1\n"), (second, b"m = 2\n"), ("ok.js", b"ok = 1\n")],
    )

    converter, _, files = _convert(test_plugin_context, monkeypatch, archive)

    assert files == {"vendor/m.js": b"m = 1\n", "ok.js": b"ok = 1\n"}
    assert [(r.path, r.member) for r in converter.refused_inputs] == [
        (f"a.{kind}", second)
    ]
    assert "same path" in converter.refused_inputs[0].reason
    assert archive_converter.archives_extracted_whole(test_plugin_context) == set()


def test_members_written_to_distinct_paths_are_all_extracted(
    test_plugin_context, monkeypatch
):
    """The control: ordinary members share no path and none is refused."""
    archive = _zip(
        Path(test_plugin_context.source_dir) / "a.zip",
        [("vendor/m.js", b"m = 1\n"), ("vendor/n.js", b"n = 1\n"), ("m.js", b"m\n")],
    )

    converter, _, files = _convert(test_plugin_context, monkeypatch, archive)

    assert sorted(files) == ["m.js", "vendor/m.js", "vendor/n.js"]
    assert converter.refused_inputs == []
    assert archive_converter.archives_extracted_whole(test_plugin_context) == {"a.zip"}
