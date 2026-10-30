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
``vendor/m.js``, a tar's repeated name, or two spellings of one name on a
case-insensitive filesystem) no longer overwrite each other silently: the later
one is written beside the earlier under a numbered name (``vendor/m~2.js``), so
both are scanned. Refusing the later one and scanning the first, the shape before
this, scanned the bytes an unpacker that keeps the first member would produce and
never the bytes one that keeps the last produces, which is what a deploy that
unpacks the archive with ``tar`` or ``unzip`` gets.
"""

from __future__ import annotations

import io
import logging
import os
import tarfile
import time
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


@pytest.fixture
def ash_log_records():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    logger = logging.getLogger("ash")
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


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
    [
        "Dockerfile",
        "Dockerfile.prod",
        "Dockerfile-prod",
        "dockerfile",
        "MAKEFILE",
        "Makefile_linux",
        ".npmrc",
        "id_rsa",
        "id_rsa.old",
        "id_ed25519-2024",
        "credentials",
        ".git-credentials",
        ".pgpass",
        ".htpasswd",
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        "config/.ENV.Staging",
        "authorized_keys",
        "known_hosts",
        "go.mod",
        "a.lock",
        "x.mjs",
        "identity",
        ".ssh/identity",
        "README",
        "docs/readme",
    ],
)
def test_the_admission_test_names_what_scanners_read(name):
    assert archive_converter._member_is_scannable(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "logo.png",
        "a.woff",
        "Dockerfiles",
        "id_card",
        "identities",
        "README-logo.png",
        ".environment",
        ".enviro.local",
        ".gitkeep",
    ],
)
def test_the_admission_test_leaves_out_what_no_scanner_reads(name):
    assert archive_converter._member_is_scannable(name) is False


def test_a_legacy_private_key_and_a_readme_are_extracted(
    test_plugin_context, monkeypatch
):
    """``identity`` is OpenSSH's legacy default private-key name, and a README is a
    text file the secret scanners read like any other. Both were left out of an
    archive as members no scanner reads, so a key kept under either name reached
    neither gitleaks nor detect-secrets."""
    archive = _zip(
        Path(test_plugin_context.source_dir) / "a.zip",
        [
            (".ssh/identity", b"-----BEGIN OPENSSH PRIVATE KEY-----\nnot a key\n"),
            ("README", b"token: not a token\n"),
            ("ok.js", b"ok = 1\n"),
        ],
    )

    converter, _, files = _convert(test_plugin_context, monkeypatch, archive)

    assert sorted(files) == [".ssh/identity", "README", "ok.js"]
    assert converter.refused_inputs == []
    assert archive_converter.archives_extracted_whole(test_plugin_context) == {"a.zip"}


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
    ("kind", "first", "second", "renamed"),
    [
        pytest.param(
            "zip", "vendor//m.js", "vendor/m.js", "vendor/m~2.js", id="zip-spellings"
        ),
        pytest.param(
            "tar", "./vendor/m.js", "vendor/m.js", "vendor/m~2.js", id="tar-spellings"
        ),
        pytest.param(
            "tar", "vendor/m.js", "vendor/m.js", "vendor/m~2.js", id="tar-repeated"
        ),
        pytest.param("zip", "Dockerfile", "Dockerfile", "Dockerfile~2", id="no-ext"),
        pytest.param("zip", "lib/M.js", "lib/m.js", "lib/m~2.js", id="case-fold"),
    ],
)
def test_two_members_written_to_one_path_are_both_extracted(
    test_plugin_context, monkeypatch, kind, first, second, renamed, ash_log_records
):
    """The later member holds the finding here: it is the one a deploy that unpacks
    the archive with tar or unzip gets, and it used to be refused unscanned."""
    maker = _zip if kind == "zip" else _tar
    archive = maker(
        Path(test_plugin_context.source_dir) / f"a.{kind}",
        [(first, b"m = 1\n"), (second, b"m = 2\n"), ("ok.js", b"ok = 1\n")],
    )

    converter, _, files = _convert(test_plugin_context, monkeypatch, archive)

    expected_first = archive_converter._member_written_path(first, kind)
    assert files == {
        expected_first: b"m = 1\n",
        renamed: b"m = 2\n",
        "ok.js": b"ok = 1\n",
    }
    assert converter.refused_inputs == []
    notices = [
        r.getMessage()
        for r in ash_log_records
        if r.levelno >= logging.WARNING and renamed in r.getMessage()
    ]
    assert len(notices) == 1 and f"a.{kind}" in notices[0], notices


def test_three_members_written_to_one_path_count_up(test_plugin_context, monkeypatch):
    archive = _zip(
        Path(test_plugin_context.source_dir) / "a.zip",
        [("m.js", b"1\n"), ("m.js", b"2\n"), ("./m.js", b"3\n")],
    )

    _, _, files = _convert(test_plugin_context, monkeypatch, archive)

    assert files == {"m.js": b"1\n", "m~2.js": b"2\n", "m~3.js": b"3\n"}


def test_a_renamed_member_never_takes_a_later_members_own_name(
    test_plugin_context, monkeypatch
):
    """``m~2.js`` is the archive's own third member. Picking the rename against the
    members written so far gave the second ``m.js`` that name, and the real
    ``m~2.js`` was then renamed in its turn, so the scan's paths named the wrong
    bytes. Every member's name is read before any is renamed."""
    archive = _zip(
        Path(test_plugin_context.source_dir) / "a.zip",
        [("m.js", b"1\n"), ("m.js", b"2\n"), ("m~2.js", b"3\n")],
    )

    _, _, files = _convert(test_plugin_context, monkeypatch, archive)

    assert files == {"m.js": b"1\n", "m~3.js": b"2\n", "m~2.js": b"3\n"}


@pytest.mark.skipif(os.sep != "/", reason="a backslash separates on this host")
def test_a_backslash_stays_part_of_a_name_where_the_extractor_keeps_it(
    test_plugin_context, monkeypatch
):
    """On POSIX zipfile writes ``a\\b.js`` as one file at the archive's top; the
    rename used to read the backslash as a separator and put the second member at
    ``a/b~2.js``, a different place from the member it stood beside."""
    archive = _zip(
        Path(test_plugin_context.source_dir) / "a.zip",
        [("a\\b.js", b"1\n"), ("a\\b.js", b"2\n")],
    )

    _, _, files = _convert(test_plugin_context, monkeypatch, archive)

    assert files == {"a\\b.js": b"1\n", "a\\b~2.js": b"2\n"}


def test_many_members_bound_for_one_path_are_renamed_in_bounded_time(
    test_plugin_context, monkeypatch, ash_log_records
):
    """N members named alike cost N names and a bounded number of notices. The
    rename used to try every counter from 2 for each duplicate (N squared key
    computations: 2,000 duplicates took about two million) and logged a WARNING
    apiece."""
    count = 2000
    calls = {"n": 0}
    real_key = archive_converter._written_key

    def counting_key(member_name, kind):
        calls["n"] += 1
        return real_key(member_name, kind)

    monkeypatch.setattr(archive_converter, "_written_key", counting_key)
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )
    members = [zipfile.ZipInfo("m.js") for _ in range(count)]

    started = time.monotonic()
    admitted = converter.inspect_members(members, target_path=None)
    elapsed = time.monotonic() - started

    names = [member.filename for member in admitted]
    assert len(names) == count and len(set(names)) == count
    assert names[:3] == ["m.js", "m~2.js", "m~3.js"]
    # Linear: one key per member before the loop, one for its destination, one
    # or two per rename; never a walk over every earlier counter.
    assert calls["n"] <= 6 * count, calls["n"]
    assert elapsed < 10, elapsed
    notices = [r.getMessage() for r in ash_log_records if r.levelno >= logging.WARNING]
    single = [n for n in notices if "is written as" in n]
    aggregate = [n for n in notices if "more members" in n]
    assert len(single) == archive_converter.MEMBER_REFUSALS_LISTED, len(single)
    expected = count - 1 - archive_converter.MEMBER_REFUSALS_LISTED
    assert len(aggregate) == 1 and f"{expected} more members" in aggregate[0], aggregate


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


@pytest.mark.parametrize("kind", ["zip", "tar"])
def test_a_member_under_a_file_member_is_refused_alone(
    test_plugin_context, monkeypatch, kind
):
    """``x.js`` and then ``x.js/y.js``: the second cannot be written under a file.
    The extractor failed on it, and the whole archive was recorded as a failed
    input, ``x.js`` and ``ok.js`` lost with it, so two members were enough to keep
    an archive's content from being scanned. The member is refused alone now,
    naming the file its path runs through, and the rest is extracted."""
    maker = _zip if kind == "zip" else _tar
    archive = maker(
        Path(test_plugin_context.source_dir) / f"a.{kind}",
        [("x.js", b"x\n"), ("x.js/y.js", b"y\n"), ("ok.js", b"ok\n")],
    )

    converter, _, files = _convert(test_plugin_context, monkeypatch, archive)

    assert files == {"x.js": b"x\n", "ok.js": b"ok\n"}
    assert converter.failed_inputs == []
    (refused,) = converter.refused_inputs
    assert (refused.path, refused.member) == (f"a.{kind}", "x.js/y.js")
    assert "'x.js'" in refused.reason, refused.reason
    assert archive_converter.archives_extracted_whole(test_plugin_context) == set()


@pytest.mark.parametrize("kind", ["zip", "tar"])
def test_a_member_written_where_earlier_members_are_extracted_below_is_refused_alone(
    test_plugin_context, monkeypatch, kind
):
    """The reverse order: ``a/b.js`` and then a file named ``a``. The later member
    cannot be written where the directory stands (IsADirectoryError failed the
    whole archive before); it is refused alone and ``a/b.js`` is scanned."""
    maker = _zip if kind == "zip" else _tar
    archive = maker(
        Path(test_plugin_context.source_dir) / f"a.{kind}",
        [("a/b.js", b"b\n"), ("a", b"a\n"), ("ok.js", b"ok\n")],
    )

    converter, _, files = _convert(test_plugin_context, monkeypatch, archive)

    assert files == {"a/b.js": b"b\n", "ok.js": b"ok\n"}
    assert converter.failed_inputs == []
    (refused,) = converter.refused_inputs
    assert (refused.path, refused.member) == (f"a.{kind}", "a")
    assert "below its path" in refused.reason, refused.reason
