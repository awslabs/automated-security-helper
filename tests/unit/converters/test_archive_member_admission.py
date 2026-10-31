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
one is written in a numbered directory beside the earlier with its file name kept
(``vendor/m~2/m.js``), so both are scanned. Refusing the later one and scanning the
first, the shape before this, scanned the bytes an unpacker that keeps the first
member would produce and never the bytes one that keeps the last produces, which
is what a deploy that unpacks the archive with ``tar`` or ``unzip`` gets. The file
name is kept because scanners find a manifest, a lockfile or a Dockerfile by it:
renamed to ``package~2.json``, the later copy, the one tar and unzip keep, was
scanned as a file the dependency scanners skip.
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
            "zip", "vendor//m.js", "vendor/m.js", "vendor/m~2/m.js", id="zip-spellings"
        ),
        pytest.param(
            "tar", "./vendor/m.js", "vendor/m.js", "vendor/m~2/m.js", id="tar-spellings"
        ),
        pytest.param(
            "tar", "vendor/m.js", "vendor/m.js", "vendor/m~2/m.js", id="tar-repeated"
        ),
        pytest.param(
            "zip", "Dockerfile", "Dockerfile", "Dockerfile~2/Dockerfile", id="no-ext"
        ),
        pytest.param(
            "zip",
            "package-lock.json",
            "package-lock.json",
            "package-lock~2/package-lock.json",
            id="lockfile",
        ),
        pytest.param("zip", "lib/M.js", "lib/m.js", "lib/m~2/m.js", id="case-fold"),
    ],
)
def test_two_members_written_to_one_path_are_both_extracted(
    test_plugin_context, monkeypatch, kind, first, second, renamed, ash_log_records
):
    """The later member holds the finding here: it is the one a deploy that unpacks
    the archive with tar or unzip gets, and it used to be refused unscanned. It
    keeps its file name, in a numbered directory beside the first: written as
    ``package-lock~2.json`` or ``Dockerfile~2``, it was a file the scanners that
    find a lockfile or a Dockerfile by name never read."""
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
    # The duplicate's file name is the name as read; only its directory is new.
    assert renamed.rsplit("/", 1)[-1] == second.rsplit("/", 1)[-1]
    assert converter.refused_inputs == []
    notices = [
        r.getMessage()
        for r in ash_log_records
        if r.levelno >= logging.WARNING and renamed in r.getMessage()
    ]
    assert len(notices) == 1 and f"a.{kind}" in notices[0], notices
    assert "numbered directory" in notices[0] and "file name kept" in notices[0]


def test_three_members_written_to_one_path_count_up(test_plugin_context, monkeypatch):
    archive = _zip(
        Path(test_plugin_context.source_dir) / "a.zip",
        [("m.js", b"1\n"), ("m.js", b"2\n"), ("./m.js", b"3\n")],
    )

    _, _, files = _convert(test_plugin_context, monkeypatch, archive)

    assert files == {"m.js": b"1\n", "m~2/m.js": b"2\n", "m~3/m.js": b"3\n"}


def test_a_renamed_member_never_takes_a_later_members_own_name(
    test_plugin_context, monkeypatch
):
    """``m~2/m.js`` is the archive's own third member. Picking the placement
    against the members written so far gave the second ``m.js`` that place, and
    the real ``m~2/m.js`` was then moved in its turn, so the scan's paths named
    the wrong bytes. Every member's name is read before any is renamed."""
    archive = _zip(
        Path(test_plugin_context.source_dir) / "a.zip",
        [("m.js", b"1\n"), ("m.js", b"2\n"), ("m~2/m.js", b"3\n")],
    )

    _, _, files = _convert(test_plugin_context, monkeypatch, archive)

    assert files == {"m.js": b"1\n", "m~3/m.js": b"2\n", "m~2/m.js": b"3\n"}


def test_a_renamed_member_never_takes_a_directory_a_member_is_named_as(
    test_plugin_context, monkeypatch
):
    """``m~2`` is the archive's own file: the duplicate cannot be placed in a
    directory of that name, so it takes the next counter. Every member's name
    counts, whether or not a scanner reads it."""
    monkeypatch.setattr(archive_converter, "_member_is_scannable", lambda name: True)
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )
    members = [zipfile.ZipInfo("m.js"), zipfile.ZipInfo("m.js"), zipfile.ZipInfo("m~2")]

    admitted = converter.inspect_members(members, target_path=None)

    assert [member.filename for member in admitted] == ["m.js", "m~3/m.js", "m~2"]


@pytest.mark.parametrize(
    ("kind", "order"),
    [
        pytest.param("zip", "directory-first", id="zip-directory-first"),
        pytest.param("zip", "directory-last", id="zip-directory-last"),
        pytest.param("tar", "directory-first", id="tar-directory-first"),
        pytest.param("tar", "directory-last", id="tar-directory-last"),
    ],
)
def test_a_renamed_member_never_lands_on_a_directory_of_another_member(
    test_plugin_context, monkeypatch, kind, order
):
    """``m~2/m.js`` is a directory the archive's own ``x.py`` is written below, so
    the duplicate ``m.js`` cannot be placed there as a file; it takes the next
    counter whichever way round the members come. Checked against the members
    written so far alone, the placement landed on that directory: with the
    directory's member first the extractor failed the whole archive on it
    (IsADirectoryError, an input error a suppression could waive), and with it
    last the archive's own ``x.py`` was refused as under a file."""
    maker = _zip if kind == "zip" else _tar
    below = ("m~2/m.js/x.py", b"x = 1\n")
    duplicates = [("m.js", b"1\n"), ("m.js", b"2\n")]
    members = (
        [below, *duplicates] if order == "directory-first" else [*duplicates, below]
    )
    archive = maker(Path(test_plugin_context.source_dir) / f"a.{kind}", members)

    converter, _, files = _convert(test_plugin_context, monkeypatch, archive)

    assert files == {"m~2/m.js/x.py": b"x = 1\n", "m.js": b"1\n", "m~3/m.js": b"2\n"}
    assert converter.failed_inputs == []
    assert converter.refused_inputs == []


def test_members_under_a_file_are_listed_up_to_the_cap_and_counted_past_it(
    test_plugin_context,
):
    """Twenty-five pairs ``xN.js`` / ``xN.js/y.js``: the later member of each is
    refused as under a file. The reason is one constant text, so the listing cap
    applies: 20 refusals recorded one by one, the other 5 counted in one record.
    With the colliding path inside the reason every pair was its own reason and
    25 records and 25 warnings were made, the shape the cap exists to prevent."""
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )
    members = []
    for index in range(25):
        members.append(zipfile.ZipInfo(f"x{index}.js"))
        members.append(zipfile.ZipInfo(f"x{index}.js/y.js"))

    admitted = converter.inspect_members(members, target_path=None, archive="a.zip")

    assert [member.filename for member in admitted] == [
        f"x{index}.js" for index in range(25)
    ]
    listed = [r for r in converter.refused_inputs if r.member is not None]
    counted = [r for r in converter.refused_inputs if r.member is None]
    assert len(listed) == archive_converter.MEMBER_REFUSALS_LISTED
    assert {r.reason for r in listed} == {archive_converter._MEMBER_UNDER_A_FILE}
    assert "x0.js" not in archive_converter._MEMBER_UNDER_A_FILE
    (summary,) = counted
    assert summary.unlisted_members == 25 - archive_converter.MEMBER_REFUSALS_LISTED
    assert summary.reason == archive_converter._MEMBER_UNDER_A_FILE


@pytest.mark.skipif(os.sep != "/", reason="a backslash separates on this host")
def test_a_backslash_stays_part_of_a_name_where_the_extractor_keeps_it(
    test_plugin_context, monkeypatch
):
    """On POSIX zipfile writes ``a\\b.js`` as one file at the archive's top; the
    rename used to read the backslash as a separator and put the second member
    under a directory ``a``, a different place from the member it stood beside.
    The numbered directory is beside the file, at the top, and the name keeps
    its backslash."""
    archive = _zip(
        Path(test_plugin_context.source_dir) / "a.zip",
        [("a\\b.js", b"1\n"), ("a\\b.js", b"2\n")],
    )

    _, _, files = _convert(test_plugin_context, monkeypatch, archive)

    assert files == {"a\\b.js": b"1\n", "a\\b~2/a\\b.js": b"2\n"}


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

    def counting_key(member_name, kind, fold=True):
        calls["n"] += 1
        return real_key(member_name, kind, fold)

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
    assert names[:3] == ["m.js", "m~2/m.js", "m~3/m.js"]
    # Linear, seven keys per renamed member: one before the loop (taken), one
    # for its destination, one for the written key the rename counts from, two
    # for the rename (the placement and its directory), one for the renamed
    # destination and one for the renamed path's one directory; never a walk
    # over every earlier counter. Measured 13,995 for 2,000 members (the first
    # member costs two): the bound is the arithmetic, not a margin.
    assert calls["n"] <= 7 * count, calls["n"]
    assert elapsed < 10, elapsed
    notices = [r.getMessage() for r in ash_log_records if r.levelno >= logging.WARNING]
    single = [n for n in notices if "is written as" in n]
    aggregate = [n for n in notices if "more members" in n]
    assert len(single) == archive_converter.MEMBER_REFUSALS_LISTED, len(single)
    expected = count - 1 - archive_converter.MEMBER_REFUSALS_LISTED
    assert len(aggregate) == 1 and f"{expected} more members" in aggregate[0], aggregate


def test_a_member_left_out_costs_no_directory_strings(test_plugin_context, monkeypatch):
    """Every prefix of every member's path used to be built up front, so a name of
    thousands of components built a string per prefix, each as long as the prefix
    (a 64 KiB ``a/a/.../a`` is about a gigabyte of characters), even for a member
    no scanner reads and that is left out unlooked at. A member left out reaches
    no prefix key now: the run's only calls are for members past that point."""
    calls = {"n": 0}
    real = archive_converter._written_prefix_keys

    def counting(member_name, kind, fold=True):
        calls["n"] += 1
        return real(member_name, kind, fold)

    monkeypatch.setattr(archive_converter, "_written_prefix_keys", counting)
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )
    members = [zipfile.ZipInfo("a/" * 50 + f"logo{i}.png") for i in range(20)]

    admitted = converter.inspect_members(members, target_path=None)

    assert admitted == []
    assert converter.refused_inputs == []
    assert calls["n"] == 0


def test_a_member_runs_through_a_directory_only_where_a_key_starts_with_it_and_a_separator():
    """The directory test the rename reads: over the sorted keys of every member,
    one bisect. ``m~2/m.js`` is a directory because a member is written below it;
    ``m.js`` and ``m`` are not, nor ``m~3/m.js``; and a key that merely starts
    with the same characters (``ab`` beside ``abc/x``) is not a directory."""
    keys = sorted(["m.js", "m~2/m.js/x.py", "abc/x", "other"])
    runs_through = archive_converter._a_member_runs_through

    assert runs_through("m~2/m.js", keys) is True
    assert runs_through("m~2", keys) is True
    assert runs_through("abc", keys) is True
    assert runs_through("m.js", keys) is False
    assert runs_through("m", keys) is False
    assert runs_through("m~3/m.js", keys) is False
    assert runs_through("ab", keys) is False
    assert runs_through("m.js", []) is False


def test_a_renamed_member_never_takes_a_name_a_later_members_directory_stands_on(
    test_plugin_context,
):
    """The control for the directory test, end to end: the second ``m.js`` would be
    placed at ``m~2/m.js``, where the later member ``m~2/m.js/x.py`` needs a
    directory, so it is placed at ``m~3/m.js`` and the later member is kept."""
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )
    members = [
        zipfile.ZipInfo("m.js"),
        zipfile.ZipInfo("m.js"),
        zipfile.ZipInfo("m~2/m.js/x.py"),
    ]

    admitted = converter.inspect_members(members, target_path=None)

    assert [m.filename for m in admitted] == ["m.js", "m~3/m.js", "m~2/m.js/x.py"]
    assert converter.refused_inputs == []


def _tmp_folds_case(directory: Path) -> bool:
    """The test's own read of the filesystem under ``directory``: whether a file
    written in lower case is found by its upper-case spelling."""
    probe = directory / "case-probe-lower.tmp"
    probe.write_bytes(b"")
    try:
        return (directory / "CASE-PROBE-LOWER.TMP").exists()
    finally:
        probe.unlink()


def test_the_case_probe_reads_the_output_filesystem_and_leaves_nothing(tmp_path):
    """The probe's answer for a not-yet-made extraction directory is the answer
    for its nearest existing ancestor, equal to the test's own read of the same
    filesystem, and the probe file is gone afterwards. With no target path the
    answer is True, the side that loses nothing."""
    expected = _tmp_folds_case(tmp_path)

    answer = archive_converter._filesystem_folds_case(tmp_path / "out" / "a.zip")

    assert answer is expected
    assert list(tmp_path.iterdir()) == []
    assert archive_converter._filesystem_folds_case(None) is True


def test_a_member_under_a_directory_spelled_like_a_file_is_extracted_where_case_counts(
    test_plugin_context, tmp_path, monkeypatch
):
    """``Foo.js`` then ``foo.js/bar.js``: on a case-sensitive filesystem these are
    a file and a directory with different names, and both are written. The keys
    used to fold case whatever the filesystem, so the second read as a member
    under the first's file and was refused for a collision the host never has;
    ``Foo.js`` and ``foo.js`` were likewise renamed as one path. The filesystem's
    answer is set here, so the test reads the same on every host."""
    monkeypatch.setattr(
        archive_converter, "_filesystem_folds_case", lambda target_path: False
    )
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )
    members = [
        zipfile.ZipInfo("Foo.js"),
        zipfile.ZipInfo("foo.js/bar.js"),
        zipfile.ZipInfo("foo.js"),
    ]

    admitted = converter.inspect_members(members, target_path=tmp_path, archive="a.zip")

    assert [m.filename for m in admitted] == ["Foo.js", "foo.js/bar.js", "foo.js"]
    assert converter.refused_inputs == []


def test_a_member_under_a_directory_spelled_like_a_file_is_refused_where_case_folds(
    test_plugin_context, tmp_path, monkeypatch
):
    """The control: where the filesystem folds case, ``foo.js/bar.js`` would be
    written under the file ``Foo.js`` and is refused alone, and ``foo.js`` is
    written beside ``Foo.js`` in a numbered directory, as before."""
    monkeypatch.setattr(
        archive_converter, "_filesystem_folds_case", lambda target_path: True
    )
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )
    members = [
        zipfile.ZipInfo("Foo.js"),
        zipfile.ZipInfo("foo.js/bar.js"),
        zipfile.ZipInfo("foo.js"),
    ]

    admitted = converter.inspect_members(members, target_path=tmp_path, archive="a.zip")

    assert [m.filename for m in admitted] == ["Foo.js", "foo~2/foo.js"]
    (refused,) = converter.refused_inputs
    assert refused.member == "foo.js/bar.js"
    assert refused.reason == archive_converter._MEMBER_UNDER_A_FILE


def test_the_written_key_keeps_case_with_the_fold_off_on_a_host_that_lower_cases_names(
    monkeypatch,
):
    """``os.path.normcase`` lower-cases on Windows (ntpath), so a key that applied
    it before reading the fold switch folded case whatever the output filesystem
    was measured to do: a case-sensitive NTFS directory never got the behavior,
    and the test of ``Foo.js`` beside ``foo.js/bar.js`` failed on the Windows leg.
    The host's normcase is stood in for here (``str.lower``), so the test reads
    the same on every host: with the fold off the key keeps the case, with it on
    the key folds (the control)."""
    monkeypatch.setattr(os.path, "normcase", str.lower)

    assert archive_converter._written_key("Foo.js", "zip", fold=False) == "Foo.js"
    assert archive_converter._written_prefix_keys(
        "Lib/Sub/Foo.js", "zip", fold=False
    ) == ["Lib", "Lib/Sub"]
    assert archive_converter._written_key("Foo.js", "zip", fold=True) == "foo.js"
    assert archive_converter._written_prefix_keys(
        "Lib/Sub/Foo.js", "zip", fold=True
    ) == ["lib", "lib/sub"]


def test_a_zip_with_a_file_and_a_directory_differing_in_case_extracts_both_where_case_counts(
    test_plugin_context, monkeypatch
):
    """End to end on this host's filesystem, where it is case-sensitive: the
    archive is extracted with both members in place. Skipped where the
    filesystem folds case, since there the refusal is right."""
    source = Path(test_plugin_context.source_dir)
    source.mkdir(parents=True, exist_ok=True)
    if _tmp_folds_case(source):
        pytest.skip("the filesystem under test folds case")
    archive = _zip(source / "a.zip", [("Foo.js", b"1\n"), ("foo.js/bar.js", b"2\n")])

    converter, _, files = _convert(test_plugin_context, monkeypatch, archive)

    assert files == {"Foo.js": b"1\n", "foo.js/bar.js": b"2\n"}
    assert converter.refused_inputs == []


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
    with a reason saying its path runs through a file (the log line names which
    file, so the reason stays one string per kind for the listing cap), and the
    rest is extracted."""
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
    assert "runs through a path" in refused.reason, refused.reason
    assert archive_converter.archives_extracted_whole(test_plugin_context) == set()


@pytest.mark.parametrize("kind", ["zip", "tar"])
def test_a_member_written_where_earlier_members_are_extracted_below_is_refused_alone(
    test_plugin_context, monkeypatch, kind
):
    """The reverse order: ``d.js/b.js`` and then a file named ``d.js``. The later
    member cannot be written where the directory stands (IsADirectoryError failed
    the whole archive before); it is refused alone and ``d.js/b.js`` is scanned.
    The file is named as one a scanner reads: a name no scanner reads is left out
    before the collision check and records nothing."""
    maker = _zip if kind == "zip" else _tar
    archive = maker(
        Path(test_plugin_context.source_dir) / f"a.{kind}",
        [("d.js/b.js", b"b\n"), ("d.js", b"d\n"), ("ok.js", b"ok\n")],
    )

    converter, _, files = _convert(test_plugin_context, monkeypatch, archive)

    assert files == {"d.js/b.js": b"b\n", "ok.js": b"ok\n"}
    assert converter.failed_inputs == []
    (refused,) = converter.refused_inputs
    assert (refused.path, refused.member) == (f"a.{kind}", "d.js")
    assert "below its path" in refused.reason, refused.reason
