# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What a whole ``ash scan`` reports when the archive converter refuses an archive.

``test_scan_archive_extraction_limits.py`` checks what the scan extracted and
recorded. This checks the verdict and the reports: an archive over an extraction
limit fails the completeness gate, so the scan exits 1 and names the archive and
the limit, and the refusal is in ``ash.sarif``, ``ash.flat.json`` and both
summaries. A nested archive is reported the same way and leaves the exit code
alone.

Each scan runs the real command in a child process, through the convert, scan and
report phases with detect-secrets, the scanner that runs in-process.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tests.utils.archive_builders import TEBIBYTE, tar_bytes, zip_bytes

pytestmark = pytest.mark.integration

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _console_text(raw: str) -> str:
    """The console output as plain words: no color codes, and lines rejoined."""
    return " ".join(_ANSI.sub("", raw).split())


def _scan(base: Path, archives: dict[str, bytes]) -> tuple[int, str, Path]:
    tree = base / "tree"
    tree.mkdir(parents=True)
    for name, data in archives.items():
        (tree / name).write_bytes(data)
    (tree / "app.py").write_text("print('hello')\n")
    output = base / "out"
    env = dict(os.environ)
    env.pop("ASH_CONFIG", None)
    env.update({"ASH_OFFLINE": "YES", "NO_COLOR": "1", "COLUMNS": "200"})
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "automated_security_helper.cli.main",
            "scan",
            "--source-dir",
            str(tree),
            "--output-dir",
            str(output),
            "--mode",
            "local",
            "--scanners",
            "detect-secrets",
            "--phases",
            "convert",
            "--phases",
            "scan",
            "--phases",
            "report",
            "--no-progress",
            "--no-fail-on-findings",
        ],
        capture_output=True,
        # The scan writes UTF-8. Without an encoding, a Windows parent decodes the
        # pipe with its ANSI code page, a byte it cannot map ends the reader thread,
        # and stdout comes back as None.
        encoding="utf-8",
        errors="replace",
        timeout=600,
        env=env,
        cwd=base,
    )
    assert (output / "ash_aggregated_results.json").is_file(), (
        f"exit {completed.returncode}\n"
        + completed.stdout[-4000:]
        + completed.stderr[-4000:]
    )
    return (
        completed.returncode,
        _console_text(completed.stdout + completed.stderr),
        output,
    )


def _notifications(output: Path) -> list[tuple[str, str, str]]:
    doc = json.loads((output / "reports" / "ash.sarif").read_text())
    return sorted(
        (
            note["level"],
            note["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            note["message"]["text"],
        )
        for run in doc["runs"]
        for invocation in run.get("invocations") or []
        for note in invocation.get("toolExecutionNotifications") or []
    )


@pytest.fixture(scope="module")
def over_limit(tmp_path_factory):
    return _scan(
        tmp_path_factory.mktemp("over-limit"),
        {
            "declared.zip": zip_bytes(
                {"declared.py": "print('declared')\n"},
                declared_sizes={"declared.py": TEBIBYTE},
            ),
            "ok.zip": zip_bytes({"ok.py": "print('ok')\n"}),
        },
    )


@pytest.fixture(scope="module")
def nested_only(tmp_path_factory):
    return _scan(
        tmp_path_factory.mktemp("nested-only"),
        {
            "nested.zip": zip_bytes(
                {
                    "top.py": "print('top')\n",
                    "inner.zip": zip_bytes({"inner.py": "print('inner')\n"}),
                }
            )
        },
    )


def test_an_archive_over_a_limit_fails_the_scan_and_says_why(over_limit):
    code, out, _ = over_limit

    assert code == 1, out[-4000:]
    assert "conversion was incomplete" in out
    assert "declared.zip (max_member_bytes)" in out


def test_an_archive_over_a_limit_is_in_every_report(over_limit):
    _, out, output = over_limit
    reports = output / "reports"

    assert [
        (level, uri)
        for level, uri, _ in _notifications(output)
        if uri == "declared.zip"
    ] == [("error", "declared.zip")]
    flat = json.loads((reports / "ash.flat.json").read_text())
    assert [
        (row["path"], row["limit"], row["scan_incomplete"])
        for row in flat["converter_refusals"]
    ] == [("declared.zip", "max_member_bytes", True)]
    for summary in ("ash.summary.txt", "ash.summary.md"):
        assert "declared.zip" in (reports / summary).read_text(), summary
    assert "Not scanned (scan incomplete): archive: 'declared.zip'" in out


def test_a_nested_archive_is_reported_and_the_scan_still_passes(nested_only):
    code, out, output = nested_only

    assert code == 0, out[-4000:]
    assert [(level, uri) for level, uri, _ in _notifications(output)] == [
        ("warning", "nested.zip")
    ]
    flat = json.loads((output / "reports" / "ash.flat.json").read_text())
    assert [
        (row["path"], row["member"], row["scan_incomplete"])
        for row in flat["converter_refusals"]
    ] == [("nested.zip", "inner.zip", False)]
    assert "Not scanned: archive: member 'inner.zip' of 'nested.zip'" in out


#: Assembled at run time, so this file holds no private key header of its own.
_KEY_HEADER = "-----BEGIN " + "RSA PRIVATE" + " KEY-----"
_LFS_POINTER = (
    b"version https://git-lfs.github.com/spec/v1\n"
    b"oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\n"
    b"size 12345\n"
)


@pytest.fixture(scope="module")
def gzip_and_lfs(tmp_path_factory):
    import gzip

    secret = f"KEY = '''{_KEY_HEADER}\nMIIEowIBAAKCAQEA\n'''\n".encode()
    return _scan(
        tmp_path_factory.mktemp("gzip-and-lfs"),
        {
            "settings.py.gz": gzip.compress(secret, mtime=0),
            "assets.zip": _LFS_POINTER,
        },
    )


def test_a_plain_gzip_is_scanned_and_an_lfs_pointer_does_not_fail_the_scan(
    gzip_and_lfs,
):
    code, out, output = gzip_and_lfs

    assert code == 0, out[-4000:]
    doc = json.loads((output / "reports" / "ash.sarif").read_text())
    found = [
        location["physicalLocation"]["artifactLocation"]["uri"].rsplit("/", 1)[-1]
        for run in doc["runs"]
        for result in run.get("results") or []
        for location in result.get("locations") or []
    ]
    assert "settings.py" in found, found
    assert [(level, uri) for level, uri, _ in _notifications(output)] == [
        ("warning", "assets.zip")
    ]
    assert "git lfs pull" in out


@pytest.fixture(scope="module")
def corrupt(tmp_path_factory):
    raw = bytearray(zip_bytes({"ok.py": "print(1)\n", "bad.py": "print(2)\n"}))
    # A zip whose second member fails its CRC check after the first is written.
    import struct

    second = raw.rfind(b"PK\x01\x02")
    struct.pack_into("<I", raw, second + 16, 0xDEADBEEF)
    # A tar cut off where its second member's header starts: tarfile reads it as a
    # one-member archive without an error.
    whole = tar_bytes({"ok_tar.py": "print(3)\n", "rest.py": "print(4)\n"})
    cut = whole[: 2 * 512]
    # A zip whose second member, a file, is named like the directory its first made.
    clash = zip_bytes({"ok_clash.py/a.py": "print(5)\n", "ok_clash.py": "print(6)\n"})
    return _scan(
        tmp_path_factory.mktemp("corrupt"),
        {"crc.zip": bytes(raw), "cut.tar": cut, "clash.zip": clash},
    )


def test_a_corrupt_archive_is_a_failed_input_that_fails_the_scan(corrupt):
    code, out, output = corrupt

    assert code == 1, out[-4000:]
    results = json.loads((output / "ash_aggregated_results.json").read_text())
    row = results["converter_results"]["archive"]
    assert sorted(item["path"] for item in row.get("failed_inputs") or []) == [
        "clash.zip",
        "crc.zip",
        "cut.tar",
    ]
    for leftover in ("ok.py", "ok_tar.py", "a.py"):
        assert not list((output / "converted").rglob(leftover)), (
            f"partial output left: {leftover}"
        )
    assert "could not convert 3 inputs:" in out
