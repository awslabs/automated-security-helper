# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A whole ``ash scan`` over a tree whose archives the extraction limits refuse.

The unit tests in ``tests/unit/converters/test_archive_converter_limits.py`` drive the
converter alone, and ``tests/unit/config/test_archive_limits_are_operator_settings.py``
the config resolution. This one runs the real command, in a child process, through
the convert, scan and report phases with detect-secrets, the scanner that runs
in-process, and inspects what the run wrote.

The tree holds:

- ``.ash/.ash.yaml``, the repository's own config, raising every extraction limit
  above anything the archives below declare;
- ``declared.zip``, whose one member declares 1 TiB and holds a few bytes;
- ``nested.zip``, holding ``top_level.py`` and ``inner.zip``;
- ``ok.zip`` and ``ok.tar.gz``, ordinary archives, the positive control.

Every ``.py`` member holds a private key header, which detect-secrets reports, so
whether a member was scanned can be read off the findings.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.utils.archive_builders import TEBIBYTE, tar_bytes, zip_bytes

#: Assembled at run time, so this file holds no private key header of its own.
KEY_HEADER = "-----BEGIN " + "RSA PRIVATE" + " KEY-----"

DECLARED_MARKER = "DECLARED-ONLY-41d2"
NESTED_MARKER = "NESTED-ONLY-9b3e"

#: The repository config's limits: above the declared 1 TiB member of declared.zip,
#: and its ratio of about 7e9.
REPOSITORY_CONFIG = (
    "project_name: scanned\n"
    "converters:\n"
    "  archive:\n"
    "    options:\n"
    "      max_members: 100000000\n"
    f"      max_member_bytes: {2 * TEBIBYTE}\n"
    f"      max_total_bytes: {4 * TEBIBYTE}\n"
    "      max_compression_ratio: 1000000000000\n"
)


def holding_a_key(marker: str) -> str:
    return f"MARKER = '{marker}'\nKEY = '''{KEY_HEADER}\nMIIEowIBAAKCAQEA\n'''\n"


def build(base: Path) -> Path:
    tree = base / "tree"
    (tree / ".ash").mkdir(parents=True)
    (tree / ".ash" / ".ash.yaml").write_text(REPOSITORY_CONFIG)
    (tree / "declared.zip").write_bytes(
        zip_bytes(
            {"declared_member.py": holding_a_key(DECLARED_MARKER)},
            declared_sizes={"declared_member.py": TEBIBYTE},
        )
    )
    (tree / "nested.zip").write_bytes(
        zip_bytes(
            {
                "top_level.py": holding_a_key("top-level"),
                "inner.zip": zip_bytes(
                    {"nested_member.py": holding_a_key(NESTED_MARKER)}
                ),
            }
        )
    )
    (tree / "ok.zip").write_bytes(zip_bytes({"zip_member.py": holding_a_key("zip")}))
    (tree / "ok.tar.gz").write_bytes(
        tar_bytes({"targz_member.py": holding_a_key("tar.gz")}, gz=True)
    )
    (tree / "app.py").write_text("print('hello')\n")
    return tree


@pytest.fixture(scope="module")
def scan(tmp_path_factory):
    base = tmp_path_factory.mktemp("archive-limits")
    tree = build(base)
    output = base / "out"
    env = dict(os.environ)
    env.pop("ASH_CONFIG", None)
    # Keep the child off the network and away from the caller's terminal settings.
    env.update({"ASH_OFFLINE": "YES", "NO_COLOR": "1", "COLUMNS": "200"})
    # A fixed argv run by the test's own interpreter. `-I` keeps the child's imports
    # to that interpreter's site-packages, which is the ASH under test when the suite
    # runs from an installed checkout, as CI does.
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
        text=True,
        timeout=600,
        env=env,
        cwd=base,
    )
    # A precondition of every test below rather than a test of its own. The exit
    # code is not asserted: what a refusal does to it is reported, not fixed, here.
    results_file = output / "ash_aggregated_results.json"
    assert results_file.is_file(), (
        f"exit {completed.returncode}\n"
        + completed.stdout[-4000:]
        + completed.stderr[-4000:]
    )
    results = json.loads(results_file.read_text())
    return tree, output, results


def refused(results) -> list[tuple[str, str | None]]:
    rows = results["converter_results"]["archive"].get("refused_inputs") or []
    return sorted((row["path"], row["member"]) for row in rows)


def scanned_files(results) -> list[str]:
    """The file name of every location detect-secrets reported a finding in."""
    names = []
    for run in results["sarif"]["runs"]:
        for result in run.get("results") or []:
            for location in result.get("locations") or []:
                uri = location["physicalLocation"]["artifactLocation"]["uri"]
                names.append(uri.rsplit("/", 1)[-1])
    return sorted(names)


def converted_holding(output: Path, marker: str) -> list[str]:
    converted = output / "converted"
    return [
        str(path.relative_to(output))
        for path in converted.rglob("*")
        if path.is_file() and marker.encode() in path.read_bytes()
    ]


def test_an_archive_over_the_default_limits_is_refused_though_the_repository_raises_them(
    scan,
):
    _, output, results = scan
    recorded = refused(results)
    assert [path for path, _ in recorded if path == "declared.zip"] == [
        "declared.zip"
    ], recorded
    assert converted_holding(output, DECLARED_MARKER) == []
    assert "declared_member.py" not in scanned_files(results)


def test_a_nested_archive_is_recorded_in_the_results_and_the_log(scan):
    _, output, results = scan
    recorded = refused(results)
    assert ("nested.zip", "inner.zip") in recorded, recorded
    warnings = [
        line
        for line in (output / "ash.log").read_text().splitlines()
        if "\tWARNING\t" in line and "'inner.zip'" in line and "'nested.zip'" in line
    ]
    assert len(warnings) == 1, warnings


def test_a_nested_archive_is_not_scanned(scan):
    """Extraction is one level deep; the inner archive's members are not reached."""
    _, output, results = scan
    assert converted_holding(output, NESTED_MARKER) == []
    assert "nested_member.py" not in scanned_files(results)


def test_positive_control_the_repository_config_was_applied(scan):
    """The repository's config file was the scan's config, limits and all.

    So a refusal of declared.zip is the trusted limits winning over the file's, not
    the file going unread.
    """
    _, _, results = scan
    assert results["ash_config"]["project_name"] == "scanned"


def test_positive_control_ordinary_archives_are_extracted_and_scanned(scan):
    _, output, results = scan
    found = scanned_files(results)
    for name in ("zip_member.py", "targz_member.py", "top_level.py"):
        assert name in found, found
    by_name = {
        path.name: path.read_text()
        for path in (output / "converted").rglob("*.py")
        if path.is_file()
    }
    assert by_name["zip_member.py"] == holding_a_key("zip")
    assert by_name["targz_member.py"] == holding_a_key("tar.gz")
    assert by_name["top_level.py"] == holding_a_key("top-level")
