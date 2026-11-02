# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The gitleaks re-scan copies each named file under the name the tree lists.

gitleaks walks the directory and reports each file by the name the directory
lists, and the rejoined ``.gitleaksignore`` line is matched exactly against
``<file>:<rule>:<line>`` with that name. An entry spelled in another letter
case therefore hid no finding, even on a case-insensitive filesystem (macOS and
Windows by default) where it opens the listed file: it is not copied, and no
re-scan is spent on it. Mapping it to the listed spelling made two copies of
one path, which failed the scan, and findings reported under the entry's
spelling that the first run's results never matched.

The ignore file itself is a different question and is decided by identity, not
by spelling. A repository that commits it as ``.GITLEAKSIGNORE`` has it read as
the ignore file on a case-insensitive filesystem, and a copy of it at the copy
tree's root would be read as the ignore file again and hide the same
fingerprints. A case-insensitive filesystem is stood in for by a ``samefile``
that answers True for two names differing only in case, so the behavior is
measured on every platform; on a real one the stand-in changes nothing.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    gitleaks_scanner as module,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
    IGNORE_FILE_NAME,
    GitleaksScanner,
)
from tests.unit.plugin_modules.ash_builtin.test_gitleaks_scanner import (
    _add_back,
    _report,
    _rescan_harness,
    _result,
    _write,
)

pytestmark = pytest.mark.unit


def _case_insensitive_names(monkeypatch) -> None:
    """``os.path.samefile`` as a case-insensitive filesystem answers it: two names
    that differ only in case are one file when the listed one exists."""
    real = os.path.samefile

    def samefile(first, second):
        a, b = os.fspath(first), os.fspath(second)
        if a != b and a.casefold() == b.casefold():
            return os.path.exists(a) or os.path.exists(b)
        return real(first, second)

    monkeypatch.setattr(module.os.path, "samefile", samefile)


def test_a_name_spelled_as_listed_is_returned_as_is(tmp_path):
    _write(tmp_path, "app/settings.py")
    assert (
        GitleaksScanner._on_disk_spelling(tmp_path, "app/settings.py", {})
        == "app/settings.py"
    )


def test_a_name_that_reaches_no_file_is_none(tmp_path):
    _write(tmp_path, "app/settings.py")
    assert GitleaksScanner._on_disk_spelling(tmp_path, "app/missing.py", {}) is None


def test_another_case_is_not_the_listed_name_on_any_filesystem(tmp_path):
    """The directory lists ``app/settings.py``; the rejoined ignore line is
    matched exactly against that name, so an entry spelled otherwise hid nothing
    even where the filesystem would open the file under it."""
    _write(tmp_path, "app/settings.py")
    assert GitleaksScanner._on_disk_spelling(tmp_path, "App/Settings.py", {}) is None


def test_a_differently_cased_entry_is_not_re_scanned(tmp_path, monkeypatch):
    hidden = _result("app/settings.py", "github-pat", 4, column=18)
    scanner, calls = _rescan_harness(
        tmp_path, monkeypatch, {"app/settings.py": [hidden]}
    )
    source = Path(scanner.context.source_dir)
    _write(source, "app/settings.py")
    (source / ".gitleaksignore").write_text("App/Settings.py:github-pat:4\n")

    assert _add_back(scanner, source, _report(), tmp_path) == []
    assert calls == []


def test_an_entry_in_another_case_beside_the_exact_one_is_one_copy(
    tmp_path, monkeypatch
):
    _case_insensitive_names(monkeypatch)
    hidden = _result("app/settings.py", "github-pat", 4, column=18)
    scanner, calls = _rescan_harness(
        tmp_path, monkeypatch, {"app/settings.py": [hidden]}
    )
    source = Path(scanner.context.source_dir)
    _write(source, "app/settings.py")
    (source / ".gitleaksignore").write_text(
        "app/settings.py:github-pat:4\nApp/Settings.py:github-pat:5\n"
    )

    assert _add_back(scanner, source, _report(), tmp_path) == [
        ("app/settings.py", "github-pat", 4, 18)
    ]
    assert [call["files"] for call in calls] == [["app/settings.py"]]


def test_the_ignore_file_named_in_another_case_is_not_re_scanned(tmp_path, monkeypatch):
    """The tree lists ``.gitleaksignore``; an entry for ``.GitleaksIgnore`` hid
    nothing. Only the other named file is copied."""
    _case_insensitive_names(monkeypatch)
    other = _result("app/x.py", "github-pat", 1)
    scanner, calls = _rescan_harness(tmp_path, monkeypatch, {"app/x.py": [other]})
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    (source / ".gitleaksignore").write_text(
        ".GitleaksIgnore:github-pat:2\napp/x.py:github-pat:1\n"
    )

    assert _add_back(scanner, source, _report(), tmp_path) == [
        ("app/x.py", "github-pat", 1, None)
    ]
    [tree] = calls
    assert tree["files"] == ["app/x.py"]


def _add_back_with(scanner, source: Path, tmp_path: Path, data: bytes) -> list:
    """The add-back for an ignore file whose bytes are ``data``, read by the
    caller: on a case-sensitive filesystem the scanner's own read of
    ``.gitleaksignore`` would find nothing where the tree commits another case."""
    raw = _report()
    results_file = tmp_path / "res" / "gitleaks.sarif"
    results_file.parent.mkdir(exist_ok=True)
    scanner._add_back_gitleaksignore_drops(
        raw,
        source,
        scanner._build_arguments(source, results_file),
        results_file,
        data,
    )
    return sorted(
        (
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["ruleId"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
        )
        for r in raw["runs"][0]["results"]
    )


def test_an_ignore_file_committed_in_another_case_is_re_scanned_alone(
    tmp_path, monkeypatch
):
    """On a case-insensitive filesystem the tree's ``.GITLEAKSIGNORE`` is the
    file gitleaks reads as the ignore file, and the directory lists that
    spelling. Decided by the string, it was copied to the copy tree's root, where
    the re-scan read it as the ignore file again and hid the same fingerprints:
    nothing was added back and the report looked clean."""
    _case_insensitive_names(monkeypatch)
    hidden = _result(".GITLEAKSIGNORE", "github-pat", 2)
    other = _result("app/x.py", "github-pat", 1)
    scanner, calls = _rescan_harness(
        tmp_path, monkeypatch, {".GITLEAKSIGNORE": [hidden], "app/x.py": [other]}
    )
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    _write(source, ".GITLEAKSIGNORE")

    added = _add_back_with(
        scanner,
        source,
        tmp_path,
        b".GITLEAKSIGNORE:github-pat:2\napp/x.py:github-pat:1\n",
    )

    assert added == [
        (".GITLEAKSIGNORE", "github-pat", 2),
        ("app/x.py", "github-pat", 1),
    ]
    tree, itself = calls
    assert tree["files"] == ["app/x.py"]
    assert itself["argv"][-2:] == ["--", ".GITLEAKSIGNORE"]
    assert itself["cwd"] != tree["cwd"]


def test_a_copy_the_copy_filesystem_reads_as_the_ignore_file_fails_the_scan(
    tmp_path, monkeypatch
):
    """The tree keeps ``.GITLEAKSIGNORE`` apart from ``.gitleaksignore`` (a
    case-sensitive filesystem), so it is an ordinary file; the copies are made on
    a filesystem that reads the two as one. A copy at the tree's root would be the
    ignore file for the re-scan, so the scan fails instead of reporting less.

    The tree's case-sensitivity is stood in for as well, because the test must
    hold on a case-insensitive host (macOS and Windows by default): there the
    real ``samefile`` reads the tree's ``.GITLEAKSIGNORE`` as the ignore file,
    classes it with the ignore file's own batch, and nothing is copied into the
    tree's batch for the guard to refuse. Here ``.gitleaksignore`` reaches no
    file, as it does on a case-sensitive filesystem."""
    scanner, _ = _rescan_harness(tmp_path, monkeypatch, {})
    source = Path(scanner.context.source_dir)
    _write(source, ".GITLEAKSIGNORE")

    real_samefile = os.path.samefile

    def samefile(first, second):
        # Only the comparison with the ignore file is stood in for; the
        # patched function is the shared ``os.path`` one, so any other caller
        # in the process gets the real answer.
        if os.path.basename(os.fspath(second)) == IGNORE_FILE_NAME:
            raise FileNotFoundError(os.fspath(second))
        return real_samefile(first, second)

    monkeypatch.setattr(module.os.path, "samefile", samefile)
    real_exists = Path.exists

    def exists(self, *args, **kwargs):
        if self.name == IGNORE_FILE_NAME and self.parent.name == "tree":
            return any(
                item.name.casefold() == IGNORE_FILE_NAME
                for item in self.parent.iterdir()
            )
        return real_exists(self, *args, **kwargs)

    monkeypatch.setattr(Path, "exists", exists)

    with pytest.raises(ScannerError, match="would be read as"):
        _add_back_with(scanner, source, tmp_path, b".GITLEAKSIGNORE:github-pat:2\n")
