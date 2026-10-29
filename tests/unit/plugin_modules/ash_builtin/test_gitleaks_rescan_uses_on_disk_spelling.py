# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The gitleaks re-scan copies each named file under the spelling the tree lists.

gitleaks walks the directory and reports each file by the name the directory
lists. A ``.gitleaksignore`` entry can spell that name in another letter case,
and on a case-insensitive filesystem (macOS and Windows by default) it names
the listed file. The re-scan copied the file under the entry's spelling and
reported it so, which matched none of the first run's results, so every finding
in it was added a second time; two spellings of one file were two copies of one
path, which failed the scan; and an entry naming ``.gitleaksignore`` itself in
another case put a copy of it at the copy tree's root, where gitleaks read it as
the ignore file again and hid the same findings.

The copy now goes under the spelling the directory lists. A case-insensitive
filesystem is stood in for by a ``samefile`` that answers True for two names
differing only in case, so the behavior is measured on every platform; on a
real one the stand-in changes nothing.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    gitleaks_scanner as module,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
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


def test_another_case_is_the_listed_spelling_only_where_it_is_the_same_file(
    tmp_path,
):
    _write(tmp_path, "app/settings.py")
    insensitive = (tmp_path / "APP" / "SETTINGS.PY").exists()
    spelled = GitleaksScanner._on_disk_spelling(tmp_path, "App/Settings.py", {})
    assert spelled == ("app/settings.py" if insensitive else None)


def test_a_differently_cased_entry_is_re_scanned_under_the_listed_spelling(
    tmp_path, monkeypatch
):
    _case_insensitive_names(monkeypatch)
    hidden = _result("app/settings.py", "github-pat", 4, column=18)
    scanner, calls = _rescan_harness(
        tmp_path, monkeypatch, {"app/settings.py": [hidden]}
    )
    source = Path(scanner.context.source_dir)
    _write(source, "app/settings.py")
    (source / ".gitleaksignore").write_text("App/Settings.py:github-pat:4\n")

    assert _add_back(scanner, source, _report(), tmp_path) == [
        ("app/settings.py", "github-pat", 4, 18)
    ]
    assert [call["files"] for call in calls] == [["app/settings.py"]]


def test_a_finding_the_first_run_kept_is_not_added_under_another_case(
    tmp_path, monkeypatch
):
    _case_insensitive_names(monkeypatch)
    kept = _result("app/settings.py", "github-pat", 4, column=18)
    scanner, _ = _rescan_harness(tmp_path, monkeypatch, {"app/settings.py": [kept]})
    source = Path(scanner.context.source_dir)
    _write(source, "app/settings.py")
    (source / ".gitleaksignore").write_text("App/Settings.py:github-pat:4\n")

    assert _add_back(scanner, source, _report(copy.deepcopy(kept)), tmp_path) == [
        ("app/settings.py", "github-pat", 4, 18)
    ]


def test_two_spellings_of_one_file_are_one_copy(tmp_path, monkeypatch):
    _case_insensitive_names(monkeypatch)
    scanner, calls = _rescan_harness(tmp_path, monkeypatch, {})
    source = Path(scanner.context.source_dir)
    _write(source, "app/settings.py")
    (source / ".gitleaksignore").write_text(
        "app/settings.py:github-pat:4\nApp/Settings.py:github-pat:5\n"
    )

    _add_back(scanner, source, _report(), tmp_path)

    assert [call["files"] for call in calls] == [["app/settings.py"]]


def test_the_ignore_file_named_in_another_case_is_re_scanned_alone(
    tmp_path, monkeypatch
):
    """At the copy tree's root, under any spelling a case-insensitive filesystem
    reads as its own, the copy would be read as the ignore file again."""
    _case_insensitive_names(monkeypatch)
    hidden = _result(".gitleaksignore", "github-pat", 2)
    other = _result("app/x.py", "github-pat", 1)
    scanner, calls = _rescan_harness(
        tmp_path, monkeypatch, {".gitleaksignore": [hidden], "app/x.py": [other]}
    )
    source = Path(scanner.context.source_dir)
    _write(source, "app/x.py")
    (source / ".gitleaksignore").write_text(
        ".GitleaksIgnore:github-pat:2\napp/x.py:github-pat:1\n"
    )

    assert _add_back(scanner, source, _report(), tmp_path) == [
        (".gitleaksignore", "github-pat", 2, None),
        ("app/x.py", "github-pat", 1, None),
    ]
    tree, itself = calls
    assert tree["files"] == ["app/x.py"]
    assert itself["argv"][-2:] == ["--", ".gitleaksignore"]
    assert itself["cwd"] != tree["cwd"]
