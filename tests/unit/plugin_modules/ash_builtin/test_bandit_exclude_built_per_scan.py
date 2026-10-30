# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""bandit's ``--exclude`` is assembled for each scan, with the global ignore paths.

The value was built once, when the scanner was constructed, from the known ignore
paths and ``scanners.bandit.options.excluded_paths``. ``_execute_scan`` then added
the scan's ``global_settings.ignore_paths`` to ``excluded_paths``, but nothing
rebuilt the value, so bandit never received them: it read the files the operator
ignored, and its own results file under ``scanners/bandit/`` held their findings
(the aggregated report drops them afterwards).

Now the value is built when the command is assembled. Each global ignore path is
translated to the bandit globs that skip no file it does not cover
(``bandit_exclude_globs``: ``dir/**`` becomes ``<target>/dir/*``, ``pkg/gen_*.py``
becomes ``<target>/pkg/gen_*.py``), anchored at the target as it appears in argv.
bandit 1.9.4 leaves out a walked file when an entry matches it with ``fnmatch`` or
is a substring of its path, and rewrites an entry naming an existing directory to
``<entry>/*``, so an entry that would also leave out a file nobody ignored (a bare
directory, a literal that is a substring of another path) is not passed; ASH still
drops that file's findings after the scan.
"""

from __future__ import annotations

import fnmatch
import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
    BanditScannerConfig,
    BanditScannerConfigOptions,
    bandit_excluded_path_globs,
)

PluginContext.model_rebuild()

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="bandit exclude entries are POSIX paths here"
    ),
]


def _ignore(*paths: str) -> list[IgnorePathWithReason]:
    return [IgnorePathWithReason(path=path, reason="ignored") for path in paths]


def _tree(base: Path, files: list[str]) -> Path:
    source = base / "source"
    for rel in files:
        (source / rel).parent.mkdir(parents=True, exist_ok=True)
        (source / rel).write_text("x = 1\n", encoding="utf-8")
    source.mkdir(exist_ok=True)
    return source


def _scanner(source: Path, base: Path, options=None) -> BanditScanner:
    output = base / "ash-output"
    output.mkdir(exist_ok=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    return BanditScanner(
        context=context,
        config=BanditScannerConfig(options=options or BanditScannerConfigOptions()),
    )


def _entries(argv: list[str]) -> list[str]:
    (token,) = [a for a in argv if str(a).startswith("--exclude=")]
    return token[len("--exclude=") :].split(",")


def _excluded(path: str, entries: list[str]) -> bool:
    """The exclusion half of bandit 1.9.4's ``_is_file_included``."""
    return any(fnmatch.fnmatch(path, e) for e in entries) or any(
        e in path for e in entries
    )


def test_a_global_ignore_path_reaches_bandit(tmp_path):
    source = _tree(
        tmp_path,
        ["app.py", "thirdparty/bad.py", "thirdparty/sub/deep.py", "thirdparty2/x.py"],
    )
    scanner = _scanner(source, tmp_path)

    argv, _, _ = scanner._execute_scan(source, "source", _ignore("thirdparty/**"))

    entries = _entries(argv)
    root = source.as_posix()
    assert f"{root}/thirdparty/*" in entries
    for rel in ("thirdparty/bad.py", "thirdparty/sub/deep.py"):
        assert _excluded(f"{root}/{rel}", entries), rel
    for rel in ("app.py", "thirdparty2/x.py"):
        assert not _excluded(f"{root}/{rel}", entries), rel


def test_a_partly_ignored_directory_is_passed_as_its_glob(tmp_path):
    source = _tree(tmp_path, ["pkg/gen_a.py", "pkg/gen_b.py", "pkg/real.py"])
    scanner = _scanner(source, tmp_path)

    argv, _, _ = scanner._execute_scan(source, "source", _ignore("pkg/gen_*.py"))

    entries = _entries(argv)
    root = source.as_posix()
    assert f"{root}/pkg/gen_*.py" in entries
    assert _excluded(f"{root}/pkg/gen_a.py", entries)
    assert _excluded(f"{root}/pkg/gen_b.py", entries)
    assert not _excluded(f"{root}/pkg/real.py", entries)


def test_an_entry_that_would_leave_out_another_file_is_not_passed(tmp_path):
    """x.py is ignored, x.pyw is not: the entry for x.py is a substring of x.pyw."""
    source = _tree(tmp_path, ["x.py", "x.pyw", "y.py"])
    scanner = _scanner(source, tmp_path)

    argv, _, _ = scanner._execute_scan(source, "source", _ignore("x.py", "y.py"))

    entries = _entries(argv)
    root = source.as_posix()
    assert not _excluded(f"{root}/x.pyw", entries)
    assert _excluded(f"{root}/y.py", entries)


def test_the_value_is_built_for_each_scan_and_not_kept(tmp_path):
    source = _tree(tmp_path, ["a/x.py", "b/y.py"])
    scanner = _scanner(source, tmp_path)
    before = [(arg.key, arg.value) for arg in scanner.args.extra_args]
    root = source.as_posix()

    first, _, _ = scanner._execute_scan(source, "source", _ignore("a/**"))
    second, _, _ = scanner._execute_scan(source, "source", _ignore("b/**"))

    assert f"{root}/a/*" in _entries(first)
    assert f"{root}/a/*" not in _entries(second)
    assert f"{root}/b/*" in _entries(second)
    assert [(arg.key, arg.value) for arg in scanner.args.extra_args] == before
    assert scanner.config.options.excluded_paths == []


def test_options_changed_after_construction_reach_bandit(tmp_path):
    """configure() replaces the config; the value read at init would be stale."""
    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(source, tmp_path)
    scanner.configure(
        BanditScannerConfig(
            options=BanditScannerConfigOptions(excluded_paths=_ignore("generated"))
        )
    )

    argv, _, _ = scanner._execute_scan(source, "source", [])

    entries = _entries(argv)
    for entry in bandit_excluded_path_globs(source.as_posix(), "generated"):
        assert entry in entries, entry


def test_the_operators_and_the_known_exclusions_are_still_passed(tmp_path):
    from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS

    source = _tree(tmp_path, ["app.py"])
    scanner = _scanner(
        source,
        tmp_path,
        BanditScannerConfigOptions(excluded_paths=_ignore("vendor")),
    )

    argv, _, _ = scanner._execute_scan(source, "source", [])

    entries = _entries(argv)
    anchor = source.as_posix()
    for entry in bandit_excluded_path_globs(anchor, "vendor"):
        assert entry in entries, entry
    for known in KNOWN_IGNORE_PATHS:
        for entry in bandit_excluded_path_globs(anchor, known):
            assert entry in entries, entry


def test_a_converted_target_outside_the_source_gets_no_ignore_entries(tmp_path):
    """Global ignore paths name paths below the source directory."""
    source = _tree(tmp_path, ["app.py"])
    converted = tmp_path / "work" / "converted"
    (converted / "thirdparty").mkdir(parents=True)
    (converted / "thirdparty" / "nb.py").write_text("x = 1\n", encoding="utf-8")
    scanner = _scanner(source, tmp_path)

    argv, _, _ = scanner._execute_scan(converted, "converted", _ignore("thirdparty/**"))

    assert not any("thirdparty" in entry for entry in _entries(argv))


def test_a_link_name_with_a_line_break_refuses_the_target(tmp_path):
    """A key with a line break fails ASH's flag check, which would drop --exclude."""
    source = _tree(tmp_path, ["app.py"])
    outside = tmp_path / "outside.py"
    outside.write_text("x = 1\n", encoding="utf-8")
    (source / "a\nb.py").symlink_to(outside)
    scanner = _scanner(source, tmp_path)

    with pytest.raises(ScannerError) as refused:
        scanner._execute_scan(source, "source", [])

    assert "'a\\nb.py'" in str(refused.value)


def test_many_ignored_files_keep_the_value_inside_one_argument(tmp_path):
    """Linux caps one argument at 128 KiB; the link entries are always kept."""
    names = [f"gen/{'g' * 60}_{index:05d}.py" for index in range(3000)]
    source = _tree(tmp_path, [*names, "gen/keep.py", "app.py"])
    outside = tmp_path / "outside.py"
    outside.write_text("x = 1\n", encoding="utf-8")
    (source / "link_out.py").symlink_to(outside)
    scanner = _scanner(source, tmp_path)

    argv, _, _ = scanner._execute_scan(source, "source", _ignore("gen/g*.py"))

    (token,) = [a for a in argv if str(a).startswith("--exclude=")]
    assert len(token.encode()) < 128 * 1024
    # The link's entry is a glob that matches its path alone (bandit also reads
    # an entry as a plain substring, so the literal path is not what is passed).
    # A broad entry would match the link too, so the two files beside it that
    # nothing excludes are checked the way bandit checks them: not excluded.
    link = f"{source.as_posix()}/link_out.py"
    entries = _entries(argv)
    assert any(fnmatch.fnmatchcase(link, entry) for entry in entries), argv
    assert not _excluded(f"{source.as_posix()}/app.py", entries), entries
    assert not _excluded(f"{source.as_posix()}/gen/keep.py", entries), entries
