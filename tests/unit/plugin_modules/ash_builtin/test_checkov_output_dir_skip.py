# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""checkov must not scan ASH's own output directory by default (#628).

ASH hands checkov the whole source directory. With ``--output-dir`` pointed at a
visible directory inside it, checkov parsed ASH's previous reports, and one it
could not read stalled the run until the scan timeout killed it. checkov skips
hidden directories on its own, so the default ``.ash/ash_output`` was never the
problem; these tests use a visible one.

The values are checked the way checkov applies ``--skip-path``
(``filter_ignored_paths`` in ``checkov/common/runners/base_runner.py``): as a
regex with ``re.search`` and as a substring, against ``os.path.join(root, name)``.
"""

import os
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

# checkov joins walked paths with os.sep; the exclusion is POSIX-only, and on
# Windows nothing is emitted (see test_nothing_is_emitted_on_windows).
posix_only = pytest.mark.skipif(os.sep != "/", reason="exclusion is POSIX-only")

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)

PluginContext.model_rebuild()


def _scanner(source: Path, output: Path, work: Path | None = None, **opts):
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=work or output / "converted",
        config=AshConfig(),
    )
    return CheckovScanner(
        context=context,
        config=CheckovScannerConfig(options=CheckovScannerConfigOptions(**opts)),
    )


def _skip_values(argv):
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--skip-path"]


def _skipped(patterns, path: str) -> bool:
    return any(re.search(p, path) or p in path for p in patterns)


@pytest.fixture
def tree(tmp_path):
    source = tmp_path / "src"
    output = source / "ash-out"
    output.mkdir(parents=True)
    return source, output


@posix_only
def test_an_output_dir_inside_the_source_is_skipped(tree):
    source, output = tree
    argv, _, _ = _scanner(source, output)._execute_scan(source, "source", [])

    patterns = _skip_values(argv)
    root = source.as_posix()
    assert _skipped(patterns, os.path.join(root, "ash-out", "ash.log"))
    assert _skipped(patterns, os.path.join(root, "ash-out", "reports", "ash.sarif"))
    # Anchored: a sibling that only shares the prefix is still scanned.
    assert not _skipped(patterns, os.path.join(root, "ash-out-of-tree", "main.tf"))
    assert not _skipped(patterns, os.path.join(root, "main.tf"))


@posix_only
def test_a_nested_output_dir_is_matched_where_checkov_walks_it(tmp_path):
    source = tmp_path / "src"
    output = source / "build" / "ash"
    output.mkdir(parents=True)
    argv, _, _ = _scanner(source, output)._execute_scan(source, "source", [])

    walked = os.path.join(os.path.join(source.as_posix(), "build"), "ash", "x.json")
    assert _skipped(_skip_values(argv), walked)


def test_an_output_dir_outside_the_source_adds_nothing(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    argv, _, _ = _scanner(source, output)._execute_scan(source, "source", [])

    # Every default skip value is relative; an absolute one can only be an
    # output-dir exclusion that should not have been emitted.
    assert not any(Path(v).is_absolute() for v in _skip_values(argv))


def test_the_converted_target_is_not_excluded(tree):
    """work_dir lives under output_dir, so excluding output_dir there would
    exclude every file the converters produced."""
    source, output = tree
    work = output / "converted"
    work.mkdir()
    argv, _, _ = _scanner(source, output, work)._execute_scan(work, "converted", [])

    assert not _skipped(
        _skip_values(argv), os.path.join(work.as_posix(), "notebook.py")
    )


def test_the_default_can_be_turned_off(tree):
    source, output = tree
    scanner = _scanner(source, output, skip_ash_output_dir=False)
    argv, _, _ = scanner._execute_scan(source, "source", [])

    assert not _skipped(
        _skip_values(argv), os.path.join(source.as_posix(), "ash-out", "ash.log")
    )


def test_repeated_scans_do_not_accumulate_the_pattern(tree):
    source, output = tree
    scanner = _scanner(source, output)
    before = list(scanner.args.extra_args)

    first, _, _ = scanner._execute_scan(source, "source", [])
    second, _, _ = scanner._execute_scan(source, "source", [])

    assert first == second
    assert scanner.args.extra_args == before


def _module_finder_regex(skip_paths):
    """The regex checkov 3.3.26's terraform module finder builds from --skip-path
    (``find_modules`` in ``module_loading/module_finder.py``), character by
    character. When it does not compile, the whole terraform scan fails."""
    return re.compile("|".join(f"({skip_paths})"))


@posix_only
@pytest.mark.parametrize(
    "name", ["ash-out", "ash.out", "ash[1]", "a]b", "a{2}|b*c?d+$^"]
)
def test_the_module_finder_regex_compiles(tmp_path, name):
    """For ASH's values alone, and after a user skip_path holding a "]", which
    closes the character class the joined list opens. An unmatched parenthesis
    then breaks it, which is why a path holding one is not emitted (the next
    test)."""
    source = tmp_path / "src"
    output = source / name
    output.mkdir(parents=True)
    argv, _, _ = _scanner(source, output)._execute_scan(source, "source", [])

    values = _skip_values(argv)
    assert any(name in v or re.escape(name) in v for v in values), values
    _module_finder_regex(values)
    _module_finder_regex(["user]dir", *values])


def test_a_path_checkov_cannot_take_is_not_emitted(tmp_path):
    source = tmp_path / "src (copy)"
    output = source / "ash-out"
    output.mkdir(parents=True)
    argv, _, _ = _scanner(source, output)._execute_scan(source, "source", [])

    assert not any("ash-out" in v for v in _skip_values(argv))
    with pytest.raises(re.error):
        # What emitting a path with an unmatched parenthesis would do, after a
        # user skip_path holding a "]". ASH leaves out every path with one.
        _module_finder_regex(["user]dir", re.escape("/t/src (copy/ash-out/")])


def test_nothing_is_emitted_on_windows(tree, monkeypatch):
    """Run on every OS by faking the separator, so the branch is not only
    exercised on the Windows legs."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        checkov_scanner,
    )

    source, output = tree
    scanner = _scanner(source, output)
    monkeypatch.setattr(checkov_scanner.os, "sep", "\\")
    argv, _, _ = scanner._execute_scan(source, "source", [])

    assert not any("ash-out" in v for v in _skip_values(argv))
