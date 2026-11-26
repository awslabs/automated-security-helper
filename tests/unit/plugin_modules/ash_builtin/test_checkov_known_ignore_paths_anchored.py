"""The ``--skip-path`` values for ``KNOWN_IGNORE_PATHS`` match whole directory names
below the scanned directory, and no directory above it.

checkov applies each ``--skip-path`` value with ``re.search`` and as a substring
against the walked path (``checkov/common/runners/base_runner.py``,
``filter_ignored_paths``, the same code in 3.4.7 and 3.4.11), and every path it
walks starts with the absolute path of the scanned directory. ``_skipped`` below
applies the values the way checkov does.

Two defects of the earlier values are pinned here. Passed as the bare ``venv/``,
the value skipped every file under any directory whose name merely ends in
``venv`` (``devenv/``, ``prevenv/``) and ``node_modules/`` every file under
``old_node_modules/``. Passed as ``/venv/``, it fixed that and still matched a
directory above the scanned one: a target below ``/home/me/venv`` had every entry
removed, checkov read nothing, and the scan read as clean. The values are now built
for each scan from the scanned directory's path (``_known_directory_skip_values``):
``<root>/<name>/`` for a known directory directly below it and
``<root>/.{0,}/<name>/`` for one deeper.

The values hold no ``^``, no group and no alternation. A Windows launch route that
re-read the command line through cmd.exe split the earlier ``(^|/)`` form at its
unquoted ``|`` (the Install Method Validation failure), cmd.exe consumes an unquoted
``^`` as its escape character, and a parenthesis can unbalance the regex checkov's
terraform module finder joins from the values. ASH sends none of them on Windows,
where checkov's walked paths are not ``/``-joined.
"""

from __future__ import annotations

import logging
import os
import re
import string
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    checkov_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    _known_directory_skip_values,
    _module_finder_compiles,
    _skip_path_root,
    _skip_path_text,
    _under_a_known_ignore_path,
)

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

posix_only = pytest.mark.skipif(
    os.sep != "/", reason="the values are sent on POSIX only"
)
needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)

#: A scanned directory, as ``_skip_path_root`` spells it.
ROOT = "/repo"


def _skipped(patterns, path: str) -> bool:
    """checkov's test: a regex search or a substring match on the walked path."""
    return any(re.search(p, path) or p in path for p in patterns)


def _values(root: str = ROOT) -> list[str]:
    """The values for a scanned directory spelled ``root``."""
    return _known_directory_skip_values(root)


def _scanner(source: Path, output: Path) -> CheckovScanner:
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    return CheckovScanner(context=context, config=CheckovScannerConfig())


def _argv_skip_values(argv) -> list[str]:
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--skip-path"]


def _source(base: Path, *links: str) -> Path:
    """``base/src`` with a link to a file outside it at each of ``links``."""
    base.mkdir(parents=True, exist_ok=True)
    outside = base / "outside.tf"
    outside.write_text("", encoding="utf-8")
    source = base / "src"
    source.mkdir()
    for relative in links:
        link = source / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(outside)
    return source


# ---------------------------------------------------------------------------
# What the values match
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/repo/devenv/main.tf",
        "/repo/prevenv/main.tf",
        "/repo/old_node_modules/stack.yaml",
        "/repo/my.venv/main.tf",
        "/repo/venvx/main.tf",
        "/repo/sub/devenv/main.tf",
        "/repo/sub/old_node_modules/stack.yaml",
    ],
)
def test_a_directory_whose_name_only_ends_in_a_known_name_is_scanned(path):
    values = _values()
    assert values, "KNOWN_IGNORE_PATHS produced no --skip-path values"
    assert not _skipped(values, path), (
        f"{path} is skipped by {values!r}; at the base the bare 'venv/' and "
        "'node_modules/' matched it as a substring"
    )


@pytest.mark.parametrize(
    "path",
    [
        "/repo/venv/lib/main.tf",
        "/repo/.venv/lib/main.tf",
        "/repo/node_modules/pkg/stack.yaml",
        "/repo/sub/venv/main.tf",
        "/repo/node_modules/a/node_modules/b/main.tf",
        "/repo/a/b/c/.venv/lib/main.tf",
    ],
)
def test_the_known_directories_themselves_are_still_skipped(path):
    values = _values()
    assert _skipped(values, path), f"{path} is not skipped by {values!r}"


@pytest.mark.parametrize("ancestor", ["venv", ".venv", "node_modules"])
def test_a_component_of_the_target_or_above_it_is_never_matched(ancestor):
    """The defect this file's first paragraph describes, pinned against its fix.

    Every path checkov walks for a target below ``/home/u/<ancestor>`` holds
    ``/<ancestor>/``, so the value that named the directory alone matched all of
    them. The values start with the target's own path, so they match nothing above
    it.
    """
    root = f"/home/u/{ancestor}/proj"
    values = _values(root)
    paths = [f"{root}/main.tf", f"{root}/sub/main.tf", f"{root}/devenv/main.tf"]
    unanchored = [f"/{_skip_path_text(ancestor)}/"]
    for path in paths:
        # The control: the earlier value skips each of them, so a regression to it
        # turns the assertion below red.
        assert _skipped(unanchored, path), (unanchored, path)
        assert not _skipped(values, path), f"{path} is skipped by {values!r}"
    # Known directories below the target are still skipped, at both depths.
    assert _skipped(values, f"{root}/venv/x.tf")
    assert _skipped(values, f"{root}/sub/node_modules/x.tf")


@pytest.mark.parametrize("name", ["venv", ".venv", "node_modules"])
def test_a_target_that_is_itself_named_like_a_known_directory_is_scanned(name):
    root = f"/home/u/{name}"
    values = _values(root)
    assert not _skipped(values, f"{root}/main.tf")
    assert not _skipped(values, f"{root}/sub/main.tf")
    # One of the same name inside it is a known directory below the target.
    assert _skipped(values, f"{root}/{name}/x.tf")
    assert _skipped(values, f"{root}/sub/{name}/x.tf")


def test_a_root_level_directory_under_an_absolute_target_is_skipped():
    # ASH always hands checkov an absolute target (_execute_scan's abspath), so
    # every walked path starts with the target's own path and a known directory at
    # the scan root is the directly-below value, for the filesystem root too.
    assert _skipped(_values(""), "/venv/lib/main.tf")
    assert _skipped(_values(""), "/a/b/.venv/lib/main.tf")
    assert _skipped(_values(ROOT), "/repo/.venv/bin/template.yaml")
    assert not _skipped(_values(""), "/devenv/lib/main.tf")


def test_the_one_uncovered_shape_is_a_relative_root_named_like_a_known_dir():
    """A RELATIVE walked path is matched by no value, pinned on purpose.

    Every value starts with the scanned directory's absolute path, so a walked
    path that is relative, such as a scan root directly named ``venv`` scanned by
    a relative path, matches none. For that scan root this is the contract: a
    target named like a known directory is scanned. No ASH invocation produces such
    a path: ``_execute_scan`` makes the target absolute and checkov runs from the
    filesystem root, so this is a limit of the values, not of the scan. If this test
    ever matters, the walked paths stopped being absolute.
    """
    assert not _skipped(_values(), "venv/main.tf")
    assert not _skipped(_values(""), "venv/main.tf")
    assert not _skipped(_values(), "sub/venv/main.tf")


def test_a_newline_above_a_known_directory_leaves_it_unmatched():
    """The limit of ``.{0,}``, which does not match a newline, pinned on purpose.

    A known directory below one whose name holds a newline is read by checkov, and
    the link filter says so, so a link there is not taken for skipped.
    """
    values = _values()
    assert not _skipped(values, "/repo/a\nb/venv/x.tf")
    # A newline below the known directory, or none, changes nothing.
    assert _skipped(values, "/repo/venv/a\nb/x.tf")
    assert _skipped(values, "/repo/a/venv/x.tf")
    assert not _under_a_known_ignore_path("a\nb/venv/x.tf")
    assert not _under_a_known_ignore_path("a\nb/c/node_modules/x.tf")
    assert _under_a_known_ignore_path("venv/a\nb/x.tf")
    assert _under_a_known_ignore_path("a/venv/x.tf")


# ---------------------------------------------------------------------------
# The shape of the values
# ---------------------------------------------------------------------------


def test_every_known_ignore_path_is_anchored_to_a_path_component():
    """Each value starts at the scanned directory and names a whole directory."""
    values = _values()
    assert len(values) == 2 * len(KNOWN_IGNORE_PATHS), values
    pairs = zip(KNOWN_IGNORE_PATHS, zip(values[::2], values[1::2]))
    for entry, (directly_below, deeper) in pairs:
        name = entry.strip("/").replace(".", "[.]")
        assert directly_below == f"/repo/{name}/"
        assert deeper == f"/repo/.{{0,}}/{name}/"
    for value in values:
        assert value.startswith("/repo/"), value
        assert value.endswith("/"), value
        assert "\\." not in value, f"{value!r}: a dot is written [.], never \\."
        assert "^" not in value and "|" not in value, value
        assert "(" not in value and ")" not in value, value


def test_every_known_ignore_value_survives_a_cmd_exe_re_read():
    """No value ASH writes holds a character cmd.exe acts on when it re-reads a line.

    ``< > | & ^ ( )`` act when written bare (``subprocess_utils``'s
    ``_CMD_CHARACTERS``), and ``%`` can pair into a variable name: the
    ``(^|/)`` form was split at its ``|`` by a batch interpreter below
    ``uv tool run`` on windows-latest, and an unquoted ``^`` is cmd.exe's
    escape character, consumed silently. ASH sends no known-directory value on
    Windows now, so none reaches that launch route; the values it writes for a
    POSIX root are kept free of these characters all the same, as a root with one
    brings it in escaped and ASH adds none.
    """
    for value in _values():
        acted_on = set(value) & set("<>|&^()%\"' \t")
        assert not acted_on, f"{value!r} holds {sorted(acted_on)!r}"


def test_the_scanners_own_skip_values_are_the_portable_component_anchors():
    """The exact values, for a root such as ``/repo`` and for the filesystem root.

    One pair per ``KNOWN_IGNORE_PATHS`` name, in its order: ``<root>/<name>/`` and
    ``<root>/.{0,}/<name>/`` with dots as ``[.]``, the root's own text escaped
    first. The filesystem root is the empty string (``_skip_path_root``), so its
    values start with a single ``/``, not ``//``.
    """
    assert _values("/repo") == [
        "/repo/[.]venv/",
        "/repo/.{0,}/[.]venv/",
        "/repo/venv/",
        "/repo/.{0,}/venv/",
        "/repo/node_modules/",
        "/repo/.{0,}/node_modules/",
    ]
    assert _values("") == [
        "/[.]venv/",
        "/.{0,}/[.]venv/",
        "/venv/",
        "/.{0,}/venv/",
        "/node_modules/",
        "/.{0,}/node_modules/",
    ]
    assert _skip_path_root(Path("/")) == ""
    assert _values(_skip_path_root(Path("/home/me/my.proj"))) == [
        "/home/me/my[.]proj/[.]venv/",
        "/home/me/my[.]proj/.{0,}/[.]venv/",
        "/home/me/my[.]proj/venv/",
        "/home/me/my[.]proj/.{0,}/venv/",
        "/home/me/my[.]proj/node_modules/",
        "/home/me/my[.]proj/.{0,}/node_modules/",
    ]


@posix_only
def test_the_scanners_own_argv_carries_the_values_for_its_target(tmp_path):
    """The argv-level pin: what a real scan puts in its arguments, in this order,
    and nothing else under the default config."""
    source = tmp_path / "src"
    source.mkdir()
    argv, _, _ = _scanner(source, tmp_path / "out")._execute_scan(source, "source", [])
    expected = _values(_skip_path_root(source))
    assert _argv_skip_values(argv) == expected
    assert expected[0] == f"{_skip_path_text(source.as_posix())}/[.]venv/"


def test_the_known_directory_values_are_built_per_scan_not_at_construction(tmp_path):
    """They depend on the target, which construction does not know, so the
    arguments built at construction hold the config file's and the operator's
    values only: none under the default config."""
    source = tmp_path / "src"
    source.mkdir()
    scanner = _scanner(source, tmp_path / "out")
    held = [a.key for a in scanner.args.extra_args if a.key.startswith("--skip-path")]
    assert held == []


# ---------------------------------------------------------------------------
# checkov's terraform module finder
# ---------------------------------------------------------------------------

_ROOTS = [
    "",
    "/repo",
    "/home/u/proj",
    "/a.b/c-d",
    "/x y/z",
    "/w+x/q",
    "/r[1]/s",
    "/t{2}/u",
    "/a|b/c",
    "/m$n/o",
    "/p?q/r",
    "/s*t/u",
    "/h#i/j",
    "/c,d/e",
    "/ed's/q",
    '/dq"x/y',
    "/back\\slash/p",
    "/.hidden/p",
    "/a.b.c/d.e",
]


def test_the_anchored_values_compile_in_checkovs_module_finder_regex():
    """checkov joins every value into one regex a character at a time."""
    values = _values()
    assert _module_finder_compiles(values)
    assert _module_finder_compiles([*values, "^/repo/x[.]tf$", "^/repo/out/"])


# The join puts a ``|`` between every two characters, so a root holding a ``|``
# leaves ``||`` inside the character class the list opens, and ``re`` warns of a
# possible set union there (a FutureWarning). The regex still compiles, which is
# what is asserted.
@pytest.mark.filterwarnings("ignore::FutureWarning")
@pytest.mark.parametrize("root", _ROOTS)
def test_the_values_compile_in_checkovs_module_finder_regex(root):
    """checkov joins every value into one regex a character at a time: alone, and
    beside the other shapes the scanner sends (an output directory, a link, an
    ignored directory, an operator value holding a bracket), before and after."""
    values = _values(root)
    assert _module_finder_compiles(values)
    escaped = _skip_path_text(root)
    others = [
        f"^{escaped}/ash\\-out/",
        f"^{escaped}/x[.]tf$",
        f"^{escaped}/vendor/",
        "dir[0-9]",
    ]
    assert _module_finder_compiles([*values, *others])
    assert _module_finder_compiles([*others, *values])


@pytest.mark.filterwarnings("ignore::FutureWarning")
def test_a_root_holding_any_printable_character_but_a_parenthesis_compiles():
    for char in string.printable:
        if char in "()/":
            continue
        root = f"/a{char}b/c"
        assert _module_finder_compiles(_values(root)), repr(char)


@pytest.mark.parametrize("root", ["", "/repo", "/a.b/c-d"])
def test_the_dot_star_spelling_does_not_compile_which_is_why_the_values_count(root):
    """``.*`` after a ``|`` is "nothing to repeat" once an earlier ``]`` has closed
    the character class the joined list opens, and the ``[.]`` of the first value
    does that. ``.{0,}`` is the same regex and compiles."""
    values = _values(root)
    assert _module_finder_compiles(values)
    star = [value.replace(".{0,}", ".*") for value in values]
    assert star != values
    assert not _module_finder_compiles(star)


# ---------------------------------------------------------------------------
# Where the values are not sent
# ---------------------------------------------------------------------------


@posix_only
def test_a_root_holding_a_parenthesis_gets_none_and_a_warning(tmp_path, caplog):
    source = _source(tmp_path / "proj (1)")
    scanner = _scanner(source, tmp_path / "out")
    with caplog.at_level(logging.WARNING, logger="ash"):
        argv, _, _ = scanner._execute_scan(source, "source", [])
    root = _skip_path_root(source)
    assert not set(_values(root)) & set(_argv_skip_values(argv))
    warned = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any(
        root in w and "venv" in w and "node_modules" in w and "will read" in w
        for w in warned
    ), warned
    # Where the path holds none, the same scan sends them and says nothing.
    plain = _source(tmp_path / "plain")
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="ash"):
        argv, _, _ = _scanner(plain, tmp_path / "out")._execute_scan(
            plain, "source", []
        )
    assert set(_values(_skip_path_root(plain))) <= set(_argv_skip_values(argv))
    assert not [r for r in caplog.records if "node_modules" in r.getMessage()]


@posix_only
@needs_symlinks
def test_a_link_under_a_known_directory_keeps_its_own_value_for_a_parenthesis_root(
    tmp_path,
):
    """Without the values that skip ``venv/`` whole, a link under it that leaves the
    tree is in the list: it gets a value of its own, or the target is refused when
    that value breaks checkov's module finder (which depends on the characters of
    the temporary path above the parenthesis, so it is computed here)."""
    source = _source(tmp_path / "proj (1)", "venv/link.tf")
    scanner = _scanner(source, tmp_path / "out")
    assert CheckovScanner._links_leaving_tree(source) == []
    assert CheckovScanner._links_leaving_tree(
        source, known_directories_skipped=False
    ) == ["venv/link.tf"]
    (own_value,) = scanner._link_skip_patterns(source, ["venv/link.tf"])
    if _module_finder_compiles([own_value]):
        argv, _, _ = scanner._execute_scan(source, "source", [])
        assert own_value in _argv_skip_values(argv)
    else:
        with pytest.raises(ScannerError, match="venv/link.tf"):
            scanner._execute_scan(source, "source", [])


@needs_symlinks
def test_links_under_known_directories_stay_in_the_list_when_not_skipped(tmp_path):
    source = _source(
        tmp_path, "app/link.tf", "node_modules/pkg/link.tf", "sub/venv/link.tf"
    )
    assert CheckovScanner._links_leaving_tree(source) == ["app/link.tf"]
    assert CheckovScanner._links_leaving_tree(
        source, known_directories_skipped=True
    ) == ["app/link.tf"]
    assert sorted(
        CheckovScanner._links_leaving_tree(source, known_directories_skipped=False)
    ) == ["app/link.tf", "node_modules/pkg/link.tf", "sub/venv/link.tf"]


@needs_symlinks
def test_a_link_below_a_newline_named_directory_is_not_taken_for_skipped(tmp_path):
    source = _source(tmp_path, "venv/link.tf", "a\nb/venv/link.tf")
    assert CheckovScanner._links_leaving_tree(source) == ["a\nb/venv/link.tf"]


@posix_only
@needs_symlinks
def test_values_that_fail_beside_the_operators_are_left_out_with_a_warning(
    tmp_path, caplog
):
    """The operator's values compile alone, so they are not blamed: the known
    directory values are left out, a warning says checkov will read the
    directories, and the link under one is passed on to get a value of its own."""
    source = _source(tmp_path, "app/link.tf", "venv/link.tf")
    scanner = _scanner(source, tmp_path / "out")
    known = set(_values(_skip_path_root(source)))

    def fails_with_the_known_values(values):
        return not known & set(values)

    with (
        patch.object(
            checkov_scanner, "_module_finder_compiles", fails_with_the_known_values
        ),
        caplog.at_level(logging.WARNING, logger="ash"),
    ):
        argv, _, _ = scanner._execute_scan(source, "source", [])

    given = _argv_skip_values(argv)
    assert not known & set(given)
    root = _skip_path_text(source.as_posix())
    assert f"^{root}/venv/link[.]tf$" in given
    assert f"^{root}/app/link[.]tf$" in given
    assert any(
        "node_modules" in r.getMessage() and "module finder" in r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING
    )


@posix_only
@needs_symlinks
def test_nothing_is_sent_on_windows_and_a_link_under_a_known_directory_refuses(
    tmp_path, monkeypatch
):
    """Run on every OS by faking the separator, as the output-directory test does.

    checkov's walked paths are not ``/``-joined there, so no value could match.
    Without them a link under ``venv/`` that leaves the tree is not taken for
    skipped, and with no way to skip a single file there the target is refused.
    """
    source = _source(tmp_path / "plain")
    scanner = _scanner(source, tmp_path / "out")
    linked = _source(tmp_path / "linked", "venv/link.tf")
    linked_scanner = _scanner(linked, tmp_path / "out2")
    monkeypatch.setattr(checkov_scanner.os, "sep", "\\")

    assert scanner._known_directory_skip_patterns(source) == []
    argv, _, _ = scanner._execute_scan(source, "source", [])
    assert not set(_values(_skip_path_root(source))) & set(_argv_skip_values(argv))

    with pytest.raises(ScannerError, match="venv/link.tf"):
        linked_scanner._execute_scan(linked, "source", [])


# ---------------------------------------------------------------------------
# The output directory's own value
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.sep != "/", reason="the output-dir exclusion is POSIX-only")
def test_the_output_dir_value_skips_no_deeper_path_holding_the_same_text(tmp_path):
    """An in-tree output directory's value is anchored at the start of the path.

    Unanchored, the escaped output path also matched a deeper path that holds
    the same text, such as a copy of the tree kept under itself.
    """
    source = tmp_path / "src"
    output = source / "ash-out"
    output.mkdir(parents=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    scanner = CheckovScanner(context=context, config=CheckovScannerConfig())
    argv, _, _ = scanner._execute_scan(source, "source", [])
    values = _argv_skip_values(argv)
    # The value is an escaped regex, so the hyphen is written "\-" (re.escape).
    output_values = [v for v in values if re.escape("ash-out") in v]
    assert output_values, values
    assert all(v.startswith("^") for v in output_values), output_values

    root = source.as_posix()
    assert _skipped(values, f"{root}/ash-out/ash.log")
    deeper = f"{root}/copy{root}/ash-out/ash.log"
    assert not _skipped(values, deeper), (
        f"{deeper} is skipped by {output_values!r}; at the base the unanchored "
        "value matched the output path's text anywhere in a walked path"
    )
