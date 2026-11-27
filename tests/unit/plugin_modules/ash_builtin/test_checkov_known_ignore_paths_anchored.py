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
``^`` as its escape character, and an escaped parenthesis or bracket changes the
regex checkov's terraform module finder joins from the values, so a parenthesis or
bracket in the scanned directory's path is written as a class holding it alone. ASH
sends none of them on Windows, where checkov's walked paths are not ``/``-joined.
"""

from __future__ import annotations

import logging
import os
import re
import string
import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    checkov_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    _KNOWN_DIRECTORY_NAMES,
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
    _config_file_sets_all_files_secret_scan,
    _known_directories_checkov_skips,
    _known_directory_skip_values,
    _module_finder_compiles,
    _secrets_all_files_may_be_on,
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


def _scanner(source: Path, output: Path, **opts) -> CheckovScanner:
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    return CheckovScanner(
        context=context,
        config=CheckovScannerConfig(options=CheckovScannerConfigOptions(**opts)),
    )


def _argv_skip_values(argv) -> list[str]:
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--skip-path"]


def _argv_skip_values_in_order(argv) -> list[str]:
    """Every ``--skip-path`` value in ``argv``, in the order checkov is given them:
    the two-token form (the values ASH builds for a scan) and the
    ``--skip-path=<value>`` form (the values of the operator's checkov config file
    and of ``skip_path``)."""
    values = []
    for index, token in enumerate(argv):
        if token == "--skip-path" and index + 1 < len(argv):
            values.append(argv[index + 1])
        elif token.startswith("--skip-path="):
            values.append(token[len("--skip-path=") :])
    return values


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
    """The leading known component of a relative walked path is matched by no value,
    pinned on purpose.

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
    POSIX root are kept free of these characters all the same: a root brings its
    own characters in, and ASH adds none.
    """
    for value in _values():
        acted_on = set(value) & set("<>|&^()%\"' \t")
        assert not acted_on, f"{value!r} holds {sorted(acted_on)!r}"


def test_the_scanners_own_skip_values_are_the_portable_component_anchors():
    """The exact values, for a root such as ``/repo`` and for the filesystem root.

    One pair per ``KNOWN_IGNORE_PATHS`` name, in its order: ``<root>/<name>/`` and
    ``<root>/.{0,}/<name>/`` with dots as ``[.]``, the root's own text escaped
    first. The filesystem root is the empty string (``_skip_path_root``), so its
    values start with a single ``/``, not ``//``. A root that holds a parenthesis or
    a bracket has it written as a class holding it alone, as a dot is, and a space
    is ``re.escape``d: the last two pins are those spellings.
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
    assert _values("/home/me/proj (v1.2)") == [
        r"/home/me/proj\ [(]v1[.]2[)]/[.]venv/",
        r"/home/me/proj\ [(]v1[.]2[)]/.{0,}/[.]venv/",
        r"/home/me/proj\ [(]v1[.]2[)]/venv/",
        r"/home/me/proj\ [(]v1[.]2[)]/.{0,}/venv/",
        r"/home/me/proj\ [(]v1[.]2[)]/node_modules/",
        r"/home/me/proj\ [(]v1[.]2[)]/.{0,}/node_modules/",
    ]
    assert _values("/x/a[b]c") == [
        r"/x/a[\[]b[\]]c/[.]venv/",
        r"/x/a[\[]b[\]]c/.{0,}/[.]venv/",
        r"/x/a[\[]b[\]]c/venv/",
        r"/x/a[\[]b[\]]c/.{0,}/venv/",
        r"/x/a[\[]b[\]]c/node_modules/",
        r"/x/a[\[]b[\]]c/.{0,}/node_modules/",
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


@posix_only
def test_the_known_values_sit_between_the_files_skip_path_and_the_operators(tmp_path):
    """The known-directory values stand where the fixed values they replaced stood.

    checkov's terraform module finder joins every ``--skip-path`` value, in the
    order it is given them, into one regex, and the values before an operator's
    value decide how it is read there. The fixed values came after the ``skip-path``
    values of the operator's checkov config file and before the operator's
    ``skip_path``, so the known values are put in that place too: the file's value
    first, then the six known values, then the operator's.
    """
    source = tmp_path / "src"
    source.mkdir()
    config = tmp_path / "conf" / ".checkov.yaml"
    config.parent.mkdir()
    config.write_text("skip-path:\n  - from-file/\n", encoding="utf-8")
    scanner = _scanner(
        source,
        tmp_path / "out",
        config_file=str(config),
        skip_path=[IgnorePathWithReason(path="from-option/", reason="r")],
    )
    argv, _, _ = scanner._execute_scan(source, "source", [])
    assert _argv_skip_values_in_order(argv) == [
        "from-file/",
        *_values(_skip_path_root(source)),
        "from-option/",
    ]


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

#: Roots that hold a parenthesis or a bracket, which ``_skip_path_text`` writes as a
#: class holding it alone.
_PARENTHESIS_ROOTS = [
    "/home/me/proj (v1.2)",
    "/x/a(b",
    "/x/a)b",
    "/x/a]b(c",
    "/x/a[b(c",
    "/p/[(]/q",
]

#: A root with each printable character in it, none left out.
_PRINTABLE_ROOTS = [f"/a{char}b/c" for char in string.printable]

#: Every root the tests over all roots use. ``dict.fromkeys`` drops the repeats
#: (``/a|b/c`` is in ``_ROOTS`` and in ``_PRINTABLE_ROOTS``) and keeps the order.
_ALL_ROOTS = list(dict.fromkeys([*_ROOTS, *_PRINTABLE_ROOTS, *_PARENTHESIS_ROOTS]))

#: The roots without a newline. A newline in a walked path is the case
#: ``test_a_newline_above_a_known_directory_leaves_it_unmatched`` pins on its own.
_MATCH_ROOTS = [root for root in _ALL_ROOTS if "\n" not in root]

#: The fixed values ASH sent for KNOWN_IGNORE_PATHS before they were anchored to
#: the scanned directory, in their order.
_FIXED_VALUES = ["/[.]venv/", "/venv/", "/node_modules/"]

#: Values the operator's checkov config file can hold before the known values.
_FILE_VALUES = [[], ["from-file/"], ["tests/*"], ["a]b"], ["[x"]]

#: Operator skip_path values whose fate in the module finder depends on what comes
#: before them: some compile only inside the character class the joined list
#: opens, some only outside it.
_OPERATOR_VALUES = [
    "tests/*",
    ".*\\.bak$",
    "test(s)?/",
    "vendor(",
    "a(]b)",
    "^/repo/(build|dist)/",
    "(foo|bar)/",
    "[a-z]+_test\\.tf$",
    "cdk.out",
    "dir[0-9]",
    "x]",
    "[",
    "(",
    ")",
    "]",
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
    # The other shapes are spelled the way their builders spell them
    # (``_link_skip_patterns``, ``_ignore_skip_patterns``): ``re.escape`` with each
    # dot as ``[.]``, not ``_skip_path_text``, which only the known-directory values
    # use. ``_ROOTS`` holds no parenthesis, so both orders still compile.
    escaped = re.escape(root).replace("\\.", "[.]")
    others = [
        f"^{escaped}/ash\\-out/",
        f"^{escaped}/x[.]tf$",
        f"^{escaped}/vendor/",
        "dir[0-9]",
    ]
    assert _module_finder_compiles([*values, *others])
    assert _module_finder_compiles([*others, *values])


@pytest.mark.filterwarnings("ignore::FutureWarning")
@pytest.mark.parametrize("root", _ALL_ROOTS)
def test_the_operators_values_compile_behind_the_values_exactly_as_behind_the_fixed_ones(
    root,
):
    """The known-directory values leave checkov's module finder reading the
    operator's values as the fixed values they replaced did, so the same values
    compile, and the same ones are refused, as before.

    The values compile alone for every root, a parenthesis or a bracket in it
    included: each is written as a class holding it alone, which opens no group and
    leaves no class open wherever the values sit. And behind them (after the
    ``skip-path`` values of the operator's checkov config file, as ``_execute_scan``
    puts them) each operator value compiles exactly when it compiled behind the
    fixed values: both end in a ``[.]`` that leaves the module finder outside a
    character class. ``tests/*`` and ``vendor(`` are refused behind either, and
    ``a(]b)`` compiles behind either.
    """
    values = _values(root)
    assert _module_finder_compiles(values), root
    for file_values in _FILE_VALUES:
        for value in _OPERATOR_VALUES:
            behind_known = _module_finder_compiles([*file_values, *values, value])
            behind_fixed = _module_finder_compiles(
                [*file_values, *_FIXED_VALUES, value]
            )
            assert behind_known == behind_fixed, (
                f"root {root!r}, file values {file_values!r}, operator value "
                f"{value!r}: compiles behind the known values: {behind_known}, "
                f"behind the fixed values: {behind_fixed}"
            )


@pytest.mark.filterwarnings("ignore::FutureWarning")
@pytest.mark.parametrize("root", _MATCH_ROOTS)
def test_the_values_match_below_any_root_and_never_above_it(root):
    """For every root, a parenthesis or a bracket in it included, the values skip a
    known directory below it, at both depths, and nothing else: not a sibling that
    only ends like one, not a file of the root, and not a root that sits below a
    ``venv`` directory.

    A dot, a parenthesis and a bracket of the root are written as a class holding
    it alone, which matches that character only, so the root's own text is matched
    literally."""
    values = _values(root)
    assert _skipped(values, f"{root}/venv/a.tf")
    assert _skipped(values, f"{root}/s/node_modules/a.tf")
    assert _skipped(values, f"{root}/.venv/bin/python")
    assert not _skipped(values, f"{root}/devenv/a.tf")
    assert not _skipped(values, f"{root}/main.tf")
    above = f"/x/venv{root}"
    assert not _skipped(_values(above), f"{above}/main.tf")


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
# A root holding a parenthesis, links, the operator's values and Windows
# ---------------------------------------------------------------------------


@posix_only
def test_a_root_holding_a_parenthesis_gets_the_values_and_no_warning(tmp_path, caplog):
    """A target whose path holds a parenthesis gets the same six values as any
    other, the parenthesis written as a class holding it alone, in one run in the
    argument list, and the scan says nothing about leaving the directories out."""
    source = _source(tmp_path / "proj (v1.2)")
    scanner = _scanner(source, tmp_path / "out")
    with caplog.at_level(logging.WARNING, logger="ash"):
        argv, _, _ = scanner._execute_scan(source, "source", [])
    values = _values(_skip_path_root(source))
    given = _argv_skip_values(argv)
    assert values[0] in given, given
    start = given.index(values[0])
    assert given[start : start + len(values)] == values, given
    assert all("[(]" in value and "[)]" in value for value in values), values
    warned = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert not [w for w in warned if "node_modules" in w], warned


@posix_only
@needs_symlinks
def test_a_virtualenv_in_a_parenthesis_root_is_scanned_without_values_for_its_links(
    tmp_path,
):
    """A target in a root holding a parenthesis is scanned when its ``.venv`` was
    made with the default symlinks: that holds links to the interpreter, which leave
    the tree. Its links get no value of their own, since the values skip ``.venv``
    and ``venv`` whole, so the scan runs and the module finder is asked to compile
    none of them."""
    source = _source(
        tmp_path / "proj (v1.2)",
        ".venv/bin/python",
        ".venv/bin/python3",
        "venv/link.tf",
    )
    # The links are there to be found, and the known directories account for all
    # of them.
    assert CheckovScanner._links_leaving_tree(
        source, skipped_directories=frozenset(), tf_files_skipped=True
    ) == [".venv/bin/python", ".venv/bin/python3", "venv/link.tf"]
    assert (
        CheckovScanner._links_leaving_tree(
            source, skipped_directories=_KNOWN_DIRECTORY_NAMES, tf_files_skipped=True
        )
        == []
    )
    scanner = _scanner(source, tmp_path / "out")
    argv, _, _ = scanner._execute_scan(source, "source", [])
    given = _argv_skip_values(argv)
    assert set(_values(_skip_path_root(source))) <= set(given), given
    link_values = ("python$", "python3$", "link[.]tf$")
    own = [value for value in given if value.endswith(link_values)]
    assert not own, own


@posix_only
@needs_symlinks
def test_a_link_in_a_parenthesis_root_gets_its_own_value_as_before(tmp_path):
    """The link values keep their spelling, and the known values stand before them
    as the fixed values did. Behind them a balanced parenthesis in the root
    compiles, so the link is left out by its own value, and an unbalanced one does
    not, so the target is refused: the two outcomes the target had before the
    values were anchored."""
    source = _source(tmp_path / "proj (v1.2)", "app/shared.tf")
    scanner = _scanner(source, tmp_path / "out")
    (own_value,) = scanner._link_skip_patterns(source, ["app/shared.tf"])
    argv, _, _ = scanner._execute_scan(source, "source", [])
    assert own_value in _argv_skip_values(argv)

    unbalanced = _source(tmp_path / "a(b", "app/link.tf")
    refused = _scanner(unbalanced, tmp_path / "out2")
    with pytest.raises(ScannerError, match="app/link.tf"):
        refused._execute_scan(unbalanced, "source", [])


@posix_only
def test_an_operator_value_that_fails_behind_the_known_values_refuses_as_before(
    tmp_path,
):
    """``tests/*`` puts a ``*`` right after the ``|`` the module finder joins its
    characters with, which is "nothing to repeat" once the ``[.]`` of the first
    ``.venv`` value has closed the character class the joined list opens. It failed
    behind the fixed values these replaced and fails behind the known values, which
    leave the same state, so the target is refused naming ``skip_path``, as it was.
    """
    source = tmp_path / "src"
    source.mkdir()
    (source / "main.tf").write_text("", encoding="utf-8")
    assert not _module_finder_compiles([*_FIXED_VALUES, "tests/*"])
    scanner = _scanner(
        source,
        tmp_path / "out",
        skip_path=[IgnorePathWithReason(path="tests/*", reason="r")],
    )
    with pytest.raises(ScannerError, match="skip_path"):
        scanner._execute_scan(source, "source", [])


@needs_symlinks
def test_links_under_known_directories_stay_in_the_list_when_not_skipped(tmp_path):
    source = _source(
        tmp_path, "app/link.tf", "node_modules/pkg/link.tf", "sub/venv/link.tf"
    )
    assert CheckovScanner._links_leaving_tree(
        source, skipped_directories=_KNOWN_DIRECTORY_NAMES, tf_files_skipped=True
    ) == ["app/link.tf"]
    assert sorted(
        CheckovScanner._links_leaving_tree(
            source, skipped_directories=frozenset(), tf_files_skipped=True
        )
    ) == ["app/link.tf", "node_modules/pkg/link.tf", "sub/venv/link.tf"]


@needs_symlinks
def test_a_link_below_a_newline_named_directory_is_not_taken_for_skipped(tmp_path):
    source = _source(tmp_path, "venv/link.tf", "a\nb/venv/link.tf")
    assert CheckovScanner._links_leaving_tree(
        source, skipped_directories=_KNOWN_DIRECTORY_NAMES, tf_files_skipped=True
    ) == ["a\nb/venv/link.tf"]


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
# Windows: a link under a known directory refuses unless checkov skips it
# ---------------------------------------------------------------------------

#: The variables checkov's own directory rules read.
_CHECKOV_DIRECTORY_VARIABLES = (
    "CKV_IGNORED_DIRECTORIES",
    "CKV_IGNORE_HIDDEN_DIRECTORIES",
    "CKV_SECRETS_SCAN_ENABLE_ALL",
)

#: What checkov skips of the known directories on its own: both under its defaults,
#: one when the rule for the other is off.
_BOTH = frozenset({"node_modules", ".venv"})
_ONLY_NODE_MODULES = frozenset({"node_modules"})
_ONLY_DOT_VENV = frozenset({".venv"})


@pytest.fixture
def checkov_defaults(monkeypatch):
    """The variables checkov's directory rules read, unset, so a row starts from
    checkov's defaults whatever the host sets. A row then sets what it needs."""
    for name in _CHECKOV_DIRECTORY_VARIABLES:
        monkeypatch.delenv(name, raising=False)


def _as_on_windows(monkeypatch) -> None:
    """Fake the separator checkov's walked paths are joined with, as the test above
    does. Called after the scanners are built."""
    monkeypatch.setattr(checkov_scanner.os, "sep", "\\")


@posix_only
@needs_symlinks
def test_on_windows_links_checkov_never_reads_need_no_value_and_do_not_refuse(
    tmp_path, monkeypatch, checkov_defaults
):
    """checkov's own rules skip ``node_modules`` and dot-named directories, so a link
    to a file under ``node_modules`` or ``.venv`` is never read: the scan runs, with
    no ``--skip-path`` value of ASH's."""
    source = _source(
        tmp_path / "linked", "node_modules/pkg/index.js", ".venv/bin/python"
    )
    scanner = _scanner(source, tmp_path / "out")
    # The links are there to be found, and both leave the tree.
    assert CheckovScanner._links_leaving_tree(
        source, skipped_directories=frozenset(), tf_files_skipped=True
    ) == [".venv/bin/python", "node_modules/pkg/index.js"]
    _as_on_windows(monkeypatch)

    argv, _, _ = scanner._execute_scan(source, "source", [])

    assert _argv_skip_values(argv) == []


@posix_only
@needs_symlinks
@pytest.mark.parametrize(
    ("variables", "link", "refused"),
    [
        pytest.param({}, "venv/bin/python", True, id="venv-is-read"),
        pytest.param({}, "node_modules/pkg/main.tf", True, id="tf-under-node_modules"),
        pytest.param({}, ".venv/lib/x.tf", True, id="tf-under-dot-venv"),
        pytest.param(
            {"CKV_IGNORED_DIRECTORIES": ".terraform"},
            "node_modules/pkg/index.js",
            True,
            id="node_modules-left-out-of-the-ignored-list",
        ),
        pytest.param(
            {"CKV_IGNORE_HIDDEN_DIRECTORIES": "false"},
            ".venv/bin/python",
            True,
            id="hidden-directories-are-not-ignored",
        ),
        pytest.param(
            {"CKV_IGNORE_HIDDEN_DIRECTORIES": "false"},
            "node_modules/pkg/index.js",
            False,
            id="node_modules-does-not-depend-on-the-hidden-rule",
        ),
        pytest.param(
            {"CKV_SECRETS_SCAN_ENABLE_ALL": "true"},
            ".venv/bin/python",
            True,
            id="secrets-all-files-reads-dot-venv",
        ),
        pytest.param(
            {"CKV_SECRETS_SCAN_ENABLE_ALL": "true"},
            "node_modules/pkg/index.js",
            False,
            id="secrets-all-files-still-skips-node_modules",
        ),
        pytest.param(
            {"CKV_IGNORED_DIRECTORIES": "node_modules,venv"},
            "venv/bin/python",
            True,
            id="a-list-naming-venv-is-not-counted",
        ),
    ],
)
def test_on_windows_a_link_refuses_exactly_when_checkov_reads_the_file(
    tmp_path, monkeypatch, checkov_defaults, variables, link, refused
):
    """With no value of ASH's to leave one file out, a link that leaves the tree
    stops the scan unless checkov itself skips the directory it is under and the
    file is not one the terraform module finder reads. The variables checkov reads
    for that are the row's."""
    for name, value in variables.items():
        monkeypatch.setenv(name, value)
    source = _source(tmp_path / "linked", link)
    scanner = _scanner(source, tmp_path / "out")
    # The link is there to be found, and leaves the tree.
    assert CheckovScanner._links_leaving_tree(
        source, skipped_directories=frozenset(), tf_files_skipped=True
    ) == [link]
    _as_on_windows(monkeypatch)

    if refused:
        with pytest.raises(ScannerError, match=re.escape(link)):
            scanner._execute_scan(source, "source", [])
    else:
        argv, _, _ = scanner._execute_scan(source, "source", [])
        assert _argv_skip_values(argv) == []


@posix_only
@needs_symlinks
def test_on_windows_a_config_file_that_scans_all_secret_files_makes_dot_venv_refuse(
    tmp_path, monkeypatch, checkov_defaults
):
    """checkov's secrets framework walks ``.venv`` when the operator's config file
    sets ``enable-secret-scan-all-files``. The files are outside the scanned
    directory: a config file inside it is not passed to checkov."""
    on_file = tmp_path / "conf-on" / ".checkov.yaml"
    off_file = tmp_path / "conf-off" / ".checkov.yaml"
    for path, text in ((on_file, "true"), (off_file, "false")):
        path.parent.mkdir()
        path.write_text(f"enable-secret-scan-all-files: {text}\n", encoding="utf-8")
    on = _source(tmp_path / "on", ".venv/bin/python")
    off = _source(tmp_path / "off", ".venv/bin/python")
    scanner_on = _scanner(on, tmp_path / "out-on", config_file=str(on_file))
    scanner_off = _scanner(off, tmp_path / "out-off", config_file=str(off_file))
    # What each scanner read from its file.
    assert scanner_on._config_file_secrets_all_files is True
    assert scanner_off._config_file_secrets_all_files is False
    _as_on_windows(monkeypatch)

    with pytest.raises(ScannerError, match=re.escape(".venv/bin/python")):
        scanner_on._execute_scan(on, "source", [])
    argv, _, _ = scanner_off._execute_scan(off, "source", [])
    assert _argv_skip_values(argv) == []


@posix_only
@needs_symlinks
def test_on_posix_the_known_values_skip_the_directories_whatever_checkov_is_set_to(
    tmp_path, monkeypatch, checkov_defaults
):
    """The values ASH sends on POSIX skip the three directories whole, in every
    walk, so the variables that decide what checkov skips on its own change nothing
    there: the links get no value of their own, and the scan runs."""
    monkeypatch.setenv("CKV_IGNORED_DIRECTORIES", ".terraform")
    monkeypatch.setenv("CKV_IGNORE_HIDDEN_DIRECTORIES", "false")
    monkeypatch.setenv("CKV_SECRETS_SCAN_ENABLE_ALL", "true")
    source = _source(
        tmp_path, "node_modules/pkg/main.tf", ".venv/bin/python", "venv/bin/python"
    )
    # The links are there to be found.
    assert CheckovScanner._links_leaving_tree(
        source, skipped_directories=frozenset(), tf_files_skipped=True
    ) == [".venv/bin/python", "node_modules/pkg/main.tf", "venv/bin/python"]
    scanner = _scanner(source, tmp_path / "out")

    argv, _, _ = scanner._execute_scan(source, "source", [])

    given = _argv_skip_values(argv)
    assert set(_values(_skip_path_root(source))) <= set(given), given
    own = [value for value in given if value.endswith(("main[.]tf$", "python$"))]
    assert not own, own


@posix_only
def test_the_debug_line_on_windows_names_checkovs_variables_and_not_skip_path(
    tmp_path, monkeypatch, caplog
):
    """The line says what checkov skips on its own by the variables that decide it,
    and gives no advice to add the directories to ``skip_path``: those values cannot
    match Windows paths either."""
    source = _source(tmp_path / "plain")
    scanner = _scanner(source, tmp_path / "out")
    _as_on_windows(monkeypatch)

    with caplog.at_level(logging.DEBUG, logger="ash"):
        assert scanner._known_directory_skip_patterns(source) == []

    lines = [record.getMessage() for record in caplog.records]
    named = [line for line in lines if "CKV_IGNORED_DIRECTORIES" in line]
    assert named, lines
    assert "CKV_IGNORE_HIDDEN_DIRECTORIES" in named[0], named
    assert not [line for line in lines if "skip_path" in line], lines


@needs_symlinks
def test_a_tf_link_stays_in_the_list_unless_tf_files_are_skipped(tmp_path):
    """checkov's terraform module finder reads every ``.tf`` file in every directory,
    so where no value skips a directory whole, a ``.tf`` link under a directory
    checkov skips in its framework walks is kept."""
    source = _source(
        tmp_path,
        "node_modules/pkg/index.js",
        "node_modules/pkg/main.tf",
        ".venv/bin/python",
        "venv/lib/x.tf",
    )
    assert CheckovScanner._links_leaving_tree(
        source, skipped_directories=_BOTH, tf_files_skipped=False
    ) == ["node_modules/pkg/main.tf", "venv/lib/x.tf"]
    assert CheckovScanner._links_leaving_tree(
        source, skipped_directories=_BOTH, tf_files_skipped=True
    ) == ["venv/lib/x.tf"]


def test_under_a_known_ignore_path_takes_the_names_it_is_given():
    only_node_modules = frozenset({"node_modules"})
    assert _under_a_known_ignore_path("node_modules/pkg/x.js", only_node_modules)
    assert _under_a_known_ignore_path("venv/node_modules/x.js", only_node_modules)
    assert not _under_a_known_ignore_path("venv/bin/python", only_node_modules)
    assert not _under_a_known_ignore_path(".venv/bin/python", only_node_modules)
    assert not _under_a_known_ignore_path("node_modules/x.js", frozenset())
    # The newline rule holds for whatever names it is given.
    assert not _under_a_known_ignore_path("a\nb/node_modules/x.js", only_node_modules)
    # With no names given it is every known directory, as before.
    assert _under_a_known_ignore_path("venv/bin/python")
    assert _under_a_known_ignore_path(".venv/bin/python")


def test_a_scan_reads_the_environment_once(tmp_path, monkeypatch):
    """The environment that decides which known directories checkov skips on its own
    is the one checkov is started with: one read serves the whole scan."""
    source = _source(tmp_path / "plain")
    scanner = _scanner(source, tmp_path / "out")
    reads = []
    snapshot = checkov_scanner.snapshot_environ

    def counted():
        reads.append(None)
        return snapshot()

    monkeypatch.setattr(checkov_scanner, "snapshot_environ", counted)

    scanner._execute_scan(source, "source", [])

    assert len(reads) == 1


# ---------------------------------------------------------------------------
# What checkov skips on its own, from its environment and its config file
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        pytest.param({}, _BOTH, id="defaults"),
        pytest.param(
            {"CKV_IGNORED_DIRECTORIES": ".terraform"},
            _ONLY_DOT_VENV,
            id="node_modules-left-out-of-the-list",
        ),
        pytest.param(
            {"CKV_IGNORED_DIRECTORIES": "node_modules,venv"},
            _BOTH,
            id="a-list-naming-venv-adds-nothing",
        ),
        pytest.param(
            {"CKV_IGNORED_DIRECTORIES": " node_modules"},
            _ONLY_DOT_VENV,
            id="the-list-is-split-without-stripping",
        ),
        pytest.param(
            {"CKV_IGNORED_DIRECTORIES": ""},
            _ONLY_DOT_VENV,
            id="an-empty-list-names-nothing",
        ),
        *(
            pytest.param(
                {"CKV_IGNORE_HIDDEN_DIRECTORIES": value},
                _ONLY_NODE_MODULES,
                id=f"hidden-{value}",
            )
            for value in ("false", "0", "OFF", "maybe")
        ),
        *(
            pytest.param(
                {"CKV_IGNORE_HIDDEN_DIRECTORIES": value}, _BOTH, id=f"hidden-{value}"
            )
            for value in ("TRUE", "yes", "1")
        ),
        pytest.param(
            {"ckv_ignored_directories": ".terraform"},
            _ONLY_DOT_VENV,
            id="a-lower-case-key-is-the-same-variable",
        ),
        pytest.param(
            {
                "CKV_IGNORED_DIRECTORIES": "node_modules",
                "ckv_ignored_directories": ".terraform",
            },
            _ONLY_DOT_VENV,
            id="two-spellings-with-different-values-cannot-be-told",
        ),
        pytest.param(
            {
                "CKV_IGNORE_HIDDEN_DIRECTORIES": "true",
                "ckv_ignore_hidden_directories": "false",
            },
            _ONLY_NODE_MODULES,
            id="hidden-two-spellings-with-different-values-cannot-be-told",
        ),
        pytest.param(
            {
                "CKV_IGNORE_HIDDEN_DIRECTORIES": "true",
                "ckv_ignore_hidden_directories": "true",
            },
            _BOTH,
            id="two-spellings-with-the-same-value-can-be-told",
        ),
    ],
)
def test_the_known_directories_checkov_skips_follow_its_variables(env, expected):
    assert _known_directories_checkov_skips(env, secrets_all_files=False) == expected


def test_the_secrets_all_files_mode_leaves_only_node_modules():
    skipped = _known_directories_checkov_skips({}, secrets_all_files=True)
    assert skipped == _ONLY_NODE_MODULES


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        pytest.param({}, False, id="unset"),
        *(
            pytest.param(
                {"CKV_SECRETS_SCAN_ENABLE_ALL": value}, False, id=f"off-{value}"
            )
            for value in ("false", "No", "0")
        ),
        *(
            pytest.param(
                {"CKV_SECRETS_SCAN_ENABLE_ALL": value},
                True,
                id=f"on-{value or 'empty'}",
            )
            for value in ("true", "1", "yes", "anything", "")
        ),
        pytest.param(
            {"ckv_secrets_scan_enable_all": "true"}, True, id="a-lower-case-key"
        ),
        pytest.param(
            {
                "CKV_SECRETS_SCAN_ENABLE_ALL": "false",
                "ckv_secrets_scan_enable_all": "true",
            },
            True,
            id="two-spellings-with-different-values-cannot-be-told",
        ),
    ],
)
def test_the_secrets_all_files_mode_may_be_on_by_its_variable(env, expected):
    assert _secrets_all_files_may_be_on(env, config_file_sets_it=False) is expected


def test_a_config_file_that_sets_the_mode_counts_whatever_the_variable_says():
    assert _secrets_all_files_may_be_on({}, config_file_sets_it=True) is True
    off = {"CKV_SECRETS_SCAN_ENABLE_ALL": "false"}
    assert _secrets_all_files_may_be_on(off, config_file_sets_it=True) is True


@pytest.mark.parametrize(
    ("file_values", "expected"),
    [
        pytest.param({}, False, id="absent"),
        pytest.param({"framework": ["terraform"]}, False, id="another-key"),
        pytest.param({"enable-secret-scan-all-files": True}, True, id="true"),
        pytest.param({"enable_secret_scan_all_files": True}, True, id="underscores"),
        pytest.param({"enable-secret-scan-all-files": "true"}, True, id="string-true"),
        pytest.param({"enable-secret-scan-all-files": 1}, True, id="one"),
        pytest.param({"enable-secret-scan-all-files": ""}, True, id="empty-string"),
        pytest.param({"enable-secret-scan-all-files": False}, False, id="false"),
        pytest.param({"enable-secret-scan-all-files": None}, False, id="none"),
        pytest.param({"enable-secret-scan-all-files": 0}, False, id="zero"),
        pytest.param(
            {"enable-secret-scan-all-files": "False"}, False, id="string-false"
        ),
        pytest.param({"enable-secret-scan-all-files": "No"}, False, id="string-no"),
        pytest.param({"enable-secret-scan-all-files": "0"}, False, id="string-zero"),
        pytest.param(
            {
                "enable-secret-scan-all-files": False,
                "enable_secret_scan_all_files": True,
            },
            True,
            id="either-spelling-sets-it",
        ),
    ],
)
def test_a_config_file_sets_the_all_files_mode_unless_it_plainly_says_off(
    file_values, expected
):
    assert _config_file_sets_all_files_secret_scan(file_values) is expected


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
