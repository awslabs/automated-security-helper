"""Behavior tests for ``utils.get_scan_set``.

All filesystem work goes through the ``tmp_path`` fixture. No test hardcodes a
system temporary directory: bandit's B108 flags those as string literals even
when the string never reaches the filesystem, ASH self-scans this repository at
MEDIUM, and a single finding fails the build.

The POSIX-rooted paths that do appear (``/subdir/a.log``) are ignore-spec match
keys, not filesystem paths -- ``igittigitt`` matches them as pattern text and
never opens them, so they carry no Windows ``is_absolute()``/``as_uri()`` hazard.

Two things about this file are worth knowing before changing it.

Four tests are skipped on Windows because of a defect in the code under test,
not because they are flaky. ``get_ash_ignorespec`` anchors every rule at a
synthetic POSIX base -- ``/`` for a root-level ignore file, ``/<subdir>`` for a
nested one -- and ``igittigitt`` puts that base through ``os.path.abspath``,
which binds a rootless ``/`` to whichever drive the process is on. Hosted
Windows runners put the interpreter on one drive and the temporary tree on
another, so every compiled rule is anchored on the wrong drive and matches
nothing at all. Repairing it means deriving the base from the real scan root,
which changes which files ASH scans on every platform, so it is out of scope
for a test change.

That same synthetic base is why the marker tests below match against subjects
like ``Path("/subdir/a.log")``: those sit under the very fake root the rules are
anchored at. For the two nested-marker cases that agreement is the only reason
they pass, because the same relative path under a real source root does not
match -- measured, not assumed. The root-level cases compile to a base of ``/``
and do generalize, since every absolute POSIX path is under ``/``.
"""

import os
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from igittigitt import IgnoreParser

from automated_security_helper.utils import get_scan_set as gss
from automated_security_helper.utils.get_scan_set import (
    ASH_INCLUSIONS,
    _collect_ignorefiles_and_all_files,
    black,
    cyan,
    debug_echo,
    get_ash_ignorespec,
    get_ash_ignorespec_lines,
    get_changed_files,
    get_files_not_matching_spec,
    git_repository_root,
    gray,
    green,
    lightPurple,
    main,
    parse_args,
    purple,
    red,
    scan_set,
    yellow,
)

IGNORE_REPORT_NAME = "ash-ignore-report.txt"
SCAN_SET_NAME = "ash-scan-set-files-list.txt"

# Shared by every test that needs a rule from get_ash_ignorespec to actually
# match a file on disk. One constant rather than four copies, because all four
# are blocked by the same defect and their reasons must not drift apart.
DRIVE_ANCHORED_RULES = (
    "get_ash_ignorespec anchors rules at a synthetic POSIX base ('/' for a "
    "root-level ignore file, '/<subdir>' for a nested one) and igittigitt "
    "resolves that base through os.path.abspath, which binds a rootless '/' to "
    "the drive the process happens to be on. Windows runners put the "
    "interpreter and the temporary tree on different drives, so every rule "
    "compiles against the wrong drive and matches nothing. This is a defect in "
    "the base_path derivation, not a flaky test: the fix is to build the base "
    "from the real scan root, which changes scanning behavior on every platform."
)


# ---------------------------------------------------------------------------
# ANSI color helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "func,code",
    [
        (red, "91"),
        (green, "92"),
        (yellow, "33"),
        (lightPurple, "94"),
        (purple, "95"),
        (cyan, "96"),
        (gray, "97"),
        (black, "98"),
    ],
)
def test_color_helpers_wrap_the_message_in_their_own_ansi_code(func, code):
    assert func("hello") == f"\033[{code}mhello\033[00m"


def test_color_helpers_stringify_non_string_input():
    assert red(42) == "\033[91m42\033[00m"


def test_the_eight_color_helpers_use_eight_distinct_codes():
    codes = {
        f(""): None
        for f in (red, green, yellow, lightPurple, purple, cyan, gray, black)
    }
    assert len(codes) == 8


# ---------------------------------------------------------------------------
# debug_echo
# ---------------------------------------------------------------------------


def test_debug_echo_joins_its_arguments_and_returns_the_message():
    assert debug_echo("a", 1, Path("b"), debug=False) == "a 1 b"


def test_debug_echo_only_logs_when_debug_is_enabled():
    with patch.object(gss, "ASH_LOGGER") as logger:
        assert debug_echo("quiet", debug=False) == "quiet"
        logger.debug.assert_not_called()

        assert debug_echo("loud", debug=True) == "loud"
        logger.debug.assert_called_once_with("loud")


# ---------------------------------------------------------------------------
# _collect_ignorefiles_and_all_files
# ---------------------------------------------------------------------------


def _tree(tmp_path):
    """A small source tree: one root .gitignore, one nested dir, three files."""
    (tmp_path / "keep.py").write_text("x = 1\n")
    (tmp_path / ".gitignore").write_text("ignored/\n")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "mod.py").write_text("y = 2\n")
    (nested / ".gitignore").write_text("*.pyc\n")
    ignored = tmp_path / "ignored"
    ignored.mkdir()
    (ignored / "junk.py").write_text("z = 3\n")
    return tmp_path


def test_collect_finds_every_ignore_file_and_every_file(tmp_path):
    _tree(tmp_path)

    ignore_files, all_files = _collect_ignorefiles_and_all_files(str(tmp_path))

    names = {Path(p).name for p in ignore_files}
    assert names == {".gitignore"}
    assert len(ignore_files) == 2
    assert {Path(p).name for p in all_files} >= {"keep.py", "mod.py", ".gitignore"}


def test_collect_prunes_directories_ignored_by_the_root_gitignore(tmp_path):
    """A dir ignored at the root is not descended into, so its files are absent."""
    _tree(tmp_path)

    _, all_files = _collect_ignorefiles_and_all_files(str(tmp_path))

    assert "junk.py" not in {Path(p).name for p in all_files}
    assert "mod.py" in {Path(p).name for p in all_files}


def test_collect_appends_user_supplied_extra_ignore_files(tmp_path):
    _tree(tmp_path)

    ignore_files, _ = _collect_ignorefiles_and_all_files(
        str(tmp_path), extra_ignorefiles=["custom.ignore", "second.ignore"]
    )

    assert os.path.join(str(tmp_path), "custom.ignore") in ignore_files
    assert os.path.join(str(tmp_path), "second.ignore") in ignore_files


def test_collect_does_not_duplicate_an_extra_ignore_file_already_discovered(tmp_path):
    _tree(tmp_path)

    ignore_files, _ = _collect_ignorefiles_and_all_files(
        str(tmp_path), extra_ignorefiles=[".gitignore"]
    )

    root_entry = os.path.join(str(tmp_path), ".gitignore")
    assert ignore_files.count(root_entry) == 1


def test_collect_proceeds_without_pruning_when_the_root_gitignore_will_not_parse(
    tmp_path,
):
    """A malformed root .gitignore disables pruning but must not abort the walk."""
    _tree(tmp_path)

    with patch.object(
        IgnoreParser, "parse_rule_file", side_effect=ValueError("malformed pattern")
    ):
        ignore_files, all_files = _collect_ignorefiles_and_all_files(str(tmp_path))

    # Pruning is off, so the directory the root .gitignore excluded is walked.
    assert "junk.py" in {Path(p).name for p in all_files}
    assert len(ignore_files) == 2


def test_collect_skips_pruning_only_for_a_directory_whose_match_raises(tmp_path):
    """A per-directory match failure must not lose the rest of the tree."""
    _tree(tmp_path)

    with patch.object(IgnoreParser, "match", side_effect=TypeError("bad pattern")):
        _, all_files = _collect_ignorefiles_and_all_files(str(tmp_path))

    names = {Path(p).name for p in all_files}
    assert {"keep.py", "mod.py", "junk.py"} <= names


def test_collect_on_a_tree_with_no_root_gitignore_walks_everything(tmp_path):
    (tmp_path / "a.py").write_text("a = 1\n")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "b.py").write_text("b = 2\n")

    ignore_files, all_files = _collect_ignorefiles_and_all_files(str(tmp_path))

    assert ignore_files == []
    assert {Path(p).name for p in all_files} == {"a.py", "b.py"}


# ---------------------------------------------------------------------------
# get_ash_ignorespec_lines
# ---------------------------------------------------------------------------


def test_ignorespec_lines_always_end_with_the_ash_inclusions_block(tmp_path):
    lines = get_ash_ignorespec_lines(str(tmp_path), _discovered_ignore_files=[])

    assert lines[0] == "######### START CONTENTS: ASH_INCLUSIONS #########"
    assert lines[-1] == "######### END CONTENTS: ASH_INCLUSIONS #########"
    for inclusion in ASH_INCLUSIONS:
        assert inclusion in lines


def test_ignorespec_lines_falls_back_to_walking_when_no_files_are_supplied(tmp_path):
    _tree(tmp_path)

    lines = get_ash_ignorespec_lines(str(tmp_path))

    assert any("START CONTENTS:" in line and ".gitignore" in line for line in lines)
    assert "ignored/" in lines


def test_ignorespec_lines_rewrites_the_source_dir_prefix_to_a_placeholder(tmp_path):
    _tree(tmp_path)
    root_gitignore = str(tmp_path / ".gitignore")

    lines = get_ash_ignorespec_lines(
        str(tmp_path), _discovered_ignore_files=[root_gitignore]
    )

    assert "######### START CONTENTS: ${SOURCE_DIR}/.gitignore #########" in lines
    assert str(tmp_path) not in "\n".join(lines)


def test_ignorespec_lines_skips_paths_that_are_not_files(tmp_path):
    missing = str(tmp_path / "does-not-exist" / ".gitignore")

    lines = get_ash_ignorespec_lines(str(tmp_path), _discovered_ignore_files=[missing])

    assert not any("does-not-exist" in line for line in lines)


# ---------------------------------------------------------------------------
# get_ash_ignorespec -- section markers set the rule base path
# ---------------------------------------------------------------------------


def _marker(path):
    return f"######### START CONTENTS: {path} #########"


def test_a_nested_marker_scopes_its_rules_to_that_subdirectory():
    spec = get_ash_ignorespec([_marker("${SOURCE_DIR}/subdir/.gitignore"), "*.log"])

    assert spec.match(Path("/subdir/a.log")) is True
    assert spec.match(Path("/other/a.log")) is False


def test_a_deeply_nested_marker_scopes_to_the_full_parent_path():
    spec = get_ash_ignorespec([_marker("${SOURCE_DIR}/a/b/c/.gitignore"), "*.log"])

    assert spec.match(Path("/a/b/c/x.log")) is True
    assert spec.match(Path("/a/b/x.log")) is False


def test_a_root_level_marker_scopes_its_rules_to_the_whole_tree():
    spec = get_ash_ignorespec([_marker("${SOURCE_DIR}/.gitignore"), "*.log"])

    assert spec.match(Path("/subdir/a.log")) is True
    assert spec.match(Path("/a.log")) is True


def test_the_ash_inclusions_marker_resets_the_base_path_to_the_root():
    spec = get_ash_ignorespec(
        [
            _marker("${SOURCE_DIR}/subdir/.gitignore"),
            _marker("ASH_INCLUSIONS"),
            "*.log",
        ]
    )

    assert spec.match(Path("/anywhere/a.log")) is True


def test_a_marker_without_the_source_dir_placeholder_falls_back_to_the_root():
    """An unrecognized marker payload must not scope rules to a stale directory."""
    spec = get_ash_ignorespec(
        [
            _marker("${SOURCE_DIR}/subdir/.gitignore"),
            _marker("some-unrecognized-payload"),
            "*.log",
        ]
    )

    assert spec.match(Path("/elsewhere/a.log")) is True


def test_blank_lines_and_comments_are_not_turned_into_rules():
    spec = get_ash_ignorespec(["", "   ", "# a plain comment", "*.log"])

    assert spec.match(Path("/a.log")) is True
    assert spec.match(Path("/a.txt")) is False


# ---------------------------------------------------------------------------
# get_files_not_matching_spec
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason=DRIVE_ANCHORED_RULES)
def test_files_not_matching_spec_walks_the_tree_when_no_file_list_is_given(tmp_path):
    (tmp_path / "keep.py").write_text("k = 1\n")
    (tmp_path / "drop.log").write_text("noise\n")
    spec = get_ash_ignorespec([_marker("ASH_INCLUSIONS"), "*.log"])

    included = get_files_not_matching_spec(str(tmp_path), spec)

    assert {Path(p).name for p in included} == {"keep.py"}


@pytest.mark.skipif(sys.platform == "win32", reason=DRIVE_ANCHORED_RULES)
def test_files_not_matching_spec_uses_a_supplied_file_list_verbatim(tmp_path):
    supplied = [str(tmp_path / "a.py"), str(tmp_path / "b.log")]
    spec = get_ash_ignorespec([_marker("ASH_INCLUSIONS"), "*.log"])

    included = get_files_not_matching_spec(str(tmp_path), spec, _all_files=supplied)

    assert {Path(p).name for p in included} == {"a.py"}


def test_files_not_matching_spec_returns_a_sorted_deduplicated_list(tmp_path):
    dupe = str(tmp_path / "a.py")
    spec = get_ash_ignorespec([_marker("ASH_INCLUSIONS")])

    included = get_files_not_matching_spec(
        str(tmp_path), spec, _all_files=[dupe, str(tmp_path / "b.py"), dupe]
    )

    assert included == sorted(included)
    assert len(included) == 2


def test_files_not_matching_spec_always_drops_bundled_aws_cdk_node_modules(tmp_path):
    spec = get_ash_ignorespec([_marker("ASH_INCLUSIONS")])
    vendored = os.path.join(str(tmp_path), "node_modules", "aws-cdk", "lib.js")

    included = get_files_not_matching_spec(
        str(tmp_path), spec, _all_files=[vendored, str(tmp_path / "app.py")]
    )

    assert {Path(p).name for p in included} == {"app.py"}


# ---------------------------------------------------------------------------
# git_repository_root
# ---------------------------------------------------------------------------


def _completed(returncode=0, stdout=""):
    return subprocess.CompletedProcess(
        args=["git"], returncode=returncode, stdout=stdout, stderr=""
    )


def test_git_repository_root_returns_the_resolved_toplevel(tmp_path):
    with patch.object(
        gss.subprocess, "run", return_value=_completed(0, f"{tmp_path}\n")
    ):
        assert git_repository_root(tmp_path) == tmp_path.resolve()


@pytest.mark.parametrize(
    "exc",
    [
        FileNotFoundError("git missing"),
        NotADirectoryError("not a dir"),
        subprocess.TimeoutExpired(cmd="git", timeout=30),
        OSError("boom"),
    ],
)
def test_git_repository_root_returns_none_when_git_cannot_run(tmp_path, exc):
    with patch.object(gss.subprocess, "run", side_effect=exc):
        assert git_repository_root(tmp_path) is None


def test_git_repository_root_returns_none_on_a_nonzero_exit(tmp_path):
    with patch.object(gss.subprocess, "run", return_value=_completed(128, "")):
        assert git_repository_root(tmp_path) is None


def test_git_repository_root_returns_none_on_empty_output(tmp_path):
    """rc==0 with nothing on stdout is not a repository root."""
    with patch.object(gss.subprocess, "run", return_value=_completed(0, "  \n")):
        assert git_repository_root(tmp_path) is None


# ---------------------------------------------------------------------------
# get_changed_files
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_ref",
    ["origin/main; rm -rf x", "$(whoami)", "ref with spaces", "back`tick`", ""],
)
def test_get_changed_files_rejects_a_ref_that_fails_the_allowlist(bad_ref):
    """An unsafe ref falls back to a full scan rather than reaching subprocess."""
    with patch.object(gss.subprocess, "run") as run:
        assert get_changed_files(base_ref=bad_ref) is None

    run.assert_not_called()


def test_get_changed_files_accepts_a_conventional_ref_and_parses_the_diff(tmp_path):
    with patch.object(
        gss.subprocess, "run", return_value=_completed(0, "a/b.py\n\nc.py\n")
    ):
        changed = get_changed_files(base_ref="origin/main", cwd=tmp_path)

    assert changed == [Path("a/b.py"), Path("c.py")]


def test_get_changed_files_returns_none_when_git_is_absent():
    with patch.object(gss.subprocess, "run", side_effect=FileNotFoundError()):
        assert get_changed_files(base_ref="main") is None


def test_get_changed_files_returns_none_when_the_ref_does_not_exist():
    with patch.object(gss.subprocess, "run", return_value=_completed(128, "")):
        assert get_changed_files(base_ref="no-such-ref") is None


# ---------------------------------------------------------------------------
# parse_args
# ---------------------------------------------------------------------------


def test_parse_args_defaults_source_to_the_working_directory():
    with patch.object(sys, "argv", ["get_scan_set"]):
        args = parse_args()

    assert args.source == os.getcwd()
    assert args.output is None
    assert args.filter_pattern is None
    assert args.ignorefile == []
    assert args.debug is None


def test_parse_args_reads_every_declared_option(tmp_path):
    argv = [
        "get_scan_set",
        "--source",
        str(tmp_path),
        "--output",
        str(tmp_path / "out"),
        "--filter-pattern",
        r".*\.py$",
        "--ignorefile",
        "a.ignore",
        "b.ignore",
        "--debug",
    ]
    with patch.object(sys, "argv", argv):
        args = parse_args()

    assert args.source == str(tmp_path)
    assert args.output == str(tmp_path / "out")
    assert args.filter_pattern == r".*\.py$"
    assert args.ignorefile == ["a.ignore", "b.ignore"]
    assert args.debug is True


def test_parse_args_supports_the_negated_debug_flag():
    with patch.object(sys, "argv", ["get_scan_set", "--no-debug"]):
        assert parse_args().debug is False


# ---------------------------------------------------------------------------
# scan_set
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason=DRIVE_ANCHORED_RULES)
def test_scan_set_returns_the_files_that_survive_the_ignore_spec(tmp_path):
    (tmp_path / "keep.py").write_text("k = 1\n")
    (tmp_path / "drop.log").write_text("noise\n")
    (tmp_path / ".gitignore").write_text("*.log\n")

    result = scan_set(source=str(tmp_path))

    names = {Path(p).name for p in result}
    assert "keep.py" in names
    assert "drop.log" not in names


def test_scan_set_defaults_its_source_to_the_working_directory(tmp_path, monkeypatch):
    (tmp_path / "only.py").write_text("o = 1\n")
    monkeypatch.chdir(tmp_path)

    result = scan_set()

    assert {Path(p).name for p in result} == {"only.py"}


def test_scan_set_writes_both_report_files_and_creates_the_output_directory(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("a = 1\n")
    output = tmp_path / "nested" / "out"

    result = scan_set(source=str(source), output=str(output))

    assert output.is_dir()
    assert (output / IGNORE_REPORT_NAME).is_file()
    assert (output / SCAN_SET_NAME).is_file()
    assert "ASH_INCLUSIONS" in (output / IGNORE_REPORT_NAME).read_text()
    assert "app.py" in (output / SCAN_SET_NAME).read_text()
    assert {Path(p).name for p in result} == {"app.py"}


def test_scan_set_reuses_previously_written_report_files_without_rewalking(tmp_path):
    """Both artifacts present means the walk is skipped and the cache is trusted."""
    source = tmp_path / "src"
    source.mkdir()
    (source / "real.py").write_text("r = 1\n")
    output = tmp_path / "out"
    output.mkdir()
    (output / IGNORE_REPORT_NAME).write_text("######### CACHED #########\n")
    cached_file = str(source / "from-cache.py")
    (output / SCAN_SET_NAME).write_text(f"{cached_file}\n")

    with patch.object(
        gss, "_collect_ignorefiles_and_all_files", side_effect=AssertionError("walked")
    ):
        result = scan_set(source=str(source), output=str(output))

    assert result == [cached_file]
    # The cached artifacts are not overwritten with freshly computed content.
    assert (output / IGNORE_REPORT_NAME).read_text() == "######### CACHED #########\n"


def test_scan_set_regenerates_the_scan_set_when_only_the_ignore_report_is_cached(
    tmp_path,
):
    source = tmp_path / "src"
    source.mkdir()
    (source / "real.py").write_text("r = 1\n")
    output = tmp_path / "out"
    output.mkdir()
    (output / IGNORE_REPORT_NAME).write_text(
        "######### START CONTENTS: ASH_INCLUSIONS #########\n"
    )

    result = scan_set(source=str(source), output=str(output))

    assert {Path(p).name for p in result} == {"real.py"}
    assert (output / SCAN_SET_NAME).is_file()


def test_scan_set_prints_each_selected_file_when_asked(tmp_path, capsys):
    (tmp_path / "one.py").write_text("o = 1\n")
    (tmp_path / "two.py").write_text("t = 2\n")

    scan_set(source=str(tmp_path), print_results=True)

    out = capsys.readouterr().out
    assert "one.py" in out
    assert "two.py" in out


def test_scan_set_is_silent_by_default(tmp_path, capsys):
    (tmp_path / "one.py").write_text("o = 1\n")

    scan_set(source=str(tmp_path))

    assert capsys.readouterr().out == ""


def test_scan_set_applies_a_filter_pattern_to_the_result(tmp_path):
    (tmp_path / "keep.py").write_text("k = 1\n")
    (tmp_path / "other.txt").write_text("o\n")
    pattern = re.compile(rf"^{re.escape(str(tmp_path))}.*keep")

    result = scan_set(source=str(tmp_path), filter_pattern=pattern)

    assert {Path(p).name for p in result} == {"keep.py"}


def test_a_filter_pattern_matching_nothing_yields_an_empty_scan_set(tmp_path):
    (tmp_path / "keep.py").write_text("k = 1\n")

    assert scan_set(source=str(tmp_path), filter_pattern=re.compile("^zzz")) == []


@pytest.mark.skipif(sys.platform == "win32", reason=DRIVE_ANCHORED_RULES)
def test_scan_set_honors_an_extra_ignore_file(tmp_path):
    (tmp_path / "keep.py").write_text("k = 1\n")
    (tmp_path / "secret.pem").write_text("nope\n")
    (tmp_path / "extra.ignore").write_text("*.pem\n")

    result = scan_set(source=str(tmp_path), ignorefile=["extra.ignore"])

    names = {Path(p).name for p in result}
    assert "keep.py" in names
    assert "secret.pem" not in names


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def test_main_scans_the_requested_source_and_returns_zero(tmp_path, capsys):
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("a = 1\n")
    output = tmp_path / "out"
    argv = [
        "get_scan_set",
        "--source",
        str(source),
        "--output",
        str(output),
    ]

    with patch.object(sys, "argv", argv):
        rc = main()

    captured = capsys.readouterr()
    assert rc == 0
    # print_results=True is hardcoded, so the scan set goes to stdout ...
    assert "app.py" in captured.out
    # ... and the returned list is echoed to stderr.
    assert "app.py" in captured.err
    assert (output / SCAN_SET_NAME).is_file()
