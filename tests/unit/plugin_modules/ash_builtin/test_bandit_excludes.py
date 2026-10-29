# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""bandit's ``--exclude`` carries the scan's ignore paths and ASH's output directory.

bandit is the scanner that pre-filters by handing its tool an ``--exclude`` list,
so the list is rebuilt for each scan, from the known ignore paths, bandit's own
``excluded_paths``, the global ``ignore_paths`` the scan passes in, and ASH's output
directory: under the default ``.ash/ash_output`` bandit would otherwise read the
converters' output under the source tree as well as in the converted pass, and a
finding in a converted file would appear twice.

Entries anchored at the target the
scan passes to bandit are added for

* each live global ignore path whose bandit glob skips no file the ignore path
  does not cover (bandit matches ``fnmatch`` globs and plain substrings against
  ``<target>/<relative path>``, case-sensitively). A pattern without such a glob
  is left to the SARIF step, which drops its findings after the scan; scanning
  a file the SARIF step then ignores costs time, while skipping one it would
  keep loses findings;
* ASH's output directory, when it sits inside the target. Not for the converted
  target, which lives inside the output directory.
"""

import fnmatch
import glob
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners import bandit_scanner
from automated_security_helper.utils.suppression_matcher import (
    file_path_matches,
    ignore_path_matches,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
    BanditScannerConfig,
    BanditScannerConfigOptions,
)
from automated_security_helper.utils.scan_output_dirs import ash_own_dir_names
from tests.unit.workspace.test_execution import _git
from tests.utils.tool_guard import GIT_PROGRAM_VARIABLES, popen_runs_only_git, real_git

#: Popen's positional parameters after ``args``, by name, for the ones read here.
_POPEN_POSITIONS = {"executable": 1, "shell": 7, "cwd": 8, "env": 9}


def _popen_argument(name, rest, kwargs, default=None):
    if name in kwargs:
        return kwargs[name]
    position = _POPEN_POSITIONS[name]
    return rest[position] if len(rest) > position else default


@pytest.fixture(autouse=True)
def _no_tool_runs(monkeypatch, request):
    """Building a scanner here must not start a tool.

    BanditScanner's construction asks for bandit's version, which ran
    ``uv --version`` and ``uv tool run --from 'bandit[sarif,toml]...' bandit
    --version``: it wrote uv's tool lock and entry-point cache, and with a cold
    uv cache resolved bandit from the index. These tests are about the
    --exclude list, so the version is stubbed. Any process still started through
    ``subprocess.Popen`` is refused and fails the test at teardown (``os.system``,
    ``posix_spawn`` and the like are not intercepted), and the uv runner
    singleton, which caches a failed probe as "uv is not available", is reset so
    a refusal here cannot fail a later test in the same worker.

    The one exception is git in a test that uses ``checkout_context``: its tree
    is a git checkout, and what git says is committed there is what the test is
    about. Every other process those tests start is still refused. git is told by
    the file its argument list resolves to, the one on PATH when the test starts
    (``tool_guard.popen_runs_only_git``), with no shell and no ``executable=``: by
    its name alone, a link named git, another git first on PATH, ``executable=``
    and a shell command line ending in git all ran ``id``. checkout_context keeps
    git from starting anything of its own.
    """
    from automated_security_helper.base.uv_tool_mixin import UVToolMixin
    from automated_security_helper.utils import get_scan_set, scan_output_dirs
    from automated_security_helper.utils.uv_tool_runner import reset_uv_tool_runner

    in_a_checkout = "checkout_context" in request.fixturenames
    monkeypatch.setattr(
        UVToolMixin, "_get_uv_tool_version", lambda self, *args, **kwargs: None
    )
    # Working out which of ASH's output directories to exclude reads the scan set,
    # which asks git which files a repository committed there. The other tests'
    # trees are not repositories, so git's answer is "no committed files", the
    # None that tracked_files_in returns when git cannot answer; stubbed to that.
    if not in_a_checkout:
        for module in (get_scan_set, scan_output_dirs):
            monkeypatch.setattr(module, "tracked_files_in", lambda directory: None)
    started = []
    real_init = subprocess.Popen.__init__
    git = real_git()

    def refuse(popen, args, *rest, **kwargs):
        if in_a_checkout and popen_runs_only_git(
            git,
            args,
            executable=_popen_argument("executable", rest, kwargs),
            shell=_popen_argument("shell", rest, kwargs, False),
            env=_popen_argument("env", rest, kwargs),
            cwd=_popen_argument("cwd", rest, kwargs),
        ):
            return real_init(popen, args, *rest, **kwargs)
        started.append(args)
        raise OSError(f"test refused to start {args!r}")

    monkeypatch.setattr(subprocess.Popen, "__init__", refuse)
    # The refusals so far; a test of the refusal clears what it caused.
    yield started
    reset_uv_tool_runner()
    assert started == [], f"building a scanner started {started}"


@pytest.fixture
def context(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    work = output / "converted"
    work.mkdir()
    return PluginContext(
        source_dir=source, output_dir=output, work_dir=work, config=get_default_config()
    )


@pytest.fixture
def scanner(context):
    return BanditScanner(context=context, config=BanditScannerConfig())


def _entries(final_args):
    (token,) = [a for a in final_args if a.startswith("--exclude=")]
    return token[len("--exclude=") :].split(",")


def _run(scanner, target, *patterns, target_type="source"):
    final_args, _, _ = scanner._execute_scan(
        target=target,
        target_type=target_type,
        global_ignore_paths=[
            IgnorePathWithReason(path=p, reason="ignored") for p in patterns
        ],
    )
    return final_args


ANCHOR = "/work/repo"


@pytest.mark.parametrize(
    "pattern,expected",
    [
        ("vendor/**", ["/work/repo/vendor/*"]),
        ("vendor/", ["/work/repo/vendor/*"]),
        # ASH's matcher drops no ./, so this covers no file of the tree.
        ("./vendor/", []),
        ("./vendor/**", []),
        ("./app.py", []),
        ("third_party/lib/**", ["/work/repo/third_party/lib/*"]),
        ("**/generated/**", ["/work/repo/generated/*", "/work/repo/*/generated/*"]),
        ("**/generated/", ["/work/repo/generated/*", "/work/repo/*/generated/*"]),
        ("src/*.py", ["/work/repo/src/*.py"]),
        # A literal names that path only. As plain text "/work/repo/vendor"
        # would also skip vendor/ and vendored.py, so one character is a class:
        # the glob matches the path itself, and the text occurs in no ordinary
        # path. (These were left to the SARIF step.)
        ("vendor", ["/work/repo/vendo[r]"]),
        ("src/app.py", ["/work/repo/src/app.p[y]"]),
        ("/src/app.py", []),
        ("src/./app.py", []),
        # ** in a shape without an exact bandit glob.
        ("src/**/test_*.py", []),
        ("**/*.py", []),
        ("**", []),
        # bandit splits --exclude on commas.
        ("a,b/**", []),
        ("", []),
        ("/", []),
        # A character class. ASH lower-cases the pattern and the path before
        # matching, which changes what a class means, and bandit does not:
        # measured with bandit 1.9.4, bandit skipped src/b.py for each of these
        # while the ignore path did not cover it.
        ("src/[!A-Z].py", []),
        ("lib/[!a-z]*.py", []),
        ("src/[Z-a].py", []),
        ("src/[ab].py", []),
        # A glob in a directory component of a ** shape.
        ("v*ndor/**", []),
        ("**/ven?or/**", []),
        ("third_party/[l]ib/**", []),
        ("**/a*/b/**", []),
    ],
)
@pytest.mark.unit
def test_translation(pattern, expected):
    assert bandit_scanner.bandit_exclude_globs(ANCHOR, pattern) == expected


@pytest.mark.unit
def test_a_comma_in_the_target_emits_nothing():
    """bandit splits --exclude on commas, so an anchor holding one would split."""
    assert bandit_scanner.bandit_exclude_globs("/work/a,b", "vendor/**") == []


def _context_with_output(tmp_path, output_name):
    source = tmp_path / "src"
    source.mkdir()
    output = source / output_name
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )


@pytest.mark.unit
def test_a_comma_in_the_output_dir_emits_nothing_for_it(tmp_path):
    context = _context_with_output(tmp_path, "out,put")
    scanner = BanditScanner(context=context, config=BanditScannerConfig())
    entries = _entries(_run(scanner, context.source_dir))
    # An entry for "<src>/out,put/*" would reach bandit split in two.
    assert not [e for e in entries if e.endswith("/out") or e.startswith("put")], (
        entries
    )


@pytest.mark.unit
def test_a_comma_in_the_output_dir_is_named_in_a_warning(tmp_path, caplog):
    """The directory is still read by bandit, and its findings dropped after the
    scan; the operator is told why bandit was not asked to skip it, as ferret-scan's
    operator is."""
    import logging

    context = _context_with_output(tmp_path, "out,put")
    scanner = BanditScanner(context=context, config=BanditScannerConfig())
    with caplog.at_level(logging.WARNING):
        _run(scanner, context.source_dir)
    assert any(
        "out,put" in record.getMessage() and record.levelno == logging.WARNING
        for record in caplog.records
    ), [r.getMessage() for r in caplog.records]


@pytest.mark.unit
def test_glob_characters_in_the_output_dir_are_escaped(tmp_path):
    context = _context_with_output(tmp_path, "out[1]")
    scanner = BanditScanner(context=context, config=BanditScannerConfig())
    anchor = glob.escape(Path(context.source_dir).as_posix())
    entries = _entries(_run(scanner, context.source_dir))
    assert f"{anchor}/{glob.escape('out[1]')}/*" in entries, entries
    assert f"{anchor}/out[1]/*" not in entries


@pytest.mark.unit
def test_glob_characters_in_the_target_are_escaped():
    assert bandit_scanner.bandit_exclude_globs("/work/re[po]", "vendor/**") == [
        glob.escape("/work/re[po]") + "/vendor/*"
    ]


@pytest.mark.unit
def test_global_ignore_paths_reach_bandit(scanner, context):
    target = context.source_dir
    anchor = glob.escape(Path(target).as_posix())
    entries = _entries(_run(scanner, target, "vendor/", "**/generated/**"))
    assert f"{anchor}/vendor/*" in entries
    assert f"{anchor}/generated/*" in entries
    assert f"{anchor}/*/generated/*" in entries


@pytest.mark.unit
def test_an_expired_global_ignore_path_does_not(scanner, context):
    final_args, _, _ = scanner._execute_scan(
        target=context.source_dir,
        target_type="source",
        global_ignore_paths=[
            IgnorePathWithReason(
                path="vendor/**", reason="vendored", expiration="2000-01-01"
            )
        ],
    )
    assert not [e for e in _entries(final_args) if "vendor" in e]


@pytest.mark.unit
def test_the_output_directory_is_excluded_from_the_source_pass(scanner, context):
    anchor = glob.escape(Path(context.source_dir).as_posix())
    entries = _entries(_run(scanner, context.source_dir))
    assert f"{anchor}/.ash/ash_output/*" in entries, entries


@pytest.mark.unit
def test_not_from_the_converted_pass(scanner, context):
    """The converted target is inside the output directory; excluding it there
    would exclude everything the converters wrote. Checked by what bandit
    skips: the entries are anchored at the converted target, whose path holds
    ``ash_output`` itself."""
    work = Path(context.work_dir)
    for relative in ("nb.py", "archive/x.py"):
        (work / relative).parent.mkdir(parents=True, exist_ok=True)
        (work / relative).write_text("assert True\n", encoding="utf-8")
    entries = _entries(_run(scanner, work, target_type="converted"))
    assert _bandit_skips(work, entries) == set(), entries


@pytest.mark.unit
def test_ignore_paths_are_not_anchored_at_the_converted_target(scanner, context):
    """Ignore paths are relative to the source directory. Anchored at the
    converted target, "archive/**" would skip the archive converter's whole
    output, whose findings the SARIF step keeps."""
    entries = _entries(
        _run(scanner, context.work_dir, "archive/**", target_type="converted")
    )
    assert not [e for e in entries if "archive" in e], entries


@pytest.mark.unit
def test_an_output_directory_outside_the_target_adds_nothing(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )
    scanner = BanditScanner(context=context, config=BanditScannerConfig())
    entries = _entries(_run(scanner, source))
    assert not [e for e in entries if Path(output).as_posix() in e], entries


@pytest.fixture
def checkout_context(tmp_path, monkeypatch):
    """A source tree holding an earlier run's default output directory, scanned by
    a run whose own output directory is outside the tree.

    The tree is a git checkout with nothing committed in that directory: git then
    says none of its files are the repository's, and it is named as ASH's output.
    Outside a checkout an earlier run's directory is scanned instead
    (tests/unit/test_leftover_output_dir_without_git_is_scanned.py). git runs for
    real here (``_no_tool_runs``), and reads no configuration but the checkout's
    own: a system, global or environment one can name a program git starts itself,
    as a ``!`` alias or ``core.fsmonitor`` does.
    """
    no_config = tmp_path / "empty.gitconfig"
    no_config.write_text("", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(no_config))
    for name in (
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        *GIT_PROGRAM_VARIABLES,
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    source = tmp_path / "src"
    (source / ".ash" / "ash_output" / "reports").mkdir(parents=True)
    assert _git(source, "init", "-q").returncode == 0
    output = tmp_path / "out"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )


@pytest.mark.integration
def test_an_earlier_runs_default_output_dir_is_excluded_too(checkout_context):
    """The directories every other directory-walking scanner skips
    (``ScannerPluginBase._ash_output_dirs_inside``), not only this run's: an
    earlier run's ``.ash/ash_output`` holds its reports and converted files, and
    bandit read them back in."""
    context = checkout_context
    scanner = BanditScanner(context=context, config=BanditScannerConfig())
    anchor = glob.escape(Path(context.source_dir).as_posix())

    entries = _entries(_run(scanner, context.source_dir))

    assert f"{anchor}/.ash/ash_output/*" in entries, entries
    assert scanner._ash_output_dirs_inside(Path(context.source_dir)) == [
        Path(".ash/ash_output")
    ]


@pytest.mark.integration
def test_a_look_alike_deeper_in_the_tree_is_not_excluded(checkout_context):
    """Only the directories ASH names as its own: ``.ash/ash_output`` at the root
    of the source tree, and this run's output directory. One deeper down is the
    tree's own content."""
    context = checkout_context
    (Path(context.source_dir) / "pkg" / ".ash" / "ash_output").mkdir(parents=True)
    scanner = BanditScanner(context=context, config=BanditScannerConfig())

    entries = _entries(_run(scanner, context.source_dir))

    assert not [e for e in entries if "pkg" in e], entries


@pytest.mark.integration
def test_a_default_output_dir_with_committed_files_is_scanned(
    checkout_context, monkeypatch
):
    """A named directory whose files git tracks is in the scan set, so it is
    not skipped, as for every other scanner: only ASH's own directories in it
    are, none of which holds a committed file; the executor drops the results in
    its other files."""
    context = checkout_context
    committed = Path(context.source_dir) / ".ash" / "ash_output" / "kept.py"
    committed.write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(
        "automated_security_helper.utils.scan_output_dirs.scan_set_of",
        lambda _context: [str(committed)],
    )
    scanner = BanditScanner(context=context, config=BanditScannerConfig())
    anchor = glob.escape(Path(context.source_dir).as_posix())

    entries = _entries(_run(scanner, context.source_dir))

    assert f"{anchor}/.ash/ash_output/*" not in entries, entries
    assert {e for e in entries if "ash_output" in e} == {
        f"{anchor}/.ash/ash_output/{name}/*" for name in ash_own_dir_names()
    }, entries


# ---------------------------------------------------------------------------
# In a checkout, git runs and nothing else does
# ---------------------------------------------------------------------------

#: A program that is not git, standing for whatever one passed for git would run.
NOT_GIT = shutil.which("id") or "/usr/bin/id"

POSIX_ONLY = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX links, shells and git config"
)


@POSIX_ONLY
@pytest.mark.integration
def test_the_real_git_runs_in_a_checkout(checkout_context, _no_tool_runs):
    """The control for the refusals below."""
    git = shutil.which("git")
    assert git is not None
    for argv in (["git", "--version"], [git, "--version"]):
        subprocess.run(argv, check=True, capture_output=True)
    assert _no_tool_runs == []


@POSIX_ONLY
@pytest.mark.parametrize(
    "way",
    [
        "a link named git",
        "a git first on PATH",
        "executable=",
        "a shell string ending in git",
        "the real git through a shell",
        "env git",
    ],
)
@pytest.mark.integration
def test_nothing_else_runs_under_gits_name(
    checkout_context, _no_tool_runs, tmp_path, monkeypatch, way
):
    """Each of the first four passed when git was told by its name alone, and ran
    ``id``. A shell given even the real git alone reads its own startup files
    (BASH_ENV, when /bin/sh is bash) first."""
    git = shutil.which("git")
    kwargs = {}
    if way == "a link named git":
        (tmp_path / "links").mkdir()
        (tmp_path / "links" / "git").symlink_to(NOT_GIT)
        args = [str(tmp_path / "links" / "git"), "--version"]
    elif way == "a git first on PATH":
        (tmp_path / "shadow").mkdir()
        (tmp_path / "shadow" / "git").symlink_to(NOT_GIT)
        monkeypatch.setenv(
            "PATH", f"{tmp_path / 'shadow'}{os.pathsep}{os.environ['PATH']}"
        )
        args = ["git", "--version"]
    elif way == "executable=":
        args, kwargs = ["git", "--version"], {"executable": NOT_GIT}
    elif way == "a shell string ending in git":
        args, kwargs = f"{NOT_GIT}; {git}", {"shell": True}
    elif way == "the real git through a shell":
        args, kwargs = [git], {"shell": True}
    else:
        args = ["env", "git", "--version"]

    with pytest.raises(OSError, match="test refused to start"):
        subprocess.run(args, capture_output=True, **kwargs)

    assert len(_no_tool_runs) == 1, _no_tool_runs
    _no_tool_runs.clear()


@pytest.fixture
def operator_git_config(request, tmp_path, monkeypatch):
    """Git configuration the environment running the suite names, set up before the
    checkout is: ``request.param`` is (how, key, value), with how one of "global"
    (GIT_CONFIG_GLOBAL, as a developer's environment may set it), "system"
    (GIT_CONFIG_SYSTEM) or "environment" (GIT_CONFIG_COUNT and its keys). In the
    value, ``{marker}`` is a file the configured command creates, and ``{hook}`` a
    script that creates it. Returns the marker."""
    how, key, value = request.param
    marker = tmp_path / "ran"
    hook = tmp_path / "hook.sh"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    hook.chmod(0o755)
    value = value.format(marker=marker, hook=hook)
    if how == "environment":
        monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", key)
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", value)
    else:
        section, name = key.split(".", 1)
        planted = tmp_path / f"{how}.gitconfig"
        planted.write_text(f'[{section}]\n\t{name} = "{value}"\n', encoding="utf-8")
        variable = "GIT_CONFIG_GLOBAL" if how == "global" else "GIT_CONFIG_SYSTEM"
        monkeypatch.setenv(variable, str(planted))
    return marker


ROUTES = ("global", "system", "environment")


@POSIX_ONLY
@pytest.mark.parametrize(
    "operator_git_config",
    [(how, "alias.probe", "!touch {marker}") for how in ROUTES],
    ids=ROUTES,
    indirect=True,
)
@pytest.mark.integration
def test_no_alias_from_the_environments_config_runs(
    operator_git_config, checkout_context
):
    """A ``!`` alias is a shell command, which git runs as its own child."""
    subprocess.run(
        ["git", "probe"], cwd=checkout_context.source_dir, capture_output=True
    )

    assert not operator_git_config.exists(), "git ran the configured alias"


@POSIX_ONLY
@pytest.mark.parametrize(
    "operator_git_config",
    [(how, "core.fsmonitor", "{hook}") for how in ROUTES],
    ids=ROUTES,
    indirect=True,
)
@pytest.mark.integration
def test_no_fsmonitor_from_the_environments_config_runs(
    operator_git_config, checkout_context
):
    """``core.fsmonitor`` names a program git starts for ``git status``."""
    subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=checkout_context.source_dir,
        capture_output=True,
    )

    assert not operator_git_config.exists(), "git ran the configured fsmonitor"


@pytest.mark.unit
def test_the_configured_entries_are_kept(context):
    scanner = BanditScanner(
        context=context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                excluded_paths=[IgnorePathWithReason(path="legacy", reason="r")]
            )
        ),
    )
    entries = _entries(_run(scanner, context.source_dir, "vendor/**"))
    anchor = glob.escape(Path(context.source_dir).as_posix())
    assert f"{anchor}/legacy/*" in entries and f"{anchor}/*/legacy/*" in entries
    assert f"{anchor}/.venv/*" in entries and f"{anchor}/*/.venv/*" in entries


@pytest.mark.unit
def test_one_exclude_token_per_scan_and_none_left_behind(scanner, context):
    before = [a.key for a in scanner.args.extra_args]
    for _ in range(3):
        final_args = _run(scanner, context.source_dir, "vendor/**")
        assert len([a for a in final_args if a.startswith("--exclude=")]) == 1
    assert [a.key for a in scanner.args.extra_args] == before, (
        "the scan's exclude token must not stay on the scanner for the next scan"
    )


def _fake_directories(monkeypatch, directories):
    """Make ``os.path.isdir`` true for these paths too, as bandit reads them.

    bandit rewrites an --exclude entry that names an existing directory to
    ``<entry>/*`` (manager.discover_files). Names with ``*`` or ``?`` cannot
    exist on Windows, so the directories are faked, as the walk is.
    """
    real_isdir = os.path.isdir
    fake = {str(d) for d in directories}
    monkeypatch.setattr(
        os.path, "isdir", lambda path: str(path) in fake or real_isdir(path)
    )


@pytest.mark.parametrize(
    "layout,ignore,excluded",
    [
        # An empty directory literally named "*.md".
        ("docs/*.md", "docs/*.md", None),
        # The same name, holding only a symlink to a directory, which the walk
        # lists as a directory and never descends into.
        ("docs/*.md", "docs/*.md", None),
        # A symlink "*.md" to the target itself.
        ("*.md", "*.md", None),
        ("lib/?", "lib/?", None),
        # The literal form of an excluded_paths file entry.
        ("app.p[y]", None, "app.py"),
    ],
    ids=["empty-dir", "dir-symlink", "symlink-to-root", "question-mark", "class"],
)
@pytest.mark.unit
def test_no_entry_names_an_existing_directory(
    context, monkeypatch, layout, ignore, excluded
):
    """bandit turns such an entry into ``<entry>/*``, which covers the files of
    every directory the glob matches. On each layout (POSIX), bandit 1.9.4 would
    skip a file the ignore path does not cover, so such an entry is left out. A
    pull request can ship the symlink."""
    source = Path(context.source_dir)
    _fake_walk(monkeypatch, str(source), {"": ["setup.py"]})
    _fake_directories(monkeypatch, [os.path.join(str(source), *layout.split("/"))])
    options = BanditScannerConfigOptions(
        excluded_paths=(
            [IgnorePathWithReason(path=excluded, reason="r")] if excluded else []
        )
    )
    scanner = BanditScanner(
        context=context, config=BanditScannerConfig(options=options)
    )
    patterns = [ignore] if ignore else []
    entries = _entries(_run(scanner, source, *patterns))
    named = [e for e in entries if not e.endswith("/*") and os.path.isdir(e)]
    assert not named, named


def _fake_walk(monkeypatch, top, layout):
    """Make the scanner's tree walk see ``layout`` under ``top``.

    ``layout`` maps a directory relative to ``top`` ("" for ``top`` itself) to
    its file names. A real tree can't hold these names on Windows, where ``*``
    and ``?`` are not allowed in a file name, so the walk is faked; the paths
    are joined the way bandit joins them (``os.path.join(root, name)``).

    Top-down, with each directory's subdirectories in the list it yields, and,
    as ``os.walk`` does, descending only into the ones a caller leaves in that
    list. The scan set walks the same tree and prunes ASH's output directory
    that way; a walk that ignored the pruning put the output directory's files
    in the scan set, which made the directory look as if it held committed
    files.
    """
    real_walk = os.walk
    files_in = {}
    children = {}
    for relative, files in layout.items():
        parts = Path(relative).parts if relative else ()
        files_in[parts] = list(files)
        for depth in range(len(parts)):
            names = children.setdefault(parts[:depth], [])
            if parts[depth] not in names:
                names.append(parts[depth])

    def visit(parts):
        dirs = list(children.get(parts, []))
        yield os.path.join(str(top), *parts), dirs, list(files_in.get(parts, []))
        for name in dirs:
            yield from visit(parts + (name,))

    def walk(path, *args, **kwargs):
        if str(path) != str(top):
            yield from real_walk(path, *args, **kwargs)
            return
        yield from visit(())

    monkeypatch.setattr(os, "walk", walk)


@pytest.mark.unit
def test_an_entry_a_path_contains_as_text_is_left_out(context, monkeypatch):
    """bandit skips a path that contains an --exclude entry as plain text too.

    With bandit 1.9.4, ``--exclude=<src>/docs/*.md`` would also skip
    ``<src>/docs/*.md/app.py``, a file in a directory literally named ``*.md``
    that the ignore path ``docs/*.md`` does not cover, so such an entry is left
    out; the SARIF step still applies the ignore path.

    On Windows bandit's paths use ``\\`` and the entries ``/``, so its substring
    test cannot fire there, and the assertion below has nothing to catch.
    """
    source = str(context.source_dir)
    _fake_walk(
        monkeypatch,
        source,
        {"": ["setup.py"], "docs": ["a.md"], os.path.join("docs", "*.md"): ["evil.py"]},
    )
    evil = os.path.join(source, "docs", "*.md", "evil.py")
    assert not file_path_matches("docs/*.md/evil.py", "docs/*.md")

    scanner = BanditScanner(context=context, config=BanditScannerConfig())
    entries = _entries(_run(scanner, context.source_dir, "docs/*.md", "vendor/**"))

    assert not [e for e in entries if e in evil], entries
    anchor = glob.escape(Path(source).as_posix())
    assert f"{anchor}/vendor/*" in entries, entries
    assert f"{anchor}/.ash/ash_output/*" in entries, entries


@pytest.mark.unit
def test_the_output_dir_entry_is_kept_for_paths_inside_it(context, monkeypatch):
    """A directory named ``*`` inside the output directory: the path of a file
    under it holds the entry ``<src>/.ash/ash_output/*`` as text, but it is
    inside the output directory, which the entry is meant to skip, so the entry
    stays.

    On Windows bandit's paths use ``\\`` and the entries ``/``, so its substring
    test cannot fire there, and neither does this check.
    """
    source = str(context.source_dir)
    _fake_walk(
        monkeypatch,
        source,
        {
            "": ["setup.py"],
            os.path.join(".ash", "ash_output", "*", "converted"): ["a.py"],
        },
    )
    scanner = BanditScanner(context=context, config=BanditScannerConfig())
    entries = _entries(_run(scanner, context.source_dir))
    anchor = glob.escape(Path(source).as_posix())
    assert f"{anchor}/.ash/ash_output/*" in entries, entries


@pytest.mark.unit
def test_the_output_dir_entry_is_left_out_when_a_path_outside_contains_it(
    context, monkeypatch
):
    """The entry is an absolute glob. A directory tree below the source that
    repeats the source path ends in a path holding the entry as text, outside
    the output directory, which bandit would then skip."""
    source = str(context.source_dir)
    nested = os.path.join("copy", *Path(source).parts[1:], ".ash", "ash_output", "*")
    _fake_walk(monkeypatch, source, {"": ["setup.py"], nested: ["app.py"]})
    scanner = BanditScanner(context=context, config=BanditScannerConfig())
    entries = _entries(_run(scanner, context.source_dir))
    outside = os.path.join(source, nested, "app.py")
    assert not [e for e in entries if e in outside], entries


# ---------------------------------------------------------------------------
# What bandit skips, by bandit's own rules, on a real tree.
# ---------------------------------------------------------------------------


def _bandit_skips(target, entries):
    """The ``.py`` files under ``target`` that bandit 1.9.4 would skip.

    A copy of bandit's rules (``manager.discover_files`` and
    ``_is_file_included``): an --exclude entry that names an existing directory
    gets ``/*`` appended; a file is skipped when an entry matches its path as
    an ``fnmatch`` glob or is a plain substring of it; the path is
    ``os.path.join(root, name)`` while walking the target as given.
    """
    expanded = [os.path.join(e, "*") if os.path.isdir(e) else e for e in entries]
    skipped = set()
    for root, _dirs, files in os.walk(str(target)):
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            if any(fnmatch.fnmatch(path, e) or e in path for e in expanded):
                skipped.add(Path(path).relative_to(target).as_posix())
    return skipped


TREE = [
    "app.py",
    "app.pyx.py",
    "app.py.d/inner.py",
    "myapp.py",
    "sub/app.py",
    "sub/other.py",
    "vendor/v.py",
    "vendor.py",
    "vendored/x.py",
    "src/vendor/v.py",
    "src/main.py",
    "tests/t.py",
    "src/tests/t.py",
]


def _tree(root):
    for relative in TREE:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("assert True\n", encoding="utf-8")
    return root


def _skipped_for(context, excluded):
    source = _tree(Path(context.source_dir))
    scanner = BanditScanner(
        context=context,
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                excluded_paths=[IgnorePathWithReason(path=excluded, reason="r")]
            )
        ),
    )
    return _bandit_skips(source, _entries(_run(scanner, source)))


@pytest.mark.parametrize(
    "excluded,expected",
    [
        # A file: that file, wherever it sits below the target, and nothing
        # whose path merely starts with its name; not "**/app.py/**", which
        # would match only paths inside a directory named app.py and skip no
        # file.
        ("app.py", {"app.py", "sub/app.py"}),
        ("sub/app.py", {"sub/app.py"}),
        ("./app.py", {"app.py", "sub/app.py"}),
        # A directory: its files, wherever it sits below the target.
        ("vendor", {"vendor/v.py", "src/vendor/v.py"}),
        ("vendor/", {"vendor/v.py", "src/vendor/v.py"}),
        ("vendor/**", {"vendor/v.py", "src/vendor/v.py"}),
        ("**/vendor/**", {"vendor/v.py", "src/vendor/v.py"}),
        ("src/vendor", {"src/vendor/v.py"}),
        # A glob: the files it matches, and the files of directories it matches.
        ("*.pyx.py", {"app.pyx.py"}),
        ("app.py.*", {"app.py.d/inner.py"}),
        ("tests/*", {"tests/t.py", "src/tests/t.py"}),
    ],
)
@pytest.mark.unit
def test_an_excluded_path_skips_what_it_names(context, excluded, expected):
    assert _skipped_for(context, excluded) == expected


@pytest.mark.parametrize(
    "pattern,exact",
    [
        ("app.py", True),
        ("sub/app.py", True),
        # A leading ./ is not dropped, so these cover no file and skip none.
        ("./app.py", True),
        ("./vendor/**", True),
        ("vendor/", True),
        ("vendor/**", True),
        ("**/vendor/**", True),
        ("**/vendor/", True),
        ("src/vendor/", True),
        ("src/*.py", True),
        ("*.pyx.py", True),
        ("tests/*", True),
        # A bare directory name covers nothing in it, so bandit skips nothing.
        ("vendor", True),
        # Left to the SARIF step.
        ("src/**/v.py", False),
        ("[a]pp.py", False),
    ],
)
@pytest.mark.unit
def test_a_global_ignore_path_skips_only_what_it_covers(context, pattern, exact):
    """bandit skips no file the ignore path does not cover, by bandit's rules.

    The SARIF step applies every ignore path afterwards, so skipping fewer only
    costs time; where the form has an exact bandit equivalent (a file, a
    directory, a glob without ``**``), bandit skips exactly what it covers.
    A file gets an entry of its own.
    """
    source = _tree(Path(context.source_dir))
    scanner = BanditScanner(context=context, config=BanditScannerConfig())
    skipped = _bandit_skips(source, _entries(_run(scanner, source, pattern)))
    # What the ignore path covers, read as ASH reads an ignore path.
    covered = {path for path in TREE if ignore_path_matches(path, pattern)}
    assert skipped <= covered, sorted(skipped - covered)
    if exact:
        assert skipped == covered, sorted(covered - skipped)


@pytest.mark.unit
def test_no_entry_skips_files_above_or_beside_the_target(tmp_path):
    """The known directories (``.venv/``, ``venv/``, ``node_modules/``) are
    anchored below the target, so a project inside a directory named ``venv``
    keeps every file in the scan."""
    source = tmp_path / "venv" / "project"
    source.mkdir(parents=True)
    output = tmp_path / "out"
    output.mkdir()
    context = PluginContext(
        source_dir=source, output_dir=output, config=get_default_config()
    )
    _tree(source)
    (source / "venv" / "lib").mkdir(parents=True)
    (source / "venv" / "lib" / "site.py").write_text("x = 1\n", encoding="utf-8")
    scanner = BanditScanner(context=context, config=BanditScannerConfig())
    skipped = _bandit_skips(source, _entries(_run(scanner, source)))
    assert skipped == {"venv/lib/site.py"}
