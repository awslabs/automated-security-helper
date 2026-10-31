# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Readings of ``scan_output_dirs`` at its edges, none of which starts git.

- ``escape_for_pattern`` escapes a trailing space for the gitignore-style GLOB
  syntax, which trims an unescaped one.
- The two warnings said during the walk say the files are scanned as far as the
  ignore files allow, since those are applied after the walk.
- ``_repository_root_of`` compares GIT_CEILING_DIRECTORIES entries with their
  links resolved, as git does and as the walked directory is.
- ``git_index_below`` answers "not a directory" for one that cannot be looked up
  rather than letting a ``PermissionError`` through.
- A checked-out submodule as the output directory is reported as the entry its
  superproject tracks.
- A ``file:`` URI without an authority names the path it holds; a percent-encoded
  relative URI is decoded as the filesystem decodes a name.
- ``output_dirs_to_exclude`` and the drop compare names as the filesystem does, and
  the workspace output directory's own directories are excluded with ASH's.
- A source directory spelled through a link to itself does not reject every
  output-directory candidate.

Every path here is under ``tmp_path``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils import scan_output_dirs, subprocess_utils
from automated_security_helper.utils.scan_output_dirs import (
    PatternSyntax,
    _repository_root_of,
    _result_paths,
    _through_a_link_in_the_tree,
    committed_files_at_results_paths,
    drop_results_in_ash_output_dirs,
    escape_for_pattern,
    git_index_below,
    output_dir_candidates,
    output_dirs_to_exclude,
    warn_about_committed_files,
    warn_about_look_alike,
)
from automated_security_helper.utils.undecodable_text import path_in_record_form

pytestmark = pytest.mark.unit

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


@pytest.fixture(autouse=True)
def no_git_runs_and_none_is_searched_for_above_the_test_directory(
    tmp_path, monkeypatch
):
    """None of these tests starts git, and none may find a repository above its
    own directory. With ``--basetemp`` inside a checkout, or a temporary directory
    under a work tree, the upward search for ``.git`` found the developer's
    checkout, and the tests that stub no git ran the real one against it. The
    test directory is a ceiling (a test that sets its own overrides this), and a
    spawn is recorded and refused: the code under test turns a refused spawn into
    "git could not be run", so the record is what fails the test."""
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", os.path.realpath(tmp_path))
    started: list = []

    def refused(argv, **_kwargs):
        started.append(list(argv))
        raise AssertionError(f"git was started: {argv}")

    monkeypatch.setattr(subprocess_utils, "spawn_run", refused)
    yield
    assert started == []


def test_a_repository_above_the_test_directory_is_not_searched_for(tmp_path):
    tree = Path(os.path.realpath(tmp_path))
    (tree / ".git").mkdir()
    source = tree / "src"
    source.mkdir()

    assert _repository_root_of(source) is None


def test_control_a_repository_in_the_test_directory_is_still_found(tmp_path):
    source = Path(os.path.realpath(tmp_path)) / "src"
    (source / ".git").mkdir(parents=True)

    assert _repository_root_of(source / "deeper") == source


@pytest.mark.parametrize(
    "spelling",
    [
        pytest.param("{empty}{ceiling}", id="leading-empty-entry"),
        pytest.param("{ceiling}{empty}", id="trailing-empty-entry"),
        pytest.param("{empty}{empty}{ceiling}", id="two-leading-empty-entries"),
    ],
)
def test_empty_entries_of_the_ceiling_list_are_skipped_and_the_rest_honored(
    tmp_path, monkeypatch, spelling
):
    tree = Path(os.path.realpath(tmp_path))
    inner = tree / "real" / "outer" / "inner"
    inner.mkdir(parents=True)
    (tree / "real" / "outer" / ".git").mkdir()
    monkeypatch.setenv(
        "GIT_CEILING_DIRECTORIES",
        spelling.format(empty=os.pathsep, ceiling=str(tree / "real" / "outer")),
    )

    assert _repository_root_of(inner) is None


def test_control_a_ceiling_list_of_empty_entries_stops_nothing(tmp_path, monkeypatch):
    tree = Path(os.path.realpath(tmp_path))
    inner = tree / "real" / "outer" / "inner"
    inner.mkdir(parents=True)
    (tree / "real" / "outer" / ".git").mkdir()
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", os.pathsep * 2)

    assert _repository_root_of(inner) == tree / "real" / "outer"


def test_a_trailing_space_is_escaped_for_the_gitignore_style_glob():
    assert escape_for_pattern("out ", PatternSyntax.GLOB, separator="/") == "out\\ "
    assert escape_for_pattern("a b", PatternSyntax.GLOB, separator="/") == "a b"
    assert escape_for_pattern("out ", PatternSyntax.FNMATCH, separator="/") == "out "
    assert escape_for_pattern("out ", PatternSyntax.GLOB, separator="\\") == "out "


def test_the_walk_warnings_say_the_ignore_files_still_apply(monkeypatch):
    said = []
    monkeypatch.setattr(
        scan_output_dirs.ASH_LOGGER, "warning", lambda text: said.append(text)
    )

    warn_about_look_alike("shard-1")
    warn_about_committed_files(".ash/ash_output", 2)

    assert "so it is scanned like the rest of the tree" in said[0]
    assert "as far as the ignore files allow" in said[0]
    assert "They are scanned, as far as the ignore files allow" in said[1]


@needs_symlinks
def test_a_ceiling_spelled_through_a_link_stops_the_walk(tmp_path, monkeypatch):
    tree = Path(os.path.realpath(tmp_path))
    inner = tree / "real" / "outer" / "inner"
    inner.mkdir(parents=True)
    (tree / "real" / "outer" / ".git").mkdir()
    (tree / "link").symlink_to(tree / "real", target_is_directory=True)
    monkeypatch.setenv(
        "GIT_CEILING_DIRECTORIES",
        os.pathsep.join([str(tree / "link" / "outer"), str(tree)]),
    )

    assert _repository_root_of(inner) is None


def test_control_without_the_ceiling_the_repository_above_is_found(
    tmp_path, monkeypatch
):
    tree = Path(os.path.realpath(tmp_path))
    inner = tree / "real" / "outer" / "inner"
    inner.mkdir(parents=True)
    (tree / "real" / "outer" / ".git").mkdir()
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tree))

    assert _repository_root_of(inner) == tree / "real" / "outer"


def test_a_directory_that_cannot_be_looked_up_is_answered_not_asked(
    tmp_path, monkeypatch
):
    # The refusal is confined to the path the function under test builds for
    # itself: patching Path.is_dir on the class would refuse pytest's own
    # teardown lookups too (measured: the test's body passed and its teardown
    # failed on the venue).
    class Refusing(type(Path())):
        def is_dir(self, *args, **kwargs):
            raise PermissionError(13, "Permission denied", str(self))

    monkeypatch.setattr(
        scan_output_dirs, "_absolute", lambda path: Refusing(os.path.abspath(path))
    )

    answer = git_index_below(tmp_path / "out")

    assert answer.names is None
    assert answer.repository is None


@needs_symlinks
def test_the_link_check_takes_a_resolved_root_alone_as_its_other_caller_does(
    tmp_path,
):
    """The form the check had before the spelled root was told apart from the
    resolved one, and the one ``get_scan_set._own_output_of`` passed for a while:
    when it was refused, every scan set raised TypeError with it."""
    root = Path(os.path.realpath(tmp_path)) / "repo"
    (root / "real").mkdir(parents=True)
    (root / "link").symlink_to(root / "real", target_is_directory=True)

    assert _through_a_link_in_the_tree(root / "link" / "out", root) is True
    assert _through_a_link_in_the_tree(root / "real" / "out", root) is False
    # The same answers as the two-root form, the root being its own resolution.
    assert _through_a_link_in_the_tree(root / "link" / "out", root, root) is True
    assert _through_a_link_in_the_tree(root / "real" / "out", root, root) is False


def test_get_scan_sets_own_output_lookup_runs_on_the_shared_link_check(tmp_path):
    """A pin, green before and after: the caller that once raised TypeError on the
    link check's signature answers, whatever form it passes."""
    from automated_security_helper.utils.get_scan_set import _own_output_of

    source = tmp_path / "repo"
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)

    own = _own_output_of(output, source)

    assert own is not None
    assert own.path == os.path.normcase(str(output))
    assert own.identity is not None


def test_a_checked_out_submodule_is_the_entry_its_superproject_tracks(
    tmp_path, monkeypatch
):
    tree = Path(os.path.realpath(tmp_path))
    outer = tree / "outer"
    sub = outer / "sub"
    sub.mkdir(parents=True)
    roots = {sub: sub, outer: outer}
    monkeypatch.setattr(
        scan_output_dirs,
        "_repository_root_of",
        lambda directory: roots.get(Path(directory)),
    )
    listings = {(sub, "."): ["x.txt"], (outer, "sub"): [""]}
    monkeypatch.setattr(
        scan_output_dirs,
        "_index_listing",
        lambda root, relative, **_: (listings[(root, relative)], None, False),
    )

    found = committed_files_at_results_paths(sub)

    assert found == [sub]


def test_a_superproject_that_lists_nothing_at_the_path_does_not_track_the_submodule(
    tmp_path, monkeypatch
):
    """The commonest shape of the question: the directory is a repository of its
    own that a superproject does NOT track (a nested clone, an ignored checkout).
    The superproject answers with an empty list, which is "no", so the directory
    is not reported as the entry; only the files its own index lists at the
    results paths are. The superproject is asked once, about the directory's
    path under it."""
    tree = Path(os.path.realpath(tmp_path))
    outer = tree / "outer"
    sub = outer / "sub"
    sub.mkdir(parents=True)
    roots = {sub: sub, outer: outer}
    monkeypatch.setattr(
        scan_output_dirs,
        "_repository_root_of",
        lambda directory: roots.get(Path(directory)),
    )
    asked = []

    def listing(root, relative, **_):
        asked.append((root, relative))
        if (root, relative) == (sub, "."):
            return ["ash_aggregated_results.json", "x.txt"], None, False
        return [], None, False

    monkeypatch.setattr(scan_output_dirs, "_index_listing", listing)

    found = committed_files_at_results_paths(sub)

    assert found == [sub / "ash_aggregated_results.json"]
    assert asked == [(sub, "."), (outer, "sub")]


def test_control_a_superproject_that_tracks_the_path_adds_the_directory_itself(
    tmp_path, monkeypatch
):
    tree = Path(os.path.realpath(tmp_path))
    outer = tree / "outer"
    sub = outer / "sub"
    sub.mkdir(parents=True)
    roots = {sub: sub, outer: outer}
    monkeypatch.setattr(
        scan_output_dirs,
        "_repository_root_of",
        lambda directory: roots.get(Path(directory)),
    )
    listings = {
        (sub, "."): ["ash_aggregated_results.json"],
        (outer, "sub"): [""],
    }
    monkeypatch.setattr(
        scan_output_dirs,
        "_index_listing",
        lambda root, relative, **_: (listings[(root, relative)], None, False),
    )

    found = committed_files_at_results_paths(sub)

    assert found == [sub, sub / "ash_aggregated_results.json"]


def test_a_superproject_that_gives_no_listing_is_not_read_as_not_tracking(
    tmp_path, monkeypatch
):
    """The directory is a repository of its own, so its superproject is asked once
    whether it tracks the directory's path. git giving no list there is not "no",
    and the refusal must not read it as one: the committed-output check then counts
    what is on disk instead (``GitIndexUnavailable``), as it does when the
    directory's own repository gives no list."""
    tree = Path(os.path.realpath(tmp_path))
    outer = tree / "outer"
    sub = outer / "sub"
    sub.mkdir(parents=True)
    roots = {sub: sub, outer: outer}
    monkeypatch.setattr(
        scan_output_dirs,
        "_repository_root_of",
        lambda directory: roots.get(Path(directory)),
    )

    def listing(root, relative, **_):
        if (root, relative) == (sub, "."):
            return ["x.txt"], None, False
        return None, "git exited with status 128: fatal: index file corrupt", False

    monkeypatch.setattr(scan_output_dirs, "_index_listing", listing)

    with pytest.raises(scan_output_dirs.GitIndexUnavailable) as raised:
        committed_files_at_results_paths(sub)

    assert raised.value.answer.repository == outer
    assert "index file corrupt" in str(raised.value)


def test_control_a_plain_output_directory_in_a_repository_is_not_an_entry(
    tmp_path, monkeypatch
):
    tree = Path(os.path.realpath(tmp_path))
    out = tree / "repo" / "out"
    out.mkdir(parents=True)
    monkeypatch.setattr(
        scan_output_dirs, "_repository_root_of", lambda directory: tree / "repo"
    )
    monkeypatch.setattr(
        scan_output_dirs,
        "_index_listing",
        lambda root, relative, **_: (["x.txt"], None, False),
    )

    assert committed_files_at_results_paths(out) == []


def _located(uri: str) -> SimpleNamespace:
    return SimpleNamespace(
        locations=[
            SimpleNamespace(
                physicalLocation=SimpleNamespace(
                    root=SimpleNamespace(artifactLocation=SimpleNamespace(uri=uri))
                )
            )
        ]
    )


def test_a_file_uri_without_an_authority_names_the_path_it_holds(tmp_path):
    source = Path(os.path.realpath(tmp_path))
    (source / "a.py").write_text("", encoding="utf-8")

    paths = list(
        _result_paths(_located("file:" + (source / "a.py").as_posix()), source)
    )

    assert paths == [source / "a.py"]


@pytest.mark.skipif(
    sys.platform in ("darwin", "win32"), reason="the file system refuses the name"
)
def test_an_encoded_name_that_is_not_utf8_is_decoded_as_the_file_system_decodes_it(
    tmp_path,
):
    source = Path(os.path.realpath(tmp_path))
    name = b"a\xff.txt".decode("utf-8", "surrogateescape")
    try:
        (source / name).write_text("", encoding="utf-8")
    except (OSError, UnicodeEncodeError) as error:
        pytest.skip(f"the file system refuses the name: {error}")

    paths = list(_result_paths(_located("a%FF.txt"), source))

    assert paths == [path_in_record_form(source / name)]


def _platform(monkeypatch, name: str) -> None:
    monkeypatch.setattr(sys, "platform", name)


def test_a_committed_file_in_another_case_keeps_its_directory_on_macos(
    tmp_path, monkeypatch
):
    source = Path(os.path.realpath(tmp_path)) / "src"
    out = source / "out"
    (out / "Reports").mkdir(parents=True)
    (out / "Reports" / "x.md").write_text("committed\n", encoding="utf-8")
    monkeypatch.chdir(source)
    _platform(monkeypatch, "darwin")

    excluded = output_dirs_to_exclude(
        source, output_dir=out, scanned_files=[out / "Reports" / "x.md"]
    )

    assert out / "reports" not in excluded
    assert out / "analysis" in excluded


def test_control_on_linux_another_case_is_another_directory(tmp_path, monkeypatch):
    source = Path(os.path.realpath(tmp_path)) / "src"
    out = source / "out"
    (out / "Reports").mkdir(parents=True)
    (out / "Reports" / "x.md").write_text("committed\n", encoding="utf-8")
    monkeypatch.chdir(source)
    _platform(monkeypatch, "linux")

    excluded = output_dirs_to_exclude(
        source, output_dir=out, scanned_files=[out / "Reports" / "x.md"]
    )

    assert out / "reports" in excluded


def test_the_drop_keeps_a_committed_file_reported_in_another_case_on_macos(
    tmp_path, monkeypatch
):
    source = Path(os.path.realpath(tmp_path)) / "src"
    out = source / "out"
    (out / "Reports").mkdir(parents=True)
    (out / "Reports" / "x.md").write_text("committed\n", encoding="utf-8")
    monkeypatch.chdir(source)
    _platform(monkeypatch, "darwin")
    context = SimpleNamespace(
        source_dir=source, output_dir=out, work_dir=out / "converted", run_id=None
    )
    report = SimpleNamespace(
        runs=[
            SimpleNamespace(
                results=[_located("out/reports/x.md"), _located("out/reports/y.md")]
            )
        ]
    )

    removed = drop_results_in_ash_output_dirs(
        report, context, scanned_files=[out / "Reports" / "x.md"]
    )

    assert removed == 1
    # The committed file is the one that stays; the other, in the same output
    # directory but not committed, is the one dropped.
    (kept,) = report.runs[0].results
    assert (
        kept.locations[0].physicalLocation.root.artifactLocation.uri
        == "out/reports/x.md"
    )


def test_the_workspace_output_directorys_own_directories_are_excluded(
    tmp_path, monkeypatch
):
    source = Path(os.path.realpath(tmp_path)) / "src"
    ws_out = source / "ws-out"
    this_run = ws_out / "projects" / "p1"
    (this_run / "reports").mkdir(parents=True)
    (ws_out / ".workspace-spool").mkdir()
    (ws_out / "README.md").write_text("committed\n", encoding="utf-8")
    monkeypatch.chdir(source)

    excluded = output_dirs_to_exclude(
        source,
        output_dir=this_run,
        scanned_files=[ws_out / "README.md"],
        workspace_output_dir=ws_out,
    )

    assert ws_out / "projects" in excluded
    assert ws_out / ".workspace-spool" in excluded
    assert ws_out not in excluded


def test_control_a_single_scans_output_directory_excludes_no_projects_dir(
    tmp_path, monkeypatch
):
    source = Path(os.path.realpath(tmp_path)) / "src"
    out = source / "out"
    (out / "projects").mkdir(parents=True)
    (out / "README.md").write_text("committed\n", encoding="utf-8")
    monkeypatch.chdir(source)

    excluded = output_dirs_to_exclude(
        source, output_dir=out, scanned_files=[out / "README.md"]
    )

    assert out / "projects" not in excluded


@needs_symlinks
def test_a_source_spelled_through_a_link_to_itself_keeps_this_runs_output_dir(
    tmp_path, monkeypatch
):
    root = Path(os.path.realpath(tmp_path)) / "repo"
    (root / ".ash" / "ash_output").mkdir(parents=True)
    (root / "self").symlink_to(".", target_is_directory=True)
    source = root / "self"
    output_dir = source / ".ash" / "ash_output"
    monkeypatch.chdir(root)

    candidates = output_dir_candidates(source, output_dir)

    assert output_dir in candidates


@needs_symlinks
def test_control_a_link_inside_the_tree_on_the_way_to_the_output_dir_is_refused(
    tmp_path, monkeypatch
):
    root = Path(os.path.realpath(tmp_path)) / "repo"
    (root / "real").mkdir(parents=True)
    (root / "link").symlink_to(root / "real", target_is_directory=True)
    monkeypatch.chdir(root)

    candidates = output_dir_candidates(root, root / "link" / "out")

    assert root / "link" / "out" not in candidates
