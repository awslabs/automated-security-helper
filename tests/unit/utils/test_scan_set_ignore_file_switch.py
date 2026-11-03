# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scan_set`` with and without the scanned repository's ignore files, in process.

The whole-scan tests in ``tests/unit/interactions/test_scan_ignore_file_switch.py``
cover the CLI flag, the config tiers and the reports. These cover what they cannot
reach from outside:

- the record ``scan_set`` hands back through ``exclusions``, including the files
  under a directory the root ``.gitignore`` prunes (never walked for the scan set,
  so counted separately) and the files ASH would leave out anyway;
- ``ash-ignore-report.txt`` saying the ignore files were not honored;
- every scanner and converter that calls ``scan_set`` passing the switch on, so a
  scan set computed outside the orchestrator does not quietly honor the ignore
  files the operator turned off;
- the standalone ``get_scan_set`` command's flag.
"""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Dict
from unittest.mock import patch

import pytest
from igittigitt import IgnoreParser

from automated_security_helper.utils import get_scan_set as gss
from automated_security_helper.utils.get_scan_set import (
    NOT_HONORED_REPORT_LINE,
    honors_ignore_files,
    scan_set,
)

pytestmark = pytest.mark.unit

PACKAGE_ROOT = Path(gss.__file__).resolve().parents[1]


def _build(root: Path, files: Dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _names(root: Path, files) -> set[str]:
    return {Path(f).relative_to(root).as_posix() for f in files}


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")


def _record(root: Path, **kwargs) -> dict:
    exclusions: dict = {}
    scan_set(source=str(root), exclusions=exclusions, **kwargs)
    return exclusions


class TestPrunedDirectoriesAreCounted:
    """The root ``.gitignore`` prunes ``build/`` before the walk descends into it."""

    TREE = {
        ".gitignore": "build/\n*.log\n",
        "app.py": "x = 1\n",
        "a.log": "log\n",
        "build/one.txt": "out\n",
        "build/two.txt": "out\n",
        "build/deep/three.txt": "out\n",
    }

    def test_the_root_gitignore_counts_the_files_under_the_pruned_directory(
        self, tmp_path
    ):
        root = _build(tmp_path / "src", self.TREE)
        record = _record(root)
        assert record["by_ignore_file"] == {".gitignore": 4}, record
        assert record["excluded_file_count"] == 4, record

    def test_the_count_matches_the_files_actually_missing(self, tmp_path):
        root = _build(tmp_path / "src", self.TREE)
        found = _names(root, scan_set(source=str(root)))
        missing = set(self.TREE) - found
        assert missing == {
            "a.log",
            "build/one.txt",
            "build/two.txt",
            "build/deep/three.txt",
        }
        assert _record(root)["excluded_file_count"] == len(missing)

    def test_the_log_line_carries_the_pruned_files_too(self, tmp_path):
        """The INFO line read 1 here before: only a.log was walked and dropped."""
        root = _build(tmp_path / "src", self.TREE)
        with patch.object(gss.ASH_LOGGER, "info") as info:
            scan_set(source=str(root))
        logged = {
            call.args[1]: call.args[2]
            for call in info.call_args_list
            if len(call.args) >= 3 and "excluded" in str(call.args[0])
        }
        assert logged.get("${SOURCE_DIR}/.gitignore") == 4, logged

    def test_files_ash_leaves_out_on_its_own_are_not_counted(self, tmp_path):
        """A ``.git`` and CDK assets under a pruned directory were not the ignore file's doing.

        The count is what turning the ignore files off adds back. ``vendor/lib.py``
        is in it; whether the template under ``cdk.out`` is depends on whether the
        walk keeps templates from a pruned cloud assembly, so the count is compared
        with the scan sets rather than fixed at a number.
        """
        root = _build(
            tmp_path / "src",
            {
                ".gitignore": "vendor/\ncdk.out/\n",
                "app.py": "x = 1\n",
                "vendor/lib.py": "y = 2\n",
                "vendor/.git/HEAD": "ref: refs/heads/main\n",
                "cdk.out/asset.abc/handler.py": "z = 3\n",
                "cdk.out/Stack.template.json": "{}\n",
            },
        )
        record = _record(root)
        honored = _names(root, scan_set(source=str(root)))
        unhonored = _names(root, scan_set(source=str(root), honor_ignore_files=False))
        assert {"vendor/lib.py", "cdk.out/Stack.template.json"} <= unhonored
        assert "vendor/.git/HEAD" not in unhonored
        assert "cdk.out/asset.abc/handler.py" not in unhonored
        assert "vendor/lib.py" in unhonored - honored
        assert record["by_ignore_file"] == {".gitignore": len(unhonored - honored)}, (
            record,
            sorted(unhonored - honored),
        )

    def test_an_ignore_file_inside_a_pruned_directory_is_not_listed(self, tmp_path):
        """git never reads it, and neither does ASH, so it removed nothing."""
        root = _build(
            tmp_path / "src",
            {
                ".gitignore": "build/\n",
                "app.py": "x = 1\n",
                "build/.gitignore": "*\n",
                "build/out.txt": "out\n",
            },
        )
        record = _record(root)
        assert record["by_ignore_file"] == {".gitignore": 2}, record


class TestPrunedCountsMatchTheSwitch:
    """The total is exactly what turning the ignore files off would add back.

    Asserted as that property over trees that put each of ASH's own exclusions
    under a directory the root ``.gitignore`` prunes, which is where the count
    is taken without the parser: the bundled aws-cdk tree in a pruned
    ``node_modules`` (the usual CDK project layout), CDK assets and their
    templates in a pruned build directory, and a ``.git`` below one.
    """

    TREES = {
        "bundled-cdk": {
            ".gitignore": "node_modules/\n",
            "app.py": "x = 1\n",
            "node_modules/aws-cdk/lib/x.json": "{}\n",
            "node_modules/aws-cdk-lib/y.js": "y\n",
            "node_modules/left-pad/index.js": "z\n",
        },
        "cdk-assets": {
            ".gitignore": "build/\n",
            "app.py": "x = 1\n",
            "build/cdk.out/asset.123/handler.py": "h\n",
            "build/cdk.out/asset.123/nested.template.json": "{}\n",
            "build/cdk.out/Stack.template.json": "{}\n",
            "build/other.txt": "o\n",
        },
        "vendored-checkout": {
            ".gitignore": "vendor/\n",
            "app.py": "x = 1\n",
            "vendor/lib/.git/HEAD": "ref\n",
            "vendor/lib/.git/objects/ab": "o\n",
            "vendor/lib/src.py": "s\n",
        },
    }

    @pytest.mark.parametrize("name", sorted(TREES))
    def test_the_total_is_what_the_switch_adds_back(self, tmp_path, name):
        root = _build(tmp_path / "src", self.TREES[name])
        honored = set(scan_set(source=str(root)))
        everything = set(scan_set(source=str(root), honor_ignore_files=False))
        record = _record(root)
        assert record["excluded_file_count"] == len(everything - honored), (
            record,
            sorted(_names(root, everything - honored)),
        )
        assert record["by_ignore_file"] == {".gitignore": len(everything - honored)}

    def test_a_pruned_directory_is_counted_without_matching_each_file(
        self, tmp_path, monkeypatch
    ):
        """One parser match per pruned file stats each one: 100,000 took 2.3 s."""
        root = _build(
            tmp_path / "src",
            {".gitignore": "node_modules/\n", "app.py": "x = 1\n"},
        )
        pruned = root / "node_modules"
        for index in range(50):
            _build(pruned, {f"pkg{index}/index.js": "x\n"})
        matched_below = []
        real_match = IgnoreParser.match

        def recording_match(self, file_path):
            candidate = Path(str(file_path))
            if candidate.name != "placeholder" and pruned in candidate.parents:
                matched_below.append(candidate)
            return real_match(self, file_path)

        monkeypatch.setattr(IgnoreParser, "match", recording_match)
        record = _record(root)
        assert record["excluded_file_count"] == 50, record
        assert matched_below == [], matched_below[:3]


class TestAPrunedLinkIsNotFollowed:
    """A directory the root ``.gitignore`` prunes can be a link, and its target is not read.

    The scan-set walk never descends a link to a directory, so the files behind it
    are in no scan set, with the ignore files or without them. Counting them would
    walk wherever the repository's link points, outside the tree included, and put
    the number of files found there into the results.
    """

    def test_a_link_out_of_the_tree_is_not_walked_or_counted(
        self, tmp_path, monkeypatch
    ):
        outside = _build(tmp_path / "outside", {f"f{i}.txt": "x\n" for i in range(5)})
        root = _build(
            tmp_path / "src", {".gitignore": "vendor/\n", "app.py": "x = 1\n"}
        )
        _symlink_or_skip(root / "vendor", outside)
        walked = []
        real_walk = os.walk

        def recording_walk(top, *args, **kwargs):
            walked.append(os.path.abspath(top))
            return real_walk(top, *args, **kwargs)

        monkeypatch.setattr(gss.os, "walk", recording_walk)
        record = _record(root)

        assert record["excluded_file_count"] == 0, record
        assert record["by_ignore_file"] == {".gitignore": 0}, record
        assert walked == [os.path.abspath(root)], walked
        assert _names(root, scan_set(source=str(root))) == {".gitignore", "app.py"}

    @pytest.mark.parametrize(
        "link_name",
        [".git", "cdk.out/asset.1"],
        ids=["git-directory", "cdk-asset-directory"],
    )
    def test_a_link_below_a_pruned_directory_is_not_walked(
        self, tmp_path, monkeypatch, link_name
    ):
        """One level down, under the names the count searches for templates.

        A ``.git`` directory and a CDK asset directory below a pruned directory are
        searched only for ``*.template.json`` files. As links, they point wherever
        the repository says, and their templates are in no scan set either way.
        """
        outside = _build(
            tmp_path / "outside",
            {f"t{i}.template.json": "{}\n" for i in range(5)},
        )
        root = _build(
            tmp_path / "src",
            {".gitignore": "build/\n", "app.py": "x = 1\n", "build/real.txt": "r\n"},
        )
        link = root / "build" / link_name
        link.parent.mkdir(parents=True, exist_ok=True)
        _symlink_or_skip(link, outside)
        walked = []
        real_walk = os.walk

        def recording_walk(top, *args, **kwargs):
            walked.append(os.path.abspath(top))
            return real_walk(top, *args, **kwargs)

        monkeypatch.setattr(gss.os, "walk", recording_walk)
        record = _record(root)

        assert not any(
            top == os.path.abspath(link) or top.startswith(os.path.abspath(outside))
            for top in walked
        ), walked
        assert record["by_ignore_file"] == {".gitignore": 1}, record
        assert record["excluded_file_count"] == 1, record

    def test_every_count_walk_refuses_a_link_given_as_its_top(self, tmp_path):
        """The one guard the counts share, asked directly for each count."""
        outside = _build(
            tmp_path / "outside",
            {"a.txt": "a\n", "b.template.json": "{}\n", "sub/c.txt": "c\n"},
        )
        root = _build(tmp_path / "src", {"app.py": "x = 1\n"})
        link = root / "linked"
        _symlink_or_skip(link, outside)
        assert list(gss._walk_unless_link(link)) == []
        assert gss._count_templates(str(link)) == 0
        assert gss._count_files_in_own_output(str(link)) == 0
        assert gss._count_files_ash_would_scan(link, str(root)) == 0
        # The control: the same directory, reached as itself, is walked.
        assert [Path(top) for top, _dirs, _files in gss._walk_unless_link(outside)][
            0
        ] == outside
        assert gss._count_templates(str(outside)) == 1

    def test_a_template_under_a_template_named_directory_is_not_counted(self, tmp_path):
        """The scan set does not force in a template below a directory that is itself
        named ``*.template.json`` (``_forced_in``), so a count of what a pruned
        ``.git`` or asset directory gives back leaves it out too."""
        root = _build(
            tmp_path / "src",
            {
                "build/.git/ok.template.json": "{}\n",
                "build/.git/dir.template.json/inner.template.json": "{}\n",
                "build/.git/dir.template.json/deeper/more.template.json": "{}\n",
            },
        )

        assert gss._count_templates(str(root / "build" / ".git"), str(root)) == 1
        assert gss._count_templates(str(root / "build" / ".git")) == 1

    def test_a_link_inside_the_tree_is_not_counted_twice(self, tmp_path):
        root = _build(
            tmp_path / "src",
            {
                ".gitignore": "mirror/\n",
                "data/a.txt": "a\n",
                "data/b.txt": "b\n",
                "data/c.txt": "c\n",
            },
        )
        _symlink_or_skip(root / "mirror", root / "data")
        record = _record(root)
        assert record["by_ignore_file"] == {".gitignore": 0}, record
        assert {"data/a.txt", "data/b.txt", "data/c.txt"} <= _names(
            root, scan_set(source=str(root))
        )

    def test_a_directory_with_no_files_is_not_listed_again_for_links(
        self, tmp_path, monkeypatch
    ):
        """The link names come from one more listing of a directory, which only a file
        can use. A pruned ``node_modules`` is mostly directories that hold no file
        (``@scope/``, nested levels), and each paid that second listing for nothing."""
        root = _build(
            tmp_path / "src",
            {
                "build/@scope/pkg/a.txt": "a\n",
                "build/@scope/pkg/b.txt": "b\n",
                "build/only/dirs/x/y.txt": "y\n",
            },
        )
        real = gss._names_of_links_in
        listed = []

        def spy(directory):
            listed.append(Path(directory).relative_to(root).as_posix())
            return real(directory)

        monkeypatch.setattr(gss, "_names_of_links_in", spy)

        assert gss._count_files_ash_would_scan(root / "build", str(root)) == 3
        assert sorted(listed) == ["build/@scope/pkg", "build/only/dirs/x"], listed


class TestIgnoreFileTextCannotRewriteTheRecord:
    """A line in a repository's ignore file is a rule or a comment, never a section marker.

    ASH copies each ignore file's text between ``START/END CONTENTS`` marker lines
    and reads the markers back to tell which file a rule came from. A comment line
    in the file shaped like a marker used to be read as one, so the file's rules
    were credited to ``ASH_INCLUSIONS`` or to an ignore file that does not exist.
    git reads such a line as a comment.
    """

    def test_a_marker_shaped_comment_does_not_hide_what_the_file_removed(
        self, tmp_path
    ):
        root = _build(
            tmp_path / "src",
            {
                ".gitignore": "######### START CONTENTS: ASH_INCLUSIONS #########\n"
                "secret.txt\n",
                "app.py": "x = 1\n",
                "secret.txt": "s\n",
            },
        )
        assert _names(root, scan_set(source=str(root))) == {".gitignore", "app.py"}
        record = _record(root)
        assert record["by_ignore_file"] == {".gitignore": 1}, record
        assert record["excluded_file_count"] == 1, record

    def test_an_indented_marker_shaped_comment_is_read_the_same_way(self, tmp_path):
        root = _build(
            tmp_path / "src",
            {
                ".gitignore": "   ######### START CONTENTS: ASH_INCLUSIONS #########\n"
                "secret.txt\n",
                "app.py": "x = 1\n",
                "secret.txt": "s\n",
            },
        )
        record = _record(root)
        assert record["by_ignore_file"] == {".gitignore": 1}, record
        assert record["excluded_file_count"] == 1, record

    def test_a_nested_file_cannot_claim_to_be_the_root_one(self, tmp_path):
        """Its rules stay in its own directory, and are credited to it."""
        root = _build(
            tmp_path / "src",
            {
                "sub/.gitignore": "######### START CONTENTS: ${SOURCE_DIR}/.gitignore"
                " #########\n*.py\n",
                "sub/x.py": "x = 1\n",
                "app.py": "x = 1\n",
                "other/y.py": "y = 2\n",
            },
        )
        found = _names(root, scan_set(source=str(root)))
        assert {"app.py", "other/y.py"} <= found, found
        assert "sub/x.py" not in found, found
        record = _record(root)
        assert record["by_ignore_file"] == {"sub/.gitignore": 1}, record
        assert record["excluded_file_count"] == 1, record

    def test_no_ignore_file_is_invented(self, tmp_path):
        root = _build(
            tmp_path / "src",
            {
                ".gitignore": "*.log\n######### START CONTENTS: ${SOURCE_DIR}/zzz/"
                ".gitignore #########\n",
                "a.log": "a\n",
                "app.py": "x = 1\n",
            },
        )
        record = _record(root)
        assert record["by_ignore_file"] == {".gitignore": 1}, record

    def test_the_total_does_not_depend_on_attribution(self, tmp_path):
        """A total summed from the attribution can only be as right as the attribution.

        With the attribution emptied, as a parser the mapping does not match would
        leave it, the per-file counts are lost and the total is still the number of
        files the ignore files removed, pruned ones included.
        """
        root = _build(
            tmp_path / "src",
            {
                ".gitignore": "build/\n*.log\n",
                "a.log": "a\n",
                "build/o.txt": "o\n",
                "app.py": "x = 1\n",
            },
        )
        real = gss.get_ash_ignorespec_with_attribution

        def without_attribution(*args, **kwargs):
            parser, _mapping = real(*args, **kwargs)
            return parser, {}

        with patch.object(
            gss, "get_ash_ignorespec_with_attribution", without_attribution
        ):
            record = _record(root)
        assert record["excluded_file_count"] == 2, record


def _mkdir_or_skip(path: Path) -> Path:
    try:
        path.mkdir(parents=True)
    except OSError as exc:  # ':' is not allowed in a Windows file name
        pytest.skip(f"this file system does not allow the name {path.name!r}: {exc}")
    return path


class TestADirectoryNameCannotRewriteTheRecord:
    """The marker names an ignore file by its path, and a directory name is part of it.

    Linux and macOS allow ``START CONTENTS:`` and ``#########`` in a directory name.
    The marker text has to be read exactly, prefix and suffix, so such a name is
    only a name: the rules stay in that directory and are credited to that file.
    """

    MARKED = "notes START CONTENTS: draft"

    def test_the_rules_stay_in_the_directory_that_holds_them(self, tmp_path):
        root = _build(tmp_path / "src", {"app.py": "x = 1\n", "other/y.py": "y = 2\n"})
        _mkdir_or_skip(root / self.MARKED)
        _build(root / self.MARKED, {".gitignore": "*.py\n", "x.py": "x = 1\n"})
        found = _names(root, scan_set(source=str(root)))
        assert {"app.py", "other/y.py"} <= found, found
        assert f"{self.MARKED}/x.py" not in found, found
        record = _record(root)
        assert record["by_ignore_file"] == {f"{self.MARKED}/.gitignore": 1}, record
        assert record["excluded_file_count"] == 1, record

    def test_a_name_ending_in_the_marker_suffix_is_read_whole(self, tmp_path):
        """A name that closes one marker and opens ASH_INCLUSIONS is still a name."""
        name = "z START CONTENTS: ASH_INCLUSIONS #########"
        root = _build(tmp_path / "src", {"app.py": "x = 1\n", "secret.txt": "s\n"})
        _mkdir_or_skip(root / name)
        _build(root / name, {".gitignore": "secret.txt\n", "secret.txt": "s\n"})
        found = _names(root, scan_set(source=str(root)))
        assert "secret.txt" in found, found
        assert f"{name}/secret.txt" not in found, found
        assert _record(root)["by_ignore_file"] == {f"{name}/.gitignore": 1}

    def test_the_markers_are_read_exactly_on_every_platform(self, tmp_path):
        """The same lines, handed to the reader directly, with no file system."""
        marker = f"${{SOURCE_DIR}}/{self.MARKED}/.gitignore"
        lines = [
            f"######### START CONTENTS: {marker} #########",
            "*.py",
            f"######### END CONTENTS: {marker} #########",
            (
                f"######### SKIPPED: ${{SOURCE_DIR}}/{self.MARKED}/b/.gitignore: a"
                " link #########"
            ),
            "######### START CONTENTS: ASH_INCLUSIONS #########",
            ".git",
            "######### END CONTENTS: ASH_INCLUSIONS #########",
        ]
        parser, rule_ids = gss.get_ash_ignorespec_with_attribution(lines, tmp_path)
        assert list(rule_ids) == [marker, gss.ASH_INCLUSIONS_MARKER], list(rule_ids)
        (py_rule,) = [r for r in parser.rules if r.pattern_original == "*.py"]
        assert id(py_rule) in rule_ids[marker]
        assert str(py_rule.pattern_glob).startswith(
            (tmp_path / self.MARKED).as_posix()
        ), py_rule.pattern_glob

    def test_a_source_dir_token_inside_a_name_is_not_replaced(self, tmp_path):
        """Only the leading token stands for the scan root."""
        name = "a${SOURCE_DIR}b"
        marker = f"${{SOURCE_DIR}}/{name}/.gitignore"
        lines = [f"######### START CONTENTS: {marker} #########", "*.py"]
        parser, _rule_ids = gss.get_ash_ignorespec_with_attribution(lines, tmp_path)
        (rule,) = parser.rules
        assert str(rule.pattern_glob).startswith((tmp_path / name).as_posix()), (
            rule.pattern_glob
        )


class TestAshsOwnExclusionsByName:
    """The name-based test for ASH's own exclusions answers what the parser answers.

    The totals and the pruned-directory counts decide "ASH leaves this out anyway"
    from path names, without a parser match per file. That is only right while it
    restates ``ASH_INCLUSIONS``, so the two are compared on paths that sit on each
    side of every rule.
    """

    PATHS = [
        "a.py",
        ".git/HEAD",
        "sub/.git",
        "x/.git/objects/ab",
        ".git/x.template.json",
        "dir.git/a",
        ".gitx/a",
        "cdk.out/asset.1/h.py",
        "cdk.out/asset.1/t.template.json",
        "cdk.out/asset.",
        "cdk.out/Stack.template.json",
        "a/cdk.out/asset.x",
        "asset.1/h.py",
        "cdk.out/assets/h.py",
        "cdk.out.bak/asset.1/a",
        "node_modules/aws-cdk/x.json",
        "node_modules/aws-cdk-lib/x.json",
        "node_modules/aws-cdk/t.template.json",
        "src/node_modules/aws-cdkmine/y.py",
        "node_modules/aws/cdk.py",
        ".git/y.template.json/a",
        ".git/a.template.json/b.template.json",
    ]

    def test_the_restated_rules_are_ash_inclusions(self):
        assert gss._RESTATED_ASH_INCLUSIONS == tuple(gss.ASH_INCLUSIONS), (
            "ASH_INCLUSIONS changed: update _excluded_by_ash_itself to match"
        )

    def test_the_name_test_agrees_with_the_parser(self, tmp_path):
        root = _build(tmp_path / "src", dict.fromkeys(self.PATHS, "x\n"))
        own_spec = IgnoreParser()
        for entry in gss.ASH_INCLUSIONS:
            own_spec.add_rule(entry, base_path=root)
        forced = gss._forced_inclusion_spec(root)
        forced_directories = {}
        disagree = []
        for path in self.PATHS:
            if sys.platform == "win32" and path.endswith("."):
                # Windows drops a trailing dot from a name, so "cdk.out/asset."
                # is the file "cdk.out/asset" there and the case cannot exist.
                continue
            full = root / path
            by_parser = gss._is_bundled_cdk_path(str(full)) or (
                own_spec.match(full)
                and not gss._forced_in(forced, str(root), full, forced_directories)
            )
            by_name = gss._excluded_by_ash_itself(str(full), tuple(path.split("/")))
            if by_parser != by_name:
                disagree.append((path, by_parser, by_name))
        assert disagree == [], disagree


class TestTheBundledCdkTreeIsAshsOwnExclusion:
    def test_an_ignore_rule_matching_it_is_not_credited_with_removing_it(
        self, tmp_path
    ):
        root = _build(
            tmp_path / "src",
            {
                "app.py": "x = 1\n",
                "pkg/.gitignore": "*.json\n",
                "pkg/node_modules/aws-cdk/fixture.json": "{}\n",
                "pkg/other.json": "{}\n",
            },
        )
        record = _record(root)
        assert record["by_ignore_file"] == {"pkg/.gitignore": 1}, record

    def test_a_source_dir_inside_the_bundled_tree_is_scanned_like_any_other(
        self, tmp_path
    ):
        """The carve-out is for the aws-cdk tree inside the scanned code, judged by
        the path below the scan root.

        A source directory that itself lies below ``node_modules/aws-cdk*`` was left
        out of the scan set whole, with the ignore files or without them, and only
        when the source was spelled as an absolute path. Scanned like any other, the
        ignore files remove what they name, and the record counts it.
        """
        root = _build(
            tmp_path / "node_modules" / "aws-cdk-lib" / "proj",
            {
                ".gitignore": "build/\n*.log\n",
                "app.py": "x = 1\n",
                "a.log": "a\n",
                "build/x.txt": "x\n",
            },
        )
        honored = _names(root, scan_set(source=str(root)))
        unhonored = _names(root, scan_set(source=str(root), honor_ignore_files=False))
        record = _record(root)
        assert "app.py" in honored, sorted(honored)
        assert unhonored - honored == {"a.log", "build/x.txt"}, (
            sorted(honored),
            sorted(unhonored),
        )
        assert record["excluded_file_count"] == 2, record
        assert record["by_ignore_file"] == {".gitignore": 2}, record

    def test_a_relative_and_an_absolute_source_inside_it_agree(
        self, tmp_path, monkeypatch
    ):
        root = _build(
            tmp_path / "node_modules" / "aws-cdk-lib" / "proj",
            {"app.py": "x = 1\n", "other.py": "y = 2\n"},
        )
        absolute = _names(root, scan_set(source=str(root)))
        monkeypatch.chdir(root)
        relative = {os.path.relpath(name, root) for name in scan_set(source=".")}

        assert absolute == relative == {"app.py", "other.py"}


class TestNotHonored:
    TREE = {
        ".gitignore": "build/\n*.log\n",
        ".ignore": "notes.txt\n",
        ".git/HEAD": "ref: refs/heads/main\n",
        "app.py": "x = 1\n",
        "a.log": "log\n",
        "notes.txt": "notes\n",
        "build/out.txt": "out\n",
        "vendor/.gitignore": "*\n",
        "vendor/dep.py": "y = 2\n",
    }

    def test_every_file_but_ashs_own_exclusions_is_in_the_scan_set(self, tmp_path):
        root = _build(tmp_path / "src", self.TREE)
        found = _names(root, scan_set(source=str(root), honor_ignore_files=False))
        assert found == set(self.TREE) - {".git/HEAD"}

    def test_the_record_says_so(self, tmp_path):
        root = _build(tmp_path / "src", self.TREE)
        assert _record(root, honor_ignore_files=False) == {
            "honored": False,
            "excluded_file_count": 0,
            "by_ignore_file": {},
            "output_dir_file_count": 0,
        }

    def test_the_ignore_report_says_so(self, tmp_path):
        root = _build(tmp_path / "src", self.TREE)
        output = tmp_path / "out"
        # Without a run ID the pair is written only on request, as the command
        # line asks for it.
        scan_set(
            source=str(root),
            output=str(output),
            honor_ignore_files=False,
            write_lists=True,
        )
        report = (output / "ash-ignore-report.txt").read_text(encoding="utf-8")
        assert report.splitlines()[0] == NOT_HONORED_REPORT_LINE
        assert "START CONTENTS: ${SOURCE_DIR}/.gitignore" not in report
        assert "START CONTENTS: ASH_INCLUSIONS" in report

    def test_no_ignore_files_were_found_is_not_claimed(self, tmp_path):
        root = _build(tmp_path / "src", self.TREE)
        with patch.object(gss.ASH_LOGGER, "info") as info:
            scan_set(source=str(root), honor_ignore_files=False)
        messages = [str(call.args[0]) for call in info.call_args_list if call.args]
        assert not any("No ignore files were found" in m for m in messages), messages
        assert any("not honored" in m for m in messages), messages

    def test_control_honored_by_default(self, tmp_path):
        """vendor/.gitignore's ``*`` matches the ignore file itself as well."""
        root = _build(tmp_path / "src", self.TREE)
        record = _record(root)
        assert record["honored"] is True
        assert record["by_ignore_file"] == {
            ".gitignore": 2,
            ".ignore": 1,
            "vendor/.gitignore": 2,
        }, record

    def test_a_reused_scan_set_records_nothing(self, tmp_path):
        """Nothing was matched, so there is nothing to attribute.

        A scan set is reused only by the run that wrote it, so both calls carry
        the same run ID.
        """
        root = _build(tmp_path / "src", self.TREE)
        output = tmp_path / "out"
        run_id = gss.new_run_id()
        scan_set(source=str(root), output=str(output), run_id=run_id)
        assert _record(root, output=str(output), run_id=run_id) == {}


class TestAshsOwnOutputDirectory:
    """ASH's log and reports are not part of the code being scanned.

    The default output directory is ``.ash/ash_output`` inside the source
    directory, and only ``.ash/.gitignore`` (written by ``ash config init``) kept
    it out of the scan set. With the ignore files not honored, ASH's own log
    entered it.
    """

    TREE = {
        "app.py": "x = 1\n",
        ".ash/.gitignore": "ash_output*\n",
        ".ash/ash_output/ash.log": "log\n",
        ".ash/ash_output/reports/ash.summary.txt": "summary\n",
    }

    @pytest.mark.parametrize("honor", [True, False])
    def test_it_is_never_in_the_scan_set(self, tmp_path, honor):
        root = _build(tmp_path / "src", self.TREE)
        output = root / ".ash" / "ash_output"
        found = _names(
            root,
            scan_set(source=str(root), output=str(output), honor_ignore_files=honor),
        )
        assert not any(name.startswith(".ash/ash_output/") for name in found), found
        assert "app.py" in found and ".ash/.gitignore" in found

    def test_the_ignore_file_is_not_credited_with_it(self, tmp_path):
        root = _build(tmp_path / "src", self.TREE)
        output = root / ".ash" / "ash_output"
        exclusions: dict = {}
        scan_set(source=str(root), output=str(output), exclusions=exclusions)
        assert exclusions["by_ignore_file"] == {".ash/.gitignore": 0}, exclusions

    def test_not_counted_under_a_directory_the_root_gitignore_prunes(self, tmp_path):
        root = _build(tmp_path / "src", {**self.TREE, ".gitignore": ".ash/\n"})
        output = root / ".ash" / "ash_output"
        exclusions: dict = {}
        scan_set(source=str(root), output=str(output), exclusions=exclusions)
        # .ash/.gitignore itself, and nothing from the output directory.
        assert exclusions["by_ignore_file"] == {".gitignore": 1}, exclusions

    @pytest.mark.parametrize("honor", [True, False])
    def test_files_already_in_it_are_counted_and_warned_about(self, tmp_path, honor):
        """Repository files there are left out too; the record and the log say so.

        This run's own log files are not counted: the logger has opened them by the
        time the scan set is built, so every scan would report them.
        """
        root = _build(
            tmp_path / "src",
            {
                "app.py": "x = 1\n",
                ".ash/ash_output/ash.log": "log\n",
                ".ash/ash_output/ash.log.jsonl": "{}\n",
                ".ash/ash_output/stack.template.json": "{}\n",
                ".ash/ash_output/nb/analysis.ipynb": "{}\n",
            },
        )
        output = root / ".ash" / "ash_output"
        exclusions: dict = {}
        with patch.object(gss.ASH_LOGGER, "warning") as warning:
            found = scan_set(
                source=str(root),
                output=str(output),
                honor_ignore_files=honor,
                exclusions=exclusions,
            )
        assert _names(root, found) == {"app.py"}
        assert exclusions["output_dir_file_count"] == 2, exclusions
        assert exclusions["excluded_file_count"] == 0, exclusions
        messages = [
            str(call.args[0]) % call.args[1:] for call in warning.call_args_list
        ]
        assert any(
            "2 files" in m and "${SOURCE_DIR}/.ash/ash_output" in m for m in messages
        ), messages

    def test_only_this_runs_log_files_is_no_warning(self, tmp_path):
        root = _build(
            tmp_path / "src",
            {"app.py": "x = 1\n", ".ash/ash_output/ash.log": "log\n"},
        )
        exclusions: dict = {}
        with patch.object(gss.ASH_LOGGER, "warning") as warning:
            scan_set(
                source=str(root),
                output=str(root / ".ash" / "ash_output"),
                exclusions=exclusions,
            )
        assert exclusions["output_dir_file_count"] == 0, exclusions
        assert warning.call_args_list == []

    def test_it_is_recognized_whatever_the_source_is_spelled(self, tmp_path):
        """The same directory reached through a link to the source tree.

        Container mode reaches it as /src/.ash/ash_output while the output is
        mounted at /out; a symlinked checkout path does the same locally.
        """
        real = _build(
            tmp_path / "real",
            {"app.py": "x = 1\n", ".ash/ash_output/ash.log": "log\n"},
        )
        link = tmp_path / "link"
        _symlink_or_skip(link, real)
        found = _names(
            link,
            scan_set(
                source=str(link),
                output=str(real / ".ash" / "ash_output"),
                honor_ignore_files=False,
            ),
        )
        assert found == {"app.py"}, found

    def test_files_in_it_are_counted_under_a_pruned_parent(self, tmp_path):
        """``.ash/`` ignored: the count of ``.ash`` still finds the output directory.

        Its files are reported as ASH's own, with the warning, and not credited to
        the root ``.gitignore``, the same as when the walk reaches it directly.
        """
        root = _build(
            tmp_path / "src",
            {
                ".gitignore": ".ash/\n",
                "app.py": "x = 1\n",
                ".ash/other.txt": "o\n",
                ".ash/ash_output/ash.log": "log\n",
                ".ash/ash_output/stack.template.json": "{}\n",
                ".ash/ash_output/nb/analysis.ipynb": "{}\n",
            },
        )
        exclusions: dict = {}
        with patch.object(gss.ASH_LOGGER, "warning") as warning:
            found = scan_set(
                source=str(root),
                output=str(root / ".ash" / "ash_output"),
                exclusions=exclusions,
            )
        assert _names(root, found) == {".gitignore", "app.py"}
        assert exclusions["by_ignore_file"] == {".gitignore": 1}, exclusions
        assert exclusions["excluded_file_count"] == 1, exclusions
        assert exclusions["output_dir_file_count"] == 2, exclusions
        messages = [
            str(call.args[0]) % call.args[1:] for call in warning.call_args_list
        ]
        assert any("2 files" in m for m in messages), messages

    def test_a_file_system_without_inode_numbers_falls_back_to_the_path(
        self, tmp_path, monkeypatch
    ):
        """``st_ino`` 0 is no identity: every directory on that device would share it."""
        root = _build(
            tmp_path / "src",
            {
                "app.py": "x = 1\n",
                "src/code.py": "c = 1\n",
                "docs/x.md": "x\n",
                "out/ash.log": "log\n",
                "out/old.txt": "o\n",
            },
        )
        real_identity = gss._directory_identity

        def no_inode_numbers(path, follow_symlinks=False):
            identity = real_identity(path, follow_symlinks=follow_symlinks)
            return None if identity is None else (identity[0], 0)

        monkeypatch.setattr(gss, "_directory_identity", no_inode_numbers)
        exclusions: dict = {}
        found = scan_set(
            source=str(root),
            output=str(root / "out"),
            honor_ignore_files=False,
            exclusions=exclusions,
        )
        assert _names(root, found) == {"app.py", "src/code.py", "docs/x.md"}, found
        assert exclusions["output_dir_file_count"] == 1, exclusions

    def test_control_a_directory_of_that_name_elsewhere_is_scanned(self, tmp_path):
        root = _build(
            tmp_path / "src", {"app.py": "x = 1\n", "docs/ash_output/note.md": "n\n"}
        )
        found = _names(
            root,
            scan_set(
                source=str(root),
                output=str(tmp_path / "out"),
                honor_ignore_files=False,
            ),
        )
        assert "docs/ash_output/note.md" in found


class TestHonorsIgnoreFiles:
    @pytest.mark.parametrize(
        "config, expected",
        [
            (SimpleNamespace(honor_ignore_files=False), False),
            (SimpleNamespace(honor_ignore_files=True), True),
            (SimpleNamespace(), True),
            (None, True),
        ],
    )
    def test_only_a_real_false_turns_them_off(self, config, expected):
        assert honors_ignore_files(config) is expected


def _scan_set_calls(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "scan_set"
        ):
            yield node


def _consumers():
    found = []
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        if path.name == "get_scan_set.py":
            continue
        for call in _scan_set_calls(path):
            found.append((path.relative_to(PACKAGE_ROOT).as_posix(), call))
    return found


class TestEveryConsumerPassesTheSwitch:
    """A scan set recomputed outside the orchestrator must follow the operator's switch.

    The orchestrator writes the list first and the consumers reuse it, but a
    consumer that recomputes it (no list on disk, a plugin run on its own) would
    otherwise honor the ignore files whatever the config says.
    """

    def test_the_consumers_are_found(self):
        """cfn-nag and cdk-nag read the scan set through
        ``utils/cfn_template_discovery.candidate_files``, so that module is the
        consumer for both."""
        modules = {module for module, _call in _consumers()}
        assert {
            "core/orchestrator.py",
            "plugin_modules/ash_builtin/scanners/detect_secrets_scanner.py",
            "utils/cfn_template_discovery.py",
            "plugin_modules/ash_builtin/scanners/npm_audit_scanner.py",
            "plugin_modules/ash_builtin/converters/archive_converter.py",
            "plugin_modules/ash_builtin/converters/jupyter_converter.py",
        } <= modules, sorted(modules)

    def test_each_call_passes_the_configs_switch(self):
        """The keyword alone is not enough: ``honor_ignore_files=True`` passes the name.

        Each call has to hand on what its config says, through
        ``honors_ignore_files(<context>.config)``, or
        ``honors_ignore_files(getattr(<context>, "config", None))`` where the
        context is loosely typed.
        """

        def names_the_config(argument: ast.expr) -> bool:
            if isinstance(argument, ast.Attribute):
                return argument.attr == "config"
            return (
                isinstance(argument, ast.Call)
                and isinstance(argument.func, ast.Name)
                and argument.func.id == "getattr"
                and len(argument.args) >= 2
                and isinstance(argument.args[1], ast.Constant)
                and argument.args[1].value == "config"
            )

        def passes_the_switch(call: ast.Call) -> bool:
            for keyword in call.keywords:
                if keyword.arg != "honor_ignore_files":
                    continue
                value = keyword.value
                return (
                    isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Name)
                    and value.func.id == "honors_ignore_files"
                    and len(value.args) == 1
                    and names_the_config(value.args[0])
                )
            return False

        missing = [
            f"{module}:{call.lineno}"
            for module, call in _consumers()
            if not passes_the_switch(call)
        ]
        assert missing == [], missing


class TestAConverterFollowsItsConfig:
    """One consumer end to end: the jupyter converter's own scan set."""

    def test_a_notebook_an_ignore_file_matches_is_found_when_not_honored(
        self, tmp_path
    ):
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
            JupyterConverter,
        )

        root = _build(
            tmp_path / "src",
            {".gitignore": "*.ipynb\n", "nb.ipynb": "{}\n", "app.py": "x = 1\n"},
        )

        def notebooks(honor: bool):
            output = tmp_path / f"out-{honor}"
            context = PluginContext(
                source_dir=root,
                output_dir=output,
                work_dir=output / "converted",
                config=AshConfig(project_name="t", honor_ignore_files=honor),
            )
            converter = JupyterConverter(context=context)
            return [Path(n).name for n in converter._notebooks_in_scan_set()]

        assert notebooks(True) == []
        assert notebooks(False) == ["nb.ipynb"]


class TestTheStandaloneCommand:
    def test_no_honor_ignore_files_lists_the_ignored_files(self, tmp_path, capsys):
        root = _build(tmp_path / "src", {".gitignore": "*.log\n", "a.log": "x\n"})
        argv = ["get_scan_set", "--source", str(root), "--no-honor-ignore-files"]
        with patch.object(sys, "argv", argv):
            assert gss.main() == 0
        assert str(root / "a.log") in capsys.readouterr().out.splitlines()

    def test_control_honored_by_default(self, tmp_path, capsys):
        root = _build(tmp_path / "src", {".gitignore": "*.log\n", "a.log": "x\n"})
        with patch.object(sys, "argv", ["get_scan_set", "--source", str(root)]):
            assert gss.main() == 0
        assert str(root / "a.log") not in capsys.readouterr().out.splitlines()
