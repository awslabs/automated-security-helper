# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Edges of ``get_scan_set``: what the walk says it could not list, what the counts
include, which ignore files win, and what a rule igittigitt cannot compile costs.

Each class pins one behavior; none starts a process or touches the network.
"""

from __future__ import annotations

import errno
import os
import re
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Dict
from unittest.mock import patch

import pytest
from igittigitt import IgnoreParser
from igittigitt import igittigitt as igittigitt_module

from automated_security_helper.utils import get_scan_set as gss
from automated_security_helper.utils.get_scan_set import scan_set

pytestmark = pytest.mark.unit


def _build(root: Path, files: Dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _names(root: Path, files) -> set[str]:
    return {Path(f).relative_to(root).as_posix() for f in files}


def _said(mock) -> list[str]:
    """The text of each call a patched logger method received."""
    texts = []
    for call in mock.call_args_list:
        template, *arguments = call.args
        texts.append(template % tuple(arguments) if arguments else str(template))
    return texts


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlink creation unavailable on this platform: {error}")


def _running_as_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


class TestAJunctionBeforePython312:
    """``os.path.isjunction`` is absent on 3.10 and 3.11, and answered False for
    every junction there; the entry's own status says what it is."""

    @staticmethod
    def _junction():
        # ``stat.IO_REPARSE_TAG_MOUNT_POINT`` is defined by Windows builds of the
        # ``stat`` module only (the ``FILE_ATTRIBUTE_*`` names are on every
        # platform), so the stand-in names the tag's value itself and this class
        # runs on Linux and macOS too.
        return SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o755,
            st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT
            | stat.FILE_ATTRIBUTE_DIRECTORY,
            st_reparse_tag=getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003),
        )

    def test_a_path_that_is_one_is_a_link_to_a_directory(self, tmp_path, monkeypatch):
        target = tmp_path / "junction"
        target.mkdir()
        real_lstat = os.lstat

        def lstat(path, *args, **kwargs):
            if os.fspath(path) == os.fspath(target):
                return self._junction()
            return real_lstat(path, *args, **kwargs)

        monkeypatch.delattr(os.path, "isjunction", raising=False)
        monkeypatch.setattr(gss, "_WINDOWS", True)
        monkeypatch.setattr(gss.os, "lstat", lstat)

        assert gss._is_link_to_directory(target)
        assert not gss._is_link_to_directory(tmp_path)

    def test_a_scandir_entry_that_is_one_is_a_link_to_a_directory(self, monkeypatch):
        entry = SimpleNamespace(
            is_symlink=lambda: False,
            path="junction",
            stat=lambda follow_symlinks=True: self._junction(),
        )
        monkeypatch.delattr(os.path, "isjunction", raising=False)
        monkeypatch.setattr(gss, "_WINDOWS", True)

        assert gss._entry_is_link_to_directory(entry)

    def test_off_windows_nothing_is_a_junction(self, tmp_path, monkeypatch):
        monkeypatch.delattr(os.path, "isjunction", raising=False)
        monkeypatch.setattr(gss, "_WINDOWS", False)

        assert not gss._is_link_to_directory(tmp_path)


class TestADirectoryThatCannotBeListed:
    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
    @pytest.mark.skipif(_running_as_root(), reason="root lists every directory")
    def test_the_walk_says_so(self, tmp_path):
        """``os.walk`` goes on without a word, so a directory the scanning user could
        not list was left out of the scan set with nothing logged."""
        root = _build(tmp_path / "src", {"app.py": "x\n", "locked/inner.py": "y\n"})
        locked = root / "locked"
        locked.chmod(0)
        try:
            with patch.object(gss.ASH_LOGGER, "warning") as warning:
                found = _names(root, scan_set(source=str(root)))
        finally:
            locked.chmod(0o755)

        assert found == {"app.py"}
        said = _said(warning)
        assert any(
            "locked" in text and "could not be listed" in text for text in said
        ), said


class TestTheBundledCdkTreeBelowTheScanRoot:
    def test_it_is_judged_by_the_path_below_the_root(self, tmp_path):
        root = str(tmp_path / "node_modules" / "aws-cdk-lib" / "proj")
        absolute = os.path.abspath(root)

        assert not gss._is_bundled_cdk_below(os.path.join(root, "app.py"), absolute)
        assert gss._is_bundled_cdk_below(
            os.path.join(root, "node_modules", "aws-cdk", "t.json"), absolute
        )

    def test_the_name_test_reads_the_components_below_the_root(self):
        assert gss._excluded_by_ash_itself("ignored", ("node_modules", "aws-cdk", "x"))
        assert not gss._excluded_by_ash_itself("ignored", ("aws-cdk-lib", "proj", "x"))

    def test_a_root_that_is_a_node_modules_directory_keeps_the_bundled_tree_out(
        self, tmp_path
    ):
        """Judged by the path below the root alone, ``aws-cdk/...`` under a root
        named ``node_modules`` lost the ``/node_modules`` before it, and the bundled
        fixtures entered the scan set."""
        root = _build(
            tmp_path / "node_modules",
            {
                "aws-cdk/lib/fixture.template.json": "{}\n",
                "mine/stack.template.json": "{}\n",
            },
        )
        absolute = os.path.abspath(root)

        assert gss._is_bundled_cdk_below(
            os.path.join(root, "aws-cdk", "lib", "fixture.template.json"), absolute
        )
        assert not gss._is_bundled_cdk_below(
            os.path.join(root, "mine", "stack.template.json"), absolute
        )
        assert gss._excluded_by_ash_itself("x", ("aws-cdk", "lib", "x"), "node_modules")
        assert not gss._excluded_by_ash_itself("x", ("aws-cdk", "lib", "x"), "src")
        assert _names(root, scan_set(source=str(root))) == {"mine/stack.template.json"}


class TestTheAssetsOfAKeptAssembly:
    TREE = {
        ".gitignore": "synth/\n",
        "app.py": "x = 1\n",
        "synth/cdk.out": "{}\n",
        "synth/manifest.json": "{}\n",
        "synth/Stack.template.json": "{}\n",
        "synth/asset.abc/handler.js": "h\n",
        "synth/asset.abc/lib/util.js": "u\n",
    }

    def test_an_assembly_not_named_cdk_out_counts_them_as_removed(self, tmp_path):
        """The root ``.gitignore`` excludes the assembly, which is walked for its
        templates; the asset directories inside it are not, and ASH has no rule of
        its own for an assembly with another name, so their files went uncounted."""
        root = _build(tmp_path / "src", self.TREE)
        pruned: Dict[str, int] = {}

        gss._collect_ignorefiles_and_all_files(str(root), pruned_counts=pruned)

        assert pruned == {os.path.join(str(root), ".gitignore"): 2}, pruned


class TestOutputDirectoriesUnderAPrunedParent:
    def test_another_named_one_is_ashs_own_and_not_counted_as_removed(self, tmp_path):
        root = _build(
            tmp_path / "src",
            {
                ".gitignore": "build/\n",
                "app.py": "x\n",
                "build/real.txt": "r\n",
                "build/out/report.json": "{}\n",
                "build/out/sub/more.json": "{}\n",
            },
        )
        pruned: Dict[str, int] = {}
        own: Dict[str, int] = {}

        gss._collect_ignorefiles_and_all_files(
            str(root),
            pruned_counts=pruned,
            own_output_counts=own,
            output_dir=str(root / "build" / "out"),
        )

        assert pruned == {os.path.join(str(root), ".gitignore"): 1}, pruned
        assert own == {os.path.join(str(root), "build", "out"): 2}, own

    def test_a_file_link_leaving_the_tree_is_not_counted_as_removed(self, tmp_path):
        outside = _build(tmp_path / "outside", {"secret.txt": "s\n"})
        root = _build(
            tmp_path / "src",
            {".gitignore": "build/\n", "app.py": "x\n", "build/inside.txt": "i\n"},
        )
        _symlink_or_skip(root / "build" / "leaving.txt", outside / "secret.txt")
        _symlink_or_skip(root / "build" / "staying.txt", root / "app.py")
        pruned: Dict[str, int] = {}

        gss._collect_ignorefiles_and_all_files(str(root), pruned_counts=pruned)

        assert pruned == {os.path.join(str(root), ".gitignore"): 2}, pruned

    def test_a_regular_file_in_it_costs_no_call_to_islink(self, tmp_path):
        """Whether a file is a link comes from the listing of its directory, so a
        pruned ``node_modules`` of regular files costs no ``lstat`` per file."""
        files = {f"build/f{number}.txt": "x\n" for number in range(5)}
        root = _build(tmp_path / "src", {".gitignore": "build/\n", **files})
        asked = []
        real_islink = os.path.islink

        def recording(path):
            asked.append(os.fspath(path))
            return real_islink(path)

        pruned: Dict[str, int] = {}
        with patch.object(os.path, "islink", recording):
            gss._collect_ignorefiles_and_all_files(str(root), pruned_counts=pruned)

        assert pruned == {os.path.join(str(root), ".gitignore"): 5}, pruned
        assert not [path for path in asked if os.path.basename(path).startswith("f")], (
            asked
        )


class TestCommittedFilesInASkippedOutputDirectory:
    def test_they_are_in_the_scan_set_and_not_counted_as_left_out(self, tmp_path):
        root = _build(
            tmp_path / "src",
            {"app.py": "x\n", "out/committed.txt": "c\n", "out/fresh.txt": "f\n"},
        )
        out = root / "out"
        own: Dict[str, int] = {}

        def committed(directory):
            return [Path(directory) / "committed.txt"]

        with patch.object(gss, "tracked_files_in", committed):
            _ignores, all_files = gss._collect_ignorefiles_and_all_files(
                str(root),
                own_output=str(out),
                own_output_counts=own,
                output_dir=str(out),
            )

        assert os.path.join(str(root), "out", "committed.txt") in all_files
        assert own == {os.path.join(str(root), "out"): 1}, own


class TestTheFilesThisRunWrites:
    def test_the_scan_set_pair_and_the_run_record_are_not_files_found_there(
        self, tmp_path
    ):
        """A walk made while the scan runs finds the lists the scan wrote as it
        started, and counted them as files already in the output directory."""
        files = dict.fromkeys(gss.SCAN_START_FILE_NAMES, "x\n")
        files[gss.SCAN_SET_RUN_FILE_NAME] = "{}\n"
        files["ash.log"] = "log\n"
        files["earlier.json"] = "{}\n"
        out = _build(tmp_path / "out", files)

        assert gss._count_files_in_own_output(str(out)) == 1


class TestADirectoryNamedLikeATemplate:
    def test_what_is_inside_it_is_not_forced_into_the_scan_set(self, tmp_path):
        """A rule that names ``*.template.json`` names a directory of that name too,
        and the parser then reports everything below it as matched, so a user's own
        ignore rules lost to it for every file inside."""
        root = _build(
            tmp_path / "src",
            {
                ".gitignore": "secret.py\ncfg.template.json\n",
                "ok.py": "x\n",
                "secret.py": "s\n",
                "cfg.template.json": "{}\n",
                "evil.template.json/secret.py": "s\n",
                "evil.template.json/inner.py": "i\n",
            },
        )

        found = _names(root, scan_set(source=str(root)))

        assert found == {
            ".gitignore",
            "ok.py",
            "cfg.template.json",
            "evil.template.json/inner.py",
        }, sorted(found)


class TestAnEscapedSpaceInABracketExpression:
    def test_it_is_a_plain_member_of_the_class(self):
        """``[a\\ b]`` was rewritten to ``[a[ ]b]``, whose first ``]`` closes the class
        early, so the rule named something else."""
        assert gss.gitignore_rule_for_igittigitt(r"x[a\ b]y") == "x[a b]y"

    def test_outside_a_class_it_is_still_a_one_character_class(self):
        assert gss.gitignore_rule_for_igittigitt(r"a\ b") == "a[ ]b"

    def test_the_rule_matches_the_names_the_class_lists(self, tmp_path):
        parser = IgnoreParser()
        parser.add_rule(gss.gitignore_rule_for_igittigitt(r"x[a\ b]y"), tmp_path)

        assert parser.match(tmp_path / "x y")
        assert parser.match(tmp_path / "xay")
        assert not parser.match(tmp_path / "xcy")

    def test_a_bracket_with_no_end_is_an_ordinary_character(self):
        assert gss.gitignore_rule_for_igittigitt(r"x[a\ b") == "x[a[ ]b"


class TestARuleIgittigittCannotCompile:
    def test_it_costs_that_rule_and_not_the_scan(self, tmp_path, monkeypatch):
        """igittigitt compiles a rule's glob when a path is first matched against it,
        so ``add_rule`` took a pattern wcmatch refuses and the first match that
        reached it raised out of the scan set."""
        real = igittigitt_module._globmatch
        refused_calls = []

        def refusing(path, glob):
            if "BADRULE" in glob:
                refused_calls.append((path, glob))
                raise re.error("bad character range")
            return real(path, glob)

        monkeypatch.setattr(igittigitt_module, "_globmatch", refusing)
        root = _build(
            tmp_path / "src", {"BADRULE.txt": "x\n", "a.log": "l\n", "b.py": "p\n"}
        )
        lines = [
            f"{gss.START_MARKER_PREFIX}${{SOURCE_DIR}}/.gitignore{gss.MARKER_SUFFIX}",
            "BADRULE.txt",
            "*.log",
            f"{gss.END_MARKER_PREFIX}${{SOURCE_DIR}}/.gitignore{gss.MARKER_SUFFIX}",
        ]

        with patch.object(gss.ASH_LOGGER, "warning") as warning:
            spec, _ids = gss.get_ash_ignorespec_with_attribution(lines, root)
            included = gss.get_files_not_matching_spec(
                str(root),
                spec,
                _all_files=[
                    str(root / name) for name in ("BADRULE.txt", "a.log", "b.py")
                ],
            )

        assert [Path(name).name for name in included] == ["BADRULE.txt", "b.py"]
        assert any("Skipped ignore rule" in text for text in _said(warning)), _said(
            warning
        )

        # The refusal has to come from the check itself, and from the call it is
        # written to make: igittigitt's function asked about the empty path with
        # the exact glob the parser built for the rule. A check that asked about
        # some path, or about a different glob, would still see this stand-in
        # refuse a rule whose text names BADRULE, so the refusal alone proves
        # neither. The rule was never added, so no match reached its glob.
        built = IgnoreParser()
        built.add_rule(
            gss.gitignore_rule_for_igittigitt("BADRULE.txt"),
            base_path=Path(os.path.abspath(root)),
        )
        built_globs = [rule.pattern_glob for rule in built.rules]
        assert built_globs, "igittigitt built no rule for the pattern"
        assert refused_calls == [("", built_globs[0])], refused_calls

    def test_a_file_named_probe_in_the_tree_changes_nothing(
        self, tmp_path, monkeypatch
    ):
        """The check asked a parser about ``<base>/probe``, which only compiles a
        directory-only rule while that is not a file. A tree with a file of that name
        beside its ignore file let such a rule through, and it raised at the first
        match."""
        real = igittigitt_module._globmatch

        def refusing(path, glob):
            if "BADRULE" in glob:
                raise re.error("bad character range")
            return real(path, glob)

        monkeypatch.setattr(igittigitt_module, "_globmatch", refusing)
        root = _build(tmp_path / "src", {"probe": "p\n", "BADRULE/x.txt": "x\n"})
        lines = [
            f"{gss.START_MARKER_PREFIX}${{SOURCE_DIR}}/.gitignore{gss.MARKER_SUFFIX}",
            "BADRULE/",
            f"{gss.END_MARKER_PREFIX}${{SOURCE_DIR}}/.gitignore{gss.MARKER_SUFFIX}",
        ]

        with patch.object(gss.ASH_LOGGER, "warning") as warning:
            spec, _ids = gss.get_ash_ignorespec_with_attribution(lines, root)
            included = gss.get_files_not_matching_spec(
                str(root),
                spec,
                _all_files=[str(root / name) for name in ("probe", "BADRULE/x.txt")],
            )

        assert sorted(_names(root, included)) == ["BADRULE/x.txt", "probe"]
        assert any("Skipped ignore rule" in text for text in _said(warning)), _said(
            warning
        )

    def test_a_changed_glob_function_is_not_taken_for_a_bad_rule(
        self, tmp_path, monkeypatch
    ):
        """A release whose ``_globmatch`` takes other arguments raises ``TypeError``
        from the check, which the caller counts as a rule that cannot compile; every
        rule, ``.git`` among them, would be skipped. The check asks about a path that
        is not a file instead."""
        asked = []

        class RecordingParser(IgnoreParser):
            def match(self, file_path):
                asked.append(file_path)
                return False

        monkeypatch.setattr(gss, "IgnoreParser", RecordingParser)
        monkeypatch.setattr(igittigitt_module, "_globmatch", lambda glob: False)
        monkeypatch.setattr(gss, "_RULE_CHECK_DEGRADED_WARNED", False)

        with patch.object(gss.ASH_LOGGER, "warning") as warning:
            gss._check_rule_compiles(".git", tmp_path)
            gss._check_rule_compiles("*.log", tmp_path)

        assert gss._igittigitt_glob_function() is None
        assert len(asked) == 2, asked
        # The fallback checks less than the glob compile does, so it says so, and
        # says it once for the process, not once per rule.
        assert len(_said(warning)) == 1, _said(warning)
        assert "igittigitt" in _said(warning)[0], _said(warning)

    def test_the_installed_glob_function_is_used_without_asking_a_path(
        self, tmp_path, monkeypatch
    ):
        """The control for the test above: with igittigitt's own function in place the
        rule's glob is compiled directly and no path is asked about."""
        asked = []

        class RecordingParser(IgnoreParser):
            def match(self, file_path):
                asked.append(file_path)
                return False

        monkeypatch.setattr(gss, "IgnoreParser", RecordingParser)
        monkeypatch.setattr(gss, "_RULE_CHECK_DEGRADED_WARNED", False)

        with patch.object(gss.ASH_LOGGER, "warning") as warning:
            gss._check_rule_compiles(".git", tmp_path)

        assert gss._igittigitt_glob_function() is not None
        assert asked == []
        assert _said(warning) == [], _said(warning)

    def test_a_negation_it_cannot_compile_is_skipped_too(self, tmp_path, monkeypatch):
        """The check holds the rule alone, so it has to compile a negation without a
        positive rule before it matching first. A parser that kept negations apart
        and compiled them only after a positive rule matched would pass the check
        and raise at the first file that positive rule reached."""
        real = igittigitt_module._globmatch

        def refusing(path, glob):
            if "BADRULE" in glob:
                raise re.error("bad character range")
            return real(path, glob)

        monkeypatch.setattr(igittigitt_module, "_globmatch", refusing)
        root = _build(tmp_path / "src", {"BADRULE.log": "x\n", "a.log": "l\n"})
        lines = [
            f"{gss.START_MARKER_PREFIX}${{SOURCE_DIR}}/.gitignore{gss.MARKER_SUFFIX}",
            "*.log",
            "!BADRULE.log",
            f"{gss.END_MARKER_PREFIX}${{SOURCE_DIR}}/.gitignore{gss.MARKER_SUFFIX}",
        ]

        with patch.object(gss.ASH_LOGGER, "warning") as warning:
            spec, _ids = gss.get_ash_ignorespec_with_attribution(lines, root)
            included = gss.get_files_not_matching_spec(
                str(root),
                spec,
                _all_files=[str(root / name) for name in ("BADRULE.log", "a.log")],
            )

        assert included == []
        assert any("Skipped ignore rule" in text for text in _said(warning)), _said(
            warning
        )


class TestAnIgnoreFileTheCallerNamesThatGoesBeforeItIsOpened:
    def test_it_is_skipped_with_a_word(self, tmp_path, monkeypatch):
        """The file passed the regular-file check and was gone at the open, which
        raised out of the scan set. It is now a skip with a warning and a SKIPPED
        line, because the operator typed the name. A file found in the tree and gone
        by the open is skipped without a word (it was never named by anyone), so the
        two differ on purpose."""
        root = _build(tmp_path / "src", {"a.py": "x\n"})
        missing = str(tmp_path / "gone.ignore")
        real_isfile = os.path.isfile

        def isfile(path):
            return True if str(path) == missing else real_isfile(path)

        monkeypatch.setattr(os.path, "isfile", isfile)

        with patch.object(gss.ASH_LOGGER, "warning") as warning:
            lines = gss.get_ash_ignorespec_lines(str(root), [missing])

        assert any(
            line.startswith(gss.SKIPPED_MARKER_PREFIX) and "it does not exist" in line
            for line in lines
        ), lines
        assert any("Skipped ignore file" in text for text in _said(warning)), _said(
            warning
        )


class TestTheOrderOfIgnoreFiles:
    def test_one_outside_the_tree_sorts_the_same_for_a_relative_and_an_absolute_source(
        self, tmp_path, monkeypatch
    ):
        """Counted by the path as spelled, an ignore file outside the tree sorted by
        its absolute depth against tree files whose depth followed how the source was
        written, so whether it overrode a nested file's negation depended on that."""
        root = _build(
            tmp_path / "src",
            {".gitignore": "*.log\n", "sub/.gitignore": "!keep.log\n"},
        )
        outside = _build(tmp_path / "elsewhere", {"rules.txt": "*.tmp\n"})
        rules = str(outside / "rules.txt")

        def order(source):
            lines = gss.get_ash_ignorespec_lines(source, [rules])
            paths = (gss._start_marker_path(line.strip()) for line in lines)
            return [path for path in paths if path is not None]

        absolute = order(str(root))
        monkeypatch.chdir(root)
        relative = order(".")

        expected = [
            "${SOURCE_DIR}/.gitignore",
            rules.replace(os.sep, "/"),
            "${SOURCE_DIR}/sub/.gitignore",
            "ASH_INCLUSIONS",
        ]
        assert absolute == relative == expected


class TestAnIgnoreFileTheCallerNamedAndIsNotThere:
    @pytest.mark.parametrize(
        "name, reason",
        [("missing.ignore", "does not exist"), ("adir", "not a regular file")],
    )
    def test_it_is_warned_about_and_has_a_line_in_the_report(
        self, tmp_path, name, reason
    ):
        root = _build(tmp_path / "src", {"app.py": "x\n"})
        (root / "adir").mkdir()

        with patch.object(gss.ASH_LOGGER, "warning") as warning:
            lines = gss.get_ash_ignorespec_lines(str(root), [name])

        skipped = [line for line in lines if line.startswith(gss.SKIPPED_MARKER_PREFIX)]
        assert len(skipped) == 1 and name in skipped[0] and reason in skipped[0], lines
        assert any(name in text for text in _said(warning)), _said(warning)


class TestTheReportWhenEveryIgnoreFileWasSkipped:
    @staticmethod
    def _report(tmp_path, **kwargs):
        with patch.object(gss.ASH_LOGGER, "info") as info:
            gss.report_ignore_file_exclusions(
                str(tmp_path),
                IgnoreParser(),
                [],
                {gss.ASH_INCLUSIONS_MARKER: []},
                [],
                **kwargs,
            )
        return [str(call.args[0]) for call in info.call_args_list]

    def test_it_does_not_say_none_were_found(self, tmp_path):
        said = self._report(tmp_path, skipped_ignore_files=2)

        assert not any(text.startswith("No ignore files were found") for text in said)
        assert any("could be applied" in text for text in said), said

    def test_with_none_found_it_still_says_so(self, tmp_path):
        said = self._report(tmp_path)

        assert any(text.startswith("No ignore files were found") for text in said), said


class TestGitThatCannotBeStarted:
    @pytest.mark.parametrize(
        "error",
        [
            NotADirectoryError(errno.ENOTDIR, "Not a directory"),
            PermissionError(errno.EACCES, "Permission denied"),
        ],
        ids=["not-a-directory", "permission-denied"],
    )
    def test_the_changed_files_fall_back_to_every_finding(
        self, tmp_path, monkeypatch, error
    ):
        def refuse(*args, **kwargs):
            raise error

        monkeypatch.setattr(gss, "_git_executable", lambda: "git")
        monkeypatch.setattr(gss.subprocess, "run", refuse)

        with patch.object(gss.ASH_LOGGER, "warning") as warning:
            changed = gss.get_changed_files("origin/main", cwd=tmp_path)

        assert changed is None
        assert any("reporting every finding" in text for text in _said(warning))


class TestAScanSetBuiltAgainForARun:
    def test_a_call_that_states_nothing_takes_the_runs_setting(self, tmp_path):
        """The orchestrator turned the ignore files off; a scanner that builds the
        scan set again because the run's could not be read back stated nothing, and
        built one that honored them."""
        root = _build(
            tmp_path / "src",
            {".gitignore": "ignored.txt\n", "ignored.txt": "i\n", "kept.py": "k\n"},
        )
        output = tmp_path / "out"
        extra = tmp_path / "extra.ignore"
        extra.write_text("", encoding="utf-8")

        first = _names(
            root,
            scan_set(
                source=str(root),
                output=str(output),
                run_id="run-1",
                honor_ignore_files=False,
            ),
        )
        later = _names(
            root,
            scan_set(
                source=str(root),
                output=str(output),
                run_id="run-1",
                ignorefile=[str(extra)],
            ),
        )
        stated = _names(
            root,
            scan_set(
                source=str(root),
                output=str(output),
                run_id="run-1",
                ignorefile=[str(extra)],
                honor_ignore_files=True,
            ),
        )

        assert "ignored.txt" in first
        assert "ignored.txt" in later
        assert "ignored.txt" not in stated

    def test_a_run_with_no_record_honors_them(self, tmp_path):
        root = _build(
            tmp_path / "src", {".gitignore": "ignored.txt\n", "ignored.txt": "i\n"}
        )

        found = _names(root, scan_set(source=str(root)))

        assert "ignored.txt" not in found


class TestThePrintedScanSet:
    def test_print_results_shows_what_the_filter_leaves(self, tmp_path, capsys):
        root = _build(tmp_path / "src", {"a.py": "", "b.txt": ""})

        returned = scan_set(
            source=str(root),
            print_results=True,
            filter_pattern=re.compile(r".*\.py$"),
        )

        printed = capsys.readouterr().out
        assert "a.py" in printed
        assert "b.txt" not in printed, printed
        assert _names(root, returned) == {"a.py"}


class TestTheCommandLineFilterPattern:
    def test_a_pattern_anchored_at_the_end_filters_the_real_scan_set(self, tmp_path):
        """The command line compiles ``\\.py$`` and asks ``scan_set`` to search for
        it. Matched from the start of the path, as a library caller's pattern is, the
        usual spelling filtered out everything with exit 0. The test below mocks
        ``scan_set`` and cannot see that."""
        root = _build(tmp_path / "src", {"a.py": "", "b.txt": "", "sub/c.py": ""})

        found = scan_set(
            source=str(root), filter_pattern=re.compile(r"\.py$"), filter_anywhere=True
        )

        assert _names(root, found) == {"a.py", "sub/c.py"}

    def test_a_library_caller_keeps_the_match_from_the_start(self, tmp_path):
        """``scan_set(filter_pattern=...)`` is a library API with in-process callers.
        A pattern that leans on the start of the path, such as a leading negative
        lookahead, must keep leaving out what it names: searched for anywhere, it
        starts matching after ``node_modules`` and lets those files through."""
        root = _build(tmp_path / "src", {"a.py": "", "node_modules/b.py": ""})

        found = scan_set(
            source=str(root),
            filter_pattern=re.compile(r"(?!.*node_modules).*\.py$"),
        )

        assert _names(root, found) == {"a.py"}

    @staticmethod
    def _arguments(pattern):
        return SimpleNamespace(
            source=".",
            output=None,
            filter_pattern=pattern,
            ignorefile=[],
            honor_ignore_files=True,
            debug=False,
        )

    def test_it_reaches_scan_set(self, monkeypatch):
        seen = {}

        def record(**kwargs):
            seen.update(kwargs)
            return []

        monkeypatch.setattr(gss, "parse_args", lambda: self._arguments(r"\.py$"))
        monkeypatch.setattr(gss, "scan_set", record)

        assert gss.main() == 0
        assert seen["filter_pattern"].pattern == r"\.py$"
        assert seen["filter_anywhere"] is True

    def test_a_pattern_that_is_not_a_regular_expression_is_refused(
        self, monkeypatch, capsys
    ):
        called = []
        monkeypatch.setattr(gss, "parse_args", lambda: self._arguments("("))
        monkeypatch.setattr(gss, "scan_set", lambda **kwargs: called.append(kwargs))

        assert gss.main() == 2
        assert called == []
        assert "not a regular expression" in capsys.readouterr().err


class TestTheOwnOutputDirectoryOfAWalk:
    def test_it_is_found_for_a_plain_output_directory(self, tmp_path):
        """The helper that asks whether the way to the output directory runs through a
        link the tree holds takes the root as spelled and the root resolved; called
        with the old two arguments it raised TypeError on every walk."""
        root = _build(tmp_path / "src", {"app.py": "x\n"})
        output = tmp_path / "out"
        output.mkdir()

        own = gss._own_output_of(output, root)

        assert own is not None
        assert own.path == os.path.normcase(str(output))

    def test_a_walk_with_an_output_directory_lists_the_tree(self, tmp_path):
        root = _build(tmp_path / "src", {"app.py": "x\n", "lib/util.py": "y\n"})
        output = tmp_path / "out"
        output.mkdir()

        found = _names(root, scan_set(source=str(root), output=str(output)))

        assert found == {"app.py", "lib/util.py"}
