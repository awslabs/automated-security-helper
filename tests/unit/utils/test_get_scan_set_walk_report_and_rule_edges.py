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
        return SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o755,
            st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT
            | stat.FILE_ATTRIBUTE_DIRECTORY,
            st_reparse_tag=stat.IO_REPARSE_TAG_MOUNT_POINT,
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

        def refusing(path, glob):
            if "BADRULE" in glob:
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

    def test_a_pattern_that_is_not_a_regular_expression_is_refused(
        self, monkeypatch, capsys
    ):
        called = []
        monkeypatch.setattr(gss, "parse_args", lambda: self._arguments("("))
        monkeypatch.setattr(gss, "scan_set", lambda **kwargs: called.append(kwargs))

        assert gss.main() == 2
        assert called == []
        assert "not a regular expression" in capsys.readouterr().err
