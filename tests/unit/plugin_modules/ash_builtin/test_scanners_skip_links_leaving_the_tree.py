# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Scanners that walk their target themselves are told to skip links that leave it.

bandit, checkov and ferret-scan are handed a directory and walk it. bandit and
checkov 3.3.26 read a link to a file wherever it points (measured); ferret-scan's
link handling is unmeasured. ASH's scan set already leaves such links out, but these
tools do not read the scan set, and they walk directories the ignore files leave
out, too. So each works out, for its own target, every link to a file whose target
leaves it (``get_scan_set.file_links_leaving_tree``) and passes each one in the
tool's own exclusion option:

- bandit: ``--exclude``, as a glob that matches the link's path alone. bandit
  matches each entry with ``fnmatch`` and as a substring, so a glob character in
  the path is escaped and one character is bracketed (``link.p[y]``), a text no
  ordinary path holds. A comma or a line break in the path cannot be carried, and
  a path that another walked path holds as text even so, or that names a
  directory under the target, still refuses the target.
- checkov: one ``--skip-path`` per link, anchored and escaped, so it matches that
  path and no other (checkov applies it with ``re.search`` and as a substring).
  checkov's terraform module finder joins every value into one regex a character
  at a time, so values that fail to compile there cannot be given: an unmatched
  parenthesis after a ``[.]`` does that, a balanced pair does not.
- ferret-scan: ``--exclude`` patterns, comma-joined, so a path with a comma cannot
  be carried (tests/unit/plugin_modules/ash_ferret_plugins/).

When a link cannot be expressed that way the target is not scanned at all: the
scanner raises, naming the path, and the tool is not started.

The matching rules are checked as each tool applies them, read from bandit 1.9.4
(``bandit/core/manager.py``) and checkov 3.3.26
(``checkov/common/runners/base_runner.py``,
``checkov/terraform/module_loading/module_finder.py``); the integration tests run
the tools.
"""

from __future__ import annotations

import fnmatch
import os
import re
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.utils.get_scan_set import file_links_leaving_tree

PluginContext.model_rebuild()

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    ),
]


def _tree(base: Path, files: dict[str, str], links: dict[str, str]) -> Path:
    """A source tree with *files* and *links* in it, and an ``outside`` beside it.

    A link target of ``outside``, or starting with ``outside/``, points at that
    directory or into it; any other target is a path inside the tree.
    """
    outside = base / "outside"
    source = base / "source"
    for directory in (outside, source):
        directory.mkdir(exist_ok=True)
    for name in ("secret.py", "main.tf", "Dockerfile"):
        (outside / name).write_text(f"# outside {name}\n", encoding="utf-8")
    for rel, text in files.items():
        (source / rel).parent.mkdir(parents=True, exist_ok=True)
        (source / rel).write_text(text, encoding="utf-8")
    for rel, target in links.items():
        link = source / rel
        link.parent.mkdir(parents=True, exist_ok=True)
        if target == "outside" or target.startswith("outside/"):
            resolved = base / target
        else:
            resolved = source / target
        link.symlink_to(resolved, target_is_directory=resolved.is_dir())
    return source


def _context(source: Path, base: Path) -> PluginContext:
    output = base / "ash-output"
    output.mkdir(exist_ok=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )


def _refused(scanner, source: Path) -> ScannerError:
    """scan() raises before the tool is started."""
    scanner.dependencies_satisfied = True
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess") as run,
    ):
        with pytest.raises(ScannerError) as refused:
            scanner.scan(target=source, target_type="source")
    run.assert_not_called()
    return refused.value


# ---------------------------------------------------------------------------
# The walk
# ---------------------------------------------------------------------------


def test_the_walk_finds_every_file_link_that_leaves_the_target(tmp_path):
    source = _tree(
        tmp_path,
        files={".gitignore": "ignored/\n", "app.py": "x = 1\n", "real/in.py": ""},
        links={
            "link_out.py": "outside/secret.py",
            "infra/link.tf": "outside/main.tf",
            # In a directory the ignore files leave out: the tools walk it anyway.
            "ignored/x.py": "outside/secret.py",
            "chain.py": "link_out.py",
            "link_in.py": "real/in.py",
            "dir_out": "outside",
        },
    )
    all_files: list[str] = []

    links = file_links_leaving_tree(source, all_files=all_files)

    assert links == ["chain.py", "ignored/x.py", "infra/link.tf", "link_out.py"]
    # A link to a directory is not descended, so nothing below dir_out is listed.
    assert sorted(all_files) == sorted(
        [".gitignore", "app.py", "real/in.py", "link_in.py", *links]
    )


# ---------------------------------------------------------------------------
# bandit
# ---------------------------------------------------------------------------


def _bandit(source: Path, base: Path):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
        BanditScannerConfig,
    )

    return BanditScanner(context=_context(source, base), config=BanditScannerConfig())


def _bandit_excluded_entries(argv: list[str]) -> list[str]:
    (token,) = [a for a in argv if str(a).startswith("--exclude=")]
    return token[len("--exclude=") :].split(",")


def _bandit_excludes(path: str, entries: list[str]) -> bool:
    """The exclusion half of bandit 1.9.4's ``_is_file_included``."""
    return any(fnmatch.fnmatch(path, glob) for glob in entries) or any(
        entry in path for entry in entries if entry
    )


class TestBandit:
    def test_each_link_leaving_the_target_is_excluded_and_nothing_else(self, tmp_path):
        source = _tree(
            tmp_path,
            files={"app.py": "x = 1\n", "real/in.py": "y = 2\n"},
            links={
                "link_out.py": "outside/secret.py",
                "pkg/rel_out.py": "outside/secret.py",
                "link_in.py": "real/in.py",
            },
        )
        scanner = _bandit(source, tmp_path)

        argv, _, _ = scanner._execute_scan(source, "source", [])

        entries = _bandit_excluded_entries(argv)
        root = Path(source).as_posix()
        for rel in ("link_out.py", "pkg/rel_out.py"):
            # The last character bracketed: a glob only that path matches, and a
            # text no other path holds (bandit also skips every path an entry is
            # a substring of).
            assert f"{root}/{rel[:-1]}[{rel[-1]}]" in entries
            assert _bandit_excludes(os.path.join(root, rel), entries)
        for rel in ("app.py", "real/in.py", "link_in.py"):
            assert not _bandit_excludes(os.path.join(root, rel), entries)

    def test_the_exclusion_is_for_this_resolution_only(self, tmp_path):
        source = _tree(
            tmp_path, files={"app.py": ""}, links={"l.py": "outside/secret.py"}
        )
        scanner = _bandit(source, tmp_path)
        before = [a.key for a in scanner.args.extra_args]

        scanner._execute_scan(source, "source", [])
        scanner._execute_scan(source, "source", [])

        assert [a.key for a in scanner.args.extra_args] == before

    @pytest.mark.parametrize("link", ["a,b.py", "a\nb.py"], ids=["comma", "line-break"])
    def test_a_link_bandit_cannot_exclude_alone_refuses_the_target(
        self, tmp_path, link
    ):
        """A comma splits bandit's --exclude value and a line break is dropped
        with the whole flag, so neither path can be carried in any spelling."""
        source = _tree(
            tmp_path, files={"app.py": "x = 1\n"}, links={link: "outside/secret.py"}
        )

        refused = _refused(_bandit(source, tmp_path), source)

        assert repr(link) in str(refused)
        assert "link leaves the scanned tree" in str(refused)

    @pytest.mark.parametrize(
        "link, also",
        [
            ("a[1].py", {}),
            ("a*b.py", {}),
            ("a?b.py", {}),
            # bandit also excludes every path the entry is a substring of; the
            # bracketed spelling is a text the longer name does not hold.
            ("x.py", {"x.pyw": "z = 3\n"}),
        ],
        ids=["bracket", "star", "question-mark", "a-longer-name"],
    )
    def test_a_link_with_a_glob_character_or_a_longer_neighbor_is_excluded_alone(
        self, tmp_path, link, also
    ):
        """The glob characters are escaped and one character is bracketed, so
        these are left out alone where they used to refuse the whole target."""
        source = _tree(
            tmp_path,
            files={"app.py": "x = 1\n", **also},
            links={link: "outside/secret.py"},
        )
        scanner = _bandit(source, tmp_path)

        argv, _, _ = scanner._execute_scan(source, "source", [])

        entries = _bandit_excluded_entries(argv)
        root = Path(source).as_posix()
        assert _bandit_excludes(os.path.join(root, link), entries)
        for rel in ("app.py", *also):
            assert not _bandit_excludes(os.path.join(root, rel), entries)


# ---------------------------------------------------------------------------
# checkov
# ---------------------------------------------------------------------------


def _checkov(source: Path, base: Path):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScanner,
        CheckovScannerConfig,
    )

    return CheckovScanner(context=_context(source, base), config=CheckovScannerConfig())


def _skip_values(argv: list[str]) -> list[str]:
    values = []
    for index, arg in enumerate(argv):
        if arg == "--skip-path" and index + 1 < len(argv):
            values.append(argv[index + 1])
        elif str(arg).startswith("--skip-path="):
            values.append(str(arg)[len("--skip-path=") :])
    return values


def _checkov_skips(path: str, values: list[str]) -> bool:
    """checkov 3.3.26's ``filter_ignored_paths`` test for one walked path."""
    for value in values:
        pattern = re.compile(
            re.escape(value) if re.match(r"^\.[^\.]", value) else value
        )
        if pattern.search(path) or value in path:
            return True
    return False


def _checkov_secrets_all_files_skips(path: str, values: list[str]) -> bool:
    """checkov 3.3.26's ``filter_excluded_paths``, the secrets runner's test with
    --enable-secret-scan-all-files: each value is compiled after ".terraform" is
    replaced with "\\.terraform"."""
    for value in values:
        try:
            pattern = re.compile(value.replace(".terraform", r"\.terraform"))
        except re.error:
            continue
        if pattern.search(path) or value in path:
            return True
    return False


def _module_finder_compiles(values: list[str]) -> bool:
    """checkov 3.3.26's ``find_modules`` regex over every --skip-path value."""
    try:
        re.compile("|".join(f"({values})"))
    except re.error:
        return False
    return True


posix_only = pytest.mark.skipif(os.sep != "/", reason="checkov skip paths are POSIX")


class TestCheckov:
    @posix_only
    def test_each_link_leaving_the_target_is_skipped_and_nothing_else(self, tmp_path):
        source = _tree(
            tmp_path,
            files={
                "main.tf": "",
                "a/main.tf.json": "{}",
                "a/main.tf.d/x.tf": "",
                "real/in.tf": "",
                "we(ird) [name].tf": "",
            },
            links={
                "a/main.tf": "outside/main.tf",
                "docker/Dockerfile": "outside/Dockerfile",
                "l [1]+{x}.tf": "outside/main.tf",
                "link_in.tf": "real/in.tf",
            },
        )
        scanner = _checkov(source, tmp_path)

        argv, _, _ = scanner._execute_scan(source, "source", [])

        values = _skip_values(argv)
        root = Path(os.path.abspath(source)).as_posix()
        for rel in ("a/main.tf", "docker/Dockerfile", "l [1]+{x}.tf"):
            assert _checkov_skips(os.path.join(root, rel), values), rel
        for rel in (
            "main.tf",
            "a/main.tf.json",
            "a/main.tf.d/x.tf",
            "real/in.tf",
            "link_in.tf",
            "we(ird) [name].tf",
        ):
            assert not _checkov_skips(os.path.join(root, rel), values), rel
        assert _module_finder_compiles(values)

    @posix_only
    def test_the_secrets_runner_skips_them_in_scan_all_files_mode_too(self, tmp_path):
        source = _tree(
            tmp_path,
            files={"real.terraform.yml": "", "main.tf": ""},
            links={
                "infra/x.terraform.yml": "outside/main.tf",
                "config.yml": "outside/main.tf",
            },
        )
        scanner = _checkov(source, tmp_path)

        argv, _, _ = scanner._execute_scan(source, "source", [])

        values = _skip_values(argv)
        root = Path(os.path.abspath(source)).as_posix()
        for rel in ("infra/x.terraform.yml", "config.yml"):
            path = os.path.join(root, rel)
            assert _checkov_skips(path, values), rel
            assert _checkov_secrets_all_files_skips(path, values), rel
        for rel in ("real.terraform.yml", "main.tf"):
            path = os.path.join(root, rel)
            assert not _checkov_skips(path, values), rel
            assert not _checkov_secrets_all_files_skips(path, values), rel

    @posix_only
    def test_the_skip_paths_are_for_this_resolution_only(self, tmp_path):
        source = _tree(tmp_path, files={"m.tf": ""}, links={"l.tf": "outside/main.tf"})
        scanner = _checkov(source, tmp_path)
        before = [(a.key, a.value) for a in scanner.args.extra_args]

        scanner._execute_scan(source, "source", [])

        assert [(a.key, a.value) for a in scanner.args.extra_args] == before

    @posix_only
    @pytest.mark.parametrize("name", ["b(c.tf", "b)c.tf"])
    def test_a_link_whose_value_breaks_the_module_finder_refuses_the_target(
        self, tmp_path, name
    ):
        """An unmatched parenthesis, with a dotted link before it: the values fail
        the module finder's regex to compile, and with it checkov's whole terraform
        scan. (The links are given in the walk's order, so a(b.tf, which sorts
        before a.tf, compiles.)"""
        source = _tree(
            tmp_path,
            files={"m.tf": ""},
            links={"a.tf": "outside/main.tf", name: "outside/main.tf"},
        )
        values = [
            "^" + re.escape(f"{source.as_posix()}/{rel}").replace("\\.", "[.]") + "$"
            for rel in file_links_leaving_tree(source)
        ]
        assert not _module_finder_compiles(values), "the case no longer fails"

        refused = _refused(_checkov(source, tmp_path), source)

        assert repr(name) in str(refused)
        assert "link leaves the scanned tree" in str(refused)

    @posix_only
    @pytest.mark.parametrize("name", ["l (1).tf", "x (1).tf"])
    def test_a_link_with_balanced_parentheses_is_skipped(self, tmp_path, name):
        """Its value compiles in the module finder's regex, so checkov runs."""
        source = _tree(
            tmp_path,
            files={"m.tf": "", "keep (1).tf": ""},
            links={"a.tf": "outside/main.tf", name: "outside/main.tf"},
        )
        scanner = _checkov(source, tmp_path)

        argv, _, _ = scanner._execute_scan(source, "source", [])

        values = _skip_values(argv)
        root = Path(os.path.abspath(source)).as_posix()
        for rel in ("a.tf", name):
            assert _checkov_skips(os.path.join(root, rel), values), rel
        for rel in ("m.tf", "keep (1).tf"):
            assert not _checkov_skips(os.path.join(root, rel), values), rel
        assert _module_finder_compiles(values)

    @posix_only
    def test_a_target_whose_own_path_has_a_parenthesis_is_refused(self, tmp_path):
        """Every value holds the target's path, so a parenthesis there reaches the
        module finder's regex too: with two links it fails to compile."""
        base = tmp_path / "base(1"
        base.mkdir()
        source = _tree(
            base,
            files={"m.tf": ""},
            links={"a.tf": "outside/main.tf", "b.tf": "outside/main.tf"},
        )

        refused = _refused(_checkov(source, base), source)

        assert "link leaves the scanned tree" in str(refused)

    @posix_only
    def test_a_target_whose_path_has_balanced_parentheses_is_scanned(self, tmp_path):
        """Its values compile in the module finder's regex: both links are skipped."""
        base = tmp_path / "proj (1)"
        base.mkdir()
        source = _tree(
            base,
            files={"m.tf": ""},
            links={"a.tf": "outside/main.tf", "b.tf": "outside/main.tf"},
        )
        scanner = _checkov(source, base)

        argv, _, _ = scanner._execute_scan(source, "source", [])

        values = _skip_values(argv)
        root = Path(os.path.abspath(source)).as_posix()
        for rel in ("a.tf", "b.tf"):
            assert _checkov_skips(os.path.join(root, rel), values), rel
        assert not _checkov_skips(os.path.join(root, "m.tf"), values)
        assert _module_finder_compiles(values)

    def test_where_paths_cannot_be_skipped_the_target_is_refused(
        self, tmp_path, monkeypatch
    ):
        """checkov joins walked paths with os.sep; on Windows they cannot be matched.

        Run on every OS by faking the separator, as test_checkov_output_dir_skip does.
        """
        from automated_security_helper.plugin_modules.ash_builtin.scanners import (
            checkov_scanner,
        )

        source = _tree(tmp_path, files={"m.tf": ""}, links={"l.tf": "outside/main.tf"})
        scanner = _checkov(source, tmp_path)
        monkeypatch.setattr(checkov_scanner.os, "sep", "\\")

        refused = _refused(scanner, source)

        assert "'l.tf'" in str(refused)
