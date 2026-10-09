# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The other places ASH copies scanned-tree content into its own output.

- ``scan_set`` copies every ``.gitignore``/``.ignore`` it finds into
  ``ash-ignore-report.txt``.
- Inline suppression reads the reason after ``ash-ignore:`` into the SARIF
  justification.
- Package identity reads ``package-lock.json`` names and versions into SARIF
  properties.

Each reads under the scanned-tree rule now, so a symlink in the tree pointing at a host
file does not get that file copied out.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.package_identity import (
    NpmLockIndex,
    load_npm_lock_entries,
)
from automated_security_helper.utils.suppression_matcher import (
    find_inline_suppressions,
)

MARKER = "HOST-ONLY-CONTENT-5e02"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


@pytest.fixture
def warnings_seen():
    """Every WARNING the 'ash' logger emits during the test."""
    records: list[str] = []

    class _Collector(logging.Handler):
        def emit(self, record):
            if record.levelno == logging.WARNING:
                records.append(record.getMessage())

    handler = _Collector(level=logging.WARNING)
    logger = logging.getLogger("ash")
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


@pytest.fixture
def layout(tmp_path):
    host = tmp_path / "host"
    tree = tmp_path / "tree"
    out = tmp_path / "out"
    for directory in (host, tree, out):
        directory.mkdir()
    return tree, host, out


class TestIgnoreFiles:
    def test_a_symlinked_gitignore_is_not_copied_into_the_report(
        self, layout, warnings_seen
    ):
        tree, host, out = layout
        (host / "rules").write_text(f"{MARKER}\n*.tmp\n")
        (tree / "sub").mkdir()
        (tree / "sub" / ".gitignore").symlink_to(host / "rules")
        (tree / "sub" / "kept.tmp").write_text("x\n")
        (tree / ".gitignore").write_text("*.log\n")
        (tree / "noise.log").write_text("x\n")

        files = scan_set(source=str(tree), output=str(out))

        report = (out / "ash-ignore-report.txt").read_text()
        assert MARKER not in report
        assert (
            "######### SKIPPED: ${SOURCE_DIR}/sub/.gitignore: it is a symbolic link"
            in (report)
        )
        # The positive control: the regular .gitignore is copied exactly as before and
        # still applies; the skipped one's rules do not.
        assert report.splitlines()[:3] == [
            "######### START CONTENTS: ${SOURCE_DIR}/.gitignore #########",
            "*.log",
            "######### END CONTENTS: ${SOURCE_DIR}/.gitignore #########",
        ]
        assert not any(f.endswith("noise.log") for f in files)
        assert any(f.endswith("kept.tmp") for f in files)
        assert warnings_seen == [
            (
                "Skipped ignore file 'sub/.gitignore': it is a symbolic link, so its "
                "rules were not applied"
            )
        ]

    def test_a_symlinked_root_gitignore_does_not_prune_the_walk(self, layout):
        tree, host, out = layout
        (host / "rules").write_text("vendor/\n")
        (tree / ".gitignore").symlink_to(host / "rules")
        (tree / "vendor").mkdir()
        (tree / "vendor" / "lib.py").write_text("x = 1\n")

        files = scan_set(source=str(tree), output=str(out))

        assert any(f.endswith("lib.py") for f in files)

    @pytest.mark.skipif(
        not hasattr(os, "geteuid") or os.geteuid() == 0,
        reason="file modes do not stop root",
    )
    def test_an_unreadable_ignore_file_still_raises(self, layout, warnings_seen):
        """Only a refusal is skipped; an unreadable file is an error, as before."""
        tree, _, out = layout
        (tree / "sub").mkdir()
        rules = tree / "sub" / ".gitignore"
        rules.write_text("*.tmp\n")
        rules.chmod(0)
        try:
            with pytest.raises(PermissionError):
                scan_set(source=str(tree), output=str(out))
        finally:
            rules.chmod(0o644)


class TestInlineSuppressions:
    def test_a_symlinked_source_file_is_not_read_for_reasons(
        self, layout, warnings_seen
    ):
        tree, host, _ = layout
        (host / "secret.py").write_text(f"x = 1  # ash-ignore: B101 {MARKER}\n")
        (tree / "app.py").symlink_to(host / "secret.py")
        (tree / "real.py").write_text("x = 1  # ash-ignore: B101 reviewed\n")
        # A link to a file inside the tree is followed: a scanner reported the
        # finding under the link's path, and the file behind it is tree content.
        (tree / "alias.py").symlink_to(tree / "real.py")

        found = find_inline_suppressions(tree / "app.py", scan_root=tree)
        regular = find_inline_suppressions(tree / "real.py", scan_root=tree)
        aliased = find_inline_suppressions(tree / "alias.py", scan_root=tree)

        assert found == []
        assert [(s.line_number, s.rule_id, s.reason) for s in regular] == [
            (1, "B101", "reviewed")
        ]
        assert aliased == regular
        assert warnings_seen == [
            (
                "Inline suppressions in 'app.py' were not read: it is a symbolic "
                "link that resolves outside the scanned tree"
            )
        ]

    def test_a_uri_outside_the_tree_is_not_read(self, layout):
        tree, host, _ = layout
        (host / "secret.py").write_text(f"x = 1  # ash-ignore: B101 {MARKER}\n")

        assert find_inline_suppressions(tree / ".." / "host" / "secret.py", tree) == []

    def test_a_regular_file_is_read_as_before(self, layout, warnings_seen):
        tree, _, _ = layout
        (tree / "app.py").write_text(
            "x = 1  # ash-ignore: B101 reviewed\r\ny = 2\n"
            "# ash-ignore-next-line: B102 also reviewed\nz = 3\n"
        )

        found = find_inline_suppressions(tree / "app.py", scan_root=tree)

        assert [(s.line_number, s.rule_id, s.reason) for s in found] == [
            (1, "B101", "reviewed"),
            (4, "B102", "also reviewed"),
        ]
        assert found == find_inline_suppressions(tree / "app.py")
        assert warnings_seen == []


LOCKFILE = {
    "name": "app",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "app"},
        "node_modules/left-pad": {"version": "1.3.0"},
    },
}


class TestLockfiles:
    def test_a_symlinked_lockfile_is_not_read(self, layout, warnings_seen):
        tree, host, _ = layout
        host_lock = dict(LOCKFILE)
        host_lock["packages"] = {
            "": {"name": "app"},
            f"node_modules/{MARKER.lower()}": {"version": "9.9.9"},
        }
        (host / "package-lock.json").write_text(json.dumps(host_lock))
        (tree / "package-lock.json").symlink_to(host / "package-lock.json")
        (tree / "web").mkdir()
        (tree / "web" / "package-lock.json").write_text(json.dumps(LOCKFILE))
        (tree / "api").mkdir()
        (tree / "api" / "package-lock.json").symlink_to(
            tree / "web" / "package-lock.json"
        )
        index = NpmLockIndex(tree)

        assert index.entries("package-lock.json") is None
        # A link to a lockfile inside the tree is followed.
        assert index.entries("api/package-lock.json") == index.entries(
            "web/package-lock.json"
        )
        # The positive control: a regular lockfile beside it reads as before.
        entries = index.entries("web/package-lock.json")
        assert [(e.name, e.version) for e in entries or []] == [("left-pad", "1.3.0")]
        assert entries == load_npm_lock_entries(
            Path(tree / "web" / "package-lock.json")
        )
        assert warnings_seen == [
            (
                "Lockfile 'package-lock.json' was not read for package identity: "
                "it is a symbolic link that resolves outside the scanned tree"
            )
        ]


class TestInlineSuppressionsInConvertedFiles:
    """A finding in a converted file is looked up against work_dir, not the source tree.

    Its URI is absolute and points into ``output_dir/converted``, so it is outside the
    source tree. Judging it against the source tree would stop every ``ash-ignore``
    comment in a notebook or archive from applying. Judging it against work_dir keeps
    those, and still refuses a link there.
    """

    def _result(self, rule_id: str):
        from automated_security_helper.schemas.sarif_schema_model import (
            Message,
            Result,
        )

        return Result(ruleId=rule_id, message=Message(text="msg"))

    def test_converted_files_keep_their_suppressions_and_links_are_refused(
        self, layout, warnings_seen
    ):
        from automated_security_helper.utils.sarif_utils import (
            _apply_inline_suppression,
        )

        tree, host, out = layout
        work_dir = out / "converted"
        (work_dir / "jupyter").mkdir(parents=True)
        converted = work_dir / "jupyter" / "nb-converted.py"
        converted.write_text("run()  # ash-ignore: B602 reviewed in the notebook\n")
        (host / "secret.py").write_text(f"run()  # ash-ignore: B602 {MARKER}\n")
        linked = work_dir / "jupyter" / "linked-converted.py"
        linked.symlink_to(host / "secret.py")
        cache: dict = {}

        kept = self._result("B602")
        assert _apply_inline_suppression(
            kept, converted.as_posix(), tree, 1, cache, work_dir=work_dir
        )
        assert kept.suppressions[0].justification == (
            "(ASH inline) reviewed in the notebook"
        )

        refused = self._result("B602")
        assert not _apply_inline_suppression(
            refused, linked.as_posix(), tree, 1, cache, work_dir=work_dir
        )
        assert not refused.suppressions
        assert warnings_seen == [
            (
                "Inline suppressions in 'jupyter/linked-converted.py' were not read: "
                "it is a symbolic link that resolves outside the scanned tree"
            )
        ]
