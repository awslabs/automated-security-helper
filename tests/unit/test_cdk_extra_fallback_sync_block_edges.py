# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Comments inside the block ``scripts/sync_cdk_extra_fallback.py`` reads and rewrites.

Three behaviors, each of which could make ``--fix`` damage the scanner module or
make ``--check`` misreport it:

* A comment after an element is not part of the requirement. It used to make
  ``--check`` stop with "is not a string" on a file that was already in sync.
* ``--fix`` replaces every line of the list, and whole-line comments were already
  read past, so it deleted them without a word. It now refuses and writes nothing.
* ``main`` builds its parser from the module docstring, which ``python -OO``
  strips.

A closer that gained a trailing comment is pinned here as a control. Reading the
block already refuses it (the closer line sits inside the range being read and is
not a string literal), so ``--fix`` cannot scan on to a later ``]``.

The files are small copies in ``tmp_path``; nothing here reads the real scanner.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "sync_cdk_extra_fallback.py"

#: In the shape both pyproject readers accept, so the 3.10 fallback parser and
#: tomllib answer alike.
PYPROJECT_TEXT = (
    "[project.optional-dependencies]\n"
    "cdk = [\n"
    '    "alpha>=1.0,<2.0.0",\n'
    '    "beta>=2.0,<3.0.0",\n'
    "]\n"
)
ALPHA = "alpha>=1.0,<2.0.0"
BETA = "beta>=2.0,<3.0.0"


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "_sync_cdk_extra_fallback_block_edges", SCRIPT
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


script = _load_script()


def _block(elements: list[str], closer: str | None = None) -> list[str]:
    """A scanner module around the list, with a second list after it."""
    return [
        "import x",
        script.ANCHOR,
        *elements,
        script.CLOSER if closer is None else closer,
        "",
        "OTHER = [",
        "    1,",
        "]",
    ]


def _files(tmp_path, monkeypatch, scanner_lines: list[str], argv: list[str]):
    """The script pointed at a small pyproject and the given scanner text."""
    pyproject = tmp_path / "pyproject.toml"
    scanner = tmp_path / "scanner.py"
    pyproject.write_text(PYPROJECT_TEXT, encoding="utf-8")
    scanner.write_text("\n".join(scanner_lines) + "\n", encoding="utf-8")
    monkeypatch.setattr(script, "PYPROJECT", pyproject)
    monkeypatch.setattr(script, "SCANNER", scanner)
    monkeypatch.setattr(sys, "argv", ["sync_cdk_extra_fallback.py", *argv])
    return scanner


class TestAnInlineCommentIsNotPartOfTheRequirement:
    def test_it_is_read_past(self):
        """Red at the base: the line read back as a one-element tuple and was
        refused with "is not a string"."""
        lines = _block([f'    "{ALPHA}",  # floor from the 1.x line'])
        assert script.committed_requirements(lines) == [ALPHA]

    def test_a_hash_inside_the_requirement_is_not_a_comment(self):
        """Red at the base for the trailing comment, as above; it also holds the
        ``#`` inside the string literal in place, which a split on ``#`` would cut."""
        requirement = "pkg @ https://example.test/p.whl#frag"
        lines = _block([f'    "{requirement}",  # direct reference'])
        assert script.committed_requirements(lines) == [requirement]

    def test_check_reads_past_a_commented_list(self, tmp_path, monkeypatch):
        """Red at the base: ``--check`` stopped with "is not a string" on a list
        that agrees with pyproject."""
        _files(
            tmp_path,
            monkeypatch,
            _block(
                [
                    "    # why the pair below",
                    f'    "{ALPHA}",  # first',
                    f'    "{BETA}",',
                ]
            ),
            [],
        )
        assert script.main() == 0


class TestFixDoesNotDeleteComments:
    def test_a_whole_line_comment_is_refused_and_nothing_is_written(
        self, tmp_path, monkeypatch
    ):
        """Red at the base: the rewrite replaced the comment line and exited 0."""
        scanner = _files(
            tmp_path,
            monkeypatch,
            _block(["    # why alpha", f'    "{ALPHA}",']),
            ["--fix"],
        )
        before = scanner.read_bytes()

        with pytest.raises(SystemExit, match="hold a comment"):
            script.main()

        assert scanner.read_bytes() == before

    def test_an_inline_comment_is_refused_and_nothing_is_written(
        self, tmp_path, monkeypatch
    ):
        """Red at the base: ``--fix`` stopped earlier with "is not a string",
        never reaching the comment-specific refusal."""
        scanner = _files(
            tmp_path,
            monkeypatch,
            _block([f'    "{ALPHA}",  # pinned for the 1.x line']),
            ["--fix"],
        )
        before = scanner.read_bytes()

        with pytest.raises(SystemExit, match="hold a comment"):
            script.main()

        assert scanner.read_bytes() == before

    def test_a_list_with_no_comment_is_still_rewritten(self, tmp_path, monkeypatch):
        """Control, green at the base: a blank line is not content, so it is
        normalized away and the rewrite goes ahead."""
        scanner = _files(
            tmp_path,
            monkeypatch,
            _block([f'    "{ALPHA}",', "", '    "gamma>=3.0",']),
            ["--fix"],
        )

        assert script.main() == 0

        lines = scanner.read_text(encoding="utf-8").splitlines()
        assert script.committed_requirements(lines) == [ALPHA, BETA]
        assert "OTHER = [" in lines

    def test_a_closer_with_a_trailing_comment_is_refused_without_writing(
        self, tmp_path, monkeypatch
    ):
        """Control, green at the base: the closer line is inside the range read
        as elements and is not a string literal, so nothing reaches the rewrite
        and the code up to the later ``]`` survives."""
        scanner = _files(
            tmp_path,
            monkeypatch,
            _block([f'    "{ALPHA}",'], closer="]  # end of the list"),
            ["--fix"],
        )
        before = scanner.read_bytes()

        with pytest.raises(SystemExit):
            script.main()

        assert scanner.read_bytes() == before


class TestTheParserSurvivesStrippedDocstrings:
    def test_main_runs_when_the_module_has_no_docstring(self, tmp_path, monkeypatch):
        """Red at the base: ``None.splitlines()`` raised AttributeError, which
        is what ``python -OO`` hits."""
        _files(tmp_path, monkeypatch, _block([f'    "{ALPHA}",', f'    "{BETA}",']), [])
        monkeypatch.setattr(script, "__doc__", None)

        assert script.main() == 0
