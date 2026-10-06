# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for scripts/e2e/brew_formula.py, the head-build copy of Formula/ash.rb.

The Homebrew e2e job never installs Formula/ash.rb verbatim, because its `url`
line names a release tag and would build that release. It installs the copy
this script writes. So the copy has to differ from the formula in exactly one
place, the source, and the negative control's copy in exactly one more, the
dropped resource. Anything else it changed would be a formula nobody ships,
passing in CI.
"""

from __future__ import annotations

import difflib
import hashlib
import importlib.util
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
FORMULA = REPO / "Formula" / "ash.rb"
SCRIPT = REPO / "scripts" / "e2e" / "brew_formula.py"

_spec = importlib.util.spec_from_file_location("brew_formula", SCRIPT)
assert _spec is not None and _spec.loader is not None
brew_formula = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(brew_formula)

TARBALL = Path("/work/automated-security-helper-3.7.0.tar.gz").resolve()
SHA = "0" * 64


def _changed_lines(before: str, after: str) -> tuple[list[str], list[str]]:
    removed: list[str] = []
    added: list[str] = []
    for line in difflib.unified_diff(
        before.splitlines(), after.splitlines(), lineterm="", n=0
    ):
        if line.startswith(("---", "+++", "@@")):
            continue
        if line.startswith("-"):
            removed.append(line[1:])
        elif line.startswith("+"):
            added.append(line[1:])
    return removed, added


def _resources(text: str) -> list[str]:
    return re.findall(r'^  resource "([^"]+)" do$', text, re.MULTILINE)


class TestRenderAgainstTheRealFormula:
    def test_only_the_url_line_changes(self) -> None:
        formula = FORMULA.read_text(encoding="utf-8")
        rendered = brew_formula.render(formula, TARBALL, "3.7.0", SHA)
        removed, added = _changed_lines(formula, rendered)
        assert len(removed) == 1
        assert re.fullmatch(r'  url "[^"]+\.git", tag: "v[^"]+"', removed[0])
        assert added == [
            f'  url "{TARBALL.as_uri()}"',
            f'  sha256 "{SHA}"',
        ]

    def test_the_copy_keeps_every_resource_and_the_test_block(self) -> None:
        formula = FORMULA.read_text(encoding="utf-8")
        rendered = brew_formula.render(formula, TARBALL, "3.7.0", SHA)
        assert _resources(rendered) == _resources(formula)
        assert len(_resources(formula)) > 0
        assert rendered.count("test do") == formula.count("test do") == 1
        assert "tag:" not in rendered

    def test_drop_resource_removes_exactly_that_stanza(self) -> None:
        formula = FORMULA.read_text(encoding="utf-8")
        rendered = brew_formula.render(
            formula, TARBALL, "3.7.0", SHA, drop=["detect-secrets"]
        )
        before = _resources(formula)
        assert "detect-secrets" in before
        after = _resources(rendered)
        assert after == [name for name in before if name != "detect-secrets"]
        assert "detect_secrets-" not in rendered
        # Nothing but the url line and the one stanza (plus its trailing blank line).
        removed, _ = _changed_lines(formula, rendered)
        non_blank = [line for line in removed if line.strip()]
        assert len(non_blank) == 1 + 4

    def test_the_release_formula_test_block_runs_ashx_and_checks_the_ash_alias(
        self,
    ) -> None:
        # The patch this job exists to make safe: the test block names the v4 command,
        # and checks that the deprecated alias Homebrew keeps still runs and says so.
        formula = FORMULA.read_text(encoding="utf-8")
        test_block = formula[formula.index("  test do") :]
        assert 'ashx = bin/"ashx"' in test_block
        assert "the 'ash' command is deprecated" in test_block
        assert "#{bin}/ash --version" in test_block
        assert 'bin/"ash"' not in test_block


class TestRenderRefusesTheWrongShape:
    def test_no_tag_url_line(self) -> None:
        with pytest.raises(brew_formula.FormulaShapeError, match="found 0"):
            brew_formula.render('  url "file:///x.tar.gz"\n', TARBALL, "3.7.0", SHA)

    def test_two_tag_url_lines(self) -> None:
        line = '  url "https://example.invalid/a.git", tag: "v1.0.0"\n'
        with pytest.raises(brew_formula.FormulaShapeError, match="found 2"):
            brew_formula.render(line + line, TARBALL, "3.7.0", SHA)

    def test_a_resource_url_with_a_tag_is_not_the_formula_url(self) -> None:
        # Four-space indent: a stanza inside a resource block, never the formula's own.
        text = '  resource "x" do\n    url "https://example.invalid/x.git", tag: "v1"\n  end\n'
        with pytest.raises(brew_formula.FormulaShapeError, match="found 0"):
            brew_formula.render(text, TARBALL, "3.7.0", SHA)

    def test_missing_resource(self) -> None:
        formula = FORMULA.read_text(encoding="utf-8")
        with pytest.raises(brew_formula.FormulaShapeError, match="found 0"):
            brew_formula.render(
                formula, TARBALL, "3.7.0", SHA, drop=["no-such-resource"]
            )

    def test_relative_tarball(self) -> None:
        formula = FORMULA.read_text(encoding="utf-8")
        with pytest.raises(brew_formula.FormulaShapeError, match="absolute"):
            brew_formula.render(formula, Path("x.tar.gz"), "3.7.0", SHA)

    def test_tarball_name_without_the_version(self) -> None:
        # Homebrew reads the version from the name; a name carrying another version
        # would install under that version and the leg's version checks would chase it.
        formula = FORMULA.read_text(encoding="utf-8")
        wrong = Path("/work/automated-security-helper-3.6.0.tar.gz").resolve()
        with pytest.raises(brew_formula.FormulaShapeError, match="must be named"):
            brew_formula.render(formula, wrong, "3.7.0", SHA)

    def test_version_that_is_not_dotted_integers(self) -> None:
        formula = FORMULA.read_text(encoding="utf-8")
        with pytest.raises(brew_formula.FormulaShapeError, match="dotted integers"):
            brew_formula.render(formula, TARBALL, "3.7.0rc1", SHA)


class TestMain:
    def test_writes_the_copy_with_the_tarball_sha256(self, tmp_path: Path) -> None:
        tarball = tmp_path / "automated-security-helper-3.7.0.tar.gz"
        tarball.write_bytes(b"not really a tarball")
        out = tmp_path / "tap" / "ash.rb"
        rc = brew_formula.main(
            [
                "--formula",
                str(FORMULA),
                "--tarball",
                str(tarball),
                "--version",
                "3.7.0",
                "--out",
                str(out),
            ]
        )
        assert rc == 0
        text = out.read_text(encoding="utf-8")
        expected = hashlib.sha256(b"not really a tarball").hexdigest()
        assert f'  sha256 "{expected}"\n' in text
        assert f'  url "{tarball.resolve().as_uri()}"\n' in text

    def test_missing_tarball_is_an_error(self, tmp_path: Path) -> None:
        rc = brew_formula.main(
            [
                "--formula",
                str(FORMULA),
                "--tarball",
                str(tmp_path / "absent.tar.gz"),
                "--version",
                "3.7.0",
                "--out",
                str(tmp_path / "ash.rb"),
            ]
        )
        assert rc == 1
        assert not (tmp_path / "ash.rb").exists()
