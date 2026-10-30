# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scripts/version_bump.py`` reads and writes versions in PEP 440, and only PEP 440.

Why this file exists
--------------------
``parse_version`` matched ``X.Y.Z`` followed by an optional hyphen and any text.
Two things followed from that grammar:

* The forms the installed distribution reports, 3.8.0rc1 and 3.8.0.dev1, have no
  hyphen, so ``bump`` failed with "Invalid version format" on any pre-release or
  development version, and ``set`` refused to write one.
* The text after a hyphen was never checked, so ``set`` wrote a string that is not
  a version into pyproject.toml, a quote or a trailing newline included, where it
  broke the TOML string it was inserted into.

The grammar is now PEP 440's with three release numbers. ``validate_version`` also
requires the spelling pip prints, so what ``set`` writes is what importlib.metadata
will report for the built distribution.

What is asserted
----------------
The release numbers of every PEP 440 pre-release, post-release and development form
parse; text that is not PEP 440 is refused by ``validate_version`` and, through
``set``, leaves pyproject.toml and the generated pages as they were; a pre-release
version round-trips through ``set`` and ``bump``; and a ``bump`` from a version that
is not a final release says that its pre-release part is dropped.

Each test builds its trees under ``tmp_path`` and points the script's own-checkout
lookup elsewhere, so no run touches this repository's pyproject.toml.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "version_bump.py"
MODULE = "automated_security_helper.utils.version_management"


def _load_version_bump(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "version_bump_grammar_under_test", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _pyproject(version: str) -> str:
    return (
        "[project]\n"
        'name = "automated-security-helper"\n'
        f'version = "{version}"\n'
        "\n"
        "[tool.commitizen]\n"
        f'version = "{version}"\n'
    )


def _checkout(root: Path, version: str) -> Path:
    root.mkdir()
    root.joinpath("pyproject.toml").write_text(_pyproject(version), encoding="utf-8")
    root.joinpath("README.md.template").write_text(
        "pip install git+https://example.invalid/ash.git@v{{VERSION}}\n",
        encoding="utf-8",
    )
    root.joinpath("README.md").write_text(
        f"pip install git+https://example.invalid/ash.git@v{version}\n",
        encoding="utf-8",
    )
    return root


@pytest.fixture
def project(tmp_path, monkeypatch):
    """A project root at 1.2.3; the script's own checkout is a stand-in."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    elsewhere.joinpath("pyproject.toml").write_text(
        _pyproject("0.0.1"), encoding="utf-8"
    )
    monkeypatch.setattr(f"{MODULE}.get_project_root", lambda: elsewhere)
    return _checkout(tmp_path / "project", "1.2.3")


def _bumper(module, project: Path):
    bumper = module.VersionBumper(project)
    bumper.template_manager.target_files = ["README.md"]
    return bumper


PEP440_NON_FINAL = [
    "3.8.0a2",
    "3.8.0b3",
    "3.8.0rc1",
    "3.8.0.dev1",
    "3.8.0.post1",
    "3.8.0rc1.dev2",
]


class TestPep440VersionsParse:
    @pytest.mark.parametrize("version", PEP440_NON_FINAL)
    def test_parse_version_returns_the_release_numbers(self, monkeypatch, version):
        # Red at the base: no hyphen, so the pattern does not match and
        # parse_version raises "Invalid version format".
        module = _load_version_bump(monkeypatch)
        assert module.parse_version(version) == (3, 8, 0)

    def test_parse_version_reads_a_hyphenated_pre_release_as_before(self, monkeypatch):
        # A pyproject.toml written by the old ``set`` can still carry this spelling.
        module = _load_version_bump(monkeypatch)
        assert module.parse_version("3.8.0-rc1") == (3, 8, 0)

    @pytest.mark.parametrize("version", PEP440_NON_FINAL)
    def test_bump_counts_from_the_release_numbers(self, monkeypatch, version):
        module = _load_version_bump(monkeypatch)
        assert module.bump_version(version, "patch") == "3.8.1"
        assert module.bump_version(version, "minor") == "3.9.0"
        assert module.bump_version(version, "major") == "4.0.0"

    @pytest.mark.parametrize(
        "version", ["3.8", "3.8.0.1", "1!3.8.0", "latest", "", "3.8.x"]
    )
    def test_a_version_without_three_release_numbers_is_refused(
        self, monkeypatch, version
    ):
        module = _load_version_bump(monkeypatch)
        with pytest.raises(ValueError, match="Invalid version format"):
            module.parse_version(version)


class TestValidateVersionIsPep440:
    @pytest.mark.parametrize("version", ["3.8.0", "0.0.1", *PEP440_NON_FINAL])
    def test_a_canonical_pep440_version_is_valid(self, monkeypatch, version):
        # Red at the base for every form but the first two.
        module = _load_version_bump(monkeypatch)
        assert module.validate_version(version) is True

    @pytest.mark.parametrize(
        "version",
        [
            "3.8.0-anything",
            "3.8.0-rc1",
            '3.8.0-a"b',
            "3.8.0-",
            "3.8.0\n",
            " 3.8.0",
            "v3.8.0",
            "3.8",
            "3.8.0.1",
            "1!3.8.0",
            "3.8.0+local",
            "3.8.0rc",
            "",
        ],
    )
    def test_text_that_is_not_a_canonical_pep440_version_is_not_valid(
        self, monkeypatch, version
    ):
        # Red at the base for the hyphen forms and the trailing newline: the
        # pattern took a hyphen followed by anything, and "$" matches before a
        # final newline.
        module = _load_version_bump(monkeypatch)
        assert module.validate_version(version) is False


class TestSetWritesOnlyAVersion:
    @pytest.mark.parametrize("version", ['3.8.0-a"b', "3.8.0-rc1", "3.8.0\n"])
    def test_a_refused_version_changes_nothing(
        self, project, monkeypatch, capsys, version
    ):
        # Red at the base: validate_version accepted these, so set wrote them
        # into both tables of pyproject.toml and into the generated page.
        module = _load_version_bump(monkeypatch)
        before = {
            name: project.joinpath(name).read_text(encoding="utf-8")
            for name in ("pyproject.toml", "README.md")
        }
        assert _bumper(module, project).set_version(version) is False
        for name, text in before.items():
            assert project.joinpath(name).read_text(encoding="utf-8") == text
        out = capsys.readouterr().out
        assert "Invalid version format" in out
        assert "PEP 440" in out
        assert "Successfully updated" not in out

    def test_a_pre_release_is_written_to_both_tables_and_the_pages(
        self, project, monkeypatch
    ):
        # Red at the base: validate_version refused 2.0.0rc1, so set returned False.
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).set_version("2.0.0rc1") is True
        pyproject = project.joinpath("pyproject.toml").read_text(encoding="utf-8")
        assert pyproject.count('version = "2.0.0rc1"') == 2, pyproject
        assert (
            project.joinpath("README.md").read_text(encoding="utf-8")
            == "pip install git+https://example.invalid/ash.git@v2.0.0rc1\n"
        )

    def test_a_bump_after_setting_a_pre_release_counts_from_its_release_numbers(
        self, project, monkeypatch
    ):
        module = _load_version_bump(monkeypatch)
        bumper = _bumper(module, project)
        assert bumper.set_version("2.0.0rc1") is True
        assert bumper.bump_version("patch") is True
        pyproject = project.joinpath("pyproject.toml").read_text(encoding="utf-8")
        assert pyproject.count('version = "2.0.1"') == 2, pyproject


class TestBumpFromANonFinalVersionSaysSo:
    def test_the_dropped_part_is_reported(self, project, monkeypatch, capsys):
        module = _load_version_bump(monkeypatch)
        bumper = _bumper(module, project)
        assert bumper.set_version("2.0.0rc1") is True
        capsys.readouterr()
        assert bumper.bump_version("minor") is True
        out = capsys.readouterr().out
        assert "2.0.0rc1 is not a final release" in out
        assert "2.1.0 follows" in out

    def test_a_final_release_is_bumped_without_the_note(
        self, project, monkeypatch, capsys
    ):
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).bump_version("patch") is True
        out = capsys.readouterr().out
        assert "not a final release" not in out
        assert "Successfully updated version to 1.2.4" in out

    def test_a_bump_from_text_that_is_not_a_version_fails_with_the_reason(
        self, project, monkeypatch, capsys
    ):
        project.joinpath("pyproject.toml").write_text(
            _pyproject("not-a-version"), encoding="utf-8"
        )
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).bump_version("patch") is False
        assert "Invalid version format: not-a-version" in capsys.readouterr().out
