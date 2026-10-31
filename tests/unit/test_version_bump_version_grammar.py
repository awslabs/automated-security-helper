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
will report for the built distribution. ``set`` goes further and writes final
X.Y.Z versions only: the install-command pins in the generated pages, and every
check that reads them, know a release as X.Y.Z alone, so a pre-release, post-release
or development version written into a page would read as a malformed pin.

What is asserted
----------------
The release numbers of every PEP 440 pre-release, post-release and development form
parse; text that is not PEP 440 is refused by ``validate_version`` and, through
``set``, leaves pyproject.toml and the generated pages as they were; ``set`` refuses
a version that is not final and changes nothing; and a ``bump`` from a version that
is not final (one a pyproject.toml can still carry) finalizes a pre-release or
development version when the bump names the release it leads up to (2.0.0rc1 patch
gives 2.0.0, as in semver and commitizen), counts from the release numbers otherwise
and says that the pre-release part is dropped, and bumps a post-release version
without a note.

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

    @pytest.mark.parametrize(
        "version",
        [
            "3.8.0a2",
            "3.8.0b3",
            "3.8.0rc1",
            "3.8.0.dev1",
            "3.8.0rc1.dev2",
            # The spelling an old ``set`` wrote: PEP 440 reads it as 3.8.0rc1, so the
            # finalize rule applies to it as to the pip spelling.
            "3.8.0-rc1",
        ],
    )
    def test_a_bump_from_a_version_before_its_release_finalizes_it(
        self, monkeypatch, version
    ):
        # Red before the finalize rule: the release numbers alone were counted, so
        # 3.8.0rc1 went to 3.8.1 or 3.9.0 and 3.8.0, the release it led up to, could
        # never come out of ``bump``.
        module = _load_version_bump(monkeypatch)
        assert module.bump_version(version, "patch") == "3.8.0"
        assert module.bump_version(version, "minor") == "3.8.0"
        assert module.bump_version(version, "major") == "4.0.0"

    @pytest.mark.parametrize(
        "version, patch, minor, major",
        [
            # A bump that does not name the release the version leads up to counts
            # from the release numbers: 3.8.2rc1 is before 3.8.2, not before 3.9.0.
            ("3.8.2rc1", "3.8.2", "3.9.0", "4.0.0"),
            ("3.8.2.dev3", "3.8.2", "3.9.0", "4.0.0"),
            # Every number after the first is 0, so the major bump names it too.
            ("4.0.0rc1", "4.0.0", "4.0.0", "4.0.0"),
            ("4.0.0.dev1", "4.0.0", "4.0.0", "4.0.0"),
            ("4.1.0rc2", "4.1.0", "4.1.0", "5.0.0"),
        ],
    )
    def test_the_bump_that_names_the_release_finalizes_and_no_other_does(
        self, monkeypatch, version, patch, minor, major
    ):
        module = _load_version_bump(monkeypatch)
        assert module.bump_version(version, "patch") == patch
        assert module.bump_version(version, "minor") == minor
        assert module.bump_version(version, "major") == major

    @pytest.mark.parametrize("version", ["3.8.0.post1", "3.8.0.post1.dev2"])
    def test_a_version_after_its_release_counts_from_the_release_numbers(
        self, monkeypatch, version
    ):
        # 3.8.0.post1 comes after 3.8.0, so nothing is finalized: the next patch is
        # 3.8.1, as for 3.8.0 itself.
        module = _load_version_bump(monkeypatch)
        assert module.bump_version(version, "patch") == "3.8.1"
        assert module.bump_version(version, "minor") == "3.9.0"
        assert module.bump_version(version, "major") == "4.0.0"

    def test_a_pre_release_with_a_post_release_part_still_precedes_its_release(
        self, monkeypatch
    ):
        module = _load_version_bump(monkeypatch)
        assert module.bump_version("3.8.0rc1.post1", "patch") == "3.8.0"

    def test_a_final_version_is_bumped_as_before(self, monkeypatch):
        module = _load_version_bump(monkeypatch)
        assert module.bump_version("3.8.0", "patch") == "3.8.1"
        assert module.bump_version("3.8.0", "minor") == "3.9.0"
        assert module.bump_version("3.8.0", "major") == "4.0.0"

    def test_a_bump_type_that_does_not_exist_is_refused(self, monkeypatch):
        module = _load_version_bump(monkeypatch)
        with pytest.raises(ValueError, match="Invalid bump type"):
            module.bump_version("3.8.0rc1", "micro")

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

    @pytest.mark.parametrize("version", ["2.0.0rc1", "2.0.0.post1", "2.0.0.dev1"])
    def test_a_version_that_is_not_final_is_refused_and_changes_nothing(
        self, project, monkeypatch, capsys, version
    ):
        # Red at the previous commit: validate_version accepted these, so set wrote
        # "@v2.0.0rc1" into the page, a pin the readers of the pages (X.Y.Z only)
        # take as malformed, and returned True.
        module = _load_version_bump(monkeypatch)
        before = {
            name: project.joinpath(name).read_text(encoding="utf-8")
            for name in ("pyproject.toml", "README.md")
        }
        assert _bumper(module, project).set_version(version) is False
        for name, text in before.items():
            assert project.joinpath(name).read_text(encoding="utf-8") == text
        out = capsys.readouterr().out
        assert f"{version} is not a final release" in out
        assert "X.Y.Z" in out
        assert "Successfully updated" not in out

    def test_a_final_version_is_written_to_both_tables_and_the_pages(
        self, project, monkeypatch
    ):
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).set_version("2.0.0") is True
        pyproject = project.joinpath("pyproject.toml").read_text(encoding="utf-8")
        assert pyproject.count('version = "2.0.0"') == 2, pyproject
        assert (
            project.joinpath("README.md").read_text(encoding="utf-8")
            == "pip install git+https://example.invalid/ash.git@v2.0.0\n"
        )

    def test_a_bump_from_a_pre_release_writes_the_release_it_led_up_to(
        self, project, monkeypatch
    ):
        # Red before the finalize rule: this wrote 2.0.1, and 2.0.0 could not come
        # out of ``bump`` at all.
        project.joinpath("pyproject.toml").write_text(
            _pyproject("2.0.0rc1"), encoding="utf-8"
        )
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).bump_version("patch") is True
        pyproject = project.joinpath("pyproject.toml").read_text(encoding="utf-8")
        assert pyproject.count('version = "2.0.0"') == 2, pyproject
        assert (
            project.joinpath("README.md").read_text(encoding="utf-8")
            == "pip install git+https://example.invalid/ash.git@v2.0.0\n"
        )

    def test_a_bump_past_the_release_counts_from_the_release_numbers(
        self, project, monkeypatch
    ):
        project.joinpath("pyproject.toml").write_text(
            _pyproject("2.0.1rc1"), encoding="utf-8"
        )
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).bump_version("minor") is True
        pyproject = project.joinpath("pyproject.toml").read_text(encoding="utf-8")
        assert pyproject.count('version = "2.1.0"') == 2, pyproject


class TestBumpFromANonFinalVersionSaysSo:
    def test_the_dropped_part_is_reported(self, project, monkeypatch, capsys):
        # A pre-release version a pyproject.toml can still carry (hand-edited,
        # or written by an earlier set); set itself no longer writes one. Here the
        # bump goes past the release 2.0.1rc1 leads up to, so the part is dropped.
        project.joinpath("pyproject.toml").write_text(
            _pyproject("2.0.1rc1"), encoding="utf-8"
        )
        module = _load_version_bump(monkeypatch)
        bumper = _bumper(module, project)
        assert bumper.bump_version("minor") is True
        out = capsys.readouterr().out
        assert "2.0.1rc1 is not a final release" in out
        assert "that part is dropped" in out
        assert "2.1.0 follows" in out

    def test_the_finalized_release_is_reported(self, project, monkeypatch, capsys):
        project.joinpath("pyproject.toml").write_text(
            _pyproject("2.0.0rc1"), encoding="utf-8"
        )
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).bump_version("minor") is True
        out = capsys.readouterr().out
        assert "2.0.0rc1 is not a final release" in out
        assert "finalizes it: 2.0.0 follows" in out
        assert "dropped" not in out

    def test_a_post_release_is_bumped_without_the_note(
        self, project, monkeypatch, capsys
    ):
        # 2.0.0.post1 comes after the final 2.0.0; dropping .post1 on a patch bump
        # is right, and calling it "not a final release" was not.
        project.joinpath("pyproject.toml").write_text(
            _pyproject("2.0.0.post1"), encoding="utf-8"
        )
        module = _load_version_bump(monkeypatch)
        assert _bumper(module, project).bump_version("patch") is True
        out = capsys.readouterr().out
        assert "not a final release" not in out
        assert "Successfully updated version to 2.0.1" in out

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
