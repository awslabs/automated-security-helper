"""The drift gate itself.

Regression tests for a gate that could pass having compared nothing. It detected
drift by running ``git status --porcelain --untracked-files=all -- <dir>`` and reading
empty output as agreement. ``--untracked-files=all`` does not list **ignored** paths,
so with ``generated/`` under any ignore rule the query returned nothing and the gate
printed "match byte for byte" and exited 0 over a directory whose contents had been
replaced wholesale. It also failed in the other direction, reporting drift for
untracked files whose content matched exactly. And it called ``write_all()`` before
asking, overwriting the committed files, so in the ignored case there was nothing left
to compare even in principle.

``TestIgnoredDirectoryControl`` is the discriminating case: it demonstrates inside the
test that the old oracle returns nothing, and that the new one fails anyway.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from ash_operator.generate_manifests import (
    GENERATED_GLOB,
    TRANSLATION_REPORT,
    check,
    generated_on_disk,
    render_all,
    write_all,
)


@pytest.fixture(scope="module")
def expected() -> dict[str, str]:
    return render_all()


@pytest.fixture
def populated(tmp_path, expected):
    """A directory holding exactly what the generator emits."""
    write_all(tmp_path)
    return tmp_path


def old_git_oracle(directory: Path) -> str:
    """The query the gate used to rely on, so its blind spot is shown not asserted."""
    return subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all", "--", str(directory)],
        capture_output=True,
        text=True,
        cwd=directory,
        check=False,
    ).stdout


def init_repo(directory: Path, *, ignore: str | None = None) -> None:
    subprocess.run(["git", "init", "-q", "."], cwd=directory, check=True)
    if ignore:
        (directory / ".gitignore").write_text(f"{ignore}\n")
    subprocess.run(["git", "add", "-A"], cwd=directory, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            "init",
        ],
        cwd=directory,
        check=True,
    )


class TestRenderAll:
    def test_it_emits_both_crds_and_the_translation_report(self, expected):
        assert sorted(expected) == [
            TRANSLATION_REPORT,
            "crd-ashmcpservers.yaml",
            "crd-ashscans.yaml",
        ]

    def test_it_writes_nothing(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        render_all()
        assert list(tmp_path.iterdir()) == []

    def test_it_is_deterministic(self, expected):
        assert render_all() == expected


class TestCheck:
    def test_a_matching_directory_passes(self, populated, capsys):
        # Positive control. Without it every failure case below could be a gate that
        # fails unconditionally -- which is exactly the shape of the bug it replaced,
        # inverted.
        assert check(populated) == 0
        assert "match byte for byte" in capsys.readouterr().out

    def test_check_writes_nothing(self, populated):
        before = {p.name: p.read_bytes() for p in generated_on_disk(populated)}
        mtimes = {p.name: p.stat().st_mtime_ns for p in generated_on_disk(populated)}
        check(populated)
        after = {p.name: p.read_bytes() for p in generated_on_disk(populated)}
        assert before == after
        assert mtimes == {p.name: p.stat().st_mtime_ns for p in generated_on_disk(populated)}

    def test_one_changed_byte_fails_and_the_message_locates_it(self, populated, capsys):
        target = populated / "crd-ashscans.yaml"
        body = target.read_text()
        target.write_text(body.replace("Namespaced", "Cluster", 1))
        assert check(populated) == 1
        err = capsys.readouterr().err
        assert "crd-ashscans.yaml: differs" in err
        assert "first differs at byte" in err

    def test_a_trailing_newline_is_not_forgiven(self, populated, capsys):
        # A gate that normalises whitespace would launder a real diff; the committed
        # file is the deliverable, byte for byte.
        target = populated / TRANSLATION_REPORT
        target.write_bytes(target.read_bytes().rstrip(b"\n"))
        assert check(populated) == 1
        assert "lengths differ" in capsys.readouterr().err

    def test_a_missing_file_fails(self, populated, capsys):
        (populated / "crd-ashmcpservers.yaml").unlink()
        assert check(populated) == 1
        err = capsys.readouterr().err
        assert "crd-ashmcpservers.yaml: missing" in err
        assert "never committed" in err

    def test_a_missing_translation_report_fails(self, populated, capsys):
        (populated / TRANSLATION_REPORT).unlink()
        assert check(populated) == 1
        assert f"{TRANSLATION_REPORT}: missing" in capsys.readouterr().err

    def test_an_orphan_generated_file_fails(self, populated, capsys):
        # A CRD whose kind was removed. The git-based version inferred this from a
        # deletion git reported after write_all removed it; now it is stated directly.
        (populated / "crd-ashwidgets.yaml").write_text("# left over from a removed kind\n")
        assert check(populated) == 1
        err = capsys.readouterr().err
        assert "crd-ashwidgets.yaml: orphan" in err
        assert "no longer emits it" in err

    def test_an_empty_directory_fails(self, tmp_path, capsys):
        assert check(tmp_path) == 1
        assert "missing" in capsys.readouterr().err

    def test_an_unrelated_neighbour_is_left_alone(self, populated):
        # Ownership is by filename pattern, so a README or kustomization beside the
        # generated files must not read as an orphan.
        (populated / "README.md").write_text("hand written\n")
        (populated / "kustomization.yaml").write_text("resources: []\n")
        assert check(populated) == 0

    def test_it_needs_no_git_repository_at_all(self, populated):
        # Also dissolves an act limitation: the crd-drift job used to fail under
        # nektos/act with "fatal: not a git repository", because act's checkout leaves
        # no usable .git in the job container.
        assert not (populated / ".git").exists()
        assert check(populated) == 0


class TestIgnoredDirectoryControl:
    """The case the old gate passed and this one must fail.

    Not merely "the new gate fails here" -- the test also runs the old oracle and
    shows it returns nothing, so the reason is pinned rather than the outcome.
    """

    @pytest.fixture
    def ignored_repo(self, tmp_path):
        repo = tmp_path / "repo"
        generated = repo / "generated"
        generated.mkdir(parents=True)
        write_all(generated)
        init_repo(repo, ignore="generated/")
        assert (
            subprocess.run(
                ["git", "check-ignore", "-q", "generated"], cwd=repo, check=False
            ).returncode
            == 0
        ), "the fixture did not actually ignore the directory"
        return generated

    def test_the_old_oracle_sees_nothing_even_when_content_is_replaced(self, ignored_repo):
        (ignored_repo / "crd-ashscans.yaml").write_text("COMPLETELY DIFFERENT\n")
        assert old_git_oracle(ignored_repo).strip() == "", (
            "git now reports ignored paths without --ignored, so the original gate's "
            "blind spot may have closed; re-measure before trusting this test's premise"
        )

    def test_the_new_check_fails_anyway(self, ignored_repo, capsys):
        (ignored_repo / "crd-ashscans.yaml").write_text("COMPLETELY DIFFERENT\n")
        assert check(ignored_repo) == 1, (
            "the gate passed over an ignored directory whose content was replaced. "
            "This is the exact failure the in-memory comparison exists to prevent."
        )
        assert "crd-ashscans.yaml: differs" in capsys.readouterr().err

    def test_an_ignored_directory_that_matches_still_passes(self, ignored_repo):
        # The fix must not turn "ignored" into a failure of its own; content is the
        # only question being asked.
        assert check(ignored_repo) == 0


class TestUntrackedButCorrect:
    """The inverse failure: drift reported for files that match exactly."""

    @pytest.fixture
    def untracked(self, tmp_path):
        repo = tmp_path / "repo"
        generated = repo / "generated"
        generated.mkdir(parents=True)
        (repo / "README.md").write_text("x\n")
        init_repo(repo)
        write_all(generated)
        return generated

    def test_the_old_oracle_reported_drift(self, untracked):
        assert old_git_oracle(untracked).strip() != "", (
            "the premise of this test is that untracked files show as ?? ; they no "
            "longer do, so re-measure"
        )

    def test_the_new_check_passes(self, untracked):
        # Previously unclearable: regenerating could not silence it, only `git add`.
        assert check(untracked) == 0


class TestWriteAll:
    def test_it_removes_a_file_it_no_longer_emits(self, populated):
        orphan = populated / "crd-ashwidgets.yaml"
        orphan.write_text("# removed kind\n")
        write_all(populated)
        assert not orphan.exists()

    def test_it_leaves_unrelated_files_alone(self, populated):
        keeper = populated / "README.md"
        keeper.write_text("hand written\n")
        write_all(populated)
        assert keeper.read_text() == "hand written\n"

    def test_write_then_check_agrees(self, tmp_path):
        # The two paths consume one render_all(), so this is structural rather than a
        # coincidence -- but it is the property the gate depends on, so it is asserted.
        write_all(tmp_path)
        assert check(tmp_path) == 0

    def test_the_glob_and_the_report_are_both_owned(self, populated):
        owned = {p.name for p in generated_on_disk(populated)}
        assert TRANSLATION_REPORT in owned
        assert any(Path(name).match(GENERATED_GLOB) for name in owned)
