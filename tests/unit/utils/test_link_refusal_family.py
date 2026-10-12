"""One family of link refusals, and the writes that name their own guarded root.

``OutputDirLinkRefused`` (a ``ValueError``) is raised when the output directory, or
a fixed name under it, is reached through a link. ``fs_guard`` raises
``OutputLinkRefused`` and ``OutputHardLinkRefused`` (``OSError``) when a write below
the output directory meets a link. Both of fs_guard's derive from
``OutputDirLinkRefused`` too, so an ``except`` clause written for either kind sees
both, and none of them is lost on the way through a pickle.

``open_for_write(..., root=...)`` guards the directory a writer names for that one
open, registering nothing, for the writers that can run where no ``PluginContext``
registered the output directory: the log files, the scan-set lists and the
workspace spool. ``exclusive`` creates the file and refuses one that is already
there.
"""

from __future__ import annotations

import errno
import pickle
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.output_dir_links import (
    OutputDirLinkRefused,
    open_no_follow,
)
from automated_security_helper.utils.sandbox import fs_guard
from automated_security_helper.utils.sandbox.fs_guard import (
    OutputHardLinkRefused,
    OutputLinkRefused,
)

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)

ORIGINAL = "outside content\n"


@pytest.fixture
def victim(tmp_path) -> Path:
    """A file outside the output directory that a link below it points at."""
    path = tmp_path / "outside" / "victim.txt"
    path.parent.mkdir()
    path.write_text(ORIGINAL)
    return path


@pytest.fixture
def output(tmp_path) -> Path:
    """An output directory that no PluginContext registered."""
    path = tmp_path / "out"
    path.mkdir()
    assert fs_guard._writable_root_for(path / "x") is None
    return path


class TestOneFamily:
    @pytest.mark.parametrize(
        "refusal, code",
        [
            (OutputLinkRefused("out/ash.log", "out/ash.log"), errno.ELOOP),
            (OutputHardLinkRefused("out/ash.log", 2), errno.EMLINK),
        ],
        ids=["symlink", "hard-link"],
    )
    def test_a_refused_write_is_both_kinds_of_refusal(self, refusal, code):
        assert isinstance(refusal, OSError)
        assert isinstance(refusal, OutputDirLinkRefused)
        assert isinstance(refusal, ValueError)
        assert refusal.errno == code
        assert "out/ash.log" in refusal.found

    def test_a_refused_output_directory_stays_a_value_error(self):
        refusal = OutputDirLinkRefused("the output directory out is a symlink")

        assert isinstance(refusal, ValueError)
        assert not isinstance(refusal, OSError)

    @pytest.mark.parametrize(
        "refusal",
        [
            OutputLinkRefused("out/a.json", "out/reports"),
            OutputHardLinkRefused("out/a.json", 3),
            OutputDirLinkRefused("out/reports is a symlink", "Use another."),
        ],
        ids=["symlink", "hard-link", "output-directory"],
    )
    def test_each_refusal_comes_back_whole_from_a_pickle(self, refusal):
        """A worker process hands its exception back to the parent pickled."""
        back = pickle.loads(pickle.dumps(refusal))

        assert type(back) is type(refusal)
        assert str(back) == str(refusal)
        assert back.found == refusal.found
        assert getattr(back, "errno", None) == getattr(refusal, "errno", None)

    @needs_symlinks
    def test_a_clause_for_the_output_directory_catches_a_refused_write(
        self, output, victim
    ):
        (output / "ash.log").symlink_to(victim)

        try:
            fs_guard.open_for_write(output / "ash.log", root=output)
        except OutputDirLinkRefused as refusal:
            caught = refusal
        else:
            pytest.fail("a link at the name was written through")

        assert isinstance(caught, OutputLinkRefused)
        assert victim.read_text() == ORIGINAL


@needs_symlinks
class TestARootTheWriterNames:
    def test_a_link_at_the_name_is_refused(self, output, victim):
        (output / "ash-scan-set-files-list.txt").symlink_to(victim)

        with pytest.raises(OutputLinkRefused):
            fs_guard.open_for_write(output / "ash-scan-set-files-list.txt", root=output)

        assert victim.read_text() == ORIGINAL

    def test_a_link_at_a_directory_below_it_is_refused(self, output, victim):
        (output / ".workspace-spool").symlink_to(
            victim.parent, target_is_directory=True
        )

        with pytest.raises(OutputLinkRefused):
            fs_guard.open_for_write(
                output / ".workspace-spool" / "victim.txt", root=output
            )

        assert victim.read_text() == ORIGINAL

    def test_without_it_the_same_link_is_followed(self, output, victim):
        """Control: the outside-root rule is unchanged."""
        (output / "ash.log").symlink_to(victim)

        with fs_guard.open_for_write(output / "ash.log") as handle:
            handle.write("written\n")

        assert victim.read_text() == "written\n"

    def test_a_path_outside_it_is_not_opened(self, output, tmp_path):
        with pytest.raises(ValueError, match="is not below"):
            fs_guard.open_for_write(tmp_path / "elsewhere.txt", root=output)

        assert not (tmp_path / "elsewhere.txt").exists()

    def test_a_registered_root_above_it_is_checked_too(self, tmp_path, victim):
        outer = tmp_path / "registered"
        (outer / "reports").mkdir(parents=True)
        fs_guard.register_writable_root(outer)
        (outer / "reports" / "nested").symlink_to(
            victim.parent, target_is_directory=True
        )

        with pytest.raises(OutputLinkRefused):
            fs_guard.open_for_write(
                outer / "reports" / "nested" / "victim.txt",
                root=outer / "reports" / "nested",
            )

        assert victim.read_text() == ORIGINAL

    def test_a_regular_file_there_is_written(self, output):
        with fs_guard.open_for_write(output / "ash.log", root=output) as handle:
            handle.write("written\n")

        assert (output / "ash.log").read_text() == "written\n"

    def test_open_no_follow_is_open_for_write_on_the_file_s_directory(
        self, output, victim
    ):
        (output / "ash.log").symlink_to(victim)

        with pytest.raises(OutputLinkRefused):
            open_no_follow(output / "ash.log")
        with open_no_follow(output / "ash.log.jsonl") as handle:
            handle.write("written\n")

        assert victim.read_text() == ORIGINAL
        assert (output / "ash.log.jsonl").read_text() == "written\n"


class TestExclusiveCreation:
    @pytest.mark.parametrize("guarded", [True, False], ids=["guarded", "unguarded"])
    def test_a_file_already_at_the_name_is_not_opened(self, output, guarded):
        existing = output / "notebook-converted.py"
        existing.write_text(ORIGINAL)
        root = output if guarded else None

        with pytest.raises(FileExistsError):
            fs_guard.open_for_write(existing, mode=0o644, exclusive=True, root=root)

        assert existing.read_text() == ORIGINAL

    @pytest.mark.parametrize("guarded", [True, False], ids=["guarded", "unguarded"])
    def test_a_new_file_is_created(self, output, guarded):
        target = output / "notebook-converted.py"
        root = output if guarded else None

        with fs_guard.open_for_write(
            target, binary=True, mode=0o644, exclusive=True, root=root
        ) as handle:
            handle.write(b"print(1)\n")

        assert target.read_bytes() == b"print(1)\n"

    @needs_symlinks
    def test_a_link_at_the_name_is_refused(self, output, victim):
        (output / "notebook-converted.py").symlink_to(victim)

        with pytest.raises(OutputLinkRefused):
            fs_guard.open_for_write(
                output / "notebook-converted.py", exclusive=True, root=output
            )

        assert victim.read_text() == ORIGINAL

    def test_it_cannot_also_append(self, output):
        with pytest.raises(ValueError, match="cannot also append"):
            fs_guard.open_for_write(output / "a.txt", exclusive=True, append=True)


@needs_symlinks
class TestTheNameWithoutDirectoryDescriptors:
    """Without directory descriptors (Windows) a named root is checked by name."""

    @pytest.fixture(autouse=True)
    def _no_directory_descriptors(self, monkeypatch):
        monkeypatch.setattr(fs_guard, "_HAS_DIR_FD", False)

    def test_a_link_at_the_name_is_refused(self, output, victim):
        (output / "ash.log").symlink_to(victim)

        with pytest.raises(OutputLinkRefused):
            fs_guard.open_for_write(output / "ash.log", root=output)

        assert victim.read_text() == ORIGINAL

    def test_outside_a_root_the_link_is_followed(self, output, victim):
        """Control: the same link, with no root named or registered."""
        (output / "ash.log").symlink_to(victim)

        with fs_guard.open_for_write(output / "ash.log") as handle:
            handle.write("written\n")

        assert victim.read_text() == "written\n"


@needs_symlinks
class TestARootThatIsALink:
    """A root is opened by name, so a link at the root itself is refused."""

    def test_registering_it_is_refused(self, tmp_path, victim):
        linked = tmp_path / "linked-out"
        linked.symlink_to(victim.parent, target_is_directory=True)
        before = fs_guard.registered_roots()

        with pytest.raises(OutputLinkRefused, match="linked-out is a symlink"):
            fs_guard.register_writable_root(linked)

        assert fs_guard.registered_roots() == before

    def test_naming_it_to_open_for_write_is_refused(self, tmp_path, victim):
        linked = tmp_path / "linked-out"
        linked.symlink_to(victim.parent, target_is_directory=True)

        with pytest.raises(OutputLinkRefused):
            fs_guard.open_for_write(linked / "victim.txt", root=linked)

        assert victim.read_text() == ORIGINAL

    def test_a_directory_is_registered(self, output):
        """Control."""
        with fs_guard.writable_root(output) as root:
            assert root in fs_guard.registered_roots()


@needs_symlinks
class TestTheAtomicRename:
    """write_text_atomically's rename does not replace a link at the target."""

    def test_a_link_at_the_name_when_it_renames_is_refused_and_kept(
        self, output, victim
    ):
        """The link appears after the directory was opened; the rename checks again."""
        import os

        from automated_security_helper.utils.atomic_write import _write_beneath

        target = output / "ash_aggregated_results.json"
        target.symlink_to(victim)
        dir_fd = os.open(output, os.O_RDONLY)

        with pytest.raises(OutputLinkRefused):
            _write_beneath(dir_fd, target.name, content="{}", encoding="utf-8")

        assert target.is_symlink(), "the link was replaced"
        assert victim.read_text() == ORIGINAL
        assert [p.name for p in output.iterdir()] == [target.name], (
            "the staging file was left behind"
        )

    def test_a_regular_file_there_is_replaced(self, output):
        """Control."""
        import os

        from automated_security_helper.utils.atomic_write import _write_beneath

        target = output / "ash_aggregated_results.json"
        target.write_text("old")

        _write_beneath(
            os.open(output, os.O_RDONLY), target.name, content="new", encoding="utf-8"
        )

        assert target.read_text() == "new"


@needs_symlinks
class TestThePackageManagerCopies:
    """npm's and pnpm's private copies are made below the scanner's results directory."""

    def test_a_link_in_the_private_directory_is_not_written_through(
        self, output, victim
    ):
        from automated_security_helper.utils.package_manager_child import _write_copy

        private = output / "scanners" / "npm-audit" / "source" / "ash-npm-x"
        (private / "project").mkdir(parents=True)
        (private / "project" / "package-lock.json").symlink_to(victim)

        with pytest.raises(OutputLinkRefused):
            _write_copy(private / "project" / "package-lock.json", b"{}", private)

        assert victim.read_text() == ORIGINAL

    def test_the_copies_are_written(self, output, tmp_path):
        from automated_security_helper.utils.package_manager_child import (
            package_manager_child,
        )

        package = tmp_path / "package"
        package.mkdir()
        (package / "package.json").write_text('{"name": "p"}\n')
        (package / "package-lock.json").write_text('{"lockfileVersion": 3}\n')

        with package_manager_child("npm", package, parent=output) as child:
            copied = {p.name: p.read_text() for p in child.cwd.iterdir()}

        assert copied == {
            "package.json": '{"name": "p"}\n',
            "package-lock.json": '{"lockfileVersion": 3}\n',
        }
