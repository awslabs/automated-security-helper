# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The image's license check and the script's command line.

* ``reports_version`` accepted a prerelease or distro build of the pinned version
  (0.12.2rc1, 0.12.2-1) as the pinned release. It still accepted the dotted
  PEP 440 spellings (1.125.0.post1, 1.2.3.dev0, 1.2.3.rc1) and Debian's tilde
  (1.2.3~rc1), which matter most for the Python tools.
* ``version_output`` decoded the tool's output strictly, so a banner that was not
  valid text raised out of the whole verification.
* ``verify_third_party`` left the index of an earlier passing run in place when the
  current run found problems, never looked at the search permission of the
  directories it reads through, crashed on a SOURCE file that is not UTF-8, and ran a
  version probe through whatever the process PATH held, relative entries included.
* ``main`` recognized the license modes and ``--assert-root-only`` only as the very
  first argument, so ``--pins-dir DIR --uv-tool-pins`` and ``--licenses-only=TOOL``
  failed with a usage error from the wrong parser.

Nothing here reaches the network. The one test that starts a child process says so.
"""

from __future__ import annotations

import errno
import importlib.util
import json
import os
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "automated_security_helper" / "assets" / "install-pinned-tool.py"
PACKAGE_ROOT = REPO_ROOT / "automated_security_helper"


def _load_script():
    spec = importlib.util.spec_from_file_location("_install_pinned_tool_verify", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = _load_script()


@pytest.mark.unit
@pytest.mark.parametrize(
    "output,version,expected",
    [
        ("uv 0.12.2 (x86_64-unknown-linux-gnu)", "0.12.2", True),
        ("0.12.2\n", "0.12.2", True),
        ("grype 0.12.2, built today", "0.12.2", True),
        ("Haskell Dockerfile Linter v2.12.0.", "2.12.0", True),
        ("uv 0.12.2rc1", "0.12.2", False),
        ("uv 0.12.2-1", "0.12.2", False),
        ("semgrep 1.125.0rc1", "1.125.0", False),
        ("cfn-lint 3.1.2-dev", "3.1.2", False),
        ("tool 1.2.3+local", "1.2.3", False),
        ("tool 1.2.3_extra", "1.2.3", False),
        # PEP 440 post, dev and release-candidate suffixes join with a dot.
        ("semgrep 1.125.0.post1", "1.125.0", False),
        ("tool 1.2.3.dev0", "1.2.3", False),
        ("tool 1.2.3.rc1", "1.2.3", False),
        ("tool 1.2.3.RC1", "1.2.3", False),
        # The other dotted spellings of PEP 440, and a fourth release number.
        ("tool 1.2.3.a1", "1.2.3", False),
        ("tool 1.2.3.b1", "1.2.3", False),
        ("tool 1.2.3.alpha1", "1.2.3", False),
        ("tool 1.2.3.beta1", "1.2.3", False),
        ("tool 1.2.3.c1", "1.2.3", False),
        ("tool 1.2.3.pre1", "1.2.3", False),
        ("tool 1.2.3.r1", "1.2.3", False),
        ("tool 1.2.3.4", "1.2.3", False),
        # Debian joins a pre-release with a tilde.
        ("tool 1.2.3~rc1", "1.2.3", False),
        # Controls: a dot that ends a sentence is not a suffix.
        ("tool 1.2.3.", "1.2.3", True),
        ("tool 1.2.3. Built today", "1.2.3", True),
        ("tool 1.2.3\n", "1.2.3", True),
    ],
)
def test_a_prerelease_or_distro_build_is_not_the_pinned_release(
    output, version, expected
):
    assert installer.reports_version(output, version) is expected


@pytest.mark.integration
@pytest.mark.skipif(os.name == "nt", reason="needs a POSIX shell")
def test_version_output_survives_bytes_that_are_not_text():
    """Starts a shell that writes bytes no text encoding here decodes."""
    argv = ["/bin/sh", "-c", "printf '\\377\\376 1.2.3'"]
    output = installer.version_output(argv[0], argv)
    assert installer.reports_version(output, "1.2.3")


def _entry(tool: str = "demo", probe: "tuple[str, ...]" = ("demo-probe", "--version")):
    return types.SimpleNamespace(
        tool=tool,
        version="v1.2.3",
        commit="commit-marker-for-tests",
        files=(),
        version_probe=probe,
        executable_names=(tool,),
        index_record=lambda: {"tool": tool},
        source_notice=lambda installed_from=None: (
            f"{tool}\nCommit: commit-marker-for-tests\n"
        ),
    )


class _Verify:
    """A one-entry third-party tree, and the table and probe stand-ins around it."""

    def __init__(self, monkeypatch, tmp_path: Path):
        self.entry = _entry()
        self.tmp_path = tmp_path
        self.third_party = tmp_path / "third-party"
        self.directory = self.third_party / self.entry.tool
        self.directory.mkdir(parents=True)
        self.source = self.directory / "SOURCE"
        self.source.write_text(self.entry.source_notice(), encoding="utf-8")
        self.source.chmod(0o644)
        self.directory.chmod(0o755)
        self.third_party.chmod(0o755)
        self.bin_dir = tmp_path / "bin"
        self.bin_dir.mkdir()
        self.probe = self.bin_dir / "demo-probe"
        self.probe.write_text("#!/bin/sh\n", encoding="utf-8")
        self.probe.chmod(0o755)
        monkeypatch.setenv("PATH", str(self.bin_dir))
        self.probe_calls: list = []
        pins = types.SimpleNamespace(THIRD_PARTY_LICENSES={self.entry.tool: self.entry})
        monkeypatch.setattr(installer, "load_pins", lambda root: pins)
        monkeypatch.setattr(installer, "_uv_tool_dir", lambda: None)

        def version_output(executable, argv=None):
            self.probe_calls.append(list(argv or [executable]))
            return "demo 1.2.3\n"

        monkeypatch.setattr(installer, "version_output", version_output)

    def run(self) -> "list[str]":
        return installer.verify_third_party(self.tmp_path, self.third_party, None, [])


@pytest.mark.skipif(
    os.name == "nt",
    reason="runs only in the Linux image build; the fixtures are POSIX executables and modes",
)
@pytest.mark.unit
class TestVerifyThirdParty:
    def test_a_clean_tree_passes_and_gets_an_index(self, monkeypatch, tmp_path):
        verify = _Verify(monkeypatch, tmp_path)
        assert verify.run() == []
        index = json.loads((verify.third_party / "index.json").read_text())
        assert index == {"tools": [{"tool": "demo"}]}

    def test_a_failing_run_removes_the_index_an_earlier_run_wrote(
        self, monkeypatch, tmp_path
    ):
        verify = _Verify(monkeypatch, tmp_path)
        assert verify.run() == []
        assert (verify.third_party / "index.json").exists()
        verify.source.write_text("demo\nno commit here\n", encoding="utf-8")

        problems = verify.run()

        assert any("does not name commit" in p for p in problems), problems
        assert not (verify.third_party / "index.json").exists(), (
            "the index describes a tree that no longer verifies"
        )

    @pytest.mark.parametrize("which", ["entry", "root"])
    def test_a_directory_others_cannot_search_is_a_problem(
        self, monkeypatch, tmp_path, which
    ):
        verify = _Verify(monkeypatch, tmp_path)
        victim = verify.directory if which == "entry" else verify.third_party
        victim.chmod(0o700)
        try:
            problems = verify.run()
        finally:
            victim.chmod(0o755)
        assert any(str(victim) in p and "cannot be searched" in p for p in problems), (
            problems
        )
        assert not (verify.third_party / "index.json").exists()

    def test_the_work_directory_of_a_killed_publish_is_not_a_license_claim(
        self, monkeypatch, tmp_path
    ):
        verify = _Verify(monkeypatch, tmp_path)
        (verify.third_party / ".ash-third-party-leftover").mkdir()
        assert verify.run() == []

    @pytest.mark.parametrize("leftover", ["old", "KEPT"])
    def test_a_work_directory_that_still_holds_an_earlier_entry_is_a_problem(
        self, monkeypatch, tmp_path, leftover
    ):
        """A publish that did not finish kept the previous entry in a hidden directory.

        Without this the image ships stale license files there, and the check passes
        because the directory is skipped as scratch space.
        """
        # The layout is the one publish_third_party writes: the earlier entry as a
        # directory ``old``, and the kept marker as a FILE holding the tool's name.
        verify = _Verify(monkeypatch, tmp_path)
        work = verify.third_party / f"{installer._PUBLISH_WORK_PREFIX}kept"
        work.mkdir()
        if leftover == "old":
            (work / "old").mkdir()
            (work / "old" / "LICENSE").write_text("stale\n", encoding="utf-8")
        else:
            (work / installer._PUBLISH_KEPT_MARKER).write_text(
                "demo\n", encoding="utf-8"
            )

        problems = verify.run()

        assert any(work.name in p and "did not finish" in p for p in problems), problems
        assert not (verify.third_party / "index.json").exists()

    def test_the_directory_a_failed_publish_keeps_is_the_one_verify_reports(
        self, monkeypatch, tmp_path
    ):
        """End to end: publish keeps the old entry, and verify finds what it kept."""
        verify = _Verify(monkeypatch, tmp_path)
        staged = tmp_path / "staging" / "demo"
        staged.mkdir(parents=True)
        (staged / "LICENSE").write_text("new\n", encoding="utf-8")
        real = os.replace

        def replace(src, dst, *args, **kwargs):
            if Path(dst) == verify.directory and Path(src).name == "incoming":
                raise OSError(errno.ENOSPC, "No space left on device")
            if Path(dst) == verify.directory and Path(src).name == "old":
                raise OSError(errno.EACCES, "Permission denied")
            return real(src, dst, *args, **kwargs)

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(os, "replace", replace)
            with pytest.raises(PermissionError):
                installer.publish_third_party(staged, verify.third_party)

        kept = [
            p
            for p in verify.third_party.iterdir()
            if p.name.startswith(installer._PUBLISH_WORK_PREFIX)
        ]
        assert len(kept) == 1, "the work directory holding the old entry was deleted"
        assert (kept[0] / installer._PUBLISH_KEPT_MARKER).is_file()

        problems = verify.run()

        assert any(kept[0].name in p and "did not finish" in p for p in problems), (
            problems
        )
        assert not (verify.third_party / "index.json").exists()

    def test_a_work_directory_holding_only_the_new_copy_is_not_a_problem(
        self, monkeypatch, tmp_path
    ):
        """Control: a publish killed before it set the old entry aside left no old copy."""
        verify = _Verify(monkeypatch, tmp_path)
        work = verify.third_party / ".ash-third-party-killed"
        (work / "incoming").mkdir(parents=True)
        (work / "incoming" / "LICENSE").write_text("new\n", encoding="utf-8")

        assert verify.run() == []

    def test_any_other_directory_with_no_entry_is_still_a_problem(
        self, monkeypatch, tmp_path
    ):
        """Control for the test above."""
        verify = _Verify(monkeypatch, tmp_path)
        (verify.third_party / "retired-tool").mkdir()
        problems = verify.run()
        assert any(
            "retired-tool: directory with no license entry" in p for p in problems
        )

    def test_a_source_file_that_is_not_utf8_is_a_problem_not_a_crash(
        self, monkeypatch, tmp_path
    ):
        verify = _Verify(monkeypatch, tmp_path)
        verify.source.write_bytes(b"demo \xff\xfe\n")

        problems = verify.run()

        assert any("could not be read" in p and "SOURCE" in p for p in problems), (
            problems
        )

    def test_a_probe_found_only_through_a_relative_path_entry_is_not_run(
        self, monkeypatch, tmp_path
    ):
        verify = _Verify(monkeypatch, tmp_path)
        planted = tmp_path / "relative-bin"
        planted.mkdir()
        (planted / "demo-probe").write_text("#!/bin/sh\n", encoding="utf-8")
        (planted / "demo-probe").chmod(0o755)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("PATH", os.pathsep.join(["relative-bin", ""]))

        problems = verify.run()

        assert verify.probe_calls == [], "a probe ran from a relative PATH entry"
        assert any("demo-probe" in p and "absolute PATH entry" in p for p in problems)

    def test_a_probe_on_an_absolute_entry_runs_from_there(self, monkeypatch, tmp_path):
        verify = _Verify(monkeypatch, tmp_path)

        assert verify.run() == []

        assert verify.probe_calls == [[str(verify.probe), "--version"]]

    def test_uv_is_not_taken_from_a_relative_path_entry(self, monkeypatch, tmp_path):
        planted = tmp_path / "relative-bin"
        planted.mkdir()
        (planted / "uv").write_text("#!/bin/sh\n", encoding="utf-8")
        (planted / "uv").chmod(0o755)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("PATH", "relative-bin")

        def forbidden(*args, **kwargs):
            raise AssertionError(f"ran {args!r}")

        monkeypatch.setattr(installer.subprocess, "run", forbidden)

        assert installer._uv_tool_dir() is None

    def test_uv_tool_dir_starts_uv_without_the_scripts_own_stdin(
        self, monkeypatch, tmp_path
    ):
        # Red before: the spawn had no stdin=, so uv inherited the installer's own
        # standard input (the image build's, or an operator's terminal).
        uv = tmp_path / "bin" / "uv"
        uv.parent.mkdir()
        uv.write_text("#!/bin/sh\n", encoding="utf-8")
        uv.chmod(0o755)
        monkeypatch.setenv("PATH", str(uv.parent))
        seen = {}

        def record(argv, **kwargs):
            seen["argv"], seen["kwargs"] = argv, kwargs
            return types.SimpleNamespace(returncode=0, stdout="/somewhere\n")

        monkeypatch.setattr(installer.subprocess, "run", record)

        assert installer._uv_tool_dir() == "/somewhere"
        assert seen["argv"] == [str(uv), "tool", "dir"]
        assert seen["kwargs"]["stdin"] == installer.subprocess.DEVNULL


@pytest.mark.unit
class TestTheModeFlagNeedNotComeFirst:
    def test_pins_dir_before_the_uv_tool_pins_mode(self, capsys):
        rc = installer.main(["--pins-dir", str(PACKAGE_ROOT), "--uv-tool-pins"])
        assert rc == 0
        assert capsys.readouterr().out.split() == installer.uv_tool_pins(PACKAGE_ROOT)

    def test_the_equals_spelling_of_licenses_only(self, monkeypatch, tmp_path):
        seen = []
        monkeypatch.setattr(
            installer,
            "install_licenses_only",
            lambda tool, package_root, third_party_dir: seen.append(
                (tool, third_party_dir)
            ),
        )

        rc = installer.main(
            ["--third-party-dir", str(tmp_path), "--licenses-only=opengrep"]
        )

        assert rc == 0
        assert seen == [("opengrep", tmp_path)]

    def test_assert_root_only_after_its_own_option(self, monkeypatch, tmp_path):
        seen = []

        def problems(paths, trusted):
            seen.append((paths, trusted))
            return []

        monkeypatch.setattr(installer, "root_only_problems", problems)

        rc = installer.main(["--trusted-uid", "7", "--assert-root-only", str(tmp_path)])

        assert rc == 0
        assert seen == [([tmp_path], (0, 7))]

    def test_the_first_argument_spellings_still_work(self, monkeypatch, tmp_path):
        """Control: the dispatch change must not move what already worked."""
        seen = []
        monkeypatch.setattr(
            installer,
            "root_only_problems",
            lambda paths, trusted: seen.append(paths) or [],
        )
        assert installer.main(["--assert-root-only", str(tmp_path)]) == 0
        assert seen == [[tmp_path]]

    def test_a_tool_install_is_not_taken_for_a_mode(self, monkeypatch, tmp_path):
        seen = []
        monkeypatch.setattr(
            installer,
            "install",
            lambda tool, bin_dir, package_root, third_party_dir=None: seen.append(
                (tool, bin_dir)
            ),
        )
        rc = installer.main(
            ["syft", "-b", str(tmp_path / "bin"), "--pins-dir", str(PACKAGE_ROOT)]
        )
        assert rc == 0
        assert seen == [("syft", tmp_path / "bin")]
