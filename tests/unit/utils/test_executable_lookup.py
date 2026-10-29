# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Where ASH finds the programs it starts, and the ones it will not start.

ASH usually runs from the repository it scans, so its working directory is scanned
content. Two lookups reach into it without anyone asking: Windows, where
``shutil.which`` and ``CreateProcess`` both try the working directory before PATH,
and an empty, ``.`` or relative PATH entry on any platform. ``find_executable`` never
answers from either, and the spawn helpers will not start a bare name the operating
system would find that way.

Everything an operator installs is still found, by the path its PATH entry gives:
system package managers, Homebrew, nix profiles, pipx and uv shims, asdf and mise
shims, conda, ``/opt``, ASH's own bin directory, and on Windows Program Files,
``%LOCALAPPDATA%``, scoop and Chocolatey shims with ``.exe``, ``.cmd`` and ``.bat``
names. A tool on an absolute PATH entry inside the scanned tree, such as an activated
in-repo ``.venv/bin``, goes to one decision point,
``subprocess_utils.HONOR_IN_TREE_PATH_ENTRIES``; both of its outcomes are tested.

The binaries are fakes in temporary directories. Where a test starts one for real it
is a POSIX shell script that leaves a file behind, so "it ran" is observed rather than
inferred from a return code.
"""

from __future__ import annotations

import contextvars
import logging
import os
import subprocess
import sys
import threading
import types
from pathlib import Path

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.scanned_tree import is_inside_tree
from automated_security_helper.utils.subprocess_utils import (
    ALLOW_IN_TREE_TOOLS_ENV,
    ALLOW_IN_TREE_TOOLS_FLAG,
    child_environ,
    find_executable,
    find_executable_for_scan,
    find_trusted_executable,
    in_tree_refusal,
    parse_allow_in_tree_tools,
    run_command,
    run_command_with_output_handling,
    scanning_tree,
    spawn_run,
)
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS

WINDOWS = sys.platform == "win32"
posix_only = pytest.mark.skipif(WINDOWS, reason="starts a POSIX shell script")
needs_symlinks = pytest.mark.skipif(
    WINDOWS, reason="creating symlinks needs privileges on Windows"
)


def fake_tool(directory: Path, name: str = "tool", ran: Path | None = None) -> Path:
    """An executable ``name`` in ``directory``; when run, it creates ``ran``."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (f"{name}.exe" if WINDOWS and "." not in name else name)
    # A redirection, not touch: the tests' PATH may hold nothing but the fake.
    body = f"#!/bin/sh\n: > '{ran}'\n" if ran is not None else "#!/bin/sh\nexit 0\n"
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.fixture(autouse=True)
def hermetic(monkeypatch, tmp_path):
    """Lookups see the PATH a test sets, and the cache does not carry answers over."""
    monkeypatch.setattr(
        subprocess_utils, "path_independent_dirs", lambda: [tmp_path / "ash-bin"]
    )
    subprocess_utils.clear_find_executable_cache()
    yield
    subprocess_utils.clear_find_executable_cache()


@pytest.fixture
def repo(tmp_path, monkeypatch) -> Path:
    """The scanned tree, and ASH's working directory, as ``cd repo && ash scan``."""
    tree = tmp_path / "repo"
    tree.mkdir()
    monkeypatch.chdir(tree)
    return tree


@pytest.fixture
def installs(tmp_path) -> Path:
    """Where the stand-in install locations go: outside the tree."""
    return tmp_path / "root"


@pytest.fixture
def plain_runs(monkeypatch) -> list[list[str]]:
    """Stands in for the runner of a plain spawn; the argv of each start it is given.

    ``run_command`` starts a child outside a sandbox and a cancel scope through
    ``subprocess_utils._run_plain``, which ``_runner`` looks up at each call, so
    replacing it is replacing the start. The cells that use this are about the
    decision made before the start (a program the operating system would find through
    the working directory is not handed to it), so nothing is started: an empty list
    is a program that was refused, a one-item list is one that was handed over.

    Replacing the ``subprocess`` module of ``subprocess_utils`` with a namespace of
    ``run`` and the constants does not do this: the runner starts its child with
    ``Popen``, never calls ``run``, and a cell that records ``run`` records nothing
    whether or not the program was refused.
    """
    started: list[list[str]] = []

    def run(argv, **kwargs):
        started.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(subprocess_utils, "_run_plain", run)
    return started


@pytest.fixture
def ash_warnings():
    messages: list[str] = []

    class _Collector(logging.Handler):
        def emit(self, record):
            messages.append(record.getMessage())

    handler = _Collector(level=logging.WARNING)
    logger = logging.getLogger("ash")
    logger.addHandler(handler)
    try:
        yield messages
    finally:
        logger.removeHandler(handler)


class TestInstalledToolsAreFound:
    @pytest.mark.unit
    @pytest.mark.parametrize(
        "layout",
        [
            "usr/bin",
            "usr/local/bin",
            "bin",
            "opt/homebrew/bin",
            "nix/store/0a1b2c-semgrep-1.0/bin",
            "home/user/.local/bin",
            "opt/semgrep/bin",
            "home/user/.asdf/shims",
            "home/user/.local/share/mise/shims",
            "home/user/miniconda3/bin",
        ],
    )
    def test_a_tool_on_an_absolute_path_entry(
        self, layout, repo, installs, monkeypatch, ash_warnings
    ):
        tool = fake_tool(installs / layout)
        monkeypatch.setenv("PATH", str(tool.parent))

        assert find_executable("tool") == str(tool)
        assert find_executable_for_scan("tool", repo) == str(tool)
        assert ash_warnings == []

    @pytest.mark.unit
    @needs_symlinks
    @pytest.mark.parametrize(
        "entry, target",
        [
            # Homebrew links bin/<tool> into the Cellar.
            ("opt/homebrew/bin", "opt/homebrew/Cellar/tool/1.0/bin"),
            # A nix profile links into the store.
            ("home/user/.nix-profile/bin", "nix/store/0a1b2c-tool-1.0/bin"),
        ],
    )
    def test_a_linked_install_is_named_by_its_path_entry(
        self, entry, target, repo, installs, monkeypatch, ash_warnings
    ):
        real = fake_tool(installs / target)
        link = installs / entry / "tool"
        link.parent.mkdir(parents=True)
        link.symlink_to(real)
        monkeypatch.setenv("PATH", str(link.parent))

        assert find_executable("tool") == str(link)
        assert find_executable_for_scan("tool", repo) == str(link)
        assert ash_warnings == []

    @pytest.mark.unit
    def test_a_tool_in_ashs_bin_directory(self, repo, installs, monkeypatch):
        ash_bin = installs / "home/user/.ash/bin"
        tool = fake_tool(ash_bin)
        monkeypatch.setenv("ASH_BIN_PATH", str(ash_bin))
        monkeypatch.setattr(
            subprocess_utils, "path_independent_dirs", lambda: [Path(ash_bin)]
        )
        empty = installs / "empty"
        empty.mkdir(parents=True)
        monkeypatch.setenv("PATH", str(empty))

        assert find_executable("tool") == tool.as_posix()
        assert find_executable_for_scan("tool", repo) == tool.as_posix()

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "layout",
        [
            "Program Files/Semgrep",
            "Users/user/AppData/Local/Programs/semgrep",
            "Users/user/scoop/shims",
            "ProgramData/chocolatey/bin",
        ],
    )
    @pytest.mark.parametrize("suffix", [".exe", ".cmd", ".bat"])
    def test_windows_install_locations_and_suffixes(
        self, layout, suffix, repo, installs, monkeypatch
    ):
        """PATHEXT-style names: ``semgrep`` resolves to ``semgrep.exe|.cmd|.bat``."""
        monkeypatch.setattr(subprocess_utils.platform, "system", lambda: "Windows")
        tool = fake_tool(installs / layout, f"semgrep{suffix}")
        monkeypatch.setenv("PATH", str(tool.parent))

        assert find_executable("semgrep") == str(tool)
        assert find_executable_for_scan("semgrep", repo) == str(tool)

    @pytest.mark.integration
    @posix_only
    def test_run_command_starts_an_installed_tool(self, repo, installs, monkeypatch):
        ran = installs / "ran"
        tool = fake_tool(installs / "usr/local/bin", ran=ran)
        monkeypatch.setenv("PATH", str(tool.parent))

        result = run_command(["tool"], cwd=repo, timeout=CHILD_TIMEOUT_SECONDS)

        assert result.returncode == 0
        assert ran.exists()


@pytest.mark.unit
class TestNothingIsFoundThroughTheWorkingDirectory:
    @pytest.mark.parametrize("entry", ["", ".", "bin"])
    def test_a_relative_path_entry_is_not_searched(self, entry, repo, monkeypatch):
        fake_tool(repo)
        fake_tool(repo / "bin")
        monkeypatch.setenv("PATH", entry)

        assert find_executable("tool") is None
        assert find_executable_for_scan("tool", repo) is None

    def test_an_installed_tool_later_on_path_is_found_instead(
        self, repo, installs, monkeypatch
    ):
        fake_tool(repo)
        tool = fake_tool(installs / "usr/bin")
        monkeypatch.setenv("PATH", os.pathsep.join([".", str(tool.parent)]))

        assert find_executable("tool") == str(tool)

    def test_windows_searching_the_working_directory_first_is_not_followed(
        self, repo, installs, monkeypatch
    ):
        local = fake_tool(repo)
        tool = fake_tool(installs / "Program Files/Tool")
        monkeypatch.setenv("PATH", str(tool.parent))
        real_which = subprocess_utils.shutil.which

        def windows_which(cmd, mode=os.F_OK | os.X_OK, path=None):
            # shutil.which on Windows: the working directory, then PATH.
            if not os.path.dirname(cmd):
                here = os.path.join(os.curdir, cmd)
                if os.path.isfile(here):
                    return here
            return real_which(cmd, mode, path)

        monkeypatch.setattr(subprocess_utils.shutil, "which", windows_which)
        # The emulation does what Windows does with the bare name.
        assert Path(windows_which(local.name)).resolve() == local.resolve()

        assert find_executable("tool") == str(tool)

    @posix_only
    def test_run_command_does_not_start_a_tool_reached_through_a_relative_entry(
        self, repo, installs, monkeypatch
    ):
        """POSIX resolves a relative entry against the child's ``cwd``."""
        ran = installs / "ran"
        fake_tool(repo / "bin", ran=ran)
        empty = installs / "empty"
        empty.mkdir(parents=True)
        monkeypatch.setenv("PATH", os.pathsep.join(["bin", str(empty)]))

        result = run_command(["tool"], cwd=repo, timeout=CHILD_TIMEOUT_SECONDS)

        assert result.returncode == 127
        assert str(repo / "bin" / "tool") in result.stderr
        assert not ran.exists(), "the tool in the working directory ran"

    @posix_only
    def test_the_childs_working_directory_is_the_one_judged_on_posix(
        self, repo, installs, tmp_path, monkeypatch
    ):
        """The child changes directory before the PATH search, so ``cwd`` is searched."""
        ran = installs / "ran"
        fake_tool(repo / "bin", ran=ran)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        monkeypatch.setenv("PATH", "bin")

        result = run_command(["tool"], cwd=repo, timeout=CHILD_TIMEOUT_SECONDS)

        assert result.returncode == 127
        assert not ran.exists()

    def test_a_relative_ash_bin_path_is_not_searched(self, repo, installs, monkeypatch):
        fake_tool(repo / "rel-bin")
        monkeypatch.setattr(
            subprocess_utils, "path_independent_dirs", lambda: [Path("rel-bin")]
        )
        empty = installs / "empty"
        empty.mkdir(parents=True)
        monkeypatch.setenv("PATH", str(empty))

        assert find_executable("tool") is None

    @posix_only
    def test_the_other_spawn_helpers_refuse_it_too(self, repo, installs, monkeypatch):
        ran = installs / "ran"
        fake_tool(repo / "bin", ran=ran)
        monkeypatch.setenv("PATH", "bin")

        handled = run_command_with_output_handling(["tool"], results_dir=None, cwd=repo)
        with pytest.raises(FileNotFoundError):
            spawn_run(["tool"], cwd=repo, capture_output=True)

        assert handled["returncode"] == 127
        assert handled.get("spawn_failed") is True
        assert not ran.exists()

    def test_windows_starting_a_name_from_the_working_directory_is_refused(
        self, repo, installs, monkeypatch, plain_runs
    ):
        """CreateProcess tries ASH's working directory before PATH."""
        monkeypatch.setattr(subprocess_utils.platform, "system", lambda: "Windows")
        fake_tool(repo, "tool.exe")
        empty = installs / "empty"
        empty.mkdir(parents=True)
        monkeypatch.setenv("PATH", str(empty))

        result = run_command(["tool"])

        assert plain_runs == []
        assert result.returncode == 127

    def test_a_missing_tool_is_still_handed_to_the_os_when_the_cwd_has_none(
        self, repo, installs, monkeypatch, plain_runs
    ):
        """The positive control: only a start through the cwd is refused (on POSIX)."""
        monkeypatch.setattr(subprocess_utils.platform, "system", lambda: "Linux")
        empty = installs / "empty"
        empty.mkdir(parents=True)
        monkeypatch.setenv("PATH", str(empty))

        run_command(["tool", "--version"])

        assert plain_runs == [["tool", "--version"]]


@pytest.mark.unit
class TestToolsInsideTheScannedTree:
    """Refused by default, by every lookup and spawn; the operator's opt-in allows them."""

    @pytest.fixture
    def opt_in_off(self, monkeypatch):
        monkeypatch.delenv(ALLOW_IN_TREE_TOOLS_ENV, raising=False)

    @pytest.mark.parametrize(
        "where", [".venv/bin", "node_modules/.bin"], ids=["uv-run", "npm-run"]
    )
    def test_an_in_tree_copy_is_refused_and_the_next_one_used(
        self, where, repo, installs, monkeypatch, ash_warnings, opt_in_off
    ):
        in_tree = fake_tool(repo / where)
        other = fake_tool(installs / "usr/bin")
        monkeypatch.setenv(
            "PATH", os.pathsep.join([str(in_tree.parent), str(other.parent)])
        )

        with scanning_tree(repo):
            assert find_executable("tool") == str(other)
            assert in_tree_refusal("tool") is None, "not missing: another was used"
        assert [m for m in ash_warnings if str(in_tree) in m], ash_warnings

    def test_with_nothing_else_it_is_missing_and_says_why(
        self, repo, monkeypatch, opt_in_off
    ):
        in_tree = fake_tool(repo / ".venv" / "bin")
        monkeypatch.setenv("PATH", str(in_tree.parent))

        with scanning_tree(repo):
            assert find_executable("tool") is None
            reason = in_tree_refusal("tool")
        assert reason is not None
        assert str(in_tree) in reason
        assert ALLOW_IN_TREE_TOOLS_ENV in reason and ALLOW_IN_TREE_TOOLS_FLAG in reason

    def test_the_opt_in_runs_it_with_a_warning(self, repo, monkeypatch, ash_warnings):
        monkeypatch.setenv(ALLOW_IN_TREE_TOOLS_ENV, "1")
        in_tree = fake_tool(repo / ".venv" / "bin")
        monkeypatch.setenv("PATH", str(in_tree.parent))

        with scanning_tree(repo):
            assert find_executable("tool") == str(in_tree)
        assert [
            m
            for m in ash_warnings
            if m.startswith("Running tool") and str(in_tree) in m
        ], ash_warnings

    @pytest.mark.parametrize("value", ["1", "true", "YES", " on "])
    def test_one_parser_reads_the_opt_in(self, value):
        assert parse_allow_in_tree_tools(value)

    @pytest.mark.parametrize("value", ["", "0", "false", "no", None])
    def test_anything_else_is_off(self, value):
        assert not parse_allow_in_tree_tools(value)

    def test_a_process_that_does_not_honor_the_opt_in_refuses_anyway(
        self, repo, monkeypatch, opt_in_off
    ):
        """The decision point ``ash mcp`` sets: MCP_HONORS_IN_TREE_OPT_IN."""
        monkeypatch.setenv(ALLOW_IN_TREE_TOOLS_ENV, "1")
        monkeypatch.setattr(subprocess_utils, "_opt_in_honored", False)
        in_tree = fake_tool(repo / ".venv" / "bin")
        monkeypatch.setenv("PATH", str(in_tree.parent))

        with scanning_tree(repo):
            assert find_executable("tool") is None
            reason = in_tree_refusal("tool")
        assert ALLOW_IN_TREE_TOOLS_FLAG not in reason, (
            "names a remedy that would not work"
        )

    def test_without_a_scan_nothing_is_refused(self, repo, monkeypatch, opt_in_off):
        in_tree = fake_tool(repo / ".venv" / "bin")
        monkeypatch.setenv("PATH", str(in_tree.parent))

        assert find_executable("tool") == str(in_tree)

    @needs_symlinks
    def test_a_link_on_path_into_the_tree_is_judged_by_where_it_lands(
        self, repo, installs, monkeypatch, opt_in_off
    ):
        in_tree = fake_tool(repo / "tools")
        link = installs / "usr/local/bin" / "tool"
        link.parent.mkdir(parents=True)
        link.symlink_to(in_tree)
        monkeypatch.setenv("PATH", str(link.parent))

        with scanning_tree(repo):
            assert find_executable("tool") is None

    def test_the_running_interpreter_is_never_refused(self, monkeypatch, opt_in_off):
        """ASH installed in the scanned repository's own .venv starts sys.executable."""
        interpreter = Path(sys.executable)
        monkeypatch.setenv("PATH", str(interpreter.parent))

        with scanning_tree(interpreter.parent.parent):
            assert find_executable(interpreter.name) is not None

    def test_each_scan_keeps_its_own_trees(
        self, repo, tmp_path, monkeypatch, opt_in_off
    ):
        """Per context: a scan in another thread does not see this one's tree."""
        in_tree = fake_tool(repo / ".venv" / "bin")
        monkeypatch.setenv("PATH", str(in_tree.parent))
        seen = {}

        with scanning_tree(repo):
            other = threading.Thread(
                target=lambda: seen.update(bare=find_executable("tool"))
            )
            other.start()
            other.join()
            copied = threading.Thread(
                target=contextvars.copy_context().run,
                args=(lambda: seen.update(copied=find_executable("tool")),),
            )
            copied.start()
            copied.join()
            seen["here"] = find_executable("tool")

        assert seen == {"bare": str(in_tree), "copied": None, "here": None}

    def test_a_nested_scan_keeps_the_outer_scans_trees(
        self, repo, tmp_path, monkeypatch, opt_in_off
    ):
        """A workspace project's scan, inside the workspace root's."""
        in_tree = fake_tool(repo / ".venv" / "bin")
        monkeypatch.setenv("PATH", str(in_tree.parent))
        project = tmp_path / "project"

        with scanning_tree(repo), scanning_tree(project):
            assert subprocess_utils.scanned_trees() == [str(repo), str(project)]
            assert find_executable("tool") is None

    def test_a_cached_answer_still_records_the_refusal(
        self, repo, monkeypatch, opt_in_off
    ):
        in_tree = fake_tool(repo / ".venv" / "bin")
        monkeypatch.setenv("PATH", str(in_tree.parent))
        with scanning_tree(repo):
            find_executable("tool")

        with scanning_tree(repo):
            assert find_executable("tool") is None
            assert in_tree_refusal("tool") is not None

    def test_scopes_leave_other_caches_alone(self, repo, monkeypatch):
        """Entering and leaving a scan does not empty the uv tool version memo (#542)."""
        from automated_security_helper.utils import uv_tool_runner

        monkeypatch.setitem(uv_tool_runner._uv_tool_version_cache, ("x", None), "1.0")
        with scanning_tree(repo):
            pass
        assert uv_tool_runner._uv_tool_version_cache[("x", None)] == "1.0"


class TestSpawnsRefuseInTreePrograms:
    @pytest.fixture(autouse=True)
    def opt_in_off(self, monkeypatch):
        monkeypatch.delenv(ALLOW_IN_TREE_TOOLS_ENV, raising=False)

    @pytest.mark.unit
    @posix_only
    @pytest.mark.parametrize("spelling", ["bare", "absolute"])
    def test_run_command_does_not_start_a_refused_program(
        self, spelling, repo, installs, monkeypatch
    ):
        installs.mkdir(parents=True)
        ran = installs / "ran"
        in_tree = fake_tool(repo / ".venv" / "bin", ran=ran)
        monkeypatch.setenv("PATH", str(in_tree.parent))
        argv = ["tool"] if spelling == "bare" else [str(in_tree)]

        with scanning_tree(repo):
            result = run_command(argv, cwd=repo)

        assert result.returncode == 127
        assert str(in_tree) in result.stderr
        assert not ran.exists()

    @pytest.mark.integration
    @posix_only
    def test_the_opt_in_lets_it_start(self, repo, installs, monkeypatch):
        monkeypatch.setenv(ALLOW_IN_TREE_TOOLS_ENV, "1")
        installs.mkdir(parents=True)
        ran = installs / "ran"
        in_tree = fake_tool(repo / ".venv" / "bin", ran=ran)
        monkeypatch.setenv("PATH", str(in_tree.parent))

        with scanning_tree(repo):
            result = run_command(["tool"], cwd=repo, timeout=CHILD_TIMEOUT_SECONDS)

        assert result.returncode == 0
        assert ran.exists()

    @pytest.mark.unit
    def test_children_are_started_without_the_trees_path_entries(
        self, repo, installs, monkeypatch
    ):
        """A child's own lookups (``env node``, a binstub) cannot reach the tree."""
        kept = installs / "usr/bin"
        kept.mkdir(parents=True)
        path = os.pathsep.join(
            [str(repo / ".venv" / "bin"), "relative/bin", "", str(kept)]
        )
        monkeypatch.setenv("PATH", path)

        with scanning_tree(repo):
            env = child_environ()

        assert env["PATH"] == str(kept)
        assert ALLOW_IN_TREE_TOOLS_ENV not in env

    @pytest.mark.unit
    def test_with_the_opt_in_children_keep_path_and_inherit_the_decision(
        self, repo, monkeypatch
    ):
        monkeypatch.setenv(ALLOW_IN_TREE_TOOLS_ENV, "1")
        # Both entries anchored: a child's PATH keeps only those, and "/usr/bin"
        # has no drive letter on Windows.
        path = os.pathsep.join(
            [str(repo / ".venv" / "bin"), os.path.abspath("/usr/bin")]
        )
        monkeypatch.setenv("PATH", path)

        with scanning_tree(repo):
            # The scan decided on entry; its children carry that decision even
            # once the variable is gone from this process's environment.
            monkeypatch.delenv(ALLOW_IN_TREE_TOOLS_ENV)
            env = child_environ()

        assert env["PATH"] == path
        assert env[ALLOW_IN_TREE_TOOLS_ENV] == "1"

    @pytest.mark.unit
    def test_a_process_that_does_not_honor_the_opt_in_tells_its_children_so(
        self, repo, monkeypatch
    ):
        monkeypatch.setenv(ALLOW_IN_TREE_TOOLS_ENV, "1")
        monkeypatch.setattr(subprocess_utils, "_opt_in_honored", False)

        with scanning_tree(repo):
            env = child_environ()

        assert ALLOW_IN_TREE_TOOLS_ENV not in env

    @pytest.mark.unit
    def test_windows_does_not_hand_an_unresolved_name_to_createprocess(
        self, repo, installs, monkeypatch, plain_runs
    ):
        monkeypatch.setattr(subprocess_utils.platform, "system", lambda: "Windows")
        empty = installs / "empty"
        empty.mkdir(parents=True)
        monkeypatch.setenv("PATH", str(empty))

        result = run_command(["tool"])

        assert plain_runs == []
        assert result.returncode == 127


@pytest.mark.unit
class TestTheSandboxsOwnPrograms:
    """bwrap, firejail, readlink, true: the opt-in covers them too (its own decision point)."""

    def test_an_in_tree_bwrap_is_refused_by_default(self, repo, installs, monkeypatch):
        monkeypatch.delenv(ALLOW_IN_TREE_TOOLS_ENV, raising=False)
        in_tree = fake_tool(repo / "bin", "bwrap")
        system = fake_tool(installs / "usr/bin", "bwrap")
        monkeypatch.setenv(
            "PATH", os.pathsep.join([str(in_tree.parent), str(system.parent)])
        )

        with scanning_tree(repo):
            assert find_trusted_executable("bwrap") == str(system)

    @pytest.mark.parametrize("follows", [True, False])
    def test_the_opt_in_covers_them_as_the_decision_point_says(
        self, follows, repo, monkeypatch, ash_warnings
    ):
        monkeypatch.setenv(ALLOW_IN_TREE_TOOLS_ENV, "1")
        monkeypatch.setattr(subprocess_utils, "SANDBOX_PROGRAMS_FOLLOW_OPT_IN", follows)
        in_tree = fake_tool(repo / "bin", "bwrap")
        monkeypatch.setenv("PATH", str(in_tree.parent))

        with scanning_tree(repo):
            found = find_trusted_executable("bwrap")

        assert found == (str(in_tree) if follows else None)
        assert [m for m in ash_warnings if str(in_tree) in m], ash_warnings

    def test_the_working_directory_is_not_a_root(self, installs, tmp_path, monkeypatch):
        """ASH started from $HOME still finds ~/.local/bin/bwrap."""
        home = tmp_path / "home"
        tool = fake_tool(home / ".local" / "bin", "bwrap")
        monkeypatch.chdir(home)
        monkeypatch.setenv("PATH", str(tool.parent))

        with scanning_tree(tmp_path / "elsewhere"):
            assert find_trusted_executable("bwrap") == str(tool)

    def test_the_backend_probe_uses_it(self, repo, installs, monkeypatch):
        """Not shutil.which: an empty PATH entry would answer from the cwd."""
        from automated_security_helper.utils.sandbox import backends

        fake_tool(repo, "bwrap")
        monkeypatch.setenv("PATH", os.pathsep.join(["", str(installs / "none")]))

        assert backends._sandbox_program("bwrap") is None


@pytest.mark.unit
class TestIsInsideTree:
    def test_as_written_and_as_resolved(self, tmp_path):
        tree = tmp_path / "repo"
        (tree / "sub").mkdir(parents=True)
        (tmp_path / "elsewhere").mkdir()

        assert is_inside_tree(tree / "sub" / "x", tree)
        assert is_inside_tree(tree, tree)
        assert not is_inside_tree(tmp_path / "elsewhere" / "x", tree)
        assert not is_inside_tree(tmp_path / "repo2" / "x", tree)

    @needs_symlinks
    def test_a_link_in_the_tree_to_elsewhere_is_inside(self, tmp_path):
        """Judged by where it is written as well: the tree chose that name."""
        tree = tmp_path / "repo"
        tree.mkdir()
        (tmp_path / "elsewhere").mkdir()
        (tree / ".venv").symlink_to(tmp_path / "elsewhere")

        assert is_inside_tree(tree / ".venv" / "x", tree)

    @needs_symlinks
    def test_a_link_into_the_tree_is_inside(self, tmp_path):
        tree = tmp_path / "repo"
        (tree / "bin").mkdir(parents=True)
        (tmp_path / "linked").symlink_to(tree / "bin")

        assert is_inside_tree(tmp_path / "linked" / "x", tree)


@pytest.mark.unit
class TestEverySpellingOfTheTree:
    @needs_symlinks
    def test_a_link_whose_directory_is_in_the_tree_is_inside(self, tmp_path):
        """``alias/tool``, where alias -> tree/bin and tree/bin/tool -> elsewhere."""
        from automated_security_helper.utils import scanned_tree

        tree = tmp_path / "repo"
        (tree / "bin").mkdir(parents=True)
        (tmp_path / "elsewhere").mkdir()
        (tmp_path / "elsewhere" / "tool").write_text("")
        (tree / "bin" / "tool").symlink_to(tmp_path / "elsewhere" / "tool")
        (tmp_path / "alias").symlink_to(tree / "bin")

        assert scanned_tree.is_inside_tree(tmp_path / "alias" / "tool", tree)

    @needs_symlinks
    def test_a_spelling_names_cannot_match_is_caught_by_inode(
        self, tmp_path, monkeypatch
    ):
        """As on macOS, where /var is /private/var and names can differ in case."""
        from automated_security_helper.utils import scanned_tree

        tree = tmp_path / "repo"
        (tree / "bin").mkdir(parents=True)
        (tmp_path / "Alias").symlink_to(tree)
        # With links left unresolved, only the device and inode can tell.
        monkeypatch.setattr(scanned_tree.os.path, "realpath", lambda p: os.fspath(p))

        assert scanned_tree.is_inside_tree(tmp_path / "Alias" / "bin" / "x", tree)

    def test_ntpath_needs_a_drive_or_share(self):
        import ntpath

        from automated_security_helper.utils.subprocess_utils import _is_anchored

        assert _is_anchored("C:\\tools", ntpath)
        assert _is_anchored("\\\\server\\share\\bin", ntpath)
        assert not _is_anchored("\\tools", ntpath), "rooted on the current drive"
        assert not _is_anchored("tools", ntpath)

    def test_a_rooted_entry_needs_a_drive_where_isabs_accepts_it(self):
        """Before Python 3.13, ``ntpath.isabs("\\tools")`` is True."""
        import ntpath

        from automated_security_helper.utils.subprocess_utils import _is_anchored

        before_313 = types.SimpleNamespace(
            __name__="ntpath",
            isabs=lambda p: ntpath.splitdrive(p)[1][:1] in ("\\", "/"),
            splitdrive=ntpath.splitdrive,
        )

        assert before_313.isabs("\\tools")
        assert not _is_anchored("\\tools", before_313)
        assert _is_anchored("C:\\tools", before_313)

    @needs_symlinks
    def test_without_inode_numbers_a_link_into_the_tree_is_inside(
        self, tmp_path, monkeypatch
    ):
        """``bin/tool -> repo/tools/tool``: only the real path names the tree."""
        from automated_security_helper.utils import scanned_tree

        tree = tmp_path / "repo"
        (tree / "tools").mkdir(parents=True)
        (tree / "tools" / "tool").write_text("")
        (tmp_path / "bin").mkdir()
        (tmp_path / "bin" / "tool").symlink_to(tree / "tools" / "tool")
        # A filesystem that reports no inode numbers.
        monkeypatch.setattr(scanned_tree, "_has_ancestor_file", lambda *a: False)

        assert scanned_tree.is_inside_tree(tmp_path / "bin" / "tool", tree)

    @needs_symlinks
    def test_without_inode_numbers_a_path_through_a_link_in_the_tree_is_inside(
        self, tmp_path, monkeypatch
    ):
        """``repo/out -> elsewhere``: the tree chose where ``repo/out/tool`` is."""
        from automated_security_helper.utils import scanned_tree

        tree = tmp_path / "repo"
        tree.mkdir()
        (tmp_path / "elsewhere").mkdir()
        (tmp_path / "elsewhere" / "tool").write_text("")
        (tree / "out").symlink_to(tmp_path / "elsewhere")
        monkeypatch.setattr(scanned_tree, "_has_ancestor_file", lambda *a: False)

        assert scanned_tree.is_inside_tree(tree / "out" / "tool", tree)


@pytest.mark.unit
class TestRelativeProgramPaths:
    @posix_only
    def test_a_program_named_by_a_relative_path_is_not_started(
        self, repo, installs, monkeypatch
    ):
        installs.mkdir(parents=True)
        ran = installs / "ran"
        fake_tool(repo / "bin", ran=ran)

        result = run_command(["./bin/tool"], cwd=repo)

        assert result.returncode == 127
        assert not ran.exists()
        assert find_executable("./bin/tool") is None


@pytest.mark.unit
@posix_only
class TestTheSandboxProbes:
    """The backends find their programs through find_trusted_executable."""

    def test_bwrap_from_the_working_directory_is_not_used(
        self, repo, installs, monkeypatch
    ):
        from automated_security_helper.utils.sandbox import backends

        installs.mkdir(parents=True)
        ran = installs / "ran"
        fake_tool(repo, "bwrap", ran=ran)
        monkeypatch.setenv("PATH", os.pathsep.join(["", str(installs / "none")]))

        reason = backends.BwrapBackend()._probe()

        assert reason is not None and "not installed" in reason
        assert not ran.exists()

    def test_firejail_from_the_working_directory_is_not_used(
        self, repo, installs, monkeypatch
    ):
        from automated_security_helper.utils.sandbox import backends

        installs.mkdir(parents=True)
        ran = installs / "ran"
        fake_tool(repo, "firejail", ran=ran)
        monkeypatch.setenv("PATH", os.pathsep.join(["", str(installs / "none")]))

        reason = backends.FirejailBackend()._probe()

        assert reason is not None and "not installed" in reason
        assert not ran.exists()
