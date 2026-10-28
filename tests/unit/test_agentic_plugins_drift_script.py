# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for scripts/check_agentic_plugins_drift.sh.

Why this file exists
--------------------
The script is a kit step whose only product is an exit status: 0 for no drift, 1 for
drift, 2 for "the check could not run". A wrong status with no error is the failure
that matters, because the consumer reads 1 as "the outputs are stale" and 0 as "they
match". Each test here plants a tree where the script's answer is known and asserts
the status, and the cells that assert a fault (2) sit beside a control that asserts the
healthy status (0) or the drift status (1) on a nearly identical tree, so a script that
returned 2 for everything would fail the controls.

What runs
---------
Nothing from the transpiler. Each test builds a small tree in ``tmp_path`` whose
``transpiler`` package is a stub (``orchestrator.check_drift`` and
``registry.BackendRegistry`` are a few lines each), links the interpreter running the
tests as the tree's ``.venv/bin/python``, and runs the real script with ``bash`` and
the tree as the working directory. No network, no install, nothing written outside
``tmp_path``.
"""

import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="runs the kit's bash script against a POSIX tree layout; the workflow "
    "runs it on Linux, and the bash first on a Windows runner's PATH is the WSL launcher",
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_agentic_plugins_drift.sh"
TRANSPILER_REL = Path("ash-agent-plugins/agentic-coding/transpiler")

HEALTHY_BODY = 'print("OK: stub")\nreturn 0'
DRIFT_BODY = 'print("ERROR: stub drift")\nreturn 1'

# The render-path packages the script compares with the transpiler's uv.lock, and the
# distribution names their metadata directories carry.
DEFAULT_VERSIONS = {"jinja2": "3.1.6", "markupsafe": "3.0.3", "pyyaml": "6.0.3"}
DIST_NAMES = {"jinja2": "Jinja2", "markupsafe": "MarkupSafe", "pyyaml": "PyYAML"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _env(tree: Path) -> dict[str, str]:
    """A minimal environment: named variables only, git configuration read from nowhere,
    and git discovery stopped at the directory that holds the tree."""
    home = tree.parent / "home"
    home.mkdir(exist_ok=True)
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "TMPDIR": str(tree.parent),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CEILING_DIRECTORIES": str(tree.parent),
    }


def _git(tree: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(tree), *args],
        env=_env(tree),
        check=True,
        capture_output=True,
        timeout=60,
    )


def _commit(tree: Path, *rel_paths: str) -> None:
    """Commit the named paths, or everything the tree holds when none are named."""
    _git(tree, "add", *(("--", *rel_paths) if rel_paths else ("-A",)))
    _git(
        tree,
        "-c",
        "user.name=tester",
        "-c",
        "user.email=tester@example.invalid",
        "commit",
        "--no-gpg-sign",
        "-m",
        "outputs",
    )


def _build_tree(
    tmp_path: Path,
    *,
    check_body: str = HEALTHY_BODY,
    installed: dict[str, str] | None = None,
    pinned: dict[str, str] | None = None,
    backends: tuple[str, ...] = ("alpha", "beta"),
    import_body: str = "",
    lock_text: str | None = None,
    names_body: str | None = None,
) -> Path:
    """A tree the script accepts, with a stub transpiler whose check is ``check_body``
    and whose registry lists ``backends``. ``import_body`` runs when the stub
    orchestrator is imported, before the script prints anything.

    ``installed`` is planted as metadata directories next to the stub package, which the
    script puts first on ``sys.path``, so the interpreter's own packages never answer.
    ``pinned`` is written as the transpiler's ``uv.lock``.
    """
    tree = tmp_path / "tree"
    td = tree / TRANSPILER_REL
    tree.mkdir(parents=True)
    _git(tree, "init", "--quiet")
    bin_dir = tree / ".venv" / "bin"
    bin_dir.mkdir(parents=True)
    # The base interpreter: a venv interpreter linked from elsewhere would not find
    # its own standard library through the link.
    (bin_dir / "python").symlink_to(getattr(sys, "_base_executable", sys.executable))
    _write(td / "_base" / "manifest.json", "{}\n")
    _write(td / "_base" / "skill.md", "stub\n")
    _write(td / "transpiler" / "__init__.py", "")
    _write(
        td / "transpiler" / "orchestrator.py",
        "import sys\n"
        + import_body
        + "\n\ndef check_drift():\n"
        + textwrap.indent(check_body, "    ")
        + "\n",
    )
    if names_body is None:
        names_body = f"return {list(backends)!r}"
    _write(
        td / "transpiler" / "registry.py",
        "class BackendRegistry:\n"
        "    @staticmethod\n"
        "    def names():\n" + textwrap.indent(names_body, "        ") + "\n",
    )
    installed = DEFAULT_VERSIONS if installed is None else installed
    pinned = DEFAULT_VERSIONS if pinned is None else pinned
    for name, version in installed.items():
        dist = DIST_NAMES[name]
        _write(
            td / f"{dist}-{version}.dist-info" / "METADATA",
            f"Metadata-Version: 2.1\nName: {dist}\nVersion: {version}\n",
        )
    if lock_text is None:
        lock_text = "version = 1\n" + "".join(
            f'\n[[package]]\nname = "{n}"\nversion = "{v}"\n' for n, v in pinned.items()
        )
    _write(td / "uv.lock", lock_text)
    # The script refuses to compare when the transpiler inputs differ from the commit, so
    # the planted tree is committed whole. The interpreter link stays out of the commit
    # the way the real tree's environment does.
    _write(tree / ".gitignore", ".venv/\n__pycache__/\n")
    _commit(tree)
    return tree


def _run(tree: Path, res: Path | None = None):
    res = res or (tree.parent / "res")
    res.mkdir(exist_ok=True)
    proc = subprocess.run(
        ["bash", str(SCRIPT), str(res)],
        cwd=tree,
        env=_env(tree),
        capture_output=True,
        text=True,
        timeout=120,
    )
    return proc, res


def _out_lines(res: Path) -> list[str]:
    return (res / "drift.out").read_text(encoding="utf-8").splitlines()


class TestVerdictsOfAFinishedCheck:
    """Controls: a check that returns gives 0 or 1, with the matching rc.txt."""

    def test_no_drift_exits_0_and_writes_rc_txt(self, tmp_path):
        tree = _build_tree(tmp_path)
        proc, res = _run(tree)
        assert proc.returncode == 0, proc.stderr
        assert (res / "rc.txt").read_text() == "agentic-plugins-drift 0 files=2\n"

    def test_real_drift_exits_1_and_writes_rc_txt(self, tmp_path):
        tree = _build_tree(tmp_path, check_body=DRIFT_BODY)
        proc, res = _run(tree)
        assert proc.returncode == 1, proc.stderr
        assert (res / "rc.txt").read_text() == "agentic-plugins-drift 1 files=2\n"


class TestAnUnfinishedCheckIsAFault:
    """The FILES line prints before the comparison runs, so it proves nothing about
    whether the comparison finished. Only the closing RESULT line does."""

    def test_a_finished_check_ends_drift_out_with_its_result(self, tmp_path):
        for body, status in ((HEALTHY_BODY, 0), (DRIFT_BODY, 1)):
            tree = _build_tree(tmp_path / str(status), check_body=body)
            proc, res = _run(tree)
            assert proc.returncode == status, proc.stderr
            assert _out_lines(res)[-1] == f"RESULT {status}"

    def test_exit_1_inside_the_build_is_exit_2_not_drift(self, tmp_path):
        tree = _build_tree(tmp_path, check_body="sys.exit(1)")
        proc, res = _run(tree)
        assert _out_lines(res)[0].startswith("FILES "), "the FILES line was printed"
        assert proc.returncode == 2, proc.stderr
        assert not (res / "rc.txt").exists()
        assert "did not finish" in proc.stderr

    def test_exit_0_inside_the_build_is_exit_2_not_a_pass(self, tmp_path):
        tree = _build_tree(tmp_path, check_body="sys.exit(0)")
        proc, res = _run(tree)
        assert proc.returncode == 2, proc.stderr
        assert not (res / "rc.txt").exists()

    def test_an_exception_in_the_build_is_exit_2(self, tmp_path):
        tree = _build_tree(tmp_path, check_body='raise ValueError("boom")')
        proc, res = _run(tree)
        assert proc.returncode == 2, proc.stderr
        assert not (res / "rc.txt").exists()


class TestRenderPathVersionsMatchTheTranspilerLock:
    """The comparison is byte for byte, so a different jinja2, markupsafe or PyYAML in
    the tree's environment can flip the verdict with no other sign. The script prints
    the installed versions and the pins, and refuses to compare when they differ."""

    def test_matching_versions_run_the_check_and_are_printed(self, tmp_path):
        tree = _build_tree(tmp_path)
        proc, res = _run(tree)
        assert proc.returncode == 0, proc.stderr
        lines = _out_lines(res)
        assert lines[0].startswith("FILES ")
        assert lines[1].startswith("VERSIONS python=")
        assert lines[2] == "INSTALLED jinja2=3.1.6 markupsafe=3.0.3 pyyaml=6.0.3"
        assert lines[3] == "PINS jinja2=3.1.6 markupsafe=3.0.3 pyyaml=6.0.3"

    @pytest.mark.parametrize("name", sorted(DEFAULT_VERSIONS))
    def test_a_version_that_differs_from_its_pin_is_exit_2(self, tmp_path, name):
        installed = dict(DEFAULT_VERSIONS, **{name: "0.0.1"})
        marker = tmp_path / "tree" / "check-ran"
        tree = _build_tree(
            tmp_path,
            check_body=f'open({str(marker)!r}, "w").close()\nreturn 0',
            installed=installed,
        )
        proc, res = _run(tree)
        assert proc.returncode == 2, proc.stderr
        assert not (res / "rc.txt").exists()
        assert not marker.exists(), "the comparison must not run on a version mismatch"
        pinned = DEFAULT_VERSIONS[name]
        assert (
            f"{name} installed 0.0.1, pinned {pinned}"
            in (res / "drift.err").read_text()
        )
        lines = _out_lines(res)
        assert f"{name}=0.0.1" in lines[2], "the installed version is printed"
        assert f"{name}={pinned}" in lines[3], "the pin is printed"

    def test_a_package_the_lock_does_not_pin_is_exit_2(self, tmp_path):
        pinned = {n: v for n, v in DEFAULT_VERSIONS.items() if n != "pyyaml"}
        tree = _build_tree(tmp_path, pinned=pinned)
        proc, res = _run(tree)
        assert proc.returncode == 2, proc.stderr
        assert not (res / "rc.txt").exists()
        assert (
            "pyyaml installed 6.0.3, pinned unpinned" in (res / "drift.err").read_text()
        )


class TestUvLockShapesTheReaderMustSurvive:
    """uv writes entries the pin reader must not trip on: a source-tree package can have
    no version field, and an environment-forked resolution can hold one name twice. The
    first is not a fault; the second refuses with its own message, because a
    last-entry-wins read would compare a pin CI may not install."""

    def test_a_versionless_package_entry_is_tolerated(self, tmp_path):
        lock = 'version = 1\n\n[[package]]\nname = "ash-stub-root"\n' + "".join(
            f'\n[[package]]\nname = "{n}"\nversion = "{v}"\n'
            for n, v in DEFAULT_VERSIONS.items()
        )
        tree = _build_tree(tmp_path, lock_text=lock)
        proc, res = _run(tree)
        assert proc.returncode == 0, proc.stderr
        assert (res / "rc.txt").read_text() == "agentic-plugins-drift 0 files=2\n"

    def test_a_duplicate_render_path_pin_is_exit_2_with_its_own_message(self, tmp_path):
        lock = (
            "version = 1\n"
            '\n[[package]]\nname = "jinja2"\nversion = "2.0.0"\n'
            '\n[[package]]\nname = "jinja2"\nversion = "3.1.6"\n'
            '\n[[package]]\nname = "markupsafe"\nversion = "3.0.3"\n'
            '\n[[package]]\nname = "pyyaml"\nversion = "6.0.3"\n'
        )
        tree = _build_tree(tmp_path, lock_text=lock)
        proc, res = _run(tree)
        assert proc.returncode == 2, proc.stderr
        assert not (res / "rc.txt").exists()
        assert "pins jinja2 at both 2.0.0 and 3.1.6" in (res / "drift.err").read_text()


def _poison_tomllib(tree: Path) -> None:
    """Swap the tree interpreter for a wrapper that blocks ``import tomllib`` the way a
    3.10 interpreter does (``None`` in ``sys.modules`` makes the import raise
    ImportError), leaving every other module alone."""
    python = tree / ".venv" / "bin" / "python"
    real = python.resolve()
    python.unlink()
    python.write_text(
        "#!/bin/sh\n"
        "# Expects the exact call the drift script makes: -I -B -c <code> <td>.\n"
        '[ "$3" = -c ] || exit 97\n'
        f"exec '{real}' -I -B -c \"import sys\n"
        "sys.modules['tomllib'] = None\n"
        '$4" "$5"\n'
    )
    python.chmod(0o755)


def _plant_tomli_stub(tree: Path) -> None:
    """A tomli whose ``load()`` answers the stub lock, planted on the path the snippet
    puts first, so the test proves the fallback import is reached and used."""
    entries = ", ".join(
        f'{{"name": "{n}", "version": "{v}"}}' for n, v in DEFAULT_VERSIONS.items()
    )
    _write(
        tree / TRANSPILER_REL / "tomli.py",
        f'def load(fh):\n    return {{"package": [{entries}]}}\n',
    )
    _commit(tree, f"{TRANSPILER_REL}/tomli.py")


class TestASnippetImportFailureIsANamedFault:
    """tomllib arrived in Python 3.11 and ASH supports 3.10. On an interpreter without
    it, the snippet must fail inside its handler -- a traceback and a FAULT line in
    drift.err, exit status 2 -- never die before printing anything, which left an empty
    drift.out that the shell blamed on the wrong cause ("not a FILES line")."""

    def test_a_missing_tomllib_without_tomli_is_a_named_fault(self, tmp_path):
        tree = _build_tree(tmp_path)
        _poison_tomllib(tree)
        proc, res = _run(tree)
        assert proc.returncode == 2, proc.stderr
        assert not (res / "rc.txt").exists()
        assert "FAULT" in (res / "drift.err").read_text()
        assert "exited 2" in proc.stderr
        assert "not a FILES line" not in proc.stderr

    def test_a_missing_tomllib_falls_back_to_tomli(self, tmp_path):
        tree = _build_tree(tmp_path)
        _poison_tomllib(tree)
        _plant_tomli_stub(tree)
        proc, res = _run(tree)
        assert proc.returncode == 0, proc.stderr
        assert (res / "rc.txt").read_text() == "agentic-plugins-drift 0 files=2\n"


PLUGINS_REL = "ash-agent-plugins/agentic-coding/plugins"
SKILLS_REL = "skills"


def _commit_outputs(tree: Path) -> None:
    _write(tree / PLUGINS_REL / "AGENTS.md", "committed output\n")
    _write(tree / SKILLS_REL / "demo" / "SKILL.md", "committed skill\n")
    _commit(tree, f"{PLUGINS_REL}/AGENTS.md", f"{SKILLS_REL}/demo/SKILL.md")


def _add_untracked_in_plugins(tree: Path) -> None:
    _write(tree / PLUGINS_REL / "stray.txt", "untracked\n")


def _add_untracked_in_skills(tree: Path) -> None:
    _write(tree / SKILLS_REL / "demo" / "stray.txt", "untracked\n")


def _add_ignored_in_plugins(tree: Path) -> None:
    with (tree / ".gitignore").open("a", encoding="utf-8") as fh:
        fh.write("*.swp\n")
    _write(tree / PLUGINS_REL / "AGENTS.md.swp", "ignored\n")


def _edit_a_committed_output(tree: Path) -> None:
    _write(tree / PLUGINS_REL / "AGENTS.md", "regenerated, not committed\n")


class TestTheOutputPathsMustMatchTheCommit:
    """check_drift() reads the disk. Outside a clean checkout an untracked or ignored
    file reads as drift and an uncommitted regeneration reads as a pass, so the script
    refuses to compare unless git reports nothing over the two output paths."""

    def test_committed_outputs_give_the_normal_verdicts(self, tmp_path):
        for body, status in ((HEALTHY_BODY, 0), (DRIFT_BODY, 1)):
            tree = _build_tree(tmp_path / str(status), check_body=body)
            _commit_outputs(tree)
            proc, res = _run(tree)
            assert proc.returncode == status, proc.stderr
            assert (res / "rc.txt").exists()

    @pytest.mark.parametrize(
        "dirty",
        [
            _add_untracked_in_plugins,
            _add_untracked_in_skills,
            _add_ignored_in_plugins,
            _edit_a_committed_output,
        ],
        ids=lambda f: f.__name__.removeprefix("_"),
    )
    def test_a_path_that_differs_from_the_commit_is_exit_2(self, tmp_path, dirty):
        marker = tmp_path / "tree" / "check-ran"
        tree = _build_tree(
            tmp_path, check_body=f'open({str(marker)!r}, "w").close()\nreturn 0'
        )
        _commit_outputs(tree)
        dirty(tree)
        proc, res = _run(tree)
        assert proc.returncode == 2, proc.stderr
        assert not (res / "rc.txt").exists()
        assert not marker.exists(), "nothing is built when the paths are not clean"
        assert "differ from the commit" in proc.stderr

    def test_a_failed_git_status_is_exit_2(self, tmp_path):
        tree = _build_tree(tmp_path)
        shutil.rmtree(tree / ".git")
        (tree / ".git").mkdir()
        proc, res = _run(tree)
        assert proc.returncode == 2, proc.stderr
        assert not (res / "rc.txt").exists()
        assert "git status failed" in proc.stderr


class TestGitWarningsAreNotADirtyListing:
    """git status can warn on stderr and still exit 0; an unreadable core.excludesFile
    is the common case in sandboxed or container HOMEs. A warning is not a dirty path:
    if the dirty test read stderr too, the script would fault on every run in such an
    environment and name paths that are not dirty as the cause."""

    @pytest.mark.skipif(
        getattr(os, "geteuid", lambda: -1)() == 0,
        reason="root can read a chmod-0 file",
    )
    def test_a_git_stderr_warning_with_a_clean_tree_is_not_a_fault(self, tmp_path):
        tree = _build_tree(tmp_path)
        unreadable = tmp_path / "excludes"
        unreadable.write_text("")
        unreadable.chmod(0)
        _git(tree, "config", "core.excludesFile", str(unreadable))
        proc, res = _run(tree)
        assert proc.returncode == 0, proc.stderr
        assert (res / "rc.txt").read_text() == "agentic-plugins-drift 0 files=2\n"


def _add_untracked_base_reference(tree: Path) -> None:
    _write(tree / TRANSPILER_REL / "_base" / "references" / "notes.md", "untracked\n")


def _edit_a_committed_base_input(tree: Path) -> None:
    _write(tree / TRANSPILER_REL / "_base" / "skill.md", "edited, not committed\n")


class TestTheInputPathsMustMatchTheCommit:
    """check_drift() renders from disk inputs too: transpiler/_base (the references/*.md
    glob included), the templates and the transpiler code. An untracked reference or an
    uncommitted input edit changes what every backend renders to, so the script would
    report drift against a commit that is in fact consistent -- the wrong status with no
    error. The script refuses to compare instead."""

    @pytest.mark.parametrize(
        "dirty",
        [_add_untracked_base_reference, _edit_a_committed_base_input],
        ids=lambda f: f.__name__.removeprefix("_"),
    )
    def test_an_input_that_differs_from_the_commit_is_exit_2(self, tmp_path, dirty):
        marker = tmp_path / "tree" / "check-ran"
        tree = _build_tree(
            tmp_path, check_body=f'open({str(marker)!r}, "w").close()\nreturn 0'
        )
        dirty(tree)
        proc, res = _run(tree)
        assert proc.returncode == 2, proc.stderr
        assert not (res / "rc.txt").exists()
        assert not marker.exists(), "nothing is built when the inputs are not clean"
        assert "transpiler inputs differ from the commit" in proc.stderr

    def test_an_ignored_file_under_the_transpiler_is_not_an_input(self, tmp_path):
        tree = _build_tree(tmp_path)
        _write(
            tree / TRANSPILER_REL / "transpiler" / "__pycache__" / "orchestrator.pyc",
            "bytecode\n",
        )
        proc, res = _run(tree)
        assert proc.returncode == 0, proc.stderr
        assert (res / "rc.txt").exists()


class TestTheCountIsWhatWasCompared:
    """files= counts the transpiler's _base inputs, which are always present. What a
    drift check compares is the registered backends' outputs; with none, only AGENTS.md
    is compared and the check would report a healthy 0."""

    def test_drift_out_reports_the_backends_and_rc_txt_keeps_the_kit_grammar(
        self, tmp_path
    ):
        tree = _build_tree(tmp_path, backends=("a", "b", "c"))
        proc, res = _run(tree)
        assert proc.returncode == 0, proc.stderr
        assert "BACKENDS 3" in _out_lines(res)
        # The kit parses exactly "<name> <rc> [tests=<n>] [files=<n>]"; any other token
        # makes it refuse the whole file.
        assert (res / "rc.txt").read_text() == "agentic-plugins-drift 0 files=2\n"

    def test_a_diagnostic_print_before_the_backends_line_is_not_a_fault(self, tmp_path):
        """The shell reads BACKENDS by its tag, not by line number: the print order has
        changed before, and a positional read turned any extra diagnostic print into a
        false fault."""
        tree = _build_tree(
            tmp_path,
            names_body='print("NOTE planted diagnostic", flush=True)\n'
            'return ["alpha", "beta"]',
        )
        proc, res = _run(tree)
        assert proc.returncode == 0, proc.stderr
        lines = _out_lines(res)
        assert "NOTE planted diagnostic" in lines, "the planted print reached drift.out"
        assert "BACKENDS 2" in lines

    def test_no_registered_backend_is_exit_2_not_a_pass(self, tmp_path):
        marker = tmp_path / "tree" / "check-ran"
        tree = _build_tree(
            tmp_path,
            check_body=f'open({str(marker)!r}, "w").close()\nreturn 0',
            backends=(),
        )
        proc, res = _run(tree)
        assert proc.returncode == 2, proc.stderr
        assert not (res / "rc.txt").exists()
        assert not marker.exists(), "the comparison must not run with no backend"
        assert "no backends are registered" in (res / "drift.err").read_text()


REMOVE_BASE_FILES_ON_IMPORT = (
    "import pathlib\n"
    "_base = pathlib.Path(__file__).resolve().parents[1] / '_base'\n"
    "for _p in list(_base.rglob('*')):\n"
    "    if _p.is_file():\n"
    "        _p.unlink()\n"
)


class TestAFaultNamesItsCause:
    """drift.err is the record of a fault, and the shell's message is the first thing a
    reader sees; each says which of the distinct causes it was."""

    def test_an_exception_prints_its_traceback_and_fault_line(self, tmp_path):
        tree = _build_tree(tmp_path, check_body='raise ValueError("boom")')
        proc, res = _run(tree)
        assert proc.returncode == 2, proc.stderr
        err = (res / "drift.err").read_text()
        assert "Traceback (most recent call last)" in err
        assert "orchestrator.py" in err, "the frame that raised is named"
        assert "FAULT ValueError boom" in err

    def test_output_before_the_files_line_is_its_own_message(self, tmp_path):
        tree = _build_tree(
            tmp_path, import_body='print("printed by the transpiler at import")\n'
        )
        proc, res = _run(tree)
        assert proc.returncode == 2, proc.stderr
        assert not (res / "rc.txt").exists()
        assert "not a FILES line" in proc.stderr
        assert "no _base files" not in proc.stderr

    def test_a_base_directory_with_no_files_is_its_own_message(self, tmp_path):
        tree = _build_tree(tmp_path, import_body=REMOVE_BASE_FILES_ON_IMPORT)
        proc, res = _run(tree)
        assert proc.returncode == 2, proc.stderr
        assert not (res / "rc.txt").exists()
        assert "no _base files" in proc.stderr
        assert "not a FILES line" not in proc.stderr


def _remove_the_environment(tree: Path) -> None:
    shutil.rmtree(tree / ".venv")


def _make_the_build_raise(tree: Path) -> None:
    orchestrator = tree / TRANSPILER_REL / "transpiler" / "orchestrator.py"
    _write(orchestrator, 'def check_drift():\n    raise RuntimeError("boom")\n')
    # Committed, so this helper keeps planting a build fault rather than dirty inputs.
    _commit(tree, f"{TRANSPILER_REL}/transpiler/orchestrator.py")


class TestAFaultLeavesNoOutputOfAnEarlierRun:
    """A res dir that holds the previous run's rc.txt would read, after a run that
    could not finish, as that earlier run's verdict."""

    @pytest.mark.parametrize(
        "fault",
        [_remove_the_environment, _add_untracked_in_plugins, _make_the_build_raise],
        ids=lambda f: f.__name__.removeprefix("_"),
    )
    def test_exit_2_deletes_the_files_of_an_earlier_run(self, tmp_path, fault):
        tree = _build_tree(tmp_path)
        _commit_outputs(tree)
        fault(tree)
        res = tmp_path / "res"
        res.mkdir()
        for name in ("rc.txt", "drift.out", "drift.err"):
            (res / name).write_text("STALE agentic-plugins-drift 0 files=9\n")
        proc, res = _run(tree, res)
        assert proc.returncode == 2, proc.stderr
        assert not (res / "rc.txt").exists()
        for name in ("drift.out", "drift.err"):
            path = res / name
            assert not path.exists() or "STALE" not in path.read_text(), name
