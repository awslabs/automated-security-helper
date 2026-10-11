# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The rules that make a snapshot change a decision rather than a side effect.

Three properties, each with a negative control so a check that has stopped seeing
anything cannot pass by default:

* nothing CI runs passes syrupy's update or warn-unused flags (either would turn a
  failing snapshot into a rewritten or ignored one);
* every snapshot file maps to a test module that exists, which syrupy cannot check for a
  module that was deleted or renamed;
* .github/scripts/check-snapshot-trailers.py rejects a golden change whose commit has no
  ``Snapshot-Update:`` trailer.
"""

from __future__ import annotations

import fnmatch
import importlib.util
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from types import ModuleType

import pytest

from tests.utils.helpers import iter_repo_files

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / ".github/scripts/check-snapshot-trailers.py"


@pytest.fixture(scope="module")
def trailers() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_snapshot_trailers", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves string annotations through sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# No CI path may pass the flags that defeat snapshots
# ---------------------------------------------------------------------------

# Prefix match, so --snapshot-update-new-only and any other --snapshot-update-* are
# caught by the first alternative.
_BANNED = re.compile(r"--snapshot-(?:update|warn-unused)")

# A `#` at line start or after whitespace starts a comment in YAML, shell, Python, TOML
# and INI. Comments are stripped so a note explaining the rule does not trip it; nothing
# a comment says is executed.
_COMMENT = re.compile(r"(?:^|\s)#.*$", re.MULTILINE)


def banned_flags(text: str) -> list[str]:
    return _BANNED.findall(_COMMENT.sub("", text))


# Everything CI executes or configures pytest from. .github/ is scanned whole (workflows,
# composite actions, the scripts they call); scripts/ because CI runs some of it.
_CONFIG_FILES = (
    "pytest.ini",
    "pyproject.toml",
    "setup.cfg",
    "tox.ini",
    "noxfile.py",
    "Makefile",
    ".pre-commit-config.yaml",
)


def _ci_files() -> list[Path]:
    # __pycache__ is skipped: other xdist workers write .pyc files there (this module
    # imports a script from .github/scripts), and a half-written one can vanish mid-scan.
    files = [
        p
        for top in (".github", "scripts")
        for p in (REPO_ROOT / top).rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    ]
    files += [
        REPO_ROOT / name for name in _CONFIG_FILES if (REPO_ROOT / name).is_file()
    ]
    return files


def test_banned_flag_scanner_detects_an_invocation() -> None:
    # Negative control: the forms a workflow would actually use are found.
    assert banned_flags("run: uv run pytest tests --snapshot-update")
    assert banned_flags("addopts = -n auto --snapshot-update-new-only")
    assert banned_flags('args: ["--snapshot-warn-unused"]')
    assert not banned_flags("# never pass --snapshot-update in CI")
    assert not banned_flags("run: uv run pytest tests/snapshot")


def test_no_ci_file_passes_snapshot_update_or_warn_unused() -> None:
    files = _ci_files()
    assert any(p.name == "ash-unified-ci.yml" for p in files), "scanned the wrong tree"
    offenders = {}
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        found = banned_flags(text)
        if found:
            offenders[path.relative_to(REPO_ROOT).as_posix()] = found
    assert offenders == {}, (
        "CI must never update or ignore snapshots; a failing snapshot is fixed locally "
        f"and committed with a Snapshot-Update trailer. Found: {offenders}"
    )


# ---------------------------------------------------------------------------
# Orphaned snapshots
# ---------------------------------------------------------------------------


def test_every_snapshot_belongs_to_an_existing_test_module(trailers) -> None:
    assert trailers.find_orphans(REPO_ROOT) == []


def _git_init(path: Path) -> None:
    """find_orphans reads the tree through git, so a synthetic tree has to be a repo."""
    subprocess.run(["git", "init", "-q", str(path)], check=True)


def test_orphan_check_reports_a_deleted_module(trailers, tmp_path: Path) -> None:
    _git_init(tmp_path)
    snaps = tmp_path / "tests/x/__snapshots__"
    (snaps / "test_kept").mkdir(parents=True)
    (snaps / "test_kept/case.md").write_text("x")
    (tmp_path / "tests/x/test_kept.py").write_text("")
    assert trailers.find_orphans(tmp_path) == []

    (snaps / "test_deleted.ambr").write_text("x")
    (snaps / "test_renamed").mkdir()
    (snaps / "test_renamed/case.json").write_text("x")
    (tmp_path / "tests/y/__snapshots__").mkdir(parents=True)
    problems = "\n".join(trailers.find_orphans(tmp_path))
    assert "test_deleted.ambr belongs to test_deleted.py" in problems
    assert "test_renamed belongs to test_renamed.py" in problems
    assert "tests/y/__snapshots__/ is empty" in problems


def test_orphan_check_counts_tracked_and_untracked_but_not_ignored(
    trailers, tmp_path: Path
) -> None:
    """The tree is what git counts: tracked, untracked, never ignored.

    tests/pytest-temp is ignored, and other test workers create and remove
    directories there while this runs on the real checkout, so the check must not
    look inside it. A snapshot that is committed and one that is not yet added are
    both checked.
    """
    _git_init(tmp_path)
    (tmp_path / ".gitignore").write_text("tests/pytest-temp/\n")
    snaps = tmp_path / "tests/x/__snapshots__"
    snaps.mkdir(parents=True)
    (tmp_path / "tests/x/test_kept.py").write_text("")
    (snaps / "test_committed_orphan.ambr").write_text("x")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    (snaps / "test_new_orphan.ambr").write_text("x")
    scratch = tmp_path / "tests/pytest-temp/worker"
    (scratch / "__snapshots__").mkdir(parents=True)
    (scratch / "__snapshots__/test_scratch.ambr").write_text("x")
    (scratch / "empty/__snapshots__").mkdir(parents=True)

    problems = "\n".join(trailers.find_orphans(tmp_path))

    assert "test_committed_orphan.ambr belongs to" in problems
    assert "test_new_orphan.ambr belongs to" in problems
    assert "pytest-temp" not in problems


def test_orphan_check_refuses_a_tree_git_cannot_read(
    trailers, tmp_path: Path, monkeypatch
) -> None:
    """A tree git cannot list is an error, not a tree with no snapshots in it."""
    plain = tmp_path / "plain"
    (plain / "tests/x/__snapshots__").mkdir(parents=True)
    # Stop git searching above tmp_path, so an enclosing repository cannot answer.
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    with pytest.raises(trailers.GitError):
        trailers.find_orphans(plain)


# ---------------------------------------------------------------------------
# check-snapshot-trailers.py
# ---------------------------------------------------------------------------


@pytest.fixture
def repo(trailers, tmp_path: Path):
    return trailers._Repo(tmp_path / "repo")


def test_self_test_passes(trailers, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    assert trailers.self_test() == 0


# Characters a Windows file name cannot hold, plus the separators. ``\`` is a separator
# there, so a name holding one silently becomes a directory, then fails on the ``"``.
_NTFS_FORBIDDEN = re.compile(r'[<>:"|?*\\\x00-\x1f]')


def test_self_test_writes_only_names_a_windows_checkout_can_hold(
    trailers, tmp_path: Path, monkeypatch
) -> None:
    """The self-test runs on the Windows unit-test legs too.

    A case that needs a path NTFS refuses (``"``, ``\\``, a trailing dot or space)
    must build that commit from git objects rather than write the name to the working
    tree. This makes every working-tree write behave as NTFS does, so the Linux and
    macOS legs catch such a case before it fails only on Windows.
    """
    real_write = trailers._Repo.write

    def ntfs_write(self, rel: str, text: str) -> None:
        for part in PurePosixPath(rel).parts:
            if _NTFS_FORBIDDEN.search(part) or part.endswith((" ", ".")):
                raise OSError(f"NTFS cannot hold the name {part!r} in {rel!r}")
        real_write(self, rel, text)

    monkeypatch.setattr(trailers._Repo, "write", ntfs_write)
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    assert trailers.self_test() == 0


def test_golden_change_without_trailer_fails(trailers, repo, capsys) -> None:
    # NEGATIVE CONTROL: the check exists to produce this failure.
    path = "tests/snapshot/__snapshots__/test_cli/summary.md"
    repo.write(path, "new output\n")
    repo.commit("feat(cli): change the summary")

    rng = trailers.Range(repo.base, "HEAD", "test")
    assert trailers.run_check(repo.path, rng) == 1
    out = capsys.readouterr().out
    assert f"::error file={path}::" in out
    assert "git commit --amend --no-edit --trailer" in out


def test_golden_change_with_trailer_passes(trailers, repo) -> None:
    repo.write("tests/snapshot/__snapshots__/test_cli.ambr", "new\n")
    repo.commit("feat(cli): change\n\nSnapshot-Update: the summary gained a column")
    assert trailers.run_check(repo.path, trailers.Range(repo.base, "HEAD", "t")) == 0


def test_fix_for_an_older_commit_is_a_rebase(trailers, repo, capsys) -> None:
    path = "tests/snapshot/__snapshots__/test_cli.ambr"
    repo.write(path, "new\n")
    repo.commit("feat: change")
    repo.write("other.txt", "x\n")
    repo.commit("chore: later")
    assert trailers.run_check(repo.path, trailers.Range(repo.base, "HEAD", "t")) == 1
    out = capsys.readouterr().out
    assert f"git rebase $(git merge-base {repo.base} HEAD) --exec" in out
    assert f"git diff-tree --quiet HEAD^ HEAD -- {path}" in out


_MCP_TOOL_REFERENCE = (
    "ash-agent-plugins/agentic-coding/transpiler/_base/references/tool-reference.md"
)


@pytest.mark.parametrize(
    ("path", "golden"),
    [
        ("tests/snapshot/__snapshots__/test_cli.ambr", True),
        ("tests/snapshot/__snapshots__/test_cli/summary.md", True),
        (".github/actions/validate-mcp/tool_surface.golden.json", True),
        ("automated_security_helper/schemas/AshConfig.json", True),
        ("docs/content/docs/cli-reference-generated.md", True),
        (_MCP_TOOL_REFERENCE, True),
        ("tests/snapshot/test_cli.py", False),
        ("docs/content/docs/cli-reference.md", False),
        ("automated_security_helper/schemas/generate_schemas.py", False),
        ("automated_security_helper/schemas/ocsf/x.json", False),
        ("skills/ash-mcp/references/tool-reference.md", False),
    ],
)
def test_golden_set(trailers, path: str, golden: bool) -> None:
    assert bool(trailers.golden_reason(path)) is golden


def test_golden_set_names_files_that_exist(trailers) -> None:
    # A golden pattern that matches nothing in the tree is a typo that silently exempts
    # the file it meant.
    #
    # Listed with iter_repo_files rather than REPO_ROOT.glob, which
    # tests/unit/test_repo_walkers_skip_scratch.py forbids (a walk from the root can
    # descend into another xdist worker's scratch dir as it is removed). Every GOLDEN
    # pattern globs a file name inside a literal directory, so only that directory is
    # listed, and the name is matched the way golden_reason matches a component.
    for pattern, _ in trailers.GOLDEN:
        if pattern == "__snapshots__":
            continue
        pattern_path = PurePosixPath(pattern)
        assert not any(c in str(pattern_path.parent) for c in "*?["), (
            f"{pattern}: a glob in a directory part needs a different existence check"
        )
        directory = REPO_ROOT / pattern_path.parent
        names = [p.name for p in iter_repo_files(directory) if p.parent == directory]
        assert any(fnmatch.fnmatchcase(name, pattern_path.name) for name in names), (
            f"{pattern} matches no file"
        )


def test_squash_sections_expose_mid_message_trailers(trailers, repo) -> None:
    message = (
        "feat: x (#1)\n\n"
        "* feat: first\n\nbody\n\nSnapshot-Update: first reason\n\n"
        "* fix: second\n\nSigned-off-by: a <a@example.invalid>\n"
    )
    sections = trailers.message_sections(message)
    assert sections[0] == message
    assert len(sections) == 3
    assert trailers.snapshot_reasons(repo.path, message) == ["first reason"]
    # The same trailer is invisible to git when the message is read whole.
    whole = trailers.parse_trailers(repo.path, message)
    assert ("Snapshot-Update", "first reason") not in whole
