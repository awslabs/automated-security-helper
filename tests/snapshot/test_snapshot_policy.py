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


def test_no_ci_file_passes_snapshot_update_or_warn_unused(trailers) -> None:
    files = _ci_files()
    assert any(p.name == "ash-unified-ci.yml" for p in files), "scanned the wrong tree"
    # The trailer script's --policy names every editor update flag, syrupy's among them,
    # in order to look for them in workflows: in its patterns and its self-test
    # fixtures. It passes none, so it is the one file exempt here, by exact path, and
    # only while it is still that checker and still looks for syrupy's flag.
    # editors/vscode/test/snapshot-policy.test.ts exempts it the same way.
    assert trailers.UPDATE_FLAGS.search("pytest --snapshot-update")
    offenders = {}
    for path in files:
        if path == SCRIPT:
            continue
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


def test_orphan_check_reports_a_deleted_module(trailers, tmp_path: Path) -> None:
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


# A frozen copy of PRE_RULE_EXEMPTIONS' keys and the cutoff. The table may only shrink:
# a commit made after #717 takes a trailer, not an entry. Removing an entry here and in
# the script is fine; adding one, or moving the cutoff, fails below.
# pragma: allowlist nextline secret
_FROZEN_RULE_COMMIT = "2a09ec3ad071e40718183630ff9899360b74fe3d"
_FROZEN_CUTOFF = 1791309669  # committer date of the #717 merge on main
_FROZEN_EXEMPTIONS = frozenset(
    {
        "7e54dba560cee37bb267f8cb8f78dc3e185ce4e3",  # pragma: allowlist secret
        "0695ce962e4909e0032168ef3e8f8cefc271be89",  # pragma: allowlist secret
        "19cfbc5aa0a81447b2d960b5dc1294f346aba633",  # pragma: allowlist secret
        "215c48542afa2aed88c6b085915e45d9d54af0ce",  # pragma: allowlist secret
        "5de8897fd27e80913b2ccfb5fd47bbcb39f82f33",  # pragma: allowlist secret
        "ab82c950008d6bbbb4c9b2f51b326859b01aed6a",  # pragma: allowlist secret
        "25ca8f6f8fad028ccab7760715c7da37beb3e2ba",  # pragma: allowlist secret
        "d9e2e9571d25726c97808f1c5af9045834ab21c1",  # pragma: allowlist secret
        "e6099d50d3bf34ac33944959fdfd0014b6d8f4a7",  # pragma: allowlist secret
        "19fd417e028f973b65e4f520ad7f71492e49b260",  # pragma: allowlist secret
        "10b4fe01b5f6793d1fcac75ba6532e7adc7c230e",  # pragma: allowlist secret
        "b9a782f5c694f2a788909f49ab1a60fd22c7a055",  # pragma: allowlist secret
        "6efd0d20da424a95d5ebd30f94429dac75596390",  # pragma: allowlist secret
    }
)


def test_pre_rule_exemptions_only_shrink(trailers) -> None:
    added = set(trailers.PRE_RULE_EXEMPTIONS) - _FROZEN_EXEMPTIONS
    assert not added, f"PRE_RULE_EXEMPTIONS is shrink-only; new entries: {added}"
    assert trailers.TRAILER_RULE_COMMIT == _FROZEN_RULE_COMMIT
    assert trailers.TRAILER_RULE_COMMITTED_AT == _FROZEN_CUTOFF
    for sha, reason in trailers.PRE_RULE_EXEMPTIONS.items():
        assert reason.strip(), f"{sha} has no reason"


def test_listed_commit_after_the_rule_still_fails(trailers, repo, capsys) -> None:
    # NEGATIVE CONTROL through run_check: a golden change committed after the rule, with
    # its SHA in the table, is judged like any other commit.
    path = "tests/snapshot/__snapshots__/test_cli.ambr"
    repo.write(path, "new\n")
    sha = repo.commit(
        "feat: change", committed_at=trailers.TRAILER_RULE_COMMITTED_AT + 60
    )
    table = {sha: "should not be honored"}
    commits = trailers.commits_in_range(repo.path, repo.base, "HEAD")
    assert [
        v.path for v in trailers.find_violations(repo.path, commits, "HEAD", table)
    ] == [path]
    early = trailers._Repo(repo.path.parent / "early")
    early.write(path, "new\n")
    early_sha = early.commit(
        "feat: change", committed_at=trailers.TRAILER_RULE_COMMITTED_AT - 60
    )
    early_commits = trailers.commits_in_range(early.path, early.base, "HEAD")
    assert (
        trailers.find_violations(
            early.path, early_commits, "HEAD", {early_sha: "pre-rule"}
        )
        == []
    )


def test_exempted_commit_does_not_explain_a_later_schema_change(trailers, repo) -> None:
    # NEGATIVE CONTROL: an exempted pre-rule commit is skipped, not counted as a
    # trailer, so under the any-commit rule an untrailered post-rule change to the same
    # schema file still fails.
    path = "automated_security_helper/schemas/AshConfig.json"
    cutoff = trailers.TRAILER_RULE_COMMITTED_AT
    repo.write(path, "{}\n")
    exempt = repo.commit("feat: pre-rule schema change", committed_at=cutoff - 60)
    table = {exempt: "pre-rule"}
    alone = trailers.commits_in_range(repo.path, repo.base, "HEAD")
    assert trailers.find_violations(repo.path, alone, "HEAD", table) == []
    repo.write(path, '{"a": 1}\n')
    repo.commit("feat: post-rule schema change", committed_at=cutoff + 60)
    commits = trailers.commits_in_range(repo.path, repo.base, "HEAD")
    violations = trailers.find_violations(repo.path, commits, "HEAD", table)
    assert [v.path for v in violations] == [path]
    assert [c.sha for c in violations[0].commits] != [exempt]
    # A trailered later change still explains the file, as the any-commit rule says.
    repo.write(path, '{"a": 2}\n')
    repo.commit("feat: explained\n\nSnapshot-Update: the schema gained a field")
    commits = trailers.commits_in_range(repo.path, repo.base, "HEAD")
    assert trailers.find_violations(repo.path, commits, "HEAD", table) == []


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
