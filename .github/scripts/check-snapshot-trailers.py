#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fails when a golden file changes without a ``Snapshot-Update:`` trailer saying why.

WHY THIS EXISTS
---------------
A snapshot test fails when output changes, and syrupy's update flag makes it pass again
by rewriting the snapshot (see DEVELOPMENT.md). That rewrite is one command and
produces a diff nobody has to read, so on its own a snapshot suite only proves that
someone ran the command. What makes a changed snapshot a decision is a sentence, attached to the commit
that changed it, saying why the output is now different. This script requires that
sentence: every golden file touched in the range must be touched by at least one commit
that carries ``Snapshot-Update: <non-empty reason>`` as a git trailer.

The rule is per commit, not per pull request. A follow-up commit that only adds the
trailer (an empty commit, or one touching some other file) does not satisfy it, because
then the reason is not attached to the change it explains, and after a rebase or a
cherry-pick the two travel separately. The error message prints the exact command that
amends the right commits.

WHAT COUNTS AS GOLDEN
---------------------
``GOLDEN`` below is the one list. A file is golden when it is committed output that
users or clients see AND it is entirely produced by a generator or a test, so a change
to it is always a change in behaviour rather than an edit. Files that are partly
hand-written are out: requiring a trailer for a typo fix in prose teaches people to
paste a meaningless reason, and a trailer that is always pasted means nothing. Each
entry, and each rejected candidate, is explained next to the list.

ORPHANED SNAPSHOTS
------------------
syrupy fails the session for a snapshot that a collected test module no longer asserts.
It cannot see a snapshot whose test module was deleted or renamed: the module is not
collected, so its ``__snapshots__/test_old.ambr`` is never opened and a full run exits 0
(measured with syrupy 5.5 under pytest-xdist). ``--orphans`` closes that gap by mapping
every file under a ``tests/**/__snapshots__/`` directory back to the module that owns it.
Between the two, a snapshot that nothing asserts fails CI either way.

HOW THE RANGE IS CHOSEN (one per event; see ``resolve_range``)
-------------------------------------------------------------
* pull_request: ``pull_request.base.sha..pull_request.head.sha``. The head sha, not
  GITHUB_SHA, because GITHUB_SHA is GitHub's synthetic merge commit, whose message
  carries no trailers. Commits merged in from the base branch are ancestors of base.sha
  and drop out of the range.
* merge_group: ``merge_group.base_sha..merge_group.head_sha``. The queue squashes, so
  each commit here is one pull request's squash commit. See ``message_sections`` for why
  its message is parsed per section.
* push: ``before..after``. An all-zero ``before`` (a newly created ref) has no range, so
  only ``after`` itself is checked against its first parent. A ``before`` that is no
  longer in the clone (a force-push that discarded it) gets the same treatment, with a
  warning, rather than a pass.
* workflow_dispatch: there is no event range, so the branch is checked against the
  merge base with the default branch, which is what a pull request from it would check.
  On the default branch itself that range is empty.

The checkout must have full history (``fetch-depth: 0``). A sha that is missing is
fetched once; if it is still missing the script fails rather than checking less.

USAGE
-----
    python3 .github/scripts/check-snapshot-trailers.py --self-test
    python3 .github/scripts/check-snapshot-trailers.py              # range from the event
    python3 .github/scripts/check-snapshot-trailers.py --base origin/main --head HEAD
    python3 .github/scripts/check-snapshot-trailers.py --orphans

Standard library only, like the other gate scripts, so the job installs nothing.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

TRAILER_KEY = "Snapshot-Update"
ZERO_SHA = "0" * 40

# ---------------------------------------------------------------------------
# THE GOLDEN SET
#
# (pattern, why). A pattern containing "__snapshots__" matches any path with a
# `__snapshots__` directory component; every other pattern is an fnmatch glob against
# the repository-relative posix path, where `*` does not cross `/`.
#
# In:
# * any `__snapshots__/` tree: syrupy output, written only by `--snapshot-update`.
# * .github/actions/validate-mcp/*.golden.json: the MCP tool surface a client sees,
#   compared against the live server by compare_tool_surface.py.
# * automated_security_helper/schemas/*.json: the published config and results JSON
#   schemas. Written whole by `python -m automated_security_helper.schemas.generate_schemas`;
#   the lint job regenerates them and fails on any difference.
# * docs/content/docs/cli-reference-generated.md: written whole by
#   scripts/generate_cli_docs.py; tests/unit/test_generated_docs_freshness.py regenerates
#   and diffs it.
# * ash-agent-plugins/.../transpiler/_base/references/tool-reference.md: written whole by
#   scripts/generate_mcp_tool_reference.py (its editorial notes live in that script, not
#   in the file); the same freshness test runs its --check.
#
# Out, deliberately:
# * The per-backend copies of tool-reference.md under ash-agent-plugins/.../plugins/ and
#   skills/ash-mcp/references/: byte copies of the _base file, held equal by the
#   transpiler's own byte-compare gate. The _base change is where the reason belongs;
#   requiring it again on each copy adds annotations and no information.
# * Pages with regions maintained by scripts/generate_reporter_docs.py (output-formats.md,
#   plugins/**.md): only the marker-delimited regions are generated, the rest is prose,
#   so a whole-file rule would demand a trailer for a typo fix.
# * docs/content/docs/cli-reference.md: hand-written.
# * ash-agent-plugins/.../transpiler/generated_models/*.py: generated code, not output a
#   user sees.
# ---------------------------------------------------------------------------
GOLDEN: tuple[tuple[str, str], ...] = (
    ("__snapshots__", "syrupy snapshot"),
    (".github/actions/validate-mcp/*.golden.json", "MCP tool-surface golden"),
    ("automated_security_helper/schemas/*.json", "generated JSON schema"),
    ("docs/content/docs/cli-reference-generated.md", "generated CLI reference"),
    (
        "ash-agent-plugins/agentic-coding/transpiler/_base/references/tool-reference.md",
        "generated MCP tool reference",
    ),
)


def golden_reason(path: str) -> str | None:
    """Return why ``path`` is golden, or None when it is not."""
    posix = PurePosixPath(path)
    for pattern, why in GOLDEN:
        if pattern == "__snapshots__":
            if "__snapshots__" in posix.parts[:-1]:
                return why
            continue
        # fnmatch's `*` crosses `/`; compare component-wise so it does not.
        pat = PurePosixPath(pattern)
        if len(pat.parts) == len(posix.parts) and all(
            fnmatch.fnmatchcase(p, q) for p, q in zip(posix.parts, pat.parts)
        ):
            return why
    return None


# ---------------------------------------------------------------------------
# git plumbing
# ---------------------------------------------------------------------------


class GitError(RuntimeError):
    pass


def git(repo: Path, *args: str, stdin: str | None = None, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def commit_exists(repo: Path, sha: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", f"{sha}^{{commit}}"],
        capture_output=True,
    )
    return proc.returncode == 0


def ensure_commit(repo: Path, sha: str) -> bool:
    """True when ``sha`` is present, fetching it once from origin if it is not."""
    if commit_exists(repo, sha):
        return True
    subprocess.run(
        ["git", "-C", str(repo), "fetch", "--no-tags", "--quiet", "origin", sha],
        capture_output=True,
    )
    return commit_exists(repo, sha)


@dataclass
class Commit:
    sha: str
    subject: str
    message: str
    files: list[str] = field(default_factory=list)


def touched_files(repo: Path, sha: str) -> list[str]:
    """Paths a commit adds, modifies or deletes.

    ``--no-renames`` so a rename is a deletion plus an addition: both paths count as
    touched, and moving a snapshot needs a reason just as editing one does. A merge
    commit is read with ``-c``, which lists only paths whose merged content matches no
    parent, so a conflict resolution that hand-edits a snapshot is still seen while the
    files the merge merely brought in from the other side are not.
    """
    parents = git(repo, "rev-list", "--parents", "-n", "1", sha).split()[1:]
    if len(parents) > 1:
        out = git(repo, "diff-tree", "-r", "-c", "--no-renames", "--name-only", sha)
        names = out.splitlines()[1:]  # the first line is the commit id
    else:
        out = git(
            repo,
            "diff-tree",
            "-r",
            "--root",
            "--no-commit-id",
            "--no-renames",
            "--name-only",
            sha,
        )
        names = out.splitlines()
    return [n for n in names if n]


def commits_in_range(repo: Path, base: str | None, head: str) -> list[Commit]:
    """Commits reachable from ``head`` and not from ``base``; ``head`` alone if no base."""
    spec = [f"{base}..{head}"] if base else ["-n", "1", head]
    shas = git(repo, "rev-list", "--reverse", *spec).split()
    commits = []
    for sha in shas:
        message = git(repo, "log", "-1", "--format=%B", sha)
        subject = git(repo, "log", "-1", "--format=%s", sha).strip()
        commits.append(Commit(sha, subject, message, touched_files(repo, sha)))
    return commits


# ---------------------------------------------------------------------------
# Trailers
# ---------------------------------------------------------------------------

# A squash-merge body under squash_merge_commit_message=COMMIT_MESSAGES is each commit
# of the pull request rendered as "* <subject>" followed by its body.
_SECTION_START = re.compile(r"^\* ", re.MULTILINE)


def message_sections(message: str) -> list[str]:
    """The whole message, then each ``* subject`` section of a squash body.

    git reads trailers only from the last paragraph of a message. This repository
    squash-merges with squash_merge_commit_message=COMMIT_MESSAGES, which concatenates
    every commit of the pull request as "* subject\\n\\nbody", so a trailer that ended
    the first of three commits ends up in the middle of the squash commit and git no
    longer sees it as a trailer. That squash commit is what the merge queue and the push
    to main check. Parsing each section separately restores the trailers each original
    commit had.

    A body line that is itself a "* " bullet starts a spurious section. That only adds
    candidates whose last paragraph is still a real paragraph of the message, so it can
    find a trailer git would also have found in the original commit; it cannot invent one.
    """
    starts = [m.start() for m in _SECTION_START.finditer(message)]
    sections = [message]
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(message)
        sections.append(message[start:end])
    return sections


def parse_trailers(repo: Path, text: str) -> list[tuple[str, str]]:
    """``git interpret-trailers --parse``, as (key, value) pairs.

    git decides what a trailer block is (last paragraph, folding, separators), so this
    agrees with every other git tool about what the commit says. A regex over the
    message would accept a "Snapshot-Update:" line quoted in the middle of prose.
    """
    out = git(repo, "interpret-trailers", "--parse", stdin=text)
    pairs = []
    for line in out.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            pairs.append((key.strip(), value.strip()))
    return pairs


def _is_placeholder(value: str) -> bool:
    # The documented command is `--trailer "Snapshot-Update: <why the output changed>"`;
    # pasting it unedited is not a reason.
    return value.startswith("<") and value.endswith(">")


def snapshot_reasons(repo: Path, message: str) -> list[str]:
    """Every non-empty Snapshot-Update reason the message carries, in any section."""
    reasons = []
    for section in message_sections(message):
        for key, value in parse_trailers(repo, section):
            if (
                key.lower() == TRAILER_KEY.lower()
                and value
                and not _is_placeholder(value)
            ):
                reasons.append(value)
    return reasons


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------


@dataclass
class Violation:
    path: str
    why_golden: str
    commits: list[Commit]


def find_violations(repo: Path, commits: list[Commit]) -> list[Violation]:
    touched: dict[str, list[Commit]] = {}
    for commit in commits:
        for path in commit.files:
            if golden_reason(path):
                touched.setdefault(path, []).append(commit)
    reasons = {c.sha: snapshot_reasons(repo, c.message) for c in commits}
    return [
        Violation(path, golden_reason(path) or "", touching)
        for path, touching in sorted(touched.items())
        if not any(reasons[c.sha] for c in touching)
    ]


def fix_instructions(violation: Violation, base: str | None, head_sha: str) -> str:
    trailer = f'--trailer "{TRAILER_KEY}: <why the output changed>"'
    if [c.sha for c in violation.commits] == [head_sha]:
        return f"git commit --amend --no-edit {trailer}"
    # Otherwise replay the branch onto its own fork point, so nothing but messages
    # changes, and amend each replayed commit that touched this path. The `||` runs the
    # amend only when the commit just replayed changed it.
    onto = (
        f"$(git merge-base {base} HEAD)"
        if base
        else f"{violation.commits[0].sha[:12]}^"
    )
    exec_cmd = (
        f"git diff-tree --quiet HEAD^ HEAD -- {shlex.quote(violation.path)} || "
        f"git commit --amend --no-edit {trailer}"
    )
    return f"git rebase {onto} --exec {shlex.quote(exec_cmd)}"


def _annotation_data(text: str) -> str:
    # Commit subjects are author-controlled and land in a workflow command, so they get
    # the runner's own escaping and cannot end the annotation or start a new command.
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _annotation_property(text: str) -> str:
    return _annotation_data(text).replace(":", "%3A").replace(",", "%2C")


def report(violations: list[Violation], base: str | None, head_sha: str) -> None:
    for v in violations:
        touched_by = ", ".join(f"{c.sha[:10]} ({c.subject})" for c in v.commits)
        message = (
            f"{v.path} ({v.why_golden}) changed in "
            f"{(base or '')[:10] or '(root)'}..{head_sha[:10]} without a "
            f"'{TRAILER_KEY}: <reason>' trailer on the commit that changed it. Touched "
            f"by: {touched_by}. A separate commit carrying the trailer does not count. "
            f"Fix: {fix_instructions(v, base, head_sha)} -- replace <why the output "
            f"changed> with the reason, review `git log`, then "
            f"`git push --force-with-lease`."
        )
        print(
            f"::error file={_annotation_property(v.path)}::{_annotation_data(message)}"
        )


# ---------------------------------------------------------------------------
# Range resolution
# ---------------------------------------------------------------------------


@dataclass
class Range:
    base: str | None
    head: str
    note: str


def resolve_range(repo: Path, event_name: str, payload: dict) -> Range | None:
    """The commits an event introduces, or None when there are none to check."""
    if event_name in ("pull_request", "pull_request_target"):
        pr = payload["pull_request"]
        return Range(pr["base"]["sha"], pr["head"]["sha"], "pull request")
    if event_name == "merge_group":
        mg = payload["merge_group"]
        return Range(mg["base_sha"], mg["head_sha"], "merge queue entry")
    if event_name == "push":
        before, after = payload.get("before") or ZERO_SHA, payload["after"]
        if after == ZERO_SHA:
            return None  # a deleted ref introduces nothing
        if before == ZERO_SHA:
            return Range(None, after, "new ref: its tip commit only")
        if not ensure_commit(repo, before):
            print(
                f"::warning::push 'before' {before} is not in the clone (force-push?); "
                f"checking only {after}."
            )
            return Range(None, after, "force-push: tip commit only")
        return Range(before, after, "push")
    if event_name == "workflow_dispatch":
        default = (payload.get("repository") or {}).get("default_branch") or "main"
        head = git(repo, "rev-parse", "HEAD").strip()
        ref = f"origin/{default}"
        if not commit_exists(repo, ref):
            raise GitError(f"{ref} is not in the clone; check out with fetch-depth: 0")
        base = git(repo, "merge-base", ref, head).strip()
        return Range(base, head, f"dispatch: branch vs merge base with {ref}")
    raise GitError(f"unsupported event {event_name!r}")


def run_check(repo: Path, rng: Range) -> int:
    for sha in (rng.base, rng.head):
        if sha and not ensure_commit(repo, sha):
            print(f"::error::{sha} is not in the clone; check out with fetch-depth: 0")
            return 1
    commits = commits_in_range(repo, rng.base, rng.head)
    violations = find_violations(repo, commits)
    head_sha = git(repo, "rev-parse", f"{rng.head}^{{commit}}").strip()
    report(violations, rng.base, head_sha)
    golden = sorted({p for c in commits for p in c.files if golden_reason(p)})
    print(
        f"{rng.note}: {len(commits)} commit(s), {len(golden)} golden file(s) touched, "
        f"{len(violations)} without a {TRAILER_KEY} trailer."
    )
    return 1 if violations else 0


# ---------------------------------------------------------------------------
# Orphaned snapshots
# ---------------------------------------------------------------------------


def find_orphans(root: Path) -> list[str]:
    """Problems with snapshot files under ``root/tests`` that syrupy cannot report.

    ``__snapshots__/<mod>.ambr`` and ``__snapshots__/<mod>/...`` must each have a
    ``<mod>.py`` next to the ``__snapshots__`` directory, and no ``__snapshots__``
    directory (or per-module directory inside one) may be empty: an empty one is what a
    deleted snapshot leaves behind locally.
    """
    problems = []
    for snapdir in sorted((root / "tests").rglob("__snapshots__")):
        if not snapdir.is_dir():
            continue
        rel = snapdir.relative_to(root).as_posix()
        entries = sorted(snapdir.iterdir())
        if not entries:
            problems.append(f"{rel}/ is empty; delete it")
        for entry in entries:
            if entry.is_dir():
                module = entry.name
                if not any(p.is_file() for p in entry.rglob("*")):
                    problems.append(f"{rel}/{entry.name}/ is empty; delete it")
            elif entry.suffix == ".ambr":
                module = entry.stem
            else:
                problems.append(
                    f"{rel}/{entry.name} is neither <module>.ambr nor inside "
                    f"<module>/, so no test can own it"
                )
                continue
            if not (snapdir.parent / f"{module}.py").is_file():
                problems.append(
                    f"{rel}/{entry.name} belongs to {module}.py, which does not exist "
                    f"next to {rel}/. Delete the snapshot, or move it with its module."
                )
    return problems


# ---------------------------------------------------------------------------
# Self-test
#
# Runs first in CI for the same reason as assert-publish-surfaces.py's: a checker whose
# failure mode is "found nothing, exit 0" reads as a clean tree. Every case below runs
# through the same functions the real check uses.
# ---------------------------------------------------------------------------

GOOD = f"{TRAILER_KEY}: the summary table gained a column"


class _Repo:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.mkdir(parents=True)
        self._git("init", "-q", "-b", "main")
        self.write("README.md", "x\n")
        self.base = self.commit("chore: initial")

    def _git(self, *args: str) -> str:
        # Isolated from the caller's config: no signing prompt, no hooks, a fixed identity.
        return git(
            self.path,
            "-c",
            "user.name=self-test",
            "-c",
            "user.email=self-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            *args,
        )

    def write(self, rel: str, text: str) -> None:
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def commit(self, message: str, *, allow_empty: bool = False) -> str:
        self._git("add", "-A")
        extra = ["--allow-empty"] if allow_empty else []
        self._git("commit", "-q", *extra, "-m", message)
        return self._git("rev-parse", "HEAD").strip()

    def violations(self) -> list[str]:
        commits = commits_in_range(self.path, self.base, "HEAD")
        return [v.path for v in find_violations(self.path, commits)]


SNAP = "tests/snapshot/__snapshots__/test_cli.ambr"


def _case_trailer_present(r: _Repo) -> list[str]:
    r.write(SNAP, "a\n")
    r.commit(f"test: update\n\nbody\n\n{GOOD}")
    return []


def _case_trailer_missing(r: _Repo) -> list[str]:
    r.write(SNAP, "a\n")
    r.commit("test: update\n\nno trailer here")
    return [SNAP]


def _case_empty_reason(r: _Repo) -> list[str]:
    r.write(SNAP, "a\n")
    r.commit(f"test: update\n\n{TRAILER_KEY}:\nSigned-off-by: a <a@b.c>")
    return [SNAP]


def _case_placeholder_reason(r: _Repo) -> list[str]:
    r.write(SNAP, "a\n")
    r.commit(f"test: update\n\n{TRAILER_KEY}: <why the output changed>")
    return [SNAP]


def _case_trailer_on_other_commit(r: _Repo) -> list[str]:
    r.write(SNAP, "a\n")
    r.commit("test: update")
    r.commit(f"chore: explain\n\n{GOOD}", allow_empty=True)
    return [SNAP]


def _case_trailer_mid_prose(r: _Repo) -> list[str]:
    # Not the last paragraph, so not a trailer -- the reason a regex is not used.
    r.write(SNAP, "a\n")
    r.commit(f"test: update\n\n{GOOD}\n\nand then more prose.")
    return [SNAP]


def _case_non_golden(r: _Repo) -> list[str]:
    r.write("automated_security_helper/core.py", "x = 1\n")
    r.write("tests/snapshot/test_cli.py", "def test(): pass\n")
    r.commit("feat: no golden file")
    return []


def _case_squash_message(r: _Repo) -> list[str]:
    r.write(SNAP, "a\n")
    r.write(".github/actions/validate-mcp/tool_surface.golden.json", "{}\n")
    r.commit(
        "feat(cli): new summary (#123)\n\n"
        "* feat(cli): add the column\n\n"
        f"Renders the new field.\n\n{GOOD}\n\n"
        "* fix: typo\n\n"
        "* chore: lint\n\n"
        "Co-authored-by: someone <s@example.invalid>"
    )
    return []


def _case_squash_without_trailer(r: _Repo) -> list[str]:
    r.write(SNAP, "a\n")
    r.commit("feat: x (#1)\n\n* feat: x\n\nbody\n\n* fix: y\n\nmore")
    return [SNAP]


def _case_deleted_golden(r: _Repo) -> list[str]:
    (r.path / SNAP).unlink()
    r.commit("test: drop snapshot")
    return [SNAP]


def _case_renamed_golden(r: _Repo) -> list[str]:
    new = "tests/snapshot/__snapshots__/test_cli_renamed.ambr"
    r._git("mv", SNAP, new)
    r.commit("test: rename module")
    return sorted([SNAP, new])


def _case_renamed_golden_with_trailer(r: _Repo) -> list[str]:
    r._git("mv", SNAP, "tests/snapshot/__snapshots__/test_x.ambr")
    r.commit(f"test: rename\n\n{GOOD}")
    return []


def _case_schema_and_generated_doc(r: _Repo) -> list[str]:
    r.write("automated_security_helper/schemas/AshConfig.json", "{}\n")
    r.write("docs/content/docs/cli-reference-generated.md", "x\n")
    r.write("docs/content/docs/cli-reference.md", "hand-written\n")
    r.commit("docs: regenerate")
    return sorted(
        [
            "automated_security_helper/schemas/AshConfig.json",
            "docs/content/docs/cli-reference-generated.md",
        ]
    )


_CASES = {
    "trailer present -> pass": (_case_trailer_present, False),
    "trailer missing -> fail": (_case_trailer_missing, False),
    "empty reason -> fail": (_case_empty_reason, False),
    "placeholder reason -> fail": (_case_placeholder_reason, False),
    "trailer on a different commit -> fail": (_case_trailer_on_other_commit, False),
    "trailer-looking line mid-prose -> fail": (_case_trailer_mid_prose, False),
    "non-golden change -> pass": (_case_non_golden, False),
    "squash-style message -> pass": (_case_squash_message, False),
    "squash-style message, no trailer -> fail": (_case_squash_without_trailer, False),
    "deleted golden -> requires trailer": (_case_deleted_golden, True),
    "renamed golden -> requires trailer": (_case_renamed_golden, True),
    "renamed golden with trailer -> pass": (_case_renamed_golden_with_trailer, True),
    "schema + generated doc -> fail, hand doc ignored": (
        _case_schema_and_generated_doc,
        False,
    ),
}


def _self_test_ranges(tmp: Path) -> list[str]:
    failures = []
    r = _Repo(tmp / "ranges")
    first = r.base
    r.write("a.txt", "a\n")
    second = r.commit("chore: second")
    got = resolve_range(r.path, "push", {"before": ZERO_SHA, "after": second})
    if not (got and got.base is None and got.head == second):
        failures.append(f"push from all-zero before: got {got}")
    got = resolve_range(r.path, "push", {"before": first, "after": second})
    if not (got and got.base == first):
        failures.append(f"push before..after: got {got}")
    got = resolve_range(r.path, "push", {"before": "1" * 40, "after": second})
    if not (got and got.base is None):
        failures.append(f"push with a vanished before: got {got}")
    if resolve_range(r.path, "push", {"before": first, "after": ZERO_SHA}) is not None:
        failures.append("deleted ref should introduce nothing")
    pr = {"pull_request": {"base": {"sha": first}, "head": {"sha": second}}}
    got = resolve_range(r.path, "pull_request", pr)
    if not (got and (got.base, got.head) == (first, second)):
        failures.append(f"pull_request: got {got}")
    mg = {"merge_group": {"base_sha": first, "head_sha": second}}
    got = resolve_range(r.path, "merge_group", mg)
    if not (got and (got.base, got.head) == (first, second)):
        failures.append(f"merge_group: got {got}")
    return failures


def _self_test_orphans(tmp: Path) -> list[str]:
    root = tmp / "orphans"
    snaps = root / "tests/snapshot/__snapshots__"
    (snaps / "test_alive").mkdir(parents=True)
    (snaps / "test_alive/case.md").write_text("x")
    (snaps / "test_alive.ambr").write_text("x")
    (root / "tests/snapshot/test_alive.py").write_text("")
    clean = find_orphans(root)
    (snaps / "test_gone.ambr").write_text("x")
    (snaps / "test_gone_dir").mkdir()
    (snaps / "test_gone_dir/case.md").write_text("x")
    (snaps / "test_empty").mkdir()
    (snaps / "stray.txt").write_text("x")
    (root / "tests/unit/__snapshots__").mkdir(parents=True)
    dirty = "\n".join(find_orphans(root))
    failures = [f"clean tree reported: {clean}"] if clean else []
    for expected in (
        "test_gone.ambr",
        "test_gone_dir",
        "test_empty/ is empty",
        "stray.txt",
        "tests/unit/__snapshots__/ is empty",
    ):
        if expected not in dirty:
            failures.append(f"orphan check missed {expected!r}:\n{dirty}")
    return failures


def self_test() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="snapshot-trailers-") as tmpdir:
        tmp = Path(tmpdir)
        for i, (name, (case, seed)) in enumerate(_CASES.items()):
            r = _Repo(tmp / f"case{i}")
            if seed:  # cases that delete or rename need the file to exist at base
                r.write(SNAP, "seed\n")
                r.base = r.commit(f"test: seed\n\n{GOOD}")
            expected = case(r)
            got = sorted(r.violations())
            if got != expected:
                failures.append(f"{name}: expected violations {expected}, got {got}")
        failures += _self_test_ranges(tmp)
        failures += _self_test_orphans(tmp)
    if not golden_reason("tests/snapshot/__snapshots__/test_a/b.md"):
        failures.append("nested single-file snapshot not golden")
    if golden_reason("automated_security_helper/schemas/sub/x.json"):
        failures.append("schemas glob crossed a directory")
    for f in failures:
        print(f"::error::self-test: {f}")
    print(
        f"self-test: {len(_CASES)} trailer cases plus range and orphan cases, "
        f"{len(failures)} failure(s)"
    )
    return 1 if failures else 0


# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--orphans", action="store_true", help="check snapshot ownership"
    )
    parser.add_argument("--base", help="check BASE..HEAD instead of the event's range")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    opts = parser.parse_args(argv)

    if opts.self_test:
        return self_test()
    if opts.orphans:
        problems = find_orphans(opts.repo)
        for p in problems:
            print(f"::error::orphaned snapshot: {p}")
        print(f"orphan check: {len(problems)} problem(s)")
        return 1 if problems else 0
    try:
        if opts.base:
            rng = Range(opts.base, opts.head, f"{opts.base}..{opts.head}")
        else:
            event_name = os.environ.get("GITHUB_EVENT_NAME")
            event_path = os.environ.get("GITHUB_EVENT_PATH")
            if not event_name or not event_path:
                parser.error("outside Actions, pass --base (e.g. --base origin/main)")
            payload = json.loads(Path(event_path).read_text(encoding="utf-8"))
            rng = resolve_range(opts.repo, event_name, payload)
            if rng is None:
                print(
                    f"{event_name}: the event introduces no commits; nothing to check."
                )
                return 0
        return run_check(opts.repo, rng)
    except GitError as exc:
        print(f"::error::{exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
