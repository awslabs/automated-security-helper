#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fails when an editor snapshot changes without a ``Snapshot-Update:`` trailer saying why.

WHY THIS EXISTS
---------------
The editor plugins under editors/ have snapshot suites of their own: text snapshots of
what a plugin shows a user and PNG baselines of how it looks. For the VS Code extension
those are jest ``.snap`` files and the visual suite's PNGs (editors/vscode/test/visual/
README.md); for the JetBrains plugin, the text snapshots under
src/test/snapshots/__snapshots__ and the PNGs (plus the environment text the visual suite
pins) under src/uiTest/snapshots/__snapshots__ (editors/jetbrains/README.jetbrains). Each
suite fails when its output changes, and each has an update flag that rewrites the
snapshots and makes it pass again. That rewrite is one command and produces a diff nobody
has to read, so on its own a snapshot suite only proves that someone ran the command.
What makes a changed snapshot a decision is a sentence, attached to the commit that
changed it, saying why the output is now different. This script requires that sentence:
every commit in the range that touches an editor snapshot must carry
``Snapshot-Update: <non-empty reason>`` as a git trailer.

The rule is per commit, not per pull request or per path. A follow-up commit that only
adds the trailer (an empty commit, or one touching some other file) does not satisfy it,
because then the reason is not attached to the change it explains, and after a rebase or
a cherry-pick the two travel separately. A second, unexplained change to a snapshot an
earlier commit explained fails too. The error message prints the exact command that
amends the right commits.

One script serves both editors. The VS Code and JetBrains branches each added a copy of
this file; they were merged into this one, which keeps the VS Code copy's per-commit rule
and ownership check and the JetBrains copy's ``--golden-root`` and ``--policy``.

RELATION TO check-snapshot-trailers.py (core ASH's snapshot suite)
------------------------------------------------------------------
Core ASH's snapshot pull request adds .github/scripts/check-snapshot-trailers.py for its
own golden files. This script is that script's logic with two things swapped: which files
are golden (the editor snapshot trees, see below) and the orphan check
(``find_editor_orphans`` in place of core's ``find_orphans`` for syrupy). The trailer key,
its placeholder rule, the ``git interpret-trailers --parse`` reading, the per-section
parse of squash bodies, the event-to-range rules and the fix instructions are the same
code, so a commit that satisfies this script satisfies that one.

That is what lets the core script absorb this one. Core's golden set already treats any
path with a ``__snapshots__`` directory component as golden, and every editor snapshot,
PNG baselines included, lives under one, so core's trailer check covers these paths as it
stands. Absorbing then takes these edits there: call ``find_editor_orphans`` from
``--orphans``, take ``find_update_flags`` for ``--policy``, take the per-commit rule in
``find_violations``, and make sure the jobs that run it trigger on ``editors/**``. This
file is then deleted. The per-commit rule is the stricter one: core accepts a path once
any commit in the range that touched it carries a trailer. When core absorbs this script
it should take the stricter rule, or the editor paths lose it.

WHAT COUNTS AS GOLDEN
---------------------
Any file with a ``__snapshots__`` directory component under one of the ``--golden-root``
directories (default: ``editors``, so both editors' trees). The roots are a parameter so
each editor's CI job can scope the check to its own tree. Every such file is written only
by an update flag and never edited by hand, so a change to one is always a change in what
an editor shows.

ORPHANED SNAPSHOTS
------------------
``--orphans`` checks the VS Code extension's snapshot ownership statically.
``jest --ci`` fails a run that leaves a snapshot unchecked or a snapshot file obsolete
(measured: exit 1 for both), but only for files under its ``roots``, and the visual suite
fails a baseline it did not compare, but only when it runs. So: every ``X.snap`` must sit
in a ``__snapshots__`` directory beside a test file ``X``, and every PNG must be named in
the ``scenarios.json`` beside its ``__snapshots__`` directory, which must in turn have a
PNG for each name. The JetBrains plugin's snapshots are named after test classes and
cases rather than files, so its suite records every snapshot it compares and fails on a
file nothing compared (editors/jetbrains/assert-snapshots-used.py) instead; it is not in
``EDITOR_ROOTS``.

POLICY
------
``--policy`` fails when a workflow under .github/workflows passes an editor's snapshot
update flag (``-Psnapshot-update``, ``ASH_SNAPSHOT_UPDATE=1``, ``--snapshot-update`` or
jest's ``--updateSnapshot``). The suites also refuse their flag when CI or GITHUB_ACTIONS
is "true", so this is the second of two locks: CI only ever compares.

HOW THE RANGE IS CHOSEN (one per event; see ``resolve_range``)
-------------------------------------------------------------
* pull_request: ``<fork point>..pull_request.head.sha``. The head sha, not GITHUB_SHA,
  because GITHUB_SHA is GitHub's synthetic merge commit, whose message carries no
  trailers. The fork point is ``git merge-base`` of the head with the base branch, not
  ``pull_request.base.sha`` itself: that sha is recorded when the event fires and can
  be older than base-branch commits the pull request has since merged in (a
  ``synchronize`` after merging main, a re-run of an old event). Used directly, every
  such main commit would land in the range and be charged to the pull request. So the
  merge base is taken against both ``base.sha`` and the clone's
  ``origin/<base.ref>``, and the later of the two starts the range.
* merge_group: ``merge-base(base_sha, head_sha)..head_sha``. The queue builds the head
  on the base, so the merge base is normally ``base_sha`` itself; computing it means a
  queue entry whose base moved is still checked from where it forked. The queue
  squashes, so each commit here is one pull request's squash commit. See
  ``message_sections`` for why its message is parsed per section.
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
    python3 .github/scripts/check-editor-snapshot-trailers.py --self-test
    python3 .github/scripts/check-editor-snapshot-trailers.py              # range from the event
    python3 .github/scripts/check-editor-snapshot-trailers.py --base origin/main --head HEAD
    python3 .github/scripts/check-editor-snapshot-trailers.py --golden-root editors/jetbrains
    python3 .github/scripts/check-editor-snapshot-trailers.py --orphans
    python3 .github/scripts/check-editor-snapshot-trailers.py --policy

Standard library only, like the other gate scripts, so the job installs nothing.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

TRAILER_KEY = "Snapshot-Update"
ZERO_SHA = "0" * 40

# ---------------------------------------------------------------------------
# THE GOLDEN SET
#
# A file is golden when it sits under one of GOLDEN_ROOTS and has a `__snapshots__`
# directory component. Every such file is written only by an editor suite's update flag, so a
# change to one is always a change in what the plugin shows, never a hand edit. The roots are
# a parameter so one script serves both editors and the caller can scope a job to one tree.
# ---------------------------------------------------------------------------
DEFAULT_GOLDEN_ROOTS: tuple[str, ...] = ("editors",)
GOLDEN_ROOTS: list[str] = list(DEFAULT_GOLDEN_ROOTS)

# What passes an editor snapshot suite's update flag. Matched in workflow files only.
UPDATE_FLAGS = re.compile(
    r"-Psnapshot-update|ASH_SNAPSHOT_UPDATE\s*[:=]\s*['\"]?1|--snapshot-update|--updateSnapshot"
)


def golden_reason(path: str) -> str | None:
    """Return why ``path`` is golden, or None when it is not."""
    posix = PurePosixPath(path)
    if "__snapshots__" not in posix.parts[:-1]:
        return None
    for root in GOLDEN_ROOTS:
        root_parts = PurePosixPath(root).parts
        if posix.parts[: len(root_parts)] == root_parts:
            kind = "image snapshot" if posix.suffix == ".png" else "text snapshot"
            return f"editor {kind}"
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
    """Each golden path, with the commits that changed it and carry no reason.

    Every commit that touches the path needs its own trailer. Core's script accepts
    a path once ANY commit in the range that touched it has one, so a second,
    unexplained change to a snapshot an earlier commit explained passes there. This
    is the stricter rule; see the module docstring.
    """
    touched: dict[str, list[Commit]] = {}
    for commit in commits:
        for path in commit.files:
            if golden_reason(path):
                touched.setdefault(path, []).append(commit)
    reasons = {c.sha: snapshot_reasons(repo, c.message) for c in commits}
    violations = []
    for path, touching in sorted(touched.items()):
        unexplained = [c for c in touching if not reasons[c.sha]]
        if unexplained:
            violations.append(Violation(path, golden_reason(path) or "", unexplained))
    return violations


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


def is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", ancestor, descendant],
        capture_output=True,
    )
    return proc.returncode == 0


def fork_point(repo: Path, bases: list[str], head: str) -> str:
    """The latest ``git merge-base <base> <head>`` over ``bases`` that are present.

    Each candidate base yields the newest commit of that base the head contains; the
    latest of those (the one every other is an ancestor of) excludes the most
    base-branch history, which is all history the head did not introduce.
    """
    best: str | None = None
    for base in bases:
        if not commit_exists(repo, base):
            continue
        merge_base = git(repo, "merge-base", base, head, check=False).strip()
        if not merge_base:
            continue  # unrelated histories: this base says nothing about the head
        if best is None or is_ancestor(repo, best, merge_base):
            best = merge_base
    if best is None:
        raise GitError(
            f"no merge base between {head} and any of {bases}; "
            f"check out with fetch-depth: 0"
        )
    return best


def _base_branch_tip(repo: Path, ref: str | None) -> list[str]:
    """``origin/<ref>`` if the clone has it (fetched once if not), else nothing."""
    if not ref:
        return []
    remote = f"refs/remotes/origin/{ref}"
    if not commit_exists(repo, remote):
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "fetch",
                "--no-tags",
                "--quiet",
                "origin",
                f"+refs/heads/{ref}:{remote}",
            ],
            capture_output=True,
        )
    return [remote] if commit_exists(repo, remote) else []


def resolve_range(repo: Path, event_name: str, payload: dict[str, Any]) -> Range | None:
    """The commits an event introduces, or None when there are none to check."""
    if event_name in ("pull_request", "pull_request_target"):
        pr = payload["pull_request"]
        head = pr["head"]["sha"]
        if not ensure_commit(repo, head):
            raise GitError(f"{head} is not in the clone; check out with fetch-depth: 0")
        ensure_commit(repo, pr["base"]["sha"])
        bases = [pr["base"]["sha"], *_base_branch_tip(repo, pr["base"].get("ref"))]
        return Range(fork_point(repo, bases, head), head, "pull request")
    if event_name == "merge_group":
        mg = payload["merge_group"]
        head = mg["head_sha"]
        for sha in (mg["base_sha"], head):
            if not ensure_commit(repo, sha):
                raise GitError(
                    f"{sha} is not in the clone; check out with fetch-depth: 0"
                )
        return Range(
            fork_point(repo, [mg["base_sha"]], head), head, "merge queue entry"
        )
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


# The editor package roots whose snapshot ownership is checked here. A new editor plugin
# with snapshots in this ownership shape adds its root. editors/jetbrains is not listed:
# its snapshots are named after test classes, and its suite checks their use itself
# (editors/jetbrains/assert-snapshots-used.py).
EDITOR_ROOTS: tuple[str, ...] = ("editors/vscode",)


def _visual_scenario_names(scenarios: Path) -> tuple[list[str], str | None]:
    """The scenario names a ``scenarios.json`` lists, or a problem reading it."""
    try:
        data = json.loads(scenarios.read_text(encoding="utf-8"))
        names = [entry["name"] for entry in data["scenarios"]]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return [], f"cannot read scenario names: {exc}"
    if not all(isinstance(n, str) and n for n in names):
        return [], "every scenario needs a non-empty string name"
    return names, None


def find_editor_orphans(root: Path) -> list[str]:
    """Snapshot files under the editor roots that no test owns.

    Under each ``__snapshots__`` directory (skipping node_modules and build output):

    * ``X.snap`` belongs to the test file ``X`` beside the directory (jest's layout).
    * ``X.png`` belongs to the scenario ``X`` in the ``scenarios.json`` beside the
      directory, and each scenario there must have its PNG.
    * Anything else, and an empty directory, is a problem: nothing can own it.
    """
    problems = []
    for editor in EDITOR_ROOTS:
        base = root / editor
        if not base.is_dir():
            problems.append(f"{editor}/ does not exist; update EDITOR_ROOTS")
            continue
        for snapdir in sorted(base.rglob("__snapshots__")):
            rel_parts = snapdir.relative_to(root).parts
            if not snapdir.is_dir() or {"node_modules", "out", "out-integration"} & set(
                rel_parts
            ):
                continue
            rel = snapdir.relative_to(root).as_posix()
            entries = sorted(snapdir.iterdir())
            if not entries:
                problems.append(f"{rel}/ is empty; delete it")
            pngs = []
            for entry in entries:
                if entry.is_file() and entry.suffix == ".snap":
                    owner = snapdir.parent / entry.stem
                    if not owner.is_file():
                        problems.append(
                            f"{rel}/{entry.name} belongs to {entry.stem}, which does not "
                            f"exist next to {rel}/. Delete the snapshot, or move it with "
                            f"its test."
                        )
                elif entry.is_file() and entry.suffix == ".png":
                    pngs.append(entry.stem)
                else:
                    problems.append(
                        f"{rel}/{entry.name} is neither <test file>.snap nor a "
                        f"<scenario>.png, so no test can own it"
                    )
            scenarios = snapdir.parent / "scenarios.json"
            if pngs or scenarios.is_file():
                names, error = _visual_scenario_names(scenarios)
                if error:
                    problems.append(
                        f"{rel}/ holds PNG baselines but "
                        f"{scenarios.relative_to(root).as_posix()}: {error}"
                    )
                    continue
                for stem in sorted(set(pngs) - set(names)):
                    problems.append(
                        f"{rel}/{stem}.png names no scenario in scenarios.json. Delete "
                        f"it, or add the scenario back."
                    )
                for name in sorted(set(names) - set(pngs)):
                    problems.append(
                        f"scenario {name!r} has no baseline {rel}/{name}.png. Write it "
                        f"with the update flag (editors/vscode/test/visual/README.md)."
                    )
    return problems


# ---------------------------------------------------------------------------
# Policy: no workflow passes an update flag
# ---------------------------------------------------------------------------


def find_update_flags(root: Path) -> list[str]:
    """Lines in .github/workflows that pass an editor snapshot update flag."""
    hits = []
    workflows = sorted((root / ".github/workflows").glob("*.y*ml"))
    for wf in workflows:
        for number, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if UPDATE_FLAGS.search(line):
                hits.append(
                    f"{wf.relative_to(root).as_posix()}:{number}: {line.strip()}"
                )
    return hits


# ---------------------------------------------------------------------------
# Self-test
#
# Runs first in CI for the same reason as assert-publish-surfaces.py's: a checker whose
# failure mode is "found nothing, exit 0" reads as a clean tree. Every case below runs
# through the same functions the real check uses.
# ---------------------------------------------------------------------------

GOOD = f"{TRAILER_KEY}: the incomplete-scan warning names the scanner"


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


@dataclass(frozen=True)
class _Fixture:
    """One editor's paths for the trailer cases, which run once per editor."""

    snap: str  # a text snapshot
    png: str  # a PNG baseline
    renamed: str  # where the rename cases move ``snap``
    source: str  # a non-golden file in the same editor
    other_png: str  # the other editor's PNG baseline


_VSCODE = _Fixture(
    snap="editors/vscode/test/__snapshots__/ui-snapshots.test.ts.snap",
    png="editors/vscode/test/visual/__snapshots__/problems-panel.png",
    renamed="editors/vscode/test/__snapshots__/ui-renamed.test.ts.snap",
    source="editors/vscode/test/visual/run.ts",
    other_png="editors/jetbrains/src/uiTest/snapshots/__snapshots__/VisualSnapshotTest/settings-page.png",
)
_JETBRAINS = _Fixture(
    snap="editors/jetbrains/src/test/snapshots/__snapshots__/NotificationSnapshotTest/clean.txt",
    png="editors/jetbrains/src/uiTest/snapshots/__snapshots__/VisualSnapshotTest/settings-page.png",
    renamed="editors/jetbrains/src/test/snapshots/__snapshots__/NotificationSnapshotTest/clean-renamed.txt",
    source="editors/jetbrains/src/uiTest/kotlin/A.kt",
    other_png="editors/vscode/test/visual/__snapshots__/problems-panel.png",
)
_FIXTURES = {"vscode": _VSCODE, "jetbrains": _JETBRAINS}


def _case_trailer_present(r: _Repo, f: _Fixture) -> list[str]:
    r.write(f.snap, "a\n")
    r.commit(f"test: update\n\nbody\n\n{GOOD}")
    return []


def _case_trailer_missing(r: _Repo, f: _Fixture) -> list[str]:
    r.write(f.snap, "a\n")
    r.commit("test: update\n\nno trailer here")
    return [f.snap]


def _case_empty_reason(r: _Repo, f: _Fixture) -> list[str]:
    r.write(f.snap, "a\n")
    r.commit(f"test: update\n\n{TRAILER_KEY}:\nSigned-off-by: a <a@b.c>")
    return [f.snap]


def _case_placeholder_reason(r: _Repo, f: _Fixture) -> list[str]:
    r.write(f.snap, "a\n")
    r.commit(f"test: update\n\n{TRAILER_KEY}: <why the output changed>")
    return [f.snap]


def _case_trailer_on_other_commit(r: _Repo, f: _Fixture) -> list[str]:
    r.write(f.snap, "a\n")
    r.commit("test: update")
    r.commit(f"chore: explain\n\n{GOOD}", allow_empty=True)
    return [f.snap]


def _case_second_change_untrailered(r: _Repo, f: _Fixture) -> list[str]:
    # The first change is explained; the second, to the same file, is not.
    r.write(f.snap, "a\n")
    r.commit(f"test: update\n\n{GOOD}")
    r.write(f.snap, "b\n")
    r.commit("test: change it again")
    return [f.snap]


def _case_trailer_mid_prose(r: _Repo, f: _Fixture) -> list[str]:
    # Not the last paragraph, so not a trailer -- the reason a regex is not used.
    r.write(f.snap, "a\n")
    r.commit(f"test: update\n\n{GOOD}\n\nand then more prose.")
    return [f.snap]


def _case_non_golden(r: _Repo, f: _Fixture) -> list[str]:
    r.write(f.source, "x\n")
    r.write("editors/vscode/src/extension.ts", "export {};\n")
    r.write("editors/vscode/test/ui-snapshots.test.ts", "test('x', () => {});\n")
    r.write("editors/jetbrains/src/main/kotlin/A.kt", "class A\n")
    r.write(
        "editors/jetbrains/src/test/snapshots/README.txt", "not under __snapshots__\n"
    )
    r.write("automated_security_helper/core.py", "x = 1\n")
    # core ASH's own snapshots: golden for its script, not for this one.
    r.write("tests/snapshot/__snapshots__/test_cli.ambr", "x\n")
    r.commit("feat: no editor golden file")
    return []


def _case_squash_message(r: _Repo, f: _Fixture) -> list[str]:
    r.write(f.snap, "a\n")
    r.write(f.png, "png\n")
    r.commit(
        "feat(cli): new summary (#123)\n\n"
        "* feat(cli): add the column\n\n"
        f"Renders the new field.\n\n{GOOD}\n\n"
        "* fix: typo\n\n"
        "* chore: lint\n\n"
        "Co-authored-by: someone <s@example.invalid>"
    )
    return []


def _case_squash_without_trailer(r: _Repo, f: _Fixture) -> list[str]:
    r.write(f.snap, "a\n")
    r.commit("feat: x (#1)\n\n* feat: x\n\nbody\n\n* fix: y\n\nmore")
    return [f.snap]


def _case_deleted_golden(r: _Repo, f: _Fixture) -> list[str]:
    (r.path / f.snap).unlink()
    r.commit("test: drop snapshot")
    return [f.snap]


def _case_renamed_golden(r: _Repo, f: _Fixture) -> list[str]:
    r._git("mv", f.snap, f.renamed)
    r.commit("test: rename module")
    return sorted([f.snap, f.renamed])


def _case_renamed_golden_with_trailer(r: _Repo, f: _Fixture) -> list[str]:
    r._git("mv", f.snap, f.renamed)
    r.commit(f"test: rename\n\n{GOOD}")
    return []


def _case_png_baseline(r: _Repo, f: _Fixture) -> list[str]:
    r.write(f.png, "png\n")
    r.write(f.source, "x\n")
    r.commit("test: new picture")
    return [f.png]


def _case_png_with_trailer(r: _Repo, f: _Fixture) -> list[str]:
    r.write(f.png, "png\n")
    r.commit(f"test: new picture\n\n{GOOD}")
    return []


def _case_png_and_other_editor(r: _Repo, f: _Fixture) -> list[str]:
    # The default roots cover both editors, so one commit is charged for both.
    r.write(f.png, "png\n")
    r.write(f.other_png, "png\n")
    r.commit("test: new baselines")
    return sorted([f.png, f.other_png])


_CASES = {
    "trailer present -> pass": (_case_trailer_present, False),
    "trailer missing -> fail": (_case_trailer_missing, False),
    "empty reason -> fail": (_case_empty_reason, False),
    "placeholder reason -> fail": (_case_placeholder_reason, False),
    "trailer on a different commit -> fail": (_case_trailer_on_other_commit, False),
    "second, untrailered change to an explained file -> fail": (
        _case_second_change_untrailered,
        False,
    ),
    "trailer-looking line mid-prose -> fail": (_case_trailer_mid_prose, False),
    "non-golden change -> pass": (_case_non_golden, False),
    "squash-style message -> pass": (_case_squash_message, False),
    "squash-style message, no trailer -> fail": (_case_squash_without_trailer, False),
    "deleted golden -> requires trailer": (_case_deleted_golden, True),
    "renamed golden -> requires trailer": (_case_renamed_golden, True),
    "renamed golden with trailer -> pass": (_case_renamed_golden_with_trailer, True),
    "PNG baseline without trailer -> fail": (_case_png_baseline, False),
    "PNG baseline with trailer -> pass": (_case_png_with_trailer, False),
    "png baseline and another editor's snapshot -> fail": (
        _case_png_and_other_editor,
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
    failures += _self_test_stale_base(tmp)
    return failures


def _self_test_stale_base(tmp: Path) -> list[str]:
    """A pull request that merged main after its event recorded ``base.sha``.

    main: B -- M1 -- M2 (M2 changes a snapshot without a trailer, which is main's
    business, not the pull request's). The branch forks at B, commits F1, merges M2,
    then commits F2. The event still says ``base.sha = M1``, so ``M1..F2`` would
    include M2 and blame the pull request for it.
    """
    failures = []
    r = _Repo(tmp / "stale-base")
    fork = r.base
    r.write("main.txt", "1\n")
    m1 = r.commit("chore: m1")
    r.write(_VSCODE.snap, "from main\n")
    m2 = r.commit("test: main changed a snapshot")
    r._git("checkout", "-q", "-b", "feature", fork)
    r.write("feature.txt", "1\n")
    r.commit("feat: f1")
    r._git("merge", "-q", "--no-edit", m2)
    r.write("feature.txt", "2\n")
    f2 = r.commit("feat: f2")
    # The clone's view of the base branch, as actions/checkout leaves it.
    r._git("update-ref", "refs/remotes/origin/main", m2)
    pr = {
        "pull_request": {
            "base": {"sha": m1, "ref": "main"},
            "head": {"sha": f2},
        }
    }
    got = resolve_range(r.path, "pull_request", pr)
    if not (got and got.base == m2 and got.head == f2):
        failures.append(f"stale base.sha: expected range {m2}..{f2}, got {got}")
    elif find_violations(r.path, commits_in_range(r.path, got.base, got.head)):
        failures.append(
            "stale base.sha: main's own snapshot commit was charged to the PR"
        )
    # The pitfall itself, so the case keeps proving something: M1..F2 includes M2.
    if not find_violations(r.path, commits_in_range(r.path, m1, f2)):
        failures.append("stale base.sha: M1..F2 should have included main's M2")
    # Without origin/main in the clone, the merge base with base.sha alone is used.
    r._git("update-ref", "-d", "refs/remotes/origin/main")
    got = resolve_range(r.path, "pull_request", pr)
    if not (got and got.base == m1):
        failures.append(f"no origin ref: expected base {m1}, got {got}")
    # A base.sha newer than the fork point (main moved on, the PR did not merge it)
    # starts the range at the fork point, not at a commit the head does not contain.
    r._git("checkout", "-q", "main")
    r.write("main.txt", "3\n")
    m3 = r.commit("chore: m3")
    pr["pull_request"]["base"]["sha"] = m3
    got = resolve_range(r.path, "pull_request", pr)
    if not (got and got.base == m2):
        failures.append(f"base moved on: expected fork point {m2}, got {got}")
    mg = {"merge_group": {"base_sha": m3, "head_sha": f2}}
    got = resolve_range(r.path, "merge_group", mg)
    if not (got and got.base == m2):
        failures.append(f"merge_group with a moved base: expected {m2}, got {got}")
    return failures


def _self_test_orphans(tmp: Path) -> list[str]:
    root = tmp / "orphans"
    test = root / "editors/vscode/test"
    (test / "__snapshots__").mkdir(parents=True)
    (test / "ui.test.ts").write_text("")
    (test / "__snapshots__/ui.test.ts.snap").write_text("x")
    visual = test / "visual"
    (visual / "__snapshots__").mkdir(parents=True)
    (visual / "scenarios.json").write_text(
        json.dumps({"scenarios": [{"name": "panel"}, {"name": "hover"}]})
    )
    (visual / "__snapshots__/panel.png").write_text("x")
    (visual / "__snapshots__/hover.png").write_text("x")
    # Build output is not checked: it is not committed.
    (root / "editors/vscode/out/__snapshots__").mkdir(parents=True)
    clean = find_editor_orphans(root)
    (test / "__snapshots__/gone.test.ts.snap").write_text("x")
    (test / "__snapshots__/stray.txt").write_text("x")
    (visual / "__snapshots__/old.png").write_text("x")
    (visual / "__snapshots__/hover.png").unlink()
    (test / "empty/__snapshots__").mkdir(parents=True)
    dirty = "\n".join(find_editor_orphans(root))
    failures = [f"clean tree reported: {clean}"] if clean else []
    for expected in (
        "gone.test.ts.snap belongs to gone.test.ts",
        "stray.txt is neither",
        "old.png names no scenario",
        "scenario 'hover' has no baseline",
        "editors/vscode/test/empty/__snapshots__/ is empty",
    ):
        if expected not in dirty:
            failures.append(f"orphan check missed {expected!r}:\n{dirty}")
    (visual / "scenarios.json").write_text("{not json")
    if "cannot read scenario names" not in "\n".join(find_editor_orphans(root)):
        failures.append("an unreadable scenarios.json was not reported")
    return failures


def _self_test_policy(tmp: Path) -> list[str]:
    root = tmp / "policy"
    wf = root / ".github/workflows"
    wf.mkdir(parents=True)
    (wf / "clean.yml").write_text(
        "# -Psnapshot-update is never passed here\n"
        "run: ./gradlew uiTest\n"
        "run: npm run snapshots -- structural\n"
    )
    failures = [f"clean workflow reported: {h}" for h in find_update_flags(root)]
    (wf / "bad.yml").write_text(
        "run: ./gradlew test -Psnapshot-update\n"
        "env:\n  ASH_SNAPSHOT_UPDATE: '1'\n"
        "run: pytest --snapshot-update\n"
        "run: npx jest --updateSnapshot\n"
    )
    hits = find_update_flags(root)
    if len(hits) != 4:
        failures.append(f"policy expected 4 hits, got {hits}")
    return failures


def _self_test_roots() -> list[str]:
    failures = []
    if not golden_reason(_VSCODE.png):
        failures.append("a VS Code PNG baseline is not golden")
    if not golden_reason(
        "editors/jetbrains/src/uiTest/snapshots/__snapshots__/A/b.png"
    ):
        failures.append("a JetBrains PNG baseline is not golden")
    if golden_reason("editors/jetbrains/src/test/snapshots/x.txt"):
        failures.append("a file outside __snapshots__ is golden")
    if golden_reason("editors/vscode/test/__snapshots__"):
        failures.append("a bare __snapshots__ path (no file below it) read as golden")
    if golden_reason("tests/snapshot/__snapshots__/test_cli.ambr"):
        failures.append("core ASH's snapshot is golden for the editor check")
    saved = list(GOLDEN_ROOTS)
    GOLDEN_ROOTS[:] = ["editors/jetbrains"]
    try:
        if golden_reason("editors/vscode/__snapshots__/a.png"):
            failures.append(
                "--golden-root editors/jetbrains still covers editors/vscode"
            )
        if not golden_reason("editors/jetbrains/__snapshots__/a.txt"):
            failures.append("--golden-root editors/jetbrains no longer covers itself")
    finally:
        GOLDEN_ROOTS[:] = saved
    return failures


def self_test() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="editor-snapshot-trailers-") as tmpdir:
        tmp = Path(tmpdir)
        for editor, fixture in _FIXTURES.items():
            for i, (name, (case, seed)) in enumerate(_CASES.items()):
                r = _Repo(tmp / f"{editor}-case{i}")
                if seed:  # cases that delete or rename need the file to exist at base
                    r.write(fixture.snap, "seed\n")
                    r.base = r.commit(f"test: seed\n\n{GOOD}")
                expected = case(r, fixture)
                got = sorted(r.violations())
                if got != expected:
                    failures.append(
                        f"{editor}: {name}: expected violations {expected}, got {got}"
                    )
        failures += _self_test_ranges(tmp)
        failures += _self_test_orphans(tmp)
        failures += _self_test_policy(tmp)
    failures += _self_test_roots()
    for f in failures:
        print(f"::error::self-test: {f}")
    print(
        f"self-test: {len(_CASES)} trailer cases for each of {len(_FIXTURES)} editors "
        f"plus range, orphan, policy and root cases, {len(failures)} failure(s)"
    )
    return 1 if failures else 0


# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--orphans", action="store_true", help="check snapshot ownership"
    )
    parser.add_argument(
        "--policy",
        action="store_true",
        help="fail on a workflow that passes an editor snapshot update flag",
    )
    parser.add_argument(
        "--golden-root",
        action="append",
        help="a directory whose __snapshots__ trees are golden (repeatable; default: editors)",
    )
    parser.add_argument("--base", help="check BASE..HEAD instead of the event's range")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    opts = parser.parse_args(argv)
    if opts.golden_root:
        GOLDEN_ROOTS[:] = [r.strip("/") for r in opts.golden_root]

    if opts.self_test:
        return self_test()
    if opts.orphans:
        problems = find_editor_orphans(opts.repo)
        for p in problems:
            print(f"::error::orphaned snapshot: {p}")
        print(f"orphan check: {len(problems)} problem(s)")
        return 1 if problems else 0
    if opts.policy:
        hits = find_update_flags(opts.repo)
        for hit in hits:
            print(f"::error::a workflow passes a snapshot update flag: {hit}")
        print(f"update-flag policy: {len(hits)} workflow line(s) pass an update flag")
        return 1 if hits else 0
    rng: Range | None
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
        print(f"golden roots: {', '.join(GOLDEN_ROOTS)}")
        return run_check(opts.repo, rng)
    except GitError as exc:
        print(f"::error::{exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
