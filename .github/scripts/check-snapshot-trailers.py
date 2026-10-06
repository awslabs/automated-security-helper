#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fails when a golden file changes without a ``Snapshot-Update:`` trailer saying why.

WHY THIS EXISTS
---------------
A snapshot test fails when output changes, and every suite here has an update flag that
makes it pass again by rewriting the snapshot: syrupy's for core ASH (DEVELOPMENT.md
"Snapshot tests"), jest's and the visual suite's for the VS Code extension
(editors/vscode/test/visual/README.md), Gradle's ``-Psnapshot-update`` for the JetBrains
plugin (editors/jetbrains/README.jetbrains). That rewrite is one command and produces a
diff nobody has to read, so on its own a snapshot suite only proves that someone ran the
command. What makes a changed snapshot a decision is a sentence, attached to the commit
that changed it, saying why the output is now different. This script requires that
sentence as a ``Snapshot-Update: <non-empty reason>`` git trailer on the commit that
changed the file. A follow-up commit that only adds the trailer (an empty commit, or one
touching some other file) does not satisfy it, because then the reason is not attached
to the change it explains, and after a rebase or a cherry-pick the two travel
separately. The error message prints the exact command that amends the right commits.

TWO RULES
---------
* Under ``PER_COMMIT_ROOTS`` (editors/), EVERY commit in the range that touches a golden
  file must carry a trailer, so a second, unexplained change to a snapshot an earlier
  commit explained fails.
* Everywhere else, a golden file passes once ANY commit in the range that touched it
  carries one.

The per-commit rule is not applied to core ASH's golden files because it cannot be met
by a branch that merges main. main checks its own pull requests with the any-commit
rule and squash-merges them, and some of its history predates this check, so main's
commits are not each trailered: #726 changed docs/content/docs/cli-reference-generated.md
with no trailer, before #717 added the check. When a branch merges main, those commits
enter the branch's push range and cannot be amended; under the per-commit rule every
such push would fail on main's history. Under the any-commit rule the merge commit's
own trailer (a merge is read with ``-c``, see ``touched_files``) explains a golden file
the merge resolved. The editor trees exist only on branches that hold every commit
that touched them, all trailered, so the stricter rule costs nothing there.

ONE SCRIPT FOR CORE ASH AND THE EDITORS
---------------------------------------
Core ASH's snapshot suite (tests/snapshot) and the editor suites each had a trailer
check: this file, and .github/scripts/check-snapshot-trailers.py, which was this
file's logic with the golden set and the orphan check swapped. The editor script was
folded in here and deleted. From it this file took the per-commit rule for the editor
trees (see TWO RULES), ``--golden-root``, ``--policy``, the editor orphan check,
reading paths with ``-z`` so a name git would quote is still matched, and the push range
for a new or force-pushed branch (see below). The editor snapshots and PNG baselines were
already golden here, because every one of them sits under a ``__snapshots__`` directory.

WHAT COUNTS AS GOLDEN
---------------------
``GOLDEN`` below is the one list. A file is golden when it is committed output that
users or clients see AND it is entirely produced by a generator or a test, so a change
to it is always a change in behavior rather than an edit. Files that are partly
hand-written are out: requiring a trailer for a typo fix in prose teaches people to
paste a meaningless reason, and a trailer that is always pasted means nothing. Each
entry, and each rejected candidate, is explained next to the list.

``--golden-root DIR`` (repeatable) narrows the set to golden files under those
directories, so an editor's CI job can check its own tree. Without it, the whole list
applies.

ORPHANED SNAPSHOTS
------------------
``--orphans`` runs two static checks, because no suite can report a snapshot that nothing
opens:

* core ASH: syrupy fails the session for a snapshot that a collected test module no
  longer asserts. It cannot see a snapshot whose test module was deleted or renamed: the
  module is not collected, so its ``__snapshots__/test_old.ambr`` is never opened and a
  full run exits 0 (measured with syrupy 5.5 under pytest-xdist). ``find_orphans`` maps
  every file under a ``tests/**/__snapshots__/`` directory back to the module that owns
  it.
* the VS Code extension: ``jest --ci`` fails a run that leaves a snapshot unchecked or a
  snapshot file obsolete (measured: exit 1 for both), but only for files under its
  ``roots``, and the visual suite fails a baseline it did not compare, but only when it
  runs. ``find_editor_orphans`` requires every ``X.snap`` to sit in a ``__snapshots__``
  directory beside a test file ``X``, and every PNG to be named in the
  ``scenarios.json`` beside its ``__snapshots__`` directory, which must in turn have a
  PNG for each name.

The JetBrains plugin's snapshots are named after test classes and cases rather than
files, so its suite records every snapshot it compares and fails on a file nothing
compared (editors/jetbrains/assert-snapshots-used.py) instead; it is not in
``EDITOR_ROOTS``.

POLICY
------
``--policy`` fails when a workflow under .github/workflows passes an editor's snapshot
update flag: Gradle's ``-Psnapshot-update`` in any spelling (``-P snapshot-update``,
``--project-prop``, ``ORG_GRADLE_PROJECT_snapshot-update``), ``ASH_SNAPSHOT_UPDATE=1``,
``--snapshot-update``, or jest's ``--updateSnapshot``, ``--update-snapshot``, ``-u``,
``--ci=false`` or ``--no-ci``. Lines are read with their YAML continuations joined (see
``logical_lines``), so a flag folded onto the next line still counts. The suites also
refuse their flag when CI or GITHUB_ACTIONS is "true", so this is the second of two
locks: CI only ever compares. For core ASH's syrupy flags the same lock is
tests/snapshot/test_snapshot_policy.py, which reads every file CI runs, not only
workflows.

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
* push: ``before..after``. An all-zero ``before`` (a newly created ref) has no range,
  and neither has a ``before`` that is no longer in the clone (a force-push that
  discarded it; that one also warns). Both check ``after`` from its merge base with the
  default branch, the range a pull request from the branch would check, so the earlier
  commits of a new branch are not let through. Pushed to the default branch itself,
  where that range would be empty, only ``after`` is checked against its first parent.
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
    python3 .github/scripts/check-snapshot-trailers.py --golden-root editors/jetbrains
    python3 .github/scripts/check-snapshot-trailers.py --orphans
    python3 .github/scripts/check-snapshot-trailers.py --policy

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
from typing import Any

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
# * any `__snapshots__/` tree: syrupy output under tests/, the VS Code extension's jest
#   `.snap` files and PNG baselines, and the JetBrains plugin's text snapshots and PNG
#   baselines under editors/. Each is written only by its suite's update flag.
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
    ("__snapshots__", "snapshot"),
    (".github/actions/validate-mcp/*.golden.json", "MCP tool-surface golden"),
    ("automated_security_helper/schemas/*.json", "generated JSON schema"),
    ("docs/content/docs/cli-reference-generated.md", "generated CLI reference"),
    (
        "ash-agent-plugins/agentic-coding/transpiler/_base/references/tool-reference.md",
        "generated MCP tool reference",
    ),
)

# Golden files under these directories need a trailer on EVERY commit that touches
# them; the rest of the golden set needs one on at least one such commit in the range.
# See "TWO RULES" in the module docstring.
PER_COMMIT_ROOTS: tuple[str, ...] = ("editors",)

# `--golden-root`: when non-empty, only golden files under one of these directories
# count. Empty, the default, means the whole GOLDEN list.
GOLDEN_ROOTS: list[str] = []

# What passes an editor snapshot suite's update flag, matched against the logical lines
# of workflow files (see ``logical_lines``). editors/vscode/test/snapshot-policy.test.ts
# holds the same list for every file under .github/; a form added here goes there too.
_UPDATE_FLAG_FORMS: tuple[str, ...] = (
    # Gradle, for the JetBrains plugin: -P with or without a space, the long
    # option, and the environment variable Gradle maps to the same property.
    r"-P\s*snapshot-update",
    r"--project-prop(?:=|\s+)snapshot-update",
    r"ORG_GRADLE_PROJECT_snapshot-update",
    # The VS Code suites' own flag and the variable it sets in the container.
    r"--snapshot-update",
    r"ASH_SNAPSHOT_UPDATE\s*[:=]\s*['\"]?1",
    # jest's: both spellings of the long flag, the two ways to turn --ci off,
    # and -u after a jest or npm test command.
    r"--updateSnapshot",
    r"--update-snapshot",
    r"--no-ci\b",
    r"--ci[= ]false",
    r"\b(?:jest|npm\b.*\s(?:test|t))\b.*\s-u\b",
)
UPDATE_FLAGS = re.compile("|".join(_UPDATE_FLAG_FORMS))

# A `#` at the start of a line or after whitespace starts a comment, in YAML and in
# shell. Nothing a comment says is executed.
_COMMENT = re.compile(r"(?:^|\s)#.*$")
# A YAML line split into its indentation, its sequence dashes and the rest, and the
# rest read as `key:` with an optional value.
_LINE_PARTS = re.compile(r"^(\s*)((?:-\s+)*)(.*)$")
_KEY_VALUE = re.compile(r"^[^\s#'\"][^:#]*:(?:\s+(\S.*))?$")


def _scalar_owner(line: str) -> tuple[int, str] | None:
    """For a line that starts a scalar, the column its continuations must be right of
    and the scalar's first text; None for a line that starts none (`key:` alone, which
    opens a mapping or a sequence, or anything that is not YAML structure).

    `key: value` (also `key: |` or `key: >-`) continues right of the key's column;
    a sequence item `- value` right of its dash.
    """
    lead, dashes, rest = _LINE_PARTS.match(line).groups()  # type: ignore[union-attr]
    key = _KEY_VALUE.match(rest)
    if key:
        return (len(lead) + len(dashes), key.group(1)) if key.group(1) else None
    if dashes:
        return len(lead) + dashes.rstrip().rfind("-"), rest
    return None


def logical_lines(text: str) -> list[tuple[int, str]]:
    """``text``'s lines, with every YAML scalar continuation joined to its first line.

    A flag on the line after its command is still that command's flag when YAML folds
    the two into one string: a `>` block, a plain or quoted scalar continued on a more
    indented line, or a `|` block line ending in a shell `\\`. Each of those is joined
    here, so the patterns see the command and its flag on one line. Lines of a `|`
    block are separate shell commands and stay separate, so a `-u` given to some other
    program in the same `run:` is not read as jest's. Returns (first line number, text)
    pairs, comments removed and blank lines dropped. Not a YAML parser: it only has to
    keep a command and its arguments together, and errs towards joining.
    """
    out: list[tuple[int, str]] = []
    owner_indent: int | None = None  # the column a continuation must be right of
    literal = False  # inside a `|` block
    joins_next = False  # the previous line of a `|` block ended in a backslash
    for number, raw in enumerate(text.splitlines(), 1):
        line = _COMMENT.sub("", raw).rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if owner_indent is not None and indent > owner_indent:
            body = line.strip()
            if literal and not joins_next:
                out.append((number, body))
            else:
                first, previous = out[-1]
                joined = previous.removesuffix("\\").rstrip()
                out[-1] = (first, f"{joined} {body}")
            joins_next = literal and body.endswith("\\")
            continue
        out.append((number, line.strip()))
        owner = _scalar_owner(line)
        if owner:
            owner_indent, literal = owner[0], owner[1].startswith("|")
        else:
            owner_indent, literal = None, False
        joins_next = False
    return out


def _under(posix: PurePosixPath, root: str) -> bool:
    root_parts = PurePosixPath(root).parts
    return posix.parts[: len(root_parts)] == root_parts


def per_commit(path: str) -> bool:
    """True when every commit that touches ``path`` needs its own trailer."""
    posix = PurePosixPath(path)
    return any(_under(posix, root) for root in PER_COMMIT_ROOTS)


def golden_reason(path: str) -> str | None:
    """Return why ``path`` is golden, or None when it is not."""
    posix = PurePosixPath(path)
    if GOLDEN_ROOTS and not any(_under(posix, root) for root in GOLDEN_ROOTS):
        return None
    for pattern, why in GOLDEN:
        if pattern == "__snapshots__":
            if "__snapshots__" not in posix.parts[:-1]:
                continue
            kind = "image snapshot" if posix.suffix == ".png" else "text snapshot"
            return f"editor {kind}" if _under(posix, "editors") else why
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
    # core.quotepath=off as well as -z where paths are read: no git output this
    # script parses, or prints, spells a path in git's quoted octal form.
    proc = subprocess.run(
        ["git", "-C", str(repo), "-c", "core.quotepath=off", *args],
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
    # -z: NUL-separated and never quoted. Without it git quotes a path holding a
    # non-ASCII byte, a quote, a backslash or a control character as "editors/...",
    # whose first component is then `"editors` and is not under any golden root.
    merge = ["-c"] if len(parents) > 1 else ["--root"]
    out = git(
        repo,
        "diff-tree",
        "-r",
        *merge,
        "-z",
        "--no-commit-id",
        "--no-renames",
        "--name-only",
        sha,
    )
    return [n for n in out.split("\0") if n]


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

    Under ``PER_COMMIT_ROOTS`` every commit that touches the path needs its own
    trailer. Elsewhere a path is accepted once ANY commit in the range that touched
    it has one; see "TWO RULES" in the module docstring for why.
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
        if not unexplained:
            continue
        if per_commit(path) or len(unexplained) == len(touching):
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
        if not ensure_commit(repo, after):
            raise GitError(
                f"{after} is not in the clone; check out with fetch-depth: 0"
            )
        if before == ZERO_SHA:
            return _from_default_branch(repo, payload, after, "new ref")
        if not ensure_commit(repo, before):
            print(
                f"::warning::push 'before' {before} is not in the clone (force-push?); "
                f"checking {after} from its merge base with the default branch."
            )
            return _from_default_branch(repo, payload, after, "force-push")
        return Range(before, after, "push")
    if event_name == "workflow_dispatch":
        default = _default_branch(payload)
        head = git(repo, "rev-parse", "HEAD").strip()
        ref = f"origin/{default}"
        if not commit_exists(repo, ref):
            raise GitError(f"{ref} is not in the clone; check out with fetch-depth: 0")
        base = git(repo, "merge-base", ref, head).strip()
        return Range(base, head, f"dispatch: branch vs merge base with {ref}")
    raise GitError(f"unsupported event {event_name!r}")


def _default_branch(payload: dict[str, Any]) -> str:
    return (payload.get("repository") or {}).get("default_branch") or "main"


def _from_default_branch(
    repo: Path, payload: dict[str, Any], head: str, why: str
) -> Range:
    """A push with no usable ``before``: ``head`` from its fork point with the default branch.

    A new branch, or a force-push whose old tip is gone, has no ``before..after``.
    Checking only the tip would let every earlier commit of the branch through, so
    the range is what a pull request from the branch would check, as
    workflow_dispatch already does. On the default branch itself the fork point is
    the head, which would check nothing, so there only the tip is checked, as before.
    """
    default = _default_branch(payload)
    tips = _base_branch_tip(repo, default)
    if not tips:
        raise GitError(
            f"origin/{default} is not in the clone, so the {why} has no range; "
            "check out with fetch-depth: 0"
        )
    base = fork_point(repo, tips, head)
    head_sha = git(repo, "rev-parse", f"{head}^{{commit}}").strip()
    if base == head_sha:
        return Range(None, head, f"{why} on {default}: its tip commit only")
    return Range(base, head, f"{why}: branch vs merge base with origin/{default}")


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


def find_all_orphans(root: Path) -> list[str]:
    """``find_orphans`` for core ASH's tests, then ``find_editor_orphans``."""
    return [*find_orphans(root), *find_editor_orphans(root)]


# ---------------------------------------------------------------------------
# Policy: no workflow passes an update flag
# ---------------------------------------------------------------------------


def find_update_flags(root: Path) -> list[str]:
    """Lines in .github/workflows that pass an editor snapshot update flag."""
    hits = []
    workflows = sorted((root / ".github/workflows").glob("*.y*ml"))
    for wf in workflows:
        for number, line in logical_lines(wf.read_text(encoding="utf-8")):
            if UPDATE_FLAGS.search(line):
                hits.append(f"{wf.relative_to(root).as_posix()}:{number}: {line}")
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
    r.write("tests/snapshot/test_cli.py", "def test(): pass\n")
    r.write("docs/content/docs/cli-reference.md", "hand-written\n")
    r.commit("feat: no golden file")
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


def _quoted_name(f: _Fixture) -> str:
    """A golden path git would quote: a non-ASCII letter, a double quote, a backslash."""
    return str(PurePosixPath(f.snap).parent / 'caf\u00e9 "q" \\.test.ts.snap')


def _case_non_ascii_golden(r: _Repo, f: _Fixture) -> list[str]:
    r.write(_quoted_name(f), "x\n")
    r.commit("test: a snapshot whose name git quotes")
    return [_quoted_name(f)]


def _case_non_ascii_golden_in_merge(r: _Repo, f: _Fixture) -> list[str]:
    # An evil merge: the merge commit itself edits a golden file git quotes, so only
    # the merge (-c) branch of touched_files can see it.
    r.write(_quoted_name(f), "base\n")
    r.commit(f"test: seed the quoted name\n\n{GOOD}")
    r._git("checkout", "-q", "-b", "side")
    r.write("side.txt", "1\n")
    r.commit("chore: side")
    r._git("checkout", "-q", "main")
    r.write("main.txt", "1\n")
    r.commit("chore: main")
    r._git("merge", "-q", "--no-commit", "side")
    r.write(_quoted_name(f), "edited in the merge\n")
    r.commit("Merge branch 'side'")
    return [_quoted_name(f)]


# Core ASH's own golden files, which the editor fixtures above do not reach.
CORE_SNAP = "tests/snapshot/__snapshots__/test_cli.ambr"


def _core_case_snapshot_without_trailer(r: _Repo) -> list[str]:
    r.write(CORE_SNAP, "a\n")
    r.commit("test: update\n\nno trailer here")
    return [CORE_SNAP]


def _core_case_snapshot_with_trailer(r: _Repo) -> list[str]:
    r.write(CORE_SNAP, "a\n")
    r.commit(f"test: update\n\nbody\n\n{GOOD}")
    return []


def _core_case_second_change_untrailered(r: _Repo) -> list[str]:
    # The any-commit rule outside PER_COMMIT_ROOTS: the first change's trailer covers
    # the path for the range. The editor fixtures run the same sequence and fail.
    r.write(CORE_SNAP, "a\n")
    r.commit(f"test: update\n\n{GOOD}")
    r.write(CORE_SNAP, "b\n")
    r.commit("test: change it again")
    return []


def _merge_resolving_golden(r: _Repo, merge_message: str) -> list[str]:
    # A branch that merges main: main's untrailered change to a generated doc enters the
    # range, the branch's own change to it is untrailered too, and the merge commit
    # resolves the file. Only the merge's trailer can explain it.
    doc = "docs/content/docs/cli-reference-generated.md"
    r.write(doc, "base\n")
    r.base = r.commit(f"docs: seed\n\n{GOOD}")
    r._git("checkout", "-q", "-b", "upstream")
    r.write(doc, "base\nupstream\n")
    r.commit("fix(cli): main changed the help, no trailer")
    r._git("checkout", "-q", "main")
    r.write(doc, "ours\nbase\n")
    r.commit("docs: ours, no trailer")
    r._git("merge", "-q", "--no-commit", "upstream")
    r.write(doc, "ours\nbase\nupstream\n")
    r.commit(merge_message)
    return [doc]


def _core_case_merge_with_trailer(r: _Repo) -> list[str]:
    _merge_resolving_golden(r, f"Merge upstream\n\n{GOOD}")
    return []


def _core_case_merge_without_trailer(r: _Repo) -> list[str]:
    return _merge_resolving_golden(r, "Merge upstream")


def _core_case_squash_message(r: _Repo) -> list[str]:
    r.write(CORE_SNAP, "a\n")
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


def _core_case_schema_and_generated_doc(r: _Repo) -> list[str]:
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


_CORE_CASES = {
    "core snapshot, no trailer -> fail": _core_case_snapshot_without_trailer,
    "core snapshot with trailer -> pass": _core_case_snapshot_with_trailer,
    "core snapshot, second change untrailered -> pass (any-commit rule)": (
        _core_case_second_change_untrailered
    ),
    "merge resolving a golden file, trailer on the merge -> pass": (
        _core_case_merge_with_trailer
    ),
    "merge resolving a golden file, no trailer anywhere -> fail": (
        _core_case_merge_without_trailer
    ),
    "core squash-style message -> pass": _core_case_squash_message,
    "schema + generated doc -> fail, hand doc ignored": (
        _core_case_schema_and_generated_doc
    ),
}


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
    "golden name git quotes, no trailer -> fail": (_case_non_ascii_golden, False),
    "golden name git quotes, edited in a merge -> fail": (
        _case_non_ascii_golden_in_merge,
        False,
    ),
}


def _self_test_ranges(tmp: Path) -> list[str]:
    failures = []
    r = _Repo(tmp / "ranges")
    first = r.base
    r.write("a.txt", "a\n")
    second = r.commit("chore: second")
    r._git("update-ref", "refs/remotes/origin/main", second)
    # Pushed to the default branch itself: the fork point is the head, so the tip.
    got = resolve_range(r.path, "push", {"before": ZERO_SHA, "after": second})
    if not (got and got.base is None and got.head == second):
        failures.append(f"push of a new default branch: got {got}")
    got = resolve_range(r.path, "push", {"before": first, "after": second})
    if not (got and got.base == first):
        failures.append(f"push before..after: got {got}")
    got = resolve_range(r.path, "push", {"before": "1" * 40, "after": second})
    if not (got and got.base is None):
        failures.append(f"force-push to the default branch: got {got}")
    failures += _self_test_new_branch(r, second)
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


def _self_test_new_branch(r: _Repo, fork: str) -> list[str]:
    """A new branch whose untrailered PNG is in its first commit, not its tip.

    With only the tip checked, a push that creates the branch, or force-pushes it
    over a tip the clone no longer has, lets that commit through.
    """
    failures = []
    r._git("checkout", "-q", "-b", "feature", fork)
    r.write(_VSCODE.png, "png\n")
    r.commit("test: new picture")
    r.write("feature.txt", "1\n")
    tip = r.commit("feat: later work")
    for before, why in ((ZERO_SHA, "new branch"), ("2" * 40, "force-pushed branch")):
        got = resolve_range(r.path, "push", {"before": before, "after": tip})
        if not (got and got.base == fork and got.head == tip):
            failures.append(f"{why}: expected range {fork}..{tip}, got {got}")
            continue
        found = [
            v.path
            for v in find_violations(r.path, commits_in_range(r.path, got.base, tip))
        ]
        if found != [_VSCODE.png]:
            failures.append(f"{why}: the untrailered PNG was not caught: {found}")
    r._git("update-ref", "-d", "refs/remotes/origin/main")
    try:
        resolve_range(r.path, "push", {"before": ZERO_SHA, "after": tip})
        failures.append(
            "new branch with no origin/main: checked less instead of failing"
        )
    except GitError:
        pass
    r._git("checkout", "-q", "main")
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


def _self_test_core_orphans(tmp: Path) -> list[str]:
    root = tmp / "core-orphans"
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
            failures.append(f"core orphan check missed {expected!r}:\n{dirty}")
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
        "run: npm run snapshots -- structural  # not --snapshot-update\n"
        "steps:\n"
        "  - run: |\n"
        "      npm test -- --ci\n"
        "      sort -u names.txt\n"
        "  - name: next step\n"
        "    run: echo -u\n"
    )
    failures = [f"clean workflow reported: {h}" for h in find_update_flags(root)]
    bad = [
        "run: ./gradlew test -Psnapshot-update",
        "run: ./gradlew test -P snapshot-update",
        "run: ./gradlew test --project-prop snapshot-update",
        "run: ./gradlew test --project-prop=snapshot-update",
        "env:\n  ORG_GRADLE_PROJECT_snapshot-update: 'true'",
        "env:\n  ASH_SNAPSHOT_UPDATE: '1'",
        "run: pytest --snapshot-update",
        "run: npx jest --updateSnapshot",
        "run: npx jest --update-snapshot",
        "run: npx jest --no-ci",
        "run: npx jest --ci=false",
        "run: npm test -- -u",
        "run: npm t -- -u",
        "run: npm run test -- -u",
        'run: npm --prefix "editors/vscode" test -- -u',
        "run: >\n  npx jest --ci\n  -u",
        "run: npx jest --ci\n  -u",
        "- run: >-\n    npm test --\n    --update-snapshot",
        "run: |\n  npx jest --ci \\\n    -u",
    ]
    for i, text in enumerate(bad):
        (wf / f"bad{i}.yml").write_text(text + "\n")
        hits = find_update_flags(root)
        if len(hits) != 1:
            failures.append(f"policy missed or overcounted {text!r}: {hits}")
        (wf / f"bad{i}.yml").unlink()
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
    if not golden_reason(CORE_SNAP):
        failures.append("core ASH's snapshot is not golden")
    if not golden_reason("tests/snapshot/__snapshots__/test_a/b.md"):
        failures.append("a nested single-file core snapshot is not golden")
    if golden_reason("automated_security_helper/schemas/sub/x.json"):
        failures.append("the schemas glob crossed a directory")
    if per_commit(CORE_SNAP) or not per_commit(_VSCODE.snap):
        failures.append("PER_COMMIT_ROOTS no longer splits core from the editors")
    saved = list(GOLDEN_ROOTS)
    GOLDEN_ROOTS[:] = ["editors"]
    try:
        if golden_reason(CORE_SNAP):
            failures.append("--golden-root editors still covers tests/")
        if not golden_reason(_JETBRAINS.png):
            failures.append("--golden-root editors no longer covers an editor")
    finally:
        GOLDEN_ROOTS[:] = saved
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
    with tempfile.TemporaryDirectory(prefix="snapshot-trailers-") as tmpdir:
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
        for i, (name, core_case) in enumerate(_CORE_CASES.items()):
            r = _Repo(tmp / f"core-case{i}")
            expected = core_case(r)
            got = sorted(r.violations())
            if got != expected:
                failures.append(
                    f"core: {name}: expected violations {expected}, got {got}"
                )
        failures += _self_test_ranges(tmp)
        failures += _self_test_core_orphans(tmp)
        failures += _self_test_orphans(tmp)
        failures += _self_test_policy(tmp)
    failures += _self_test_roots()
    for f in failures:
        print(f"::error::self-test: {f}")
    print(
        f"self-test: {len(_CASES)} trailer cases for each of {len(_FIXTURES)} editors, "
        f"{len(_CORE_CASES)} core cases, plus range, orphan, policy and root cases, "
        f"{len(failures)} failure(s)"
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
        help="check only golden files under this directory (repeatable; default: all)",
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
        problems = find_all_orphans(opts.repo)
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
        if GOLDEN_ROOTS:
            print(f"golden roots: {', '.join(GOLDEN_ROOTS)}")
        return run_check(opts.repo, rng)
    except GitError as exc:
        print(f"::error::{exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
