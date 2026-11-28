"""A docs deploy never force-pushes gh-pages, and no tag push reaches a job that writes it.

Why this file exists
--------------------
A pushed tag runs the workflow files of the commit it points at, not main's. On
2026-11-12 a tag push reached a commit whose ``ash-repo-docs.yml`` still triggered on
every tag and ran ``mkdocs gh-deploy --clean --force``. ``gh-deploy`` builds one
unversioned site and force-pushes it to gh-pages as a commit with no parent, so the
released versions and the ``latest`` alias disappeared from the published site.

Main's copy of that file no longer has the shape: it runs on pushes to main only, its
deploy job admits only a push to main, and it publishes through
``scripts/docs_versions.py``, which adds one version with mike and pushes without
force. Nothing, though, kept a later change from bringing the shape back. Commits that
already carry the old copy cannot be edited, and a ruleset on gh-pages that refuses
non-fast-forward updates is a repository setting, not a file this suite can read; the
releases page of the contributing guide says what to do about both.

What it asserts
---------------
For every file under ``.github/workflows/``, read with ``tests/utils/github_actions.py``:

1. No step runs ``mkdocs gh-deploy`` or ``ghp-import``. Each replaces the whole branch
   with one build.
2. No step pushes gh-pages with a force spelling: ``--force``, ``-f``,
   ``--force-with-lease``, ``--mirror`` or a ``+`` refspec. A push that names another
   branch is not a push of gh-pages. A push whose branch the text does not name, such
   as a push of ``HEAD`` or ``@``, or names with a variable or a wildcard, is read as
   one that could be.
3. No job that can write gh-pages is reachable from a ``push`` trigger on tags. A job
   can when its token can write repository contents (``contents: write``, or no
   permissions declared, so the repository default applies) or when one of its steps
   publishes the site. Triggers, ``if:`` conditions and calls of local reusable
   workflows are evaluated, so moving the deploy into another file, or narrowing a
   tag filter, changes the answer the way it changes what GitHub runs.

Rules 1 and 2 also read the steps of the local composite actions under
``.github/actions/``, since a workflow can call one.

A step's script is read as a shell reads it. Quotes come first, so a separator inside
quotes ends no command; comments, backslash continuations, redirections and
here-documents are read too, and a redirection with its target is no word of the
command it sits in. The script a shell runs with ``-c`` and the text of a
here-document are read as scripts of their own, up to ``MAX_SHELL_DEPTH`` of them
inside one another.

How each rule is shown to fail
------------------------------
* ``OLD_COPY`` is the workflow file as it was at the v3.7.1 release commit, its git
  blob id pinned. It is planted in ``tmp_path`` and read with the same loader as the
  real files. It breaks all three rules, and each rule reports it with a message of
  its own.
* Planted workflows break one rule each, in several spellings. Dropping a rule from
  ``RULES`` leaves its cases unreported, and the tests that expect them go red.
* The same shapes made safe, and every real workflow and composite action, break no
  rule. A push to main still reaches the real deploy job, which shows the checks read
  something.

What it does not cover
----------------------
* A publisher reached through a script, a Makefile target or a third-party action. A
  job that calls one is still caught by rule 3 when its token can write.
* A ``uses: ./.github/actions/...`` step. Rules 1 and 2 read the action files directly,
  but rule 3 does not follow the step, so a job with a read token that calls an action
  which pushes gh-pages with a credential of its own breaks no rule.
* A reusable workflow named by repository and ref instead of by local path.
* A local action outside ``.github/actions/``.
* Triggers other than ``push``, such as ``create`` and ``workflow_run``.
* A job condition on an event field the probe context leaves out, such as
  ``github.event.created``. It reads as null, so the job is judged not to run.
* A deletion of gh-pages (``git push --delete``), which no rule here reads.
* Tag names. Triggers are evaluated for a fixed set of names and for names built from
  the workflow's own tag filters, so an unusual filter may need a name added.
* A script handed to ``eval``, ``xargs``, ``ssh``, a here-string or a pipe into a
  shell, a command built at run time, and a command substitution inside quotes.
* A shell string or here-document nested more than ``MAX_SHELL_DEPTH`` deep.
* Anything outside the repository, such as a ruleset on gh-pages.
"""

from __future__ import annotations

import hashlib
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.utils import github_actions as ga

pytestmark = pytest.mark.unit

REPO = "awslabs/automated-security-helper"
DOCS_WORKFLOW = "ash-repo-docs.yml"

#: The rules, by name. A violation carries one of these.
NO_BRANCH_REPLACING_PUBLISHER = "no-branch-replacing-publisher"
NO_FORCE_PUSH = "no-force-push"
NO_TAG_REACHABLE_WRITER = "no-tag-reachable-writer"

#: Tag names a push is tried with, besides the names built from a workflow's own tag
#: filters: a floating major, a release, a prerelease, a word, a name with a slash.
TAG_PROBES = ("v3", "v3.8.0", "v4.0.0-rc.1", "docs-preview", "release/1.0", "latest")

#: How many calls of local reusable workflows are followed.
MAX_CALL_DEPTH = 4

#: How many shell strings and here-documents are read inside one another.
MAX_SHELL_DEPTH = 4

#: ``.github/workflows/ash-repo-docs.yml`` as it was at the v3.7.1 release commit
#: (af1206aff596f1288ad066828058b3011de2a998), and the git blob id of that file. A
#: test below hashes the text, so the planted file is that file and not a likeness.
OLD_COPY_BLOB = "301767fe4f75f5d93433b01d1dcf701654eeb5b4"
OLD_COPY = """\
name: Docs Build & Deploy
on:
  push:
    branches:
      - "*"
    tags:
      - "*"
  pull_request:
    branches:
      - "*"
  workflow_dispatch: {}
env:
  PYTHON_VERSION: "3.12"

permissions:
  contents: read

concurrency:
  # One in-flight run per pull request; pushing again supersedes the previous run.
  #
  # github.ref is refs/pull/<n>/merge on pull_request, and on merge_group it is the
  # per-entry gh-readonly-queue/main/pr-<n>-<sha> branch, so every queue entry lands
  # in its own group and entries never serialize behind one another.
  group: ${{ github.workflow }}-${{ github.ref }}
  # Only pull_request runs may be cancelled. A merge_group run must finish or the
  # queue loses its verdict, and push/tag runs feed docs and releases.
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  build-docs:
    name: Build documentation
    needs: []
    runs-on: ubuntu-latest
    timeout-minutes: 20
    permissions:
      contents: read
    if: github.event_name == 'pull_request' || (github.event_name == 'push' && github.ref != 'refs/heads/main')

    steps:
      - uses: actions/checkout@v7

      - name: Install uv
        uses: astral-sh/setup-uv@v7
        with:
          enable-cache: true

      - name: Set up Python
        uses: actions/setup-python@v7
        with:
          python-version: ${{ env.PYTHON_VERSION }}

      - name: Install dependencies
        run: uv sync

      - name: Build documentation
        run: uv run mkdocs build --clean

  deploy-docs:
    name: Deploy documentation
    needs: []
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      #checkov:skip=CKV2_GHA_1:The permissions are not set to write-all at the top-level, or any level
      contents: write
    if: github.event_name == 'push' && (github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/'))

    steps:
      - uses: actions/checkout@v7

      - name: Install uv
        uses: astral-sh/setup-uv@v7
        with:
          enable-cache: true

      - name: Set up Python
        uses: actions/setup-python@v7
        with:
          python-version: ${{ env.PYTHON_VERSION }}

      - name: Install dependencies
        run: uv sync

      - name: Deploy documentation
        run: uv run mkdocs gh-deploy --clean --force
"""


# --------------------------------------------------------------------------- shapes


@dataclass(frozen=True)
class Violation:
    rule: str
    where: str
    message: str

    def __str__(self) -> str:
        return f"[{self.rule}] {self.where}: {self.message}"


@dataclass(frozen=True)
class Step:
    """One ``run:`` step, with where it sits for a message."""

    where: str
    run: str


@dataclass(frozen=True)
class Unit:
    """A file the rules read: a workflow, or a local composite action (no workflow)."""

    name: str
    steps: tuple[Step, ...]
    workflow: ga.Workflow | None
    root: Path


@dataclass(frozen=True)
class ReachedJob:
    """A job an event starts, with what its token can do once its callers have capped it."""

    workflow: str
    job_id: str
    steps: tuple[Step, ...]
    token_can_write: bool
    via: tuple[str, ...]


# --------------------------------------------------------------------------- shell

_SHELLS = frozenset({"bash", "sh", "zsh", "dash"})

#: A shell option that takes the next word as its value, as in ``-o pipefail`` and
#: ``-O extglob``. The letter that takes it can end a cluster, as in ``-euo pipefail``.
_SHELL_OPTION_WITH_A_VALUE = re.compile(r"[-+][A-Za-z]*[oO]")
_GIT_OPTIONS_WITH_A_VALUE = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
)

#: ``gh-deploy`` is mkdocs' command, and ``gh_deploy`` its module; ``ghp-import`` is the
#: package it wraps, and ``ghp_import`` the module. Both build one site and replace
#: the whole branch with it.
_BRANCH_REPLACING_PUBLISHER = re.compile(
    r"(?<![\w-])(?:gh[-_]deploy|ghp[-_]import)(?![\w-])"
)

#: Commands that add or change a version of the site without replacing the branch.
_PUBLISHES_DOCS = re.compile(
    r"docs_versions\.py\s+deploy\b"
    r"|\bmike\s+(?:deploy|delete|alias|retitle|set-default|rename)\b"
)


def _strip_comment(line: str) -> str:
    """The line without a shell comment: a ``#`` that opens a word outside quotes."""
    quote = ""
    skip = False
    for position, char in enumerate(line):
        if skip:
            skip = False
        elif char == "\\" and quote != "'":
            skip = True
        elif quote:
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char == "#" and (position == 0 or line[position - 1] in " \t;&|("):
            return line[:position]
    return line


def _logical_lines(script: str) -> list[str]:
    """The script's lines with comments dropped and backslash continuations joined."""
    lines: list[str] = []
    pending = ""
    for raw in script.splitlines():
        line = pending + _strip_comment(raw)
        pending = ""
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            pending = stripped[:-1] + " "
        else:
            lines.append(line)
    if pending:
        lines.append(pending)
    return lines


#: A script reads as a list of tokens, in the order a shell meets them: a word with its
#: quotes taken off, the end of a command, or the text of a here-document.
_WORD = "word"
_END = "end"
_BODY = "body"
_Token = tuple[str, str]
_DOUBLE_QUOTE_ESCAPES = ('"', "\\", "$", "`", "\n")

#: A redirection operator: ``<`` and ``>``, alone or doubled, with an ``&`` before or
#: after them (``&>``, ``>&``, ``<&``) or a ``|`` after them (``>|``).
_REDIRECTION = re.compile(r"&?[<>]+[&|]?")

#: The digits in front of an operator that name a file descriptor, as in ``2>&1``.
_FILE_DESCRIPTOR = re.compile(r"[0-9]+")

#: What ends a command outside quotes, and what ends a word: a blank, a separator, or
#: the start of a redirection.
_SEPARATORS = ";|()`&"
_WORD_ENDS = " \t\r\n" + _SEPARATORS + "<>"


def _is_file_descriptor(text: str, start: int, end: int) -> bool:
    """Whether ``text[start:end]`` is the number of a redirection, as in ``2>file``."""
    digits = _FILE_DESCRIPTOR.fullmatch(text, start, end)
    return digits is not None and text[end : end + 1] in ("<", ">")


def _read_word(
    text: str, start: int, literal: frozenset[int]
) -> tuple[str, int, int | None]:
    """The word at ``start`` with its quotes taken off, and the position after it.

    The third value is the position of a quote the text never closes, or None. A quote
    at a position in ``literal`` is an ordinary character.
    """
    chars: list[str] = []
    position = start
    while position < len(text):
        char = text[position]
        if char in _WORD_ENDS:
            break
        if char == "\\":
            escaped = text[position + 1 : position + 2]
            if escaped != "\n":
                chars.append(escaped or char)
            position += 2
        elif char == "'" and position not in literal:
            end = text.find("'", position + 1)
            if end == -1:
                return "".join(chars), len(text), position
            chars.append(text[position + 1 : end])
            position = end + 1
        elif char == '"' and position not in literal:
            opened = position
            position += 1
            while position < len(text) and text[position] != '"':
                escaped = text[position + 1 : position + 2]
                if text[position] == "\\" and escaped in _DOUBLE_QUOTE_ESCAPES:
                    position += 1
                    if escaped != "\n":
                        chars.append(escaped)
                else:
                    chars.append(text[position])
                position += 1
            if position >= len(text):
                return "".join(chars), position, opened
            position += 1
        else:
            chars.append(char)
            position += 1
    return "".join(chars), position, None


def _read_body(
    text: str, start: int, delimiter: str, strip_tabs: bool
) -> tuple[str, int]:
    """The lines of a here-document from ``start``, up to the line of its delimiter."""
    lines: list[str] = []
    position = start
    while position < len(text):
        end = text.find("\n", position)
        if end == -1:
            end = len(text)
        line = text[position:end]
        position = end + 1
        compared = line.rstrip("\r")
        if (compared.lstrip("\t") if strip_tabs else compared) == delimiter:
            break
        lines.append(line)
    return "\n".join(lines), min(position, len(text))


def _scan(text: str, literal: frozenset[int]) -> tuple[list[_Token], int | None]:
    """The tokens of ``text``, reading each quote before anything else.

    A redirection gives no token, nor does its target or the number of its file
    descriptor: none of them is a word of the command it sits in.

    The second value is the position of a quote the text never closes, or None.
    """
    tokens: list[_Token] = []
    here_documents: list[tuple[str, bool]] = []
    position = 0
    while position < len(text):
        char = text[position]
        if char in " \t\r":
            position += 1
        elif text.startswith("\\\n", position):
            position += 2
        elif char == "\n":
            tokens.append((_END, ""))
            position += 1
            for delimiter, strip_tabs in here_documents:
                body, position = _read_body(text, position, delimiter, strip_tabs)
                tokens.append((_BODY, body))
            here_documents = []
        elif char == "#":
            end = text.find("\n", position)
            position = len(text) if end == -1 else end
        elif text.startswith("<<", position) and not text.startswith("<<<", position):
            strip_tabs = text.startswith("<<-", position)
            position += 3 if strip_tabs else 2
            while text[position : position + 1] in (" ", "\t"):
                position += 1
            delimiter, position, opened = _read_word(text, position, literal)
            if opened is not None:
                return tokens, opened
            if delimiter:
                here_documents.append((delimiter, strip_tabs))
        elif redirection := _REDIRECTION.match(text, position):
            position = redirection.end()
            while text[position : position + 1] in (" ", "\t"):
                position += 1
            _, position, opened = _read_word(text, position, literal)
            if opened is not None:
                return tokens, opened
        elif char in _SEPARATORS:
            tokens.append((_END, ""))
            position += 1
        else:
            start = position
            word, position, opened = _read_word(text, start, literal)
            if opened is not None:
                return tokens, opened
            if not _is_file_descriptor(text, start, position):
                tokens.append((_WORD, word))
    return tokens, None


def _tokens(text: str) -> list[_Token]:
    """The tokens of ``text``. A quote it never closes is an ordinary character."""
    literal: frozenset[int] = frozenset()
    while True:
        tokens, opened = _scan(text, literal)
        if opened is None:
            return tokens
        literal |= {opened}


def _shell_script(words: list[str]) -> str | None:
    """The script a command hands to a shell with ``-c``, or None.

    It is the first word after the shell's options and their values, when one of the
    options is ``-c`` or a cluster such as ``-ec``.
    """
    for index, word in enumerate(words):
        if Path(word).name not in _SHELLS:
            continue
        position = index + 1
        takes_a_script = False
        while position < len(words) and words[position][:1] in ("-", "+"):
            option = words[position]
            takes_a_script = takes_a_script or _short_options_include(option, "c")
            position += 2 if _SHELL_OPTION_WITH_A_VALUE.fullmatch(option) else 1
        if takes_a_script and position < len(words):
            return words[position]
    return None


def _commands(script: str, depth: int = 0) -> list[list[str]]:
    """Every command of a script as its words.

    Quotes are read before separators, so a separator inside quotes ends nothing. The
    script a shell runs with -c and the text of a here-document are read as scripts of
    their own, up to MAX_SHELL_DEPTH of them inside one another.
    """
    commands: list[list[str]] = []
    scripts: list[str] = []
    words: list[str] = []
    for kind, text in [*_tokens(script), (_END, "")]:
        if kind == _WORD:
            words.append(text)
        elif kind == _BODY:
            scripts.append(text)
        elif words:
            commands.append(words)
            handed_over = _shell_script(words)
            if handed_over is not None:
                scripts.append(handed_over)
            words = []
    if depth < MAX_SHELL_DEPTH:
        for nested in scripts:
            commands += _commands(nested, depth + 1)
    return commands


def _git_push_args(words: list[str]) -> list[str] | None:
    """The words after ``git push``, or None when the command is not a push."""
    for index, word in enumerate(words):
        if Path(word).name != "git":
            continue
        position = index + 1
        while position < len(words) and words[position].startswith("-"):
            position += 2 if words[position] in _GIT_OPTIONS_WITH_A_VALUE else 1
        if position < len(words) and words[position] == "push":
            return words[position + 1 :]
    return None


def _short_options_include(word: str, letter: str) -> bool:
    """Whether ``word`` is short options, such as ``-f`` or ``-fu``, that include ``letter``."""
    return re.fullmatch(r"-[A-Za-z]+", word) is not None and letter in word


def _forces_git_push(arguments: list[str]) -> bool:
    return any(
        word.startswith("--force")
        or word == "--mirror"
        or _short_options_include(word, "f")
        or (word.startswith("+") and len(word) > 1)
        for word in arguments
    )


def _may_name_gh_pages(refspec: str) -> bool:
    """Whether a refspec's destination is gh-pages, or cannot be told from its text.

    A destination with a variable or a wildcard in it could be any branch. So could
    ``HEAD`` and ``@``, which stand for the checked-out branch without naming it.
    """
    refspec = refspec.lstrip("+")
    if refspec in ("HEAD", "@"):
        return True
    destination = refspec.rpartition(":")[2].removeprefix("refs/heads/")
    return destination == "gh-pages" or any(char in destination for char in "$*?[")


def _may_push_gh_pages(arguments: list[str]) -> bool:
    """Whether a ``git push`` can update gh-pages.

    It can when it names the branch, pushes every branch, or does not name one: the
    first word that is not an option is the remote, and the words after it are
    refspecs.
    """
    if "--all" in arguments or "--mirror" in arguments:
        return True
    positional = [word for word in arguments if not word.startswith("-")]
    refspecs = positional[1:]
    return not refspecs or any(_may_name_gh_pages(refspec) for refspec in refspecs)


def _forces_a_gh_pages_push(words: list[str]) -> bool:
    """Whether one command pushes gh-pages with a force spelling."""
    if any(re.fullmatch(r"gh[-_]deploy", word) for word in words):
        return "--force" in words
    if any(re.fullmatch(r"ghp[-_]import", Path(word).name) for word in words):
        return any(
            word == "--force" or _short_options_include(word, "f") for word in words
        )
    arguments = _git_push_args(words)
    return (
        arguments is not None
        and _forces_git_push(arguments)
        and _may_push_gh_pages(arguments)
    )


def _publishes(run: str) -> bool:
    """Whether a step's script publishes the docs site, or pushes a branch that may be it."""
    for line in _logical_lines(run):
        if _BRANCH_REPLACING_PUBLISHER.search(line) or _PUBLISHES_DOCS.search(line):
            return True
    for words in _commands(run):
        arguments = _git_push_args(words)
        if arguments is not None and _may_push_gh_pages(arguments):
            return True
    return False


# --------------------------------------------------------------------------- triggers


def _push(ref: str, ref_type: str) -> dict[str, Any]:
    return ga.base_context(
        event_name="push",
        ref=ref,
        ref_name=ref.split("/", 2)[2],
        ref_type=ref_type,
        repository=REPO,
        repository_owner=REPO.split("/")[0],
        event={"repository": {"default_branch": "main", "full_name": REPO}},
    )


def _tag_push(name: str) -> dict[str, Any]:
    return _push(f"refs/tags/{name}", "tag")


def _branch_push(name: str) -> dict[str, Any]:
    return _push(f"refs/heads/{name}", "branch")


def _example_name(pattern: str) -> str | None:
    """A tag name the push filter ``pattern`` admits: its wildcards filled in."""
    if pattern.startswith("!"):
        return None
    name = re.sub(r"\[([^\]])[^\]]*\]", r"\1", pattern)
    name = re.sub(r"\*+", "x", name)
    return name.replace("?", "").replace("+", "")


def _tag_names(workflow: ga.Workflow) -> list[str]:
    """The tag names to push: the probes, then one built from each of the tag filters."""
    names = list(TAG_PROBES)
    config = workflow.on.get("push")
    patterns = config.get("tags") if isinstance(config, dict) else None
    if isinstance(patterns, str):
        patterns = [patterns]
    for pattern in patterns or []:
        name = _example_name(str(pattern))
        if name and name not in names:
            names.append(name)
    return names


def _allows_write(permissions: dict[str, str] | None) -> bool:
    """Whether declared permissions leave the token able to write contents.

    Nothing declared leaves the repository's default, which may be write.
    """
    return permissions is None or permissions.get("contents") == "write"


def _run_steps(label: str, steps: Any) -> list[Step]:
    found: list[Step] = []
    for number, step in enumerate(steps or [], start=1):
        if isinstance(step, dict) and isinstance(step.get("run"), str):
            name = step.get("name") or f"step {number}"
            found.append(Step(f"{label}, step {name!r}", step["run"]))
    return found


def _local_callee(job: dict[str, Any], root: Path) -> ga.Workflow | None:
    """The workflow a job calls by a path in this repository, if it calls one."""
    uses = str(job.get("uses") or "")
    if not uses.startswith("./"):
        return None
    path = root / uses.removeprefix("./")
    return ga.load_workflow(path) if path.is_file() else None


def _call_context(
    job: dict[str, Any], callee: ga.Workflow, context: dict[str, Any]
) -> dict[str, Any]:
    """The context a called workflow sees: the caller's, plus the inputs of the call."""
    try:
        return ga.with_inputs(context, ga.call_inputs(job, callee, context))
    except ga.ExpressionError:
        return context


def _reached_jobs(
    workflow: ga.Workflow,
    context: dict[str, Any],
    root: Path,
    *,
    caller_may_write: bool = True,
    via: tuple[str, ...] = (),
) -> list[ReachedJob]:
    """The jobs that start when the event in ``context`` starts ``workflow``.

    A job that calls a workflow of this repository stands for that workflow's jobs,
    which can write only if the calling job lets them.
    """
    scoped = dict(context)
    scoped["needs"] = {
        job_id: {"result": "success", "outputs": {}} for job_id in workflow.jobs
    }
    reached: list[ReachedJob] = []
    for job_id, job in workflow.jobs.items():
        if not ga.job_runs(job, scoped):
            continue
        may_write = caller_may_write and _allows_write(
            ga.job_permissions(workflow, job)
        )
        label = f"{workflow.name}: job {job_id!r}"
        callee = _local_callee(job, root)
        if callee is not None and len(via) < MAX_CALL_DEPTH:
            reached += _reached_jobs(
                callee,
                _call_context(job, callee, scoped),
                root,
                caller_may_write=may_write,
                via=(*via, label),
            )
            continue
        steps = tuple(_run_steps(label, job.get("steps")))
        reached.append(ReachedJob(workflow.name, job_id, steps, may_write, via))
    return reached


def _writes_gh_pages(job: ReachedJob) -> str | None:
    """Why the job can write gh-pages, or None when it cannot."""
    if job.token_can_write:
        return "its token can write repository contents"
    for step in job.steps:
        if _publishes(step.run):
            return f"it publishes the site: {step.where}"
    return None


# --------------------------------------------------------------------------- the rules


def _check_publishers(unit: Unit) -> list[Violation]:
    found: list[Violation] = []
    for step in unit.steps:
        for line in _logical_lines(step.run):
            match = _BRANCH_REPLACING_PUBLISHER.search(line)
            if match:
                found.append(
                    Violation(
                        NO_BRANCH_REPLACING_PUBLISHER,
                        step.where,
                        f"runs {match.group(0)!r}, which replaces the whole gh-pages "
                        "branch with one build and drops every published version; "
                        "publish with scripts/docs_versions.py deploy instead",
                    )
                )
                break
    return found


def _check_force_pushes(unit: Unit) -> list[Violation]:
    found: list[Violation] = []
    for step in unit.steps:
        for words in _commands(step.run):
            if _forces_a_gh_pages_push(words):
                found.append(
                    Violation(
                        NO_FORCE_PUSH,
                        step.where,
                        f"force-pushes gh-pages with `{' '.join(words)}`; a push that "
                        "is not a fast-forward discards the branch's history, and "
                        "every published version with it",
                    )
                )
    return found


def _check_tag_reachable_writers(unit: Unit) -> list[Violation]:
    workflow = unit.workflow
    if workflow is None:
        return []
    found: list[Violation] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for name in _tag_names(workflow):
        context = _tag_push(name)
        if not ga.triggers(workflow, context):
            continue
        for job in _reached_jobs(workflow, context, unit.root):
            reason = _writes_gh_pages(job)
            key = (job.workflow, job.job_id, job.via)
            if reason is None or key in seen:
                continue
            seen.add(key)
            where = f"{job.workflow}: job {job.job_id!r}"
            if job.via:
                where += f", called from {' > '.join(job.via)}"
            found.append(
                Violation(
                    NO_TAG_REACHABLE_WRITER,
                    where,
                    f"can write gh-pages ({reason}), and a push of the tag {name!r} "
                    "starts it; no tag push may reach a job that can write the "
                    "published docs",
                )
            )
    return found


RULES = (
    _check_publishers,
    _check_force_pushes,
    _check_tag_reachable_writers,
)


def violations(unit: Unit) -> list[Violation]:
    found: list[Violation] = []
    for rule in RULES:
        found += rule(unit)
    return found


# --------------------------------------------------------------------------- files


def _workflow_unit(workflow: ga.Workflow, root: Path) -> Unit:
    steps: list[Step] = []
    for job_id, job in workflow.jobs.items():
        steps += _run_steps(f"{workflow.name}: job {job_id!r}", job.get("steps"))
    return Unit(workflow.name, tuple(steps), workflow, root)


def _action_unit(path: Path, root: Path) -> Unit:
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    runs = document.get("runs") if isinstance(document, dict) else None
    steps = runs.get("steps") if isinstance(runs, dict) else None
    label = path.relative_to(root).as_posix()
    return Unit(label, tuple(_run_steps(label, steps)), None, root)


WORKFLOW_FILES = sorted(
    path.name for path in ga.WORKFLOWS_DIR.iterdir() if path.suffix in (".yml", ".yaml")
)
ACTION_FILES = sorted(
    path.relative_to(ga.REPO_ROOT).as_posix()
    for path in (ga.REPO_ROOT / ".github" / "actions").rglob("action.y*ml")
)


def _describe(found: list[Violation]) -> str:
    return "\n".join(f"  {violation}" for violation in found)


def _rules_broken(workflow: ga.Workflow, root: Path) -> set[str]:
    return {violation.rule for violation in violations(_workflow_unit(workflow, root))}


# --------------------------------------------------------------------------- planting

READ = {"contents": "read"}
WRITE = {"contents": "write"}
ON_MAIN = {"push": {"branches": ["main"]}}
ON_ANY_TAG = {"push": {"tags": ["*"]}}
DEPLOY = 'uv run python scripts/docs_versions.py deploy --ref "$GITHUB_REF" --push'


def _workflow(
    on: dict[str, Any],
    run: str = DEPLOY,
    *,
    permissions: Any = WRITE,
    condition: str | None = None,
) -> dict[str, Any]:
    """A workflow with one job and one step, as the document a YAML file would hold."""
    job: dict[str, Any] = {
        "runs-on": "ubuntu-latest",
        "steps": [{"name": "Publish", "run": run}],
    }
    if condition is not None:
        job["if"] = condition
    document: dict[str, Any] = {"name": "Planted", "on": on, "jobs": {"publish": job}}
    if permissions is not None:
        document["permissions"] = permissions
    return document


def _plant(
    directory: Path, document: dict[str, Any], name: str = "planted.yml"
) -> ga.Workflow:
    """Write ``document`` as a file and read it back with the repository's loader."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return ga.load_workflow(path)


def _old_copy(tmp_path: Path) -> ga.Workflow:
    path = tmp_path / DOCS_WORKFLOW
    path.write_text(OLD_COPY, encoding="utf-8")
    return ga.load_workflow(path)


def _cases(table: dict[str, Any]) -> list[Any]:
    return [pytest.param(value, id=label) for label, value in table.items()]


#: Each of these replaces the branch, and none forces a push.
PUBLISHER_CASES = {
    "mkdocs gh-deploy": "uv run mkdocs gh-deploy --clean",
    "gh-deploy after a global option": "uv run mkdocs --quiet gh-deploy",
    "gh-deploy through python -m": "python -m mkdocs gh-deploy",
    "gh-deploy at the end of a chain": (
        "uv sync && uv run mkdocs build && uv run mkdocs gh-deploy"
    ),
    "gh-deploy in a shell string": "bash -c 'uv run mkdocs gh-deploy'",
    "gh-deploy called from python": (
        "python -c 'from mkdocs.commands.gh_deploy import gh_deploy'"
    ),
    "ghp-import": "ghp-import --push site",
    "ghp-import as a module": "python -m ghp_import -n -p site",
    "ghp-import through uvx": "uvx ghp-import -p site",
}

#: Each of these forces a push of gh-pages with a command other than gh-deploy and
#: ghp-import, so only the force rule reports it.
FORCE_CASES = {
    "--force": "git push --force origin gh-pages",
    "-f": "git push -f origin HEAD:gh-pages",
    "--force-with-lease": "git push --force-with-lease origin gh-pages",
    "--force-with-lease with a value": (
        "git push --force-with-lease=gh-pages:abc123 origin gh-pages"
    ),
    "a clustered -f": "git push -fu origin gh-pages",
    "a + refspec": "git push origin +HEAD:gh-pages",
    "a + refspec of the full ref": "git push origin +HEAD:refs/heads/gh-pages",
    "after a global option": "git -C site push --force origin gh-pages",
    "after other commands": (
        "cd site && git add -A && git commit -m 'Deploy #12' "
        "&& git push -f origin gh-pages"
    ),
    "over continued lines": "git push \\\n  --force \\\n  origin gh-pages",
    "in a subshell": "(cd site && git push --force origin gh-pages)",
    "in a shell string": "sh -c 'git push --force origin gh-pages'",
    "two commands in a shell string": (
        'bash -c "cd site && git push -f origin gh-pages"'
    ),
    "three commands in a shell string": (
        "sh -c 'git add -A; git commit -m deploy; git push --force origin gh-pages'"
    ),
    "a + refspec in a shell string of two commands": (
        "sh -c 'cd site && git push origin +HEAD:gh-pages'"
    ),
    "in a quoted script over several lines": (
        'bash -c "\n  cd site\n  git push --force origin gh-pages"'
    ),
    "in a shell string inside a shell string": (
        "bash -c \"sh -c 'cd site && git push --force origin gh-pages'\""
    ),
    "in a shell string run with combined options": (
        'bash -ec "cd site && git push --force origin gh-pages"'
    ),
    "in a shell string run after an option with a value": (
        'bash -o pipefail -c "cd site && git push --force origin gh-pages"'
    ),
    "in a shell string run after a cluster of options that ends in a value": (
        'bash -euo pipefail -c "cd site && git push --force origin gh-pages"'
    ),
    "in a shell string run after a shopt option": (
        'bash -O extglob -c "cd site && git push --force origin gh-pages"'
    ),
    "after a here-document with an apostrophe": (
        "cat <<EOF > note.txt\ndon't panic\nEOF\ngit push --force origin 'gh-pages'"
    ),
    "in a script a shell reads from a here-document": (
        "bash <<EOF\ncd site && git push --force origin gh-pages\nEOF"
    ),
    "beside comments with an apostrophe": (
        "# don't wait\ngit push --force origin gh-pages  # it's the deploy"
    ),
    "with its output redirected": (
        "git push --force origin gh-pages > push.log 2>&1 && echo done"
    ),
    "with a redirection before its options": "git push 2>&1 --force origin gh-pages",
    "with its errors discarded": "git push --force origin 2>/dev/null",
    "with its errors piped to tee": "git push --force origin 2>&1 | tee push.log",
    "with its output sent away": "git push --force origin > /dev/null 2>&1",
    "with both outputs sent away at once": "git push -f origin &> /dev/null",
    "with its output appended to a file": "git push --force origin >> push.log",
    "with its input read from a file": "git push --force origin < /dev/null",
    "with a file opened for reading and writing": (
        "git push --force origin <> /dev/null"
    ),
    "to a destination glued to a redirection": (
        "git push --force origin gh-pages>push.log"
    ),
    "to a + refspec glued to a redirection": "git push origin +HEAD:gh-pages>push.log",
    "with a redirection of both outputs before its options": (
        "git push &> /dev/null --force origin gh-pages"
    ),
    "with a clobbering redirection before its options": (
        "git push >| push.log --force origin gh-pages"
    ),
    "with its input taken from a descriptor, before its options": (
        "git push <&3 --force origin gh-pages"
    ),
    "with its errors discarded, in a shell string": (
        'bash -c "cd site && git push --force origin 2>/dev/null"'
    ),
    "with its errors discarded, in a shell string run with a cluster": (
        'bash -euo pipefail -c "cd site && git push --force origin 2>/dev/null"'
    ),
    "with its errors discarded, in a script a shell reads from a here-document": (
        "bash <<EOF\ncd site && git push --force origin 2>/dev/null\nEOF"
    ),
    "in a shell string that comes after a redirection": (
        "sh -c 2>/dev/null 'cd site && git push --force origin gh-pages'"
    ),
    "to a remote with no branch, after a continued line": (
        "git push \\\n  --force origin"
    ),
    "after an apostrophe that nothing closes": (
        "echo don't\ngit push --force origin gh-pages"
    ),
    "to a destination the text does not name": (
        'git push --force origin "HEAD:${TARGET}"'
    ),
    "to no named destination": "git push --force",
    "to HEAD, after a checkout of the branch": (
        "git checkout gh-pages && git push --force origin HEAD"
    ),
    "to @, with a lease": "git push --force-with-lease origin @",
    "to HEAD, in a shell string run with a cluster": (
        'bash -euo pipefail -c "git checkout gh-pages && git push -f origin HEAD"'
    ),
    "of every branch": "git push --force --all origin",
    "as a mirror": "git push --mirror origin",
    "as a + refspec with a wildcard destination": (
        "git push origin '+refs/heads/*:refs/heads/*'"
    ),
    "as a forced refspec with a wildcard destination": (
        "git push --force origin 'refs/heads/*:refs/heads/*'"
    ),
}

#: gh-deploy and ghp-import with their force spellings break both rules.
FORCING_PUBLISHER_CASES = {
    "gh-deploy --force": "uv run mkdocs gh-deploy --clean --force",
    "ghp-import -f": "ghp-import -p -f site",
    "ghp-import --force": "ghp-import --push --force site",
    "ghp-import with clustered options": "ghp-import -pf site",
}

#: Each of these breaks no rule. The two comment cases show that a comment is not a
#: command, and the last three that text inside quotes is not one either.
CLEAN_CASES = {
    "the versioned deploy": DEPLOY,
    "a strict build": "uv run mkdocs build --clean --strict",
    "serving a preview": "uv run mkdocs serve --no-strict",
    "a build with a config file": "uv run mkdocs build -f mkdocs.yml",
    "a plain push of gh-pages": "git push origin gh-pages",
    "a plain push of the current branch": 'git push -u origin "$BRANCH"',
    "a forced push of another branch": "git push --force origin refs/heads/preview",
    "a forced push of another branch with its errors discarded": (
        "git push --force origin preview 2>/dev/null"
    ),
    "a forced push of HEAD to another branch": "git push --force origin HEAD:preview",
    "a plain push of every branch by refspec": (
        "git push origin 'refs/heads/*:refs/heads/*'"
    ),
    "a force flag on another tool": "docker image prune --all --force",
    "a comment line naming the old command": (
        "# never run mkdocs gh-deploy --force\nuv run mkdocs build"
    ),
    "a trailing comment naming it": "uv run mkdocs build  # not mkdocs gh-deploy --force",
    "a quoted separator in an ordinary command": 'echo "a && b"',
    "a quoted separator before the text of a forced push": (
        'echo "ok; git push --force origin gh-pages; done"'
    ),
    "a quoted message over several lines": (
        'echo "Do not run:\n  git push --force origin gh-pages\nit replaces the branch"'
    ),
}

#: Each of these starts a job that publishes the site on a tag push.
TAG_REACHABLE_CASES = {
    "every tag": {"on": ON_ANY_TAG},
    "release tags": {"on": {"push": {"tags": ["v*"]}}},
    "a tag shape of its own": {"on": {"push": {"tags": ["rel-*"]}}},
    "a tag shape with a slash": {"on": {"push": {"tags": ["build/**"]}}},
    "tags beside branches": {"on": {"push": {"branches": ["main"], "tags": ["*"]}}},
    "a push with no filter": {"on": {"push": None}},
    "a push filtered by path": {"on": {"push": {"paths": ["docs/**"]}}},
    "every tag but one": {"on": {"push": {"tags-ignore": ["v3"]}}},
    "a condition that admits any push": {
        "on": ON_ANY_TAG,
        "condition": "github.event_name == 'push'",
    },
    "a condition that names tag refs": {
        "on": ON_ANY_TAG,
        "condition": "startsWith(github.ref, 'refs/tags/')",
    },
    "no permissions declared": {"on": ON_ANY_TAG, "permissions": None},
    "a read token, and a plain push of gh-pages": {
        "on": ON_ANY_TAG,
        "permissions": READ,
        "run": "git push origin gh-pages",
    },
    "a read token, and a push of gh-pages in a shell string of two commands": {
        "on": ON_ANY_TAG,
        "permissions": READ,
        "run": "sh -c 'cd site && git push origin gh-pages'",
    },
    "a read token, and a push with its errors discarded": {
        "on": ON_ANY_TAG,
        "permissions": READ,
        "run": "git push origin 2>/dev/null",
    },
    "a read token, and a push of HEAD": {
        "on": ON_ANY_TAG,
        "permissions": READ,
        "run": "git push origin HEAD",
    },
}

#: Each of these publishes the site and is reached by no tag push, or is reached by
#: one and cannot write.
TAG_UNREACHABLE_CASES = {
    "pushes to main only": {"on": ON_MAIN},
    "manual and called runs only": {
        "on": {"workflow_dispatch": None, "workflow_call": None}
    },
    "a tag trigger, and a job that admits main only": {
        "on": ON_ANY_TAG,
        "condition": "github.ref == 'refs/heads/main'",
    },
    "a tag trigger, and a job that cannot write": {
        "on": ON_ANY_TAG,
        "permissions": READ,
        "run": "uv run mkdocs build --strict",
    },
    "a tag trigger, a read token, and a push of another branch in a shell string": {
        "on": ON_ANY_TAG,
        "permissions": READ,
        "run": "sh -c 'cd site && git push origin preview'",
    },
    "a tag trigger, a read token, and a push of another branch, errors discarded": {
        "on": ON_ANY_TAG,
        "permissions": READ,
        "run": "git push origin preview 2>/dev/null",
    },
    "a tag trigger, a read token, and a push of HEAD to another branch": {
        "on": ON_ANY_TAG,
        "permissions": READ,
        "run": "git push origin HEAD:preview",
    },
}


def _nested(depth: int, script: str) -> str:
    """``script`` handed to a shell with -c, ``depth`` times over, each time quoted."""
    for _ in range(depth):
        script = f"sh -c {shlex.quote(script)}"
    return script


def _call_tree(
    root: Path,
    caller_on: dict[str, Any],
    *,
    caller_permissions: dict[str, str],
    callee_permissions: dict[str, str],
    callee_run: str,
) -> ga.Workflow:
    """A caller and the reusable workflow it calls, planted under ``root``."""
    workflows = root / ".github" / "workflows"
    callee = _workflow({"workflow_call": None}, callee_run, permissions=None)
    callee["jobs"]["publish"]["permissions"] = callee_permissions
    _plant(workflows, callee, "deploy.yml")
    caller = {
        "name": "Caller",
        "on": caller_on,
        "jobs": {
            "call": {
                "uses": "./.github/workflows/deploy.yml",
                "permissions": caller_permissions,
            }
        },
    }
    return _plant(workflows, caller, "caller.yml")


# --------------------------------------------------------------------------- tests


class TestTheWorkflowAtTheV371Commit:
    """The file that ran on 2026-11-12, planted and read like any workflow."""

    def test_the_planted_text_is_that_file(self):
        data = OLD_COPY.encode("utf-8")
        blob = hashlib.sha1(
            b"blob %d\0" % len(data) + data, usedforsecurity=False
        ).hexdigest()
        assert blob == OLD_COPY_BLOB, (
            f"the planted text hashes to the git blob {blob} ({len(data)} bytes), not "
            f"to {OLD_COPY_BLOB}, the file at the v3.7.1 release commit"
        )

    def test_it_breaks_the_rule_against_branch_replacing_publishers(self, tmp_path):
        found = violations(_workflow_unit(_old_copy(tmp_path), tmp_path))
        publishers = [v for v in found if v.rule == NO_BRANCH_REPLACING_PUBLISHER]
        assert len(publishers) == 1, _describe(found)
        assert "Deploy documentation" in publishers[0].where
        assert "'gh-deploy'" in publishers[0].message

    def test_it_breaks_the_rule_against_force_pushes(self, tmp_path):
        found = violations(_workflow_unit(_old_copy(tmp_path), tmp_path))
        forced = [v for v in found if v.rule == NO_FORCE_PUSH]
        assert len(forced) == 1, _describe(found)
        assert "mkdocs gh-deploy --clean --force" in forced[0].message

    def test_it_breaks_the_rule_against_tag_reachable_writers(self, tmp_path):
        found = violations(_workflow_unit(_old_copy(tmp_path), tmp_path))
        writers = [v for v in found if v.rule == NO_TAG_REACHABLE_WRITER]
        assert len(writers) == 1, _describe(found)
        assert "'deploy-docs'" in writers[0].where
        assert "a push of the tag" in writers[0].message

    def test_each_rule_reports_it_once_with_a_message_of_its_own(self, tmp_path):
        found = violations(_workflow_unit(_old_copy(tmp_path), tmp_path))
        assert len(found) == 3, _describe(found)
        assert {v.rule for v in found} == {
            NO_BRANCH_REPLACING_PUBLISHER,
            NO_FORCE_PUSH,
            NO_TAG_REACHABLE_WRITER,
        }
        assert len({v.message for v in found}) == 3

    def test_a_tag_push_starts_its_deploy_job(self, tmp_path):
        """The shape itself: the trigger takes the tag and the job's condition admits it."""
        workflow = _old_copy(tmp_path)
        context = _tag_push("v3")
        assert ga.triggers(workflow, context)
        started = [job.job_id for job in _reached_jobs(workflow, context, tmp_path)]
        assert "deploy-docs" in started


class TestEachRuleFlagsItsOwnShape:
    @pytest.mark.parametrize("command", _cases(PUBLISHER_CASES))
    def test_a_branch_replacing_publisher_breaks_that_rule_alone(
        self, tmp_path, command
    ):
        workflow = _plant(tmp_path, _workflow(ON_MAIN, command, permissions=READ))
        assert _rules_broken(workflow, tmp_path) == {NO_BRANCH_REPLACING_PUBLISHER}

    @pytest.mark.parametrize("command", _cases(FORCE_CASES))
    def test_a_forced_push_of_gh_pages_breaks_that_rule_alone(self, tmp_path, command):
        workflow = _plant(tmp_path, _workflow(ON_MAIN, command, permissions=READ))
        assert _rules_broken(workflow, tmp_path) == {NO_FORCE_PUSH}

    @pytest.mark.parametrize("depth", range(1, MAX_SHELL_DEPTH + 1))
    def test_a_script_inside_nested_shell_strings_is_read(self, tmp_path, depth):
        command = _nested(depth, "cd site && git push --force origin gh-pages")
        workflow = _plant(tmp_path, _workflow(ON_MAIN, command, permissions=READ))
        assert _rules_broken(workflow, tmp_path) == {NO_FORCE_PUSH}

    @pytest.mark.parametrize("command", _cases(FORCING_PUBLISHER_CASES))
    def test_a_publisher_that_forces_its_push_breaks_both_rules(
        self, tmp_path, command
    ):
        workflow = _plant(tmp_path, _workflow(ON_MAIN, command, permissions=READ))
        assert _rules_broken(workflow, tmp_path) == {
            NO_BRANCH_REPLACING_PUBLISHER,
            NO_FORCE_PUSH,
        }

    @pytest.mark.parametrize("shape", _cases(TAG_REACHABLE_CASES))
    def test_a_tag_push_that_starts_a_publishing_job_breaks_that_rule_alone(
        self, tmp_path, shape
    ):
        workflow = _plant(tmp_path, _workflow(**shape))
        assert _rules_broken(workflow, tmp_path) == {NO_TAG_REACHABLE_WRITER}

    def test_a_local_composite_action_is_read_by_the_first_two_rules(self, tmp_path):
        action = tmp_path / ".github" / "actions" / "deploy" / "action.yml"
        action.parent.mkdir(parents=True)
        steps = [{"run": "uv run mkdocs gh-deploy --clean --force", "shell": "bash"}]
        document = {"name": "Deploy", "runs": {"using": "composite", "steps": steps}}
        action.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        found = violations(_action_unit(action, tmp_path))
        assert {v.rule for v in found} == {
            NO_BRANCH_REPLACING_PUBLISHER,
            NO_FORCE_PUSH,
        }

    def test_a_tag_push_reaches_a_publisher_called_from_another_workflow(
        self, tmp_path
    ):
        caller = _call_tree(
            tmp_path,
            ON_ANY_TAG,
            caller_permissions=WRITE,
            callee_permissions=WRITE,
            callee_run=DEPLOY,
        )
        found = violations(_workflow_unit(caller, tmp_path))
        assert [v.rule for v in found] == [NO_TAG_REACHABLE_WRITER], _describe(found)
        assert "deploy.yml" in found[0].where
        assert "caller.yml" in found[0].where


class TestTheSafeShapesBreakNoRule:
    @pytest.mark.parametrize("command", _cases(CLEAN_CASES))
    def test_a_command_that_is_none_of_the_three_shapes(self, tmp_path, command):
        workflow = _plant(tmp_path, _workflow(ON_MAIN, command))
        found = violations(_workflow_unit(workflow, tmp_path))
        assert not found, _describe(found)

    @pytest.mark.parametrize("shape", _cases(TAG_UNREACHABLE_CASES))
    def test_a_publisher_no_tag_push_reaches(self, tmp_path, shape):
        workflow = _plant(tmp_path, _workflow(**shape))
        found = violations(_workflow_unit(workflow, tmp_path))
        assert not found, _describe(found)

    def test_a_publisher_called_only_from_a_push_to_main(self, tmp_path):
        caller = _call_tree(
            tmp_path,
            ON_MAIN,
            caller_permissions=WRITE,
            callee_permissions=WRITE,
            callee_run=DEPLOY,
        )
        found = violations(_workflow_unit(caller, tmp_path))
        assert not found, _describe(found)

    def test_a_called_job_cannot_write_more_than_its_caller_allows(self, tmp_path):
        caller = _call_tree(
            tmp_path,
            ON_ANY_TAG,
            caller_permissions=READ,
            callee_permissions=WRITE,
            callee_run="echo nothing is published",
        )
        found = violations(_workflow_unit(caller, tmp_path))
        assert not found, _describe(found)


class TestTheRealFiles:
    @pytest.mark.parametrize("name", WORKFLOW_FILES)
    def test_a_real_workflow_breaks_no_rule(self, name):
        workflow = ga.load_workflow(ga.WORKFLOWS_DIR / name)
        found = violations(_workflow_unit(workflow, ga.REPO_ROOT))
        assert not found, f"{name} breaks a rule:\n{_describe(found)}"

    @pytest.mark.parametrize("relative", ACTION_FILES)
    def test_a_real_composite_action_breaks_no_rule(self, relative):
        found = violations(_action_unit(ga.REPO_ROOT / relative, ga.REPO_ROOT))
        assert not found, f"{relative} breaks a rule:\n{_describe(found)}"

    def test_the_controls_read_the_docs_workflow(self):
        assert DOCS_WORKFLOW in WORKFLOW_FILES
        assert len(WORKFLOW_FILES) > 1

    def test_a_push_to_main_reaches_the_real_publisher_and_no_tag_push_does(self):
        """The control: the checks above read a deploy job, and it is reached by main."""
        workflow = ga.load_workflow(ga.WORKFLOWS_DIR / DOCS_WORKFLOW)
        reached = _reached_jobs(workflow, _branch_push("main"), ga.REPO_ROOT)
        writers = [job for job in reached if _writes_gh_pages(job) is not None]
        assert writers, (
            "a push to main no longer reaches a job that can write gh-pages, so the "
            "checks against tag pushes would compare nothing"
        )
        assert any(_publishes(step.run) for job in writers for step in job.steps), (
            "no step of the job that main's push starts is recognized as publishing "
            "the site, so the publisher check would pass whatever it ran"
        )
        for name in _tag_names(workflow):
            assert not ga.triggers(workflow, _tag_push(name)), (
                f"a push of the tag {name!r} starts {DOCS_WORKFLOW}, whose deploy "
                "job holds a token that can write gh-pages"
            )
