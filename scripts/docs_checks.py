# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Static checks for the code blocks, commands, links and navigation in ASH's docs.

Loaded by path from scripts/verify_docs_freshness.py, which registers each public
``check_*`` function below as one of its checks, and from the docs-example runner in
tests/integration/docs/, which uses the same block parser to decide what to execute.
scripts/ is not a package, so nothing here is imported by name.

The contract these checks implement is the contributor page
docs/content/contributing/documentation.md. In short: a fenced block may carry a
marker on the line directly above it,

    <!-- doctest: <mode> [key=value | key="quoted value"]... -->

and every block is checked according to its language and marker. Every ``ash``
command line in the docs, in a block or an inline code span, is parsed against the
real click tree; every ``ASH_*`` name is compared with the environment variables ASH
reads; every config block is validated by ASH's own models; every link and anchor
must resolve; every page must be in the navigation or deliberately left out of it.

Why one module rather than eight more functions in verify_docs_freshness.py: those
checks share a markdown block parser, a shell word splitter and three expensive
models of the code (the click tree, the env-var read set, the config plugin
registry), and the runner needs the parser too. Keeping them together keeps one
answer to "what is a block" for the checks and the runner.

Every check is generic over the corpus it is handed. Page paths appear only in the
constants block directly below, so a reorganized docs tree changes those constants
and nothing else.
"""

from __future__ import annotations

import ast
import difflib
import fnmatch
import functools
import importlib
import importlib.util
import json
import logging
import os
import posixpath
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator
from urllib.parse import unquote, urlsplit

# ---------------------------------------------------------------------------
# Layout constants. Everything that names a page, a directory or a URL lives here.
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent

#: The mkdocs config. docs_dir, the nav plugin, not_in_nav, validation and hooks are
#: all read from it rather than restated here.
MKDOCS_YML = "mkdocs.yml"

#: The awesome-nav file name. One may sit in any directory under docs_dir.
NAV_FILE_NAME = ".nav.yml"

#: Old page path (relative to docs_dir) -> the page it moved to. Read by the mkdocs
#: hook that writes the redirect pages, and checked here.
REDIRECTS_FILE = "docs/redirects.yml"

#: The mkdocs hook that turns REDIRECTS_FILE into redirect pages.
REDIRECT_HOOK = "docs/hooks/redirects.py"

#: The workflow whose build job must run ``mkdocs build --strict``.
DOCS_WORKFLOW = ".github/workflows/ash-repo-docs.yml"

#: Fixture projects the docs-example runner can start a page in. ``fixture=<name>``
#: on a marker names a directory here.
DOC_FIXTURES_DIR = "tests/test_data/docs_fixtures"
DEFAULT_FIXTURE = "sample-project"

#: The repository's pre-commit hook manifest, for ``config kind=pre-commit``.
PRE_COMMIT_HOOKS = ".pre-commit-hooks.yaml"

#: Where this repository is published. Links to repository files from docs pages
#: use the blob/tree forms of this URL; links to the site use SITE_URL.
GITHUB_REPO_URL = "https://github.com/awslabs/automated-security-helper"
GITHUB_REPO_SLUG = "awslabs/automated-security-helper"

#: Records of past releases. Their entries describe the CLI and variables as they were
#: then, so the checks that compare against today's code skip them; markers, config,
#: python and link checks still apply.
HISTORICAL_DOCS = frozenset({"CHANGELOG.md"})

#: Template placeholder the version manager renders (scripts/version_template_manager.py).
VERSION_PLACEHOLDER = "{{VERSION}}"

# ---------------------------------------------------------------------------
# Block languages and markers
# ---------------------------------------------------------------------------

SHELL_LANGS = frozenset(
    {
        "bash",
        "sh",
        "shell",
        "console",
        "zsh",
        "powershell",
        "pwsh",
        "ps1",
        "cmd",
        "bat",
        "fish",
    }
)
#: There is no Windows runner in the docs job, so these can only be illustrative.
WINDOWS_SHELLS = frozenset({"powershell", "pwsh", "ps1", "cmd", "bat"})
#: The runner executes these with bash. zsh and fish blocks would need their own
#: interpreter in CI, so they are illustrative-only like the Windows shells.
RUNNER_SHELLS = frozenset({"bash", "sh", "shell", "console"})
CONFIG_LANGS = frozenset({"yaml", "yml", "json", "jsonc", "toml"})
PYTHON_LANGS = frozenset({"python", "py"})
DOCKERFILE_LANGS = frozenset({"dockerfile", "containerfile"})

#: ``config kind=<kind>``: the kinds that are an ASH config, and the extra keys each kind
#: takes. ``reason`` is required where listed.
ASH_CONFIG_KINDS = {
    "ash": set(),
    "ash-fragment": {"at"},
    "pyproject": set(),
    "ash-invalid": {"reason"},
}
#: Kinds that are some other program's file. Each must parse; the value is the set of
#: mapping keys whose string values are shell commands, which get the CLI checks.
OTHER_CONFIG_KINDS = {
    "github-actions": {"run"},
    "gitlab-ci": {"script", "before_script", "after_script"},
    "buildspec": {"commands"},
    "azure-pipelines": {"script", "bash"},
    "jenkins": {"sh", "script"},
    "docker-compose": {"command", "entrypoint"},
    "pre-commit": set(),
    "mcp-client": set(),
    "ash-output": set(),
    "other": set(),
}
REQUIRED_REASON_KINDS = frozenset({"ash-invalid", "other"})

RUN_KEYS = frozenset({"expect-exit", "fixture", "env", "timeout", "fresh"})
#: Bare words a marker may carry without ``=value``.
BARE_KEYS = frozenset({"fresh"})
DEFAULT_TIMEOUT_S = 60
MAX_TIMEOUT_S = 900

#: Reasons that say nothing. Compared after lowercasing and stripping punctuation.
PLACEHOLDER_REASONS = frozenset(
    {
        "",
        "todo",
        "tbd",
        "na",
        "n/a",
        "none",
        "fixme",
        "xxx",
        "placeholder",
        "reason",
        "wip",
        "later",
        "skip",
    }
)

_MARKER_LINE = re.compile(r"^\s*<!--\s*doctest\b")
_MARKER_FULL = re.compile(r"^\s*<!--\s*doctest:(?P<body>.*?)-->\s*$")
_FENCE_OPEN = re.compile(r"^(?P<indent>[ \t]*)(?P<fence>`{3,}|~{3,})(?P<info>.*)$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class Finding:
    """One problem, at one place. ``str()`` is the line a contributor reads."""

    check: str
    path: str
    line: int
    message: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: [{self.check}] {self.message}"


@dataclass
class Marker:
    mode: str
    keys: dict[str, Any]
    line: int


@dataclass
class Block:
    """A fenced code block, with the marker that governs it if there is one."""

    path: Path
    lang: str
    info: str
    fence_line: int
    body: str
    body_line: int
    indent: str
    closed: bool
    marker: Marker | None = None

    @property
    def family(self) -> str:
        if self.lang in SHELL_LANGS:
            return "shell"
        if self.lang in CONFIG_LANGS:
            return "config"
        if self.lang in PYTHON_LANGS:
            return "python"
        if self.lang in DOCKERFILE_LANGS:
            return "dockerfile"
        return "other"

    @property
    def mode(self) -> str:
        """The effective mode: the marker's, or the unmarked default for the family."""
        if self.marker is not None:
            return self.marker.mode
        return {"shell": "run", "python": "run", "config": "config"}.get(
            self.family, ""
        )

    @property
    def config_kind(self) -> str:
        if self.marker is not None and self.marker.mode == "config":
            return str(self.marker.keys.get("kind", ""))
        return "ash"

    def body_lines(self) -> list[tuple[int, str]]:
        return [
            (self.body_line + i, text) for i, text in enumerate(self.body.split("\n"))
        ]


@dataclass
class Page:
    path: Path
    rel: str
    text: str
    blocks: list[Block] = field(default_factory=list)
    #: (line number, text) for every line outside a fence, marker lines excluded.
    prose: list[tuple[int, str]] = field(default_factory=list)
    #: Problems found while splitting the page: markers with no block, unclosed fences.
    structure: list[Finding] = field(default_factory=list)


def rel_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


# ---------------------------------------------------------------------------
# Which tree the code comes from
# ---------------------------------------------------------------------------
#
# The docs and the code may come from different checkouts: a docs rewrite describes
# code that is not on main yet, so its pages are checked against another tree's ASH.
# Every check is handed a docs root, and markdown, the nav, mkdocs.yml, the redirect
# map and the runner's fixtures come from there. Everything about the code comes from
# the ASH the interpreter imports: the click tree, the config models, the environment
# variables it reads, and the files shipped beside the package (.pre-commit-hooks.yaml,
# action.yml files). With one checkout, the two are the same tree.


@functools.lru_cache(maxsize=1)
def installed_package_dir() -> Path:
    """The automated_security_helper package this interpreter imports, without importing it."""
    spec = importlib.util.find_spec(ASH_MODULE)
    if spec is None or not spec.submodule_search_locations:
        raise RuntimeError(f"this interpreter cannot import {ASH_MODULE}")
    return Path(next(iter(spec.submodule_search_locations))).resolve()


def code_root(docs_root: Path) -> Path:
    """The checkout the installed ASH comes from, or docs_root when it is not a checkout.

    An editable install (uv sync, pip install -e) imports the package from a checkout,
    whose root holds pyproject.toml. A wheel install has no checkout; the files the
    code ships beside the package are then read from docs_root.
    """
    try:
        parent = installed_package_dir().parent
    except RuntimeError:
        return docs_root
    return parent if (parent / "pyproject.toml").is_file() else docs_root


@functools.lru_cache(maxsize=None)
def current_version(root: str) -> str:
    """The version templates render to, from [tool.commitizen] like the version manager."""
    pyproject = Path(root) / "pyproject.toml"
    if not pyproject.is_file():
        return "0.0.0"
    text = pyproject.read_text(encoding="utf-8")
    table = re.search(
        r"^\[tool\.commitizen\]\n(.*?)(?=^\[|\Z)", text, re.MULTILINE | re.DOTALL
    )
    match = re.search(
        r'^version\s*=\s*"([^"]+)"', table.group(1) if table else "", re.MULTILINE
    )
    return match.group(1) if match else "0.0.0"


def _parse_marker(body: str, line: int) -> tuple[Marker | None, str | None]:
    """Split ``<mode> key=value key="v w" bare`` into a Marker, or say why it cannot."""
    import shlex

    try:
        words = shlex.split(body)
    except ValueError as exc:
        return None, f"marker cannot be split into words ({exc}); check its quotes"
    if not words:
        return None, "marker names no mode; write <!-- doctest: <mode> ... -->"
    mode, keys = words[0], {}
    for word in words[1:]:
        key, sep, value = word.partition("=")
        if not sep:
            if key in BARE_KEYS:
                keys[key] = True
                continue
            return (
                None,
                f"marker word '{word}' is neither key=value nor a known bare word",
            )
        if key in keys:
            return None, f"marker sets '{key}' twice"
        keys[key] = value
    return Marker(mode=mode, keys=keys, line=line), None


def parse_page(path: Path, root: Path, text: str | None = None) -> Page:
    """Split a markdown file into fenced blocks and prose, attaching markers to blocks.

    A marker binds to the fence on the very next line. Blank lines in between are an
    error rather than tolerated, so a marker can never drift onto the wrong block when
    the text around it is edited.
    """
    if text is None:
        text = path.read_text(encoding="utf-8")
    if path.name.endswith(".md.template"):
        text = text.replace(VERSION_PLACEHOLDER, current_version(str(root)))
    rel = rel_path(path, root)
    page = Page(path=path, rel=rel, text=text)
    lines = text.split("\n")
    pending: Marker | None = None
    pending_line = 0
    index = 0

    def flush_pending(reason: str) -> None:
        nonlocal pending
        if pending is not None:
            page.structure.append(Finding("markers", rel, pending_line, reason))
        pending = None

    while index < len(lines):
        line = lines[index]
        lineno = index + 1
        opened = _FENCE_OPEN.match(line)
        if opened and not (
            opened.group("fence")[0] == "`" and "`" in opened.group("info")
        ):
            fence = opened.group("fence")
            info = opened.group("info").strip()
            indent = opened.group("indent")
            body: list[str] = []
            closed = False
            scan = index + 1
            while scan < len(lines):
                candidate = lines[scan]
                stripped = candidate.strip()
                if stripped.startswith(fence[0] * len(fence)) and set(stripped) == {
                    fence[0]
                }:
                    closed = True
                    break
                body.append(
                    candidate[len(indent) :]
                    if candidate.startswith(indent)
                    else candidate.lstrip()
                )
                scan += 1
            block = Block(
                path=path,
                lang=_fence_language(info),
                info=info,
                fence_line=lineno,
                body="\n".join(body),
                body_line=lineno + 1,
                indent=indent,
                closed=closed,
                marker=pending,
            )
            pending = None
            page.blocks.append(block)
            if not closed:
                page.structure.append(
                    Finding(
                        "markers",
                        rel,
                        lineno,
                        "this fence is never closed, so the rest of the page is one code block",
                    )
                )
            index = scan + 1
            continue

        if _MARKER_LINE.match(line):
            flush_pending("marker is not directly followed by a fenced code block")
            full = _MARKER_FULL.match(line)
            if not full:
                page.structure.append(
                    Finding(
                        "markers",
                        rel,
                        lineno,
                        "malformed marker; it must be one line: <!-- doctest: <mode> key=value -->",
                    )
                )
            else:
                marker, error = _parse_marker(full.group("body"), lineno)
                if error:
                    page.structure.append(Finding("markers", rel, lineno, error))
                else:
                    pending, pending_line = marker, lineno
                    following = lines[index + 1] if index + 1 < len(lines) else None
                    if following is not None and not following.strip():
                        page.structure.append(
                            Finding(
                                "markers",
                                rel,
                                lineno,
                                "a blank line separates this marker from the block below it; "
                                "the marker must be on the line directly above the opening fence",
                            )
                        )
                        pending = None
            index += 1
            continue

        flush_pending("marker is not directly followed by a fenced code block")
        page.prose.append((lineno, line))
        index += 1

    flush_pending("marker is the last line of the page, with no block after it")
    return page


def _fence_language(info: str) -> str:
    """The language word of a fence info string: ``yaml title="x"`` and ``{.yaml}`` give yaml."""
    word = info.split()[0] if info.split() else ""
    word = word.strip("{}").lstrip(".")
    return word.lower()


def load_pages(files: Iterable[Path], root: Path) -> list[Page]:
    """Parse every file afresh. Cheap (about 50 ms for the whole corpus), and a cache
    keyed on modification time would serve a stale parse on a filesystem whose clock
    is coarser than two writes in a test."""
    return [parse_page(path, root) for path in files]


# ---------------------------------------------------------------------------
# Check: markers and block languages
# ---------------------------------------------------------------------------


def _reason_problem(value: Any) -> str | None:
    if not isinstance(value, str):
        return 'reason must be a quoted sentence, for example reason="needs Docker"'
    folded = re.sub(r"[^a-z/]+", "", value.lower())
    if folded in PLACEHOLDER_REASONS or not re.search(r"[A-Za-z]{3}", value):
        return f"reason {value!r} is a placeholder; say why the block cannot run"
    return None


def _run_key_problems(marker: Marker, root: Path) -> list[str]:
    problems = []
    for key, value in marker.keys.items():
        if key not in RUN_KEYS:
            problems.append(
                f"'{key}' is not a key of run; allowed: {', '.join(sorted(RUN_KEYS))}"
            )
            continue
        if key == "expect-exit" and not (
            value in ("nonzero", "any")
            or (isinstance(value, str) and value.isdigit() and int(value) < 256)
        ):
            problems.append(f"expect-exit={value} must be 0-255, nonzero or any")
        if key == "timeout":
            try:
                seconds = float(value)
            except (TypeError, ValueError):
                seconds = -1
            if not 0 < seconds <= MAX_TIMEOUT_S:
                problems.append(
                    f"timeout={value} must be a number of seconds from 1 to {MAX_TIMEOUT_S}"
                )
        if key == "fixture":
            if (
                not isinstance(value, str)
                or not (root / DOC_FIXTURES_DIR / value).is_dir()
            ):
                known = sorted(
                    p.name for p in (root / DOC_FIXTURES_DIR).glob("*") if p.is_dir()
                )
                problems.append(
                    f"fixture={value} names no directory in {DOC_FIXTURES_DIR}; known: {known}"
                )
        if key == "env":
            for pair in str(value).split(","):
                name, sep, _ = pair.strip().partition("=")
                if not sep or not _ENV_NAME.match(name):
                    problems.append(f"env entry {pair!r} must be NAME=value")
    return problems


def marker_problems(block: Block, root: Path) -> list[str]:
    """Everything wrong with how a block is labeled and marked."""
    problems: list[str] = []
    marker, lang, family = block.marker, block.lang, block.family
    if not block.info:
        problems.append(
            "fenced block has no language. Name one (text for output samples), so a "
            "command or config in it cannot escape every check"
        )
    if lang in ("pycon", "python-repl"):
        problems.append("doctest-style >>> blocks are not used; write a python block")
    if marker is None:
        if lang in WINDOWS_SHELLS or lang in ("zsh", "fish"):
            problems.append(
                f"{lang} blocks cannot run in the docs job (it executes bash on Linux); "
                f'mark it <!-- doctest: illustrative reason="..." -->'
            )
        return problems

    mode, keys = marker.mode, marker.keys
    if family == "shell" or family == "python":
        if mode == "run":
            problems += _run_key_problems(marker, root)
            if lang in WINDOWS_SHELLS or lang in ("zsh", "fish"):
                problems.append(
                    f"{lang} blocks may only be illustrative; the docs runner executes bash"
                )
        elif mode == "illustrative":
            extra = set(keys) - {"reason"}
            if extra:
                problems.append(f"illustrative takes only reason=, not {sorted(extra)}")
            if "reason" not in keys:
                problems.append(
                    'illustrative needs reason="..." saying why the block cannot run'
                )
            else:
                reason = _reason_problem(keys["reason"])
                if reason:
                    problems.append(reason)
        else:
            problems.append(
                f"unknown mode '{mode}' for a {lang} block; use run or illustrative"
            )
    elif family == "config":
        if mode != "config":
            problems.append(
                f"unknown mode '{mode}' for a {lang} block; use config kind=<kind>"
            )
            return problems
        kind = keys.get("kind")
        allowed = (
            ASH_CONFIG_KINDS.get(kind, set())
            if kind in ASH_CONFIG_KINDS
            else ({"reason"} if kind in REQUIRED_REASON_KINDS else set())
        )
        if kind is None:
            problems.append("config needs kind=<kind>")
        elif kind not in ASH_CONFIG_KINDS and kind not in OTHER_CONFIG_KINDS:
            known = sorted(set(ASH_CONFIG_KINDS) | set(OTHER_CONFIG_KINDS))
            problems.append(f"unknown config kind '{kind}'; known: {', '.join(known)}")
        else:
            extra = set(keys) - {"kind"} - allowed
            if extra:
                problems.append(f"config kind={kind} does not take {sorted(extra)}")
            if kind in REQUIRED_REASON_KINDS:
                if "reason" not in keys:
                    problems.append(f'config kind={kind} needs reason="..."')
                else:
                    reason = _reason_problem(keys["reason"])
                    if reason:
                        problems.append(reason)
            if kind == "ash-fragment":
                at = keys.get("at")
                if not isinstance(at, str) or not re.match(
                    r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$", at
                ):
                    problems.append(
                        "config kind=ash-fragment needs at=<dotted.path>, e.g. at=scanners.bandit"
                    )
            if kind == "pyproject" and lang != "toml":
                problems.append("config kind=pyproject is a toml block")
    else:
        problems.append(
            f"markers apply to shell, python and config blocks; a {lang or 'unlabeled'} block "
            "is never executed or validated, so this marker does nothing"
        )
    return problems


def check_markers(files: Iterable[Path], root: Path = REPO_ROOT) -> list[Finding]:
    """Markers are well formed, bind to a block, and suit the block they govern."""
    findings: list[Finding] = []
    for page in load_pages(files, root):
        findings += page.structure
        for block in page.blocks:
            line = block.marker.line if block.marker else block.fence_line
            for problem in marker_problems(block, root):
                findings.append(Finding("markers", page.rel, line, problem))
    return findings


# ---------------------------------------------------------------------------
# Shell word splitting
# ---------------------------------------------------------------------------

#: Operators that end a simple command.
_COMMAND_SEPARATORS = frozenset(
    {"&&", "||", ";", ";;", "|", "|&", "&", "(", ")", "{", "}", "\n"}
)
#: Redirections. Each is followed by one word (its target), which is dropped with it.
_REDIRECTS = frozenset({">", ">>", "<", "<<<", "&>", "&>>", ">&", "<&", ">|", "<>"})
_OPERATORS = sorted(
    _COMMAND_SEPARATORS - {"\n", "{", "}"} | _REDIRECTS | {"<<", "<<-"},
    key=len,
    reverse=True,
)
#: Words that start a compound command or negate one; the command proper follows.
_SHELL_KEYWORDS = frozenset(
    {
        "if",
        "then",
        "else",
        "elif",
        "fi",
        "do",
        "done",
        "while",
        "until",
        "!",
        "{",
        "}",
        "time",
    }
)


_PLACEHOLDER_AT = re.compile(r"<[A-Za-z][\w.:/|=-]*>")


@dataclass
class ShellCommand:
    words: list[str]
    #: Command substitutions inside the words, each analyzed as its own script.
    substitutions: list[str] = field(default_factory=list)
    #: Zero-based line, within the script, that the command starts on.
    line: int = 0


def _read_substitution(text: str, start: int, closer: str) -> int:
    """Index just past the closer of a $( or backtick opened before ``start``."""
    depth, index, quote = 1, start, ""
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\" and quote == '"':
                index += 2
                continue
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char == "\\":
            index += 2
            continue
        elif closer == ")" and text.startswith("$(", index):
            depth += 1
            index += 2
            continue
        elif char == closer:
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return len(text)


def split_shell(script: str) -> list[ShellCommand]:
    """Split a shell script into simple commands of words, the way a reader means it.

    Not a shell, and not trying to be one. It handles what docs contain: quotes,
    backslash-newline continuations, comments, ``&&``/``||``/``;``/pipes, redirections,
    ``$(...)`` and backtick substitutions (returned for separate analysis) and here
    documents (whose bodies are skipped, since they are data rather than commands).
    shlex is not used because it ends a word at ``#`` (``a#b`` is one word to a shell)
    and splits ``$(`` into pieces.
    """
    commands: list[ShellCommand] = []
    words: list[str] = []
    substitutions: list[str] = []
    word: list[str] = []
    in_word = False
    heredocs: list[str] = []
    index = 0
    start = -1
    text = script.replace("\r\n", "\n")

    def end_word() -> None:
        nonlocal in_word
        if in_word:
            words.append("".join(word))
        word.clear()
        in_word = False

    def end_command() -> None:
        nonlocal start
        end_word()
        if words or substitutions:
            line = text.count("\n", 0, start) if start >= 0 else 0
            commands.append(ShellCommand(list(words), list(substitutions), line))
        words.clear()
        substitutions.clear()
        start = -1

    while index < len(text):
        char = text[index]
        if start < 0 and not words and not in_word and char not in " \t\n#":
            start = index
        if char == "\\" and index + 1 < len(text):
            if text[index + 1] == "\n":
                index += 2
                continue
            word.append(text[index + 1])
            in_word = True
            index += 2
            continue
        if char == "'":
            close = text.find("'", index + 1)
            close = len(text) if close < 0 else close
            word.append(text[index + 1 : close])
            in_word = True
            index = close + 1
            continue
        if char == '"':
            index += 1
            in_word = True
            while index < len(text) and text[index] != '"':
                if (
                    text[index] == "\\"
                    and index + 1 < len(text)
                    and text[index + 1] in '"\\$`\n'
                ):
                    if text[index + 1] != "\n":
                        word.append(text[index + 1])
                    index += 2
                    continue
                if text.startswith("$(", index):
                    end = _read_substitution(text, index + 2, ")")
                    substitutions.append(text[index + 2 : end - 1])
                    word.append(text[index:end])
                    index = end
                    continue
                word.append(text[index])
                index += 1
            index += 1
            continue
        if text.startswith("$(", index) and not text.startswith("$((", index):
            end = _read_substitution(text, index + 2, ")")
            substitutions.append(text[index + 2 : end - 1])
            word.append(text[index:end])
            in_word = True
            index = end
            continue
        if char == "`":
            end = _read_substitution(text, index + 1, "`")
            substitutions.append(text[index + 1 : end - 1])
            word.append(text[index:end])
            in_word = True
            index = end
            continue
        if char == "#" and not in_word:
            newline = text.find("\n", index)
            index = len(text) if newline < 0 else newline
            continue
        if char in " \t":
            end_word()
            index += 1
            continue
        if char == "\n":
            end_command()
            index += 1
            if heredocs:
                # Skip every here-document body opened on the line just ended.
                for delimiter in heredocs:
                    while index < len(text):
                        newline = text.find("\n", index)
                        line_end = len(text) if newline < 0 else newline
                        line = text[index:line_end]
                        index = line_end + 1
                        if line.strip() == delimiter:
                            break
                heredocs.clear()
            continue
        if char == "<":
            # <path> in a docs command is a placeholder for a value, not a redirection.
            placeholder = _PLACEHOLDER_AT.match(text, index)
            if placeholder:
                word.append(placeholder.group(0))
                in_word = True
                index = placeholder.end()
                continue
        operator = next((op for op in _OPERATORS if text.startswith(op, index)), None)
        if operator and not (operator in ("(", ")") and in_word):
            if operator in _REDIRECTS or operator in ("<<", "<<-"):
                # A file-descriptor prefix ("2>") is part of the redirection.
                if in_word and "".join(word).isdigit():
                    word.clear()
                    in_word = False
                end_word()
                index += len(operator)
                # The target is the next word; read it now and drop it.
                while index < len(text) and text[index] in " \t":
                    index += 1
                target_start = index
                while index < len(text) and text[index] not in " \t\n;&|()<>":
                    index += 1
                target = text[target_start:index].strip("'\"")
                if operator in ("<<", "<<-") and target:
                    heredocs.append(target)
                continue
            end_word()
            index += len(operator)
            end_command()
            continue
        word.append(char)
        in_word = True
        index += 1

    end_command()
    return commands


def console_commands(body: str) -> str:
    """The command part of a console block: prompt lines, with their continuations.

    A console block shows commands after a ``$`` prompt and their output after them. If
    no line has a prompt, the whole block is commands.
    """
    lines = body.split("\n")
    if not any(line.startswith("$ ") or line == "$" for line in lines):
        return body
    kept: list[str] = []
    continuing = False
    for line in lines:
        if line.startswith("$ ") or line == "$":
            kept.append(line[2:])
            continuing = line.rstrip().endswith("\\")
        elif continuing:
            kept.append(line)
            continuing = line.rstrip().endswith("\\")
        else:
            kept.append("")
    return "\n".join(kept)


# ---------------------------------------------------------------------------
# The CLI model
# ---------------------------------------------------------------------------

ASH_PROGRAMS = frozenset({"ash", "ashv3", "automated-security-helper"})
ASH_PACKAGE = "automated-security-helper"
ASH_MODULE = "automated_security_helper"
CONTAINER_RUNTIMES = frozenset({"docker", "podman", "finch", "nerdctl"})


@dataclass
class CliOption:
    names: tuple[str, ...]
    takes_value: bool
    nargs: int = 1


@dataclass
class CliCommand:
    path: tuple[str, ...]
    options: dict[str, CliOption]
    max_args: int | None
    subcommands: dict[str, "CliCommand"]
    #: True when click is told to pass unknown options through (scan and
    #: build-image forward them to the ASH inside the container).
    forwards_unknown: bool = False

    @property
    def display(self) -> str:
        return " ".join(self.path)


def _command_from_click(cmd: Any, path: tuple[str, ...]) -> CliCommand:
    options: dict[str, CliOption] = {}
    max_args: int | None = 0
    for param in cmd.params:
        if param.param_type_name == "option":
            takes_value = not (param.is_flag or getattr(param, "count", False))
            option = CliOption(
                names=tuple(param.opts) + tuple(param.secondary_opts),
                takes_value=takes_value,
                nargs=max(1, getattr(param, "nargs", 1) or 1),
            )
            for name in option.names:
                options[name] = option
        elif param.param_type_name == "argument":
            if param.nargs == -1 or max_args is None:
                max_args = None
            else:
                max_args += param.nargs
    help_names = cmd.context_settings.get("help_option_names", ["--help"])
    for name in help_names:
        options[name] = CliOption(names=tuple(help_names), takes_value=False)
    subcommands = {}
    for name, sub in sorted(getattr(cmd, "commands", {}).items()):
        subcommands[name] = _command_from_click(sub, path + (name,))
    return CliCommand(
        path=path,
        options=options,
        max_args=max_args,
        subcommands=subcommands,
        forwards_unknown=bool(cmd.context_settings.get("ignore_unknown_options")),
    )


@functools.lru_cache(maxsize=1)
def load_cli() -> CliCommand:
    """The real command tree, from typer's own conversion of the ASH app."""
    import typer

    from automated_security_helper.cli.main import app

    return _command_from_click(typer.main.get_command(app), ("ash",))


def all_option_names(command: CliCommand) -> set[str]:
    names = set(command.options)
    for sub in command.subcommands.values():
        names |= all_option_names(sub)
    return names


_PLACEHOLDER_WORD = re.compile(r"^(<[^<>]+>|\[.*|.*\]|\.\.\.|…)$")


def _is_placeholder(word: str) -> bool:
    """Synopsis notation: <value>, [OPTIONAL ...] (split across words or not), and ..."""
    return bool(_PLACEHOLDER_WORD.match(word))


def ash_args_problems(
    args: list[str], cli: CliCommand, complete: bool = True
) -> list[str]:
    """Problems with one ``ash`` invocation's arguments, judged as click would parse them.

    Options before a subcommand belong to the group, options after it to the
    subcommand: click groups do not accept their own options after the subcommand name.
    Where the command forwards unknown options to the ASH inside a container (scan,
    build-image), an option that is not the command's own must be one the root command
    accepts, since that is what receives it.

    ``complete`` is False for an inline code span, where ```ash --config``` names
    an option in prose rather than running a command, so a missing value is not
    reported there.
    """
    problems: list[str] = []
    command = cli
    positionals = 0
    index = 0
    while index < len(args):
        word = args[index]
        if word == "--":
            break
        if _is_placeholder(word) or "$" in word.partition("=")[0]:
            index += 1
            continue
        if word.startswith("-") and len(word) > 1 and not word[1:].isdigit():
            used, problem = _match_option(command, args, index, cli, complete)
            if problem:
                problems.append(problem)
                # An unknown option's value would otherwise be read as a subcommand
                # or positional argument, reporting one mistake several times.
                if (
                    used == 1
                    and "=" not in word
                    and index + 1 < len(args)
                    and not args[index + 1].startswith("-")
                ):
                    used = 2
            index += used
            continue
        if command.subcommands:
            sub = command.subcommands.get(word)
            if sub is None:
                close = difflib.get_close_matches(word, list(command.subcommands), n=1)
                hint = f"; did you mean '{close[0]}'?" if close else ""
                problems.append(
                    f"'{command.display} {word}': {command.display} has no subcommand '{word}'{hint}"
                )
                return problems
            command = sub
            positionals = 0
            index += 1
            continue
        positionals += 1
        if command.max_args is not None and positionals > command.max_args:
            problems.append(
                f"'{command.display}' takes {command.max_args or 'no'} positional "
                f"argument{'s' if command.max_args != 1 else ''}, but '{word}' is one more"
            )
        index += 1
    return problems


def _match_option(
    command: CliCommand, args: list[str], index: int, cli: CliCommand, complete: bool
) -> tuple[int, str | None]:
    word = args[index]
    name, has_inline, _value = word.partition("=")
    option = command.options.get(name)
    if option is None and command.forwards_unknown:
        option = cli.options.get(name)
    if option is not None:
        if has_inline and not option.takes_value:
            return 1, f"'{command.display} {word}': {name} is a flag and takes no value"
        if option.takes_value and not has_inline:
            if complete and index + option.nargs >= len(args):
                return (
                    1 + option.nargs,
                    f"'{command.display} {word}': {name} needs a value",
                )
            return 1 + option.nargs, None
        return 1, None
    if not word.startswith("--") and len(word) > 2:
        # Short options cluster: -vd is -v -d; -ofile is -o with the value "file".
        for position, letter in enumerate(word[1:], start=1):
            short = command.options.get(f"-{letter}")
            if short is None:
                break
            if short.takes_value:
                return (1 if position < len(word) - 1 else 2), None
        else:
            return 1, None
    known = sorted({n for n in command.options if n.startswith("--")})
    close = difflib.get_close_matches(name, known, n=1)
    hint = f"; did you mean {close[0]}?" if close else ""
    return (
        1,
        f"'{command.display} {word}': {name} is not an option of '{command.display}'{hint}",
    )


# ---------------------------------------------------------------------------
# Finding ash invocations inside commands
# ---------------------------------------------------------------------------

_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
#: Options that take a value, for the wrappers whose own options precede the program.
_UV_VALUE_OPTIONS = frozenset(
    {
        "--from",
        "--with",
        "--with-editable",
        "--with-requirements",
        "--python",
        "-p",
        "--index",
        "--index-url",
        "--extra-index-url",
        "--default-index",
        "--cache-dir",
        "--directory",
        "--project",
        "--config-file",
        "--constraints",
        "-c",
        "--overrides",
        "--env-file",
        "--extra",
        "--group",
        "--only-group",
        "--no-group",
        "--package",
        "--color",
        "-w",
        "--python-preference",
        "--build-constraints",
        "--refresh-package",
        "--reinstall-package",
        "--upgrade-package",
        "-P",
        "--exclude-newer",
        "--prerelease",
        "--resolution",
        "--link-mode",
    }
)
_PIPX_VALUE_OPTIONS = frozenset(
    {"--spec", "--python", "--index-url", "-i", "--pip-args", "--backend"}
)
_SUDO_VALUE_OPTIONS = frozenset({"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"})
#: docker run options that are flags. Every other option takes a value.
_CONTAINER_RUN_FLAGS = frozenset(
    {
        "--rm",
        "-i",
        "-t",
        "-it",
        "-ti",
        "-d",
        "--init",
        "--privileged",
        "--read-only",
        "-P",
        "--tty",
        "--interactive",
        "--detach",
        "--no-healthcheck",
        "--oom-kill-disable",
        "--sig-proxy",
        "-q",
        "--quiet",
        "--publish-all",
        "--disable-content-trust",
        "--help",
    }
)


@dataclass
class Invocation:
    """One ``ash`` command line found somewhere in the docs."""

    display: str
    args: list[str]
    #: A problem with how ASH is being started, independent of its arguments.
    problem: str | None = None
    #: Zero-based line within the script it was found in.
    line: int = 0


def _package_spec_is_ash(spec: str) -> bool:
    lowered = spec.lower()
    name = re.split(r"[\[=<>~!@ ;]", lowered, maxsplit=1)[0]
    return name == ASH_PACKAGE or (
        lowered.startswith("git+") and GITHUB_REPO_SLUG.split("/")[1] in lowered
    )


def find_invocations(words: list[str], depth: int = 0) -> list[Invocation]:
    """The ASH invocation a simple command makes, through any wrappers, if it makes one."""
    if depth > 4 or not words:
        return []
    index = 0
    while index < len(words):
        word = words[index]
        base = posixpath.basename(word)
        if _ASSIGNMENT.match(word) or base in _SHELL_KEYWORDS:
            index += 1
            continue
        if base in ("exec", "nohup", "command", "builtin"):
            index += 1
            continue
        if base == "sudo":
            index += 1
            while index < len(words) and words[index].startswith("-"):
                index += 2 if words[index] in _SUDO_VALUE_OPTIONS else 1
            continue
        if base == "env":
            index += 1
            while index < len(words) and (
                words[index].startswith("-") or _ASSIGNMENT.match(words[index])
            ):
                index += (
                    2 if words[index] in ("-u", "--unset", "-C", "--chdir", "-S") else 1
                )
            continue
        if base in ("timeout", "nice"):
            index += 1
            while index < len(words) and words[index].startswith("-"):
                index += 1
            if base == "timeout" and index < len(words):
                index += 1  # the duration
            continue
        break
    words = words[index:]
    if not words:
        return []
    head = posixpath.basename(words[0])
    rest = words[1:]

    if head in ASH_PROGRAMS:
        return [Invocation(" ".join(words), rest)]
    if head == "uvx" or (head == "uv" and rest[:2] == ["tool", "run"]):
        return _tool_runner(
            words, rest if head == "uvx" else rest[2:], _UV_VALUE_OPTIONS, "--from"
        )
    if head == "pipx" and rest[:1] == ["run"]:
        return _tool_runner(words, rest[1:], _PIPX_VALUE_OPTIONS, "--spec")
    if head == "uv" and rest[:1] == ["run"]:
        inner = rest[1:]
        position = 0
        while position < len(inner) and inner[position].startswith("-"):
            position += (
                2
                if inner[position].split("=")[0] in _UV_VALUE_OPTIONS
                and "=" not in inner[position]
                else 1
            )
        return find_invocations(inner[position:], depth + 1)
    if re.match(r"^python(3(\.\d+)?)?$|^py$", head):
        return _python_module(words, rest)
    if head in CONTAINER_RUNTIMES:
        return _container_run(rest, depth)
    if head in ("bash", "sh", "zsh") and "-c" in rest:
        script = rest[rest.index("-c") + 1] if rest.index("-c") + 1 < len(rest) else ""
        found = []
        for command in split_shell(script):
            found += find_invocations(command.words, depth + 1)
        return found
    if head == "alias":
        found = []
        for word in rest:
            name, _sep, value = word.partition("=")
            if value:
                for command in split_shell(value):
                    found += find_invocations(command.words, depth + 1)
        return found
    return []


def _tool_runner(
    words: list[str], rest: list[str], value_options: frozenset, from_option: str
) -> list[Invocation]:
    position, from_spec = 0, None
    while position < len(rest) and rest[position].startswith("-"):
        name, sep, value = rest[position].partition("=")
        if name == from_option:
            from_spec = (
                value
                if sep
                else (rest[position + 1] if position + 1 < len(rest) else "")
            )
        if name in value_options and not sep:
            position += 2
        else:
            position += 1
    if position >= len(rest):
        return []
    tool = rest[position]
    if posixpath.basename(tool) in ASH_PROGRAMS or (
        from_spec is None and _package_spec_is_ash(tool)
    ):
        return [Invocation(" ".join(words), rest[position + 1 :])]
    return []


def _python_module(words: list[str], rest: list[str]) -> list[Invocation]:
    if "-m" not in rest:
        return []
    position = rest.index("-m")
    module = rest[position + 1] if position + 1 < len(rest) else ""
    if not (module == ASH_MODULE or module.startswith(ASH_MODULE + ".")):
        return []
    display = " ".join(words)
    try:
        spec = importlib.util.find_spec(module)
    except (ImportError, ValueError):
        spec = None
    if spec is None:
        return [
            Invocation(display, [], problem=f"'{display}': there is no module {module}")
        ]
    if spec.submodule_search_locations is not None:
        main = importlib.util.find_spec(module + ".__main__")
        if main is None:
            return [
                Invocation(
                    display,
                    [],
                    problem=f"'{display}': {module} is a package with no __main__, so python -m cannot run it",
                )
            ]
        if module == ASH_MODULE:
            return [Invocation(display, rest[position + 2 :])]
        return []
    source = Path(spec.origin or "").read_text(encoding="utf-8") if spec.origin else ""
    if "__name__" not in source or "__main__" not in source:
        return [
            Invocation(
                display,
                [],
                problem=f"'{display}': {module} has no __main__ guard, so python -m runs nothing",
            )
        ]
    return []


def _container_run(rest: list[str], depth: int) -> list[Invocation]:
    if rest[:2] == ["container", "run"]:
        rest = rest[2:]
    elif rest[:1] in (["run"], ["exec"]):
        is_exec = rest[0] == "exec"
        rest = rest[1:]
        if is_exec:
            position = 0
            while position < len(rest) and rest[position].startswith("-"):
                position += (
                    1
                    if rest[position] in _CONTAINER_RUN_FLAGS or "=" in rest[position]
                    else 2
                )
            return find_invocations(rest[position + 1 :], depth + 1)
    else:
        return []
    position = 0
    while position < len(rest) and rest[position].startswith("-"):
        option = rest[position]
        if (
            option in _CONTAINER_RUN_FLAGS
            or "=" in option
            or (
                not option.startswith("--")
                and len(option) > 2
                and set(option[1:]) <= set("itdP")
            )
        ):
            position += 1
        else:
            position += 2
    # rest[position] is the image; what follows is the command the container runs.
    return find_invocations(rest[position + 1 :], depth + 1)


def invocations_in_script(script: str) -> list[Invocation]:
    found = []
    for command in split_shell(script):
        inner_found = find_invocations(command.words)
        for inner in command.substitutions:
            inner_found += invocations_in_script(inner)
        for invocation in inner_found:
            invocation.line = command.line
        found += inner_found
    return found


_INLINE_CODE = re.compile(r"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)")


def inline_code_spans(text: str) -> list[str]:
    return [match.group(2).strip() for match in _INLINE_CODE.finditer(text)]


_BARE_OPTION = re.compile(r"^(--[A-Za-z][\w-]*(=\S*)?(/--?[A-Za-z][\w-]*)*|-[A-Za-z])$")


# ---------------------------------------------------------------------------
# Check: ash command lines
# ---------------------------------------------------------------------------


def _dockerfile_commands(body: str) -> list[tuple[int, list[str]]]:
    """(line, words) of every RUN/CMD/ENTRYPOINT instruction, exec form or shell form."""
    commands = []
    lines = body.split("\n")
    index = 0
    while index < len(lines):
        start = index
        line = lines[index]
        while line.rstrip().endswith("\\") and index + 1 < len(lines):
            index += 1
            line = line.rstrip()[:-1] + " " + lines[index]
        index += 1
        match = re.match(r"^\s*(RUN|CMD|ENTRYPOINT)\s+(.*)$", line, re.IGNORECASE)
        if not match:
            continue
        argument = match.group(2).strip()
        if argument.startswith("["):
            try:
                words = json.loads(argument)
            except json.JSONDecodeError:
                continue
            if isinstance(words, list):
                commands.append((start, [str(w) for w in words]))
        else:
            commands += [(start, c.words) for c in split_shell(argument)]
    return commands


def _shell_script_of(block: Block) -> str:
    return console_commands(block.body) if block.lang == "console" else block.body


def _strings_under_keys(document: Any, keys: set[str]) -> Iterator[str]:
    if isinstance(document, dict):
        for key, value in document.items():
            if key in keys:
                if isinstance(value, str):
                    yield value
                elif isinstance(value, list):
                    yield from (item for item in value if isinstance(item, str))
            yield from _strings_under_keys(value, keys)
    elif isinstance(document, list):
        for item in document:
            yield from _strings_under_keys(item, keys)


def _mcp_client_commands(document: Any) -> Iterator[list[str]]:
    """``command`` plus ``args`` of every MCP server entry, wherever it is nested."""
    if isinstance(document, dict):
        command = document.get("command")
        if isinstance(command, str):
            args = document.get("args") or []
            if isinstance(args, list):
                yield [command] + [str(a) for a in args]
        for value in document.values():
            yield from _mcp_client_commands(value)
    elif isinstance(document, list):
        for item in document:
            yield from _mcp_client_commands(item)


def block_invocations(
    block: Block, root: Path, code: Path | None = None
) -> tuple[list[Invocation], list[str]]:
    """Every ash invocation a block makes, plus problems found while looking for them.

    ``code`` is the tree whose .pre-commit-hooks.yaml and action.yml files a CI block
    is checked against; it defaults to ``root``.
    """
    code = code or root
    found: list[Invocation] = []
    problems: list[str] = []
    if block.family == "shell":
        if block.lang in WINDOWS_SHELLS or block.lang == "fish":
            # Not bash syntax, but an ash line in it is still an ash line.
            for _number, line in block.body_lines():
                stripped = re.sub(r"^\s*(PS[^>]*>|>|\$)\s*", "", line)
                found += invocations_in_script(stripped.replace("`\n", " "))
        else:
            found += invocations_in_script(_shell_script_of(block))
    elif block.family == "dockerfile":
        for line, words in _dockerfile_commands(block.body):
            for invocation in find_invocations(words):
                invocation.line = line
                found.append(invocation)
    elif block.family == "config":
        kind = block.config_kind
        if kind in OTHER_CONFIG_KINDS:
            document, error = parse_config_text(block.body, block.lang)
            if error is None:
                for script in _strings_under_keys(document, OTHER_CONFIG_KINDS[kind]):
                    found += invocations_in_script(script)
                if kind == "mcp-client":
                    for words in _mcp_client_commands(document):
                        found += find_invocations(words)
                if kind == "pre-commit":
                    pre_found, pre_problems = _pre_commit_invocations(document, code)
                    found += pre_found
                    problems += pre_problems
                if kind == "github-actions":
                    problems += _github_action_uses(document, code)
    return found, problems


def _pre_commit_invocations(
    document: Any, root: Path
) -> tuple[list[Invocation], list[str]]:
    import yaml

    found: list[Invocation] = []
    problems: list[str] = []
    manifest_path = root / PRE_COMMIT_HOOKS
    try:
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or []
    except (OSError, yaml.YAMLError) as exc:
        return [], [f"cannot read {PRE_COMMIT_HOOKS}: {exc}"]
    hooks = {hook.get("id"): hook for hook in manifest if isinstance(hook, dict)}
    repos = document.get("repos", []) if isinstance(document, dict) else []
    for repo in repos if isinstance(repos, list) else []:
        if not isinstance(repo, dict) or GITHUB_REPO_SLUG not in str(
            repo.get("repo", "")
        ):
            continue
        for hook in repo.get("hooks") or []:
            if not isinstance(hook, dict):
                continue
            hook_id = hook.get("id")
            if hook_id not in hooks:
                problems.append(
                    f"pre-commit hook id '{hook_id}' is not in {PRE_COMMIT_HOOKS}; "
                    f"it has {sorted(h for h in hooks if h)}"
                )
                continue
            entry = str(hooks[hook_id].get("entry", ""))
            args = [
                str(a) for a in hook.get("args") or hooks[hook_id].get("args") or []
            ]
            for command in split_shell(entry):
                for invocation in find_invocations(command.words + args):
                    found.append(invocation)
    return found, problems


def _github_action_uses(document: Any, root: Path) -> list[str]:
    """``uses:`` of an action in this repository must name one that exists, with its inputs."""
    import yaml

    problems = []
    for step in _dicts_with_key(document, "uses"):
        uses = str(step.get("uses"))
        if not uses.lower().startswith(
            GITHUB_REPO_SLUG + "/"
        ) and not uses.lower().startswith(GITHUB_REPO_SLUG + "@"):
            continue
        path = uses.split("@", 1)[0][len(GITHUB_REPO_SLUG) :].strip("/")
        action = next(
            (
                root / path / name
                for name in ("action.yml", "action.yaml")
                if (root / path / name).is_file()
            ),
            None,
        )
        if action is None:
            problems.append(
                f"uses: {uses} names no action: this repository has no action.yml at "
                f"'{path or '<repository root>'}'"
            )
            continue
        declared = (yaml.safe_load(action.read_text(encoding="utf-8")) or {}).get(
            "inputs"
        ) or {}
        for name in (
            (step.get("with") or {}) if isinstance(step.get("with"), dict) else {}
        ):
            if name not in declared:
                problems.append(
                    f"uses: {uses} has no input '{name}'; it declares {sorted(declared)}"
                )
    return problems


def _dicts_with_key(document: Any, key: str) -> Iterator[dict]:
    if isinstance(document, dict):
        if key in document:
            yield document
        for value in document.values():
            yield from _dicts_with_key(value, key)
    elif isinstance(document, list):
        for item in document:
            yield from _dicts_with_key(item, key)


def check_cli(
    files: Iterable[Path],
    root: Path = REPO_ROOT,
    cli: CliCommand | None = None,
    code: Path | None = None,
) -> list[Finding]:
    """Every ash invocation in a block or inline code span parses against the real CLI."""
    cli = cli or load_cli()
    code = code or code_root(root)
    every_option = all_option_names(cli)
    findings: list[Finding] = []
    for page in load_pages(files, root):
        if page.rel in HISTORICAL_DOCS:
            continue
        for block in page.blocks:
            invocations, problems = block_invocations(block, root, code)
            for problem in problems:
                findings.append(Finding("cli", page.rel, block.fence_line, problem))
            for invocation in invocations:
                line = (
                    block.body_line + invocation.line
                    if block.family in ("shell", "dockerfile")
                    else block.fence_line
                )
                if invocation.problem:
                    findings.append(Finding("cli", page.rel, line, invocation.problem))
                for problem in ash_args_problems(invocation.args, cli):
                    findings.append(Finding("cli", page.rel, line, problem))
            if (
                block.family == "shell"
                and block.mode == "run"
                and block.lang in RUNNER_SHELLS
            ):
                for number, line in block.body_lines():
                    placeholder = re.search(
                        r"(?<![<\w])<[A-Za-z][\w .:/|-]*>(?![>\w])", line
                    )
                    if placeholder and "<<" not in line:
                        findings.append(
                            Finding(
                                "cli",
                                page.rel,
                                number,
                                f"run block contains the placeholder {placeholder.group(0)}, which "
                                "a shell reads as a redirection; use a real value or mark the "
                                'block <!-- doctest: illustrative reason="..." -->',
                            )
                        )
        for number, line in page.prose:
            for span in inline_code_spans(line):
                findings += _inline_span_findings(
                    span, page.rel, number, cli, every_option
                )
    return findings


def _inline_span_findings(
    span: str, rel: str, line: int, cli: CliCommand, every_option: set[str]
) -> list[Finding]:
    findings = []
    if _BARE_OPTION.match(span):
        for part in span.split("/"):
            name = part.split("=")[0]
            if name and name not in every_option:
                close = difflib.get_close_matches(name, sorted(every_option), n=1)
                hint = f" (did you mean {close[0]}?)" if close else ""
                findings.append(
                    Finding(
                        "cli",
                        rel,
                        line,
                        f"`{span}`: {name} is not an option of any ash command{hint}. To mention "
                        "another program's option, put the program in the span",
                    )
                )
        return findings
    first = span.split()[0] if span.split() else ""
    if posixpath.basename(first) in ASH_PROGRAMS or first in (
        "uvx",
        "uv",
        "pipx",
        "docker",
        "podman",
        "finch",
        "nerdctl",
        "python",
        "python3",
    ):
        for invocation in invocations_in_script(span):
            if invocation.problem:
                findings.append(Finding("cli", rel, line, invocation.problem))
            for problem in ash_args_problems(invocation.args, cli, complete=False):
                findings.append(Finding("cli", rel, line, problem))
    return findings


# ---------------------------------------------------------------------------
# Check: environment variables
# ---------------------------------------------------------------------------

#: The environment-variable read set. Owned by scripts/generate_env_var_reference.py,
#: whose read_env_names() covers the package and its shipped entry scripts. Until that
#: generator exists in a checkout, the fallback below walks the package only, which
#: is the narrower set: names read only by an entry script then fail here rather than
#: pass, so the fallback can only err loudly.
ENV_VAR_GENERATOR = "scripts/generate_env_var_reference.py"

_ASH_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])ASH_[A-Z0-9_]*[A-Z0-9](?:_\*|\*)?(?![A-Za-z0-9_])|(?<![A-Za-z0-9_])ASH_[A-Z0-9_]+_(?![A-Za-z0-9_])"
)
_ENV_TABLE_HEADERS = ("variable", "environment variable")
_UPPER_NAME = re.compile(r"(?<![A-Za-z0-9_])[A-Z][A-Z0-9_]*[A-Z0-9](?![A-Za-z0-9_])")


@dataclass
class EnvReadSet:
    names: set[str]
    dynamic: list[str]
    source: str


def _load_by_path(name: str, path: Path) -> Any:
    """Load a script as a module, registered first so its dataclasses can resolve."""
    import sys

    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@functools.lru_cache(maxsize=None)
def load_env_read_set(root_str: str = str(REPO_ROOT)) -> EnvReadSet:
    """Every variable the code in ``root_str`` reads, and the lookups it cannot resolve.

    ``root_str`` is the code tree: its package and entry scripts are what is read. The
    generator that reads them is taken from that tree, or failing that from the tree
    this module is in, since a docs branch may carry a newer generator than the code.
    """
    root = Path(root_str)
    for generator in (root / ENV_VAR_GENERATOR, REPO_ROOT / ENV_VAR_GENERATOR):
        if generator.is_file():
            module = _load_by_path("_ash_env_var_reference", generator)
            names, dynamic = module.read_env_names(root)
            return EnvReadSet(
                set(names), list(dynamic), f"{ENV_VAR_GENERATOR} over {root}"
            )
    names, dynamic = _collect_package_env_names(root / ASH_MODULE, root)
    return EnvReadSet(
        names, dynamic, f"{ASH_MODULE}/ only, because {ENV_VAR_GENERATOR} is absent"
    )


_ENV_OBJECTS = {"os.environ", "environ", "os.environb"}
_GETENV = {"os.getenv", "getenv"}
_ENV_METHODS = {"get", "setdefault", "pop", "__contains__"}


def _attr_chain(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def env_lookups(
    tree: ast.AST, label: str, constants: dict[str, str] | None = None
) -> tuple[set[str], list[str]]:
    """(literal names, dynamic sites) of every environment lookup in a syntax tree.

    The same shapes as the collector in tests/unit/test_generated_docs_freshness.py:
    environ subscripts, ``in environ``, getenv, environ.get/setdefault/pop and click's
    ``envvar=``. A key that is a name or attribute found in ``constants`` (string
    constants this module defines or imports) resolves to that string; any other
    non-literal key is recorded as a dynamic site rather than assumed absent.
    """
    constants = constants or {}
    literals: set[str] = set()
    dynamic: list[str] = []

    def record(key: ast.AST, shape: str, lineno: int) -> None:
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            literals.add(key.value)
        elif (
            isinstance(key, (ast.Name, ast.Attribute)) and _attr_chain(key) in constants
        ):
            literals.add(constants[_attr_chain(key)])
        else:
            dynamic.append(f"{label}:{lineno} [{shape}]")

    for node in ast.walk(tree):
        lineno = getattr(node, "lineno", 0)
        if isinstance(node, ast.Subscript) and _attr_chain(node.value) in _ENV_OBJECTS:
            record(node.slice, "subscript", lineno)
        if isinstance(node, ast.Compare):
            for op, comp in zip(node.ops, node.comparators):
                if (
                    isinstance(op, (ast.In, ast.NotIn))
                    and _attr_chain(comp) in _ENV_OBJECTS
                ):
                    record(node.left, "in-environ", lineno)
        if isinstance(node, ast.Call):
            if _attr_chain(node.func) in _GETENV and node.args:
                record(node.args[0], "getenv", lineno)
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in _ENV_METHODS
                and _attr_chain(node.func.value) in _ENV_OBJECTS
                and node.args
            ):
                record(node.args[0], f"environ.{node.func.attr}", lineno)
            for keyword in node.keywords:
                if keyword.arg != "envvar":
                    continue
                if isinstance(keyword.value, (ast.List, ast.Tuple)):
                    for element in keyword.value.elts:
                        record(element, "envvar-list", lineno)
                else:
                    record(keyword.value, "envvar", lineno)
    return literals, dynamic


def _module_string_constants(tree: ast.AST) -> dict[str, str]:
    """Module-level ``NAME = "literal"`` assignments."""
    found: dict[str, str] = {}
    for node in getattr(tree, "body", []):
        targets = (
            node.targets
            if isinstance(node, ast.Assign)
            else [node.target]
            if isinstance(node, ast.AnnAssign)
            else []
        )
        value = getattr(node, "value", None)
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            for target in targets:
                if isinstance(target, ast.Name):
                    found[target.id] = value.value
    return found


def _package_sources(package: Path) -> list[Path]:
    """The package's .py files, without the ignored build copies git does not track.

    Uses git's own listing when the package sits in a checkout, so a gitignored copy
    (the build writes some modules into automated_security_helper/assets/) is not read
    twice; a plain walk otherwise.
    """
    import subprocess

    checkout = package.parent
    listing = subprocess.run(
        [
            "git",
            "-C",
            str(checkout),
            "ls-files",
            "-z",
            "-co",
            "--exclude-standard",
            "--",
            f"{package.name}/*.py",
        ],
        capture_output=True,
        check=False,
    )
    if listing.returncode == 0 and listing.stdout:
        found = [
            checkout / os.fsdecode(entry)
            for entry in listing.stdout.split(b"\0")
            if entry
        ]
        return sorted(path for path in found if path.is_file())
    return sorted(package.rglob("*.py"))


def package_modules(package: Path) -> list[tuple[Path, ast.AST, dict[str, str]]]:
    """(path, syntax tree, string constants in scope) for every module in the package.

    The constants are the module's own ``NAME = "literal"`` assignments plus those it
    imports from other modules of the package, by ``from x import NAME`` or as
    ``x.NAME`` after ``import x``. Both the env-var fallback and the code-links check
    use them to resolve a key or a URL that the source spells as a constant.
    """
    trees: dict[str, tuple[Path, ast.AST]] = {}
    for path in _package_sources(package):
        relative = path.relative_to(package.parent).with_suffix("")
        parts = relative.parts[:-1] if relative.name == "__init__" else relative.parts
        tree = ast.parse(
            path.read_text(encoding="utf-8", errors="replace"), filename=str(path)
        )
        trees[".".join(parts)] = (path, tree)
    own = {
        module: _module_string_constants(tree)
        for module, (_path, tree) in trees.items()
    }
    modules = []
    for module, (path, tree) in trees.items():
        constants = dict(own[module])
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module in own
                and not node.level
            ):
                for alias in node.names:
                    if alias.name in own[node.module]:
                        constants[alias.asname or alias.name] = own[node.module][
                            alias.name
                        ]
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in own:
                        for constant, value in own[alias.name].items():
                            constants[f"{alias.asname or alias.name}.{constant}"] = (
                                value
                            )
        modules.append((path, tree, constants))
    return modules


def _collect_package_env_names(package: Path, root: Path) -> tuple[set[str], list[str]]:
    """The fallback read set: every env lookup in the package, constants resolved."""
    names: set[str] = set()
    dynamic: list[str] = []
    for path, tree, constants in package_modules(package):
        found, sites = env_lookups(tree, rel_path(path, root), constants)
        names |= found
        dynamic += sites
    return names, dynamic


def env_table_names(page: Page) -> list[tuple[int, str]]:
    """Names in the first column of every table headed Variable or Environment variable."""
    found: list[tuple[int, str]] = []
    lines = page.prose
    for position, (number, line) in enumerate(lines):
        cells = _table_cells(line)
        if not cells or cells[0].lower().strip("`* ") not in _ENV_TABLE_HEADERS:
            continue
        if position + 1 >= len(lines) or not _is_delimiter_row(lines[position + 1][1]):
            continue
        for row_number, row in lines[position + 2 :]:
            row_cells = _table_cells(row)
            if not row_cells:
                break
            for name in _UPPER_NAME.findall(row_cells[0]):
                found.append((row_number, name))
    return found


def _table_cells(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|"):
        return []
    return [cell.strip() for cell in stripped.strip("|").split("|")]


def _is_delimiter_row(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("|") and set(stripped) <= set("|-: ") and "-" in stripped


def _ash_tokens(text: str) -> list[str]:
    return _ASH_TOKEN.findall(text)


def _python_string_names(body: str) -> list[str] | None:
    """ASH_ names a python block uses as strings. Identifiers are code, not env vars."""
    try:
        tree = ast.parse(body)
    except SyntaxError:
        return None
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            names += _ash_tokens(node.value)
    return names


def _name_is_read(name: str, read: EnvReadSet) -> bool:
    if name.endswith(("*", "_")):
        prefix = name.rstrip("*")
        return any(candidate.startswith(prefix) for candidate in read.names)
    return name in read.names


#: An environment reference in a config value, as the config loader matches it.
_CONFIG_ENV_REFERENCE = re.compile(r"\$\{(\w+)(?::[^}]*)?\}")


def _config_interpolation_rule() -> Callable[[str], bool]:
    """The installed ASH's rule for which names a config ``${NAME}`` may read."""
    try:
        from automated_security_helper.config.ash_config import (
            config_env_var_is_interpolatable,
        )
    except ImportError:  # an older ASH without the rule interpolates nothing here
        return lambda name: False
    return config_env_var_is_interpolatable


def check_env_vars(
    files: Iterable[Path],
    root: Path = REPO_ROOT,
    read: EnvReadSet | None = None,
    code: Path | None = None,
) -> list[Finding]:
    """Every ASH_* name in the docs, and every env-var table row, is a variable ASH reads.

    One kind of read cannot be in the read set: a config file's ``${NAME}`` reference,
    which the config loader resolves for any name its rule allows (every ``ASH_*``
    name and a few AWS ones). A name that one of the page's ASH config blocks
    references that way counts as read everywhere on that page, so a page may export
    the variable its own config example consumes.
    """
    read = read or load_env_read_set(str(code or code_root(root)))
    interpolatable = _config_interpolation_rule()
    findings: list[Finding] = []
    dynamic_note = (
        f"; {len(read.dynamic)} lookup(s) build their name at runtime and are not resolved"
        if read.dynamic
        else ""
    )

    def report(rel: str, line: int, name: str, where: str) -> None:
        findings.append(
            Finding(
                "env",
                rel,
                line,
                f"{name}{where} is not an environment variable ASH reads "
                f"(read set: {read.source}{dynamic_note})",
            )
        )

    for page in load_pages(files, root):
        if page.rel in HISTORICAL_DOCS:
            continue
        via_config = {
            name
            for block in page.blocks
            if block.family == "config" and block.config_kind in ASH_CONFIG_KINDS
            for name in _CONFIG_ENV_REFERENCE.findall(block.body)
            if interpolatable(name)
        }

        def is_read(name: str) -> bool:
            return name in via_config or _name_is_read(name, read)

        seen: set[tuple[int, str]] = set()
        for number, line in page.prose:
            for name in _ash_tokens(line):
                if not is_read(name) and (number, name) not in seen:
                    seen.add((number, name))
                    report(page.rel, number, name, "")
        for block in page.blocks:
            if block.family == "python":
                names = _python_string_names(block.body)
                if names is None:
                    names = _ash_tokens(block.body)
                for name in sorted(set(names)):
                    if not is_read(name):
                        report(page.rel, block.fence_line, name, " in a python block")
                continue
            for number, line in block.body_lines():
                for name in _ash_tokens(line):
                    if not is_read(name) and (number, name) not in seen:
                        seen.add((number, name))
                        report(page.rel, number, name, "")
        for number, name in env_table_names(page):
            if not name.startswith("ASH_") and name not in read.names:
                report(page.rel, number, name, " (in an environment-variable table)")
    return findings


# ---------------------------------------------------------------------------
# Config parsing and validation
# ---------------------------------------------------------------------------


def _strip_jsonc(text: str) -> str:
    """JSON with // and /* */ comments and trailing commas, as JSON."""
    out: list[str] = []
    index, in_string = 0, False
    while index < len(text):
        char = text[index]
        if in_string:
            out.append(char)
            if char == "\\" and index + 1 < len(text):
                out.append(text[index + 1])
                index += 2
                continue
            if char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if text.startswith("//", index):
            newline = text.find("\n", index)
            index = len(text) if newline < 0 else newline
            continue
        if text.startswith("/*", index):
            close = text.find("*/", index + 2)
            index = len(text) if close < 0 else close + 2
            continue
        out.append(char)
        index += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _parse_toml(text: str) -> Any:
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:  # pragma: no cover - 3.10 only
        import toml

        return toml.loads(text)
    return tomllib.loads(text)


def parse_config_text(text: str, lang: str) -> tuple[Any, str | None]:
    """Parse a block in its language. Returns (document, error message or None)."""
    import yaml

    try:
        if lang in ("yaml", "yml"):
            documents = list(yaml.safe_load_all(text))
            return (documents[0] if len(documents) == 1 else documents), None
        if lang == "json":
            return json.loads(text), None
        if lang == "jsonc":
            return json.loads(_strip_jsonc(text)), None
        if lang == "toml":
            return _parse_toml(text), None
    except Exception as exc:  # noqa: BLE001 -- every parser's error is the finding
        first = (
            str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
        )
        return None, f"does not parse as {lang}: {first}"
    return None, f"no parser for {lang}"


@dataclass
class ConfigModels:
    """ASH's config model and the config class of every plugin the package ships."""

    ash_config: type
    segments: dict[str, type]
    plugin_configs: dict[str, dict[str, type]]
    passthrough: frozenset[str]
    #: Options base class -> undeclared keys that ASH reads from every subclass anyway.
    generic_option_keys: dict[type, frozenset[str]] = field(default_factory=dict)


#: Option keys the scanner base class reads from ANY scanner's options with getattr,
#: declared or not (base/scanner_plugin.py: getattr(options, "offline") in the offline
#: check and getattr(options, "scan_timeout") in the timeout lookup). Setting either on
#: a scanner whose options model does not declare it still takes effect, so it is not
#: reported as ignored. test_docs_checks_can_fail.py pins that both reads still exist.
GENERIC_SCANNER_OPTION_KEYS = frozenset({"offline", "scan_timeout"})


#: Models whose undeclared keys ASH hands on rather than drops, so an extra key there
#: is not "accepted and ignored". Each entry cites where the extras are consumed.
#: The detect-secrets scan settings are dumped whole into detect-secrets'
#: transient_settings (plugin_modules/ash_builtin/scanners/detect_secrets_scanner.py,
#: scan_settings.model_dump), so a detect-secrets plugin parameter such as
#: ``limit`` variants it defines itself reaches detect-secrets unchanged.
PASSTHROUGH_MODELS = frozenset(
    {
        "DetectSecretsScanSettings",
        "DetectSecretsScanSettingsPluginsUsed",
        "DetectSecretsScanSettingsFiltersUsed",
        "DetectSecretsScanSettingsResults",
    }
)


@functools.lru_cache(maxsize=1)
def load_config_models() -> ConfigModels:
    import pkgutil

    from automated_security_helper import plugin_modules
    from automated_security_helper.config.ash_config import (
        AshConfig,
        ConverterConfigSegment,
        ReporterConfigSegment,
        ScannerConfigSegment,
    )

    segments = {
        "scanners": ScannerConfigSegment,
        "reporters": ReporterConfigSegment,
        "converters": ConverterConfigSegment,
    }
    suffixes = {
        "scanners": "ScannerConfig",
        "reporters": "ReporterConfig",
        "converters": "ConverterConfig",
    }
    configs: dict[str, dict[str, type]] = {section: {} for section in segments}
    for info in pkgutil.walk_packages(
        plugin_modules.__path__, plugin_modules.__name__ + "."
    ):
        try:
            module = importlib.import_module(info.name)
        except Exception:  # noqa: BLE001, S112  # nosec B112 -- an optional extra is not a docs problem
            continue
        for attr in dir(module):
            obj = getattr(module, attr)
            if not isinstance(obj, type) or not hasattr(obj, "model_fields"):
                continue
            for section, suffix in suffixes.items():
                if attr.endswith(suffix) and "name" in obj.model_fields:
                    default = obj.model_fields["name"].default
                    if isinstance(default, str) and default:
                        configs[section].setdefault(default, obj)
    from automated_security_helper.base.options import ScannerOptionsBase

    return ConfigModels(
        AshConfig,
        segments,
        configs,
        PASSTHROUGH_MODELS,
        {ScannerOptionsBase: GENERIC_SCANNER_OPTION_KEYS},
    )


def _validation_messages(exc: Exception) -> list[str]:
    errors = getattr(exc, "errors", None)
    if callable(errors):
        out = []
        for error in errors():
            loc = ".".join(str(part) for part in error.get("loc", ()))
            out.append(f"{loc or '<root>'}: {error.get('msg')}")
        return out
    return [str(exc).splitlines()[0]]


def _field_keys(model_cls: type) -> dict[str, str]:
    """Every key the model accepts for a declared field, mapped to the field name."""
    keys: dict[str, str] = {}
    config = getattr(model_cls, "model_config", {})
    by_name = config.get("populate_by_name") or config.get("validate_by_name")
    for name, info in model_cls.model_fields.items():
        keys[info.alias or name] = name
        if by_name or not info.alias:
            keys[name] = name
    # _PluginConfigSegment folds the field-name spelling of an aliased plugin into its
    # alias in a before-validator, so both spellings reach the declared field.
    if any(base.__name__ == "_PluginConfigSegment" for base in model_cls.__mro__):
        for name, info in model_cls.model_fields.items():
            keys[name] = name
    return keys


def ignored_keys(
    model: Any, raw: Any, loc: str, models: ConfigModels, external_plugins: bool
) -> list[str]:
    """Keys in ``raw`` that the validated ``model`` accepted without reading.

    pydantic drops an undeclared key under extra="ignore" (AshConfig's setting, and
    pydantic's default) and keeps it unread under extra="allow" (every plugin config
    and options model). Either way a reader who copies the key gets no error and no
    effect, so both are reported. The three plugin segments are different: their
    undeclared keys are plugin names, so each is looked up among the plugins ASH ships
    and validated against that plugin's own config class.
    """
    from pydantic import BaseModel

    problems: list[str] = []
    if not isinstance(raw, dict) or not isinstance(model, BaseModel):
        return problems
    cls = type(model)
    if cls.__name__ in models.passthrough:
        return problems
    keys = _field_keys(cls)
    for base, generic in models.generic_option_keys.items():
        if issubclass(cls, base):
            keys.update(dict.fromkeys(generic, ""))
    extra_mode = cls.model_config.get("extra") or "ignore"
    section = next((name for name, seg in models.segments.items() if seg is cls), None)
    for key, value in raw.items():
        where = f"{loc}.{key}" if loc else str(key)
        field_name = keys.get(key)
        if field_name is None:
            if section is not None:
                problems += _plugin_extra(
                    section, str(key), value, where, models, external_plugins
                )
            elif extra_mode != "forbid":
                problems.append(
                    f"{where} is not a field of {cls.__name__}; extra={extra_mode!r} means ASH "
                    "accepts it and never reads it"
                )
            continue
        if not field_name:
            continue  # read generically, not a declared field; nothing to descend into
        problems += _descend(
            getattr(model, field_name, None), value, where, models, external_plugins
        )
    return problems


def _descend(
    value: Any, raw: Any, where: str, models: ConfigModels, external_plugins: bool
) -> list[str]:
    from pydantic import BaseModel

    if isinstance(value, BaseModel):
        return ignored_keys(value, raw, where, models, external_plugins)
    problems: list[str] = []
    if isinstance(value, (list, tuple)) and isinstance(raw, list):
        for position, (item, raw_item) in enumerate(zip(value, raw)):
            problems += _descend(
                item, raw_item, f"{where}[{position}]", models, external_plugins
            )
    elif isinstance(value, dict) and isinstance(raw, dict):
        for key, raw_item in raw.items():
            if key in value:
                problems += _descend(
                    value[key], raw_item, f"{where}.{key}", models, external_plugins
                )
    return problems


def _plugin_extra(
    section: str,
    name: str,
    value: Any,
    where: str,
    models: ConfigModels,
    external: bool,
) -> list[str]:
    from pydantic import ValidationError

    config_cls = models.plugin_configs.get(section, {}).get(name)
    if config_cls is None:
        if external:
            return []
        known = sorted(models.plugin_configs.get(section, {}))
        close = difflib.get_close_matches(name, known, n=1)
        hint = f"; did you mean '{close[0]}'?" if close else ""
        return [
            (
                f"{where}: ASH ships no {section[:-1]} named '{name}'{hint}. A third-party "
                "plugin's config validates only with that plugin installed; load it with "
                "ash_plugin_modules in the same block, or mark the block config kind=other"
            )
        ]
    if not isinstance(value, dict):
        return [f"{where} must be a mapping"]
    try:
        model = config_cls.model_validate(value)
    except ValidationError as exc:
        return [f"{where}.{message}" for message in _validation_messages(exc)]
    return ignored_keys(model, value, where, models, external)


def validate_ash_config(data: Any, models: ConfigModels | None = None) -> list[str]:
    """Problems with a parsed config, as ASH would load it, plus every ignored key."""
    from pydantic import ValidationError

    models = models or load_config_models()
    if not isinstance(data, dict):
        return [f"an ASH config is a mapping, not {type(data).__name__}"]
    data = dict(data)
    problems: list[str] = []
    # extends and patch are resolved by the loader before validation, from files this
    # block cannot name, so only their shape is checked here.
    extends = data.pop("extends", None)
    if extends is not None and not (
        isinstance(extends, str)
        or (isinstance(extends, list) and all(isinstance(e, str) for e in extends))
    ):
        problems.append("extends must be a path or a list of paths")
    patch = data.pop("patch", None)
    if patch is not None and not (
        isinstance(patch, list)
        and all(isinstance(p, dict) and "op" in p for p in patch)
    ):
        problems.append(
            "patch must be a list of JSON Patch operations, each with an op"
        )
    known = set(_field_keys(models.ash_config)) | {"extends", "patch"}
    if data and not known.intersection(data):
        listed = ", ".join(sorted(str(k) for k in data)[:6])
        return problems + [
            (
                f"this is not an ASH config: none of its top-level keys ({listed}) is an "
                "AshConfig field. Mark it with the kind of file it is, for example config "
                "kind=github-actions"
            )
        ]
    try:
        model = models.ash_config.model_validate(data, strict=True)
    except ValidationError as exc:
        return problems + _validation_messages(exc)
    modules = data.get("ash_plugin_modules") or []
    external = (
        any(not str(m).startswith(ASH_MODULE) for m in modules)
        if isinstance(modules, list)
        else False
    )
    return problems + ignored_keys(model, data, "", models, external)


def _read_ash_config(
    text: str, lang: str, as_pyproject: bool
) -> tuple[Any, str | None]:
    """Parse a config block with ASH's own reader (``!ENV`` tags, [tool.ash] tables)."""
    from automated_security_helper.config.config_sources import read_config_file

    suffix = {
        "yaml": ".yaml",
        "yml": ".yaml",
        "json": ".json",
        "jsonc": ".json",
        "toml": ".toml",
    }[lang]
    if lang == "jsonc":
        text = _strip_jsonc(text)
    with tempfile.TemporaryDirectory(prefix="ash-docs-config-") as scratch:
        name = "pyproject.toml" if as_pyproject else f"block{suffix}"
        path = Path(scratch) / name
        path.write_text(text, encoding="utf-8")
        # The reader logs a warning for every unset !ENV variable; in a docs check that
        # is noise around the findings, so logging is held off while it runs.
        previous = logging.root.manager.disable
        logging.disable(logging.WARNING)
        try:
            return read_config_file(path), None
        except Exception as exc:  # noqa: BLE001 -- the reader's error is the finding
            first = (
                str(exc).strip().splitlines()[0]
                if str(exc).strip()
                else type(exc).__name__
            )
            return None, f"does not parse as {lang}: {first}"
        finally:
            logging.disable(previous)


def config_block_problems(
    block: Block, models: ConfigModels | None = None
) -> list[str]:
    """What is wrong with one config block, by its kind."""
    kind = block.config_kind
    marker_keys = block.marker.keys if block.marker else {}
    if kind in ASH_CONFIG_KINDS:
        data, error = _read_ash_config(
            block.body, block.lang, as_pyproject=(kind == "pyproject")
        )
        if error:
            return [error] if kind != "ash-invalid" else []
        if kind == "ash-fragment":
            for part in reversed(str(marker_keys.get("at", "")).split(".")):
                data = {part: data}
        problems = validate_ash_config(data, models)
        if kind == "ash-invalid":
            return (
                []
                if problems
                else [
                    "config kind=ash-invalid documents a config ASH rejects, but ASH accepts this one"
                ]
            )
        return problems
    if kind in OTHER_CONFIG_KINDS:
        _document, error = parse_config_text(block.body, block.lang)
        return [error] if error else []
    return []


def check_config_blocks(files: Iterable[Path], root: Path = REPO_ROOT) -> list[Finding]:
    """Config blocks parse, and those that are ASH configs validate with nothing ignored."""
    findings: list[Finding] = []
    models: ConfigModels | None = None
    for page in load_pages(files, root):
        for block in page.blocks:
            if block.family != "config":
                continue
            kind = block.config_kind
            if kind not in ASH_CONFIG_KINDS and kind not in OTHER_CONFIG_KINDS:
                continue  # the markers check reports the unknown kind
            if kind in ASH_CONFIG_KINDS and models is None:
                models = load_config_models()
            label = f"config kind={kind}" + (
                " (unmarked)" if block.marker is None else ""
            )
            for problem in config_block_problems(block, models):
                findings.append(
                    Finding("config", page.rel, block.fence_line, f"{label}: {problem}")
                )
    return findings


# ---------------------------------------------------------------------------
# Check: python blocks
# ---------------------------------------------------------------------------


def _import_problems(tree: ast.AST) -> list[tuple[int, str]]:
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if not _module_exists(alias.name):
                    problems.append(
                        (
                            node.lineno,
                            f"import {alias.name}: no such module in the docs environment",
                        )
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                problems.append(
                    (node.lineno, "a relative import cannot run outside a package")
                )
                continue
            module = node.module or ""
            if not _module_exists(module):
                problems.append(
                    (
                        node.lineno,
                        f"from {module} import ...: no such module in the docs environment",
                    )
                )
                continue
            if module == ASH_MODULE or module.startswith(ASH_MODULE + "."):
                try:
                    imported = importlib.import_module(module)
                except Exception as exc:  # noqa: BLE001 -- an import that raises is the finding
                    problems.append(
                        (
                            node.lineno,
                            f"from {module} import ...: importing it raises {exc!r}",
                        )
                    )
                    continue
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    if not hasattr(imported, alias.name) and not _module_exists(
                        f"{module}.{alias.name}"
                    ):
                        problems.append(
                            (node.lineno, f"{module} has no name {alias.name}")
                        )
    return problems


@functools.lru_cache(maxsize=None)
def _module_exists(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def check_python_blocks(
    files: Iterable[Path], root: Path = REPO_ROOT, code: Path | None = None
) -> list[Finding]:
    """Every python block parses, and every import in it resolves; imports are never waived.

    "Resolves" means in the docs environment: the interpreter's ASH and its virtualenv,
    with the root of the checkout that ASH comes from importable, as it is for a
    contributor working in a checkout, so a contributing page may import tests.utils.
    That root is the code tree, never the docs root: putting a separate docs checkout
    first on the path would import its copy of the package instead.
    """
    import sys

    code = code or code_root(root)
    if str(code) not in sys.path:
        sys.path.insert(0, str(code))
        _module_exists.cache_clear()
    findings: list[Finding] = []
    for page in load_pages(files, root):
        for block in page.blocks:
            if block.family != "python":
                continue
            try:
                tree = ast.parse(block.body)
            except SyntaxError as exc:
                line = block.body_line + (exc.lineno or 1) - 1
                findings.append(
                    Finding("python", page.rel, line, f"does not parse: {exc.msg}")
                )
                continue
            for offset, problem in _import_problems(tree):
                findings.append(
                    Finding("python", page.rel, block.body_line + offset - 1, problem)
                )
    return findings


# ---------------------------------------------------------------------------
# Links, anchors, navigation, redirects
# ---------------------------------------------------------------------------


_RESOLVABLE_TAG_MODULES = ("pymdownx.", "material.", "markdown.")


class _TolerantLoader:
    """A YAML loader for mkdocs.yml: ``!!python/name:x`` resolves, ``!ENV`` gives its default."""

    @staticmethod
    def load(text: str) -> Any:
        import yaml

        class Loader(yaml.SafeLoader):
            pass

        def python_name(loader: Any, suffix: str, node: Any) -> Any:
            # Only the markdown extension packages, whose functions the anchor check
            # needs to render a page the way mkdocs does. Anything else stays a string.
            module_name, _, attr = suffix.rpartition(".")
            if not module_name.startswith(_RESOLVABLE_TAG_MODULES):
                return suffix
            try:
                return getattr(importlib.import_module(module_name), attr)
            except Exception:  # noqa: BLE001 -- an unimportable tag is not a docs problem here
                return suffix

        def env(loader: Any, node: Any) -> Any:
            if isinstance(node, yaml.SequenceNode):
                values = loader.construct_sequence(node)
                for name in values[:-1]:
                    if isinstance(name, str) and name in os.environ:
                        return os.environ[name]
                return values[-1] if values else None
            return os.environ.get(loader.construct_scalar(node))

        Loader.add_multi_constructor("tag:yaml.org,2002:python/name:", python_name)
        Loader.add_multi_constructor(
            "tag:yaml.org,2002:python/object", lambda loader, suffix, node: None
        )
        Loader.add_constructor("!ENV", env)
        return yaml.load(text, Loader=Loader)  # nosec B506 -- SafeLoader subclass; tags limited above


@dataclass
class Site:
    root: Path
    config: dict
    docs_dir: Path
    use_directory_urls: bool
    site_url: str
    #: The code tree (see code_root); a repository path may exist there instead.
    code: Path


def load_site(root_str: str = str(REPO_ROOT)) -> Site:
    root = Path(root_str)
    config = _TolerantLoader.load((root / MKDOCS_YML).read_text(encoding="utf-8")) or {}
    return Site(
        root=root,
        config=config,
        docs_dir=(root / str(config.get("docs_dir", "docs"))).resolve(),
        use_directory_urls=bool(config.get("use_directory_urls", True)),
        site_url=str(config.get("site_url") or "").rstrip("/"),
        code=code_root(root),
    )


def _markdown_extensions(site: Site) -> tuple[list[Any], dict[str, Any]]:
    extensions: list[Any] = ["toc", "tables", "fenced_code"]
    configs: dict[str, Any] = {}
    for entry in site.config.get("markdown_extensions") or []:
        if isinstance(entry, str):
            extensions.append(entry)
        elif isinstance(entry, dict):
            for name, options in entry.items():
                extensions.append(name)
                if isinstance(options, dict):
                    configs[name] = options
    return list(dict.fromkeys(extensions)), configs


@functools.lru_cache(maxsize=None)
def _site_page_ids(path_str: str, root_str: str, text: str) -> frozenset[str]:
    """Element ids python-markdown gives a page, with the extensions mkdocs.yml enables."""
    import markdown

    site = load_site(root_str)
    extensions, configs = _markdown_extensions(site)
    if path_str.endswith(".md.template"):
        text = text.replace(VERSION_PLACEHOLDER, current_version(root_str))
    try:
        md = markdown.Markdown(extensions=extensions, extension_configs=configs)
    except Exception:  # noqa: BLE001 -- fall back to the core set if an extension will not load
        md = markdown.Markdown(extensions=["toc", "tables", "fenced_code"])
    html = md.convert(text)
    ids = set(re.findall(r'\bid="([^"]+)"', html)) | set(
        re.findall(r'\bname="([^"]+)"', html)
    )

    def walk(tokens: list[dict]) -> None:
        for token in tokens:
            ids.add(token["id"])
            walk(token.get("children", []))

    walk(getattr(md, "toc_tokens", []))
    return frozenset(ids)


def github_slug(text: str) -> str:
    """The anchor GitHub gives a heading: lowercase, punctuation dropped, spaces to hyphens."""
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = text.replace("`", "")
    text = text.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


@functools.lru_cache(maxsize=None)
def _github_page_ids(path_str: str, text: str) -> frozenset[str]:
    """Anchors GitHub gives a rendered markdown file: heading slugs and <a id|name>."""
    page = parse_page(Path(path_str), REPO_ROOT, text)
    ids: set[str] = set()
    counts: dict[str, int] = {}
    previous = ""
    for number, line in page.prose:
        heading = re.match(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$", line)
        text = heading.group(2) if heading else None
        if (
            text is None
            and re.match(r"^\s{0,3}(=+|-+)\s*$", line)
            and previous.strip()
            and not _table_cells(previous)
        ):
            text = previous.strip()
        if text is not None:
            slug = github_slug(re.sub(r"\s*\{#[^}]*\}\s*$", "", text))
            if slug in counts:
                counts[slug] += 1
                slug = f"{slug}-{counts[slug]}"
            else:
                counts[slug] = 0
            ids.add(slug)
        for match in re.finditer(r'<a\s[^>]*(?:id|name)="([^"]+)"', line):
            ids.add(match.group(1))
        previous = line
    return frozenset(ids)


_LINK_INLINE = re.compile(
    r"(!?)\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+[\"'(][^)]*[\"')])?\s*\)"
)
_LINK_REFERENCE_DEF = re.compile(r"^\s{0,3}\[([^\]]+)\]:\s*<?(\S+?)>?(?:\s+.*)?$")
_LINK_HTML = re.compile(
    r"<(?:a|img|source)\s[^>]*?(?:href|src)=\"([^\"]+)\"", re.IGNORECASE
)
_LINK_AUTO = re.compile(r"<(https?://[^>\s]+)>")


def page_links(page: Page) -> list[tuple[int, str]]:
    """(line, target) of every link and image in a page's prose, code spans excluded."""
    links = []
    for number, line in page.prose:
        visible = _INLINE_CODE.sub("", line)
        for match in _LINK_INLINE.finditer(visible):
            links.append((number, match.group(2)))
        definition = _LINK_REFERENCE_DEF.match(visible)
        if definition:
            links.append((number, definition.group(2)))
        for match in _LINK_HTML.finditer(visible):
            links.append((number, match.group(1)))
        for match in _LINK_AUTO.finditer(visible):
            links.append((number, match.group(1)))
    return links


def _in_dir(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
        return True
    except ValueError:
        return False


def _page_ids(target: Path, site: Site) -> frozenset[str]:
    text = target.read_text(encoding="utf-8")
    if _in_dir(target, site.docs_dir):
        return _site_page_ids(str(target), str(site.root), text)
    return _github_page_ids(str(target), text)


def _url_path_to_page(url_path: str, site: Site) -> Path | None:
    """The source page a site URL path serves, if any."""
    url_path = unquote(url_path).strip("/")
    if url_path.endswith("index.html"):
        url_path = url_path[: -len("index.html")].strip("/")
    elif url_path.endswith(".html"):
        url_path = url_path[: -len(".html")]
    candidates = (
        [f"{url_path}.md", f"{url_path}/index.md", f"{url_path}/README.md"]
        if url_path
        else ["index.md", "README.md"]
    )
    for candidate in candidates:
        path = site.docs_dir / candidate
        if path.is_file():
            return path
    return None


#: Repository pages a GitHub-rendered file may reach with a relative link (../../issues).
_GITHUB_REPO_PAGES = frozenset(
    {
        "issues",
        "pulls",
        "security",
        "discussions",
        "wiki",
        "releases",
        "actions",
        "labels",
        "milestones",
        "projects",
        "compare",
        "commits",
        "tags",
        "branches",
    }
)


def repository_file(rel: str, site: Site) -> Path | None:
    """A repository path in the docs root or, failing that, the code tree."""
    for base in (site.root, site.code):
        path = base / rel
        if path.exists():
            return path
    return None


def repository_path_problem(
    target: str, rel: str, fragment: str, site: Site
) -> str | None:
    """Why a path in this repository, named by a GitHub URL, does not resolve."""
    path = repository_file(rel, site)
    if path is None:
        return f"{target}: {rel} does not exist in this repository"
    if fragment and path.is_file() and path.suffix == ".md":
        if fragment not in _github_page_ids(
            str(path), path.read_text(encoding="utf-8")
        ):
            return f"{target}: {rel} has no heading or anchor '#{fragment}'"
    return None


def site_target(
    url_path: str, site: Site, redirects: dict[str, str]
) -> tuple[Path | None, str, str | None]:
    """(page, the redirect's own fragment, the redirected old page) a site URL reaches."""
    served = _url_path_to_page(url_path, site)
    if served is not None:
        return served, "", None
    source = unquote(url_path).strip("/")
    for old, new in redirects.items():
        if _redirect_url(old, site).strip("/") == source:
            new_path, _, new_fragment = new.partition("#")
            target = site.docs_dir / new_path
            return (target if target.is_file() else None), new_fragment, old
    return None, "", None


def site_url_problem(
    target: str, url_path: str, fragment: str, site: Site, redirects: dict[str, str]
) -> str | None:
    """Why a URL on the published site does not reach an existing page and anchor.

    A redirect is followed. The redirect page carries the URL's own fragment across
    (docs/hooks/redirects.py), so that fragment, or the redirect's when the URL has
    none, must exist on the page the redirect ends at.
    """
    page, redirect_fragment, via = site_target(url_path, site, redirects)
    if page is None:
        if via:
            return (
                f"{target}: the redirect from {via} ends at a page that does not exist"
            )
        return f"{target}: no page on the site serves this URL, and no redirect does"
    wanted = fragment or redirect_fragment
    if wanted and wanted not in _page_ids(page, site):
        through = f" (through the redirect from {via})" if via else ""
        return (
            f"{target}: {rel_path(page, site.root)}{through} has no anchor '#{wanted}'"
        )
    return None


def link_problem(
    page: Page, target: str, site: Site, redirects: dict[str, str]
) -> str | None:
    """Why one link target does not resolve, or None."""
    root = site.root
    parts = urlsplit(target)
    if parts.scheme in ("mailto", "tel", "data", "javascript"):
        return None
    in_site = _in_dir(page.path, site.docs_dir)
    fragment = unquote(parts.fragment)
    if parts.scheme in ("http", "https"):
        url = target.split("#", 1)[0]
        repo = GITHUB_REPO_URL.lower()
        lowered = url.lower()
        for form in ("blob", "tree"):
            prefix = f"{repo}/{form}/main/"
            if lowered.startswith(prefix) or lowered == prefix.rstrip("/"):
                return repository_path_problem(
                    target, unquote(url[len(prefix) :]).strip("/"), fragment, site
                )
        if site.site_url and lowered.startswith(site.site_url.lower()):
            return site_url_problem(
                target, url[len(site.site_url) :], fragment, site, redirects
            )
        return None
    if parts.scheme or parts.netloc:
        return None
    link_path = unquote(parts.path)
    if not link_path:
        if fragment and fragment not in _page_ids(page.path, site):
            return f"#{fragment}: this page has no heading or anchor with that id"
        return None
    if link_path.startswith("/"):
        if in_site:
            return f"{target}: absolute links break when the site is not served from /; use a relative path"
        resolved = (root / link_path.lstrip("/")).resolve()
    else:
        resolved = (page.path.parent / link_path).resolve()
    if in_site and not _in_dir(resolved, site.docs_dir):
        if _in_dir(resolved, root) and resolved.exists():
            rel = rel_path(resolved, root)
            form = "tree" if resolved.is_dir() else "blob"
            return (
                f"{target}: points outside {rel_path(site.docs_dir, root)}, which mkdocs cannot "
                f"serve; link to {GITHUB_REPO_URL}/{form}/main/{rel}"
            )
        return f"{target}: points outside {rel_path(site.docs_dir, root)} and does not exist"
    if not _in_dir(resolved, root):
        # GitHub resolves a relative link in a rendered file against
        # /<owner>/<repo>/blob/main/<dir>/, so ../../issues reaches the repository's
        # issues page. Only those repository pages are allowed out of the tree.
        url = posixpath.normpath(
            posixpath.join("blob/main", rel_path(page.path.parent, root), link_path)
        )
        if not in_site and url.split("/")[0] in _GITHUB_REPO_PAGES:
            return None
        return f"{target}: points outside the repository"
    if not resolved.exists():
        return f"{target}: {rel_path(resolved, root)} does not exist"
    if resolved.is_dir():
        if in_site:
            return f"{target}: links to a directory; link to the page file in it (for example index.md)"
        return None
    if fragment and resolved.suffix == ".md":
        if fragment not in _page_ids(resolved, site):
            return f"{target}: {rel_path(resolved, root)} has no heading or anchor '#{fragment}'"
    return None


def load_redirects(root: Path) -> tuple[dict[str, str], str | None]:
    path = root / REDIRECTS_FILE
    if not path.is_file():
        return {}, None
    import yaml

    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        return {}, f"{REDIRECTS_FILE} does not parse: {exc}"
    redirects = document.get("redirects") if isinstance(document, dict) else None
    if redirects is None:
        return {}, None
    if not isinstance(redirects, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in redirects.items()
    ):
        return (
            {},
            f"{REDIRECTS_FILE}: redirects must map old page paths to new page paths",
        )
    return dict(redirects), None


def _redirect_url(old: str, site: Site) -> str:
    """The URL path mkdocs would have served the old page at."""
    stem = old.removesuffix(".md")
    if site.use_directory_urls:
        if posixpath.basename(stem) in ("index", "README"):
            return posixpath.dirname(stem) + "/"
        return stem + "/"
    return stem + ".html"


def check_links(files: Iterable[Path], root: Path = REPO_ROOT) -> list[Finding]:
    """Relative links resolve (inside docs_dir for site pages), and so do their anchors."""
    site = load_site(str(root))
    redirects, _error = load_redirects(root)
    findings: list[Finding] = []
    for page in load_pages(files, root):
        for number, target in page_links(page):
            problem = link_problem(page, target, site, redirects)
            if problem:
                findings.append(Finding("links", page.rel, number, problem))
    return findings


# ---------------------------------------------------------------------------
# Check: docs links in the ASH source
# ---------------------------------------------------------------------------
#
# The package names docs pages too: error messages and help text point at the site
# (an advanced-usage anchor), at a raw GitHub file (`ash get-genai-guide` fetches the
# GenAI guide by path), or at a docs path in the repository. A docs reorganization
# that moves those pages breaks them silently, because nothing renders them. So every
# such reference in the package must reach a page, file and anchor that exist.

#: Stands for a part of an f-string this check cannot resolve to a literal.
DYNAMIC = "\x00"

_REPO_URL_IN_TEXT = re.compile(
    r"https://(?:raw\.githubusercontent\.com/awslabs/automated-security-helper/(?P<raw>[^\s\"'<>)\]]+)"
    r"|github\.com/awslabs/automated-security-helper/(?:blob|tree|raw)/(?P<rest>[^\s\"'<>)\]]+))"
)
_DOCS_PATH_IN_TEXT = re.compile(r"(?<![\w/.:-])(docs/[\w./-]+\.md)(?:#([\w-]+))?")
_HEADING_REFERENCE = re.compile(
    "[\"'\u2018\u201c]([^\"'\u2019\u201d\n]{3,100})[\"'\u2019\u201d] in (docs/[\\w./-]+\\.md)"
)


def _docstring_ids(tree: ast.AST) -> set[int]:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = getattr(node, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
            ):
                ids.add(id(body[0].value))
    return ids


def code_strings(tree: ast.AST, constants: dict[str, str]) -> Iterator[tuple[int, str]]:
    """(line, text) of every string the code builds, docstrings excepted.

    An f-string becomes its text with each placeholder replaced by the constant it
    names, or by DYNAMIC when it names something else. A chain of ``/`` joins with
    string operands (``Path(...) / "docs" / "content" / "x.md"``) becomes the path its
    string operands spell.
    """
    skip = _docstring_ids(tree)
    for node in ast.walk(tree):
        if id(node) in skip:
            continue
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                for inner in ast.walk(value):
                    skip.add(id(inner))
                if isinstance(value, ast.Constant):
                    parts.append(str(value.value))
                elif isinstance(value, ast.FormattedValue) and isinstance(
                    value.value, (ast.Name, ast.Attribute)
                ):
                    parts.append(constants.get(_attr_chain(value.value), DYNAMIC))
                else:
                    parts.append(DYNAMIC)
            yield node.lineno, "".join(parts)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            operands: list[ast.AST] = []

            def flatten(item: ast.AST) -> None:
                if isinstance(item, ast.BinOp) and isinstance(item.op, ast.Div):
                    skip.add(id(item))
                    flatten(item.left)
                    flatten(item.right)
                else:
                    operands.append(item)

            flatten(node)
            segments = [
                o.value
                for o in operands
                if isinstance(o, ast.Constant) and isinstance(o.value, str)
            ]
            for operand in operands:
                if isinstance(operand, ast.Constant):
                    skip.add(id(operand))
            if "docs" in segments:
                yield node.lineno, "/".join(segments[segments.index("docs") :])
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.lineno, node.value


def _is_docs_path(rel: str, site: Site) -> bool:
    """A path the docs tree owns: under docs/, which holds docs_dir and the redirect map."""
    return rel == MKDOCS_YML or rel.startswith("docs/")


def _docs_path_problem(
    shown: str,
    rel: str,
    fragment: str,
    site: Site,
    redirects: dict[str, str],
    *,
    fetched: bool,
) -> str | None:
    """Why a docs path the code names does not exist in the docs root."""
    path = site.root / rel
    if path.is_file():
        if fragment and path.suffix == ".md" and fragment not in _page_ids(path, site):
            return f"{shown}: {rel} has no heading or anchor '#{fragment}'"
        return None
    docs_rel = rel_path(site.root / rel, site.docs_dir)
    moved = redirects.get(docs_rel)
    if moved:
        how = (
            "a fetch of the file does not follow it"
            if fetched
            else "point at the new page"
        )
        return f"{shown}: {rel} moved to {moved} (docs/redirects.yml); {how}"
    return f"{shown}: {rel} does not exist in the docs"


def code_reference_problems(
    text: str, site: Site, redirects: dict[str, str]
) -> list[str]:
    """Why each docs URL or docs path in one string the code builds does not resolve."""
    problems: list[str] = []

    def shown(value: str) -> str:
        return value.replace(DYNAMIC, "{...}")

    dynamic_note = "is built at runtime from a value this check cannot resolve; write its path as a literal"
    if site.site_url:
        pattern = re.escape(site.site_url) + "(?P<path>[^\\s\"'<>)\\]]*)"
        for match in re.finditer(pattern, text):
            whole = match.group(0).rstrip(".,;:")
            url, _, fragment = whole.partition("#")
            if DYNAMIC in whole:
                problems.append(f"{shown(whole)} {dynamic_note}")
                continue
            problem = site_url_problem(
                whole, url[len(site.site_url) :], unquote(fragment), site, redirects
            )
            if problem:
                problems.append(problem)
    for match in _REPO_URL_IN_TEXT.finditer(text):
        whole = match.group(0).rstrip(".,;:")
        rest = (match.group("raw") or match.group("rest") or "").rstrip(".,;:")
        segments = rest.split("/")
        skip = (
            3
            if match.group("raw")
            and segments[:2] in (["refs", "heads"], ["refs", "tags"])
            else 1
        )
        rel, _, fragment = "/".join(segments[skip:]).partition("#")
        if DYNAMIC in rel:
            problems.append(f"{shown(whole)} {dynamic_note}")
            continue
        if not rel:
            continue
        if _is_docs_path(rel, site):
            problem = _docs_path_problem(
                shown(whole), rel, unquote(fragment), site, redirects, fetched=True
            )
        else:
            problem = repository_path_problem(
                shown(whole), rel, unquote(fragment), site
            )
        if problem:
            problems.append(problem)
    # A docs path after a placeholder (f"{root}/docs/content/x.md") is still a docs
    # path: only its prefix is unknown.
    for match in re.finditer(DYNAMIC + "/(docs/[\\w./-]+\\.md)", text):
        problem = _docs_path_problem(
            match.group(1), match.group(1), "", site, redirects, fetched=False
        )
        if problem:
            problems.append(problem)
    for match in _DOCS_PATH_IN_TEXT.finditer(text):
        problem = _docs_path_problem(
            match.group(0),
            match.group(1),
            match.group(2) or "",
            site,
            redirects,
            fetched=False,
        )
        if problem:
            problems.append(problem)
    for match in _HEADING_REFERENCE.finditer(text):
        heading, rel = match.group(1), match.group(2)
        path = site.root / rel
        if path.is_file() and path.suffix == ".md":
            from markdown.extensions.toc import slugify

            if slugify(heading, "-") not in _page_ids(path, site):
                problems.append(f"'{heading}' in {rel}: that page has no such heading")
    return list(dict.fromkeys(problems))


def check_code_links(
    root: Path = REPO_ROOT, package: Path | None = None
) -> list[Finding]:
    """Docs URLs, docs paths and heading references in the ASH source all resolve."""
    site = load_site(str(root))
    redirects, _error = load_redirects(root)
    package = package or installed_package_dir()
    findings: list[Finding] = []
    for path, tree, constants in package_modules(package):
        rel = rel_path(path, package.parent)
        for line, text in code_strings(tree, constants):
            if "docs/" not in text and "github" not in text:
                continue
            for problem in code_reference_problems(text, site, redirects):
                findings.append(Finding("code-links", rel, line, problem))
    return findings


def _nav_entries(document: Any) -> Iterator[str]:
    """Every string target in an awesome-nav or mkdocs nav structure."""
    if isinstance(document, str):
        yield document
    elif isinstance(document, list):
        for item in document:
            yield from _nav_entries(item)
    elif isinstance(document, dict):
        for value in document.values():
            yield from _nav_entries(value)


def nav_targets(site: Site) -> tuple[set[Path], list[tuple[str, int, str]]]:
    """Pages reachable from the navigation, and nav entries that name nothing."""
    import yaml

    reachable: set[Path] = set()
    missing: list[tuple[str, int, str]] = []
    nav_files = sorted(site.docs_dir.rglob(NAV_FILE_NAME))
    sources: list[tuple[Path, Any]] = []
    for nav_file in nav_files:
        document = yaml.safe_load(nav_file.read_text(encoding="utf-8")) or {}
        sources.append(
            (nav_file, document.get("nav", []) if isinstance(document, dict) else [])
        )
    if not nav_files and site.config.get("nav"):
        sources.append((site.docs_dir / MKDOCS_YML, site.config["nav"]))
    for nav_file, nav in sources:
        base = nav_file.parent
        text = nav_file.read_text(encoding="utf-8") if nav_file.is_file() else ""
        for entry in _nav_entries(nav):
            if re.match(r"^[a-z]+://", entry):
                continue
            line = next(
                (n for n, l in enumerate(text.splitlines(), 1) if entry in l), 1
            )
            if any(char in entry for char in "*?["):
                matched = [p for p in base.glob(entry) if p.suffix == ".md"]
                if not matched:
                    missing.append(
                        (
                            rel_path(nav_file, site.root),
                            line,
                            f"nav pattern '{entry}' matches no page",
                        )
                    )
                reachable |= {p.resolve() for p in matched}
                continue
            target = (base / entry).resolve()
            if target.is_dir():
                reachable |= {p.resolve() for p in target.rglob("*.md")}
            elif target.is_file():
                reachable.add(target)
            else:
                missing.append(
                    (
                        rel_path(nav_file, site.root),
                        line,
                        f"nav entry '{entry}' names no page",
                    )
                )
    return reachable, missing


def _not_in_nav_spec(site: Site) -> Callable[[str], bool]:
    patterns = str(site.config.get("not_in_nav") or "")
    lines = [
        line
        for line in patterns.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    try:
        import pathspec

        spec = pathspec.GitIgnoreSpec.from_lines(lines)
        return spec.match_file
    except ImportError:  # pragma: no cover - mkdocs depends on pathspec
        return lambda rel: any(
            fnmatch.fnmatch(rel, line.strip().lstrip("/")) for line in lines
        )


def check_nav(root: Path = REPO_ROOT) -> list[Finding]:
    """Every site page is in the nav or deliberately not; every nav entry and redirect resolves."""
    site = load_site(str(root))
    findings: list[Finding] = []
    reachable, missing = nav_targets(site)
    for where, line, problem in missing:
        findings.append(Finding("nav", where, line, problem))
    unlisted = _not_in_nav_spec(site)
    for page in sorted(site.docs_dir.rglob("*.md")):
        rel_to_docs = page.resolve().relative_to(site.docs_dir).as_posix()
        if page.resolve() in reachable or unlisted(rel_to_docs):
            continue
        findings.append(
            Finding(
                "nav",
                rel_path(page, root),
                1,
                f"page is in no {NAV_FILE_NAME} and not in mkdocs.yml not_in_nav, so no reader "
                "can reach it from the site navigation",
            )
        )
    redirects, error = load_redirects(root)
    if error:
        findings.append(Finding("redirects", REDIRECTS_FILE, 1, error))
    redirect_text = (
        (root / REDIRECTS_FILE).read_text(encoding="utf-8")
        if (root / REDIRECTS_FILE).is_file()
        else ""
    )
    for old, new in redirects.items():
        line = next(
            (
                n
                for n, l in enumerate(redirect_text.splitlines(), 1)
                if l.strip().startswith(f"{old}:") or l.strip().startswith(f'"{old}":')
            ),
            1,
        )
        if (site.docs_dir / old).is_file():
            findings.append(
                Finding(
                    "redirects",
                    REDIRECTS_FILE,
                    line,
                    f"{old} still exists, so a redirect from it would overwrite a page",
                )
            )
        new_path, _, fragment = new.partition("#")
        target = site.docs_dir / new_path
        if new_path in redirects:
            findings.append(
                Finding(
                    "redirects",
                    REDIRECTS_FILE,
                    line,
                    f"{old} redirects to {new_path}, which is itself redirected; point it at the final page",
                )
            )
        elif not target.is_file():
            findings.append(
                Finding(
                    "redirects",
                    REDIRECTS_FILE,
                    line,
                    f"{old} redirects to {new}, which is not a page in {rel_path(site.docs_dir, root)}",
                )
            )
        elif fragment and fragment not in _page_ids(target, site):
            findings.append(
                Finding(
                    "redirects",
                    REDIRECTS_FILE,
                    line,
                    f"{old} redirects to {new}, but that page has no anchor '#{fragment}'",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Check: the site build is strict and offline
# ---------------------------------------------------------------------------

#: mkdocs ``validation`` settings that strict mode turns into build failures. A value
#: of ``warn`` here plus ``--strict`` is what makes a broken link fail the build.
REQUIRED_VALIDATION = {
    ("validation", "nav", "omitted_files"): "warn",
    ("validation", "nav", "not_found"): "warn",
    ("validation", "nav", "absolute_links"): "warn",
    ("validation", "links", "not_found"): "warn",
    ("validation", "links", "absolute_links"): "warn",
    ("validation", "links", "unrecognized_links"): "warn",
    ("validation", "links", "anchors"): "warn",
}


def check_site_build(root: Path = REPO_ROOT) -> list[Finding]:
    """mkdocs.yml and the docs workflow keep the build strict, offline, and redirecting."""
    import yaml

    site = load_site(str(root))
    findings: list[Finding] = []
    for path, wanted in REQUIRED_VALIDATION.items():
        value: Any = site.config
        for part in path:
            value = value.get(part) if isinstance(value, dict) else None
        if value != wanted:
            findings.append(
                Finding(
                    "site",
                    MKDOCS_YML,
                    1,
                    f"{'.'.join(path)} is {value!r}; it must be {wanted!r} so --strict fails on it",
                )
            )
    hooks = [str(h) for h in site.config.get("hooks") or []]
    if REDIRECT_HOOK not in hooks:
        findings.append(
            Finding(
                "site",
                MKDOCS_YML,
                1,
                f"hooks does not list {REDIRECT_HOOK}, so no redirect page is written",
            )
        )
    if not (root / REDIRECT_HOOK).is_file():
        findings.append(
            Finding("site", REDIRECT_HOOK, 1, "the redirect hook does not exist")
        )
    plugins = site.config.get("plugins") or []
    names = [
        p if isinstance(p, str) else next(iter(p))
        for p in plugins
        if isinstance(p, (str, dict))
    ]
    if "privacy" not in names:
        findings.append(
            Finding("site", MKDOCS_YML, 1, "the privacy plugin is not configured")
        )
    workflow = root / DOCS_WORKFLOW
    if workflow.is_file():
        document = yaml.safe_load(workflow.read_text(encoding="utf-8")) or {}
        runs = list(_strings_under_keys(document, {"run"}))
        builds = [r for r in runs if re.search(r"\bmkdocs\s+build\b", r)]
        if not builds:
            findings.append(
                Finding("site", DOCS_WORKFLOW, 1, "no step runs mkdocs build")
            )
        for run in builds:
            if "--strict" not in run:
                findings.append(
                    Finding(
                        "site",
                        DOCS_WORKFLOW,
                        1,
                        f"'{run.strip()}' does not pass --strict",
                    )
                )
    else:
        findings.append(
            Finding("site", DOCS_WORKFLOW, 1, "the docs workflow does not exist")
        )
    return findings


def site_pages(files: Iterable[Path], root: Path) -> list[Path]:
    """The corpus files mkdocs renders: markdown under docs_dir."""
    docs_dir = load_site(str(root)).docs_dir
    return [path for path in files if path.suffix == ".md" and _in_dir(path, docs_dir)]
