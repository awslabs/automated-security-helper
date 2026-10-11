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
import sys
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

#: The script that publishes the site as versions with mike, and checks that it can.
DOCS_VERSIONS_SCRIPT = "scripts/docs_versions.py"

#: The workflow that creates release tags, and so has to start the docs deploy for
#: them: a tag pushed with GITHUB_TOKEN starts no workflow of its own.
RELEASE_TAG_WORKFLOW = ".github/workflows/ash-tag-on-merge.yml"

#: Fixture projects the docs-example runner can start a page in. ``fixture=<name>``
#: on a marker names a directory here.
DOC_FIXTURES_DIR = "tests/test_data/docs_fixtures"
DEFAULT_FIXTURE = "sample-project"

#: The container definitions ASH ships, relative to the code tree. Their ARG names are
#: build arguments, a second set of names the env check accepts.
SHIPPED_DOCKERFILES = ("Dockerfile",)

#: Pages for contributors. Variables only the test suite and CI read are documented
#: here and nowhere else (a path ending in "/" is a directory).
CONTRIBUTOR_PAGES = ("docs/content/contributing/", "CONTRIBUTING.md", "DEVELOPMENT.md")

#: Where the test suite and CI live in the code tree, for those test-only variables.
TEST_SOURCES = "tests"
CI_ENV_SOURCES = (
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    ".github/actions/**/action.yml",
)

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

RUN_KEYS = frozenset({"expect-exit", "fixture", "env", "timeout", "fresh", "save-as"})
#: ``save-as=<path>``: the runner writes the block's content to that path in the page's
#: project before later blocks run. Valid on any block. With no mode the block is only
#: saved; with ``run`` it is saved and run; a config block is still validated.
SAVE_AS = "save-as"
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
        """The effective mode: the marker's, or the unmarked default for the family.

        A marker with save-as and no mode makes a block "save": written to the page's
        project and not run. A config block keeps "config", so it is still validated.
        """
        if self.marker is not None and self.marker.mode:
            return self.marker.mode
        if self.marker is not None and self.family == "config":
            return "config"
        if self.marker is not None:
            return "save"
        return {"shell": "run", "python": "run", "config": "config"}.get(
            self.family, ""
        )

    @property
    def save_as(self) -> str | None:
        if self.marker is None:
            return None
        value = self.marker.keys.get(SAVE_AS)
        return value if isinstance(value, str) else None

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
class Table:
    """A markdown table in a page's prose, with the options marker above it, if any."""

    header_line: int
    header: list[str]
    #: (line number, cells) of every data row.
    rows: list[tuple[int, list[str]]]
    marker: Marker | None = None


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
    #: Every table in the prose.
    tables: list[Table] = field(default_factory=list)


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
    # A marker may start with a key instead of a mode: <!-- doctest: save-as=x.py -->.
    mode, rest = ("", words) if "=" in words[0] else (words[0], words[1:])
    keys: dict[str, Any] = {}
    for word in rest:
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
    the text around it is edited. The one marker that is not for a block is
    ``options``, which binds to the table whose header row is on the next line.
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
    table_markers: dict[int, Marker] = {}

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
            if pending is not None and pending.mode == "options":
                page.structure.append(
                    Finding(
                        "markers",
                        rel,
                        pending_line,
                        "an options marker goes on the line directly above a table's "
                        "header row, not above a code block",
                    )
                )
                pending = None
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
                                "the marker must be on the line directly above the opening "
                                "fence (for an options marker, the table's header row)",
                            )
                        )
                        pending = None
            index += 1
            continue

        if pending is not None and pending.mode == "options":
            following = lines[index + 1] if index + 1 < len(lines) else ""
            if _table_cells(line) and _is_delimiter_row(following):
                table_markers[lineno] = pending
                pending = None
            else:
                flush_pending(
                    "an options marker must be directly followed by a table's header row"
                )
        flush_pending("marker is not directly followed by a fenced code block")
        page.prose.append((lineno, line))
        index += 1

    flush_pending("marker is the last line of the page, with no block after it")
    page.tables = _prose_tables(page.prose, table_markers)
    return page


def _prose_tables(
    prose: list[tuple[int, str]], markers: dict[int, Marker]
) -> list[Table]:
    """Every table in the prose: a header row, a delimiter row, then contiguous rows."""
    tables: list[Table] = []
    position = 0
    while position < len(prose):
        number, line = prose[position]
        header = _table_cells(line)
        following = prose[position + 1] if position + 1 < len(prose) else None
        if (
            header
            and following is not None
            and following[0] == number + 1
            and _is_delimiter_row(following[1])
        ):
            rows: list[tuple[int, list[str]]] = []
            scan = position + 2
            while scan < len(prose) and prose[scan][0] == prose[scan - 1][0] + 1:
                cells = _table_cells(prose[scan][1])
                if not cells:
                    break
                rows.append((prose[scan][0], cells))
                scan += 1
            tables.append(Table(number, header, rows, markers.get(number)))
            position = scan
            continue
        position += 1
    return tables


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


def save_as_problem(value: Any) -> str | None:
    """Why a save-as path cannot be written inside the page's project, or None."""
    if not isinstance(value, str) or not value.strip():
        return (
            "save-as needs a relative path, for example save-as=my_plugins/scanner.py"
        )
    pure = value.replace("\\", "/")
    if pure.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", pure):
        return f"save-as={value} is not a relative path inside the page's project"
    parts = [part for part in pure.split("/") if part not in ("", ".")]
    if not parts or ".." in parts:
        return f"save-as={value} leaves the page's project; paths may not contain .."
    return None


def marker_problems(block: Block, root: Path) -> list[str]:
    """Everything wrong with how a block is labeled and marked."""
    problems: list[str] = []
    marker, lang, family = block.marker, block.lang, block.family
    if marker is not None and SAVE_AS in marker.keys:
        problem = save_as_problem(marker.keys[SAVE_AS])
        if problem:
            problems.append(problem)
        if marker.mode == "illustrative":
            problems.append(
                "an illustrative block is not run, so the runner never saves it; drop "
                "illustrative to save the block, or drop save-as"
            )
    if not block.info:
        problems.append(
            "fenced block has no language. Name one (text for output samples), so a "
            "command or config in it cannot escape every check"
        )
    if lang in ("pycon", "python-repl"):
        problems.append("doctest-style >>> blocks are not used; write a python block")
    if marker is not None and not marker.mode:
        extra = set(marker.keys) - {SAVE_AS}
        if SAVE_AS not in marker.keys or extra:
            problems.append(
                "a marker without a mode may only carry save-as=<path>; name a mode for "
                f"{sorted(extra) or 'it'}"
            )
        return problems
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
            extra = set(keys) - {"reason", SAVE_AS}
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
            extra = set(keys) - {"kind", SAVE_AS} - allowed
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
    #: Build arguments: name -> where it is declared (a shipped Dockerfile ARG) or
    #: passed (a --build-arg in the package). None until first needed.
    build_args: dict[str, str] | None = None
    #: Names only the test suite or CI reads: name -> where. Allowed on contributor
    #: pages only. None until first needed: walking tests/ takes seconds.
    test_only: dict[str, str] | None = None
    #: The code tree the two sets above are read from when they are first needed.
    code: Path | None = None

    def known_build_args(self) -> dict[str, str]:
        if self.build_args is None:
            found = build_argument_names(self.code) if self.code else {}
            self.build_args = {n: w for n, w in found.items() if n not in self.names}
        return self.build_args

    def known_test_only(self) -> dict[str, str]:
        if self.test_only is None:
            found = suite_env_names(self.code) if self.code else {}
            build_args = self.known_build_args()
            self.test_only = {
                n: w
                for n, w in found.items()
                if n not in self.names and n not in build_args
            }
        return self.test_only


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
    read: EnvReadSet | None = None
    for generator in (root / ENV_VAR_GENERATOR, REPO_ROOT / ENV_VAR_GENERATOR):
        if generator.is_file():
            module = _load_by_path("_ash_env_var_reference", generator)
            names, dynamic = module.read_env_names(root)
            read = EnvReadSet(
                set(names), list(dynamic), f"{ENV_VAR_GENERATOR} over {root}"
            )
            break
    if read is None:
        names, dynamic = _collect_package_env_names(root / ASH_MODULE, root)
        read = EnvReadSet(
            names, dynamic, f"{ASH_MODULE}/ only, because {ENV_VAR_GENERATOR} is absent"
        )
    read.code = root
    return read


def _dockerfile_arg_words(text: str) -> Iterator[tuple[int, str]]:
    """(line, word) for every word of every ``ARG`` instruction in a Dockerfile.

    Continuation lines are joined, comments and here-document bodies skipped, and only
    an instruction whose keyword is ARG counts, so a name in a comment, a RUN line or a
    string is not a declaration.
    """
    import shlex

    lines = text.split("\n")
    index = 0
    while index < len(lines):
        start = index
        line = lines[index]
        index += 1
        if line.lstrip().startswith("#"):
            continue
        while line.rstrip().endswith("\\") and index < len(lines):
            line = line.rstrip()[:-1] + " " + lines[index]
            index += 1
        heredoc = re.search(r"<<-?\s*['\"]?(\w+)['\"]?", line)
        if heredoc:
            delimiter = heredoc.group(1)
            while index < len(lines) and lines[index].strip() != delimiter:
                index += 1
            index += 1
        match = re.match(r"^\s*ARG\s+(.*)$", line, re.IGNORECASE)
        if not match:
            continue
        try:
            words = shlex.split(match.group(1), comments=True)
        except ValueError:
            words = match.group(1).split()
        for word in words:
            yield start + 1, word


def dockerfile_args(text: str, label: str) -> dict[str, str]:
    """Names an ``ARG`` instruction declares in a Dockerfile, with where (see above)."""
    declared: dict[str, str] = {}
    for line, word in _dockerfile_arg_words(text):
        name = word.split("=", 1)[0]
        if _ENV_NAME.match(name):
            declared.setdefault(name, f"{label}:{line} (ARG)")
    return declared


def dockerfile_arg_defaults(text: str) -> dict[str, set[str | None]]:
    """Every default each ARG is declared with; None for a declaration without one.

    A multi-stage Dockerfile can declare one ARG several times, so a name can have
    more than one default.
    """
    defaults: dict[str, set[str | None]] = {}
    for _line, word in _dockerfile_arg_words(text):
        name, sep, value = word.partition("=")
        if _ENV_NAME.match(name):
            defaults.setdefault(name, set()).add(value if sep else None)
    return defaults


def build_argument_names(code: Path) -> dict[str, str]:
    """Build arguments: ARGs of the shipped Dockerfiles, and --build-arg names ASH passes."""
    found: dict[str, str] = {}
    for rel in SHIPPED_DOCKERFILES:
        path = code / rel
        if path.is_file():
            found.update(dockerfile_args(path.read_text(encoding="utf-8"), rel))
    package = code / ASH_MODULE
    if package.is_dir():
        for path, tree, constants in package_modules(package):
            label = rel_path(path, code)
            for line, name in _passed_build_args(tree, constants):
                found.setdefault(name, f"{label}:{line} (--build-arg)")
    return found


def _passed_build_args(
    tree: ast.AST, constants: dict[str, str]
) -> Iterator[tuple[int, str]]:
    """(line, NAME) of every ``--build-arg NAME=...`` the code builds."""
    for node in ast.walk(tree):
        if not isinstance(node, (ast.List, ast.Tuple)):
            continue
        for first, second in zip(node.elts, node.elts[1:]):
            if not (isinstance(first, ast.Constant) and first.value == "--build-arg"):
                continue
            text = None
            if isinstance(second, ast.Constant) and isinstance(second.value, str):
                text = second.value
            elif isinstance(second, ast.JoinedStr) and second.values:
                head = second.values[0]
                if isinstance(head, ast.Constant):
                    text = str(head.value)
            match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=", text or "")
            if match:
                yield second.lineno, match.group(1)
    for line, text in code_strings(tree, constants):
        for match in re.finditer(r"--build-arg[ =]([A-Za-z_][A-Za-z0-9_]*)=", text):
            yield line, match.group(1)


def suite_env_names(code: Path) -> dict[str, str]:
    """Names the test suite reads (AST of tests/**/*.py) or CI sets in an ``env:`` block."""
    import yaml

    found: dict[str, str] = {}
    tests = code / TEST_SOURCES
    if tests.is_dir():
        for path, tree, constants in package_modules(tests):
            label = rel_path(path, code)
            names, _dynamic = env_lookups(tree, label, constants)
            for name in sorted(names):
                found.setdefault(name, f"read in {label}")
    for pattern in CI_ENV_SOURCES:
        for path in sorted(code.glob(pattern)):
            try:
                document = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError):
                continue
            for mapping in _dicts_with_key(document, "env"):
                env = mapping.get("env")
                if isinstance(env, dict):
                    for name in env:
                        if isinstance(name, str) and _ENV_NAME.match(name):
                            found.setdefault(name, f"set in {rel_path(path, code)}")
    return found


def is_contributor_page(rel: str) -> bool:
    return any(
        rel.startswith(entry) if entry.endswith("/") else rel == entry
        for entry in CONTRIBUTOR_PAGES
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
        import warnings

        with warnings.catch_warnings():
            # A test file's docstring with "\`" warns when parsed; the warning is
            # about that file, not about anything this check reports.
            warnings.simplefilter("ignore", SyntaxWarning)
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
    """The cells of a table row; a pipe escaped as \\| or inside a code span is text."""
    stripped = line.strip()
    if not stripped.startswith("|"):
        return []
    cells: list[str] = []
    cell: list[str] = []
    index, ticks = 0, 0
    body = stripped[1:]
    while index < len(body):
        char = body[index]
        if char == "\\" and index + 1 < len(body) and body[index + 1] == "|":
            cell.append("|")
            index += 2
            continue
        if char == "`":
            run = len(body[index:]) - len(body[index:].lstrip("`"))
            ticks = 0 if ticks == run else (run if ticks == 0 else ticks)
            cell.append(body[index : index + run])
            index += run
            continue
        if char == "|" and not ticks:
            cells.append("".join(cell).strip())
            cell = []
        else:
            cell.append(char)
        index += 1
    if "".join(cell).strip():
        cells.append("".join(cell).strip())
    return cells


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


def _matching(name: str, names: Iterable[str]) -> str | None:
    """The member of names that name is, or that a family name (ASH_X_*) prefixes."""
    if name.endswith(("*", "_")):
        prefix = name.rstrip("*")
        return next((n for n in sorted(names) if n.startswith(prefix)), None)
    return name if name in names else None


def check_env_vars(
    files: Iterable[Path],
    root: Path = REPO_ROOT,
    read: EnvReadSet | None = None,
    code: Path | None = None,
    notes: list[str] | None = None,
) -> list[Finding]:
    """Every ASH_* name in the docs, and every env-var table row, is a variable ASH reads.

    A name may also be one of three other known kinds, each from the code tree:

    - a config file's ``${NAME}`` reference, which the config loader resolves for any
      name its rule allows. A name one of the page's ASH config blocks references that
      way counts everywhere on that page, so a page may set what its config consumes;
    - a build argument: an ``ARG`` of a shipped Dockerfile, or a ``--build-arg NAME=``
      the package passes (``ASH_BASE_IMAGE`` reaches a custom Containerfile that way);
    - a variable only the test suite reads or CI sets, which is allowed on contributor
      pages (CONTRIBUTOR_PAGES) and is an error anywhere else.

    ``notes``, when given, receives which set every accepted name matched, for the
    gate's --verbose output.
    """
    read = read or load_env_read_set(str(code or code_root(root)))
    interpolatable = _config_interpolation_rule()
    findings: list[Finding] = []
    dynamic_note = (
        f"; {len(read.dynamic)} lookup(s) build their name at runtime and are not resolved"
        if read.dynamic
        else ""
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
        contributor = is_contributor_page(page.rel)
        noted: set[str] = set()

        def accepted(name: str, line: int, where: str) -> bool:
            kinds = (
                ("read set", lambda: read.names, False),
                ("config ${NAME} reference on this page", lambda: via_config, False),
                ("build argument", read.known_build_args, True),
                ("test suite and CI", read.known_test_only, True),
            )
            for kind, load, has_origins in kinds:
                names = load()
                origins = names if has_origins else None
                match = _matching(name, names)
                if match is None:
                    continue
                if kind == "test suite and CI" and not contributor:
                    findings.append(
                        Finding(
                            "env",
                            page.rel,
                            line,
                            f"{name}{where} is read only by the test suite or CI "
                            f"({read.known_test_only()[match]}); document it on a contributor page "
                            f"({', '.join(CONTRIBUTOR_PAGES)}), not here",
                        )
                    )
                    return True
                if notes is not None and name not in noted:
                    noted.add(name)
                    origin = f" ({origins[match]})" if origins else ""
                    notes.append(
                        f"{page.rel}:{line}: {name} matched the {kind}{origin}"
                    )
                return True
            return False

        def check(name: str, line: int, where: str) -> None:
            if not accepted(name, line, where):
                findings.append(
                    Finding(
                        "env",
                        page.rel,
                        line,
                        f"{name}{where} is not an environment variable ASH reads "
                        f"(read set: {read.source}{dynamic_note}), nor a build argument "
                        "of a shipped Dockerfile",
                    )
                )

        seen: set[tuple[int, str]] = set()
        for number, line in page.prose:
            for name in _ash_tokens(line):
                if (number, name) not in seen:
                    seen.add((number, name))
                    check(name, number, "")
        for block in page.blocks:
            if block.family == "python":
                names = _python_string_names(block.body)
                if names is None:
                    names = _ash_tokens(block.body)
                for name in sorted(set(names)):
                    check(name, block.fence_line, " in a python block")
                continue
            for number, line in block.body_lines():
                for name in _ash_tokens(line):
                    if (number, name) not in seen:
                        seen.add((number, name))
                        check(name, number, "")
        for number, name in env_table_names(page):
            if not name.startswith("ASH_"):
                check(name, number, " (in an environment-variable table)")
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
    #: The workspace policy file's model, a second config schema, if this ASH has one.
    workspace_policy: type | None = None


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

    try:
        from automated_security_helper.config.ash_workspace_config import (
            AshWorkspaceConfig,
        )
    except ImportError:  # an ASH without workspace mode
        AshWorkspaceConfig = None
    return ConfigModels(
        AshConfig,
        segments,
        configs,
        PASSTHROUGH_MODELS,
        {ScannerOptionsBase: GENERIC_SCANNER_OPTION_KEYS},
        AshWorkspaceConfig,
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
# Check: option tables and config paths in prose
# ---------------------------------------------------------------------------
#
# Config blocks are validated whole, but options are also documented in tables and
# named in prose, and those had no check: a table could list an option that does not
# exist or a default that changed. So a table that documents options or config keys
# carries a marker naming the section it documents,
#
#     <!-- doctest: options of=scanners.bandit -->
#     | Option | Type | Default | Description |
#
# and every row must be a key of that section, with the Default cell equal to the
# model's default. A table that looks like one and has no marker is an error, so a
# new table cannot skip the check by omission.

#: First header cells that make a table an options table. A Default column does too.
OPTION_TABLE_HEADERS = frozenset(
    {
        "option",
        "options",
        "key",
        "keys",
        "field",
        "fields",
        "setting",
        "settings",
        "argument",
        "arguments",
        "param",
        "parameter",
        "parameters",
        "prop",
        "props",
    }
)
#: Headers of the column a table states one key's default in. Renaming the column does
#: not take a table out of the default comparison. "Defaults" is left out: a summary
#: table uses it for a list of several keys' defaults in one row.
DEFAULT_HEADERS = frozenset(
    {
        "default",
        "default value",
        "defaults to",
        "if not passed",
        "if not set",
        "if unset",
    }
)
#: ``of=`` prefix for the workspace policy file, whose schema is not AshConfig's.
WORKSPACE_POLICY = "workspace-policy"
#: Keys an ASH config file may carry that are loader directives, not AshConfig fields.
LOADER_KEYS = {"extends": None, "patch": None}
#: Default-cell phrases that state no comparable value (refgen's reference pages).
DEFAULT_PHRASES_NOT_COMPARED = frozenset(
    {
        "computed at run time",
        "depends on the platform",
        "the plugin's own name",
        "the plugin's defaults",
    }
)
_WILDCARD = re.compile(r"^(\*|<[^>]*>|\{[^}]*\}|\.\.\.)$")
_PLATFORMS = {"linux": "Linux", "darwin": "macOS", "win32": "Windows"}
#: Not a value, so nothing to compare: the sentinel for a section's default.
SECTION = object()
COMPUTED = object()
#: A CloudFormation parameter or GitHub input with no default: given at deploy or call time.
REQUIRED = object()


@dataclass
class KeySpec:
    """One key a table row may name: its spellings, and the default to compare against."""

    names: tuple[str, ...]
    required: bool = False
    default: Any = None
    compare: bool = True
    #: How the Default cell is read: "yaml" (config, CLI and MCP values), "python"
    #: (a literal, or the source of the default), or "text" (the string as written:
    #: Dockerfile and CloudFormation defaults are strings, and YAML would read NO as
    #: false).
    syntax: str = "yaml"


@dataclass(frozen=True)
class Expression:
    """A default that is an expression in the code rather than a literal
    (ExecutionStrategy.PARALLEL), compared by its text. A cell may name the member
    alone: PARALLEL for ExecutionStrategy.PARALLEL."""

    text: str

    def matches(self, written: str) -> bool:
        written = re.sub(r"\s+", "", written)
        return written == self.text or self.text.endswith("." + written)


@dataclass
class Section:
    """What an options marker's ``of=`` names: a label and the keys under it."""

    label: str
    keys: dict[str, KeySpec]


def _model_of(annotation: Any) -> tuple[str, Any]:
    """('model' | 'list' | 'dict' | 'value', model class or None) for a field type."""
    import typing

    from pydantic import BaseModel

    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return "model", annotation
    origin = typing.get_origin(annotation)
    args = [a for a in typing.get_args(annotation) if a is not type(None)]
    if origin in (list, tuple, set, frozenset):
        inner = next(
            (a for a in args if isinstance(a, type) and issubclass(a, BaseModel)), None
        )
        return ("list", inner) if inner else ("value", None)
    if origin is dict:
        inner = args[1] if len(args) == 2 else None
        kind, model = _model_of(inner) if inner is not None else ("value", None)
        return ("dict", model if kind == "model" else None)
    for arg in args:
        kind, model = _model_of(arg)
        if model is not None:
            return kind, model
    return "value", None


def _plugin_entry_base(section: str, models: ConfigModels) -> type | None:
    """The base config class every plugin of a section derives from (name, enabled, options)."""
    for config_cls in models.plugin_configs.get(section, {}).values():
        for base in config_cls.__mro__:
            if base.__name__.endswith("PluginConfigBase"):
                return base
    return None


def _options_model(config_cls: type) -> type | None:
    info = config_cls.model_fields.get("options")
    return _model_of(info.annotation)[1] if info is not None else None


@dataclass
class PathEnd:
    """Where a config path ends: a model, or a value (model None)."""

    model: type | None
    plugin: str | None = None
    #: The path ended at a free-form mapping or a placeholder; nothing more is checked.
    open: bool = False


def resolve_config_path(
    segments: list[str], models: ConfigModels
) -> tuple[PathEnd | None, str | None]:
    """Walk a dotted config path from the top of an ASH config, as ASH reads it.

    Under scanners, reporters and converters a segment is a plugin name, which must be
    one this ASH ships (community plugins included, when their module imports). A
    placeholder there (``*``, ``<name>``) stands for any plugin: the rest of the path
    must hold for the plugin base or for at least one plugin. A placeholder elsewhere
    ends the check. A list of sections is entered directly
    (``global_settings.suppressions.reason``).
    """
    return _resolve_from(models.ash_config, segments, [], models)


def _resolve_from(
    current: type | None, segments: list[str], walked: list[str], models: ConfigModels
) -> tuple[PathEnd | None, str | None]:
    from automated_security_helper.base.options import ScannerOptionsBase

    walked = list(walked)
    plugin: str | None = None
    position = 0
    while position < len(segments):
        segment = re.sub(r"\[\d*\]$", "", segments[position])
        position += 1
        walked.append(segment)
        here = ".".join(walked)
        section = next(
            (n for n, seg in models.segments.items() if seg is current), None
        )
        if section is not None:
            if _WILDCARD.match(segment):
                base = _plugin_entry_base(section, models)
                rest = segments[position:]
                if not rest:
                    return PathEnd(base, plugin="*"), None
                first_problem = None
                candidates = [base, *models.plugin_configs.get(section, {}).values()]
                for candidate in candidates:
                    end, problem = _resolve_from(candidate, rest, walked, models)
                    if problem is None:
                        return end, None
                    first_problem = first_problem or problem
                return None, first_problem
            config_cls = models.plugin_configs.get(section, {}).get(segment)
            if config_cls is None:
                field_name = _field_keys(current).get(segment)
                if field_name is not None:
                    config_cls = _model_of(current.model_fields[field_name].annotation)[
                        1
                    ]
            if config_cls is None:
                known = sorted(models.plugin_configs.get(section, {}))
                close = difflib.get_close_matches(segment, known, n=1)
                hint = f"; did you mean '{close[0]}'?" if close else ""
                return (
                    None,
                    f"{here}: this ASH ships no {section[:-1]} named '{segment}'{hint}",
                )
            current, plugin = config_cls, segment
            continue
        plugin = None
        if current is None:
            return (
                None,
                f"{'.'.join(walked[:-1])} is a value, so it has no key '{segment}'",
            )
        if _WILDCARD.match(segment):
            return PathEnd(None, open=True), None
        keys = dict(_field_keys(current))
        if current is models.ash_config:
            keys.update({key: key for key in LOADER_KEYS})
        if issubclass(current, ScannerOptionsBase):
            keys.update(
                {key: key for key in GENERIC_SCANNER_OPTION_KEYS if key not in keys}
            )
        if segment not in keys:
            close = difflib.get_close_matches(segment, sorted(keys), n=1)
            hint = f"; did you mean '{close[0]}'?" if close else ""
            return None, f"{here}: {current.__name__} has no key '{segment}'{hint}"
        field_name = keys[segment]
        if field_name not in current.model_fields:
            current = None  # a loader directive or a generically read option
            continue
        kind, model = _model_of(current.model_fields[field_name].annotation)
        if kind == "dict":
            if model is None or position >= len(segments):
                return PathEnd(None, open=True), None
            position += 1  # the free key under the mapping
            walked.append(segments[position - 1])
        current = model
    return PathEnd(current, plugin=plugin), None


def _normalize(value: Any) -> Any:
    import enum

    from pydantic import BaseModel

    if isinstance(value, BaseModel):
        return SECTION
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _normalize(v) for k, v in value.items()}
    return value


def _model_keys(model: type) -> dict[str, KeySpec]:
    from pydantic import BaseModel  # noqa: F401 -- for the isinstance in _normalize

    keys: dict[str, KeySpec] = {}
    spellings = _field_keys(model)
    for field_name, info in model.model_fields.items():
        names = tuple(sorted({k for k, v in spellings.items() if v == field_name}))
        if info.is_required():
            spec = KeySpec(names, required=True, compare=True)
        else:
            try:
                spec = KeySpec(
                    names,
                    default=_normalize(info.get_default(call_default_factory=True)),
                )
            except Exception:  # noqa: BLE001 -- a factory that needs the other fields
                spec = KeySpec(names, default=COMPUTED, compare=False)
        for name in names:
            keys[name] = spec
    return keys


def options_section(
    of: str, models: ConfigModels, code: Path | None = None
) -> tuple[Section | None, str | None]:
    """The keys an ``options of=`` marker names, or why it names nothing.

    ``code`` is the tree the Python, Dockerfile and CloudFormation sections are read
    from; it defaults to the checkout of the installed ASH.
    """
    from automated_security_helper.base.options import ScannerOptionsBase

    code = code or code_root(REPO_ROOT)
    if of == "mcp" or of.startswith("mcp."):
        return mcp_section(of)
    if of == "python" or of.startswith("python."):
        return python_section(of, code)
    if of == "dockerfile":
        return dockerfile_section(code)
    if of == "cloudformation" or of.startswith("cloudformation:"):
        return cloudformation_section(of, code)
    if of == "github-inputs" or of.startswith("github-inputs:"):
        return github_inputs_section(of, code)
    if of == "typescript" or of.startswith("typescript:"):
        return typescript_section(of, code)
    if of == "config":
        keys = _model_keys(models.ash_config)
        keys.update({key: KeySpec((key,), default=None) for key in LOADER_KEYS})
        return Section("the top level of an ASH config", keys), None
    if of == "cli" or of.startswith("cli."):
        return cli_section(of)
    if of == WORKSPACE_POLICY or of.startswith(WORKSPACE_POLICY + "."):
        if models.workspace_policy is None:
            return None, f"of={of}: this ASH has no workspace policy file"
        rest = of.split(".")[1:]
        if not rest:
            return Section(
                "the workspace policy file", _model_keys(models.workspace_policy)
            ), None
        end, problem = _resolve_from(
            models.workspace_policy, rest, [WORKSPACE_POLICY], models
        )
        if problem:
            return None, problem
        if end.model is None:
            return None, f"of={of} names a value, not a section with keys"
        return Section(f"{of} ({end.model.__name__})", _model_keys(end.model)), None
    end, problem = resolve_config_path(of.split("."), models)
    if problem:
        return None, problem
    model = end.model
    if end.plugin and end.plugin != "*" and model is not None:
        model = _options_model(model)  # a plugin's table lists its options
    if model is None:
        return None, f"of={of} names a value, not a section with keys"
    keys = _model_keys(model)
    if issubclass(model, ScannerOptionsBase):
        for key in GENERIC_SCANNER_OPTION_KEYS:
            keys.setdefault(key, KeySpec((key,), compare=False))
    return Section(f"{of} ({model.__name__})", keys), None


def cli_section(of: str) -> tuple[Section | None, str | None]:
    """The options and arguments of an ``ash`` command, from the click tree."""
    import typer

    from automated_security_helper.cli.main import app

    command = typer.main.get_command(app)
    words = of.split(".")[1:]
    for word in words:
        sub = getattr(command, "commands", {}).get(word)
        if sub is None:
            return None, f"of={of}: ash {' '.join(words)} is not a command"
        command = sub
    keys: dict[str, KeySpec] = {}
    for param in command.params:
        if param.param_type_name == "option":
            names = tuple(param.opts) + tuple(param.secondary_opts)
        else:
            names = (param.name, param.name.upper(), param.human_readable_name)
        default = param.default
        compare = not callable(default)
        spec = KeySpec(
            names,
            required=bool(param.required),
            default=_normalize(default) if compare else COMPUTED,
            compare=compare,
        )
        for name in names:
            keys[name] = spec
    keys["--help"] = KeySpec(("--help",), compare=False)
    return Section(f"of={of} (ash {' '.join(words)})".replace(" )", ")"), keys), None


@functools.lru_cache(maxsize=None)
def _mcp_tool_schemas() -> dict[str, dict[str, Any]]:
    """Each MCP tool's input schema, as the server lists it to a client."""
    import asyncio

    from automated_security_helper.cli import mcp_server

    tools = asyncio.run(mcp_server.mcp.list_tools())
    return {tool.name: dict(tool.input_schema or {}) for tool in tools}


def mcp_section(of: str) -> tuple[Section | None, str | None]:
    """The parameters of one MCP tool: its input schema's properties and defaults."""
    try:
        tools = _mcp_tool_schemas()
    except Exception as exc:  # noqa: BLE001 -- the server not loading is the finding
        return None, f"of={of}: the MCP server's tools cannot be listed ({exc!r})"
    words = of.split(".")[1:]
    if len(words) != 1:
        return None, (
            f"of={of}: name one tool, as of=mcp.<tool>; tools: {', '.join(sorted(tools))}"
        )
    schema = tools.get(words[0])
    if schema is None:
        close = difflib.get_close_matches(words[0], sorted(tools), n=1)
        hint = f"; did you mean '{close[0]}'?" if close else ""
        return None, f"of={of}: the MCP server has no tool {words[0]}{hint}"
    required = set(schema.get("required", []))
    keys: dict[str, KeySpec] = {}
    for name, prop in schema.get("properties", {}).items():
        if name in required:
            keys[name] = KeySpec((name,), required=True)
        else:
            keys[name] = KeySpec((name,), default=_normalize(prop.get("default")))
    return Section(f"of={of} (the input schema of the {words[0]} tool)", keys), None


def python_section(of: str, code: Path) -> tuple[Section | None, str | None]:
    """The parameters of a Python function, method or class, read from its source.

    of=python.<module>.<name>[.<method>] names a module file under the code tree, then
    a function, a class (its __init__) or a class's method. The source is parsed, not
    imported, so a module that needs an extra the docs job lacks can still be named.
    Defaults are compared as Python: a literal by value, anything else
    (ExecutionStrategy.PARALLEL) by its source text.
    """
    words = of.split(".")[1:]
    module_file: Path | None = None
    rest: list[str] = []
    for end in range(len(words), 0, -1):
        base = code.joinpath(*words[:end])
        for candidate in (base.parent / f"{base.name}.py", base / "__init__.py"):
            if candidate.is_file():
                module_file, rest = candidate, words[end:]
                break
        if module_file is not None:
            break
    if module_file is None:
        return (
            None,
            f"of={of}: no module {'.'.join(words) or '<module>'} in the code tree",
        )
    if not rest:
        return None, (
            f"of={of} names a module; add the function or class, as of={of}.<function>"
        )
    try:
        tree = ast.parse(module_file.read_text(encoding="utf-8"))
    except SyntaxError as exc:
        return (
            None,
            f"of={of}: {rel_path(module_file, code)} does not parse ({exc.msg})",
        )
    body: list[ast.stmt] = tree.body
    node: ast.AST | None = None
    parent_is_class = False
    for index, name in enumerate(rest):
        found = next(
            (
                item
                for item in body
                if isinstance(
                    item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                )
                and item.name == name
            ),
            None,
        )
        if found is None:
            where = ".".join(words[: len(words) - len(rest) + index])
            nor = (
                f", and there is no module {where}.{name}"
                if index == 0 and module_file.name == "__init__.py"
                else ""
            )
            return None, f"of={of}: {where} defines no function or class {name}{nor}"
        if index < len(rest) - 1 and not isinstance(found, ast.ClassDef):
            return (
                None,
                f"of={of}: {name} is a function, so it has no {rest[index + 1]}",
            )
        parent_is_class = isinstance(node, ast.ClassDef)
        node = found
        if isinstance(found, ast.ClassDef):
            body = found.body
    if isinstance(node, ast.ClassDef):
        init = next(
            (
                item
                for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                and item.name == "__init__"
            ),
            None,
        )
        if init is None:
            return None, f"of={of}: the class defines no __init__; name a method"
        node, parent_is_class = init, True
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None, f"of={of} names no function"
    arguments = node.args
    positional = arguments.posonlyargs + arguments.args
    defaults: list[ast.expr | None] = [None] * (
        len(positional) - len(arguments.defaults)
    ) + list(arguments.defaults)
    pairs = list(zip(positional, defaults)) + list(
        zip(arguments.kwonlyargs, arguments.kw_defaults)
    )
    if parent_is_class and pairs and pairs[0][0].arg in ("self", "cls"):
        pairs = pairs[1:]
    keys: dict[str, KeySpec] = {}
    for argument, default in pairs:
        if default is None:
            spec = KeySpec((argument.arg,), required=True, syntax="python")
        else:
            try:
                value: Any = ast.literal_eval(default)
            except (ValueError, SyntaxError, TypeError):
                value = Expression(re.sub(r"\s+", "", ast.unparse(default)))
            spec = KeySpec((argument.arg,), default=value, syntax="python")
        keys[argument.arg] = spec
    label = f"of={of} ({rel_path(module_file, code)}:{node.lineno})"
    return Section(label, keys), None


def dockerfile_section(code: Path) -> tuple[Section | None, str | None]:
    """The build arguments of the shipped Dockerfile, with the defaults its ARGs give."""
    keys: dict[str, KeySpec] = {}
    found = False
    for rel in SHIPPED_DOCKERFILES:
        path = code / rel
        if not path.is_file():
            continue
        found = True
        for name, declared in dockerfile_arg_defaults(
            path.read_text(encoding="utf-8")
        ).items():
            # A stage that re-declares an ARG without a value inherits the global one.
            values = {value for value in declared if value is not None}
            spec = (
                KeySpec((name,), default=next(iter(values)), syntax="text")
                if len(values) == 1
                else KeySpec((name,), default=None, compare=not values, syntax="text")
            )
            keys[name] = spec
    if not found:
        return None, "of=dockerfile: the code tree has no " + ", ".join(
            SHIPPED_DOCKERFILES
        )
    return Section(f"of=dockerfile ({', '.join(SHIPPED_DOCKERFILES)})", keys), None


def cloudformation_section(of: str, code: Path) -> tuple[Section | None, str | None]:
    """The Parameters of CloudFormation templates: one file, or every template in a
    directory, whose parameters are pooled. A parameter whose default differs between
    templates is listed without a default to compare."""
    import yaml

    rel = of.partition(":")[2].strip()
    problem = save_as_problem(rel) if rel else "a path is missing"
    if problem:
        return None, (
            f"of={of}: name a template or a directory of templates in the code tree, "
            f"as of=cloudformation:deploy/cdk/templates ({problem})"
        )
    target = code / rel
    if target.is_dir():
        files = sorted(
            p
            for p in target.iterdir()
            if p.is_file() and p.suffix in (".json", ".yaml", ".yml")
        )
    elif target.is_file():
        files = [target]
    else:
        return None, f"of={of}: {rel} is not in the code tree"

    class _TagTolerantLoader(yaml.SafeLoader):
        """Reads !Ref, !Sub and the other short-form intrinsics as plain values."""

    _TagTolerantLoader.add_multi_constructor("!", lambda loader, suffix, node: None)
    pooled: dict[str, list[Any]] = {}
    templates = 0
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
            data = (
                json.loads(text)
                if path.suffix == ".json"
                else yaml.load(text, Loader=_TagTolerantLoader)  # noqa: S506 -- a SafeLoader subclass
            )
        except (ValueError, yaml.YAMLError) as exc:
            return None, f"of={of}: {rel_path(path, code)} does not parse ({exc})"
        parameters = data.get("Parameters") if isinstance(data, dict) else None
        if not isinstance(parameters, dict):
            continue
        templates += 1
        for name, spec in parameters.items():
            default = (
                spec.get("Default", REQUIRED) if isinstance(spec, dict) else REQUIRED
            )
            pooled.setdefault(name, []).append(default)
    if not templates:
        return None, f"of={of}: {rel} holds no CloudFormation template with Parameters"
    keys: dict[str, KeySpec] = {}
    for name, defaults in pooled.items():
        distinct = {json.dumps(d, default=str) for d in defaults}
        if len(distinct) > 1:
            keys[name] = KeySpec((name,), compare=False, syntax="text")
        elif defaults[0] is REQUIRED:
            keys[name] = KeySpec((name,), required=True, syntax="text")
        else:
            value = defaults[0]
            keys[name] = KeySpec(
                (name,),
                default=value if isinstance(value, str) else json.dumps(value),
                syntax="text",
            )
    count = f"{templates} template{'s' if templates != 1 else ''}"
    return Section(f"of={of} ({count})", keys), None


def github_inputs_section(of: str, code: Path) -> tuple[Section | None, str | None]:
    """The inputs of a GitHub Action (its action.yml, or the directory holding one) or of
    a workflow (its workflow_call and workflow_dispatch inputs).

    Defaults are compared as the text GitHub passes: a workflow's boolean default true
    is the string true, as an action's default 'true' is.
    """
    import yaml

    rel = of.partition(":")[2].strip()
    problem = save_as_problem(rel) if rel else "a path is missing"
    if problem:
        return None, (
            f"of={of}: name an action or a workflow in the code tree, as "
            f"of=github-inputs:.github/workflows/<file>.yml ({problem})"
        )
    target = code / rel
    if target.is_dir():
        target = next(
            (
                target / n
                for n in ("action.yml", "action.yaml")
                if (target / n).is_file()
            ),
            target,
        )
    if not target.is_file():
        return None, f"of={of}: {rel} is not an action or a workflow in the code tree"
    try:
        data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        return None, f"of={of}: {rel} does not parse ({exc})"
    if not isinstance(data, dict):
        return None, f"of={of}: {rel} is not an action or a workflow"
    groups: list[dict[str, Any]] = []
    if isinstance(data.get("inputs"), dict) and "runs" in data:
        groups.append(data["inputs"])
        kind = "action"
    else:
        # PyYAML reads the key on: as the boolean true.
        triggers = data.get("on", data.get(True))
        triggers = triggers if isinstance(triggers, dict) else {}
        for trigger in ("workflow_call", "workflow_dispatch"):
            inputs = (triggers.get(trigger) or {}).get("inputs")
            if isinstance(inputs, dict):
                groups.append(inputs)
        kind = "workflow"
    if not groups:
        return None, f"of={of}: {rel} declares no inputs"

    def as_text(value: Any) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        return "" if value is None else str(value)

    keys: dict[str, KeySpec] = {}
    seen: dict[str, set[str]] = {}
    for inputs in groups:
        for name, spec in inputs.items():
            spec = spec if isinstance(spec, dict) else {}
            if spec.get("required") is True and "default" not in spec:
                state = REQUIRED
            else:
                state = as_text(spec.get("default"))
            seen.setdefault(str(name), set()).add(state)
    for name, states in seen.items():
        if len(states) > 1:
            keys[name] = KeySpec((name,), compare=False, syntax="text")
        elif REQUIRED in states:
            keys[name] = KeySpec((name,), required=True, syntax="text")
        else:
            keys[name] = KeySpec((name,), default=next(iter(states)), syntax="text")
    return Section(f"of={of} (the {kind}'s inputs)", keys), None


#: A JSDoc comment, or the start of an interface property (``readonly name?:``).
_TS_TOKEN = re.compile(
    r"/\*\*(?P<doc>.*?)\*/"
    r"|^[ \t]*(?:readonly[ \t]+)?(?P<name>[A-Za-z_$][\w$]*)(?P<optional>\?)?[ \t]*:",
    re.DOTALL | re.MULTILINE,
)


def typescript_section(of: str, code: Path) -> tuple[Section | None, str | None]:
    """The properties of a TypeScript interface, with the defaults their JSDoc states.

    of=typescript:<file>:<Interface>. A property without ? is required. A default is
    the text after @default, compared as written; "@default - <words>" describes a
    default in prose, so it is not compared. Properties inherited with extends are not
    listed.
    """
    rel, _, interface = of.partition(":")[2].rpartition(":")
    problem = save_as_problem(rel) if rel and interface else "a path or name is missing"
    if problem:
        return None, (
            f"of={of}: name a file in the code tree and an interface in it, as "
            f"of=typescript:<file>.ts:<Interface> ({problem})"
        )
    path = code / rel
    if not path.is_file():
        return None, f"of={of}: {rel} is not in the code tree"
    text = path.read_text(encoding="utf-8")
    start = re.search(rf"\binterface\s+{re.escape(interface)}\b[^{{]*{{", text)
    if start is None:
        return None, f"of={of}: {rel} declares no interface {interface}"
    depth, index = 1, start.end()
    while index < len(text) and depth:
        depth += {"{": 1, "}": -1}.get(text[index], 0)
        index += 1
    body = text[start.end() : index - 1]
    keys: dict[str, KeySpec] = {}
    doc: str | None = None
    for token in _TS_TOKEN.finditer(body):
        if token.group("doc") is not None:
            doc = token.group("doc")
            continue
        tag = re.search(r"@default[ \t]+(.+)", doc) if doc else None
        doc = None
        name = token.group("name")
        if not token.group("optional"):
            keys[name] = KeySpec((name,), required=True, syntax="text")
        elif tag is None:
            keys[name] = KeySpec((name,), default=None, syntax="text")
        elif tag.group(1).startswith("-"):
            keys[name] = KeySpec((name,), compare=False, syntax="text")
        else:
            value = tag.group(1).strip()
            quoted = re.fullmatch(r"(['\"])(.*)\1", value)
            if quoted:
                default: Any = quoted.group(2)
            elif re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+", value):
                default = Expression(value)  # ASHInstallMode.PIP
            else:
                default = value
            keys[name] = KeySpec((name,), default=default, syntax="text")
    if not keys:
        return None, f"of={of}: interface {interface} declares no properties"
    return Section(f"of={of}", keys), None


_SPAN = re.compile(r"(`+)(.+?)\1")
_ENV_FORM = re.compile(r"^(?:from `([A-Za-z_][A-Za-z0-9_]*)`, else )+")
_ENV_NAMES = re.compile(r"from `([A-Za-z_][A-Za-z0-9_]*)`, else ")


def _cell_value(text: str, syntax: str = "yaml") -> tuple[bool, Any]:
    """(parsed, value) of a Default cell holding one value, in a code span or bare."""
    import yaml

    spans = _SPAN.findall(text)
    if len(spans) == 1 and _SPAN.fullmatch(text.strip()):
        content = spans[0][1].strip()
    elif not spans:
        content = text.strip()
        if content.lower() in ("", "-", "—", "none", "null", "n/a"):
            return True, None
    else:
        return False, None
    if syntax == "text":
        quoted = re.fullmatch(r"(['\"])(.*)\1", content)
        return True, quoted.group(2) if quoted else content
    if syntax == "python":
        try:
            return True, ast.literal_eval(content)
        except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
            return True, Expression(re.sub(r"\s+", "", content))
    try:
        return True, yaml.safe_load(content) if content else ""
    except yaml.YAMLError:
        return True, content


def _same_default(written: Any, actual: Any) -> bool:
    if isinstance(written, Expression) and isinstance(actual, str):
        # A Python string written without quotes: `t3.medium` for "t3.medium".
        return written.text == re.sub(r"\s+", "", actual)
    if isinstance(actual, Expression) and isinstance(written, (str, Expression)):
        return actual.matches(written if isinstance(written, str) else written.text)
    if isinstance(written, str) and isinstance(actual, str):
        if written.startswith("<repository>/"):
            return actual.endswith(written[len("<repository>") :])
        if written.startswith("~/"):
            return actual == os.path.expanduser(written) or actual.endswith(written[1:])
    if (
        isinstance(written, (int, float))
        and isinstance(actual, (int, float))
        and not isinstance(written, bool)
    ):
        return float(written) == float(actual) and not isinstance(actual, bool)
    if written is None and actual in (None, "", [], {}):
        return True
    return written == actual


def default_problem(cell: str, spec: KeySpec) -> str | None:
    """Why a Default cell does not state the model's default, or None."""
    text = re.sub(r"<[^>]+>", "", cell).strip()
    # A phrase may be set in emphasis (*required*); a value belongs in a code span.
    lowered = re.sub(r"^([*_]+)(.+?)\1$", r"\2", text).strip().lower()
    if lowered in DEFAULT_PHRASES_NOT_COMPARED or not spec.compare:
        return None

    def shown() -> str:
        return _shown(spec.default, spec.syntax)

    if lowered == "required":
        return None if spec.required else f"says required, but the default is {shown()}"
    if spec.required:
        return f"says {text or 'nothing'}, but the key is required"
    if lowered == "see the section":
        return (
            None
            if spec.default is SECTION
            else f"says see the section, but the default is {shown()}"
        )
    if lowered in ("not set", "empty", "off", "on"):
        allowed = {
            "not set": (None, False, [], ""),
            "empty": ("", [], {}),
            "off": (False,),
            "on": (True,),
        }[lowered]
        return (
            None
            if any(spec.default == a and type(spec.default) is type(a) for a in allowed)
            else f"says {text}, but the default is {shown()}"
        )
    env = _ENV_FORM.match(text)
    if env:
        names = _ENV_NAMES.findall(text)
        if any(name in os.environ for name in names):
            return None  # the model's default was read from this environment
        text = text[env.end() :]
    platform = _PLATFORMS.get(sys.platform)
    if " on " in text and re.search(r"\bon (Linux|macOS|Windows)\b", text):
        chosen = None
        for group in text.split("; "):
            value, _, where = group.rpartition(" on ")
            names = re.split(r", | and ", where)
            if platform in names:
                chosen = value
        if chosen is None:
            return None  # this platform is not one the cell names
        text = chosen
    parsed, value = _cell_value(text, spec.syntax)
    if not parsed:
        return f"'{cell}' is not a value or a recognized phrase; put the default in one code span"
    if spec.default is SECTION:
        return f"says {text}, but the key is a section (write: see the section)"
    if not _same_default(value, spec.default):
        return f"says {text}, but the default is {shown()}"
    return None


def _shown(value: Any, syntax: str = "yaml") -> str:
    if value is SECTION:
        return "a section"
    if isinstance(value, Expression):
        return f"`{value.text}`"
    if syntax == "python":
        return f"`{value!r}`"
    if syntax == "text":
        return f"`{value}`" if value else "empty"
    return "`" + json.dumps(value, default=str) + "`"


def _is_options_table(table: Table) -> bool:
    if not table.header:
        return False
    cells = [re.sub(r"[`*_]", "", cell).strip().lower() for cell in table.header]
    if cells[0] in _ENV_TABLE_HEADERS:
        return False
    return cells[0] in OPTION_TABLE_HEADERS or bool(DEFAULT_HEADERS & set(cells))


def _row_key(cell: str) -> str:
    """The key a row names: its first code span, after any anchor element."""
    cell = re.sub(r"<a\s[^>]*>\s*</a>", "", cell)
    span = _SPAN.search(cell)
    return (span.group(2) if span else re.sub(r"<[^>]+>", "", cell)).strip()


_LIST_SEPARATORS = re.compile(r"(?:\s|,|\band\b|\bor\b)*")


def _row_keys(cell: str) -> list[str]:
    """The keys a row names: every code span when the cell is only a list of them
    (`quiet`, `simple` and `debug`), else the first one."""
    bare = re.sub(r"<a\s[^>]*>\s*</a>", "", cell)
    spans = [match.group(2).strip() for match in _SPAN.finditer(bare)]
    if len(spans) > 1 and _LIST_SEPARATORS.fullmatch(_SPAN.sub("", bare)):
        return spans
    return [_row_key(cell)]


def _row_defaults(cell: str, count: int) -> list[str]:
    """The Default cell for each of a row's keys: one value per key, in order, when
    the cell lists exactly that many code spans; else the one cell for all of them."""
    if count > 1:
        spans = [match.group(0) for match in _SPAN.finditer(cell)]
        if len(spans) == count and _LIST_SEPARATORS.fullmatch(_SPAN.sub("", cell)):
            return spans
    return [cell] * count


#: A config path in prose: a top-level key, dotted, maybe with a value after it.
_CONFIG_PATH_SPAN = re.compile(
    r"^(?P<path>[A-Za-z_][\w-]*(?:\.(?:[\w-]+|\*|<[^<>]+>|\{[^{}]+\})(?:\[\d*\])?)+)"
    r"(?:\s*(?:\+?=|:)\s*.*)?$"
)
_FILE_EXTENSIONS = frozenset(
    {
        "md",
        "yaml",
        "yml",
        "json",
        "toml",
        "py",
        "txt",
        "sh",
        "html",
        "xml",
        "csv",
        "sarif",
        "zip",
        "tar",
        "gz",
        "js",
        "ts",
        "lock",
    }
)


def config_path_problem(span: str, models: ConfigModels) -> str | None:
    """Why a code span that is a dotted config path does not resolve, or None."""
    match = _CONFIG_PATH_SPAN.match(span.strip())
    if not match:
        return None
    segments = match.group("path").split(".")
    top = dict(_field_keys(models.ash_config))
    top.update({key: key for key in LOADER_KEYS})
    if segments[0] not in top or "/" in span:
        return None
    if len(segments) == 2 and segments[-1].lower() in _FILE_EXTENSIONS:
        return None  # sandbox.md and reporters.csv read as file names
    _end, problem = resolve_config_path(segments, models)
    if problem and models.workspace_policy is not None:
        # The workspace policy file is a second schema whose top-level key,
        # workspace, is also an AshConfig key; a path that holds there is valid.
        _end, other = _resolve_from(models.workspace_policy, segments, [], models)
        if other is None:
            return None
    return f"`{span}`: {problem}" if problem else None


def check_option_tables(
    files: Iterable[Path], root: Path = REPO_ROOT, code: Path | None = None
) -> list[Finding]:
    """Option tables name their section, list its keys with its defaults; config paths resolve.

    ``code`` is the tree Python, Dockerfile and CloudFormation sections are read from;
    by default the checkout of the installed ASH.
    """
    models = load_config_models()
    code = code or code_root(root)
    findings: list[Finding] = []
    for page in load_pages(files, root):
        if page.rel in HISTORICAL_DOCS:
            continue
        for table in page.tables:
            if table.marker is None:
                if _is_options_table(table):
                    findings.append(
                        Finding(
                            "options",
                            page.rel,
                            table.header_line,
                            "this table documents options or keys but names no section: put "
                            "<!-- doctest: options of=<section> --> on the line above its header, "
                            "for example of=scanners.bandit, of=cli.scan, of=mcp.run_ash_scan, "
                            "of=python.<module>.<function>, of=dockerfile, "
                            "of=cloudformation:<template or directory>, "
                            "of=github-inputs:<action or workflow> or "
                            "of=typescript:<file>:<Interface>",
                        )
                    )
                continue
            line = table.marker.line
            of = table.marker.keys.get("of")
            extra = set(table.marker.keys) - {"of"}
            if extra:
                findings.append(
                    Finding(
                        "options",
                        page.rel,
                        line,
                        f"an options marker takes only of=, not {sorted(extra)}",
                    )
                )
            if not isinstance(of, str) or not of:
                findings.append(
                    Finding(
                        "options",
                        page.rel,
                        line,
                        "an options marker needs of=<section>",
                    )
                )
                continue
            section, problem = options_section(of, models, code)
            if problem:
                findings.append(Finding("options", page.rel, line, problem))
                continue
            headers = [
                re.sub(r"[`*_]", "", cell).strip().lower() for cell in table.header
            ]
            default_column = next(
                (
                    index
                    for index, cell in enumerate(headers)
                    if cell in DEFAULT_HEADERS
                ),
                None,
            )
            for number, cells in table.rows:
                keys = _row_keys(cells[0]) if cells else [""]
                defaults = (
                    _row_defaults(cells[default_column], len(keys))
                    if default_column is not None and default_column < len(cells)
                    else None
                )
                for position, key in enumerate(keys):
                    spec = section.keys.get(key)
                    head = re.split(r"[\s=]", key, maxsplit=1)[0]
                    if spec is None and head != key:
                        spec = section.keys.get(head)  # `--build-target ci`
                    if spec is None:
                        close = difflib.get_close_matches(
                            key, sorted(section.keys), n=1
                        )
                        hint = f"; did you mean '{close[0]}'?" if close else ""
                        findings.append(
                            Finding(
                                "options",
                                page.rel,
                                number,
                                f"'{key}' is not a key of {section.label}{hint}",
                            )
                        )
                        continue
                    if defaults is not None:
                        problem = default_problem(defaults[position], spec)
                        if problem:
                            findings.append(
                                Finding(
                                    "options",
                                    page.rel,
                                    number,
                                    f"'{key}' default {problem}",
                                )
                            )
        for number, line in page.prose:
            for span in inline_code_spans(line):
                problem = config_path_problem(span, models)
                if problem:
                    findings.append(Finding("options", page.rel, number, problem))
    return findings


# ---------------------------------------------------------------------------
# Check: python blocks
# ---------------------------------------------------------------------------


def saved_module(path: str | None) -> tuple[str, str] | None:
    """The module a save-as path creates and the package its relative imports use.

    my_plugins/scanner.py gives ("my_plugins.scanner", "my_plugins"), and
    my_plugins/__init__.py gives ("my_plugins", "my_plugins"). None when the path is not
    an importable module (not .py, refused, or a directory such as .ash in the way).
    """
    if not path or not path.endswith(".py") or save_as_problem(path):
        return None
    parts = [p for p in path.replace("\\", "/").split("/") if p not in ("", ".")]
    parts[-1] = parts[-1][: -len(".py")]
    is_package = parts[-1] == "__init__"
    if is_package:
        parts = parts[:-1]
    if not parts or not all(part.isidentifier() for part in parts):
        return None
    package = parts if is_package else parts[:-1]
    return ".".join(parts), ".".join(package)


def _module_names(tree: ast.Module) -> frozenset[str] | None:
    """The names a module defines at top level, or None when it can add names at run
    time (a star import, a module __getattr__, or globals()/setattr/exec)."""
    names = {
        name
        for node in ast.walk(tree)
        if isinstance(node, ast.Global)
        for name in node.names
    }
    pending: list[ast.AST] = list(tree.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == "__getattr__":
                return None
            names.add(node.name)
            continue
        if isinstance(node, ast.Lambda):
            continue
        if isinstance(node, ast.alias):
            if node.name == "*":
                return None
            names.add(node.asname or node.name.split(".")[0])
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in ("globals", "setattr", "exec")
        ):
            return None
        pending.extend(ast.iter_child_nodes(node))
    return frozenset(names)


def page_saved_modules(page: Page) -> dict[str, frozenset[str] | None]:
    """Modules the page's own save-as blocks create, with the names each defines.

    Later blocks of the page can import them. Saving my_plugins/scanner.py also makes
    my_plugins a package, which defines no names unless my_plugins/__init__.py is saved
    too. A value of None means any name is accepted (see _module_names).
    """
    modules: dict[str, frozenset[str] | None] = {}
    for block in page.blocks:
        saved = saved_module(block.save_as)
        if saved is None:
            continue
        parts = saved[0].split(".")
        for end in range(1, len(parts)):
            modules.setdefault(".".join(parts[:end]), frozenset())
        try:
            modules[saved[0]] = _module_names(ast.parse(block.body))
        except SyntaxError:
            modules[saved[0]] = None  # the python check reports the syntax error
    return modules


def _import_problems(
    tree: ast.AST,
    local: dict[str, frozenset[str] | None] | None = None,
    package: str = "",
) -> list[tuple[int, str]]:
    """Imports that do not resolve.

    ``local`` holds the modules the page saves itself (page_saved_modules), and
    ``package`` is the package of the block's own save-as path, which relative imports
    resolve against.
    """
    local = local or {}
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in local:
                    continue
                if not _module_exists(alias.name):
                    problems.append(
                        (
                            node.lineno,
                            f"import {alias.name}: no such module in the docs environment",
                        )
                    )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                base = package.split(".") if package else []
                if not base:
                    problems.append(
                        (
                            node.lineno,
                            (
                                "a relative import cannot run outside a package; save "
                                "the block into one with save-as=<package>/<module>.py"
                            ),
                        )
                    )
                    continue
                if node.level - 1 >= len(base):
                    problems.append(
                        (
                            node.lineno,
                            f"this relative import goes above the top-level package {base[0]}",
                        )
                    )
                    continue
                base = base[: len(base) - (node.level - 1)]
                module = ".".join(base + ([node.module] if node.module else []))
            if module in local:
                names = local[module]
                for alias in node.names:
                    if names is None or alias.name == "*" or alias.name in names:
                        continue
                    if f"{module}.{alias.name}" not in local:
                        problems.append(
                            (
                                node.lineno,
                                (
                                    f"{module} has no name {alias.name}: the page "
                                    f"saves {module} without defining it"
                                ),
                            )
                        )
                continue
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
        local = page_saved_modules(page)
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
            saved = saved_module(block.save_as)
            package = saved[1] if saved else ""
            for offset, problem in _import_problems(tree, local, package):
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


def _uses_awesome_nav(site: Site) -> tuple[bool, str]:
    """Whether mkdocs.yml enables awesome-nav, and the nav file name it reads."""
    for plugin in site.config.get("plugins") or []:
        if plugin == "awesome-nav":
            return True, NAV_FILE_NAME
        if isinstance(plugin, dict) and "awesome-nav" in plugin:
            options = plugin["awesome-nav"] or {}
            return True, str(options.get("filename", NAV_FILE_NAME))
    return False, NAV_FILE_NAME


def awesome_nav_targets(
    site: Site, filename: str
) -> tuple[set[Path], list[tuple[str, int, str]]]:
    """Pages in the navigation awesome-nav builds, and the entries it cannot resolve.

    Runs mkdocs-awesome-nav's own resolver over the docs_dir's files, so a glob means
    exactly what it means in the build: wcmatch with GLOBSTAR and EXTGLOB, relative to
    the .nav.yml it is in, matched against pages and directories that no explicit
    entry already took, in awesome-nav's priority order (explicit pages, then
    directories, deepest first, then patterns). A pattern that matches nothing is what
    awesome-nav logs as a warning, which --strict makes a build failure; here it is a
    finding. A titled entry naming a page that does not exist becomes a link in
    awesome-nav and a nav "not found" warning in mkdocs, and is a finding too.
    """
    from mkdocs.structure.files import File, Files, InclusionLevel
    from mkdocs_awesome_nav import log as nav_log
    from mkdocs_awesome_nav.nav.context import MkdocsFilesContext
    from mkdocs_awesome_nav.nav.directory import RootNavDirectory
    from mkdocs_awesome_nav.nav.link import NavLink
    from mkdocs_awesome_nav.nav.page import NavPage
    from mkdocs_awesome_nav.nav.section import NavSection

    unlisted = _not_in_nav_spec(site)
    files = []
    for path in sorted(p for p in site.docs_dir.rglob("*") if p.is_file()):
        rel = path.relative_to(site.docs_dir).as_posix()
        inclusion = (
            InclusionLevel.NOT_IN_NAV
            if rel.endswith(".md") and unlisted(rel)
            else InclusionLevel.INCLUDED
        )
        files.append(
            File(
                rel,
                str(site.docs_dir),
                str(site.docs_dir.parent / ".docs-check-site"),
                site.use_directory_urls,
                inclusion=inclusion,
            )
        )

    class Capture(logging.Handler):
        def __init__(self) -> None:
            super().__init__(logging.WARNING)
            self.messages: list[str] = []

        def emit(self, record: logging.LogRecord) -> None:
            self.messages.append(record.getMessage())

    capture = Capture()
    logger = logging.getLogger("mkdocs.plugins.awesome-nav")
    logger.addHandler(capture)
    try:
        nav_log.levels = nav_log.LogLevelsConfig()
        context = MkdocsFilesContext(Files(files), filename)
        root_section = RootNavDirectory(context.root).resolve(context)
    finally:
        logger.removeHandler(capture)

    reachable: set[Path] = set()
    problems: list[tuple[str, int, str]] = []

    def walk(items: list) -> None:
        for item in items:
            if isinstance(item, NavPage):
                reachable.add((site.docs_dir / item.page.path.as_posix()).resolve())
            elif isinstance(item, NavSection):
                walk(item.children)
            elif isinstance(item, NavLink) and not re.match(
                r"^[a-z]+:|^/|^#", item.url
            ):
                problems.append(
                    (
                        rel_path(site.docs_dir / filename, site.root),
                        1,
                        f"nav entry '{item.title}: {item.url}' names no page",
                    )
                )

    walk(root_section.children)
    for message in capture.messages:
        located = re.search(r"\[([^\]]+)\]$", message)
        where = (
            rel_path(site.docs_dir / located.group(1), site.root)
            if located
            else rel_path(site.docs_dir / filename, site.root)
        )
        pattern = re.search(r"'([^']+)'", message)
        line = _line_of(site.root / where, pattern.group(1) if pattern else "")
        problems.append((where, line, re.sub(r"\s*\[[^\]]+\]$", "", message)))
    return reachable, problems


def _line_of(path: Path, needle: str) -> int:
    if not needle or not path.is_file():
        return 1
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if needle in line:
            return number
    return 1


def nav_targets(site: Site) -> tuple[set[Path], list[tuple[str, int, str]]]:
    """Pages reachable from the navigation, and nav entries that name nothing.

    With awesome-nav, its own resolver decides (awesome_nav_targets). Without it, the
    ``nav`` in mkdocs.yml is read: each entry is a page or a URL.
    """
    awesome, filename = _uses_awesome_nav(site)
    if awesome:
        return awesome_nav_targets(site, filename)
    reachable: set[Path] = set()
    missing: list[tuple[str, int, str]] = []
    for entry in _nav_entries(site.config.get("nav") or []):
        if re.match(r"^[a-z]+://", entry):
            continue
        target = (site.docs_dir / entry).resolve()
        if target.is_file():
            reachable.add(target)
        else:
            missing.append(
                (
                    MKDOCS_YML,
                    _line_of(site.root / MKDOCS_YML, entry),
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
                f"page is in no {NAV_FILE_NAME} entry or glob and not in mkdocs.yml "
                "not_in_nav, so no reader can reach it from the site navigation",
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
# Check: the site build is strict, offline and versioned
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

#: mkdocs.yml settings the versioned site depends on. ``strict`` makes the builds mike
#: runs strict too, since mike passes no --strict; the mike plugin's two settings and
#: Material's ``extra.version`` are what scripts/docs_versions.py check verifies in a
#: real build, and are checked here as well so the lint job names a removed one.
REQUIRED_VERSIONING = {
    ("strict",): True,
    ("extra", "version", "provider"): "mike",
    ("extra", "version", "default"): "latest",
}
REQUIRED_MIKE_PLUGIN = {"alias_type": "copy", "canonical_version": "latest"}


def _workflow_runs(path: Path) -> list[str] | None:
    """Every ``run:`` script in a workflow, or None when the file does not exist."""
    import yaml

    if not path.is_file():
        return None
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return list(_strings_under_keys(document, {"run"}))


def check_site_build(root: Path = REPO_ROOT) -> list[Finding]:
    """mkdocs.yml and the docs workflows keep the build strict, offline, redirecting
    and versioned."""
    site = load_site(str(root))
    findings: list[Finding] = []

    def setting(path: tuple[str, ...]) -> Any:
        value: Any = site.config
        for part in path:
            value = value.get(part) if isinstance(value, dict) else None
        return value

    for path, wanted in REQUIRED_VALIDATION.items():
        value = setting(path)
        if value != wanted:
            findings.append(
                Finding(
                    "site",
                    MKDOCS_YML,
                    1,
                    f"{'.'.join(path)} is {value!r}; it must be {wanted!r} so --strict fails on it",
                )
            )
    for path, wanted in REQUIRED_VERSIONING.items():
        value = setting(path)
        if value != wanted:
            findings.append(
                Finding(
                    "site",
                    MKDOCS_YML,
                    1,
                    f"{'.'.join(path)} is {value!r}; the versioned site needs {wanted!r}",
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
    privacy = _plugin_config(site, "privacy")
    if privacy is None:
        findings.append(
            Finding("site", MKDOCS_YML, 1, "the privacy plugin is not configured")
        )
    else:
        findings += _privacy_fetch_findings(site, root, privacy)
    findings += _emoji_findings(site)
    mike = _plugin_config(site, "mike")
    if mike is None:
        findings.append(
            Finding(
                "site",
                MKDOCS_YML,
                1,
                "the mike plugin is not listed, so mike adds it with its defaults "
                "and extra.docs_version never reaches the pages",
            )
        )
    else:
        for key, wanted in REQUIRED_MIKE_PLUGIN.items():
            value = mike.get(key)
            if value != wanted:
                findings.append(
                    Finding(
                        "site",
                        MKDOCS_YML,
                        1,
                        f"plugins.mike.{key} is {value!r}; the versioned site needs {wanted!r}",
                    )
                )
    if not (root / DOCS_VERSIONS_SCRIPT).is_file():
        findings.append(
            Finding(
                "site",
                DOCS_VERSIONS_SCRIPT,
                1,
                "the docs versions script does not exist",
            )
        )
    workflow = root / DOCS_WORKFLOW
    if workflow.is_file():
        import yaml

        document = yaml.safe_load(workflow.read_text(encoding="utf-8")) or {}
        findings += [
            Finding("site", DOCS_WORKFLOW, 1, problem)
            for problem in _build_step_problems(document)
        ]
        runs = list(_strings_under_keys(document, {"run"}))
        for run in runs:
            if re.search(r"\bgh-deploy\b", run):
                findings.append(
                    Finding(
                        "site",
                        DOCS_WORKFLOW,
                        1,
                        f"'{run.strip()}' replaces the whole gh-pages branch with one "
                        "unversioned build, deleting every published version; deploy "
                        f"with {DOCS_VERSIONS_SCRIPT} deploy",
                    )
                )
        for command, why in (
            ("deploy", "no step publishes the site with it"),
            ("check", "no step checks the versioned site with it"),
        ):
            if not any(
                re.search(rf"{re.escape(DOCS_VERSIONS_SCRIPT)}\s+{command}\b", r)
                for r in runs
            ):
                findings.append(
                    Finding(
                        "site",
                        DOCS_WORKFLOW,
                        1,
                        f"{DOCS_VERSIONS_SCRIPT} {command} is not run: {why}",
                    )
                )
    else:
        findings.append(
            Finding("site", DOCS_WORKFLOW, 1, "the docs workflow does not exist")
        )
    tag_runs = _workflow_runs(root / RELEASE_TAG_WORKFLOW)
    workflow_name = Path(DOCS_WORKFLOW).name
    if tag_runs is not None and not any(
        re.search(rf"\bgh\s+workflow\s+run\s+{re.escape(workflow_name)}\b", r)
        for r in tag_runs
    ):
        findings.append(
            Finding(
                "site",
                RELEASE_TAG_WORKFLOW,
                1,
                f"the tag workflow does not start {workflow_name} on the release tag, "
                "so no release gets a docs version: a tag created with GITHUB_TOKEN "
                "starts no workflow by itself",
            )
        )
    return findings


#: Emoji generators that write no image link: the Unicode character, or Material's
#: inline SVG. pymdownx's other generators (to_png is its default) link CDN images,
#: which the privacy plugin would download at build time.
OFFLINE_EMOJI_GENERATORS = frozenset(
    {"pymdownx.emoji.to_alt", "material.extensions.emoji.to_svg"}
)
#: What Material loads for a mermaid fence, and for its fonts unless theme.font is
#: false. The privacy plugin downloads both at build time unless they are excluded.
MERMAID_ASSET = "https://unpkg.com/mermaid@11/dist/mermaid.min.js"
GOOGLE_FONTS_ASSET = "https://fonts.googleapis.com/css"
#: An external image, script, media source or stylesheet in a page's markdown or HTML.
_PAGE_ASSET = re.compile(
    r"!\[[^\]]*\]\(\s*<?(https?://[^)\s>]+)"
    r"|<(?:img|script|source|video|audio)\b[^>]*\bsrc=[\"'](https?://[^\"']+)"
    r"|<link\b[^>]*\bhref=[\"'](https?://[^\"']+)",
    re.IGNORECASE,
)


def _plugin_config(site: Site, name: str) -> dict[str, Any] | None:
    """A plugin's options from mkdocs.yml: {} when listed bare, None when absent."""
    for entry in site.config.get("plugins") or []:
        if entry == name:
            return {}
        if isinstance(entry, dict) and name in entry:
            return entry[name] if isinstance(entry[name], dict) else {}
    return None


def _asset_path(url: str) -> str:
    """The URL as the privacy plugin matches assets_exclude against it: host and path."""
    import posixpath
    from urllib.parse import urlsplit

    parsed = urlsplit(url)
    return parsed.netloc + posixpath.normpath(parsed.path or "/")


def _external_assets(site: Site, root: Path) -> list[tuple[str, int, str, str]]:
    """(file, line, url, why) for every external asset a page or the theme loads."""
    assets: list[tuple[str, int, str, str]] = []
    for key in ("extra_javascript", "extra_css"):
        for item in site.config.get(key) or []:
            url = item.get("path") if isinstance(item, dict) else item
            if isinstance(url, str) and re.match(r"https?://", url):
                assets.append((MKDOCS_YML, 1, url, f"listed in {key}"))
    theme = site.config.get("theme") or {}
    theme = {"name": theme} if isinstance(theme, str) else theme
    if theme.get("name") == "material":
        _extensions, configs = _markdown_extensions(site)
        fences = (configs.get("pymdownx.superfences") or {}).get("custom_fences") or []
        if any(isinstance(f, dict) and f.get("name") == "mermaid" for f in fences):
            assets.append(
                (MKDOCS_YML, 1, MERMAID_ASSET, "Material loads it for a mermaid fence")
            )
        if theme.get("font") is not False:
            assets.append(
                (
                    MKDOCS_YML,
                    1,
                    GOOGLE_FONTS_ASSET,
                    "Material loads Google Fonts unless theme.font is false",
                )
            )
    for path in sorted(site.docs_dir.rglob("*.md")):
        page = parse_page(path, root)
        for number, text in page.prose:
            for match in _PAGE_ASSET.finditer(_SPAN.sub("", text)):
                url = next(group for group in match.groups() if group)
                assets.append((page.rel, number, url, "the page shows it"))
    return assets


def _privacy_fetch_findings(
    site: Site, root: Path, privacy: dict[str, Any]
) -> list[Finding]:
    """External assets the privacy plugin would download, which needs the network."""
    from fnmatch import fnmatch

    if privacy.get("enabled", True) is False or privacy.get("assets", True) is False:
        return []  # the plugin leaves every external asset alone
    include = [str(p) for p in privacy.get("assets_include") or []]
    exclude = [str(p) for p in privacy.get("assets_exclude") or []]
    findings = []
    for rel, line, url, why in _external_assets(site, root):
        path = _asset_path(url)
        if include and not any(fnmatch(path, pattern) for pattern in include):
            continue
        if any(fnmatch(path, pattern) for pattern in exclude):
            continue
        if privacy.get("assets_fetch", True) is False:
            effect = "with assets_fetch false the plugin warns about it, which fails --strict"
        else:
            effect = (
                "the privacy plugin downloads it at build time, so the build needs the "
                "network"
            )
        theme_hint = "; or set theme.font: false" if url == GOOGLE_FONTS_ASSET else ""
        findings.append(
            Finding(
                "site",
                rel,
                line,
                f"{path} is an external asset the privacy plugin downloads ({why}): "
                f"{effect}. Add a pattern for it to plugins.privacy.assets_exclude"
                f"{theme_hint}",
            )
        )
    return findings


def _emoji_findings(site: Site) -> list[Finding]:
    extensions, configs = _markdown_extensions(site)
    if "pymdownx.emoji" not in extensions:
        return []
    generator = (configs.get("pymdownx.emoji") or {}).get(
        "emoji_generator", "pymdownx.emoji.to_png"
    )
    name = (
        generator
        if isinstance(generator, str)
        else f"{getattr(generator, '__module__', '')}.{getattr(generator, '__name__', '')}"
    )
    if name in OFFLINE_EMOJI_GENERATORS:
        return []
    return [
        Finding(
            "site",
            MKDOCS_YML,
            1,
            f"pymdownx.emoji's emoji_generator is {name}, which links CDN images that "
            "the privacy plugin downloads at build time; use pymdownx.emoji.to_alt or "
            "material.extensions.emoji.to_svg",
        )
    ]


_MKDOCS_BUILD = re.compile(r"\bmkdocs\s+build\b")
#: Shell control operators: after the build on its line, each one hands the step's
#: exit status to something else.
_CONTROL_OPERATORS = frozenset({"|", "||", "&", "&&", ";", ";;", "|&"})


def _build_step_problems(document: dict[str, Any]) -> list[str]:
    """Why the docs workflow's mkdocs build step could pass with a failed build."""
    import shlex

    problems: list[str] = []
    found = False
    jobs = document.get("jobs") if isinstance(document, dict) else None
    for job_name, job in (jobs or {}).items():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps") or []:
            run = step.get("run") if isinstance(step, dict) else None
            if not isinstance(run, str) or not _MKDOCS_BUILD.search(run):
                continue
            found = True
            if "--strict" not in run:
                problems.append(f"'{run.strip()}' does not pass --strict")
            for where, value in (("job", job), ("step", step)):
                if value.get("continue-on-error") not in (None, False):
                    problems.append(
                        f"the {where} that runs mkdocs build (job {job_name}) sets "
                        "continue-on-error, so a failed build does not fail the workflow"
                    )
            shell = step.get("shell")
            if isinstance(shell, str) and "{0}" in shell and "-e" not in shell:
                problems.append(
                    f"shell: {shell} runs the script without -e, so a command after the "
                    "build decides the step's result"
                )
            script = re.sub(r"\\\n", " ", run)
            lines = script.splitlines()
            for index, line in enumerate(lines):
                build = _MKDOCS_BUILD.search(line)
                if build is None:
                    continue
                before = "\n".join(lines[:index])
                if re.search(
                    r"^\s*set\s+(\+e\b|\+o\s+errexit\b)", before, re.MULTILINE
                ):
                    problems.append(
                        "the build step runs set +e before mkdocs build, so a failed "
                        "build does not stop the script"
                    )
                lexer = shlex.shlex(
                    line[build.end() :], posix=True, punctuation_chars=True
                )
                lexer.whitespace_split = True
                try:
                    tokens = list(lexer)
                except ValueError:
                    tokens = []
                operators = sorted(set(tokens) & _CONTROL_OPERATORS)
                if operators:
                    problems.append(
                        f"'{line.strip()}': its exit status cannot fail the step, because "
                        f"{' '.join(operators)} after mkdocs build hands the result to "
                        "another command; run mkdocs build on its own line"
                    )
    if not found:
        problems.append("no step runs mkdocs build")
    return problems


def site_pages(files: Iterable[Path], root: Path) -> list[Path]:
    """The corpus files mkdocs renders: markdown under docs_dir."""
    docs_dir = load_site(str(root)).docs_dir
    return [path for path in files if path.suffix == ".md" and _in_dir(path, docs_dir)]
