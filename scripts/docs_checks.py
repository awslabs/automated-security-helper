# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Static checks for the code blocks, commands, links and navigation in ASH's docs.

Loaded by path from scripts/verify_docs_freshness.py, which registers each public
``check_*`` function below as one of its checks, and from the docs-example runner in
tests/integration/docs/, which uses the same block parser to decide what to execute.
The CI pipeline runners there read the CI pages' blocks through the same parser too
(ci_marker, ci_pipeline_text and ci_runner_census). scripts/ is not a package, so
nothing here is imported by name.

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
import textwrap
import unicodedata
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

#: The mkdocs hook that renders the version-pinned pages for the version mike builds,
#: so the main version's install commands install main.
INSTALL_REFS_HOOK = "docs/hooks/install_refs.py"

#: Renders the version-pinned pages from their templates, and names the forms an
#: install command can take (check_release_placeholders reads both).
TEMPLATE_MANAGER = "scripts/version_template_manager.py"

#: The workflow that must run ``mkdocs build --strict`` and the versioned-site check:
#: the one the required-checks gate covers, so a failed site build blocks a merge.
DOCS_BUILD_WORKFLOW = ".github/workflows/ash-unified-ci.yml"

#: The workflow that publishes the site with ``docs_versions.py deploy``.
DOCS_WORKFLOW = ".github/workflows/ash-repo-docs.yml"

#: The script that publishes the site as versions with mike, and checks that it can.
DOCS_VERSIONS_SCRIPT = "scripts/docs_versions.py"

#: Fixture projects the docs-example runner can start a page in. ``fixture=<name>``
#: on a marker names a directory here.
DOC_FIXTURES_DIR = "tests/test_data/docs_fixtures"
DEFAULT_FIXTURE = "sample-project"

#: The container definitions ASH ships, relative to the code tree. Their ARG names are
#: build arguments, a second set of names the env check accepts.
SHIPPED_DOCKERFILES = ("Dockerfile",)

#: Pages for contributors. Variables only the test suite and CI read are documented
#: here and nowhere else (a path ending in "/" is a directory).
#: Pages written for contributors, where a variable only the test suite or CI
#: reads may be documented. A trailing slash names a directory prefix; a document
#: under tests/ (tests/NAMING_CONVENTIONS.md names the tier and shard variables)
#: is contributor material by its location.
CONTRIBUTOR_PAGES = (
    "docs/content/contributing/",
    "CONTRIBUTING.md",
    "DEVELOPMENT.md",
    "tests/",
)

#: Where the test suite and CI live in the code tree, for those test-only variables.
TEST_SOURCES = "tests"
CI_ENV_SOURCES = (
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    ".github/actions/**/action.yml",
)

#: The repository's pre-commit hook manifest, for ``config kind=pre-commit``.
PRE_COMMIT_HOOKS = ".pre-commit-hooks.yaml"

#: Pages an MCP client's author reads (a path ending in "/" is a directory). Their
#: error-type names are held to what the MCP tools return; see check_mcp_contract.
MCP_PAGES = (
    "docs/content/how-to/mcp-server.md",
    "docs/content/concepts/trust-model.md",
    "docs/content/docs/genai-steering-guide.md",
    "docs/content/getting-started/agents.md",
    "docs/content/reference/mcp-tools.md",
    "ash-agent-plugins/agentic-coding/transpiler/_base/",
)
#: Reads what each MCP tool returns from the server's source; beside this module.
MCP_CONTRACT_READER = "_mcp_contract.py"

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
        "shell-session",
        "bash-session",
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
RUNNER_SHELLS = frozenset(
    {"bash", "sh", "shell", "console", "shell-session", "bash-session"}
)
#: Blocks that show commands after a ``$`` prompt with their output below them.
#: shell-session and bash-session are other highlighters' names for a console block.
CONSOLE_LANGS = frozenset({"console", "shell-session", "bash-session"})
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
    # A CircleCI run step is a string, or a mapping whose command: is the script.
    "circleci": {"run", "command"},
    "docker-compose": {"command", "entrypoint"},
    "pre-commit": set(),
    "mcp-client": set(),
    "ash-output": set(),
    "mcp-response": set(),
    "other": set(),
}
REQUIRED_REASON_KINDS = frozenset({"ash-invalid", "other"})
#: ``config kind=mcp-response of=mcp.<tool>``: an example of what an MCP tool returns,
#: whose keys check_mcp_contract compares with the tool's return statements. It may
#: also mark a ``text`` block, for an example with placeholders that is not JSON.
MCP_RESPONSE_KIND = "mcp-response"
MCP_RESPONSE_LANGS = frozenset({"json", "text"})
#: Marker keys the other kinds take, beyond kind= and save-as=. Every one is required.
OTHER_KIND_KEYS = {"ash-output": {"model"}}

#: ``config kind=jenkinsfile``: a declarative Jenkinsfile. It is groovy, so it marks a
#: groovy block, whose ``sh`` steps get the CLI checks (groovy_sh_scripts). The YAML
#: ``jenkins`` kind above is a different file.
JENKINSFILE_KIND = "jenkinsfile"
#: The kinds that are a CI system's pipeline file. ci_marker reads their markers, and
#: ci_runner_census sorts their blocks by the runner that runs them.
CI_KINDS = frozenset(
    {
        "github-actions",
        "gitlab-ci",
        "buildspec",
        "azure-pipelines",
        "jenkins",
        JENKINSFILE_KIND,
        "circleci",
    }
)
#: CI kind -> the legs of the Docs CI Runners workflow that run its blocks, each the
#: CI system's own local runner. A Jenkinsfile runs on two Jenkins cores. A CI kind
#: missing here has no local runner, so only the static checks read its blocks: Azure
#: Pipelines has none, and nothing runs the YAML jenkins kind.
CI_RUNNERS = {
    "github-actions": ("act",),
    "gitlab-ci": ("gitlab-ci-local",),
    JENKINSFILE_KIND: ("jenkinsfile-runner-lts", "jenkinsfile-runner-bundled"),
    "buildspec": ("codebuild-agent",),
    "circleci": ("circleci",),
}
#: The keys a CI block's marker may carry beyond kind= and save-as=, on a kind in
#: CI_RUNNERS: ``extends=<path>`` (a fragment, run merged into the block an earlier
#: marker on the page saved at <path>), ``event=<event>`` (the event the runner
#: emulates), and ``runner=none reason="..."`` (no runner runs the block; the static
#: checks still read it, and the reason follows the illustrative rules).
CI_RUNNER_KEYS = ("extends", "event", "runner", "reason")
CI_RUNNER_NONE = "none"
#: CI kind -> the events event= may name. A kind missing here takes no event=: its
#: runner starts the pipeline with no event to choose.
CI_EVENTS = {
    "github-actions": ("pull_request", "push"),
    "gitlab-ci": ("push", "merge_request"),
}
#: The kinds compose_ci_pipeline can merge a fragment into a saved pipeline of. A
#: buildspec, a Jenkinsfile and a CircleCI config have no such rule, so a fragment of
#: one could only run as a pipeline the page does not show; they take no extends=.
CI_MERGE_KINDS = frozenset({"github-actions", "gitlab-ci"})

RUN_KEYS = frozenset({"expect-exit", "fixture", "env", "timeout", "fresh", "save-as"})
#: ``<!-- doctest: output -->`` marks a block (text and the like) as the output of the
#: block directly above it, which the runner must run (output_samples). The runner
#: compares the two, and the CLI check does not read the sample's ``ash`` lines as
#: commands. Anywhere else the marker is reported (output_marker_problems).
OUTPUT_MODE = "output"
#: ``save-as=<path>``: the runner writes the block's content to that path in the page's
#: project before later blocks run. Valid on any block. With no mode the block is only
#: saved; with ``run`` it is saved and run; a config block is still validated.
SAVE_AS = "save-as"
#: Bare words a marker may carry without ``=value``: ``fresh`` on a run block, and
#: ``complete`` on an options marker.
BARE_KEYS = frozenset({"fresh", "complete"})
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
        "example",
        "examples",
        "anexample",
        "illustrative",
        "notrunnable",
        "doesnotrun",
        "notrun",
        "output",
    }
)
#: Words that say only that a block is an example that does not run. A reason made of
#: nothing else names no cause, however it is worded: "illustrative example only".
_VAGUE_REASON_WORDS = frozenset(
    {
        "a",
        "an",
        "the",
        "this",
        "that",
        "it",
        "is",
        "isn",
        "just",
        "only",
        "for",
        "of",
        "not",
        "no",
        "t",
        "does",
        "doesn",
        "do",
        "can",
        "cannot",
        "be",
        "run",
        "runs",
        "runnable",
        "executed",
        "example",
        "examples",
        "illustrative",
        "illustration",
        "demo",
        "demonstration",
        "purposes",
        "sample",
        "snippet",
        "code",
        "block",
        "config",
        "configuration",
        "file",
        "output",
        "shown",
        "here",
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
        return f"reason {value!r} is a placeholder and names no cause; say why the block cannot run"
    if all(
        word in _VAGUE_REASON_WORDS for word in re.findall(r"[a-z0-9]+", value.lower())
    ):
        return (
            f"reason {value!r} names no cause; say what stops the block running, or "
            "what kind of file it is, for example needs Docker or a SARIF excerpt"
        )
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
    if lang == "jenkinsfile":
        # A Jenkinsfile fenced with its file name (jenkinsfile or Jenkinsfile) instead of
        # groovy. The config kind=jenkinsfile marker rules and the sh-step checks apply
        # only to a groovy block, so this one is never checked, and unmarked it drops
        # out of the runs.
        problems.append(
            "a jenkinsfile block gets none of the Jenkinsfile checks, and without "
            f"config kind={JENKINSFILE_KIND} it drops out of the runner census: fence "
            f"it as groovy and mark it config kind={JENKINSFILE_KIND}, with "
            'runner=none reason="..." when no runner can run it'
        )
        return problems
    if marker is not None and not marker.mode:
        extra = set(marker.keys) - {SAVE_AS}
        if SAVE_AS not in marker.keys or extra:
            problems.append(
                "a marker without a mode may only carry save-as=<path>; name a mode for "
                f"{sorted(extra) or 'it'}"
            )
        elif lang == "groovy":
            # The census counts a groovy block only as config kind=jenkinsfile, so a
            # Jenkinsfile marked otherwise would drop out of the runs unnoticed.
            problems.append(
                "a groovy block marked only save-as= drops out of the runner census: "
                f"mark it config kind={JENKINSFILE_KIND} save-as=<path>, with "
                'runner=none reason="..." when no runner can run it'
            )
        return problems
    if marker is None:
        if lang == "groovy":
            problems.append(
                "an unmarked groovy block drops out of the runner census: mark the "
                f"Jenkinsfile config kind={JENKINSFILE_KIND}, with "
                'runner=none reason="..." when no runner can run it, or mark groovy '
                'that is not a Jenkinsfile illustrative reason="..."'
            )
        if lang in WINDOWS_SHELLS or lang in ("zsh", "fish"):
            problems.append(
                f"{lang} blocks cannot run in the docs job (it executes bash on Linux); "
                f'mark it <!-- doctest: illustrative reason="..." -->'
            )
        return problems

    mode, keys = marker.mode, marker.keys
    if mode == OUTPUT_MODE:
        if family != "other":
            problems.append(
                f"output marks a sample of a program's output, which a {lang} block "
                "is not; drop the marker or label the block text"
            )
        elif set(keys) - {SAVE_AS}:
            problems.append(
                f"output takes no keys, not {sorted(set(keys) - {SAVE_AS})}"
            )
        return problems
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
            | OTHER_KIND_KEYS.get(kind, set())
        )
        if kind == MCP_RESPONSE_KIND:
            allowed = {"of"}
        if kind in CI_KINDS:
            # Reported by _ci_key_problems, each wrong use with its own message.
            allowed = allowed | set(CI_RUNNER_KEYS)
        if kind is None:
            problems.append("config needs kind=<kind>")
        elif kind == JENKINSFILE_KIND:
            problems.append(
                f"config kind={JENKINSFILE_KIND} is a groovy block: a declarative "
                f"Jenkinsfile is groovy, so fence it as groovy; a {lang} Jenkins "
                "definition is config kind=jenkins"
            )
        elif kind not in ASH_CONFIG_KINDS and kind not in OTHER_CONFIG_KINDS:
            known = sorted(set(ASH_CONFIG_KINDS) | set(OTHER_CONFIG_KINDS))
            known.append(f"and {JENKINSFILE_KIND} on a groovy block")
            problems.append(f"unknown config kind '{kind}'; known: {', '.join(known)}")
        else:
            extra = set(keys) - {"kind", SAVE_AS} - allowed
            if extra:
                problems.append(f"config kind={kind} does not take {sorted(extra)}")
            if kind in CI_KINDS:
                problems += _ci_key_problems(kind, keys)
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
            if kind == "ash-output" and not keys.get("model"):
                problems.append(
                    "config kind=ash-output needs model=<module>.<Model>[.<field>...], "
                    "the output model the block is part of, for example model="
                    f"{ASH_MODULE}.models.asharp_model.AshAggregatedResults.scanner_results"
                )
            if kind == MCP_RESPONSE_KIND:
                problems += _mcp_response_marker_problems(lang, keys)
    elif (
        lang in MCP_RESPONSE_LANGS
        and mode == "config"
        and keys.get("kind") == MCP_RESPONSE_KIND
    ):
        extra = set(keys) - {"kind", "of", SAVE_AS}
        if extra:
            problems.append(
                f"config kind={MCP_RESPONSE_KIND} does not take {sorted(extra)}"
            )
        problems += _mcp_response_marker_problems(lang, keys)
    elif lang == "groovy" and mode == "config" and keys.get("kind") == JENKINSFILE_KIND:
        extra = set(keys) - {"kind", SAVE_AS, *CI_RUNNER_KEYS}
        if extra:
            problems.append(
                f"config kind={JENKINSFILE_KIND} does not take {sorted(extra)}"
            )
        problems += _ci_key_problems(JENKINSFILE_KIND, keys)
    elif lang == "groovy" and mode == "illustrative":
        # Groovy that is not a Jenkinsfile (a Gradle build file, a test class)
        # has no truthful config kind, so it is marked shown-only, the reason
        # recording why it stays out of the runner census.
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
    elif lang == "groovy":
        problems.append(
            f"a groovy block takes config kind={JENKINSFILE_KIND}, for a declarative "
            f'Jenkinsfile, or illustrative reason="..." for groovy that is not one; '
            f"'{mode}'"
            + (f" kind={keys['kind']}" if "kind" in keys else "")
            + " does nothing on it"
        )
    else:
        problems.append(
            f"markers apply to shell, python and config blocks, and output to an output "
            f"sample; a {lang or 'unlabeled'} block is never executed or validated, so "
            f"'{mode}' does nothing"
        )
    return problems


def _ci_key_problems(kind: str, keys: dict[str, Any]) -> list[str]:
    """What is wrong with the runner keys (CI_RUNNER_KEYS) on a CI block's marker.

    Each wrong use has its own message, so the contributor reads which key to change,
    rather than the generic "does not take" that an unknown key gets. Whether an
    extends= names an earlier saved block of the same kind needs the rest of the page,
    so ci_extends_problems checks that.
    """
    given = [key for key in keys if key in CI_RUNNER_KEYS]
    if not given:
        return []
    if kind not in CI_RUNNERS:
        return [
            (
                f"config kind={kind} has no runner, so it takes no "
                f"{_or_list(key + '=' for key in given)}; only the static checks read it"
            )
        ]
    problems: list[str] = []
    runner = keys.get("runner")
    if "runner" in keys and runner != CI_RUNNER_NONE:
        problems.append(
            f"runner= takes only none, to mark a block no runner runs; the kind names "
            f"the runner that runs the others, so drop runner={runner}"
        )
    elif runner == CI_RUNNER_NONE:
        if "reason" not in keys:
            problems.append(
                'runner=none needs reason="..." saying why no runner runs the block'
            )
        else:
            reason = _reason_problem(keys["reason"])
            if reason:
                problems.append(reason)
    elif "reason" in keys:
        problems.append(
            "reason= goes with runner=none: add runner=none if no runner can run the "
            "block, or drop reason="
        )
    if "event" in keys:
        events = CI_EVENTS.get(kind, ())
        if not events:
            problems.append(
                f"config kind={kind} takes no event=: its runner starts the pipeline "
                "with no event to choose"
            )
        elif keys["event"] not in events:
            problems.append(
                f"event={keys['event']} is not an event of config kind={kind}; it "
                f"takes {_or_list(events)}"
            )
    if "extends" in keys:
        if kind not in CI_MERGE_KINDS:
            problems.append(
                f"config kind={kind} has no merge rule, so it takes no extends=: drop "
                "extends=, and show the whole pipeline or mark the block runner=none "
                "with the reason it cannot run alone"
            )
        elif SAVE_AS in keys:
            problems.append(
                "extends= makes the block a fragment, and a fragment cannot also be "
                "saved: drop save-as=, and extend the block that saves the pipeline"
            )
    return problems


@dataclass(frozen=True)
class CiMarker:
    """What the marker of a CI block says. Each value is the marker's string as written,
    or None when the marker does not set it. ci_marker does not validate: on a marker
    the markers check accepts, ``runner`` is "none" when set, but an invalid marker
    (runner=act) reads back its own value, which _ci_key_problems reports."""

    kind: str
    save_as: str | None
    extends: str | None
    event: str | None
    runner: str | None
    reason: str | None


def ci_marker(block: Block) -> CiMarker | None:
    """The CI keys of a block marked ``config kind=<CI kind>``, or None for any other
    block (an ASH config, an unmarked groovy block).

    The static checks and the Docs CI Runners harness both read a CI block through
    this, so they cannot disagree about what a marker says. It reads the marker as
    written, on whatever block it is: marker_problems reports a kind on the wrong
    language and a key used wrongly.
    """
    marker = block.marker
    if marker is None or marker.mode != "config":
        return None
    kind = marker.keys.get("kind")
    if kind not in CI_KINDS:
        return None

    def value(key: str) -> str | None:
        found = marker.keys.get(key)
        return found if isinstance(found, str) else None

    return CiMarker(
        kind=kind,
        save_as=value(SAVE_AS),
        extends=value("extends"),
        event=value("event"),
        runner=value("runner"),
        reason=value("reason"),
    )


def extended_block(page: Page, block: Block) -> Block | None:
    """The block a fragment's ``extends=<path>`` names: the nearest block above it on the
    page saved with ``save-as=<path>``, whose content is what the runner's file at that
    path holds when the fragment runs. None when the block extends nothing, or nothing
    above it saves the path."""
    marker = ci_marker(block)
    if marker is None or marker.extends is None:
        return None
    above = next(
        (index for index, other in enumerate(page.blocks) if other is block), 0
    )
    for other in reversed(page.blocks[:above]):
        if other.save_as == marker.extends:
            return other
    return None


def ci_extends_problems(page: Page) -> list[Finding]:
    """A fragment (extends=) of a kind with a merge rule must name a block above it on
    the page, saved at that path, of its own kind: the merge reads that block. Later
    blocks do not count, since the runner has not saved them when the fragment runs.
    """
    findings: list[Finding] = []
    for block in page.blocks:
        marker = ci_marker(block)
        if marker is None or marker.extends is None or block.marker is None:
            continue
        if marker.kind not in CI_MERGE_KINDS:
            continue  # _ci_key_problems refuses extends= on this kind
        saved = extended_block(page, block)
        problem = None
        if saved is None:
            problem = (
                f"extends={marker.extends} names no earlier block on this page saved "
                f"with save-as={marker.extends}; save the pipeline it changes in a "
                "block above it"
            )
        else:
            base = ci_marker(saved)
            if base is None or base.kind != marker.kind:
                what = (
                    f"a config kind={saved.config_kind}"
                    if saved.family == "config"
                    else f"a {saved.lang or 'unlabeled'}"
                )
                problem = (
                    f"extends={marker.extends} names {what} block (line "
                    f"{saved.fence_line}), and a config kind={marker.kind} block can "
                    "extend only a block of its own kind"
                )
        if problem:
            findings.append(Finding("markers", page.rel, block.marker.line, problem))
    return findings


def ci_event_problems(page: Page) -> list[Finding]:
    """event= on a GitHub workflow must name an event its on: has, read from the merged
    workflow for a fragment. A runner sending an event the workflow does not run on
    starts none of its jobs, so the block would pass with nothing run. An event outside
    the kind's set is _ci_key_problems' to report, and a fragment that does not merge
    is the config check's."""
    findings: list[Finding] = []
    for block in page.blocks:
        marker = ci_marker(block)
        if (
            marker is None
            or block.marker is None
            or marker.kind != "github-actions"
            or marker.event not in CI_EVENTS["github-actions"]
        ):
            continue
        try:
            text = ci_pipeline_text(page, block)
        except CiComposeError:
            continue
        document, error = _parse_workflow(text)
        if error is not None:
            continue
        triggers = _triggers(document)
        if marker.event in triggers:
            continue
        has = _or_list(sorted(triggers)) if triggers else "no event"
        findings.append(
            Finding(
                "markers",
                page.rel,
                block.marker.line,
                f"event={marker.event}: the workflow's on: has no {marker.event} (it "
                f"has {has}), so a runner sending {marker.event} starts none of its "
                f"jobs; drop event=, or add {marker.event} to on:",
            )
        )
    return findings


def _mcp_response_marker_problems(lang: str, keys: dict[str, Any]) -> list[str]:
    problems = []
    if lang not in MCP_RESPONSE_LANGS:
        problems.append(
            f"config kind={MCP_RESPONSE_KIND} is a json block, or a text block for an "
            "example that is not JSON"
        )
    of = keys.get("of")
    if not isinstance(of, str) or not re.match(r"^mcp\.[a-z][a-z0-9_]*$", of):
        problems.append(
            f"config kind={MCP_RESPONSE_KIND} needs of=mcp.<tool>, the tool whose "
            "response the block shows"
        )
    return problems


def runner_runs(block: Block) -> bool:
    """Whether the docs-example runner executes this block: an unmarked or ``run``
    shell block in a language it runs with bash, or an unmarked or ``run`` python one."""
    if block.mode != "run" or not block.closed:
        return False
    return block.family == "python" or (
        block.family == "shell" and block.lang in RUNNER_SHELLS
    )


def output_marker_problems(page: Page) -> list[Finding]:
    """A block marked output that is not a run block's output sample (output_samples).

    The marker says a program printed the block, so the runner would compare it with
    that output and the CLI check would skip its ash lines. Directly after a block the
    runner runs, both hold. Anywhere else nothing printed it, so the marker would only
    take the block out of the CLI check. A marker on a shell, python or config block is
    reported by marker_problems instead.
    """
    samples = output_samples(page)
    return [
        Finding(
            "markers",
            page.rel,
            block.marker.line,
            "marked output but follows no run block, so nothing is compared with it; "
            "put it directly after the block whose output it shows (a shell or python "
            "block the runner runs), or drop the marker",
        )
        for block in page.blocks
        if block.marker is not None
        and block.marker.mode == OUTPUT_MODE
        and block.family == "other"
        and id(block) not in samples
    ]


def unchecked_exit_problems(page: Page) -> list[Finding]:
    """A run block with expect-exit=any passes whatever it exits with, so something
    else must check what it did: an output sample directly after it, which the runner
    compares with its output."""
    findings: list[Finding] = []
    samples = output_samples(page)
    for index, block in enumerate(page.blocks):
        marker = block.marker
        if marker is None or marker.mode != "run":
            continue
        if marker.keys.get("expect-exit") != "any":
            continue
        following = page.blocks[index + 1] if index + 1 < len(page.blocks) else None
        if (
            following is not None
            and samples.get(id(following)) is block
            and any(line not in _ELLIPSES for line in normalize_output(following.body))
        ):
            continue
        findings.append(
            Finding(
                "markers",
                page.rel,
                marker.line,
                "expect-exit=any checks nothing about the block: name the exit code it "
                "should end with, or put an <!-- doctest: output --> sample of its "
                "output directly after it",
            )
        )
    return findings


def check_markers(files: Iterable[Path], root: Path = REPO_ROOT) -> list[Finding]:
    """Markers are well formed, bind to a block, and suit the block they govern."""
    findings: list[Finding] = []
    for page in load_pages(files, root):
        findings += page.structure
        for block in page.blocks:
            line = block.marker.line if block.marker else block.fence_line
            for problem in marker_problems(block, root):
                findings.append(Finding("markers", page.rel, line, problem))
        findings += output_marker_problems(page)
        findings += unchecked_exit_problems(page)
        findings += ci_extends_problems(page)
        findings += ci_event_problems(page)
    return findings


# ---------------------------------------------------------------------------
# Output samples: comparing a text block with the output of the block above it
# ---------------------------------------------------------------------------
#
# The runner captures each block's output (stdout and stderr together, with COLUMNS
# fixed at 100 so Rich lays a table out the same way every run). An output sample is
# compared with it after both are normalized the same way:
#
# - ANSI escape sequences are removed;
# - Rich's box-drawing characters become spaces, so a table row reads as its cells;
# - durations (46ms, 1.23s, 3 seconds), clock times (0:00:03) and timestamps
#   (2026-10-11T12:00:01Z) become <time>;
# - the session's paths are replaced: the project directory the page runs in reads
#   as a relative path (its own path as ".", anything under it without the prefix),
#   and its HOME as "~";
# - each line's runs of whitespace become one space, and blank lines are dropped.
#
# Then every line of the sample, other than a line that is only "...", must be part
# of a line of the output, in order. "..." inside a line matches any text there.

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_BOX_DRAWING = re.compile("[\u2500-\u257f]")
_TIMESTAMP = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)
_CLOCK_TIME = re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?\b")
_DURATION = re.compile(
    r"(?<![\w.])\d+(?:\.\d+)?\s?(?:ms|s|sec|secs|seconds?|min|minutes?)\b"
)
_TIME = "<time>"
_ELLIPSES = ("...", "\u2026")


def normalize_output(text: str, paths: Iterable[tuple[str, str]] = ()) -> list[str]:
    """``text`` as the lines an output comparison reads (see the comment above).

    ``paths`` pairs a directory with what it reads as: "." for the project directory,
    whose contents then read as relative paths, or a label such as "~".
    """
    text = _ANSI_ESCAPE.sub("", text)
    for path, label in sorted(paths, key=lambda pair: -len(pair[0])):
        if not path:
            continue
        text = text.replace(path + "/", "" if label == "." else label + "/")
        text = text.replace(path, label)
    lines = []
    for line in text.splitlines():
        line = _BOX_DRAWING.sub(" ", line)
        line = _TIMESTAMP.sub(_TIME, line)
        line = _CLOCK_TIME.sub(_TIME, line)
        line = _DURATION.sub(_TIME, line)
        line = " ".join(line.split())
        if line:
            lines.append(line)
    return lines


def _line_matches(pieces: list[str], line: str) -> bool:
    """Whether the pieces of a sample line (split at its ellipses) appear in an output
    line, in order. A piece starts and ends at a word boundary, so the sample "OK" is
    not in the output "BROKEN", except where an ellipsis stands beside it: a piece
    before one may end mid-word ("FindingsListRe..." for FindingsListReporter), and a
    piece after one may start mid-word."""
    position = 0
    last = len(pieces) - 1
    for index, piece in enumerate(pieces):
        if not piece:
            continue
        word_start = (piece[0].isalnum() or piece[0] == "_") and index == 0
        word_end = (piece[-1].isalnum() or piece[-1] == "_") and index == last
        pattern = (
            (r"(?<!\w)" if word_start else "")
            + re.escape(piece)
            + (r"(?!\w)" if word_end else "")
        )
        found = re.compile(pattern).search(line, position)
        if found is None:
            return False
        position = found.end()
    return True


def output_sample_problem(
    sample: str, output: str, paths: Iterable[tuple[str, str]] = ()
) -> tuple[int, str] | None:
    """The first sample line the output lacks, as (its offset in the sample, the line
    as normalized), or None when every line is there in order."""
    paths = list(paths)
    have = normalize_output(output, paths)
    position = 0
    for offset, raw in enumerate(sample.split("\n")):
        wanted = normalize_output(raw, paths)
        if not wanted or wanted[0] in _ELLIPSES:
            continue
        line = wanted[0]
        pieces = [piece.strip() for piece in re.split("\\.\\.\\.|\u2026", line)]
        found = next(
            (
                index
                for index in range(position, len(have))
                if _line_matches(pieces, have[index])
            ),
            None,
        )
        if found is None:
            return offset, line
        position = found + 1
    return None


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
    #: Subshells opened with ( and not yet closed. Inside one, a ) ends the word it
    #: follows, as in (cd x && ash dependencies install --tool trivy).
    subshells = 0
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
        closes_subshell = operator == ")" and subshells > 0
        if operator and not (
            operator in ("(", ")") and in_word and not closes_subshell
        ):
            if operator == "(":
                subshells += 1
            elif closes_subshell:
                subshells -= 1
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
# Check: a shell variable is set in the session that reads it
# ---------------------------------------------------------------------------
#
# The docs-example runner runs a page's blocks in sessions. A shell block hands the
# variables it set to the next block of its session; a block marked fresh, or on another
# fixture, starts a new session holding only the runner's environment. A page that sets
# a variable on one fixture and reads it on another reads an empty string, and a command
# such as `ash scan --config "$OPERATOR_CONFIG"` then runs with --config "" and can pass
# for the wrong reason. The sessions and the environment are the runner's own
# (page_sessions, session_environment), read from it rather than restated here.

DOCS_RUNNER = "tests/integration/docs/docs_runner.py"

_SHELL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
#: A word that sets a variable: NAME=..., NAME+=..., or a bare NAME after declare.
_SETTING_WORD = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(\+?=|$)")
#: After ${NAME, what to do when NAME is unset: a default, an assignment, an
#: alternative or an error. An unset NAME is then handled, not silently empty.
_UNSET_OPERATORS = (":-", ":=", ":+", ":?", "-", "=", "+", "?")
_HEREDOC = re.compile(r"<<-?[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_DECLARING = frozenset({"export", "declare", "typeset", "local", "readonly"})
#: read's options that take a value; for -a, the value is the variable it sets.
_READ_VALUE_OPTIONS = frozenset("adinNptu")


def _docs_runner() -> Any:
    """The docs-example runner, loaded by path under the name its tests use."""
    name = "_ash_docs_runner"
    if name in sys.modules:
        return sys.modules[name]
    path = REPO_ROOT / DOCS_RUNNER
    if not path.is_file():
        raise RuntimeError(
            f"cannot read the docs-example runner at {path}, so the sessions a page "
            "runs in are unknown and this check cannot run"
        )
    return _load_by_path(name, path)


def _expansion_at(text: str, index: int) -> tuple[str | None, int]:
    """(NAME, length) for the expansion at text[index] == "$", or (None, length)."""
    following = text[index + 1 : index + 2]
    if following == "{":
        start = index + 2
        if text.startswith("#", start):
            start += 1
        name = _SHELL_NAME.match(text, start)
        if not name:
            return None, 2
        if text.startswith(_UNSET_OPERATORS, name.end()):
            return None, name.end() - index
        return name.group(0), name.end() - index
    if following == "'":
        # $'...' is ANSI-C quoting: no expansion inside.
        close = text.find("'", index + 2)
        return None, (len(text) if close < 0 else close + 1) - index
    name = _SHELL_NAME.match(text, index + 1)
    if name:
        return name.group(0), name.end() - index
    return None, 1


def _expansions_in(line: str) -> list[str]:
    """The names a here-document body line expands: every $NAME not escaped."""
    names, index = [], 0
    while index < len(line):
        if line[index] == "\\":
            index += 2
            continue
        if line[index] == "$":
            name, length = _expansion_at(line, index)
            if name:
                names.append(name)
            index += length
            continue
        index += 1
    return names


def shell_reads(script: str) -> list[tuple[int, str]]:
    """(zero-based line, NAME) for each $NAME or ${NAME} a shell would expand.

    Not a shell. It skips what a shell does not expand: single-quoted text, an escaped
    dollar, a comment, $'...', and the body of a here-document with a quoted delimiter.
    A ${NAME...} that names its own default, assignment, alternative or error is skipped
    too, since it says what an unset NAME does.
    """
    text = script.replace("\r\n", "\n")
    reads: list[tuple[int, str]] = []
    heredocs: list[tuple[str, bool]] = []
    index, line, double, word_start = 0, 0, False, True
    while index < len(text):
        char = text[index]
        if char == "\n":
            index += 1
            line += 1
            word_start = True
            if heredocs and not double:
                for delimiter, expands in heredocs:
                    while index < len(text):
                        end = text.find("\n", index)
                        end = len(text) if end < 0 else end
                        body = text[index:end]
                        index = end + 1
                        line += 1
                        if body.strip() == delimiter:
                            break
                        if expands:
                            reads += [(line - 1, name) for name in _expansions_in(body)]
                heredocs.clear()
            continue
        if char == "\\":
            line += text[index + 1 : index + 2] == "\n"
            index += 2
            word_start = False
            continue
        if char == "'" and not double:
            close = text.find("'", index + 1)
            close = len(text) if close < 0 else close
            line += text.count("\n", index, close)
            index = close + 1
            word_start = False
            continue
        if char == '"':
            double = not double
            index += 1
            word_start = False
            continue
        if char == "#" and not double and word_start:
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
            continue
        if char == "<" and not double and text.startswith("<<", index):
            heredoc = (
                None if text.startswith("<<<", index) else _HEREDOC.match(text, index)
            )
            if heredoc:
                heredocs.append((heredoc.group(2), not heredoc.group(1)))
                index = heredoc.end()
                word_start = False
                continue
        if char == "$":
            name, length = _expansion_at(text, index)
            if name:
                reads.append((line, name))
            index += length
            word_start = False
            continue
        word_start = char in " \t;&|()"
        index += 1
    return reads


def shell_sets(script: str) -> set[str]:
    """The variables a script sets: NAME=..., export/declare/local/readonly/typeset,
    for/select loops, read, mapfile/readarray and getopts, including inside $(...)."""
    names: set[str] = set()
    for command in split_shell(script):
        words = list(command.words)
        while words and words[0] in _SHELL_KEYWORDS:
            words.pop(0)
        while words and "=" in words[0]:
            setting = _SETTING_WORD.match(words[0])
            if not setting:
                break
            names.add(setting.group(1))
            words.pop(0)
        if words:
            head, rest = words[0], words[1:]
            if head in _DECLARING:
                for word in rest:
                    setting = _SETTING_WORD.match(word)
                    if setting and not word.startswith("-"):
                        names.add(setting.group(1))
            elif head in ("for", "select") and rest and _SHELL_NAME.fullmatch(rest[0]):
                names.add(rest[0])
            elif head == "read":
                takes_value = False
                for word in rest:
                    if takes_value:
                        takes_value = False
                        continue
                    if word.startswith("-") and len(word) > 1:
                        takes_value = word[-1] in _READ_VALUE_OPTIONS
                        if word[-1] == "a":
                            takes_value = False
                        continue
                    if _SHELL_NAME.fullmatch(word):
                        names.add(word)
            elif head in ("mapfile", "readarray"):
                plain = [w for w in rest if not w.startswith("-")]
                names.add(plain[-1] if plain else "MAPFILE")
            elif head == "getopts" and len(rest) >= 2:
                names.add(rest[1])
        for substitution in command.substitutions:
            names |= shell_sets(substitution)
    return names


def check_session_variables(
    files: Iterable[Path], root: Path = REPO_ROOT
) -> list[Finding]:
    """A runnable shell block reads a variable that only an earlier session set."""
    runner = _docs_runner()
    provided = set(runner.session_environment(Path("session"), 0, ""))
    findings: list[Finding] = []
    for page in load_pages(files, root):
        known: dict[int, set[str]] = {}
        setters: dict[str, tuple[int, str, int]] = {}
        started: dict[int, tuple[int, bool]] = {}
        for number, fixture, block in runner.page_sessions(page):
            started.setdefault(
                number,
                (
                    block.fence_line,
                    block.marker is not None and bool(block.marker.keys.get("fresh")),
                ),
            )
            if block.family != "shell" or not runner_runs(block):
                continue
            script = (
                console_commands(block.body)
                if block.lang in CONSOLE_LANGS
                else block.body
            )
            sets = shell_sets(script)
            own = sets | set(runner.marker_env(block))
            session_sets = known.setdefault(number, set())
            reported: set[tuple[int, str]] = set()
            for offset, name in shell_reads(script):
                setter = setters.get(name)
                if (
                    name in provided
                    or name in own
                    or name in session_sets
                    or setter is None
                    or setter[0] == number
                    or (offset, name) in reported
                ):
                    continue
                reported.add((offset, name))
                start_line, fresh = started[number]
                why = "it is marked fresh" if fresh else "the fixture changes"
                findings.append(
                    Finding(
                        "session",
                        page.rel,
                        block.body_line + offset,
                        f"${name} is read in a session on fixture '{fixture}', but "
                        f"only the block at line {setter[2]} sets it, in an earlier "
                        f"session on fixture '{setter[1]}'. The block at line "
                        f"{start_line} starts this session because {why}, and a new "
                        f"session holds only the runner's environment, so ${name} is "
                        "empty here. Set it in this session, or keep these blocks on "
                        "one fixture.",
                    )
                )
            session_sets |= sets
            for name in sets:
                setters[name] = (number, fixture, block.fence_line)
    return findings


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
    #: The values a click.Choice option accepts, as click compares them; None when
    #: click accepts any value.
    choices: tuple[str, ...] | None = None
    case_sensitive: bool = True


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
            choices = getattr(param.type, "choices", None) if takes_value else None
            option = CliOption(
                names=tuple(param.opts) + tuple(param.secondary_opts),
                takes_value=takes_value,
                nargs=max(1, getattr(param, "nargs", 1) or 1),
                choices=(
                    None
                    if choices is None
                    else tuple(str(getattr(c, "value", c)) for c in choices)
                ),
                case_sensitive=bool(getattr(param.type, "case_sensitive", True)),
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
    args: list[str],
    cli: CliCommand,
    complete: bool = True,
    check_values: bool = True,
    metavars: bool = False,
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

    An option's value is held to what the option accepts (see option_value_problems)
    unless ``check_values`` is False, for a block the runner runs to show the refusal.

    ``metavars`` is True for a line read out of a block of another language, where an
    uppercase word (``ash [OPTIONS] COMMAND [ARGS]...``) is click's usage notation for
    an argument, not a subcommand or a value.
    """
    problems: list[str] = []
    command = cli
    outside_plugins = _loads_outside_plugins(args)
    positionals = 0
    index = 0
    while index < len(args):
        word = args[index]
        if word == "--":
            break
        if (
            _is_placeholder(word)
            or "$" in word.partition("=")[0]
            or (metavars and re.fullmatch(r"[A-Z][A-Z0-9_]*", word))
        ):
            index += 1
            continue
        if word.startswith("-") and len(word) > 1 and not word[1:].isdigit():
            used, problem = _match_option(command, args, index, cli, complete)
            if not problem and check_values:
                problems += option_value_problems(
                    command, cli, args, index, outside_plugins
                )
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
# Option values
# ---------------------------------------------------------------------------
#
# click checks a choice option's value itself, and CliOption.choices records what it
# accepts. Other options take any string as far as click is concerned, and ASH checks
# the value after parsing, against one of its registries: those are listed here with
# the kind of name each one takes.

#: (command path, the option's first name) -> the kind of name its value is.
REGISTRY_OPTIONS = {
    (("ash",), "--scanners"): "scanner",
    (("ash",), "--exclude-scanners"): "scanner",
    (("ash",), "--output-formats"): "output format",
    (("ash", "scan"), "--scanners"): "scanner",
    (("ash", "scan"), "--exclude-scanners"): "scanner",
    (("ash", "scan"), "--output-formats"): "output format",
    (("ash", "merge"), "--output-formats"): "output format",
    (("ash", "report"), "--format"): "reporter",
    (("ash", "dependencies", "install"), "--tool"): "tool",
}
PLUGIN_KINDS = ("converter", "scanner", "reporter")


@dataclass(frozen=True)
class ValueSet:
    """The values one option accepts, and how ASH compares a value with them."""

    #: What a value names, for the message: "scanner", "output format".
    noun: str
    names: frozenset[str]
    #: A value may list several, separated by commas (``--scanners a,b``).
    comma_list: bool
    case_sensitive: bool
    #: A plugin module the invocation loads may add names (scanners, reporters, tools).
    plugins_add_names: bool


def _declared_plugin_name(plugin: Any) -> str:
    """The name a plugin is configured and selected by: its config class's ``name`` default.

    Read from the field's annotation, not by constructing the plugin, because
    constructing a scanner can install its tool. A plugin that declares no name is
    known by its lowercased class name, as ASH falls back to.
    """
    import typing

    field = (getattr(plugin, "model_fields", None) or {}).get("config")
    annotation = field.annotation if field is not None else None
    for candidate in [
        a for a in typing.get_args(annotation) if a is not type(None)
    ] or [annotation]:
        name = (getattr(candidate, "model_fields", None) or {}).get("name")
        default = getattr(name, "default", None)
        if isinstance(default, str) and default:
            return default
    return str(getattr(plugin, "__name__", "")).lower()


@functools.lru_cache(maxsize=None)
def plugin_names(kind: str) -> frozenset[str]:
    """The names of the plugins of one kind (converter, scanner, reporter) ASH ships.

    Read from the ASH_CONVERTERS, ASH_SCANNERS and ASH_REPORTERS lists of every plugin
    module in the package, which are what ASH's plugin loader registers, so a plugin
    whose config class has an unusual name is still found. A module that does not
    import contributes nothing here; load_config_models records it, and the checks
    that print skipped modules name it.
    """
    import pkgutil

    from automated_security_helper import plugin_modules

    attribute = f"ASH_{kind.upper()}S"
    names: set[str] = set()
    for info in pkgutil.walk_packages(
        plugin_modules.__path__, plugin_modules.__name__ + "."
    ):
        try:
            module = importlib.import_module(info.name)
        except Exception:  # an optional extra that is not installed
            continue
        for plugin in getattr(module, attribute, None) or []:
            names.add(_declared_plugin_name(plugin))
    return frozenset(names)


@functools.lru_cache(maxsize=None)
def option_value_set(command: tuple[str, ...], option: str) -> ValueSet | None:
    """What a registry option of ``command`` accepts, or None for any other option."""
    kind = REGISTRY_OPTIONS.get((command, option))
    if kind is None:
        return None
    if kind == "output format":
        # Validated by ExportFormat(value) in cli/scan.py and cli/merge.py.
        from automated_security_helper.core.enums import ExportFormat

        return ValueSet(
            kind, frozenset(f.value for f in ExportFormat), True, True, False
        )
    if kind == "tool":
        # ash dependencies install --tool: a plugin name of any kind, or a deprecated
        # alias (cli/dependencies.py), compared exactly.
        from automated_security_helper.cli import dependencies

        aliases = getattr(dependencies, "DEPRECATED_TOOL_ALIASES", {}) or {}
        names = frozenset().union(*(plugin_names(k) for k in PLUGIN_KINDS))
        return ValueSet(
            "converter, scanner, or reporter",
            names | frozenset(aliases),
            False,
            True,
            True,
        )
    # Scanner names are split on commas and lowercased (core/execution_engine.py,
    # core/phases/scan_phase.py); ash report lowercases --format.
    return ValueSet(kind, plugin_names(kind), kind == "scanner", False, True)


def usage_error_exit() -> int | None:
    """The exit code of an invocation ASH refuses, when no other outcome shares it.

    None when ASH has no code of its own for a usage error, or when it is also the code
    for actionable findings (click's default, 2): a run block that expects that code
    cannot tell a refused value from a scan that found something.
    """
    try:
        from automated_security_helper.core import constants
    except ImportError:
        return None
    usage = getattr(constants, "ASH_EXIT_USAGE_ERROR", None)
    codes = getattr(constants, "ASH_EXIT_CODES", None) or {}
    findings = {code for code, meaning in codes.items() if "findings" in str(meaning)}
    if not isinstance(usage, int) or usage in (findings or {2}):
        return None
    return usage


_PLUGIN_MODULE_OVERRIDE = re.compile(
    r"^\s*ash_plugin_modules\s*\+?=\s*\[?(?P<modules>[^\]]*)\]?\s*$"
)


def _loads_outside_plugins(args: list[str]) -> bool:
    """Whether an invocation loads a plugin module from outside ASH, which may add names.

    Through --ash-plugin-modules, or a --config-overrides that sets ash_plugin_modules.
    A module named by a variable may be anything, so it counts as outside.
    """
    modules: list[str] = []
    for index, word in enumerate(args):
        name, inline, value = word.partition("=")
        if name not in ("--ash-plugin-modules", "--config-overrides"):
            continue
        if not inline:
            value = args[index + 1] if index + 1 < len(args) else ""
        if name == "--ash-plugin-modules":
            modules += value.split(",")
        elif match := _PLUGIN_MODULE_OVERRIDE.match(value):
            modules += match.group("modules").split(",")
    for module in (m.strip().strip("'\"") for m in modules):
        if module and not (module == ASH_MODULE or module.startswith(ASH_MODULE + ".")):
            return True
    return False


def _or_list(items: Iterable[str]) -> str:
    items = list(items)
    if len(items) <= 2:
        return " or ".join(items)
    return ", ".join(items[:-1]) + ", or " + items[-1]


def option_value_problems(
    command: CliCommand,
    cli: CliCommand,
    args: list[str],
    index: int,
    outside_plugins: bool = False,
) -> list[str]:
    """Problems with the value of the option at ``args[index]``.

    A choice option's value must be one of its choices; a registry option's value (or
    each value in its comma list) must name something ASH has. A value that is a
    placeholder or a variable is not judged. Where the invocation loads a plugin
    module from outside ASH, an unknown scanner, reporter or tool name may be that
    module's, so only a name close to one of ASH's own is reported, as a likely typo.
    """
    word = args[index]
    name, inline, value = word.partition("=")
    option, owner = command.options.get(name), command
    if option is None and command.forwards_unknown:
        option, owner = cli.options.get(name), cli
    if option is None or not option.takes_value:
        return []
    if not inline:
        if index + 1 >= len(args):
            return []
        value = args[index + 1]
    if not value or _is_placeholder(value) or any(c in value for c in "$`{"):
        return []
    shown = f"'{command.display} {word}" + ("" if inline else f" {value}") + "'"
    if option.choices is not None:
        fold = (lambda v: v) if option.case_sensitive else str.lower
        if fold(value) in {fold(choice) for choice in option.choices}:
            return []
        close = difflib.get_close_matches(value, list(option.choices), n=1)
        hint = f"; did you mean '{close[0]}'?" if close else ""
        return [
            f"{shown}: {name} takes {_or_list(option.choices)}, not '{value}'{hint}"
        ]
    values = option_value_set(owner.path, option.names[0])
    if values is None:
        return []
    known = values.names if values.case_sensitive else {n.lower() for n in values.names}
    open_names = outside_plugins and values.plugins_add_names
    problems = []
    for item in value.split(",") if values.comma_list else [value]:
        item = item.strip()
        if not item or (item if values.case_sensitive else item.lower()) in known:
            continue
        close = difflib.get_close_matches(
            item, sorted(values.names), n=1, cutoff=0.8 if open_names else 0.6
        )
        if open_names and not close:
            continue
        hint = f"; did you mean '{close[0]}'?" if close else ""
        if values.noun == "output format":
            problems.append(
                f"{shown}: '{item}' is not an output format; {name} takes "
                f"{_or_list(sorted(values.names))}"
            )
        else:
            problems.append(f"{shown}: ASH has no {values.noun} named '{item}'{hint}")
    return problems


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
    return console_commands(block.body) if block.lang in CONSOLE_LANGS else block.body


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


_ASH_LINE = re.compile(r"^\s*(?:\$\s*)?ash\s")
#: Lines of a diff that are not commands to run: removed lines and headers.
_DIFF_NOT_RUN = re.compile(r"^(?:-|@@|\+\+\+|diff |index )")


def ash_lines(body: str, lang: str = "") -> list[tuple[int, str]]:
    """(zero-based line, command) of each line of a block that starts an ash command.

    For the blocks whose commands no other rule parses: text, markdown, diff, json5,
    ini and the like. A line counts when it starts with ``ash`` after its indentation
    and an optional ``$`` prompt; a line that ends in a backslash continues on the
    next. In a diff only added and context lines are read: a removed line is the old
    command.
    """
    lines = body.split("\n")
    if lang == "diff":
        lines = ["" if _DIFF_NOT_RUN.match(line) else line[1:] for line in lines]
    found = []
    index = 0
    while index < len(lines):
        start, line = index, lines[index]
        index += 1
        if not _ASH_LINE.match(line):
            continue
        command = re.sub(r"^\s*\$\s*", "", line)
        while command.rstrip().endswith("\\") and index < len(lines):
            command = command.rstrip()[:-1] + " " + lines[index].strip()
            index += 1
        found.append((start, command))
    return found


def reads_ash_lines(block: Block, output_sample: bool = False) -> bool:
    """Whether the CLI check reads a block's ash lines one by one (see ash_lines).

    A block whose commands no other rule parses: a block of another language (groovy
    has its ``sh`` steps parsed instead), or a config block whose kind holds no
    commands. ``output_sample`` is True for a sample of a run block's output (see
    output_samples), which holds output, not commands.
    """
    if output_sample:
        return False
    if block.family == "other":
        return block.lang != "groovy"
    if block.family == "config":
        kind = block.config_kind
        return kind in ASH_CONFIG_KINDS or kind in ("other", "ash-output")
    return False


_GROOVY_SH = re.compile(
    r"\bsh\s*(?:\(\s*)?(?:script\s*:\s*)?(?P<quote>\'\'\'|\"\"\"|\'|\")"
)


def groovy_sh_scripts(body: str) -> list[tuple[int, str]]:
    """(zero-based line, shell script) of each ``sh`` step in a Jenkinsfile.

    The forms Jenkins pipelines use: ``sh '...'``, ``sh "..."``, the triple-quoted
    ``sh \'\'\'...\'\'\'`` and ``sh(script: '...')``. Groovy's escaped backslash is
    a backslash in the script.
    """
    found = []
    for match in _GROOVY_SH.finditer(body):
        quote, start = match.group("quote"), match.end()
        if len(quote) == 3:
            end = body.find(quote, start)
            end = len(body) if end < 0 else end
        else:
            end = start
            while end < len(body) and body[end] not in (quote, "\n"):
                end += 2 if body[end] == "\\" else 1
        script = body[start:end].replace("\\\\", "\\")
        if len(quote) == 1:
            script = script.replace("\\" + quote, quote)
        found.append((body.count("\n", 0, start), script))
    return found


_QUOTE_PREFIX = re.compile(r"^[ ]{0,3}(?:>[ ]?)+")
_INDENTED_CODE = re.compile(r"^(?: {4}|\t)")


def prose_code_blocks(page: Page) -> list[Block]:
    """Code in a page's prose that parse_page does not split out, as Blocks.

    A fence inside a blockquote (``> ```bash``), and an indented code block (four
    spaces or a tab, after a blank line). They are for the CLI check, which reads
    them as it reads any block; the runner never runs them, and no other check sees
    them.
    """
    blocks: list[Block] = []
    prose = page.prose
    position = 0
    while position < len(prose):
        number, line = prose[position]
        quote = _QUOTE_PREFIX.match(line)
        opened = _FENCE_OPEN.match(line[quote.end() :]) if quote else None
        if opened:
            fence, body = opened.group("fence"), []
            scan = position + 1
            while scan < len(prose) and prose[scan][0] == prose[scan - 1][0] + 1:
                inner = _QUOTE_PREFIX.sub("", prose[scan][1], count=1)
                if inner.strip().startswith(fence) and set(inner.strip()) == {fence[0]}:
                    break
                body.append(inner)
                scan += 1
            info = opened.group("info").strip()
            blocks.append(
                Block(
                    page.path,
                    _fence_language(info),
                    info,
                    number,
                    "\n".join(body),
                    number + 1,
                    "",
                    scan < len(prose),
                )
            )
            position = scan + 1
            continue
        previous = prose[position - 1] if position else (0, "")
        if _INDENTED_CODE.match(line) and line.strip() and not previous[1].strip():
            body, scan = [], position
            while (
                scan < len(prose)
                and prose[scan][0] == number + len(body)
                and (_INDENTED_CODE.match(prose[scan][1]) or not prose[scan][1].strip())
            ):
                body.append(re.sub(r"^(?: {4}|\t)", "", prose[scan][1]))
                scan += 1
            blocks.append(
                Block(
                    page.path, "text", "text", number, "\n".join(body), number, "", True
                )
            )
            position = scan
            continue
        position += 1
    return blocks


def block_invocations(
    block: Block, root: Path, code: Path | None = None, output_sample: bool = False
) -> tuple[list[Invocation], list[str]]:
    """Every ash invocation a block makes, plus problems found while looking for them.

    ``code`` is the tree whose .pre-commit-hooks.yaml and action.yml files a CI block
    is checked against; it defaults to ``root``. ``output_sample`` is True for a
    sample of a run block's output, whose ash lines are not read.
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
    elif block.lang == "groovy":
        for base, script in groovy_sh_scripts(block.body):
            for invocation in invocations_in_script(script):
                invocation.line += base
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
    if reads_ash_lines(block, output_sample):
        for line, command in ash_lines(block.body, block.lang):
            for invocation in invocations_in_script(command):
                invocation.line = line
                found.append(invocation)
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
        if path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
            problems += _reusable_workflow_call_problems(step, uses, path, root)
            continue
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


def _reusable_workflow_call_problems(
    job: dict, uses: str, path: str, root: Path
) -> list[str]:
    """A job that calls this repository's reusable workflow: the workflow must exist
    and be callable, the job's with: keys must be inputs it declares under
    on.workflow_call, every required input must be passed, and secrets: must name
    declared secrets (or be inherit). The workflow's triggers are read from its on:
    key alone (_workflow_on), as GitHub reads them."""
    workflow = root / path
    if not workflow.is_file():
        return [
            f"uses: {uses} names no workflow: there is no {path} in this repository"
        ]
    document, error = _parse_workflow(workflow.read_text(encoding="utf-8"))
    if error is not None:
        return [f"uses: {uses} calls {path}, which {error}"]
    triggers = _workflow_on(document)
    if not (isinstance(triggers, dict) and "workflow_call" in triggers):
        return [
            (
                f"uses: {uses} calls {path}, which declares no on.workflow_call, so "
                "it cannot be called from another workflow"
            )
        ]
    call = (
        triggers["workflow_call"] if isinstance(triggers["workflow_call"], dict) else {}
    )
    inputs = call.get("inputs") if isinstance(call.get("inputs"), dict) else {}
    secrets = call.get("secrets") if isinstance(call.get("secrets"), dict) else {}
    passed = job.get("with") if isinstance(job.get("with"), dict) else {}
    problems = [
        f"uses: {uses} has no input '{name}'; {path} declares {sorted(inputs)}"
        for name in passed
        if name not in inputs
    ]
    problems += [
        f"uses: {uses} does not pass its required input '{name}'"
        for name, spec in inputs.items()
        if isinstance(spec, dict)
        and spec.get("required") is True
        and "default" not in spec
        and name not in passed
    ]
    given = job.get("secrets")
    if isinstance(given, dict):
        problems += [
            f"uses: {uses} has no secret '{name}'; {path} declares {sorted(secrets)}"
            for name in given
            if name not in secrets
        ]
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


# ---------------------------------------------------------------------------
# Check: values a docs example passes to the scan workflow pass its input check
# ---------------------------------------------------------------------------
#
# run-ash-security-scan.yml refuses, in its first step, a string input that holds a
# control character or the legacy command marker ##[, since the runner would read what
# follows as a workflow command on any line that prints it. It drops one line feed at
# the end first, so a one-line `|` block passes, and refuses a value that is only a
# line feed, which would be empty to the checked value and not to a step reading the
# input as given. The CI checks above read only the names in
# with:, so an example whose ash-args is a two-line block passed them and failed in the
# reader's first run. The inputs checked are the workflow's own: the step that loops
# over "${!INPUT_@}", whose env maps each INPUT_<NAME> to ${{ inputs.<name> }}.

SCAN_WORKFLOW = ".github/workflows/run-ash-security-scan.yml"
_INPUT_EXPRESSION = re.compile(r"^\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*\}\}$")
_LEGACY_COMMAND_MARKER = "##["
_ONLY_A_LINE_FEED = "is only a line feed"
#: What the step refuses as a control character, whatever the runner's locale: C0 and
#: DEL through [[:cntrl:]] under LC_ALL=C, and C1 and the line and paragraph separators
#: by their UTF-8 bytes. Those are categories Cc, Zl and Zp.
_CONTROL_CATEGORIES = frozenset({"Cc", "Zl", "Zp"})


def checked_workflow_inputs(workflow_text: str) -> set[str]:
    """The inputs a workflow's input check reads: the env of every step whose run loops
    over "${!INPUT_@}", where INPUT_<NAME> is set to ${{ inputs.<name> }}."""
    import yaml

    document = yaml.safe_load(workflow_text) or {}
    jobs = document.get("jobs") if isinstance(document, dict) else None
    names: set[str] = set()
    for step in _dicts_with_key(jobs or {}, "run"):
        if '"${!INPUT_@}"' not in str(step.get("run")):
            continue
        env = step.get("env") if isinstance(step.get("env"), dict) else {}
        for key, value in env.items():
            match = _INPUT_EXPRESSION.match(str(value).strip())
            if str(key).startswith("INPUT_") and match:
                names.add(match.group(1))
    return names


def refused_input_value(value: str) -> str | None:
    """Why the scan workflow's input check refuses a string value, or None.

    One line feed at the end is dropped first. What is left is refused if it holds a
    control character or ##[, or if it is empty and the value was not.
    """
    text = value.removesuffix("\n")
    if _LEGACY_COMMAND_MARKER in text:
        return f"holds the legacy command marker {_LEGACY_COMMAND_MARKER}"
    for char in text:
        if unicodedata.category(char) in _CONTROL_CATEGORIES:
            if char in "\n\r":
                return "holds a line break"
            return f"holds the control character {ord(char):#04x}"
    if value and not text:
        return _ONLY_A_LINE_FEED
    return None


def _calls_scan_workflow(uses: str) -> bool:
    target = uses.split("@", 1)[0].strip().lower()
    return target in (f"{GITHUB_REPO_SLUG}/{SCAN_WORKFLOW}", f"./{SCAN_WORKFLOW}")


def _with_key_line(block: Block, name: str) -> int:
    key = re.compile(rf"^\s*{re.escape(name)}\s*:")
    return next(
        (number for number, text in block.body_lines() if key.match(text)),
        block.fence_line,
    )


def check_workflow_inputs(
    files: Iterable[Path],
    root: Path = REPO_ROOT,
    code: Path | None = None,
    notes: list[str] | None = None,
) -> list[Finding]:
    """Every string value a github-actions block passes to the scan workflow is one
    the workflow's input check accepts."""
    code = code or code_root(root)
    workflow = code / SCAN_WORKFLOW
    if not workflow.is_file():
        return [
            Finding(
                "workflow-inputs",
                SCAN_WORKFLOW,
                1,
                f"the code tree has no {SCAN_WORKFLOW}, so this check cannot tell "
                "which inputs it refuses",
            )
        ]
    checked = checked_workflow_inputs(workflow.read_text(encoding="utf-8"))
    if not checked:
        return [
            Finding(
                "workflow-inputs",
                SCAN_WORKFLOW,
                1,
                f'{SCAN_WORKFLOW} has no step that loops over "${{!INPUT_@}}" with '
                "INPUT_<NAME> set to ${{ inputs.<name> }}, so this check cannot tell "
                "which inputs it refuses",
            )
        ]
    findings: list[Finding] = []
    blocks = values = 0
    for page in load_pages(files, root):
        for block in page.blocks:
            if block.family != "config" or block.config_kind != "github-actions":
                continue
            document, error = parse_config_text(block.body, block.lang)
            if error is not None:
                continue
            calls = [
                job
                for job in _dicts_with_key(document, "uses")
                if _calls_scan_workflow(str(job.get("uses")))
            ]
            blocks += bool(calls)
            for job in calls:
                passed = job.get("with") if isinstance(job.get("with"), dict) else {}
                for name, value in passed.items():
                    if name not in checked or not isinstance(value, str):
                        continue
                    values += 1
                    why = refused_input_value(value)
                    if why is None:
                        continue
                    shown = value if len(value) <= 60 else value[:57] + "..."
                    remedy = (
                        "Leave it empty instead."
                        if why == _ONLY_A_LINE_FEED
                        else "Pass it on one line, with no control character and "
                        f"no {_LEGACY_COMMAND_MARKER}."
                    )
                    findings.append(
                        Finding(
                            "workflow-inputs",
                            page.rel,
                            _with_key_line(block, name),
                            f"{name}: {shown!r} {why}, so {SCAN_WORKFLOW} refuses it "
                            f"in its first step and the scan never runs. {remedy}",
                        )
                    )
    if notes is not None:
        notes.append(
            f"examined {values} input value{'' if values == 1 else 's'} in {blocks} "
            f"block{' that calls' if blocks == 1 else 's that call'} {SCAN_WORKFLOW}"
        )
    return findings


def _invocation_line(block: Block, invocation: Invocation) -> int:
    """The line an invocation is on. A CI config is parsed as a document, so its
    invocations are reported at the block's fence."""
    if block.family == "config" and not reads_ash_lines(block):
        return block.fence_line
    return block.body_line + invocation.line


def shows_a_refusal(block: Block) -> bool:
    """Whether a block runs a refused value on purpose, to show ASH refusing it.

    A run block whose expect-exit is ASH's usage-error code: the runner proves that a
    command in it is refused. Where that code is also the code for findings,
    usage_error_exit is None, and no block counts.
    """
    usage = usage_error_exit()
    return (
        usage is not None
        and block.marker is not None
        and block.mode == "run"
        and str(block.marker.keys.get("expect-exit")) == str(usage)
    )


def output_samples(page: Page) -> dict[int, Block]:
    """id() of each block marked output that directly follows a block the runner runs,
    mapped to that block.

    That is a sample of the run block's output, which the runner compares with what
    the block prints. A block marked output anywhere else is not a sample of anything:
    its ash lines are read as commands like any other, and output_marker_problems
    reports the marker.
    """
    samples: dict[int, Block] = {}
    for previous, block in zip(page.blocks, page.blocks[1:]):
        if (
            block.marker is not None
            and block.marker.mode == OUTPUT_MODE
            and block.family == "other"
            and block.closed
            and runner_runs(previous)
        ):
            samples[id(block)] = previous
    return samples


def _block_cli_findings(
    block: Block,
    rel: str,
    root: Path,
    code: Path,
    cli: CliCommand,
    output_sample: bool = False,
) -> list[Finding]:
    invocations, problems = block_invocations(block, root, code, output_sample)
    findings = [Finding("cli", rel, block.fence_line, problem) for problem in problems]
    # A block runs under set -e, so it ends at its first refused command, and that
    # command alone is shown refusing. A refused value in any other is reported.
    refusal_shown = not shows_a_refusal(block)
    metavars = reads_ash_lines(block, output_sample)
    for invocation in invocations:
        line = _invocation_line(block, invocation)
        if invocation.problem:
            findings.append(Finding("cli", rel, line, invocation.problem))
        problems = ash_args_problems(invocation.args, cli, metavars=metavars)
        if not refusal_shown:
            without_values = ash_args_problems(
                invocation.args, cli, check_values=False, metavars=metavars
            )
            if without_values != problems:
                problems, refusal_shown = without_values, True
        for problem in problems:
            findings.append(Finding("cli", rel, line, problem))
    return findings


#: The comment a reference generator opens its page with.
_GENERATED_BY = re.compile(r"\s*<!--\s*Generated by scripts/generate_\w+\.py\b")
#: The sections whose plugins' options tables the generated reference pages carry.
PLUGIN_SECTIONS = frozenset({"scanners", "reporters", "converters"})
#: The end of an environment variable's purpose quoted from a plugin module's code,
#: as generate_env_var_reference.py writes it: the file, then the scope, if any.
_PLUGIN_COMMENT_AT = re.compile(
    r"\(`automated_security_helper/plugin_modules/[^`]+`(?:, `[^`]+`)?\)$"
)


def plugin_written_rows(page: Page) -> set[int]:
    """The lines of a generated reference page whose text a plugin's code wrote.

    Those are the rows of a plugin's options table (of=scanners.<name>,
    of=reporters.<name>, of=converters.<name>), and the rows of an environment
    variable table whose purpose is quoted from a plugin module. A hand-written page
    has none: its author chose each word.
    """
    if not _GENERATED_BY.match(page.text):
        return set()
    rows: set[int] = set()
    for table in page.tables:
        of = table.marker.keys.get("of") if table.marker else None
        if isinstance(of, str) and of.split(".")[0] in PLUGIN_SECTIONS and "." in of:
            rows.update(number for number, _cells in table.rows)
            continue
        header = [cell.strip().lower() for cell in table.header]
        if "variable" in header and "purpose" in header:
            purpose = header.index("purpose")
            rows.update(
                number
                for number, cells in table.rows
                if purpose < len(cells)
                and _PLUGIN_COMMENT_AT.search(cells[purpose].strip())
            )
    return rows


def check_cli(
    files: Iterable[Path],
    root: Path = REPO_ROOT,
    cli: CliCommand | None = None,
    code: Path | None = None,
) -> list[Finding]:
    """Every ash invocation in a block or inline code span parses against the real CLI.

    Every block is read: shell, Dockerfile and CI blocks as commands, a Jenkinsfile's
    sh steps, the ash lines of every other block that is not a run block's output
    sample (output_samples), and the code in a page's prose that is not a fenced
    block (a fence in a blockquote, an
    indented code block). The TypeScript blocks that construct one of the code tree's
    CDK constructs are held to its props and enums (typescript_problems).

    A bare option span in prose must be an option of some ash command. In a row a
    plugin's code wrote (plugin_written_rows) it must name its program even then: there
    a bare `--config` could be ASH's or the plugin's tool's, so ASH's own is written
    `ash --config`.
    """
    cli = cli or load_cli()
    code = code or code_root(root)
    every_option = all_option_names(cli)
    findings: list[Finding] = []
    for page in load_pages(files, root):
        if page.rel in HISTORICAL_DOCS:
            continue
        plugin_rows = plugin_written_rows(page)
        samples = output_samples(page)
        for block in page.blocks:
            findings += _block_cli_findings(
                block, page.rel, root, code, cli, id(block) in samples
            )
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
        for block in prose_code_blocks(page):
            findings += _block_cli_findings(block, page.rel, root, code, cli)
        findings += [
            Finding("cli", page.rel, line, problem)
            for line, problem in typescript_problems(page, code)
        ]
        for number, line in page.prose:
            for span in inline_code_spans(line):
                if number in plugin_rows and _BARE_OPTION.match(span):
                    findings.append(
                        Finding(
                            "cli",
                            page.rel,
                            number,
                            f"`{span}`: a plugin's code wrote this row, where a bare option "
                            "could be ASH's or the plugin's tool's: put the program in the "
                            f"span (`<program> {span}`), or write `ash {span}` for ASH's own "
                            "option. The page is generated, so change the text in the code",
                        )
                    )
                    continue
                findings += _inline_span_findings(
                    span, page.rel, number, cli, every_option
                )
    return findings


# ---------------------------------------------------------------------------
# TypeScript blocks that construct a CDK construct of the code tree
# ---------------------------------------------------------------------------

TS_LANGS = frozenset({"ts", "typescript", "tsx", "js", "javascript"})
_TS_SKIP_DIRS = frozenset({"node_modules", "dist", "cdk.out", "coverage"})


@dataclass(frozen=True)
class TsDeclarations:
    """The interfaces and enums a TypeScript package declares, from its sources."""

    #: Interface -> (its properties, whether it extends another, the file it is in).
    interfaces: dict[str, tuple[frozenset[str], bool, str]]
    #: Enum -> (its members, the file it is in).
    enums: dict[str, tuple[frozenset[str], str]]


def _ts_body(text: str, open_brace: int) -> str:
    depth, index = 1, open_brace + 1
    while index < len(text) and depth:
        depth += {"{": 1, "}": -1}.get(text[index], 0)
        index += 1
    return text[open_brace + 1 : index - 1]


@functools.lru_cache(maxsize=None)
def ts_declarations(package: str, code: str) -> TsDeclarations:
    """Every interface and enum declared in a package's .ts files (not its dependencies)."""
    interfaces: dict[str, tuple[frozenset[str], bool, str]] = {}
    enums: dict[str, tuple[frozenset[str], str]] = {}
    for path in listed_files(Path(package), ["**/*.ts"]):
        if _TS_SKIP_DIRS & set(path.relative_to(package).parts):
            continue
        text = re.sub(
            r"/\*.*?\*/|//[^\n]*", "", path.read_text(encoding="utf-8"), flags=re.DOTALL
        )
        rel = rel_path(path, Path(code))
        for match in re.finditer(r"\binterface\s+(\w+)\b([^{]*)\{", text):
            body = _ts_body(text, match.end() - 1)
            names = frozenset(
                t.group("name") for t in _TS_TOKEN.finditer(body) if t.group("name")
            )
            interfaces.setdefault(
                match.group(1), (names, "extends" in match.group(2), rel)
            )
        for match in re.finditer(r"\benum\s+(\w+)\s*\{", text):
            body = _ts_body(text, match.end() - 1)
            members = frozenset(
                re.findall(r"(?:^|,)\s*([A-Za-z_$][\w$]*)\s*(?==|,|$)", body.strip())
            )
            enums.setdefault(match.group(1), (members, rel))
    return TsDeclarations(interfaces, enums)


def _ts_package(page: Page, code: Path) -> Path | None:
    """The TypeScript package a page documents: the nearest package.json above it."""
    directory = (code / page.rel).parent
    code = code.resolve()
    while directory.resolve().is_relative_to(code):
        if (directory / "package.json").is_file():
            return directory
        if directory.resolve() == code:
            break
        directory = directory.parent
    return None


def _object_literal_keys(text: str, start: int) -> list[tuple[int, str]]:
    """(offset, key) of each top-level property of the object literal at text[start]."""
    keys: list[tuple[int, str]] = []
    closers = {"(": ")", "[": "]", "{": "}"}
    expected: list[str] = []
    index = segment = start + 1
    while index < len(text):
        char = text[index]
        if char in "'\"`":
            end = text.find(char, index + 1)
            index = len(text) if end < 0 else end + 1
            continue
        if char in closers:
            expected.append(closers[char])
        elif expected and char == expected[-1]:
            expected.pop()
        elif not expected and char in ",}":
            part = text[segment:index]
            key = re.match(r"\s*['\"]?([A-Za-z_$][\w$]*)['\"]?\s*(?::|$)", part)
            if key and not part.strip().startswith("..."):
                keys.append((segment + key.start(1), key.group(1)))
            if char == "}":
                break
            segment = index + 1
        index += 1
    return keys


def _ts_calls(
    page: Page, code: Path
) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    """(examined, problems) for the TypeScript blocks of a page, as (line, text)."""
    package = _ts_package(page, code)
    if package is None:
        return [], []
    declared = ts_declarations(str(package), str(code))
    examined: list[tuple[int, str]] = []
    problems: list[tuple[int, str]] = []
    for block in page.blocks:
        if block.lang not in TS_LANGS:
            continue
        body = block.body

        def line_of(offset: int) -> int:
            return block.body_line + body.count("\n", 0, offset)

        for call in re.finditer(r"\bnew\s+([A-Za-z_$][\w$]*)\s*\(", body):
            props = declared.interfaces.get(call.group(1) + "Props")
            literal = body.find("{", call.end())
            if props is None or literal < 0 or ")" in body[call.end() : literal]:
                continue
            names, extends, rel = props
            examined.append((line_of(call.start()), f"new {call.group(1)}"))
            if extends:
                continue
            for offset, key in _object_literal_keys(body, literal):
                if key not in names:
                    problems.append(
                        (
                            line_of(offset),
                            (
                                f"new {call.group(1)}(...) passes '{key}', which "
                                f"{call.group(1)}Props in {rel} does not declare; it "
                                f"declares {', '.join(sorted(names))}"
                            ),
                        )
                    )
        for ref in re.finditer(r"\b([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)", body):
            enum = declared.enums.get(ref.group(1))
            if enum is None:
                continue
            members, rel = enum
            examined.append((line_of(ref.start()), ref.group(0)))
            if ref.group(2) not in members:
                problems.append(
                    (
                        line_of(ref.start()),
                        (
                            f"{ref.group(1)} has no member {ref.group(2)}; {rel} declares "
                            f"{', '.join(sorted(members))}"
                        ),
                    )
                )
    return examined, problems


def typescript_calls(page: Page, code: Path) -> list[tuple[int, str]]:
    """The construct calls and enum references of a page's TypeScript blocks that the
    CLI check compares with the code tree, as (line, text)."""
    return _ts_calls(page, code)[0]


def typescript_problems(page: Page, code: Path) -> list[tuple[int, str]]:
    """A construct prop or enum member a page's TypeScript blocks use that the
    construct's package does not declare, as (line, message).

    ``new X(id, { ... })`` is compared with interface ``XProps`` when the page's
    package (the nearest package.json above it in the code tree) declares one that
    extends nothing; a class from a dependency is not compared. ``E.M`` is compared
    with enum ``E`` when the package declares it.
    """
    return _ts_calls(page, code)[1]


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
#: Headers of a column of environment variable names, first or not.
_ENV_TABLE_HEADERS = (
    "variable",
    "variables",
    "environment variable",
    "environment variables",
    "env var",
    "env vars",
    "env variable",
)
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
    #: Each variable's Default column entries, from the env-var generator
    #: (default_entries), for comparing an env table's Default column. None until
    #: first needed.
    defaults: dict[str, list[str]] | None = None
    #: The generator module the read set came from, which supplies the defaults.
    generator: Any = None

    def known_build_args(self) -> dict[str, str]:
        if self.build_args is None:
            found = build_argument_names(self.code) if self.code else {}
            self.build_args = {n: w for n, w in found.items() if n not in self.names}
        return self.build_args

    def known_defaults(self) -> dict[str, list[str]]:
        if self.defaults is None:
            supply = getattr(self.generator, "default_entries", None)
            self.defaults = supply(self.code) if supply and self.code else {}
        return self.defaults

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
            read.generator = module
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
        for path in listed_files(code, [pattern]):
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


def listed_files(directory: Path, patterns: Iterable[str] = ()) -> list[Path]:
    """The files under ``directory`` that git lists: tracked ones, and untracked ones it
    does not ignore, narrowed to the glob ``patterns`` (relative to ``directory``) if any.

    A listing rather than a walk. git never descends into an ignored directory, so the
    tests' scratch tree, the scan output, a virtual environment and node_modules stay
    out of every check that reads files through this, however busy other test workers
    are in them; a walk entered them and raced those workers. A directory git cannot
    list, or one its checkout ignores (which git would list as empty), raises instead,
    so a check built on this cannot pass by reading nothing.
    """
    import subprocess

    def git(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", "-C", str(directory), *args], capture_output=True, check=False
        )

    top = git("rev-parse", "--show-toplevel")
    if top.returncode != 0:
        raise RuntimeError(
            f"git cannot list {directory}, so its files are unknown: "
            f"{top.stderr.decode(errors='replace').strip()}"
        )
    inside = Path(os.fsdecode(top.stdout.strip()))
    rel = Path(os.path.realpath(directory)).relative_to(os.path.realpath(inside))
    if rel.parts and git("check-ignore", "-q", "--", ".").returncode == 0:
        raise RuntimeError(
            f"{directory} is ignored by the checkout at {inside}, so git lists none "
            "of its files"
        )
    listing = git(
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
        "--",
        *(f":(glob){pattern}" for pattern in patterns),
    )
    if listing.returncode != 0:
        raise RuntimeError(
            f"git ls-files failed in {directory}, so its files are unknown: "
            f"{listing.stderr.decode(errors='replace').strip()}"
        )
    found = {
        directory / os.fsdecode(entry) for entry in listing.stdout.split(b"\0") if entry
    }
    # --cached still lists a tracked file deleted from the working tree.
    return sorted(path for path in found if path.is_file())


def _package_sources(package: Path) -> list[Path]:
    """The package's .py files, without the ignored build copies git does not track
    (the build writes some modules into automated_security_helper/assets/), which would
    otherwise be read twice."""
    return listed_files(package, ["**/*.py"])


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
    """Names in every column of a table headed Variable, Environment variable, Env var
    or the like, wherever in the table that column is."""
    found: list[tuple[int, str]] = []
    for table in page.tables:
        columns = [
            index
            for index, cell in enumerate(table.header)
            if cell.lower().strip("`* ") in _ENV_TABLE_HEADERS
        ]
        for row_number, cells in table.rows:
            for index in columns:
                if index < len(cells):
                    for name in _UPPER_NAME.findall(cells[index]):
                        found.append((row_number, name))
    return found


def _default_values(cell: str) -> list[str | None]:
    """The defaults a Default cell states, one per <br>-separated entry: the code
    span's content, or the text; None for an entry that says there is none."""
    values: list[str | None] = []
    for part in re.split(r"<br\s*/?>", cell):
        part = re.sub(r"\s*\(the default of `[^`]*`\)\s*$", "", part.strip())
        if part.lower().strip("*_ .") in ("", "not set", "none", "-", "—", "n/a"):
            values.append(None)
            continue
        spans = _SPAN.findall(part)
        if len(spans) == 1 and _SPAN.fullmatch(part):
            values.append(spans[0][1].strip())
        else:
            values.append(part)
    return values


def env_default_problems(page: Page, read: EnvReadSet) -> list[tuple[int, str]]:
    """Default cells of an environment-variable table that the code does not give.

    Each value the cell names must be a default the env-var generator records for the
    variable (its Default column); a cell that says there is none must be for a
    variable with no default.
    """
    problems: list[tuple[int, str]] = []
    for table in page.tables:
        if table.marker is not None or not _is_env_table(table):
            continue
        headers = _header_cells(table)
        column = next(
            (index for index, cell in enumerate(headers) if cell in DEFAULT_HEADERS),
            None,
        )
        if column is None:
            continue
        defaults = read.known_defaults()
        for number, cells in table.rows:
            names = _UPPER_NAME.findall(cells[0]) if cells else []
            if column >= len(cells) or len(names) != 1 or names[0] not in defaults:
                continue
            name, entries = names[0], defaults[names[0]]
            expected = [value for e in entries for value in _default_values(e)]
            written = _default_values(cells[column])
            given = [value for value in expected if value is not None]
            if all(value is None for value in written):
                wrong = bool(given) and None not in expected
            else:
                wrong = any(v is not None and v not in given for v in written)
            if wrong:
                shown = " or ".join(entries) if given else "no default"
                problems.append(
                    (
                        number,
                        (
                            f"{name}'s default says {cells[column].strip() or 'nothing'}, "
                            f"but the code gives {shown}"
                        ),
                    )
                )
    return problems


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
    """The member of names that name is, or that a family name (ASH_X_*) prefixes.

    A family ends at an underscore: ASH_SANDBOX_* is the ASH_SANDBOX_ variables, and
    ASH_S* names no family, however many names start with ASH_S.
    """
    if name.endswith(("*", "_")):
        prefix = name.rstrip("*")
        if not prefix.endswith("_"):
            return None
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
                family = (
                    "; a family name ends at an underscore, as ASH_SANDBOX_*"
                    if name.endswith("*") and not name.rstrip("*").endswith("_")
                    else ""
                )
                findings.append(
                    Finding(
                        "env",
                        page.rel,
                        line,
                        f"{name}{where} is not an environment variable ASH reads "
                        f"(read set: {read.source}{dynamic_note}), nor a build argument "
                        f"of a shipped Dockerfile{family}",
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
        for number, problem in env_default_problems(page, read):
            findings.append(Finding("env", page.rel, number, problem))
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
    except ModuleNotFoundError:  # Python 3.10
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
    except Exception as exc:  # every parser's error is the finding
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
    #: Plugin modules that raised on import (an optional extra that is not installed),
    #: with the error. Their plugins' config classes are not in plugin_configs.
    unloaded: dict[str, str] = field(default_factory=dict)
    #: Modules from outside ASH that a config block loads with ash_plugin_modules and
    #: that were imported to validate it; their plugins are in plugin_configs too.
    extra_modules: tuple[str, ...] = ()

    def skipped_notes(self) -> list[str]:
        """One line per plugin module that did not import, for a check to print."""
        return [
            f"plugin module {name} did not import ({error}), so its plugins' "
            "config classes were not checked"
            for name, error in sorted(self.unloaded.items())
        ]


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


def _plugin_config_bases() -> dict[str, type]:
    """The config base class each plugin section's configs derive from."""
    from automated_security_helper.base.converter_plugin import (
        ConverterPluginConfigBase,
    )
    from automated_security_helper.base.reporter_plugin import ReporterPluginConfigBase
    from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase

    return {
        "scanners": ScannerPluginConfigBase,
        "reporters": ReporterPluginConfigBase,
        "converters": ConverterPluginConfigBase,
    }


def plugin_config_classes(module: Any) -> dict[str, dict[str, type]]:
    """Section -> {plugin name: config class} for every plugin config in a module.

    A config is found by its base class and its ``name`` default, not by its class
    name: a plugin's config may be called anything (the scanner tutorial's is
    RuffSecurityConfig).
    """
    bases = _plugin_config_bases()
    found: dict[str, dict[str, type]] = {section: {} for section in bases}
    for attr in dir(module):
        obj = getattr(module, attr)
        if not isinstance(obj, type) or "name" not in getattr(obj, "model_fields", {}):
            continue
        for section, base in bases.items():
            if obj is not base and issubclass(obj, base):
                default = obj.model_fields["name"].default
                if isinstance(default, str) and default:
                    found[section].setdefault(default, obj)
    return found


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
    configs: dict[str, dict[str, type]] = {section: {} for section in segments}
    unloaded: dict[str, str] = {}
    for info in pkgutil.walk_packages(
        plugin_modules.__path__, plugin_modules.__name__ + "."
    ):
        module = None
        try:
            module = importlib.import_module(info.name)
        except Exception as exc:
            # An optional extra that is not installed is not a docs problem. It is
            # recorded, and the checks that use these models say what they skipped.
            unloaded[info.name] = f"{type(exc).__name__}: {exc}"
        if module is None:
            continue
        for section, found in plugin_config_classes(module).items():
            for name, config_cls in found.items():
                configs[section].setdefault(name, config_cls)
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
        unloaded,
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

    ``model`` has already validated, so a key in ``raw`` that names none of its
    fields is one the model let through: dropped or kept, nothing reads it, and a
    reader who copies it gets no error and no effect. Each such key is reported. A
    model that refuses unknown keys, by ``extra="forbid"`` or by a validator, never
    gets here with one, because validation fails first and that failure is the
    finding. Which models refuse and which let keys through is not assumed here, so
    the check answers the same way for any version of the models. The three plugin
    segments are different: their undeclared keys are plugin names, so each is looked
    up among the plugins ASH ships and validated against that plugin's own config
    class.
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
                    f"{where} is not a field of {cls.__name__}; {cls.__name__} accepted "
                    "it, and ASH never reads it"
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
        known = sorted(models.plugin_configs.get(section, {}))
        if external:
            # A module the block loads could not be imported, so its plugins are
            # unknown; a name this close to one ASH ships is still a misspelling.
            close = difflib.get_close_matches(name, known, n=1, cutoff=0.8)
            if not close:
                return []
            return [
                (
                    f"{where}: ASH ships no {section[:-1]} named '{name}'; did you mean "
                    f"'{close[0]}'? The modules this block loads with ash_plugin_modules "
                    "could not be imported here, so only names this close to one ASH "
                    "ships are reported"
                )
            ]
        close = difflib.get_close_matches(name, known, n=1)
        hint = f"; did you mean '{close[0]}'?" if close else ""
        if models.extra_modules:
            return [
                (
                    f"{where}: neither ASH nor the modules this block loads "
                    f"({', '.join(models.extra_modules)}) define a {section[:-1]} "
                    f"named '{name}'{hint}"
                )
            ]
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


def outside_modules(data: Any) -> list[str]:
    """The modules a config's ash_plugin_modules lists that are not part of ASH."""
    modules = data.get("ash_plugin_modules") if isinstance(data, dict) else None
    if not isinstance(modules, list):
        return []
    return [
        str(m)
        for m in modules
        if not (str(m) == ASH_MODULE or str(m).startswith(ASH_MODULE + "."))
    ]


def validate_ash_config(
    data: Any,
    models: ConfigModels | None = None,
    unimported: Iterable[str] | None = None,
) -> list[str]:
    """Problems with a parsed config, as ASH would load it, plus every ignored key.

    ``unimported`` lists the modules from outside ASH the config loads whose plugins
    ``models`` does not have; by default every such module the config names. Their
    plugins' names are then checked only for being close to one ASH ships.
    """
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
    external = bool(
        list(unimported) if unimported is not None else outside_modules(data)
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
        except Exception as exc:  # the reader's error is the finding
            first = (
                str(exc).strip().splitlines()[0]
                if str(exc).strip()
                else type(exc).__name__
            )
            return None, f"does not parse as {lang}: {first}"
        finally:
            logging.disable(previous)


def _block_ash_config(
    text: str, lang: str, kind: str, at: Any
) -> tuple[Any, str | None]:
    """A config block of an ASH kind, read with ASH's reader and placed at its path."""
    data, error = _read_ash_config(text, lang, as_pyproject=(kind == "pyproject"))
    if error:
        return None, error
    if kind == "ash-fragment":
        for part in reversed(str(at or "").split(".")):
            data = {part: data}
    return data, None


def validate_with_outside_modules(
    text: str, lang: str, kind: str, at: Any, modules: list[str]
) -> list[str]:
    """Validate a config block with the modules it loads imported into this process.

    The plugin configs each module defines, found by base class, are added to ASH's.
    Run in a child process (see _outside_module_problems), so the modules and the
    plugins their import registers do not stay in the process the checks run in.
    """
    import dataclasses

    data, error = _block_ash_config(text, lang, kind, at)
    if error:
        return [error]
    base = load_config_models()
    configs = {section: dict(found) for section, found in base.plugin_configs.items()}
    imported: list[str] = []
    unimported: list[str] = []
    for name in modules:
        try:
            module = importlib.import_module(name)
        except Exception:
            unimported.append(name)
            continue
        imported.append(name)
        # What ASH sees is what importing the module loads: the module, and the
        # submodules its import brings in. Others are not walked.
        loaded = [module] + [
            each
            for key, each in sorted(sys.modules.items())
            if key.startswith(name + ".") and each is not None
        ]
        for each in loaded:
            for section, found in plugin_config_classes(each).items():
                for plugin, config_cls in found.items():
                    configs[section].setdefault(plugin, config_cls)
    models = dataclasses.replace(
        base, plugin_configs=configs, extra_modules=tuple(imported)
    )
    return validate_ash_config(data, models, unimported=unimported)


_CHILD_RESULT = "ash-docs-checks-result:"
#: Run as ``python -I -c``: loads this file by path and validates one block with the
#: modules it loads, then prints the problems as one JSON line.
_CHILD_VALIDATOR = f"""
import importlib.util, json, sys
request = json.loads(sys.stdin.read())
# After the standard library, so a saved difflib.py cannot replace the checker's own.
at = next((i for i, p in enumerate(sys.path) if p.endswith("-packages")), len(sys.path))
sys.path[at:at] = request["paths"]
spec = importlib.util.spec_from_file_location("_ash_docs_checks", request["checks"])
module = importlib.util.module_from_spec(spec)
sys.modules["_ash_docs_checks"] = module
spec.loader.exec_module(module)
problems = module.validate_with_outside_modules(
    request["text"], request["lang"], request["kind"], request["at"], request["modules"]
)
print({_CHILD_RESULT!r} + json.dumps(problems))
"""


def _page_module_paths(
    page: Page, scratch: Path, modules: list[str]
) -> tuple[list[str], set[str]]:
    """Write the page's saved files under ``scratch``, and return the directories that
    put each module on the import path the way the page does (``ash-plugins`` for a
    page that saves ``ash-plugins/acme/__init__.py`` and exports that directory), with
    the modules the page saves."""
    saved: list[str] = []
    for block in page.blocks:
        if block.save_as and not save_as_problem(block.save_as):
            rel = "/".join(
                part
                for part in block.save_as.replace("\\", "/").split("/")
                if part not in ("", ".")
            )
            target = scratch / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(block.body + "\n", encoding="utf-8")
            saved.append(rel)
    paths = [str(scratch)]
    on_page: set[str] = set()
    for name in modules:
        module = name.replace(".", "/")
        for rel in saved:
            for suffix in (f"{module}.py", f"{module}/"):
                at = ("/" + rel).rfind("/" + suffix)
                if at >= 0:
                    on_page.add(name)
                    directory = str(scratch / rel[:at]) if at else str(scratch)
                    if directory not in paths:
                        paths.append(directory)
    return paths, on_page


def _outside_module_problems(
    block: Block, kind: str, page: Page, modules: list[str]
) -> list[str] | None:
    """Validate the block in a child process with the modules it loads importable, or
    None when none of them can be: neither saved on the page nor installed."""
    import subprocess

    marker_keys = block.marker.keys if block.marker else {}
    with tempfile.TemporaryDirectory(prefix="ash-docs-plugins-") as scratch:
        paths, on_page = _page_module_paths(page, Path(scratch), modules)
        if not on_page and not any(_module_exists(n.split(".")[0]) for n in modules):
            return None
        # The page's code runs here, so it gets a private HOME and none of the
        # caller's credentials or tokens: only what an import needs.
        home = Path(scratch) / "home"
        home.mkdir()
        environment = {
            name: os.environ[name]
            for name in ("PATH", "LANG", "LC_ALL", "SYSTEMROOT", "VIRTUAL_ENV")
            if name in os.environ
        }
        environment.update(
            {"HOME": str(home), "TMPDIR": str(home), "PYTHONDONTWRITEBYTECODE": "1"}
        )
        request = {
            "checks": str(Path(__file__).resolve()),
            "paths": paths,
            "text": block.body,
            "lang": block.lang,
            "kind": kind,
            "at": marker_keys.get("at"),
            "modules": modules,
        }
        try:
            completed = subprocess.run(
                [sys.executable, "-I", "-c", _CHILD_VALIDATOR],
                input=json.dumps(request),
                capture_output=True,
                text=True,
                cwd=scratch,
                env=environment,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return [f"importing {', '.join(modules)} to validate this block timed out"]
    result = next(
        (
            line[len(_CHILD_RESULT) :]
            for line in reversed(completed.stdout.splitlines())
            if line.startswith(_CHILD_RESULT)
        ),
        None,
    )
    if completed.returncode != 0 or result is None:
        tail = (completed.stderr.strip().splitlines() or ["no output"])[-1]
        return [
            (
                f"importing {', '.join(modules)} with the page's saved files to validate "
                f"this block failed: {tail}"
            )
        ]
    return json.loads(result)


#: Output models whose undeclared keys are not mistakes: SARIF's property bag is the
#: format's extension point, open by the specification, and ASH writes its own keys
#: there (scanner_name, scanner_details, ...).
OPEN_OUTPUT_MODELS = frozenset({"PropertyBag"})


def output_model(dotted: str) -> tuple[Any, str | None]:
    """The type ``model=<module>.<Class>[.<field>...]`` names: an output model class,
    or the annotation of one of its fields (``AshAggregatedResults.scanner_results``
    is a mapping of scanner names to ScannerTargetStatusInfo). Only ASH's own
    modules are imported."""
    if not (dotted == ASH_MODULE or dotted.startswith(ASH_MODULE + ".")):
        return None, (
            f"model={dotted} names no class in {ASH_MODULE}; name an output model, as "
            f"model={ASH_MODULE}.models.asharp_model.AshAggregatedResults"
        )
    parts = dotted.split(".")
    module, end = None, 0
    for end in range(len(parts), 0, -1):
        name = ".".join(parts[:end])
        if _module_exists(name):
            try:
                module = importlib.import_module(name)
            except Exception as exc:  # the import failing is the finding
                return None, f"model={dotted}: importing {name} raises {exc!r}"
            break
    if module is None:
        return None, f"model={dotted}: no module of {dotted} imports"
    current: Any = module
    label = ".".join(parts[:end])
    annotation: Any = None
    for part in parts[end:]:
        if annotation is None:
            current = getattr(current, part, None)
            if current is None:
                return None, f"model={dotted}: {label} has no {part}"
            label = f"{label}.{part}"
            if isinstance(current, type):
                if not hasattr(current, "model_fields"):
                    return None, f"model={dotted}: {label} is not a pydantic model"
                annotation = current
            continue
        model = _model_of(annotation)[1]
        if model is None:
            return (
                None,
                f"model={dotted}: {label} holds values, not a model with {part}",
            )
        field_name = _field_keys(model).get(part)
        if field_name is None:
            return None, f"model={dotted}: {model.__name__} has no field {part}"
        annotation = model.model_fields[field_name].annotation
        label = f"{label}.{part}"
    if annotation is None:
        return None, f"model={dotted}: {label} is not a pydantic model"
    return annotation, None


def _output_field_names(model: type) -> dict[str, str]:
    """Every key the model writes for a field, mapped to the field ("" when computed)."""
    names: dict[str, str] = {}
    for name, info in model.model_fields.items():
        names[name] = name
        for alias in (info.alias, info.serialization_alias):
            if isinstance(alias, str):
                names[alias] = name
    for name in getattr(model, "model_computed_fields", {}) or {}:
        names.setdefault(name, "")
    return names


def undeclared_output_keys(raw: Any, annotation: Any, where: str = "") -> list[str]:
    """Keys of a results excerpt that the output models do not declare.

    Compared explicitly because the status models use extra="allow": pydantic keeps
    a renamed key without a word, and the excerpt would teach a reader a key ASH
    never writes.
    """
    import types
    import typing

    choices = [
        arg
        for arg in typing.get_args(annotation)
        if arg is not type(None) and _model_of(arg)[1] is not None
    ]
    union = typing.get_origin(annotation) in (typing.Union, types.UnionType)
    if union and len(choices) > 1:
        # One of several models: the excerpt is read as the one it fits best.
        return min(
            (undeclared_output_keys(raw, choice, where) for choice in choices), key=len
        )
    kind, model = _model_of(annotation)
    if model is None:
        return []
    if getattr(model, "__pydantic_root_model__", False) and kind == "model":
        # A RootModel (SARIF's Message) holds its value in root, not under a key.
        return undeclared_output_keys(raw, model.model_fields["root"].annotation, where)
    problems: list[str] = []
    if kind == "model":
        if not isinstance(raw, dict) or model.__name__ in OPEN_OUTPUT_MODELS:
            return []
        names = _output_field_names(model)
        for key, value in raw.items():
            here = f"{where}.{key}" if where else str(key)
            field_name = names.get(key)
            if field_name is None:
                problems.append(
                    f"{here} is not a field of {model.__name__}; ASH does not write it"
                )
            elif field_name:
                problems += undeclared_output_keys(
                    value, model.model_fields[field_name].annotation, here
                )
    elif kind == "list" and isinstance(raw, list):
        for position, item in enumerate(raw):
            problems += undeclared_output_keys(item, model, f"{where}[{position}]")
    elif kind == "dict" and isinstance(raw, dict):
        for key, item in raw.items():
            problems += undeclared_output_keys(
                item, model, f"{where}.{key}" if where else str(key)
            )
    return problems


def ash_output_problems(document: Any, dotted: str) -> list[str]:
    """A results excerpt against the output model it is part of: it validates, and
    every key in it is one the model declares."""
    from pydantic import TypeAdapter, ValidationError

    annotation, problem = output_model(dotted)
    if problem:
        return [problem]
    problems: list[str] = []
    try:
        TypeAdapter(annotation).validate_python(document)
    except ValidationError as exc:
        problems += _validation_messages(exc)
    return problems + undeclared_output_keys(document, annotation)


def config_block_problems(
    block: Block, models: ConfigModels | None = None, page: Page | None = None
) -> list[str]:
    """What is wrong with one config block, by its kind.

    ``page`` is the page the block is on. An ASH config that loads a module from
    outside ASH is validated with that module imported, from the files the page
    saves or from the environment; without the page, or when the module cannot be
    found, only plugin names close to one ASH ships are checked under it.
    """
    kind = block.config_kind
    marker_keys = block.marker.keys if block.marker else {}
    if kind in ASH_CONFIG_KINDS:
        data, error = _block_ash_config(
            block.body, block.lang, kind, marker_keys.get("at")
        )
        if error:
            return [error] if kind != "ash-invalid" else []
        outside = outside_modules(data)
        problems = (
            _outside_module_problems(block, kind, page, outside)
            if outside and page is not None
            else None
        )
        if problems is None:
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
        document, error = parse_config_text(block.body, block.lang)
        if error:
            return [error]
        if kind == "gitlab-ci" and block.lang in ("yaml", "yml"):
            problem = _gitlab_block_reading_problem(block)
            if problem:
                return [problem]
        if kind == "github-actions" and block.lang in ("yaml", "yml"):
            problem = _saved_workflow_reading_problem(block)
            if problem:
                return [problem]
        model = marker_keys.get("model")
        if kind == "ash-output" and isinstance(model, str) and model:
            return ash_output_problems(document, model)
        return []
    return []


def check_config_blocks(
    files: Iterable[Path], root: Path = REPO_ROOT, notes: list[str] | None = None
) -> list[Finding]:
    """Config blocks parse, and those that are ASH configs validate with nothing ignored.

    ``notes``, when given, receives a line for each plugin module that did not
    import, whose plugins' keys the ASH config blocks were not checked against.
    """
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
            problems = config_block_problems(block, models, page)
            if not problems:
                problems = _fragment_merge_problems(page, block)
            for problem in problems:
                findings.append(
                    Finding("config", page.rel, block.fence_line, f"{label}: {problem}")
                )
    if notes is not None and models is not None:
        notes.extend(models.skipped_notes())
    return findings


def _fragment_merge_problems(page: Page, block: Block) -> list[str]:
    """A fragment (extends=) that parses must merge into the block it extends, as the
    runner merges it (ci_pipeline_text). A fragment the markers check refuses (no
    merge rule, nothing saved above it, a block of another kind) is left to that
    check, and so is a saved block with a problem of its own (it does not parse,
    GitLab reads one of its values otherwise, or the merge cannot carry one of its
    plain values), which is reported at its own fence."""
    marker = ci_marker(block)
    if marker is None or marker.extends is None or marker.kind not in CI_MERGE_KINDS:
        return []
    saved = extended_block(page, block)
    base = ci_marker(saved) if saved is not None else None
    if saved is None or base is None or base.kind != marker.kind:
        return []
    if config_block_problems(saved):
        return []
    try:
        ci_pipeline_text(page, block)
    except CiComposeError as exc:
        return [str(exc)]
    return []


# ---------------------------------------------------------------------------
# CI pipelines: fragments merged into the pipeline they extend, and which runner runs
# each block
# ---------------------------------------------------------------------------
#
# The merge rules, the YAML 1.1/1.2 reading comparisons, the hand-ported Psych
# scalar reading and the runner census live in scripts/_ci_pipelines.py, loaded
# by path the way the MCP contract reader is, so those reading semantics, with
# their pinned upstream references, review and revert apart from the page
# checks. The module receives this module's page model helpers and marker
# constants through bind(), and its names are re-exported below, so every
# existing caller keeps reading them from this module.

_ci_pipelines = _load_by_path(
    "_ash_ci_pipelines", Path(__file__).resolve().parent / "_ci_pipelines.py"
)
_ci_pipelines.bind(
    ci_marker=ci_marker,
    extended_block=extended_block,
    groovy_sh_scripts=groovy_sh_scripts,
    parse_config_text=parse_config_text,
    split_shell=split_shell,
    find_invocations=find_invocations,
    invocations_in_script=invocations_in_script,
    _dicts_with_key=_dicts_with_key,
    _calls_scan_workflow=_calls_scan_workflow,
    _strings_under_keys=_strings_under_keys,
    CI_MERGE_KINDS=CI_MERGE_KINDS,
    CI_RUNNERS=CI_RUNNERS,
    CI_RUNNER_NONE=CI_RUNNER_NONE,
    JENKINSFILE_KIND=JENKINSFILE_KIND,
    OTHER_CONFIG_KINDS=OTHER_CONFIG_KINDS,
    _SHELL_KEYWORDS=_SHELL_KEYWORDS,
)
CiComposeError = _ci_pipelines.CiComposeError
compose_ci_pipeline = _ci_pipelines.compose_ci_pipeline
ci_pipeline_text = _ci_pipelines.ci_pipeline_text
ci_runner_census = _ci_pipelines.ci_runner_census
CiCensusEntry = _ci_pipelines.CiCensusEntry
CiRunnerCensus = _ci_pipelines.CiRunnerCensus
_float_value = _ci_pipelines._float_value
_yaml11_reading = _ci_pipelines._yaml11_reading
_yaml12_reading = _ci_pipelines._yaml12_reading
_psych_reading = _ci_pipelines._psych_reading
_reading_text = _ci_pipelines._reading_text
_gitlab_reading_message = _ci_pipelines._gitlab_reading_message
_yaml_reading_problem = _ci_pipelines._yaml_reading_problem
_trigger_key_node = _ci_pipelines._trigger_key_node
_TRIGGER_KEY_TAG = _ci_pipelines._TRIGGER_KEY_TAG
_TriggerKey = _ci_pipelines._TriggerKey
_PlainStr = _ci_pipelines._PlainStr
_pipeline_loader = _ci_pipelines._pipeline_loader
_load_pipeline = _ci_pipelines._load_pipeline
_dump_pipeline = _ci_pipelines._dump_pipeline
_gitlab_block_reading_problem = _ci_pipelines._gitlab_block_reading_problem
_saved_workflow_reading_problem = _ci_pipelines._saved_workflow_reading_problem
_parse_workflow = _ci_pipelines._parse_workflow
_workflow_on = _ci_pipelines._workflow_on
_type_name = _ci_pipelines._type_name
_gitlab_include_merge = _ci_pipelines._gitlab_include_merge
_merge_github_steps = _ci_pipelines._merge_github_steps
_merge_github_workflow = _ci_pipelines._merge_github_workflow
_step_label = _ci_pipelines._step_label
_step_matches = _ci_pipelines._step_matches
_triggers = _ci_pipelines._triggers
_pipeline_scripts = _ci_pipelines._pipeline_scripts
_scans_changed_files = _ci_pipelines._scans_changed_files


# ---------------------------------------------------------------------------
# Check: MCP error types and example responses
# ---------------------------------------------------------------------------
#
# The MCP pages tell a client which error_type a refusal carries and show example
# responses. Both are statements about the dicts the tools return, and before this
# check the only statement of either was the prose: a renamed error_type literal or
# response key passed everything. scripts/_mcp_contract.py reads each tool's return
# statements from the server's source; this check holds the pages to what it reads.
#
# An error-type span is a code span the text around it names as one:
#
#     with `error_type` `config_field_denied`      `error_type: config_field_denied`
#     an error of type `denied_by_runtime_policy`  refused with `config_policy_unreadable`
#
# and, on the MCP pages, a heading that is one such name (the troubleshooting
# entries), and the first column of a table under a paragraph about `error_type`.
# A name found that way is then checked wherever else the MCP pages show it, so a
# renamed error is reported at every place a reader would meet it.

#: The phrases that put a value right after them: `error_type` `X`, `error_category` `X`.
_ERROR_FIELDS = {"error_type": "types", "error_category": "categories"}
_FIELD_GAP = re.compile(r"^\s+(?:is\s+(?:(?P<one_of>one\s+of)\s+)?)?$")
#: Between the names of a list: "`a`, `b` or `c`", and after "one of", "and" too. A
#: comma and "and" alone also join clauses ("`X`, and `set_source_git` ..."), so they
#: continue a list only after "one of".
_LIST_GAP = re.compile(r"^(?:,\s*(?:or\s+)?|\s+or\s+)$")
_ONE_OF_GAP = re.compile(r"^(?:,\s*(?:or\s+|and\s+)?|\s+or\s+|\s+and\s+)$")
_FIELD_SPAN = re.compile(
    r'^"?(error_type|error_category)"?\s*[:=]\s*"?([A-Za-z_][\w.]*)"?$'
)
_TYPE_LEAD = re.compile(r"\berrors?\s+of\s+type\s+$")
_REFUSAL_LEAD = re.compile(r"\b(?:refused|rejected|fails|failed)\s+with\s+$")
_ERROR_NAME = re.compile(
    r"^(?:[a-z][a-z0-9]*(?:_[a-z0-9]+)+|[A-Z]\w*(?:Error|Exception))$"
)
_ERROR_HEADING = re.compile(r"^#{1,6}\s+`([^`]+)`\s*$")
_JSON_ERROR_TYPE = re.compile(r'"error_type"\s*:\s*"([^"]+)"')


@dataclass
class McpContract:
    """What the MCP tools return, as the server's source says."""

    tools: dict[str, Any]
    #: error_type values, errors[].type values, and exception class names.
    types: set[str]
    #: ErrorCategory values, which error_category carries.
    categories: set[str]
    source: str
    #: scripts/_mcp_contract.py, loaded: it also reads the examples' keys.
    reader: Any


@functools.lru_cache(maxsize=None)
def load_mcp_contract(package_str: str) -> McpContract:
    """Read every tool's contract from the package at ``package_str``."""
    reader = _load_by_path(
        "_ash_mcp_contract", Path(__file__).resolve().parent / MCP_CONTRACT_READER
    )
    package = Path(package_str)
    tools = reader.tool_contracts(package)
    types: set[str] = set()
    class_names = False
    for contract in tools.values():
        types.update(contract.error_types, contract.entry_types)
        class_names |= contract.error_class_name or contract.entry_class_name
    if class_names:
        types |= reader.exception_class_names(package)
    return McpContract(
        tools=tools,
        types=types,
        categories=reader.enum_values(package, "ErrorCategory"),
        source=f"scripts/{MCP_CONTRACT_READER} over {package}",
        reader=reader,
    )


def is_mcp_page(rel: str) -> bool:
    return any(
        rel.startswith(entry) if entry.endswith("/") else rel == entry
        for entry in MCP_PAGES
    )


@dataclass(frozen=True)
class ErrorSpan:
    line: int
    value: str
    #: "types", "categories" or "either": which names the context allows.
    allows: str
    context: str


def _paragraphs(page: Page) -> list[tuple[str, list[tuple[int, int]]]]:
    """The prose as paragraphs: their text, and (offset, line) where each line starts.

    Table rows and headings are paragraphs of their own, so a context never reaches
    across a cell or out of a heading.
    """
    found: list[tuple[str, list[tuple[int, int]]]] = []
    text, starts, previous = "", [], -1

    def close() -> None:
        nonlocal text, starts
        if text.strip():
            found.append((text, starts))
        text, starts = "", []

    for number, line in page.prose:
        alone = line.lstrip().startswith(("|", "#"))
        if not line.strip() or number != previous + 1 or alone:
            close()
        if line.strip():
            starts.append((len(text), number))
            text += line + "\n"
        if alone:
            close()
        previous = number
    close()
    return found


def _line_at(starts: list[tuple[int, int]], offset: int) -> int:
    line = starts[0][1]
    for start, number in starts:
        if start > offset:
            break
        line = number
    return line


def error_type_spans(
    page: Page, mcp_page: bool, tool_names: Iterable[str] = ()
) -> list[ErrorSpan]:
    """Every code span on ``page`` that the text around it names as an error type.

    ``tool_names`` end a list of names: "`error_type` `X` or `run_ash_scan` ..." is
    one name and a tool.
    """
    tool_names = set(tool_names)
    found: list[ErrorSpan] = []
    for text, starts in _paragraphs(page):
        spans = list(_INLINE_CODE.finditer(text))
        heading = _ERROR_HEADING.match(text.strip())
        if mcp_page and heading and _ERROR_NAME.match(heading.group(1)):
            found.append(
                ErrorSpan(_line_at(starts, 0), heading.group(1), "either", "a heading")
            )
        index = 0
        while index < len(spans):
            span = spans[index]
            content = span.group(2).strip()
            field_value = _FIELD_SPAN.match(content)
            if field_value:
                found.append(
                    ErrorSpan(
                        _line_at(starts, span.start()),
                        field_value.group(2),
                        _ERROR_FIELDS[field_value.group(1)],
                        f"`{content}`",
                    )
                )
            elif content in _ERROR_FIELDS:
                allows = _ERROR_FIELDS[content]
                scan = index + 1
                list_gap = None
                while scan < len(spans):
                    gap = text[spans[scan - 1].end() : spans[scan].start()]
                    value = spans[scan].group(2).strip()
                    if list_gap is None:
                        opened = _FIELD_GAP.match(gap)
                        if not opened:
                            break
                        list_gap = _ONE_OF_GAP if opened.group("one_of") else _LIST_GAP
                    elif not (
                        list_gap.match(gap)
                        and _ERROR_NAME.match(value)
                        and value not in tool_names
                    ):
                        break
                    found.append(
                        ErrorSpan(
                            _line_at(starts, spans[scan].start()),
                            value,
                            allows,
                            f"after `{content}`",
                        )
                    )
                    scan += 1
                index = max(index + 1, scan)
                continue
            elif mcp_page:
                before = text[: span.start()]
                if _TYPE_LEAD.search(before):
                    found.append(
                        ErrorSpan(
                            _line_at(starts, span.start()), content, "types", "of type"
                        )
                    )
                elif _REFUSAL_LEAD.search(before) and _ERROR_NAME.match(content):
                    found.append(
                        ErrorSpan(
                            _line_at(starts, span.start()),
                            content,
                            "types",
                            "refused or failing with",
                        )
                    )
            index += 1
    if mcp_page:
        found += _error_table_spans(page)
        for block in page.blocks:
            for number, line in block.body_lines():
                for match in _JSON_ERROR_TYPE.finditer(line):
                    found.append(
                        ErrorSpan(
                            number, match.group(1), "types", '"error_type" in a block'
                        )
                    )
    return found


def _error_table_spans(page: Page) -> list[ErrorSpan]:
    """First-column names of a table under a paragraph that names `error_type`.

    A cell names its errors first: "`a`, or `b` from a results tool". A span after
    other words ("`scan_incomplete` with `output_holds_previous_results` true") is
    about the error, not another one.
    """
    found: list[ErrorSpan] = []
    prose = dict(page.prose)
    for table in page.tables:
        number = table.header_line - 1
        while number in prose and not prose[number].strip():
            number -= 1
        above: list[str] = []
        while number in prose and prose[number].strip():
            above.append(prose[number])
            number -= 1
        if "`error_type`" not in " ".join(above):
            continue
        for row_number, cells in table.rows:
            cell = cells[0] if cells else ""
            spans = list(_INLINE_CODE.finditer(cell))
            if not spans or cell[: spans[0].start()].strip():
                continue
            for position, span in enumerate(spans):
                gap = cell[spans[position - 1].end() : span.start()] if position else ""
                if position and not _LIST_GAP.match(gap):
                    break
                content = span.group(2).strip()
                if _ERROR_NAME.match(content):
                    found.append(
                        ErrorSpan(row_number, content, "either", "an error table")
                    )
    return found


def _error_type_problem(span: ErrorSpan, contract: McpContract) -> str | None:
    allowed = {
        "types": contract.types,
        "categories": contract.categories,
        "either": contract.types | contract.categories,
    }[span.allows]
    if span.value in allowed:
        return None
    what = {
        "types": "no MCP tool returns it as an error_type (or an errors entry's type)",
        "categories": "no ErrorCategory has that value",
        "either": "no MCP tool returns it as an error_type, and no ErrorCategory has "
        "that value",
    }[span.allows]
    close = difflib.get_close_matches(span.value, sorted(allowed), n=1, cutoff=0.6)
    hint = f"; did you mean `{close[0]}`?" if close else ""
    return (
        f"`{span.value}` is named as an error ({span.context}), but {what}{hint} "
        f"(read by {contract.source})"
    )


def mcp_response_problems(block: Block, contract: McpContract) -> list[str]:
    """What is wrong with one ``config kind=mcp-response`` example."""
    reader = contract.reader
    of = str(block.marker.keys.get("of", "")) if block.marker else ""
    tool = of.split(".", 1)[1] if of.startswith("mcp.") else ""
    if tool not in contract.tools:
        close = difflib.get_close_matches(tool, sorted(contract.tools), n=1)
        hint = f"; did you mean mcp.{close[0]}?" if close else ""
        return [f"of={of} names no MCP tool{hint}"]
    keys = reader.example_keys(block.body)
    if not keys:
        return ["the example has no keys, so there is nothing to compare with the tool"]
    response = contract.tools[tool].response
    missing = reader.missing_keys(keys, response)
    if not missing:
        return []
    named = ", ".join(f"`{k}`" for k in missing)
    built = ", ".join(f"`{k}`" for k in response.keys())
    return [
        (
            f"no response {tool} returns has {named}; the keys its returns build "
            f"are {built} (read by {contract.source})"
        )
    ]


#: Response alternatives the reader cannot follow, and open dicts without an
#: error_type key, that are known to carry no error_type: (tool, the site's
#: file, the function enclosing the site, a fragment of the site's source
#: line, the entry's stale-after date, the reason). Either shape could
#: otherwise carry an error_type the pages miss, so any site not named here is
#: a finding. The function rather than the line, because sites move with every
#: commit of the package being read; the function rather than the file alone,
#: so new code in the same file is never explained by a stale reason; and the
#: line fragment, matched against the stripped source line at the site, so a
#: NEW site inside an already-explained function (a refusal path added to a
#: tool body) is never silently covered: the fragment survives the line
#: moving, not its content changing. An entry that explains no site in the
#: package being read is named in the check's notes until its stale-after
#: date, because the trees this check runs against do not all hold the same
#: helpers until the stack converges; past that date an unused entry is a
#: finding, so retired code cannot leave a standing exemption behind.
UNREAD_RESPONSE_EXPLAINED = (
    # get_config's unread values are all the config dump: the file's own data,
    # with get_config's refusals as separate dict literals the reader follows.
    (
        "get_config",
        "automated_security_helper/config/environment_record.py",
        "record_environment_references",
        "def record_environment_references(",
        "2026-12-31",
        (
            "returns the config dump it was given, reshaped so values read from"
            " the environment show as the file wrote them."
        ),
    ),
    (
        "get_config",
        "automated_security_helper/config/environment_record.py",
        "_Index.record",
        "def record(",
        "2026-12-31",
        "the recorder's per-node walk over the same dump.",
    ),
    (
        "get_config",
        "automated_security_helper/config/environment_record.py",
        "_Index.record",
        "result[key] = recorded",
        "2026-12-31",
        "the recorder's per-node walk over the same dump.",
    ),
    (
        "get_config",
        "automated_security_helper/config/environment_record.py",
        "_Index.record",
        "return type(item)(",
        "2026-12-31",
        "the recorder's per-node walk over the same dump.",
    ),
    (
        "get_config",
        "automated_security_helper/config/environment_record.py",
        "_recorded_string",
        "def _recorded_string(",
        "2026-12-31",
        "a string-shaping helper of the same dump.",
    ),
    (
        "get_config",
        "automated_security_helper/config/environment_record.py",
        "_recorded_string",
        "return prefix + _without_tag(reference.written)",
        "2026-12-31",
        "a string-shaping helper of the same dump.",
    ),
    (
        "get_config",
        "automated_security_helper/config/environment_record.py",
        "_recorded_string",
        "return reference.written",
        "2026-12-31",
        "a string-shaping helper of the same dump.",
    ),
    (
        "get_config",
        "automated_security_helper/config/environment_record.py",
        "_recorded_string",
        "text = text.replace(reference.value, _bare(reference.written))",
        "2026-12-31",
        "a string-shaping helper of the same dump.",
    ),
    (
        "get_config",
        "automated_security_helper/config/environment_record.py",
        "_Index._string",
        "def _string(",
        "2026-12-31",
        "a string-shaping helper of the same dump.",
    ),
    (
        "get_config",
        "automated_security_helper/config/environment_record.py",
        "_Index._string",
        # The statement spans three lines; the reader records its first.
        "text = text.replace(",
        "2026-12-31",
        "a string-shaping helper of the same dump.",
    ),
    (
        "get_config",
        "automated_security_helper/config/environment_record.py",
        "_Index._whole",
        "return reference.written if self.mark is None else self.mark(",
        "2026-12-31",
        "a string-shaping helper of the same dump.",
    ),
    (
        "get_config",
        "automated_security_helper/cli/mcp_tools.py",
        "_config_as_written",
        'return _json.loads(contents().decode("utf-8-sig"))',
        "2026-12-31",
        "the same dump as the file wrote it.",
    ),
    (
        "get_config",
        "automated_security_helper/cli/mcp_tools.py",
        "_config_as_written",
        "document = loader.get_single_data()",
        "2026-12-31",
        "the same dump as the file wrote it.",
    ),
    (
        "get_config",
        "automated_security_helper/cli/mcp_tools.py",
        "_mark_toml_references",
        "def _mark_toml_references(",
        "2026-12-31",
        "the same dump with TOML references marked.",
    ),
    (
        "get_config",
        "automated_security_helper/cli/mcp_tools.py",
        "_mark_toml_references",
        "return ENV_VALUE_PREFIX + value",
        "2026-12-31",
        "the same dump with TOML references marked.",
    ),
    (
        "get_config",
        "automated_security_helper/cli/mcp_tools.py",
        "_mark_toml_references",
        "return {k: _mark_toml_references(v) for k, v in value.items()}",
        "2026-12-31",
        "the same dump with TOML references marked.",
    ),
    # The scan views return the loaded results file reshaped; each tool's
    # refusals are separate dict literals the reader follows.
    (
        "get_scan_results",
        "automated_security_helper/cli/mcp_server.py",
        "get_scan_results",
        "results = _add_findings_list(results)",
        "2026-12-31",
        "the tool's body returns the loaded results file reshaped.",
    ),
    (
        "get_scan_results",
        "automated_security_helper/core/resource_management/result_filters.py",
        "filter_actionable_only",
        "filtered_results = copy.deepcopy(results)",
        "2026-12-31",
        "the content filters return the loaded results file reshaped.",
    ),
    (
        "get_scan_results",
        "automated_security_helper/core/resource_management/result_filters.py",
        "apply_content_filters",
        "filtered_results = copy.deepcopy(results)",
        "2026-12-31",
        "the content filters return the loaded results file reshaped.",
    ),
    (
        "get_scan_summary",
        "automated_security_helper/core/resource_management/result_filters.py",
        "filter_actionable_only",
        "filtered_results = copy.deepcopy(results)",
        "2026-12-31",
        "the content filters return the loaded results file reshaped.",
    ),
    (
        "get_scan_summary",
        "automated_security_helper/core/resource_management/result_filters.py",
        "apply_content_filters",
        "filtered_results = copy.deepcopy(results)",
        "2026-12-31",
        "the content filters return the loaded results file reshaped.",
    ),
    (
        "get_scan_summary",
        "automated_security_helper/cli/mcp_server.py",
        "get_scan_results",
        "results = _add_findings_list(results)",
        "2026-12-31",
        "the summary view is built from the reshaped results.",
    ),
    # The coverage keys (_COVERAGE_KEYS: coverage_complete and the gap lists)
    # are copied from the loaded results document onto the filtered view by a
    # comprehension keyed by the loop's name, which the reader cannot read;
    # none of those names is an error_type.
    (
        "get_scan_results",
        "automated_security_helper/core/resource_management/result_filters.py",
        "_coverage_fields",
        "return {key: results[key] for key in _COVERAGE_KEYS if key in results}",
        "2026-12-31",
        "the coverage keys copied from the loaded results file onto the view.",
    ),
    (
        "get_scan_summary",
        "automated_security_helper/core/resource_management/result_filters.py",
        "_coverage_fields",
        "return {key: results[key] for key in _COVERAGE_KEYS if key in results}",
        "2026-12-31",
        "the coverage keys copied from the loaded results file onto the view.",
    ),
    (
        "get_scan_progress",
        "automated_security_helper/core/resource_management/scan_registry.py",
        "ScanRegistry.check_scan_progress",
        "coverage = entry.coverage",
        "2026-12-31",
        (
            "the progress record's keys come from the registry entry, whose"
            " failure field is error_message; the tool's refusals are separate"
            " dict literals the reader follows."
        ),
    ),
)


def _site_file_line(site: str) -> tuple[str, int]:
    """The ``rel:line`` prefix of an unread site, which may carry a trailing
    note (``... parameter name``)."""
    head = site.split(" ", 1)[0]
    rel, _, line = head.rpartition(":")
    return rel, int(line) if line.isdigit() else 0


def _function_at(package_root: Path, rel: str, line: int, cache: dict) -> str:
    """The innermost function enclosing ``rel:line``, as a dotted qualified
    name (``Class.method``, ``outer.inner``), so a same-named method of a new
    class or a helper nested elsewhere never matches a top-level entry."""
    if rel not in cache:
        spans: list[tuple[int, int, str]] = []
        try:
            tree = ast.parse((package_root / rel).read_text(encoding="utf-8"))
        except (OSError, SyntaxError, ValueError):
            tree = None

        def visit(node: ast.AST, path: tuple[str, ...]) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(
                    child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    inner = path + (child.name,)
                    if not isinstance(child, ast.ClassDef):
                        spans.append(
                            (
                                child.lineno,
                                getattr(child, "end_lineno", child.lineno),
                                ".".join(inner),
                            )
                        )
                    visit(child, inner)
                else:
                    visit(child, path)

        if tree is not None:
            visit(tree, ())
        cache[rel] = spans
    best = ""
    for start, end, name in cache[rel]:
        if start <= line <= end and (not best or len(name) > len(best)):
            best = name  # the longest qualified name is the innermost
    return best or "<module>"


def check_mcp_contract(
    files: Iterable[Path],
    root: Path = REPO_ROOT,
    notes: list[str] | None = None,
    package: Path | None = None,
) -> list[Finding]:
    """Error-type names and example responses in the docs match what the MCP tools return.

    ``package`` is the source read for the contract, by default the package this
    interpreter imports. ``notes``, when given, receives what was compared.
    """
    try:
        contract = load_mcp_contract(str(package or installed_package_dir()))
    except Exception as exc:  # the server's source not reading is the finding
        return [
            Finding(
                "mcp-error-type",
                "",
                0,
                f"the MCP tools' returns cannot be read ({exc!r})",
            )
        ]
    findings: list[Finding] = []
    # A tool whose whole response alternative the reader cannot follow lists no
    # error types there, which is not the same as having none: the response
    # could be a dict carrying one. So could an open dict with no error_type
    # key. Each such site is a finding, unless UNREAD_RESPONSE_EXPLAINED names
    # the tool, the file, the enclosing function and a fragment of the site's
    # source line; the generator is not stopped, and entries that explained
    # nothing are named in the notes until their stale-after date, findings
    # past it.
    package_root = Path(str(package or installed_package_dir())).parent
    function_cache: dict[str, list[tuple[int, int, str]]] = {}
    line_cache: dict[str, list[str]] = {}
    used_explanations: set[int] = set()

    def site_line_text(rel: str, line: int) -> str:
        if rel not in line_cache:
            try:
                text = (package_root / rel).read_text(encoding="utf-8")
            except (OSError, ValueError):
                text = ""
            line_cache[rel] = text.splitlines()
        rows = line_cache[rel]
        return rows[line - 1].strip() if 0 < line <= len(rows) else ""

    def explained(tool_name: str, site: str) -> bool:
        rel, line = _site_file_line(site)
        function = _function_at(package_root, rel, line, function_cache)
        text = site_line_text(rel, line)
        hit = False
        for index, (tool, file, func, fragment, _stale, _) in enumerate(
            UNREAD_RESPONSE_EXPLAINED
        ):
            if (
                tool == tool_name
                and file == rel
                and func == function
                and fragment in text
            ):
                used_explanations.add(index)
                hit = True
        return hit

    for name in sorted(contract.tools):
        for site in contract.tools[name].response_unread:
            if explained(name, site):
                continue
            findings.append(
                Finding(
                    "mcp-response",
                    "",
                    0,
                    (
                        f"{name} has a response at {site} the reader cannot read, "
                        "and UNREAD_RESPONSE_EXPLAINED does not explain it: it "
                        "could be a dict carrying an error_type the pages miss "
                        f"(read by {contract.source})"
                    ),
                )
            )
        open_reported: set[str] = set()
        for variant in contract.tools[name].response.variants:
            if not isinstance(variant, contract.reader.DictV) or not variant.open_at:
                continue
            if any(key == "error_type" for key, _ in variant.keys):
                continue
            for site in variant.open_at:
                if site in open_reported or explained(name, site):
                    continue
                open_reported.add(site)
                findings.append(
                    Finding(
                        "mcp-response",
                        "",
                        0,
                        (
                            f"{name} has a response whose keys cannot all be read "
                            f"at {site}, with no error_type key, and "
                            "UNREAD_RESPONSE_EXPLAINED does not explain it "
                            f"(read by {contract.source})"
                        ),
                    )
                )
    import datetime

    today = datetime.datetime.now(datetime.timezone.utc).date()
    fresh_unused: list[str] = []
    for index, (tool, file, func, fragment, stale_after, _) in enumerate(
        UNREAD_RESPONSE_EXPLAINED
    ):
        if index in used_explanations:
            continue
        label = f"{tool} {file} {func} ({fragment!r})"
        if datetime.date.fromisoformat(stale_after) < today:
            # The code the entry explained is gone or has changed; a standing
            # exemption for it must not outlive the convergence window.
            findings.append(
                Finding(
                    "mcp-response",
                    "",
                    0,
                    (
                        f"UNREAD_RESPONSE_EXPLAINED entry {label} explained no "
                        f"site and is past its stale-after date {stale_after}; "
                        f"remove it, or re-pin it to the current source "
                        f"(read by {contract.source})"
                    ),
                )
            )
        else:
            fresh_unused.append(label)
    if notes is not None and fresh_unused:
        notes.append(
            "UNREAD_RESPONSE_EXPLAINED entries that explained nothing "
            f"({contract.source}): " + "; ".join(fresh_unused)
        )
    spans_checked = 0
    examples_checked = 0
    pages = load_pages(files, root)
    bad: dict[str, str] = {}
    seen: set[tuple[str, int, str]] = set()
    for page in pages:
        if page.rel in HISTORICAL_DOCS:
            continue
        for span in error_type_spans(page, is_mcp_page(page.rel), contract.tools):
            spans_checked += 1
            seen.add((page.rel, span.line, span.value))
            problem = _error_type_problem(span, contract)
            if problem:
                bad.setdefault(span.value, f"{page.rel}:{span.line}")
                findings.append(Finding("mcp-error-type", page.rel, span.line, problem))
        for block in page.blocks:
            if block.config_kind != MCP_RESPONSE_KIND or block.mode != "config":
                continue
            examples_checked += 1
            for problem in mcp_response_problems(block, contract):
                findings.append(
                    Finding("mcp-response", page.rel, block.fence_line, problem)
                )
    # A name the docs call an error somewhere is one wherever the MCP pages show it.
    for page in pages:
        if not bad or not is_mcp_page(page.rel):
            continue
        for number, line in page.prose:
            for content in inline_code_spans(line):
                if content in bad and (page.rel, number, content) not in seen:
                    spans_checked += 1
                    findings.append(
                        Finding(
                            "mcp-error-type",
                            page.rel,
                            number,
                            f"`{content}` is named as an error at {bad[content]}, and "
                            "no MCP tool returns it",
                        )
                    )
    if not spans_checked:
        findings.append(
            Finding(
                "mcp-error-type",
                "",
                0,
                "found no error-type names in the docs; the MCP pages moved or the "
                "phrasing this check reads changed, so it cannot report success",
            )
        )
    if not examples_checked:
        findings.append(
            Finding(
                "mcp-response",
                "",
                0,
                f"found no config kind={MCP_RESPONSE_KIND} examples; the MCP tools "
                "reference lost its markers, so this check cannot report success",
            )
        )
    if notes is not None:
        notes.append(
            f"compared {spans_checked} error-type names and {examples_checked} example "
            f"responses with {len(contract.tools)} MCP tools ({contract.source})"
        )
    return sorted(findings, key=lambda f: (f.path, f.line, f.message))


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
#: Default-cell phrases, used on the generated reference pages, that state no comparable value.
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
    #: Whether a table marked complete must have a row for the key. --help, and the
    #: options ASH reads from every scanner, belong to no one section.
    listed: bool = True
    #: The phrases of DEFAULT_PHRASES_NOT_COMPARED that are true of this key's
    #: default, and so may stand for it in a Default cell.
    phrases: frozenset[str] = frozenset()
    #: For a key that is a plugin's name under scanners, reporters or converters: the
    #: plugin's config class, whose enabled default an enabled column states.
    plugin: type | None = None


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


#: Attribute chains that read the platform, as the configuration generator's
#: _PLATFORM_READS: a default naming one depends on where ASH runs.
_PLATFORM_READS = frozenset(
    {"platform.system", "platform.machine", "sys.platform", "os.name"}
)


@functools.lru_cache(maxsize=None)
def _platform_default_fields(model: type) -> frozenset[str]:
    """Fields whose default expression, in the class source, reads the platform."""
    import inspect
    import textwrap

    found: set[str] = set()
    for klass in model.__mro__:
        if klass is object or "model_fields" not in dir(klass):
            continue
        try:
            tree = ast.parse(textwrap.dedent(inspect.getsource(klass)))
        except (OSError, TypeError, SyntaxError):
            continue
        for statement in getattr(tree.body[0], "body", []):
            if (
                isinstance(statement, ast.AnnAssign)
                and isinstance(statement.target, ast.Name)
                and statement.value is not None
                and any(
                    isinstance(node, ast.Attribute)
                    and ast.unparse(node) in _PLATFORM_READS
                    for node in ast.walk(statement.value)
                )
            ):
                found.add(statement.target.id)
    return frozenset(found)


def _computed_by_code(model: type, field_name: str, info: Any) -> bool:
    """Whether the field's default is computed when ASH runs: by a default factory
    (a function, not a type such as list), or by a validator that runs on it."""
    factory = info.default_factory
    if factory is not None and not isinstance(factory, type):
        return True
    decorators = getattr(model, "__pydantic_decorators__", None)
    validate_default = info.validate_default or model.model_config.get(
        "validate_default"
    )
    if decorators is None or not validate_default:
        return False
    return any(
        field_name in decorator.info.fields or "*" in decorator.info.fields
        for decorator in decorators.field_validators.values()
    )


def _is_plugin_config(model: type) -> bool:
    return any(base.__name__ == "PluginConfigBase" for base in model.__mro__)


def _model_keys(model: type) -> dict[str, KeySpec]:
    keys: dict[str, KeySpec] = {}
    spellings = _field_keys(model)
    platform_fields = _platform_default_fields(model)
    for field_name, info in model.model_fields.items():
        names = tuple(sorted({k for k, v in spellings.items() if v == field_name}))
        phrases: set[str] = set()
        if field_name in platform_fields:
            phrases.add("depends on the platform")
        if _computed_by_code(model, field_name, info):
            phrases.add("computed at run time")
        if _is_plugin_config(model) and field_name == "name":
            phrases.add("the plugin's own name")
        if _is_plugin_config(model) and field_name == "options":
            phrases.add("the plugin's defaults")
        if info.is_required():
            spec = KeySpec(names, required=True, compare=True)
        else:
            try:
                spec = KeySpec(
                    names,
                    default=_normalize(info.get_default(call_default_factory=True)),
                )
            except Exception:  # a factory that needs the other fields
                spec = KeySpec(names, default=COMPUTED, compare=False)
                phrases.add("computed at run time")
        spec.phrases = frozenset(phrases)
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
    if of == "terraform" or of.startswith("terraform:"):
        return terraform_section(of, code)
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
            keys.setdefault(key, KeySpec((key,), compare=False, listed=False))
    segment = next((n for n, seg in models.segments.items() if seg is model), None)
    if segment is not None:
        # The section's keys are plugin names: the ones it declares, and every plugin
        # ASH ships for it, community modules included, which it accepts as extras.
        for name, config_cls in models.plugin_configs.get(segment, {}).items():
            spec = keys.get(name)
            if spec is None:
                spec = keys[name] = KeySpec((name,), default=SECTION)
            spec.plugin = config_cls
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
        if (
            getattr(param, "is_flag", False)
            and default is None
            and not param.expose_value
        ):
            # An action flag (typer's --install-completion): its value never reaches
            # the command, so not passing it is off. A three-way flag is exposed, and
            # there None means "not set".
            default = False
        compare = not callable(default)
        spec = KeySpec(
            names,
            required=bool(param.required),
            default=_normalize(default) if compare else COMPUTED,
            compare=compare,
            listed=not getattr(param, "hidden", False),
            phrases=frozenset() if compare else frozenset({"computed at run time"}),
        )
        for name in names:
            keys[name] = spec
    keys["--help"] = KeySpec(("--help",), compare=False, listed=False)
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
    except Exception as exc:  # the server not loading is the finding
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

    def load_template(text: str) -> Any:
        # What yaml.load(text, Loader=_TagTolerantLoader) does, written out.
        loader = _TagTolerantLoader(text)
        try:
            return loader.get_single_data()
        finally:
            loader.dispose()

    pooled: dict[str, list[Any]] = {}
    templates = 0
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
            data = json.loads(text) if path.suffix == ".json" else load_template(text)
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
    is the string true, as an action's default 'true' is. A workflow's triggers are
    read from its on: key alone (_workflow_on), as GitHub reads them.
    """
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
    data, error = _parse_workflow(target.read_text(encoding="utf-8"))
    if error is not None:
        return None, f"of={of}: {rel} {error}"
    data = data or {}
    if not isinstance(data, dict):
        return None, f"of={of}: {rel} is not an action or a workflow"
    groups: list[dict[str, Any]] = []
    if isinstance(data.get("inputs"), dict) and "runs" in data:
        groups.append(data["inputs"])
        kind = "action"
    else:
        triggers = _workflow_on(data)
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


_TF_VARIABLE = re.compile(r'^\s*variable\s+"([^"]+)"\s*\{(?P<rest>.*)$')
_TF_DEFAULT = re.compile(r"^\s*default\s*=\s*(.*?)\s*$")
_TF_HEREDOC = re.compile(r"<<-?\s*([A-Za-z_]\w*)\s*$")


def _hcl_code(line: str) -> str:
    """A line of HCL without its trailing # or // comment (outside strings)."""
    index, in_string = 0, False
    while index < len(line):
        char = line[index]
        if in_string:
            if char == "\\":
                index += 2
                continue
            if char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "#" or line.startswith("//", index):
            return line[:index].rstrip()
        index += 1
    return line


def _hcl_brace_delta(line: str) -> tuple[int, int]:
    """(braces opened minus closed, brackets opened minus closed) in a line of HCL,
    outside strings and comments."""
    braces = brackets = 0
    index, in_string = 0, False
    code = _hcl_code(line)
    while index < len(code):
        char = code[index]
        if in_string:
            if char == "\\":
                index += 2
                continue
            if char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        else:
            braces += {"{": 1, "}": -1}.get(char, 0)
            brackets += {"[": 1, "]": -1}.get(char, 0)
        index += 1
    return braces, brackets


def _hcl_literal(expression: str) -> Any:
    """The value of a literal HCL default (a string, number, bool, null, or a list or
    map of them), or COMPUTED when it is not one JSON can read."""
    text = re.sub(r",(\s*[\]}])", r"\1", expression.strip())
    try:
        return json.loads(text)
    except ValueError:
        return COMPUTED


def terraform_variables(text: str) -> list[tuple[str, Any]]:
    """(name, default) of every ``variable`` block in a Terraform file; the default is
    REQUIRED when the block sets none, and COMPUTED when it is not a literal (a
    heredoc, or an expression JSON cannot read)."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    lines = text.split("\n")
    found: list[tuple[str, Any]] = []
    index = 0
    while index < len(lines):
        opened = _TF_VARIABLE.match(lines[index])
        index += 1
        if not opened:
            continue
        rest = _hcl_code(opened.group("rest"))
        depth, default = 1 + _hcl_brace_delta(rest)[0], REQUIRED
        if depth <= 0:
            # variable "x" { default = 1 }: the whole block on one line.
            inline = re.match(r"^\s*default\s*=\s*(.*?)\s*\}\s*$", rest)
            found.append(
                (opened.group(1), _hcl_literal(inline.group(1)) if inline else REQUIRED)
            )
            continue
        while index < len(lines) and depth > 0:
            line = lines[index]
            index += 1
            heredoc = _TF_HEREDOC.search(_hcl_code(line))
            assignment = _TF_DEFAULT.match(_hcl_code(line)) if depth == 1 else None
            if heredoc:
                while index < len(lines) and lines[index].strip() != heredoc.group(1):
                    index += 1
                index += 1
                if assignment:
                    default = COMPUTED
                depth += _hcl_brace_delta(line[: heredoc.start()])[0]
                continue
            if assignment:
                expression = assignment.group(1)
                braces, brackets = _hcl_brace_delta(expression)
                while (braces or brackets) and index < len(lines):
                    expression += "\n" + _hcl_code(lines[index])
                    more = _hcl_brace_delta(lines[index])
                    braces, brackets = braces + more[0], brackets + more[1]
                    index += 1
                default = _hcl_literal(expression)
                continue
            depth += _hcl_brace_delta(line)[0]
        found.append((opened.group(1), default))
    return found


def terraform_section(of: str, code: Path) -> tuple[Section | None, str | None]:
    """The input variables of a Terraform module: every ``variable`` block in the
    ``*.tf`` files of one directory, with the literal default each sets. A variable
    without a default is required; one whose default is not a literal is listed
    without a default to compare."""
    rel = of.partition(":")[2].strip()
    problem = save_as_problem(rel) if rel else "a path is missing"
    if problem:
        return None, (
            f"of={of}: name a Terraform module directory in the code tree, as "
            f"of=terraform:deploy/terraform/modules/<module> ({problem})"
        )
    target = code / rel
    if not target.is_dir():
        return None, f"of={of}: {rel} is not a directory of the code tree"
    keys: dict[str, KeySpec] = {}
    for path in sorted(target.glob("*.tf")):
        for name, default in terraform_variables(path.read_text(encoding="utf-8")):
            if default is REQUIRED:
                keys[name] = KeySpec((name,), required=True)
            elif default is COMPUTED:
                keys[name] = KeySpec((name,), compare=False)
            else:
                keys[name] = KeySpec((name,), default=default)
    if not keys:
        return None, f"of={of}: {rel} holds no Terraform variable blocks"
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


def default_problem(cell: str, spec: KeySpec, what: str = "the default") -> str | None:
    """Why a Default cell does not state the model's default, or None.

    A phrase of DEFAULT_PHRASES_NOT_COMPARED passes only where it is true of the
    key (KeySpec.phrases): "computed at run time" for a default the code computes,
    "depends on the platform" for one that reads the platform, and the plugin
    phrases for a plugin's own name and options. ``what`` names the default in
    the message ("its enabled default" for an enabled column).
    """
    text = re.sub(r"<[^>]+>", "", cell).strip()
    # A phrase may be set in emphasis (*required*); a value belongs in a code span.
    lowered = re.sub(r"^([*_]+)(.+?)\1$", r"\2", text).strip().lower()
    if lowered in DEFAULT_PHRASES_NOT_COMPARED and lowered in spec.phrases:
        return None
    if not spec.compare:
        return None

    def shown() -> str:
        return _shown(spec.default, spec.syntax)

    if lowered in DEFAULT_PHRASES_NOT_COMPARED:
        if spec.required:
            return f"says {text}, but the key is required"
        return f"says {text}, but {what} is {shown()}"

    if lowered == "required":
        return None if spec.required else f"says required, but {what} is {shown()}"
    if spec.required:
        return f"says {text or 'nothing'}, but the key is required"
    if lowered == "see the section":
        return (
            None
            if spec.default is SECTION
            else f"says see the section, but {what} is {shown()}"
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
            else f"says {text}, but {what} is {shown()}"
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
        return f"says {text}, but {what} is {shown()}"
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


#: Headers of a column that says whether each plugin a row names is on by default,
#: compared with the plugin config's enabled default.
ENABLED_HEADERS = frozenset({"enabled by default", "on by default"})


def _header_cells(table: Table) -> list[str]:
    return [re.sub(r"[`*_]", "", cell).strip().lower() for cell in table.header]


def _states_defaults(header: str) -> bool:
    """Whether a column header says the column holds defaults ("Default when unset")."""
    return bool(re.search(r"\bdefaults?\b", header))


def _is_env_table(table: Table) -> bool:
    """A table of environment variables: headed Variable or the like, most of its rows
    naming an upper-case one (http_proxy is a variable too; a Terraform module's
    variables, all lower case, are headed Variable as well and are not)."""
    cells = _header_cells(table)
    if not cells or cells[0] not in _ENV_TABLE_HEADERS:
        return False
    named = [row[0] for _number, row in table.rows if row and row[0]]
    upper = [cell for cell in named if _UPPER_NAME.search(cell)]
    return bool(named) and 2 * len(upper) > len(named)


def _is_options_table(table: Table, keys: frozenset[str] = frozenset()) -> bool:
    """Whether a table documents options or keys, and so needs a marker naming them.

    It is headed like one (Option, Key, Parameter, ...) or has a column that states
    defaults, and most of its rows name a key (_names_a_key) of something a marker
    can name: ``keys`` is documented_key_names. A table of other things, a list of
    defenses on or off or of machines and their memory, holds nothing a section has,
    so it needs no marker. A table of environment variables is checked as one
    (check_env_vars) instead.
    """
    if not table.header or _is_env_table(table):
        return False
    cells = _header_cells(table)
    if cells[0] not in OPTION_TABLE_HEADERS and not any(
        _states_defaults(cell) for cell in cells
    ):
        return False
    named = [_row_key(row[0]) for _number, row in table.rows if row and row[0].strip()]
    return bool(named) and 2 * sum(_names_a_key(k, keys) for k in named) > len(named)


def _names_a_key(name: str, keys: frozenset[str]) -> bool:
    """Whether a row's name is one of ``keys``, close to one (a misspelled key is still
    a row of keys, which the marked table then reports), or a dotted path of them."""
    if not name or re.search(r"\s", name):
        return False
    if name in keys:
        return True
    parts = [p for p in re.split(r"\.", re.sub(r"\[\d*\]", "", name)) if p]
    if len(parts) > 1:
        return all(
            p in keys or p == "*" or re.fullmatch(r"<[^<>]+>|\{[^{}]+\}", p)
            for p in parts
        )
    return bool(difflib.get_close_matches(name, keys, n=1, cutoff=0.8))


def documented_key_names(models: ConfigModels, code: Path) -> frozenset[str]:
    """Every key a row of an options table may name: the keys of each kind of section
    an options marker can name (options_section), across the code tree.

    The ASH config model (every field at every depth, the plugins under scanners,
    reporters and converters, and their options), every ash command's options and
    arguments, every MCP tool's parameters, and in the code tree: the parameters of its
    Python functions, its Terraform variables, the inputs of its actions and
    reusable workflows, the Dockerfile's ARGs, its CloudFormation templates'
    parameters and its TypeScript interfaces' properties.
    """
    names = set(_config_model_names(models)) | _cli_names() | _mcp_names()
    tracked = _tracked_paths(code)
    for rel in sorted(tracked):
        path = code / rel
        name = path.name
        if rel.endswith(".py"):
            names |= _python_parameter_names(path)
        elif rel.endswith(".tf"):
            try:
                names |= {v for v, _ in terraform_variables(path.read_text("utf-8"))}
            except (OSError, UnicodeDecodeError):
                continue
        elif name in ("action.yml", "action.yaml") or (
            rel.startswith(".github/workflows/") and name.endswith((".yml", ".yaml"))
        ):
            names |= _section_names(github_inputs_section(f"github-inputs:{rel}", code))
        elif rel.endswith(".ts") and not _TS_SKIP_DIRS.intersection(rel.split("/")):
            names |= _typescript_names(path, rel, code)
        if path.suffix in (".json", ".yaml", ".yml", ".template") and _is_template(
            path
        ):
            names |= _section_names(
                cloudformation_section(f"cloudformation:{rel}", code)
            )
    names |= _section_names(dockerfile_section(code))
    return frozenset(n for n in names if n)


def _section_names(found: tuple[Section | None, str | None]) -> set[str]:
    section, _problem = found
    return set(section.keys) if section is not None else set()


def _config_model_names(models: ConfigModels) -> frozenset[str]:
    """Every key of the ASH config model: each field's spellings at every depth, the
    plugins of each plugin section, and every plugin config's fields and options."""
    names: set[str] = set()
    seen: set[type] = set()
    pending: list[type] = [models.ash_config, *models.segments.values()]
    for section, plugins in models.plugin_configs.items():
        names.add(section)
        names.update(plugins)
        pending.extend(plugins.values())
    if isinstance(models.workspace_policy, type):
        pending.append(models.workspace_policy)
    while pending:
        model = pending.pop()
        if model in seen or not hasattr(model, "model_fields"):
            continue
        seen.add(model)
        names.update(_field_keys(model))
        for info in model.model_fields.values():
            _kind, inner = _model_of(info.annotation)
            if inner is not None:
                pending.append(inner)
    return frozenset(names)


@functools.lru_cache(maxsize=None)
def _cli_names() -> frozenset[str]:
    """Every option spelling and argument name of every ash command."""
    import typer

    from automated_security_helper.cli.main import app

    names: set[str] = set()
    pending = [typer.main.get_command(app)]
    while pending:
        command = pending.pop()
        pending.extend(getattr(command, "commands", {}).values())
        for param in command.params:
            names.update(param.opts)
            names.update(param.secondary_opts)
            if param.name:
                names.add(param.name)
    return frozenset(names)


def _mcp_names() -> set[str]:
    try:
        tools = _mcp_tool_schemas()
    except Exception:  # an MCP server that does not load: mcp_section reports it
        return set()
    return {name for schema in tools.values() for name in schema.get("properties", {})}


def _python_parameter_names(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
        return set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = node.args
            for arg in (
                *arguments.posonlyargs,
                *arguments.args,
                *arguments.kwonlyargs,
            ):
                if arg.arg not in ("self", "cls"):
                    names.add(arg.arg)
    return names


def _typescript_names(path: Path, rel: str, code: Path) -> set[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return set()
    names: set[str] = set()
    for interface in re.findall(r"\binterface\s+([A-Za-z_$][\w$]*)", text):
        names |= _section_names(
            typescript_section(f"typescript:{rel}:{interface}", code)
        )
    return names


def _is_template(path: Path) -> bool:
    """Whether a file is a CloudFormation template, by its format version line."""
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            return "AWSTemplateFormatVersion" in handle.read(4096)
    except OSError:
        return False


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
    if "/" in span:
        return None
    if segments[0] not in top:
        # scanner.bandit.enabled: a misspelled top-level key, when the rest of the
        # path holds under the key it is close to. Other dotted words (config.yaml,
        # os.environ) are not config paths.
        close = difflib.get_close_matches(segments[0], sorted(top), n=1, cutoff=0.8)
        if not close or resolve_config_path([close[0], *segments[1:]], models)[1]:
            return None
        return (
            f"`{span}`: there is no top-level key '{segments[0]}'; did you mean "
            f"'{close[0]}'?"
        )
    # sandbox.md and reporters.md read as file names; a value after the path
    # (reporters.xml: true) makes it a config path whatever its last word is.
    has_value = len(span.strip()) > len(match.group("path"))
    if (
        len(segments) == 2
        and segments[-1].lower() in _FILE_EXTENSIONS
        and not has_value
    ):
        return None
    _end, problem = resolve_config_path(segments, models)
    if problem and models.workspace_policy is not None:
        # The workspace policy file is a second schema whose top-level key,
        # workspace, is also an AshConfig key; a path that holds there is valid.
        _end, other = _resolve_from(models.workspace_policy, segments, [], models)
        if other is None:
            return None
    return f"`{span}`: {problem}" if problem else None


def _marked_table_problems(
    table: Table, section: Section, of: str, complete: bool
) -> list[tuple[int, str]]:
    """(line, problem) for a table whose marker names its section: rows that are not
    keys, Default and enabled-by-default cells that disagree with the code, columns
    that state defaults nothing compares, and, for a complete table, keys no row names.
    """
    problems: list[tuple[int, str]] = []
    line = table.marker.line if table.marker else table.header_line
    headers = _header_cells(table)
    default_column = next(
        (index for index, cell in enumerate(headers) if cell in DEFAULT_HEADERS), None
    )
    enabled_column = next(
        (index for index, cell in enumerate(headers) if cell in ENABLED_HEADERS), None
    )
    for index, cell in enumerate(headers):
        if index in (default_column, enabled_column) or not _states_defaults(cell):
            continue
        problems.append(
            (
                line,
                (
                    f"column '{table.header[index]}' states defaults, but it is not compared "
                    f"with the code: head it {' or '.join(sorted(DEFAULT_HEADERS))} for one "
                    "key's default, or Enabled by default for whether each plugin is on"
                ),
            )
        )
    plugin_rows = any(spec.plugin is not None for spec in section.keys.values())
    if enabled_column is not None and not plugin_rows:
        problems.append(
            (
                line,
                (
                    f"column '{table.header[enabled_column]}' states whether each plugin is "
                    f"enabled, but of={of} names no plugin section (scanners, reporters or "
                    "converters)"
                ),
            )
        )
        enabled_column = None
    named: set[int] = set()
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
                close = difflib.get_close_matches(key, sorted(section.keys), n=1)
                hint = f"; did you mean '{close[0]}'?" if close else ""
                problems.append(
                    (number, f"'{key}' is not a key of {section.label}{hint}")
                )
                continue
            named.add(id(spec))
            if defaults is not None:
                problem = default_problem(defaults[position], spec)
                if problem:
                    problems.append((number, f"'{key}' default {problem}"))
            if (
                enabled_column is not None
                and enabled_column < len(cells)
                and spec.plugin is not None
            ):
                problem = enabled_problem(cells[enabled_column], spec.plugin)
                if problem:
                    problems.append(
                        (number, f"'{key}' {headers[enabled_column]} {problem}")
                    )
    if complete:
        missing = {
            id(spec): spec
            for spec in section.keys.values()
            if spec.listed and id(spec) not in named
        }
        for spec in sorted(missing.values(), key=lambda spec: spec.names[0]):
            problems.append(
                (
                    line,
                    (
                        f"'{spec.names[0]}' is a key of {section.label} that no row names; "
                        "the marker says the table is complete"
                    ),
                )
            )
    return problems


def enabled_problem(cell: str, config_cls: type) -> str | None:
    """Why an enabled-by-default cell (yes, no, or "yes on Linux and macOS; no on
    Windows") does not state the plugin config's enabled default here, or None."""
    info = config_cls.model_fields.get("enabled")
    if info is None:
        return f"says {cell.strip()}, but {config_cls.__name__} has no enabled field"
    phrases = (
        frozenset({"depends on the platform"})
        if "enabled" in _platform_default_fields(config_cls)
        else frozenset()
    )
    spec = KeySpec(
        ("enabled",),
        default=bool(info.get_default(call_default_factory=True)),
        phrases=phrases,
    )
    return default_problem(cell, spec, what="its enabled default")


def check_option_tables(
    files: Iterable[Path],
    root: Path = REPO_ROOT,
    code: Path | None = None,
    notes: list[str] | None = None,
) -> list[Finding]:
    """Option tables name their section, list its keys with its defaults; config paths resolve.

    ``code`` is the tree Python, Dockerfile and CloudFormation sections are read from;
    by default the checkout of the installed ASH. ``notes``, when given, receives a
    line for each plugin module that did not import, whose sections were not checked.
    """
    models = load_config_models()
    if notes is not None:
        notes.extend(models.skipped_notes())
    code = code or code_root(root)
    keys: frozenset[str] | None = None
    findings: list[Finding] = []
    for page in load_pages(files, root):
        if page.rel in HISTORICAL_DOCS:
            continue
        for table in page.tables:
            if table.marker is None:
                if keys is None:
                    keys = documented_key_names(models, code)
                if _is_options_table(table, keys):
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
                            "of=github-inputs:<action or workflow>, "
                            "of=typescript:<file>:<Interface> or "
                            "of=terraform:<module directory>",
                        )
                    )
                continue
            line = table.marker.line
            of = table.marker.keys.get("of")
            extra = set(table.marker.keys) - {"of", "complete"}
            if extra:
                findings.append(
                    Finding(
                        "options",
                        page.rel,
                        line,
                        f"an options marker takes only of= and complete, not {sorted(extra)}",
                    )
                )
            complete = table.marker.keys.get("complete")
            if complete not in (None, True):
                findings.append(
                    Finding(
                        "options",
                        page.rel,
                        line,
                        f"complete is a bare word: write complete, not complete={complete}",
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
            for number, message in _marked_table_problems(
                table, section, of, complete is True
            ):
                findings.append(Finding("options", page.rel, number, message))
        for number, line in page.prose:
            for span in inline_code_spans(line):
                problem = config_path_problem(span, models)
                if problem:
                    findings.append(Finding("options", page.rel, number, problem))
    return findings


# ---------------------------------------------------------------------------
# Check: report and output file names in prose
# ---------------------------------------------------------------------------
#
# A reader opens reports/ash.sarif because a page names it. The name comes from the
# SARIF reporter's extension, so renaming the extension in the code must fail every
# page that names the old file. A code span that names a file ash.<name>, alone or as
# the last part of a path, or reports/<name>, is held to the files the code names.

#: A module or class attribute whose name says it holds a file name or names.
_FILE_CONSTANT = re.compile(
    r"^[A-Z][A-Z0-9_]*(?:_FILE|_FILES|_FILENAME|_FILENAMES|_FILE_NAME|_FILE_NAMES)$"
)
_ASH_FILE_TOKEN = re.compile(r"(?:^|/)(ash\.[\w.-]*\w)$")
_REPORTS_FILE_TOKEN = re.compile(r"(?:^|/)reports/([^/\s]+)$")
#: Directories of the code tree whose files are test data or docs, not files ASH
#: ships or writes; a name that exists only there is not evidence for a page.
_NOT_SHIPPED_DIRS = frozenset({"tests", "test", "test_data", "docs", "site"})


@dataclass
class OutputFiles:
    """The file names the code gives an ASH output, and the files the repository has."""

    #: Files a reporter writes in reports/: ash.<extension> for each one, the name a
    #: reporter without an extension gets, the files reporters write beside their
    #: report, and the file names their options default to.
    reports: set[str]
    #: Every other file name a file-name constant in the package holds.
    constants: set[str]
    #: Paths of files tracked in the code tree outside tests and docs.
    tracked: set[str]
    #: The reports of each plugin package the repository ships outside ASH's package
    #: (example_plugin_files), by the package's path. Only a page that documents the
    #: package may name them (documented_plugin_files).
    plugins: dict[str, set[str]] = field(default_factory=dict)

    def names(self) -> set[str]:
        return self.reports | self.constants | {Path(p).name for p in self.tracked}


def _string_values(node: ast.AST | None) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return [v for element in node.elts for v in _string_values(element)]
    if isinstance(node, ast.Call) and _attr_chain(node.func) in (
        "frozenset",
        "set",
        "tuple",
    ):
        return [v for arg in node.args for v in _string_values(arg)]
    return []


def file_name_constants(code: Path) -> set[str]:
    """Every string a module- or class-level file-name constant of the package holds
    (OUTPUT_LOG_FILES, SESSION_CONFIG_FILENAME, MARKDOWN_FILE_NAME), as a file name."""
    package = code / ASH_MODULE
    found: set[str] = set()
    if not package.is_dir():
        return found
    for _path, tree, _constants in package_modules(package):
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign):
                targets, value = [node.target], node.value
            else:
                continue
            if any(
                isinstance(t, ast.Name) and _FILE_CONSTANT.match(t.id) for t in targets
            ):
                found.update(Path(v).name for v in _string_values(value) if v)
    return found


def _tracked_paths(code: Path) -> set[str]:
    """Repository-relative paths of the code tree's files outside tests and docs."""
    paths = [path.relative_to(code).as_posix() for path in listed_files(code)]
    return {p for p in paths if not _NOT_SHIPPED_DIRS.intersection(p.split("/")[:-1])}


def reporter_file_names(models: ConfigModels) -> set[str]:
    """The files the registered reporters write in reports/, with their defaults."""
    from automated_security_helper.base import reporter_plugin

    names: set[str] = set()
    without_extension = getattr(reporter_plugin, "reporter_file_name", None)
    if without_extension is not None:
        from types import SimpleNamespace

        names.add(
            without_extension(SimpleNamespace(config=SimpleNamespace(extension=None)))
        )
    for config_cls in models.plugin_configs.get("reporters", {}).values():
        try:
            config = config_cls()
        except (
            Exception
        ):  # a config that needs settings: its field default still names it
            config = None
        info = config_cls.model_fields.get("extension")
        extension = (
            getattr(config, "extension", None)
            if config is not None
            else (info.default if info is not None else None)
        )
        if isinstance(extension, str) and extension:
            names.add(f"ash.{extension}")
        options = _options_model(config_cls)
        for field_name, field_info in (options.model_fields if options else {}).items():
            default = field_info.default
            if (
                re.search(r"(?:^|_)file(?:_?name)?$", field_name)
                and isinstance(default, str)
                and default
            ):
                names.add(Path(default).name)
    names |= _companion_file_names()
    names |= _written_by_reporters()
    return names


def _written_by_reporters() -> set[str]:
    """The files each reporter plugin's own code writes in reports/
    (reporter_written_files), read from its class's source."""
    import inspect

    names: set[str] = set()
    for cls in _reporter_plugin_classes():
        try:
            tree = ast.parse(textwrap.dedent(inspect.getsource(cls)))
        except (OSError, TypeError, SyntaxError):
            continue  # no source to read: its companion names still count
        names |= reporter_written_files(tree)
    return names


def _is_string(node: ast.AST, value: str) -> bool:
    return isinstance(node, ast.Constant) and node.value == value


def _is_joinpath(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "joinpath"
    )


def _is_reports_dir(node: ast.AST, dirs: set[str]) -> bool:
    """``<x> / "reports"``, ``<x>.joinpath("reports")``, or a variable assigned one."""
    if isinstance(node, ast.Name):
        return node.id in dirs
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return _is_string(node.right, "reports")
    return (
        _is_joinpath(node) and bool(node.args) and _is_string(node.args[-1], "reports")
    )


def _spelled_names(
    node: ast.AST, assigned: dict[str, list[ast.expr]], depth: int = 0
) -> set[str] | None:
    """Every string node can be, when the code spells each one out: a string, an
    f-string or a conditional made of strings, or a variable the function only assigns
    such values to. None when a part comes from anything else (an option, a call)."""
    if depth > 4:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.IfExp):
        body = _spelled_names(node.body, assigned, depth + 1)
        orelse = _spelled_names(node.orelse, assigned, depth + 1)
        return body | orelse if body is not None and orelse is not None else None
    if isinstance(node, ast.Name):
        values = [
            _spelled_names(value, assigned, depth + 1)
            for value in assigned.get(node.id, [])
        ]
        if not values or any(v is None for v in values):
            return None
        return set().union(*values)
    if isinstance(node, ast.JoinedStr):
        names = {""}
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                options: set[str] | None = {part.value}
            elif (
                isinstance(part, ast.FormattedValue)
                and part.conversion == -1
                and part.format_spec is None
            ):
                options = _spelled_names(part.value, assigned, depth + 1)
            else:
                options = None
            if options is None:
                return None
            names = {name + option for name in names for option in options}
        return names
    return None


def reporter_written_files(tree: ast.AST) -> set[str]:
    """The names a reporter's code gives the files it writes in reports/.

    A file is ``<reports dir> / <name>``, ``<reports dir>.joinpath(<name>)`` or
    ``<x>.joinpath("reports", <name>)`` (see _is_reports_dir), in any function. The
    name counts when the code spells it out (_spelled_names), as the S3 reporter's
    ``f"s3-report.{file_extension}"`` with ``file_extension = "json" if ... else
    "yaml"``. A name built from an option is the options' file default instead
    (reporter_file_names).
    """
    found: set[str] = set()
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        assigned: dict[str, list[ast.expr]] = {}
        for node in ast.walk(function):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assigned.setdefault(target.id, []).append(node.value)
            elif (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.value is not None
            ):
                assigned.setdefault(node.target.id, []).append(node.value)
        dirs = {
            name
            for name, values in assigned.items()
            if any(_is_reports_dir(value, set()) for value in values)
        }
        for node in ast.walk(function):
            names = None
            if (
                isinstance(node, ast.BinOp)
                and isinstance(node.op, ast.Div)
                and _is_reports_dir(node.left, dirs)
            ):
                names = _spelled_names(node.right, assigned)
            elif _is_joinpath(node):
                args = node.args
                if len(args) >= 2 and _is_string(args[-2], "reports"):
                    names = _spelled_names(args[-1], assigned)
                elif len(args) == 1 and _is_reports_dir(node.func.value, dirs):
                    names = _spelled_names(args[0], assigned)
            found |= {name for name in names or () if name and "/" not in name}
    return found


def _reporter_plugin_classes() -> list[type]:
    """Every reporter plugin class in the plugin modules load_config_models imported.

    Read from the modules, not from ash_plugin_manager: the manager caches its list
    the first time it is asked, which can be before a plugin module is imported.
    """
    from automated_security_helper.base.reporter_plugin import ReporterPluginBase

    prefix = f"{ASH_MODULE}.plugin_modules."
    found: list[type] = []
    for name, module in sorted(sys.modules.items()):
        if not name.startswith(prefix) or module is None:
            continue
        for value in vars(module).values():
            if (
                isinstance(value, type)
                and issubclass(value, ReporterPluginBase)
                and value is not ReporterPluginBase
                and value.__module__ == name
                and value not in found
            ):
                found.append(value)
    return found


def _companion_file_names() -> set[str]:
    """The files each reporter plugin writes beside its report with its default
    config (companion_file_names), from an instance built in a throwaway context."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    names: set[str] = set()
    previous = logging.root.manager.disable
    logging.disable(logging.WARNING)
    try:
        with tempfile.TemporaryDirectory(prefix="ash-docs-reporters-") as scratch:
            source, output = Path(scratch) / "source", Path(scratch) / "output"
            source.mkdir()
            output.mkdir()
            context = PluginContext(
                source_dir=source, output_dir=output, config=AshConfig()
            )
            for cls in _reporter_plugin_classes():
                names |= declared_companion_names(cls, context)
    finally:
        logging.disable(previous)
    return names


def declared_companion_names(cls: type, context: Any) -> set[str]:
    """The files a reporter class declares it writes beside its report
    (companion_file_names), with its default config and with each value of every
    option that takes one of a fixed set (a Literal, an Enum or a bool), one option
    at a time: the S3 reporter's local copy is s3-report.json or s3-report.yaml by
    its file_format."""
    import enum
    import typing

    if not callable(getattr(cls, "companion_file_names", None)):
        return set()
    configs: list[Any] = [None]
    info = getattr(cls, "model_fields", {}).get("config")
    config_cls = _model_of(info.annotation)[1] if info is not None else None
    options_cls = _options_model(config_cls) if config_cls is not None else None
    for name, field_info in (options_cls.model_fields if options_cls else {}).items():
        annotation = field_info.annotation
        if typing.get_origin(annotation) is typing.Literal:
            choices: list[Any] = list(typing.get_args(annotation))
        elif isinstance(annotation, type) and issubclass(annotation, enum.Enum):
            choices = list(annotation)
        elif annotation is bool:
            choices = [False, True]
        else:
            continue
        for choice in choices:
            try:
                configs.append(config_cls(options=options_cls(**{name: choice})))
            except Exception:  # an option that needs others set: not declared here
                continue
    names: set[str] = set()
    for config in configs:
        try:
            reporter = (
                cls(context=context)
                if config is None
                else cls(context=context, config=config)
            )
            declared = reporter.companion_file_names()
        except Exception:  # a reporter that cannot be built here names none
            continue
        names.update(n for n in declared if isinstance(n, str))
    return names


def _class_extensions(tree: ast.AST) -> set[str]:
    """ash.<extension> for every ``extension = "<suffix>"`` a class body sets."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for statement in node.body:
            target = statement.target if isinstance(statement, ast.AnnAssign) else None
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
                target = statement.targets[0]
            if isinstance(target, ast.Name) and target.id == "extension":
                found.update(f"ash.{v}" for v in _string_values(statement.value) if v)
    return found


def _top_package(rel: str, tracked: set[str]) -> str | None:
    """The outermost package directory that holds the module at rel, or None."""
    parts = rel.split("/")[:-1]
    top = None
    while parts and "/".join([*parts, "__init__.py"]) in tracked:
        top = "/".join(parts)
        parts = parts[:-1]
    return top


def example_plugin_files(code: Path, tracked: set[str]) -> dict[str, set[str]]:
    """The reports of each plugin package the repository ships outside ASH's package,
    such as the example plugin package, by the package's path: ash.<extension> of each
    class that sets an extension, and the files its code writes in reports/."""
    packages: dict[str, set[str]] = {}
    for rel in sorted(tracked):
        if not rel.endswith(".py") or rel.startswith(ASH_MODULE + "/"):
            continue
        package = _top_package(rel, tracked)
        if package is None:
            continue
        try:
            tree = ast.parse((code / rel).read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        files = _class_extensions(tree) | reporter_written_files(tree)
        if files:
            packages.setdefault(package, set()).update(files)
    return packages


def documented_plugin_files(page: Page, plugins: dict[str, set[str]]) -> set[str]:
    """The reports of the plugin packages a page documents: a page in the package's
    project (the directory that holds it), or a page that names the package."""
    found: set[str] = set()
    for package, files in plugins.items():
        project, _, name = package.rpartition("/")
        inside = bool(project) and page.rel.startswith(project + "/")
        if inside or re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w-])", page.text):
            found |= files
    return found


def output_files(code: Path, models: ConfigModels) -> OutputFiles:
    tracked = _tracked_paths(code)
    return OutputFiles(
        reporter_file_names(models),
        file_name_constants(code),
        tracked,
        example_plugin_files(code, tracked),
    )


def page_reporter_files(page: Page) -> set[str]:
    """ash.<extension> for every reporter config a python block on the page declares:
    a tutorial's own reporter writes a file ASH does not register."""
    found: set[str] = set()
    for block in page.blocks:
        if block.family != "python":
            continue
        try:
            found |= _class_extensions(ast.parse(block.body))
        except SyntaxError:
            continue
    return found


def report_file_problem(token: str, files: OutputFiles, own: set[str]) -> str | None:
    """Why a path-like word of a code span names an ASH file the code does not, or None."""
    if re.search(r"[<>{}*]", token):
        return None  # a placeholder: reports/ash.<extension>
    reports = _REPORTS_FILE_TOKEN.search(token)
    if reports:
        name = reports.group(1)
        if name in files.reports or name in own:
            return None
        close = difflib.get_close_matches(name, sorted(files.reports | own), n=1)
        hint = f"; did you mean reports/{close[0]}?" if close else ""
        return (
            f"ASH writes no reports/{name}: the reports directory holds "
            f"ash.<extension> of each registered reporter and the files they write "
            f"beside it{hint}"
        )
    named = _ASH_FILE_TOKEN.search(token)
    if not named:
        return None
    name = named.group(1)
    path = token.lstrip("./")
    if name in files.names() or name in own:
        return None
    if "/" in path and any(t == path or t.endswith("/" + path) for t in files.tracked):
        return None
    close = difflib.get_close_matches(name, sorted(files.names() | own), n=1)
    hint = f"; did you mean {close[0]}?" if close else ""
    return (
        f"names {name}, which no reporter ASH registers writes and no file-name "
        f"constant in ASH names{hint}"
    )


def check_report_files(
    files: Iterable[Path],
    root: Path = REPO_ROOT,
    code: Path | None = None,
    models: ConfigModels | None = None,
) -> list[Finding]:
    """Report and output file names in code spans are files ASH writes.

    ``ash.<name>``, alone or at the end of a path, must be a registered reporter's
    report (ash.<extension>), a file a reporter's code writes beside it, a file name a
    reporter's options default to, a string a file-name constant of the package
    holds (OUTPUT_LOG_FILES, SESSION_CONFIG_FILENAME), a reporter a python block on
    the same page declares, a report of a plugin package the page documents (the
    example plugin package), or a file the repository ships (Formula/ash.rb).
    ``reports/<name>`` must be a report or a file a reporter writes beside it.
    """
    models = models or load_config_models()
    code = code or code_root(root)
    known = output_files(code, models)
    findings: list[Finding] = []
    for page in load_pages(files, root):
        if page.rel in HISTORICAL_DOCS:
            continue
        own = page_reporter_files(page) | documented_plugin_files(page, known.plugins)
        for number, line in page.prose:
            for span in inline_code_spans(line):
                for token in re.split(r"[\s,;]+", span.strip()):
                    if "://" in token or "(" in token:
                        continue  # a URL, or a call such as ash.run_ash_scan()
                    token = token.strip("[]'\"").rstrip(".:")
                    problem = report_file_problem(token, known, own) if token else None
                    if problem:
                        findings.append(
                            Finding("files", page.rel, number, f"`{span}` {problem}")
                        )
    return findings


# ---------------------------------------------------------------------------
# Check: scanner names in tables
# ---------------------------------------------------------------------------
#
# Tables that list scanners in plain text (reference/coverage.md's "By stack" and
# "By scanner") were checked by nothing, so an invented gitleakz passed. A column
# headed Scanner, Scanners, Built-in scanners or Community plugins lists scanners:
# each item of its cells must be one name, of a scanner ASH ships, built in or from a
# community module as the header says. An item of several words ("the CloudFormation
# scanners") is reported: nothing can check it, and "trufflehog scanner" would hide an
# invented name. A note in parentheses is dropped first. Whether such a table lists
# every scanner is the options marker's complete: of=scanners complete.

#: Column header -> the kind of scanner its cells name (None: either kind).
SCANNER_COLUMN_HEADERS = {
    "scanner": None,
    "scanners": None,
    "built-in scanners": "built-in",
    "community plugins": "community",
    "community scanners": "community",
}
_SCANNER_ITEM = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")


def shipped_scanners(models: ConfigModels) -> dict[str, str]:
    """Every scanner ASH ships, by config name: "built-in" or "community"."""
    builtin_package = f"{ASH_MODULE}.plugin_modules.ash_builtin."
    found = {
        name: "built-in"
        if config_cls.__module__.startswith(builtin_package)
        else "community"
        for name, config_cls in models.plugin_configs.get("scanners", {}).items()
    }
    for name in _field_keys(models.segments["scanners"]):
        found.setdefault(name, "built-in")
    return found


def scanner_cell_items(cell: str) -> list[str]:
    """The items of a cell listing scanners: links and code spans unwrapped,
    parentheticals dropped, split on commas, semicolons, and, or."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", cell)
    text = re.sub(r"<[^>]+>", "", text).replace("`", "")
    text = re.sub(r"\([^()]*\)", "", text)
    items = re.split(r",|;|\band\b|\bor\b", text)
    return [item.strip().rstrip(".") for item in items if item.strip()]


def check_scanner_names(
    files: Iterable[Path],
    root: Path = REPO_ROOT,
    models: ConfigModels | None = None,
    notes: list[str] | None = None,
) -> list[Finding]:
    """Scanner names in a table's scanner columns are scanners ASH ships.

    Every item of a scanner column's cells is checked: one name must be a scanner
    ASH ships, and anything else is reported, since nothing could check it. ``notes``,
    when given, receives a line counting the cells, names and other items examined.
    """
    models = models or load_config_models()
    shipped = shipped_scanners(models)
    findings: list[Finding] = []
    column_count = cell_count = name_count = other_count = 0
    for page in load_pages(files, root):
        if page.rel in HISTORICAL_DOCS:
            continue
        for table in page.tables:
            headers = _header_cells(table)
            columns = [
                (index, table.header[index], SCANNER_COLUMN_HEADERS[cell])
                for index, cell in enumerate(headers)
                if cell in SCANNER_COLUMN_HEADERS
            ]
            column_count += len(columns)
            for number, cells in table.rows:
                for index, header, kind in columns:
                    if index >= len(cells) or not cells[index].strip():
                        continue
                    cell_count += 1
                    for item in scanner_cell_items(cells[index]):
                        if _SCANNER_ITEM.fullmatch(item):
                            name_count += 1
                            problem = _scanner_item_problem(
                                item.lower(), header, kind, shipped
                            )
                        else:
                            other_count += 1
                            problem = (
                                f"'{item}' in the {header} column is not one scanner "
                                "name, so nothing checks it: list scanner names there, "
                                "with any note in parentheses, and put other words in "
                                "another column"
                            )
                        if problem:
                            findings.append(
                                Finding("scanners", page.rel, number, problem)
                            )
    if notes is not None:
        notes.append(
            f"examined {cell_count} cells in {column_count} scanner columns: "
            f"{name_count} scanner names, {other_count} other items"
        )
    return findings


def _scanner_item_problem(
    item: str, header: str, kind: str | None, shipped: dict[str, str]
) -> str | None:
    actual = shipped.get(item)
    if actual is None:
        close = difflib.get_close_matches(item, sorted(shipped), n=1)
        hint = f"; did you mean '{close[0]}'?" if close else ""
        return f"'{item}' in the {header} column is not a scanner ASH ships{hint}"
    if kind == "built-in" and actual == "community":
        return (
            f"'{item}' in the {header} column is a community plugin, not a built-in "
            "scanner"
        )
    if kind == "community" and actual == "built-in":
        return f"'{item}' in the {header} column is a built-in scanner, not a community plugin"
    return None


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
                except Exception as exc:  # an import that raises is the finding
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
    """A YAML loader for mkdocs.yml: ``!!python/name:x`` resolves, ``!ENV`` gives its default.

    It is ``yaml.SafeLoader`` with three constructors added. ``!!python/name:x``
    imports ``x`` only from a module under :data:`_RESOLVABLE_TAG_MODULES` and is
    otherwise kept as its text; ``!!python/object`` tags read as ``None``; ``!ENV``
    reads the variable, or its default. Every other tag is an error, as it is for
    ``yaml.safe_load``.
    """

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
            except Exception:  # an unimportable tag is not a docs problem here
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
        loader = Loader(text)
        try:
            return loader.get_single_data()
        finally:
            loader.dispose()


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
    except Exception:  # fall back to the core set if an extension will not load
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


def _decoded_path_to_page(url_path: str, site: Site) -> Path | None:
    """The source page a percent-decoded site URL path serves, if any."""
    url_path = url_path.strip("/")
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


DOCS_VERSIONS_PATH = Path(__file__).resolve().parent / "docs_versions.py"


@functools.lru_cache(maxsize=1)
def site_version_pattern() -> re.Pattern[str]:
    """The version a URL on the published site can name before the page path.

    scripts/docs_versions.py publishes main as `main`, a release tag vX.Y.Z as X.Y.Z,
    and the newest release also as `latest`; the root redirects an unversioned path to
    `latest/`. The names come from that script, so a path segment that no deploy
    publishes, such as `3/` or `v3.7.0/`, is read as part of the page path, where it
    reaches no page.
    """
    versions = _load_by_path("_ash_docs_versions", DOCS_VERSIONS_PATH)
    names = "|".join(re.escape(n) for n in (versions.LATEST, versions.DEV_VERSION))
    return re.compile(rf"(?:{names}|{versions.RELEASE_VERSION.pattern})(?:/|$)")


def site_target(
    url_path: str, site: Site, redirects: dict[str, str]
) -> tuple[Path | None, str, str | None]:
    """(page, the redirect's own fragment, the redirected old page) a site URL reaches.

    The path is percent-decoded once, here; a second decode would turn `%2541` into
    `A` rather than `%41`.
    """
    path = unquote(url_path).lstrip("/")
    version = site_version_pattern().match(path)
    if version:
        path = path[version.end() :]
    served = _decoded_path_to_page(path, site)
    if served is not None:
        return served, "", None
    source = path.strip("/")
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
    """Why a docs path the code names does not exist in the docs root.

    A path that is not a file of the repository may be a site page named by its path
    under docs_dir (help text saying "See docs/config-overrides.md"). That resolves
    the way the page's URL does: to a page, or through docs/redirects.yml to one, with
    the fragment checked on the final page. A fetched file (raw GitHub) does not
    follow a redirect, so this applies only to paths shown to a reader.
    """
    path = site.root / rel
    if path.is_file():
        if fragment and path.suffix == ".md" and fragment not in _page_ids(path, site):
            return f"{shown}: {rel} has no heading or anchor '#{fragment}'"
        return None
    if not fetched and rel.endswith(".md"):
        url_path = _redirect_url(rel, site)
        page, _redirect_fragment, via = site_target(url_path, site, redirects)
        if page is not None or via is not None:
            return site_url_problem(shown, url_path, fragment, site, redirects)
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
    for path in listed_files(site.docs_dir):
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
    # mkdocs matches not_in_nav with pathspec's gitignore rules, and depends on
    # pathspec, so the check uses that matcher rather than an approximation of it.
    import pathspec

    patterns = str(site.config.get("not_in_nav") or "")
    lines = [
        line
        for line in patterns.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    return pathspec.GitIgnoreSpec.from_lines(lines).match_file


def check_nav(root: Path = REPO_ROOT) -> list[Finding]:
    """Every site page is in the nav or deliberately not; every nav entry and redirect resolves."""
    site = load_site(str(root))
    findings: list[Finding] = []
    reachable, missing = nav_targets(site)
    for where, line, problem in missing:
        findings.append(Finding("nav", where, line, problem))
    unlisted = _not_in_nav_spec(site)
    for page in listed_files(site.docs_dir, ["**/*.md"]):
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
# Check: a release number never becomes an install ref on the main version
# ---------------------------------------------------------------------------


def check_release_placeholders(root: Path = REPO_ROOT) -> list[Finding]:
    """No template names the ref of an install command with the release placeholder.

    A template has two placeholders. ``{{VERSION}}`` is the ref an install command
    uses, and the docs site's main version renders it as ``main``. ``{{RELEASE}}`` is
    the current release number on every build, for what ``ash --version`` prints and
    for sentences about a release. Written as the ref of an install command, it would
    make the main version's docs install a release, so every form the template
    manager lists (``@v``, ``--branch v``, ``rev: v``, ``refs/tags/v``, a flake ref,
    ``--ash-revision-to-install v``, ``ash-version: v``) followed by it is reported.
    A table row and a ``text`` block may name the release: neither is a command a
    reader runs.
    """
    path = root / TEMPLATE_MANAGER
    if not path.is_file():
        return [
            Finding(
                "templates", TEMPLATE_MANAGER, 1, "the template manager does not exist"
            )
        ]
    manager = _load_by_path(
        "_ash_version_template_manager", path
    ).VersionTemplateManager(root)
    pattern = manager.release_in_install_ref()
    templates = [
        root / (target + manager.template_suffix)
        for target in manager.target_files
        if (root / (target + manager.template_suffix)).is_file()
    ]
    if not templates:
        return [
            Finding(
                "templates",
                TEMPLATE_MANAGER,
                1,
                "no target of the template manager has a template, so nothing was checked",
            )
        ]
    message = (
        f"{manager.release_placeholder} is the ref of an install command, so the main "
        f"version of the docs would install a release; use {manager.version_placeholder}, "
        f"or move the release number to a table or a text sample"
    )
    findings: list[Finding] = []
    for template in templates:
        page = parse_page(template, root)
        in_tables = {table.header_line for table in page.tables} | {
            line for table in page.tables for line, _cells in table.rows
        }
        lines = [(line, text) for line, text in page.prose if line not in in_tables]
        for block in page.blocks:
            if block.lang != "text":
                lines += [
                    (block.body_line + offset, text)
                    for offset, text in enumerate(block.body.splitlines())
                ]
        findings += [
            Finding("templates", page.rel, line, message)
            for line, text in sorted(lines)
            if pattern.search(text)
        ]
    return findings


# ---------------------------------------------------------------------------
# Check: install commands name extras, Pythons and refs that exist
# ---------------------------------------------------------------------------
#
# No docs job installs ASH, so every install command is illustrative and the runner
# never runs one; the CLI check reads only ash's own commands. This check reads every
# install command statically: in shell blocks whether or not they run, in CI files, in
# a Jenkinsfile, in inline code spans and in templates (with {{VERSION}} rendered as
# parse_page renders it).

#: The rules, as the keys of the counts check_install_commands reports.
INSTALL_RULES = ("extras", "python", "refs", "curl")
_REPOSITORY = GITHUB_REPO_SLUG.split("/")[1]
_SPEC_EXTRAS = re.compile(
    rf"{re.escape(ASH_PACKAGE)}\[(?P<extras>[^\]]*)\]", re.IGNORECASE
)
_LOCAL_SPEC_EXTRAS = re.compile(r"^\.(?:/)?\[(?P<extras>[^\]]*)\]$")
_UV_INSTALLER = re.compile(r"^https?://astral\.sh/uv/(?:[\w.-]+/)?install\.sh$")
_PYTHON_VERSION = re.compile(r"(?<![\d.])(\d+)\.(\d+)(?:\.\d+)?(?![\d.])")
#: What ends a ref: the stop characters of the pin reader in
#: tests/unit/test_agent_plugin_ash_version.py, # for a URL fragment, and / for the
#: path after a ref in a raw.githubusercontent.com URL.
_REF = r"(?P<ref>[^\s`'\"),;\]#/]+)"
#: uv subcommands that act on the project in the current directory, or on --project.
_UV_PROJECT_COMMANDS = frozenset(
    {"sync", "run", "lock", "venv", "export", "tree", "add", "remove", "pip"}
)
_FLOATING_WORDS = re.compile(
    r"\b(?:float\w*|moves?|moving|latest|tracks?|follows?)\b", re.IGNORECASE
)
_PROGRAM_WRAPPERS = frozenset({"sudo", "env", "time", "exec", "command", "nohup"})
#: The first word of an inline code span that is an install command.
_INSTALL_PROGRAMS = frozenset(
    {"uv", "uvx", "pip", "pip3", "pipx", "curl", "git", "python", "python3"}
)


@dataclass(frozen=True)
class ProjectFacts:
    """What a pyproject.toml says an install of its project may ask for."""

    #: "ASH", or the pyproject.toml's path in the code tree.
    label: str
    #: The project's extras, normalized as PEP 685 compares them.
    extras: frozenset[str]
    requires_python: str | None


def _normalized_extra(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


@functools.lru_cache(maxsize=None)
def project_facts(directory: str, code: str) -> ProjectFacts | None:
    """The extras and requires-python of the project whose pyproject.toml is in directory."""
    pyproject = Path(directory) / "pyproject.toml"
    if not pyproject.is_file():
        return None
    project = (_parse_toml(pyproject.read_text(encoding="utf-8")) or {}).get(
        "project"
    ) or {}
    label = (
        "ASH"
        if Path(directory).resolve() == Path(code).resolve()
        else rel_path(pyproject, Path(code))
    )
    return ProjectFacts(
        label,
        frozenset(
            _normalized_extra(name)
            for name in (project.get("optional-dependencies") or {})
        ),
        project.get("requires-python"),
    )


def _page_project(page: Page, code: Path) -> ProjectFacts | None:
    """The project a page's commands act on: the nearest pyproject.toml above the page."""
    directory = (code / page.rel).parent
    while True:
        facts = project_facts(str(directory), str(code))
        if facts is not None:
            return facts
        if directory.resolve() == code.resolve() or directory == directory.parent:
            return project_facts(str(code), str(code))
        directory = directory.parent


def _option_values(words: list[str], names: tuple[str, ...]) -> list[tuple[str, str]]:
    """(the option as written, its value) for each of names in words."""
    found = []
    for index, word in enumerate(words):
        name, inline, value = word.partition("=")
        if name not in names:
            continue
        if inline:
            found.append((word, value))
        elif index + 1 < len(words):
            found.append((f"{word} {words[index + 1]}", words[index + 1]))
    return found


@dataclass
class InstallRules:
    """The facts every install command on one page is compared with."""

    root: Path
    code: Path
    page: Page
    #: (form name, the text before a ref, whether the form names a branch only, and
    #: whether the text names ASH by itself) from INSTALL_REF_FORMS.
    forms: list[tuple[str, str, bool, bool]]
    version: str
    counts: dict[str, int]

    @functools.cached_property
    def ash(self) -> ProjectFacts:
        facts = project_facts(str(self.code), str(self.code))
        return facts or ProjectFacts("ASH", frozenset(), None)

    @functools.cached_property
    def default_project(self) -> ProjectFacts | None:
        return _page_project(self.page, self.code)

    @functools.cached_property
    def explains_floating(self) -> bool:
        tag = re.compile(rf"(?<![\w.])@?v{re.escape(self.major)}(?![\w.])")
        return any(
            tag.search(text) and _FLOATING_WORDS.search(text)
            for _line, text in self.page.prose
        )

    @property
    def major(self) -> str:
        return self.version.split(".")[0]

    def count(self, rule: str) -> None:
        self.counts[rule] = self.counts.get(rule, 0) + 1

    def project_at(self, path: str | None) -> ProjectFacts | None:
        """The project of a --project or --directory value, from the page's directory up."""
        if path is None:
            return self.default_project
        directory = (self.code / self.page.rel).parent
        while True:
            facts = project_facts(str(directory / path), str(self.code))
            if facts is not None or directory.resolve() == self.code.resolve():
                return facts
            if directory == directory.parent:
                return None
            directory = directory.parent

    # -- the four rules ----------------------------------------------------

    def extras_problems(self, project: ProjectFacts | None, extras: str) -> list[str]:
        problems = []
        for extra in (e for e in extras.split(",") if e.strip()):
            self.count("extras")
            if project is not None and _normalized_extra(extra) not in project.extras:
                problems.append(
                    f"{project.label} has no extra '{extra.strip()}'; its extras are "
                    f"{_or_list(sorted(project.extras)) or 'none'}"
                )
        return problems

    def ref_problem(self, name: str, ref: str, branch_only: bool) -> str | None:
        # A placeholder (v<version>, $REF) is not a ref. {{VERSION}} is rendered in a
        # template, so one left there is misspelled; a page about templates names it.
        if any(c in ref for c in "<>$") or (
            "{{" in ref and not self.page.path.name.endswith(".md.template")
        ):
            return None
        self.count("refs")
        if ref == "main":
            return None
        if not branch_only and (
            ref == f"v{self.version}"
            or re.fullmatch(r"[0-9a-f]{40}", ref)
            or (ref == f"v{self.major}" and self.explains_floating)
        ):
            return None
        return (
            f"the {name} ref names {ref}; an install command names v{self.version} (the "
            f"current release, {VERSION_PLACEHOLDER} in a template), main, a full "
            f"40-character commit SHA, or v{self.major} on a page that says that tag moves"
        )

    def text_problems(self, text: str, names_ash: bool) -> list[str]:
        """The extras and refs a string names: a word, a YAML value, a Groovy line."""
        problems = []
        for match in _SPEC_EXTRAS.finditer(text):
            problems += self.extras_problems(self.ash, match.group("extras"))
        for name, prefix, branch_only, anchored in self.forms:
            if not (anchored or names_ash):
                continue
            for match in re.finditer(prefix + _REF, text):
                problem = self.ref_problem(name, match.group("ref"), branch_only)
                if problem:
                    problems.append(problem)
        return problems

    def command_problems(self, words: list[str]) -> list[str]:
        """Every rule, on one simple shell command."""
        position = 0
        while position < len(words) and (
            _ASSIGNMENT.match(words[position]) or words[position] in _PROGRAM_WRAPPERS
        ):
            position += 1
        head = posixpath.basename(words[position]) if position < len(words) else ""
        rest = words[position + 1 :]
        names_ash = head in ASH_PROGRAMS or any(
            _REPOSITORY in word.lower() for word in words
        )
        problems = []
        anchored_only = " ".join(words)
        for word in words:
            problems += self.text_problems(word, names_ash=False)
            local = _LOCAL_SPEC_EXTRAS.match(word)
            if local:
                problems += self.extras_problems(
                    self.default_project, local.group("extras")
                )
        if names_ash:
            # The forms that do not name the repository themselves (--branch,
            # refs/tags/, --ash-revision-to-install) count in a command that does.
            for name, prefix, branch_only, anchored in self.forms:
                if anchored:
                    continue
                for match in re.finditer(prefix + _REF, anchored_only):
                    problem = self.ref_problem(name, match.group("ref"), branch_only)
                    if problem:
                        problems.append(problem)
        subcommand = next((w for w in rest if not w.startswith("-")), "")
        on_project = head == "uv" and subcommand in _UV_PROJECT_COMMANDS
        directory = next(
            (v for _o, v in _option_values(rest, ("--project", "--directory"))), None
        )
        project = self.project_at(directory) if on_project else None
        if on_project:
            for _option, value in _option_values(rest, ("--extra",)):
                problems += self.extras_problems(project, value)
        python_options = ("--python", "-p") if head in ("uv", "uvx") else ("--python",)
        if head in ("uv", "uvx", "pipx", "pip", "pip3"):
            facts = self.ash if names_ash else project
            for written, value in _option_values(rest, python_options):
                version = _PYTHON_VERSION.search(value)
                if facts is None or not facts.requires_python or version is None:
                    continue
                self.count("python")
                from packaging.specifiers import SpecifierSet

                if not SpecifierSet(facts.requires_python).contains(
                    f"{version.group(1)}.{version.group(2)}", prereleases=True
                ):
                    problems.append(
                        f"{written} is outside {facts.label}'s requires-python "
                        f"{facts.requires_python}"
                    )
        if head == "curl" and any(_UV_INSTALLER.match(word) for word in rest):
            self.count("curl")
            follows = any(
                word in ("--location", "--location-trusted")
                or re.fullmatch(r"-[A-Za-z]*L[A-Za-z]*", word)
                for word in rest
            )
            if not follows:
                problems.append(
                    "curl fetches the uv installer without -L; "
                    "https://astral.sh/uv/install.sh answers with a 301 redirect, so "
                    "curl passes the redirect page to sh instead of the installer "
                    "(write curl -LsSf)"
                )
        return problems

    def script_problems(self, script: str) -> list[tuple[int, str]]:
        """(zero-based line, problem) for every command of a shell script."""
        found = []
        for command in split_shell(script):
            found += [(command.line, p) for p in self.command_problems(command.words)]
            for inner in command.substitutions:
                found += [(command.line, p) for _l, p in self.script_problems(inner)]
        return found


def _install_ref_forms(manager: Any) -> list[tuple[str, str, bool, bool]]:
    """INSTALL_REF_FORMS as (name, text before a ref, branch only, names ASH itself).

    The @ form is anchored to the repository it follows, as in git+...<repo>.git@ and
    uses: <owner>/<repo>/<path>@; on its own, @ would match any package's pin. A form
    whose branch rendering differs from its release prefix (refs/heads/ for refs/tags/)
    is listed again, for branches. Both are regular expressions, as the manager's
    branch_ref_pattern reads them.
    """
    forms = []
    for name, prefix, branch in manager.INSTALL_REF_FORMS:
        anchored = _REPOSITORY in prefix
        pattern = prefix
        if prefix == "@":
            pattern, anchored = rf"{re.escape(_REPOSITORY)}(?:\.git|/[\w./-]*)?@", True
        forms.append((name, pattern, False, anchored))
        branch_prefix = branch.split("{branch}")[0]
        if branch_prefix != prefix:
            forms.append((name, branch_prefix, True, anchored))
    return forms


def _body_line(block: Block, needle: str) -> int:
    """The page line of the first body line of block that contains needle."""
    for number, text in block.body_lines():
        if needle and needle in text:
            return number
    return block.fence_line


def _yaml_strings(document: Any) -> Iterator[str]:
    if isinstance(document, dict):
        for value in document.values():
            yield from _yaml_strings(value)
    elif isinstance(document, list):
        for item in document:
            yield from _yaml_strings(item)
    elif isinstance(document, str):
        yield document


def _config_ref_values(document: Any) -> Iterator[tuple[str, str]]:
    """(form name, value) of the refs a CI file or pre-commit config sets for ASH:
    a pre-commit repo entry's rev, and ash-version under with: of a job or step that
    uses ASH's workflow or action."""
    for entry in _dicts_with_key(document, "repo"):
        if GITHUB_REPO_SLUG in str(entry.get("repo", "")).lower() and "rev" in entry:
            yield "rev:", str(entry["rev"])
    for entry in _dicts_with_key(document, "uses"):
        given = entry.get("with")
        if GITHUB_REPO_SLUG in str(entry.get("uses", "")).lower() and isinstance(
            given, dict
        ):
            if "ash-version" in given:
                yield "ash-version:", str(given["ash-version"])


def _install_block_problems(block: Block, rules: InstallRules) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    if block.family == "shell":
        script = _shell_script_of(block)
        found += [(block.body_line + l, p) for l, p in rules.script_problems(script)]
    elif block.family == "dockerfile":
        for line, words in _dockerfile_commands(block.body):
            found += [
                (block.body_line + line, p) for p in rules.command_problems(words)
            ]
    elif block.lang == "groovy":
        in_steps: set[int] = set()
        for base, script in groovy_sh_scripts(block.body):
            in_steps |= set(range(base, base + script.count("\n") + 1))
            found += [
                (block.body_line + base + l, p)
                for l, p in rules.script_problems(script)
            ]
        # The rest of a Jenkinsfile, such as an environment { } spec string.
        for offset, (number, text) in enumerate(block.body_lines()):
            if offset not in in_steps:
                found += [
                    (number, p) for p in rules.text_problems(text, names_ash=False)
                ]
    elif block.family == "config":
        document, error = parse_config_text(block.body, block.lang)
        if error is not None:
            return found
        keys = OTHER_CONFIG_KINDS.get(block.config_kind) or set()
        scripts = list(_strings_under_keys(document, keys))
        for script in scripts:
            first = next((s for s in script.splitlines() if s.strip()), "")
            line = _body_line(block, first.strip())
            found += [(line + l, p) for l, p in rules.script_problems(script)]
        # Every other string, such as an env value holding the install spec.
        for text in _yaml_strings(document):
            if text in scripts:
                continue
            line = _body_line(block, text.splitlines()[0] if text else "")
            found += [(line, p) for p in rules.text_problems(text, names_ash=False)]
        for name, value in _config_ref_values(document):
            problem = rules.ref_problem(name, value, False)
            if problem:
                found.append((_body_line(block, value), problem))
    return found


def check_install_commands(
    files: Iterable[Path],
    root: Path = REPO_ROOT,
    code: Path | None = None,
    counts: dict[str, int] | None = None,
) -> list[Finding]:
    """Every install command names an extra, a Python and a ref that exist.

    Read in every shell block (illustrative ones too), Dockerfile, CI file and
    pre-commit config, every ``sh`` step and string of a Jenkinsfile, and every inline
    code span that starts with an install program or names ASH's package:

    * an extra, in ``automated-security-helper[...]``, ``.[...]`` or uv's ``--extra``,
      must be in [project.optional-dependencies] of the project it installs;
    * a ``--python`` (``-p`` for uv) must be within that project's requires-python;
    * an install ref, in any form scripts/version_template_manager.py lists in
      INSTALL_REF_FORMS, must be the current release, main, a full commit SHA, or the
      floating major tag on a page that says it moves;
    * a curl of the uv installer must follow redirects (-L).

    ``counts`` receives how many items each rule examined, keyed by INSTALL_RULES. A
    corpus with no install command at all is reported, since nothing was checked.
    """
    path = root / TEMPLATE_MANAGER
    if not path.is_file():
        return [
            Finding(
                "install", TEMPLATE_MANAGER, 1, "the template manager does not exist"
            )
        ]
    forms = _install_ref_forms(_load_by_path("_ash_version_template_manager", path))
    code = code or code_root(root)
    counts = {} if counts is None else counts
    version = current_version(str(root))
    findings: list[Finding] = []
    pages = load_pages(files, root)
    for page in pages:
        if page.rel in HISTORICAL_DOCS:
            continue
        rules = InstallRules(root, code, page, forms, version, counts)
        located: list[tuple[int, str]] = []
        for block in page.blocks:
            located += _install_block_problems(block, rules)
        for block in prose_code_blocks(page):
            located += _install_block_problems(block, rules)
        for number, text in page.prose:
            for span in inline_code_spans(text):
                first = span.split()[0] if span.split() else ""
                if first in _INSTALL_PROGRAMS or _REPOSITORY in span.lower():
                    located += [(number, p) for _l, p in rules.script_problems(span)]
        for line, problem in dict.fromkeys(located):
            findings.append(Finding("install", page.rel, line, problem))
    if not any(counts.get(rule) for rule in INSTALL_RULES):
        where = pages[0].rel if pages else TEMPLATE_MANAGER
        findings.append(
            Finding(
                "install",
                where,
                1,
                "found no install command in the docs (no extra, --python, ref or uv "
                "installer), so nothing was checked",
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
    if INSTALL_REFS_HOOK not in hooks:
        findings.append(
            Finding(
                "site",
                MKDOCS_YML,
                1,
                f"hooks does not list {INSTALL_REFS_HOOK}, so the install commands "
                "of the main version pin the last release",
            )
        )
    if not (root / INSTALL_REFS_HOOK).is_file():
        findings.append(
            Finding(
                "site", INSTALL_REFS_HOOK, 1, "the install refs hook does not exist"
            )
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
    findings += _workflow_findings(root)
    return findings


def _workflow_findings(root: Path) -> list[Finding]:
    """The build workflow builds strictly and checks the versions; the docs workflow
    deploys; neither replaces gh-pages with one unversioned build."""
    import yaml

    findings: list[Finding] = []
    documents: dict[str, Any] = {}
    for rel, what in (
        (DOCS_BUILD_WORKFLOW, "the workflow that builds the docs"),
        (DOCS_WORKFLOW, "the docs workflow"),
    ):
        path = root / rel
        if not path.is_file():
            findings.append(Finding("site", rel, 1, f"{what} does not exist"))
            continue
        documents[rel] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for rel, document in documents.items():
        for run in _strings_under_keys(document, {"run"}):
            if re.search(r"\bgh-deploy\b", run):
                findings.append(
                    Finding(
                        "site",
                        rel,
                        1,
                        f"'{run.strip()}' replaces the whole gh-pages branch with one "
                        "unversioned build, deleting every published version; deploy "
                        f"with {DOCS_VERSIONS_SCRIPT} deploy",
                    )
                )
    for rel, command, why in (
        (DOCS_WORKFLOW, "deploy", "no step publishes the site with it"),
        (DOCS_BUILD_WORKFLOW, "check", "no step checks the versioned site with it"),
    ):
        if rel not in documents:
            continue
        if not any(
            re.search(rf"{re.escape(DOCS_VERSIONS_SCRIPT)}\s+{command}\b", run)
            for run in _strings_under_keys(documents[rel], {"run"})
        ):
            findings.append(
                Finding(
                    "site",
                    rel,
                    1,
                    f"{DOCS_VERSIONS_SCRIPT} {command} is not run: {why}",
                )
            )
    if DOCS_BUILD_WORKFLOW in documents:
        findings += [
            Finding("site", DOCS_BUILD_WORKFLOW, 1, problem)
            for problem in _build_step_problems(documents[DOCS_BUILD_WORKFLOW])
        ]
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
    for path in listed_files(site.docs_dir, ["**/*.md"]):
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
    """Why the build workflow's mkdocs build step could pass with a failed build.

    That the job runs on every pull request, and that required-checks depends on it,
    is held by tests/unit/test_required_checks_census.py.
    """
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
