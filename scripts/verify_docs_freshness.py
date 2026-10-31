#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
CI check: verify documentation stays in sync with source code.

Run with: uv run python scripts/verify_docs_freshness.py

Exit code 0 if all checks pass, exit code 1 with a detailed report if any fail, and
exit code 2 if any check raised and so did not run (an ERROR line names it).
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths (relative to repo root)
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
MCP_SERVER_PY = REPO_ROOT / "automated_security_helper" / "cli" / "mcp_server.py"
PYPROJECT_TOML = REPO_ROOT / "pyproject.toml"
DOCS_DIR = REPO_ROOT / "docs"

# The name inventories (scanners, reporters, MCP tools) are compared against the
# reference pages, which scripts/generate_*.py write from the code. A row there is
# fixed by fixing the code or the generator and regenerating, never by editing the
# page: tests/unit/test_generated_docs_freshness.py fails when a page differs from
# its generator's output. These checks are the other half: the generator could
# itself drop or invent a name, and here the page is held against a second source
# (the config models, the plugin registry, the @mcp.tool decorators).
REFERENCE_DIR = DOCS_DIR / "content" / "reference"
SCANNERS_REFERENCE_MD = REFERENCE_DIR / "scanners.md"
REPORTERS_REFERENCE_MD = REFERENCE_DIR / "reporters.md"
MCP_TOOLS_REFERENCE_MD = REFERENCE_DIR / "mcp-tools.md"

# The version pin is checked in the generated files, not their templates:
# scripts/version_template_manager.py renders README.md.template and
# docs/content/how-to/install.md.template with the release version, so the
# rendered string exists only in the generated file. These are the two pages that
# tell a reader which ref to install.
README_MD = REPO_ROOT / "README.md"
INSTALL_MD = DOCS_DIR / "content" / "how-to" / "install.md"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def get_version_from_pyproject() -> str:
    """The version this repository releases, read from its designated authority.

    That authority is ``[tool.commitizen] version``, not ``[project] version``. This
    function used to read the latter, which made it a third opinion about the same fact:
    commitizen bumps from its own table -- ``version_provider`` is ``commitizen``, so
    ``CommitizenProvider`` reads it, and ``cz version --project`` in
    ``.github/workflows/ash-create-release.yml`` reports it -- while
    ``tests/unit/test_agent_plugin_ash_version.py`` and
    ``tests/unit/test_version_template_round_trip.py`` both read it too.

    The two fields agree today, but only because ``pyproject.toml:^version`` matches both
    lines so a bump moves them together, and because
    ``test_the_two_pyproject_version_fields_agree`` fails if a hand edit desyncs them.
    That is a guarantee held by a test, and reading the non-authoritative field meant this
    check's verdict depended on it. If the two ever diverge, the failure a maintainer needs
    to see is that one test, not this script reporting every doc stale against a version
    nothing releases.
    """
    text = read_text(PYPROJECT_TOML)

    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:  # pragma: no cover - only reachable on 3.10
        tomllib = None

    if tomllib:
        return tomllib.loads(text)["tool"]["commitizen"]["version"]

    # Regex fallback for 3.10, scoped to the commitizen table. An unscoped
    # `^version = "..."` search cannot express which field it wants: it returns whichever
    # comes first in the file, and [project] does, so the fallback would silently disagree
    # with the tomllib path above on exactly the divergence this function exists to avoid.
    table = re.search(
        r"^\[tool\.commitizen\]\n(.*?)(?=^\[|\Z)", text, re.MULTILINE | re.DOTALL
    )
    if not table:
        raise RuntimeError("pyproject.toml has no [tool.commitizen] table")
    m = re.search(r'^version\s*=\s*"([^"]+)"', table.group(1), re.MULTILINE)
    if not m:
        raise RuntimeError(
            "[tool.commitizen] in pyproject.toml has no version; that field is what "
            "`cz bump` moves, so there is nothing authoritative to check docs against"
        )
    return m.group(1)


# Directories that hold no prose a reader is ever sent to, or hold generated or
# vendored copies of prose that lives elsewhere. Everything else in the tree is
# in scope.
#
# Why an exclusion list rather than an inclusion list: the previous glob was
# `docs/**/*.md` plus README.md, which left skills/, examples/, quickstart/,
# SECURITY.md, CONTRIBUTING.md, DEVELOPMENT.md and every doc shipped inside the
# package outside every check here. A config example with an invented option key
# is exactly as wrong in examples/ as in docs/, and the reader is exactly as
# stuck. An inclusion list reproduces the bug the first time someone adds a
# directory, because the omission is silent.
_EXCLUDED_MD_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "site",  # mkdocs build output
        "public",  # configured MkDocs build output
        ".previews",
        "playwright-report",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        "test-results",
        "__pycache__",
        # Gitignored caches: the docs build's privacy plugin and the jsii package
        # cache the cdk-nag tests extract, which holds the README of every bundled
        # npm package. The docs-example runner would otherwise run their examples.
        ".cache",
        # syrupy's golden files. A markdown reporter snapshot is generated output, so
        # checking it as a docs page reports the fixture's text, not the docs.
        "__snapshots__",
    }
)

# Directories excluded by their path below REPO_ROOT, not by name, for prose that
# is a dated record rather than documentation a reader is sent to.
_EXCLUDED_MD_PATHS = (
    # ferret-scan's spec/ notes are the analysis and work log of one upgrade,
    # kept as their authors wrote them. They quote ferret-scan's own flags and
    # its earlier behavior, which the checks here would report as ASH options
    # and as current claims. The plugin's README.md and DEVELOPMENT.md beside
    # them are documentation and stay in the corpus.
    "automated_security_helper/plugin_modules/ash_ferret_plugins/spec/",
)


def collect_md_files() -> list[Path]:
    """Collect every doc in the repository that a reader might be sent to.

    Deliberately repo-wide. Measured when this was widened from
    ``docs/**/*.md`` + README.md: 86 files before, 179 after, and the three
    checks that consume this list reported zero new failures -- so the narrow
    glob was not holding anything back, it was simply not looking.

    ``.md.template`` files are included alongside the ``.md`` files they render
    to. Ten docs in this repository are generated from a sibling template, and
    the template is the file an edit has to land in -- a fix applied only to the
    rendered doc is discarded at the next release. Checking both means a stale
    list in a template is reported against the template's own path.

    This is not redundant with tests/unit/test_version_template_round_trip.py,
    which asserts doc == rendered template. That test makes the two agree; it
    does not know whether what they agree on is correct. Including templates here
    is also what caught the omission that this docstring is the record of: the
    first version of this change edited docs/content/faq.md and not
    docs/content/faq.md.template, and the round-trip test is what noticed.

    The exclusions are matched against the path below REPO_ROOT (the docs root with
    --docs-root), never the absolute path: a checkout that itself sits under a
    directory named .cache, site or venv used to collect nothing, and every check
    reading the corpus then passed on zero files. An empty corpus raises instead.

    The list comes from git (docs_checks.listed_files): every tracked file, plus every
    untracked one that is not ignored, so a new doc is checked before it is added. git
    never enters an ignored directory. A walk did, and the unit tests call this on the
    real checkout under xdist: ``REPO_ROOT.rglob`` descended into tests/pytest-temp,
    which is ignored, while other workers created and removed directories there. It
    raised FileNotFoundError when one went away mid-walk, and it returned the markdown
    those workers had written. tests/unit/test_repo_walkers_skip_scratch.py shows both.
    A tree git cannot list raises here rather than yielding no docs.
    """
    files = [
        path
        for path in _docs_checks().listed_files(
            REPO_ROOT, ["**/*.md", "**/*.md.template"]
        )
        if not _EXCLUDED_MD_DIRS.intersection(path.relative_to(REPO_ROOT).parts[:-1])
        and not path.relative_to(REPO_ROOT).as_posix().startswith(_EXCLUDED_MD_PATHS)
    ]
    if not files:
        raise RuntimeError(
            f"no markdown files were collected under {REPO_ROOT}, so every check "
            "that reads the docs would pass on nothing"
        )
    return sorted(set(files))


# ---------------------------------------------------------------------------
# Shared helpers for the name-inventory checks
# ---------------------------------------------------------------------------

_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")


def normalize_name(text: str) -> str:
    """Fold a name to its comparable core: link label, alphanumerics, lowercase.

    The docs and the code legitimately spell the same plugin differently --
    ``cfn_nag`` in a README link label against the ``cfn-nag`` config key,
    ``JUnit XML`` in a table against the ``junitxml`` field. Comparing on
    alphanumerics alone accepts those and nothing looser: it still separates
    ``sarif`` from ``ocsf``. Link URLs are dropped first, because
    ``[Bandit](https://github.com/PyCQA/bandit)`` would otherwise match any name
    that happens to appear in a URL.
    """
    return re.sub(r"[^a-z0-9]+", "", _MD_LINK.sub(r"\1", text).lower())


_TRAILING_PARENTHETICAL = re.compile(r"\s*\([^()]*\)\s*$")


def _row_name(row: str) -> str:
    """A table row's first cell without a trailing parenthetical qualifier."""
    return _TRAILING_PARENTHETICAL.sub("", row.strip())


class _EnvReference(str):
    """The text of an ``!ENV`` scalar, marked so value validation can skip it.

    ASH substitutes the variable before it validates the config, so the
    documented ``${VAR}`` text is not the value the field will hold: an
    ``!ENV`` on an int, bool, enum or patterned string field is valid config
    that would fail ``model_validate`` here. The key still has to be a field of
    the model, so the text is kept (it compares equal to a plain str) and only
    the value check leaves it out.
    """

    __slots__ = ()


def _options_loader():
    """A SafeLoader that keeps an ``!ENV`` scalar as its own text."""
    import yaml

    class _KeepsEnvTag(yaml.SafeLoader):
        pass

    _KeepsEnvTag.add_constructor(
        "!ENV", lambda loader, node: _EnvReference(loader.construct_scalar(node))
    )
    return _KeepsEnvTag


def _load_options_yaml(body: str):
    """Parse a documented YAML block, keeping an ``!ENV`` scalar as its own text.

    ``yaml.safe_load`` raises on ASH's ``!ENV`` tag, and that error used to be read
    as a deliberately invalid block, so every options block that referenced the
    environment was skipped and its option keys were never validated. The tag is
    the config's own syntax, so it is accepted here as text; YAML that does not
    parse still returns None.
    """
    import yaml

    try:
        return yaml.load(body, Loader=_options_loader())  # nosec B506 - a SafeLoader subclass
    except yaml.YAMLError:
        return None


def _load_options_documents(body: str) -> list:
    """Every document of a documented YAML block, read as ``_load_options_yaml`` reads one.

    A block holding two documents (a ``---`` between two configs) raised in the
    single-document load and was skipped as deliberately invalid YAML, so neither
    document's option keys were checked. YAML that does not parse yields no
    document.
    """
    import yaml

    try:
        return list(yaml.load_all(body, Loader=_options_loader()))  # nosec B506 - a SafeLoader subclass
    except yaml.YAMLError:
        return []


def _alias_names(alias: object) -> list[str]:
    """The key spellings a pydantic alias declaration accepts."""
    if alias is None:
        return []
    if isinstance(alias, str):
        return [alias]
    choices = getattr(alias, "choices", None)
    if choices is not None:
        names: list[str] = []
        for choice in choices:
            names.extend(_alias_names(choice))
        return names
    path = getattr(alias, "path", None)
    if path:
        return [str(path[0])]
    return []


def _accepted_option_keys(model: type) -> set[str]:
    """The field names of an options model plus every alias the runtime reads.

    The key test used to consult ``model_fields`` names only, while a model may
    declare an ``alias`` or a ``validation_alias`` and ASH reads a config written
    under either, so an option documented under its alias was reported as one
    the plugin does not declare.
    """
    keys: set[str] = set()
    for name, info in model.model_fields.items():
        keys.add(name)
        keys.update(_alias_names(getattr(info, "alias", None)))
        keys.update(_alias_names(getattr(info, "validation_alias", None)))
    return keys


def _validation_detail(exc: Exception) -> str:
    """The first validation error as ``<field>: <message>``.

    The detail used to be the first non-empty line after pydantic's title line,
    which for a wrong value is the field-location line alone, so the report
    named the field and not what was wrong with its value.
    """
    errors = getattr(exc, "errors", None)
    if callable(errors):
        for error in errors():
            location = ".".join(str(part) for part in error.get("loc", ()))
            message = str(error.get("msg", "")).strip()
            return f"{location or 'options'}: {message}".rstrip(": ")
    return str(exc).splitlines()[0]


def _model_for(models: dict[str, type], plugin_name: str) -> type | None:
    """The options model for a documented plugin key, under either spelling.

    ASH accepts ``cdk_nag`` and ``cdk-nag`` for one scanner (the config field and
    its alias), and the docs use both. Looking the model up by the exact key
    skipped every block written under the spelling the registry does not use, so
    four documented scanner blocks were never validated.
    """
    for candidate in (
        plugin_name,
        plugin_name.replace("_", "-"),
        plugin_name.replace("-", "_"),
    ):
        model = models.get(candidate)
        if model is not None:
            return model
    return None


def _is_delimiter_row(line: str) -> bool:
    """Whether ``line`` is a markdown table delimiter row such as ``|---|:--:|``.

    A delimiter row is non-empty and holds at least one dash and one pipe. The
    subset test alone passed a blank line, because the empty set is a subset of
    anything, so a data row whose first entry matched the header text and sat
    before a blank line was taken as a header row.
    """
    stripped = line.strip()
    return (
        bool(stripped)
        and "-" in stripped
        and "|" in stripped
        and set(stripped) <= set("|-: ")
    )


def table_first_column(text: str, header_cell: str) -> list[str] | None:
    """Return the first cell of each data row of one specific markdown table.

    The table is located by the exact text of its first header cell. Returns
    ``None`` when no such table exists, which callers MUST treat as a failure --
    a whole-file substring search was what let a flag mentioned only in a
    deprecation note count as documented, and silently finding no table would
    reintroduce the same vacuity in a new place.
    """
    lines = text.splitlines()
    want = header_cell.strip().lower()

    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if not cells or cells[0].lower() != want:
            continue
        # A header row is only a header row when a delimiter row follows it. A
        # data row named like the header, followed by a blank line at its table's
        # end, used to pass as one and shadow the real table.
        if index + 1 >= len(lines):
            continue
        if not _is_delimiter_row(lines[index + 1]):
            continue

        rows: list[str] = []
        for row in lines[index + 2 :]:
            candidate = row.strip()
            if not candidate.startswith("|"):
                break
            first = candidate.strip("|").split("|")[0].strip()
            if first:
                rows.append(first)
        return rows

    return None


def compare_inventories(
    label: str,
    code_names: dict[str, str],
    doc_text: str,
    header_cell: str,
    doc_label: str,
) -> list[str]:
    """Compare a code-derived inventory against one published table, BOTH ways.

    ``code_names`` maps the user-facing name to the thing it came from, for the
    failure message.

    Both directions, because only one of them was ever checked. code-to-docs
    catches a plugin shipped without a mention. docs-to-code catches a row that
    names something removed -- a promise to a reader that nothing keeps, and the
    direction that was silently passing.
    """
    failures: list[str] = []

    rows = table_first_column(doc_text, header_cell)
    if rows is None:
        return [
            (
                f"{label}: {doc_label} has no table whose first header cell is "
                f"'{header_cell}'. The table was renamed, moved or removed; this "
                f"check cannot run and must not report success."
            )
        ]
    if not rows:
        return [
            (
                f"{label}: the '{header_cell}' table in {doc_label} has no data "
                f"rows, so every comparison against it would pass trivially."
            )
        ]

    # Whole names, never substrings. A substring test let one row cover two
    # names whenever one name contained another: a table with only a
    # gitlab-cyclonedx row satisfied the cyclonedx entry, and a leftover
    # cyclonedx row was covered by the gitlab-cyclonedx entry, so a missing or
    # stale row was hidden in both directions. A trailing parenthetical on a
    # row ("cfn-nag (CloudFormation)") is not part of the name.
    normalized_rows = {row: normalize_name(_row_name(row)) for row in rows}
    normalized_code = {name: normalize_name(name) for name in code_names}

    for name, origin in sorted(code_names.items()):
        needle = normalized_code[name]
        if needle not in normalized_rows.values():
            failures.append(
                f"{label}: '{name}' (from {origin}) is in the code but no row of "
                f"the '{header_cell}' table in {doc_label} names it"
            )

    for row, normalized in sorted(normalized_rows.items()):
        if normalized not in normalized_code.values():
            failures.append(
                f"{label}: the '{header_cell}' table in {doc_label} has a row "
                f"'{row}' that names nothing in the code -- it was removed or "
                f"renamed and the row was left behind"
            )

    return failures


# ---------------------------------------------------------------------------
# CLI options: no check here
# ---------------------------------------------------------------------------
#
# "CLI flags in docs match source" grepped scan.py for --flags and required each to
# appear somewhere in the hand-written docs/content/docs/cli-reference.md. That
# page is gone. Its replacement, docs/content/reference/cli.md, is written by
# scripts/generate_cli_docs.py from the click tree of every command, and
# tests/unit/test_generated_docs_freshness.py fails when the page differs from the
# generator's output, so every option of every command is on it by construction.
# Every other mention of an option in the docs is parsed and checked against the
# same click tree by "ASH commands in docs match the CLI" (docs_checks.check_cli).
# A grep of one command's source file against the generated page would be a weaker
# copy of the freshness test.


# ---------------------------------------------------------------------------
# Check 1: Reporter list in docs matches code
# ---------------------------------------------------------------------------


def _segment_names(segment: type) -> dict[str, str]:
    """Map each plugin's user-facing name to the config field that declares it."""
    names: dict[str, str] = {}
    for field_name, field_info in segment.model_fields.items():
        display_name = field_info.alias or field_name.replace("_", "-")
        names[display_name] = f"field {field_name}"
    return names


REPORTER_DOCS_GENERATOR = REPO_ROOT / "scripts" / "generate_reporter_docs.py"
_reporter_generator_module = None


def _reporter_generator():
    """Load scripts/generate_reporter_docs.py by path, once.

    By path because scripts/ is not a package, and this module is itself loaded
    by path in the unit tests, where scripts/ is not on sys.path.
    """
    global _reporter_generator_module
    if _reporter_generator_module is None:
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "_ash_generate_reporter_docs", REPORTER_DOCS_GENERATOR
        )
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load {REPORTER_DOCS_GENERATOR}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _reporter_generator_module = module
    return _reporter_generator_module


def reporter_names() -> dict[str, str]:
    """Map each registered reporter's name to the class that registers it.

    Read through the doc generator's own ``registered_reporters()``, which is
    what writes the reporter-quick-reference table this check compares against.

    This used to read the fields declared on ``ReporterConfigSegment``. That is
    a different source, and the generator's docstring lists it among the seven
    places that stated the reporter set and disagreed. It lagged the registry for
    any reporter configured only through the segment's ``extra="allow"``:
    ``unused-suppressions`` was registered, got a generated row, and had no
    declared field, so this check reported the generated row as a leftover for a
    removed reporter while ``generate_reporter_docs.py --check`` required it.
    The two gates could not both pass. Calling the generator's function, rather
    than re-deriving the registry here, is what keeps them from diverging again.

    Whether every built-in reporter is also a declared field (and so appears in
    the published AshConfig.json schema) is a property of the config model, not
    of the docs, so it is not checked here. It is pinned in both directions by
    test_declared_reporter_fields_match_the_builtin_registry in
    tests/unit/test_docs_freshness_gate_can_fail.py.
    """
    rows = _reporter_generator().registered_reporters()
    return {row["name"]: f"registered class {row['class_name']}" for row in rows}


def check_reporters() -> list[str]:
    """The registered reporter set and the built-in reporters table must be the same set.

    The first table headed Reporter in reference/reporters.md lists the built-in
    reporters; the plugin-module reporters come in a second table after it.
    """
    names = reporter_names()
    if not names:
        return [
            (
                "Reporter: the plugin registry returned no reporters, so there is "
                "nothing to compare the reporters reference against"
            )
        ]

    return compare_inventories(
        "Reporter",
        names,
        read_text(REPORTERS_REFERENCE_MD),
        "Reporter",
        "docs/content/reference/reporters.md",
    )


# ---------------------------------------------------------------------------
# Check 2: Scanner list in docs matches code
# ---------------------------------------------------------------------------


def scanner_names() -> dict[str, str]:
    """Every scanner ASH ships, by config name: the fields of ScannerConfigSegment
    (the built-in scanners) and the scanner config classes of the community plugin
    modules in the package, which are configured under the same ``scanners`` key."""
    from automated_security_helper.config.ash_config import ScannerConfigSegment

    names = _segment_names(ScannerConfigSegment)
    models = _docs_checks().load_config_models()
    for name, config_cls in sorted(models.plugin_configs.get("scanners", {}).items()):
        names.setdefault(name, f"{config_cls.__module__}.{config_cls.__name__}")
    return names


def check_scanners() -> list[str]:
    """The scanners ASH ships and the scanners reference's inventory must be the same set.

    The three "variants" this used to try were one variant and two no-ops: the
    third was ``field_name.replace("_", "_")``, which is the field name
    unchanged, and the first two collapsed to the same string for every scanner
    ASH ships. All three were whole-file substring tests against the generated
    README, so `bandit` matched the word inside an unrelated code sample.
    normalize_name plus a table-scoped comparison replaces all of it.
    """
    names = scanner_names()
    _print_skipped(_docs_checks().load_config_models().skipped_notes())
    return compare_inventories(
        "Scanner",
        names,
        read_text(SCANNERS_REFERENCE_MD),
        "Scanner",
        "docs/content/reference/scanners.md",
    )


# ---------------------------------------------------------------------------
# Check 3: MCP tool names in docs match code
# ---------------------------------------------------------------------------


def mcp_tool_names() -> dict[str, str]:
    """Return every function decorated with ``@mcp.tool``, found by parsing.

    Parsed rather than matched. The regex this replaced required ``@mcp.tool()``
    to be followed by ``async def``, so it found 19 of the 21 registered tools:
    ``list_scanners`` and ``validate_config`` are plain ``def`` and were
    invisible to it. A decorator is a property of the function, not of the line
    after it, so the only way to read it correctly is from the syntax tree.

    Accepts both ``@mcp.tool`` and ``@mcp.tool(...)``, since either registers. A
    ``name=`` argument to the decorator is the name the tool is registered under,
    and the one the reference documents; the function's own name was taken
    before, so such a tool was demanded of the page under a name no client sees.
    """
    tree = ast.parse(read_text(MCP_SERVER_PY))
    names: dict[str, str] = {}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if (
                isinstance(target, ast.Attribute)
                and target.attr == "tool"
                and isinstance(target.value, ast.Name)
                and target.value.id == "mcp"
            ):
                registered = _registered_tool_name(decorator, node.name)
                names[registered] = f"mcp_server.py:{node.lineno}"
                break

    return names


def _registered_tool_name(decorator: ast.expr, function_name: str) -> str:
    """The name ``@mcp.tool`` registers: its ``name=`` argument, else the function's."""
    if isinstance(decorator, ast.Call):
        for keyword in decorator.keywords:
            if (
                keyword.arg == "name"
                and isinstance(keyword.value, ast.Constant)
                and isinstance(keyword.value.value, str)
            ):
                return keyword.value.value
    return function_name


#: A tool's section in the MCP tools reference: ``## run_ash_scan``.
_TOOL_HEADING = re.compile(r"^## ([a-z][a-z0-9_]*)\s*$", re.MULTILINE)


def check_mcp_tools() -> list[str]:
    """The registered MCP tool set and the MCP tools reference's sections must be the
    same set. The reference gives each tool a ``## <tool>`` section; other sections
    (Resources, Severity levels) are not identifiers and are not compared.

    Overlaps deliberately with tests/unit/cli/mcp/test_tool_surface_parity.py,
    and neither subsumes the other. That test derives the registered side from
    ``await mcp.list_tools()`` -- the runtime answer a client receives, which is
    stronger than any parse -- but it needs the package importable and runs in
    the unit suite. This runs in the lint job with the docs checks, where a
    documentation-only pull request gets its answer. The shared property is the
    set of names; if they ever disagree, the runtime one is right.
    """
    tools = mcp_tool_names()
    if not tools:
        return ["MCP tool inventory is empty; the parse found nothing to check"]
    label = "docs/content/reference/mcp-tools.md"
    sections = set(_TOOL_HEADING.findall(read_text(MCP_TOOLS_REFERENCE_MD)))
    if not sections:
        return [
            (
                f"MCP tool: {label} has no '## <tool>' sections. The page was "
                "renamed, moved or restructured; this check cannot run and must not "
                "report success."
            )
        ]
    failures = [
        f"MCP tool: '{name}' (from {origin}) is registered but {label} has no "
        f"'## {name}' section"
        for name, origin in sorted(tools.items())
        if name not in sections
    ]
    failures += [
        f"MCP tool: {label} has a '## {name}' section, but no @mcp.tool is named "
        f"{name}; it was removed or renamed and the section was left behind"
        for name in sorted(sections - set(tools))
    ]
    return failures


# ---------------------------------------------------------------------------
# Check 4: Version consistency
# ---------------------------------------------------------------------------


#: A release pin as the install pages write it, read as a whole token: ``@v3.7.0``
#: and whatever a tag carries after the patch number (``@v3.7.0-beta``,
#: ``@v3.7.0rc1``). Stopping at the patch number read a pre-release pin as the
#: release whose digits it starts with.
_VERSION_PIN = re.compile(r"@v\d[0-9A-Za-z.+-]*")


def _version_pins(content: str) -> list[str]:
    """Every ``@v...`` pin in ``content`` as a whole token, sentence punctuation dropped.

    Both the outdated-pin search and the presence test used to stop at the patch
    number, so ``@v3.0.0-beta.1`` satisfied a current ``@v3.0.0`` and was
    never reported as the stale pin it is.
    """
    return [match.rstrip(".,;:") for match in _VERSION_PIN.findall(content)]


def _is_floating_tag(pin: str, version: str) -> bool:
    """Whether ``pin`` is a moving major or minor tag of ``version``.

    The release process moves ``v3`` to each 3.x release, and the install pages
    document it beside the exact pin, so ``@v3`` (or ``@v3.7``) is current while
    the version it abbreviates is. A pre-release or build suffix is a tag of its
    own and never floats; an exact pin of another release is outdated.
    """
    parts = pin.removeprefix("@v").split(".")
    current = version.split(".")
    if not parts or len(parts) >= len(current):
        return False
    if not all(part.isdigit() for part in parts):
        return False
    return parts == current[: len(parts)]


def check_version_consistency() -> list[str]:
    """Verify key docs files reference the current version."""
    failures: list[str] = []
    version = get_version_from_pyproject()
    version_tag = f"@v{version}"

    files_to_check = [
        (README_MD, "README.md"),
        (INSTALL_MD, "docs/content/how-to/install.md"),
    ]

    for path, label in files_to_check:
        if not path.exists():
            failures.append(f"File {label} does not exist")
            continue
        pins = set(_version_pins(read_text(path)))
        # Every older pin is reported, whether or not the current one is also on the
        # page: a reader who copies the one stale command installs the wrong release.
        # A floating major or minor tag of the current version is not a stale pin.
        outdated = {
            pin
            for pin in pins
            if pin != version_tag and not _is_floating_tag(pin, version)
        }
        if outdated:
            failures.append(
                f"{label} references outdated version(s) {sorted(outdated)} "
                f"instead of {version_tag}"
            )
        elif version_tag not in pins:
            failures.append(f"{label} does not reference version {version_tag}")

    return failures


# ---------------------------------------------------------------------------
# Check 5: Config file path consistency
# ---------------------------------------------------------------------------


# A list item whose entire content is a code span holding a config file path:
# "1. `.ash/.ash.yaml`", "- `ash.yml`". The code span is required, so ordinary
# prose that happens to mention a filename is not mistaken for a published
# inventory.
_CONFIG_LIST_ITEM = re.compile(
    r"^\s*(?:[-*+]|\d+[.)])\s+`(?:\./)?(\.ash/)?"
    r"([A-Za-z0-9_.-]+\.(?:ya?ml|json|toml))`\s*$"
)


def _config_list_problems(
    rel_path: str,
    lines: list[str],
    supported: set[str],
    newer: set[str],
) -> tuple[list[str], int]:
    """Check every config-discovery list in one page; return (failures, lists).

    The ``.ash/`` prefix is kept, not stripped: ASH searches for the
    ASH_CONFIG_FILE_NAMES names under ``.ash/`` but discovers the ashrc names and
    pyproject.toml at the project root only, so a list placing one of those
    under ``.ash/`` sends a reader to a file ASH never reads there. Stripping the
    prefix before comparing let exactly that list pass.
    """
    failures: list[str] = []
    lists_found = 0
    run: list[tuple[int, str, str]] = []

    def close_run() -> None:
        nonlocal lists_found, run
        # A run of one is a single example, not an inventory.
        if len(run) >= 2:
            lists_found += 1
            names = {name for _, _, name in run}
            start = run[0][0]

            missing = sorted(supported - names)
            if names & newer:
                missing += sorted(newer - names)
            if missing:
                failures.append(
                    f"{rel_path}:{start} publishes a config-discovery list of "
                    f"{len(names)} name(s) but omits {missing}, which ASH does "
                    f"search for (ASH_CONFIG_FILE_NAMES, or ASH_RC_FILE_NAMES and "
                    f"pyproject.toml). A reader cannot "
                    f"discover a working config filename from this list."
                )
            unknown = sorted(names - supported - newer)
            if unknown:
                failures.append(
                    f"{rel_path}:{start} publishes a config-discovery list "
                    f"naming {unknown}, which ASH does NOT search for "
                    f"(ASH_CONFIG_FILE_NAMES, ASH_RC_FILE_NAMES, pyproject.toml). "
                    f"A file with that name is "
                    f"silently ignored unless --config points at it."
                )
            misplaced = sorted(
                f"{prefix}{name}" for _, prefix, name in run if prefix and name in newer
            )
            if misplaced:
                failures.append(
                    f"{rel_path}:{start} publishes a config-discovery list placing "
                    f"{misplaced} under .ash/, where ASH never looks for them: the "
                    f"ashrc names and pyproject.toml are discovered at the project "
                    f"root only. A reader who puts the file there is silently ignored."
                )
        run = []

    for lineno, line in enumerate(lines, start=1):
        match = _CONFIG_LIST_ITEM.match(line)
        if match:
            run.append((lineno, match.group(1) or "", match.group(2)))
            continue
        # A blank line between items makes a loose list, not two lists. It used
        # to close the run, so a loose inventory was read as several runs of one
        # item and none of them was checked.
        if not line.strip():
            continue
        close_run()
    close_run()
    return failures, lists_found


def check_config_path() -> list[str]:
    """Every published config-discovery list must match ASH_CONFIG_FILE_NAMES.

    What this checks, and why it is the only form that can work
    -----------------------------------------------------------
    ASH_CONFIG_FILE_NAMES in core/constants.py is the set of names
    find_config_file() searches for automatically. It is NOT a restriction on
    what --config accepts, which is any path -- and the docs correctly reference
    around forty per-project config files (`.ash/terraform.yaml`,
    `.ash/production.yaml`, and so on) that are passed explicitly. So a check
    that flagged every `.ash/<name>` absent from the constant would report forty
    failures against correct documentation, which is why the earlier attempt at
    this check was neutered instead of fixed.

    What the constant genuinely constrains is the AUTO-DISCOVERY inventory, and
    the docs publish that inventory as a list in at least three places. Those
    lists are checkable, exactly, in both directions: a name in the list that ASH
    does not search for sends a reader to a file that will be ignored, and a name
    ASH searches for that the list omits hides a working option.

    This was a live defect when the check was written, not a hypothetical:
    configuration-guide.md and faq.md both published four of the six names,
    omitting the .json variants and the non-dotted `ash.*` forms entirely.

    The ashrc names and pyproject.toml (#313) are discovered after
    ASH_CONFIG_FILE_NAMES. A list may publish the older names alone, as the
    docs did before those existed, but a list that names any of the newer
    sources is the full inventory and must name all of them.
    """
    from automated_security_helper.core.constants import (
        ASH_CONFIG_FILE_NAMES,
        ASH_PYPROJECT_FILE_NAME,
        ASH_RC_FILE_NAMES,
    )

    failures: list[str] = []
    supported = set(ASH_CONFIG_FILE_NAMES)
    newer = set(ASH_RC_FILE_NAMES) | {ASH_PYPROJECT_FILE_NAME}
    lists_found = 0

    for md_file in collect_md_files():
        rel_path = md_file.relative_to(REPO_ROOT)
        lines = read_text(md_file).splitlines()
        # Group consecutive matching list items into one published inventory.
        page_failures, page_lists = _config_list_problems(
            str(rel_path), lines, supported, newer
        )
        failures.extend(page_failures)
        lists_found += page_lists

    if not lists_found:
        failures.append(
            "No config-discovery list was found in any markdown file. The docs "
            "published three; they have been reformatted or removed, and this "
            "check is no longer comparing anything."
        )

    return failures


# ---------------------------------------------------------------------------
# Check 6: Suppression field name
# ---------------------------------------------------------------------------


# A ``file_path`` mapping key: a YAML block key, optionally a list item; a quoted
# JSON key; or a key inside a flow mapping (``{rule_id: B101, file_path: x}``).
# An expression that merely ends in ``file_path:`` (a Python if-statement) is not
# a key, and a Python annotation ``file_path: str`` never reaches this regex,
# because only YAML and JSON blocks are read.
_FILE_PATH_KEY = re.compile(r"""(?:^\s*-?\s*|[{,]\s*)["']?file_path["']?\s*:(?:\s|$)""")

#: The fence languages a suppression example is written in. A block with no
#: language is read too; a Python or shell block never is.
_SUPPRESSION_BLOCK_LANGS = frozenset({"yaml", "yml", "json", "jsonc", "json5", ""})

#: The mapping key that makes a block a suppression config.
_SUPPRESSIONS_KEY = re.compile(
    r"""(?:^\s*|[{,]\s*)["']?suppressions["']?\s*:""", re.MULTILINE
)


def check_suppression_field_name() -> list[str]:
    """Flag docs using 'file_path:' as a suppression key (the key is 'path:').

    Read per fenced block, through the parser the other docs checks use, and only
    in YAML and JSON blocks that declare a ``suppressions`` mapping. The earlier
    form scanned every line of a page for a YAML-shaped key and then looked twenty
    lines around it for the substring ``suppress`` or ``rule_id``. That reported
    three correct shapes: a Python annotation ``file_path: str`` near the word
    ``rule_id``; ASH's own flat finding output, whose records carry ``file_path``,
    ``rule_id`` and ``is_suppressed`` fields side by side; and any config example
    within twenty lines of ``unused-suppressions``. It also missed a JSON or
    flow-mapping suppression written ``"file_path":``, which the block-style key
    regex never matched. The block is the context: a ``file_path`` key is a wrong
    suppression key when the same block configures ``suppressions``, and nothing
    about the lines around the block says so.
    """
    failures: list[str] = []

    for md_file in collect_md_files():
        page = _docs_checks().parse_page(md_file, REPO_ROOT, read_text(md_file))
        rel_path = md_file.relative_to(REPO_ROOT)
        for block in page.blocks:
            if (block.lang or "").lower() not in _SUPPRESSION_BLOCK_LANGS:
                continue
            if not _SUPPRESSIONS_KEY.search(block.body):
                continue
            for offset, line in enumerate(block.body.splitlines()):
                if _FILE_PATH_KEY.search(line):
                    failures.append(
                        f"{rel_path}:{block.body_line + offset} uses 'file_path:' as "
                        f"a suppression key (the key is 'path:')"
                    )

    return failures


# ---------------------------------------------------------------------------
# Check 7: documented plugin options exist and validate
# ---------------------------------------------------------------------------


def _plugin_option_models(
    config_suffix: str,
    options_base: type,
    package: object = None,
    notes: list[str] | None = None,
) -> dict[str, type]:
    """Map each built-in plugin's config name to its options model.

    Keyed on the ``name`` Literal of the plugin's config class, because that is the
    string a user actually writes in the config -- ``npm-audit``, not
    ``NpmAuditScanner``.

    Every module under ``plugin_modules`` is walked rather than filtering on a
    module-name suffix. Reporter and converter modules do not follow one naming
    convention (``s3_reporter.py`` but also ``github_ghas_reporter.py``,
    ``archive_converter.py``), and a suffix filter silently shrinks the model set,
    which would make this check pass by simply not knowing about a plugin.

    A module whose import raises ImportError is skipped and named in ``notes``:
    an optional dependency missing from this environment is not a documentation
    problem, but a check that passed without seeing a plugin has to say so, and
    the skip used to be silent. Any other exception propagates, so a built-in
    plugin broken at import makes the check ERROR instead of leaving its
    documented options unchecked behind a passing gate. ``package`` is the
    package to walk; the tests pass one of their own.
    """
    import importlib
    import pkgutil

    if package is None:
        from automated_security_helper import plugin_modules as package

    models: dict[str, type] = {}
    for mod in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
        try:
            module = importlib.import_module(mod.name)
        except ImportError as err:
            if notes is not None:
                notes.append(
                    f"{mod.name} did not import ({err}); the options it documents "
                    "are not checked in this environment"
                )
            continue

        config_name = None
        options_cls = None
        for attr in dir(module):
            obj = getattr(module, attr)
            if not isinstance(obj, type):
                continue
            if attr.endswith(config_suffix) and hasattr(obj, "model_fields"):
                field = obj.model_fields.get("name")
                if field is not None and field.default:
                    config_name = field.default
            elif attr.endswith("ConfigOptions") and issubclass(obj, options_base):
                options_cls = obj

        if config_name and options_cls is not None:
            models[config_name] = options_cls

    return models


def check_plugin_option_keys() -> list[str]:
    """Every documented <section>.<name>.options block must validate.

    Each option key in such a block must be a field of the plugin's options model,
    and the whole mapping must validate against that model. The check reports a key
    that is not a field whatever the model does with it, so it gives the same answer
    on an ASH that accepts the key and never reads it and on one that refuses the
    config.

    Why this check exists
    ---------------------
    A plugin never reads an option it does not declare. 46 invented option keys
    accumulated across the configuration guide and the built-in plugin pages --
    ``severity_level`` for bandit (the field is ``severity_threshold``), ``rules``
    and ``timeout`` for semgrep (``config`` and ``scan_timeout``), ``framework`` for
    checkov (``frameworks``), and others -- and a reader who copied one got nothing
    the page promised.

    Validating rather than only checking key names also catches wrong *values*,
    which fail loudly at runtime instead of silently: ``confidence_level`` is
    lowercase-only while ``severity_threshold`` is uppercase-only, and cdk-nag's
    ``nag_packs`` is an object of per-pack booleans rather than a list.

    All three plugin kinds are covered, not just scanners. Scanners were fixed first
    and reporters and converters were left, which hid 53 more invented reporter keys
    and 30 converter keys behind a passing check -- seven reporters (``csv``,
    ``cyclonedx``, ``html``, ``ocsf``, ``sarif``, ``spdx``, ``yaml``) and the
    ``archive`` converter expose *no* options at all, so every option documented for
    them was fictional.

    ``global_settings`` is deliberately not in this table: it sets
    ``extra="forbid"``, so a wrong key there is already a startup error rather than a
    silent no-op, and it has accumulated none.

    Only blocks that parse as a mapping with one of these section keys are
    considered, and only for plugins this build knows about, so a snippet documenting
    a third-party plugin is skipped rather than reported.

    A block marked ``config kind=ash-invalid`` is skipped. It shows a config ASH
    refuses, such as an option the plugin does not declare, and "Config blocks in
    docs validate" (docs_checks.config_block_problems) already requires that it be
    invalid, so a valid config marked that way is still reported. Blocks are found
    with docs_checks.parse_page, the parser that check and the docs runner use, so
    the three agree on which marker governs which block.
    """
    from automated_security_helper.base.options import (
        ConverterOptionsBase,
        ReporterOptionsBase,
        ScannerOptionsBase,
    )

    # (config section key, config class suffix, options base class)
    kinds = (
        ("scanners", "ScannerConfig", ScannerOptionsBase),
        ("reporters", "ReporterConfig", ReporterOptionsBase),
        ("converters", "ConverterConfig", ConverterOptionsBase),
    )

    failures: list[str] = []
    models: dict[str, dict[str, type]] = {}
    notes: list[str] = []
    for section, config_suffix, base in kinds:
        found = _plugin_option_models(config_suffix, base, notes=notes)
        if not found:
            return [f"Could not import any built-in {section} options model"]
        models[section] = found
    _print_skipped(sorted(set(notes)))

    for md_file in collect_md_files():
        page = _docs_checks().parse_page(md_file, REPO_ROOT, read_text(md_file))
        rel_path = md_file.relative_to(REPO_ROOT)

        for block in page.blocks:
            if block.lang not in ("yaml", "yml") or block.config_kind == "ash-invalid":
                continue
            line_no = block.body_line
            # Deliberately-invalid YAML is documented on purpose in places and
            # yields no document; an !ENV reference is valid ASH config and
            # parses. A block of several documents is checked document by
            # document.
            for parsed in _load_options_documents(block.body):
                if not isinstance(parsed, dict):
                    continue
                failures.extend(
                    _options_block_problems(
                        parsed, models, kinds, f"{rel_path}:~{line_no}"
                    )
                )

    return failures


def _options_block_problems(
    parsed: dict, models: dict[str, dict[str, type]], kinds, where: str
) -> list[str]:
    """The option-key and validation problems of one parsed config document."""
    from pydantic import ValidationError

    failures: list[str] = []
    for section, _config_suffix, _base in kinds:
        entries = parsed.get(section)
        if not isinstance(entries, dict):
            continue

        for plugin_name, plugin_cfg in entries.items():
            if not isinstance(plugin_cfg, dict):
                continue
            options = plugin_cfg.get("options")
            if not isinstance(options, dict):
                continue
            model = _model_for(models[section], plugin_name)
            if model is None:
                continue

            accepted = _accepted_option_keys(model)
            for key in options:
                if key not in accepted:
                    failures.append(
                        f"{where} {section}.{plugin_name}"
                        f".options.{key} is not a field of "
                        f"{model.__name__}. Use an option {plugin_name} "
                        "declares, or mark a block that shows the mistake "
                        "config kind=ash-invalid"
                    )

            # An !ENV value is substituted by ASH before it validates, so the
            # documented text is not what the field will hold; its key was
            # checked above, its value is left to the runtime. A required field
            # documented through !ENV would read as missing here; none of the
            # options models declares one, and such a block is marked
            # kind=ash-invalid if it ever has to be documented.
            concrete = {
                key: value
                for key, value in options.items()
                if not isinstance(value, _EnvReference)
            }
            try:
                model.model_validate(concrete)
            except ValidationError as exc:
                failures.append(
                    f"{where} {section}.{plugin_name}.options "
                    f"does not validate against {model.__name__}: "
                    f"{_validation_detail(exc)}"
                )
    return failures


# ---------------------------------------------------------------------------
# Checks 9-16: doc blocks, commands, environment variables, links, navigation
# ---------------------------------------------------------------------------
#
# Implemented in scripts/docs_checks.py, which the docs-example runner in
# tests/integration/docs/ loads too, so the checks and the runner agree on what a
# block and its marker are. Each wrapper below hands that module this script's corpus
# and root, so a test that monkeypatches collect_md_files or REPO_ROOT here steers
# these checks the same way it steers the eight above.

DOCS_CHECKS = REPO_ROOT / "scripts" / "docs_checks.py"
_docs_checks_module = None


def _docs_checks():
    """Load scripts/docs_checks.py by path, once.

    Registered in sys.modules before it runs: its dataclasses resolve their
    annotations through the module's entry there.
    """
    global _docs_checks_module
    name = "_ash_docs_checks"
    if _docs_checks_module is None and name in sys.modules:
        # The docs runner loads the same file under the same name; one module per
        # process, so a patch or a cache in one is seen by the other.
        _docs_checks_module = sys.modules[name]
    if _docs_checks_module is None:
        import importlib.util

        spec = importlib.util.spec_from_file_location(name, DOCS_CHECKS)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load {DOCS_CHECKS}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        _docs_checks_module = module
    return _docs_checks_module


def check_doc_markers() -> list[str]:
    return [str(f) for f in _docs_checks().check_markers(collect_md_files(), REPO_ROOT)]


def check_doc_cli() -> list[str]:
    return [str(f) for f in _docs_checks().check_cli(collect_md_files(), REPO_ROOT)]


#: Set by --verbose: checks that can say why something passed print it.
_VERBOSE = False


def _print_skipped(notes: list[str]) -> None:
    """What a check could not look at, printed whether or not --verbose is set.

    A plugin module that does not import (an optional extra that is not installed)
    is not a docs finding, but a check that passes without having seen its plugins
    has to say so.
    """
    for note in notes:
        print(f"        skipped: {note}")


def check_doc_env_vars() -> list[str]:
    notes: list[str] | None = [] if _VERBOSE else None
    findings = _docs_checks().check_env_vars(collect_md_files(), REPO_ROOT, notes=notes)
    for note in notes or []:
        print(f"        note: {note}")
    return [str(f) for f in findings]


def check_doc_config_blocks() -> list[str]:
    notes: list[str] = []
    findings = _docs_checks().check_config_blocks(
        collect_md_files(), REPO_ROOT, notes=notes
    )
    _print_skipped(notes)
    return [str(f) for f in findings]


def check_doc_python_blocks() -> list[str]:
    return [
        str(f)
        for f in _docs_checks().check_python_blocks(collect_md_files(), REPO_ROOT)
    ]


def check_doc_links() -> list[str]:
    return [str(f) for f in _docs_checks().check_links(collect_md_files(), REPO_ROOT)]


def check_doc_nav() -> list[str]:
    return [str(f) for f in _docs_checks().check_nav(REPO_ROOT)]


def check_doc_site_build() -> list[str]:
    return [str(f) for f in _docs_checks().check_site_build(REPO_ROOT)]


def check_doc_release_placeholders() -> list[str]:
    return [str(f) for f in _docs_checks().check_release_placeholders(REPO_ROOT)]


def check_doc_code_links() -> list[str]:
    return [str(f) for f in _docs_checks().check_code_links(REPO_ROOT)]


def check_doc_mcp_contract() -> list[str]:
    notes: list[str] = []
    findings = _docs_checks().check_mcp_contract(
        collect_md_files(), REPO_ROOT, notes=notes
    )
    for note in notes:
        print(f"        note: {note}")
    return [str(f) for f in findings]


def check_doc_install_commands() -> list[str]:
    return [
        str(f)
        for f in _docs_checks().check_install_commands(collect_md_files(), REPO_ROOT)
    ]


def check_doc_option_tables() -> list[str]:
    notes: list[str] = []
    findings = _docs_checks().check_option_tables(
        collect_md_files(), REPO_ROOT, notes=notes
    )
    _print_skipped(notes)
    return [str(f) for f in findings]


def check_doc_report_files() -> list[str]:
    return [
        str(f) for f in _docs_checks().check_report_files(collect_md_files(), REPO_ROOT)
    ]


def check_doc_scanner_names() -> list[str]:
    notes: list[str] = []
    findings = _docs_checks().check_scanner_names(
        collect_md_files(), REPO_ROOT, notes=notes
    )
    for note in notes:
        print(f"        note: {note}")
    return [str(f) for f in findings]


def check_doc_session_variables() -> list[str]:
    return [
        str(f)
        for f in _docs_checks().check_session_variables(collect_md_files(), REPO_ROOT)
    ]


def check_doc_workflow_inputs() -> list[str]:
    notes: list[str] = []
    findings = _docs_checks().check_workflow_inputs(
        collect_md_files(), REPO_ROOT, notes=notes
    )
    for note in notes:
        print(f"        note: {note}")
    return [str(f) for f in findings]


# ---------------------------------------------------------------------------
# Docs from one tree, code from another
# ---------------------------------------------------------------------------
#
# A docs rewrite describes code that is not on main yet, so its pages have to be
# checked against another checkout's code. `--docs-root <tree>` reads every markdown
# file, the nav, mkdocs.yml and the redirect map from <tree>, while everything about
# the code comes from the ASH this interpreter imports: run it as
#
#     <code-tree>/.venv/bin/python <docs-tree>/scripts/verify_docs_freshness.py \
#         --docs-root <docs-tree>
#
# The path constants at the top of this file are rebased here rather than rewritten,
# so they stay the single statement of where each file is.

#: Constants naming a file the docs tree owns, and ones naming a package source file.
_DOCS_PATHS = (
    "README_MD",
    "DOCS_DIR",
    "REFERENCE_DIR",
    "SCANNERS_REFERENCE_MD",
    "REPORTERS_REFERENCE_MD",
    "MCP_TOOLS_REFERENCE_MD",
    "INSTALL_MD",
)
#: Code files, by their path inside the package, so a rebase never depends on where
#: the previous one put them.
_CODE_PATHS = {"MCP_SERVER_PY": Path("cli") / "mcp_server.py"}


def _use_trees(docs_root: Path) -> None:
    """Read docs from docs_root and code from the installed ASH, for every check."""
    names = globals()
    old_root = names["REPO_ROOT"]
    docs_root = docs_root.resolve()
    package = _docs_checks().installed_package_dir()
    code = _docs_checks().code_root(docs_root)
    for name in _DOCS_PATHS:
        names[name] = docs_root / names[name].relative_to(old_root)
    for name, inside in _CODE_PATHS.items():
        names[name] = package / inside
    names["PYPROJECT_TOML"] = code / "pyproject.toml"
    names["REPO_ROOT"] = docs_root


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument(
        "--docs-root",
        type=Path,
        help="check the docs in this checkout against the installed ASH's code "
        "(default: the checkout this script is in)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="also say which known set each accepted environment variable matched",
    )
    args = parser.parse_args(argv)
    global _VERBOSE
    _VERBOSE = args.verbose
    if args.docs_root is not None:
        _use_trees(args.docs_root)
    print(f"ASH package: {_docs_checks().installed_package_dir()}")
    print(f"Docs root:   {REPO_ROOT}")
    print()

    checks = [
        ("Reporter list in docs matches code", check_reporters),
        ("Scanner list in docs matches code", check_scanners),
        ("MCP tool names in docs match code", check_mcp_tools),
        ("Version consistency", check_version_consistency),
        ("Config file path consistency", check_config_path),
        ("Suppression field name", check_suppression_field_name),
        ("Plugin options in docs exist and validate", check_plugin_option_keys),
        ("Doc block markers are well formed", check_doc_markers),
        ("ASH commands in docs match the CLI", check_doc_cli),
        ("ASH environment variables in docs are read by ASH", check_doc_env_vars),
        ("Config blocks in docs validate", check_doc_config_blocks),
        ("Python blocks in docs parse and import", check_doc_python_blocks),
        ("Links and anchors in docs resolve", check_doc_links),
        ("Docs navigation and redirects resolve", check_doc_nav),
        ("Docs site build is strict, offline and versioned", check_doc_site_build),
        (
            "Release numbers in templates stay out of install commands",
            check_doc_release_placeholders,
        ),
        ("Docs links in the ASH source resolve", check_doc_code_links),
        (
            "Option tables and config paths in docs match the models",
            check_doc_option_tables,
        ),
        (
            "MCP error types and example responses in docs match the tools",
            check_doc_mcp_contract,
        ),
        (
            "Install commands in docs name real extras, Pythons and refs",
            check_doc_install_commands,
        ),
        ("Report file names in docs are files ASH writes", check_doc_report_files),
        (
            "Scanner names in docs tables are scanners ASH ships",
            check_doc_scanner_names,
        ),
        (
            "Shell variables in docs examples are set in the session that reads them",
            check_doc_session_variables,
        ),
        (
            "Values docs examples pass the scan workflow pass its input check",
            check_doc_workflow_inputs,
        ),
    ]

    all_failures: list[tuple[str, list[str]]] = []
    passed = 0
    failed = 0
    not_run = 0

    for name, check_fn in checks:
        try:
            failures = check_fn()
        except Exception as e:  # noqa: BLE001 -- reported as a check that did not run
            # Not a finding: the check never got as far as the docs. Printed apart
            # from findings, counted apart and exited on apart, so that two runs
            # where it raised the same way cannot compare as two runs that agree.
            not_run += 1
            print(f"ERROR {name}")
            print(f"        - the check did not run: {type(e).__name__}: {e}")
            continue

        if failures:
            failed += 1
            all_failures.append((name, failures))
            print(f"FAIL  {name}")
            for f in failures:
                print(f"        - {f}")
        else:
            passed += 1
            print(f"PASS  {name}")

    print()
    did_not_run = f"{not_run} did not run, " if not_run else ""
    print(
        f"Results: {passed} passed, {failed} failed, {did_not_run}"
        f"{passed + failed + not_run} total"
    )

    if all_failures:
        print()
        print("Documentation is out of sync with source code.")
        print("Fix the issues above and re-run this script.")

    if not_run:
        print()
        print("A check that did not run checked nothing, so its docs are unverified.")
        print("Fix what stopped it (the ERROR above) and re-run this script.")
        return 2

    if all_failures:
        return 1

    print()
    print("All documentation freshness checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
