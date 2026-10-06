#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
CI check: verify documentation stays in sync with source code.

Run with: uv run python scripts/verify_docs_freshness.py

Exit code 0 if all checks pass, exit code 1 with a detailed report if any fail.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths (relative to repo root)
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
MCP_SERVER_PY = REPO_ROOT / "automated_security_helper" / "cli" / "mcp_server.py"
PYPROJECT_TOML = REPO_ROOT / "pyproject.toml"
README_MD = REPO_ROOT / "README.md"

# README.md is GENERATED. scripts/version_template_manager.py renders
# README.md.template over it on every release that bumps the version, so an edit
# made to README.md alone is discarded at the next bump -- which is exactly what
# happened to a `@v3.0,1` typo fix that survived six releases (see
# tests/unit/test_version_template_round_trip.py for the measurement).
#
# Every check below that looks for a NAME therefore reads the template, so a
# contributor sent here by a failure edits the file that survives.
# check_version_consistency is the deliberate exception: it asserts the rendered
# version string, which by construction exists only in the generated file.
README_TEMPLATE_MD = REPO_ROOT / "README.md.template"
DOCS_DIR = REPO_ROOT / "docs"
CLI_REFERENCE_MD = DOCS_DIR / "content" / "docs" / "cli-reference.md"
OUTPUT_FORMATS_MD = DOCS_DIR / "content" / "docs" / "output-formats.md"
DOCS_INDEX_MD = DOCS_DIR / "content" / "index.md"

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
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        "test-results",
        "__pycache__",
    }
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
    """
    patterns = ("*.md", "*.md.template")
    files = [
        path
        for pattern in patterns
        for path in REPO_ROOT.rglob(pattern)
        if not _EXCLUDED_MD_DIRS.intersection(path.parts)
    ]
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
        # A header row is only a header row when a delimiter row follows it.
        if index + 1 >= len(lines):
            continue
        if not set(lines[index + 1].strip()) <= set("|-: "):
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

    normalized_rows = {row: normalize_name(row) for row in rows}
    normalized_code = {name: normalize_name(name) for name in code_names}

    for name, origin in sorted(code_names.items()):
        needle = normalized_code[name]
        if not any(needle in row for row in normalized_rows.values()):
            failures.append(
                f"{label}: '{name}' (from {origin}) is in the code but no row of "
                f"the '{header_cell}' table in {doc_label} names it"
            )

    for row, normalized in sorted(normalized_rows.items()):
        if not any(needle in normalized for needle in normalized_code.values()):
            failures.append(
                f"{label}: the '{header_cell}' table in {doc_label} has a row "
                f"'{row}' that names nothing in the code -- it was removed or "
                f"renamed and the row was left behind"
            )

    return failures


# ---------------------------------------------------------------------------
# Check 1: CLI flags in docs match source
# ---------------------------------------------------------------------------


def cli_option_spellings() -> set[str]:
    """Every option spelling the top-level scan surface actually exposes.

    Introspects the built click command rather than regexing scan.py. The regex
    it replaced had two blind spots that made this check pass while covering
    nothing:

    - Its pattern was ``"(--[a-z][a-z0-9-]*)"``, so it only ever saw long flags.
      Short forms -- ``-q``, ``-V``, ``-C``, ``-rev`` -- were invisible to it.
    - It could not see a spelling that is not a literal in the source. A boolean
      flag's negation is derived by typer from the parameter name, and the short
      form for the OFF side is declared as ``"  /-C"``, which no regex looking
      for a quoted flag will match.

    Scope is deliberately the root callback plus ``scan``, which is what scan.py
    defined and therefore what this check has always covered. Widening it to the
    whole command tree would surface 12 further undocumented spellings under
    ``config``, ``plugin`` and ``dependencies``; that is a real gap, but it is
    pre-existing and belongs in its own change.
    """
    import click
    import typer.main

    from automated_security_helper.cli.deprecations import CANONICAL_CLI_NAME
    from automated_security_helper.cli.main import app

    root = typer.main.get_command(app)
    ctx = click.Context(root, info_name=CANONICAL_CLI_NAME)
    scan = root.get_command(ctx, "scan")

    spellings: set[str] = set()
    for command in (root, scan):
        if command is None:
            continue
        for param in command.params:
            spellings.update(getattr(param, "opts", []) or [])
            spellings.update(getattr(param, "secondary_opts", []) or [])
    return {s for s in spellings if s.startswith("-")}


# Injected by the framework, not part of ASH's documented surface.
FRAMEWORK_SPELLINGS = frozenset(
    {"--help", "-h", "--install-completion", "--show-completion"}
)

# A count this check must not silently fall below. Without a floor, anything that
# makes introspection return an empty set -- an import error swallowed upstream, a
# renamed subcommand -- yields zero failures and reports PASS.
MIN_EXPECTED_SPELLINGS = 60


def flag_is_documented(flag: str, docs: str) -> bool:
    """True when ``flag`` appears in ``docs`` as a whole token.

    The substring test this replaced reported ``--ash-revision`` as documented
    because ``--ash-revision-to-install`` was in the table. Any flag that is a
    prefix of a longer one passed without being mentioned anywhere.
    """
    pattern = r"(?<![\w-])" + re.escape(flag) + r"(?![\w-])"
    return re.search(pattern, docs) is not None


def check_cli_flags(
    spellings: set[str] | None = None, docs: str | None = None
) -> list[str]:
    """Verify every option spelling on the scan surface appears in cli-reference.md.

    Both arguments exist so the negative control in
    tests/unit/test_verify_docs_freshness_cli_flags.py can hand this a docs body
    with a flag removed and confirm it actually fails. A gate with no such test
    is indistinguishable from one that cannot fail.
    """
    failures: list[str] = []
    if spellings is None:
        spellings = cli_option_spellings()
    if docs is None:
        docs = read_text(CLI_REFERENCE_MD)

    if len(spellings) < MIN_EXPECTED_SPELLINGS:
        failures.append(
            f"only {len(spellings)} CLI option spellings were found, expected at "
            f"least {MIN_EXPECTED_SPELLINGS}. The check cannot be trusted -- treat "
            f"this as a broken check rather than as clean docs."
        )
        return failures

    for flag in sorted(spellings):
        if flag in FRAMEWORK_SPELLINGS:
            continue
        if flag_is_documented(flag, docs):
            continue
        # A boolean flag's auto-derived negation is covered by its positive form:
        # typer generates --no-X from --X, and the docs describe the pair. This
        # replaces a hand-maintained skip list that had grown to hold --no-build,
        # --no-run, --no-progress and --no-color -- the last of which is why the
        # -c/--no-color divergence went unflagged for so long.
        if flag.startswith("--no-") and flag_is_documented("--" + flag[5:], docs):
            continue
        failures.append(
            f"CLI flag {flag} is exposed by the CLI but missing from cli-reference.md"
        )

    return failures


# ---------------------------------------------------------------------------
# Check 2: Reporter list in docs matches code
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
    """The registered reporter set and the output-formats table must be the same set."""
    names = reporter_names()
    if not names:
        return [
            (
                "Reporter: the plugin registry returned no reporters, so there is "
                "nothing to compare the output-formats table against"
            )
        ]

    return compare_inventories(
        "Reporter",
        names,
        read_text(OUTPUT_FORMATS_MD),
        "Format",
        "docs/content/docs/output-formats.md",
    )


# ---------------------------------------------------------------------------
# Check 3: Scanner list in docs matches code
# ---------------------------------------------------------------------------


def check_scanners() -> list[str]:
    """The scanner inventory and README's scanner table must be the same set.

    The three "variants" this used to try were one variant and two no-ops: the
    third was ``field_name.replace("_", "_")``, which is the field name
    unchanged, and the first two collapsed to the same string for every scanner
    ASH ships. All three were whole-file substring tests against the generated
    README, so `bandit` matched the word inside an unrelated code sample.
    normalize_name plus a table-scoped comparison replaces all of it.
    """
    from automated_security_helper.config.ash_config import ScannerConfigSegment

    return compare_inventories(
        "Scanner",
        _segment_names(ScannerConfigSegment),
        read_text(README_TEMPLATE_MD),
        "Scanner",
        "README.md.template",
    )


# ---------------------------------------------------------------------------
# Check 4: MCP tool names in docs match code
# ---------------------------------------------------------------------------


def mcp_tool_names() -> dict[str, str]:
    """Return every function decorated with ``@mcp.tool``, found by parsing.

    Parsed rather than matched. The regex this replaced required ``@mcp.tool()``
    to be followed by ``async def``, so it found 19 of the 21 registered tools:
    ``list_scanners`` and ``validate_config`` are plain ``def`` and were
    invisible to it. A decorator is a property of the function, not of the line
    after it, so the only way to read it correctly is from the syntax tree.

    Accepts both ``@mcp.tool`` and ``@mcp.tool(...)``, since either registers.
    """
    import ast

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
                names[node.name] = f"mcp_server.py:{node.lineno}"
                break

    return names


def check_mcp_tools() -> list[str]:
    """The registered MCP tool set and README's tool table must be the same set.

    Overlaps deliberately with tests/unit/cli/mcp/test_tool_surface_parity.py,
    and neither subsumes the other. That test derives the registered side from
    ``await mcp.list_tools()`` -- the runtime answer a client receives, which is
    stronger than any parse -- but it needs the package importable and runs in
    the unit suite. This runs in the lint job with the docs checks, where a
    documentation-only pull request gets its answer. The shared property is the
    set of names; if they ever disagree, the runtime one is right.
    """
    failures = ["MCP tool inventory is empty; the parse found nothing to check"]
    tools = mcp_tool_names()
    if not tools:
        return failures

    return compare_inventories(
        "MCP tool",
        tools,
        read_text(README_TEMPLATE_MD),
        "Tool",
        "README.md.template",
    )


# ---------------------------------------------------------------------------
# Check 5: Version consistency
# ---------------------------------------------------------------------------


def check_version_consistency() -> list[str]:
    """Verify key docs files reference the current version."""
    failures: list[str] = []
    version = get_version_from_pyproject()
    version_tag = f"@v{version}"

    files_to_check = [
        (README_MD, "README.md"),
        (DOCS_INDEX_MD, "docs/content/index.md"),
    ]

    for path, label in files_to_check:
        if not path.exists():
            failures.append(f"File {label} does not exist")
            continue
        content = read_text(path)
        if version_tag not in content:
            # Check if ANY version tag is present (might just be outdated)
            old_tags = re.findall(r"@v\d+\.\d+\.\d+", content)
            if old_tags:
                outdated = set(old_tags) - {version_tag}
                if outdated:
                    failures.append(
                        f"{label} references outdated version(s) {sorted(outdated)} "
                        f"instead of {version_tag}"
                    )
            else:
                failures.append(f"{label} does not reference version {version_tag}")

    return failures


# ---------------------------------------------------------------------------
# Check 6: Config file path consistency
# ---------------------------------------------------------------------------


# A list item whose entire content is a code span holding a config file path:
# "1. `.ash/.ash.yaml`", "- `ash.yml`". The code span is required, so ordinary
# prose that happens to mention a filename is not mistaken for a published
# inventory.
_CONFIG_LIST_ITEM = re.compile(
    r"^\s*(?:[-*+]|\d+[.)])\s+`(?:\./)?(?:\.ash/)?"
    r"([A-Za-z0-9_.-]+\.(?:ya?ml|json))`\s*$"
)


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
    """
    from automated_security_helper.core.constants import ASH_CONFIG_FILE_NAMES

    failures: list[str] = []
    supported = set(ASH_CONFIG_FILE_NAMES)
    lists_found = 0

    for md_file in collect_md_files():
        rel_path = md_file.relative_to(REPO_ROOT)
        lines = read_text(md_file).splitlines()

        # Group consecutive matching list items into one published inventory.
        run: list[tuple[int, str]] = []
        for lineno, line in enumerate(lines + [""], start=1):
            match = _CONFIG_LIST_ITEM.match(line)
            if match:
                run.append((lineno, match.group(1)))
                continue

            # A run of one is a single example, not an inventory.
            if len(run) >= 2:
                lists_found += 1
                names = {name for _, name in run}
                start = run[0][0]

                missing = sorted(supported - names)
                if missing:
                    failures.append(
                        f"{rel_path}:{start} publishes a config-discovery list of "
                        f"{len(names)} name(s) but omits {missing}, which ASH does "
                        f"search for (ASH_CONFIG_FILE_NAMES). A reader cannot "
                        f"discover a working config filename from this list."
                    )
                unknown = sorted(names - supported)
                if unknown:
                    failures.append(
                        f"{rel_path}:{start} publishes a config-discovery list "
                        f"naming {unknown}, which ASH does NOT search for "
                        f"(ASH_CONFIG_FILE_NAMES). A file with that name is "
                        f"silently ignored unless --config points at it."
                    )
            run = []

    if not lists_found:
        failures.append(
            "No config-discovery list was found in any markdown file. The docs "
            "published three; they have been reformatted or removed, and this "
            "check is no longer comparing anything."
        )

    return failures


# ---------------------------------------------------------------------------
# Check 7: Suppression field name
# ---------------------------------------------------------------------------


# Matches a YAML mapping key "file_path:", optionally as a list item, and not
# an expression that merely ends in "file_path:" (Python if-statements etc).
_YAML_FILE_PATH_KEY = re.compile(r"^\s*-?\s*file_path\s*:(\s|$)")


def check_suppression_field_name() -> list[str]:
    """Flag docs using 'file_path:' in suppression context (should be 'path:')."""
    failures: list[str] = []

    for md_file in collect_md_files():
        content = read_text(md_file)
        lines = content.splitlines()

        for i, line in enumerate(lines):
            # Only flag YAML mapping keys. A bare substring test also matches
            # Python inside fenced code blocks, e.g. "if rule_id and file_path:",
            # where file_path is a local variable and the colon ends an if-statement.
            if not _YAML_FILE_PATH_KEY.match(line):
                continue

            # Check surrounding context (20 lines before/after) for suppression keywords
            context_start = max(0, i - 20)
            context_end = min(len(lines), i + 20)
            context_block = "\n".join(lines[context_start:context_end]).lower()

            if "suppress" in context_block or "rule_id" in context_block:
                rel_path = md_file.relative_to(REPO_ROOT)
                failures.append(
                    f"{rel_path}:{i + 1} uses 'file_path:' in suppression context "
                    f"(should be 'path:')"
                )

    return failures


# ---------------------------------------------------------------------------
# Check 8: documented plugin options exist and validate
# ---------------------------------------------------------------------------


def _plugin_option_models(config_suffix: str, options_base: type) -> dict[str, type]:
    """Map each built-in plugin's config name to its options model.

    Keyed on the ``name`` Literal of the plugin's config class, because that is the
    string a user actually writes in the config -- ``npm-audit``, not
    ``NpmAuditScanner``.

    Every module under ``plugin_modules`` is walked rather than filtering on a
    module-name suffix. Reporter and converter modules do not follow one naming
    convention (``s3_reporter.py`` but also ``github_ghas_reporter.py``,
    ``archive_converter.py``), and a suffix filter silently shrinks the model set,
    which would make this check pass by simply not knowing about a plugin.
    """
    import importlib
    import pkgutil

    from automated_security_helper import plugin_modules

    models: dict[str, type] = {}
    for mod in pkgutil.walk_packages(
        plugin_modules.__path__, plugin_modules.__name__ + "."
    ):
        try:
            module = importlib.import_module(mod.name)
        except Exception:  # noqa: BLE001, S112  # nosec B112 -- see below
            # Deliberately broad and deliberately silent. A plugin module whose
            # optional dependency is missing in this environment is not a
            # documentation problem, and failing the docs gate on it would make
            # the gate depend on which extras happen to be installed.
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

    Why this check exists
    ---------------------
    The three options bases -- scanner, reporter, converter -- all set
    ``extra="allow"``, so an option name that does not
    exist is accepted and then never read. A reader who copies it gets no error and
    no effect. That let 46 invented option keys accumulate across the configuration
    guide and the built-in plugin pages -- ``severity_level`` for bandit (the field
    is ``severity_threshold``), ``rules`` and ``timeout`` for semgrep (``config`` and
    ``scan_timeout``), ``framework`` for checkov (``frameworks``), and others.

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
    """
    import yaml
    from pydantic import ValidationError

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
    for section, config_suffix, base in kinds:
        found = _plugin_option_models(config_suffix, base)
        if not found:
            return [f"Could not import any built-in {section} options model"]
        models[section] = found

    fence = re.compile(r"```ya?ml\n(.*?)```", re.DOTALL)

    for md_file in collect_md_files():
        content = read_text(md_file)
        rel_path = md_file.relative_to(REPO_ROOT)

        for block in fence.finditer(content):
            body = block.group(1)
            line_no = content[: block.start()].count("\n") + 2
            try:
                parsed = yaml.safe_load(body)
            except yaml.YAMLError:
                # Deliberately-invalid YAML is documented on purpose in places.
                continue
            if not isinstance(parsed, dict):
                continue

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
                    model = models[section].get(plugin_name)
                    if model is None:
                        continue

                    for key in options:
                        if key not in model.model_fields:
                            failures.append(
                                f"{rel_path}:~{line_no} {section}.{plugin_name}"
                                f".options.{key} is not a field on "
                                f"{model.__name__}; extra='allow' means it is "
                                f"accepted and ignored"
                            )

                    try:
                        model.model_validate(options)
                    except ValidationError as exc:
                        detail = next(
                            (
                                ln.strip()
                                for ln in str(exc).splitlines()[1:]
                                if ln.strip() and "further information" not in ln
                            ),
                            str(exc).splitlines()[0],
                        )
                        failures.append(
                            f"{rel_path}:~{line_no} {section}.{plugin_name}.options "
                            f"does not validate against {model.__name__}: {detail}"
                        )

    return failures


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    checks = [
        ("CLI flags in docs match source", check_cli_flags),
        ("Reporter list in docs matches code", check_reporters),
        ("Scanner list in docs matches code", check_scanners),
        ("MCP tool names in docs match code", check_mcp_tools),
        ("Version consistency", check_version_consistency),
        ("Config file path consistency", check_config_path),
        ("Suppression field name", check_suppression_field_name),
        ("Plugin options in docs exist and validate", check_plugin_option_keys),
    ]

    all_failures: list[tuple[str, list[str]]] = []
    passed = 0
    failed = 0

    for name, check_fn in checks:
        try:
            failures = check_fn()
        except Exception as e:
            failures = [f"Check raised an exception: {e}"]

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
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")

    if all_failures:
        print()
        print("Documentation is out of sync with source code.")
        print("Fix the issues above and re-run this script.")
        return 1

    print()
    print("All documentation freshness checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
