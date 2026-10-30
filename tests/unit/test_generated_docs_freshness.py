# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generated reference docs must match what their generators produce right now.

WHY THIS EXISTS
---------------
Three separate doc-vs-code divergences shipped because a generator existed but
nothing compared its output to what was committed, and because some reference
tables had no generator at all:

* ``docs/content/docs/cli-reference-generated.md`` was produced by
  ``scripts/generate_cli_docs.py`` and then drifted. Re-running the generator at
  the commit that added this module produced a file that differed from the
  committed one, so the published "auto-generated" page was not the generator's
  output. A generator whose output nobody diffs is a suggestion.

* The reporter inventory was stated in four docs and three code sites with six
  different counts. See ``scripts/generate_reporter_docs.py`` for the measured
  numbers.

* ``docs/content/docs/cli-reference.md`` documented five environment variables
  that do not exist anywhere in ``automated_security_helper/`` -- ``ASH_NO_COLOR``,
  ``ASH_QUIET``, and three ``ASH_CONTAINER_*`` names. These were invented rather
  than drifted, which is why no comparison against a previous version would have
  found them; only a comparison against the code does. The environment-variable
  reference is now generated from the code that reads each variable, and the docs
  doctest uses the same collector to refuse a name nothing reads.

* The committed reporters page said the S3 and CloudWatch reporters default to
  ``aws_region: us-west-2``. That was the ``AWS_REGION`` of the shell that
  generated it: the generators removed only ``ASH_*`` variables, and those
  defaults are ``os.environ.get("AWS_REGION", ...)``. A page has to be the same
  whatever environment it is generated in.

WHAT EACH TEST PINS, AND WHAT IT DOES NOT
-----------------------------------------
``test_reference_page_is_current`` runs each reference generator's ``--check``
in a fresh interpreter. It pins the whole rendered page, so a flag renamed, a
config key added, a variable read somewhere new or a scanner registered all
surface here. It does not check that a page is *good*, only that it is current.
A fresh interpreter rather than an in-process call because the plugin registry
is process-global (another test importing a plugin package changes what a
generator would see) and because each generator removes the variables the code
reads before importing ASH, which it can only do before the first import.

It runs every generator twice with :data:`PLANTED_ENVIRONMENT` set: the
variables whose values once leaked, or would, into a page (``AWS_REGION``,
``ASH_PROJECT_NAME``, ``XDG_CACHE_HOME``, ``COLUMNS``, ``TZ``, a C locale, ...),
a planted ``TMPDIR``, and fake scanner tools and container runtimes first on
``PATH`` that report a planted version. The two runs differ in the hash seed,
which reorders every set a generator might iterate, and in ``HOME``: the first
points it at an empty directory that must still be empty afterwards (a
generator builds every plugin, and building one once installed its tool into
the real home), the second at ``/d``, a home whose path occurs inside ordinary
words ("Enable/disable"). A generator that let any of it through would render
it and fail ``--check``, so the test proves the pages do not depend on the
environment they are generated in, rather than assuming CI's environment is
clean.

``test_docs_root_*`` runs a generator against a docs tree other than this
checkout, the way pages are generated from one tree's code into another tree's
docs: the page goes where ``--docs-root`` says, and the scanner page links to
exactly the per-scanner pages that tree holds.

The options-table and Default-cell tests pin the format the docs checks rely on
when they compare a prose table with these pages: each options table carries
``<!-- doctest: options of=<section>.<name> -->`` directly above it, and each
Default cell has one of the forms in ``generate_config_reference.py``.

One generator owns a file outside ``docs/content/reference/`` as well, and its
``--check`` covers it too: ``generate_mcp_tool_reference.py`` writes the agentic-plugins
``_base/references/tool-reference.md``, which closes a gap the ``agentic-plugins
check`` gate structurally cannot see: that gate rebuilds each plugin backend and
byte-compares the output trees against ``_base/``, proving the copies match the
source but not that the source matches ``mcp_server.py``. It was passing while
``_base/`` was 13 tools and 3 resources behind. After regenerating it, run
``uv run --project ash-agent-plugins/agentic-coding/transpiler agentic-plugins build``.

The ``read_env_names`` tests prove the collector behind the environment-variable
page can find each kind of read, and can refuse each kind of non-read, on a
planted tree, so the page being "current" means something.

Paths live in the constants below and in each generator's own constants. The
pages these tests used to read, ``docs/content/docs/cli-reference-generated.md``
and the hand-written ``docs/content/docs/cli-reference.md``, are no longer read by
any test.
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import textwrap
import types
from pathlib import Path
from typing import Literal, Optional, Union

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"
REFERENCE_DIR = REPO_ROOT / "docs" / "content" / "reference"

#: Every generated reference page: generator script -> the page it writes.
#: generate_mcp_tool_reference.py also owns the agentic-plugins tool-reference.md, and
#: its --check covers both files.
REFERENCE_PAGES = {
    "generate_cli_docs.py": "cli.md",
    "generate_config_reference.py": "configuration.md",
    "generate_converter_reference.py": "converters.md",
    "generate_env_var_reference.py": "environment-variables.md",
    "generate_mcp_tool_reference.py": "mcp-tools.md",
    "generate_reporter_docs.py": "reporters.md",
    "generate_scanner_reference.py": "scanners.md",
}
#: The pages with plugin options tables, and the config section each one documents.
OPTIONS_PAGES = {
    "scanners.md": "scanners",
    "reporters.md": "reporters",
    "converters.md": "converters",
}
#: Where a docs tree keeps per-scanner pages (as in generate_scanner_reference.py).
BUILTIN_SCANNER_PAGES = Path("docs/content/docs/plugins/builtin")
COMMUNITY_SCANNER_PAGES = Path("docs/content/docs/plugins/community")

#: Set for every generator run. Each one changes a default some page shows when
#: it leaks: AshConfig.project_name, the severity threshold, the AWS and Bedrock
#: reporter options, cache directories, CI detection, and click's usage width.
PLANTED_ENVIRONMENT = {
    "AWS_REGION": "eu-west-3",
    "AWS_DEFAULT_REGION": "ap-south-2",
    "AWS_PROFILE": "planted-profile",
    "ASH_PROJECT_NAME": "planted-project",
    "ASH_DEFAULT_SEVERITY_LEVEL": "LOW",
    "ASH_BEDROCK_MODEL_ID": "planted-model",
    "ASH_BEDROCK_MAX_TOKENS": "7",
    "XDG_CACHE_HOME": "/planted/xdg-cache",
    "CI": "true",
    "COLUMNS": "41",
    "TZ": "Pacific/Chatham",
    "LANG": "C",
    "LC_ALL": "C",
}
#: Programs a page could report a version of, if a generator ran them. Each fake
#: prints PLANTED_TOOL_VERSION.
PLANTED_TOOLS = (
    "actionlint",
    "bandit",
    "cdk",
    "cfn-guard",
    "cfn-lint",
    "checkov",
    "detect-secrets",
    "docker",
    "finch",
    "gitleaks",
    "grype",
    "nerdctl",
    "node",
    "npm",
    "opengrep",
    "podman",
    "semgrep",
    "syft",
    "trivy",
    "zizmor",
)
PLANTED_TOOL_VERSION = "99.9.9"
#: The two runs' hash seeds and homes: an empty directory (None here), then a home
#: whose path occurs inside words on the pages.
PLANTED_RUNS = (("1", None), ("2", "/d"))
#: Seconds one generator run may take. A generator that does not return fails the
#: test that ran it, naming the script, rather than holding the shard until the
#: job's own limit.
GENERATOR_TIMEOUT_S = 300


def _run_generator(
    script: str, *args: str, env: dict | None = None
) -> subprocess.CompletedProcess:
    if env is None:
        env = {**os.environ, **PLANTED_ENVIRONMENT}
    try:
        return subprocess.run(
            [sys.executable, str(SCRIPTS / script), *args],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            env=env,
            timeout=GENERATOR_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(
            f"scripts/{script} did not finish within {GENERATOR_TIMEOUT_S} s"
            f" (arguments: {' '.join(args) or 'none'}); it was killed"
        )


def _planted_tools(directory: Path) -> Path:
    """Fake tools that answer any arguments with the planted version, on any platform."""
    directory.mkdir(parents=True, exist_ok=True)
    for name in PLANTED_TOOLS:
        script = directory / name
        script.write_text(f"#!/bin/sh\necho {PLANTED_TOOL_VERSION}\n", encoding="utf-8")
        script.chmod(0o755)
        (directory / f"{name}.cmd").write_text(
            f"@echo {PLANTED_TOOL_VERSION}\n", encoding="utf-8"
        )
    return directory


def _planted_environment(root: Path, seed: str, home: str | None) -> tuple[dict, Path]:
    """The environment of one planted run, and the home it uses."""
    home_dir = Path(home) if home else root / "home"
    if home is None:
        home_dir.mkdir(parents=True)
    tmp = root / "planted-tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    tools = _planted_tools(root / "planted-bin")
    env = {
        **os.environ,
        **PLANTED_ENVIRONMENT,
        "PYTHONHASHSEED": seed,
        "HOME": str(home_dir),
        "TMPDIR": str(tmp),
        "PATH": os.pathsep.join([str(tools), os.environ.get("PATH", "")]),
    }
    if os.name == "nt":
        env["USERPROFILE"] = str(home_dir)
    return env, home_dir


@pytest.mark.integration
@pytest.mark.parametrize("script", sorted(REFERENCE_PAGES))
def test_reference_page_is_current(script: str, tmp_path: Path) -> None:
    """The committed reference page equals what its generator emits now, twice.

    Each run plants the environment above with its own hash seed and home. After
    the first, the empty home it pointed at must still be empty.
    """
    page = REFERENCE_DIR / REFERENCE_PAGES[script]
    assert page.is_file(), f"{page.relative_to(REPO_ROOT)} is missing"
    for seed, home in PLANTED_RUNS:
        env, home_dir = _planted_environment(tmp_path / f"run-{seed}", seed, home)
        result = _run_generator(script, "--check", env=env)
        assert result.returncode == 0, (
            f"{page.relative_to(REPO_ROOT)} is stale (PYTHONHASHSEED={seed}, "
            f"HOME={home_dir}).\n"
            f"Regenerate with: uv run python scripts/{script}\n\n"
            + result.stdout
            + result.stderr
        )
        if home is None:
            # The top level is enough: a home anything was written under has an entry
            # there.
            written = sorted(p.name for p in home_dir.iterdir())
            assert written == [], f"{script} wrote under HOME: {written[:10]}"


@pytest.mark.unit
@pytest.mark.parametrize("script", sorted(REFERENCE_PAGES))
def test_reference_page_names_its_generator(script: str) -> None:
    """Each page's banner names the script that writes it and how to rerun it."""
    head = (REFERENCE_DIR / REFERENCE_PAGES[script]).read_text(encoding="utf-8")[:600]
    assert f"Generated by scripts/{script}" in head
    assert f"uv run python scripts/{script}" in head


@pytest.mark.integration
def test_docs_root_decides_where_pages_go_and_what_they_link(tmp_path: Path) -> None:
    """--docs-root is the tree written to, and the source of per-scanner links.

    The planted tree holds a page for one built-in scanner, one page covering two
    (named with -and-), and a community module's page; the generated page must
    link exactly those four scanners, and land under the planted tree.
    """
    builtin = tmp_path / BUILTIN_SCANNER_PAGES
    community = tmp_path / COMMUNITY_SCANNER_PAGES
    for page in (
        builtin / "bandit.md",
        builtin / "checkov-and-cdk-nag.md",
        builtin / "scanners.md",
        community / "snyk-plugin.md",
    ):
        page.parent.mkdir(parents=True, exist_ok=True)
        page.write_text("# planted\n", encoding="utf-8")

    result = _run_generator(
        "generate_scanner_reference.py", "--docs-root", str(tmp_path)
    )
    assert result.returncode == 0, result.stdout + result.stderr
    written = tmp_path / "docs" / "content" / "reference" / "scanners.md"
    assert written.is_file(), result.stderr
    text = written.read_text(encoding="utf-8")

    links = {
        line.split("`")[1]: line.rsplit("(", 1)[1].rstrip(")")
        for line in text.splitlines()
        if line.startswith("- Scanner page: ")
    }
    assert links == {
        "bandit": "../docs/plugins/builtin/bandit.md",
        "checkov": "../docs/plugins/builtin/checkov-and-cdk-nag.md",
        "cdk-nag": "../docs/plugins/builtin/checkov-and-cdk-nag.md",
        "snyk-code": "../docs/plugins/community/snyk-plugin.md",
    }
    assert "automated_security_helper" in result.stderr.split("Documenting ", 1)[1]


@pytest.mark.integration
def test_reporter_page_needs_no_other_page(tmp_path: Path) -> None:
    """The reporter generator writes its page into a docs tree that holds nothing else.

    It used to rewrite generated regions in output-formats.md and three plugin
    pages, and stopped with an error when one was missing; the docs rewrite deletes
    those pages, so the reference page must be all it reads or writes.
    """
    result = _run_generator("generate_reporter_docs.py", "--docs-root", str(tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr
    written = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*.md"))
    assert written == ["docs/content/reference/reporters.md"]
    committed = (REFERENCE_DIR / "reporters.md").read_text(encoding="utf-8")
    assert (tmp_path / written[0]).read_text(encoding="utf-8") == committed


def _cells(row: str) -> list[str]:
    """A markdown table row's cells, split on pipes outside code spans and escapes."""
    cells, current, i, fence = [], "", 0, 0
    body = row.strip()[1:-1] if row.strip().startswith("|") else row
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            current += body[i : i + 2]
            i += 2
            continue
        if ch == "`":
            run = len(body[i:]) - len(body[i:].lstrip("`"))
            if fence == 0:
                fence = run
            elif run == fence:
                fence = 0
            current += "`" * run
            i += run
            continue
        if ch == "|" and fence == 0:
            cells.append(current.strip())
            current = ""
        else:
            current += ch
        i += 1
    cells.append(current.strip())
    return cells


def _tables(text: str) -> list[tuple[int, str, list[str]]]:
    """(line index of the header, the line above it, body rows) for each table."""
    lines = text.splitlines()
    found = []
    for i, line in enumerate(lines):
        if (
            line.startswith("| ")
            and i + 1 < len(lines)
            and lines[i + 1].startswith("|--")
        ):
            body = []
            for row in lines[i + 2 :]:
                if not row.startswith("|"):
                    break
                body.append(row)
            found.append((i, lines[i - 1] if i else "", [line, *body]))
    return found


@pytest.mark.unit
@pytest.mark.parametrize("page", sorted(OPTIONS_PAGES))
def test_options_tables_carry_the_doctest_marker(page: str) -> None:
    """Every options table is marked with the plugin it belongs to, and only those are.

    The marker is on the line directly above the header, and names the same
    ``<section>.<name>`` that each row's anchor starts with. The page's inventory
    tables, which say whether each plugin is enabled by default, are marked with the
    section alone, so the docs checks compare that column with the code.
    """
    section = OPTIONS_PAGES[page]
    text = (REFERENCE_DIR / page).read_text(encoding="utf-8")
    marker_re = re.compile(r"^<!-- doctest: options of=([a-z]+)\.([A-Za-z0-9_-]+) -->$")
    options_tables = 0
    for _index, above, rows in _tables(text):
        is_options = _cells(rows[0]) == ["Option", "Type", "Default", "Description"]
        match = marker_re.match(above)
        assert bool(match) == is_options, f"{page}: table {rows[0]!r} after {above!r}"
        if not is_options:
            continue
        options_tables += 1
        assert match.group(1) == section, above
        prefix = f'<a id="{section}.{match.group(2)}.options.'
        for row in rows[1:]:
            assert _cells(row)[0].startswith(prefix), f"{above}: {row}"
    marker_lines = [ln for ln in text.splitlines() if marker_re.match(ln)]
    assert options_tables == len(marker_lines) > 0
    inventories = [
        above
        for _index, above, rows in _tables(text)
        if "Enabled by default" in _cells(rows[0])
    ]
    assert inventories, f"{page} has no table saying which plugins are on by default"
    assert set(inventories) == {f"<!-- doctest: options of={section} -->"}


#: First header cells that make a table one the docs checks compare with the code,
#: as scripts/docs_checks.py decides it (a Default column does too). Environment
#: variable tables are not such tables.
_KEYED_HEADERS = {
    "option",
    "options",
    "key",
    "keys",
    "field",
    "fields",
    "setting",
    "settings",
    "argument",
    "param",
    "parameter",
    "parameters",
}
#: Pages whose every keyed table must be marked: all of them.
MARKED_PAGES = sorted(set(REFERENCE_PAGES.values()))
_HEADING_TOOL = re.compile(r"^## ([a-z][a-z0-9_]*)$")
_HEADING_COMMAND = re.compile(
    r"^#{2,3} (?:<a id=\"[^\"]+\"></a>)?`ash((?: [a-z][\w-]*)*)`$"
)


@pytest.mark.unit
@pytest.mark.parametrize("page", MARKED_PAGES)
def test_every_keyed_table_names_what_it_documents(page: str) -> None:
    """A table of options, keys or parameters carries a marker naming what it lists.

    The docs checks treat a keyed table without a marker as an error, so a
    generated page that emitted one would fail them. On cli.md the marker must be
    of=cli.<the command words of the heading above the table>, and on mcp-tools.md
    of=mcp.<the tool named by the heading above it>.
    """
    text = (REFERENCE_DIR / page).read_text(encoding="utf-8")
    lines = text.splitlines()
    marker_re = re.compile(r"^<!-- doctest: options of=(\S+) -->$")
    for index, above, rows in _tables(text):
        header = [re.sub(r"[`*_]", "", c).strip().lower() for c in _cells(rows[0])]
        # Any column that states defaults makes a table keyed, "Enabled by default"
        # included: the generated pages' tables of it list plugins.
        keyed = header[0] not in ("variable", "environment variable") and (
            header[0] in _KEYED_HEADERS
            or any(re.search(r"\bdefaults?\b", cell) for cell in header)
        )
        match = marker_re.match(above)
        if not keyed:
            assert match is None, f"{page}:{index + 1}: marker on {rows[0]!r}"
            continue
        assert match, f"{page}:{index + 1}: {rows[0]!r} has no options marker"
        if page == "cli.md":
            heading = next(
                m for ln in reversed(lines[:index]) if (m := _HEADING_COMMAND.match(ln))
            )
            expected = ".".join(["cli", *heading.group(1).split()])
            assert match.group(1) == expected, f"cli.md:{index + 1}: {above}"
        if page == "mcp-tools.md":
            tool = next(
                m for ln in reversed(lines[:index]) if (m := _HEADING_TOOL.match(ln))
            )
            expected = f"mcp.{tool.group(1)}"
            assert match.group(1) == expected, f"mcp-tools.md:{index + 1}: {above}"


#: Bare phrases a Default cell may hold (generate_config_reference.py, "Default cells").
DEFAULT_PHRASES = {
    "required",
    "computed at run time",
    "see the section",
    "depends on the platform",
    "the plugin's own name",
    "the plugin's defaults",
}
#: The CLI page's phrases (generate_cli_docs.py, "Defaults"), which also has no
#: environment or platform forms: an option's variable has its own column.
CLI_DEFAULT_PHRASES = {"required", "computed at run time", "not set", "on", "off"}
#: The MCP page's phrases: the schema's required list, and a null default.
MCP_DEFAULT_PHRASES = {"*required*", "not set"}
_SPAN = r"(?:``.+?``|`[^`]+`)"
_PLATFORMS = r"(?:Linux|macOS|Windows)(?:(?:, (?:Linux|macOS|Windows))* and (?:Linux|macOS|Windows))?"
DEFAULT_FORMS = (
    re.compile(rf"^(?:from `[A-Za-z_][A-Za-z0-9_]*`, else )*(?P<value>{_SPAN})$"),
    re.compile(rf"^{_SPAN} on {_PLATFORMS}(?:; {_SPAN} on {_PLATFORMS})*$"),
)


@pytest.mark.unit
@pytest.mark.parametrize(
    "page", ["cli.md", "configuration.md", "mcp-tools.md", *sorted(OPTIONS_PAGES)]
)
def test_default_cells_keep_to_the_documented_forms(page: str) -> None:
    """Every Default cell of a key or option table is a form the docs checks can read.

    A single code span must also load with yaml.safe_load, since that is how a
    reader of the page (and the docs checks) turn it back into a value.
    """
    import yaml

    text = (REFERENCE_DIR / page).read_text(encoding="utf-8")
    phrases, forms = {
        "cli.md": (CLI_DEFAULT_PHRASES, DEFAULT_FORMS[:1]),
        "mcp-tools.md": (MCP_DEFAULT_PHRASES, DEFAULT_FORMS[:1]),
    }.get(page, (DEFAULT_PHRASES, DEFAULT_FORMS))
    checked = 0
    for _index, _above, rows in _tables(text):
        header = _cells(rows[0])
        if header[1:3] != ["Type", "Default"]:
            continue
        for row in rows[1:]:
            cell = _cells(row)[2]
            checked += 1
            if cell in phrases:
                continue
            if page in ("cli.md", "mcp-tools.md") and cell.startswith("from `"):
                raise AssertionError(f"{page}: environment form in {row}")
            match = next((m for f in forms if (m := f.match(cell))), None)
            assert match is not None, f"{page}: Default cell {cell!r} in {row}"
            value = match.groupdict().get("value")
            if value:
                inner = value.strip("`").strip()
                yaml.safe_load(inner)
    assert checked > 0, f"{page} has no key or option tables"


def _config_generator():
    sys.path.insert(0, str(SCRIPTS))
    try:
        import generate_config_reference
    finally:
        sys.path.remove(str(SCRIPTS))
    return generate_config_reference


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    [
        "off",
        "true",
        "",
        "5",
        "~",
        "null",
        "ash-scan",
        ">=1.7.0,<2.0.0",
        "a: b",
        "~/x",
        " padded",
        None,
        True,
        3,
        0.5,
        [],
        ["a", "b"],
        {"k": 1},
    ],
)
def test_default_values_read_back_as_themselves(value) -> None:
    """A rendered default, read with yaml.safe_load, is the default."""
    import yaml

    assert yaml.safe_load(_config_generator().yaml_value(value)) == value


@pytest.mark.unit
def test_bounds_are_written_with_digit_grouping() -> None:
    """A Type cell's bounds are grouped, ``at most 1,048,576``, never run together.

    Every kind of bound goes through the same formatting: ge, gt, le, lt and the
    length bounds, integers and floats. Run together, the nine-digit upper bound of
    ``max_message_size_bytes`` was reported as a Social Security number by the
    secret scanner the repository's own scan runs. Default cells keep the raw value,
    which the docs checks compare with the model.
    """
    from typing import Annotated

    from pydantic import BaseModel, Field

    class Bounded(BaseModel):
        size: Annotated[int, Field(ge=1024, le=1_048_576)] = 2048
        ratio: Annotated[float, Field(gt=0.5, lt=1234.5)] = 1.0
        name: Annotated[str, Field(min_length=1, max_length=10_000)] = "x"

    generator = _config_generator()
    assert {
        name: generator.constraints_text(info)
        for name, info in Bounded.model_fields.items()
    } == {
        "size": "at least 1,024, at most 1,048,576",
        "ratio": "greater than 0.5, less than 1,234.5",
        "name": "length at least 1, length at most 10,000",
    }
    assert generator.default_cell(Bounded.model_fields["size"]) == "`2048`"


@pytest.mark.unit
def test_env_and_platform_defaults_are_found_in_the_model_source(
    tmp_path: Path,
) -> None:
    """Which defaults come from a variable, and which from the platform, on a planted model.

    The forms are the ones ASH's models use: an assigned read with a nested
    fallback, a ``Field(default_factory=lambda: ...)`` inside ``Annotated``, a
    module constant, and ``platform.system()``. A variable named only in a
    description is not a default, and an environment read is not a platform one
    (``project_name`` was once rendered "depends on the platform").
    """
    module_path = tmp_path / "planted_env_model.py"
    module_path.write_text(
        textwrap.dedent(
            """
            import os
            import platform
            from typing import Annotated, Optional

            from pydantic import BaseModel, Field

            PLANTED_CONSTANT = os.environ.get("PLANT_CONSTANT", "c")


            class Base(BaseModel):
                inherited: Optional[str] = os.environ.get("PLANT_INHERITED")


            class Planted(Base):
                region: Optional[str] = os.environ.get(
                    "PLANT_REGION", os.environ.get("PLANT_DEFAULT_REGION", "x-1")
                )
                profile: Annotated[
                    Optional[str],
                    Field(default_factory=lambda: os.environ.get("PLANT_PROFILE")),
                ]
                from_constant: str = PLANTED_CONSTANT
                described: Annotated[
                    str, Field(description=os.environ.get("PLANT_DESCRIBED", "d"))
                ] = "plain"
                windows_off: bool = platform.system().lower() != "windows"
                plain: int = 3
            """
        ),
        encoding="utf-8",
    )
    import importlib.util

    spec = importlib.util.spec_from_file_location("planted_env_model", module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["planted_env_model"] = module
    try:
        spec.loader.exec_module(module)
        generator = _config_generator()
        assert generator.env_defaults(module.Planted) == {
            "inherited": ["PLANT_INHERITED"],
            "region": ["PLANT_REGION", "PLANT_DEFAULT_REGION"],
            "profile": ["PLANT_PROFILE"],
            "from_constant": ["PLANT_CONSTANT"],
        }
        assert set(generator.platform_defaults(module.Planted)) == {"windows_off"}
        field = module.Planted.model_fields["region"]
        assert (
            generator.default_cell(
                field, None, ["PLANT_REGION", "PLANT_DEFAULT_REGION"]
            )
            == "from `PLANT_REGION`, else from `PLANT_DEFAULT_REGION`, else `x-1`"
        )
    finally:
        del sys.modules["planted_env_model"]


_PLATFORM_LABELS = ("Linux", "macOS", "Windows")


def _per_platform(*values) -> list:
    return list(zip(_PLATFORM_LABELS, values))


@pytest.mark.unit
@pytest.mark.parametrize(
    "module, name",
    [
        ("semgrep_scanner", "SemgrepScannerConfig"),
        ("opengrep_scanner", "OpengrepScannerConfig"),
    ],
)
def test_scanner_enabled_default_is_evaluated_per_platform(
    module: str, name: str
) -> None:
    """``enabled`` is ``platform.system().lower() != "windows"``: on, except on Windows.

    These two are the platform-dependent defaults ASH has, and that expression is
    the only form they take. ``evaluate_default`` reads it against each stub
    platform, so the page says "yes on Linux and macOS; no on Windows" wherever it
    is generated.
    """
    import importlib

    config_cls = getattr(
        importlib.import_module(
            f"automated_security_helper.plugin_modules.ash_builtin.scanners.{module}"
        ),
        name,
    )
    generator = _config_generator()
    assert generator.platform_defaults(config_cls)["enabled"] == _per_platform(
        True, True, False
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "annotation,expected",
    [
        (
            Optional[Literal["LOW", "HIGH", "CRITICAL"]],
            "one of `LOW`, `HIGH`, `CRITICAL`, or null",
        ),
        (Optional[Literal["LOW"]], "one of `LOW` or null"),
        (Literal["LOW", "HIGH", "CRITICAL"], "one of `LOW`, `HIGH`, `CRITICAL`"),
        (Union[Path, str, None], "path, string, or null"),
        (Union[int, str], "integer or string"),
    ],
    ids=["enum or null", "one value or null", "enum", "three types", "two types"],
)
def test_type_cells_use_the_oxford_comma(annotation, expected: str) -> None:
    """A list of three or more alternatives ends in ", or"; null ends an enumeration."""
    assert _config_generator().type_text(annotation) == expected


@pytest.mark.unit
def test_platform_groups_use_the_oxford_comma() -> None:
    generator = _config_generator()
    assert generator.word_list(["a"], "and") == "a"
    assert generator.word_list(["a", "b"], "and") == "a and b"
    assert generator.word_list(["a", "b", "c"], "and") == "a, b, and c"
    text = generator.per_platform_text(
        [("Linux", True), ("macOS", True), ("Windows", True)], str
    )
    assert text == "True on Linux, macOS, and Windows"


@pytest.mark.unit
def test_platform_defaults_evaluate_only_the_forms_they_know(tmp_path: Path) -> None:
    """Every planted default reads the platform; the ones outside the known forms are None.

    The first five use the forms ``evaluate_default`` reads (a str method, ``or``,
    ``not``, ``x if c else y``, ``os.environ.get`` and ``os.getenv`` with a keyword)
    and get a value per platform. The rest are a lambda, a subscript of a dunder, a
    call of a name outside the stub namespace and a dunder attribute: each is
    "depends on the platform" (``None`` on every platform), never a value.
    """
    module_path = tmp_path / "planted_platform_model.py"
    module_path.write_text(
        textwrap.dedent(
            """
            import os
            import platform
            import sys
            from typing import Any

            from pydantic import BaseModel


            class Planted(BaseModel):
                windows_off: bool = platform.system().lower() != "windows"
                not_linux: bool = platform.system() == "Windows" or not (
                    platform.system().startswith("Lin")
                )
                chosen: str = "nt" if platform.system() == "Windows" else "posix"
                from_environ: str = os.environ.get("PLANT_UNSET", os.name)
                from_getenv: str = os.getenv("PLANT_UNSET", default=sys.platform)
                by_lambda: Any = (lambda: platform.system())()
                subscript_of_dunder: Any = platform.system.__globals__["__name__"]
                outside_name: Any = len(platform.system()) > 0
                dunder: Any = platform.system().__class__
            """
        ),
        encoding="utf-8",
    )
    import importlib.util

    spec = importlib.util.spec_from_file_location("planted_platform_model", module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["planted_platform_model"] = module
    try:
        spec.loader.exec_module(module)
        generator = _config_generator()
        unknown = _per_platform(None, None, None)
        assert generator.platform_defaults(module.Planted) == {
            "windows_off": _per_platform(True, True, False),
            "not_linux": _per_platform(False, True, True),
            "chosen": _per_platform("posix", "posix", "nt"),
            "from_environ": _per_platform("posix", "posix", "nt"),
            "from_getenv": _per_platform("linux", "darwin", "win32"),
            "by_lambda": unknown,
            "subscript_of_dunder": unknown,
            "outside_name": unknown,
            "dunder": unknown,
        }
    finally:
        del sys.modules["planted_platform_model"]


@pytest.mark.unit
@pytest.mark.parametrize(
    "source",
    [
        "platform.system().__class__",
        "platform.system.__globals__",
        "platform.__dict__",
        "'{0.__class__}'.format(platform)",
        "__import__('os')",
        "len(platform.system())",
    ],
)
def test_evaluate_default_refuses_dunders_and_outside_names(source: str) -> None:
    """A dunder attribute, ``str.format`` and a name outside the namespace raise.

    The same namespace evaluates ``platform.system().lower()``, so what is refused
    is the form, not the stub.
    """
    generator = _config_generator()
    namespace = {"platform": types.SimpleNamespace(system=lambda: "Linux")}

    def evaluate(text: str):
        return generator.evaluate_default(ast.parse(text, mode="eval").body, namespace)

    assert evaluate("platform.system().lower()") == "linux"
    with pytest.raises(ValueError):
        evaluate(source)


# ---------------------------------------------------------------------------
# The environment-variable collector
# ---------------------------------------------------------------------------


def _env_module():
    sys.path.insert(0, str(SCRIPTS))
    try:
        import generate_env_var_reference
    finally:
        sys.path.remove(str(SCRIPTS))
    return generate_env_var_reference


def _plant(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    return root


@pytest.mark.unit
def test_read_env_names_finds_every_read_shape(tmp_path: Path) -> None:
    """Each kind of read is found, on a tree whose every read is known."""
    tree = _plant(
        tmp_path,
        {
            "automated_security_helper/__init__.py": "",
            "automated_security_helper/names.py": 'IMPORTED_ENV = "PLANT_IMPORTED"\n',
            "automated_security_helper/reads.py": """
                import os
                from os import environ, getenv
                from automated_security_helper.names import IMPORTED_ENV

                LOCAL_ENV = "PLANT_CONSTANT"
                CI_NAMES = ("PLANT_LOOP_A", "PLANT_LOOP_B")
                PAIRS = (("PLANT_PAIR", None),)

                a = os.environ["PLANT_SUBSCRIPT"]
                b = os.environ.get("PLANT_GET", "fallback")
                c = environ.setdefault("PLANT_SETDEFAULT", "x")
                d = "PLANT_IN" in os.environ
                e = getenv("PLANT_GETENV")
                f = os.environ.get(LOCAL_ENV)
                g = os.environ.get(IMPORTED_ENV)
                h = any(n in os.environ for n in CI_NAMES)


                def flag(name):
                    return os.environ.get(name, "")


                flag("PLANT_PARAM")

                for key, _default in PAIRS:
                    os.environ.get(key)


                def option(**kw):
                    return kw


                option(envvar="PLANT_ENVVAR")
                option(envvar=["PLANT_ENVVAR_LIST"])
                os.environ.get(f"PLANT_{a}")
            """,
            "ash": """
                #!/bin/bash
                LOCAL_ONLY="x"
                echo "$LOCAL_ONLY"
                RUNNER="${PLANT_SHELL_DEFAULT:-docker}"
                echo "$PLANT_SHELL_BARE"
            """,
            "utils/helper.ps1": """
                $runner = $env:PLANT_PS_READ
                $env:PLANT_PS_WRITE_ONLY = "x"
            """,
            "Dockerfile": "FROM scratch AS final\nENV PLANT_GET=from-image\n",
        },
    )
    names, dynamic = _env_module().read_env_names(tree)

    expected = {
        "PLANT_SUBSCRIPT",
        "PLANT_GET",
        "PLANT_SETDEFAULT",
        "PLANT_IN",
        "PLANT_GETENV",
        "PLANT_CONSTANT",
        "PLANT_IMPORTED",
        "PLANT_LOOP_A",
        "PLANT_LOOP_B",
        "PLANT_PARAM",
        "PLANT_PAIR",
        "PLANT_ENVVAR",
        "PLANT_ENVVAR_LIST",
        "PLANT_SHELL_DEFAULT",
        "PLANT_SHELL_BARE",
        "PLANT_PS_READ",
    }
    assert expected <= names, f"not found: {sorted(expected - names)}"
    assert [d for d in dynamic if "reads.py" in d and "PLANT_{a}" in d], (
        f"the f-string key was not reported as a dynamic site: {dynamic}"
    )

    scan = _env_module().collect_env_reads(tree)
    assert scan.image_env["PLANT_GET"] == [("final", "from-image", 2)]
    defaults = {r.name: r.default for r in scan.reads}
    assert defaults["PLANT_GET"] == "fallback"
    assert defaults["PLANT_SHELL_DEFAULT"] == "docker"


@pytest.mark.unit
def test_read_env_names_refuses_what_is_not_a_read(tmp_path: Path) -> None:
    """Writes, comments, shell locals and help text do not count as reads."""
    tree = _plant(
        tmp_path,
        {
            "automated_security_helper/__init__.py": "",
            "automated_security_helper/writes.py": """
                import os

                # PLANT_COMMENT is mentioned here and never read.
                os.environ["PLANT_WRITE"] = "1"
                del os.environ["PLANT_WRITE"]
                text = "PLANT_STRING is only a string"
            """,
            "ash": """
                #!/bin/bash
                # Set $PLANT_SH_COMMENT before running.
                SCRIPT_SET="x"
                echo "${SCRIPT_SET}"
                SCRIPT_SET_FIRST="a"
                echo "${SCRIPT_SET_FIRST:-unused}"
                lower_local="y"
                echo "$lower_local $undefined_lower"
            """,
            "utils/helper.ps1": """
                <#
                .DESCRIPTION
                Defaults to $env:PLANT_PS_HELP when set.
                #>
                # $env:PLANT_PS_COMMENT
                $env:PLANT_PS_WRITE = "x"
            """,
            "Dockerfile": "FROM scratch\nENV PLANT_IMAGE_ONLY=1\n",
        },
    )
    names, _dynamic = _env_module().read_env_names(tree)
    planted = {n for n in names if n.startswith(("PLANT_", "SCRIPT_"))}
    assert planted == set(), f"counted as reads: {sorted(planted)}"
    assert "lower_local" not in names and "undefined_lower" not in names
    assert _env_module().collect_env_reads(tree).image_env == {}


@pytest.mark.unit
def test_an_empty_read_default_does_not_hide_the_option_default() -> None:
    """An empty-string read default gives way to the option's or config key's.

    ``os.environ.get("ASH_BIN_PATH", "")`` in a lookup cache's key made the page
    say ASH_BIN_PATH defaults to ``""``. Unset, ASH searches and installs into
    ``~/.ash/bin``, the default of the ``--bin-path`` option the variable sets.
    """
    module = _env_module()

    def read(default):
        return module.EnvRead(
            name="PLANT_DIR",
            path="automated_security_helper/reads.py",
            line=1,
            language="python",
            shape="environ.get",
            default=default,
        )

    option = [("ash plant", "--dir", "cli.md#plant--dir", "`~/.plant`", "Dir.")]
    config = [("plant.dir", "configuration.md#plant.dir", "`~/.plant-config`")]

    assert module._default_entries([read(None), read("")], option, []) == ["`~/.plant`"]
    assert module._default_entries([read("")], [], config) == [
        "`~/.plant-config` (the default of `plant.dir`)"
    ]
    # With no option or config key to say what unset means, "" is what the code gives.
    assert module._default_entries([read("")], [], []) == ['`""`']
    # Beside a read that gives a value, "" is one of the spellings the code uses.
    assert module._default_entries([read(""), read("NO")], option, []) == [
        '`""`',
        "`NO`",
    ]
    assert module._default_entries([read("x")], option, []) == ["`x`"]


@pytest.mark.unit
def test_environment_page_survives_lines_moving(tmp_path: Path) -> None:
    """Each read is cited by file and enclosing function, never by line number.

    The page used to cite about a hundred ``path:line`` sites, so any change that
    moved a line in a file with a read made the page stale on every other branch.
    Here every file of a planted tree gains a line at its top between two renders,
    and the page must not change; and each read's scope is the function, method or
    script function around it.
    """
    files = {
        "automated_security_helper/__init__.py": "",
        "automated_security_helper/reads.py": """
            import os

            TOP = os.environ.get("PLANT_MODULE_LEVEL", "m")


            class Loader:
                def load(self):
                    # PLANT_METHOD picks the loader.
                    return os.environ.get("PLANT_METHOD")


            def helper():
                def inner():
                    return os.getenv("PLANT_NESTED")

                return inner() or os.environ[f"PLANT_{TOP}"]
        """,
        "ash": """
            #!/bin/bash
            echo "$PLANT_SH_TOP"
            run_it() {
              echo "${PLANT_SH_FUNC:-x}"
            }
        """,
        "utils/helper.ps1": """
            function Invoke-Plant {
                $x = $env:PLANT_PS_FUNC
            }
            $y = $env:PLANT_PS_TOP
        """,
    }
    tree = _plant(tmp_path, files)
    module = _env_module()
    scopes = {(r.name, r.scope) for r in module.collect_env_reads(tree).reads}
    assert {
        ("PLANT_MODULE_LEVEL", ""),
        ("PLANT_METHOD", "Loader.load"),
        ("PLANT_NESTED", "helper.inner"),
        ("PLANT_SH_TOP", ""),
        ("PLANT_SH_FUNC", "run_it"),
        ("PLANT_PS_FUNC", "Invoke-Plant"),
        ("PLANT_PS_TOP", ""),
    } <= scopes, scopes

    before, _stats = module.generate(tree, with_cli=False)
    for rel in files:
        path = tree / rel
        path.write_text("\n" + path.read_text(encoding="utf-8"), encoding="utf-8")
    after, _stats = module.generate(tree, with_cli=False)
    assert after == before
    assert "`Loader.load`" in before and "`run_it`" in before


@pytest.mark.unit
def test_environment_page_cites_no_line_numbers() -> None:
    """The committed page names files and scopes, not lines (see the test above)."""
    text = (REFERENCE_DIR / "environment-variables.md").read_text(encoding="utf-8")
    cited = re.findall(r"(?:\.py|\.sh|\.ps1|\bash)`?:\s*\d+", text)
    assert cited == [], f"line citations on the page: {cited[:5]}"


@pytest.mark.integration
@pytest.mark.parametrize("script", sorted(REFERENCE_PAGES))
def test_check_refuses_stdout(script: str) -> None:
    """``--check --output -`` would print the page and compare nothing, so it is refused."""
    result = _run_generator(script, "--check", "--output", "-")
    assert result.returncode != 0, f"{script} accepted --check --output -"
    assert "--output -" in result.stderr, result.stderr
    assert result.stdout == "", "a refused run must not print a page"


@pytest.mark.integration
@pytest.mark.parametrize("script", sorted(REFERENCE_PAGES))
def test_check_compares_the_output_file(script: str, tmp_path: Path) -> None:
    """``--check --output FILE`` compares FILE, and leaves a stale one as it was."""
    stale = tmp_path / "stale.md"
    stale.write_text("stale\n", encoding="utf-8")
    result = _run_generator(script, "--check", "--output", str(stale))
    assert result.returncode == 1, result.stdout + result.stderr
    assert stale.read_text(encoding="utf-8") == "stale\n"


@pytest.mark.unit
def test_install_text_shows_packages_not_uv_arguments() -> None:
    """A ``uv tool install`` command's options are not shown as if they were packages.

    A plugin may install with
    ``uv tool install --python '>=3.10,<3.14' 'example-scanner==2.0.0'``; the page must
    not show ``--python >=3.10,<3.14 example-scanner==2.0.0`` as the package.
    """
    from types import SimpleNamespace

    sys.path.insert(0, str(SCRIPTS))
    try:
        import _plugin_reference
    finally:
        sys.path.remove(str(SCRIPTS))
    instance = SimpleNamespace(
        use_uv_tool=True,
        uv_tool_install_commands=[
            "uv tool install --python '>=3.10,<3.14' 'example-scanner==2.0.0'",
            "uv tool install bandit[toml]>=1.7",
        ],
    )
    text = _plugin_reference.install_text(instance)
    assert text == (
        "`uv tool install` on first use (`example-scanner==2.0.0` with Python "
        "`>=3.10,<3.14`, `bandit[toml]>=1.7`)"
    ), text


@pytest.mark.integration
def test_read_env_names_covers_this_tree() -> None:
    """On the real checkout the walk reaches the package and the entry scripts.

    One name per source: a CLI ``envvar`` (ASH_CONFIG), a direct
    ``os.environ.get`` (ASH_DEFAULT_SEVERITY_LEVEL), the ``ash`` shell script
    (OCI_RUNNER_WRAPPER) and the PowerShell helper (ASH_OCI_RUNNER, which only
    that helper reads).
    """
    names, dynamic = _env_module().read_env_names()
    for name in (
        "ASH_CONFIG",
        "ASH_DEFAULT_SEVERITY_LEVEL",
        "OCI_RUNNER_WRAPPER",
        "ASH_OCI_RUNNER",
    ):
        assert name in names, f"{name} not found; dynamic sites: {dynamic}"
    assert all(isinstance(site, str) and ":" in site for site in dynamic)


# ---------------------------------------------------------------------------
# What the pages say, checked against the code that decides it
#
# Each of these pins a statement on a reference page to the code that decides it,
# so the page cannot drift back.
# ---------------------------------------------------------------------------


def _page(name: str) -> str:
    return (REFERENCE_DIR / name).read_text(encoding="utf-8")


def _row(text: str, anchor: str) -> str:
    """The table row whose first cell carries ``<a id="anchor">``."""
    marker = f'<a id="{anchor}"></a>'
    rows = [line for line in text.splitlines() if marker in line]
    assert len(rows) == 1, f"{anchor}: {len(rows)} rows"
    return rows[0]


def _section(text: str, heading_code: str) -> str:
    """The body of the ``##``/``###`` section whose heading holds ``heading_code``."""
    lines = text.splitlines()
    start = next(
        i
        for i, line in enumerate(lines)
        if line.startswith("#") and heading_code in line
    )
    end = next(
        (
            i
            for i in range(start + 1, len(lines))
            if lines[i].startswith("## ") or lines[i].startswith("### ")
        ),
        len(lines),
    )
    return "\n".join(lines[start:end])


def _builtin_reporter_names() -> set[str]:
    """The built-in reporters, from the reporters page's own built-in table."""
    table = (
        _page("reporters.md").split("## Built-in reporters", 1)[1].split("\n## ", 1)[0]
    )
    return set(re.findall(r"^\| \[[^\]]+\]\(#([a-z-]+)\)", table, re.MULTILINE))


def _in_code_tree(tmp_path: Path, source: str, *args: str):
    """Run ``source`` in a fresh interpreter outside this checkout; return the JSON
    its last line prints.

    tests/conftest.py puts this checkout first on sys.path, so code imported here
    is this checkout's. The pages, though, are generated from the ASH the
    interpreter installs, which is another checkout's when the docs are checked
    against other code (see the contributor page). A fresh interpreter started in
    an empty directory imports that ASH, as the generators do.
    """
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(source), *args],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={k: v for k, v in os.environ.items() if k != "ASH_CONFIG"},
        timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.integration
def test_output_formats_say_which_values_write_a_report(tmp_path: Path) -> None:
    """``--output-formats`` is checked against ExportFormat, and only reporter names write.

    A value that names no reporter is accepted and writes nothing; a reporter whose
    name is not an ExportFormat value is refused (cli/scan.py's parse loop).
    """
    formats = set(
        _in_code_tree(
            tmp_path,
            """
            import json
            from automated_security_helper.core.enums import ExportFormat
            print(json.dumps([f.value for f in ExportFormat]))
            """,
        )
    )
    reporters = _builtin_reporter_names()
    assert reporters, "no built-in reporters read from reporters.md"
    _assert_output_formats_row(
        _row(_page("cli.md"), "scan--output-formats"), formats, reporters
    )


def _assert_output_formats_row(row: str, formats: set, reporters: set) -> None:
    """The row names the reporters it writes, the values that write nothing, and,
    only when there are any, the built-in reporters it refuses."""
    writes, nothing = (
        re.search(pattern, row).group(1)
        for pattern in (
            r"Values that write a report: ([^.]*)\.",
            r"name no reporter and write no report: ([^.]*)\.",
        )
    )
    assert set(re.findall(r"`([^`]+)`", writes)) == formats & reporters
    assert set(re.findall(r"`([^`]+)`", nothing)) == formats - reporters
    refused = re.search(r"reporters that are refused: ([^;.]*)[;.]", row)
    if reporters - formats:
        assert refused, f"the refused reporters are not named: {row}"
        assert set(re.findall(r"`([^`]+)`", refused.group(1))) == reporters - formats
    else:
        assert refused is None, f"no built-in reporter is refused, but: {row}"


@pytest.mark.unit
@pytest.mark.parametrize(
    "extra_reporters",
    [(), ("planted-only-reporter",)],
    ids=["every-reporter-is-a-format", "one-reporter-is-not"],
)
def test_output_formats_note_names_refused_reporters_only_when_there_are_some(
    monkeypatch, extra_reporters: tuple
) -> None:
    """Both cases of the --output-formats note, planted: with every built-in
    reporter an ExportFormat value (as on the merged code) it has no "refused"
    sentence, and with one that is not, it names that one."""
    from automated_security_helper.core.enums import ExportFormat

    generator = _script_module("generate_cli_docs")
    formats = {f.value for f in ExportFormat}
    reporters = sorted(formats - {"text"})[:3] + list(extra_reporters)
    monkeypatch.setattr(generator, "_builtin_reporters", lambda: sorted(reporters))
    note = generator._output_formats_note(None)
    _assert_output_formats_row(note, formats, set(reporters))
    assert ("refused" in note) == bool(extra_reporters)


@pytest.mark.unit
def test_report_format_lists_the_reporters() -> None:
    """``ash report --format`` takes a loaded reporter's name, not an ExportFormat value."""
    row = _row(_page("cli.md"), "report--format")
    accepted = re.search(r"Accepted values: ([^.]*)\.", row).group(1)
    assert _builtin_reporter_names() <= set(re.findall(r"`([^`]+)`", accepted))


#: What generate_cli_docs.py writes under a command that ignores unknown options.
UNKNOWN_OPTIONS_SENTENCE = "does not reject an option it does not define"


def _ignores_unknown_options(root) -> dict[str, bool]:
    """Each command's label (``ash``, ``ash config get``) -> whether its click settings
    ignore unknown options, for every command, walked as generate_cli_docs.py walks."""
    generator = _script_module("generate_cli_docs")
    return {
        "ash" + "".join(f" {part}" for part in path): bool(
            (getattr(cmd, "context_settings", None) or {}).get("ignore_unknown_options")
        )
        for path, cmd, _ctx in generator.iter_commands(root)
    }


def _says_it_ignores_unknown_options(page: str, labels) -> dict[str, bool]:
    return {
        label: UNKNOWN_OPTIONS_SENTENCE in _section(page, f"`{label}`")
        for label in labels
    }


@pytest.mark.unit
def test_cli_page_says_which_commands_ignore_unknown_options() -> None:
    """A command whose click settings ignore unknown options says so; no other does.

    Which commands ignore unknown options is read from the app: it is a property of
    the code, and code trees differ in it. The page compared is the generator's output
    for this code, so the test holds on every tree; that the committed page is that
    output is test_reference_page_is_current's job.
    """
    import typer.main

    from automated_security_helper.cli.main import app

    root = typer.main.get_command(app)
    expected = _ignores_unknown_options(root)
    assert len(expected) > 1, expected
    page, _stats = _script_module("generate_cli_docs").generate(root)
    assert _says_it_ignores_unknown_options(page, expected) == expected


@pytest.mark.unit
def test_a_command_that_ignores_unknown_options_is_named_on_the_cli_page() -> None:
    """The positive case, planted on a copy of the app, so it is exercised whether or not
    the code under test has such a command: one at the top level and one nested in a
    group say so, and a planted command beside them that rejects unknown options does
    not."""
    import copy

    import click
    import typer.main

    from automated_security_helper.cli.main import app

    root = copy.copy(typer.main.get_command(app))
    root.commands = dict(root.commands)
    ignores = {"ignore_unknown_options": True}
    root.commands["planted-ignores"] = click.Command(
        "planted-ignores", help="Planted.", context_settings=ignores
    )
    root.commands["planted-strict"] = click.Command("planted-strict", help="Planted.")
    root.commands["planted-group"] = click.Group(
        "planted-group",
        help="Planted.",
        commands={
            "deep": click.Command("deep", help="Planted.", context_settings=ignores)
        },
    )
    expected = _ignores_unknown_options(root)
    page, _stats = _script_module("generate_cli_docs").generate(root)
    said = _says_it_ignores_unknown_options(page, expected)
    assert said == expected
    assert said["ash planted-ignores"] and said["ash planted-group deep"], said
    assert not said["ash planted-strict"] and not said["ash planted-group"], said


@pytest.mark.unit
def test_cli_page_does_not_claim_every_variable() -> None:
    """The env column is the variable click reads, and the page says other variables exist."""
    intro = _page("cli.md").split("## Commands", 1)[0]
    assert "where one exists" not in intro
    assert "names the variable click reads" in intro
    assert "(environment-variables.md)" in intro


@pytest.mark.unit
def test_flags_without_a_default_read_as_off() -> None:
    """``--install-completion`` defaults to None, which for a flag means off, as for the rest."""
    for anchor in ("ash--install-completion", "ash--show-completion"):
        assert _cells(_row(_page("cli.md"), anchor))[2] == "off"


#: Asks ``ash config validate --config`` about each top-level key a scan accepts,
#: under each spelling, and about `name` in a plugin entry. A verdict is "rejects"
#: when the command exits non-zero, "warns" when it passes the file but prints a
#: line naming the key, and "" when it says nothing about it.
VALIDATE_DRIVER = """
import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.ash_config import AshConfig

base = {"project_name": "probe"}
probes = []


def verdict(config, key):
    path = Path(f"probe-{len(probes)}.yaml")
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    result = CliRunner().invoke(app, ["config", "validate", "--config", str(path)])
    said = f"exit {result.exit_code}, {config}: {result.output}"
    probes.append(said)
    if result.exit_code != 0:
        return "rejects", said
    return ("warns" if f"'{key}'" in result.output else ""), said


defaults = AshConfig().model_dump(mode="json", by_alias=True)
fields = []
for name, info in AshConfig.model_fields.items():
    key = info.alias or name
    if key not in defaults:
        continue
    # A section as an empty mapping: its default can carry fields (a plugin's
    # name) that validate reports on their own.
    value = {} if isinstance(defaults[key], dict) else defaults[key]
    own, own_said = verdict({**base, key: value}, key)
    spelled, spelled_said = (
        verdict({**base, name: value}, name) if name != key else ("", "")
    )
    fields.append(
        {"key": key, "name": name, "verdict": own, "said": own_said,
         "spelled": spelled, "spelled_said": spelled_said}
    )
plugin_name = {
    section: verdict({**base, section: {plugin: {"name": plugin}}}, "name")
    for section, plugin in (
        ("scanners", "bandit"), ("reporters", "sarif"), ("converters", "archive")
    )
}
print(json.dumps({
    "baseline": verdict(base, "project_name"),
    "fields": fields,
    "plugin_name": plugin_name,
}))
"""


def _validator_note_kind(note: str) -> str:
    """The verdict a page note states: "rejects", "warns" or "" (no note)."""
    if "`ash config validate`" not in note:
        return ""
    return "warns" if "`ash config validate` warns" in note else "rejects"


@pytest.mark.integration
def test_configuration_says_what_ash_config_validate_does_with_each_key(
    tmp_path: Path,
) -> None:
    """Each top-level key's row, and the plugin entries' `name` row, say what
    ``ash config validate`` does with the key, asked of the command itself.

    Which keys it flags, and whether a flag fails validation or only warns,
    differ between versions of ASH, so nothing here is a list of keys: every
    spelling a scan accepts is put in a config of its own, with its default (a
    section empty), and the row must state the command's verdict. The command
    runs in the ASH the page is generated from (see :func:`_in_code_tree`).
    """
    facts = _in_code_tree(tmp_path, VALIDATE_DRIVER)
    verdict, said = facts["baseline"]
    assert verdict == "", f"a config with only project_name does not validate: {said}"
    text = _page("configuration.md")
    checked = 0
    for field in facts["fields"]:
        key, name = field["key"], field["name"]
        if not text.count(f'<a id="{key}"></a>'):
            continue
        row = _row(text, key)
        own_note = row
        if name != key:
            spelled = field["spelled"]
            mentions = f"as `{name}`, which `ash config validate`" in row
            assert mentions == bool(spelled), (key, spelled, row, field["spelled_said"])
            if spelled:
                stated = _validator_note_kind(row.split(f"as `{name}`, which")[1])
                assert stated == spelled, (key, spelled, row, field["spelled_said"])
            own_note = row.split(f"as `{name}`, which")[0]
        verdict, said = field["verdict"], field["said"]
        assert _validator_note_kind(own_note) == verdict, (key, verdict, row, said)
        checked += 1
    assert checked >= 10, f"only {checked} top-level rows were compared"

    common = _section(text, "## Plugin sections").split("### ", 1)[0]
    name_row = next(r for r in common.splitlines() if r.startswith("| `name` |"))
    verdicts = {section: v for section, (v, _said) in facts["plugin_name"].items()}
    assert set(verdicts.values()) <= {"rejects", "warns", ""}, verdicts
    for verdict in set(verdicts.values()) - {""}:
        kinds = [s[:-1] for s, v in verdicts.items() if v == verdict]
        phrase = "warns" if verdict == "warns" else "rejects"
        assert f"`ash config validate` {phrase}" in name_row, (verdicts, name_row)
        assert all(kind in name_row for kind in kinds), (verdicts, name_row)
    if not any(verdicts.values()):
        assert "`ash config validate`" not in name_row, name_row


@pytest.mark.unit
@pytest.mark.parametrize("verdict", ["rejects", "warns", ""])
def test_validator_notes_state_the_verdict_they_are_given(monkeypatch, verdict) -> None:
    """Planted verdicts, since a version of ASH shows only some of them: each note
    the generator writes says what the validator did with the key, or nothing."""
    generator = _config_generator()

    def planted(config: dict, key: str) -> tuple[str, str]:
        if not verdict:
            return "", ""
        if key == "name":
            return verdict, f"Scanner 'x' contains internal-only field '{key}'"
        if key == "build":
            return verdict, f"Top-level field '{key}' is an internal field"
        return verdict, f"Unknown top-level field '{key}' - a scan ignores it"

    monkeypatch.setattr(generator, "validator_verdict", planted)
    note = generator.top_level_validator_note("build", "build")
    assert _validator_note_kind(note) == verdict, note
    both = generator.top_level_validator_note("mcp-resource-management", "mcp_resource")
    own, _, spelled = both.partition("as `mcp_resource`, which")
    assert _validator_note_kind(own) == verdict, both
    assert _validator_note_kind(spelled) == verdict, both
    plugin = generator.plugin_entry_validator_note("name")
    assert _validator_note_kind(plugin) == verdict, plugin
    named = all(kind in plugin for kind in ("scanner", "reporter", "converter"))
    assert named == bool(verdict), plugin


@pytest.mark.unit
def test_validator_note_refuses_a_message_it_has_no_words_for() -> None:
    """A validator complaint that is neither "internal" nor "unknown" stops the
    generator, rather than being worded as one of them."""
    with pytest.raises(SystemExit, match="no wording"):
        _config_generator()._top_level_reason("Top-level field 'x' is set twice")


@pytest.mark.unit
def test_configuration_types_name_no_classes() -> None:
    """A Type cell describes values (string, mapping, list of ...), never a Python class."""
    for page in ("configuration.md", "scanners.md", "reporters.md", "converters.md"):
        for _index, _above, rows in _tables(_page(page)):
            if _cells(rows[0])[1:2] != ["Type"]:
                continue
            for row in rows[1:]:
                kind = _cells(row)[1]
                assert not re.search(r"`[A-Z][a-z]+[A-Z]\w*`", kind), f"{page}: {row}"
    common = _section(_page("configuration.md"), "## Plugin sections")
    assert "| Scanner options |" not in common


@pytest.mark.unit
def test_reporter_page_names_every_file_a_reporter_writes() -> None:
    """unused-suppressions also writes ash.unused-suppressions.md with its default options."""
    body = _section(_page("reporters.md"), "## `unused-suppressions`")
    assert "`reports/ash.unused-suppressions.md`" in body
    row = _row(
        _page("reporters.md"), "reporters.unused-suppressions.options.output_format"
    )
    assert '"json", "markdown", or "both"' in row


@pytest.mark.unit
def test_scanner_page_says_network_scanners_replaces_the_default() -> None:
    """Each scanner's network line is its default, which sandbox.network_scanners replaces."""
    text = _page("scanners.md")
    assert "yes, when the scan is online" not in text
    assert "replaces every scanner's declared need" in _section(
        text, "## Environment in the sandbox"
    )
    assert "- Network in the sandbox, by default: " in _section(text, "## `bandit`")


@pytest.mark.unit
def test_environment_page_purposes_and_defaults() -> None:
    """No purpose scraped from an unrelated comment, and config-backed defaults shown."""
    text = _page("environment-variables.md")

    def row(name: str) -> list[str]:
        hits = [r for r in text.splitlines() if r.startswith(f"| `{name}` |")]
        assert len(hits) == 1, name
        return _cells(hits[0])

    assert "Project information" not in row("ASH_PROJECT_NAME")[4]
    assert "global_settings.severity_threshold" in row("ASH_DEFAULT_SEVERITY_LEVEL")[4]
    assert "`MEDIUM`" in row("ASH_DEFAULT_SEVERITY_LEVEL")[1]
    assert "width constraint" not in row("ASH_IN_CONTAINER")[4]


@pytest.mark.unit
def test_read_site_comments_must_name_the_variable(tmp_path: Path) -> None:
    """A comment above a read is its purpose when it names it or is a sentence.

    A section label above a read ("# Project information") is about the code
    around it. A comment on the constant that holds the name, or above a shell
    line that assigns the variable itself, is about the variable.
    """
    tree = _plant(
        tmp_path,
        {
            "automated_security_helper/__init__.py": "",
            "automated_security_helper/reads.py": """
                import os

                #: PLANT_NAMED is read here, and this says so.
                A = os.environ.get("PLANT_NAMED")

                # Project information
                B = os.environ.get("PLANT_UNNAMED")

                # Overrides which flake supplies the toolchain.
                C = os.environ.get("PLANT_SENTENCE")

                #: Where the cache lives.
                HELD_ENV = "PLANT_HELD"


                def cache():
                    return os.environ.get(HELD_ENV)
            """,
            "ash": """
                #!/bin/bash
                # How many times to retry.
                PLANT_SH_SELF="${PLANT_SH_SELF:-3}"
                # Unrelated heading
                echo "${PLANT_SH_OTHER:-x}"
            """,
        },
    )
    purposes = {r.name: r.comment for r in _env_module().collect_env_reads(tree).reads}
    assert purposes["PLANT_NAMED"].startswith("PLANT_NAMED is read here")
    assert purposes["PLANT_UNNAMED"] is None
    assert purposes["PLANT_SENTENCE"] == "Overrides which flake supplies the toolchain."
    assert purposes["PLANT_HELD"] == "Where the cache lives."
    assert purposes["PLANT_SH_SELF"] == "How many times to retry."
    assert purposes["PLANT_SH_OTHER"] is None


@pytest.mark.unit
def test_reads_through_a_constant_inside_a_function(tmp_path: Path) -> None:
    """``os.environ.get(CONST)`` in a function, the shape ASH_ALLOW_IN_TREE_TOOLS uses."""
    tree = _plant(
        tmp_path,
        {
            "automated_security_helper/__init__.py": "",
            "automated_security_helper/utils.py": """
                import os

                ALLOW_ENV = "PLANT_ALLOW"


                def parse(value):
                    return value == "1"


                def allowed():
                    return parse(os.environ.get(ALLOW_ENV))
            """,
        },
    )
    names, dynamic = _env_module().read_env_names(tree)
    assert "PLANT_ALLOW" in names, dynamic


@pytest.mark.integration
def test_build_args_are_not_environment_variables() -> None:
    """ASH_BASE_IMAGE is a container build argument; no code reads it from the environment."""
    names, _dynamic = _env_module().read_env_names()
    assert "ASH_BASE_IMAGE" not in names
    assert "| `ASH_BASE_IMAGE` |" not in _page("environment-variables.md")


@pytest.mark.unit
def test_mcp_notes_match_the_server() -> None:
    """The MCP notes, held to what the server does."""
    text = _page("mcp-tools.md")
    scan = _section(text, "## run_ash_scan")
    source_dir = next(r for r in scan.splitlines() if r.startswith("| `source_dir` |"))
    assert "refused" in source_dir and "working directory" in source_dir
    config = next(r for r in scan.splitlines() if r.startswith("| `config_path` |"))
    # `ash mcp --profile` registers profiles, so a profile the session bound with
    # select_profile comes before the config ASH discovers.
    assert "discovers in the source directory" in config and "`ASH_CONFIG`" in config
    assert config.index("select_profile") < config.index("discovers")
    clean = next(r for r in scan.splitlines() if r.startswith("| `clean_output` |"))
    # The previous results are set aside and put back on failure, not deleted.
    assert "previous scan's results" in clean and "put back" in clean
    git = _section(text, "## set_source_git")
    depth = next(r for r in git.splitlines() if r.startswith("| `depth` |"))
    # The depth is a whole number from 1 to 1000 (MAX_CLONE_DEPTH); 0 is refused,
    # not a full clone.
    assert "from 1 to 1000" in depth and "full clone" not in depth
    ssh_key = next(r for r in git.splitlines() if r.startswith("| `ssh_key_id` |"))
    assert "refused" in ssh_key and "private repos" not in ssh_key
    threshold = next(
        r for r in scan.splitlines() if r.startswith("| `severity_threshold` |")
    )
    assert "stricter" in threshold and "never looser" in threshold
    cancel = _section(text, "## cancel_scan")
    assert "Stops a running scan." in cancel
    assert "does not stop" not in cancel
    progress = _section(text, "## get_scan_progress")
    assert "until `is_complete` is `true`" in progress
    # The page names a progress key exactly when the server returns it.
    returned = _progress_keys()
    assert "results_available" not in returned or "`results_available`" in progress
    assert "results_available" in returned or "`results_available`" not in progress
    assert "ash mcp --profile NAME=path/to/ash.yaml" in _section(
        text, "## list_profiles"
    )
    install = _section(text, "## check_installation")
    assert "`installs_on_first_scan`" in install and "until a scan" not in install


def _mcp_reference_module():
    sys.path.insert(0, str(SCRIPTS))
    try:
        import generate_mcp_tool_reference
    finally:
        sys.path.remove(str(SCRIPTS))
    return generate_mcp_tool_reference


def _progress_keys() -> set[str]:
    """The keys of the widest get_scan_progress ANSWER the server returns.

    The tool's refusals (a scan id never issued, a session that cannot read the
    scan) are response dicts too, and each carries an exit code, an error
    category, a context and the operation, so a refusal can hold more keys than
    the answer itself. The answer is the shape that carries ``is_complete``;
    the widest dict of that shape is the one the page's example is held to.
    """
    import importlib.util

    sys.path.insert(0, str(SCRIPTS))
    try:
        import _mcp_contract
    finally:
        sys.path.remove(str(SCRIPTS))
    spec = importlib.util.find_spec("automated_security_helper")
    assert spec is not None and spec.origin
    contracts = _mcp_contract.tool_contracts(Path(spec.origin).resolve().parent)
    response = contracts["get_scan_progress"].response
    answers = [
        {key for key, _ in each.keys}
        for each in response.dicts()
        if any(key == "is_complete" for key, _ in each.keys)
    ]
    assert answers, "no get_scan_progress response dict carries is_complete"
    return max(answers, key=len)


@pytest.mark.unit
def test_the_progress_example_names_only_keys_the_server_returns() -> None:
    """Every key of the get_scan_progress example, and no caveat that needs a key the
    server lacks, comes from the response the tool's return statements build."""
    text = _page("mcp-tools.md")
    progress = _section(text, "## get_scan_progress")
    # The docs page prints the example as json or, when it is a sketch, as text.
    fence = re.search(r"```(?:json|text)\n(.*?)```", progress, re.DOTALL)
    assert fence, progress
    example = fence.group(1)
    shown = set(re.findall(r'^  "([a-z_]+)":', example, re.MULTILINE))
    returned = _progress_keys()
    assert shown and shown <= returned, sorted(shown - returned)
    for key in ("finished_scanners", "scanner_status_counts"):
        assert (key in returned) == (f"`{key}`" in progress), key


@pytest.mark.unit
def test_a_dict_caveat_is_printed_only_while_the_server_returns_what_it_needs() -> None:
    generator = _mcp_reference_module()
    caveat = {
        "needs": ["flag"],
        "text": "with the flag",
        "otherwise": "without the flag",
    }
    assert (
        generator._conditional_caveat(caveat, {"flag", "x"}, set()) == "with the flag"
    )
    assert generator._conditional_caveat(caveat, {"x"}, set()) == "without the flag"
    bare = {"needs": ["flag"], "text": "with the flag"}
    assert generator._conditional_caveat(bare, {"x"}, set()) is None
    typed = {"needs_types": ["busy"], "text": "refused as busy"}
    assert generator._conditional_caveat(typed, set(), {"busy"}) == "refused as busy"
    assert generator._conditional_caveat(typed, set(), {"other"}) is None


@pytest.mark.unit
def test_the_error_type_paragraph_names_the_types_the_tool_returns() -> None:
    generator = _mcp_reference_module()
    caveat = {
        "lead": "A refusal returns an `error_type`:",
        "error_types": [("a", "first"), ("b", ""), ("c", "third")],
        "untyped_unless": ["c"],
        "untyped": "Anything else has none.",
    }
    only_a_and_b = generator._conditional_caveat(caveat, set(), {"a", "b"})
    assert only_a_and_b == (
        "A refusal returns an `error_type`: `a` (first), or `b`. "
        "Anything else has none."
    )
    with_c = generator._conditional_caveat(caveat, set(), {"a", "c"})
    assert with_c == ("A refusal returns an `error_type`: `a` (first), or `c` (third).")
    assert generator._conditional_caveat(caveat, set(), {"z"}) is None


@pytest.mark.unit
def test_the_clone_paragraph_names_no_type_the_server_lacks() -> None:
    """set_source_git's page names the clone types the reader finds in the server's
    source, none from an older or newer one."""
    git = _section(_page("mcp-tools.md"), "## set_source_git")
    paragraph = next(p for p in git.split("\n\n") if p.startswith("A refusal"))
    named = set(re.findall(r"`([a-z_]+)`", paragraph)) - {"error_type"}
    clone_types = {
        n for n in named if n.startswith(("clone_", "git_", "invalid_clone"))
    }
    import importlib.util

    sys.path.insert(0, str(SCRIPTS))
    try:
        import _mcp_contract
    finally:
        sys.path.remove(str(SCRIPTS))
    spec = importlib.util.find_spec("automated_security_helper")
    assert spec is not None and spec.origin
    contracts = _mcp_contract.tool_contracts(Path(spec.origin).resolve().parent)
    assert clone_types <= set(contracts["set_source_git"].error_types), clone_types


@pytest.mark.unit
def test_check_installation_notes_list_no_scanners() -> None:
    """The check_installation notes say which scanners a first scan installs by how, not by name.

    The scanners whose tool ASH installs with uv change with the scanner set, so a
    list of them in TOOL_NOTES goes stale without any check failing, and the
    server already reports the current set in ``installs_on_first_scan``. One
    scanner may be named for a behavior of its own (semgrep's rules cache); two or
    more is a list. The names come from the generated scanner reference, so a
    scanner added there is covered here too.
    """
    scanners = re.findall(r"^## `([^`]+)`$", _page("scanners.md"), re.MULTILINE)
    assert len(scanners) >= 10, scanners
    install = _section(_page("mcp-tools.md"), "## check_installation")
    named = [
        name
        for name in scanners
        if re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", install)
    ]
    assert len(named) <= 1, f"check_installation lists scanners by name: {named}"


@pytest.mark.unit
def test_community_loading_is_scoped_to_ash_scan() -> None:
    """ "Loaded only when named" is said of ``ash scan``; the MCP server is pointed elsewhere.

    Under ``ash mcp`` a community scanner registered by an earlier call stays
    registered for later scans, so the unscoped statement is not true there. The
    plugins page says what holds for the MCP server, and this page links to it.
    """
    text = _page("scanners.md")
    intro = text.split("\n| Scanner |", 1)[0]
    assert "that `ash scan` loads only when" in intro
    assert "(../plugins/index.md#what-a-plugin-can-do)" in intro
    provided = [
        ln for ln in text.splitlines() if ln.startswith("- Provided by: community")
    ]
    assert provided, "no community scanners on the page"
    for line in provided:
        assert "which `ash scan` loads when" in line, line


# ---------------------------------------------------------------------------
# What a generator's run touches, and what it renders from the environment
# ---------------------------------------------------------------------------


def _script_module(name: str):
    sys.path.insert(0, str(SCRIPTS))
    try:
        return __import__(name)
    finally:
        sys.path.remove(str(SCRIPTS))


@pytest.mark.unit
def test_home_is_replaced_only_where_it_is_a_path(monkeypatch) -> None:
    """HOME=/d made "Enable/disable" read "Enable~isable" on the CLI page.

    A home path inside a word, or followed by more of a file name, is not the
    home; at the end of a sentence it is. The checkouts' own paths, which a page
    shows as <repository>, follow the same rule.
    """
    module = _script_module("_reference_docs")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/d")))
    monkeypatch.setattr(module, "_ROOTS", [Path("/app")])
    text = (
        "Enable/disable /d/cache, /d and (/d); `/d` /dx /d.bak under /d. "
        "/app/x /application"
    )
    assert module.normalize_paths(text) == (
        "Enable/disable ~/cache, ~ and (~); `~` /dx /d.bak under ~. "
        "<repository>/x /application"
    )


#: What prepare_environment must leave set, and the proxies it points at a closed port.
ISOLATED_DIRECTORIES = (
    "UV_TOOL_DIR",
    "UV_CACHE_DIR",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
)
PROXY_VARIABLES = (
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
)


@pytest.mark.integration
def test_prepare_environment_keeps_a_run_off_the_network_and_out_of_home(
    tmp_path: Path,
) -> None:
    """Building every plugin ran `uv tool run` and wrote into the user's home.

    Online, a scanner page's --check installed every scanner's tool there. After
    prepare_environment, uv and pip are offline, every proxy is a local port that
    refuses connections, and uv's and the XDG directories are temporary ones that
    are gone when the generator exits.
    """
    probe = tmp_path / "probe.py"
    probe.write_text(
        textwrap.dedent(
            """
            import json, os, socket, sys
            sys.path.insert(0, sys.argv[1])
            from _reference_docs import prepare_environment
            prepare_environment()
            names = json.loads(sys.argv[2])
            proxy = os.environ.get("https_proxy") or ""
            refused = None
            if proxy:
                host, port = proxy.rsplit("/", 1)[-1].rsplit(":", 1)
                try:
                    socket.create_connection((host, int(port)), timeout=5).close()
                    refused = False
                except ConnectionRefusedError:
                    refused = True
            print(json.dumps({
                "env": {n: os.environ.get(n) for n in names},
                "refused": refused,
                "dirs": [os.path.isdir(os.environ.get(n) or "") for n in names[:5]],
            }))
            """
        ),
        encoding="utf-8",
    )
    names = [
        *ISOLATED_DIRECTORIES,
        "UV_OFFLINE",
        "PIP_NO_INDEX",
        "NO_PROXY",
        "no_proxy",
    ]
    names += PROXY_VARIABLES
    env = {
        **os.environ,
        "NO_PROXY": "*",
        "no_proxy": "*",
        "UV_CACHE_DIR": str(tmp_path / "planted-cache"),
    }
    result = subprocess.run(
        [sys.executable, str(probe), str(SCRIPTS), json.dumps(names)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    values = report["env"]
    assert values["UV_OFFLINE"] == "1" and values["PIP_NO_INDEX"] == "1", values
    assert values["NO_PROXY"] is None and values["no_proxy"] is None, values
    proxies = {values[n] for n in PROXY_VARIABLES}
    assert len(proxies) == 1 and next(iter(proxies)).startswith("http://127.0.0.1:")
    assert report["refused"] is True
    assert report["dirs"] == [True] * len(ISOLATED_DIRECTORIES)
    roots = {Path(values[n]).parent for n in ISOLATED_DIRECTORIES}
    assert len(roots) == 1, values
    root = next(iter(roots))
    assert str(tmp_path) not in str(root), "the planted UV_CACHE_DIR was kept"
    assert not root.exists(), f"{root} was left behind after the run"


def _hidden_option_page(hidden: bool) -> str:
    import typer

    app = typer.Typer()

    @app.command()
    def scan(
        progress: bool = typer.Option(
            True, "--progress/--no-progress", help="Show progress.", hidden=hidden
        ),
    ) -> None:
        """Scan."""

    @app.command()
    def report() -> None:
        """Report."""

    content, _stats = _script_module("generate_cli_docs").generate(
        typer.main.get_command(app)
    )
    return content


@pytest.mark.unit
def test_hidden_options_are_marked() -> None:
    """An option click hides from --help says so, as a hidden command does."""

    def row(page: str) -> str:
        return next(ln for ln in page.splitlines() if 'id="scan--progress"' in ln)

    assert "hidden" not in row(_hidden_option_page(False))
    assert row(_hidden_option_page(True)).endswith(
        "| Show progress. This option is hidden from `--help` output. |"
    )


@pytest.mark.integration
def test_a_hidden_option_in_ash_changes_the_cli_page(tmp_path: Path) -> None:
    """In ASH itself: hidden=True on `ash scan --progress` fails --check."""
    import importlib.util
    import shutil

    from tests.utils.helpers import iter_repo_files

    spec = importlib.util.find_spec("automated_security_helper")
    assert spec is not None and spec.origin
    source = Path(spec.origin).resolve().parent

    def copy(name: str, plant: bool) -> Path:
        root = tmp_path / name
        # File by file from iter_repo_files, which never enters the tests' scratch
        # tree, rather than copytree, whose walk from a find_spec() result cannot be
        # shown to stay out of it.
        for path in iter_repo_files(source, skip_dirs=frozenset({"__pycache__"})):
            target = root / "automated_security_helper" / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
        shutil.copy2(source.parent / "pyproject.toml", root / "pyproject.toml")
        if plant:
            scan = root / "automated_security_helper" / "cli" / "scan.py"
            text = scan.read_text(encoding="utf-8")
            old = 'help="Show progress of each job live in the console. Defaults to True.",'
            assert text.count(old) == 1
            scan.write_text(text.replace(old, old + " hidden=True,"), encoding="utf-8")
        return root

    page = tmp_path / "cli.md"

    def run(root: Path, *args: str) -> subprocess.CompletedProcess:
        return _run_generator(
            "generate_cli_docs.py",
            "--output",
            str(page),
            *args,
            env={**os.environ, "PYTHONPATH": str(root)},
        )

    control = copy("control", plant=False)
    assert run(control).returncode == 0
    assert run(control, "--check").returncode == 0
    checked = run(copy("planted", plant=True), "--check")
    assert checked.returncode == 1, checked.stderr
    added = [ln for ln in checked.stderr.splitlines() if ln.startswith("+")]
    assert any(
        'id="scan--progress"' in ln and "This option is hidden from `--help`" in ln
        for ln in added
    ), checked.stderr
