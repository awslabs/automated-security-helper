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

It runs every generator with :data:`PLANTED_ENVIRONMENT` set: the variables
whose values once leaked, or would, into a page (``AWS_REGION``,
``ASH_PROJECT_NAME``, ``XDG_CACHE_HOME``, ``COLUMNS``, ...). A generator that
let any of them through would render that value and fail ``--check``, so the
test proves the pages do not depend on the environment they are generated in,
rather than assuming CI's environment is clean.

``test_docs_root_*`` runs a generator against a docs tree other than this
checkout, the way pages are generated from one tree's code into another tree's
docs: the page goes where ``--docs-root`` says, and the scanner page links to
exactly the per-scanner pages that tree holds.

The options-table and Default-cell tests pin the format the docs checks rely on
when they compare a prose table with these pages: each options table carries
``<!-- doctest: options of=<section>.<name> -->`` directly above it, and each
Default cell has one of the forms in ``generate_config_reference.py``.

Two generators own files outside ``docs/content/reference/`` as well, and their
``--check`` covers those too. ``generate_reporter_docs.py`` rewrites the marker
regions in the older docs pages listed in its ``REGIONS``.
``generate_mcp_tool_reference.py`` writes the agentic-plugins
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

import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"
REFERENCE_DIR = REPO_ROOT / "docs" / "content" / "reference"

#: Every generated reference page: generator script -> the page it writes.
#: generate_reporter_docs.py also owns the marker regions listed in its REGIONS, and
#: generate_mcp_tool_reference.py also owns the agentic-plugins tool-reference.md;
#: each one's --check covers everything it writes.
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
}


def _run_generator(script: str, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, **PLANTED_ENVIRONMENT}
    return subprocess.run(
        [sys.executable, str(SCRIPTS / script), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
    )


@pytest.mark.parametrize("script", sorted(REFERENCE_PAGES))
def test_reference_page_is_current(script: str) -> None:
    """The committed reference page equals what its generator emits now."""
    page = REFERENCE_DIR / REFERENCE_PAGES[script]
    assert page.is_file(), f"{page.relative_to(REPO_ROOT)} is missing"
    result = _run_generator(script, "--check")
    assert result.returncode == 0, (
        f"{page.relative_to(REPO_ROOT)} is stale.\n"
        f"Regenerate with: uv run python scripts/{script}\n\n"
        + result.stdout
        + result.stderr
    )


@pytest.mark.parametrize("script", sorted(REFERENCE_PAGES))
def test_reference_page_names_its_generator(script: str) -> None:
    """Each page's banner names the script that writes it and how to rerun it."""
    head = (REFERENCE_DIR / REFERENCE_PAGES[script]).read_text(encoding="utf-8")[:600]
    assert f"Generated by scripts/{script}" in head
    assert f"uv run python scripts/{script}" in head


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


@pytest.mark.parametrize("page", sorted(OPTIONS_PAGES))
def test_options_tables_carry_the_doctest_marker(page: str) -> None:
    """Every options table is marked with the plugin it belongs to, and only those are.

    The marker is on the line directly above the header, and names the same
    ``<section>.<name>`` that each row's anchor starts with.
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
    marker_lines = [
        ln for ln in text.splitlines() if ln.startswith("<!-- doctest: options")
    ]
    assert options_tables == len(marker_lines) > 0


#: Bare phrases a Default cell may hold (generate_config_reference.py, "Default cells").
DEFAULT_PHRASES = {
    "required",
    "computed at run time",
    "see the section",
    "depends on the platform",
    "the plugin's own name",
    "the plugin's defaults",
}
_SPAN = r"(?:``.+?``|`[^`]+`)"
_PLATFORMS = r"(?:Linux|macOS|Windows)(?:(?:, (?:Linux|macOS|Windows))* and (?:Linux|macOS|Windows))?"
DEFAULT_FORMS = (
    re.compile(rf"^(?:from `[A-Za-z_][A-Za-z0-9_]*`, else )*(?P<value>{_SPAN})$"),
    re.compile(rf"^{_SPAN} on {_PLATFORMS}(?:; {_SPAN} on {_PLATFORMS})*$"),
)


@pytest.mark.parametrize("page", ["configuration.md", *sorted(OPTIONS_PAGES)])
def test_default_cells_keep_to_the_documented_forms(page: str) -> None:
    """Every Default cell of a key or option table is a form the docs checks can read.

    A single code span must also load with yaml.safe_load, since that is how a
    reader of the page (and the docs checks) turn it back into a value.
    """
    import yaml

    text = (REFERENCE_DIR / page).read_text(encoding="utf-8")
    checked = 0
    for _index, _above, rows in _tables(text):
        header = _cells(rows[0])
        if header[1:3] != ["Type", "Default"]:
            continue
        for row in rows[1:]:
            cell = _cells(row)[2]
            checked += 1
            if cell in DEFAULT_PHRASES:
                continue
            match = next((m for f in DEFAULT_FORMS if (m := f.match(cell))), None)
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
