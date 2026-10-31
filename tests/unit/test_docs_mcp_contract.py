# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP pages' error types and example responses are held to the tools' returns.

WHY THIS EXISTS
---------------
The MCP pages tell a client which ``error_type`` a refusal carries and show what a
tool returns, and the only statement of either was the prose. Renaming the
``output_dir_not_permitted`` literal in ``run_ash_scan``, or a key of its response,
passed every check and every generator's ``--check``. Now
``scripts/_mcp_contract.py`` reads the tools' return statements,
``scripts/generate_mcp_tool_reference.py`` lists each tool's error types from it,
and ``check_mcp_contract`` in ``scripts/docs_checks.py`` compares the pages'
error-type names and the ``config kind=mcp-response`` examples with it.

WHAT EACH TEST PINS
-------------------
The planted-defect tests copy the source of the ASH this interpreter imports,
make one rename in the copy, and run the check (and the generator) against the
copy and against an unchanged copy: the rename must be reported where the pages
name it, and the unchanged copy must give no finding about that name. They look
only at findings about the planted name, because on a docs branch the pages can
describe newer code than the interpreter's, which other findings then report.

The reader tests plant a small package of their own, one for each way a tool
builds its response, so what the reader can follow is written down and a
refactor that loses one of them fails by name.
"""

from __future__ import annotations

import ast
import fnmatch
import importlib.util
import os
import shutil
import subprocess
import sys
import textwrap
import types
from pathlib import Path

import pytest

from tests.utils.helpers import iter_repo_files

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"
FENCE = "```"


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


dc = _load("_ash_docs_checks", SCRIPTS / "docs_checks.py")


def _reader():
    return _load("_ash_mcp_contract", SCRIPTS / "_mcp_contract.py")


def _installed_package() -> Path:
    spec = importlib.util.find_spec("automated_security_helper")
    assert spec is not None and spec.origin
    return Path(spec.origin).resolve().parent


def _copy_package(dest: Path, edits: dict[str, tuple[str, str]], *, data: bool = False):
    """A copy of the installed package's source under ``dest``, with ``edits`` made.

    ``edits`` maps a path inside the package to (old, new); each old text must occur
    exactly once, so a plant that no longer matches the code fails loudly instead
    of planting nothing. With ``data`` the copy is a source checkout the
    generators accept: every file, and a pyproject.toml beside the package.
    """
    source = _installed_package()
    package = dest / "automated_security_helper"
    # File by file from iter_repo_files, which never enters the tests' scratch tree,
    # rather than copytree, whose walk from a find_spec() result cannot be shown to
    # stay out of it.
    ignored = ("__pycache__", *(() if data else ("*.[!p]*",)))
    for path in iter_repo_files(source):
        rel = path.relative_to(source)
        if any(fnmatch.fnmatch(part, glob) for part in rel.parts for glob in ignored):
            continue
        (package / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, package / rel)
    if data:
        shutil.copy2(source.parent / "pyproject.toml", dest / "pyproject.toml")
    for rel, (old, new) in edits.items():
        path = package / rel
        text = path.read_text(encoding="utf-8")
        assert text.count(old) == 1, (
            f"{rel}: the plant {old!r} matches {text.count(old)} times"
        )
        path.write_text(text.replace(old, new), encoding="utf-8")
    return package


def _mcp_page_files() -> list[Path]:
    """The MCP pages and the generated references, as the gate reads them."""
    found = set()
    for rel in dc.MCP_PAGES:
        if rel.endswith("/"):
            found.update(dc.listed_files(REPO_ROOT / rel, ["**/*.md"]))
        else:
            found.add(REPO_ROOT / rel)
    return sorted(found)


def _findings_about(findings, text: str) -> list[str]:
    return [str(f) for f in findings if text in f.message]


def _findings_naming(findings, error_type: str) -> list[str]:
    """The findings about ``error_type`` itself, not those that only suggest it
    ("did you mean `output_dir_not_permitted`?") for another name."""
    return [str(f) for f in findings if f.message.startswith(f"`{error_type}` ")]


def _check(package: Path, files=None, root: Path = REPO_ROOT):
    dc.load_mcp_contract.cache_clear()
    try:
        return dc.check_mcp_contract(
            files if files is not None else _mcp_page_files(), root, package=package
        )
    finally:
        dc.load_mcp_contract.cache_clear()


# ---------------------------------------------------------------------------
# Planted defects in the real server, against the real pages
# ---------------------------------------------------------------------------

#: run_ash_scan's refusal of a symlinked .ash/ash_output, under a new error_type.
RENAMED_REFUSAL_ERROR_TYPE = {
    "cli/mcp_server.py": (
        '"error_type": "output_dir_not_permitted",',
        '"error_type": "output_dir_refused",',
    )
}
#: A key of run_ash_scan's success response, under a new name.
RENAMED_SUCCESS_KEY = {
    "cli/mcp_server.py": (
        '"directory_path": str(directory_path_obj),',
        '"scanned_path": str(directory_path_obj),',
    )
}


@pytest.mark.integration
def test_a_renamed_error_type_is_reported_where_the_pages_name_it(tmp_path: Path):
    """The pages name output_dir_not_permitted in prose, in the steering guide's
    error table and as a troubleshooting heading; each is reported."""
    control = _check(_copy_package(tmp_path / "control", {}))
    assert _findings_naming(control, "output_dir_not_permitted") == []

    planted = _check(_copy_package(tmp_path / "planted", RENAMED_REFUSAL_ERROR_TYPE))
    reported = _findings_naming(planted, "output_dir_not_permitted")
    assert all("[mcp-error-type]" in line for line in reported)
    places = {line.split(": [", 1)[0] for line in reported}
    named = {
        f"{page.rel}:{number}"
        for page in dc.load_pages(_mcp_page_files(), REPO_ROOT)
        for number, text in page.prose
        if "`output_dir_not_permitted`" in text
    }
    assert places <= named, sorted(places - named)
    for page in (
        "docs/content/how-to/mcp-server.md",
        "docs/content/docs/genai-steering-guide.md",
        "ash-agent-plugins/agentic-coding/transpiler/_base/references/troubleshooting.md",
        "docs/content/reference/mcp-tools.md",
    ):
        on_page = {p for p in named if p.startswith(f"{page}:")}
        assert on_page, f"{page} no longer names output_dir_not_permitted"
        assert on_page <= places, sorted(on_page - places)


@pytest.mark.integration
def test_a_renamed_response_key_is_reported_on_every_example(tmp_path: Path):
    """Every run_ash_scan example shows directory_path; with the key renamed, each
    of them is reported, and the unchanged server gives no such finding."""
    examples = [
        page
        for page in dc.load_pages(_mcp_page_files(), REPO_ROOT)
        for block in page.blocks
        if block.marker is not None
        and block.marker.keys.get("of") == "mcp.run_ash_scan"
    ]
    assert examples, "no run_ash_scan example is marked; nothing would be compared"

    control = _check(_copy_package(tmp_path / "control", {}))
    assert _findings_about(control, "no response run_ash_scan returns") == []

    planted = _check(_copy_package(tmp_path / "planted", RENAMED_SUCCESS_KEY))
    reported = _findings_about(
        planted, "no response run_ash_scan returns has `directory_path`"
    )
    assert len(reported) == len(examples), reported
    assert all("[mcp-response]" in line for line in reported)


@pytest.mark.integration
def test_the_generator_check_fails_on_a_renamed_error_type(tmp_path: Path):
    """--check of the MCP reference fails on the renamed refusal, naming both spellings.

    The page is generated from an unchanged copy first, so this does not depend on
    the committed page being current for this interpreter's code. A renamed
    response key does not change the page (its examples are editorial notes),
    which is why the docs check compares the examples with the returns.
    """
    page = tmp_path / "mcp-tools.md"
    control = _copy_package(tmp_path / "control", {}, data=True)
    planted = _copy_package(tmp_path / "planted", RENAMED_REFUSAL_ERROR_TYPE, data=True)

    def run(package: Path, *args: str) -> subprocess.CompletedProcess:
        env = {**os.environ, "PYTHONPATH": str(package.parent)}
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "generate_mcp_tool_reference.py"),
                "--output",
                str(page),
                *args,
            ],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            env=env,
            timeout=300,
        )

    written = run(control)
    assert written.returncode == 0, written.stderr
    assert str(control) in written.stderr
    assert run(control, "--check").returncode == 0
    checked = run(planted, "--check")
    assert checked.returncode == 1, checked.stderr
    diff = checked.stderr.splitlines()
    removed = [ln for ln in diff if ln.startswith("-On failure")]
    added = [ln for ln in diff if ln.startswith("+On failure")]
    assert any("`output_dir_not_permitted`" in ln for ln in removed), checked.stderr
    assert any("`output_dir_refused`" in ln for ln in added), checked.stderr


# ---------------------------------------------------------------------------
# The rule: what counts as an error-type name on a page
# ---------------------------------------------------------------------------

MCP_PAGE = "docs/content/how-to/mcp-server.md"


def _page(tmp_path: Path, text: str, rel: str = MCP_PAGE):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    return path


def _spans(tmp_path: Path, text: str, rel: str = MCP_PAGE) -> list[tuple[int, str]]:
    page = dc.parse_page(_page(tmp_path, text, rel), tmp_path)
    return [
        (s.line, s.value)
        for s in dc.error_type_spans(page, dc.is_mcp_page(rel), {"run_ash_scan"})
    ]


@pytest.mark.unit
def test_each_phrasing_names_an_error_type(tmp_path: Path):
    spans = _spans(
        tmp_path,
        """
        A refusal has `error_type` `alpha_refused`, and a delivered one
        `error_type`
        `beta_refused`. The reference says `error_type` is one of `gamma_one`, `gamma_two` and
        `gamma_three`, or the class name of an exception.

        The MCP tools report it with `error_type: delta_denied`, and `"error_category": "eps_cat"`.
        `validate_config` reports an error of type `zeta_denied`, and a file is refused with
        `eta_unreadable`. After a restart `get_scan_progress` fails with `theta_not_found`.

        ## `iota_not_permitted`

        A failed call returns an `error_type`. The names:

        | You see | Do this |
        |---------|---------|
        | `kappa_refused`, or `lambda_path` from a results tool | Ask. |
        | `nu_incomplete` with `a_response_field` true | Run it again. |
        | Exit code 1, or status `incomplete` | Tell the user. |

        <!-- doctest: config kind=mcp-response of=mcp.run_ash_scan -->
        ```json
        {"success": false, "error_type": "mu_refused"}
        ```
        """,
    )
    assert [value for _, value in spans] == [
        "alpha_refused",
        "beta_refused",
        "gamma_one",
        "gamma_two",
        "gamma_three",
        "delta_denied",
        "eps_cat",
        "zeta_denied",
        "eta_unreadable",
        "theta_not_found",
        "iota_not_permitted",
        "kappa_refused",
        "lambda_path",
        "nu_incomplete",
        "mu_refused",
    ]
    assert {v: line for line, v in spans}["beta_refused"] == 3


@pytest.mark.unit
def test_what_is_not_an_error_type_name(tmp_path: Path):
    """A clause after the name, a tool after it, and prose without a context."""
    spans = _spans(
        tmp_path,
        """
        It is refused with `error_type` `ok_refused`, and `set_source_git` with an error.
        The tools return `error_type`
        `ok_two`, and `run_ash_scan` does not start. Another returns `error_type` `ok_three` or
        `run_ash_scan`.

        A plain `no_context_name` is not one, and neither is a table under a paragraph
        that names no error field:

        | You see | Do this |
        |---------|---------|
        | `not_under_error_type` | Nothing. |
        """,
    )
    assert [value for _, value in spans] == ["ok_refused", "ok_two", "ok_three"]
    other = _spans(
        tmp_path,
        """
        ## `a_heading_name`

        Refused with `a_refused_name`; an error of type `a_typed_name`.
        Still checked everywhere: `error_type` `named_by_field`.
        """,
        rel="docs/content/how-to/other.md",
    )
    assert [value for _, value in other] == ["named_by_field"]


def _plant_server(root: Path, body: str) -> Path:
    package = root / "automated_security_helper"
    (package / "cli").mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "cli" / "__init__.py").write_text("", encoding="utf-8")
    (package / "cli" / "mcp_server.py").write_text(
        textwrap.dedent(body).lstrip("\n"), encoding="utf-8"
    )
    return package


@pytest.mark.unit
def test_mcp_contract_check_can_fail(tmp_path: Path):
    """The gate's registered check: each kind of finding, and a clean control."""
    package = _plant_server(
        tmp_path / "code",
        """
        mcp = object()


        @mcp.tool()
        def run_thing(path):
            if not path:
                return {"success": False, "error": "no", "error_type": "thing_refused"}
            return {"success": True, "status": "running", "detail": {"id": 1}}
        """,
    )
    clean = _page(
        tmp_path / "docs",
        f"""
        A call without a path is refused with `error_type` `thing_refused`.

        <!-- doctest: config kind=mcp-response of=mcp.run_thing -->
        {FENCE}json
        {{"success": true, "status": "running", "detail": {{"id": 1}}}}
        {FENCE}

        <!-- doctest: config kind=mcp-response of=mcp.run_thing -->
        {FENCE}text
        {{ "success": bool, "status": "running | failed", "detail": {{ ... }} }}
        {FENCE}
        """,
    )
    assert _check(package, [clean], tmp_path / "docs") == []

    planted = _page(
        tmp_path / "docs",
        f"""
        A call without a path is refused with `error_type` `thing_refusd`.

        <!-- doctest: config kind=mcp-response of=mcp.run_thing -->
        {FENCE}json
        {{"success": true, "state": "running", "detail": {{"id": 1, "idx": 2}}}}
        {FENCE}

        <!-- doctest: config kind=mcp-response of=mcp.run_thingy -->
        {FENCE}text
        {{ "success": bool }}
        {FENCE}

        <!-- doctest: config kind=mcp-response of=mcp.run_thing -->
        {FENCE}text
        nothing that looks like a key
        {FENCE}

        ## `thing_refusd`
        """,
    )
    findings = _check(package, [planted], tmp_path / "docs")
    messages = [str(f) for f in findings]
    assert any(
        ":1: [mcp-error-type] `thing_refusd` is named as an error (after `error_type`)"
        in m
        and "did you mean `thing_refused`?" in m
        for m in messages
    ), messages
    assert any(":18: [mcp-error-type] `thing_refusd`" in m for m in messages), messages
    assert any(
        "[mcp-response] no response run_thing returns has `state`, `detail.idx`" in m
        for m in messages
    ), messages
    assert any(
        "of=mcp.run_thingy names no MCP tool; did you mean mcp.run_thing?" in m
        for m in messages
    ), messages
    assert any("the example has no keys" in m for m in messages), messages


@pytest.mark.unit
def test_a_check_that_reads_nothing_fails(tmp_path: Path):
    """No error-type names and no examples is a finding, never a pass."""
    package = _plant_server(
        tmp_path / "code",
        """
        mcp = object()


        @mcp.tool()
        def run_thing():
            return {"success": True}
        """,
    )
    empty = _page(tmp_path / "docs", "# Nothing about errors here\n")
    messages = [f.message for f in _check(package, [empty], tmp_path / "docs")]
    assert any("found no error-type names" in m for m in messages), messages
    assert any("found no config kind=mcp-response examples" in m for m in messages)


@pytest.mark.unit
@pytest.mark.parametrize(
    "marker, lang, expected",
    [
        ("config kind=mcp-response of=mcp.run_ash_scan", "json", None),
        ("config kind=mcp-response of=mcp.run_ash_scan", "text", None),
        ("config kind=mcp-response", "json", "needs of=mcp.<tool>"),
        ("config kind=mcp-response of=run_ash_scan", "text", "needs of=mcp.<tool>"),
        ("config kind=mcp-response of=mcp.run_ash_scan", "yaml", "is a json block"),
        (
            'config kind=mcp-response of=mcp.run_ash_scan reason="an example"',
            "json",
            "does not take ['reason']",
        ),
        ("config kind=other of=mcp.run_ash_scan", "text", "markers apply to"),
    ],
)
def test_the_response_marker(tmp_path: Path, marker: str, lang: str, expected):
    page = _page(
        tmp_path,
        f'<!-- doctest: {marker} -->\n{FENCE}{lang}\n{{"success": true}}\n{FENCE}\n',
        rel="docs/page.md",
    )
    findings = dc.check_markers([page], tmp_path)
    if expected is None:
        assert findings == []
    else:
        assert any(expected in f.message for f in findings), [str(f) for f in findings]


# ---------------------------------------------------------------------------
# The reader: each way a tool builds its response
# ---------------------------------------------------------------------------

PLANTED_TOOLS = """
from typing import NamedTuple, Optional

from automated_security_helper.cli.helpers import (
    DENIED,
    CloneRefused,
    Registry,
    clone_it,
    denied_response,
    get_registry,
)

mcp = object()
UNREADABLE = "policy_unreadable"


class _Resolution(NamedTuple):
    path: Optional[str] = None
    error: Optional[dict] = None


def _resolve(session):
    if session is None:
        return _Resolution(error={"success": False, "error_type": "no_source"})
    return _Resolution(path="/x")


def _with_session(result, session):
    return {**result, "session_id": session}


@mcp.tool()
async def scan(session=None, flag=False):
    resolved = _resolve(session)
    if resolved.error is not None:
        return resolved.error
    result = await start(session)
    if result.get("error_type") in (DENIED, UNREADABLE):
        return result
    if flag:
        return {"error_type": UNREADABLE if session else DENIED}
    try:
        pass
    except Exception as e:
        return {"success": False, "error_type": type(e).__name__}
    return {"success": True, "scan_id": result["scan_id"], "important": {"next": []}}


async def start(session):
    if session == "deny":
        return denied_response()
    if session == "other":
        return {"success": False, "error_type": "never_returned_by_scan"}
    return {"success": True, "scan_id": "1", "only_start_has_this": 1}


@mcp.tool(name="progress")
def get_progress(scan_id):
    info = get_registry().check(scan_id)
    info["scanners"] = {}
    info.update(severity_counts={}, timestamp="t")
    return _with_session(info, "s")


@mcp.tool()
def validate(text):
    def classify(raw):
        if raw:
            return {"field": "", "message": raw, "type": "yaml_parse_error"}
        return {"field": "", "message": raw, "type": "validation_error"}

    errors = [classify(e) for e in text]
    errors.append({"field": "", "message": "x", "type": "denied_field"})
    return {"valid": not errors, "errors": errors}


@mcp.tool()
def unreadable(kind):
    return {"error_type": kind.upper()}


@mcp.tool()
def clone(url):
    try:
        clone_it(url)
    except CloneRefused as e:
        return {"success": False, "error_type": e.error_type}
    except ValueError as e:
        return {"success": False, "error": str(e)}
    return {"success": True}
"""

PLANTED_HELPERS = """
from enum import Enum

DENIED = "field_denied"


class Category(Enum):
    MISSING = "scan_not_found"


class Registry:
    def check(self, scan_id):
        base = {"scan_id": scan_id, "status": "running"}
        return {**base, "error_category": Category.MISSING.value}


def get_registry() -> Registry:
    return Registry()


def denied_response():
    return {"success": False, "error_type": DENIED, "operation": "scan"}


URL_REFUSED = "clone_url_refused"


class CloneRefused(RuntimeError):
    def __init__(self, message, error_type):
        super().__init__(message)
        self.error_type = error_type


def clone_it(url):
    if url.startswith("-"):
        raise CloneRefused(f"refused {url}", URL_REFUSED)
    raise CloneRefused("git failed", "clone_failed")
"""


def _line_of(text: str) -> int:
    """The line of the planted server that holds ``text``."""
    lines = textwrap.dedent(PLANTED_TOOLS).lstrip("\n").splitlines()
    return next(i for i, line in enumerate(lines, 1) if text in line)


@pytest.fixture
def planted_contracts(tmp_path: Path):
    package = _plant_server(tmp_path, PLANTED_TOOLS)
    (package / "cli" / "helpers.py").write_text(
        textwrap.dedent(PLANTED_HELPERS).lstrip("\n"), encoding="utf-8"
    )
    return _reader().tool_contracts(package), package


@pytest.mark.unit
def test_error_types_through_constants_calls_attributes_and_guards(planted_contracts):
    """Imported constants, a helper's dict, a NamedTuple's field, a conditional,
    and type(e).__name__; under the guard, only the start() responses whose
    error_type the guard allows are returned."""
    contracts, _ = planted_contracts
    scan = contracts["scan"]
    assert scan.error_types == ("field_denied", "no_source", "policy_unreadable")
    assert scan.error_class_name is True
    assert scan.error_types_unread == ()
    assert "never_returned_by_scan" not in scan.error_types
    keys = scan.response.keys()
    assert "only_start_has_this" not in keys
    assert {"scan_id", "important", "operation"} <= set(keys)


@pytest.mark.unit
def test_response_keys_through_methods_stores_updates_and_spreads(planted_contracts):
    """A method found from a return annotation, keys a subscript store and update()
    add, a dict spread, and a parameter bound at the call (_with_session)."""
    contracts, _ = planted_contracts
    progress = contracts["progress"]
    assert progress.origin.endswith(f"mcp_server.py:{_line_of('def get_progress')}")
    keys = set(progress.response.keys())
    assert {
        "scan_id",
        "status",
        "error_category",
        "scanners",
        "severity_counts",
        "timestamp",
        "session_id",
    } <= keys
    reader = _reader()
    assert (
        reader.missing_keys({"scan_id": None, "session_id": None}, progress.response)
        is None
    )
    assert reader.missing_keys({"scan_id": None, "nope": None}, progress.response) == [
        "nope"
    ]


@pytest.mark.unit
def test_entry_types_and_what_cannot_be_read(planted_contracts):
    """validate_config's errors[].type, through a nested function and append();
    an error_type computed at run time is reported as unread, never guessed."""
    contracts, package = planted_contracts
    assert contracts["validate"].entry_types == (
        "denied_field",
        "validation_error",
        "yaml_parse_error",
    )
    unreadable = contracts["unreadable"]
    assert unreadable.error_types == ()
    assert unreadable.error_types_unread == (
        f"automated_security_helper/cli/mcp_server.py:{_line_of('kind.upper()')}",
    )
    assert _reader().enum_values(package, "Category") == {"scan_not_found"}


@pytest.mark.unit
def test_error_types_carried_by_a_caught_exception(planted_contracts):
    """``except CloneRefused as e: ... e.error_type``: each value the package
    builds the exception with, and only that handler's exception, not the
    ValueError another handler binds to the same name."""
    contracts, _ = planted_contracts
    clone = contracts["clone"]
    assert clone.error_types == ("clone_failed", "clone_url_refused")
    assert clone.error_types_unread == ()


PLANTED_STEP_SERVER = """
from automated_security_helper.cli.tools import mcp_fetch, mcp_loose

mcp = object()


@mcp.tool()
def fetch(url):
    return mcp_fetch(url)


@mcp.tool()
def loose(url):
    return mcp_loose(url)
"""

PLANTED_STEP_TOOLS = """
FETCH_FAILED = "fetch_failed"
PARSE_FAILED = "parse_failed"
LOOSE_FAILED = "loose_failed"


class StepError(RuntimeError):
    def __init__(self, message, error_type, *, retried=False):
        super().__init__(message)
        self.error_type = error_type
        self.retried = retried


def _step(url, *, what, error_type):
    try:
        return len(url)
    except (OSError, ValueError) as e:
        raise StepError(f"{what} failed ({e})", error_type) from e


def _fetch(url):
    try:
        _step(url, what="fetch", error_type=FETCH_FAILED)
        _step(url, what="parse", error_type=PARSE_FAILED)
    except StepError as e:
        raise StepError(f"retry: {e}", e.error_type, retried=True) from e


def mcp_fetch(url):
    try:
        _fetch(url)
    except StepError as e:
        return {"success": False, "error": str(e), "error_type": e.error_type}
    return {"success": True}


class LooseError(RuntimeError):
    def __init__(self, message, error_type):
        super().__init__(message)
        self.error_type = error_type


def _loose_step(url, error_type):
    raise LooseError("loose", error_type)


def mcp_loose(url):
    # The helper is also reached through a name, which this reader does not follow.
    step = _loose_step
    try:
        _loose_step(url, LOOSE_FAILED)
        step(url, url)
    except LooseError as e:
        return {"success": False, "error_type": e.error_type}
    return {"success": True}
"""


@pytest.fixture
def planted_step_contracts(tmp_path: Path):
    package = _plant_server(tmp_path, PLANTED_STEP_SERVER)
    (package / "cli" / "tools.py").write_text(
        textwrap.dedent(PLANTED_STEP_TOOLS).lstrip("\n"), encoding="utf-8"
    )
    return _reader().tool_contracts(package)


@pytest.mark.unit
def test_a_type_passed_to_a_helper_and_a_type_raised_again_are_read(
    planted_step_contracts,
):
    """``raise StepError(msg, error_type)`` in a helper reads as what every call of
    the helper passes, and ``raise StepError(msg, e.error_type)`` in the handler
    of ``except StepError as e`` adds nothing of its own."""
    fetch = planted_step_contracts["fetch"]
    assert fetch.error_types == ("fetch_failed", "parse_failed")
    assert fetch.error_types_unread == ()


@pytest.mark.unit
def test_a_helper_reached_other_than_by_a_call_keeps_its_type_unread(
    planted_step_contracts,
):
    """With ``step = _loose_step`` the helper has a caller the reader does not
    place, so the type it is given stays unread rather than guessed."""
    loose = planted_step_contracts["loose"]
    assert loose.error_types_unread != ()
    assert "loose_failed" not in loose.error_types


PLANTED_EDGE_SERVER = """
from automated_security_helper.cli.tools import (
    _ren_step as _again,
    mcp_default,
    mcp_foreign,
    mcp_lambda,
    mcp_positional,
    mcp_renamed,
    mcp_reraise_only,
    mcp_suffixed,
)

mcp = object()


@mcp.tool()
def positional(url):
    return mcp_positional(url)


@mcp.tool()
def default(url):
    return mcp_default(url)


@mcp.tool()
def renamed(url):
    _again(url, "ren_via_alias")
    return mcp_renamed(url)


@mcp.tool()
def lambda_built(url):
    return mcp_lambda(url)


@mcp.tool()
def foreign(url):
    return mcp_foreign(url)


@mcp.tool()
def suffixed(url):
    return mcp_suffixed(url)


@mcp.tool()
def reraise_only(url):
    return mcp_reraise_only(url)
"""

PLANTED_EDGE_TOOLS = """
POS_FAILED = "pos_failed"
DFLT_FAILED = "dflt_failed"


class Typed(RuntimeError):
    def __init__(self, message, error_type):
        super().__init__(message)
        self.error_type = error_type


class PosErr(Typed):
    pass


class DfltErr(Typed):
    pass


class RenErr(Typed):
    pass


class LamErr(Typed):
    pass


class FamErr(Typed):
    pass


class OnlyRe(Typed):
    pass


class OtherErr(RuntimeError):
    error_type = "other_x"


class Suffixed(RuntimeError):
    def __init__(self, message, error_type):
        super().__init__(message)
        self.error_type = error_type
        self.error_type += "_x"


def _pos_step(url, error_type):
    raise PosErr("pos", error_type)


def mcp_positional(url):
    try:
        _pos_step(url, POS_FAILED)
    except PosErr as e:
        return {"success": False, "error_type": e.error_type}
    return {"success": True}


def _dflt_step(url, error_type=DFLT_FAILED):
    raise DfltErr("dflt", error_type)


def mcp_default(url):
    try:
        _dflt_step(url)
        _dflt_step(url, error_type="dflt_other")
    except DfltErr as e:
        return {"success": False, "error_type": e.error_type}
    return {"success": True}


def _ren_step(url, error_type):
    raise RenErr("ren", error_type)


def mcp_renamed(url):
    try:
        _ren_step(url, "ren_direct")
    except RenErr as e:
        return {"success": False, "error_type": e.error_type}
    return {"success": True}


def mcp_lambda(url, error_type="caller_value"):
    make = lambda error_type: LamErr("lam", error_type)
    try:
        raise make("lam_arg")
    except LamErr as e:
        return {"success": False, "error_type": e.error_type}


def _foreign_step(url):
    try:
        raise OtherErr("other")
    except OtherErr as e:
        raise FamErr("from other", e.error_type) from e


def mcp_foreign(url):
    try:
        _foreign_step(url)
        raise FamErr("fam", "fam_a")
    except FamErr as e:
        return {"success": False, "error_type": e.error_type}


def _suffixed_again(url):
    try:
        raise Suffixed("first", "fetch")
    except Suffixed as e:
        raise Suffixed("again", e.error_type) from e


def mcp_suffixed(url):
    try:
        _suffixed_again(url)
    except Suffixed as e:
        return {"success": False, "error_type": e.error_type}


_make = OnlyRe


def _only_again(url):
    try:
        raise _make("first", "only_failed")
    except OnlyRe as e:
        raise OnlyRe("again", e.error_type) from e


def mcp_reraise_only(url):
    try:
        _only_again(url)
    except OnlyRe as e:
        return {"success": False, "error_type": e.error_type}
"""


@pytest.fixture
def planted_edge_contracts(tmp_path: Path):
    package = _plant_server(tmp_path, PLANTED_EDGE_SERVER)
    (package / "cli" / "tools.py").write_text(
        textwrap.dedent(PLANTED_EDGE_TOOLS).lstrip("\n"), encoding="utf-8"
    )
    return _reader().tool_contracts(package)


def _edge_line(text: str) -> str:
    """The reader's site for the planted tools' line that holds ``text``."""
    lines = textwrap.dedent(PLANTED_EDGE_TOOLS).lstrip("\n").splitlines()
    number = next(i for i, line in enumerate(lines, 1) if text in line)
    return f"automated_security_helper/cli/tools.py:{number}"


@pytest.mark.unit
def test_a_helper_called_by_position_or_by_default_gives_its_types(
    planted_edge_contracts,
):
    """A call that passes the type by position, and one that leaves it to the
    parameter's default, are read like one that names it."""
    assert planted_edge_contracts["positional"].error_types == ("pos_failed",)
    assert planted_edge_contracts["positional"].error_types_unread == ()
    default = planted_edge_contracts["default"]
    assert default.error_types == ("dflt_failed", "dflt_other")
    assert default.error_types_unread == ()


@pytest.mark.unit
def test_a_helper_imported_under_another_name_keeps_its_type_unread(
    planted_edge_contracts,
):
    """The server calls ``_ren_step`` as ``_again``: a caller by another name, so
    the type given at the one call the reader sees is not the whole list."""
    renamed = planted_edge_contracts["renamed"]
    assert renamed.error_types_unread != ()
    assert renamed.error_types == ()


@pytest.mark.unit
def test_a_construction_in_a_lambda_does_not_read_the_functions_parameter(
    planted_edge_contracts,
):
    """The lambda's own ``error_type`` shadows the function's parameter."""
    built = planted_edge_contracts["lambda_built"]
    assert built.error_types_unread != ()
    assert not {"caller_value", "lam_arg"} & set(built.error_types)


@pytest.mark.unit
def test_a_type_raised_again_from_another_class_stays_unread(
    planted_edge_contracts,
):
    """``except OtherErr as e: raise FamErr(m, e.error_type)``: OtherErr is not in
    FamErr's family, so what it carries is not among FamErr's own types."""
    foreign = planted_edge_contracts["foreign"]
    assert foreign.error_types == ("fam_a",)
    assert foreign.error_types_unread == (
        _edge_line('raise FamErr("from other", e.error_type)'),
    )


@pytest.mark.unit
def test_a_type_the_init_transforms_is_not_raised_again_as_it_was(
    planted_edge_contracts,
):
    """``self.error_type = error_type`` then ``self.error_type += "_x"``: the
    object raised again carries ``fetch_x_x``, a type no construction passes. The
    reader does not model the ``+=``, so the re-raise's argument is unread
    rather than taken to be a type already listed."""
    suffixed = planted_edge_contracts["suffixed"]
    assert _edge_line('raise Suffixed("again", e.error_type)') in (
        suffixed.error_types_unread
    )


@pytest.mark.unit
def test_a_class_built_only_by_raising_again_is_not_a_complete_empty_list(
    planted_edge_contracts,
):
    """The one visible construction raises a caught object again, and the real
    one goes through an alias the reader does not follow: nothing is known, which
    is unread, not an empty list read to the end."""
    only = planted_edge_contracts["reraise_only"]
    assert only.error_types == ()
    assert only.error_types_unread != ()


PLANTED_EXECUTOR_SERVER = """
import asyncio
import functools
from asyncio import to_thread

from automated_security_helper.cli.tools import get_registry, mcp_clear, mcp_clone

mcp = object()


def _scoped(session):
    return {"session_id": session}


async def _run_on(function, kwargs):
    return await asyncio.get_running_loop().run_in_executor(
        None, functools.partial(function, **kwargs)
    )


async def _run_clone(function, /, **kwargs):
    return await _run_on(function, kwargs)


async def _run_delivery(function, /, **kwargs):
    return await _run_on(function, kwargs)


async def _run_elsewhere(function, /, **kwargs):
    return await _run_on(function, kwargs)


def _with_session(result, session):
    return {**result, "session_id": session}


@mcp.tool()
async def clone(url):
    result = await _run_clone(mcp_clone, url=url)
    return _with_session(result, "s")


@mcp.tool()
async def clear():
    return _with_session(await _run_delivery(mcp_clear, session_id="s"), "s")


@mcp.tool()
async def elsewhere():
    return _with_session(await _run_elsewhere(mcp_clear, session_id="s"), "s")


@mcp.tool()
async def clone_on_thread(url):
    result = await asyncio.to_thread(mcp_clone, url)
    return _with_session(result, "s")


@mcp.tool()
async def progress_on_thread(scan_id):
    registry = get_registry()
    return await to_thread(registry.progress, scan_id, **_scoped("s"))


@mcp.tool()
async def literal_on_thread():
    return await asyncio.to_thread("not a callable")
"""

PLANTED_EXECUTOR_TOOLS = """
BUSY = "workspace_busy"
TIMED_OUT = "clone_timed_out"


class Registry:
    def progress(self, scan_id, session_id=None):
        try:
            if session_id is None:
                raise Busy("held")
        except Busy as e:
            return {"success": False, "error_type": e.error_type}
        return {"success": True, "scan_id": scan_id, "status": "RUNNING"}


def get_registry() -> Registry:
    return Registry()


class CloneRefused(RuntimeError):
    error_type = "clone_refused"


class TimedOut(CloneRefused):
    error_type = TIMED_OUT


class Busy(RuntimeError):
    error_type = BUSY


def _fail(url):
    if not url:
        raise TimedOut("slow")
    raise CloneRefused("no")


def mcp_clone(url):
    try:
        _fail(url)
    except CloneRefused as e:
        return {"success": False, "error": str(e), "error_type": e.error_type}
    return {"success": True}


def mcp_clear(session_id):
    try:
        raise Busy("held")
    except Busy as e:
        return {"success": False, "error_type": e.error_type}
    return {"success": True}
"""


@pytest.fixture
def planted_executor_contracts(tmp_path: Path):
    package = _plant_server(tmp_path, PLANTED_EXECUTOR_SERVER)
    (package / "cli" / "tools.py").write_text(
        textwrap.dedent(PLANTED_EXECUTOR_TOOLS).lstrip("\n"), encoding="utf-8"
    )
    return _reader().tool_contracts(package)


@pytest.mark.unit
def test_a_tool_that_runs_its_implementation_on_an_executor_returns_its_types(
    planted_executor_contracts,
):
    """``await _run_clone(f, **kw)`` is ``f(**kw)``: the types ``f`` returns are the
    tool's, and the dict it returns is read rather than left open at the
    ``_with_session`` spread. A wrapper that is not a declared runner stays unread,
    so the planted ``elsewhere`` tool is the control that nothing else is followed."""
    contracts = planted_executor_contracts
    for name, expected in (
        ("clone", ("clone_refused", "clone_timed_out")),
        ("clear", ("workspace_busy",)),
    ):
        contract = contracts[name]
        assert contract.error_types == expected, name
        assert contract.error_types_unread == (), name
        assert [
            v for v in contract.response.variants if getattr(v, "open_at", ())
        ] == [], name
    elsewhere = contracts["elsewhere"]
    assert elsewhere.error_types == ()
    assert any(getattr(v, "open_at", ()) for v in elsewhere.response.variants)


@pytest.mark.unit
def test_a_tool_that_runs_its_implementation_on_a_thread_returns_its_types(
    planted_executor_contracts,
):
    """``await asyncio.to_thread(f, *args, **kw)`` is ``f(*args, **kw)``: the
    types ``f`` returns are the tool's and its dict is read, whether ``f`` is a
    package function called through ``asyncio.to_thread`` or a method on an
    object the source names, called through ``to_thread`` imported by name with
    a positional argument and a keyword spread. Before the reader followed it,
    the call was an unread value, so a tool whose whole response came through it
    listed no error type and no key."""
    contracts = planted_executor_contracts
    clone = contracts["clone_on_thread"]
    assert clone.error_types == ("clone_refused", "clone_timed_out")
    assert clone.error_types_unread == ()
    assert [v for v in clone.response.variants if getattr(v, "open_at", ())] == []
    assert {"success", "error_type", "session_id"} <= set(clone.response.keys())
    progress = contracts["progress_on_thread"]
    assert progress.error_types == ("workspace_busy",)
    assert progress.error_types_unread == ()
    assert {"success", "error_type", "scan_id", "status"} <= set(
        progress.response.keys()
    )


@pytest.mark.unit
def test_a_thread_run_of_a_non_callable_stays_unread(planted_executor_contracts):
    """The planted-negative control for the runner: ``asyncio.to_thread`` of a
    string literal names no function the reader can follow, so the tool's
    response is the unread value it was before the reader followed the runner,
    with no error type and nothing read into its keys."""
    reader = _reader()
    literal = planted_executor_contracts["literal_on_thread"]
    assert literal.error_types == ()
    assert [type(v) for v in literal.response.variants] == [reader.UnreadV]


PLANTED_SELF_READING_TOOLS = """
class Boom(RuntimeError):
    error_type = "boom"

    def __init__(self, detail):
        super().__init__(detail)
        self.detail = detail


def helper(flag):
    try:
        raise Boom("first")
    except Boom as e:
        detail = e.detail if flag else "second"
        raise Boom(detail)


def run(flag):
    try:
        helper(flag)
    except Boom as e:
        return {"success": False, "error_type": e.error_type, "detail": e.detail}
    return {"success": True}
"""


@pytest.mark.unit
def test_a_construction_that_reads_a_caught_exception_of_its_own_class_ends(
    tmp_path: Path,
):
    """``raise Boom(detail)`` under ``except Boom as e`` with ``detail`` read from
    ``e``: reading the caught Boom reads its constructions, one of which reads a
    caught Boom, which reads its constructions again. Each construction's argument
    is read in a scope of its own, so the name guard never sees the repeat; the
    class-level guard does, and the inner read is unread while the outer one
    stands. Before the guard this read ended in a RecursionError, which made every
    tool of a package with such a handler unreadable."""
    package = _plant_server(
        tmp_path,
        """
        from automated_security_helper.cli.tools import run

        mcp = object()


        @mcp.tool()
        def planted(flag):
            return run(flag)
        """,
    )
    (package / "cli" / "tools.py").write_text(
        textwrap.dedent(PLANTED_SELF_READING_TOOLS).lstrip("\n"), encoding="utf-8"
    )
    planted = _reader().tool_contracts(package)["planted"]
    assert planted.error_types == ("boom",)
    assert planted.error_types_unread == ()
    assert {"success", "error_type", "detail"} <= set(planted.response.keys())


@pytest.mark.unit
def test_the_runners_the_reader_follows_are_defined_by_the_server():
    reader = _reader()
    server = ast.parse(
        (_installed_package() / "cli" / "mcp_server.py").read_text(encoding="utf-8")
    )
    defined = {
        node.name
        for node in server.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert reader.CALLABLE_RUNNERS
    for dotted in reader.CALLABLE_RUNNERS:
        module, _, name = dotted.rpartition(".")
        assert module == reader.SERVER_MODULE, dotted
        assert name in defined, dotted


@pytest.mark.unit
def test_the_source_delivery_tools_return_the_types_their_implementations_do():
    """The clone and upload tools run on executors; their refusals still reach the
    pages' check (the `clone_*` types, and `session_workspace_busy` from a chunk)."""
    contracts = _reader().tool_contracts(_installed_package())
    assert {
        "clone_host_not_permitted",
        "clone_timed_out",
        "clone_url_not_permitted",
        "local_clone_source_refused",
        "ssh_key_not_registered",
    } <= set(contracts["set_source_git"].error_types)
    assert "session_workspace_busy" in contracts["set_source_zip_chunk"].error_types
    for name in ("clear_source", "set_source_git", "set_source_zip_finalize"):
        assert contracts[name].error_types_unread == (), name


PLANTED_FORMS = """
import re

mcp = object()

BUSY = "delivery_busy"
LIMIT = "scan_limit"
INPUT_REFUSED = "input_not_permitted"
SOURCE_DELIVERY_BUSY = "source_delivery_busy"
SESSION_SCAN_LIMIT = "session_scan_limit"
CONFIG_INPUT_NOT_PERMITTED = "config_input_not_permitted"
CONFIG_ENV_NOT_RESOLVED = "config_env_not_resolved"


async def start(kind):
    if kind == "busy":
        return {"success": False, "error_type": BUSY, "error": "busy"}
    if kind == "limit":
        return {"success": False, "error_type": LIMIT, "error": "limit"}
    if kind == "policy":
        return {"success": False, "error_type": "policy_refused", "error": "no"}
    return {"success": True, "scan_id": "1"}


@mcp.tool()
async def scan_plain(kind):
    result = await start(kind)
    return {"success": False, "error_type": result["error_type"]}


@mcp.tool()
async def scan_inline(kind):
    result = await start(kind)
    return {
        "success": False,
        "error_type": (
            result["error_type"]
            if result.get("error_type") in (BUSY, LIMIT)
            else "start_failure"
        ),
    }


@mcp.tool()
async def scan_kept(kind):
    result = await start(kind)
    if not result.get("success", False) or "scan_id" not in result:
        kept = result.get("error_type") in (BUSY, LIMIT)
        return {
            "success": False,
            "error_type": result["error_type"] if kept else "start_failure",
        }
    return {"success": True, "scan_id": result["scan_id"]}


@mcp.tool()
async def scan_accumulated(kind):
    result = await start(kind)
    kept = False
    kept |= result.get("error_type") in (BUSY, LIMIT)
    return {
        "success": False,
        "error_type": result["error_type"] if kept else "start_failure",
    }


@mcp.tool()
def validate_accumulated(text):
    errors = []
    errors += [{"field": "f", "type": "unknown_field"}]
    return {"valid": False, "errors": errors}


@mcp.tool()
def read_merged(path):
    refusal = {"success": False}
    refusal |= {"error_type": "merge_refused"}
    return refusal


@mcp.tool()
def read_overridden(path):
    return {
        "success": False,
        "error_type": "pinned_refusal",
        **globals()["transform"](path),
    }


def rewrap_source(path):
    if path:
        return {"success": False, "error_type": "inner_refused"}
    return {"success": True}


@mcp.tool()
def read_rewrapped(path):
    return {**rewrap_source(path), "error_type": "rewrapped_refusal"}


@mcp.tool()
def read_relabeled(path, label=None):
    key = "error_type" if label else None
    return {**rewrap_source(path), key: "relabel_refused"}


@mcp.tool()
def validate(text):
    def field_and_kind(raw):
        if raw.startswith("refused"):
            return "", INPUT_REFUSED
        if raw.startswith("yaml"):
            return "", "yaml_parse_error"
        if raw.startswith("unknown"):
            return raw.split()[-1], "unknown_field"
        return "", "validation_error"

    def classify(raw):
        field, kind = field_and_kind(raw)
        return {"field": field, "message": raw, "type": kind}

    return {"valid": not text, "errors": [classify(e) for e in text]}


# run_ash_scan's start-failure branch, as the server writes it.


async def start_scan(kind):
    if kind == "busy":
        return {"success": False, "error_type": SOURCE_DELIVERY_BUSY, "error": "busy"}
    if kind == "denied":
        return {"success": False, "error_type": "config_field_denied", "error": "no"}
    if kind == "broken":
        return {"success": False, "error_type": "scanner_broken", "error": "broken"}
    return {"success": True, "scan_id": "1"}


@mcp.tool()
async def run_ash_scan(kind):
    result = await start_scan(kind)
    if not result.get("success", False) or "scan_id" not in result:
        if result.get("error_type") in ("config_field_denied",):
            return result
        kept = result.get("error_type") in (
            SOURCE_DELIVERY_BUSY,
            SESSION_SCAN_LIMIT,
        )
        return {
            "success": False,
            "error": f"Failed to start scan: {result.get('error', 'Unknown error')}",
            "error_type": result["error_type"] if kept else "scan_start_failure",
        }
    return {"success": True, "scan_id": result["scan_id"]}


# validate_config's classification of a message, as the server writes it.


@mcp.tool()
def validate_config(text):
    def field_and_kind(raw):
        if raw.startswith("not permitted"):
            return "", CONFIG_INPUT_NOT_PERMITTED
        if raw.startswith("env not resolved"):
            return "", CONFIG_ENV_NOT_RESOLVED
        if raw.startswith("plugin modules"):
            return "ash_plugin_modules", "invalid_field"
        if "YAML parsing error" in raw or "yaml" in raw.lower():
            return "", "yaml_parse_error"
        if "JSON parsing error" in raw:
            return "", "json_parse_error"
        if "Missing required" in raw:
            m = re.search(r"'([^']+)'", raw)
            return (m.group(1) if m else ""), "missing_required_field"
        if "internal field" in raw:
            m = re.search(r"field '([^']+)'", raw)
            return (m.group(1) if m else ""), "internal_field"
        if "Unknown" in raw:
            m = re.search(r"'([^']+)'", raw)
            return (m.group(1) if m else ""), "unknown_field"
        if "Invalid" in raw:
            m = re.search(r"'([^']+)'", raw)
            return (m.group(1) if m else ""), "invalid_field"
        if "Duplicate" in raw:
            m = re.search(r"'([^']+)'", raw)
            return (m.group(1) if m else ""), "duplicate_field"
        return "", "validation_error"

    def classify(raw):
        field, kind = field_and_kind(raw)
        return {"field": field, "message": raw, "type": kind}

    return {"valid": not text, "errors": [classify(e) for e in text]}


# The controls: each leaves the value unread, so the generator stops.


@mcp.tool()
async def scan_unknown_test(kind):
    result = await start(kind)
    kept = len(result) > 2
    return {"success": False, "error_type": result["error_type"] if kept else "x"}


@mcp.tool()
async def scan_reassigned(kind):
    result = await start(kind)
    kept = result.get("error_type") in (BUSY, LIMIT)
    result = await start("policy")
    return {"success": False, "error_type": result["error_type"] if kept else "x"}


@mcp.tool()
async def scan_changed(kind):
    result = await start(kind)
    kept = result.get("error_type") in (BUSY, LIMIT)
    result.update(error_type="policy_refused")
    return {"success": False, "error_type": result["error_type"] if kept else "x"}


@mcp.tool()
async def scan_read_before_set(kinds):
    seen = []
    for kind in kinds:
        if seen:
            return {
                "success": False,
                "error_type": result["error_type"] if kept else "x",
            }
        result = await start(kind)
        kept = result.get("error_type") in (BUSY, LIMIT)
        seen.append(kind)
    return {"success": True}


@mcp.tool()
async def scan_none_kept(kind):
    result = await start(kind)
    kept = result.get("error_type") in ("not_from_start", "nor_this")
    return {"success": False, "error_type": result["error_type"] if kept else "x"}


def kept_type(result):
    kept = result.get("error_type") in (BUSY, LIMIT)
    return result["error_type"] if kept else "x"


@mcp.tool()
async def scan_parameter(kind):
    return {"success": False, "error_type": kept_type(await start(kind))}


@mcp.tool()
async def scan_unpacked(kind):
    result, note = await start(kind), "unused"
    kept = result.get("error_type") in (BUSY, LIMIT)
    return {"success": False, "error_type": result["error_type"] if kept else "x"}


def kind_untupled(raw):
    if raw:
        return "", "yaml_parse_error"
    return {"kind": "validation_error"}


def kind_bare_return(raw):
    if not raw:
        return
    return "", "yaml_parse_error"


def kind_falls_through(raw):
    if raw:
        return "", "yaml_parse_error"


def kind_rebound(raw):
    return "", "yaml_parse_error"


if BUSY:

    def kind_rebound(raw):
        return "", "unknown_field"


@mcp.tool()
def validate_untupled(text):
    field, kind = kind_untupled(text)
    return {"valid": False, "errors": [{"field": field, "type": kind}]}


@mcp.tool()
def validate_bare_return(text):
    field, kind = kind_bare_return(text)
    return {"valid": False, "errors": [{"field": field, "type": kind}]}


@mcp.tool()
def validate_falls_through(text):
    field, kind = kind_falls_through(text)
    return {"valid": False, "errors": [{"field": field, "type": kind}]}


@mcp.tool()
def validate_rebound(text):
    field, kind = kind_rebound(text)
    return {"valid": False, "errors": [{"field": field, "type": kind}]}


# A whole response the reader cannot follow: it could be a dict carrying an
# error_type, so the docs contract check reports the site as a finding unless
# UNREAD_RESPONSE_EXPLAINED explains it; the generator is not stopped.


@mcp.tool()
def read_opaque(path):
    return globals()["transform"](path)


@mcp.tool()
def get_scan_results(path):
    return globals()["transform"](path)


# An open dict: the spread's keys cannot all be read, and no error_type key is
# present, so the docs contract check reports the spread's site.


@mcp.tool()
def read_spread(path):
    return {**globals()["transform"](path), "success": False}


# A flag a caller passes as a constant: the branch it selects, and only that one.


def path_refusal(path, *, output):
    refusal = {"success": False, "error": "no"}
    refusal["error_type"] = "output_unusable" if output else "source_unusable"
    return refusal


def guarded_refusal(path, quiet=True):
    if quiet:
        return {"success": False, "error_type": "quiet_refusal"}
    return {"success": False, "error_type": "loud_refusal"}


@mcp.tool()
def read_results(output_dir):
    refused = path_refusal(output_dir, output=True)
    if refused is not None:
        return refused
    return {"success": True}


@mcp.tool()
def read_quietly(path):
    return guarded_refusal(path)


def strict_refusal(path, strict=False):
    strict |= path.endswith(".lock")
    if strict:
        return {"success": False, "error_type": "strict_refused"}
    return {"success": True}


@mcp.tool()
def read_strict(path):
    return strict_refusal(path)


@mcp.tool()
def read_defaulted(path):
    result = None
    if path:
        result = {"success": False, "error_type": "default_refused"}
        result |= {"detail": "d"}
    return result


@mcp.tool()
def read_gathering(path):
    tags = {"seed"}
    tags |= {path}
    return {"success": True, "tags": tags}


@mcp.tool()
def read_either(path, which):
    if which:
        return path_refusal(path, output=True)
    return path_refusal(path, output=False)


@mcp.tool()
def read_unknown(path, output):
    return path_refusal(path, output=output)
"""


FORMS_SERVER = "automated_security_helper/cli/mcp_server.py"


def _forms_lines(text: str, *, whole: bool = False) -> list[int]:
    """The planted forms' line numbers that hold ``text``, or are it with ``whole``."""
    lines = textwrap.dedent(PLANTED_FORMS).lstrip("\n").splitlines()
    return [
        number
        for number, source in enumerate(lines, 1)
        if (source == text if whole else text in source)
    ]


def _forms_site(text: str, reason: str, nth: int = 1) -> str:
    """The unread site the reader gives for the ``nth`` planted line holding ``text``."""
    return f"{FORMS_SERVER}:{_forms_lines(text)[nth - 1]} ({reason})"


@pytest.fixture
def planted_forms(tmp_path: Path):
    return _reader().tool_contracts(_plant_server(tmp_path, PLANTED_FORMS))


@pytest.mark.unit
def test_a_key_of_each_dict_a_name_can_be(planted_forms):
    """``result["error_type"]``: the error_type of each dict ``result`` can be;
    the success dict, which has none, adds nothing."""
    scan = planted_forms["scan_plain"]
    assert scan.error_types == ("delivery_busy", "policy_refused", "scan_limit")
    assert scan.error_types_unread == ()


@pytest.mark.unit
def test_a_conditional_error_type_narrowed_by_its_own_test(planted_forms):
    """``x["K"] if x.get("K") in (A, B) else LITERAL``: the ``x["K"]`` branch can
    only be A or B, never another type ``x`` holds."""
    scan = planted_forms["scan_inline"]
    assert scan.error_types == ("delivery_busy", "scan_limit", "start_failure")
    assert scan.error_types_unread == ()


@pytest.mark.unit
def test_a_conditional_error_type_narrowed_by_a_named_test(planted_forms):
    """The same with ``kept = x.get("K") in (A, B)`` set once, after ``x``."""
    scan = planted_forms["scan_kept"]
    assert scan.error_types == ("delivery_busy", "scan_limit", "start_failure")
    assert scan.error_types_unread == ()
    assert "policy_refused" not in scan.error_types


@pytest.mark.unit
def test_entry_types_from_a_helper_that_returns_tuples(planted_forms):
    """``field, kind = helper(raw)``: ``kind`` is the second element of each tuple
    the helper returns, constants followed; no ``field`` value becomes a type."""
    validate = planted_forms["validate"]
    assert validate.entry_types == (
        "input_not_permitted",
        "unknown_field",
        "validation_error",
        "yaml_parse_error",
    )
    assert validate.entry_types_unread == ()


@pytest.mark.unit
def test_run_ash_scan_keeps_only_the_types_its_start_can_return(planted_forms):
    """run_ash_scan's start-failure branch: the refusal it returns as is, the
    kept types the start call can return (source_delivery_busy; it never returns
    session_scan_limit), and scan_start_failure. The start call's other type is
    neither kept nor returned."""
    scan = planted_forms["run_ash_scan"]
    assert scan.error_types == (
        "config_field_denied",
        "scan_start_failure",
        "source_delivery_busy",
    )
    assert scan.error_types_unread == ()
    assert "session_scan_limit" not in scan.error_types
    assert "scanner_broken" not in scan.error_types


@pytest.mark.unit
def test_validate_config_entry_types_are_its_ten_kinds(planted_forms):
    """validate_config's classifier: its ten kinds, and none of the field names
    it returns beside them."""
    validate = planted_forms["validate_config"]
    assert validate.entry_types == (
        "config_env_not_resolved",
        "config_input_not_permitted",
        "duplicate_field",
        "internal_field",
        "invalid_field",
        "json_parse_error",
        "missing_required_field",
        "unknown_field",
        "validation_error",
        "yaml_parse_error",
    )
    assert validate.entry_types_unread == ()
    assert validate.entry_class_name is False
    assert "ash_plugin_modules" not in validate.entry_types
    assert "" not in validate.entry_types


@pytest.mark.unit
def test_tests_the_reader_cannot_follow_stop_it(planted_forms):
    """A test over the name the branch reads that the reader does not understand,
    and narrowing the reader cannot show is sound, are unread, with the reason:
    ``x`` set again or changed after the test, the test read before the condition
    variable is set, a test none of ``x``'s values passes, and an ``x`` that is a
    parameter or an element of an unpacking rather than set by one assignment."""
    unread = {
        name: planted_forms[name].error_types_unread
        for name in (
            "scan_unknown_test",
            "scan_reassigned",
            "scan_changed",
            "scan_read_before_set",
            "scan_none_kept",
            "scan_parameter",
            "scan_unpacked",
        )
    }
    not_assigned = "result is not set by one assignment in the function"
    branch = 'if kept else "x"'
    assert unread == {
        "scan_unknown_test": (
            _forms_site(branch, "a test on result the reader does not follow"),
        ),
        "scan_reassigned": (
            _forms_site(branch, "result can change between the test and the read", 2),
        ),
        "scan_changed": (
            _forms_site(branch, "result can change between the test and the read", 3),
        ),
        "scan_read_before_set": (
            _forms_site(branch, "kept is not set after result and before the test", 4),
        ),
        "scan_none_kept": (
            _forms_site(
                branch,
                'the test leaves result["error_type"] nothing to be;'
                ' result["error_type"] is never nor_this or not_from_start',
                5,
            ),
        ),
        "scan_parameter": (_forms_site(branch, not_assigned, 6),),
        "scan_unpacked": (_forms_site(branch, not_assigned, 7),),
    }
    for name in unread:
        assert "policy_refused" not in planted_forms[name].error_types, name


@pytest.mark.unit
def test_unpacking_a_helper_that_is_not_all_pairs_stops_the_reader(planted_forms):
    """``field, kind = helper(raw)`` with a helper that can return something that
    is not a pair (a dict, a bare ``return``), can end without returning, or is
    bound twice: the names are unread, with the reason."""
    unread = {
        name: planted_forms[name].entry_types_unread
        for name in (
            "validate_untupled",
            "validate_bare_return",
            "validate_falls_through",
            "validate_rebound",
        )
    }
    unpacks = "field, kind = "
    dict_return = _forms_lines('return {"kind": "validation_error"}')[0]
    bare_return = _forms_lines("        return", whole=True)[0]
    assert unread == {
        "validate_untupled": (
            _forms_site(
                unpacks + "kind_untupled",
                "kind_untupled can return something other than 2 values"
                f" ({FORMS_SERVER}:{dict_return})",
            ),
        ),
        "validate_bare_return": (
            _forms_site(
                unpacks + "kind_bare_return",
                "kind_bare_return can return something other than 2 values"
                f" ({FORMS_SERVER}:{bare_return})",
            ),
        ),
        "validate_falls_through": (
            _forms_site(
                unpacks + "kind_falls_through",
                "kind_falls_through can end without a return",
            ),
        ),
        "validate_rebound": (
            _forms_site(
                unpacks + "kind_rebound", "kind_rebound is bound more than once"
            ),
        ),
    }
    for name in unread:
        assert planted_forms[name].entry_types == (), name


@pytest.mark.unit
def test_a_constant_flag_selects_its_branch(planted_forms):
    """``X if output else Y`` and ``if quiet: return ...`` in a helper: a caller that
    passes the flag as a constant, or leaves it at a constant default, gets only
    the branch it selects. Callers that pass both values get both, and a flag the
    reader cannot read keeps both branches."""
    types_of = {
        name: (planted_forms[name].error_types, planted_forms[name].error_types_unread)
        for name in ("read_results", "read_quietly", "read_either", "read_unknown")
    }
    assert types_of == {
        "read_results": (("output_unusable",), ()),
        "read_quietly": (("quiet_refusal",), ()),
        "read_either": (("output_unusable", "source_unusable"), ()),
        "read_unknown": (("output_unusable", "source_unusable"), ()),
    }


@pytest.mark.unit
def test_a_flag_is_read_per_call_across_modules(tmp_path: Path):
    """A helper imported from another module of the package: each call reads the
    branch its own constant selects, whoever else calls the helper, since the
    reader reads a helper once per call, with that call's arguments. A helper
    reached through a variable is not followed (unread), and a flag a nested
    function can rebind with ``nonlocal``, or one of a decorated function, keeps
    both branches."""
    package = _plant_server(
        tmp_path,
        """
        from automated_security_helper.cli.refusals import path_refusal

        mcp = object()


        def flipped_refusal(path, output):
            def flip():
                nonlocal output
                output = not output

            flip()
            refusal = {"success": False, "error": "no"}
            refusal["error_type"] = "output_unusable" if output else "source_unusable"
            return refusal


        @mcp.tool()
        def read_output(path):
            return path_refusal(path, output=True)


        @mcp.tool()
        def read_source(path):
            return path_refusal(path, output=False)


        @mcp.tool()
        def read_through_a_variable(path):
            refuse = path_refusal
            return refuse(path, output=True)


        @mcp.tool()
        def read_flipped(path):
            return flipped_refusal(path, output=True)


        def keep(function):
            return function


        @keep
        def decorated_refusal(path, output):
            refusal = {"success": False, "error": "no"}
            refusal["error_type"] = "output_unusable" if output else "source_unusable"
            return refusal


        @mcp.tool()
        def read_decorated(path):
            return decorated_refusal(path, output=True)
        """,
    )
    (package / "cli" / "refusals.py").write_text(
        textwrap.dedent(
            """
            def path_refusal(path, *, output):
                refusal = {"success": False, "error": "no"}
                refusal["error_type"] = "output_unusable" if output else "source_unusable"
                return refusal
            """
        ).lstrip("\n"),
        encoding="utf-8",
    )
    reader = _reader()
    contracts = reader.tool_contracts(package)
    assert contracts["read_output"].error_types == ("output_unusable",)
    assert contracts["read_source"].error_types == ("source_unusable",)
    through = contracts["read_through_a_variable"]
    assert through.error_types == ()
    assert [type(v) for v in through.response.variants] == [reader.UnreadV]
    both = ("output_unusable", "source_unusable")
    assert contracts["read_flipped"].error_types == both
    # A decorator can change what the function is called with.
    assert contracts["read_decorated"].error_types == both


@pytest.mark.unit
def test_a_rebindable_flag_keeps_both_branches(tmp_path: Path):
    """A test name that is not a parameter the function binds exactly once keeps
    both branches: a module global, whether a ``global`` elsewhere rebinds it
    (read_ready) or nothing does (read_steady; what the reader cannot see is a
    cross-module attribute store or ``globals()[...]``, so no other name says
    anything); a flag a nested function rebinds with ``nonlocal``; one a
    ``match`` capture, a ``for`` target, a ``with ... as`` or an
    ``except ... as`` rebinds; and one the function reassigns. Only a parameter
    the function binds exactly once, with a constant from the call, selects a
    single branch (the control). A parameter a ``match`` capture rebinds is also
    partly unread as a VALUE, not only as a test (read_labeled)."""
    package = _plant_server(
        tmp_path,
        """
        mcp = object()

        READY_FLAG = False


        def mark_ready():
            global READY_FLAG
            READY_FLAG = True


        def ready_refusal(path):
            if READY_FLAG:
                return {"success": False, "error_type": "ready_refusal"}
            return {"success": False, "error_type": "not_ready"}


        @mcp.tool()
        def read_ready(path):
            return ready_refusal(path)


        STEADY_FLAG = True


        def steady_refusal(path):
            if STEADY_FLAG:
                return {"success": False, "error_type": "output_unusable"}
            return {"success": False, "error_type": "source_unusable"}


        @mcp.tool()
        def read_steady(path):
            return steady_refusal(path)


        # Defense in depth: the nonlocal rebinding is already kept rebindable by
        # the per-call flag block's read_flipped; this keeps a same-module case.
        def flipping_refusal(path, output):
            def flip():
                nonlocal output
                output = not output

            flip()
            if output:
                return {"success": False, "error_type": "output_unusable"}
            return {"success": False, "error_type": "source_unusable"}


        @mcp.tool()
        def read_flipping(path):
            return flipping_refusal(path, output=True)


        def looping_refusal(path, looped):
            for looped in (path,):
                pass
            if looped:
                return {"success": False, "error_type": "output_unusable"}
            return {"success": False, "error_type": "source_unusable"}


        @mcp.tool()
        def read_looping(path):
            return looping_refusal(path, looped=True)


        def holding_refusal(path, held):
            with path as held:
                pass
            if held:
                return {"success": False, "error_type": "output_unusable"}
            return {"success": False, "error_type": "source_unusable"}


        @mcp.tool()
        def read_holding(path):
            return holding_refusal(path, held=True)


        def catching_refusal(path, trouble):
            try:
                path()
            except ValueError as trouble:
                pass
            if trouble:
                return {"success": False, "error_type": "output_unusable"}
            return {"success": False, "error_type": "source_unusable"}


        @mcp.tool()
        def read_catching(path):
            return catching_refusal(path, trouble=True)


        def matching_refusal(path, routed):
            match path:
                case str() as routed:
                    pass
            if routed:
                return {"success": False, "error_type": "output_unusable"}
            return {"success": False, "error_type": "source_unusable"}


        @mcp.tool()
        def read_matching(path):
            return matching_refusal(path, routed=True)


        def inverting_refusal(path, swapped):
            swapped = not swapped
            if swapped:
                return {"success": False, "error_type": "output_unusable"}
            return {"success": False, "error_type": "source_unusable"}


        @mcp.tool()
        def read_inverting(path):
            return inverting_refusal(path, swapped=True)


        def decrementing_refusal(path, retries=1):
            retries -= 1
            if retries:
                return {"success": False, "error_type": "output_unusable"}
            return {"success": False, "error_type": "source_unusable"}


        @mcp.tool()
        def read_decrementing(path):
            return decrementing_refusal(path)


        def bundling_refusal(path, bundle):
            match path:
                case {**bundle}:
                    pass
            if bundle:
                return {"success": False, "error_type": "output_unusable"}
            return {"success": False, "error_type": "source_unusable"}


        @mcp.tool()
        def read_bundling(path):
            return bundling_refusal(path, bundle=True)


        def labeled_refusal(path, label):
            match path:
                case str() as label:
                    pass
            return {"success": False, "error_type": label}


        @mcp.tool()
        def read_labeled(path):
            return labeled_refusal(path, label="label_refusal")


        def plain_refusal(path, chosen):
            if chosen:
                return {"success": False, "error_type": "output_unusable"}
            return {"success": False, "error_type": "source_unusable"}


        @mcp.tool()
        def read_plain(path):
            return plain_refusal(path, chosen=True)
        """,
    )
    contracts = _reader().tool_contracts(package)
    both = ("output_unusable", "source_unusable")
    types_of = {
        name: contracts[name].error_types
        for name in (
            "read_ready",
            "read_steady",
            "read_flipping",
            "read_matching",
            "read_looping",
            "read_holding",
            "read_catching",
            "read_inverting",
            "read_decrementing",
            "read_bundling",
            "read_plain",
        )
    }
    assert types_of == {
        "read_ready": ("not_ready", "ready_refusal"),
        "read_steady": both,
        "read_flipping": both,
        "read_matching": both,
        "read_looping": both,
        "read_holding": both,
        "read_catching": both,
        "read_inverting": both,
        "read_decrementing": both,
        "read_bundling": both,
        "read_plain": ("output_unusable",),
    }
    # The match capture also makes the parameter's VALUE partly unread: the
    # error_type can be the caller's constant or whatever the capture bound,
    # and the unread site is the capture itself.
    labeled = contracts["read_labeled"]
    assert "label_refusal" in labeled.error_types
    source = (package / "cli" / "mcp_server.py").read_text(encoding="utf-8")
    capture_line = next(
        number
        for number, line in enumerate(source.splitlines(), 1)
        if "case str() as label" in line
    )
    assert labeled.error_types_unread == (
        f"automated_security_helper/cli/mcp_server.py:{capture_line}",
    )
    for name, contract in contracts.items():
        if name == "read_labeled":
            continue
        assert contract.error_types_unread == (), (name, contract.error_types_unread)


@pytest.mark.unit
def test_an_augmented_assignment_is_read_as_a_merge_or_its_operation(tmp_path: Path):
    """``x |= v`` reads as ``x.update(v)``, and any other ``x op= v`` as
    ``x = x op v``, never as nothing: a condition built with ``|=`` still
    depends on the dict it tests, so the narrow is poisoned rather than
    silently widened; a list built with ``+=`` keeps its entries; a dict
    merged with ``|=`` keeps its error_type; and a spread placed after an
    error_type key leaves that key open, since at runtime the spread can
    override it."""
    package = _plant_server(tmp_path, PLANTED_FORMS)
    contracts = _reader().tool_contracts(package)
    accumulated = contracts["scan_accumulated"]
    assert "start_failure" in accumulated.error_types
    assert accumulated.error_types_unread != ()
    assert contracts["validate_accumulated"].entry_types == ("unknown_field",)
    # ``refusal |= {...}`` merges into every alternative, like update: one
    # response holds BOTH keys, not one key each across two alternatives, and
    # a dict-only base gains no unread alternative from the merge.
    merged = contracts["read_merged"]
    assert merged.error_types == ("merge_refused",)
    assert merged.error_types_unread == ()
    assert merged.response_unread == ()
    reader_module = _reader()
    assert any(
        isinstance(v, reader_module.DictV)
        and {"success", "error_type"} <= {k for k, _ in v.keys}
        for v in merged.response.variants
    )
    overridden = contracts["read_overridden"]
    assert "pinned_refusal" in overridden.error_types
    assert overridden.error_types_unread != ()
    # A key written AFTER a spread replaces the spread's value, as at runtime.
    assert contracts["read_rewrapped"].error_types == ("rewrapped_refusal",)


@pytest.mark.unit
def test_a_flag_rebound_by_a_merge_is_not_a_constant(planted_forms):
    """``strict |= cond`` can turn the flag on after its constant default was
    bound, so the default no longer stands for the value: the strict branch's
    error_type stays in the contract instead of being pruned as unreachable."""
    assert "strict_refused" in planted_forms["read_strict"].error_types


@pytest.mark.unit
def test_a_merge_on_an_alternative_that_cannot_reach_it_adds_no_unread(planted_forms):
    """``result = None; ... result = {...}; result |= {...}``: the None
    alternative raises at the ``|=`` and never survives it, so the tool stays
    fully read instead of gaining an unread response alternative. A set
    literal base gains none either: a set, read as a list of its items,
    answers no truth test, so no branch can be pruned through it, and only a
    bool or number flag needs the unread part."""
    defaulted = planted_forms["read_defaulted"]
    assert defaulted.error_types == ("default_refused",)
    assert defaulted.error_types_unread == ()
    assert defaulted.response_unread == ()
    reader = _reader()
    gathering = planted_forms["read_gathering"].response
    tags = [
        dict(v.keys)["tags"]
        for v in gathering.variants
        if isinstance(v, reader.DictV) and "tags" in dict(v.keys)
    ]
    assert tags
    assert all(not value.unread for value in tags)


@pytest.mark.unit
def test_an_uncertain_key_after_a_spread_only_widens(planted_forms):
    """A key that may or may not be the string (``"error_type" if label else
    None``) cannot wipe the spread's value: at runtime that key can land
    elsewhere and the spread's error_type survive, so both stay readable."""
    relabeled = planted_forms["read_relabeled"].error_types
    assert "inner_refused" in relabeled
    assert "relabel_refused" in relabeled


@pytest.mark.unit
def test_a_name_rebound_by_a_merge_is_not_one_plain_assignment():
    """``y = {}; y |= {...}`` rebinds ``y``, so ``_set_by_one_assignment``
    refuses it on its own, not only through the callers' ``_set_once`` check:
    a narrow built on such a name would trust a binding the merge can change."""
    reader = _reader()
    source = textwrap.dedent(
        """
        def f(text):
            y = {"a": 1}
            y |= {"b": 2}
            z = {"a": 1}
        """
    )
    func = ast.parse(source).body[0]
    module = reader._Module(name="m", rel="m.py", tree=ast.parse(""), is_package=False)
    local = reader._locals_of(func, module)
    assert reader._set_by_one_assignment(local, "z") is True
    assert reader._set_by_one_assignment(local, "y") is False


@pytest.mark.unit
def test_the_cap_keeps_errorless_open_dicts_apart():
    """Past MAX_VARIANTS the dicts are merged, and one refusal among many
    success alternatives would give the merged dict an error_type, hiding the
    success alternatives' open sites from the docs check. The cap merges dicts
    with an error_type apart from those without, so an errorless open dict
    stays errorless."""
    reader = _reader()
    shapes = [
        reader.one(
            reader.DictV((("error_type", reader.one(reader.StrV(f"kind_{i}"))),), ())
        )
        for i in range(reader.MAX_VARIANTS)
    ]
    shapes.append(reader.one(reader.DictV((), ("open_site_a",))))
    capped = reader.union(*shapes)
    errorless = [
        v
        for v in capped.variants
        if isinstance(v, reader.DictV) and "error_type" not in dict(v.keys)
    ]
    assert len(errorless) == 1
    assert errorless[0].open_at == ("open_site_a",)


@pytest.mark.unit
def test_a_nonlocal_in_another_function_does_not_poison_a_local(tmp_path: Path):
    """A ``nonlocal`` can only rebind a name in its own enclosing function, and
    a ``global`` elsewhere can never rebind a function's local. So a flag
    parameter in one function stays a selector when an unrelated function's
    nested callback rebinds its own same-named flag with ``nonlocal`` or
    another function declares the name ``global``, while that function's own
    flag is rightly read as rebindable, and a function's own ``global`` makes
    its value partly unread."""
    package = _plant_server(
        tmp_path,
        """
        mcp = object()

        MODE = "steady_mode"


        def switching_refusal(path):
            global MODE
            MODE = "switched_mode"
            return {"success": False, "error_type": MODE}


        @mcp.tool()
        def read_switching(path):
            return switching_refusal(path)


        def plain_mode_refusal(path, MODE):
            if MODE:
                return {"success": False, "error_type": "output_unusable"}
            return {"success": False, "error_type": "source_unusable"}


        @mcp.tool()
        def read_plain_mode(path):
            return plain_mode_refusal(path, MODE=True)


        def tracking_refusal(path):
            chosen = False

            def mark():
                nonlocal chosen
                chosen = True

            mark()
            if chosen:
                return {"success": False, "error_type": "tracked_refusal"}
            return {"success": False, "error_type": "untracked"}


        @mcp.tool()
        def read_tracking(path):
            return tracking_refusal(path)


        def plain_refusal(path, chosen):
            if chosen:
                return {"success": False, "error_type": "output_unusable"}
            return {"success": False, "error_type": "source_unusable"}


        @mcp.tool()
        def read_plain(path):
            return plain_refusal(path, chosen=True)
        """,
    )
    contracts = _reader().tool_contracts(package)
    # The callback really can rebind tracking_refusal's own flag.
    assert contracts["read_tracking"].error_types == ("tracked_refusal", "untracked")
    # The other function's nonlocal says nothing about this parameter.
    plain = contracts["read_plain"]
    assert plain.error_types == ("output_unusable",)
    assert plain.error_types_unread == ()
    assert plain.response_unread == ()
    # A function's own ``global`` makes the name the module's, so its value is
    # partly unread; a ``global`` elsewhere says nothing about another
    # function's parameter of that name.
    switching = contracts["read_switching"]
    assert "switched_mode" in switching.error_types
    assert switching.error_types_unread != ()
    assert contracts["read_plain_mode"].error_types == ("output_unusable",)


@pytest.mark.unit
def test_the_generator_stops_on_a_value_it_cannot_narrow(tmp_path, monkeypatch):
    """The generator, given the planted server: its run stops, with exit status 1
    and the reason, on a value reassigned between its test and its read, on a
    test no value passes and on a parameter, and goes on for the narrowed one."""
    package = _plant_server(tmp_path, PLANTED_FORMS)
    generator = _load(
        "_ash_generate_mcp_tool_reference", SCRIPTS / "generate_mcp_tool_reference.py"
    )
    planted = types.ModuleType("automated_security_helper")
    planted.__file__ = str(package / "__init__.py")
    monkeypatch.setitem(sys.modules, "automated_security_helper", planted)
    monkeypatch.syspath_prepend(str(SCRIPTS))

    def run(name: str):
        return generator._tool_contracts([types.SimpleNamespace(name=name)])

    assert run("scan_kept")["scan_kept"].error_types_unread == ()
    for name, reason in (
        ("scan_reassigned", "(result can change between the test and the read)"),
        ("scan_none_kept", 'the test leaves result["error_type"] nothing to be'),
        ("scan_parameter", "(result is not set by one assignment in the function)"),
    ):
        with pytest.raises(SystemExit) as stopped:
            run(name)
        # A message as the exit code: Python prints it and exits with status 1.
        assert isinstance(stopped.value.code, str), name
        assert f"{name}: an error type at " in stopped.value.code
        assert reason in stopped.value.code


@pytest.mark.unit
def test_the_check_reports_a_response_the_reader_cannot_read_at_all(
    tmp_path, monkeypatch
):
    """A tool whose whole response the reader cannot follow lists no error types,
    which is not the same as having none: the response could be a dict carrying
    one. check_mcp_contract reports each such site as a finding naming the tool
    and the site, unless an UNREAD_RESPONSE_EXPLAINED entry names the tool, the
    file, the function enclosing the site AND a fragment of the site's source
    line: an entry naming another function in the same file, or a line the site
    does not sit on, explains nothing, so new code inside an already-explained
    function is never covered by a stale reason. An open dict without an
    error_type key is reported the same way. An entry that explained no site is
    named in the notes until its stale-after date and is a finding past it, so
    retired code cannot leave a standing exemption. The generator does not stop
    on any of them; the contracts carry their sites."""
    package = _plant_server(tmp_path, PLANTED_FORMS)
    planted_file = "automated_security_helper/cli/mcp_server.py"
    monkeypatch.setattr(
        dc,
        "UNREAD_RESPONSE_EXPLAINED",
        (
            (
                "get_scan_results",
                planted_file,
                "get_scan_results",
                "globals()",
                "2999-01-01",
                "a test reason",
            ),
            # The right file but the wrong function: explains nothing.
            (
                "read_opaque",
                planted_file,
                "transform",
                "globals()",
                "2999-01-01",
                "a stale reason",
            ),
            (
                "read_opaque",
                planted_file,
                "never_present",
                "globals()",
                "2999-01-01",
                "an unused reason",
            ),
            # The right function but a line the site does not sit on.
            (
                "read_opaque",
                planted_file,
                "read_opaque",
                "not the site's line",
                "2999-01-01",
                "a wrong-line reason",
            ),
            # Unused and past its stale-after date: a finding, not a note.
            (
                "read_opaque",
                planted_file,
                "long_gone",
                "globals()",
                "2020-01-01",
                "an expired reason",
            ),
        ),
    )

    reader = _reader()
    opaque = reader.tool_contracts(package)["read_opaque"]
    assert opaque.error_types == ()
    assert opaque.error_types_unread == ()
    assert opaque.response_unread != ()

    notes: list[str] = []
    dc.load_mcp_contract.cache_clear()
    try:
        findings = dc.check_mcp_contract([], REPO_ROOT, notes=notes, package=package)
    finally:
        dc.load_mcp_contract.cache_clear()
    for site in opaque.response_unread:
        named = _findings_about(findings, f"read_opaque has a response at {site} ")
        assert len(named) == 1
        assert "UNREAD_RESPONSE_EXPLAINED does not explain it" in named[0]
    assert not _findings_about(findings, "get_scan_results has a response at ")
    spread = _findings_about(findings, "read_spread has a response whose keys ")
    assert len(spread) == 1
    assert "no error_type key" in spread[0]
    # An open dict whose error_type key survives every spread is not reported.
    assert not _findings_about(findings, "read_overridden has a response whose keys ")
    unused = [note for note in notes if "explained nothing" in note]
    assert len(unused) == 1
    assert "never_present" in unused[0] and "transform" in unused[0]
    assert "not the site's line" in unused[0]
    assert "get_scan_results" not in unused[0]
    assert "long_gone" not in unused[0]
    expired = _findings_about(findings, "past its stale-after date")
    assert len(expired) == 1
    assert "long_gone" in expired[0] and "2020-01-01" in expired[0]

    # An entry naming the open site's own function and line explains it.
    monkeypatch.setattr(
        dc,
        "UNREAD_RESPONSE_EXPLAINED",
        (
            (
                "get_scan_results",
                planted_file,
                "get_scan_results",
                "globals()",
                "2999-01-01",
                "a test reason",
            ),
            (
                "read_opaque",
                planted_file,
                "read_opaque",
                "globals()",
                "2999-01-01",
                "a test reason",
            ),
            (
                "read_spread",
                planted_file,
                "read_spread",
                "globals()",
                "2999-01-01",
                "a test reason",
            ),
        ),
    )
    dc.load_mcp_contract.cache_clear()
    try:
        explained = dc.check_mcp_contract([], REPO_ROOT, package=package)
    finally:
        dc.load_mcp_contract.cache_clear()
    assert not _findings_about(explained, "read_spread has a response whose keys ")
    assert not _findings_about(explained, "read_opaque has a response at ")

    generator = _load(
        "_ash_generate_mcp_tool_reference", SCRIPTS / "generate_mcp_tool_reference.py"
    )
    planted = types.ModuleType("automated_security_helper")
    planted.__file__ = str(package / "__init__.py")
    monkeypatch.setitem(sys.modules, "automated_security_helper", planted)
    monkeypatch.syspath_prepend(str(SCRIPTS))
    through = generator._tool_contracts(
        [
            types.SimpleNamespace(name="read_opaque"),
            types.SimpleNamespace(name="get_scan_results"),
            types.SimpleNamespace(name="read_spread"),
        ]
    )
    assert through["read_opaque"].response_unread != ()
    assert through["get_scan_results"].response_unread != ()
    assert through["read_spread"].response_unread == ()  # open, not unread


# ---------------------------------------------------------------------------
# The two real sites, in the package this interpreter imports
# ---------------------------------------------------------------------------

#: The types run_ash_scan's start-failure branch keeps from its start call
#: (``result["error_type"] if kept else "scan_start_failure"``).
KEPT_START_TYPES = {"source_delivery_busy", "session_scan_limit"}
START_FAILURE = "scan_start_failure"
#: The kinds validate_config's ``_field_and_kind`` gives a message.
CLASSIFIER_KINDS = {
    "config_env_not_resolved",
    "config_input_not_permitted",
    "duplicate_field",
    "internal_field",
    "invalid_field",
    "json_parse_error",
    "missing_required_field",
    "unknown_field",
    "validation_error",
    "yaml_parse_error",
}


def _parsed(package: Path, rel: str) -> ast.Module:
    path = package / rel
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _function_named(tree: ast.AST, name: str):
    return next(
        (
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        ),
        None,
    )


@pytest.mark.unit
def test_run_ash_scan_reads_its_kept_start_types():
    """The real run_ash_scan: what narrowing decides at its start-failure branch.

    The kept pair and scan_start_failure are among its error types, and nothing
    is unread. The rest of its list changes with every new refusal, so it is not
    pinned here; the generated page lists it. Skipped only when run_ash_scan has
    no ``... if kept else ...`` (a tree without that branch); a missing file or
    function fails.
    """
    package = _installed_package()
    run_ash_scan = _function_named(
        _parsed(package, "cli/mcp_server.py"), "run_ash_scan"
    )
    assert run_ash_scan is not None, "cli/mcp_server.py defines no run_ash_scan"
    if not any(
        isinstance(node, ast.IfExp)
        and isinstance(node.test, ast.Name)
        and node.test.id == "kept"
        for node in ast.walk(run_ash_scan)
    ):
        pytest.skip("this package's run_ash_scan has no `... if kept else ...` branch")
    scan = _reader().tool_contracts(package)["run_ash_scan"]
    assert scan.error_types_unread == ()
    assert KEPT_START_TYPES | {START_FAILURE} <= set(scan.error_types)


@pytest.mark.unit
def test_validate_config_entry_types_hold_its_classifier_kinds():
    """The real validate_config: each kind ``_field_and_kind`` gives is an entry
    type, none of the field names it returns beside them is, and nothing is
    unread. Its other entry types come from other branches and are not pinned.
    Skipped only when cli/mcp_tools.py has no ``_field_and_kind``; a missing file
    fails.
    """
    package = _installed_package()
    classifier = _function_named(
        _parsed(package, "cli/mcp_tools.py"), "_field_and_kind"
    )
    if classifier is None:
        pytest.skip("this package's cli/mcp_tools.py has no _field_and_kind")
    field_names = {
        node.value.elts[0].value
        for node in ast.walk(classifier)
        if isinstance(node, ast.Return)
        and isinstance(node.value, ast.Tuple)
        and node.value.elts
        and isinstance(node.value.elts[0], ast.Constant)
        and isinstance(node.value.elts[0].value, str)
    }
    assert field_names, "_field_and_kind returns no field name as a string constant"
    validate = _reader().tool_contracts(package)["validate_config"]
    assert validate.entry_types_unread == ()
    assert CLASSIFIER_KINDS <= set(validate.entry_types)
    assert not field_names & set(validate.entry_types)


def _chain_server(levels: int) -> str:
    """A server whose tool calls a chain of helpers, each calling the next twice."""
    lines = [
        "import os",
        "",
        "mcp = object()",
        "",
        "",
        "def level0(kind):",
        '    return {"error_type": kind}',
    ]
    for level in range(1, levels + 1):
        lines += [
            "",
            "",
            f"def level{level}(kind):",
            '    if os.environ.get("A"):',
            f"        return level{level - 1}(kind)",
            f"    return level{level - 1}(kind)",
        ]
    lines += [
        "",
        "",
        "@mcp.tool()",
        "def run_thing():",
        f'    return level{levels}("chain_refused")',
    ]
    return "\n".join(lines) + "\n"


@pytest.mark.unit
def test_a_helper_called_with_the_same_arguments_is_read_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A chain of 14 helpers that each call the next twice is 2**14 reads of the
    last one when every call is read again, and the MCP tools page's generator
    never finished on the real server. It is one read per helper now."""
    reader = _reader()
    reads = []
    original = reader.Evaluator.returns

    def counted(self, module, func, *args, **kwargs):
        reads.append(getattr(func, "name", ""))
        return original(self, module, func, *args, **kwargs)

    monkeypatch.setattr(reader.Evaluator, "returns", counted)
    package = _plant_server(tmp_path, _chain_server(14))
    contract = reader.tool_contracts(package)["run_thing"]
    assert contract.error_types == ("chain_refused",)
    assert contract.error_types_unread == ()
    assert len(reads) < 100, f"{len(reads)} reads of 16 functions"


@pytest.mark.unit
def test_a_cached_read_does_not_depend_on_what_was_read_first(tmp_path: Path):
    """``g`` and ``h`` call each other. Read from ``g``, ``h``'s answer stops at
    ``g``, which is on the stack; read first, it does not. A result that stopped at
    a caller above it is not kept for the next caller, so a tool reads the same
    whether or not another tool was read before it."""
    package = _plant_server(
        tmp_path,
        """
        import os

        mcp = object()


        def g(kind):
            if os.environ.get("A"):
                return h(kind)
            return {"error_type": kind}


        def h(kind):
            if os.environ.get("A"):
                return g(kind)
            return {"error_type": "from_h"}


        @mcp.tool()
        def first():
            return g("shared_refused")


        @mcp.tool()
        def second():
            return h("shared_refused")
        """,
    )
    reader = _reader()
    together = reader.tool_contracts(package)
    assert set(together) == {"first", "second"}
    for name in together:
        source = reader.Source(package)
        server = source.module(reader.SERVER_MODULE)
        node = next(
            n
            for n in server.tree.body
            if isinstance(n, ast.FunctionDef) and n.name == name
        )
        alone = reader.Evaluator(source).returns(server, node)
        assert together[name].response == alone, name


@pytest.mark.unit
def test_example_keys_read_json_and_sketches():
    reader = _reader()
    sketch = """{
      "scan_id": "...",
      "warnings": [...],
      "is_complete": bool,
      "incomplete_scanners": [
        { "scanner": "grype", "status": "MISSING" }
      ],
      "severity_counts": { "critical": int },
      "scanners": { "<scanner_name>": { "<target_type>": { ... } } }
    }"""
    assert reader.example_keys(sketch) == {
        "scan_id": None,
        "warnings": {"[]": {}},
        "is_complete": None,
        "incomplete_scanners": {"[]": {"scanner": None, "status": None}},
        "severity_counts": {"critical": None},
        "scanners": {"<scanner_name>": {"<target_type>": {}}},
    }


@pytest.mark.unit
def test_no_explanation_entry_names_a_function_the_mcp_server_lacks():
    """Each UNREAD_RESPONSE_EXPLAINED entry that points into the MCP server module
    names a function that module defines. get_scan_results now returns the
    filtered views directly, so the entries that named the removed
    ``_with_coverage`` copy explain no site: the freshness check lists them as
    entries that explained nothing, and reports them once their stale-after date
    passes. The coverage keys are still spliced on in ``_coverage_fields`` in
    result_filters.py, and those entries stay."""
    server = REPO_ROOT / "automated_security_helper" / "cli" / "mcp_server.py"
    tree = ast.parse(server.read_text(encoding="utf-8"))
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "get_scan_results" in defined
    names = [
        func.rsplit(".", 1)[-1]
        for _tool, file, func, _fragment, _stale_after, _reason in (
            dc.UNREAD_RESPONSE_EXPLAINED
        )
        if file.endswith("cli/mcp_server.py")
    ]
    assert "get_scan_results" in names
    assert [name for name in names if name not in defined] == []
    assert "_with_coverage" not in defined
    assert not [
        entry for entry in dc.UNREAD_RESPONSE_EXPLAINED if entry[2] == "_with_coverage"
    ]
