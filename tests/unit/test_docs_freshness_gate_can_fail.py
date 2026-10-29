# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every check in the docs-freshness gate must be able to report a failure.

WHY THIS EXISTS
---------------
`scripts/verify_docs_freshness.py` prints `Results: 8 passed` and its exit status
is what the `lint` job gates on. That line is trusted, and it was partly false.

`check_config_path` built a regex, read every markdown file in the tree,
collected the matches into a local named `matches`, entered `if matches:`,
assigned a `rel_path` it never used, and then hit a bare `pass`. It returned a
`failures` list it never appended to. It could not fail. One of the eight
"passed" was a function that did a measurable amount of work and discarded all of
it, and the summary line could not tell that apart from a real pass.

The single fix is not the deliverable; this file is. A gate that cannot fail is
worse than no gate, because the green is load-bearing in someone's decision. So
every registered check gets a test here that feeds it the drift it exists to
catch and REQUIRES a failure. A future edit that neuters a check turns this red
instead of turning the gate quietly green.

HOW THE REGISTRY GUARD WORKS
----------------------------
`test_every_registered_check_is_covered_here` reads the check list out of the
script's own `main()` and asserts that every name in it appears in
`NON_VACUITY_COVERAGE` below. Adding a check to the script without adding a
non-vacuity test here fails that test. Without it, this file would protect
whichever checks happened to exist when it was written, and a ninth check would
be unguarded in exactly the way the first eight were.

WHAT THIS DOES NOT CHECK
------------------------
That the checks are CORRECT -- only that each is capable of returning a failure
for the drift it claims to catch. A check that fails on the synthetic drift here
and also fails spuriously on real docs would pass this file and break CI, which
is the loud direction and is what running the script on the real tree covers.
"""

from __future__ import annotations

import ast
import importlib.util
import inspect
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "verify_docs_freshness.py"


@pytest.fixture(scope="module")
def gate():
    """Import the gate script as a module.

    It lives in scripts/ rather than the package, so it is loaded by path. The
    repo root goes on sys.path because the script imports the ASH package.
    """
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    spec = importlib.util.spec_from_file_location("_ash_docs_gate", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _own_repository(root: Path) -> Path:
    """Make ``root`` a git repository of its own and return it.

    The gate lists its docs with git (``collect_md_files``), so a planted tree has to
    be one for the listing to read it. Nothing is staged or committed: the listing
    includes untracked files that are not ignored.
    """
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    return root


# Registered check name -> the test here that proves it can fail.
NON_VACUITY_COVERAGE = {
    "Reporter list in docs matches code": "test_reporter_check_can_fail_in_both_directions",
    "Scanner list in docs matches code": "test_scanner_check_can_fail",
    "MCP tool names in docs match code": "test_mcp_tool_check_can_fail",
    "Version consistency": "test_version_check_can_fail",
    "Config file path consistency": "test_config_path_check_can_fail",
    "Suppression field name": "test_suppression_check_can_fail",
    "Plugin options in docs exist and validate": "test_plugin_options_check_can_fail",
    # Checks 9-16 live in scripts/docs_checks.py, and so do their proofs, in
    # test_docs_checks_can_fail.py; "<file>::<test>" names a test in that file.
    "Doc block markers are well formed": "test_docs_checks_can_fail.py::test_marker_check_can_fail",
    "ASH commands in docs match the CLI": "test_docs_checks_can_fail.py::test_cli_check_can_fail",
    "ASH environment variables in docs are read by ASH": "test_docs_checks_can_fail.py::test_env_check_can_fail",
    "Config blocks in docs validate": "test_docs_checks_can_fail.py::test_config_check_can_fail",
    "Python blocks in docs parse and import": "test_docs_checks_can_fail.py::test_python_check_can_fail",
    "Links and anchors in docs resolve": "test_docs_checks_can_fail.py::test_links_check_can_fail",
    "Docs navigation and redirects resolve": "test_docs_checks_can_fail.py::test_nav_check_can_fail",
    "Docs site build is strict, offline and versioned": "test_docs_checks_can_fail.py::test_site_build_check_can_fail",
    "Release numbers in templates stay out of install commands": "test_docs_checks_can_fail.py::test_release_placeholder_check_can_fail",
    "Docs links in the ASH source resolve": "test_docs_checks_can_fail.py::test_code_links_check_can_fail",
    "Option tables and config paths in docs match the models": "test_docs_checks_can_fail.py::test_option_tables_check_can_fail",
    "MCP error types and example responses in docs match the tools": "test_docs_mcp_contract.py::test_mcp_contract_check_can_fail",
    "Install commands in docs name real extras, Pythons and refs": "test_docs_install_commands_can_fail.py::test_install_check_can_fail",
    "Report file names in docs are files ASH writes": "test_docs_tables_and_output_checks.py::test_report_file_check_can_fail",
    "Scanner names in docs tables are scanners ASH ships": "test_docs_tables_and_output_checks.py::test_scanner_name_check_can_fail",
    "Shell variables in docs examples are set in the session that reads them": "test_docs_session_variables_can_fail.py::test_a_variable_set_on_another_fixture_is_reported_where_it_is_read",
    "Values docs examples pass the scan workflow pass its input check": "test_docs_workflow_inputs_can_fail.py::test_a_multi_line_ash_args_is_reported",
}


def _registered_checks() -> list[tuple[str, str]]:
    """Read the check list out of main() without executing the gate: (label, callable).

    Parsed rather than called: running main() runs every check against the real
    tree, which is slow and would make this test fail for unrelated doc drift. The
    labels are string literals and the callables are names, in a list of tuples, so
    the syntax tree has them exactly.
    """
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    main_fn = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    for node in ast.walk(main_fn):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "checks" for t in node.targets):
            continue
        assert isinstance(node.value, ast.List)
        checks = []
        for element in node.value.elts:
            assert isinstance(element, ast.Tuple)
            label, function = element.elts
            assert isinstance(label, ast.Constant)
            assert isinstance(function, ast.Name)
            checks.append((label.value, function.id))
        return checks
    raise AssertionError("could not find the `checks` list in main()")


def _registered_check_names() -> list[str]:
    return [label for label, _function in _registered_checks()]


@pytest.mark.unit
def test_every_registered_check_is_covered_here():
    """A check with no non-vacuity test is a check nothing stops from going quiet."""
    registered = set(_registered_check_names())
    covered = set(NON_VACUITY_COVERAGE)

    assert registered == covered, (
        "the gate's registered checks and this file's coverage table disagree.\n"
        f"  registered but not covered here: {sorted(registered - covered)}\n"
        f"  covered here but not registered: {sorted(covered - registered)}\n"
        "Add a test that feeds the new check its drift and requires a failure."
    )


@pytest.mark.unit
def test_the_coverage_table_names_real_tests():
    """A typo in the table above would silently exempt a check."""
    module = sys.modules[__name__]
    for check, test_name in sorted(NON_VACUITY_COVERAGE.items()):
        file_name, separator, function = test_name.rpartition("::")
        if not separator:
            assert hasattr(module, test_name), (
                f"{check!r} claims to be covered by {test_name!r}, which does not "
                f"exist in this module"
            )
            continue
        other = Path(__file__).parent / file_name
        defined = {
            node.name
            for node in ast.parse(other.read_text(encoding="utf-8")).body
            if isinstance(node, ast.FunctionDef)
        }
        assert function in defined, (
            f"{check!r} claims to be covered by {test_name!r}, which does not exist"
        )


# ---------------------------------------------------------------------------
# Per-check drift tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_config_path_check_can_fail(gate, tmp_path, monkeypatch):
    """The check this file exists for. It could not fail at all before.

    Two drifts, because the check is bidirectional: a published discovery list
    that omits a name ASH searches for hides a working option, and one that adds
    a name ASH does not search for sends the reader to a file ASH will ignore.
    """
    from automated_security_helper.core.constants import ASH_CONFIG_FILE_NAMES

    def publish(names):
        doc = tmp_path / "configuration.md"
        body = "\n".join(f"{i}. `{n}`" for i, n in enumerate(names, start=1))
        doc.write_text("By default ASH looks for:\n\n" + body + "\n", encoding="utf-8")
        monkeypatch.setattr(gate, "collect_md_files", lambda: [doc])
        monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
        return gate.check_config_path()

    # Control: the complete inventory must pass, so the failures below are
    # attributable to the drift and not to the check rejecting everything.
    assert publish(ASH_CONFIG_FILE_NAMES) == []

    omitted = publish(list(ASH_CONFIG_FILE_NAMES)[:-1])
    assert omitted, "a list omitting a supported config name was accepted"
    assert "omits" in omitted[0]

    invented = publish(list(ASH_CONFIG_FILE_NAMES) + ["ash-config.yaml"])
    assert invented, "a list naming an unsupported config name was accepted"
    assert "ash-config.yaml" in invented[0]


def _generator():
    """The reporter doc generator, loaded by path the same way the gate is."""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    path = REPO_ROOT / "scripts" / "generate_reporter_docs.py"
    spec = importlib.util.spec_from_file_location("_ash_reporter_docs_gen", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.integration
def test_reporter_check_passes_on_the_generated_table():
    """The gate must accept the table the generator writes.

    The built-in reporters table in reference/reporters.md is written by
    scripts/generate_reporter_docs.py from the plugin registry. The gate used to
    build its reporter list from the fields declared on ReporterConfigSegment
    instead, a different source, and the two disagree about any reporter that
    reaches configuration only through ``extra="allow"``. unused-suppressions was
    one until it was declared: the generator gave it a row, the gate called that
    row a leftover for a removed reporter, and `generate_reporter_docs.py
    --check` and `verify_docs_freshness.py` could not both pass on any version
    of the doc.

    Nothing in the unit suite ran check_reporters against the real doc, which is
    how the gate failed on main while the suite was green. This test is that run.

    In a fresh interpreter, the way CI runs the gate. The plugin registry is
    process-global, and in a shared test worker it also holds reporters that
    other tests imported (the AWS plugin package registers aws-security-hub, s3
    and others), so an in-process run would demand rows for plugins the
    generator never sees.
    """
    code = (
        "import importlib.util, json, sys\n"
        f"sys.path.insert(0, {str(REPO_ROOT)!r})\n"
        f"spec = importlib.util.spec_from_file_location('g', {str(SCRIPT)!r})\n"
        "g = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(g)\n"
        "print(json.dumps(g.check_reporters()))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    failures = json.loads(result.stdout.strip().splitlines()[-1])
    assert failures == []


@pytest.mark.unit
def test_reporter_check_reads_the_generators_registry(gate):
    """The gate's reporter inventory is the generator's, not a second opinion.

    Asserted as set equality with the generator's own function, so the gate
    reverting to any other source (config fields, ASH_REPORTERS, the package
    ``__all__``) that happens to disagree with the registry fails here by name.
    """
    expected = {row["name"] for row in _generator().registered_reporters()}
    assert expected, "the registry returned no reporters; nothing is being compared"
    assert set(gate.reporter_names()) == expected


@pytest.mark.unit
def test_reporter_check_can_fail_in_both_directions(gate, tmp_path, monkeypatch):
    """A row naming a removed reporter used to pass; that was the whole defect."""
    names = sorted(gate.reporter_names())

    def publish(rows):
        doc = tmp_path / "reporters.md"
        lines = ["| Reporter | File extension |", "|----------|----------------|"]
        lines += [f"| {r} | `.x` |" for r in rows]
        doc.write_text("\n".join(lines) + "\n", encoding="utf-8")
        monkeypatch.setattr(gate, "REPORTERS_REFERENCE_MD", doc)
        return gate.check_reporters()

    assert publish(names) == [], "the complete reporter table was rejected"

    # docs -> code: the direction that was never checked.
    ghost = publish(names + ["carrier-pigeon"])
    assert ghost, "a table row naming a nonexistent reporter was accepted"
    assert any("names nothing in the code" in f for f in ghost)

    # code -> docs.
    dropped = publish(names[1:])
    assert dropped, "a reporter missing from the table was accepted"
    assert any(names[0] in f for f in dropped)


@pytest.mark.unit
def test_reporter_check_fails_when_a_real_row_is_deleted(gate, tmp_path, monkeypatch):
    """Against a copy of the real page, not a synthetic table.

    The synthetic test above builds its rows from the same inventory the check
    reads, so on its own it cannot tell a working comparison from a list compared
    with itself. Here the doc side is the committed page with one row removed.
    """
    real = gate.REPORTERS_REFERENCE_MD.read_text(encoding="utf-8")
    row = next(line for line in real.splitlines() if "(`unused-suppressions`)" in line)
    doc = tmp_path / "reporters.md"
    doc.write_text(real.replace(row + "\n", ""), encoding="utf-8")
    monkeypatch.setattr(gate, "REPORTERS_REFERENCE_MD", doc)

    failures = gate.check_reporters()
    assert any("'unused-suppressions'" in f and "no row" in f for f in failures), (
        f"deleting a registered reporter's row was accepted: {failures}"
    )


@pytest.mark.unit
def test_reporter_check_fails_for_a_registered_reporter_with_no_row(gate, monkeypatch):
    """The other half: the registry grows and the committed page does not."""
    generator = gate._reporter_generator()
    real_rows = generator.registered_reporters()
    extra = {
        "name": "carrier-pigeon",
        "extension": "pigeon.json",
        "enabled": False,
        "class_name": "CarrierPigeonReporter",
    }
    monkeypatch.setattr(generator, "registered_reporters", lambda: real_rows + [extra])

    failures = gate.check_reporters()
    assert any(
        "'carrier-pigeon'" in f and "CarrierPigeonReporter" in f for f in failures
    ), f"a registered reporter with no table row was accepted: {failures}"


@pytest.mark.unit
def test_reporter_check_fails_closed_on_an_empty_registry(gate, monkeypatch):
    generator = gate._reporter_generator()
    monkeypatch.setattr(generator, "registered_reporters", list)
    failures = gate.check_reporters()
    assert failures and "no reporters" in failures[0]


BUILTIN_REPORTER_MODULE_PREFIX = "automated_security_helper.plugin_modules.ash_builtin."


def _builtin_registered_reporter_names() -> set[str]:
    """Names of the registered reporters that this package itself ships.

    The plugin registry is process-global. In a shared test worker it also holds
    reporters that other tests imported -- the AWS plugin package registers
    aws-security-hub, s3 and others, and community plugins register their own.
    Those declare their config in their own packages and do not belong in core's
    ReporterConfigSegment, so the reverse check is scoped to the ash_builtin
    modules, by the module each registered class is defined in.
    """
    import typing

    import automated_security_helper.plugin_modules.ash_builtin.reporters  # noqa: F401
    from automated_security_helper.plugins import ash_plugin_manager

    names = set()
    for cls in ash_plugin_manager.plugin_modules("reporter"):
        if not cls.__module__.startswith(BUILTIN_REPORTER_MODULE_PREFIX):
            continue
        annotation = cls.model_fields["config"].annotation
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        config_cls = args[0] if args else annotation
        names.add(config_cls().name)
    return names


@pytest.mark.unit
def test_declared_reporter_fields_match_the_builtin_registry(gate):
    """ReporterConfigSegment and the built-in reporter registry agree, both ways.

    Declared -> registered is what the old config-field source checked
    incidentally. When check_reporters read ReporterConfigSegment, a declared
    field left behind for a removed reporter had no doc row and failed the gate.
    Reading the registry dropped that, so it is pinned here: every declared field
    must name a registered reporter. This direction is against the whole
    registry, as it was before.

    Built-in registered -> declared is the reverse. A registered reporter with no
    declared field still runs -- its config is kept through extra="allow" and
    get_plugin_config finds it -- but it is missing from the published
    AshConfig.json schema, so editors reading that schema do not offer it, and
    its options are not validated when the config loads. unused-suppressions was
    in exactly that state until it was declared. This direction is scoped to the
    reporters this package ships; see _builtin_registered_reporter_names.
    """
    from automated_security_helper.config.ash_config import ReporterConfigSegment

    declared = set(gate._segment_names(ReporterConfigSegment))
    registered = set(gate.reporter_names())
    builtin = _builtin_registered_reporter_names()
    assert declared, "ReporterConfigSegment declares no fields; nothing compared"
    assert builtin, "no built-in reporters are registered; nothing compared"
    # The reverse direction is only meaningful if the scoping kept the reporter
    # that motivated it, rather than filtering the registry down to nothing.
    assert "unused-suppressions" in builtin

    assert declared <= registered, (
        "ReporterConfigSegment declares fields for reporters the plugin registry "
        f"does not register: {sorted(declared - registered)}"
    )
    assert builtin <= declared, (
        "built-in reporters with no declared ReporterConfigSegment field, so "
        "they are missing from the published AshConfig.json schema: "
        f"{sorted(builtin - declared)}"
    )


@pytest.mark.unit
def test_scanner_check_can_fail(gate, tmp_path, monkeypatch):
    names = sorted(gate.scanner_names())
    doc = tmp_path / "scanners.md"

    def publish(rows):
        lines = ["| Scanner | Tool type |", "|---------|-----------|"]
        lines += [f"| `{r}` | SAST |" for r in rows]
        doc.write_text("\n".join(lines) + "\n", encoding="utf-8")
        monkeypatch.setattr(gate, "SCANNERS_REFERENCE_MD", doc)
        return gate.check_scanners()

    assert publish(names) == [], "the complete scanner table was rejected"
    assert publish(names[1:]), "a scanner missing from the table was accepted"
    assert publish(names + ["gosec"]), "a row naming a nonexistent scanner was accepted"


@pytest.mark.unit
def test_scanner_check_passes_on_the_generated_page_and_fails_without_a_real_row(
    gate, tmp_path, monkeypatch
):
    """Against the committed page. The community scanners are rows there and are not
    fields of ScannerConfigSegment, so the code side must include them: deleting
    trivy-repo's row must fail, and the page as generated must pass."""
    assert gate.check_scanners() == []
    names = gate.scanner_names()
    assert {"bandit", "trivy-repo"} <= set(names), sorted(names)

    real = gate.SCANNERS_REFERENCE_MD.read_text(encoding="utf-8")
    row = next(
        line for line in real.splitlines() if line.startswith("| [`trivy-repo`]")
    )
    doc = tmp_path / "scanners.md"
    doc.write_text(real.replace(row + "\n", ""), encoding="utf-8")
    monkeypatch.setattr(gate, "SCANNERS_REFERENCE_MD", doc)
    failures = gate.check_scanners()
    assert any("'trivy-repo'" in f and "no row" in f for f in failures), failures


@pytest.mark.unit
def test_mcp_tool_check_can_fail(gate, tmp_path, monkeypatch):
    """And that the parse sees plain `def` tools, which the old regex could not."""
    server = tmp_path / "mcp_server.py"
    server.write_text(
        "mcp = object()\n"
        "@mcp.tool()\n"
        "async def async_tool():\n"
        "    pass\n"
        "@mcp.tool()\n"
        "def plain_tool():\n"
        "    pass\n"
        "@mcp.tool\n"
        "def bare_decorator_tool():\n"
        "    pass\n"
        "def not_a_tool():\n"
        "    pass\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(gate, "MCP_SERVER_PY", server)

    found = gate.mcp_tool_names()
    assert set(found) == {"async_tool", "plain_tool", "bare_decorator_tool"}, (
        "the parse missed a decorated function or invented one; a plain `def` "
        "tool is exactly what the regex this replaced could not see"
    )

    doc = tmp_path / "mcp-tools.md"

    def publish(sections):
        body = "# MCP tools reference\n\n"
        body += "".join(f"## {name}\n\nDoes a thing.\n\n" for name in sections)
        body += "## Resources\n\n## Severity levels\n"
        doc.write_text(body, encoding="utf-8")
        monkeypatch.setattr(gate, "MCP_TOOLS_REFERENCE_MD", doc)
        return gate.check_mcp_tools()

    assert publish(sorted(found)) == [], (
        "the complete set of tool sections was rejected"
    )
    # The plain-def tool specifically: undocumenting it must now be caught.
    missing = publish(["async_tool", "bare_decorator_tool"])
    assert any("'plain_tool'" in f for f in missing), missing
    ghost = publish(sorted(found) + ["deleted_tool"])
    assert any("## deleted_tool" in f and "left behind" in f for f in ghost), ghost


@pytest.mark.unit
def test_mcp_tool_check_passes_on_the_generated_page_and_fails_without_a_section(
    gate, tmp_path, monkeypatch
):
    assert gate.check_mcp_tools() == []
    real = gate.MCP_TOOLS_REFERENCE_MD.read_text(encoding="utf-8")
    assert "\n## validate_config\n" in real
    doc = tmp_path / "mcp-tools.md"
    doc.write_text(
        real.replace("\n## validate_config\n", "\n### validate_config\n"),
        encoding="utf-8",
    )
    monkeypatch.setattr(gate, "MCP_TOOLS_REFERENCE_MD", doc)
    failures = gate.check_mcp_tools()
    assert any("'validate_config'" in f and "has no" in f for f in failures), failures


@pytest.mark.unit
def test_a_missing_table_fails_closed(gate, tmp_path, monkeypatch):
    """No table must never mean nothing to check.

    This is the failure mode the whole-file substring search had, relocated: if
    the table is renamed or removed, a set comparison against an empty set passes
    trivially. table_first_column returns None for that and the checks must turn
    it into a failure.
    """
    assert gate.table_first_column("no tables here at all", "Format") is None

    doc = tmp_path / "reporters.md"
    doc.write_text("# Reporters\n\nProse, no table.\n", encoding="utf-8")
    monkeypatch.setattr(gate, "REPORTERS_REFERENCE_MD", doc)
    failures = gate.check_reporters()
    assert failures, "a document with no table at all was accepted"
    assert "has no table" in failures[0]

    # A header row with no data rows is the same hazard.
    doc.write_text(
        "| Reporter | File extension |\n|----------|----------------|\n",
        encoding="utf-8",
    )
    empty = gate.check_reporters()
    assert empty, "a table with no data rows was accepted"

    # And an MCP tools page with no tool sections.
    page = tmp_path / "mcp-tools.md"
    page.write_text("# MCP tools reference\n\n## Resources\n", encoding="utf-8")
    monkeypatch.setattr(gate, "MCP_TOOLS_REFERENCE_MD", page)
    no_sections = gate.check_mcp_tools()
    assert no_sections and "has no '## <tool>' sections" in no_sections[0]


@pytest.mark.unit
def test_suppression_check_can_fail(gate, tmp_path, monkeypatch):
    doc = tmp_path / "suppressions.md"
    doc.write_text(
        "```yaml\nsuppressions:\n  - rule_id: B101\n    file_path: src/a.py\n```\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(gate, "collect_md_files", lambda: [doc])
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    assert gate.check_suppression_field_name(), (
        "'file_path:' in a suppression block was accepted; the field is 'path:'"
    )


@pytest.mark.unit
def test_plugin_options_check_can_fail(gate, tmp_path, monkeypatch):
    doc = tmp_path / "config.md"
    doc.write_text(
        "```yaml\nscanners:\n  bandit:\n    options:\n"
        "      severity_level: HIGH\n```\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(gate, "collect_md_files", lambda: [doc])
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    failures = gate.check_plugin_option_keys()
    assert any("severity_level" in f for f in failures), (
        f"an invented scanner option key was accepted: {failures}"
    )


_INVENTED_BANDIT_OPTION = (
    "scanners:\n  bandit:\n    options:\n      severity_level: HIGH\n"
)
_DECLARED_BANDIT_OPTION = (
    "scanners:\n  bandit:\n    options:\n      severity_threshold: HIGH\n"
)


def _one_config_block(tmp_path, monkeypatch, gate, marker: str, body: str) -> None:
    doc = tmp_path / "page.md"
    marker_line = f"{marker}\n" if marker else ""
    doc.write_text(f"# Page\n\n{marker_line}```yaml\n{body}```\n", encoding="utf-8")
    monkeypatch.setattr(gate, "collect_md_files", lambda: [doc])
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)


@pytest.mark.unit
@pytest.mark.parametrize(
    "marker",
    ["", "<!-- doctest: config kind=ash -->"],
    ids=["unmarked", "kind=ash"],
)
def test_an_invented_option_fails_both_checks_in_a_config_block(
    gate, tmp_path, monkeypatch, marker
):
    """The planted defect for the exemption below: the block it exempts, unexempted."""
    _one_config_block(tmp_path, monkeypatch, gate, marker, _INVENTED_BANDIT_OPTION)
    options = gate.check_plugin_option_keys()
    assert any("options.severity_level is not a field of" in f for f in options), (
        options
    )
    assert any("severity_level" in f for f in gate.check_doc_config_blocks())


@pytest.mark.unit
def test_an_ash_invalid_block_may_show_an_invented_option(gate, tmp_path, monkeypatch):
    """A page may show the config ASH refuses, as long as it says so.

    ``config kind=ash-invalid`` is how a page shows an option a plugin does not
    declare. The options check skips that block, and the config-blocks check holds
    it to being invalid instead, which the invented key satisfies. Without the skip,
    the options check reported the very mistake the block exists to show.
    """
    marker = '<!-- doctest: config kind=ash-invalid reason="severity_level is not a bandit option" -->'
    _one_config_block(tmp_path, monkeypatch, gate, marker, _INVENTED_BANDIT_OPTION)
    assert gate.check_plugin_option_keys() == []
    assert gate.check_doc_config_blocks() == []


@pytest.mark.unit
def test_an_ash_invalid_block_that_validates_is_still_reported(
    gate, tmp_path, monkeypatch
):
    """The skip above does not let a valid config wear the ash-invalid marker."""
    _one_config_block(tmp_path, monkeypatch, gate, "", _DECLARED_BANDIT_OPTION)
    assert gate.check_plugin_option_keys() == [], "the control config is not valid"
    assert gate.check_doc_config_blocks() == [], "the control config is not valid"

    marker = '<!-- doctest: config kind=ash-invalid reason="claims a refusal" -->'
    _one_config_block(tmp_path, monkeypatch, gate, marker, _DECLARED_BANDIT_OPTION)
    failures = gate.check_doc_config_blocks()
    assert any("ASH accepts this one" in f for f in failures), failures


@pytest.mark.unit
def test_version_check_can_fail(gate, tmp_path, monkeypatch):
    assert gate.check_version_consistency() == [], "the committed pins were rejected"
    doc = tmp_path / "install.md"
    doc.write_text("Install ASH at `@v0.0.1`\n", encoding="utf-8")
    monkeypatch.setattr(gate, "INSTALL_MD", doc)
    failures = gate.check_version_consistency()
    assert any("install.md" in f and "@v0.0.1" in f for f in failures), failures
    doc.write_text("Install ASH from the main branch.\n", encoding="utf-8")
    assert any("does not reference" in f for f in gate.check_version_consistency())


@pytest.mark.unit
def test_version_check_reports_a_stale_pin_beside_the_current_one(
    gate, tmp_path, monkeypatch
):
    """One older pin on a page that also has the current one installs the wrong release.

    The check used to look for older pins only when the current one was missing, so a
    page with seven current commands and one stale one passed.
    """
    version = gate.get_version_from_pyproject()
    major, minor, _patch = (int(part) for part in version.split("."))
    stale = f"@v{major}.{minor - 1}.0" if minor else f"@v{major - 1}.0.0"
    real = gate.INSTALL_MD.read_text(encoding="utf-8")
    assert f"@v{version}" in real and stale not in real

    doc = tmp_path / "install.md"
    doc.write_text(
        real + "\n```bash\nuvx --from "
        f"git+https://github.com/awslabs/automated-security-helper.git{stale} ash\n```\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(gate, "INSTALL_MD", doc)
    failures = gate.check_version_consistency()
    assert any("install.md" in f and stale in f for f in failures), failures

    # Control: the real page, copied unchanged, passes.
    doc.write_text(real, encoding="utf-8")
    assert gate.check_version_consistency() == []


# ---------------------------------------------------------------------------
# The widened corpus
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_the_md_corpus_reaches_past_the_docs_directory(gate):
    """The glob was `docs/**/*.md` plus README.md, so most of the tree was exempt.

    A config example with an invented option key is as wrong in examples/ as in
    docs/. Asserting specific files rather than only a count, because a count
    grows on its own as docs are added and would stop meaning anything.
    """
    files = {
        path.relative_to(gate.REPO_ROOT).as_posix() for path in gate.collect_md_files()
    }

    for expected in ("README.md", "SECURITY.md", "CONTRIBUTING.md"):
        assert expected in files, f"{expected} is outside every doc check"

    assert any(f.startswith("docs/") for f in files)
    assert any(not f.startswith("docs/") and "/" in f for f in files), (
        "no nested non-docs markdown was collected"
    )

    # Build output and caches must stay out: MkDocs output is a rendered copy of
    # docs/, so including it would double every finding.
    assert not any(
        f.startswith(("site/", "public/", ".venv/", "node_modules/")) for f in files
    )
    # syrupy's markdown golden files are reporter output, not docs.
    assert not any("/__snapshots__/" in f for f in files)


@pytest.mark.integration
@pytest.mark.parametrize("parent", [".cache", "site", "venv", "node_modules"])
def test_a_checkout_under_an_excluded_directory_name_still_collects_its_docs(
    gate, tmp_path, monkeypatch, parent
):
    """The exclusions name directories inside the checkout. A checkout that itself
    sits under a directory of that name (~/.cache/ash, /srv/site/ash) used to collect
    nothing, and every check that reads the corpus then passed."""
    root = tmp_path / parent / "checkout"
    _make = {
        "README.md": "# Readme\n",
        "docs/page.md": "# Page\n",
        "docs/site/built.md": "# A build output inside the checkout stays out\n",
        ".venv/lib/x.md": "# So does a virtual environment\n",
    }
    for rel, text in _make.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    _own_repository(root)
    monkeypatch.setattr(gate, "REPO_ROOT", root)
    files = {path.relative_to(root).as_posix() for path in gate.collect_md_files()}
    assert files == {"README.md", "docs/page.md"}


@pytest.mark.integration
def test_dated_notes_stay_out_of_the_corpus_and_their_neighbors_stay_in(gate):
    """ferret-scan's spec/ notes are a record of one upgrade, kept as written.

    The plugin's README and DEVELOPMENT.md beside them are documentation and must
    still be checked, so the exclusion is by path, not by the directory name.
    """
    files = {
        path.relative_to(gate.REPO_ROOT).as_posix() for path in gate.collect_md_files()
    }
    plugin = "automated_security_helper/plugin_modules/ash_ferret_plugins/"
    notes = sorted((gate.REPO_ROOT / plugin / "spec").glob("*.md"))
    assert notes, "the spec notes this test is about are gone; drop the exclusion"
    assert not any(f.startswith(plugin + "spec/") for f in files)
    assert {plugin + "README.md", plugin + "DEVELOPMENT.md"} <= files


@pytest.mark.integration
def test_an_empty_corpus_is_a_failure_not_a_pass(gate, tmp_path, monkeypatch):
    """Zero files makes every corpus check vacuous; it must fail, loudly."""
    root = tmp_path / "no-docs"
    (root / "src").mkdir(parents=True)
    _own_repository(root)
    monkeypatch.setattr(gate, "REPO_ROOT", root)
    with pytest.raises(RuntimeError, match="no markdown"):
        gate.collect_md_files()
    with pytest.raises(RuntimeError, match="no markdown"):
        gate.check_doc_markers()


@pytest.mark.integration
def test_the_md_corpus_excludes_generated_interface_artifacts(
    gate, tmp_path, monkeypatch
):
    """Building a preview must not add copied templates to the source corpus."""
    source = tmp_path / "docs" / "content"
    source.mkdir(parents=True)
    (source / "index.md").write_text("# Current source\n", encoding="utf-8")
    (source / "index.md.template").write_text("# Current source\n", encoding="utf-8")

    for directory in (
        tmp_path / "public" / "docs",
        tmp_path / "docs" / "ui-tests" / ".previews",
        tmp_path / "docs" / "ui-tests" / "playwright-report",
    ):
        directory.mkdir(parents=True)
        (directory / "index.md.template").write_text(
            "# Generated copy without a Markdown sibling\n", encoding="utf-8"
        )
    _own_repository(tmp_path)
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)

    assert {
        path.relative_to(tmp_path).as_posix() for path in gate.collect_md_files()
    } == {"docs/content/index.md", "docs/content/index.md.template"}


@pytest.mark.integration
def test_the_md_corpus_includes_the_templates_docs_are_generated_from(gate):
    """Docs rendered from a sibling .template are edited in the template.

    Checking only the rendered doc reports drift against a path where a fix does
    not survive. This is the same defect as the name checks reading README.md
    rather than README.md.template, in the checks that walk the whole corpus.

    Not hypothetical: the change that widened this corpus initially edited
    docs/content/faq.md and left docs/content/faq.md.template stale, and
    tests/unit/test_version_template_round_trip.py is what caught it.

    The expected templates come from scripts/version_template_manager.py's own
    target list, so a page that gains or loses a template changes this test's
    expectation without an edit here.
    """
    spec = importlib.util.spec_from_file_location(
        "_ash_version_template_manager",
        REPO_ROOT / "scripts" / "version_template_manager.py",
    )
    assert spec and spec.loader
    manager_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manager_module)
    targets = manager_module.VersionTemplateManager(REPO_ROOT).target_files
    expected = {
        f"{target}.template"
        for target in targets
        if (REPO_ROOT / f"{target}.template").is_file()
    }
    assert "README.md.template" in expected, sorted(expected)
    assert len(expected) > 1, sorted(expected)

    files = {
        path.relative_to(gate.REPO_ROOT).as_posix() for path in gate.collect_md_files()
    }
    templates = {f for f in files if f.endswith(".md.template")}
    assert expected <= templates, (
        f"templates the release renders but no check reads: {sorted(expected - templates)}"
    )

    # Each collected template's rendered sibling must be collected too, so the
    # two are never checked in isolation from one another.
    for template in templates:
        assert template[: -len(".template")] in files, (
            f"{template} is collected but its rendered doc is not"
        )


# ---------------------------------------------------------------------------
# The gate's wiring: each label runs its own check, and a finding fails the gate
# ---------------------------------------------------------------------------
#
# The tests above prove each check can fail when called directly, and for checks 9-18
# that call is to scripts/docs_checks.py, one layer below what main() runs. The
# wrappers in between were unguarded: seven of them could return [] with every test
# here green, and so could a main() that paired a label with another label's
# callable, or that lost a tuple together with its NON_VACUITY_COVERAGE entry.
#
# So each check is driven through main() itself. Its innermost function, the
# docs_checks one a wrapper calls or the gate function for the first seven, returns a
# planted finding and every other check returns nothing. main() must exit 1 and print
# the planted finding under that check's FAIL line and nowhere else. The table below
# is a third statement of the checks, beside main() and NON_VACUITY_COVERAGE, so
# deleting a check from both of those still fails here.
#
# The count main() must report comes from its own check list, not from this table. A
# change that registers a check adds a row here in the same commit; until it does,
# test_the_wiring_table_names_every_registered_check names the check that has no row,
# and the other tests here stay green because a check with no row is kept silent.

#: Each check's label in main() -> (the module that holds the function the gate ends
#: up calling, that function's name).
GATE_WIRING = {
    "Reporter list in docs matches code": ("gate", "check_reporters"),
    "Scanner list in docs matches code": ("gate", "check_scanners"),
    "MCP tool names in docs match code": ("gate", "check_mcp_tools"),
    "Version consistency": ("gate", "check_version_consistency"),
    "Config file path consistency": ("gate", "check_config_path"),
    "Suppression field name": ("gate", "check_suppression_field_name"),
    "Plugin options in docs exist and validate": ("gate", "check_plugin_option_keys"),
    "Doc block markers are well formed": ("docs_checks", "check_markers"),
    "ASH commands in docs match the CLI": ("docs_checks", "check_cli"),
    "ASH environment variables in docs are read by ASH": (
        "docs_checks",
        "check_env_vars",
    ),
    "Config blocks in docs validate": ("docs_checks", "check_config_blocks"),
    "Python blocks in docs parse and import": ("docs_checks", "check_python_blocks"),
    "Links and anchors in docs resolve": ("docs_checks", "check_links"),
    "Docs navigation and redirects resolve": ("docs_checks", "check_nav"),
    "Docs site build is strict, offline and versioned": (
        "docs_checks",
        "check_site_build",
    ),
    "Release numbers in templates stay out of install commands": (
        "docs_checks",
        "check_release_placeholders",
    ),
    "Docs links in the ASH source resolve": ("docs_checks", "check_code_links"),
    "Option tables and config paths in docs match the models": (
        "docs_checks",
        "check_option_tables",
    ),
    "MCP error types and example responses in docs match the tools": (
        "docs_checks",
        "check_mcp_contract",
    ),
    "Install commands in docs name real extras, Pythons and refs": (
        "docs_checks",
        "check_install_commands",
    ),
    "Report file names in docs are files ASH writes": (
        "docs_checks",
        "check_report_files",
    ),
    "Scanner names in docs tables are scanners ASH ships": (
        "docs_checks",
        "check_scanner_names",
    ),
    "Shell variables in docs examples are set in the session that reads them": (
        "docs_checks",
        "check_session_variables",
    ),
    "Values docs examples pass the scan workflow pass its input check": (
        "docs_checks",
        "check_workflow_inputs",
    ),
}


@pytest.mark.unit
def test_the_wiring_table_names_every_registered_check():
    registered = set(_registered_check_names())
    assert registered, "main() registers no checks; nothing is compared"
    unwired = sorted(registered - set(GATE_WIRING))
    ghosts = sorted(set(GATE_WIRING) - registered)
    assert not unwired and not ghosts, (
        f"checks main() registers with no GATE_WIRING row: {unwired}\n"
        f"GATE_WIRING rows that name no check main() registers: {ghosts}\n"
        "A change that adds, renames or removes a check updates GATE_WIRING with it."
    )


def _gate_report(output: str) -> dict[str, tuple[str, list[str]]]:
    """main()'s per-check lines: label -> (PASS, FAIL or ERROR, the lines printed under it)."""
    report: dict[str, tuple[str, list[str]]] = {}
    label = None
    for line in output.splitlines():
        if line.startswith(("PASS  ", "FAIL  ", "ERROR ")):
            label = line[len("PASS  ") :]
            assert label not in report, f"{label!r} ran twice"
            report[label] = (line[:5].rstrip(), [])
        elif line.startswith("        - ") and label is not None:
            report[label][1].append(line[len("        - ") :])
        elif not line.startswith("        "):
            label = None
    return report


def _wire(gate, monkeypatch, tmp_path, planted_label=None, raises=False):
    """Silence every check, or plant a finding in one; return what each call must get.

    With ``raises``, the planted check raises a RuntimeError carrying the planted
    message instead of returning it as a finding.

    The gate's corpus is a planted list too, so a wrapper that hands its check anything
    else (an empty list, another corpus) is caught by the arguments the call records.
    """
    docs_checks = gate._docs_checks()
    corpus = [tmp_path / "planted.md"]
    monkeypatch.setattr(gate, "collect_md_files", lambda: list(corpus))
    calls: dict[str, list[tuple]] = {}
    expected_args: dict[str, tuple] = {}
    planted_line = None
    for label, (layer, name) in GATE_WIRING.items():
        module = gate if layer == "gate" else docs_checks
        real = getattr(module, name, None)
        assert callable(real), f"{layer}.{name} does not exist"
        if layer == "gate":
            expected_args[name] = ()
        elif next(iter(inspect.signature(real).parameters)) == "files":
            expected_args[name] = (corpus, gate.REPO_ROOT)
        else:
            expected_args[name] = (gate.REPO_ROOT,)
        result: list = []
        error = None
        if label == planted_label:
            message = f"planted for {name} by the wiring test"
            if raises:
                planted_line = message
                error = RuntimeError(message)
            elif layer == "gate":
                planted_line = message
                result = [message]
            else:
                finding = docs_checks.Finding("wiring", "planted.md", 7, message)
                planted_line = str(finding)
                result = [finding]

        def check(*args, _name=name, _result=result, _error=error, **kwargs):
            # A corpus may arrive as any iterable; it is compared as a list.
            calls.setdefault(_name, []).append(
                tuple(list(a) if isinstance(a, (list, tuple)) else a for a in args)
            )
            if _error is not None:
                raise _error
            return list(_result)

        monkeypatch.setattr(module, name, check)

    # A check main() registers with no row here runs silent, so its missing row is
    # reported once, by test_the_wiring_table_names_every_registered_check, and not
    # as a real finding in every test below. The callable is left alone when a wired
    # check uses it too.
    registered = dict(_registered_checks())
    wired = {registered[label] for label in GATE_WIRING if label in registered}
    for label, function in registered.items():
        if label not in GATE_WIRING and function not in wired:
            monkeypatch.setattr(gate, function, lambda *args, **kwargs: [])
    return planted_line, calls, expected_args


@pytest.mark.unit
def test_the_gate_passes_when_every_check_is_silent(
    gate, monkeypatch, tmp_path, capsys
):
    """Control: with nothing to report, every label passes and the gate exits 0."""
    _planted, calls, expected_args = _wire(gate, monkeypatch, tmp_path)
    assert gate.main([]) == 0
    output = capsys.readouterr().out
    report = _gate_report(output)
    registered = _registered_check_names()
    assert report == {label: ("PASS", []) for label in registered}, output
    total = len(registered)
    assert f"Results: {total} passed, 0 failed, {total} total" in output, output
    wired = {GATE_WIRING[label][1] for label in registered if label in GATE_WIRING}
    assert calls == {
        name: [args] for name, args in expected_args.items() if name in wired
    }, calls


@pytest.mark.unit
@pytest.mark.parametrize("label", list(GATE_WIRING))
def test_a_finding_fails_the_gate_under_its_own_label(
    gate, monkeypatch, tmp_path, capsys, label
):
    layer, name = GATE_WIRING[label]
    planted_line, calls, expected_args = _wire(gate, monkeypatch, tmp_path, label)

    assert gate.main([]) == 1, f"a finding from {layer}.{name} did not fail the gate"
    output = capsys.readouterr().out
    report = _gate_report(output)
    assert report.get(label) == ("FAIL", [planted_line]), (
        f"{label!r} did not print its own finding: main() pairs it with another "
        f"callable, its wrapper drops what {name} returns, or it is gone\n{output}"
    )
    registered = _registered_check_names()
    others = {other: report.get(other) for other in registered if other != label}
    assert others == {other: ("PASS", []) for other in others}, output
    total = len(registered)
    assert f"Results: {total - 1} passed, 1 failed, {total} total" in output, output
    # Once, on the gate's corpus and root.
    assert calls.get(name) == [expected_args[name]], (
        f"{name} was called {calls.get(name)}, not once with {expected_args[name]}"
    )


# A check that raises did not run. main() reports it under its own label as ERROR,
# with the exception, counts it apart from failures and exits 2, so neither a reader
# of the output nor a comparison of two runs can take it for a check that ran. The
# case that matters most is a check that lists files with git (docs_checks.listed_files)
# run where git cannot list them: an extract of the tree (git archive) has all the
# files and no repository. Two runs on extracts once compared clean while two checks
# had not run on either side, because each side printed the same exception as an
# ordinary finding.


@pytest.mark.unit
@pytest.mark.parametrize("label", list(GATE_WIRING))
def test_a_check_that_raises_fails_the_gate_under_its_own_label(
    gate, monkeypatch, tmp_path, capsys, label
):
    layer, name = GATE_WIRING[label]
    planted_line, calls, expected_args = _wire(
        gate, monkeypatch, tmp_path, label, raises=True
    )

    assert gate.main([]) == 2, (
        f"{layer}.{name} raising did not fail the gate as not run"
    )
    output = capsys.readouterr().out
    report = _gate_report(output)
    assert report.get(label) == (
        "ERROR",
        [f"the check did not run: RuntimeError: {planted_line}"],
    ), f"{label!r} did not report that it did not run\n{output}"
    registered = _registered_check_names()
    others = {other: report.get(other) for other in registered if other != label}
    assert others == {other: ("PASS", []) for other in others}, output
    total = len(registered)
    assert (
        f"Results: {total - 1} passed, 0 failed, 1 did not run, {total} total" in output
    ), output
    assert calls.get(name) == [expected_args[name]], calls.get(name)


#: The checks that list a tree's files with git, so cannot run on an extract.
GIT_LISTING_CHECKS = (
    "Docs navigation and redirects resolve",
    "Docs site build is strict, offline and versioned",
)


@pytest.mark.integration
def test_the_gate_on_an_extract_fails_the_checks_that_list_files_with_git(
    gate, monkeypatch, tmp_path, capsys
):
    """The gate run on an extract of this checkout, its files without a repository,
    fails, and names each check that lists files with git as one that did not run.

    The extract is a copy of the files git lists here. If tmp_path sits inside an
    ignored directory of a checkout, git names the extract as ignored instead of
    failing to find a repository; either way the check cannot list it.
    """
    extract = tmp_path / "extract"
    for path in gate._docs_checks().listed_files(REPO_ROOT):
        target = extract / path.relative_to(REPO_ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    for label, function in _registered_checks():
        if label not in GIT_LISTING_CHECKS:
            monkeypatch.setattr(gate, function, lambda *args, **kwargs: [])
    # --docs-root repoints the gate's module-level paths; put them back afterward.
    for name in (*gate._DOCS_PATHS, *gate._CODE_PATHS, "PYPROJECT_TOML", "REPO_ROOT"):
        monkeypatch.setattr(gate, name, getattr(gate, name))

    assert gate.main(["--docs-root", str(extract)]) == 2
    output = capsys.readouterr().out
    report = _gate_report(output)
    for label in GIT_LISTING_CHECKS:
        status, lines = report.get(label, (None, []))
        assert status == "ERROR", f"{label!r} on an extract was {status}\n{output}"
        assert any(
            "git cannot list" in line or "is ignored by the checkout" in line
            for line in lines
        ), f"{label!r} did not say git could not list the extract\n{output}"
    others = [label for label in report if label not in GIT_LISTING_CHECKS]
    assert others and all(report[label] == ("PASS", []) for label in others), output
