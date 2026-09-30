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


# Registered check name -> the test here that proves it can fail.
NON_VACUITY_COVERAGE = {
    "CLI flags in docs match source": "test_cli_flags_check_can_fail",
    "Reporter list in docs matches code": "test_reporter_check_can_fail_in_both_directions",
    "Scanner list in docs matches code": "test_scanner_check_can_fail",
    "MCP tool names in docs match code": "test_mcp_tool_check_can_fail",
    "Version consistency": "test_version_check_can_fail",
    "Config file path consistency": "test_config_path_check_can_fail",
    "Suppression field name": "test_suppression_check_can_fail",
    "Plugin options in docs exist and validate": "test_plugin_options_check_can_fail",
}


def _registered_check_names() -> list[str]:
    """Read the check list out of main() without executing the gate.

    Parsed rather than called: running main() runs all eight checks against the
    real tree, which is slow and would make this test fail for unrelated doc
    drift. The names are string literals in a list of tuples, so the syntax tree
    has them exactly.
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
        names = []
        for element in node.value.elts:
            assert isinstance(element, ast.Tuple)
            label = element.elts[0]
            assert isinstance(label, ast.Constant)
            names.append(label.value)
        return names
    raise AssertionError("could not find the `checks` list in main()")


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


def test_the_coverage_table_names_real_tests():
    """A typo in the table above would silently exempt a check."""
    module = sys.modules[__name__]
    for check, test_name in sorted(NON_VACUITY_COVERAGE.items()):
        assert hasattr(module, test_name), (
            f"{check!r} claims to be covered by {test_name!r}, which does not "
            f"exist in this module"
        )


# ---------------------------------------------------------------------------
# Per-check drift tests
# ---------------------------------------------------------------------------


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


def test_reporter_check_can_fail_in_both_directions(gate, tmp_path, monkeypatch):
    """A row naming a removed reporter used to pass; that was the whole defect."""
    from automated_security_helper.config.ash_config import ReporterConfigSegment

    names = sorted(gate._segment_names(ReporterConfigSegment))

    def publish(rows):
        doc = tmp_path / "output-formats.md"
        lines = ["| Format | File extension |", "|--------|----------------|"]
        lines += [f"| {r} | `.x` |" for r in rows]
        doc.write_text("\n".join(lines) + "\n", encoding="utf-8")
        monkeypatch.setattr(gate, "OUTPUT_FORMATS_MD", doc)
        return gate.check_reporters()

    assert publish(names) == [], "the complete reporter table was rejected"

    # docs -> code: the direction that was never checked.
    ghost = publish(names + ["cloudwatch-logs"])
    assert ghost, "a table row naming a nonexistent reporter was accepted"
    assert any("names nothing in the code" in f for f in ghost)

    # code -> docs.
    dropped = publish(names[1:])
    assert dropped, "a reporter missing from the table was accepted"
    assert any(names[0] in f for f in dropped)


def test_scanner_check_can_fail(gate, tmp_path, monkeypatch):
    """Also pins that the check reads the TEMPLATE, not the generated README."""
    from automated_security_helper.config.ash_config import ScannerConfigSegment

    names = sorted(gate._segment_names(ScannerConfigSegment))
    doc = tmp_path / "README.md.template"

    def publish(rows):
        lines = ["| Scanner | Type |", "|---------|------|"]
        lines += [f"| {r} | SAST |" for r in rows]
        doc.write_text("\n".join(lines) + "\n", encoding="utf-8")
        monkeypatch.setattr(gate, "README_TEMPLATE_MD", doc)
        return gate.check_scanners()

    assert publish(names) == [], "the complete scanner table was rejected"
    assert publish(names[1:]), "a scanner missing from the table was accepted"
    assert publish(names + ["gosec"]), "a row naming a nonexistent scanner was accepted"


def test_scanner_check_reads_the_editable_file_not_the_generated_one(gate):
    """README.md is generated from README.md.template; the gate must name the source.

    Sending a contributor to README.md means their fix is discarded the next time
    a release renders the template over it. This asserts the path constant the
    name checks use, so a change back to the generated file is caught here rather
    than by someone's edit going missing after a release.
    """
    assert gate.README_TEMPLATE_MD.name == "README.md.template"
    assert gate.README_TEMPLATE_MD.is_file()
    # The version check is the one legitimate reader of the generated file.
    assert gate.README_MD.name == "README.md"


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

    doc = tmp_path / "README.md.template"

    def publish(rows):
        lines = ["| Tool | Description |", "|------|-------------|"]
        lines += [f"| `{r}` | does a thing |" for r in rows]
        doc.write_text("\n".join(lines) + "\n", encoding="utf-8")
        monkeypatch.setattr(gate, "README_TEMPLATE_MD", doc)
        return gate.check_mcp_tools()

    assert publish(sorted(found)) == [], "the complete tool table was rejected"
    # The plain-def tool specifically: undocumenting it must now be caught.
    assert publish(["async_tool", "bare_decorator_tool"]), (
        "a plain `def` tool missing from the table was accepted"
    )
    assert publish(sorted(found) + ["deleted_tool"]), (
        "a table row naming a nonexistent tool was accepted"
    )


def test_a_missing_table_fails_closed(gate, tmp_path, monkeypatch):
    """No table must never mean nothing to check.

    This is the failure mode the whole-file substring search had, relocated: if
    the table is renamed or removed, a set comparison against an empty set passes
    trivially. table_first_column returns None for that and the checks must turn
    it into a failure.
    """
    assert gate.table_first_column("no tables here at all", "Format") is None

    doc = tmp_path / "output-formats.md"
    doc.write_text("# Output formats\n\nProse, no table.\n", encoding="utf-8")
    monkeypatch.setattr(gate, "OUTPUT_FORMATS_MD", doc)
    failures = gate.check_reporters()
    assert failures, "a document with no table at all was accepted"
    assert "has no table" in failures[0]

    # A header row with no data rows is the same hazard.
    doc.write_text(
        "| Format | File extension |\n|--------|----------------|\n", encoding="utf-8"
    )
    empty = gate.check_reporters()
    assert empty, "a table with no data rows was accepted"


def test_cli_flags_check_can_fail(gate, tmp_path, monkeypatch):
    """Including a flag declared only inside typer's combined `--on/--off` form.

    The pattern this replaced required the flag to be the entire quoted string,
    so neither half of `"--python-only/--full"` was ever extracted. That is also
    why skip_flags was dead: it listed `--no-progress`, which the old pattern
    could not produce, so the entry could never match anything.
    """
    source = tmp_path / "scan.py"
    source.write_text('opt = typer.Option("--python-only/--full-scan")\n', "utf-8")
    monkeypatch.setattr(gate, "CLI_SCAN_PY", source)

    docs = tmp_path / "cli-reference.md"
    docs.write_text("| `--python-only` | does a thing |\n", encoding="utf-8")
    monkeypatch.setattr(gate, "CLI_REFERENCE_MD", docs)

    failures = gate.check_cli_flags()
    assert any("--full-scan" in f for f in failures), (
        f"a flag declared only in combined form was not extracted: {failures}"
    )

    docs.write_text(
        "| `--python-only` | does a thing |\n| `--full-scan` | the other half |\n",
        encoding="utf-8",
    )
    assert gate.check_cli_flags() == [], "documenting both halves still failed"


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


def test_version_check_can_fail(gate, tmp_path, monkeypatch):
    doc = tmp_path / "index.md"
    doc.write_text("Install ASH at `@v0.0.1-not-the-version`\n", encoding="utf-8")
    monkeypatch.setattr(gate, "DOCS_INDEX_MD", doc)
    assert gate.check_version_consistency(), "an outdated version tag was accepted"


# ---------------------------------------------------------------------------
# The widened corpus
# ---------------------------------------------------------------------------


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

    # Build output and caches must stay out: mkdocs' site/ is a rendered copy of
    # docs/, so including it would double every finding.
    assert not any(f.startswith(("site/", ".venv/", "node_modules/")) for f in files)


def test_the_md_corpus_includes_the_templates_docs_are_generated_from(gate):
    """Ten docs are rendered from a sibling .template; that is the editable file.

    Checking only the rendered doc reports drift against a path where a fix does
    not survive. This is the same defect as the name checks reading README.md
    rather than README.md.template, in the checks that walk the whole corpus.

    Not hypothetical: the change that widened this corpus initially edited
    docs/content/faq.md and left docs/content/faq.md.template stale, and
    tests/unit/test_version_template_round_trip.py is what caught it.
    """
    files = {
        path.relative_to(gate.REPO_ROOT).as_posix() for path in gate.collect_md_files()
    }

    templates = {f for f in files if f.endswith(".md.template")}
    assert templates, (
        "no .md.template file was collected, so a stale list in a template is "
        "invisible to every check that walks this corpus"
    )
    assert "docs/content/faq.md.template" in templates
    assert "README.md.template" in templates

    # Each collected template's rendered sibling must be collected too, so the
    # two are never checked in isolation from one another.
    for template in templates:
        assert template[: -len(".template")] in files, (
            f"{template} is collected but its rendered doc is not"
        )
