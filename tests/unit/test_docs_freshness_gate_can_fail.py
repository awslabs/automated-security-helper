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
import json
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
    "Native package install pages match packaging": "test_native_package_docs_check_can_fail",
    "Nothing installs ASH by its PyPI name": "test_index_name_install_check_can_fail",
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


def test_reporter_check_passes_on_the_generated_table():
    """The gate must accept the table the generator writes.

    The reporter-quick-reference block in output-formats.md is written by
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


def test_reporter_check_reads_the_generators_registry(gate):
    """The gate's reporter inventory is the generator's, not a second opinion.

    Asserted as set equality with the generator's own function, so the gate
    reverting to any other source (config fields, ASH_REPORTERS, the package
    ``__all__``) that happens to disagree with the registry fails here by name.
    """
    expected = {row["name"] for row in _generator().registered_reporters()}
    assert expected, "the registry returned no reporters; nothing is being compared"
    assert set(gate.reporter_names()) == expected


def test_reporter_check_can_fail_in_both_directions(gate, tmp_path, monkeypatch):
    """A row naming a removed reporter used to pass; that was the whole defect."""
    names = sorted(gate.reporter_names())

    def publish(rows):
        doc = tmp_path / "output-formats.md"
        lines = ["| Format | File extension |", "|--------|----------------|"]
        lines += [f"| {r} | `.x` |" for r in rows]
        doc.write_text("\n".join(lines) + "\n", encoding="utf-8")
        monkeypatch.setattr(gate, "OUTPUT_FORMATS_MD", doc)
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


def test_reporter_check_fails_when_a_real_row_is_deleted(gate, tmp_path, monkeypatch):
    """Against a copy of the real page, not a synthetic table.

    The synthetic test above builds its rows from the same inventory the check
    reads, so on its own it cannot tell a working comparison from a list compared
    with itself. Here the doc side is the committed page with one row removed.
    """
    real = gate.OUTPUT_FORMATS_MD.read_text(encoding="utf-8")
    row = next(line for line in real.splitlines() if "(`unused-suppressions`)" in line)
    doc = tmp_path / "output-formats.md"
    doc.write_text(real.replace(row + "\n", ""), encoding="utf-8")
    monkeypatch.setattr(gate, "OUTPUT_FORMATS_MD", doc)

    failures = gate.check_reporters()
    assert any("'unused-suppressions'" in f and "no row" in f for f in failures), (
        f"deleting a registered reporter's row was accepted: {failures}"
    )


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


def test_cli_flags_check_can_fail(gate):
    """Including a flag declared only inside typer's combined `--on/--off` form.

    An earlier regex over scan.py required the flag to be the entire quoted
    string, so neither half of `"--python-only/--full"` was ever extracted. The
    gate now introspects the built click command, where the OFF half is a
    `secondary_opts` entry rather than a literal, so this asserts the real
    command surface yields both halves and that removing the OFF half from the
    real page is reported.
    """
    import re

    spellings = gate.cli_option_spellings()
    assert {"--python-only", "--full"} <= spellings, (
        "a flag declared only in combined form was not extracted: "
        f"{sorted(s for s in spellings if 'python' in s or 'full' in s)}"
    )

    docs = gate.read_text(gate.CLI_REFERENCE_MD)
    assert gate.check_cli_flags(spellings, docs) == [], (
        "the committed cli-reference.md must pass before the negative control means anything"
    )

    stale = re.sub(r"(?<![\w-])--full(?![\w-])", "", docs)
    assert stale != docs, "the control did not remove anything"
    failures = gate.check_cli_flags(spellings, stale)
    assert any("--full " in f for f in failures), (
        f"removing --full from the page was not reported: {failures}"
    )


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


# ---------------------------------------------------------------------------
# Native package install pages
# ---------------------------------------------------------------------------

_NATIVE_SOURCES = (
    "docs/content/.nav.yml",
    "packaging/chocolatey/ash.nuspec",
    "packaging/chocolatey/build.ps1",
    "packaging/chocolatey/README.chocolatey",
    "packaging/winget/Amazon.AutomatedSecurityHelper.locale.en-US.yaml",
    "packaging/msix/AppxManifest.xml",
    "packaging/msix/build.ps1",
    "packaging/msix/README.msix",
    "packaging/flatpak/io.github.awslabs.automated_security_helper.yml",
    "packaging/flatpak/build.sh",
    "packaging/flatpak/README.flatpak",
    ".github/workflows/ash-tag-on-merge.yml",
    "packaging/release-assets.py",
)


# Commands that fetch ASH from its own wheel or git URL, which the name rule must accept.
# The git ref is assembled rather than written out, so the install-ref walk in
# test_agent_plugin_ash_version.py does not read a pin in this file that a bump would
# leave stale. The rule under test only cares about the shape of the command.
_GIT_REF = "git+https://github.com/awslabs/automated-security-helper" + ".git@main"
_NAME_RULE_MUST_NOT_FLAG = (
    f'pip install "automated-security-helper[symbols] @ {_GIT_REF}"',
    f"pip install {_GIT_REF}",
    'uv pip install "automated-security-helper@https://example.invalid/ash.tar.gz"',
    'pip install "automated-security-helper @ file:///srv/wheels/ash.whl"',
    f"uvx --from {_GIT_REF} ashx --version",
    "pip download ./automated_security_helper-0.0.0-py3-none-any.whl -d wheels",
)


@pytest.fixture
def native_tree(gate, tmp_path, monkeypatch):
    """A copy of the install pages and the packaging they describe, wired into the gate.

    Copied rather than edited in place, so a planted defect can never be left behind
    in the real tree by a failing assertion.
    """
    import shutil

    for rel in _NATIVE_SOURCES:
        dest = tmp_path / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO_ROOT / rel, dest)
    pages_src = REPO_ROOT / "docs" / "content" / "docs" / "native-packages"
    pages = tmp_path / "docs" / "content" / "docs" / "native-packages"
    shutil.copytree(pages_src, pages)

    packaging = tmp_path / "packaging"
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(gate, "DOCS_DIR", tmp_path / "docs")
    monkeypatch.setattr(
        gate, "DOCS_NAV_YML", tmp_path / "docs" / "content" / ".nav.yml"
    )
    monkeypatch.setattr(gate, "NATIVE_PACKAGES_DOCS_DIR", pages)
    monkeypatch.setattr(gate, "PACKAGING_DIR", packaging)
    monkeypatch.setattr(
        gate, "CHOCOLATEY_NUSPEC", packaging / "chocolatey" / "ash.nuspec"
    )
    monkeypatch.setattr(
        gate, "CHOCOLATEY_BUILD_PS1", packaging / "chocolatey" / "build.ps1"
    )
    monkeypatch.setattr(
        gate,
        "WINGET_LOCALE_MANIFEST",
        packaging / "winget" / "Amazon.AutomatedSecurityHelper.locale.en-US.yaml",
    )
    monkeypatch.setattr(
        gate, "MSIX_APPX_MANIFEST", packaging / "msix" / "AppxManifest.xml"
    )
    monkeypatch.setattr(gate, "MSIX_BUILD_PS1", packaging / "msix" / "build.ps1")
    monkeypatch.setattr(
        gate,
        "FLATPAK_MANIFEST",
        packaging / "flatpak" / "io.github.awslabs.automated_security_helper.yml",
    )
    monkeypatch.setattr(gate, "FLATPAK_BUILD_SH", packaging / "flatpak" / "build.sh")
    monkeypatch.setattr(
        gate,
        "RELEASE_WORKFLOW",
        tmp_path / ".github" / "workflows" / "ash-tag-on-merge.yml",
    )
    monkeypatch.setattr(gate, "RELEASE_ASSETS_PY", packaging / "release-assets.py")
    monkeypatch.setattr(gate, "collect_md_files", lambda: sorted(pages.glob("*.md")))
    return tmp_path


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert old in text, f"fixture drift: {old!r} is no longer in {path.name}"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def _append_text(path: Path, text: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(text)


def _append_fence(path: Path, body: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"\n```\n{body}\n```\n")


def test_native_package_docs_check_can_fail(gate, native_tree):
    """Every rule in check_native_package_docs rejects the drift it names.

    Each case plants one defect in a fresh copy of the tree and requires a failure
    whose message names that defect, so a case cannot pass on some other failure.
    The control comes first: the copied tree must pass, or the failures below would
    say nothing about the planted defects.
    """
    import shutil

    pages = native_tree / "docs" / "content" / "docs" / "native-packages"
    packaging = native_tree / "packaging"
    nav = native_tree / "docs" / "content" / ".nav.yml"
    pristine = native_tree.parent / (native_tree.name + "-pristine")
    shutil.copytree(native_tree, pristine)

    def reset() -> None:
        shutil.rmtree(native_tree)
        shutil.copytree(pristine, native_tree)

    assert gate.check_native_package_docs() == []

    cases = [
        (
            "the release starts attaching another package",
            lambda: _edit(
                packaging / "release-assets.py",
                'key="flatpak",',
                'key="appimage",',
            ),
            "release-assets.py now attaches ['appimage', 'deb',",
        ),
        (
            "the release attaches files the asset check never saw",
            lambda: _edit(
                native_tree / ".github" / "workflows" / "ash-tag-on-merge.yml",
                "            release-assets/*\n",
                "            release-assets/* dist/*.msix\n",
            ),
            "attaches ['release-assets/*', 'dist/*.msix'], not the release-assets/*",
        ),
        (
            "the release no longer checks the directory it attaches",
            lambda: _edit(
                native_tree / ".github" / "workflows" / "ash-tag-on-merge.yml",
                "release-assets.py check release-assets",
                "release-assets.py list release-assets",
            ),
            "does not run `release-assets.py check`",
        ),
        (
            "the asset check survives only as a comment",
            lambda: _edit(
                native_tree / ".github" / "workflows" / "ash-tag-on-merge.yml",
                "          python3 packaging/release-assets.py check release-assets",
                "          # python3 packaging/release-assets.py check release-assets",
            ),
            "does not run `release-assets.py check`",
        ),
        (
            "the asset check survives only in a YAML comment",
            lambda: (
                _edit(
                    native_tree / ".github" / "workflows" / "ash-tag-on-merge.yml",
                    "          python3 packaging/release-assets.py check release-assets",
                    "          true",
                ),
                _append_text(
                    native_tree / ".github" / "workflows" / "ash-tag-on-merge.yml",
                    "# python3 packaging/release-assets.py check release-assets\n",
                ),
            ),
            "does not run `release-assets.py check`",
        ),
        (
            "nuspec id renamed under the pages",
            lambda: _edit(
                packaging / "chocolatey" / "ash.nuspec",
                "<id>ash</id>",
                "<id>ash-cli</id>",
            ),
            "but the package id is 'ash-cli'",
        ),
        (
            "choco install without --source",
            lambda: _append_fence(pages / "chocolatey.md", "choco install ash"),
            "with no --source",
        ),
        (
            "winget install from the community source",
            lambda: _append_fence(pages / "winget.md", "winget install ash"),
            "without --manifest",
        ),
        (
            "flatpak install from Flathub",
            lambda: _append_fence(
                pages / "flatpak.md",
                "flatpak install flathub io.github.awslabs.automated_security_helper",
            ),
            "it is not on Flathub",
        ),
        (
            "wrong Flatpak app id",
            lambda: _append_fence(
                pages / "flatpak.md", "flatpak run io.github.awslabs.ash --version"
            ),
            "Flatpak app id 'io.github.awslabs.ash'",
        ),
        (
            "wrong MSIX identity name",
            lambda: _append_fence(
                pages / "msix.md",
                "Get-AppxPackage -Name AWSLabs.ASH | Remove-AppxPackage",
            ),
            "Get-AppxPackage -Name AWSLabs.ASH",
        ),
        (
            "wrong .msix filename",
            lambda: _edit(
                pages / "msix.md",
                "automated-security-helper-<version>.msix'",
                "automated_security_helper-<version>-x64.msix'",
            ),
            "'automated_security_helper-<version>-x64.msix' is not the filename",
        ),
        (
            "flatpak build.sh renames its bundle",
            lambda: _edit(
                packaging / "flatpak" / "build.sh",
                'BUNDLE="$OUTDIR/ash-${VERSION}',
                'BUNDLE="$OUTDIR/automated-security-helper-${VERSION}',
            ),
            "is not the filename the build writes (automated-security-helper-<version>-<arch>.flatpak)",
        ),
        (
            "a page dropped from the nav",
            lambda: _edit(
                nav,
                "          - Flatpak (Linux): docs/native-packages/flatpak.md\n",
                "",
            ),
            "docs/native-packages/flatpak.md is not in .nav.yml",
        ),
        (
            "the nav names a page that does not exist",
            lambda: (pages / "winget.md").rename(pages / "winget-old.md"),
            "lists docs/native-packages/winget.md, which does not exist",
        ),
        (
            "winget moniker changed",
            lambda: _edit(
                packaging
                / "winget"
                / "Amazon.AutomatedSecurityHelper.locale.en-US.yaml",
                "Moniker: ash",
                "Moniker: ashx",
            ),
            "no install page names winget_moniker 'ashx'",
        ),
        (
            "the deprecated ash as a command",
            lambda: _append_fence(pages / "msix.md", "ash --version"),
            "runs `ash`, which no native package installs",
        ),
        (
            "--command=ash in the sandbox",
            lambda: _append_fence(
                pages / "flatpak.md",
                "flatpak run --command=ash io.github.awslabs.automated_security_helper",
            ),
            "runs `ash`, which no native package installs",
        ),
    ]
    for label, plant, expected in cases:
        reset()
        plant()
        failures = gate.check_native_package_docs()
        assert any(expected in f for f in failures), (
            f"{label}: no failure containing {expected!r}; got {failures}"
        )


@pytest.fixture
def name_rule_tree(gate, tmp_path, monkeypatch):
    """An empty repository shape for the PyPI-name rule: one doc, one README, one module."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "packaging" / "msix").mkdir(parents=True)
    (tmp_path / "automated_security_helper").mkdir()
    (tmp_path / "docs" / "page.md").write_text("# Page\n", encoding="utf-8")
    (tmp_path / "packaging" / "msix" / "README.msix").write_text(
        "Title\n=====\n", encoding="utf-8"
    )
    (tmp_path / "automated_security_helper" / "mod.py").write_text(
        '"""Module."""\n', encoding="utf-8"
    )
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(gate, "PACKAGING_DIR", tmp_path / "packaging")
    monkeypatch.setattr(
        gate, "collect_md_files", lambda: sorted((tmp_path / "docs").glob("*.md"))
    )
    return tmp_path


def test_index_name_install_check_can_fail(gate, name_rule_tree):
    """Each surface rejects an instruction that fetches ASH by its PyPI name.

    The name belongs to an unrelated third party. Every planted case is one the
    repository actually shipped before this check existed, in the shape it shipped:
    an offline recipe in a README, a doc example, a `uvx` run, an f-string hint and a
    message split across adjacent literals.
    """
    import shutil

    doc = name_rule_tree / "docs" / "page.md"
    readme = name_rule_tree / "packaging" / "msix" / "README.msix"
    module = name_rule_tree / "automated_security_helper" / "mod.py"
    pristine = name_rule_tree.parent / (name_rule_tree.name + "-pristine")
    shutil.copytree(name_rule_tree, pristine)

    def reset() -> None:
        shutil.rmtree(name_rule_tree)
        shutil.copytree(pristine, name_rule_tree)

    assert gate.check_no_index_name_install() == []

    by_name = "installs automated-security-helper by name from an index"
    in_message = "a message sends the user to ASH's PyPI name"
    cases = [
        (
            "pip download in a README's indented command",
            lambda: _append_text(
                readme, "\n  pip download automated-security-helper==0.0.0 -d C:\\w\n"
            ),
            "README.msix:4: " + by_name,
        ),
        (
            "uv tool install with an extra, in a doc",
            lambda: _append_fence(
                doc, 'uv tool install "automated-security-helper[x]"'
            ),
            by_name,
        ),
        (
            "uvx with an index version after @",
            lambda: _append_fence(
                doc, "uvx automated-security-helper@latest --version"
            ),
            by_name,
        ),
        (
            "uv tool install with a pinned index version after @",
            lambda: _append_fence(
                doc, "uv tool install automated-security-helper@4.0.0"
            ),
            by_name,
        ),
        (
            "poetry add by name",
            lambda: _append_fence(doc, 'poetry add "automated-security-helper[cdk]"'),
            by_name,
        ),
        (
            "an @ followed by something that is not a URL",
            lambda: _append_fence(
                doc, 'pip install "automated-security-helper @ 4.0.0"'
            ),
            by_name,
        ),
        (
            "a message with an index version after @",
            lambda: _append_text(
                module, 'MSG = "install automated-security-helper@latest"\n'
            ),
            in_message,
        ),
        (
            "uvx by name, in a doc",
            lambda: _append_fence(doc, "uvx automated-security-helper --mode local"),
            by_name,
        ),
        (
            "an f-string hint naming the extra",
            lambda: _append_text(
                module,
                'EXTRA = "x"\nHINT = f"install automated-security-helper[{EXTRA}]"\n',
            ),
            "mod.py:3: " + in_message,
        ),
        (
            "a reinstall hint split across adjacent literals",
            lambda: _append_text(
                module,
                'REASON = ("reinstall ASH (`pip install --force-reinstall "\n'
                '    "automated-security-helper`)")\n',
            ),
            in_message,
        ),
        (
            "a capitalized hint with no command in front",
            lambda: _append_text(
                module, 'MSG = "Install automated-security-helper first"\n'
            ),
            in_message,
        ),
        (
            "an install argv, the shape the cdk-nag scanner shipped",
            lambda: _append_text(
                module,
                'CMD = [sys.executable, "-m", "pip", "install", '
                '"automated-security-helper[cdk]"]\n',
            ),
            "mod.py:2: builds an install command for automated-security-helper by name",
        ),
    ]
    for label, plant, expected in cases:
        reset()
        plant()
        failures = gate.check_no_index_name_install()
        assert any(expected in f for f in failures), (
            f"{label}: no failure containing {expected!r}; got {failures}"
        )

    # What the rule must accept: ASH's own wheel, its git URL, a direct reference to
    # it, prose that warns against the name, and docstrings and comments that
    # explain the history.
    reset()
    _append_fence(doc, "\n".join(_NAME_RULE_MUST_NOT_FLAG))
    _append_text(doc, "\nDo not run `pip download automated-security-helper`.\n")
    _append_text(
        readme,
        "\nDo NOT run `pip download automated-security-helper`: it is not ASH.\n",
    )
    _append_text(
        module,
        "def f():\n"
        '    """This used to install ``automated-security-helper[cdk]``."""\n'
        "    # it used to say: pip install automated-security-helper\n"
        f"    return {_NAME_RULE_MUST_NOT_FLAG[0]!r}\n"
        'GITLAB_ID = {"id": "automated-security-helper"}\n'
        'ARGV = ["pip", "install", "automated-security-helper @ git+https://example.invalid"]\n',
    )
    assert gate.check_no_index_name_install() == []
