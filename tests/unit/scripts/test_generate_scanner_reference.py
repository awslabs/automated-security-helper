"""scripts/generate_scanner_reference.py: the summary table's Tier and loading columns.

A scanner's manifest (``automated_security_helper.plugin_manifests``) declares both
facts the summary table shows beside ``On once loaded``, the scanner's ``enabled``
default:

* ``Tier`` is the manifest's maturity tier;
* ``Loads by default`` is the manifest's ``default_enabled``, so an alpha scanner
  reads "no" there while ``On once loaded`` still reads "yes" for it;
* a scanner with no manifest reads "not determined" in both, never a guessed "no".

The committed page is held to the same manifests row by row, so a page edited by
hand, or left stale by a manifest change, fails here as well as in the freshness
test.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper import plugin_manifests
from automated_security_helper.base.plugin_manifest import PluginTier
from automated_security_helper.plugin_manifests import manifest_for, scanner_manifests

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS_DIR = REPO_ROOT / "scripts"
PAGE = REPO_ROOT / "docs" / "content" / "reference" / "scanners.md"


@pytest.fixture
def generator(script_loader, monkeypatch):
    # The generator imports its sibling modules by bare name, from scripts/.
    monkeypatch.syspath_prepend(str(SCRIPTS_DIR))
    return script_loader("generate_scanner_reference")


@pytest.fixture(scope="module")
def page() -> str:
    return PAGE.read_text(encoding="utf-8")


def _loads(manifest) -> str:
    return "yes" if manifest.default_enabled else "no"


def _manifest_cells(generator, name: str) -> tuple[str, str]:
    return generator._manifest_cells(SimpleNamespace(name=name))


def _cells(row: str) -> list[str]:
    """One table row's cells; a pipe inside a code span does not split."""
    cells, current, in_code = [], "", False
    for char in row.strip().strip("|"):
        if char == "`":
            in_code = not in_code
        if char == "|" and not in_code:
            cells.append(current.strip())
            current = ""
        else:
            current += char
    cells.append(current.strip())
    return cells


def _summary(text: str) -> tuple[list[str], list[dict[str, str]]]:
    """The summary table's header cells, and its rows keyed by them."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("| Scanner |"))
    header = _cells(lines[start])
    rows = []
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        rows.append(dict(zip(header, _cells(line))))
    return header, rows


def _scanner_name(row: dict[str, str]) -> str:
    match = re.match(r"\[`([a-z0-9-]+)`\]", row["Scanner"])
    assert match, f"a summary row whose first cell names no scanner: {row}"
    return match.group(1)


def _enabled_lines(text: str) -> dict[str, str]:
    """Scanner -> what its section's "Enabled by default" line says."""
    found: dict[str, str] = {}
    name = None
    for line in text.splitlines():
        heading = re.match(r"^## `([^`]+)`$", line)
        if heading:
            name = heading.group(1)
        elif name and line.startswith("- Enabled by default: "):
            found[name] = line.removeprefix("- Enabled by default: ")
    return found


class TestManifestCells:
    @pytest.mark.parametrize("manifest", scanner_manifests(), ids=lambda m: m.name)
    def test_a_scanner_reads_its_tier_and_loading_from_its_manifest(
        self, generator, manifest
    ):
        assert _manifest_cells(generator, manifest.name) == (
            manifest.tier.value,
            _loads(manifest),
        )

    def test_an_alpha_scanner_reads_no_under_loads_by_default(self, generator):
        alpha = [m.name for m in scanner_manifests() if m.tier is PluginTier.ALPHA]
        assert alpha, "no alpha scanner has a manifest, so this checks nothing"
        for name in alpha:
            assert _manifest_cells(generator, name) == ("alpha", "no"), name

    def test_a_scanner_that_loads_by_default_reads_yes(self, generator):
        loading = [m.name for m in scanner_manifests() if m.default_enabled]
        assert loading, "no manifest loads by default, so this checks nothing"
        for name in loading:
            assert _manifest_cells(generator, name)[1] == "yes", name

    @pytest.mark.parametrize("tier", list(PluginTier), ids=lambda tier: tier.value)
    @pytest.mark.parametrize("loads", [True, False], ids=["loads", "opt-in"])
    def test_tier_and_loading_are_separate_facts(
        self, generator, monkeypatch, tier, loads
    ):
        """A manifest declares maturity and loading apart: a deprecated scanner can
        load by default and a supported one can need its module named."""
        manifest = SimpleNamespace(tier=tier, default_enabled=loads)
        monkeypatch.setattr(plugin_manifests, "manifest_for", lambda name: manifest)
        assert _manifest_cells(generator, "any-name") == (
            tier.value,
            "yes" if loads else "no",
        )

    def test_a_scanner_with_no_manifest_reads_not_determined(self, generator):
        assert manifest_for("no-such-scanner") is None
        assert _manifest_cells(generator, "no-such-scanner") == (
            "not determined",
            "not determined",
        )


class TestCommittedSummary:
    def test_the_header_gains_tier_and_loads_by_default(self, page):
        header, _rows = _summary(page)
        assert header[0] == "Scanner", header
        for column in ("Tier", "Loads by default", "On once loaded"):
            assert column in header, f"the summary has no {column!r} column: {header}"

    def test_the_old_header_is_gone(self, page):
        header, _rows = _summary(page)
        assert "Enabled by default" not in header, header

    def test_every_row_equals_its_manifest(self, page):
        header, rows = _summary(page)
        assert {"Tier", "Loads by default"} <= set(header), header
        assert len(rows) == len(scanner_manifests()) > 0
        for row in rows:
            name = _scanner_name(row)
            manifest = manifest_for(name)
            assert manifest is not None, f"{name} has a row and no manifest"
            assert row["Tier"] == manifest.tier.value, name
            assert row["Loads by default"] == _loads(manifest), name

    def test_an_alpha_module_row_reads_no_and_a_built_in_row_reads_yes(self, page):
        header, rows = _summary(page)
        assert "Loads by default" in header, header
        alpha = [r for r in rows if r["Provided by"].startswith("alpha module")]
        built_in = [r for r in rows if r["Provided by"] == "built in"]
        assert alpha and built_in, "the page has no alpha row or no built-in row"
        assert {r["Loads by default"] for r in alpha} == {"no"}
        assert {r["Loads by default"] for r in built_in} == {"yes"}

    def test_on_once_loaded_is_the_enabled_default_the_sections_state(self, page):
        header, rows = _summary(page)
        assert "On once loaded" in header, header
        stated = _enabled_lines(page)
        assert len(stated) == len(rows) > 0
        for row in rows:
            name = _scanner_name(row)
            assert row["On once loaded"] == stated[name], name
