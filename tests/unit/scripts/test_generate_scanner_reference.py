"""scripts/generate_scanner_reference.py: the summary table's Tier and loading columns.

A scanner's manifest (``automated_security_helper.plugin_manifests``) declares both
facts the summary table shows beside ``On once loaded``, the scanner's ``enabled``
default:

* ``Tier`` is the manifest's maturity tier;
* ``Loads by default`` is the manifest's ``default_enabled``, so an alpha scanner
  reads "no" there while ``On once loaded`` still reads "yes" for it;
* a scanner with no manifest is refused by name: its tier and loading are facts of
  the manifest, so the page never prints "not determined" or a guessed "no" for them;
* each scanner's own section states the same three facts as its summary row, and no
  section still calls the enabled default "Enabled by default".

The committed page is held to the same manifests row by row, so a page edited by
hand, or left stale by a manifest change, fails here as well as in the freshness
test.
"""

from __future__ import annotations

import functools
import importlib.util
import re
from enum import Enum
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
FRESHNESS = REPO_ROOT / "tests" / "unit" / "test_generated_docs_freshness.py"


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


@functools.lru_cache(maxsize=1)
def _freshness_cells():
    """``_cells`` of the freshness module, which splits on pipes outside code spans
    and escapes. It is loaded by path: tests/unit is not a package."""
    spec = importlib.util.spec_from_file_location("_ash_freshness_cells", FRESHNESS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._cells


def _summary(text: str) -> tuple[list[str], list[dict[str, str]]]:
    """The summary table's header cells, and its rows keyed by them."""
    cells_of = _freshness_cells()
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("| Scanner |"))
    header = cells_of(lines[start])
    rows = []
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        cells = cells_of(line)
        assert len(cells) == len(header), (
            f"{len(cells)} cells under {len(header)} headings: {line}"
        )
        rows.append(dict(zip(header, cells)))
    return header, rows


def _scanner_name(row: dict[str, str]) -> str:
    match = re.match(r"\[`([a-z0-9-]+)`\]", row["Scanner"])
    assert match, f"a summary row whose first cell names no scanner: {row}"
    return match.group(1)


def _section_lines(text: str) -> dict[str, dict[str, str]]:
    """Scanner -> the "- Label: value" lines of its section, by label."""
    found: dict[str, dict[str, str]] = {}
    name = None
    for line in text.splitlines():
        heading = re.match(r"^## `([^`]+)`$", line)
        if heading:
            name = heading.group(1)
            found[name] = {}
        elif name and (bullet := re.match(r"^- ([^:]+): (.*)$", line)):
            found[name][bullet.group(1)] = bullet.group(2)
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

    def test_a_scanner_with_no_manifest_is_refused_by_name(self, generator):
        assert manifest_for("no-such-scanner") is None
        with pytest.raises(SystemExit, match="no-such-scanner"):
            _manifest_cells(generator, "no-such-scanner")


class TestTierList:
    @pytest.mark.parametrize(
        "values,expected",
        [
            (("a",), "`a`"),
            (("a", "b"), "`a` or `b`"),
            (("a", "b", "c"), "`a`, `b` or `c`"),
            (("a", "b", "c", "d"), "`a`, `b`, `c` or `d`"),
        ],
        ids=["one", "two", "three", "four"],
    )
    def test_the_list_is_built_from_the_members(self, generator, values, expected):
        planted = Enum("Planted", {value: value for value in values})
        assert generator._tier_list(planted) == expected


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

    def test_every_section_states_what_its_summary_row_states(self, page):
        header, rows = _summary(page)
        assert {"Tier", "Loads by default", "On once loaded"} <= set(header), header
        sections = _section_lines(page)
        assert len(sections) == len(rows) > 0
        for row in rows:
            name = _scanner_name(row)
            for label in ("Tier", "Loads by default", "On once loaded"):
                assert sections[name].get(label) == row[label], f"{name}: {label}"

    def test_an_alpha_scanners_section_reads_no_under_loads_by_default(self, page):
        _header, rows = _summary(page)
        sections = _section_lines(page)
        alpha = [r for r in rows if r["Provided by"].startswith("alpha module")]
        assert alpha, "the page has no alpha row, so this checks nothing"
        for row in alpha:
            name = _scanner_name(row)
            assert sections[name].get("Loads by default") == "no", name

    def test_no_section_calls_the_enabled_default_enabled_by_default(self, page):
        sections = _section_lines(page)
        assert sections, "the page has no scanner section, so this checks nothing"
        said = sorted(
            name for name, lines in sections.items() if "Enabled by default" in lines
        )
        assert not said, said

    def test_the_paragraph_under_the_table_names_every_tier(self, page, generator):
        assert generator._tier_list(PluginTier) in page
