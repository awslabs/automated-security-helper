"""``ash plugin verify`` refuses a row whose results it cannot classify.

The promotion bar reads a plugin's operational row, and two shapes of its
``targets`` leave the plugin's results without a scan category: a row that names no
category (``tool_type`` UNKNOWN and no ``categories``), and a row that names several
on a plugin with no ``classify_result`` to say which one each result belongs to.
Each is refused with one problem, on a red row, that names the plugin. The same
two-category row on a plugin that does define ``classify_result`` raises neither
problem, and the fixture plugin as shipped, whose row derives its one category from
``tool_type``, raises neither (the control).

The bar is driven as the CLI drives it: ``verify_plugin`` with the fixture plugin's
manifest, a private copy of its transcripts, no pins and no tool-type override. The
fixture plugin is imported fresh in every test, and its row is replaced with
``monkeypatch.setattr`` by a ``model_copy`` of the shipped row, which runs no
validator, so the replacement records nothing by name and warns nothing.
"""

import importlib
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.core import enums
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.core.plugin_conformance import (
    BarReport,
    RowStatus,
    verify_plugin,
)

pytestmark = pytest.mark.unit

#: The conformance fixture plugin's directory: its package and its transcripts.
FIXTURE_PLUGIN = (
    Path(__file__).resolve().parents[1] / "plugin_conformance" / "fixture_plugin"
)

#: The stable parts of the two refusals.
NO_CATEGORY = "its operational row names no scan category"
NO_CLASSIFIER = "does not override classify_result"


class FixturePlugin(NamedTuple):
    """The fixture plugin as one test imported it."""

    manifest: Any
    scanner: Any


def _fixture_plugin_modules() -> list[str]:
    return [name for name in sys.modules if name.split(".")[0] == "ash_fixture_plugin"]


@pytest.fixture
def fixture_plugin(monkeypatch: pytest.MonkeyPatch) -> Iterator[FixturePlugin]:
    """The fixture plugin's manifest and scanner class, imported fresh for the test
    only, the way tests/unit/plugin_conformance/conftest.py imports them."""
    monkeypatch.syspath_prepend(str(FIXTURE_PLUGIN))
    for name in _fixture_plugin_modules():
        monkeypatch.delitem(sys.modules, name)
    manifest = importlib.import_module("ash_fixture_plugin.manifest").MANIFEST
    scanner = importlib.import_module("ash_fixture_plugin.scanner").FixtureScanner
    yield FixturePlugin(manifest=manifest, scanner=scanner)
    for name in _fixture_plugin_modules():
        sys.modules.pop(name, None)


@pytest.fixture
def transcripts(tmp_path: Path) -> Path:
    """A private copy of the fixture plugin's transcripts, laid out as the bar reads
    them."""
    shutil.copytree(FIXTURE_PLUGIN / "transcripts", tmp_path / "scanners" / "fixture")
    return tmp_path / "scanners"


def _verify(plugin: FixturePlugin, transcripts: Path) -> BarReport:
    """The bar as ``ash plugin verify`` runs it: no pins, no tool-type override."""
    return verify_plugin(plugin.manifest, transcripts, pins={})


def _problems(report: BarReport) -> list[tuple[int, RowStatus, str]]:
    """Every problem the report states, with the number and status of its row."""
    return [
        (row.number, row.status, detail)
        for row in report.rows
        for detail in row.details
    ]


def _naming(report: BarReport, phrase: str) -> list[tuple[int, RowStatus, str]]:
    return [problem for problem in _problems(report) if phrase in problem[2]]


def _scan_category() -> Any:
    found = getattr(enums, "ScanCategory", None)
    assert found is not None, "automated_security_helper.core.enums has no ScanCategory"
    return found


def _with_targets(
    plugin: FixturePlugin, targets: opsf.TargetsFacet, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Replace the fixture plugin's row with a copy whose ``targets`` is *targets*."""
    row = plugin.scanner.operational_facets.model_copy(update={"targets": targets})
    monkeypatch.setattr(plugin.scanner, "operational_facets", row)


def _two_categories(category: Any) -> opsf.TargetsFacet:
    """A targets facet over two categories, each served by a kind it scans: source
    code for ``sast`` and file contents for ``secrets``."""
    return opsf.TargetsFacet(
        kinds=(opsf.TargetKind.SOURCE_CODE, opsf.TargetKind.SECRETS_CONTENTS),
        tool_type=ScannerToolType.SAST,
        categories=(category.SAST, category.SECRETS),
        selection="every python file in the scan set",
    )


def _classify_result(self: Any, result: Any) -> frozenset[Any]:
    """A plugin's own answer to which categories one of its results belongs to."""
    return frozenset()


def test_the_fixture_plugin_as_shipped_passes_the_category_checks(
    fixture_plugin: FixturePlugin, transcripts: Path
) -> None:
    """Control, at the base and at the tip: the shipped row names one category
    (derived from ``tool_type`` SAST), so no problem names scan categories or
    ``classify_result``, and the bar does not fail."""
    report = _verify(fixture_plugin, transcripts)

    about_categories = [
        problem
        for problem in _problems(report)
        if "scan categor" in problem[2] or "classify_result" in problem[2]
    ]
    assert about_categories == [], about_categories
    assert report.verdict != "fail", _problems(report)


def test_a_row_that_derives_no_category_is_refused(
    fixture_plugin: FixturePlugin, transcripts: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``tool_type`` UNKNOWN and no ``categories``: the row derives no category, so
    the plugin's results would meet a category scope as ``other``. The bar refuses
    the row with one problem, on a red row, that names the plugin."""
    _with_targets(
        fixture_plugin,
        opsf.TargetsFacet(
            kinds=(opsf.TargetKind.SOURCE_CODE,),
            tool_type=ScannerToolType.UNKNOWN,
            selection="every python file in the scan set",
        ),
        monkeypatch,
    )

    report = _verify(fixture_plugin, transcripts)

    refused = _naming(report, NO_CATEGORY)
    assert len(refused) == 1, (
        f"expected one problem naming {NO_CATEGORY!r}: {_problems(report)}"
    )
    _, status, detail = refused[0]
    assert status is RowStatus.RED, refused
    assert "fixture-lint" in detail, detail


def test_a_two_category_row_without_a_classifier_is_refused(
    fixture_plugin: FixturePlugin, transcripts: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``categories`` (sast, secrets) on a plugin that defines no ``classify_result``:
    nothing says which of the two a result belongs to, so the bar refuses the row
    with one problem, on a red row, that names the plugin and both categories."""
    category = _scan_category()
    _with_targets(fixture_plugin, _two_categories(category), monkeypatch)

    report = _verify(fixture_plugin, transcripts)

    refused = _naming(report, NO_CLASSIFIER)
    assert len(refused) == 1, (
        f"expected one problem naming {NO_CLASSIFIER!r}: {_problems(report)}"
    )
    _, status, detail = refused[0]
    assert status is RowStatus.RED, refused
    assert "fixture-lint" in detail, detail
    assert "sast" in detail and "secrets" in detail, detail
    assert _naming(report, NO_CATEGORY) == [], _problems(report)


def test_a_two_category_row_with_a_classifier_passes(
    fixture_plugin: FixturePlugin, transcripts: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same two-category row on a plugin that defines ``classify_result``: the
    plugin says which category each result belongs to, so the bar raises neither
    category problem. The row is first verified without the method and refused, so
    the pass cannot come from a check that does not run."""
    category = _scan_category()
    _with_targets(fixture_plugin, _two_categories(category), monkeypatch)
    before = _verify(fixture_plugin, transcripts)
    assert _naming(before, NO_CLASSIFIER), _problems(before)

    monkeypatch.setattr(
        fixture_plugin.scanner, "classify_result", _classify_result, raising=False
    )
    report = _verify(fixture_plugin, transcripts)

    assert _naming(report, NO_CLASSIFIER) == [], _problems(report)
    assert _naming(report, NO_CATEGORY) == [], _problems(report)
