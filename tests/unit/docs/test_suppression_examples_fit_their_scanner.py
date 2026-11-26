# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin page's suppression examples can match the findings its scanner reports.

Why this exists
---------------
A suppression with ``line_start`` or ``line_end`` never matches a finding that has no
line (``utils/suppression_frame.py``, ``_line_ok``), and a scanner whose results carry
no region reports every finding that way. The OSV-Scanner page showed such an entry as
its suppression example, so the entry a reader copied from it suppressed nothing, and
nothing said so: an entry that matches no finding reads the same in a config as one
that works.

What this checks
----------------
For every scanner whose facets register row says ``line_range`` is n/a, no page its
manifest owns shows a suppression with a line range. The examples are the entries of
every ``suppressions`` list in the page's fenced ``yaml`` blocks; a block that names
``suppressions`` and does not parse fails the test rather than being skipped. The
pages are the ones the manifest lists in ``file_ownership``, which today only the alpha
manifests fill, so a builtin scanner's page is not reached here.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from automated_security_helper.base.scanner_facets import (
    SCANNER_FACETS_ATTR,
    FacetState,
)
from automated_security_helper.plugin_manifests import scanner_manifests
from tests.unit.docs.test_page_claims import assert_on_page
from tests.utils.scanner_enumeration import load_scanner_universe

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
_YAML_FENCE = re.compile(r"^```ya?ml[^\n]*\n(.*?)^```[ \t]*$", re.MULTILINE | re.DOTALL)
_LINE_KEYS = ("line_start", "line_end")

SCANNER_CLASSES, _LOAD_ERRORS = load_scanner_universe()


def _suppression_entries(data: Any) -> list[dict]:
    """The entries of every ``suppressions`` list anywhere in ``data``."""
    if isinstance(data, dict):
        entries: list[dict] = []
        for key, value in data.items():
            if key == "suppressions" and isinstance(value, list):
                entries += [entry for entry in value if isinstance(entry, dict)]
            else:
                entries += _suppression_entries(value)
        return entries
    if isinstance(data, list):
        return [entry for item in data for entry in _suppression_entries(item)]
    return []


def line_ranged_examples(markdown: str) -> list[dict]:
    """The suppression examples in ``markdown``'s yaml blocks that carry a line range."""
    found: list[dict] = []
    for block in _YAML_FENCE.findall(markdown):
        if "suppressions" not in block:
            continue
        for entry in _suppression_entries(yaml.safe_load(block)):
            if any(key in entry for key in _LINE_KEYS):
                found.append(entry)
    return found


def _scanner_classes_by_entry_point() -> dict[str, type]:
    return {f"{cls.__module__}:{cls.__qualname__}": cls for cls in SCANNER_CLASSES}


def _pages_of_scanners_without_a_line() -> list[tuple[str, str]]:
    """(scanner, page) for each page a scanner that reports no line owns."""
    classes = _scanner_classes_by_entry_point()
    pages: list[tuple[str, str]] = []
    for manifest in scanner_manifests():
        scanner = classes.get(manifest.entry_points.scanner)
        facets = vars(scanner).get(SCANNER_FACETS_ATTR) if scanner is not None else None
        if facets is None or facets.line_range.state is not FacetState.NA:
            continue
        pages += [
            (manifest.name, path)
            for path in manifest.file_ownership
            if path.startswith("docs/") and path.endswith(".md")
        ]
    return pages


_PAGES = _pages_of_scanners_without_a_line()


def test_the_population_is_not_vacuous() -> None:
    """Planted controls: the enumeration is whole and reaches the known scanners."""
    assert not _LOAD_ERRORS, f"plugin groups failed to import: {_LOAD_ERRORS}"
    classes = _scanner_classes_by_entry_point()
    unloaded = sorted(
        manifest.name
        for manifest in scanner_manifests()
        if any(p.startswith("docs/") for p in manifest.file_ownership)
        and manifest.entry_points.scanner not in classes
    )
    assert unloaded == [], (
        f"manifests name scanners the enumeration did not load: {unloaded}"
    )
    assert (
        "osv-scanner",
        "docs/content/docs/plugins/alpha/osv-scanner-plugin.md",
    ) in _PAGES
    assert (
        "dependency-check",
        "docs/content/docs/plugins/alpha/dependency_check-plugin.md",
    ) in _PAGES


@pytest.mark.parametrize(
    ("scanner", "page"), _PAGES, ids=[f"{name}-{Path(p).stem}" for name, p in _PAGES]
)
def test_a_page_shows_no_line_range_for_a_scanner_that_reports_no_line(
    scanner: str, page: str
) -> None:
    examples = line_ranged_examples((REPO_ROOT / page).read_text(encoding="utf-8"))
    assert examples == [], (
        f"{page}: {scanner} reports findings with no line, so these suppression "
        f"examples never match one; drop line_start and line_end: {examples}"
    )


def test_the_dependency_check_page_says_a_line_range_does_not_apply() -> None:
    assert_on_page(
        "docs/plugins/alpha/dependency_check-plugin.md",
        "ASH suppressions by rule and path work as for any scanner.",
    )
    assert_on_page(
        "docs/plugins/alpha/dependency_check-plugin.md",
        "A Dependency-Check finding names a dependency file and no line, so a "
        "suppression with `line_start` or `line_end` never matches one.",
    )


# Controls: the reader, fed pages whose verdict is known.

_LINE_RANGED = """\
Text.

```yaml
global_settings:
  suppressions:
    - rule_id: CVE-1
      path: a.lock
      line_start: 1
      line_end: 1
      reason: r
```
"""

_RULE_AND_PATH = """\
```yaml
global_settings:
  suppressions:
    - rule_id: CVE-1
      path: a.lock
      reason: r
```
"""


def test_the_reader_finds_a_line_ranged_example() -> None:
    assert line_ranged_examples(_LINE_RANGED) == [
        {
            "rule_id": "CVE-1",
            "path": "a.lock",
            "line_start": 1,
            "line_end": 1,
            "reason": "r",
        }
    ]


@pytest.mark.parametrize(
    "markdown",
    [
        _RULE_AND_PATH,
        _LINE_RANGED.replace("```yaml", "```text"),
        "```yaml\nscanners:\n  bandit:\n    line_start: 3\n```\n",
    ],
    ids=["rule and path only", "not a yaml block", "no suppressions list"],
)
def test_the_reader_passes_what_is_not_a_line_ranged_suppression(markdown: str) -> None:
    assert line_ranged_examples(markdown) == []


def test_a_suppression_block_that_does_not_parse_fails() -> None:
    with pytest.raises(yaml.YAMLError):
        line_ranged_examples("```yaml\nsuppressions: [\n```\n")
