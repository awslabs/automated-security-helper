"""The repository's own scan reads the docs site's code and data, not only its pages.

Why this exists
---------------
``.ash.yaml`` once ignored all of ``docs/`` to keep the documentation's
illustrative credential examples out of the secret scanners. ``ignore_paths``
applies to every scanner, so that also kept the browser test suite under
``docs/ui-tests`` (JavaScript and an npm lockfile), the site build hooks under
``docs/hooks`` and the theme templates out of every scan. The ignore now names
``docs/content/**``, where the pages are. This pins both halves: the pages stay
ignored, and the tooling beside them is scanned, so a widening back to
``docs/**`` reads red here.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from automated_security_helper.utils.suppression_matcher import ignore_path_matches

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
SELF_SCAN_CONFIG = REPO_ROOT / ".ash.yaml"

#: Files beside the pages that every scanner of the default self-scan reads.
SCANNED = (
    "docs/ui-tests/package-lock.json",
    "docs/ui-tests/specs/site.spec.cjs",
    "docs/hooks/redirects.py",
    "docs/overrides/main.html",
)
#: Pages whose examples the ignore keeps out of the secret scanners.
IGNORED = (
    "docs/content/getting-started/platform-teams.md",
    "docs/content/reference/coverage.md",
)


def _ignore_patterns() -> list[str]:
    document = yaml.safe_load(SELF_SCAN_CONFIG.read_text(encoding="utf-8"))
    return [entry["path"] for entry in document["global_settings"]["ignore_paths"]]


@pytest.mark.parametrize("path", SCANNED)
def test_the_docs_tooling_is_scanned(path):
    assert (REPO_ROOT / path).is_file(), f"{path} moved: update this pin"
    matching = [p for p in _ignore_patterns() if ignore_path_matches(path, p)]
    assert matching == [], f"{path} is ignored by {matching}"


@pytest.mark.parametrize("path", IGNORED)
def test_the_documentation_pages_are_ignored(path):
    assert (REPO_ROOT / path).is_file(), f"{path} moved: update this pin"
    assert any(ignore_path_matches(path, p) for p in _ignore_patterns()), (
        f"{path} matches no ignore_paths entry of {SELF_SCAN_CONFIG.name}"
    )


def test_the_matcher_tells_the_two_spellings_apart():
    """Control: the old spelling reaches the tooling, the new one does not."""
    assert ignore_path_matches("docs/ui-tests/package-lock.json", "docs/**")
    assert not ignore_path_matches("docs/ui-tests/package-lock.json", "docs/content/**")
    assert ignore_path_matches("docs/content/reference/coverage.md", "docs/content/**")
