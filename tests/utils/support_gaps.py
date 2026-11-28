"""Where a scanner tool that ASH downloads may have no build, declared once.

``support_register.no_build_rows`` derives one missing-build row for each platform that
a downloaded tool's own platform declaration leaves out. Three tests read that
declaration through this module: the two that hold the derived rows
(tests/unit/base/test_support_register.py and
tests/unit/base/test_support_configurations.py) and the one that ties the supported
configurations page to them
(tests/unit/docs/test_supported_configurations_page_claims.py).

A check that compares the derived rows with the declaration they come from agrees with
every declaration, including one that lost a platform by mistake. The platforms below
are what the declaration is held to instead.
"""

from __future__ import annotations

from collections.abc import Iterable

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base import support_register as sr
from automated_security_helper.utils import tool_downloads

#: The platforms a downloaded tool may have no build for. A platform that drops out of
#: a declaration by a typo, or because upstream stops shipping it, would otherwise turn
#: up as a missing-build row for a machine people use, and every test that compares the
#: rows with the declaration they came from would stay green. Add a platform here only
#: when upstream ships no build for it and the supported configurations page says so.
ALLOWED_GAP_PLATFORMS: frozenset[str] = frozenset({"windows/arm64"})

#: What a test says when a derived row is about a platform outside the allowed ones.
UNALLOWED_GAP = (
    "a scanner declares no build for a platform outside ALLOWED_GAP_PLATFORMS "
    "(tests/utils/support_gaps.py): fix the scanner's platform declaration, or add the "
    "platform there together with the page sentence that says so"
)


def all_platforms_but(platform: str) -> tuple[str, ...]:
    """Every platform ASH downloads tools for except ``platform``: what a tool that
    lacks only that build declares."""
    return tuple(pair for pair in sr.ALL_PLATFORMS if pair != platform)


def pinned_binaries(classes: Iterable[type]) -> list[sr.PinnedBinary]:
    """One record per scanner in ``classes`` whose tool ASH downloads, from the
    scanner's own facets and the download table the consistency test binds together."""
    found = []
    for cls in classes:
        facets: opsf.ScannerOperationalFacets = vars(cls)[opsf.OPERATIONAL_FACETS_ATTR]
        if facets.runtime.kind is not opsf.RuntimeKind.PINNED_BINARY:
            continue
        key = facets.runtime.tool_versions_key
        if key is None:
            raise ValueError(f"{facets.scanner_name} has no tool versions key")
        found.append(
            sr.PinnedBinary(
                scanner=facets.scanner_name,
                tool=key,
                version=tool_downloads.TOOL_VERSIONS[key],
                provisionable=facets.platforms.provisionable,
            )
        )
    return sorted(found, key=lambda binary: binary.scanner)


def gap_platform(row: sr.SupportRow) -> str:
    """The ``os/arch`` pair a derived missing-build row is about."""
    (os_token,) = row.match.os
    (arch,) = row.match.arch
    return f"{os_token}/{arch}"


def unallowed_gap_rows(rows: Iterable[sr.SupportRow]) -> list[str]:
    """The ids of the derived missing-build rows about a platform that may not lack a
    build."""
    return sorted(
        row.id for row in rows if gap_platform(row) not in ALLOWED_GAP_PLATFORMS
    )
