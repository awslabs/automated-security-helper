# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The summary and minimal views of get_scan_results carry every coverage key
the results document has, ``could_not_stop`` included, and the set of those
keys is defined once.

The tool's docstring promises the coverage keys at every filter level, as
get_scan_progress reports them. The summary and minimal filters in
``result_filters`` splice ``_coverage_fields(results)`` themselves, so the
tool needs no wrapper of its own to carry them. A second tuple of the keys in
the tool module, six keys long, drifted from the filters' seven the day
``could_not_stop`` was added there; a reader of the tool module then had to
reconcile two lists to learn which keys a view carries. One definition, the
filters', is the one the tool relies on.
"""

from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_server
from automated_security_helper.core.resource_management import result_filters

#: In-process, the producer and the working directory patched: the unit tier.
pytestmark = pytest.mark.unit

#: Every coverage key of an incomplete scan, with a value a view must carry
#: through unchanged. ``could_not_stop`` is the key the tool module's own tuple
#: left out.
_COVERAGE_OF_AN_INCOMPLETE_SCAN: Dict[str, Any] = {
    "coverage_complete": False,
    "incomplete_scanners": ["semgrep"],
    "no_scanner_ran": False,
    "incomplete_converters": ["jupyter"],
    "unevaluated_rules": ["cfn-nag"],
    "stale_content_databases": ["grype"],
    "could_not_stop": ["bandit"],
}


def _results_of_an_incomplete_scan() -> Dict[str, Any]:
    """A results document in the producer's shape, for a scan that did not end
    cleanly, with every coverage key set."""
    return {
        "success": True,
        "scan_id": "scan-incomplete",
        "status": "incomplete",
        "is_complete": True,
        "completion_time": "2025-01-01T00:00:00Z",
        "summary_stats": {
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
            "info": 0,
            "suppressed": 0,
            "total": 1,
            "actionable": 1,
            "passed": 1,
            "failed": 1,
            "missing": 1,
            "skipped": 0,
        },
        "scanner_reports": {"bandit": {"findings": 1}},
        "raw_results": {
            "metadata": {
                "generated_at": "2025-01-01T00:00:00Z",
                "tool_version": "2.0.0",
                "summary_stats": {"duration": 1.5},
            },
            "scanner_results": {
                "bandit": {
                    "status": "FAILED",
                    "finding_count": 1,
                    "actionable_finding_count": 1,
                    "suppressed_finding_count": 0,
                    "duration": 1.5,
                    "severity_counts": {
                        "critical": 0,
                        "high": 1,
                        "medium": 0,
                        "low": 0,
                        "info": 0,
                        "suppressed": 0,
                        "total": 1,
                        "actionable": 1,
                    },
                },
                "semgrep": {
                    "status": "MISSING",
                    "finding_count": 0,
                    "actionable_finding_count": 0,
                    "suppressed_finding_count": 0,
                    "duration": 0.0,
                },
            },
        },
        **_COVERAGE_OF_AN_INCOMPLETE_SCAN,
    }


@pytest.fixture
def ctx() -> MagicMock:
    """A stand-in for the MCP context, with the async logging methods the tool
    calls."""
    context = MagicMock()
    context.info = AsyncMock()
    context.error = AsyncMock()
    context.warning = AsyncMock()
    context.debug = AsyncMock()
    return context


async def _view(ctx: MagicMock, filter_level: str) -> Dict[str, Any]:
    """The tool's response at *filter_level* for the incomplete scan."""
    with (
        patch(
            "automated_security_helper.cli.mcp_server.mcp_get_scan_results",
            new_callable=AsyncMock,
            return_value=_results_of_an_incomplete_scan(),
        ),
        patch("pathlib.Path.cwd", return_value=Path("/workspace")),
    ):
        return await mcp_server.get_scan_results(
            ctx=ctx,
            output_dir="/workspace/.ash/ash_output",
            filter_level=filter_level,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("filter_level", ["summary", "minimal"])
async def test_the_view_carries_every_coverage_key_of_the_document(
    ctx: MagicMock, filter_level: str
) -> None:
    """Each of the seven coverage keys reaches the view with the document's
    value, could_not_stop among them, and the view still says the scan is
    incomplete."""
    view = await _view(ctx, filter_level)

    carried = {key: view.get(key) for key in _COVERAGE_OF_AN_INCOMPLETE_SCAN}
    assert carried == _COVERAGE_OF_AN_INCOMPLETE_SCAN
    assert view["status"] == "incomplete"


@pytest.mark.asyncio
@pytest.mark.parametrize("filter_level", ["summary", "minimal"])
async def test_a_view_of_a_complete_scan_says_so_and_names_no_gap(
    ctx: MagicMock, filter_level: str
) -> None:
    """A document whose coverage keys all read "nothing missing" produces a view
    that carries them as they are; no key is invented or dropped."""
    complete = {
        "coverage_complete": True,
        "incomplete_scanners": [],
        "no_scanner_ran": False,
        "incomplete_converters": [],
        "unevaluated_rules": [],
        "stale_content_databases": [],
        "could_not_stop": [],
    }
    results = {**_results_of_an_incomplete_scan(), **complete, "status": "completed"}
    with (
        patch(
            "automated_security_helper.cli.mcp_server.mcp_get_scan_results",
            new_callable=AsyncMock,
            return_value=results,
        ),
        patch("pathlib.Path.cwd", return_value=Path("/workspace")),
    ):
        view = await mcp_server.get_scan_results(
            ctx=ctx,
            output_dir="/workspace/.ash/ash_output",
            filter_level=filter_level,
        )

    assert {key: view.get(key) for key in complete} == complete
    assert view["status"] == "completed"


def test_the_coverage_keys_are_defined_once_in_the_filters() -> None:
    """The tool module keeps no list of the coverage keys of its own: the one
    the filters carry is the one every view uses, so a key added there reaches
    the summary and minimal views without a second edit."""
    own_tuple = getattr(mcp_server, "_COVERAGE_KEYS", None)
    assert own_tuple is None, (
        "the tool module carries its own coverage key tuple; the filters' "
        f"{result_filters._COVERAGE_KEYS} is the one definition"
    )
    assert not hasattr(mcp_server, "_with_coverage")
    assert "could_not_stop" in result_filters._COVERAGE_KEYS
    # This module's own fixture is a second list of the keys, which is the shape
    # the docstring blames for drift: an eighth key added to the filters would
    # leave the view tests above passing without checking it. Pinned equal, so
    # the fixture is corrected the day the filters grow.
    assert set(_COVERAGE_OF_AN_INCOMPLETE_SCAN) == set(result_filters._COVERAGE_KEYS)
