# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash://status`` and ``ash://help`` name the scanners ASH actually has.

Why this file exists
--------------------
Both resources were static text naming five scanners: Bandit, Semgrep,
detect-secrets, Checkov and cdk-nag. ASH's default configuration enables ten
built-in scanners, so an agent reading either resource to learn what a scan
covers was told about half of them, and nothing tied the text to the code.

The expected names are read from the default configuration's ``scanners``
section, which is where a scan decides what to run, not from the helper the
resources use, so a fault in that helper cannot make both sides agree.
"""

from __future__ import annotations

from typing import List

import pytest

from automated_security_helper.cli.mcp_server import mcp


def _default_scanner_names() -> List[str]:
    from automated_security_helper.config.ash_config import AshConfig

    scanners = AshConfig().model_dump(by_alias=True)["scanners"]
    return sorted(
        name
        for name, cfg in scanners.items()
        if isinstance(cfg, dict) and cfg.get("enabled", True)
    )


async def _text(uri: str) -> str:
    parts = await mcp.read_resource(uri)
    return "\n".join(str(part.content) for part in parts)


def test_the_oracle_is_not_empty():
    """Control: the comparison below is over a real set, not over nothing."""
    names = _default_scanner_names()
    assert len(names) >= 10, names
    assert "bandit" in names and "grype" in names


@pytest.mark.asyncio
@pytest.mark.parametrize("uri", ["ash://status", "ash://help"])
async def test_every_default_scanner_is_named(uri):
    text = (await _text(uri)).lower()

    missing = [name for name in _default_scanner_names() if name not in text]
    assert not missing, f"{uri} does not name these default scanners: {missing}\n{text}"


@pytest.mark.asyncio
@pytest.mark.parametrize("uri", ["ash://status", "ash://help"])
async def test_a_scanner_the_operator_disabled_is_marked_disabled(
    uri, tmp_path, monkeypatch
):
    """Read from the operator's config (ASH_CONFIG), not from the built-in default.

    Every scanner is enabled by default, so a resource that printed every one as
    enabled whatever the config said passed the test above.
    """
    config = tmp_path / "operator.yaml"
    config.write_text(
        "project_name: operator\nscanners:\n  grype:\n    enabled: false\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(config))

    lines = (await _text(uri)).splitlines()

    assert "• grype (disabled in the config)" in lines, lines
    assert "• bandit" in lines, lines


@pytest.mark.asyncio
async def test_status_points_at_list_scanners_for_installation_state():
    """The resource lists names only; whether each tool is installed is a probe.

    ``list_scanners`` runs each scanner's dependency check and version probe,
    which takes seconds; a resource an agent reads first must not, so the status
    text says where that answer is instead of guessing it.
    """
    text = await _text("ash://status")

    assert "list_scanners" in text
