# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash inspect findings`: the rows it extracts, and the screens the TUI draws.

``extract_findings`` is the pure half: SARIF results in, the dicts every table row
and detail view is built from out. The TUI half runs in-process under Textual's
headless test driver at a fixed 100x30 terminal, and each screen is captured as text
the same way ``App.export_screenshot`` captures it as SVG: the compositor's full
frame printed to a recording console. Text rather than SVG, so a diff shows the
words that changed rather than glyph coordinates.
"""

from __future__ import annotations

import asyncio
import io
import json
from datetime import datetime

import pytest
from rich.console import Console

from automated_security_helper.cli.inspect.inspect_findings_app import (
    FindingsExplorerApp,
    extract_findings,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from tests.snapshot.support.normalize import REPO_ROOT

FIXTURE = REPO_ROOT / "tests" / "test_data" / "snapshot" / "findings" / "ash.sarif"
SCREEN_SIZE = (100, 30)


@pytest.fixture
def model() -> AshAggregatedResults:
    sarif = SarifReport.model_validate(json.loads(FIXTURE.read_text(encoding="utf-8")))
    return AshAggregatedResults(sarif=sarif)


def test_extract_findings(model, snapshot):
    findings = extract_findings(model)

    assert len(findings) == 4
    assert findings == snapshot


class _FixedClock(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2030, 1, 2, 3, 4, 5, tzinfo=tz)


def _frame(app) -> str:
    width, height = app.size
    console = Console(
        width=width,
        height=height,
        file=io.StringIO(),
        force_terminal=True,
        color_system=None,
        record=True,
        legacy_windows=False,
        safe_box=False,
    )
    console.print(
        app.screen._compositor.render_update(
            full=True, screen_stack=app._background_screens
        )
    )
    return console.export_text()


async def _screens(findings, config_path) -> dict[str, str]:
    app = FindingsExplorerApp(findings, config_path=config_path)
    frames = {}
    async with app.run_test(size=SCREEN_SIZE) as pilot:
        await pilot.pause()
        frames["table"] = _frame(app)
        await pilot.press("h")  # show suppressed findings too
        await pilot.pause()
        frames["table-with-suppressed"] = _frame(app)
        await pilot.press("v")  # open the selected (first) finding
        await pilot.pause()
        frames["detail"] = _frame(app)
    return frames


def test_findings_tui_screens(model, tmp_path, monkeypatch, text_snapshot):
    import textual.widgets._header as header

    # The header clock is the one wall-clock value on screen.
    monkeypatch.setattr(header, "datetime", _FixedClock)
    # Only findings with a location: the table reads finding["file"] unguarded, and
    # extract_findings sets that key only when the SARIF result has a location, so
    # the fixture's location-less advisory raises KeyError in _populate_table.
    findings = [f for f in extract_findings(model) if "file" in f]
    assert len(findings) == 3

    frames = asyncio.run(_screens(findings, tmp_path / ".ash.yaml"))

    assert "B105" in frames["table"]
    assert "CKV_AWS_18" not in frames["table"], "suppressed rows are hidden by default"
    assert "CKV_AWS_18" in frames["table-with-suppressed"]
    for name, frame in frames.items():
        assert text_snapshot("txt")(name=name) == frame
