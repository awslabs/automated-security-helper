# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ashx inspect findings`: the rows it extracts, and the screens the TUI draws.

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


#: Pauses to wait for a screen's footer before giving up. Each is one trip through the
#: app's message queue; a footer normally draws within two.
_SETTLE_PAUSES = 200


async def _settle(pilot, app) -> None:
    """Pause until the active screen's footer has drawn its key bindings.

    Textual's ``Footer`` composes its keys only after the screen publishes its
    bindings, from a ``call_after_refresh`` -- a later turn of the event loop than the
    one ``pilot.pause()`` waits for. On windows-latest under Python 3.10 the first
    frame was captured before that turn, ending at the status line with no footer.
    Waiting for the keys to exist, then for one more refresh to draw them, makes the
    capture independent of how fast the runner is. Bounded, so a footer that never
    draws fails here instead of hanging the suite.
    """
    from textual.widgets import Footer
    from textual.widgets._footer import FooterKey

    for _ in range(_SETTLE_PAUSES):
        await pilot.pause()
        footers = list(app.screen.query(Footer))
        if footers and all(list(footer.query(FooterKey)) for footer in footers):
            await pilot.pause()
            return
    raise AssertionError(
        f"the footer had drawn no key bindings after {_SETTLE_PAUSES} pauses"
    )


async def _screens(findings, config_path) -> dict[str, str]:
    app = FindingsExplorerApp(findings, config_path=config_path)
    frames = {}
    async with app.run_test(size=SCREEN_SIZE) as pilot:
        await _settle(pilot, app)
        frames["table"] = _frame(app)
        await pilot.press("h")  # show suppressed findings too
        await _settle(pilot, app)
        frames["table-with-suppressed"] = _frame(app)
        await pilot.press("v")  # open the selected (first) finding
        await _settle(pilot, app)
        frames["detail"] = _frame(app)
        await pilot.press("escape")  # back to the table
        await _settle(pilot, app)
        # Rows are sorted by severity, so the info-level advisory, the one finding
        # with no location, is the last of the four.
        await pilot.press("j", "j", "j")
        await _settle(pilot, app)
        await pilot.press("v")
        await _settle(pilot, app)
        frames["detail-no-location"] = _frame(app)
    return frames


def test_findings_tui_screens(model, tmp_path, monkeypatch, text_snapshot):
    import textual.widgets._header as header

    # The header clock is the one wall-clock value on screen.
    monkeypatch.setattr(header, "datetime", _FixedClock)
    # Every fixture finding, including the advisory with no location: extract_findings
    # sets no "file" or "line" key for it, and the table and detail screen draw it.
    findings = extract_findings(model)
    assert len(findings) == 4

    frames = asyncio.run(_screens(findings, tmp_path / ".ash.yaml"))

    assert "B105" in frames["table"]
    assert "GHSA-0000-fixture" in frames["table"]
    assert "CKV_AWS_18" not in frames["table"], "suppressed rows are hidden by default"
    assert "CKV_AWS_18" in frames["table-with-suppressed"]
    assert "GHSA-0000-fixture" in frames["detail-no-location"]
    for name, frame in frames.items():
        assert text_snapshot("txt")(name=name) == frame
