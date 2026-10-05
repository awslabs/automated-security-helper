# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The summary table a scan prints last, and the notices printed under it.

Driven through the real chain -- ``AshAggregatedResults`` -> ``get_unified_scanner_metrics``
-> ``generate_metrics_table_from_unified_data`` -- rather than with hand-built
``ScannerMetrics``, so a change in how a status, a threshold source or a duration is derived
shows up here as a change in what the operator reads. The unit tests in
tests/unit/core/test_metrics_table_rendering.py pin the branches; these pin the page.

Widths are 120 and 80, one either side of the 100-column cutoff where the headers abbreviate.

``display_metrics_table`` builds its own ``Console`` from ``platform.system()``: on Windows it
asks for the legacy renderer and safe box characters, and the help panel's title loses its
emoji. Both variants are rendered on every OS by patching ``platform.system`` inside the
module, and the ``Console`` it builds is wrapped only to pin the width and capture the output;
every keyword the module chose is passed through untouched.
"""

from __future__ import annotations

import pytest
from rich.console import Console

from automated_security_helper.core import metrics_table
from automated_security_helper.core.metrics_table import (
    display_metrics_table,
    generate_metrics_table_from_unified_data,
    print_coverage_shortfalls,
    print_stale_content_databases,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from tests.snapshot.console.console_inputs import (
    NARROW,
    WIDE,
    recording_console,
    rendered,
    scan_results_model,
)

WIDTHS = pytest.mark.parametrize("width", [WIDE, NARROW], ids=["wide", "narrow"])

#: What ``platform.system()`` returns on the two families the module distinguishes.
PLATFORMS = pytest.mark.parametrize(
    "system", ["Linux", "Windows"], ids=["posix", "windows"]
)


def _source_and_output(tmp_path, monkeypatch):
    """The default layout: cwd is the scanned tree and the output sits inside it.

    The caption is printed relative to the cwd when it can be, so chdir-ing to the tree
    makes it read the way it does for an operator rather than as an absolute temp path.
    """
    source = tmp_path / "repo"
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    monkeypatch.chdir(source)
    return source, output


@WIDTHS
def test_summary_table(width, text_snapshot, tmp_path, monkeypatch):
    source, output = _source_and_output(tmp_path, monkeypatch)
    console = recording_console(width)

    console.print(
        generate_metrics_table_from_unified_data(
            asharp_model=scan_results_model(),
            source_dir=source,
            output_dir=output,
            console=console,
        )
    )

    assert rendered(console) == text_snapshot("txt")


@WIDTHS
def test_notices_under_the_table(width, text_snapshot):
    """The "Incomplete coverage" line for cdk-nag, then one line per stale database.

    Enforced records print red with no suffix, warned ones yellow with "(warning)"; color
    is not in a snapshot, so the suffix is what distinguishes them here.
    """
    model = scan_results_model(with_stale_databases=True)
    console = recording_console(width)

    print_coverage_shortfalls(model, console)
    print_stale_content_databases(model, console)

    assert rendered(console) == text_snapshot("txt")


def test_no_notices_when_nothing_was_lost():
    """The negative control for the test above: a complete scan prints no notice at all."""
    console = recording_console(WIDE)
    model = scan_results_model(with_incomplete_scanners=False)

    print_coverage_shortfalls(model, console)
    print_stale_content_databases(model, console)

    assert rendered(console) == ""


@PLATFORMS
@WIDTHS
def test_display_metrics_table(system, width, text_snapshot, tmp_path, monkeypatch):
    """Help panel, table, then notices: everything ``display_metrics_table`` prints."""
    source, output = _source_and_output(tmp_path, monkeypatch)
    monkeypatch.setattr(metrics_table.platform, "system", lambda: system)
    consoles: list[Console] = []

    def pinned_console(**kwargs):
        pinned = recording_console(width)
        console = Console(
            **{
                **kwargs,
                "file": pinned.file,
                "width": width,
                "height": pinned.height,
                "_environ": {},
            }
        )
        consoles.append(console)
        return console

    monkeypatch.setattr(metrics_table, "Console", pinned_console)

    display_metrics_table(
        scan_results_model(with_stale_databases=True),
        source_dir=source,
        output_dir=output,
    )

    assert len(consoles) == 1
    assert rendered(consoles[0]) == text_snapshot("txt")


def test_table_for_an_empty_scan(text_snapshot):
    """No scanners at all: the headers and nothing else, which is what a misconfigured
    allowlist looks like on the console."""
    console = recording_console(WIDE)

    console.print(
        generate_metrics_table_from_unified_data(
            asharp_model=AshAggregatedResults(), console=console
        )
    )

    assert rendered(console) == text_snapshot("txt")


def test_display_falls_back_to_plain_text(text_snapshot, capsys, monkeypatch):
    """When the table cannot be built, the scan still ends with a pointer to the files."""

    def broken(**_kwargs):
        raise RuntimeError("model is malformed")

    monkeypatch.setattr(
        metrics_table, "generate_metrics_table_from_unified_data", broken
    )

    display_metrics_table(AshAggregatedResults())

    assert capsys.readouterr().out == text_snapshot("txt")
