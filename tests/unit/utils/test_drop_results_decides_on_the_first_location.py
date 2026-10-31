# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``drop_results_in_ash_output_dirs`` decides on a result's first location.

A SARIF result's first location is the one the result is about; later locations
are related places. The drop walked every location and removed the result as soon
as any of them sat in an output directory, so a finding about a file of the
scanned tree whose related location pointed into ASH's output was dropped with
ASH's own reports. The first location that names a file now decides: in the
tree, kept; in an output directory and not committed, dropped.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils.scan_output_dirs import (
    drop_results_in_ash_output_dirs,
)

pytestmark = pytest.mark.unit


def _result(*uris: str) -> SimpleNamespace:
    return SimpleNamespace(
        locations=[
            SimpleNamespace(
                physicalLocation=SimpleNamespace(
                    root=SimpleNamespace(artifactLocation=SimpleNamespace(uri=uri))
                )
            )
            for uri in uris
        ]
    )


def _report(*results: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(runs=[SimpleNamespace(results=list(results))])


def _tree(tmp_path):
    source = Path(os.path.realpath(tmp_path)) / "src"
    output = source / ".ash" / "ash_output"
    (output / "reports").mkdir(parents=True)
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    (output / "reports" / "ash.sarif").write_text("{}", encoding="utf-8")
    context = SimpleNamespace(
        source_dir=source, output_dir=output, work_dir=output / "converted"
    )
    return source, output, context


def test_a_result_about_a_tree_file_with_a_related_output_location_is_kept(tmp_path):
    source, output, context = _tree(tmp_path)
    report = _report(_result("app.py", ".ash/ash_output/reports/ash.sarif"))

    removed = drop_results_in_ash_output_dirs(report, context, scanned_files=[])

    assert removed == 0
    assert len(report.runs[0].results) == 1


def test_control_a_result_whose_first_location_is_in_the_output_is_dropped(tmp_path):
    source, output, context = _tree(tmp_path)
    report = _report(_result(".ash/ash_output/reports/ash.sarif", "app.py"))

    removed = drop_results_in_ash_output_dirs(report, context, scanned_files=[])

    assert removed == 1
    assert report.runs[0].results == []


def test_control_a_result_located_only_in_the_tree_is_kept(tmp_path):
    source, output, context = _tree(tmp_path)
    report = _report(_result("app.py"))

    assert drop_results_in_ash_output_dirs(report, context, scanned_files=[]) == 0


def _location(uri) -> SimpleNamespace:
    return SimpleNamespace(
        physicalLocation=SimpleNamespace(
            root=SimpleNamespace(artifactLocation=SimpleNamespace(uri=uri))
        )
    )


#: First locations that name no file: a logical location with no physical one, a
#: physical one with no artifact, one with no uri, and one with an empty uri.
_NO_FILE_FIRST_LOCATIONS = [
    pytest.param(SimpleNamespace(physicalLocation=None), id="no-physical-location"),
    pytest.param(
        SimpleNamespace(
            physicalLocation=SimpleNamespace(
                root=SimpleNamespace(artifactLocation=None)
            )
        ),
        id="no-artifact-location",
    ),
    pytest.param(_location(None), id="no-uri"),
    pytest.param(_location(""), id="empty-uri"),
]


@pytest.mark.parametrize("first", _NO_FILE_FIRST_LOCATIONS)
def test_a_first_location_that_names_no_file_is_passed_over_for_one_in_the_output(
    tmp_path, first
):
    """The first location that NAMES A FILE decides, so one that names none does
    not: the result below is about ASH's own report, and is dropped."""
    source, output, context = _tree(tmp_path)
    report = _report(
        SimpleNamespace(
            locations=[first, _location(".ash/ash_output/reports/ash.sarif")]
        )
    )

    removed = drop_results_in_ash_output_dirs(report, context, scanned_files=[])

    assert removed == 1
    assert report.runs[0].results == []


@pytest.mark.parametrize("first", _NO_FILE_FIRST_LOCATIONS)
def test_control_a_first_location_that_names_no_file_then_a_tree_file_is_kept(
    tmp_path, first
):
    source, output, context = _tree(tmp_path)
    report = _report(
        SimpleNamespace(
            locations=[
                first,
                _location("app.py"),
                _location(".ash/ash_output/reports/ash.sarif"),
            ]
        )
    )

    assert drop_results_in_ash_output_dirs(report, context, scanned_files=[]) == 0
    assert len(report.runs[0].results) == 1


@pytest.mark.parametrize("locations", [[], None])
def test_control_a_result_with_no_location_at_all_is_kept(tmp_path, locations):
    source, output, context = _tree(tmp_path)
    report = _report(SimpleNamespace(locations=locations))

    assert drop_results_in_ash_output_dirs(report, context, scanned_files=[]) == 0
    assert len(report.runs[0].results) == 1
