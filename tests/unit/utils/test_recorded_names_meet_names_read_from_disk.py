# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A recorded file name meets the same name read from the filesystem or git.

A result holds a file name that is not UTF-8 in its record form, the surrogate written
as the six characters \\udcNN (utils/undecodable_text.py). The names ASH lists from
the tree, from git and from its own directories hold the surrogate itself. Each place
that compares the two has to find them equal, so the file's findings are kept where
they belong and dropped where they belong:

- ``--changed-files-only`` keeps the findings in a changed file;
- ``SarifReport.filter_results_by_files`` keeps those in a listed file;
- a result in a converted file under an output directory named so is marked as
  converted, and one in ASH's own output directory named so is dropped;
- a URI under a scan root whose name is not UTF-8 is made relative to it;
- an ignore path or suppression pattern matches the name the same way on the files
  a scanner is given and on the findings it reports.

Only some filesystems can hold such a name. Windows cannot decode one, and APFS
refuses it, so there the tests that need one on disk skip, with the reason.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.changed_files import (
    filter_results_to_changed_files,
)
from automated_security_helper.utils.finding_identity import CONVERTED_PATH_PROPERTY
from automated_security_helper.utils.sarif_utils import sanitize_sarif_paths
from automated_security_helper.utils.scan_output_dirs import (
    drop_results_in_ash_output_dirs,
    mark_converted_results,
)
from automated_security_helper.utils.suppression_matcher import (
    file_path_matches,
    ignore_path_matches,
)

ODD = os.fsdecode(b"secr\xe9t.py")
RECORDED = "secr\\udce9t.py"
ODD_DIR = os.fsdecode(b"caf\xe9")


def _make(path: Path) -> Path:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x = 1\n", encoding="utf-8")
    except (UnicodeError, OSError) as error:
        pytest.skip(f"this filesystem cannot hold a name that is not UTF-8: {error}")
    return path


def _result(uri: str) -> Result:
    return Result(
        ruleId="R1",
        message=Message(text="finding"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri=uri)
                )
            )
        ],
    )


def _report(*uris: str) -> SarifReport:
    return SarifReport(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="scripted")),
                results=[_result(uri) for uri in uris],
            )
        ]
    )


def _uris(report: SarifReport) -> List[str]:
    return [
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in report.get_all_results()
    ]


def test_changed_files_only_keeps_the_findings_in_a_changed_file_named_so(tmp_path):
    source = tmp_path / "src"
    _make(source / ODD)
    _make(source / "same.py")
    # As run_ash_scan builds the set: git's names, read as file names, resolved.
    changed = {(source / ODD).resolve()}
    model = AshAggregatedResults(sarif=_report(ODD, "same.py"))

    filter_results_to_changed_files(model, changed, source)

    assert _uris(model.sarif) == [RECORDED]


def test_a_file_set_filter_keeps_the_findings_in_a_listed_file_named_so(tmp_path):
    report = _report(ODD, "other.py")

    report.filter_results_by_files({ODD}, tmp_path)

    assert _uris(report) == [RECORDED]


def test_a_result_in_a_converted_file_under_an_output_dir_named_so_is_marked(
    tmp_path,
):
    source = tmp_path / "src"
    output = source / ODD_DIR
    work = output / "converted"
    converted = _make(work / "jupyter" / "nb.py")
    context = PluginContext(
        source_dir=source, output_dir=output, work_dir=work, config=AshConfig()
    )
    report = _report(converted.as_posix(), "app.py")

    marked = mark_converted_results(report, context)

    assert marked == 1
    first = report.runs[0].results[0]
    assert getattr(first.properties, CONVERTED_PATH_PROPERTY) == "jupyter/nb.py"


def test_a_result_in_an_output_dir_named_so_is_dropped(tmp_path, monkeypatch):
    # The drop's warning names the output directory as listed. ASH's own log
    # handlers show the surrogate as an escape; pytest-xdist cannot send a captured
    # record holding one between processes, so the warning is recorded here instead.
    from unittest.mock import MagicMock

    from automated_security_helper.utils import scan_output_dirs

    logger = MagicMock()
    monkeypatch.setattr(scan_output_dirs, "ASH_LOGGER", logger)
    source = tmp_path / "src"
    output = source / ODD_DIR
    _make(output / "reports" / "ash.sarif")
    _make(source / "app.py")
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    report = _report(f"{ODD_DIR}/reports/ash.sarif", "app.py")

    removed = drop_results_in_ash_output_dirs(report, context, scanner_name="scripted")

    assert removed == 1
    assert _uris(report) == ["app.py"]
    assert logger.warning.call_count == 1


@pytest.mark.parametrize(
    "name",
    ["app.py", ODD, f"sub/{ODD}"],
    ids=["plain", "odd", "odd-below-a-plain-directory"],
)
def test_a_uri_under_a_scan_root_named_so_is_made_relative_to_it(tmp_path, name):
    """A scanner reports an absolute URI under the root it was handed; the SARIF the
    results keep names the file relative to the root, as for a plain root."""
    root = tmp_path / ODD_DIR
    _make(root / name)
    report = _report(os.path.join(str(root), name))

    sanitize_sarif_paths(report, root)

    assert _uris(report) == [name.replace(ODD, RECORDED)]


@pytest.mark.parametrize(
    "pattern",
    ["secr*t.py", ODD, f"**/{ODD}", "**/secr*t.py"],
    ids=[
        "star",
        "pattern-holding-the-byte",
        "recursive-holding-the-byte",
        "recursive-star",
    ],
)
def test_a_pattern_matches_the_listed_and_the_recorded_name_alike(pattern):
    """The scan set holds the name as listed, a finding the recorded name; an ignore
    path or a suppression gives one answer for both."""
    for name in (ODD, RECORDED, f"sub/{ODD}", f"sub/{RECORDED}"):
        # Anchored at the top; only ** reaches the one in sub/.
        expected = "**" in pattern or "/" not in name
        # ascii(): a report holding a lone surrogate cannot be sent between workers.
        assert ignore_path_matches(name, pattern) is expected, ascii(name)
        assert file_path_matches(name, pattern) is expected, ascii(name)


def test_a_pattern_for_another_name_matches_neither_form():
    for name in (ODD, RECORDED):
        assert not ignore_path_matches(name, "secret.py"), ascii(name)
        assert not ignore_path_matches(name, os.fsdecode(b"secr\xe8t.py")), ascii(name)
        assert not file_path_matches(name, "secr\\udce8t.py"), ascii(name)
