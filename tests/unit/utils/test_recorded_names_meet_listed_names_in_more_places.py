# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""More places a recorded file name meets the same name read from the filesystem.

A result holds a file name that is not UTF-8 in its record form, the surrogate written
as the six characters \\udcNN (utils/undecodable_text.py). The names ASH lists hold the
surrogate itself. Beside the places test_recorded_names_meet_names_read_from_disk.py
holds, each of these has to find the two equal:

- a result in a converted file under an output directory named so is marked as
  converted, also when its URI reaches the file through a symlink: the location
  is resolved by the name the file has on disk, so the resolved record-form
  path, under the converted root, is the one the mark keeps;
- a URI under a scan root whose name is not UTF-8 is made relative to it, for a plain
  file, a file named so, and one below a plain directory;
- a recursive glob matches the listed and the recorded name alike.

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
from automated_security_helper.utils.finding_identity import CONVERTED_PATH_PROPERTY
from automated_security_helper.utils.sarif_utils import sanitize_sarif_paths
from automated_security_helper.utils.scan_output_dirs import mark_converted_results
from automated_security_helper.utils.suppression_matcher import (
    file_path_matches,
    ignore_path_matches,
)

# The constants below are file names that are not UTF-8.
if os.name == "nt":
    pytest.skip(
        "a file name that is not UTF-8 cannot exist on NTFS (names are UTF-16)",
        allow_module_level=True,
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


@pytest.mark.parametrize("spelling", ["as-on-disk", "in-record-form"])
def test_a_result_reached_through_a_symlink_under_a_root_named_so_is_marked(
    tmp_path, spelling
):
    """The URI names the converted file through a symlink beside the converted
    root, in either spelling a result can hold: the name as it is on disk, and
    its record form. A location is resolved by the name the file has on disk,
    which follows the link into the root; a record-form URI is read back as the
    name it records first, since no directory on disk has the six-character
    name, and resolving it as it is would read the result as outside the root
    and leave it unmarked."""
    source = tmp_path / "src"
    output = source / ODD_DIR
    work = output / "converted"
    _make(work / "jupyter" / "nb.py")
    alias = output / "alias"
    try:
        alias.symlink_to(work / "jupyter", target_is_directory=True)
    except OSError as error:
        pytest.skip(f"this filesystem cannot hold a symlink: {error}")
    context = PluginContext(
        source_dir=source, output_dir=output, work_dir=work, config=AshConfig()
    )
    on_disk = (alias / "nb.py").as_posix()
    recorded = on_disk.replace(os.fsdecode(b"\xe9"), "\\udce9")
    report = _report(recorded, "app.py")
    if spelling == "as-on-disk":
        # Validation writes the record form at construction, so the raw
        # spelling has to be assigned afterwards, as a result that was built
        # with model_construct or mutated later can hold it.
        report.runs[0].results[0].locations[
            0
        ].physicalLocation.root.artifactLocation.uri = on_disk
    # Each case holds the spelling it names before the mark runs.
    wanted = on_disk if spelling == "as-on-disk" else recorded
    assert ascii(_uris(report)[0]) == ascii(wanted)

    marked = mark_converted_results(report, context)

    assert marked == 1
    first = report.runs[0].results[0]
    assert getattr(first.properties, CONVERTED_PATH_PROPERTY) == "jupyter/nb.py"


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


def test_a_recursive_glob_matches_the_listed_and_the_recorded_name_alike():
    for name in (ODD, RECORDED, f"sub/{ODD}", f"sub/{RECORDED}"):
        # ascii(): a report holding a lone surrogate cannot be sent between workers.
        assert ignore_path_matches(name, "**/secr*t.py"), ascii(name)
        assert file_path_matches(name, "**/secr*t.py"), ascii(name)
