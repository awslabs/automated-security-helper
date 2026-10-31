# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan root is resolved once before it is compared with a path.

The root was compared as text. ``.`` matched no absolute path, ``/`` normalized to
nothing and so placed no path below it, a root reached through a link put every
path of the real directory outside it, and a relative root was taken without a
word although it names whatever directory the process runs in.
"""

import os
import sys

import pytest

from automated_security_helper.utils.meta_analysis.locations_match import (
    file_paths_match,
    resolve_scan_root,
)
from automated_security_helper.utils.meta_analysis.sarif_analysis import (
    validate_sarif_aggregation,
)

pytestmark = pytest.mark.unit

ROOT = "/work/app"


def _located(uri: str, line: int = 3) -> dict:
    return {
        "ruleId": "R1",
        "message": {"text": "m"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }


def _report(*results: dict) -> dict:
    return {"runs": [{"results": list(results)}]}


def _matched(original_uri: str, aggregated_uri: str, scan_root: str) -> int:
    result = validate_sarif_aggregation(
        {"bandit": _report(_located(original_uri))},
        _report(_located(aggregated_uri)),
        scan_root=scan_root,
    )
    return result["match_statistics"]["bandit"]["matched_results"]


@pytest.mark.parametrize("root", [".", "./", "work/app", ".."], ids=repr)
def test_a_relative_scan_root_is_refused(root):
    with pytest.raises(ValueError, match="absolute"):
        validate_sarif_aggregation(
            {"bandit": _report(_located("/work/app/lib/a.py"))},
            _report(_located("lib/a.py")),
            scan_root=root,
        )


def test_no_scan_root_is_still_no_scan_root():
    assert resolve_scan_root(None) is None
    assert resolve_scan_root("") is None
    result = validate_sarif_aggregation(
        {"bandit": _report(_located("/work/app/lib/a.py"))},
        _report(_located("a.py")),
    )
    assert result["match_statistics"]["bandit"]["matched_results"] == 1


def test_the_filesystem_root_places_every_absolute_path_below_it():
    assert file_paths_match("/work/app/lib/a.py", "work/app/lib/a.py", "/") is True
    assert file_paths_match("/work/app/lib/a.py", "lib/a.py", "/") is False
    assert _matched("/work/app/lib/a.py", "work/app/lib/a.py", "/") == 1
    assert _matched("/work/app/lib/a.py", "lib/a.py", "/") == 0


@pytest.mark.skipif(sys.platform == "win32", reason="a symbolic link needs a privilege")
def test_a_root_reached_through_a_link_names_the_directory_it_points_at(tmp_path):
    real = tmp_path / "real"
    (real / "lib").mkdir(parents=True)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    resolved = real.resolve()

    assert resolve_scan_root(str(link)) == os.path.realpath(real)
    # The reports spell the directory the way the scan resolved it.
    assert _matched(str(resolved / "lib" / "a.py"), "lib/a.py", str(link)) == 1
    # And the other way round: the root is the real directory and a report
    # spelled the file through the link.
    assert _matched(str(link / "lib" / "a.py"), "lib/a.py", str(resolved)) == 1
    # A file of the directory is still told apart by its whole relative path.
    assert _matched(str(resolved / "lib" / "a.py"), "a.py", str(link)) == 0


@pytest.mark.skipif(sys.platform == "win32", reason="a symbolic link needs a privilege")
def test_a_report_spelled_through_a_link_is_not_matched_by_its_end(tmp_path):
    """A report path that reaches the root through a link is below the root, so
    it is compared whole. Read as outside the root it met an aggregate that had
    dropped its leading directory (``lib/a.py`` written ``a.py``) by the end of
    its path, the match the root exists to refuse."""
    real = tmp_path / "real"
    (real / "lib").mkdir(parents=True)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    through_link = str(link / "lib" / "a.py")

    for root in (str(link), str(real.resolve())):
        assert _matched(through_link, "lib/a.py", root) == 1
        assert _matched(through_link, "a.py", root) == 0
        # The aggregate's path is the one that is relative.
        assert _matched("lib/a.py", through_link, root) == 1
        assert _matched("a.py", through_link, root) == 0


@pytest.mark.skipif(sys.platform == "win32", reason="a symbolic link needs a privilege")
def test_a_link_to_a_directory_of_the_root_places_the_files_under_it(tmp_path):
    """Aggregation resolves a whole URI when no ancestor of it is the source
    directory, so a report path that reaches a subdirectory of the root through a
    link outside the root is written ``lib/a.py``. The validator reads it the
    same way: no ancestor is the root, but the path leads into it."""
    root = tmp_path / "real"
    (root / "lib").mkdir(parents=True)
    (tmp_path / "elsewhere").mkdir()
    into_root = tmp_path / "shared"
    into_root.symlink_to(root / "lib", target_is_directory=True)
    outside = tmp_path / "outside"
    outside.symlink_to(tmp_path / "elsewhere", target_is_directory=True)
    through_link = str(into_root / "a.py")

    assert _matched(through_link, "lib/a.py", str(root)) == 1
    assert _matched("lib/a.py", through_link, str(root)) == 1
    # Placed as lib/a.py, so it is still told apart by its whole relative path.
    assert _matched(through_link, "a.py", str(root)) == 0
    assert _matched(through_link, "other/a.py", str(root)) == 0
    # A link that leads out of the root places nothing below it.
    assert _matched(str(outside / "a.py"), "lib/a.py", str(root)) == 0
    assert _matched(str(outside / "a.py"), "a.py", str(root)) == 0


@pytest.mark.skipif(sys.platform == "win32", reason="a symbolic link needs a privilege")
def test_a_link_to_a_file_of_the_root_places_the_file(tmp_path):
    root = tmp_path / "real"
    (root / "lib").mkdir(parents=True)
    target = root / "lib" / "a.py"
    target.write_text("x = 1\n")
    alias = tmp_path / "alias.py"
    alias.symlink_to(target)
    (tmp_path / "elsewhere").mkdir()
    stray = tmp_path / "elsewhere" / "b.py"
    stray.write_text("y = 2\n")
    stray_alias = tmp_path / "stray_alias.py"
    stray_alias.symlink_to(stray)

    assert _matched(str(alias), "lib/a.py", str(root)) == 1
    assert _matched("lib/a.py", str(alias), str(root)) == 1
    assert _matched(str(alias), "a.py", str(root)) == 0
    # A link to a file outside the root is no file of the root.
    assert _matched(str(stray_alias), "b.py", str(root)) == 0
    assert _matched(str(stray_alias), "lib/b.py", str(root)) == 0


def test_two_identical_paths_outside_the_root_are_one_file():
    assert _matched("/elsewhere/lib/a.py", "/elsewhere/lib/a.py", ROOT) == 1
    assert _matched("/elsewhere/lib/a.py", "/other/lib/a.py", ROOT) == 0


def test_a_path_outside_the_root_is_not_a_relative_one():
    """A relative path is relative to the root, and the aggregate writes one only
    for a file below the source directory: ``lib/a.py`` is not the file of a
    directory the scan did not cover."""
    assert _matched("/elsewhere/lib/a.py", "lib/a.py", ROOT) == 0
    assert _matched("lib/a.py", "/elsewhere/lib/a.py", ROOT) == 0
    # A path below the root is still compared whole.
    assert _matched("/work/app/lib/a.py", "a.py", ROOT) == 0
