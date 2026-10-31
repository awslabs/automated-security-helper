# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One rule names a SARIF file's scanner, for the helper and for the analysis.

``analyze_sarif_fields`` named a file by the component after the FIRST ``scanners``
below the searched directory, and the public helper ``get_scanner_name_from_path``
by the component after the LAST ``scanners`` in the whole path, so the helper
attributed ``out/scanners/bandit/scanners/mirror/r.sarif`` to ``mirror``, the
misattribution the analysis's own rule exists to avoid. The helper takes the
searched directory and applies the analysis's rule; the analysis calls it.
"""

import json

import pytest
import typer

from automated_security_helper.utils.sarif_field_analysis import (
    analyze_sarif_fields,
    get_scanner_name_from_path,
)

pytestmark = pytest.mark.unit


def test_with_a_root_the_scanner_is_the_directory_right_below_scanners():
    mirrored = "out/scanners/bandit/scanners/mirror/r.sarif"

    assert get_scanner_name_from_path(mirrored, root="out") == "bandit"


def test_with_a_root_an_ancestor_named_scanners_is_not_part_of_the_layout():
    path = "/x/scanners/team/out/scanners/bandit/r.sarif"

    assert get_scanner_name_from_path(path, root="/x/scanners/team/out") == "bandit"


def test_with_a_root_a_file_outside_scanners_is_named_by_its_stem():
    assert get_scanner_name_from_path("out/reports/ash.sarif", root="out") == "ash"
    # A file directly in scanners/ has no scanner directory above it.
    assert get_scanner_name_from_path("out/scanners/x.sarif", root="out") == "x"


def test_a_path_not_below_the_root_is_read_as_a_whole():
    path = "elsewhere/scanners/bandit/r.sarif"

    assert get_scanner_name_from_path(path, root="out") == "bandit"


def test_without_a_root_the_whole_path_is_read_as_before():
    """The compatibility rule: the directory under the LAST scanners component.

    Kept on purpose, and the misattribution above is its known cost. A path alone
    cannot say which ``scanners`` component is the output layout's, so a caller
    that has no searched directory gets the older reading. The helper is
    re-exported by the inspect CLI module and called without a root by three other
    test modules; the analysis, the only caller in the product, always passes the
    root it searched. Making the root required is a change to that public helper
    and is not made here."""
    mirrored = "out/scanners/bandit/scanners/mirror/r.sarif"
    under_an_ancestor = "/x/scanners/out/scanners/bandit/r.sarif"

    assert get_scanner_name_from_path(mirrored) == "mirror"
    assert get_scanner_name_from_path(under_an_ancestor) == "bandit"
    assert get_scanner_name_from_path("reports/ash.sarif") == "ash"


def test_the_analysis_names_a_file_directly_in_scanners_by_its_stem(
    tmp_path, monkeypatch
):
    """It was named ``x.sarif``, the file's own name with its extension."""
    monkeypatch.setenv("COLUMNS", "200")
    sarif_dir = tmp_path / "ash_output"
    (sarif_dir / "scanners").mkdir(parents=True)
    (sarif_dir / "scanners" / "x.sarif").write_text(
        json.dumps({"runs": [{"results": [{"ruleId": "R1"}]}]}), encoding="utf-8"
    )
    output_dir = tmp_path / "out"

    try:
        analyze_sarif_fields(sarif_dir=str(sarif_dir), output_dir=str(output_dir))
    except typer.Exit:
        pass

    fields = json.loads((output_dir / "sarif_fields.json").read_text(encoding="utf-8"))
    assert set(fields["runs[].results[].ruleId"]) == {"x"}
