# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``filter_results_by_files`` reads every URI form a scanner writes for a listed file.

The filter sliced ``file://`` off a URI and compared the rest as text, so a
percent-encoded name, a ``file:/abs`` URI, a ``file://localhost/abs`` URI and a
``FILE://`` scheme never matched the listed file and those results were dropped.
A Windows drive path whose case differed from ``source_dir`` was never made
relative; a listed name given as a Windows path object was spelled with
backslashes; a ``source_dir`` reached through a symlink or given relative left
every absolute URI unmatched where the sanitize path resolves both; and an
artifactLocation with no ``uri`` was compared as "" and dropped, where a result
with no location is retained.
"""

from __future__ import annotations

from pathlib import Path, PureWindowsPath

import pytest

from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    PhysicalLocation2,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
    _resolved_relative_text,
)

pytestmark = pytest.mark.unit


def _result(uri: str | None, line: int = 1) -> Result:
    return Result(
        ruleId="R",
        message=Message(text=f"finding {line}"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri=uri),
                        region={"startLine": line},
                    )
                )
            )
        ],
    )


def _report(*uris: str | None) -> SarifReport:
    return SarifReport(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="scanner")),
                results=[_result(uri, index + 1) for index, uri in enumerate(uris)],
            )
        ]
    )


def _lines(report: SarifReport) -> list[int]:
    return [
        result.locations[0].physicalLocation.root.region.startLine
        for result in report.runs[0].results
    ]


class TestFileUriForms:
    @pytest.mark.parametrize(
        "uri",
        [
            "file:///work/src/src/my%20file.py",
            "file:/work/src/src/my file.py",
            "file://localhost/work/src/src/my%20file.py",
            "FILE:///work/src/src/my%20file.py",
        ],
    )
    def test_the_listed_file_is_kept_under_every_file_uri_form(self, uri):
        report = _report(uri, "/work/src/src/other.py")

        report.filter_results_by_files({"src/my file.py"}, "/work/src")

        assert _lines(report) == [1]

    def test_a_host_segment_does_not_become_a_path_segment(self):
        report = _report("file://host/work/src/src/a.py")

        report.filter_results_by_files({"host/work/src/src/a.py"}, "/work/src")

        assert _lines(report) == []

    def test_a_remote_host_is_kept_as_the_unc_root_the_source_dir_names(self):
        """``file://host/share/...`` names a share: it matches a UNC source_dir
        and never a local directory of the same path."""
        report = _report("file://fileserver/share/proj/src/a.py")

        report.filter_results_by_files({"src/a.py"}, "//fileserver/share/proj")

        assert _lines(report) == [1]

    def test_a_remote_host_does_not_match_the_local_path_of_the_same_name(self):
        report = _report("file://fileserver/share/proj/src/a.py")

        report.filter_results_by_files({"src/a.py"}, "/share/proj")

        assert _lines(report) == []

    @pytest.mark.parametrize(
        ("uri", "listed"),
        [
            ("file:///work/src/src/C#/a.py", "src/C#/a.py"),
            ("file:///work/src/src/a;b.py", "src/a;b.py"),
            ("file:///work/src/src/q?.py", "src/q?.py"),
        ],
    )
    def test_a_name_holding_a_url_delimiter_is_read_whole(self, uri, listed):
        report = _report(uri, "/work/src/src/other.py")

        report.filter_results_by_files({listed}, "/work/src")

        assert _lines(report) == [1]


class TestWindowsForms:
    @pytest.mark.parametrize(
        "uri", ["file://C:/proj/src/app.py", "file://c:\\proj\\src\\app.py"]
    )
    def test_a_drive_in_the_authority_slot_keeps_its_drive(self, uri):
        report = _report(uri, "file://C:/proj/src/other.py")

        report.filter_results_by_files({"src/app.py"}, "C:/proj")

        assert _lines(report) == [1]

    def test_a_drive_path_matches_without_regard_to_case(self):
        report = _report("file:///c:/proj/Src/App.py", "C:/Proj/src/other.py")

        report.filter_results_by_files({"src/app.py"}, "C:/Proj")

        assert _lines(report) == [1]

    def test_a_tail_whose_case_differs_still_names_the_listed_file(self):
        """The whole path is compared as Windows compares it, not the root alone."""
        report = _report("file:///C:/proj/Src/App.py", "C:/proj/src/Other.py")

        report.filter_results_by_files({"src/app.py"}, "C:/proj")

        assert _lines(report) == [1]

    def test_the_resolved_fallback_folds_case_when_asked(self):
        """The fallback a relative or linked Windows source_dir reaches compares
        as that file system does; it never ran under a drive-rooted URI before."""
        assert (
            _resolved_relative_text("/Work/Proj/src/A.py", "/work/proj", True)
            == "src/A.py"
        )
        assert _resolved_relative_text("/Work/Proj/src/A.py", "/work/proj", False) in (
            None,
            "src/A.py",
        )
        assert _resolved_relative_text("/work/proj/src/a.py", None, True) is None

    def test_a_listed_windows_path_object_is_spelled_with_slashes(self):
        report = _report("C:/proj/src/app.py")

        report.filter_results_by_files(
            {PureWindowsPath("src\\app.py")}, PureWindowsPath("C:/proj")
        )

        assert _lines(report) == [1]


class TestUnresolvedSourceDir:
    def test_an_absolute_uri_matches_a_source_dir_reached_through_a_link(
        self, tmp_path
    ):
        real = tmp_path / "real"
        (real / "src").mkdir(parents=True)
        (real / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")
        link = tmp_path / "link"
        try:
            link.symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:  # pragma: no cover
            pytest.skip(f"symlinks are unavailable here: {exc}")
        report = _report((real / "src" / "a.py").as_posix())

        report.filter_results_by_files({"src/a.py"}, link)

        assert _lines(report) == [1]

    def test_an_absolute_uri_matches_a_relative_source_dir(self, tmp_path, monkeypatch):
        (tmp_path / "proj" / "src").mkdir(parents=True)
        monkeypatch.chdir(tmp_path)
        report = _report((tmp_path / "proj" / "src" / "a.py").as_posix())

        report.filter_results_by_files({"src/a.py"}, Path("proj"))

        assert _lines(report) == [1]

    def test_a_uri_outside_the_source_dir_is_still_dropped(self, tmp_path):
        """The control: resolving must not make an unrelated path match."""
        (tmp_path / "proj").mkdir()
        report = _report((tmp_path / "elsewhere" / "src" / "a.py").as_posix())

        report.filter_results_by_files({"src/a.py"}, tmp_path / "proj")

        assert _lines(report) == []


class TestALocationWithoutAUri:
    def test_a_result_located_by_index_alone_is_retained(self):
        report = _report(None, "src/other.py")
        assert (
            report.runs[0]
            .results[0]
            .locations[0]
            .physicalLocation.root.artifactLocation.uri
            is None
        )

        report.filter_results_by_files({"src/kept.py"}, "/work/src")

        assert _lines(report) == [1]
