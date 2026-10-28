"""After sanitizing, a backslash left in a location URI is part of a file name.

The host that ran the scanner writes "/" for its own separators when it
sanitizes a URI (``sarif_utils._with_slash_separators``). Every step after that
reads the URI textually, with ``utils/uri_separators.py``: suppression matching,
``ash merge``, workspace aggregation and ``SarifReport.filter_results_by_files``.
Were each of them to rewrite every backslash to "/", a finding in the POSIX file
``a\\b.py`` would be matched, located and reported as ``a/b.py``, a path that
names no file. A drive-letter or UNC path is Windows-made, and its backslashes
are separators.
"""

import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import (
    _normalize_sarif_uri,
    apply_suppressions_to_sarif,
)
from automated_security_helper.utils.uri_separators import (
    is_windows_root,
    root_text,
    sanitized_uri_text,
)
from automated_security_helper.workspace.aggregation import (
    project_relative_uri,
    to_workspace_uri,
)

PluginContext.model_rebuild()

posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="a Windows file name cannot contain a backslash",
)


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("a\\b.py", "a\\b.py"),
        ("dir/a\\b.py", "dir/a\\b.py"),
        ("/src/a\\b.py", "/src/a\\b.py"),
        ("C:\\proj\\a.py", "C:/proj/a.py"),
        ("c:/proj\\a.py", "c:/proj/a.py"),
        ("\\\\server\\share\\a.py", "//server/share/a.py"),
        ("plain/a.py", "plain/a.py"),
    ],
)
def test_a_sanitized_uri_converts_only_a_windows_path(uri, expected):
    assert sanitized_uri_text(uri) == expected


@pytest.mark.parametrize(
    ("root", "expected"),
    [
        ("C:/proj", "src/a.py"),
        ("C:\\proj", "src/a.py"),
        ("\\\\server\\share", "src/a.py"),
        (PureWindowsPath("C:/proj"), "src/a.py"),
        ("/proj", "src\\a.py"),
        (PurePosixPath("/proj"), "src\\a.py"),
        (None, "src\\a.py"),
    ],
)
def test_under_a_windows_root_every_backslash_is_a_separator(root, expected):
    assert sanitized_uri_text("src\\a.py", root) == expected


@pytest.mark.parametrize(
    "root",
    [
        "//server/share",
        "//server/share/ws/",
        "\\\\server\\share\\ws",
        "/\\server/share",
    ],
)
def test_a_unc_root_is_a_windows_root_however_its_separators_are_spelled(root):
    """root_text spells a UNC root with "/", and the sanitize prefix and the
    workspace project path pass it in that spelling."""
    assert is_windows_root(root)
    assert sanitized_uri_text("src\\app.py", root) == "src/app.py"


def test_root_texts_unc_spelling_is_a_windows_root():
    spelled = root_text(PureWindowsPath(r"\\server\share\ws"))

    assert spelled == "//server/share/ws"
    assert is_windows_root(spelled)


@pytest.mark.parametrize("root", ["/server/share", "//server", "///x/y", "/ws/a\\b"])
def test_a_posix_root_is_not_a_windows_root(root):
    assert not is_windows_root(root)


@pytest.mark.parametrize(
    ("root", "expected"),
    [
        ("/ws/a\\b", "/ws/a\\b"),
        ("C:\\ws\\api", "C:/ws/api"),
        ("\\\\server\\share\\ws", "//server/share/ws"),
    ],
)
def test_a_root_string_converts_only_a_windows_path(root, expected):
    assert root_text(root) == expected


def _report(*locations: tuple[str, int]) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="TestScanner", version="1.0")),
                results=[
                    Result(
                        ruleId="R1",
                        message=Message(text="finding"),
                        locations=[
                            Location(
                                physicalLocation=PhysicalLocation(
                                    artifactLocation=ArtifactLocation(uri=uri),
                                    region=Region(startLine=line, endLine=line),
                                )
                            )
                        ],
                    )
                    for uri, line in locations
                ],
            )
        ],
    )


@posix_only
def test_an_inline_suppression_is_read_from_the_file_whose_name_holds_a_backslash(
    tmp_path,
):
    source = tmp_path / "src"
    source.mkdir()
    (source / "a\\b.py").write_text("x = 1  # ash-ignore: R1 reviewed\n")
    (source / "a").mkdir()
    (source / "a" / "b.py").write_text("x = 1\n")
    output = tmp_path / "out"
    output.mkdir()
    context = PluginContext(source_dir=source, output_dir=output, config=AshConfig())

    report = apply_suppressions_to_sarif(
        _report(("a\\b.py", 1), ("a/b.py", 1)), context
    )

    by_uri = {
        result.locations[0].physicalLocation.root.artifactLocation.uri: result
        for result in report.runs[0].results
    }
    assert [s.kind for s in by_uri["a\\b.py"].suppressions or []] == ["inSource"]
    assert not by_uri["a/b.py"].suppressions


@posix_only
def test_the_suppression_step_strips_the_source_prefix_and_keeps_the_name():
    prefix = "/ws/src/"
    assert (
        _normalize_sarif_uri("/ws/src/a\\b.py", prefix, "/" + prefix, None, None)
        == "a\\b.py"
    )


def test_the_suppression_step_reads_a_windows_path_with_slashes():
    prefix = "D:/a/repo/src/"
    assert (
        _normalize_sarif_uri(
            "D:\\a\\repo\\src\\file.py", prefix, "/" + prefix, "/a/repo/src/", None
        )
        == "file.py"
    )


def test_workspace_aggregation_keeps_a_name_holding_a_backslash():
    assert project_relative_uri("/ws/api/a\\b.py", "/ws/api") == "a\\b.py"
    assert project_relative_uri("/ws/a\\b/x.py", "/ws/a\\b") == "x.py"
    assert to_workspace_uri("a\\b.py", "api", "/ws/api") == "api/a\\b.py"
    assert to_workspace_uri("/ws/api/a\\b.py", "api", "/ws/api") == "api/a\\b.py"


def test_workspace_aggregation_reads_a_windows_project():
    assert project_relative_uri("C:\\ws\\api\\src\\x.py", "C:\\ws\\api") == "src/x.py"
    assert (
        to_workspace_uri("C:\\ws\\api\\src\\x.py", "api", "C:\\ws\\api")
        == "api/src/x.py"
    )


def _lines(report: SarifReport) -> list[int]:
    return [
        result.locations[0].physicalLocation.root.region.startLine
        for result in report.runs[0].results
    ]


def test_filter_results_by_files_keeps_a_file_whose_name_holds_a_backslash():
    report = _report(("a\\b.py", 1), ("/src/a\\b.py", 2))

    report.filter_results_by_files({"a\\b.py"}, "/src")

    assert _lines(report) == [1, 2]


def test_filter_results_by_files_does_not_read_that_name_as_another_file():
    report = _report(("a\\b.py", 1), ("/src/a\\b.py", 2))

    report.filter_results_by_files({"a/b.py"}, "/src")

    assert _lines(report) == []


def test_filter_results_by_files_reads_a_windows_root():
    report = _report(("C:\\src\\app.py", 1))

    report.filter_results_by_files({"app.py"}, "C:\\src")

    assert len(report.runs[0].results) == 1


def test_root_text_spells_a_path_object_by_its_own_flavor():
    assert root_text(PurePosixPath("/ws/a\\b")) == "/ws/a\\b"
    assert root_text(PureWindowsPath("C:/ws/api")) == "C:/ws/api"
    assert root_text(Path("/ws")) == Path("/ws").as_posix()
