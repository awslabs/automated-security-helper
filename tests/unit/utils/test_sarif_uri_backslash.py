"""A backslash in a SARIF URI separates segments only where the scan root's paths do.

On POSIX a backslash is an ordinary character in a file name, and the POSIX
producers measured all keep it as written: ``os.path.relpath``,
``Path.relative_to``, ``as_posix()``, ``Path.as_uri()`` (as ``%5C``), and the
result keys detect-secrets writes. On Windows it is a separator, and a Windows
name cannot contain one. ``_sanitize_uri`` runs on the host that ran the
scanner, against that host's scan root, so the root's flavor is the producer's.

Rewriting every backslash to ``/`` turned the POSIX file ``a\\b.py`` into
``a/b.py``, a path that names nothing, so the finding pointed at no file and
matched no suppression written for it.
"""

import sys
from pathlib import Path, PureWindowsPath

import pytest

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
    _sanitize_uri,
    sanitize_sarif_paths,
)

pytestmark = pytest.mark.unit

posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="a Windows file name cannot contain a backslash",
)


def _root(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path.resolve()
    return root, root.as_posix() + "/"


@posix_only
@pytest.mark.parametrize("form", ["relative", "absolute", "file_uri"])
def test_a_posix_name_containing_a_backslash_is_kept(tmp_path, form):
    root, root_str = _root(tmp_path)
    named = root / "a\\b.py"
    named.write_text("x = 1\n")
    uri = {
        "relative": "a\\b.py",
        "absolute": str(named),
        "file_uri": named.as_uri(),
    }[form]

    result = _sanitize_uri(uri, root, root_str)

    assert result == "a\\b.py"
    assert (root / result).is_file()


@posix_only
def test_a_backslash_name_in_a_subdirectory_keeps_both_characters(tmp_path):
    root, root_str = _root(tmp_path)
    (root / "dir").mkdir()
    named = root / "dir" / "a\\b.py"
    named.write_text("x = 1\n")

    result = _sanitize_uri(str(named), root, root_str)

    assert result == "dir/a\\b.py"
    assert (root / result).is_file()


@posix_only
def test_on_a_posix_root_a_name_that_matches_no_file_is_kept_as_written(tmp_path):
    root, root_str = _root(tmp_path)

    assert _sanitize_uri("gone\\x.py", root, root_str) == "gone\\x.py"


@posix_only
def test_when_both_spellings_exist_the_name_as_written_wins(tmp_path):
    root, root_str = _root(tmp_path)
    (root / "a\\b.py").write_text("x = 1\n")
    (root / "a").mkdir()
    (root / "a" / "b.py").write_text("y = 2\n")

    assert _sanitize_uri("a\\b.py", root, root_str) == "a\\b.py"


def test_windows_separators_for_a_file_under_the_root_become_slashes(tmp_path):
    # A SARIF file written on Windows for the same tree, read against a
    # checkout of it: the backslash-separated form names a file that exists.
    root, root_str = _root(tmp_path)
    (root / "c").mkdir()
    (root / "c" / "d.py").write_text("x = 1\n")

    result = _sanitize_uri("c\\d.py", root, root_str)

    assert result == "c/d.py"
    assert (root / result).is_file()


def test_a_drive_letter_uri_keeps_slash_separators_on_any_root(tmp_path):
    root, root_str = _root(tmp_path)

    assert _sanitize_uri("D:\\a\\repo\\x.py", root, root_str) == "D:/a/repo/x.py"


@posix_only
def test_a_unc_uri_keeps_slash_separators_on_a_posix_root(tmp_path):
    # POSIX only because resolve() on Windows would look the share up.
    root, root_str = _root(tmp_path)

    assert (
        _sanitize_uri("\\\\server\\share\\x.py", root, root_str)
        == "//server/share/x.py"
    )


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("src\\a.py", "src/a.py"),
        ("C:\\proj\\src\\a.py", "src/a.py"),
        ("C:/proj/src/a.py", "src/a.py"),
    ],
)
def test_on_a_windows_root_every_backslash_is_a_separator(uri, expected):
    # Nothing under this root exists on the test host. On Windows no name can
    # contain a backslash, so the answer does not depend on the file system.
    root = PureWindowsPath("C:/proj")

    assert _sanitize_uri(uri, root, "C:/proj/") == expected


def _report_pointing_at(uri: str) -> SarifReport:
    def location() -> Location:
        return Location(
            physicalLocation=PhysicalLocation(
                artifactLocation=ArtifactLocation(uri=uri),
                region=Region(startLine=1),
            )
        )

    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="TestScanner", version="1.0")),
                results=[
                    Result(
                        ruleId="R1",
                        message=Message(text="finding"),
                        locations=[location()],
                        relatedLocations=[location()],
                        analysisTarget=ArtifactLocation(uri=uri),
                    )
                ],
            )
        ],
    )


@posix_only
def test_sanitize_sarif_paths_keeps_the_name_in_every_location_field(tmp_path):
    root = tmp_path.resolve()
    named = root / "a\\b.py"
    named.write_text("x = 1\n")

    report = sanitize_sarif_paths(_report_pointing_at(str(named)), root)

    result = report.runs[0].results[0]
    uris = [
        result.locations[0].physicalLocation.root.artifactLocation.uri,
        result.relatedLocations[0].physicalLocation.root.artifactLocation.uri,
        result.analysisTarget.uri,
    ]
    assert uris == ["a\\b.py"] * 3
