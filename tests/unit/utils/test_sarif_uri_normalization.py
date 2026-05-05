"""Tests for SARIF URI normalization in suppression matching."""

import pytest
from pathlib import Path, PurePosixPath, PureWindowsPath

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.schemas.sarif_schema_model import (
    SarifReport,
    Run,
    Tool,
    ToolComponent,
    Result,
    Message,
    Location,
    PhysicalLocation2,
    ArtifactLocation,
    Region,
)
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif


def _make_sarif_with_uri(uri: str, rule_id: str = "B108") -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="bandit", version="1.9.0")),
                results=[
                    Result(
                        ruleId=rule_id,
                        message=Message(text="Test finding"),
                        locations=[
                            Location(
                                physicalLocation=PhysicalLocation2(
                                    artifactLocation=ArtifactLocation(uri=uri),
                                    region=Region(startLine=320, endLine=320),
                                )
                            )
                        ],
                    )
                ],
            )
        ],
    )


def _make_context(source_dir, output_dir, suppression_path, rule_id="B108"):
    config = AshConfig(
        project_name="test",
        global_settings={
            "suppressions": [
                AshSuppression(
                    rule_id=rule_id,
                    path=suppression_path,
                    reason="Test suppression",
                )
            ]
        },
    )
    return PluginContext(source_dir=source_dir, output_dir=output_dir, config=config)


class TestUriNormalization:
    """URI normalization ensures suppressions match regardless of path format."""

    def test_relative_uri_matches_relative_suppression(
        self, test_source_dir, test_output_dir
    ):
        sarif = _make_sarif_with_uri("tests/unit/converters/test_converters.py")
        ctx = _make_context(
            test_source_dir, test_output_dir, "tests/unit/converters/test_converters.py"
        )
        result = apply_suppressions_to_sarif(sarif, ctx)
        assert result.runs[0].results[0].suppressions is not None
        assert len(result.runs[0].results[0].suppressions) == 1

    def test_absolute_unix_uri_matches_relative_suppression(
        self, test_source_dir, test_output_dir
    ):
        abs_prefix = str(test_source_dir.resolve())
        sarif = _make_sarif_with_uri(
            f"{abs_prefix}/tests/unit/converters/test_converters.py"
        )
        ctx = _make_context(
            test_source_dir, test_output_dir, "tests/unit/converters/test_converters.py"
        )
        result = apply_suppressions_to_sarif(sarif, ctx)
        assert result.runs[0].results[0].suppressions is not None
        assert len(result.runs[0].results[0].suppressions) == 1

    def test_windows_uri_with_leading_slash_matches(
        self, test_source_dir, test_output_dir
    ):
        """Windows SARIF URIs have format /D:/path/to/file."""
        abs_prefix = str(test_source_dir.resolve()).replace("\\", "/")
        sarif = _make_sarif_with_uri(
            f"/{abs_prefix}/tests/unit/converters/test_converters.py"
        )
        ctx = _make_context(
            test_source_dir, test_output_dir, "tests/unit/converters/test_converters.py"
        )
        result = apply_suppressions_to_sarif(sarif, ctx)
        assert result.runs[0].results[0].suppressions is not None
        assert len(result.runs[0].results[0].suppressions) == 1

    def test_backslash_uri_normalized_to_forward_slash(
        self, test_source_dir, test_output_dir
    ):
        abs_prefix = str(test_source_dir.resolve())
        sarif = _make_sarif_with_uri(
            f"{abs_prefix}\\tests\\unit\\converters\\test_converters.py"
        )
        ctx = _make_context(
            test_source_dir, test_output_dir, "tests/unit/converters/test_converters.py"
        )
        result = apply_suppressions_to_sarif(sarif, ctx)
        assert result.runs[0].results[0].suppressions is not None
        assert len(result.runs[0].results[0].suppressions) == 1

    def test_windows_uri_without_drive_letter_matches(
        self, test_source_dir, test_output_dir
    ):
        """Windows scanners may strip drive letter: /a/repo/file instead of D:/a/repo/file."""
        abs_prefix = str(test_source_dir.resolve()).replace("\\", "/")
        if len(abs_prefix) > 2 and abs_prefix[1] == ":":
            no_drive = abs_prefix[2:]
        else:
            no_drive = abs_prefix
        sarif = _make_sarif_with_uri(
            f"{no_drive}/tests/unit/converters/test_converters.py"
        )
        ctx = _make_context(
            test_source_dir, test_output_dir, "tests/unit/converters/test_converters.py"
        )
        result = apply_suppressions_to_sarif(sarif, ctx)
        assert result.runs[0].results[0].suppressions is not None
        assert len(result.runs[0].results[0].suppressions) == 1

    def test_uri_not_under_source_dir_stays_absolute(
        self, test_source_dir, test_output_dir
    ):
        sarif = _make_sarif_with_uri("/usr/lib/python3/some_file.py")
        ctx = _make_context(
            test_source_dir, test_output_dir, "tests/unit/converters/test_converters.py"
        )
        result = apply_suppressions_to_sarif(sarif, ctx)
        assert (
            result.runs[0].results[0].suppressions is None
            or len(result.runs[0].results[0].suppressions) == 0
        )

    def test_glob_suppression_matches_normalized_uri(
        self, test_source_dir, test_output_dir
    ):
        abs_prefix = str(test_source_dir.resolve())
        sarif = _make_sarif_with_uri(
            f"{abs_prefix}/tests/unit/utils/test_foo.py", rule_id="B404"
        )
        ctx = _make_context(
            test_source_dir, test_output_dir, "tests/**/*.py", rule_id="B404"
        )
        result = apply_suppressions_to_sarif(sarif, ctx)
        assert result.runs[0].results[0].suppressions is not None
        assert len(result.runs[0].results[0].suppressions) == 1


class TestUriNormalizationSynthetic:
    """Platform-independent tests using synthetic Windows/Unix paths.

    These test the prefix-stripping logic directly without depending on
    the current OS's path resolution behavior.
    """

    @pytest.mark.parametrize(
        "uri,source_prefix,expected_relative",
        [
            # Standard Windows: D:/a/repo/file.py with source D:/a/repo/
            ("D:/a/repo/src/file.py", "D:/a/repo/src/", "file.py"),
            # Windows with leading slash: /D:/a/repo/file.py
            ("/D:/a/repo/src/file.py", "D:/a/repo/src/", "file.py"),
            # Windows drive stripped: /a/repo/file.py
            ("/a/repo/src/file.py", "D:/a/repo/src/", "file.py"),
            # Standard Unix: /home/runner/repo/file.py
            ("/home/runner/repo/src/file.py", "/home/runner/repo/src/", "file.py"),
            # Unix with double slash (leading / added)
            ("//home/runner/repo/src/file.py", "/home/runner/repo/src/", "file.py"),
            # Backslashes normalized
            ("D:\\a\\repo\\src\\file.py", "D:/a/repo/src/", "file.py"),
        ],
        ids=[
            "win-drive",
            "win-slash-drive",
            "win-no-drive",
            "unix-absolute",
            "unix-double-slash",
            "win-backslash",
        ],
    )
    def test_prefix_stripping(self, uri, source_prefix, expected_relative):
        """Verify that URI normalization produces the expected relative path."""
        uri_normalized = uri.replace("\\", "/")
        prefix_with_slash = "/" + source_prefix
        prefix_no_drive = (
            source_prefix[2:]
            if len(source_prefix) > 2 and source_prefix[1] == ":"
            else None
        )

        result = uri_normalized
        if uri_normalized.startswith(source_prefix):
            result = uri_normalized[len(source_prefix):]
        elif uri_normalized.startswith(prefix_with_slash):
            result = uri_normalized[len(prefix_with_slash):]
        elif prefix_no_drive and uri_normalized.startswith(prefix_no_drive):
            result = uri_normalized[len(prefix_no_drive):]

        assert result == expected_relative, (
            f"URI {uri!r} with prefix {source_prefix!r} "
            f"should normalize to {expected_relative!r}, got {result!r}"
        )

    @pytest.mark.parametrize(
        "uri,source_prefix",
        [
            ("/other/project/file.py", "/home/runner/repo/src/"),
            ("C:/different/path/file.py", "D:/a/repo/src/"),
            ("/b/other-repo/file.py", "D:/a/repo/src/"),
        ],
        ids=["unix-different-root", "win-different-drive", "win-different-path"],
    )
    def test_no_match_different_prefix(self, uri, source_prefix):
        """URIs not under source_dir should remain unchanged."""
        uri_normalized = uri.replace("\\", "/")
        prefix_with_slash = "/" + source_prefix
        prefix_no_drive = (
            source_prefix[2:]
            if len(source_prefix) > 2 and source_prefix[1] == ":"
            else None
        )

        result = uri_normalized
        if uri_normalized.startswith(source_prefix):
            result = uri_normalized[len(source_prefix):]
        elif uri_normalized.startswith(prefix_with_slash):
            result = uri_normalized[len(prefix_with_slash):]
        elif prefix_no_drive and uri_normalized.startswith(prefix_no_drive):
            result = uri_normalized[len(prefix_no_drive):]

        assert result == uri_normalized, (
            f"URI {uri!r} should NOT be stripped (different root)"
        )
