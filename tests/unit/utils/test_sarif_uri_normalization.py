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
