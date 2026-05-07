"""TDD test: ignore_paths with ** glob must drop findings in nested paths.

This test reproduces the bug where ignore_paths: "tests/test_data/**" fails
to drop checkov findings at paths like tests/test_data/scanners/cdk/foo.yaml
because path_matches_pattern uses fnmatch differently than the suppression
matcher's _recursive_glob_match.
"""

import pytest
from unittest.mock import MagicMock
from pathlib import Path

from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif
from automated_security_helper.schemas.sarif_schema_model import (
    SarifReport,
    Run,
    Result,
    Tool,
    ToolComponent,
    Location,
    PhysicalLocation,
    ArtifactLocation,
)
from automated_security_helper.models.core import IgnorePathWithReason


def _make_sarif_with_finding(uri: str, rule_id: str = "CKV_AWS_56") -> SarifReport:
    """Create a minimal SARIF report with one finding at the given URI."""
    location_dict = {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": 3},
        }
    }
    result_dict = {
        "ruleId": rule_id,
        "message": {"text": f"Finding {rule_id}"},
        "level": "warning",
        "locations": [location_dict],
    }
    run_dict = {
        "tool": {"driver": {"name": "checkov", "version": "3.2.0"}},
        "results": [result_dict],
    }
    return SarifReport(runs=[Run(**run_dict)])


def _make_plugin_context(
    ignore_paths: list[str],
    source_dir: str = "/src",
) -> MagicMock:
    """Create a mock PluginContext with the given ignore_paths."""
    ctx = MagicMock()
    ctx.source_dir = Path(source_dir)
    ctx.output_dir = Path("/out")
    ctx.ignore_suppressions = False
    ctx.config = MagicMock()
    ctx.config.global_settings = MagicMock()
    ctx.config.global_settings.ignore_paths = [
        IgnorePathWithReason(path=p, reason="test ignore")
        for p in ignore_paths
    ]
    ctx.config.global_settings.suppressions = []
    return ctx


class TestIgnorePathsGlobMatching:
    def test_double_star_drops_nested_finding(self):
        """tests/test_data/** must match tests/test_data/scanners/cdk/foo.yaml"""
        sarif = _make_sarif_with_finding(
            "tests/test_data/scanners/cdk/insecure-s3-template.yaml"
        )
        ctx = _make_plugin_context(["tests/test_data/**"])

        result = apply_suppressions_to_sarif(sarif, ctx)

        remaining = [r for run in result.runs for r in (run.results or [])]
        assert len(remaining) == 0, (
            f"Expected 0 findings after ignore_paths='tests/test_data/**', "
            f"got {len(remaining)}: {[r.ruleId for r in remaining]}"
        )

    def test_double_star_drops_deeply_nested_finding(self):
        """tests/test_data/** must match 3+ levels deep."""
        sarif = _make_sarif_with_finding(
            "tests/test_data/scanners/cdk/test.yaml_cdk_nag_results/cfn-and-python.json"
        )
        ctx = _make_plugin_context(["tests/test_data/**"])

        result = apply_suppressions_to_sarif(sarif, ctx)

        remaining = [r for run in result.runs for r in (run.results or [])]
        assert len(remaining) == 0

    def test_double_star_middle_pattern(self):
        """.github/**/*.yml must match .github/workflows/foo.yml"""
        sarif = _make_sarif_with_finding(
            ".github/workflows/run-ash-security-scan.yml",
            rule_id="yaml.github-actions.security.run-shell-injection",
        )
        ctx = _make_plugin_context([".github/**/*.yml"])

        result = apply_suppressions_to_sarif(sarif, ctx)

        remaining = [r for run in result.runs for r in (run.results or [])]
        assert len(remaining) == 0

    def test_non_matching_path_preserved(self):
        """A finding NOT in the ignore path should be preserved."""
        sarif = _make_sarif_with_finding("automated_security_helper/cli/scan.py")
        ctx = _make_plugin_context(["tests/test_data/**"])

        result = apply_suppressions_to_sarif(sarif, ctx)

        remaining = [r for run in result.runs for r in (run.results or [])]
        assert len(remaining) == 1
