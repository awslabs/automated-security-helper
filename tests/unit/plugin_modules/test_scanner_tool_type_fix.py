# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression test: scanners must use ScannerToolType enum, not raw strings.

Grype was previously classified as SAST; it should be SCA.
This test also verifies that the enum members behave as expected.
"""

import pytest
from unittest.mock import MagicMock

from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig

# Rebuild models to resolve forward references
AshConfig.model_rebuild()


@pytest.fixture
def _mock_context(tmp_path):
    ctx = MagicMock(spec=PluginContext)
    ctx.source_dir = tmp_path / "src"
    ctx.output_dir = tmp_path / "out"
    ctx.source_dir.mkdir()
    ctx.output_dir.mkdir()
    ctx.global_ignore_paths = []
    return ctx


@pytest.mark.unit
class TestScannerToolTypeEnum:
    """Guard enum semantics so downstream code can safely compare values."""

    def test_sast_value(self):
        assert ScannerToolType.SAST.value == "SAST"

    def test_sca_value(self):
        assert ScannerToolType.SCA.value == "SCA"

    def test_enum_equality_with_string(self):
        """ScannerToolType extends str, so 'SAST' == ScannerToolType.SAST."""
        assert ScannerToolType.SAST == "SAST"
        assert ScannerToolType.SCA == "SCA"

    def test_enum_identity_preferred(self):
        """Prefer identity checks when both sides are enum members."""
        assert ScannerToolType.SAST is ScannerToolType.SAST
        assert ScannerToolType.SCA is not ScannerToolType.SAST


@pytest.mark.unit
class TestGrypeIsSCA:
    """Grype is a Software Composition Analysis tool, not SAST."""

    def test_grype_tool_type(self, _mock_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
            GrypeScanner,
        )

        scanner = GrypeScanner(context=_mock_context)
        assert scanner.tool_type == ScannerToolType.SCA
        assert scanner.tool_type is ScannerToolType.SCA

    def test_grype_is_not_sast(self, _mock_context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
            GrypeScanner,
        )

        scanner = GrypeScanner(context=_mock_context)
        assert scanner.tool_type is not ScannerToolType.SAST


@pytest.mark.unit
class TestTrivyToolType:
    """Trivy repo scanner should be classified as SAST."""

    def test_trivy_repo_scanner_is_sast(self, _mock_context):
        from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
            TrivyRepoScanner,
        )

        scanner = TrivyRepoScanner(context=_mock_context)
        assert scanner.tool_type == ScannerToolType.SAST
        assert scanner.tool_type is ScannerToolType.SAST
