# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for model cleanup refactors: PrivateAttr, PluginContext validator, dedup."""

from pathlib import Path

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugins.plugin_manager import AshPluginManager


class TestAshPluginManagerPrivateAttr:
    """Tests for _resolved_plugins as a proper PrivateAttr."""

    def test_resolved_plugins_is_dict(self):
        """_resolved_plugins should still be a dict usable at runtime."""
        manager = AshPluginManager()
        assert isinstance(manager._resolved_plugins, dict)

    def test_resolved_plugins_default_is_empty(self):
        """_resolved_plugins should default to an empty dict."""
        manager = AshPluginManager()
        assert manager._resolved_plugins == {}

    def test_resolved_plugins_not_in_model_dump(self):
        """Private attrs must not appear in model_dump output."""
        manager = AshPluginManager()
        dumped = manager.model_dump()
        assert "_resolved_plugins" not in dumped

    def test_resolved_plugins_independent_per_instance(self):
        """default_factory must give each instance its own dict (not shared state)."""
        a = AshPluginManager()
        b = AshPluginManager()
        a._resolved_plugins["foo"] = "bar"
        assert "foo" not in b._resolved_plugins


class TestAshConfigPrivateAttr:
    """Tests for _resolution_warnings as a proper PrivateAttr."""

    def test_resolution_warnings_is_list(self):
        from automated_security_helper.config.ash_config import AshConfig

        config = AshConfig()
        assert isinstance(config._resolution_warnings, list)

    def test_resolution_warnings_not_in_model_dump(self):
        from automated_security_helper.config.ash_config import AshConfig

        config = AshConfig()
        dumped = config.model_dump()
        assert "_resolution_warnings" not in dumped

    def test_resolution_warnings_independent_per_instance(self):
        from automated_security_helper.config.ash_config import AshConfig

        a = AshConfig()
        b = AshConfig()
        a._resolution_warnings.append("warn")
        assert b._resolution_warnings == []


class TestPluginContextWorkDir:
    """Tests for PluginContext.work_dir derivation via model_validator."""

    def test_work_dir_derived_when_none(self, tmp_path):
        """When work_dir is not passed, derive from output_dir / ASH_WORK_DIR_NAME."""
        out = tmp_path / "out"
        src = tmp_path / "src"
        ctx = PluginContext(output_dir=out, source_dir=src)
        assert ctx.work_dir is not None

    def test_work_dir_equals_output_dir_joined_with_constant(self, tmp_path):
        """work_dir should equal output_dir / ASH_WORK_DIR_NAME."""
        out = tmp_path / "out"
        src = tmp_path / "src"
        ctx = PluginContext(output_dir=out, source_dir=src)
        assert ctx.work_dir == out / ASH_WORK_DIR_NAME

    def test_work_dir_explicit_preserved(self, tmp_path):
        """An explicitly provided work_dir should be preserved."""
        out = tmp_path / "out"
        src = tmp_path / "src"
        explicit = tmp_path / "elsewhere"
        ctx = PluginContext(output_dir=out, source_dir=src, work_dir=explicit)
        assert ctx.work_dir == Path(explicit)


class TestPopulateSummaryStatsDedup:
    """Verify the duplicate method on AshAggregatedResults was removed."""

    def test_method_removed_from_model(self):
        """_populate_summary_stats_from_unified_metrics should no longer exist on the model."""
        assert not hasattr(
            AshAggregatedResults, "_populate_summary_stats_from_unified_metrics"
        )

    def test_module_function_still_exists(self):
        """The canonical module-level function should still be importable."""
        from automated_security_helper.core.unified_metrics import (
            _populate_summary_stats_from_unified_metrics,
        )

        assert callable(_populate_summary_stats_from_unified_metrics)
