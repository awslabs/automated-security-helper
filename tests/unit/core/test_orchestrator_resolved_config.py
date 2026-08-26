"""Tests for handing ASHScanOrchestrator a configuration that is already resolved.

``initialize()`` called ``resolve_config()`` unconditionally and assigned the
result over ``self.config``, so a caller that had already resolved and merged a
configuration had no way to hand it in — the orchestrator threw it away and
re-read from disk. ``resolved_config`` is the way in.

These tests pin three things: the supplied configuration is the one that reaches
the execution engine, the default path still resolves for every caller that does
not opt in, and supplying both a resolved configuration and the inputs to
resolution is refused rather than silently half-honoured.
"""

from unittest.mock import patch

import pytest
from pydantic import ValidationError

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.orchestrator import ASHScanOrchestrator


def _dirs(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    return src, tmp_path / "out"


class TestResolvedConfigIsUsedAsIs:
    """A caller-supplied configuration must survive initialize() untouched."""

    def test_initialize_does_not_re_resolve(self, tmp_path):
        src, out = _dirs(tmp_path)
        supplied = AshConfig(project_name="supplied-by-caller")

        with patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="re-resolved-from-disk"),
        ) as mock_resolve:
            orch = ASHScanOrchestrator.create(
                source_dir=src,
                output_dir=out,
                resolved_config=supplied,
                no_cleanup=False,
                metadata=None,
                ash_plugin_modules=[],
            )

        assert mock_resolve.call_count == 0, (
            "resolve_config must not run when the caller supplied a resolved config"
        )
        assert orch.config is supplied
        assert orch.config.project_name == "supplied-by-caller"

    def test_resolved_config_reaches_the_execution_engine(self, tmp_path):
        """Storing it on the model is not enough — the engine must see it."""
        src, out = _dirs(tmp_path)
        supplied = AshConfig(project_name="supplied-by-caller")

        with patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="re-resolved-from-disk"),
        ):
            orch = ASHScanOrchestrator.create(
                source_dir=src,
                output_dir=out,
                resolved_config=supplied,
                no_cleanup=False,
                metadata=None,
                ash_plugin_modules=[],
            )

        assert orch.execution_engine is not None
        assert orch.execution_engine._context.config is supplied


class TestDefaultPathUnchanged:
    """Callers that do not opt in keep resolving exactly as before."""

    def test_initialize_still_resolves_when_not_supplied(self, tmp_path):
        src, out = _dirs(tmp_path)

        with patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="re-resolved-from-disk"),
        ) as mock_resolve:
            orch = ASHScanOrchestrator.create(
                source_dir=src,
                output_dir=out,
                config_path=None,
                config_overrides=None,
                no_cleanup=False,
                metadata=None,
                ash_plugin_modules=[],
            )

        assert mock_resolve.call_count == 1
        assert orch.config.project_name == "re-resolved-from-disk"

    def test_config_path_and_overrides_are_forwarded_to_resolution(self, tmp_path):
        """The resolution inputs must still arrive at resolve_config verbatim."""
        src, out = _dirs(tmp_path)
        config_file = tmp_path / "ash.yaml"
        config_file.write_text("project_name: from-file\n", encoding="utf-8")

        with patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="re-resolved-from-disk"),
        ) as mock_resolve:
            ASHScanOrchestrator.create(
                source_dir=src,
                output_dir=out,
                config_path=config_file,
                config_overrides=["global_settings.severity_threshold=LOW"],
                no_cleanup=False,
                metadata=None,
                ash_plugin_modules=[],
            )

        kwargs = mock_resolve.call_args.kwargs
        assert kwargs["config_path"] == config_file
        assert kwargs["config_overrides"] == ["global_settings.severity_threshold=LOW"]


class TestConflictingConfigInputsRefused:
    """resolved_config plus the inputs to resolution is a contradiction."""

    def test_resolved_config_with_config_path_is_refused(self, tmp_path):
        src, out = _dirs(tmp_path)

        with pytest.raises(ValidationError, match="resolved_config"):
            ASHScanOrchestrator(
                source_dir=src,
                output_dir=out,
                resolved_config=AshConfig(project_name="supplied-by-caller"),
                config_path=tmp_path / "ash.yaml",
                no_cleanup=False,
                metadata=None,
                ash_plugin_modules=[],
            )

    def test_resolved_config_with_config_overrides_is_refused(self, tmp_path):
        src, out = _dirs(tmp_path)

        with pytest.raises(ValidationError, match="config_overrides"):
            ASHScanOrchestrator(
                source_dir=src,
                output_dir=out,
                resolved_config=AshConfig(project_name="supplied-by-caller"),
                config_overrides=["global_settings.severity_threshold=LOW"],
                no_cleanup=False,
                metadata=None,
                ash_plugin_modules=[],
            )

    def test_empty_resolution_inputs_are_not_a_conflict(self, tmp_path):
        """run_ash_scan passes ``config_overrides or []`` — an empty list is fine."""
        src, out = _dirs(tmp_path)
        supplied = AshConfig(project_name="supplied-by-caller")

        orch = ASHScanOrchestrator(
            source_dir=src,
            output_dir=out,
            resolved_config=supplied,
            config_path=None,
            config_overrides=[],
            no_cleanup=False,
            metadata=None,
            ash_plugin_modules=[],
        )

        assert orch.resolved_config is supplied
