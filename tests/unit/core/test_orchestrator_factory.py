"""TDD tests for ASHScanOrchestrator factory pattern (Track 3.1).

These tests verify:
- Constructor does NOT perform filesystem I/O
- .create() classmethod performs all setup that old model_post_init did
- .initialize() is idempotent
"""

from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.config.ash_config import AshConfig


def _minimal_kwargs(tmp_path):
    return dict(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        config_path=None,
        config_overrides=None,
        no_cleanup=False,
        metadata=None,
        ash_plugin_modules=[],
    )


class TestConstructorNoIO:
    """ASHScanOrchestrator(...) must not touch the filesystem."""

    def test_constructor_does_not_resolve_config(self, tmp_path):
        """Constructing the model raises no error even when resolve_config would fail."""
        kwargs = _minimal_kwargs(tmp_path)
        (tmp_path / "src").mkdir()

        with patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            side_effect=RuntimeError("resolve_config must not be called during construction"),
        ):
            # Should not raise — model_post_init no longer calls resolve_config
            orch = ASHScanOrchestrator(**kwargs)
            assert orch.source_dir == tmp_path / "src"

    def test_constructor_does_not_create_directories(self, tmp_path):
        """Constructing the model does not create .ash/ or any subdirectory."""
        kwargs = _minimal_kwargs(tmp_path)
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        # out does NOT exist — construction must not create it

        ASHScanOrchestrator(**kwargs)

        assert not out.exists(), ".ash output dir must not be created during construction"

    def test_constructor_does_not_instantiate_execution_engine(self, tmp_path):
        """After plain construction, execution_engine is None."""
        kwargs = _minimal_kwargs(tmp_path)
        (tmp_path / "src").mkdir()

        orch = ASHScanOrchestrator(**kwargs)

        assert orch.execution_engine is None

    def test_constructor_does_not_set_config(self, tmp_path):
        """After plain construction, config is None (not resolved)."""
        kwargs = _minimal_kwargs(tmp_path)
        (tmp_path / "src").mkdir()

        orch = ASHScanOrchestrator(**kwargs)

        assert orch.config is None


class TestCreateFactory:
    """ASHScanOrchestrator.create(...) must fully initialize the orchestrator."""

    def test_create_factory_resolves_config_and_creates_dirs(self, tmp_path):
        """.create() resolves config and creates output directories."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"

        with patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="test"),
        ):
            orch = ASHScanOrchestrator.create(
                source_dir=src,
                output_dir=out,
                config_path=None,
                config_overrides=None,
                no_cleanup=False,
                metadata=None,
                ash_plugin_modules=[],
            )

        assert orch.config is not None
        assert out.exists(), "output dir must exist after .create()"

    def test_create_factory_instantiates_execution_engine(self, tmp_path):
        """After .create(), execution_engine is not None."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"

        with patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="test"),
        ):
            orch = ASHScanOrchestrator.create(
                source_dir=src,
                output_dir=out,
                config_path=None,
                config_overrides=None,
                no_cleanup=False,
                metadata=None,
                ash_plugin_modules=[],
            )

        assert orch.execution_engine is not None

    def test_create_factory_sets_initialized_sentinel(self, tmp_path):
        """After .create(), _initialized sentinel is True."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"

        with patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="test"),
        ):
            orch = ASHScanOrchestrator.create(
                source_dir=src,
                output_dir=out,
                config_path=None,
                config_overrides=None,
                no_cleanup=False,
                metadata=None,
                ash_plugin_modules=[],
            )

        assert orch._initialized is True


class TestInitializeIdempotent:
    """initialize() called twice must not double-create resources."""

    def test_initialize_idempotent(self, tmp_path):
        """Calling .initialize() twice does not raise and does not re-run setup."""
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"

        call_count = {"n": 0}
        real_resolve = __import__(
            "automated_security_helper.config.resolve_config",
            fromlist=["resolve_config"],
        ).resolve_config

        def counting_resolve(*args, **kwargs):
            call_count["n"] += 1
            return AshConfig(project_name="test")

        with patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            side_effect=counting_resolve,
        ):
            orch = ASHScanOrchestrator(
                source_dir=src,
                output_dir=out,
                config_path=None,
                config_overrides=None,
                no_cleanup=False,
                metadata=None,
                ash_plugin_modules=[],
            )
            orch.initialize()
            first_engine = orch.execution_engine
            orch.initialize()  # second call — must be a no-op
            second_engine = orch.execution_engine

        assert call_count["n"] == 1, "resolve_config should only be called once"
        assert first_engine is second_engine, "execution_engine must not be replaced on second initialize()"
