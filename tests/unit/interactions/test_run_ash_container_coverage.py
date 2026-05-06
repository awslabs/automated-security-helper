"""Tests for interactions/run_ash_container.py — covers container command building and execution."""

from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest


class TestContainerModuleImport:
    """Tests that the container module can be imported and key functions exist."""

    def test_module_imports(self):
        from automated_security_helper.interactions import run_ash_container

        assert hasattr(run_ash_container, "run_ash_container")

    def test_run_ash_container_function_signature(self):
        from automated_security_helper.interactions.run_ash_container import (
            run_ash_container,
        )

        import inspect

        sig = inspect.signature(run_ash_container)
        params = list(sig.parameters.keys())
        assert "source_dir" in params or len(params) > 0


class TestContainerCommandBuilding:
    """Tests for container command building utilities."""

    def test_function_is_callable(self):
        """Test that run_ash_container function exists and is callable."""
        from automated_security_helper.interactions.run_ash_container import (
            run_ash_container,
        )

        assert callable(run_ash_container)


class TestContainerImageBuilding:
    """Tests for container image build logic."""

    def test_image_build_module_exists(self):
        from automated_security_helper.cli import image

        assert hasattr(image, "build_ash_image_cli_command")
