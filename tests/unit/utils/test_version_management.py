"""Tests for utils/version_management.py — covers version detection and update logic."""

from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from automated_security_helper.utils.version_management import (
    get_project_root,
    get_version_from_pyproject,
    get_version,
    update_version_in_pyproject,
)


class TestGetProjectRoot:
    """Tests for get_project_root."""

    def test_returns_path(self):
        root = get_project_root()
        assert isinstance(root, Path)

    def test_root_contains_pyproject(self):
        root = get_project_root()
        assert (root / "pyproject.toml").exists()


class TestGetVersionFromPyproject:
    """Tests for get_version_from_pyproject."""

    def test_returns_version_string(self):
        version = get_version_from_pyproject()
        assert version is not None
        assert isinstance(version, str)
        # Should be a semver-like string
        parts = version.split(".")
        assert len(parts) >= 2

    def test_returns_none_on_missing_file(self):
        with patch(
            "automated_security_helper.utils.version_management.get_project_root",
            return_value=Path("/nonexistent"),
        ):
            assert get_version_from_pyproject() is None

    def test_returns_none_on_exception(self):
        with patch(
            "automated_security_helper.utils.version_management.get_project_root",
            side_effect=RuntimeError("boom"),
        ):
            assert get_version_from_pyproject() is None


class TestGetVersion:
    """Tests for get_version."""

    def test_returns_version_string(self):
        version = get_version()
        assert version is not None
        assert version != "unknown"

    def test_fallback_to_pyproject(self):
        import importlib.metadata
        with patch(
            "automated_security_helper.utils.version_management.importlib.metadata.version",
            side_effect=importlib.metadata.PackageNotFoundError("not found"),
        ):
            version = get_version()
            # Should fallback to pyproject.toml which exists in this repo
            assert version is not None

    def test_fallback_to_unknown(self):
        import importlib.metadata
        with patch(
            "automated_security_helper.utils.version_management.importlib.metadata.version",
            side_effect=importlib.metadata.PackageNotFoundError("not found"),
        ), patch(
            "automated_security_helper.utils.version_management.get_version_from_pyproject",
            return_value=None,
        ):
            version = get_version()
            assert version == "unknown"


class TestUpdateVersionInPyproject:
    """Tests for update_version_in_pyproject."""

    def test_updates_version(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\nname = "test"\nversion = "1.0.0"\n')

        with patch(
            "automated_security_helper.utils.version_management.get_project_root",
            return_value=tmp_path,
        ):
            result = update_version_in_pyproject("2.0.0")
            assert result is True
            content = pyproject.read_text()
            assert '2.0.0' in content

    def test_returns_false_on_missing_version(self, tmp_path):
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text('[project]\nname = "test"\n')

        with patch(
            "automated_security_helper.utils.version_management.get_project_root",
            return_value=tmp_path,
        ):
            result = update_version_in_pyproject("2.0.0")
            assert result is False

    def test_returns_false_on_exception(self):
        with patch(
            "automated_security_helper.utils.version_management.get_project_root",
            side_effect=RuntimeError("boom"),
        ):
            result = update_version_in_pyproject("2.0.0")
            assert result is False
