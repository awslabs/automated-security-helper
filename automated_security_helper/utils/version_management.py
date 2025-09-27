"""
Version management utilities for Automated Security Helper.

This module provides utilities to manage version information dynamically
from pyproject.toml, ensuring a single source of truth.
"""

import toml
from pathlib import Path
from typing import Optional
import importlib.metadata


def get_project_root() -> Path:
    """Get the project root directory."""
    current_file = Path(__file__)
    # Go up from utils/version_management.py to project root
    return current_file.parent.parent.parent


def get_version_from_pyproject() -> Optional[str]:
    """
    Read version from pyproject.toml file.

    Returns:
        Version string if found, None otherwise.
    """
    try:
        project_root = get_project_root()
        pyproject_path = project_root / "pyproject.toml"

        if pyproject_path.exists():
            with open(pyproject_path, "r", encoding="utf-8") as f:
                pyproject_data = toml.load(f)
            return pyproject_data.get("project", {}).get("version")
        return None
    except Exception:
        return None


def get_version() -> str:
    """
    Get the current version of the package.

    Tries multiple methods in order:
    1. From pyproject.toml (for development - prioritized)
    2. From installed package metadata (for installed package)
    3. Fallback to "unknown" (should not happen in normal cases)

    Returns:
        Version string.
    """
    # Try to get version from pyproject.toml first (development priority)
    version = get_version_from_pyproject()
    if version:
        return version

    # Try to get version from installed package
    try:
        return importlib.metadata.version("automated_security_helper")
    except importlib.metadata.PackageNotFoundError:
        pass

    # Final fallback (should not happen in normal cases)
    return "unknown"


def update_version_in_pyproject(new_version: str) -> bool:
    """
    Update version in pyproject.toml file.

    Args:
        new_version: New version string to set.

    Returns:
        True if successful, False otherwise.
    """
    try:
        project_root = get_project_root()
        pyproject_path = project_root / "pyproject.toml"

        with open(pyproject_path, "r", encoding="utf-8") as f:
            pyproject_data = toml.load(f)

        if "project" not in pyproject_data:
            pyproject_data["project"] = {}

        pyproject_data["project"]["version"] = new_version

        with open(pyproject_path, "w", encoding="utf-8") as f:
            toml.dump(pyproject_data, f)

        return True
    except Exception:
        return False
