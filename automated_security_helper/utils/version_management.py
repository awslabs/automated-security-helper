"""
Version management utilities for Automated Security Helper.

This module provides utilities to manage version information dynamically
from pyproject.toml, ensuring a single source of truth.
"""

import re
import sys
from pathlib import Path
from typing import Optional
import importlib.metadata

# tomllib is stdlib only from Python 3.11. pyproject.toml declares
# requires-python = ">=3.10", and this module is imported by the package
# __init__, so an unconditional "import tomllib" makes the whole package
# unimportable on 3.10. There it uses tomli, which pyproject.toml declares for
# Python below 3.11, held below 2.4. tomllib was taken from tomli, and up to 2.3
# tomli reads the same TOML 1.0; 2.4 added TOML 1.1 (a trailing comma in an
# inline table, `\e`), which tomllib on 3.11-3.14 and the image's Python refuse.
# With 2.4, a pyproject.toml that only TOML 1.1 reads was ASH's to the CLI on
# 3.10 and to nothing else. It used `toml` 0.10, which implements TOML 0.5 and
# refuses valid TOML 1.0 such as an array of mixed types, so on 3.10 the CLI
# could call a tree "not ASH" that the image's clone step, on Python 3.12,
# called ASH's.
#
# Chosen by version, not by catching the failed import: mypy reads a
# sys.version_info test and checks only the branch for the Python it targets,
# while a try/except import made it report the tomli import as missing, and
# tomllib as defined twice, on 3.11 and later.
if sys.version_info >= (3, 11):  # pragma: no cover - depends on the interpreter
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib


def _load_toml(path: Path) -> dict:
    with open(path, "rb") as fh:
        return tomllib.load(fh)


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
            pyproject_data = _load_toml(pyproject_path)
            return pyproject_data.get("project", {}).get("version")
        return None
    except Exception:
        return None


def get_version() -> str:
    """
    Get the current version of the package.

    Tries multiple methods in order:
    1. From installed package metadata (works for pip install and editable installs)
    2. From pyproject.toml (fallback for bare-checkout development)
    3. Fallback to "unknown" (should not happen in normal cases)

    Returns:
        Version string.
    """
    # Prefer importlib.metadata -- works for both regular and editable installs
    try:
        return importlib.metadata.version("automated_security_helper")
    except importlib.metadata.PackageNotFoundError:
        pass

    # Fallback to pyproject.toml for bare-checkout development
    version = get_version_from_pyproject()
    if version:
        return version

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

        # Read the file as text to preserve formatting
        with open(pyproject_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Replace version using regex to preserve formatting
        pattern = r'(version\s*=\s*")([^"]+)(")'
        match = re.search(pattern, content)

        if not match:
            return False

        new_content = re.sub(pattern, rf"\g<1>{new_version}\g<3>", content, count=1)

        # Write back
        with open(pyproject_path, "w", encoding="utf-8") as f:
            f.write(new_content)

        return True
    except Exception:
        return False
