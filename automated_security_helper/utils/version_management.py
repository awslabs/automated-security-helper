"""
Version management utilities for Automated Security Helper.

This module provides utilities to manage version information dynamically
from pyproject.toml, ensuring a single source of truth.
"""

import re
import sys
from pathlib import Path
from typing import Optional, Tuple
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

#: The distribution name pyproject.toml declares. A pyproject.toml found beside
#: the package is this project's only when its [project] name is this one.
DISTRIBUTION_NAME = "automated-security-helper"

#: The two tables of pyproject.toml that carry the release number: [project],
#: which the build reads, and [tool.commitizen], which the release bump reads and
#: writes. A set that moved one and not the other left the file disagreeing with
#: itself, and the next commitizen bump started from the stale one.
VERSION_TABLES: Tuple[str, ...] = ("project", "tool.commitizen")

# The package directory these modules live in, for telling the installed
# distribution that owns them from another one on sys.path.
_PACKAGE_DIR = Path(__file__).resolve().parent.parent


def _load_toml(path: Path) -> dict:
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def get_project_root() -> Path:
    """Get the project root directory."""
    current_file = Path(__file__)
    # Go up from utils/version_management.py to project root
    return current_file.parent.parent.parent


def _resolve_project_root(project_root: Optional[Path]) -> Path:
    return Path(project_root) if project_root is not None else get_project_root()


def _normalized_name(name: object) -> Optional[str]:
    """A distribution name as PEP 503 compares it, or None for a non-string."""
    if not isinstance(name, str):
        return None
    return re.sub(r"[-_.]+", "-", name).lower()


def get_version_from_pyproject(project_root: Optional[Path] = None) -> Optional[str]:
    """
    Read version from pyproject.toml file.

    Args:
        project_root: The checkout to read; this module's own by default.

    Returns:
        Version string if found, None otherwise. A pyproject.toml whose [project]
        name is not this distribution's is some other project's file at that
        path, not a version of ASH, so it reads as None too.
    """
    try:
        pyproject_path = _resolve_project_root(project_root) / "pyproject.toml"

        if pyproject_path.exists():
            project = _load_toml(pyproject_path).get("project", {})
            if _normalized_name(project.get("name")) != DISTRIBUTION_NAME:
                return None
            version = project.get("version")
            return version if isinstance(version, str) else None
        return None
    except Exception:
        return None


def _owns_this_module(distribution: importlib.metadata.Distribution) -> bool:
    """Whether ``distribution`` installed the package this module is part of."""
    try:
        installed = Path(
            str(distribution.locate_file("automated_security_helper"))
        ).resolve()
    except Exception:
        return False
    return installed == _PACKAGE_DIR


def _installed_version() -> Optional[str]:
    """The version of the installed distribution these modules belong to.

    importlib.metadata.version() answers for the first distribution of the name
    on sys.path, which is not always the one that was imported: with two
    installs visible (a user site and a virtualenv, say) ``--version`` named the
    other one. So the distribution whose files are this package is preferred,
    and the first by name is the fallback, for an editable install whose
    dist-info points nowhere on disk.
    """
    try:
        for distribution in importlib.metadata.distributions(name=DISTRIBUTION_NAME):
            if _owns_this_module(distribution):
                return distribution.version
    except Exception:
        pass
    try:
        return importlib.metadata.version(DISTRIBUTION_NAME)
    except importlib.metadata.PackageNotFoundError:
        return None


def get_version(project_root: Optional[Path] = None) -> str:
    """
    Get the current version of the package.

    Tries multiple methods in order:
    1. From the checkout's pyproject.toml, when this module is imported from one
       (a bare checkout or an editable install). The file moves with the tree;
       installed metadata moves only when the package is reinstalled, so after
       `version_bump.py set` the metadata still named the old version and the
       docs were regenerated with it, and a second `bump` computed from the stale
       base and wrote the old version back.
    2. From the installed distribution's metadata (a regular install, which has
       no pyproject.toml beside the package).
    3. Fallback to "unknown" (should not happen in normal cases)

    Args:
        project_root: The checkout whose pyproject.toml is read first; this
            module's own by default.

    Returns:
        Version string.
    """
    version = get_version_from_pyproject(project_root)
    if version:
        return version

    version = _installed_version()
    if version:
        return version

    return "unknown"


def _replace_table_version(
    content: str, table: str, new_version: str
) -> Tuple[str, bool]:
    """``content`` with the ``version = "..."`` key of ``[table]`` set to new_version.

    Only the key inside that table: a `version` key of another table, or a
    dependency's inline-table `{version = "..."}`, is left as it is.
    """
    header = re.compile(rf"^\[{re.escape(table)}\]\s*$", re.MULTILINE)
    start = header.search(content)
    if start is None:
        return content, False
    next_header = re.compile(r"^\[", re.MULTILINE).search(content, start.end())
    end = next_header.start() if next_header else len(content)
    key = re.compile(r'^(\s*version\s*=\s*")([^"]+)(")', re.MULTILINE)
    body, replaced = key.subn(
        lambda m: f"{m.group(1)}{new_version}{m.group(3)}",
        content[start.end() : end],
        count=1,
    )
    return content[: start.end()] + body + content[end:], replaced == 1


def update_version_in_pyproject(
    new_version: str, project_root: Optional[Path] = None
) -> bool:
    """
    Update version in pyproject.toml file.

    Sets ``[project] version`` and, when the table exists, ``[tool.commitizen]
    version`` to the same value. The file is replaced atomically: the new text is
    written beside it and renamed over it, so a write that fails leaves the old
    file in place instead of a truncated one.

    Args:
        new_version: New version string to set.
        project_root: The checkout whose pyproject.toml is edited; this module's
            own by default.

    Returns:
        True if successful, False otherwise.
    """
    try:
        pyproject_path = _resolve_project_root(project_root) / "pyproject.toml"

        # Read the file as text to preserve formatting
        with open(pyproject_path, "r", encoding="utf-8") as f:
            content = f.read()

        new_content, replaced = _replace_table_version(
            content, VERSION_TABLES[0], new_version
        )
        if not replaced:
            return False
        for table in VERSION_TABLES[1:]:
            new_content, _ = _replace_table_version(new_content, table, new_version)

        _replace_file_text(pyproject_path, new_content)

        return True
    except Exception:
        return False


def _replace_file_text(path: Path, text: str) -> None:
    """Write ``text`` to a staging file beside ``path`` and rename it over ``path``.

    Through the project's own atomic-write helper, the one every other writer in
    the package uses and the fs_guard inventory test admits: a staging file created
    exclusively in the target's directory with the mode a plain open gives, renamed
    over the target when the write completes and removed when it does not.
    """
    # Not at the top: atomic_write reaches fs_guard, which imports the sandbox
    # package, and this module is imported by the package __init__.
    from automated_security_helper.utils.atomic_write import write_text_atomically

    write_text_atomically(path, text)
