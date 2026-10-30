#!/usr/bin/env python3
"""
Version Bump Script for Automated Security Helper.

This script provides automated version bumping capabilities with
template regeneration to ensure all version references are updated.
"""

import argparse
import sys
from pathlib import Path
from typing import Tuple

from packaging.version import InvalidVersion, Version

# Add the project root to the path so we can import our version management
sys.path.insert(0, str(Path(__file__).parent.parent))

from automated_security_helper.utils.version_management import (
    get_version,
    get_version_from_pyproject,
    update_version_in_pyproject,
)
from scripts.version_template_manager import VersionTemplateManager


def _read_version(version: str) -> Version:
    """``version`` read as PEP 440, limited to the shape ASH releases use.

    The release segment has exactly three numbers and there is no epoch. The
    grammar is PEP 440's, the one pip, hatch and importlib.metadata share, so a
    version read back from the installed distribution (3.8.0rc1, 3.8.0.dev1) parses
    and a hyphen followed by arbitrary text does not.
    """
    try:
        parsed = Version(version)
    except InvalidVersion:
        raise ValueError(f"Invalid version format: {version}") from None
    if parsed.epoch or len(parsed.release) != 3:
        raise ValueError(f"Invalid version format: {version}")
    return parsed


def parse_version(version: str) -> Tuple[int, int, int]:
    """Parse a PEP 440 version string into major, minor, patch components.

    Only the release numbers are returned; a pre-release, post-release or
    development part is not.
    """
    major, minor, patch = _read_version(version).release
    return major, minor, patch


def format_version(major: int, minor: int, patch: int) -> str:
    """Format version components into a semantic version string."""
    return f"{major}.{minor}.{patch}"


def bump_version(current_version: str, bump_type: str) -> str:
    """
    Bump version based on type (major, minor, patch).

    Args:
        current_version: Current version string
        bump_type: Type of bump (major, minor, patch)

    Returns:
        New version string
    """
    major, minor, patch = parse_version(current_version)

    if bump_type == "major":
        major += 1
        minor = 0
        patch = 0
    elif bump_type == "minor":
        minor += 1
        patch = 0
    elif bump_type == "patch":
        patch += 1
    else:
        raise ValueError(f"Invalid bump type: {bump_type}")

    return format_version(major, minor, patch)


def validate_version(version: str) -> bool:
    """Whether ``version`` is a version ``set`` may write into pyproject.toml.

    It must be PEP 440 as three release numbers, spelled the way pip prints it
    (3.8.0rc1, not 3.8.0-rc1), with no local part. What is written is then what
    importlib.metadata reports for the built distribution, and nothing a TOML
    string cannot hold (a quote, a newline) gets through.
    """
    try:
        parsed = _read_version(version)
    except ValueError:
        return False
    return parsed.local is None and str(parsed) == version


class VersionBumper:
    """Handles version bumping and template regeneration."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.template_manager = VersionTemplateManager(project_root)

    def get_current_version(self) -> str:
        """The version of the checkout at project_root, from its pyproject.toml.

        Read from that tree and not from the installed distribution: after a set
        the metadata still names the version installed, so a bump computed from
        it repeated or reverted the set, and the docs were regenerated with it.
        """
        return get_version(self.project_root)

    def set_version(self, new_version: str) -> bool:
        """
        Set a new version and regenerate all templates.

        Args:
            new_version: New version string to set

        Returns:
            True if successful
        """
        if not validate_version(new_version):
            print(
                f"Error: Invalid version format: {new_version} (expected PEP 440 "
                "with three release numbers, spelled as pip prints it: 3.1.0, "
                "3.1.0rc1, 3.1.0.post1 or 3.1.0.dev1)"
            )
            return False

        current_version = self.get_current_version()
        print(f"Current version: {current_version}")
        print(f"New version: {new_version}")

        # Update version in the pyproject.toml of the same checkout whose
        # templates are regenerated below; --project-root selects both.
        if not update_version_in_pyproject(new_version, self.project_root):
            print("Error: Failed to update version in pyproject.toml")
            return False

        print("Updated pyproject.toml")

        # Regenerate documentation from templates. A template that fails to
        # render is a failure of the set: generate_from_template reports it and
        # returns False, so a count short of the targets means a doc still
        # carries the old version, and saying "successfully updated" over it is
        # how a half-applied bump reached a release. The count is compared with
        # every target the manager lists, not with the templates that exist: a
        # target whose template is missing is skipped with a warning, and
        # measured against the templates alone that skip was invisible, so the
        # set printed success while the target's page kept the release it was
        # written at.
        targets = self.template_manager.target_files
        try:
            generated_count = self.template_manager.generate_all_from_templates()
        except Exception as e:
            print(f"Error: Failed to regenerate templates: {e}")
            return False
        print(f"Regenerated {generated_count} documentation files from templates")
        if generated_count < len(targets):
            print(
                f"Error: {len(targets) - generated_count} of {len(targets)} "
                "targets were not regenerated; see the messages above"
            )
            return False

        print(f"Successfully updated version to {new_version}")
        return True

    def bump_version(self, bump_type: str) -> bool:
        """
        Bump version and regenerate all templates.

        Args:
            bump_type: Type of version bump (major, minor, patch)

        Returns:
            True if successful
        """
        current_version = self.get_current_version()
        try:
            new_version = bump_version(current_version, bump_type)
        except ValueError as e:
            print(f"Error: {e}")
            return False

        current = Version(current_version)
        if current.is_prerelease or current.is_postrelease or current.is_devrelease:
            # Only the release numbers are counted; say so instead of dropping
            # the pre-release, post-release or development part silently.
            print(
                f"Note: {current_version} is not a final release. The {bump_type} "
                "bump counts from its release numbers alone, so that part is "
                f"dropped and {new_version} follows."
            )

        return self.set_version(new_version)

    def validate_consistency(self) -> bool:
        """
        Validate that all version references are consistent.

        Three things are compared, none of them with the installed distribution:
        ``[project] version`` with ``[tool.commitizen] version`` in the
        pyproject.toml at the project root, and each generated page with its
        template rendered for that version (what ``set`` would write now).

        Returns:
            True if all versions are consistent
        """
        print("Validating version consistency...")

        # The pyproject.toml itself, not get_current_version(): that falls back to
        # the installed metadata when the file is missing or is another project's,
        # and the label below would then name a file nothing was read from.
        current_version = get_version_from_pyproject(self.project_root)
        if current_version is None:
            print(
                "Error: no pyproject.toml of automated-security-helper with a "
                f"version at {self.project_root}"
            )
            return False
        print(f"Current version from pyproject.toml: {current_version}")

        consistent = True

        try:
            released = self.template_manager.packaged_release()
        except KeyError:
            released = None  # no [tool.commitizen] version to compare
        if released is not None and released != current_version:
            print(
                f"Error: [tool.commitizen] version is {released} but "
                f"[project] version is {current_version}"
            )
            consistent = False

        templates = self.template_manager.list_templates()
        if not templates:
            print("Warning: No template files found. Run 'convert' first.")
            return False

        suffix = self.template_manager.template_suffix
        for template in templates:
            target = template.parent / template.name[: -len(suffix)]
            expected = self.template_manager.render(
                template.read_text(encoding="utf-8"), current_version
            )
            try:
                actual = target.read_text(encoding="utf-8")
            except FileNotFoundError:
                print(f"Error: {target} does not exist; generate it from {template}")
                consistent = False
                continue
            if actual != expected:
                print(
                    f"Error: {target} is not its template rendered for "
                    f"{current_version}; run 'set {current_version}' to regenerate it"
                )
                consistent = False

        print(f"Found {len(templates)} template files")
        if not consistent:
            print("Version consistency validation failed")
            return False
        print("Version consistency validation passed")

        return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Version management for Automated Security Helper"
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).parent.parent,
        help="Path to project root directory",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Current version command
    subparsers.add_parser("current", help="Show current version")

    # Set version command
    set_parser = subparsers.add_parser("set", help="Set specific version")
    set_parser.add_argument(
        "version", help="Version to set, PEP 440 (e.g., 3.1.0 or 3.1.0rc1)"
    )

    # Bump version commands
    bump_parser = subparsers.add_parser("bump", help="Bump version")
    bump_parser.add_argument(
        "type", choices=["major", "minor", "patch"], help="Type of version bump"
    )

    # Validate command
    subparsers.add_parser("validate", help="Validate version consistency")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    bumper = VersionBumper(args.project_root)

    if args.command == "current":
        current_version = bumper.get_current_version()
        print(f"Current version: {current_version}")
        return 0

    elif args.command == "set":
        if bumper.set_version(args.version):
            return 0
        return 1

    elif args.command == "bump":
        if bumper.bump_version(args.type):
            return 0
        return 1

    elif args.command == "validate":
        if bumper.validate_consistency():
            return 0
        return 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
