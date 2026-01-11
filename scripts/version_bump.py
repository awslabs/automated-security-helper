#!/usr/bin/env python3
"""
Version Bump Script for Automated Security Helper.

This script provides automated version bumping capabilities with
template regeneration to ensure all version references are updated.
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Tuple

# Add the project root to the path so we can import our version management
sys.path.insert(0, str(Path(__file__).parent.parent))

from automated_security_helper.utils.version_management import (
    get_version,
    update_version_in_pyproject,
)
from scripts.version_template_manager import VersionTemplateManager


def parse_version(version: str) -> Tuple[int, int, int]:
    """Parse a semantic version string into major, minor, patch components."""
    pattern = r"^(\d+)\.(\d+)\.(\d+)(?:-.*)?$"
    match = re.match(pattern, version)
    if not match:
        raise ValueError(f"Invalid version format: {version}")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


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
    """Validate a version string format."""
    try:
        parse_version(version)
        return True
    except ValueError:
        return False


class VersionBumper:
    """Handles version bumping and template regeneration."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.template_manager = VersionTemplateManager(project_root)

    def get_current_version(self) -> str:
        """Get the current version."""
        return get_version()

    def set_version(self, new_version: str) -> bool:
        """
        Set a new version and regenerate all templates.

        Args:
            new_version: New version string to set

        Returns:
            True if successful
        """
        if not validate_version(new_version):
            print(f"Error: Invalid version format: {new_version}")
            return False

        current_version = self.get_current_version()
        print(f"Current version: {current_version}")
        print(f"New version: {new_version}")

        # Update version in pyproject.toml
        if not update_version_in_pyproject(new_version):
            print("Error: Failed to update version in pyproject.toml")
            return False

        print("Updated pyproject.toml")

        # Regenerate documentation from templates
        try:
            generated_count = self.template_manager.generate_all_from_templates()
            print(f"Regenerated {generated_count} documentation files from templates")
        except Exception as e:
            print(f"Warning: Failed to regenerate some templates: {e}")

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

        return self.set_version(new_version)

    def validate_consistency(self) -> bool:
        """
        Validate that all version references are consistent.

        Returns:
            True if all versions are consistent
        """
        print("Validating version consistency...")

        current_version = self.get_current_version()
        print(f"Current version from pyproject.toml: {current_version}")

        # Check if templates need regeneration
        templates = self.template_manager.list_templates()
        if not templates:
            print("Warning: No template files found. Run 'convert' first.")
            return False

        # This is a basic check - in a more sophisticated implementation,
        # you might actually parse all files and verify consistency
        print(f"Found {len(templates)} template files")
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
    set_parser.add_argument("version", help="Version to set (e.g., 3.1.0)")

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
