#!/usr/bin/env python3
"""
Build Integration Script for Automated Security Helper.

This script integrates version management into the build process,
ensuring all documentation is generated from templates before builds.
"""

import sys
import subprocess
from pathlib import Path
from typing import List, Optional

# Add the project root to the path so we can import our version management
sys.path.insert(0, str(Path(__file__).parent.parent))

from automated_security_helper.utils.version_management import get_version
from scripts.version_template_manager import VersionTemplateManager


class BuildIntegrator:
    """Handles build-time version management integration."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.template_manager = VersionTemplateManager(project_root)

    def pre_build_check(self) -> bool:
        """
        Pre-build checks and template generation.

        Returns:
            True if all checks pass and templates are generated successfully
        """
        print("Running pre-build version management checks...")

        # Check that pyproject.toml exists and has version
        current_version = get_version()
        if current_version == "unknown":
            print("Error: Could not determine version from pyproject.toml")
            return False

        print(f"Current version: {current_version}")

        # Check if templates exist
        templates = self.template_manager.list_templates()
        if not templates:
            print("Warning: No template files found.")
            print("This is expected for the first build after migration.")
            print("Documentation files will use existing versions.")
            return True

        print(f"Found {len(templates)} template files")

        # Generate documentation from templates
        try:
            generated_count = self.template_manager.generate_all_from_templates()
            print(f"Generated {generated_count} documentation files from templates")
        except Exception as e:
            print(f"Error generating documentation from templates: {e}")
            return False

        print("Pre-build checks completed successfully")
        return True

    def post_build_cleanup(self) -> bool:
        """
        Post-build cleanup operations.

        Returns:
            True if cleanup is successful
        """
        print("Running post-build cleanup...")

        # For now, we don't need specific cleanup operations
        # This could be extended in the future for temporary file cleanup

        print("Post-build cleanup completed successfully")
        return True

    def validate_build_environment(self) -> bool:
        """
        Validate that the build environment is correctly set up.

        Returns:
            True if environment is valid
        """
        print("Validating build environment...")

        # Check that required files exist
        required_files = [
            "pyproject.toml",
            "automated_security_helper/__init__.py",
        ]

        for file_path in required_files:
            if not (self.project_root / file_path).exists():
                print(f"Error: Required file missing: {file_path}")
                return False

        # Check that version management module can be imported
        try:
            from automated_security_helper.utils.version_management import get_version

            version = get_version()
            print(f"Version management module working, current version: {version}")
        except Exception as e:
            print(f"Error: Version management module import failed: {e}")
            return False

        print("Build environment validation passed")
        return True

    def create_version_info_file(self, output_path: Optional[Path] = None) -> bool:
        """
        Create a version info file for build artifacts.

        Args:
            output_path: Path to write version info file (optional)

        Returns:
            True if successful
        """
        if output_path is None:
            output_path = self.project_root / "version_info.txt"

        try:
            version = get_version()
            build_info = f"""Automated Security Helper Build Information
Version: {version}
Build Date: {__import__("datetime").datetime.now().isoformat()}
Python Version: {sys.version}
Platform: {__import__("platform").system()} {__import__("platform").release()}
"""

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(build_info)

            print(f"Created version info file: {output_path}")
            return True

        except Exception as e:
            print(f"Error creating version info file: {e}")
            return False


def run_command(command: List[str], cwd: Optional[Path] = None) -> bool:
    """
    Run a command and return success status.

    Args:
        command: Command to run as list of strings
        cwd: Working directory (optional)

    Returns:
        True if command succeeded
    """
    try:
        subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {' '.join(command)}")
        print(f"Error: {e.stderr}")
        return False


def main():
    """Main entry point for build integration."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Build integration for version management"
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).parent.parent,
        help="Path to project root directory",
    )
    parser.add_argument(
        "action",
        choices=["pre-build", "post-build", "validate", "version-info"],
        help="Build integration action to perform",
    )
    parser.add_argument("--output", type=Path, help="Output path for version info file")

    args = parser.parse_args()

    integrator = BuildIntegrator(args.project_root)

    if args.action == "pre-build":
        success = integrator.pre_build_check()
    elif args.action == "post-build":
        success = integrator.post_build_cleanup()
    elif args.action == "validate":
        success = integrator.validate_build_environment()
    elif args.action == "version-info":
        success = integrator.create_version_info_file(args.output)
    else:
        print(f"Unknown action: {args.action}")
        return 1

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
