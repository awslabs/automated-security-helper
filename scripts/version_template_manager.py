#!/usr/bin/env python3
"""
Version Template Manager for Automated Security Helper.

This script manages template-based documentation where version numbers
are replaced with placeholders and then dynamically generated.
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple
import argparse

# Add the project root to the path so we can import our version management
sys.path.insert(0, str(Path(__file__).parent.parent))

from automated_security_helper.utils.version_management import get_version


class VersionTemplateManager:
    """Manages version templating for documentation files."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.template_suffix = ".template"
        self.version_placeholder = "{{VERSION}}"

        # Files to process (relative to project root)
        self.target_files = [
            "README.md",
            "docs/content/index.md",
            "docs/content/faq.md",
            "docs/content/docs/installation-guide.md",
            "docs/content/docs/quick-start-guide.md",
            "docs/content/docs/migration-guide.md",
            "docs/content/docs/advanced-usage.md",
            "docs/content/tutorials/running-ash-in-ci.md",
            "docs/content/tutorials/running-ash-locally.md",
            "examples/streamlit_ui/README.md",
        ]

    def find_version_references(self, content: str) -> List[Tuple[str, str]]:
        """
        Find all version references in content.

        Returns list of (old_pattern, new_pattern) tuples.
        """
        current_version = get_version()
        patterns = []

        # Pattern 1: git+...@v3.0.1
        git_pattern = rf"git\+https://github\.com/awslabs/automated-security-helper\.git@v{re.escape(current_version)}"
        git_replacement = f"git+https://github.com/awslabs/automated-security-helper.git@v{self.version_placeholder}"
        if re.search(git_pattern, content):
            patterns.append((git_pattern, git_replacement))

        # Pattern 2: --branch v3.0.1
        branch_pattern = rf"--branch v{re.escape(current_version)}"
        branch_replacement = f"--branch v{self.version_placeholder}"
        if re.search(branch_pattern, content):
            patterns.append((branch_pattern, branch_replacement))

        # Pattern 3: version 3.0.1 (in various contexts)
        version_pattern = rf"version {re.escape(current_version)}"
        version_replacement = f"version {self.version_placeholder}"
        if re.search(version_pattern, content, re.IGNORECASE):
            patterns.append((version_pattern, version_replacement))

        # Pattern 4: ASH version 3.0.1
        ash_version_pattern = rf"ASH version {re.escape(current_version)}"
        ash_version_replacement = f"ASH version {self.version_placeholder}"
        if re.search(ash_version_pattern, content):
            patterns.append((ash_version_pattern, ash_version_replacement))

        return patterns

    def convert_to_template(self, file_path: Path) -> bool:
        """
        Convert a file to template format by replacing version numbers with placeholders.

        Args:
            file_path: Path to the file to convert.

        Returns:
            True if conversion was successful and changes were made.
        """
        if not file_path.exists():
            print(f"Warning: File {file_path} does not exist, skipping.")
            return False

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            original_content = content
            patterns = self.find_version_references(content)

            if not patterns:
                print(f"No version references found in {file_path}")
                return False

            # Apply all patterns
            for old_pattern, new_pattern in patterns:
                content = re.sub(old_pattern, new_pattern, content)

            if content == original_content:
                print(f"No changes made to {file_path}")
                return False

            # Create template file
            template_path = file_path.with_suffix(
                file_path.suffix + self.template_suffix
            )
            with open(template_path, "w", encoding="utf-8") as f:
                f.write(content)

            print(f"Created template: {template_path}")
            return True

        except Exception as e:
            print(f"Error converting {file_path} to template: {e}")
            return False

    def generate_from_template(self, template_path: Path) -> bool:
        """
        Generate final file from template by replacing placeholders with actual version.

        Args:
            template_path: Path to the template file.

        Returns:
            True if generation was successful.
        """
        if not template_path.exists():
            print(f"Warning: Template {template_path} does not exist, skipping.")
            return False

        try:
            with open(template_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Replace version placeholder with actual version
            current_version = get_version()
            content = content.replace(self.version_placeholder, current_version)

            # Generate output file (remove .template suffix)
            output_path = template_path.with_suffix("")
            if template_path.suffix == self.template_suffix:
                # Remove the .template part, keep the original extension
                name_without_template = template_path.name[: -len(self.template_suffix)]
                output_path = template_path.parent / name_without_template

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)

            print(f"Generated {output_path} from template")
            return True

        except Exception as e:
            print(f"Error generating from template {template_path}: {e}")
            return False

    def convert_all_to_templates(self) -> int:
        """
        Convert all target files to templates.

        Returns:
            Number of files successfully converted.
        """
        converted_count = 0

        for file_path_str in self.target_files:
            file_path = self.project_root / file_path_str
            if self.convert_to_template(file_path):
                converted_count += 1

        return converted_count

    def generate_all_from_templates(self) -> int:
        """
        Generate all files from their templates.

        Returns:
            Number of files successfully generated.
        """
        generated_count = 0

        for file_path_str in self.target_files:
            template_path = self.project_root / (file_path_str + self.template_suffix)
            if self.generate_from_template(template_path):
                generated_count += 1

        return generated_count

    def list_templates(self) -> List[Path]:
        """List all existing template files."""
        templates = []
        for file_path_str in self.target_files:
            template_path = self.project_root / (file_path_str + self.template_suffix)
            if template_path.exists():
                templates.append(template_path)
        return templates


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Manage version templates for documentation"
    )
    parser.add_argument(
        "action",
        choices=["convert", "generate", "list"],
        help="Action to perform: convert files to templates, generate from templates, or list templates",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).parent.parent,
        help="Path to project root directory",
    )

    args = parser.parse_args()

    manager = VersionTemplateManager(args.project_root)

    if args.action == "convert":
        print("Converting files to templates...")
        count = manager.convert_all_to_templates()
        print(f"Successfully converted {count} files to templates.")

    elif args.action == "generate":
        print("Generating files from templates...")
        count = manager.generate_all_from_templates()
        print(f"Successfully generated {count} files from templates.")

    elif args.action == "list":
        templates = manager.list_templates()
        if templates:
            print("Existing template files:")
            for template in templates:
                print(f"  {template}")
        else:
            print("No template files found.")


if __name__ == "__main__":
    main()
