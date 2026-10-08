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
        # The floating major tag (`v4` for 4.x). ash-tag-on-merge moves one tag per
        # major and the older ones keep resolving, so a doc that writes the major as
        # a literal keeps recommending the previous major's tag after a bump.
        self.major_version_placeholder = "{{MAJOR_VERSION}}"

        # Files to process (relative to project root)
        self.target_files = [
            "README.md",
            "docs/content/index.md",
            "docs/content/faq.md",
            "docs/content/docs/installation-guide.md",
            "docs/content/docs/quick-start-guide.md",
            "docs/content/docs/migration-guide.md",
            "docs/content/docs/advanced-usage.md",
            "docs/content/docs/troubleshooting.md",
            "docs/content/docs/suppressions.md",
            "docs/content/docs/building-your-own-image.md",
            "docs/content/tutorials/running-ash-in-ci.md",
            "docs/content/tutorials/running-ash-locally.md",
            "examples/streamlit_ui/README.md",
        ]

    def find_version_references(self, content: str) -> List[Tuple[str, str]]:
        """
        Find all version references in content.

        Matches ANY v3.x.y version string (not just the current version) so that
        templates stay correct even when docs are edited between releases.

        Returns list of (old_pattern, new_pattern) tuples.
        """
        # Use a generic semver pattern to match any v3.x.y reference
        semver = r"\d+\.\d+\.\d+"
        patterns = []

        # Pattern 1: git+...@v3.x.y (also without .git suffix)
        git_pattern = rf"(git\+https://github\.com/awslabs/automated-security-helper(?:\.git)?@v){semver}"
        git_replacement = rf"\g<1>{self.version_placeholder}"
        if re.search(git_pattern, content):
            patterns.append((git_pattern, git_replacement))

        # Pattern 2: --branch v3.x.y
        branch_pattern = rf"(--branch v){semver}"
        branch_replacement = rf"\g<1>{self.version_placeholder}"
        if re.search(branch_pattern, content):
            patterns.append((branch_pattern, branch_replacement))

        # Pattern 3: @v3.x.y in inline text (e.g., "pinned versions (`@v3.4.0`)")
        at_version_pattern = rf"(@v){semver}"
        at_version_replacement = rf"\g<1>{self.version_placeholder}"
        if re.search(at_version_pattern, content):
            patterns.append((at_version_pattern, at_version_replacement))

        # Pattern 4: rev: v3.x.y (pre-commit config)
        rev_pattern = rf"(rev: v){semver}"
        rev_replacement = rf"\g<1>{self.version_placeholder}"
        if re.search(rev_pattern, content):
            patterns.append((rev_pattern, rev_replacement))

        # Pattern 5: a Nix flake reference -- `github:<owner>/<repo>/v3.x.y`.
        #
        # Every pattern above keys on `@v`, because every install reference this
        # repository had ever carried used an `@`: `git+...@v`, `--branch v`, `rev: v`.
        # A flake ref separates the ref from the repository with a SLASH, so it was
        # invisible to all four -- and to `[tool.commitizen] version_files`, and to the
        # three `@v`-anchored patterns in tests/unit/test_agent_plugin_ash_version.py.
        # Five mechanisms with one blind spot, because all five had encoded the same
        # incidental delimiter as though it were part of what a reference is.
        #
        # It was not hypothetical. docs/content/docs/installation-guide.md documented an
        # ASH_NIX_FLAKE_REF override in the flake form, under a heading reading "Override
        # it with:", as a runnable copy-paste. It sat two minor releases behind the
        # shipped version and no mechanism could see it. `nix develop` resolves a git ref
        # like every other consumer here, so it succeeded and supplied an old ASH with an
        # old scanner set.
        #
        # The offending value is described rather than quoted. This file is read by the
        # tree walk in tests/unit/test_agent_plugin_ash_version.py, so pasting the stale
        # literal into this comment would be reported as a real stale pin -- the comment
        # explaining the hazard would BE the hazard. The same applies to the `/v` prefix
        # with nothing after it, which that walk reads as a truncated ref, which is why
        # the repository name below is interpolated instead of written inline.
        #
        # The OWNER is deliberately unanchored: `resolve_flake_ref()` builds its ref from
        # `ASH_REPO_URL`, so a fork's docs carry a fork's owner. The repository NAME is
        # anchored, because without it a flake ref to an unrelated project -- nixpkgs,
        # say -- would be rewritten to ASH's version.
        repo = "automated-security-" + "helper"
        flake_pattern = rf"(github:[\w.-]+/{repo}/v){semver}"
        flake_replacement = rf"\g<1>{self.version_placeholder}"
        if re.search(flake_pattern, content):
            patterns.append((flake_pattern, flake_replacement))

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

    def render(self, content: str, version: str) -> str:
        """Substitute the version placeholders in template content."""
        major = version.split(".", 1)[0]
        return content.replace(self.version_placeholder, version).replace(
            self.major_version_placeholder, major
        )

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

            content = self.render(content, get_version())

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
