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

# Every form in which a command names the ASH ref it installs: the text in front of the
# `v` of a release tag, and the same form naming a branch instead. `@` covers git URLs
# (`git+https://...@v`, `uvx --from=git+...@v`) and `uses: ...@v`. The repository name is
# interpolated for the reason the flake pattern in find_version_references gives.
#
# One list for three readers: scripts/docs_versions.py check reads which release a built
# page pins (release_pins) and requires the main version to name main in every form a
# release page uses (branch_ref_pattern); scripts/docs_checks.py refuses {{RELEASE}} in
# any of these forms in a template (release_in_install_ref).
_REPO_NAME = "automated-security-" + "helper"
INSTALL_REF_FORMS = (
    # (name, the text before `v<version>`, the form naming a branch, with {branch})
    ("@ (git URL, uses:)", r"@", r"@{branch}"),
    ("--branch", r"--branch ", r"--branch {branch}"),
    ("rev:", r"rev: ", r"rev: {branch}"),
    ("refs/tags/ (git ls-remote)", r"refs/tags/", r"refs/heads/{branch}"),
    (
        "flake ref",
        rf"github:[\w.-]+/{_REPO_NAME}/",
        rf"github:[\w.-]+/{_REPO_NAME}/{{branch}}",
    ),
    (
        "--ash-revision-to-install",
        r"--ash-revision-to-install ",
        r"--ash-revision-to-install {branch}",
    ),
    ("ash-version:", r"ash-version: ", r"ash-version: {branch}"),
)
_RELEASE_PIN = re.compile(
    "(?:" + "|".join(prefix for _name, prefix, _branch in INSTALL_REF_FORMS) + r")"
    r"v(\d+\.\d+\.\d+)"
)


class VersionTemplateManager:
    """Manages version templating for documentation files."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.template_suffix = ".template"
        # The ref an install command uses. A release's docs render it as the release,
        # the docs site's main version as `main` (see render_for_branch).
        self.version_placeholder = "{{VERSION}}"
        # The current release number, on every build: what `ash --version` prints, the
        # release this repository's generated files pin, a release named in a table.
        # Never in an install command, where the main version would then install a
        # release; scripts/docs_checks.py enforces that with release_in_install_ref.
        self.release_placeholder = "{{RELEASE}}"

        # Files to process (relative to project root)
        self.target_files = [
            "README.md",
            "docs/content/docs/advanced-usage.md",
            "docs/content/getting-started/ci.md",
            "docs/content/getting-started/local.md",
            "docs/content/getting-started/platform-teams.md",
            "docs/content/how-to/agent-plugins.md",
            "docs/content/how-to/ci/github-actions.md",
            "docs/content/how-to/ci/gitlab-ci.md",
            "docs/content/how-to/ci/other-ci.md",
            "docs/content/how-to/install.md",
            "docs/content/how-to/pre-commit.md",
            "docs/content/how-to/run-in-a-container.md",
            "docs/content/how-to/scale-large-repos.md",
            "docs/content/how-to/suppress-findings.md",
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

    def render(self, content: str, version: str) -> str:
        """A template rendered for a release: both placeholders become the version."""
        return content.replace(self.version_placeholder, version).replace(
            self.release_placeholder, version
        )

    def render_for_branch(self, content: str, branch: str, release: str) -> str:
        """A template rendered for a branch, such as main, instead of a release.

        The docs site's `main` version is built this way (docs/hooks/install_refs.py),
        so its install commands install main. A placeholder written after a `v`, as in
        `@v{{VERSION}}`, `--branch v{{VERSION}}` or `rev: v{{VERSION}}`, names a release
        tag, and the whole tag becomes the branch: `@main`, not `@vmain`. A tag looked up
        by its full name, `refs/tags/v{{VERSION}}`, becomes the branch's
        `refs/heads/<branch>`, so the command still names a ref that exists. A bare
        placeholder becomes the branch name too. The release placeholder becomes
        release, the current release number: an install of main reports it.
        """
        tag = "v" + self.version_placeholder
        return (
            content.replace("refs/tags/" + tag, "refs/heads/" + branch)
            .replace(tag, branch)
            .replace(self.version_placeholder, branch)
            .replace(self.release_placeholder, release)
        )

    def packaged_release(self) -> str:
        """The current release number: `[tool.commitizen] version` in pyproject.toml.

        That is the field commitizen bumps, and the one the committed pages were
        rendered for. Read from the file rather than with get_version(), which imports
        ASH.
        """
        if sys.version_info >= (3, 11):
            import tomllib
        else:  # pragma: no cover - exercised only on 3.10
            import tomli as tomllib

        with (self.project_root / "pyproject.toml").open("rb") as handle:
            return tomllib.load(handle)["tool"]["commitizen"]["version"]

    @staticmethod
    def release_pins(text: str) -> set:
        """The release numbers that install commands in text pin, in any form."""
        return set(_RELEASE_PIN.findall(text))

    @staticmethod
    def forms_pinning_a_release(text: str) -> List[str]:
        """The names of the install-command forms that pin a release in text."""
        return [
            name
            for name, prefix, _branch in INSTALL_REF_FORMS
            if re.search(prefix + r"v\d+\.\d+\.\d+", text)
        ]

    @staticmethod
    def branch_ref_pattern(form: str, branch: str) -> "re.Pattern[str]":
        """The named install-command form, naming branch instead of a release."""
        rendering = next(b for name, _p, b in INSTALL_REF_FORMS if name == form)
        return re.compile(rendering.format(branch=re.escape(branch)) + r"(?![\w.-])")

    def release_in_install_ref(self) -> "re.Pattern[str]":
        """The release placeholder written as the ref of an install command."""
        prefixes = "|".join(prefix for _name, prefix, _branch in INSTALL_REF_FORMS)
        return re.compile(f"(?:{prefixes})v?" + re.escape(self.release_placeholder))

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

            # Imported here rather than at the top, so loading this module (as the
            # mkdocs hook docs/hooks/install_refs.py does) does not import ASH.
            from automated_security_helper.utils.version_management import get_version

            # Replace version placeholder with actual version
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
