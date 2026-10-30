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


def leads_up_to_its_release(version: Version) -> bool:
    """Whether ``version`` comes before the final release its numbers name.

    2.0.0rc1 and 2.0.0.dev1 sort before 2.0.0; 2.0.0.post1 and 2.0.0.post1.dev1
    sort after it. A pre-release part decides it, post-release part or not
    (2.0.0rc1.post1 still precedes 2.0.0); a development part alone does only
    when there is no post-release part.
    """
    return version.pre is not None or (version.dev is not None and version.post is None)


def bump_version(current_version: str, bump_type: str) -> str:
    """
    Bump version based on type (major, minor, patch).

    A version that comes before its own release (2.0.0rc1, 2.0.0.dev1) is bumped
    the way semver and commitizen do it: the bump that names that release
    finalizes it instead of passing it. Patch gives X.Y.Z; minor gives X.Y.0 when
    the patch number is 0; major gives X.0.0 when the minor and patch numbers are
    0. Any other bump counts from the release numbers, as for a final version.

    Args:
        current_version: Current version string
        bump_type: Type of bump (major, minor, patch)

    Returns:
        New version string
    """
    parsed = _read_version(current_version)
    major, minor, patch = parsed.release

    if leads_up_to_its_release(parsed) and (
        bump_type == "patch"
        or (bump_type == "minor" and patch == 0)
        or (bump_type == "major" and minor == 0 and patch == 0)
    ):
        return format_version(major, minor, patch)

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


def _is_final(parsed: Version) -> bool:
    """Whether ``parsed`` is a final X.Y.Z release, the only kind ``set`` writes."""
    return (
        parsed.local is None
        and not parsed.is_prerelease
        and not parsed.is_postrelease
        and not parsed.is_devrelease
    )


def fix_with_set(version: str) -> str:
    """The ``set`` command that writes ``version``, or the final release nearest it.

    ``set`` takes a final X.Y.Z spelled as pip prints it and refuses anything else,
    so a tree whose pyproject.toml holds 3.8.0-rc1 or 3.8.0rc1 cannot be repaired by
    ``set`` with that text. The advice names what ``set`` accepts: the version
    itself when it is final, its release numbers (``base_version``) when it is not,
    and a placeholder when it is not a version at all.

    For a version that is not final the command CHANGES the version (2.0.0rc1 to
    2.0.0 finalizes the release; 3.8.0.post1 to 3.8.0 moves it backwards), so the
    advice says so and names how to keep the version instead.
    """
    try:
        parsed = _read_version(version)
    except ValueError:
        return "run 'set X.Y.Z' with a final version, such as 'set 3.1.0'"
    if _is_final(parsed):
        return f"run 'set {parsed}'"
    if parsed.local is None and str(parsed) != version:
        keep = f"spell it {parsed} in both [project] and [tool.commitizen]"
    else:
        keep = "edit both version fields by hand"
    return (
        f"run 'set {parsed.base_version}' to change {version} to "
        f"{parsed.base_version} (set writes final X.Y.Z versions only); "
        f"to keep {version}, {keep}"
    )


def regenerate_pages_with(version: str) -> str:
    """The command that regenerates the pages for ``version`` as it stands.

    For a final version ``set`` does it and changes nothing else. For a version
    that is not final ``set`` would change the version, so the advice is the
    template manager's ``generate``, which renders the pages with the version the
    pyproject.toml already holds.
    """
    try:
        parsed = _read_version(version)
    except ValueError:
        return fix_with_set(version)
    if _is_final(parsed):
        return f"{fix_with_set(version)} to regenerate it"
    return (
        "run 'python scripts/version_template_manager.py generate' to render the "
        f"pages for {version} (set would change the version to {parsed.base_version})"
    )


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
                "with three release numbers, spelled as pip prints it, such as 3.1.0)"
            )
            return False

        parsed = Version(new_version)
        if parsed.is_prerelease or parsed.is_postrelease or parsed.is_devrelease:
            # The install-command pins in the generated pages, and the checks that
            # read them, know a release as X.Y.Z alone; a suffix written into a
            # page would read as a malformed pin and be split off by `convert`.
            print(
                f"Error: {new_version} is not a final release. set writes final "
                "X.Y.Z versions only, because the pins in the pages and the "
                "checks that read them match X.Y.Z alone"
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
        # target whose template is missing is reported as an error and not
        # counted, and measured against the templates alone that was invisible
        # to this check, so the set printed success while the target's page
        # kept the release it was written at.
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
        if leads_up_to_its_release(current):
            if new_version == current.base_version:
                print(
                    f"Note: {current_version} is not a final release. The "
                    f"{bump_type} bump finalizes it: {new_version} follows."
                )
            else:
                # The bump is past the release the version leads up to: only the
                # release numbers are counted. Say so instead of dropping the
                # pre-release or development part silently.
                print(
                    f"Note: {current_version} is not a final release. The "
                    f"{bump_type} bump counts from its release numbers alone, so "
                    f"that part is dropped and {new_version} follows."
                )

        return self.set_version(new_version)

    def validate_consistency(self) -> bool:
        """
        Validate that all version references are consistent.

        Three things are compared, none of them with the installed distribution:
        ``[project] version`` with ``[tool.commitizen] version`` in the
        pyproject.toml at the project root, and each generated page with its
        template rendered for that version (what ``set`` would write now). While
        the two tables disagree no page is compared, because there is no one
        version to render for.

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
        tables_agree = True

        # The version itself, before anything is compared with it: a spelling
        # `set` refuses (3.8.0-rc1, written by an older set) or text that is not a
        # version at all (not-a-version) passed here as long as the pages matched,
        # and the advice below would have told the reader to run `set` with it.
        # Canonical is the spelling check only: a pre-release such as 2.0.0rc1 is
        # canonical and passes, although `set` itself writes final versions only.
        canonical = validate_version(current_version)
        if not canonical:
            print(
                f"Error: [project] version {current_version!r} is not a canonical "
                "version (PEP 440 with three release numbers, spelled as pip prints "
                f"it, no local part); {fix_with_set(current_version)}"
            )
            consistent = False

        try:
            released = self.template_manager.packaged_release()
        except KeyError:
            released = None  # no [tool.commitizen] version to compare
        if released is not None and released != current_version:
            # The pages are rendered for one of the two numbers, and which one is
            # right is exactly what disagrees. Comparing them with either would
            # report every page as stale and advise the wrong side, so only this
            # line is reported; `set` writes both tables and the pages from the
            # release version, and the pages are compared once the tables agree.
            print(
                f"Error: [tool.commitizen] version is {released} but "
                f"[project] version is {current_version}; to write both from the "
                f"release version, {fix_with_set(released)}. The pages are not "
                "compared until the two agree."
            )
            consistent = False
            tables_agree = False

        targets = list(self.template_manager.target_files)
        templates = self.template_manager.list_templates()
        if not templates:
            # Not an early return: the loop below names every listed target whose
            # template is missing, and a version error printed above still gets
            # the failure summary.
            print("Warning: No template files found. Run 'convert' first.")
            consistent = False

        # Every target the manager lists, as `set` counts them and `generate`
        # renders them, and not the templates that happen to exist: a listed
        # target whose template is missing is skipped with a warning by generate,
        # so a loop over the existing templates never reached it and validate
        # passed over a page that `set` reports as not regenerated.
        for relative in targets:
            target = self.project_root / relative
            template = self.template_manager.template_path_for(relative)
            if not template.exists():
                print(
                    f"Error: {template} does not exist, so {target} cannot be "
                    "regenerated; run 'convert' to create it"
                )
                consistent = False
                continue
            # A file that cannot be read (a directory, a permission, bytes that are
            # not UTF-8) is one more thing to report, as `set` reports a template
            # that fails to render; a traceback here ended the run and hid every
            # target after it.
            try:
                actual = target.read_text(encoding="utf-8")
            except FileNotFoundError:
                print(f"Error: {target} does not exist; generate it from {template}")
                consistent = False
                continue
            except (OSError, ValueError) as e:
                print(f"Error: could not read {target}: {e}")
                consistent = False
                continue
            if not (tables_agree and canonical):
                continue
            try:
                expected = self.template_manager.render(
                    template.read_text(encoding="utf-8"), current_version
                )
            except (OSError, ValueError) as e:
                print(f"Error: could not render {template}: {e}")
                consistent = False
                continue
            if actual != expected:
                print(
                    f"Error: {target} is not its template rendered for "
                    f"{current_version}; {regenerate_pages_with(current_version)}"
                )
                consistent = False

        # Counted against the targets the manager lists, as the loop is: a template
        # on disk that no target names is not looked at and not counted.
        print(f"Found templates for {len(templates)} of {len(targets)} listed targets")
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
    set_parser.add_argument("version", help="Final version to set, X.Y.Z (e.g., 3.1.0)")

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
