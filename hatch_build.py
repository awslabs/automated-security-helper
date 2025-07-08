"""
Custom Hatch build hook to stage build assets.
"""

import shutil
import subprocess  # nosec B404 - This code is run during package build
from pathlib import Path
from hatchling.builders.hooks.plugin.interface import BuildHookInterface

ASH_REPO_ROOT: Path = Path(__file__).parent
ASH_ASSETS_PATH: Path = ASH_REPO_ROOT.joinpath("automated_security_helper", "assets")
ASH_INSTALLED_REVISION_PATH: Path = ASH_ASSETS_PATH.joinpath("ASH_INSTALLED_REVISION")


class CustomBuildHook(BuildHookInterface):
    """Build hook to stage build assets before packaging."""

    PLUGIN_NAME = "stage-build-assets"

    def initialize(self, version, build_data):
        """Run the asset staging script."""
        # Stage assets immediately during initialization
        self._stage_assets()

    def _stage_assets(self):
        """Stage the build assets."""
        try:
            # Ensure assets directory exists
            ASH_ASSETS_PATH.mkdir(parents=True, exist_ok=True)

            # Copy the Dockerfile into the assets directory
            dockerfile_path = ASH_REPO_ROOT.joinpath("Dockerfile")
            dockerfile_copy_path = ASH_ASSETS_PATH.joinpath("Dockerfile")

            if dockerfile_path.exists():
                dockerfile_copy_path.write_text(dockerfile_path.read_text())
                print(f"Successfully copied Dockerfile to {dockerfile_copy_path}")
            else:
                print(f"Warning: Dockerfile not found at {dockerfile_path}")
                # Check if we already have a Dockerfile in assets (from previous build)
                if dockerfile_copy_path.exists():
                    print("Using existing Dockerfile in assets directory")
                else:
                    print(
                        "No Dockerfile available - this may be expected for wheel-only builds"
                    )

            # Handle Git commit SHA
            commit_sha = self._get_commit_sha()
            ASH_INSTALLED_REVISION_PATH.write_text(commit_sha)
            print(
                f"Successfully wrote commit SHA '{commit_sha}' to {ASH_INSTALLED_REVISION_PATH}"
            )

        except Exception as e:
            print(f"Unexpected error in build hook: {e}")
            # Ensure we have some revision file even if there's an error
            try:
                ASH_INSTALLED_REVISION_PATH.write_text("build-error")
            except Exception:
                pass
            print("Continuing build despite asset staging error")

    def _get_commit_sha(self) -> str:
        """Get the Git commit SHA, with fallbacks for different build scenarios."""
        git_path = shutil.which("git")
        if not git_path:
            print("Warning: git command not found")
            return "no-git-available"

        # Try to get commit SHA from current directory (source repo build)
        try:
            sha_result = subprocess.run(  # nosec B603 - This code is run during package build
                [git_path, "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                cwd=ASH_REPO_ROOT.as_posix(),
                check=True,
            )
            commit_sha = sha_result.stdout.strip()
            if commit_sha:
                return commit_sha
        except subprocess.CalledProcessError as e:
            print(f"Git command failed in current directory: {e}")
            if hasattr(e, "stderr") and e.stderr:
                print(f"stderr: {e.stderr}")

        # Fallback: Check if we already have a revision file (from sdist build)
        if ASH_INSTALLED_REVISION_PATH.exists():
            existing_sha = ASH_INSTALLED_REVISION_PATH.read_text().strip()
            if (
                existing_sha
                and not existing_sha.startswith("ERROR")
                and existing_sha
                not in ["unknown-commit", "no-git-available", "build-error"]
            ):
                print(f"Using existing commit SHA from previous build: {existing_sha}")
                return existing_sha

        # Final fallback
        print("Unable to determine commit SHA, using fallback")
        return "unknown-commit"
