import shutil
import subprocess  # nosec B404 - This code is run during package build
from pathlib import Path
import sys

# Define the path for the commit SHA file
ASH_REPO_ROOT = Path(__file__).parent.parent
ASH_ASSETS_PATH = ASH_REPO_ROOT.joinpath("automated_security_helper", "assets")
ASH_INSTALLED_REVISION_PATH = ASH_ASSETS_PATH.joinpath("ASH_INSTALLED_REVISION")


def build() -> None:
    try:
        # Copy the Dockerfile into the assets directory
        dockerfile_path = ASH_REPO_ROOT.joinpath("Dockerfile")
        dockerfile_copy_path = ASH_ASSETS_PATH.joinpath("Dockerfile")
        dockerfile_copy_path.write_text(dockerfile_path.read_text())
        print(f"Successfully copied Dockerfile to {dockerfile_copy_path}")
        git_path = shutil.which("git")

        sha = subprocess.run(  # nosec B603 - This code is run during package build
            [git_path, "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            cwd=ASH_REPO_ROOT.as_posix(),
            check=True,
        )

        # Get the commit SHA and strip any whitespace
        revision_name = sha.stdout.strip()

        # Write the commit SHA to the file in the root directory
        ASH_INSTALLED_REVISION_PATH.parent.mkdir(parents=True, exist_ok=True)
        ASH_INSTALLED_REVISION_PATH.write_text(revision_name)
        print(
            f"Successfully wrote latest revision name to {ASH_INSTALLED_REVISION_PATH.as_posix()}"
        )

    except subprocess.CalledProcessError as e:
        print(f"Error executing git command: {e}")
        print(f"stderr: {e.stderr}")
        # Create a file with error information for debugging
        ASH_INSTALLED_REVISION_PATH.write_text(
            f"ERROR: Failed to get commit SHA\n{e}\n{e.stderr if hasattr(e, 'stderr') else ''}"
        )
    except Exception as e:
        print(f"Unexpected error: {e}")
        ASH_INSTALLED_REVISION_PATH.write_text(f"ERROR: Unexpected error\n{e}")

    finally:
        sys.exit(0)


if __name__ == "__main__":
    build()
