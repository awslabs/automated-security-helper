import subprocess  # nosec B404 - This code is run during package build
from pathlib import Path
import sys

# Define the path for the commit SHA file
ASH_REPO_ROOT = Path(__file__).parent.parent
ASH_ASSETS_PATH = ASH_REPO_ROOT.joinpath("automated_security_helper", "assets")
ASH_COMMIT_SHA_PATH = ASH_ASSETS_PATH.joinpath("ASH_COMMIT_SHA")


def build() -> None:
    try:
        # Copy the Dockerfile into the assets directory
        dockerfile_path = ASH_REPO_ROOT.joinpath("Dockerfile")
        dockerfile_copy_path = ASH_ASSETS_PATH.joinpath("Dockerfile")
        dockerfile_copy_path.write_text(dockerfile_path.read_text())
        print(f"Successfully copied Dockerfile to {dockerfile_copy_path}")

        sha = subprocess.run(  # nosec B603 - This code is run during package build
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            cwd=ASH_REPO_ROOT.as_posix(),
            check=True,
        )

        # Get the commit SHA and strip any whitespace
        commit_sha = sha.stdout.strip()

        # Write the commit SHA to the file in the root directory
        ASH_COMMIT_SHA_PATH.parent.mkdir(parents=True, exist_ok=True)
        ASH_COMMIT_SHA_PATH.write_text(commit_sha)
        print(f"Successfully wrote commit SHA to {ASH_COMMIT_SHA_PATH}")

    except subprocess.CalledProcessError as e:
        print(f"Error executing git command: {e}")
        print(f"stderr: {e.stderr}")
        # Create a file with error information for debugging
        ASH_COMMIT_SHA_PATH.write_text(
            f"ERROR: Failed to get commit SHA\n{e}\n{e.stderr if hasattr(e, 'stderr') else ''}"
        )
    except Exception as e:
        print(f"Unexpected error: {e}")
        ASH_COMMIT_SHA_PATH.write_text(f"ERROR: Unexpected error\n{e}")

    finally:
        sys.exit(0)


if __name__ == "__main__":
    build()
