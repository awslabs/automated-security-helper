import subprocess
from pathlib import Path

# Define the path for the commit SHA file
ASH_COMMIT_SHA_PATH = Path(__file__).parent.parent.joinpath("ASH_COMMIT_SHA")
# Also define the path for the assets directory where we want to copy the file
ASSETS_PATH = Path(__file__).parent.parent.joinpath(
    "automated_security_helper", "assets"
)


def build() -> None:
    """Gets the current commit SHA and saves it at `automated_security_helper/assets/ASH_COMMIT_SHA`"""
    try:
        # Run git command without shell=True for better security and reliability
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent.as_posix(),
            check=True,
        )

        # Get the commit SHA and strip any whitespace
        commit_sha = sha.stdout.strip()

        # Write the commit SHA to the file in the root directory
        ASH_COMMIT_SHA_PATH.write_text(commit_sha)
        print(f"Successfully wrote commit SHA to {ASH_COMMIT_SHA_PATH}")

        # Ensure the assets directory exists
        ASSETS_PATH.mkdir(parents=True, exist_ok=True)

        # Copy the file to the assets directory
        asset_sha_path = ASSETS_PATH.joinpath("ASH_COMMIT_SHA")
        asset_sha_path.write_text(commit_sha)
        print(f"Successfully copied commit SHA to {asset_sha_path}")

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


if __name__ == "__main__":
    build()
