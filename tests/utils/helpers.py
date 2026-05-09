"""Helper functions for ASH tests."""

from pathlib import Path


def get_ash_temp_path():
    """Create a temporary directory using the gitignored tests/pytest-temp directory.

    This fixture provides a consistent temporary directory that is gitignored
    and located within the tests directory structure.

    Returns:
        Path to the temporary directory
    """
    import uuid

    # Get the tests directory
    tests_dir = Path(__file__).parent.parent
    temp_base_dir = tests_dir / "pytest-temp"

    # Create a unique subdirectory for this test session
    temp_dir = temp_base_dir / str(uuid.uuid4())
    temp_dir.mkdir(parents=True, exist_ok=True)

    return temp_dir
