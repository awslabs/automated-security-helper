"""Helper functions for ASH tests."""

from pathlib import Path

#: Root of the tests' own scratch area, inside the repository and gitignored.
#:
#: Named rather than inlined because anything that walks the repository has to be
#: able to exclude it, and a second hardcoded "pytest-temp" would be free to
#: drift from this one. ``TestPluginManagerSingletonState`` in
#: ``tests/unit/workspace/test_project_isolation.py`` imports this constant for
#: exactly that reason: its sweep reads every ``*.py`` under the repository root,
#: and the ``ash_temp_path`` fixture deletes a subtree of this directory on
#: teardown while other xdist workers are mid-sweep.
ASH_TEST_TEMP_ROOT = Path(__file__).parent.parent / "pytest-temp"


def get_ash_temp_path():
    """Create a temporary directory using the gitignored tests/pytest-temp directory.

    This fixture provides a consistent temporary directory that is gitignored
    and located within the tests directory structure.

    Returns:
        Path to the temporary directory
    """
    import uuid

    # Create a unique subdirectory for this test session
    temp_dir = ASH_TEST_TEMP_ROOT / str(uuid.uuid4())
    temp_dir.mkdir(parents=True, exist_ok=True)

    return temp_dir
