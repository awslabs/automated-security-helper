"""Utilities for parallel test execution.

This module provides utilities for ensuring tests can run in parallel without
interfering with each other.
"""

import os
import uuid
import tempfile
from pathlib import Path
from typing import Optional, Union, Dict
from contextlib import contextmanager


def get_unique_test_id() -> str:
    """Generate a unique identifier for a test run.

    Returns:
        A unique string identifier
    """
    return str(uuid.uuid4())


def get_isolated_temp_dir(prefix: str = "test_") -> Path:
    """Create an isolated temporary directory for parallel test execution.

    Args:
        prefix: Prefix for the temporary directory name

    Returns:
        Path to the temporary directory
    """
    return Path(tempfile.mkdtemp(prefix=prefix))


def get_isolated_env_var_name(base_name: str) -> str:
    """Generate an isolated environment variable name for parallel tests.

    Args:
        base_name: Base name for the environment variable

    Returns:
        A unique environment variable name
    """
    unique_id = get_unique_test_id()[:8]
    return f"{base_name}_{unique_id}"


@contextmanager
def isolated_test_context(
    temp_dir_prefix: Optional[str] = None,
    env_vars: Optional[Dict[str, str]] = None,
) -> Path:
    """Create an isolated context for parallel test execution.

    This context manager creates a unique temporary directory and sets up
    isolated environment variables to prevent tests from interfering with
    each other when running in parallel.

    Args:
        temp_dir_prefix: Optional prefix for the temporary directory
        env_vars: Optional dictionary of environment variables to set

    Yields:
        Path to the isolated temporary directory

    Example:
        >>> with isolated_test_context(temp_dir_prefix="scanner_test_") as temp_dir:
        ...     # Run test code that uses the temporary directory
        ...     result = run_scanner(temp_dir / "input.txt")
    """
    # Create a unique temporary directory
    prefix = temp_dir_prefix or "test_"
    temp_dir = get_isolated_temp_dir(prefix)

    # Store original environment variables
    original_env = {}

    try:
        # Set isolated environment variables if provided
        if env_vars:
            for key, value in env_vars.items():
                # Generate a unique environment variable name
                isolated_key = get_isolated_env_var_name(key)

                # Store original value if it exists
                if isolated_key in os.environ:
                    original_env[isolated_key] = os.environ[isolated_key]

                # Set the environment variable
                os.environ[isolated_key] = value

        yield temp_dir

    finally:
        # Clean up environment variables
        for key in env_vars or {}:
            isolated_key = get_isolated_env_var_name(key)

            if isolated_key in original_env:
                os.environ[isolated_key] = original_env[isolated_key]
            elif isolated_key in os.environ:
                del os.environ[isolated_key]

        # Clean up temporary directory
        import shutil

        shutil.rmtree(temp_dir, ignore_errors=True)


class ParallelTestHelper:
    """Helper class for parallel test execution."""

    @staticmethod
    def get_isolated_file_path(
        base_path: Union[str, Path], test_id: Optional[str] = None
    ) -> Path:
        """Get an isolated file path for parallel test execution.

        Args:
            base_path: Base path for the file
            test_id: Optional test identifier (generated if not provided)

        Returns:
            An isolated file path
        """
        if test_id is None:
            test_id = get_unique_test_id()[:8]

        path = Path(base_path)
        stem = path.stem
        suffix = path.suffix

        return path.with_name(f"{stem}_{test_id}{suffix}")

    @staticmethod
    def get_isolated_directory_path(
        base_path: Union[str, Path], test_id: Optional[str] = None
    ) -> Path:
        """Get an isolated directory path for parallel test execution.

        Args:
            base_path: Base path for the directory
            test_id: Optional test identifier (generated if not provided)

        Returns:
            An isolated directory path
        """
        if test_id is None:
            test_id = get_unique_test_id()[:8]

        path = Path(base_path)

        return path.with_name(f"{path.name}_{test_id}")
