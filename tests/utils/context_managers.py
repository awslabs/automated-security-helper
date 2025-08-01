"""Context managers for test environment setup and teardown."""

import os
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Generator
from contextlib import contextmanager
import json
import yaml
from unittest.mock import patch, MagicMock


@contextmanager
def environment_variables(**kwargs) -> Generator[None, None, None]:
    """Temporarily set environment variables for a test.

    Args:
        **kwargs: Environment variables to set as key-value pairs

    Yields:
        None

    Example:
        >>> with environment_variables(ASH_CONFIG_PATH=".ash/ash.yaml", DEBUG="true"):
        ...     # Code that uses these environment variables
        ...     pass
    """
    original = {}
    for key, value in kwargs.items():
        if key in os.environ:
            original[key] = os.environ[key]
        os.environ[key] = str(value)

    try:
        yield
    finally:
        for key in kwargs:
            if key in original:
                os.environ[key] = original[key]
            else:
                del os.environ[key]


@contextmanager
def temp_directory() -> Generator[Path, None, None]:
    """Create a temporary directory for testing that is automatically cleaned up.

    Yields:
        Path: Path to the temporary directory

    Example:
        >>> with temp_directory() as temp_dir:
        ...     # Use the temporary directory
        ...     (temp_dir / "test.txt").write_text("test content")
    """
    temp_dir = Path(tempfile.mkdtemp())
    try:
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@contextmanager
def temp_file(content: str = "", suffix: str = ".txt") -> Generator[Path, None, None]:
    """Create a temporary file for testing that is automatically cleaned up.

    Args:
        content: Optional content to write to the file
        suffix: File extension to use

    Yields:
        Path: Path to the temporary file

    Example:
        >>> with temp_file("test content", suffix=".json") as temp_file_path:
        ...     # Use the temporary file
        ...     data = json.loads(temp_file_path.read_text())
    """
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    file_path = Path(path)

    if content:
        file_path.write_text(content)

    try:
        yield file_path
    finally:
        if file_path.exists():
            file_path.unlink()


@contextmanager
def temp_config_file(
    config_data: Dict[str, Any], format: str = "yaml"
) -> Generator[Path, None, None]:
    """Create a temporary configuration file for testing.

    Args:
        config_data: Configuration data to write to the file
        format: Format of the configuration file ("yaml" or "json")

    Yields:
        Path: Path to the temporary configuration file

    Example:
        >>> config = {"project_name": "test", "scanners": {"bandit": {"enabled": True}}}
        >>> with temp_config_file(config) as config_path:
        ...     # Use the configuration file
        ...     pass
    """
    suffix = ".yaml" if format.lower() == "yaml" else ".json"

    with temp_file(suffix=suffix) as file_path:
        if format.lower() == "yaml":
            file_path.write_text(yaml.dump(config_data))
        else:
            file_path.write_text(json.dumps(config_data, indent=2))

        yield file_path


@contextmanager
def temp_project_directory(
    files: Dict[str, str] = None,
    config: Dict[str, Any] = None,
) -> Generator[Path, None, None]:
    """Create a temporary project directory with specified files and configuration.

    Args:
        files: Dictionary mapping file paths to content
        config: Optional ASH configuration to include

    Yields:
        Path: Path to the temporary project directory

    Example:
        >>> files = {
        ...     "src/main.py": "print('Hello, world!')",
        ...     "tests/test_main.py": "def test_main(): pass",
        ... }
        >>> config = {"project_name": "test_project"}
        >>> with temp_project_directory(files, config) as project_dir:
        ...     # Use the project directory
        ...     pass
    """
    with temp_directory() as project_dir:
        # Create files
        if files:
            for file_path, content in files.items():
                full_path = project_dir / file_path
                full_path.parent.mkdir(parents=True, exist_ok=True)
                full_path.write_text(content)

        # Create ASH config if specified
        if config:
            config_dir = project_dir / ".ash"
            config_dir.mkdir(exist_ok=True)
            config_path = config_dir / ".ash.yaml"
            config_path.write_text(yaml.dump(config))

        yield project_dir


@contextmanager
def mock_responses(
    responses: List[Dict[str, Any]],
    status_codes: Union[List[int], int] = 200,
) -> Generator[None, None, None]:
    """Mock HTTP responses for requests or httpx libraries.

    Args:
        responses: List of response bodies to return
        status_codes: HTTP status code(s) to return

    Yields:
        None

    Example:
        >>> responses = [{"result": "success"}, {"result": "error"}]
        >>> with mock_responses(responses, status_codes=[200, 400]):
        ...     # Code that makes HTTP requests
        ...     pass
    """
    # Convert single status code to list
    if isinstance(status_codes, int):
        status_codes = [status_codes] * len(responses)

    # Ensure status_codes and responses have the same length
    if len(status_codes) != len(responses):
        status_codes = status_codes * len(responses)
        status_codes = status_codes[: len(responses)]

    # Create mock response objects
    mock_resp_objects = []
    for i, response in enumerate(responses):
        mock_resp = MagicMock()
        mock_resp.status_code = status_codes[i]
        mock_resp.json.return_value = response
        mock_resp.text = json.dumps(response)
        mock_resp.content = json.dumps(response).encode()
        mock_resp_objects.append(mock_resp)

    # Create mock for requests.get, post, etc.
    mock_request = MagicMock()
    mock_request.side_effect = mock_resp_objects

    # Patch both requests and httpx libraries
    with (
        patch("requests.get", mock_request),
        patch("requests.post", mock_request),
        patch("requests.put", mock_request),
        patch("requests.delete", mock_request),
        patch("httpx.get", mock_request),
        patch("httpx.post", mock_request),
        patch("httpx.put", mock_request),
        patch("httpx.delete", mock_request),
    ):
        yield


@contextmanager
def redirect_stdout_stderr() -> Generator[tuple, None, None]:
    """Redirect stdout and stderr to capture output during tests.

    Yields:
        tuple: (stdout_content, stderr_content) as string buffers

    Example:
        >>> with redirect_stdout_stderr() as (stdout, stderr):
        ...     print("Hello, world!")
        ...     print("Error message", file=sys.stderr)
        >>> assert "Hello, world!" in stdout.getvalue()
        >>> assert "Error message" in stderr.getvalue()
    """
    import io

    stdout = io.StringIO()
    stderr = io.StringIO()

    with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
        yield stdout, stderr


@contextmanager
def mock_subprocess_run(
    return_codes: Union[List[int], int] = 0,
    stdout_outputs: Optional[List[str]] = None,
    stderr_outputs: Optional[List[str]] = None,
) -> Generator[None, None, None]:
    """Mock subprocess.run to return specified outputs and return codes.

    Args:
        return_codes: Return code(s) to simulate
        stdout_outputs: Standard output to simulate
        stderr_outputs: Standard error to simulate

    Yields:
        None

    Example:
        >>> with mock_subprocess_run(
        ...     return_codes=[0, 1],
        ...     stdout_outputs=["Success", ""],
        ...     stderr_outputs=["", "Error"]
        ... ):
        ...     # Code that calls subprocess.run
        ...     pass
    """
    import subprocess

    # Convert single return code to list
    if isinstance(return_codes, int):
        return_codes = [return_codes]

    # Initialize stdout and stderr lists if not provided
    if stdout_outputs is None:
        stdout_outputs = [""] * len(return_codes)
    if stderr_outputs is None:
        stderr_outputs = [""] * len(return_codes)

    # Ensure all lists have the same length
    max_len = max(len(return_codes), len(stdout_outputs), len(stderr_outputs))
    return_codes = (return_codes * max_len)[:max_len]
    stdout_outputs = (stdout_outputs * max_len)[:max_len]
    stderr_outputs = (stderr_outputs * max_len)[:max_len]

    # Create mock CompletedProcess objects
    mock_results = []
    for i in range(max_len):
        mock_result = MagicMock(spec=subprocess.CompletedProcess)
        mock_result.returncode = return_codes[i]
        mock_result.stdout = stdout_outputs[i]
        mock_result.stderr = stderr_outputs[i]
        mock_results.append(mock_result)

    # Create mock for subprocess.run
    mock_run = MagicMock(side_effect=mock_results)

    with patch("subprocess.run", mock_run):
        yield


@contextmanager
def working_directory(path: Union[str, Path]) -> Generator[Path, None, None]:
    """Temporarily change the working directory.

    Args:
        path: Directory to change to

    Yields:
        Path: Path to the working directory

    Example:
        >>> with working_directory("/tmp") as wd:
        ...     # Code that runs in the /tmp directory
        ...     pass
    """
    original_dir = Path.cwd()
    path = Path(path)

    try:
        os.chdir(path)
        yield path
    finally:
        os.chdir(original_dir)


@contextmanager
def mock_socket_connection() -> Generator[MagicMock, None, None]:
    """Mock socket connections to prevent actual network connections during tests.

    Yields:
        MagicMock: A mock socket object that can be configured for testing

    Example:
        >>> with mock_socket_connection() as mock_socket:
        ...     mock_socket.recv.return_value = b"test response"
        ...     # Code that uses socket connections
        ...     result = connect_to_service()
        ...     assert result == "test response"
    """
    mock_socket = MagicMock()

    with patch("socket.socket", return_value=mock_socket):
        yield mock_socket


@contextmanager
def mock_aws_service(
    service_name: str, responses: Dict[str, Any] = None
) -> Generator[MagicMock, None, None]:
    """Mock AWS service clients to prevent actual AWS API calls during tests.

    Args:
        service_name: Name of the AWS service to mock (e.g., 's3', 'ec2')
        responses: Dictionary mapping method names to return values

    Yields:
        MagicMock: A mock AWS service client

    Example:
        >>> responses = {
        ...     'list_buckets': {'Buckets': [{'Name': 'test-bucket'}]},
        ...     'get_object': {'Body': MagicMock(read=lambda: b'test content')}
        ... }
        >>> with mock_aws_service('s3', responses) as mock_s3:
        ...     # Code that uses boto3 S3 client
        ...     result = list_all_buckets()
        ...     assert 'test-bucket' in result
    """
    mock_client = MagicMock()

    # Configure mock responses if provided
    if responses:
        for method_name, response in responses.items():
            method_mock = getattr(mock_client, method_name)
            method_mock.return_value = response

    with patch("boto3.client", return_value=mock_client):
        yield mock_client


@contextmanager
def capture_logging(
    logger_name: str = None,
) -> Generator[List[Dict[str, Any]], None, None]:
    """Capture log messages during tests.

    Args:
        logger_name: Optional name of the logger to capture (captures root logger if None)

    Yields:
        List[Dict[str, Any]]: List of captured log records as dictionaries

    Example:
        >>> with capture_logging('my_module') as logs:
        ...     # Code that logs messages
        ...     logger.info("Test message")
        ...     logger.error("Error occurred")
        >>> assert len(logs) == 2
        >>> assert logs[0]['message'] == "Test message"
        >>> assert logs[1]['level'] == "ERROR"
    """
    import logging

    captured_records = []

    class TestHandler(logging.Handler):
        def emit(self, record):
            captured_records.append(
                {
                    "message": record.getMessage(),
                    "level": record.levelname,
                    "logger": record.name,
                    "timestamp": record.created,
                }
            )

    # Get the logger to capture
    logger = logging.getLogger(logger_name)

    # Add the test handler
    handler = TestHandler()
    logger.addHandler(handler)

    # Store the original level to restore it later
    original_level = logger.level
    logger.setLevel(logging.DEBUG)

    try:
        yield captured_records
    finally:
        # Restore original logger configuration
        logger.removeHandler(handler)
        logger.setLevel(original_level)


@contextmanager
def disable_root_logger() -> Generator[None, None, None]:
    """Temporarily disable the root logger to prevent duplicate log messages.

    This is useful when testing code that configures its own loggers but might be affected
    by handlers attached to the root logger.

    Yields:
        None

    Example:
        >>> with disable_root_logger():
        ...     # Code that configures and uses loggers
        ...     run_logging_code()
    """
    import logging

    # Store the original root logger configuration
    root_logger = logging.getLogger()
    original_handlers = list(root_logger.handlers)
    original_level = root_logger.level

    # Temporarily remove all handlers and set level to CRITICAL to suppress most messages
    root_logger.handlers = []
    root_logger.setLevel(logging.CRITICAL)

    try:
        yield
    finally:
        # Restore the original root logger configuration
        root_logger.handlers = original_handlers
        root_logger.setLevel(original_level)


@contextmanager
def mock_file_system(
    file_structure: Dict[str, Union[str, Dict]],
) -> Generator[Path, None, None]:
    """Create a mock file system structure in a temporary directory.

    Args:
        file_structure: Dictionary representing the file structure to create.
                       Keys are file/directory names, values are either file content (str)
                       or nested dictionaries for subdirectories.

    Yields:
        Path: Path to the root of the mock file system

    Example:
        >>> structure = {
        ...     "config.json": '{"setting": "value"}',
        ...     "src": {
        ...         "main.py": "print('Hello world')",
        ...         "utils": {
        ...             "helpers.py": "def helper(): pass"
        ...         }
        ...     }
        ... }
        >>> with mock_file_system(structure) as root:
        ...     # Use the mock file system
        ...     assert (root / "config.json").exists()
        ...     assert (root / "src" / "main.py").exists()
    """
    with temp_directory() as root:
        _create_file_structure(root, file_structure)
        yield root


def _create_file_structure(
    base_path: Path, structure: Dict[str, Union[str, Dict]]
) -> None:
    """Helper function to recursively create a file structure."""
    for name, content in structure.items():
        path = base_path / name
        if isinstance(content, dict):
            # It's a directory
            path.mkdir(exist_ok=True)
            _create_file_structure(path, content)
        else:
            # It's a file
            path.write_text(content)
