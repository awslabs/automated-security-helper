"""Pytest configuration file for ASH tests."""

import os
import sys
import pytest
from pathlib import Path
from typing import List, Literal

from tests.utils.helpers import get_ash_temp_path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))


def pytest_configure(config):
    """Configure pytest for ASH tests."""
    # Register custom markers
    config.addinivalue_line(
        "markers", "unit: Unit tests that test individual components in isolation"
    )
    config.addinivalue_line(
        "markers", "integration: Integration tests that test component interactions"
    )
    config.addinivalue_line("markers", "slow: Tests that take a long time to run")
    config.addinivalue_line(
        "markers", "scanner: Tests related to scanner functionality"
    )
    config.addinivalue_line(
        "markers", "reporter: Tests related to reporter functionality"
    )
    config.addinivalue_line(
        "markers", "config: Tests related to configuration functionality"
    )
    config.addinivalue_line("markers", "model: Tests related to data models")
    config.addinivalue_line("markers", "serial: Tests that should not run in parallel")


def pytest_addoption(parser):
    """Add custom command-line options to pytest."""
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="Run slow tests",
    )
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests",
    )
    parser.addoption(
        "--run-changed-only",
        action="store_true",
        default=False,
        help="Run only tests for changed files",
    )
    parser.addoption(
        "--base-branch",
        default="main",
        help="Base branch for --run-changed-only option",
    )


def pytest_collection_modifyitems(config, items):
    """Modify the collected test items based on command-line options."""
    # Skip slow tests unless --run-slow is specified
    if not config.getoption("--run-slow"):
        skip_slow = pytest.mark.skip(reason="Need --run-slow option to run")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)

    # Skip integration tests unless --run-integration is specified
    if not config.getoption("--run-integration"):
        skip_integration = pytest.mark.skip(
            reason="Need --run-integration option to run"
        )
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_integration)


@pytest.fixture
def ash_temp_path():
    """Create a temporary directory using the gitignored tests/pytest-temp directory.

    This fixture provides a consistent temporary directory that is gitignored
    and located within the tests directory structure.

    Returns:
        Path to the temporary directory
    """
    import shutil

    temp_dir = get_ash_temp_path()
    yield temp_dir

    # Cleanup after the test
    if temp_dir.exists():
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def temp_config_dir(ash_temp_path):
    """Create a temporary directory for configuration files.

    Args:
        ash_temp_path: ASH fixture that provides a temporary directory

    Returns:
        Path to the temporary configuration directory
    """
    config_dir = ash_temp_path / "config"
    config_dir.mkdir()
    return config_dir


@pytest.fixture
def temp_output_dir(ash_temp_path):
    """Create a temporary directory for output files.

    Args:
        ash_temp_path: ASH fixture that provides a temporary directory

    Returns:
        Path to the temporary output directory
    """
    output_dir = ash_temp_path / "output"
    output_dir.mkdir()
    return output_dir


@pytest.fixture
def temp_project_dir(ash_temp_path):
    """Create a temporary directory for project files.

    Args:
        ash_temp_path: ASH fixture that provides a temporary directory

    Returns:
        Path to the temporary project directory
    """
    project_dir = ash_temp_path / "project"
    project_dir.mkdir()

    # Create a basic project structure
    (project_dir / "src").mkdir()
    (project_dir / "tests").mkdir()
    (project_dir / ".ash").mkdir()

    return project_dir


@pytest.fixture
def temp_env_vars():
    """Create a fixture for temporarily setting environment variables.

    Returns:
        Function that sets environment variables for the duration of a test
    """
    original_env = {}

    def _set_env_vars(**kwargs):
        for key, value in kwargs.items():
            if key in os.environ:
                original_env[key] = os.environ[key]
            os.environ[key] = str(value)

    yield _set_env_vars

    # Restore original environment variables
    for key in original_env:
        os.environ[key] = original_env[key]

    # Remove environment variables that were not originally set
    for key in os.environ.keys() - original_env.keys():
        if key in os.environ:
            del os.environ[key]


@pytest.fixture
def test_plugin_context(ash_temp_path):
    """Create a test plugin context for testing.

    Returns:
        A mock plugin context for testing
    """
    from automated_security_helper.base.plugin_context import PluginContext
    from pathlib import Path

    # Create a real PluginContext object instead of a mock
    source_dir = Path(f"{ash_temp_path}/test_source_dir")
    output_dir = Path(f"{ash_temp_path}/test_output_dir")
    work_dir = Path(f"{ash_temp_path}/test_work_dir")

    # Use a proper AshConfig object
    from automated_security_helper.config.default_config import get_default_config

    # Use default config to ensure all required fields are present
    config = get_default_config()

    context = PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=config,
    )

    return context


@pytest.fixture
def test_source_dir(ash_temp_path):
    """Create a test source directory with sample files.

    Args:
        ash_temp_path: ASH fixture that provides a temporary directory

    Returns:
        Path to the test source directory
    """
    source_dir = ash_temp_path / "source"
    Path(source_dir).mkdir(exist_ok=True, parents=True)

    # Create a sample file
    test_file = source_dir / "test.py"
    test_file.write_text("print('Hello, world!')")

    return source_dir


@pytest.fixture
def sample_ash_model():
    """Create a mock ASH model for testing."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    # Create a real model instead of a mock
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.config.ash_config import AshConfig

    # First define AshConfig and rebuild the model
    AshConfig.model_rebuild()
    AshAggregatedResults.model_rebuild()

    # Now create the model
    model = AshAggregatedResults()
    model.metadata.scanner_name = "test_scanner"
    model.metadata.scan_id = "test_scan_id"
    model.ash_config = get_default_config()

    return model


@pytest.fixture
def test_data_dir(ash_temp_path):
    """Create a test data directory with sample files."""
    data_dir = ash_temp_path / "test_data"
    Path(data_dir).mkdir(exist_ok=True, parents=True)

    # Create a sample CloudFormation template
    cfn_dir = data_dir / "cloudformation"
    cfn_dir.mkdir()
    cfn_file = cfn_dir / "template.yaml"
    cfn_file.write_text("""
    Resources:
      MyBucket:
        Type: AWS::S3::Bucket
        Properties:
          BucketName: my-test-bucket
    """)

    # Create a sample Terraform file
    tf_dir = data_dir / "terraform"
    tf_dir.mkdir()
    tf_file = tf_dir / "main.tf"
    tf_file.write_text("""
    resource "aws_s3_bucket" "my_bucket" {
      bucket = "my-test-bucket"
    }
    """)

    return data_dir


@pytest.fixture
def test_output_dir(ash_temp_path):
    """Create a test output directory."""
    output_dir = ash_temp_path / "output"
    Path(output_dir).mkdir(exist_ok=True, parents=True)
    return output_dir


# Add fixtures for the test plugin classes to fix validation errors
@pytest.fixture
def dummy_scanner_config():
    """Create a dummy scanner config for testing."""
    from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase

    class DummyConfig(ScannerPluginConfigBase):
        """Dummy config for testing."""

        name: str = "dummy"

    return DummyConfig()


@pytest.fixture
def dummy_reporter_config():
    """Create a dummy reporter config for testing."""
    from automated_security_helper.base.reporter_plugin import ReporterPluginConfigBase

    class DummyConfig(ReporterPluginConfigBase):
        """Dummy config for testing."""

        name: str = "dummy"
        extension: str = ".txt"

    return DummyConfig()


@pytest.fixture
def dummy_converter_config():
    """Create a dummy converter config for testing."""
    from automated_security_helper.base.converter_plugin import (
        ConverterPluginConfigBase,
    )

    class DummyConfig(ConverterPluginConfigBase):
        """Dummy config for testing."""

        name: str = "dummy"

    return DummyConfig()


@pytest.fixture
def dummy_scanner(test_plugin_context, dummy_scanner_config):
    """Create a dummy scanner for testing."""
    from automated_security_helper.base.scanner_plugin import ScannerPluginBase
    from automated_security_helper.schemas.sarif_schema_model import SarifReport
    from pathlib import Path

    class DummyScanner(ScannerPluginBase):
        """Dummy scanner for testing."""

        def validate(self) -> bool:
            return True

        def scan(
            self,
            target: Path,
            target_type: Literal["source", "converted"],
            global_ignore_paths: List | None = None,
            config=None,
            *args,
            **kwargs,
        ):
            if global_ignore_paths is None:
                global_ignore_paths = []

            self.output.append("hello world")
            return SarifReport(
                version="2.1.0",
                runs=[],
            )

    # Initialize with required config
    scanner = DummyScanner(config=dummy_scanner_config, context=test_plugin_context)
    return scanner


@pytest.fixture
def dummy_reporter(test_plugin_context, dummy_reporter_config):
    """Create a dummy reporter for testing."""
    from automated_security_helper.base.reporter_plugin import ReporterPluginBase
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    class DummyReporter(ReporterPluginBase):
        """Dummy reporter for testing."""

        def validate(self) -> bool:
            return True

        def report(self, model: AshAggregatedResults) -> str:
            return '{"report": "complete"}'

    # Initialize with required config
    reporter = DummyReporter(config=dummy_reporter_config, context=test_plugin_context)
    return reporter


@pytest.fixture
def dummy_converter(test_plugin_context, dummy_converter_config):
    """Create a dummy converter for testing."""
    from automated_security_helper.base.converter_plugin import ConverterPluginBase
    from pathlib import Path

    class DummyConverter(ConverterPluginBase):
        """Dummy converter for testing."""

        def validate(self) -> bool:
            return True

        def convert(self) -> list[Path]:
            return [Path("test.txt")]

    # Initialize with required config
    converter = DummyConverter(
        config=dummy_converter_config, context=test_plugin_context
    )
    return converter
