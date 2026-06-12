"""Example tests demonstrating effective use of fixtures.

This module demonstrates best practices for creating and using fixtures in tests.
"""

import json
import pytest
import os
import tempfile
from pathlib import Path
import yaml


# Basic fixtures
@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def temp_file(temp_dir):
    """Create a temporary file for tests."""
    file_path = temp_dir / "test.txt"
    file_path.write_text("Test content")
    return file_path


@pytest.fixture
def temp_python_file(temp_dir):
    """Create a temporary Python file for tests."""
    file_path = temp_dir / "test.py"
    file_path.write_text("print('Hello, world!')")
    return file_path


# Parameterized fixtures
@pytest.fixture(params=["json", "yaml"])
def config_file(request, temp_dir):
    """Create a configuration file in different formats."""
    config_data = {
        "scanners": {"example": {"enabled": True, "options": {"severity": "HIGH"}}}
    }

    if request.param == "json":
        file_path = temp_dir / "config.json"
        with open(file_path, "w") as f:
            json.dump(config_data, f)
    else:  # yaml
        file_path = temp_dir / "config.yaml"
        with open(file_path, "w") as f:
            yaml.dump(config_data, f)

    return file_path


# Factory fixtures
@pytest.fixture
def make_python_file():
    """Factory fixture to create Python files with custom content."""
    created_files = []

    def _make_python_file(content, directory=None):
        if directory is None:
            directory = tempfile.mkdtemp()
        else:
            directory = Path(directory)
            directory.mkdir(exist_ok=True)

        file_path = Path(directory) / f"test_{len(created_files)}.py"
        file_path.write_text(content)
        created_files.append(file_path)
        return file_path

    yield _make_python_file

    # Clean up
    for file_path in created_files:
        if file_path.exists():
            file_path.unlink()


# Fixtures with cleanup
@pytest.fixture
def env_vars(ash_temp_path):
    """Set environment variables for tests and restore them afterward."""
    # Save original environment variables
    original_vars = {}
    for key in ["ASH_CONFIG_PATH", "ASH_DEBUG"]:
        if key in os.environ:
            original_vars[key] = os.environ[key]

    # Set test environment variables
    os.environ["ASH_CONFIG_PATH"] = f"{ash_temp_path}/config.yaml"
    os.environ["ASH_DEBUG"] = "true"

    yield

    # Restore original environment variables
    for key in ["ASH_CONFIG_PATH", "ASH_DEBUG"]:
        if key in original_vars:
            os.environ[key] = original_vars[key]
        else:
            os.environ.pop(key, None)


# Fixtures with autouse
@pytest.fixture(autouse=True)
def setup_test_environment():
    """Set up the test environment before each test."""
    # This fixture runs automatically for each test in this module
    print("Setting up test environment")
    yield
    print("Tearing down test environment")


# Mock class for demonstration
class ExampleScanner:
    """Example scanner class for demonstration purposes."""

    def __init__(self, config=None):
        self.name = "example"
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.findings = []

    def scan_file(self, file_path):
        """Scan a file for security issues."""
        file_path = Path(file_path)
        content = file_path.read_text()
        findings = []

        if "import pickle" in content:
            findings.append(
                {
                    "file_path": str(file_path),
                    "line": content.find("import pickle") + 1,
                    "message": "Unsafe pickle usage detected",
                    "severity": "HIGH",
                    "rule_id": "EX001",
                }
            )

        self.findings = findings
        return findings


# Fixture for the scanner
@pytest.fixture
def example_scanner():
    """Create an instance of ExampleScanner for testing."""
    return ExampleScanner()


# Fixture with custom configuration
@pytest.fixture
def configured_scanner():
    """Create an instance of ExampleScanner with custom configuration."""
    config = {"enabled": True, "options": {"severity": "HIGH"}}
    return ExampleScanner(config)


# Tests demonstrating fixture usage
def test_basic_fixtures(temp_dir, temp_file):
    """Test using basic fixtures."""
    assert temp_dir.exists()
    assert temp_file.exists()
    assert temp_file.read_text() == "Test content"


def test_parameterized_fixtures(config_file):
    """Test using parameterized fixtures."""
    assert config_file.exists()

    # Load the configuration
    if config_file.suffix == ".json":
        with open(config_file, "r") as f:
            config = json.load(f)
    else:  # .yaml
        with open(config_file, "r") as f:
            config = yaml.safe_load(f)

    # Verify the configuration
    assert "scanners" in config
    assert "example" in config["scanners"]
    assert config["scanners"]["example"]["enabled"] is True
    assert config["scanners"]["example"]["options"]["severity"] == "HIGH"


def test_factory_fixtures(make_python_file, ash_temp_path):
    """Test using factory fixtures."""
    # Create Python files with different content
    file1 = make_python_file("print('Hello, world!')", ash_temp_path)
    file2 = make_python_file("import pickle\npickle.loads(b'')", ash_temp_path)

    # Verify the files
    assert file1.exists()
    assert file2.exists()
    assert file1.read_text() == "print('Hello, world!')"
    assert file2.read_text() == "import pickle\npickle.loads(b'')"


def test_env_vars_fixture(env_vars, ash_temp_path):
    """Test using environment variable fixtures."""
    assert os.environ["ASH_CONFIG_PATH"] == f"{ash_temp_path}/config.yaml"
    assert os.environ["ASH_DEBUG"] == "true"


def test_scanner_fixture(example_scanner, temp_python_file):
    """Test using the scanner fixture."""
    # Modify the Python file to include unsafe code
    temp_python_file.write_text("import pickle\npickle.loads(b'')")

    # Scan the file
    findings = example_scanner.scan_file(temp_python_file)

    # Verify the findings
    assert len(findings) == 1
    assert findings[0]["file_path"] == str(temp_python_file)
    assert findings[0]["message"] == "Unsafe pickle usage detected"


def test_configured_scanner_fixture(configured_scanner, temp_python_file):
    """Test using the configured scanner fixture."""
    # Verify the scanner configuration
    assert configured_scanner.enabled is True
    assert configured_scanner.config["options"]["severity"] == "HIGH"

    # Modify the Python file to include unsafe code
    temp_python_file.write_text("import pickle\npickle.loads(b'')")

    # Scan the file
    findings = configured_scanner.scan_file(temp_python_file)

    # Verify the findings
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


# Example of fixture composition
@pytest.fixture
def vulnerable_python_file(make_python_file, temp_dir):
    """Create a Python file with vulnerable code."""
    return make_python_file("import pickle\npickle.loads(b'')", temp_dir)


def test_fixture_composition(example_scanner, vulnerable_python_file):
    """Test using composed fixtures."""
    # Scan the file
    findings = example_scanner.scan_file(vulnerable_python_file)

    # Verify the findings
    assert len(findings) == 1
    assert findings[0]["file_path"] == str(vulnerable_python_file)
    assert findings[0]["message"] == "Unsafe pickle usage detected"


# Example of fixture scopes
@pytest.fixture(scope="module")
def module_scoped_resource():
    """Create a resource that is shared across all tests in the module."""
    print("Creating module-scoped resource")
    resource = {"data": "test"}
    yield resource
    print("Cleaning up module-scoped resource")


@pytest.fixture(scope="function")
def function_scoped_resource(module_scoped_resource):
    """Create a resource for each test function."""
    print("Creating function-scoped resource")
    resource = module_scoped_resource.copy()
    resource["function_data"] = "test"
    yield resource
    print("Cleaning up function-scoped resource")


def test_fixture_scopes_1(module_scoped_resource, function_scoped_resource):
    """First test using scoped fixtures."""
    assert module_scoped_resource["data"] == "test"
    assert function_scoped_resource["function_data"] == "test"

    # Modify the function-scoped resource
    function_scoped_resource["function_data"] = "modified"
    assert function_scoped_resource["function_data"] == "modified"


def test_fixture_scopes_2(module_scoped_resource, function_scoped_resource):
    """Second test using scoped fixtures."""
    assert module_scoped_resource["data"] == "test"
    # The function-scoped resource is recreated for each test
    assert function_scoped_resource["function_data"] == "test"


# Example of fixture with yield
@pytest.fixture
def scanner_with_cleanup():
    """Create a scanner and clean up after the test."""
    print("Creating scanner")
    scanner = ExampleScanner()
    yield scanner
    print("Cleaning up scanner")
    scanner.findings = []


def test_fixture_with_yield(scanner_with_cleanup, vulnerable_python_file):
    """Test using a fixture with yield."""
    # Scan the file
    findings = scanner_with_cleanup.scan_file(vulnerable_python_file)

    # Verify the findings
    assert len(findings) == 1
    assert findings[0]["file_path"] == str(vulnerable_python_file)
    assert findings[0]["message"] == "Unsafe pickle usage detected"


# Example of fixture with finalizer
@pytest.fixture
def scanner_with_finalizer(request):
    """Create a scanner and register a finalizer."""
    print("Creating scanner")
    scanner = ExampleScanner()

    def finalizer():
        print("Cleaning up scanner")
        scanner.findings = []

    request.addfinalizer(finalizer)
    return scanner


def test_fixture_with_finalizer(scanner_with_finalizer, vulnerable_python_file):
    """Test using a fixture with finalizer."""
    # Scan the file
    findings = scanner_with_finalizer.scan_file(vulnerable_python_file)

    # Verify the findings
    assert len(findings) == 1
    assert findings[0]["file_path"] == str(vulnerable_python_file)
    assert findings[0]["message"] == "Unsafe pickle usage detected"
