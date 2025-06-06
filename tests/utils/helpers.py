"""Helper functions for ASH tests."""

import tempfile
from pathlib import Path
from typing import Optional, Union, List, Dict, Any


def create_test_file(content: str, suffix: str = ".py", delete: bool = False) -> Path:
    """Create a temporary file with the given content for testing.

    Args:
        content: The content to write to the file
        suffix: The file suffix (default: .py)
        delete: Whether to delete the file when the test is done (default: False)

    Returns:
        Path to the created file
    """
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
        f.write(content.encode("utf-8"))
    return Path(f.name)


def create_test_directory(
    files: Dict[str, str], base_dir: Optional[Path] = None
) -> Path:
    """Create a temporary directory with the given files for testing.

    Args:
        files: Dictionary mapping file names to content
        base_dir: Optional base directory (default: temporary directory)

    Returns:
        Path to the created directory
    """
    if base_dir is None:
        base_dir = Path(tempfile.mkdtemp())

    for file_name, content in files.items():
        file_path = base_dir / file_name
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content)

    return base_dir


def create_python_file_with_issues(path: Union[str, Path]) -> Path:
    """Create a Python file with common security issues for testing.

    Args:
        path: Path where the file should be created

    Returns:
        Path to the created file
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    content = """
import os
import subprocess
import pickle

def unsafe_function():
    # OS command injection vulnerability
    user_input = "user_input"
    os.system(f"echo {user_input}")  # nosec

    # Unsafe deserialization
    with open("data.pkl", "rb") as f:
        data = pickle.load(f)  # nosec

    # Eval injection
    expr = "2 + 2"
    result = eval(expr)  # nosec

    # Shell injection
    cmd = ["ls", "-la"]
    subprocess.call(" ".join(cmd), shell=True)  # nosec

    return result
"""

    path.write_text(content)
    return path


def create_test_config_file(
    config_data: Dict[str, Any], path: Union[str, Path]
) -> Path:
    """Create a test configuration file with the given data.

    Args:
        config_data: Configuration data to write
        path: Path where the file should be created

    Returns:
        Path to the created file
    """
    import yaml

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w") as f:
        yaml.dump(config_data, f)

    return path


def create_sarif_test_file(
    path: Union[str, Path], findings: List[Dict[str, Any]] = None
) -> Path:
    """Create a test SARIF file with the given findings.

    Args:
        path: Path where the file should be created
        findings: List of findings to include (optional)

    Returns:
        Path to the created file
    """
    import json

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if findings is None:
        findings = [
            {
                "ruleId": "TEST-001",
                "message": {"text": "Test finding 1"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/example.py"},
                            "region": {"startLine": 10, "endLine": 15},
                        }
                    }
                ],
            },
            {
                "ruleId": "TEST-002",
                "message": {"text": "Test finding 2"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/other.py"},
                            "region": {"startLine": 20, "endLine": 25},
                        }
                    }
                ],
            },
        ]

    sarif_data = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "Test Scanner", "version": "1.0.0"}},
                "results": findings,
            }
        ],
    }

    with open(path, "w") as f:
        json.dump(sarif_data, f, indent=2)

    return path


def create_iac_test_file(
    path: Union[str, Path], file_type: str = "cloudformation"
) -> Path:
    """Create a test Infrastructure as Code file for testing.

    Args:
        path: Path where the file should be created
        file_type: Type of IaC file to create (cloudformation, terraform, etc.)

    Returns:
        Path to the created file
    """
    import yaml

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if file_type.lower() == "cloudformation":
        content = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "S3Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": "test-bucket"
                        # Missing encryption and other security settings
                    },
                },
                "SecurityGroup": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "Test security group",
                        "SecurityGroupIngress": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "CidrIp": "0.0.0.0/0",  # Security issue: open to the world
                            }
                        ],
                    },
                },
            },
        }

        with open(path, "w") as f:
            yaml.dump(content, f)

    elif file_type.lower() == "terraform":
        content = """
resource "aws_s3_bucket" "test_bucket" {
  bucket = "test-bucket"
  # Missing encryption and other security settings
}

resource "aws_security_group" "test_sg" {
  name        = "test-sg"
  description = "Test security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Security issue: open to the world
  }
}
"""

        with open(path, "w") as f:
            f.write(content)

    return path


def create_context_manager_for_test_environment():
    """Create a context manager for setting up and tearing down a test environment.

    Returns:
        A context manager that sets up and tears down a test environment
    """
    import contextlib
    import tempfile
    import shutil

    @contextlib.contextmanager
    def test_environment():
        """Context manager for setting up and tearing down a test environment."""
        temp_dir = tempfile.mkdtemp()
        try:
            source_dir = Path(temp_dir) / "source"
            output_dir = Path(temp_dir) / "output"
            source_dir.mkdir()
            output_dir.mkdir()

            yield {
                "temp_dir": Path(temp_dir),
                "source_dir": source_dir,
                "output_dir": output_dir,
            }
        finally:
            shutil.rmtree(temp_dir)

    return test_environment


# Create the test environment context manager
test_environment = create_context_manager_for_test_environment()
