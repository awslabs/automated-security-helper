"""Tests for utils/get_scan_set.py — covers scan set detection logic."""

from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from automated_security_helper.utils.get_scan_set import scan_set


class TestScanSet:
    """Tests for the scan_set function."""

    def test_empty_directory(self, tmp_path):
        result = scan_set(tmp_path)
        assert isinstance(result, (set, list))

    def test_python_files_detected(self, tmp_path):
        (tmp_path / "main.py").write_text("x = 1")
        result = scan_set(tmp_path)
        assert len(result) > 0

    def test_terraform_files_detected(self, tmp_path):
        (tmp_path / "main.tf").write_text("resource {}")
        result = scan_set(tmp_path)
        assert len(result) > 0
        assert any("main.tf" in str(f) for f in result)

    def test_cloudformation_yaml_detected(self, tmp_path):
        cfn_content = "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n"
        (tmp_path / "template.yaml").write_text(cfn_content)
        result = scan_set(tmp_path)
        assert len(result) > 0

    def test_package_json_detected(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "test"}')
        result = scan_set(tmp_path)
        assert len(result) > 0

    def test_dockerfile_detected(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM python:3.12")
        result = scan_set(tmp_path)
        assert len(result) > 0

    def test_cdk_json_detected(self, tmp_path):
        (tmp_path / "cdk.json").write_text('{"app": "node"}')
        result = scan_set(tmp_path)
        assert len(result) > 0

    def test_nested_files_detected(self, tmp_path):
        sub = tmp_path / "src" / "app"
        sub.mkdir(parents=True)
        (sub / "handler.py").write_text("def handler(): pass")
        result = scan_set(tmp_path)
        assert len(result) > 0

    def test_returns_collection(self, tmp_path):
        result = scan_set(tmp_path)
        assert isinstance(result, (set, list))
