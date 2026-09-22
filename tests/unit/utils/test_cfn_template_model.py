"""Tests for cfn_template_model utilities."""

from pathlib import Path
from unittest.mock import patch, mock_open

import pytest

from automated_security_helper.utils.cfn_template_model import (
    CloudFormationResource,
    CloudFormationTemplateModel,
    get_model_from_template,
)


class TestCloudFormationResource:
    """Tests for CloudFormationResource model."""

    def test_valid_type(self):
        """A valid Type string passes validation."""
        resource = CloudFormationResource(Type="AWS::S3::Bucket")
        assert resource.Type == "AWS::S3::Bucket"

    def test_invalid_type_rejected(self):
        """A Type with invalid characters is rejected."""
        with pytest.raises(Exception):
            CloudFormationResource(Type="AWS::S3::Bucket!!")

    def test_extra_fields_allowed(self):
        """Extra fields are allowed due to ConfigDict(extra='allow')."""
        resource = CloudFormationResource(
            Type="AWS::Lambda::Function", Properties={"Handler": "index.handler"}
        )
        assert resource.Properties == {"Handler": "index.handler"}


class TestCloudFormationTemplateModel:
    """Tests for CloudFormationTemplateModel."""

    def test_valid_template(self):
        """A valid template with Resources parses correctly."""
        model = CloudFormationTemplateModel(
            Resources={"MyBucket": CloudFormationResource(Type="AWS::S3::Bucket")}
        )
        assert "MyBucket" in model.Resources
        assert model.Resources["MyBucket"].Type == "AWS::S3::Bucket"

    def test_extra_top_level_fields_allowed(self):
        """Extra top-level keys like AWSTemplateFormatVersion are allowed."""
        model = CloudFormationTemplateModel(
            AWSTemplateFormatVersion="2010-09-09",
            Resources={"Fn": CloudFormationResource(Type="AWS::Lambda::Function")},
        )
        assert model.AWSTemplateFormatVersion == "2010-09-09"


class TestGetModelFromTemplate:
    """Tests for get_model_from_template function."""

    def test_returns_none_for_none_path(self):
        """Passing None returns None."""
        assert get_model_from_template(None) is None

    def test_valid_yaml_template(self, tmp_path):
        """A valid YAML CloudFormation template is parsed into a model."""
        template_file = tmp_path / "template.yaml"  # nosec B108
        template_file.write_text(
            "Resources:\n"
            "  MyBucket:\n"
            "    Type: AWS::S3::Bucket\n"
        )

        result = get_model_from_template(template_file)

        assert result is not None
        assert "MyBucket" in result.Resources
        assert result.Resources["MyBucket"].Type == "AWS::S3::Bucket"

    def test_invalid_template_returns_none(self, tmp_path):
        """A template that fails validation returns None."""
        template_file = tmp_path / "bad.yaml"  # nosec B108
        # Missing Resources key entirely
        template_file.write_text("Description: no resources here\n")

        result = get_model_from_template(template_file)
        assert result is None

    def test_invalid_resource_type_returns_none(self, tmp_path):
        """A template with an invalid resource Type pattern returns None."""
        template_file = tmp_path / "bad_type.yaml"  # nosec B108
        template_file.write_text(
            "Resources:\n"
            "  Bad:\n"
            "    Type: 'invalid type with spaces'\n"
        )

        result = get_model_from_template(template_file)
        assert result is None
