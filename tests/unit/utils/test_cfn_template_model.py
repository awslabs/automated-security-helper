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
        template_file.write_text("Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n")

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
            "Resources:\n  Bad:\n    Type: 'invalid type with spaces'\n"
        )

        result = get_model_from_template(template_file)
        assert result is None

    # The parse step used to run above the try that wraps model_validate, so these
    # inputs raised out of the function rather than being skipped. Both are real files
    # found in ordinary repositories, which is why they are the cases chosen here: the
    # scan set is whatever the tree contains, not a curated set of templates.
    def test_json_with_comments_returns_none(self, tmp_path):
        """A tsconfig.json-style file with // comments returns None, not ParserError."""
        template_file = tmp_path / "tsconfig.json"  # nosec B108
        template_file.write_text(
            "{\n"
            "  // comments are legal in tsconfig.json and not in YAML\n"
            '  "compilerOptions": {"strict": true}\n'
            "}\n"
        )

        assert get_model_from_template(template_file) is None

    def test_python_name_tag_returns_none(self, tmp_path):
        """A mkdocs.yml-style !!python/name: tag returns None, not ConstructorError."""
        template_file = tmp_path / "mkdocs.yml"  # nosec B108
        template_file.write_text(
            "markdown_extensions:\n"
            "  - pymdownx.emoji:\n"
            "      emoji_index: !!python/name:material.extensions.emoji.twemoji\n"
        )

        assert get_model_from_template(template_file) is None

    def test_undecodable_file_returns_none(self, tmp_path):
        """A file that is not valid UTF-8 returns None rather than UnicodeDecodeError.

        This one fails in the read rather than the parse, which is why the read is
        inside the try as well -- otherwise it escapes by the route the parse error
        used to.
        """
        template_file = tmp_path / "binary.yaml"  # nosec B108
        template_file.write_bytes(b"\xff\xfe\x00Resources:\x00")

        assert get_model_from_template(template_file) is None

    def test_missing_file_returns_none(self, tmp_path):
        """A path that does not exist returns None rather than FileNotFoundError."""
        assert get_model_from_template(tmp_path / "absent.yaml") is None  # nosec B108
