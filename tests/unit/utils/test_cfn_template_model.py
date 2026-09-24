"""Tests for cfn_template_model utilities."""

import logging

import pytest

from automated_security_helper.utils.cfn_template_model import (
    CloudFormationResource,
    CloudFormationTemplateModel,
    CloudFormationTemplateModelError,
    get_model_from_template,
)

# Resource type names CloudFormation documents as legal and this model used to reject.
# The AWS CloudFormation User Guide's "Specifying custom resource type names" says a
# custom resource type name may contain alphanumerics and the characters _@-, so each
# of these is a template a security scanner must scan rather than classify away.
DOCUMENTED_CUSTOM_RESOURCE_TYPES = [
    "Custom::Ash-Image-Bootstrap",
    "Custom::DB_Migrator",
    "Custom::My@Thing",
]

# The AWS::LanguageExtensions Fn::ForEach shape: the value under Resources is a
# three-element list, not a resource mapping. This model cannot represent it, which is
# a limitation of the model and not a property of the file -- so it must be reported,
# not silently classified as "not CloudFormation".
FN_FOR_EACH_TEMPLATE = """Transform: AWS::LanguageExtensions
Resources:
  Fn::ForEach::Buckets:
    - Identifier
    - - A
      - B
    - 'Bucket${Identifier}':
        Type: AWS::S3::Bucket
  Keep:
    Type: AWS::S3::Bucket
"""


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

    def test_document_without_resources_returns_none(self, tmp_path):
        """No Resources key means the document is not CloudFormation at all."""
        template_file = tmp_path / "bad.yaml"  # nosec B108
        # Missing Resources key entirely
        template_file.write_text("Description: no resources here\n")

        result = get_model_from_template(template_file)
        assert result is None

    def test_resources_that_is_not_a_mapping_returns_none(self, tmp_path):
        """A Resources key holding something other than a mapping is also a skip.

        The sentinel split turns on exactly one question -- is there a Resources
        mapping -- so the negative side of it needs its own case.
        """
        template_file = tmp_path / "list_resources.yaml"  # nosec B108
        template_file.write_text("Resources:\n  - not: a mapping\n")

        assert get_model_from_template(template_file) is None

    def test_invalid_resource_type_raises_rather_than_skipping(self, tmp_path):
        """A Resources mapping this model rejects is reported, not classified away.

        This assertion is the inverse of the one it replaces. Returning None here
        was the defect: both consumers read None as "not a CloudFormation file"
        and skip it without counting a target, so a scan set in which every
        template trips the model ended at zero attempts and reported SKIPPED with
        exit code 0. The file has a Resources mapping, so it is CloudFormation;
        failing to model it is this model's limitation and must be counted.
        """
        template_file = tmp_path / "bad_type.yaml"  # nosec B108
        template_file.write_text(
            "Resources:\n  Bad:\n    Type: 'invalid type with spaces'\n"
        )

        with pytest.raises(CloudFormationTemplateModelError) as excinfo:
            get_model_from_template(template_file)

        assert "bad_type.yaml" in str(excinfo.value)

    def test_rejection_is_logged_with_the_path_and_the_error(self, tmp_path, caplog):
        """The swallowed diagnostic is restored at WARNING, naming both.

        The original code had two commented-out debug lines, so the function
        emitted nothing at any verbosity and a template ASH could not model left
        no trace anywhere in the log.
        """
        template_file = tmp_path / "unmodelable.yaml"  # nosec B108
        template_file.write_text("Resources:\n  Bad:\n    Type: 'has spaces'\n")

        with caplog.at_level(logging.WARNING):
            with pytest.raises(CloudFormationTemplateModelError):
                get_model_from_template(template_file)

        messages = [record.message for record in caplog.records]
        assert any("unmodelable.yaml" in message for message in messages), messages
        assert any("Type" in message for message in messages), messages

    @pytest.mark.parametrize("resource_type", DOCUMENTED_CUSTOM_RESOURCE_TYPES)
    def test_documented_custom_resource_charset_is_modeled(
        self, tmp_path, resource_type
    ):
        """Custom resource type names containing _, @ or - are CloudFormation.

        Each of these was rejected by the original ^([a-zA-Z0-9:]+)$ pattern, and
        the rejection was indistinguishable from "this file is not a template".
        """
        template_file = tmp_path / "custom.yaml"  # nosec B108
        template_file.write_text(
            f"Resources:\n  Thing:\n    Type: '{resource_type}'\n"
            "  Bucket:\n    Type: AWS::S3::Bucket\n"
        )

        result = get_model_from_template(template_file)

        assert result is not None
        assert result.Resources["Thing"].Type == resource_type
        assert "Bucket" in result.Resources

    def test_fn_for_each_shape_is_reported_rather_than_skipped(self, tmp_path):
        """An Fn::ForEach key under Resources is a failed target, not a skip.

        Widening the charset does not make this shape representable: the value is
        a three-element list where a resource mapping is expected. Accepting the
        document would hand a list to code downstream that expects a mapping, so
        the honest answer is to report that the template went unevaluated.
        """
        template_file = tmp_path / "for_each.yaml"  # nosec B108
        template_file.write_text(FN_FOR_EACH_TEMPLATE)

        with pytest.raises(CloudFormationTemplateModelError):
            get_model_from_template(template_file)
