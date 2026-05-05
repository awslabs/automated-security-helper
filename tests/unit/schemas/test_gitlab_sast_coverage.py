"""Comprehensive tests for schemas/gitlab/sast.py — instantiate all model classes to cover definitions."""

import pytest
import automated_security_helper.schemas.gitlab.sast as sast


class TestAllEnums:
    """Tests for all enum classes in the sast schema."""

    def test_level_enum(self):
        assert sast.Level.info.value == "info"
        assert sast.Level.warn.value == "warn"
        assert sast.Level.fatal.value == "fatal"

    def test_source_enum(self):
        assert sast.Source.argument.value == "argument"
        assert sast.Source.file.value == "file"
        assert sast.Source.env_variable.value == "env_variable"
        assert sast.Source.other.value == "other"

    def test_status_enum(self):
        assert sast.Status.success.value == "success"
        assert sast.Status.failure.value == "failure"

    def test_type_enum(self):
        assert sast.Type.sast.value == "sast"


class TestModelConstruction:
    """Tests that exercise model class instantiation."""

    def test_message(self):
        msg = sast.Message(level=sast.Level.info, value="Test message")
        assert msg.value == "Test message"

    def test_option(self):
        opt = sast.Option(name="TEST_OPT", value="test_value")
        assert opt.name == "TEST_OPT"

    def test_option_with_source(self):
        opt = sast.Option(name="OPT", source=sast.Source.file, value="val")
        assert opt.source == "file"

    def test_vendor(self):
        vendor = sast.Vendor(name="GitLab")
        assert vendor.name == "GitLab"

    def test_analyzer(self):
        analyzer = sast.Analyzer(
            id="test-analyzer",
            name="Test Analyzer",
            vendor=sast.Vendor(name="TestCo"),
            version="1.0.0",
        )
        assert analyzer.id == "test-analyzer"

    def test_scanner(self):
        scanner = sast.Scanner(
            id="test-scanner",
            name="Test Scanner",
            version="2.0.0",
            vendor=sast.Vendor(name="TestCo"),
        )
        assert scanner.id == "test-scanner"

    def test_primary_identifier(self):
        pid = sast.PrimaryIdentifier(
            type="cwe",
            name="CWE-79",
            value="79",
        )
        assert pid.type == "cwe"

    def test_primary_identifier_with_url(self):
        pid = sast.PrimaryIdentifier(
            type="cve",
            name="CVE-2021-44228",
            value="CVE-2021-44228",
            url="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",
        )
        assert pid.url is not None


class TestAllClassesImportable:
    """Ensure all classes in the module are importable and are types."""

    def test_all_classes_are_types(self):
        classes = [
            name
            for name in dir(sast)
            if isinstance(getattr(sast, name), type) and not name.startswith("_")
        ]
        assert len(classes) >= 10

    def test_model_classes_have_model_fields(self):
        """Pydantic models should have model_fields attribute."""
        from pydantic import BaseModel

        model_classes = [
            getattr(sast, name)
            for name in dir(sast)
            if isinstance(getattr(sast, name), type)
            and issubclass(getattr(sast, name), BaseModel)
            and name != "BaseModel"
            and name != "RootModel"
        ]
        for cls in model_classes:
            assert hasattr(cls, "model_fields"), f"{cls.__name__} missing model_fields"
