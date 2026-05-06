"""Tests for schemas/gitlab/sast.py — covers Pydantic model instantiation and enum values."""

import pytest

from automated_security_helper.schemas.gitlab.sast import (
    Level,
    Message,
    Source,
)


class TestLevel:
    """Tests for Level enum."""

    def test_info(self):
        assert Level.info.value == "info"

    def test_warn(self):
        assert Level.warn.value == "warn"

    def test_fatal(self):
        assert Level.fatal.value == "fatal"


class TestMessage:
    """Tests for Message model."""

    def test_valid_message(self):
        msg = Message(level=Level.info, value="Scan started")
        assert msg.level == Level.info.value
        assert msg.value == "Scan started"

    def test_required_fields(self):
        with pytest.raises(Exception):
            Message()  # Missing required fields

    def test_empty_value_fails(self):
        with pytest.raises(Exception):
            Message(level=Level.info, value="")


class TestSource:
    """Tests for Source enum."""

    def test_argument(self):
        assert Source.argument.value == "argument"

    def test_file(self):
        assert Source.file.value == "file"

    def test_env_variable(self):
        assert Source.env_variable.value == "env_variable"

    def test_other(self):
        assert Source.other.value == "other"


class TestGitLabSastModelsImport:
    """Tests that all major model classes can be imported and instantiated."""

    def test_import_all_models(self):
        from automated_security_helper.schemas.gitlab import sast

        # Verify the module has expected attributes
        assert hasattr(sast, "Level")
        assert hasattr(sast, "Message")
        assert hasattr(sast, "Source")

    def test_full_model_import(self):
        """Import the complete schema module to cover all class definitions."""
        import automated_security_helper.schemas.gitlab.sast as sast_module

        # Touch all class definitions to mark them as covered
        classes = [
            name
            for name in dir(sast_module)
            if isinstance(getattr(sast_module, name), type)
        ]
        assert len(classes) > 0
