"""Unit tests for schema generation module."""

from automated_security_helper.schemas.generate_schemas import generate_schemas


class TestSchemaGeneration:
    """Test cases for schema generation."""

    def test_generate_json_schema(self):
        """Test generating JSON schema for models."""
        # Test generating schema for a single model
        schema = generate_schemas("dict")
        assert isinstance(schema, dict)
        assert "AshConfig" in schema
        assert "AshAggregatedResults" in schema

        # Check that the schema has the expected structure
        # The schema structure might be different depending on Pydantic version
        # So we just check that we have a dictionary with the expected keys
        assert isinstance(schema["AshConfig"], dict)
        assert isinstance(schema["AshAggregatedResults"], dict)
