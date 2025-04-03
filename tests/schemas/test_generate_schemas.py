"""Unit tests for schema generation module."""

from automated_security_helper.schemas.generate_schemas import generate_schemas


def test_generate_json_schema():
    # Test generating schema for a single model
    schema = generate_schemas("dict")
    assert isinstance(schema, dict)
    assert "ASHConfig" in schema
    assert "ASHARPModel" in schema

    # Validate schema structure
    assert "type" in schema["ASHConfig"]
    assert "properties" in schema["ASHConfig"]
    assert isinstance(schema["ASHConfig"]["properties"], dict)

    assert "type" in schema["ASHARPModel"]
    assert "properties" in schema["ASHARPModel"]
    assert isinstance(schema["ASHARPModel"]["properties"], dict)
