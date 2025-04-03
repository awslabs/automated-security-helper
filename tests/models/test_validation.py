"""Unit tests for validation module."""

from automated_security_helper.models.validation import ConfigurationValidator
from automated_security_helper.models.config import ScannerConfig


def test_validate_config():
    """Test basic config validation functionality."""
    validator = ConfigurationValidator()

    # Test valid dict config
    valid_dict = {"name": "test", "type": "static"}
    is_valid, error = validator.validate_config(valid_dict, ScannerConfig)
    assert is_valid is True
    assert error is None

    # Test valid model config
    valid_model = ScannerConfig(name="test", type="static")
    is_valid, error = validator.validate_config(valid_model, ScannerConfig)
    assert is_valid is True
    assert error is None

    # Test invalid config
    invalid_config = {}
    is_valid, error = validator.validate_config(invalid_config, ScannerConfig)
    assert is_valid is False
    assert "Empty configuration" in str(error)

    # Test invalid type
    is_valid, error = validator.validate_config(None, ScannerConfig)  # type: ignore
    assert not is_valid
    assert error is not None


def test_validate_scanner_config():
    """Test validation of scanner configurations."""
    validator = ConfigurationValidator()

    # Test valid scanner config
    valid_scanner_config = {"name": "scanner1", "type": "static"}
    result = validator.validate_scanner_config(valid_scanner_config)
    assert isinstance(result, tuple)
    assert result[0] is True
    assert result[1] is None

    # Test invalid scanner config (None)
    is_valid, error = validator.validate_scanner_config(None)  # type: ignore
    assert is_valid is False
    assert error is not None

    # Test invalid scanner config (missing required fields)
    invalid_config = {}
    is_valid, error = validator.validate_scanner_config(invalid_config)
    assert is_valid is False
    assert error is not None
    assert "Empty configuration" in str(error)


def test_validate_parser_config():
    """Test validation of parser configurations."""
    validator = ConfigurationValidator()

    # Test valid parser config
    valid_parser_config = {
        "name": "json-parser",
        "type": "json",
        "output_format": "json",
        "config": {"format": "json"},
    }
    is_valid, error = validator.validate_parser_config(valid_parser_config)
    assert is_valid is True
    assert error is None

    # Test invalid parser config
    invalid_parser_config = {"name": "json-parser", "type": "json"}
    is_valid, error = validator.validate_parser_config(invalid_parser_config)
    assert is_valid is False
    assert error is not None

    # Test None config
    is_valid, error = validator.validate_parser_config(None)  # type: ignore
    assert is_valid is False
    assert error is not None


def test_validate_configs_integration():
    validator = ConfigurationValidator()
    # Test valid configs
    valid_configs = [
        {"name": "scanner1", "type": "STATIC"},
        {"name": "scanner2", "type": "IAC"},
    ]
    results = validator.validate_configs(valid_configs, ScannerConfig)
    assert all(result[0] for result in results)
    assert all(result[1] is None for result in results)

    # Test invalid configs
    invalid_configs = [{}, {"invalid": "config"}]
    results = validator.validate_configs(invalid_configs, ScannerConfig)
    print(results)
    assert all(not result[0] for result in results)
    assert all(result[1] is not None for result in results)
