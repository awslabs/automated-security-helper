"""Unit tests for configuration manager module."""

import os
import pytest
import tempfile
import yaml
from automated_security_helper.config.config_manager import ConfigurationManager


@pytest.fixture
def sample_config():
    return {
        "scanners": {"bandit": {"type": "static", "config_file": "bandit.yaml"}},
        "parsers": {"bandit": {"format": "json"}},
    }


@pytest.fixture
def config_file():
    # Create a temporary config file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(
            {
                "scanners": {
                    "bandit": {"type": "static", "config_file": "bandit.yaml"}
                },
                "parsers": {"bandit": {"format": "json"}},
            },
            f,
        )
        return f.name


def test_load_config(config_file):
    config_manager = ConfigurationManager()
    config = config_manager.load_config(config_file)

    assert "scanners" in config
    assert "parsers" in config
    assert config["scanners"]["bandit"]["type"] == "static"
    assert config["parsers"]["bandit"]["format"] == "json"


def test_load_config_file_not_found():
    config_manager = ConfigurationManager()
    with pytest.raises(FileNotFoundError):
        config_manager.load_config("nonexistent.yaml")


def test_load_config_invalid_yaml():
    # Create temporary file with invalid YAML
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("invalid: yaml: content:")
        f.flush()

        config_manager = ConfigurationManager()
        with pytest.raises(yaml.YAMLError):
            config_manager.load_config(f.name)

    os.unlink(f.name)


def test_save_config(sample_config):
    config_manager = ConfigurationManager()

    # Create temporary file for saving
    with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as f:
        config_manager.save_config(sample_config, f.name)

        # Verify saved config
        with open(f.name, "r") as f2:
            loaded_config = yaml.safe_load(f2)
            assert loaded_config == sample_config

    os.unlink(f.name)


def test_validate_config(sample_config):
    config_manager = ConfigurationManager()
    assert config_manager.validate_config(sample_config) is True


def test_validate_config_invalid():
    config_manager = ConfigurationManager()
    invalid_config = {"scanners": None, "parsers": {}}
    with pytest.raises(ValueError):
        config_manager.validate_config(invalid_config)


def test_get_scanner_config(sample_config):
    config_manager = ConfigurationManager()
    scanner_config = config_manager.get_scanner_config(sample_config)
    assert scanner_config == sample_config["scanners"]


def test_get_parser_config(sample_config):
    config_manager = ConfigurationManager()
    parser_config = config_manager.get_parser_config(sample_config)
    assert parser_config == sample_config["parsers"]


def test_merge_configs():
    config_manager = ConfigurationManager()
    base_config = {
        "scanners": {"scanner1": {"type": "static"}},
        "parsers": {"parser1": {"format": "json"}},
    }
    override_config = {
        "scanners": {"scanner2": {"type": "dynamic"}},
        "parsers": {"parser1": {"format": "xml"}},
    }

    merged = config_manager.merge_configs(base_config, override_config)
    assert "scanner1" in merged["scanners"]
    assert "scanner2" in merged["scanners"]
    assert (
        merged["parsers"]["parser1"]["format"] == "xml"
    )  # Override should take precedence
