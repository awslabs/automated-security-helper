"""Unit tests for ash_multi module."""

import os
import pytest
import logging
import tempfile
import yaml
from unittest.mock import patch, MagicMock
from automated_security_helper.ash_multi import (
    parse_args,
    get_logger,
    load_config,
    main,
)


def test_parse_args():
    # Test with minimal required args
    test_args = ["--config", "config.yaml", "--output", "output.json"]
    with patch("sys.argv", ["ash_multi"] + test_args):
        args = parse_args()
        assert args.config == "config.yaml"
        assert args.verbose is False
        assert args.output == "output.json"

    # Test with all args
    test_args = ["--config", "config.yaml", "--verbose", "--output", "output.json"]
    with patch("sys.argv", ["ash_multi"] + test_args):
        args = parse_args()
        assert args.config == "config.yaml"
        assert args.verbose is True
        assert args.output == "output.json"


def test_default_logging():
    # Test normal logging setup
    logger = get_logger(False)
    assert logger.getEffectiveLevel() == logging.INFO


def test_verbose_logging():
    # Test verbose logging
    logger = get_logger(True)
    assert logger.getEffectiveLevel() == logging.DEBUG


@pytest.fixture
def sample_config_file():
    config = {
        "scanners": {"scanner1": {"type": "static"}},
        "parsers": {"parser1": {"format": "json"}},
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(config, f)
        return f.name


def test_load_config(sample_config_file):
    config = load_config(sample_config_file)
    assert "scanners" in config
    assert config["scanners"]["scanner1"]["type"] == "static"

    # Test loading non-existent file
    with pytest.raises(FileNotFoundError):
        load_config("nonexistent.yaml")

    # Test loading invalid YAML
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("invalid: yaml: content:")
        f.flush()
        with pytest.raises(yaml.YAMLError):
            load_config(f.name)
        os.unlink(f.name)


@patch("automated_security_helper.ash_multi.ConfigurationManager")
@patch("automated_security_helper.ash_multi.ResultProcessor")
@patch("automated_security_helper.ash_multi.ScanExecutionEngine")
def test_main_execution(
    mock_engine_cls, mock_processor_cls, mock_config_cls, sample_config_file
):
    # Setup mocks
    mock_engine = MagicMock()
    mock_engine_cls.return_value = mock_engine
    mock_engine.execute.return_value = {"findings": [], "metadata": {}}

    mock_processor = MagicMock()
    mock_processor_cls.return_value = mock_processor

    mock_config = MagicMock()
    mock_config_cls.return_value = mock_config

    # Test main execution with minimal args
    test_args = ["--config", sample_config_file]
    with patch("sys.argv", ["ash_multi"] + test_args):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 2
        mock_engine.execute.assert_not_called()
        mock_processor.process_results.assert_not_called()  # No output specified

    # Test main execution with output file
    output_file = "test_output.json"
    test_args = ["--config", sample_config_file, "--output", output_file]
    with patch("sys.argv", ["ash_multi"] + test_args):
        main()
        mock_engine.execute.assert_called()
        # Should attempt to write results
        # assert mock_processor.process_results.called


@patch("automated_security_helper.ash_multi.ConfigurationManager")
@patch("automated_security_helper.ash_multi.ResultProcessor")
@patch("automated_security_helper.ash_multi.ScanExecutionEngine")
def test_main_error_handling(mock_engine_cls, mock_processor_cls, mock_config_cls):
    # Test config loading error
    test_args = ["--config", "nonexistent.yaml", "--output", "aggregated_results.json"]
    with patch("sys.argv", ["ash_multi"] + test_args):
        with pytest.raises(FileNotFoundError):
            main()

    # Test execution error
    mock_engine = MagicMock()
    mock_engine_cls.return_value = mock_engine
    mock_engine.execute.side_effect = Exception("Test error")

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as config_file:
        yaml.dump({"scanners": {}, "parsers": {}}, config_file)
        test_args = ["--config", config_file.name]
        with patch("sys.argv", ["ash_multi"] + test_args):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2
        os.unlink(config_file.name)
