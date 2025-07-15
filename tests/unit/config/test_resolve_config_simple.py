"""Simple tests for config resolution functionality."""

from pathlib import Path
from automated_security_helper.config.resolve_config import (
    apply_config_overrides,
    resolve_config,
)
from automated_security_helper.config.ash_config import AshConfig


def test_apply_config_overrides_empty_list():
    """Test apply_config_overrides with empty override list."""
    config = AshConfig()
    result = apply_config_overrides(config, [])
    assert isinstance(result, AshConfig)


def test_resolve_config_no_args():
    """Test resolve_config with no arguments."""
    result = resolve_config()
    assert isinstance(result, AshConfig)


def test_resolve_config_with_source_dir():
    """Test resolve_config with source directory."""
    result = resolve_config(source_dir=Path.cwd())
    assert isinstance(result, AshConfig)
