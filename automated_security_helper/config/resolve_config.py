import json
from pathlib import Path
from typing import Dict, List, Any, Optional

from pydantic import ValidationError
import yaml
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_sources import (
    _resolve_dict_key,
    default_confinement_root,
    describe_config_path,
    discover_config_source,
    log_config_discovery,
)
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.utils.log import ASH_LOGGER


def find_config_file(search_dir: Path | None = None) -> Optional[Path]:
    """Return the config source a scan of search_dir would use, or None.

    Applies the discovery precedence in ``config_sources.discover_config_source``:
    ASH_CONFIG_FILE_NAMES in order (each in search_dir, then search_dir/.ash/),
    then the ashrc names, then a pyproject.toml with a [tool.ash] table. The
    result can therefore be a TOML file; callers that edit the file in place
    must check its format.
    """
    if search_dir is None:
        search_dir = Path.cwd()
    selected = discover_config_source(search_dir).selected
    return selected.path if selected is not None else None


def _apply_config_override(
    config_dict: Dict[str, Any], key_path: str, value: str
) -> None:
    """
    Apply a single config override to a configuration dictionary.

    Args:
        config_dict: The configuration dictionary to modify
        key_path: The dot-separated path to the config value (e.g., 'reporters.cloudwatch-logs.options.aws_region')
        value: The value to set at the specified path
    """
    # Check if this is an append operation (key_path ends with +)
    append_mode = False
    if key_path.endswith("+"):
        append_mode = True
        key_path = key_path[:-1]  # Remove the + from the key path

    # Split the key path into components
    keys = key_path.split(".")

    # Navigate to the nested dictionary
    current = config_dict
    for i, key in enumerate(keys[:-1]):
        resolved = _resolve_dict_key(current, key)
        # If the key doesn't exist or isn't a dict, create a new dict
        if resolved not in current or not isinstance(current[resolved], dict):
            current[resolved] = {}
        current = current[resolved]

    # Set the value at the final key
    final_key = _resolve_dict_key(current, keys[-1])

    # Parse the value
    parsed_value = _parse_config_value(value)

    # Handle append mode for lists
    if append_mode and final_key in current and isinstance(current[final_key], list):
        if isinstance(parsed_value, list):
            current[final_key].extend(parsed_value)
            ASH_LOGGER.debug(f"Appended to list at {key_path}: {parsed_value}")
        else:
            current[final_key].append(parsed_value)
            ASH_LOGGER.debug(f"Appended to list at {key_path}: {parsed_value}")
    else:
        # Set the value
        current[final_key] = parsed_value
        ASH_LOGGER.debug(f"Applied config override: {key_path}={parsed_value}")


def _parse_config_value(value: str) -> Any:
    """
    Parse a configuration value string into the appropriate Python type.

    Args:
        value: The string value to parse

    Returns:
        The parsed value as the appropriate type
    """
    # Check for list syntax: [item1, item2, ...]
    if value.startswith("[") and value.endswith("]"):
        try:
            # Try to parse as JSON
            return json.loads(value)
        except json.JSONDecodeError:
            # If not valid JSON, try a simpler approach for basic lists
            items = value[1:-1].split(",")
            return [_parse_config_value(item.strip()) for item in items if item.strip()]

    # Check for dict syntax: {key1: value1, key2: value2, ...}
    if value.startswith("{") and value.endswith("}"):
        try:
            # Try to parse as JSON
            return json.loads(value)
        except json.JSONDecodeError:
            # If not valid JSON, return as string
            return value

    # Handle boolean values
    if value.lower() == "true":
        return True
    elif value.lower() == "false":
        return False
    elif value.lower() in ("null", "none"):
        return None

    # Try numeric conversions
    try:
        # Try to convert to int
        return int(value)
    except ValueError:
        try:
            # Try to convert to float
            return float(value)
        except ValueError:
            # Keep as string
            return value


def apply_config_overrides(config: AshConfig, config_overrides: List[str]) -> AshConfig:
    """
    Apply configuration overrides to an AshConfig object.

    Args:
        config: The AshConfig object to modify
        config_overrides: List of strings in the format 'key.path=value'

    Returns:
        The modified AshConfig object

    Raises:
        ASHConfigValidationError: If an override cannot be parsed or applied, or
            if the merged configuration does not validate. Failing here is
            deliberate: silently dropping an override would run the scan with
            settings the operator did not choose and still report success.
    """
    if not config_overrides:
        return config

    # Convert config to dict for easier manipulation
    config_dict = config.model_dump()

    # Apply each override
    for override in config_overrides:
        key_path, separator, value = override.partition("=")
        if not separator or not key_path.strip():
            raise ASHConfigValidationError(
                f"Invalid config override: '{override}'. "
                "Expected format: key.path=value"
            )
        try:
            _apply_config_override(config_dict, key_path, value)
        except Exception as e:
            raise ASHConfigValidationError(
                f"Failed to apply config override '{override}': {e}"
            ) from e

    # Convert back to AshConfig
    try:
        return AshConfig.model_validate(config_dict)
    except ValidationError as e:
        raise ASHConfigValidationError(
            "Configuration is invalid after applying the requested overrides "
            f"{config_overrides}: {e}"
        ) from e


def resolve_config(
    config_path: Path | str | None = None,
    source_dir: Path | str | None = None,
    fallback_to_default: bool = True,
    config_overrides: List[str] = None,
) -> AshConfig:
    """
    Load configuration from file or return default configuration.

    Args:
        config_path: Path to the configuration file
        source_dir: Source directory to search for configuration files
        fallback_to_default: Whether to fall back to default configuration if no config file is found
        config_overrides: List of configuration overrides in the format 'key.path=value'

    Returns:
        The resolved AshConfig object
    """
    try:
        # Start with default config
        config = get_default_config() if fallback_to_default else None
        # An explicit config_path has to survive a missing source_dir. source_dir
        # only drives *discovery* of a config file; when the caller already named
        # one, there is nothing to discover and no reason to bail out to the
        # default. Testing source_dir alone here meant `ash report --config
        # <file>` accepted the option and then reported against default settings,
        # because cli/report.py passes config_path with no source_dir (as does
        # cli/config.py). Below, source_dir falls back to Path.cwd(), which is
        # only used to resolve a relative config_path at that point.
        if source_dir is None and config_path is None and fallback_to_default:
            ASH_LOGGER.verbose(
                "source_dir and config_path are both null, returning the default config"
            )
            # Apply overrides to default config if provided
            if config_overrides:
                return apply_config_overrides(config, config_overrides)
            return config

        # Only a source_dir the caller passed may widen where `extends` bases
        # may live. The cwd fallback below must not: `ash report --config
        # <file>` run from a home directory would otherwise let that file's
        # bases reach anywhere under it.
        confinement_source_dir = source_dir

        # Resolve cwd default at call time, not import time.
        if source_dir is None:
            source_dir = Path.cwd()

        if isinstance(source_dir, str):
            source_dir = Path(source_dir)

        # Check for config file if not explicitly provided. The precedence, and
        # why sources are selected rather than merged, is documented in
        # config/config_sources.py.
        confine_to = None
        if config_path is None:
            ASH_LOGGER.verbose(
                "No configuration file provided, checking for default paths"
            )
            discovery = discover_config_source(source_dir)
            log_config_discovery(discovery)
            if discovery.selected is not None:
                config_path = discovery.selected.path
                confine_to = source_dir
                ASH_LOGGER.verbose(
                    f"Found configuration file at: {config_path.as_posix()}"
                )

        if config_path is None:
            if fallback_to_default:
                ASH_LOGGER.verbose(
                    "Configuration file not found or provided, using default config"
                )
                # Apply overrides to default config if provided
                if config_overrides:
                    return apply_config_overrides(config, config_overrides)
                return config  # Return default config if no config file found
            else:
                raise ValueError("Configuration file not found or provided")

        # Process config file
        try:
            config_path = (
                Path(config_path) if not isinstance(config_path, Path) else config_path
            )
            ASH_LOGGER.debug(f"Loading configuration from {config_path.as_posix()}")

            if not config_path.exists():
                ASH_LOGGER.warning(
                    f"Configuration file not found: {config_path.as_posix()}"
                )
                # Apply overrides to default config if provided
                if config_overrides and config:
                    return apply_config_overrides(config, config_overrides)
                return config  # Return default config if specified file doesn't exist

            ASH_LOGGER.debug("Validating file config")
            if confine_to is None:
                confine_to = default_confinement_root(
                    config_path, confinement_source_dir
                )
            config = AshConfig.from_file(
                config_path=Path(config_path), confine_to=confine_to
            )
            ASH_LOGGER.debug(f"Loaded config from file: {config_path}")

            # Apply config overrides if provided
            if config_overrides:
                config = apply_config_overrides(config, config_overrides)

            return config

        except (IOError, yaml.YAMLError, json.JSONDecodeError) as e:
            ASH_LOGGER.error(f"Failed to load configuration file: {str(e)}")
            if fallback_to_default:
                ASH_LOGGER.warning("Using default configuration due to file load error")
                # Apply overrides to default config if provided
                if config_overrides and config:
                    config = apply_config_overrides(config, config_overrides)
                config._resolution_warnings.append(
                    f"Failed to load configuration file: {str(e)}. "
                    "Using default configuration — suppressions and custom settings are NOT active."
                )
                return config  # Return default config on file error
            else:
                raise e

        except ValidationError as e:
            ASH_LOGGER.error(f"Configuration validation failed: {str(e)}")
            raise ASHConfigValidationError(
                f"Configuration validation failed for "
                f"'{describe_config_path(config_path)}': {str(e)}. "
                "Run 'ash config lint' to identify and fix issues."
            ) from e

        return config

    except ASHConfigValidationError:
        raise
    except Exception as e:
        # Always return a valid config, even in case of unexpected errors
        if fallback_to_default:
            ASH_LOGGER.error(f"Unexpected error in resolve_config: {str(e)}")
            config = get_default_config()
            # Apply overrides to default config if provided
            if config_overrides:
                return apply_config_overrides(config, config_overrides)
            return config
        raise e
