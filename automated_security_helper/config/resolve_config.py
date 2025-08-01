import json
from pathlib import Path
from typing import Dict, List, Any

from pydantic import ValidationError
import yaml
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_CONFIG_FILE_NAMES
from automated_security_helper.utils.log import ASH_LOGGER


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
        # If the key doesn't exist or isn't a dict, create a new dict
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]

    # Set the value at the final key
    final_key = keys[-1]

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
    """
    if not config_overrides:
        return config

    # Convert config to dict for easier manipulation
    config_dict = config.model_dump()

    # Apply each override
    for override in config_overrides:
        try:
            # Split at the first equals sign
            key_path, value = override.split("=", 1)
            _apply_config_override(config_dict, key_path, value)
        except ValueError:
            ASH_LOGGER.warning(
                f"Invalid config override format: {override}. Expected format: key.path=value"
            )
        except Exception as e:
            ASH_LOGGER.warning(f"Failed to apply config override {override}: {str(e)}")

    # Convert back to AshConfig
    try:
        return AshConfig.model_validate(config_dict)
    except ValidationError as e:
        ASH_LOGGER.error(
            f"Failed to validate config after applying overrides: {str(e)}"
        )
        return config  # Return original config if validation fails


def resolve_config(
    config_path: Path | str | None = None,
    source_dir: Path | str | None = Path.cwd(),
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
        if source_dir is None and fallback_to_default:
            ASH_LOGGER.verbose("source_dir is null, returning the default config")
            # Apply overrides to default config if provided
            if config_overrides:
                return apply_config_overrides(config, config_overrides)
            return config

        if isinstance(source_dir, str):
            source_dir = Path(source_dir)

        # Check for config file if not explicitly provided
        if config_path is None:
            ASH_LOGGER.verbose(
                "No configuration file provided, checking for default paths"
            )
            for item in ASH_CONFIG_FILE_NAMES:
                for poss_dir in [
                    source_dir,
                    source_dir.joinpath(".ash"),
                ]:
                    try:
                        possible_config_path = poss_dir.joinpath(item)
                        if possible_config_path.exists():
                            config_path = possible_config_path
                            ASH_LOGGER.verbose(
                                f"Found configuration file at: {config_path.as_posix()}"
                            )
                            break
                    except (AttributeError, TypeError) as e:
                        ASH_LOGGER.debug(f"Error checking config path: {e}")
                if config_path is not None:
                    break

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
            config = AshConfig.from_file(config_path=Path(config_path))
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
                    return apply_config_overrides(config, config_overrides)
                return config  # Return default config on file error
            else:
                raise e

        except ValidationError as e:
            ASH_LOGGER.error(f"Configuration validation failed: {str(e)}")
            if fallback_to_default:
                ASH_LOGGER.warning(
                    "Using default configuration due to validation error"
                )
                # Apply overrides to default config if provided
                if config_overrides and config:
                    return apply_config_overrides(config, config_overrides)
                return config  # Return default config on validation error
            else:
                raise e

        return config

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
