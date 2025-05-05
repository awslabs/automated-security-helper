import json
from pathlib import Path

from pydantic import ValidationError
import yaml
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_CONFIG_FILE_NAMES
from automated_security_helper.utils.log import ASH_LOGGER


def resolve_config(
    config_path: Path | str | None = None,
    source_dir: Path | str | None = Path.cwd(),
) -> AshConfig:
    """Load configuration from file or return default configuration."""
    try:
        # Start with default config
        config = get_default_config()
        if source_dir is None:
            ASH_LOGGER.verbose("source_dir is null, returning the default config")
            return config

        if isinstance(source_dir, str):
            source_dir = Path(source_dir)

        # Check for config file if not explicitly provided
        if not config_path:
            ASH_LOGGER.verbose(
                "No configuration file provided, checking for default paths"
            )
            for item in ASH_CONFIG_FILE_NAMES:
                try:
                    possible_config_path = source_dir.joinpath(item)
                    if possible_config_path.exists():
                        config_path = possible_config_path
                        ASH_LOGGER.verbose(
                            f"Found configuration file at: {config_path.as_posix()}"
                        )
                        break
                except (AttributeError, TypeError) as e:
                    ASH_LOGGER.debug(f"Error checking config path: {e}")
                    # Continue to next path

            if not config_path:
                ASH_LOGGER.verbose(
                    "Configuration file not found or provided, using default config"
                )
                return config  # Return default config if no config file found

        # Process config file if it exists
        if config_path:
            try:
                config_path = (
                    Path(config_path)
                    if not isinstance(config_path, Path)
                    else config_path
                )
                ASH_LOGGER.debug(f"Loading configuration from {config_path.as_posix()}")

                if not config_path.exists():
                    ASH_LOGGER.warning(
                        f"Configuration file not found: {config_path.as_posix()}"
                    )
                    return (
                        config  # Return default config if specified file doesn't exist
                    )

                with open(config_path, mode="r", encoding="utf-8") as f:
                    if str(config_path).endswith(".json"):
                        config_data = json.load(f)
                    else:
                        config_data = yaml.safe_load(f)

                if not isinstance(config_data, dict):
                    ASH_LOGGER.warning(
                        "Configuration must be a dictionary, using default config"
                    )
                    return config

                ASH_LOGGER.debug("Validating file config")
                config = AshConfig.model_validate(config_data)
                ASH_LOGGER.debug(f"Loaded config from file: {config}")

            except (IOError, yaml.YAMLError, json.JSONDecodeError) as e:
                ASH_LOGGER.error(f"Failed to load configuration file: {str(e)}")
                ASH_LOGGER.warning("Using default configuration due to file load error")
                return config  # Return default config on file error

            except ValidationError as e:
                ASH_LOGGER.error(f"Configuration validation failed: {str(e)}")
                ASH_LOGGER.warning(
                    "Using default configuration due to validation error"
                )
                return config  # Return default config on validation error

        return config

    except Exception as e:
        ASH_LOGGER.error(f"Unexpected error in resolve_config: {str(e)}")
        # Always return a valid config, even in case of unexpected errors
        return get_default_config()
