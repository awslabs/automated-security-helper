import json
from pathlib import Path

from pydantic import ValidationError
import yaml
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_CONFIG_FILE_NAMES
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.utils.log import ASH_LOGGER


def resolve_config(
    config_path: Path | str | None = None,
    source_dir: Path | str | None = Path.cwd(),
) -> AshConfig:
    """Load configuration from file or return default configuration."""
    try:
        config = get_default_config()
        if not config_path:
            ASH_LOGGER.verbose(
                "No configuration file provided, checking for default paths"
            )
            for item in ASH_CONFIG_FILE_NAMES:
                config_path = source_dir.joinpath(item)
                if config_path.exists():
                    config_path = Path(config_path)
                    ASH_LOGGER.verbose(
                        f"Found configuration file at: {Path(config_path).as_posix()}"
                    )
                    break
            ASH_LOGGER.verbose(
                "Configuration file not found or provided, using default config"
            )

        # We *always* want to evaluate this after the inverse block above runs, in
        # case self.config_path is resolved from a default location.
        # Do not use `else:` here!
        if config_path:
            ASH_LOGGER.debug(
                f"Loading configuration from {Path(config_path).as_posix()}"
            )
            try:
                with open(config_path, "r") as f:
                    if str(config_path).endswith(".json"):
                        config_data = json.load(f)
                    else:
                        config_data = yaml.safe_load(f)

                if not isinstance(config_data, dict):
                    raise ValueError("Configuration must be a dictionary")

                ASH_LOGGER.debug("Transforming file config")
                config = AshConfig(**config_data)
                ASH_LOGGER.debug(f"Loaded config from file: {config}")
            except (IOError, yaml.YAMLError, json.JSONDecodeError) as e:
                ASH_LOGGER.error(f"Failed to load configuration file: {str(e)}")
                raise ASHConfigValidationError(
                    f"Failed to load configuration: {str(e)}"
                )
            except ValidationError as e:
                ASH_LOGGER.error(f"Configuration validation failed: {str(e)}")
                raise ASHConfigValidationError(
                    f"Configuration validation failed: {str(e)}"
                )

        return config
    except Exception as e:
        raise e
