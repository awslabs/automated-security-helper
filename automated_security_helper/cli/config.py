# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import os
from pathlib import Path
import sys
from typing import Annotated, List
import yaml
import typer
from rich import print
from rich.syntax import Syntax

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import ASH_CONFIG_FILE_NAMES
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.utils.log import get_logger

config_app = typer.Typer(
    name="config",
    help="ASH configuration management",
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    pretty_exceptions_show_locals=os.environ.get("ASH_DEBUG_SHOW_LOCALS", "NO").upper()
    in ["YES", "1", "TRUE"],
)


class IndentableYamlDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(IndentableYamlDumper, self).increase_indent(flow, indentless)


@config_app.command()
def init(
    config: Annotated[
        str,
        typer.Option(
            "--config",
            "-c",
            help=f"The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_FILE_NAMES}. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH.",
            envvar="ASH_CONFIG",
        ),
    ] = ".ash/.ash.yaml",
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug", "-d", help="Enable debug logging")
    ] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
    force: Annotated[
        bool,
        typer.Option(
            help="Overwrite the config file if it already exists at the target path.",
        ),
    ] = False,
):
    get_logger(
        level=(logging.DEBUG if debug else 15 if verbose else logging.INFO),
        show_progress=False,
        use_color=color,
    )
    config_path = Path(config)
    if config_path.absolute().exists() and not force:
        typer.secho(
            f"Config file already exists at {config_path.absolute()}. Include --force to overwrite.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    config_path.parent.mkdir(exist_ok=True, parents=True)
    if config_path.parent.name == ".ash":
        ash_gitignore_path = config_path.parent.joinpath(".gitignore")
        if not ash_gitignore_path.exists():
            ash_gitignore_path.write_text(
                "# ASH default output directory (and variants)\nash_output*\n"
            )
    typer.secho(f"Saving ASH config to path: {config_path.absolute()}")
    project_name = config_path.absolute().parent.name
    if project_name == ".ash":
        project_name = config_path.absolute().parent.parent.name
    ash_config = AshConfig(
        project_name=project_name,
    )
    config_strings = [
        "# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json",
        yaml.dump(
            ash_config.model_dump(
                by_alias=True,
                exclude_defaults=False,
                exclude_none=False,
            ),
            Dumper=IndentableYamlDumper,
            default_flow_style=False,
            sort_keys=False,
        ),
    ]
    config_path.write_text("\n".join(config_strings))


@config_app.command()
def get(
    config_path: Annotated[
        str,
        typer.Argument(
            help=f"The name of the config file to get. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_FILE_NAMES}. If  a different filename is specified, it must be provided when running ASH via the `--config` option or by setting the `ASH_CONFIG` environment variable.",
        ),
    ] = None,
    config_overrides: Annotated[
        List[str],
        typer.Option(
            "--config-overrides",
            help="Configuration overrides specified as key-value pairs (e.g., 'global_settings.severity_threshold=LOW')",
        ),
    ] = [],
    verbose: Annotated[bool, typer.Option(help="Enable verbose logging")] = False,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
):
    get_logger(
        level=(logging.DEBUG if debug else 15 if verbose else logging.INFO),
        show_progress=False,
        use_color=color,
    )
    if config_path is not None and not Path(config_path).exists():
        typer.secho(f"Config file does not exist at {config_path}", fg=typer.colors.RED)
        raise typer.Exit(1)
    config = resolve_config(config_path, config_overrides=config_overrides)
    print(
        Syntax(
            code=yaml.dump(
                config.model_dump(
                    by_alias=True,
                    exclude_defaults=False,
                    exclude_none=False,
                ),
                Dumper=IndentableYamlDumper,
                default_flow_style=False,
                sort_keys=False,
            ),
            lexer="yaml",
            theme="lightbulb",
            background_color=None,
        )
    )


@config_app.command()
def update(
    config_path: Annotated[
        str,
        typer.Argument(
            help=f"The path to the configuration file to update. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_FILE_NAMES}.",
        ),
    ] = None,
    modifications: Annotated[
        List[str],
        typer.Option(
            "--set",
            help="Configuration modifications specified as key-value pairs (e.g., 'global_settings.severity_threshold=LOW'). Supports lists with [item1,item2], append mode with key+=[value], and JSON syntax.",
        ),
    ] = [],
    verbose: Annotated[bool, typer.Option(help="Enable verbose logging")] = False,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
    dry_run: Annotated[
        bool, typer.Option(help="Show changes without writing to file")
    ] = False,
):
    """
    Update an existing configuration file with the specified modifications.

    This command applies changes to an ASH configuration file using the same syntax as --config-overrides.
    """
    logger = get_logger(
        level=(logging.DEBUG if debug else 15 if verbose else logging.INFO),
        show_progress=False,
        use_color=color,
    )

    # Find the config file if not specified
    if config_path is None:
        for config_file in ASH_CONFIG_FILE_NAMES:
            def_paths = [
                Path.cwd().joinpath(config_file),
                Path.cwd().joinpath(".ash", config_file),
            ]
            for def_path in def_paths:
                if def_path.exists():
                    logger.info(f"Using config file found at: {def_path.as_posix()}")
                    config_path = def_path.as_posix()
                    break
            if config_path is not None:
                break

    # Check if config file exists
    if config_path is None or not Path(config_path).exists():
        typer.secho(
            "Config file not found. Use 'ash config init' to create one.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    # Load the existing config
    config_path = Path(config_path)
    try:
        config = AshConfig.from_file(config_path=config_path)
    except Exception as e:
        typer.secho(f"Error loading config file: {e}", fg=typer.colors.RED)
        raise typer.Exit(1)

    # Apply modifications
    if not modifications:
        typer.secho(
            "No modifications specified. Use --set to specify changes.",
            fg=typer.colors.YELLOW,
        )
        raise typer.Exit(0)

    # Convert config to dict for easier manipulation
    config_dict = config.model_dump()

    # Import the function to apply config overrides
    from automated_security_helper.config.resolve_config import _apply_config_override

    # Apply each modification
    for mod in modifications:
        try:
            # Split at the first equals sign
            key_path, value = mod.split("=", 1)
            _apply_config_override(config_dict, key_path, value)
            logger.info(f"Applied modification: {key_path}={value}")
        except ValueError:
            typer.secho(
                f"Invalid modification format: {mod}. Expected format: key.path=value",
                fg=typer.colors.RED,
            )
        except Exception as e:
            typer.secho(
                f"Failed to apply modification {mod}: {str(e)}", fg=typer.colors.RED
            )

    # Convert back to AshConfig
    try:
        updated_config = AshConfig.model_validate(config_dict)
    except Exception as e:
        typer.secho(
            f"Failed to validate config after applying modifications: {str(e)}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    # Generate the updated config content
    config_strings = []

    # Preserve the schema reference if it exists in the original file
    with open(config_path, "r") as f:
        first_line = f.readline().strip()
        if first_line.startswith("#") and "schema" in first_line.lower():
            config_strings.append(first_line)

    # If no schema reference was found, add the default one
    if not config_strings:
        config_strings.append(
            "# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json"
        )

    # Add the updated config
    config_strings.append(
        yaml.dump(
            updated_config.model_dump(
                by_alias=True,
                exclude_defaults=False,
                exclude_none=False,
            ),
            Dumper=IndentableYamlDumper,
            default_flow_style=False,
            sort_keys=False,
        )
    )

    # Show the updated config
    print(
        Syntax(
            code="\n".join(config_strings),
            lexer="yaml",
            theme="lightbulb",
            background_color=None,
        )
    )

    # Write the updated config if not in dry run mode
    if not dry_run:
        try:
            config_path.write_text("\n".join(config_strings))
            typer.secho(
                f"Successfully updated config file: {config_path.absolute()}",
                fg=typer.colors.GREEN,
            )
        except Exception as e:
            typer.secho(f"Error writing config file: {e}", fg=typer.colors.RED)
            raise typer.Exit(1)
    else:
        typer.secho(
            "Dry run mode: No changes were written to the file", fg=typer.colors.YELLOW
        )


@config_app.command()
def validate(
    config_path: Annotated[
        str,
        typer.Argument(
            help=f"The name of the config file to create. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_FILE_NAMES}. If  a different filename is specified, it must be provided when running ASH via the `--config` option or by setting the `ASH_CONFIG` environment variable.",
        ),
    ] = None,
    config_overrides: Annotated[
        List[str],
        typer.Option(
            "--config-overrides",
            help="Configuration overrides specified as key-value pairs (e.g., 'global_settings.severity_threshold=LOW')",
        ),
    ] = [],
    verbose: Annotated[bool, typer.Option(help="Enable verbose logging")] = False,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
):
    get_logger(
        level=(logging.DEBUG if debug else 15 if verbose else logging.INFO),
        show_progress=False,
        use_color=color,
    )
    if config_path is not None and not Path(config_path).exists():
        typer.secho(f"Config file does not exist at {config_path}", fg=typer.colors.RED)
        raise typer.Exit(1)
    try:
        config = resolve_config(
            config_path=config_path,
            fallback_to_default=False,
            config_overrides=config_overrides,
        )

        if config.project_name:
            if config_path:
                typer.secho(
                    f"Config file '{Path(config_path).absolute().as_posix()}' is valid",
                    fg=typer.colors.GREEN,
                )
            else:
                typer.secho(
                    f"Config file for project '{config.project_name}' is valid",
                    fg=typer.colors.GREEN,
                )
            return True

        raise ASHConfigValidationError(
            "Config validation passed, but project_name was not found on the resolved config."
        )
    except Exception as e:
        if config_path:
            typer.secho(
                f"Config file '{Path(config_path).absolute().as_posix()}' is not valid: {e}",
                fg=typer.colors.RED,
            )
            sys.exit(1)
        else:
            typer.secho(
                "Unable to resolve a valid configuration from the input details provided",
                fg=typer.colors.RED,
            )
        sys.exit(1)


if __name__ == "__main__":
    config_app()
