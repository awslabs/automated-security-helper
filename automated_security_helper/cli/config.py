# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import os
from pathlib import Path
import sys
from typing import Annotated
import yaml
import typer

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
    config_path: Annotated[
        str,
        typer.Argument(
            help=f"The name of the config file to initialize. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_FILE_NAMES}. If  a different filename is specified, it must be provided when running ASH via the `--config` option or by setting the `ASH_CONFIG` environment variable.",
            envvar="ASH_CONFIG",
        ),
    ] = ".ash/.ash.yaml",
    force: Annotated[
        bool,
        typer.Option(
            help="Overwrite the config file if it already exists at the target path.",
        ),
    ] = False,
    verbose: Annotated[bool, typer.Option(help="Enable verbose logging")] = False,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
):
    get_logger(
        level=(logging.DEBUG if debug else 15 if verbose else logging.INFO),
        show_progress=False,
        use_color=color,
    )
    config_path_path = Path(config_path)
    if config_path_path.absolute().exists() and not force:
        typer.secho(
            f"Config file already exists at {config_path_path.absolute()}. Include --force to overwrite.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    config_path_path.parent.mkdir(exist_ok=True, parents=True)
    if config_path_path.parent.name == ".ash":
        ash_gitignore_path = config_path_path.parent.joinpath(".gitignore")
        if not ash_gitignore_path.exists():
            ash_gitignore_path.write_text(
                "# ASH default output directory (and variants)\nash_output*\n"
            )
    typer.secho(f"Saving ASH config to path: {config_path_path.absolute()}")
    config = AshConfig(
        project_name=config_path_path.absolute().parent.name,
    )
    config_strings = [
        "# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/beta/src/automated_security_helper/schemas/AshConfig.json",
        yaml.dump(
            config.model_dump(by_alias=True, exclude_defaults=False),
            sort_keys=False,
            indent=2,
        ),
    ]
    config_path_path.write_text("\n".join(config_strings))


@config_app.command()
def get(
    config_path: Annotated[
        str,
        typer.Argument(
            help=f"The name of the config file to get. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_FILE_NAMES}. If  a different filename is specified, it must be provided when running ASH via the `--config` option or by setting the `ASH_CONFIG` environment variable.",
        ),
    ] = None,
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
    config = resolve_config(config_path)
    typer.secho(
        yaml.dump(
            config.model_dump(
                by_alias=True,
                exclude_defaults=False,
                exclude_none=False,
            ),
            Dumper=IndentableYamlDumper,
            default_flow_style=False,
            sort_keys=False,
        ),
    )


@config_app.command()
def validate(
    config_path: Annotated[
        str,
        typer.Argument(
            help=f"The name of the config file to create. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_FILE_NAMES}. If  a different filename is specified, it must be provided when running ASH via the `--config` option or by setting the `ASH_CONFIG` environment variable.",
        ),
    ] = None,
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
        config = resolve_config(config_path=config_path, fallback_to_default=False)

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
            raise sys.exit(1) from None
        else:
            typer.secho(
                "Unable to resolve a valid configuration from the input details provided",
                fg=typer.colors.RED,
            )
        raise sys.exit(1) from None


if __name__ == "__main__":
    config_app()
