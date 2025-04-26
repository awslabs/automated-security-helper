# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from enum import Enum
from pathlib import Path
from typing import Annotated
import yaml
import typer

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_CONFIG_FILE_NAMES
from automated_security_helper.core.exceptions import ASHConfigValidationError

config_app = typer.Typer(
    name="config",
    help="ASH configuration management",
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    pretty_exceptions_show_locals=True,
)


class ConfigFormat(str, Enum):
    json = "json"
    yaml = "yaml"


class IndentableYamlDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(IndentableYamlDumper, self).increase_indent(flow, indentless)


@config_app.command()
def init(
    filename: Annotated[
        str,
        typer.Argument(
            help=f"The name of the config file to initialize. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_FILE_NAMES}. If  a different filename is specified, it must be provided when running ASH via the `--config` option or by setting the `ASH_CONFIG` environment variable.",
        ),
    ] = ".ash.yaml",
    force: Annotated[
        bool,
        typer.Option(
            help="Overwrite the config file if it already exists at the target path.",
        ),
    ] = False,
):
    config_path = Path(filename)
    if config_path.absolute().exists() and not force:
        typer.secho(
            f"Config file already exists at {config_path.absolute()}. Include --force to overwrite.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    typer.secho(f"Saving ASH config to path: {config_path.absolute()}")
    config = AshConfig(
        project_name=config_path.absolute().parent.name,
    )
    config_strings = [
        "# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/beta/src/automated_security_helper/schemas/AshConfig.json",
        yaml.dump(
            config.model_dump(by_alias=True, exclude_defaults=False),
            sort_keys=False,
            indent=2,
        ),
    ]
    config_path.write_text("\n".join(config_strings))


@config_app.command()
def get(
    filename: Annotated[
        str,
        typer.Argument(
            help=f"The name of the config file to create. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_FILE_NAMES}. If  a different filename is specified, it must be provided when running ASH via the `--config` option or by setting the `ASH_CONFIG` environment variable.",
        ),
    ] = ".ash.yaml",
):
    if not Path(filename).exists():
        typer.secho(f"Config file does not exist at {filename}", fg=typer.colors.RED)
        raise typer.Exit(1)
    config = AshConfig.from_file(Path(filename))
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
    filename: Annotated[
        str,
        typer.Argument(
            help=f"The name of the config file to create. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_FILE_NAMES}. If  a different filename is specified, it must be provided when running ASH via the `--config` option or by setting the `ASH_CONFIG` environment variable.",
        ),
    ] = ".ash.yaml",
):
    if not Path(filename).exists():
        typer.secho(f"Config file does not exist at {filename}", fg=typer.colors.RED)
        raise typer.Exit(1)
    try:
        config = AshConfig.from_file(Path(filename))
        if config.project_name:
            typer.secho(
                f"Config file '{Path(filename).absolute().as_posix()}' is valid",
                fg=typer.colors.GREEN,
            )
            return True

        raise ASHConfigValidationError(
            "Config validation passed, but project_name was not found on the resolved config."
        )
    except Exception as e:
        typer.secho(
            f"Config file '{Path(filename).absolute().as_posix()}' is not valid: {e}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)


if __name__ == "__main__":
    config_app()
