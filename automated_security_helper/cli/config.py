# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import os
from pathlib import Path
import sys
from typing import Annotated, Dict, List
import yaml
import typer

# `print` shadows the builtin on purpose: this is rich's documented import
# idiom, so every print() below renders markup and respects the console. The
# fix A004 wants is an alias, which would mean rewriting every call in this
# module for no behavior change -- and tests/unit/cli/mcp/test_stdout_jsonrpc_safety.py
# reasons about this exact import form.
from rich import print  # noqa: A004
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from automated_security_helper.config.ash_config import (
    AshConfig,
    ConverterConfigSegment,
    ReporterConfigSegment,
    ScannerConfigSegment,
    TaggedReference,
    load_config_yaml,
    represent_tagged_reference,
)
from automated_security_helper.config.config_sources import (
    EXTENDS_KEY,
    PATCH_KEY,
    describe_config_path,
    is_regular_file,
    load_config_with_references,
    read_config_bytes,
    read_config_file,
)
from automated_security_helper.config.resolve_config import (
    check_config_path,
    find_config_file,
    resolve_config,
)
from automated_security_helper.core.constants import ASH_CONFIG_SOURCES_DESCRIPTION
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


def _config_path_or_discovered(config: str | None) -> Path:
    """The --config path, or the source a scan of the cwd would use."""
    if config:
        return Path(config)
    return find_config_file(Path.cwd()) or Path(".ash/.ash.yaml")


def _refuse_unloadable(config_path: Path) -> None:
    """Exit 3 when `config_path` cannot be loaded at all, as a scan refuses it.

    Missing, not a regular file (a directory, a FIFO), unreadable, not UTF-8,
    not valid YAML, JSON or TOML, or using a YAML alias. Read with the scan's
    reader, so a FIFO is refused rather than waited on. Its ``extends`` chain is
    not followed here: the commands report a chain that does not resolve
    themselves, as a problem in a file that loads.
    """
    try:
        check_config_path(config_path)
        read_config_file(config_path)
    except ASHConfigValidationError as e:
        typer.secho(f"❌ Invalid configuration: {e}", fg=typer.colors.RED)
        raise typer.Exit(3)
    except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError) as e:
        # json.JSONDecodeError is a ValueError.
        typer.secho(
            f"❌ Invalid configuration: could not load "
            f"{describe_config_path(config_path)}: {e}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(3)


def _print_source_chain(config_path: Path) -> None:
    """Print the files an extending config is built from, lowest precedence first."""
    from automated_security_helper.config.config_validator import ConfigValidator
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    try:
        chain = ConfigValidator.resolve_source_chain(config_path)
    except (ASHConfigSourceError, OSError, ValueError, yaml.YAMLError):
        # The validator or linter has already reported why it does not resolve.
        return
    if len(chain) < 2:
        return
    typer.secho(
        "Resolved source chain (lowest precedence first):", fg=typer.colors.BLUE
    )
    for i, label in enumerate(chain, 1):
        typer.secho(f"  {i}. {label}", fg=typer.colors.BLUE)


def _rewrite_refusal(config_path: Path) -> str | None:
    """Why `config_path` must not be rewritten from a resolved config, or None.

    `update` and `wizard` write the whole resolved config back as YAML. For a
    TOML source that would replace the file's other content, and for a file that
    uses `extends` or `patch` it would copy every base's settings into the child
    and drop the directives, so later edits to a base would no longer apply.
    """
    if config_path.name.endswith(".toml"):
        return "it is a TOML file, and this command writes YAML; edit it by hand"
    try:
        # As a scan reads it, so a FIFO at the name is refused, not waited on. A
        # file that does not load is refused when the command loads it.
        raw = load_config_yaml(read_config_bytes(config_path).decode("utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ASHConfigValidationError):
        return None
    if isinstance(raw, dict) and (EXTENDS_KEY in raw or PATCH_KEY in raw):
        return (
            f"it uses '{EXTENDS_KEY}' or '{PATCH_KEY}', which rewriting would "
            "flatten into a copy of its bases; edit it by hand"
        )
    return None


class IndentableYamlDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(IndentableYamlDumper, self).increase_indent(flow, indentless)


IndentableYamlDumper.add_representer(TaggedReference, represent_tagged_reference)


@config_app.command()
def init(
    config: Annotated[
        str,
        typer.Option(
            "--config",
            "-c",
            help=f"The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_SOURCES_DESCRIPTION}. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH.",
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
    # Exclude internal-only fields that should not appear in user configs.
    # These are used at runtime but are not valid in user-facing config files.
    internal_scanner_fields = {"name", "extension", "tool_version", "install_timeout"}
    scanner_exclusions = dict.fromkeys(
        ScannerConfigSegment.model_fields, internal_scanner_fields
    )
    reporter_exclusions = dict.fromkeys(
        ReporterConfigSegment.model_fields, internal_scanner_fields
    )
    converter_exclusions = dict.fromkeys(
        ConverterConfigSegment.model_fields, internal_scanner_fields
    )

    config_strings = [
        "# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json",
        yaml.dump(
            ash_config.model_dump(
                by_alias=True,
                exclude_defaults=False,
                exclude_none=False,
                exclude={
                    "build": True,
                    "mcp_resource_management": True,
                    "scanners": scanner_exclusions,
                    "reporters": reporter_exclusions,
                    "converters": converter_exclusions,
                },
            ),
            Dumper=IndentableYamlDumper,
            default_flow_style=False,
            sort_keys=False,
        ),
    ]
    config_path.write_text("\n".join(config_strings))


@config_app.command()
def get(
    ctx: typer.Context,
    config_path: Annotated[
        str,
        typer.Argument(
            help=f"The name of the config file to get. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_SOURCES_DESCRIPTION}. If  a different filename is specified, it must be provided when running ASH via the `--config` option or by setting the `ASH_CONFIG` environment variable.",
        ),
    ] = None,
    config: Annotated[
        str | None,
        typer.Option(
            "--config",
            "-c",
            help="The path to the configuration file to get, as for `ash scan --config`. The same as the positional path; when both name a file on the command line they must name the same one. The positional path wins over ASH_CONFIG.",
            envvar="ASH_CONFIG",
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
    # The positional path, else --config / ASH_CONFIG, as `ash scan --config`
    # takes it. Two different files named on one command line are refused rather
    # than one of them silently ignored; ASH_CONFIG yields to the argument, as it
    # yields to --config in `ash scan`.
    if config_path is not None and config is not None and config_path != config:
        if getattr(ctx.get_parameter_source("config"), "name", None) == "COMMANDLINE":
            typer.secho(
                f"Name one configuration file: the argument {config_path} and "
                f"--config {config} differ.",
                fg=typer.colors.RED,
            )
            raise typer.Exit(2)
    named = config_path if config_path is not None else config
    # The file this command is about: the one named, or the one resolve_config
    # would discover. resolve_config refuses either when it cannot be loaded --
    # missing, empty, unreadable or unparseable -- and so does discovery for a
    # source it cannot read; each exits 3 below, as `ash scan` does. The named
    # path is passed as given, so an empty one is reported as empty rather than
    # as the working directory.
    config_file = None
    try:
        config_file = named if named is not None else find_config_file()
        resolved = resolve_config(
            config_file,
            config_overrides=config_overrides,
            fallback_to_default=config_file is None,
        )
    except ASHConfigValidationError as e:
        typer.secho(f"Invalid configuration: {e}", fg=typer.colors.RED)
        raise typer.Exit(3)
    except (yaml.YAMLError, ValueError, OSError) as e:
        # Exit 3 for the same reason as the schema failure above: the CLI's
        # documented code for an invalid configuration. A file that does not
        # parse is the most invalid kind. (json.JSONDecodeError and
        # UnicodeDecodeError are both ValueErrors.)
        typer.secho(
            f"Invalid configuration: could not parse {config_file}: {e}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(3)
    from automated_security_helper.config.environment_record import (
        record_environment_references,
    )

    print(
        Syntax(
            code=yaml.dump(
                # Each value the config's files read from the environment as the
                # file wrote it, as a scan's record of its config holds it.
                record_environment_references(
                    resolved.model_dump(
                        by_alias=True,
                        exclude_defaults=False,
                        exclude_none=False,
                    ),
                    resolved._environment_references,
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
            help=f"The path to the configuration file to update. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_SOURCES_DESCRIPTION}.",
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
        try:
            found = find_config_file()
        except ASHConfigValidationError as e:
            typer.secho(f"Error locating config file: {e}", fg=typer.colors.RED)
            raise typer.Exit(1)
        if found is not None:
            logger.info(f"Using config file found at: {found.as_posix()}")
            config_path = found.as_posix()

    # Check if config file exists
    if config_path is None or not Path(config_path).exists():
        typer.secho(
            "Config file not found. Use 'ash config init' to create one.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    # Load the existing config
    config_path = Path(config_path)
    refusal = _rewrite_refusal(config_path)
    if refusal:
        typer.secho(f"Cannot update {config_path}: {refusal}", fg=typer.colors.RED)
        raise typer.Exit(1)
    try:
        # Keeping what the file reads from the environment, so the file is
        # written back with each such value as its reference, not the value.
        config = load_config_with_references(config_path)
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
            # The key only: the value can be a credential.
            logger.info(f"Applied a modification to {key_path}")
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
    # Read as a scan reads it, so a FIFO swapped in at the name is refused rather
    # than waited on; the file loaded above, so a failure here only drops the line.
    try:
        lines = read_config_bytes(config_path).decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError, ASHConfigValidationError):
        lines = []
    first_line = lines[0].strip() if lines else ""
    if first_line.startswith("#") and "schema" in first_line.lower():
        config_strings.append(first_line)

    # If no schema reference was found, add the default one
    if not config_strings:
        config_strings.append(
            "# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json"
        )

    # Add the updated config, each value the file read from the environment
    # written as its reference, tagged !ENV, so the file reads it from the
    # environment again (config/environment_record.py).
    from automated_security_helper.config.environment_record import (
        record_environment_references,
    )

    config_strings.append(
        yaml.dump(
            record_environment_references(
                updated_config.model_dump(
                    by_alias=True,
                    exclude_defaults=False,
                    exclude_none=False,
                ),
                config._environment_references,
                mark=TaggedReference,
                whole_only=True,
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
def validate_plugin_dependencies(
    config_path: Annotated[
        str,
        typer.Argument(
            help=f"The name of the config file to create. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_SOURCES_DESCRIPTION}. If  a different filename is specified, it must be provided when running ASH via the `--config` option or by setting the `ASH_CONFIG` environment variable.",
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


@config_app.command()
def lint(
    config: Annotated[
        str | None,
        typer.Option(
            "--config",
            "-c",
            help="The path to the configuration file to lint. By default, ASH lints the config a scan of the current directory would use (see the configuration guide for the discovery order), falling back to .ash/.ash.yaml.",
            envvar="ASH_CONFIG",
        ),
    ] = None,
    output_dir: Annotated[
        str,
        typer.Option(
            "--output-dir",
            "-o",
            help="Path to the ASH output directory (for unused suppressions report). Defaults to .ash/ash_output",
        ),
    ] = None,
    fix: Annotated[
        bool,
        typer.Option(
            "--fix",
            help="Auto-fix fixable issues (internal fields, missing line_end, expired suppressions, multi-line suppression reasons)",
        ),
    ] = False,
    fix_unused: Annotated[
        bool,
        typer.Option(
            "--fix-unused",
            help="Comment out unused suppressions based on the last scan's unused suppressions report",
        ),
    ] = False,
    non_interactive: Annotated[
        bool,
        typer.Option(
            "--non-interactive",
            "--yes",
            "-y",
            help="Accept all changes without prompting. Useful for pre-commit hooks and CI/CD",
        ),
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug", "-d", help="Enable debug logging")
    ] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
):
    """Lint an ASH configuration file for issues and optionally auto-fix them.

    This command performs all validation checks plus additional lint checks:
    - Internal-only fields in scanners/reporters/converters
    - Invalid or unknown top-level sections
    - Duplicate field definitions
    - Suppressions with line_start but missing line_end
    - Expired suppressions
    - Suppression reasons spanning multiple lines
    - Unused suppressions (from last scan report)

    Use --fix to auto-fix common issues (removes internal fields, sets missing
    line_end, removes expired suppressions, collapses multi-line reasons).

    Use --fix-unused to remove suppressions that are no longer matching any
    findings (based on the unused suppressions report from the last scan).

    Use --non-interactive (or --yes/-y) to skip confirmation prompts. This is
    useful for pre-commit hooks or CI/CD pipelines.

    Examples:
        # Lint the default config
        ash config lint

        # Lint and auto-fix issues
        ash config lint --fix

        # Lint, fix, and remove unused suppressions
        ash config lint --fix --fix-unused

        # Non-interactive mode for pre-commit
        ash config lint --fix --fix-unused --non-interactive

        # Lint a specific config file
        ash config lint --config path/to/config.yaml
    """
    from automated_security_helper.config.config_linter import (
        ConfigLinter,
        LintSeverity,
    )

    # Setup logging
    get_logger(
        name="ash.cli.config.lint",
        level=logging.DEBUG
        if debug
        else (logging.INFO if verbose else logging.WARNING),
        show_progress=False,
        use_color=color,
    )

    try:
        config_path = _config_path_or_discovered(config)
    except ASHConfigValidationError as e:
        typer.secho(f"❌ {e}", fg=typer.colors.RED)
        raise typer.Exit(3)
    output_dir_path = Path(output_dir) if output_dir else None

    _refuse_unloadable(config_path)

    if (fix or fix_unused) and config_path.name.endswith(".toml"):
        typer.secho(
            f"❌ --fix and --fix-unused rewrite YAML and JSON config files only; "
            f"edit {describe_config_path(config_path)} by hand.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    typer.secho(
        f"Linting configuration file: {describe_config_path(config_path)}",
        fg=typer.colors.BLUE,
    )

    # Run lint checks
    lint_result = ConfigLinter.lint(
        config_path=config_path,
        output_dir=output_dir_path,
        check_unused=fix_unused,  # Only check unused when explicitly requested
    )
    _print_source_chain(config_path)

    # Display issues
    if not lint_result.issues:
        typer.secho(
            "✅ Configuration is clean! No issues found.", fg=typer.colors.GREEN
        )
        return

    # Print all issues
    typer.secho(
        f"\nFound {len(lint_result.issues)} issue(s):",
        fg=typer.colors.YELLOW,
    )
    for issue in lint_result.issues:
        fg = {
            LintSeverity.ERROR: typer.colors.RED,
            LintSeverity.WARNING: typer.colors.YELLOW,
            LintSeverity.INFO: typer.colors.CYAN,
        }[issue.severity]
        typer.secho(f"  {issue}", fg=fg)

    typer.echo("")

    # Summary
    if lint_result.error_count:
        typer.secho(f"  Errors: {lint_result.error_count}", fg=typer.colors.RED)
    if lint_result.warning_count:
        typer.secho(f"  Warnings: {lint_result.warning_count}", fg=typer.colors.YELLOW)
    if lint_result.info_count:
        typer.secho(f"  Info: {lint_result.info_count}", fg=typer.colors.CYAN)

    fixable_count = len(lint_result.fixable_issues)
    if fixable_count and not fix and not fix_unused:
        typer.secho(
            f"\n💡 {fixable_count} issue(s) can be auto-fixed. Run with --fix to apply fixes.",
            fg=typer.colors.YELLOW,
        )

    # Apply fixes if requested
    if fix:
        _apply_fixes(config_path, lint_result, non_interactive, color)

    # Apply unused suppression removal if requested
    if fix_unused:
        _apply_unused_fixes(config_path, output_dir_path, non_interactive, color)

    # Exit with error code if there are unfixed errors
    if not fix and not fix_unused and lint_result.has_errors:
        raise typer.Exit(1)


def _apply_fixes(
    config_path: Path,
    lint_result,
    non_interactive: bool,
    color: bool,
) -> None:
    """Apply auto-fixes to the config file."""
    from automated_security_helper.config.config_linter import (
        ConfigLinter,
        LintCategory,
    )

    fixable = [
        i
        for i in lint_result.fixable_issues
        if i.category != LintCategory.SUPPRESSION_UNUSED
    ]

    if not fixable:
        typer.secho(
            "No fixable issues found (excluding unused suppressions).",
            fg=typer.colors.GREEN,
        )
        return

    typer.secho(f"\n🔧 Fixing {len(fixable)} issue(s):", fg=typer.colors.BLUE)
    for issue in fixable:
        # An issue that sets fixable=True without a fix_description would print an
        # empty bullet, which tells the user a change is coming but not which one.
        # The message always names the problem, so fall back to it.
        typer.secho(
            f"  • {issue.fix_description or issue.message}", fg=typer.colors.CYAN
        )

    if not non_interactive:
        confirm = typer.confirm("\nApply these fixes?")
        if not confirm:
            typer.secho("Aborted.", fg=typer.colors.YELLOW)
            raise typer.Exit(0)

    fixed_content, fixed_issues = ConfigLinter.fix(config_path, fixable)

    if fixed_issues:
        config_path.write_text(fixed_content, encoding="utf-8")
        typer.secho(
            f"\n✅ Fixed {len(fixed_issues)} issue(s) in {config_path}",
            fg=typer.colors.GREEN,
        )
    else:
        typer.secho("No issues were fixed.", fg=typer.colors.YELLOW)


def _apply_unused_fixes(
    config_path: Path,
    output_dir,
    non_interactive: bool,
    color: bool,
) -> None:
    """Comment out unused suppressions in the config file."""
    from automated_security_helper.config.config_linter import ConfigLinter

    # Check report age first
    report_info = ConfigLinter.get_unused_report_age(config_path, output_dir)

    if report_info is None:
        typer.secho(
            "⚠️  No unused suppressions report found. Run a scan first to generate the report.",
            fg=typer.colors.YELLOW,
        )
        return

    report_path, report_timestamp, age_seconds = report_info

    # Warn if report is too old
    if age_seconds > ConfigLinter.MAX_REPORT_AGE_SECONDS:
        age_hours = age_seconds / 3600
        typer.secho(
            f"\n⚠️  WARNING: The unused suppressions report is {age_hours:.1f} hours old "
            f"(generated at {report_timestamp.strftime('%Y-%m-%d %H:%M:%S')}).",
            fg=typer.colors.YELLOW,
        )
        typer.secho(
            "   Results may not reflect the current state of your codebase.",
            fg=typer.colors.YELLOW,
        )
        typer.secho(
            "   Consider running a fresh scan: ash scan",
            fg=typer.colors.YELLOW,
        )

        if not non_interactive:
            confirm = typer.confirm(
                "\nProceed with commenting out unused suppressions based on this old report?"
            )
            if not confirm:
                typer.secho("Aborted.", fg=typer.colors.YELLOW)
                raise typer.Exit(0)

    # Perform the fix
    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(
        config_path, output_dir
    )

    if not fixed_issues:
        typer.secho("✅ No unused suppressions to comment out.", fg=typer.colors.GREEN)
        return

    typer.secho(
        f"\n💬 Commenting out {len(fixed_issues)} unused suppression(s):",
        fg=typer.colors.BLUE,
    )
    for issue in fixed_issues:
        typer.secho(f"  • {issue.message}", fg=typer.colors.CYAN)

    if not non_interactive:
        confirm = typer.confirm("\nComment out these unused suppressions?")
        if not confirm:
            typer.secho("Aborted.", fg=typer.colors.YELLOW)
            raise typer.Exit(0)

    # Bytes: fixed_content is the file's own text with its line endings (read as
    # bytes by fix_unused_suppressions), and text mode would turn the "\n" of a
    # CRLF file into "\r\n" a second time on Windows.
    config_path.write_bytes(fixed_content.encode("utf-8"))
    typer.secho(
        f"\n✅ Commented out {len(fixed_issues)} unused suppression(s) in {config_path}",
        fg=typer.colors.GREEN,
    )


def _get_scanner_names() -> List[tuple]:
    """Return (python_name, display_name) tuples for built-in scanners.

    display_name uses the field's YAML alias when available, falling back
    to replacing underscores with hyphens.
    """
    names = []
    for name, field_info in ScannerConfigSegment.model_fields.items():
        alias = field_info.alias or name.replace("_", "-")
        names.append((name, alias))
    return names


def _get_reporter_names() -> List[tuple]:
    """Return (python_name, display_name) tuples for built-in reporters.

    display_name uses the field's YAML alias when available, falling back
    to replacing underscores with hyphens.
    """
    names = []
    for name, field_info in ReporterConfigSegment.model_fields.items():
        alias = field_info.alias or name.replace("_", "-")
        names.append((name, alias))
    return names


def _prompt_toggle_items(
    items: List[tuple],
    current_enabled: Dict[str, bool],
    label: str,
) -> Dict[str, bool]:
    """Prompt the user to toggle each item on or off.

    items is a list of (python_name, display_name) tuples.
    Returns a dict mapping python_name to enabled state.
    """
    console = Console()
    table = Table(title=label, show_header=True, header_style="bold cyan")
    table.add_column("Name", style="white")
    table.add_column("Currently enabled", justify="center")
    for python_name, display_name in items:
        status = current_enabled.get(python_name, True)
        table.add_row(display_name, "[green]yes[/green]" if status else "[red]no[/red]")
    console.print(table)

    result = {}
    for python_name, display_name in items:
        default = current_enabled.get(python_name, True)
        answer = typer.confirm(
            f"  Enable {display_name}?",
            default=default,
        )
        result[python_name] = answer
    return result


@config_app.command()
def wizard(
    config: Annotated[
        str,
        typer.Option(
            "--config",
            "-c",
            help="Path to read/write the configuration file.",
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
):
    """Interactive configuration wizard.

    Reads an existing .ash.yaml (if present), walks through scanner,
    reporter, offline-mode, and community-plugin settings interactively,
    then writes the result back.
    """
    get_logger(
        level=(logging.DEBUG if debug else 15 if verbose else logging.INFO),
        show_progress=False,
        use_color=color,
    )
    console = Console()
    config_path = Path(config)

    # --- Load existing config or start from defaults ---
    if config_path.exists() and _rewrite_refusal(config_path):
        typer.secho(
            f"Cannot edit {config_path} with the wizard: "
            f"{_rewrite_refusal(config_path)}",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    if os.path.lexists(config_path) and not is_regular_file(config_path):
        # A link to nothing, a directory: not "no config yet", and writing the
        # answers would go through the link to wherever it points.
        typer.secho(
            f"Invalid configuration: {config_path} exists but is not a regular "
            "file, so the wizard will not write it.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(3)
    if config_path.exists():
        console.print(
            Panel(
                f"Loading existing config from [bold]{config_path.absolute()}[/bold]",
                title="ASH Config Wizard",
            )
        )
        try:
            # Keeping what the file reads from the environment: the wizard shows
            # and writes back each such value as its reference.
            ash_config = load_config_with_references(config_path)
        except Exception as exc:
            # Refused, not replaced by the defaults: the wizard writes its result
            # back over this file, which would drop every setting it does not ask
            # about.
            typer.secho(
                f"Invalid configuration: {config_path} could not be loaded ({exc}). "
                "Fix the file, or move it aside to start from the defaults.",
                fg=typer.colors.RED,
            )
            raise typer.Exit(3)
    else:
        console.print(
            Panel(
                "No existing config found -- starting from defaults.",
                title="ASH Config Wizard",
            )
        )
        ash_config = AshConfig()

    from automated_security_helper.config.environment_record import (
        record_environment_references,
    )

    # --- 1. Project name ---
    # Offered as the file wrote it: a name read from the environment is shown,
    # and kept, as its reference.
    project_name = typer.prompt(
        "Project name",
        default=record_environment_references(
            {"project_name": ash_config.project_name},
            ash_config._environment_references,
        )["project_name"],
    )
    ash_config.project_name = project_name

    # --- 2. Scanners ---
    console.print("\n[bold]Scanner configuration[/bold]")
    scanner_items = _get_scanner_names()
    current_scanner_enabled: Dict[str, bool] = {}
    for python_name, _ in scanner_items:
        scanner_cfg = getattr(ash_config.scanners, python_name, None)
        current_scanner_enabled[python_name] = (
            scanner_cfg.enabled if scanner_cfg is not None else True
        )

    scanner_states = _prompt_toggle_items(
        scanner_items, current_scanner_enabled, "Scanners"
    )
    for name, enabled in scanner_states.items():
        scanner_cfg = getattr(ash_config.scanners, name, None)
        if scanner_cfg is not None:
            scanner_cfg.enabled = enabled

    # --- 3. Reporters (output formats) ---
    console.print("\n[bold]Output format configuration[/bold]")
    reporter_items = _get_reporter_names()
    current_reporter_enabled: Dict[str, bool] = {}
    for python_name, _ in reporter_items:
        reporter_cfg = getattr(ash_config.reporters, python_name, None)
        current_reporter_enabled[python_name] = (
            reporter_cfg.enabled if reporter_cfg is not None else True
        )

    reporter_states = _prompt_toggle_items(
        reporter_items, current_reporter_enabled, "Output Formats"
    )
    for name, enabled in reporter_states.items():
        reporter_cfg = getattr(ash_config.reporters, name, None)
        if reporter_cfg is not None:
            reporter_cfg.enabled = enabled

    # --- 4. Offline mode ---
    console.print("\n[bold]Offline mode[/bold]")
    console.print(
        "  Offline mode skips tool installation. Set the ASH_OFFLINE "
        "environment variable at runtime to activate it."
    )
    current_offline = os.environ.get("ASH_OFFLINE", "NO").upper() in (
        "YES",
        "TRUE",
        "1",
    )
    enable_offline = typer.confirm(
        "  Set ASH_OFFLINE=YES in the generated config comments as a reminder?",
        default=current_offline,
    )

    # --- 5. Community plugin modules ---
    console.print("\n[bold]Community plugin modules[/bold]")
    console.print(
        "  Provide Python module paths for additional plugins, "
        "one per line. Leave blank to finish."
    )
    existing_modules = list(ash_config.ash_plugin_modules)
    if existing_modules:
        console.print(f"  Currently configured: {existing_modules}")

    plugin_modules: List[str] = []
    for mod in existing_modules:
        keep = typer.confirm(f"  Keep module '{mod}'?", default=True)
        if keep:
            plugin_modules.append(mod)

    while True:
        new_mod = typer.prompt(
            "  Add a plugin module (blank to finish)",
            default="",
            show_default=False,
        )
        if not new_mod.strip():
            break
        plugin_modules.append(new_mod.strip())

    ash_config.ash_plugin_modules = plugin_modules

    # --- Write config ---
    config_path.parent.mkdir(exist_ok=True, parents=True)
    if config_path.parent.name == ".ash":
        ash_gitignore_path = config_path.parent.joinpath(".gitignore")
        if not ash_gitignore_path.exists():
            ash_gitignore_path.write_text(
                "# ASH default output directory (and variants)\nash_output*\n"
            )

    internal_scanner_fields = {"name", "extension", "tool_version", "install_timeout"}
    scanner_exclusions = dict.fromkeys(
        ScannerConfigSegment.model_fields, internal_scanner_fields
    )
    reporter_exclusions = dict.fromkeys(
        ReporterConfigSegment.model_fields, internal_scanner_fields
    )
    converter_exclusions = dict.fromkeys(
        ConverterConfigSegment.model_fields, internal_scanner_fields
    )

    config_strings = [
        "# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json",
    ]
    if enable_offline:
        config_strings.append(
            "# Reminder: export ASH_OFFLINE=YES before running ASH for offline mode"
        )

    config_strings.append(
        yaml.dump(
            # Each value the file read from the environment as its reference,
            # tagged !ENV, so the file reads it from the environment again.
            record_environment_references(
                ash_config.model_dump(
                    by_alias=True,
                    exclude_defaults=False,
                    exclude_none=False,
                    exclude={
                        "build": True,
                        "mcp_resource_management": True,
                        "scanners": scanner_exclusions,
                        "reporters": reporter_exclusions,
                        "converters": converter_exclusions,
                    },
                ),
                ash_config._environment_references,
                mark=TaggedReference,
                whole_only=True,
            ),
            Dumper=IndentableYamlDumper,
            default_flow_style=False,
            sort_keys=False,
        )
    )
    config_path.write_text("\n".join(config_strings))

    console.print(
        Panel(
            f"Config written to [bold]{config_path.absolute()}[/bold]",
            title="Done",
            style="green",
        )
    )


if __name__ == "__main__":
    config_app()


if __name__ == "__main__":
    config_app()


@config_app.command()
def validate(
    config: Annotated[
        str | None,
        typer.Option(
            "--config",
            "-c",
            help="The path to the configuration file to validate. By default, ASH validates the config a scan of the current directory would use (see the configuration guide for the discovery order), falling back to .ash/.ash.yaml.",
            envvar="ASH_CONFIG",
        ),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug", "-d", help="Enable debug logging")
    ] = False,
):
    """Validate an ASH configuration file for common issues.

    This command checks for:
    - Invalid or internal-only fields in scanners/reporters/converters
    - Duplicate top-level field definitions
    - Missing required fields
    - Invalid top-level sections
    - YAML/JSON syntax errors

    Examples:
        # Validate default config
        ash config validate

        # Validate specific config file
        ash config validate --config path/to/config.yaml

        # Validate with verbose output
        ash config validate --verbose
    """
    # Setup logging
    logger = get_logger(
        name="ash.cli.config.validate",
        level=logging.DEBUG
        if debug
        else (logging.INFO if verbose else logging.WARNING),
    )

    try:
        from automated_security_helper.config.config_validator import ConfigValidator

        try:
            config_path = _config_path_or_discovered(config)
        except ASHConfigValidationError as e:
            typer.secho(f"❌ {e}", fg=typer.colors.RED)
            raise typer.Exit(3)

        _refuse_unloadable(config_path)

        typer.secho(
            f"Validating configuration file: {describe_config_path(config_path)}",
            fg=typer.colors.BLUE,
        )

        is_valid, errors = ConfigValidator.validate_config_file(config_path)
        _print_source_chain(config_path)

        if is_valid:
            typer.secho("✅ Configuration is valid!", fg=typer.colors.GREEN)
            typer.secho(
                "\nThe configuration file passed all validation checks.",
                fg=typer.colors.GREEN,
            )
            return

        # Configuration has errors
        typer.secho(
            f"\n❌ Configuration validation failed with {len(errors)} error(s):",
            fg=typer.colors.RED,
        )
        for i, error in enumerate(errors, 1):
            typer.secho(f"  {i}. {error}", fg=typer.colors.RED)

        typer.secho(
            "\n💡 Common fixes:",
            fg=typer.colors.YELLOW,
        )
        typer.secho(
            "  - Remove internal-only fields like 'name', 'extension', 'tool_version' from scanner/reporter configs",
            fg=typer.colors.YELLOW,
        )
        typer.secho(
            "  - Remove invalid top-level sections like 'build' or 'mcp-resource-management'",
            fg=typer.colors.YELLOW,
        )
        typer.secho(
            "  - Check for duplicate field definitions in your YAML file",
            fg=typer.colors.YELLOW,
        )
        typer.secho(
            "\n📖 See the ASH configuration documentation for the correct format.",
            fg=typer.colors.BLUE,
        )

        raise typer.Exit(1)

    except typer.Exit:
        raise
    except Exception as e:
        logger.error(f"Error validating config: {e}")
        typer.secho(f"❌ Error validating config: {e}", fg=typer.colors.RED)
        raise typer.Exit(1)
