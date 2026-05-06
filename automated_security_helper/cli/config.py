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

from automated_security_helper.config.ash_config import (
    AshConfig,
    ConverterConfigSegment,
    ReporterConfigSegment,
    ScannerConfigSegment,
)
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
    # Exclude internal-only fields that should not appear in user configs.
    # These are used at runtime but are not valid in user-facing config files.
    internal_scanner_fields = {"name", "extension", "tool_version", "install_timeout"}
    scanner_exclusions = {
        scanner_name: internal_scanner_fields
        for scanner_name in ScannerConfigSegment.model_fields
    }
    reporter_exclusions = {
        reporter_name: internal_scanner_fields
        for reporter_name in ReporterConfigSegment.model_fields
    }
    converter_exclusions = {
        converter_name: internal_scanner_fields
        for converter_name in ConverterConfigSegment.model_fields
    }

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
def validate_plugin_dependencies(
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


@config_app.command()
def lint(
    config: Annotated[
        str,
        typer.Option(
            "--config",
            "-c",
            help="The path to the configuration file to lint. By default, ASH looks for config files in .ash/.ash.yaml",
            envvar="ASH_CONFIG",
        ),
    ] = ".ash/.ash.yaml",
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
            help="Auto-fix fixable issues (internal fields, missing line_end, expired suppressions)",
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
    - Unused suppressions (from last scan report)

    Use --fix to auto-fix common issues (removes internal fields, sets missing
    line_end, removes expired suppressions).

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

    config_path = Path(config)
    output_dir_path = Path(output_dir) if output_dir else None

    if not config_path.exists():
        typer.secho(f"❌ Config file not found: {config_path}", fg=typer.colors.RED)
        raise typer.Exit(1)

    typer.secho(f"Linting configuration file: {config_path}", fg=typer.colors.BLUE)

    # Run lint checks
    lint_result = ConfigLinter.lint(
        config_path=config_path,
        output_dir=output_dir_path,
        check_unused=fix_unused,  # Only check unused when explicitly requested
    )

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
        typer.secho(f"  • {issue.fix_description}", fg=typer.colors.CYAN)

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

    config_path.write_text(fixed_content, encoding="utf-8")
    typer.secho(
        f"\n✅ Commented out {len(fixed_issues)} unused suppression(s) in {config_path}",
        fg=typer.colors.GREEN,
    )


if __name__ == "__main__":
    config_app()


@config_app.command()
def validate(
    config: Annotated[
        str,
        typer.Option(
            "--config",
            "-c",
            help="The path to the configuration file to validate. By default, ASH looks for config files in .ash/.ash.yaml",
            envvar="ASH_CONFIG",
        ),
    ] = ".ash/.ash.yaml",
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

        config_path = Path(config)

        if not config_path.exists():
            typer.secho(f"❌ Config file not found: {config_path}", fg=typer.colors.RED)
            raise typer.Exit(1)

        typer.secho(
            f"Validating configuration file: {config_path}", fg=typer.colors.BLUE
        )

        is_valid, errors = ConfigValidator.validate_config_file(config_path)

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
