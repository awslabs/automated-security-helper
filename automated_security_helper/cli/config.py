# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import errno
import logging
import os
from pathlib import Path
from typing import (
    Annotated,
    Any,
    Collection,
    Dict,
    List,
    NoReturn,
    Optional,
)
import yaml
import typer
from pydantic import ValidationError

from automated_security_helper.utils.console import (
    ash_console,
    confirm,
    echo,
    prompt,
    secho,
)

# `print` shadows the builtin on purpose: this is rich's documented import
# idiom, so every print() below renders markup and respects the console. The
# fix A004 wants is an alias, which would mean rewriting every call in this
# module for no behavior change -- and tests/unit/cli/mcp/test_stdout_jsonrpc_safety.py
# reasons about this exact import form. It is utils/console.py's print, not rich's:
# its console checks each line it writes off a terminal, so none reads as a CI command.
from automated_security_helper.utils.console import print  # noqa: A004
from automated_security_helper.utils.parser_text import own_lines
from automated_security_helper.utils.terminal_text import shown_on_one_line
from automated_security_helper.utils.ui_theme import COLORS, rich_theme
from rich.text import Text
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from automated_security_helper.cli.json_input import PathRefused

from automated_security_helper.config.ash_config import (
    AshConfig,
    ReporterConfigSegment,
    ScannerConfigSegment,
    load_config_yaml,
)
from automated_security_helper.config.config_writer import (
    SCHEMA_COMMENT,
    _as_reference,
    _AsWrittenYamlDumper,
    render_config_file,
)
from automated_security_helper.config.config_sources import (
    EXTENDS_KEY,
    PATCH_KEY,
    describe_config_path,
    discover_config_source,
    is_config_parse_error,
    is_json_file,
    is_regular_file,
    is_toml_file,
    read_config_bytes,
    read_config_file,
    refuse_unless_a_file,
    resolve_config_document,
    unparsed_config_reason,
    uses_env_references,
)
from automated_security_helper.config.config_validator import (
    ConfigCheck,
    describe_validation_error,
)
from automated_security_helper.config.environment_record import (
    ENVIRONMENT_VALUE_SHOWN,
    with_environment_values_shown,
)
from automated_security_helper.config.plugin_module_trust import (
    plugin_module_refusal_message,
    refuse_plugin_modules_a_scan_refuses,
)
from automated_security_helper.config.resolve_config import (
    find_config_file,
    resolve_config,
)
from automated_security_helper.core.constants import (
    ASH_CONFIG_FILE_NAMES,
    ASH_CONFIG_SOURCES_DESCRIPTION,
    ASH_DEFAULT_CONFIG_FILE_NAME,
    ASH_EXIT_USAGE_ERROR,
    ASH_RC_FILE_NAMES,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.models.workspace import WorkspaceExitCode
from automated_security_helper.utils.directory_refusals import source_dir_refusal
from automated_security_helper.utils.error_text import error_text
from automated_security_helper.utils.log import (
    escape_markup,
    get_logger,
    show_debug_locals,
)

# The exit code for a configuration a scan would refuse, the one `ash scan` exits
# with for an invalid config (ASH_EXIT_CODES in core/constants.py).
INVALID_CONFIG_EXIT_CODE = int(WorkspaceExitCode.INVALID_PROJECT_CONFIG)


# What a scan does with a config file that cannot be used at all -- it does
# not parse (YAML, JSON, TOML, or not UTF-8), or it cannot be read:
# resolve_config refuses it with exit 3, as validate and lint exit for it,
# since none of the file applies. Read and parse are told apart in the verdict,
# so a reader is not sent to fix syntax the check never saw.
def _ignored_file_verdict(could_not_read: bool) -> str:
    problem = "cannot be read" if could_not_read else "does not parse"
    return f"A scan refuses this file too: it {problem}, so none of its settings apply"


config_app = typer.Typer(
    name="config",
    help="ASH configuration management",
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    # Not on a CI runner: locals can hold secrets (utils/log.py).
    pretty_exceptions_show_locals=show_debug_locals(),
)


_SOURCE_DIR_HELP = (
    "The directory a scan would scan, as `ash scan --source-dir`: the config is "
    "discovered there unless --config names one, and a config inside it may only "
    "extend files inside it. Defaults to the current directory."
)


def _source_dir(source_dir: str | None) -> Path:
    """--source-dir, or the current directory, as `ash scan` defaults it.

    Refused as `ash scan` refuses it, with exit 5 and the same text
    (utils/directory_refusals.py), when it names no directory a scan could read, so
    these commands never report "No config file found in" a directory that does
    not exist, as if they had looked in one.
    """
    scan_root = Path(source_dir) if source_dir else Path.cwd()
    refusal = source_dir_refusal(scan_root)
    if refusal is not None:
        echo(shown_on_one_line(refusal), err=True)
        raise typer.Exit(ASH_EXIT_USAGE_ERROR)
    return scan_root


def _config_path_or_discovered(config: str | None, source_dir: Path) -> Path | None:
    """The --config path, or the source a scan of source_dir would use, or None.

    A discovery that fails (a pyproject.toml that declares [tool.ash] and is not
    valid TOML) exits 3, as the scan does.
    """
    if config:
        return Path(config)
    try:
        return find_config_file(source_dir)
    except ASHConfigValidationError as e:
        # Labeled as `ash plugin list` labels the same refusal, and one line:
        # the refusal names the caller's path.
        secho(shown_on_one_line(f"❌ Invalid configuration: {e}"), fg=typer.colors.RED)
        raise typer.Exit(INVALID_CONFIG_EXIT_CODE)


def _refuse_missing_config(config_path: str | Path) -> NoReturn:
    """Exit 3, an unusable configuration, for a named config file that does not exist.

    A path given with --config, in ASH_CONFIG or as the command's path argument
    names the configuration to use, and one that names nothing leaves none: the
    exit code is the one for a configuration ASH cannot use, as for a directory or
    a file that cannot be read. Exit 5 is for the command line itself (an unknown
    option or selection). No config file found in the directory, with none named,
    is a state of the project and stays exit 1 (_report_no_config_found).
    """
    # A symbolic link loop fails exists() the same way a missing file does;
    # "not found" would send the operator looking for a typo instead of at the
    # link. stat says which it is.
    message = f"❌ Config file not found: {Path(config_path).as_posix()}"
    try:
        os.stat(config_path)
    except OSError as e:
        if e.errno == errno.ELOOP:
            message = (
                f"❌ Config file is a symbolic link loop: "
                f"{Path(config_path).as_posix()}"
            )
    except ValueError:
        pass
    # One line: the path is the caller's text, and a newline in it would start a
    # line of its own.
    secho(shown_on_one_line(message), fg=typer.colors.RED)
    raise typer.Exit(INVALID_CONFIG_EXIT_CODE)


def _refuse_unless_a_file(config_path: Path) -> None:
    """Exit 3 for a config path that exists and is not a regular file.

    For the commands that open the file to edit it (``update``, the wizard,
    ``init --force``, which opens it for writing): a FIFO's open waits for the
    other end, and a directory or a device is not a config. Checked with stat,
    before any open (``config_sources.refuse_unless_a_file``). A path that does
    not exist passes.
    """
    try:
        refuse_unless_a_file(Path(config_path))
    except ASHConfigValidationError as e:
        # One line: the refusal names the caller's path.
        secho(shown_on_one_line(f"❌ {e}"), fg=typer.colors.RED)
        raise typer.Exit(INVALID_CONFIG_EXIT_CODE)


def _print_unchecked_plugin_options_note(check: ConfigCheck) -> None:
    """Say which plugin sections validate cannot check, as 'ash config lint' does.

    validate does not load the modules ash_plugin_modules names, so it cannot know
    what those plugins declare, and a scan can still refuse their options (exit 3)
    when it loads them. The sentence is the one lint reports as its
    plugin-options-unchecked issue, built from the file's contents as the check
    read them, so the file is parsed once.
    """
    from automated_security_helper.config.plugin_option_check import (
        options_checked_at_scan_note,
    )

    note = options_checked_at_scan_note(
        check.config_data,
        with_environment_values_shown(check.config_data, check.file_references),
    )
    if note:
        secho(f"\nℹ️  {note}", fg=typer.colors.BLUE)


def _report_no_config_found(source_dir: Path) -> None:
    secho(
        f"❌ No config file found in {source_dir}, so a scan of it uses the default "
        "configuration. Create one with 'ash config init', or pass --config.",
        fg=typer.colors.RED,
    )


def _print_invalid_config(
    config_file: Path | None,
    source_dir: Path,
    config_overrides: List[str],
    error: Exception,
) -> None:
    """Report a config resolve_config refused, without repeating any value.

    The file is checked again and the check's messages are printed (see
    ConfigValidator.check_config_file), with the file named in the header. When
    the check finds nothing to say, the refusal came from elsewhere (the
    ASH_CONFIG file, the operator's own config, or an override), so the header
    names no file, and the refusal's own message is printed: resolve_config's
    is redacted with the values the refused chain read from the environment.
    Formatting the ValidationError behind it instead printed a key that chain
    read under the wrong file's name.
    """
    from pydantic import ValidationError

    from automated_security_helper.config.config_validator import ConfigValidator
    from automated_security_helper.plugins.loader import PluginModuleError

    messages: List[str] = []
    header: Optional[str] = "Invalid configuration:"
    # A parser's message spans lines of its own and keeps them; every other
    # message is one line, since it can name the caller's path.
    keep_layout = False
    if isinstance(error, PluginModuleError):
        # The raised refusal is the whole verdict, closed in these commands'
        # own words: str() carries the scan's closing, which names a run these
        # commands do not make and option spellings they do not take, and
        # re-checking the file would re-derive the same refusal with the
        # validator's closing, whose namespace form offers only the config
        # file - wrong for an entry --config-overrides added, which these
        # commands take.
        if config_file is not None:
            header = f"Invalid configuration in {config_file}:"
        messages = [plugin_module_refusal_message(error)]
    elif config_file is not None:
        check = ConfigValidator.check_config_file(
            config_file,
            source_dir=source_dir,
            config_overrides=config_overrides,
            # A refusal get_default_config marked is the ASH_CONFIG file's own,
            # printed below: its check would load that file once more.
            check_ash_config=getattr(error, "ash_config_file", None) is None,
        )
        # The ASH_CONFIG file's refusal is not about config_file: printed
        # under its name, it would blame the wrong file. The refusal's own
        # message below names the right one.
        messages = [e for e in check.errors if e not in check.ash_config_errors]
        keep_layout = check.ignored_by_scan
        if messages:
            # A parse refusal names the file and says it did not parse, under
            # its category prefix, and a read failure's error says the file
            # could not be read, so a "could not parse <file>:" header would
            # state either a second time: the error is printed as it is.
            # Every format's parse refusal marks the check (ignored_by_scan),
            # TOML's included.
            header = (
                None
                if check.ignored_by_scan
                else f"Invalid configuration in {config_file}:"
            )
    if not messages:
        if isinstance(error, ValidationError):
            # Not one resolve_config raises; formatted without its inputs.
            messages = [ConfigValidator.format_model_error(e) for e in error.errors()]
        else:
            messages = [str(error)]
            # The ASH_CONFIG file's parse refusal, printed as the scan prints it.
            keep_layout = bool(getattr(error, "parser_message", False))
    # The header names the file on one line, whatever its path holds.
    if header is not None:
        secho(shown_on_one_line(header), fg=typer.colors.RED)
    # Messages are indented under a header; a headerless parse refusal is the
    # whole report and starts the line.
    indent = "  " if header is not None else ""
    # The files a parser's message can quote: a newline in a name is not one of
    # the parser's lines.
    quoted = [
        path
        for path in (config_file, getattr(error, "ash_config_file", None))
        if path is not None
    ]
    for message in messages:
        if keep_layout:
            for line in own_lines(f"{indent}{message}", quoted):
                secho(shown_on_one_line(line), fg=typer.colors.RED)
        else:
            secho(shown_on_one_line(f"{indent}{message}"), fg=typer.colors.RED)


def _lint_fix_removes_something(config_path: Path, check: Any) -> bool:
    """Whether ``ash config lint --fix`` removes an internal-only field or section
    from ``config_path``, which validate then says it does.

    lint --fix rewrites no TOML file and no file that reads the environment, and
    of the file's own internal-only fields it keeps a pin the operator may have
    meant (ConfigLinter.fix_removes). It removes an internal top-level section.
    Whether a scan refuses the field does not matter: the fix is the same.

    Whether the file reads the environment comes from the check's own read
    (``file_references``), never from opening the file again: a second open is
    the swap window the one-read contract closes, and a writer racing validate
    could hand the hint a different file than the check read.
    """
    from automated_security_helper.config.config_linter import ConfigLinter
    from automated_security_helper.config.config_validator import ConfigValidator

    if is_toml_file(config_path) or check.file_references:
        return False
    if not isinstance(check.config_data, dict):
        return False
    return any(
        ConfigLinter.fix_removes(field_ref, check.config_data)
        for field_ref in ConfigValidator._internal_fields(check.config_data)
    ) or any(
        warning.startswith("Top-level field '") and "is an internal field" in warning
        for warning in check.warnings
    )


def _refused_file_label(label: str, config_file: Path, error: BaseException) -> str:
    """``label``, or the file ASH_CONFIG names when ``error`` is that file's refusal.

    resolve_config loads the ASH_CONFIG file as the base before config_file, so
    the refusal can be that file's, and printed under config_file's name it
    blamed a valid file. Which file it is comes from the refusal itself:
    get_default_config marks its own (ASHConfigValidationError.ash_config_file),
    and an OSError names the path it could not read. ASH_CONFIG can name any
    path, a directory included.
    """
    ash_config = os.environ.get("ASH_CONFIG") or ""
    refused = getattr(error, "ash_config_file", None)
    # A name that does not exist is refused as ASH_CONFIG's, not as config_file.
    if not ash_config or (refused is None and not os.path.exists(ash_config)):
        return label
    named = Path(ash_config)
    if named.resolve() == Path(config_file).resolve():
        return label
    if refused is None and isinstance(error, OSError) and error.filename:
        if Path(os.fsdecode(error.filename)).resolve() == named.resolve():
            refused = named
    if refused is None:
        return label
    return f"The file ASH_CONFIG names ('{describe_config_path(named)}')"


def _new_source_refusal(search_dir: Path, target: Path) -> str | None:
    """Why `target` must not be created in `search_dir`, or None.

    Configuration sources are never merged (config/config_sources.py): with a
    second one beside an existing source, one of the two files is not read,
    and which one depends on the precedence of their names. The older names
    win, so a new `.ashrc.yaml` next to `.ash/.ash.yaml` would be ignored.
    """
    try:
        discovery = discover_config_source(search_dir)
    except ASHConfigValidationError as e:
        return f"the existing configuration here could not be read ({e})"
    wanted = (search_dir / target).absolute()
    for source in [discovery.selected, *discovery.ignored]:
        if source is not None and source.path.absolute() != wanted:
            return (
                f"ASH already reads its configuration from {source.label}, and "
                f"configuration sources are never merged, so a new {target} here "
                f"would leave one of the two files unread. Edit {source.label}, or "
                "pass --config to write the new file somewhere else"
            )
    return None


def _ensure_output_gitignore(config_path: Path) -> None:
    """Keep scan output out of git beside a new project config file.

    A scan of the project writes to `<project>/.ash/ash_output`, which can
    hold source snippets. `config init` has always written `.ash/.gitignore`
    with the config it wrote into `.ash/`; a config under one of the names
    discovery reads at the project root gets the same file.
    """
    if config_path.parent.name == ".ash":
        ash_dir = config_path.parent
    elif config_path.name in ASH_RC_FILE_NAMES + ASH_CONFIG_FILE_NAMES:
        ash_dir = config_path.parent / ".ash"
    else:
        return
    gitignore = ash_dir / ".gitignore"
    if gitignore.exists():
        return
    ash_dir.mkdir(parents=True, exist_ok=True)
    gitignore.write_text("# ASH default output directory (and variants)\nash_output*\n")


# The config-file option every `ash config` subcommand that reads a config takes,
# with the same name, short flag and environment variable as `ash scan --config`.
_READ_CONFIG_HELP = (
    "The path to the configuration file. By default, the config a scan of the "
    f"current directory would use: {ASH_CONFIG_SOURCES_DESCRIPTION}."
)
_POSITIONAL_CONFIG_HELP = (
    "The configuration file, as a positional argument. Same as --config, which "
    "is preferred; when both are given they must name the same file."
)


def _named_config(
    ctx: typer.Context, positional: str | None, option: str | None
) -> str | None:
    """The config file a command was pointed at, or None to discover one.

    `get`, `update` and `validate-plugin-dependencies` took the path as a
    positional argument before they had --config, so both are accepted. A path
    on the command line wins over ASH_CONFIG, as `ash scan --config` does;
    two different paths on the command line are a usage error.
    """
    if positional is None:
        return option
    if option is not None:
        # Compared by name: typer builds the context from its own copy of
        # click, whose ParameterSource is not click's.
        source = getattr(ctx.get_parameter_source("config"), "name", "")
        from_command_line = source == "COMMANDLINE"
        if from_command_line and Path(positional).resolve() != Path(option).resolve():
            # The paths as given, not by repr: the usage error's printer shows
            # them once, on one line.
            raise PathRefused(
                f"names two config files, {positional} and {option}; pass one",
                param_hint="'--config'",
            )
    return positional


def _describe_load_error(error: Exception, config_path: Path) -> str:
    """Why ``config_path`` did not load, as a check prints it.

    pydantic's own text quotes every input (``input_value=...``) and links to
    its documentation; describe_validation_error names each field instead.
    AshConfig.from_file raises ASHConfigValidationError naming the file, which
    the caller's message names already, so only the fields of the
    ValidationError it keeps are given, redacted with the values the file's
    chain reads from the environment, read again here. The callers refuse such
    a file before loading it (_rewrite_refusal), but this does not depend on
    that; when the chain cannot be read again, the error's own message, which
    is redacted, is given. A parser's refusal is given as unparsed_config_reason
    gives it: the parser's own words can quote the file.
    """
    if is_config_parse_error(error):
        return unparsed_config_reason(config_path, error)
    validation_error = getattr(error, "validation_error", None)
    if isinstance(error, ValidationError):
        validation_error = error
    if not isinstance(validation_error, ValidationError):
        return str(error)
    try:
        values = resolve_config_document(Path(config_path)).environment_values
    except (yaml.YAMLError, OSError, ValueError):
        if isinstance(error, ValidationError):
            # pydantic's own text quotes every input; never print it.
            return describe_validation_error(error)
        return str(error)
    return describe_validation_error(validation_error, values)


def _print_issue(issue: Any, color: str, config_path: Path) -> None:
    """Print a lint issue as ``ash config lint`` does, its text shown once.

    An issue can quote the file's own text (an ignore path, an expiration) or
    the caller's path, and a newline in it would start a line of the file's
    choosing, so its whole line is shown as one line, and the console prints
    that as it is. A parse refusal is one line too (unparsed_config_reason):
    the parser's own message, which spanned lines, is not printed.
    """
    secho(shown_on_one_line(f"  {issue}"), fg=color)


def _print_source_chain(chain: List[Path], environment_paths: Collection[Path]) -> None:
    """Print the files an extending config is built from, lowest precedence first.

    `chain` is the one the check resolved (ConfigCheck.chain), not resolved
    again here: resolving reads every file once more and logs each `!ENV`
    warning a second time. A base an entry names through an environment
    reference, and every base below it, is `<value>` by its place
    (`environment_paths`, ConfigCheck.environment_paths), as the check's
    messages name it.
    """
    if len(chain) < 2:
        return
    secho("Resolved source chain (lowest precedence first):", fg=typer.colors.BLUE)
    for i, path in enumerate(chain, 1):
        shown = (
            ENVIRONMENT_VALUE_SHOWN
            if Path(path) in environment_paths
            else describe_config_path(path)
        )
        secho(shown_on_one_line(f"  {i}. {shown}"), fg=typer.colors.BLUE)


# Why `init`, `wizard` and `update` do not write a `.toml` file: they write
# YAML, which the TOML reader then refuses, and for pyproject.toml the file's
# other content would be lost.
_TOML_REFUSAL = "it is a TOML file, and this command writes YAML; edit it by hand"


def _rewrite_refusal(config_path: Path) -> str | None:
    """Why `config_path` must not be rewritten from a resolved config, or None.

    `update` and `wizard` write the whole resolved config back. For a TOML
    source that would replace the file's other content, for a file that uses
    `extends` or `patch` it would copy every base's settings into the child and
    drop the directives, so later edits to a base would no longer apply, and for
    a file with environment references (`${VAR}` or `!ENV`) it would write the
    values they resolve to.
    """
    if is_toml_file(config_path):
        return _TOML_REFUSAL
    # Before the safe_load below, which cannot construct an !ENV tag.
    if uses_env_references(config_path):
        return (
            "it reads values from the environment through environment references "
            "(${VAR} or !ENV), and rewriting it would replace each reference with "
            "the value it has now; edit it by hand"
        )
    try:
        # As a scan reads it, so a FIFO at the name is refused, not waited on. A
        # file that does not load is refused when the command loads it.
        raw = load_config_yaml(read_config_bytes(config_path).decode("utf-8"))
    except (OSError, ValueError, yaml.YAMLError, ASHConfigValidationError):
        # UnicodeDecodeError and a constructor's ValueError (!!int) are
        # ValueErrors. The load below reports the file it cannot read or parse.
        return None
    if isinstance(raw, dict) and (EXTENDS_KEY in raw or PATCH_KEY in raw):
        return (
            f"it uses '{EXTENDS_KEY}' or '{PATCH_KEY}', which rewriting would "
            "flatten into a copy of its bases; edit it by hand"
        )
    return None


@config_app.command()
def init(
    config: Annotated[
        str | None,
        typer.Option(
            "--config",
            "-c",
            help=f"Where to write the new config file. By default {ASH_DEFAULT_CONFIG_FILE_NAME} in the current directory, a name a scan of that directory reads. Discovery reads these names: {ASH_CONFIG_SOURCES_DESCRIPTION}. Can also be set with the ASH_CONFIG environment variable.",
            envvar="ASH_CONFIG",
        ),
    ] = None,
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
    """Create a configuration file with every setting at its default.

    Without --config, writes .ashrc.yaml in the current directory, and refuses
    when the directory already has a config source (.ash/.ash.yaml, an ashrc
    file, or the tool.ash table of pyproject.toml), since sources are never
    merged.
    """
    get_logger(
        level=(logging.DEBUG if debug else 15 if verbose else logging.INFO),
        show_progress=False,
        use_color=color,
    )
    if config is None:
        config_path = Path(ASH_DEFAULT_CONFIG_FILE_NAME)
        refusal = _new_source_refusal(Path.cwd(), config_path)
        if refusal:
            secho(
                shown_on_one_line(f"Not creating {config_path}: {refusal}."),
                fg=typer.colors.RED,
            )
            raise typer.Exit(1)
    else:
        config_path = Path(config)
    if is_toml_file(config_path):
        # Before the --force check: `init --config pyproject.toml --force` would
        # otherwise replace the project's pyproject.toml with YAML.
        secho(
            shown_on_one_line(f"Not writing {config_path}: {_TOML_REFUSAL}."),
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    # Before the --force check too: --force opens the path for writing.
    _refuse_unless_a_file(config_path)
    if config_path.absolute().exists() and not force:
        secho(
            shown_on_one_line(
                f"Config file already exists at {config_path.absolute()}. "
                "Include --force to overwrite."
            ),
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    config_path.parent.mkdir(exist_ok=True, parents=True)
    _ensure_output_gitignore(config_path)
    secho(shown_on_one_line(f"Saving ASH config to path: {config_path.absolute()}"))
    project_name = config_path.absolute().parent.name
    if project_name == ".ash":
        project_name = config_path.absolute().parent.parent.name
    ash_config = AshConfig(
        project_name=project_name,
    )
    config_path.write_text(
        render_config_file(config_path, ash_config, [SCHEMA_COMMENT]),
        encoding="utf-8",
    )


@config_app.command()
def get(
    ctx: typer.Context,
    config_path: Annotated[
        str | None,
        typer.Argument(help=_POSITIONAL_CONFIG_HELP),
    ] = None,
    config: Annotated[
        str | None,
        typer.Option("--config", "-c", help=_READ_CONFIG_HELP, envvar="ASH_CONFIG"),
    ] = None,
    config_overrides: Annotated[
        List[str],
        typer.Option(
            "--config-overrides",
            help="Configuration overrides specified as key-value pairs (e.g., 'global_settings.severity_threshold=LOW')",
        ),
    ] = [],
    source_dir: Annotated[
        str | None,
        typer.Option("--source-dir", help=_SOURCE_DIR_HELP, envvar="ASH_SOURCE_DIR"),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose/--no-verbose", "-v", help="Enable verbose logging"),
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug/--no-debug", "-d", help="Enable debug logging")
    ] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
):
    """Print the resolved configuration: the file's settings over the defaults.

    Without --config, prints the config a scan of the current directory would
    use, or the defaults when there is none. Exit codes: 0 printed, 3 the named
    file does not exist, cannot be read or is not a valid configuration.
    """
    get_logger(
        level=(logging.DEBUG if debug else 15 if verbose else logging.INFO),
        show_progress=False,
        use_color=color,
    )
    if config_path is not None and not config_path.strip():
        # A blank path argument names no file; discovering one in its place
        # would print a configuration the caller did not name. (An empty
        # --config or ASH_CONFIG is unset, as click treats it.)
        secho(
            "❌ Invalid configuration: the config file path is empty. Name a "
            "config file, or omit the path to use the one found in the directory.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(INVALID_CONFIG_EXIT_CODE)
    config_path = _named_config(ctx, config_path, config)
    if config_path is not None and not Path(config_path).exists():
        _refuse_missing_config(config_path)
    # The file this command is about: the one named, or the one resolve_config
    # would discover. When there is one, it is loaded with fallback_to_default
    # off, so a file that does not parse is refused (the shared refusal,
    # unparsed_config_reason, with nothing the parser said), which this command
    # reports in its own words (_print_invalid_config) rather than printing the
    # defaults as though they were that file's contents.
    scan_root = _source_dir(source_dir)
    config_file = _config_path_or_discovered(config_path, scan_root)
    try:
        # Not `config`: that is the --config option, which _named_config reads
        # by that parameter name.
        resolved = resolve_config(
            config_file,
            source_dir=scan_root,
            config_overrides=config_overrides,
            fallback_to_default=config_file is None,
        )
        if resolved is not None:
            # With ASH_PLUGIN_MODULES: it is a scan input (the scan option's
            # envvar), so a resolved configuration this command prints as
            # usable is one a scan of the same directory accepts.
            from automated_security_helper.config.plugin_module_trust import (
                environment_plugin_modules,
            )

            refuse_plugin_modules_a_scan_refuses(resolved, environment_plugin_modules())
    except (ASHConfigValidationError, yaml.YAMLError, ValueError, OSError) as e:
        # Exit 3 for an invalid configuration, the CLI's documented code for one.
        # A file that does not parse is the most invalid kind.
        # (json.JSONDecodeError and UnicodeDecodeError are both ValueErrors.)
        _print_invalid_config(config_file, scan_root, list(config_overrides), e)
        raise typer.Exit(INVALID_CONFIG_EXIT_CODE)
    from automated_security_helper.config.environment_record import (
        record_environment_references,
    )

    print(
        Syntax(
            code=yaml.dump(
                # Each value the config's files read from the environment as the
                # file wrote it, as a scan's record of its config holds it: the
                # displayed view, which leaves out a read an extends overlay
                # wrote a literal over (that place's value is the overlay's).
                record_environment_references(
                    resolved.model_dump(
                        mode="json",
                        by_alias=True,
                        exclude_defaults=False,
                        exclude_none=False,
                    ),
                    resolved._displayed_environment_references,
                    # Typed, so the dumper writes a reference plain (it must
                    # reload as a reference) while a string that only looks
                    # like one is quoted back, as every config writer does.
                    mark=_as_reference,
                ),
                Dumper=_AsWrittenYamlDumper,
                default_flow_style=False,
                sort_keys=False,
            ),
            lexer="yaml",
            theme="lightbulb",
            background_color=None,
        )
    )


def _reference_shaped_text(text: str) -> bool:
    """Whether ``text``, stripped as the model strips every string
    (str_strip_whitespace), is a ``${VAR...}`` reference
    (ENV_REFERENCE_PATTERN) or an explicit ``!ENV`` tag."""
    from automated_security_helper.config.ash_config import ENV_REFERENCE_PATTERN

    stripped = text.strip()
    return bool(ENV_REFERENCE_PATTERN.match(stripped)) or stripped.startswith("!ENV")


def _reference_shaped(node: Any) -> bool:
    """Whether *node*, a parsed ``--set`` value, holds a string the loader
    would read from the environment, at any depth.

    Iterative, with its own stack: a recursing walk crashed on a value nested
    a few hundred levels deep (two frames per level), with a traceback and
    exit 1 where a refusal naming the key belongs."""
    pending = [node]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            if _reference_shaped_text(current):
                return True
        elif isinstance(current, dict):
            for key, item in current.items():
                pending.append(key)
                pending.append(item)
        elif isinstance(current, (list, tuple)):
            pending.extend(current)
    return False


def _refuse_a_reference_shaped_value(key_path: str, value: str) -> None:
    """Refuse a ``--set`` whose value is shaped like an environment reference.

    ``update`` refuses to rewrite a file that reads the environment, so it
    must not create one: written plain, the value becomes a reference the next
    load resolves; written quoted, the typed reference silently becomes
    literal text. One rule, fail-closed. Only the key is named, never the
    value. The value is parsed as the apply parses it, so a reference inside
    a list or mapping value is refused the same way.
    """
    from automated_security_helper.config.resolve_config import _parse_config_value

    if any(_reference_shaped_text(part) for part in key_path.split(".")):
        # A reference-shaped key segment would be written as a quoted literal
        # key the load tolerates and ignores. The segments are the caller's
        # own typed text, which the load never resolved, so the usual
        # keys-only message may name the path.
        raise ASHConfigValidationError(
            f"--set '{key_path.removesuffix('+')}' gives a key segment shaped "
            "like an environment reference (${VAR} or !ENV), which this "
            "command does not write: edit the config file to add a reference, "
            "so the load reads it as one"
        )
    try:
        parsed = _parse_config_value(value)
    except RecursionError:
        # A value nested too deep to parse: the apply refuses it with its own
        # one-line message, so this check has nothing to add.
        return
    if _reference_shaped(parsed):
        raise ASHConfigValidationError(
            f"--set '{key_path.removesuffix('+')}' gives a value shaped like "
            "an environment reference (${VAR} or !ENV), which this command "
            "does not write: edit the config file to add a reference, so the "
            "load reads it as one"
        )


def _refuse_an_unknown_top_level_key(key_path: str) -> None:
    """Refuse a ``--set`` whose first key is not one of the configuration's own.

    A file's top level drops a key the configuration does not have, so applying
    one would change nothing and still report the file updated, hiding a typo.
    A key matches as a config file may spell it: the field name, or with '-' for
    '_' (``_apply_config_override`` follows either to the dumped section). Only the
    key is named, never the value.
    """
    first = key_path.removesuffix("+").split(".", 1)[0]
    known = [
        spelling
        for name, field in AshConfig.model_fields.items()
        for spelling in (name, name.replace("_", "-"), field.alias)
        if spelling
    ]
    if first in known:
        return
    raise ASHConfigValidationError(
        f"Invalid config override: '{key_path}'. '{first}' is not a top-level "
        f"configuration key: the keys are {', '.join(AshConfig.model_fields)}."
    )


@config_app.command()
def update(
    ctx: typer.Context,
    config_path: Annotated[
        str | None,
        typer.Argument(help=_POSITIONAL_CONFIG_HELP),
    ] = None,
    config: Annotated[
        str | None,
        typer.Option("--config", "-c", help=_READ_CONFIG_HELP, envvar="ASH_CONFIG"),
    ] = None,
    modifications: Annotated[
        List[str],
        typer.Option(
            "--set",
            help="Configuration modifications specified as key-value pairs (e.g., 'global_settings.severity_threshold=LOW'). Supports lists with [item1,item2], append mode with key+=[value], and JSON syntax.",
        ),
    ] = [],
    verbose: Annotated[
        bool,
        typer.Option("--verbose/--no-verbose", "-v", help="Enable verbose logging"),
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug/--no-debug", "-d", help="Enable debug logging")
    ] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
    dry_run: Annotated[
        bool, typer.Option(help="Show changes without writing to file")
    ] = False,
):
    """
    Update an existing configuration file with the specified modifications.

    This command applies changes to an ASH configuration file using the same syntax as --config-overrides.

    Nothing is written, and the command exits 3, when the file is not a valid
    configuration or a --set cannot be applied. A file that uses extends or
    patch, or reads the environment (${VAR} or !ENV references), or a TOML
    file, is refused with exit 1: rewriting it would lose what those express.
    """
    logger = get_logger(
        level=(logging.DEBUG if debug else 15 if verbose else logging.INFO),
        show_progress=False,
        use_color=color,
    )
    config_path = _named_config(ctx, config_path, config)

    # Find the config file if not specified
    if config_path is None:
        try:
            found = find_config_file()
        except ASHConfigValidationError as e:
            # Exit 3, as a scan of the directory does.
            secho(
                shown_on_one_line(f"Error locating config file: {e}"),
                fg=typer.colors.RED,
            )
            raise typer.Exit(INVALID_CONFIG_EXIT_CODE)
        if found is not None:
            logger.info(
                shown_on_one_line(f"Using config file found at: {found.as_posix()}")
            )
            config_path = found.as_posix()

    # Check if config file exists
    if config_path is None:
        secho(
            "Config file not found. Use 'ash config init' to create one.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    if not Path(config_path).exists():
        _refuse_missing_config(config_path)

    # Load the existing config
    config_path = Path(config_path)
    _refuse_unless_a_file(config_path)
    refusal = _rewrite_refusal(config_path)
    if refusal:
        secho(
            shown_on_one_line(f"Cannot update {config_path}: {refusal}"),
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    try:
        config = AshConfig.from_file(config_path=config_path)
    except (ValidationError, ASHConfigValidationError, yaml.YAMLError, ValueError) as e:
        # ValueError covers json.JSONDecodeError and UnicodeDecodeError.
        # The description alone: it says what is wrong with the file, so an
        # "it is not a valid configuration" frame reads double. Its own
        # trailing period folds into the sentence's.
        reason = _describe_load_error(e, config_path).rstrip(".")
        # A parse refusal names the file itself (unparsed_config_reason), so
        # the frame leaves its own name out, as the MCP tools' frame does.
        frame = (
            "Not updating"
            if reason.startswith(describe_config_path(config_path))
            else f"Not updating {config_path}"
        )
        secho(
            shown_on_one_line(
                f"{frame}: {reason}. 'ash config validate' lists the problems."
            ),
            fg=typer.colors.RED,
        )
        raise typer.Exit(INVALID_CONFIG_EXIT_CODE)
    except OSError as e:
        # error_text gives the file's name as given, not as the repr the
        # error's own text quotes it with, so the sink shows it once.
        secho(
            shown_on_one_line(
                f"Not updating {config_path}: it cannot be read ({error_text(e)})."
            ),
            fg=typer.colors.RED,
        )
        raise typer.Exit(INVALID_CONFIG_EXIT_CODE)

    # Apply modifications
    if not modifications:
        secho(
            "No modifications specified. Use --set to specify changes.",
            fg=typer.colors.YELLOW,
        )
        raise typer.Exit(0)

    # The same function, and so the same parsing and refusals, as a scan's
    # --config-overrides. A --set that does not parse, or that leaves a config
    # the model refuses, changes nothing: writing the others would leave a file
    # the user did not ask for and still exit 0. A --set of a top-level key the
    # model does not declare is refused as well, unlike a scan's override: the
    # model ignores the key, so the --set would change nothing. A --set that does
    # not parse is left to apply_config_overrides, which refuses it.
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    try:
        for mod in modifications:
            key_path, separator, value = mod.partition("=")
            if separator and key_path.strip():
                _refuse_an_unknown_top_level_key(key_path)
                _refuse_a_reference_shaped_value(key_path, value)
        updated_config = apply_config_overrides(config, list(modifications))
    except ASHConfigValidationError as e:
        secho(
            shown_on_one_line(f"Not updating {config_path}: {e}"),
            fg=typer.colors.RED,
        )
        raise typer.Exit(INVALID_CONFIG_EXIT_CODE)
    for mod in modifications:
        # The key only: the value can be a credential. `key+=` appends.
        key_path = mod.partition("=")[0]
        if key_path.endswith("+"):
            logger.info(f"Appended to {key_path[:-1]}")
        else:
            logger.info(f"Applied a modification to {key_path}")

    # Preserve the schema reference if it exists in the original file
    comments = [SCHEMA_COMMENT]
    # Read as a scan reads it, so a FIFO swapped in at the name is refused rather
    # than waited on; the file loaded above, so a failure here only drops the line.
    try:
        lines = read_config_bytes(config_path).decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError, ASHConfigValidationError):
        lines = []
    first_line = lines[0].strip() if lines else ""
    if first_line.startswith("#") and "schema" in first_line.lower():
        comments = [first_line]
    updated_text = render_config_file(
        config_path, updated_config, comments, keep_from=read_config_file(config_path)
    )

    # Show the updated config
    print(
        Syntax(
            code=updated_text,
            lexer="json" if is_json_file(config_path) else "yaml",
            theme="lightbulb",
            background_color=None,
        )
    )

    # Write the updated config if not in dry run mode
    if not dry_run:
        try:
            config_path.write_text(updated_text, encoding="utf-8")
            secho(
                shown_on_one_line(
                    f"Successfully updated config file: {config_path.absolute()}"
                ),
                fg=typer.colors.GREEN,
            )
        except Exception as e:
            secho(
                shown_on_one_line(f"Error writing config file: {error_text(e)}"),
                fg=typer.colors.RED,
            )
            raise typer.Exit(1)
    else:
        secho(
            "Dry run mode: No changes were written to the file", fg=typer.colors.YELLOW
        )


@config_app.command()
def validate_plugin_dependencies(
    ctx: typer.Context,
    config_path: Annotated[
        str | None,
        typer.Argument(help=_POSITIONAL_CONFIG_HELP),
    ] = None,
    config: Annotated[
        str | None,
        typer.Option("--config", "-c", help=_READ_CONFIG_HELP, envvar="ASH_CONFIG"),
    ] = None,
    config_overrides: Annotated[
        List[str],
        typer.Option(
            "--config-overrides",
            help="Configuration overrides specified as key-value pairs (e.g., 'global_settings.severity_threshold=LOW')",
        ),
    ] = [],
    source_dir: Annotated[
        str | None,
        typer.Option("--source-dir", help=_SOURCE_DIR_HELP, envvar="ASH_SOURCE_DIR"),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose/--no-verbose", "-v", help="Enable verbose logging"),
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug/--no-debug", "-d", help="Enable debug logging")
    ] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
):
    """Check that the configuration resolves and names a project.

    Exit codes: 0 it does, 1 no config was found or the configuration names no
    project (an empty project_name), 3 the named file does not exist, cannot be
    read or is not a valid configuration.
    """
    get_logger(
        level=(logging.DEBUG if debug else 15 if verbose else logging.INFO),
        show_progress=False,
        use_color=color,
    )
    config_path = _named_config(ctx, config_path, config)
    if config_path is not None and not Path(config_path).exists():
        _refuse_missing_config(config_path)
    label = (
        f"Config file '{Path(config_path).absolute().as_posix()}'"
        if config_path
        else "The configuration"
    )
    scan_root = _source_dir(source_dir)
    config_file = _config_path_or_discovered(config_path, scan_root)
    if config_file is None:
        _report_no_config_found(scan_root)
        raise typer.Exit(1)
    try:
        # Not `config`: that is the --config option (see get).
        resolved = resolve_config(
            config_path=config_file,
            source_dir=scan_root,
            fallback_to_default=False,
            config_overrides=config_overrides,
        )
        if resolved is not None:
            from automated_security_helper.config.plugin_module_trust import (
                environment_plugin_modules,
            )

            # A scan of the same inputs reads the variable, so this check does.
            refuse_plugin_modules_a_scan_refuses(resolved, environment_plugin_modules())
    except (ASHConfigValidationError, yaml.YAMLError, ValueError) as e:
        # ValueError covers json.JSONDecodeError and UnicodeDecodeError. The
        # label names the caller's path: one line, whatever it holds.
        secho(
            shown_on_one_line(
                f"{_refused_file_label(label, config_file, e)} is not valid."
            ),
            fg=typer.colors.RED,
        )
        _print_invalid_config(config_file, scan_root, list(config_overrides), e)
        raise typer.Exit(INVALID_CONFIG_EXIT_CODE)
    except OSError as e:
        # error_text gives the file's name as given, not as the repr the error's
        # own text quotes it with, so the line shows it once.
        secho(
            shown_on_one_line(
                f"{_refused_file_label(label, config_file, e)} could not be read: "
                f"{error_text(e)}"
            ),
            fg=typer.colors.RED,
        )
        raise typer.Exit(INVALID_CONFIG_EXIT_CODE)

    if not resolved.project_name:
        # A scan and `ash config validate` accept an empty project_name, so this
        # is not an invalid configuration (exit 3): the command's own check fails.
        secho(
            shown_on_one_line(
                f"{label} does not name a project: project_name is empty on the "
                "resolved config."
            ),
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    # Named by its path: the project name can be a value read from the
    # environment.
    secho(
        shown_on_one_line(
            f"Config file '{Path(config_file).absolute().as_posix()}' is valid"
        ),
        fg=typer.colors.GREEN,
    )
    return True


@config_app.command()
def lint(
    config: Annotated[
        str | None,
        typer.Option(
            "--config",
            "-c",
            help=_READ_CONFIG_HELP,
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
            help="Auto-fix fixable issues (internal fields, missing line_end, expired suppressions, multi-line suppression reasons). A TOML file, and a file that reads the environment (${VAR} or !ENV), are not rewritten: fix those by hand",
        ),
    ] = False,
    fix_unused: Annotated[
        bool,
        typer.Option(
            "--fix-unused",
            help="Comment out unused suppressions based on the last scan's unused suppressions report. A TOML file, and a JSON file (which holds no comments), are not rewritten: remove those by hand",
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
    source_dir: Annotated[
        str | None,
        typer.Option("--source-dir", help=_SOURCE_DIR_HELP, envvar="ASH_SOURCE_DIR"),
    ] = None,
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

    Use --fix-unused to comment out suppressions that no longer match any
    finding (based on the unused suppressions report from the last scan).

    Use --non-interactive (or --yes/-y) to skip confirmation prompts. This is
    useful for pre-commit hooks or CI/CD pipelines.

    Exit codes: 0 a scan accepts the config (whatever else is reported is a
    warning); 1 no config file was found, or --fix or --fix-unused refused to
    rewrite it; 3 a scan would refuse the config, as 'ash config validate'
    reports it, the file does not parse, or the named file does not exist or
    cannot be read. The output marks each issue that makes a scan refuse the
    config with "blocks the scan".

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

    colors = {
        LintSeverity.ERROR: typer.colors.RED,
        LintSeverity.WARNING: typer.colors.YELLOW,
        LintSeverity.INFO: typer.colors.CYAN,
    }

    # Setup logging
    get_logger(
        name="ash.cli.config.lint",
        level=logging.DEBUG
        if debug
        else (logging.INFO if verbose else logging.WARNING),
        show_progress=False,
        use_color=color,
    )

    scan_root = _source_dir(source_dir)
    config_path = _config_path_or_discovered(config, scan_root)
    output_dir_path = Path(output_dir) if output_dir else None

    if config_path is None:
        _report_no_config_found(scan_root)
        raise typer.Exit(1)
    if not config_path.exists():
        _refuse_missing_config(config_path)

    # Both refusals name the caller's path: one line, whatever it holds.
    if (fix or fix_unused) and is_toml_file(config_path):
        secho(
            shown_on_one_line(
                "❌ --fix rewrites YAML and JSON config files, and --fix-unused "
                f"YAML ones only; edit {describe_config_path(config_path)} by hand."
            ),
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    if fix_unused and is_json_file(config_path):
        secho(
            shown_on_one_line(
                "❌ --fix-unused comments suppressions out, and JSON has no "
                f"comments; remove them from {describe_config_path(config_path)} "
                "by hand."
            ),
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    # The path is the caller's text, so the header is one line whatever it holds.
    secho(
        shown_on_one_line(
            f"Linting configuration file: {describe_config_path(config_path)}"
        ),
        fg=typer.colors.BLUE,
    )

    # Run lint checks
    lint_result = ConfigLinter.lint(
        config_path=config_path,
        output_dir=output_dir_path,
        check_unused=fix_unused,  # Only check unused when explicitly requested
        source_dir=scan_root,
    )
    _print_source_chain(lint_result.chain, lint_result.environment_paths)

    # Display issues
    if not lint_result.issues:
        secho("✅ Configuration is clean! No issues found.", fg=typer.colors.GREEN)
        return

    # Print all issues
    secho(
        f"\nFound {len(lint_result.issues)} issue(s):",
        fg=typer.colors.YELLOW,
    )
    for issue in lint_result.issues:
        _print_issue(issue, colors[issue.severity], config_path)

    echo("")

    # Summary
    if lint_result.error_count:
        secho(f"  Errors: {lint_result.error_count}", fg=typer.colors.RED)
    if lint_result.warning_count:
        secho(f"  Warnings: {lint_result.warning_count}", fg=typer.colors.YELLOW)
    if lint_result.info_count:
        secho(f"  Info: {lint_result.info_count}", fg=typer.colors.CYAN)

    fixable_count = len(lint_result.fixable_issues)
    if fixable_count and not fix and not fix_unused:
        secho(
            f"\n💡 {fixable_count} issue(s) can be auto-fixed. Run with --fix to apply fixes.",
            fg=typer.colors.YELLOW,
        )

    # Apply fixes if requested. Declining a prompt stops the fixing and exits 0,
    # unless the file is one a scan refuses.
    declined = False
    try:
        if fix:
            _apply_fixes(config_path, lint_result, non_interactive, color)
        if fix_unused:
            _apply_unused_fixes(config_path, output_dir_path, non_interactive, color)
    except typer.Exit as stop:
        if stop.exit_code != 0:
            raise
        declined = True

    # The exit code describes the file as it is now, so after a fix it comes
    # from linting the fixed file: removing an internal `build` section, for
    # example, can make a config the scan refused valid again.
    remaining = lint_result
    if fix or fix_unused:
        remaining = ConfigLinter.lint(
            config_path=config_path, output_dir=output_dir_path, source_dir=scan_root
        )
        if remaining.issues and remaining.issues != lint_result.issues:
            secho("\nRemaining after the fixes:", fg=typer.colors.YELLOW)
            for issue in remaining.issues:
                _print_issue(issue, colors[issue.severity], config_path)

    if remaining.scan_ignores_file:
        secho(
            f"\n❌ {_ignored_file_verdict(remaining.file_could_not_be_read)} "
            f"(exit {INVALID_CONFIG_EXIT_CODE}).",
            fg=typer.colors.RED,
        )
        raise typer.Exit(INVALID_CONFIG_EXIT_CODE)
    if remaining.scan_refuses:
        secho(
            f"\n❌ A scan refuses this configuration (exit {INVALID_CONFIG_EXIT_CODE}) "
            "because of the issues marked [blocks the scan].",
            fg=typer.colors.RED,
        )
        raise typer.Exit(INVALID_CONFIG_EXIT_CODE)
    if declined:
        raise typer.Exit(0)
    if remaining.has_errors:
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
        secho(
            "No fixable issues found (excluding unused suppressions).",
            fg=typer.colors.GREEN,
        )
        return
    # Here, not before linting: a file with !ENV references and nothing to fix
    # passes `lint --fix`, as a pre-commit hook runs it.
    if uses_env_references(config_path):
        secho(
            f"❌ --fix rewrites the file from its parsed values, which would replace "
            f"each of the environment references (${{VAR}} or !ENV) in "
            f"{describe_config_path(config_path)} with its current value; make "
            "these fixes by hand.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    secho(f"\n🔧 Fixing {len(fixable)} issue(s):", fg=typer.colors.BLUE)
    for issue in fixable:
        # An issue that sets fixable=True without a fix_description would print an
        # empty bullet, which tells the user a change is coming but not which one.
        # The message always names the problem, so fall back to it.
        secho(f"  • {issue.fix_description or issue.message}", fg=typer.colors.CYAN)

    if not non_interactive:
        if not confirm("\nApply these fixes?"):
            secho("Aborted.", fg=typer.colors.YELLOW)
            raise typer.Exit(0)

    fixed_content, fixed_issues = ConfigLinter.fix(config_path, fixable)

    if fixed_issues:
        config_path.write_text(fixed_content, encoding="utf-8")
        secho(
            f"\n✅ Fixed {len(fixed_issues)} issue(s) in {config_path}",
            fg=typer.colors.GREEN,
        )
    else:
        secho("No issues were fixed.", fg=typer.colors.YELLOW)


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
        secho(
            "⚠️  No unused suppressions report found. Run a scan first to generate the report.",
            fg=typer.colors.YELLOW,
        )
        return

    report_path, report_timestamp, age_seconds = report_info

    # Warn if report is too old
    if age_seconds > ConfigLinter.MAX_REPORT_AGE_SECONDS:
        age_hours = age_seconds / 3600
        secho(
            f"\n⚠️  WARNING: The unused suppressions report is {age_hours:.1f} hours old "
            f"(generated at {report_timestamp.strftime('%Y-%m-%d %H:%M:%S')}).",
            fg=typer.colors.YELLOW,
        )
        secho(
            "   Results may not reflect the current state of your codebase.",
            fg=typer.colors.YELLOW,
        )
        secho(
            "   Consider running a fresh scan: ash scan",
            fg=typer.colors.YELLOW,
        )

        if not non_interactive:
            if not confirm(
                "\nProceed with commenting out unused suppressions based on this old report?"
            ):
                secho("Aborted.", fg=typer.colors.YELLOW)
                raise typer.Exit(0)

    # Perform the fix
    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(
        config_path, output_dir
    )

    if not fixed_issues:
        secho("✅ No unused suppressions to comment out.", fg=typer.colors.GREEN)
        return

    secho(
        f"\n💬 Commenting out {len(fixed_issues)} unused suppression(s):",
        fg=typer.colors.BLUE,
    )
    for issue in fixed_issues:
        secho(f"  • {issue.message}", fg=typer.colors.CYAN)

    if not non_interactive:
        if not confirm("\nComment out these unused suppressions?"):
            secho("Aborted.", fg=typer.colors.YELLOW)
            raise typer.Exit(0)

    # Bytes: fixed_content is the file's own text with its line endings (read as
    # bytes by fix_unused_suppressions), and text mode would turn the "\n" of a
    # CRLF file into "\r\n" a second time on Windows.
    config_path.write_bytes(fixed_content.encode("utf-8"))
    secho(
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
    console = ash_console(theme=rich_theme())
    table = Table(
        title=label, show_header=True, header_style=f"bold {COLORS['accent']}"
    )
    table.add_column("Name", style="white")
    table.add_column("Currently enabled", justify="center")
    for python_name, display_name in items:
        status = current_enabled.get(python_name, True)
        table.add_row(display_name, "[green]yes[/green]" if status else "[red]no[/red]")
    console.print(table)

    result = {}
    for python_name, display_name in items:
        default = current_enabled.get(python_name, True)
        answer = confirm(
            f"  Enable {display_name}?",
            default=default,
        )
        result[python_name] = answer
    return result


@config_app.command()
def wizard(
    config: Annotated[
        str | None,
        typer.Option(
            "--config",
            "-c",
            help=f"Path to read/write the configuration file. By default, the config a scan of the current directory would use, or a new {ASH_DEFAULT_CONFIG_FILE_NAME} when there is none.",
            envvar="ASH_CONFIG",
        ),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug", "-d", help="Enable debug logging")
    ] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
):
    """Interactive configuration wizard.

    Reads the existing config (the one a scan of the current directory would
    use, or --config), walks through scanner, reporter, offline-mode, and
    community-plugin settings interactively, then writes the result back.
    With no config yet, it creates .ashrc.yaml.
    """
    get_logger(
        level=(logging.DEBUG if debug else 15 if verbose else logging.INFO),
        show_progress=False,
        use_color=color,
    )
    console = ash_console(theme=rich_theme())
    if config is None:
        try:
            # Relative to the working directory, so the path is printed as the
            # user would type it.
            found = find_config_file(Path("."))
        except ASHConfigValidationError as e:
            secho(
                shown_on_one_line(
                    "Cannot run the wizard: the configuration here could not be "
                    f"read ({e})."
                ),
                fg=typer.colors.RED,
            )
            raise typer.Exit(INVALID_CONFIG_EXIT_CODE)
        config_path = found if found is not None else Path(ASH_DEFAULT_CONFIG_FILE_NAME)
    else:
        config_path = Path(config)
    _refuse_unless_a_file(config_path)

    # --- Load existing config or start from defaults ---
    # A new .toml file is refused too: the wizard would write YAML into it.
    refusal = (
        _rewrite_refusal(config_path)
        if config_path.exists() or is_toml_file(config_path)
        else None
    )
    if refusal:
        secho(
            shown_on_one_line(f"Cannot edit {config_path} with the wizard: {refusal}"),
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    if os.path.lexists(config_path) and not is_regular_file(config_path):
        # A link to nothing, a directory: not "no config yet", and writing the
        # answers would pass through the link to wherever it points. One line:
        # the path is the caller's text.
        secho(
            shown_on_one_line(
                f"Invalid configuration: {config_path} exists but is not a regular "
                "file, so the wizard will not write it."
            ),
            fg=typer.colors.RED,
        )
        raise typer.Exit(3)
    existing_data: Any = None
    if config_path.exists():
        console.print(
            Panel(
                # Shown: Text passes ESC and newline through, and the path is
                # the caller's, like the sibling prints in this function.
                Text(
                    shown_on_one_line(
                        f"Loading existing config from {config_path.absolute()}"
                    )
                ),
                title="ASH Config Wizard",
                border_style=COLORS["accent"],
            )
        )
        try:
            ash_config = AshConfig.from_file(config_path=config_path)
            existing_data = read_config_file(config_path)
        except (
            ValidationError,
            ASHConfigValidationError,
            yaml.YAMLError,
            ValueError,
        ) as exc:
            # Starting from the defaults and writing them over this file would
            # throw away every setting in it.
            secho(
                shown_on_one_line(
                    f"Cannot edit {config_path} with the wizard: it is not a valid "
                    f"configuration ({_describe_load_error(exc, config_path)}). Fix "
                    "it ('ash config validate' lists the problems) or move it "
                    "aside, then run the wizard again."
                ),
                fg=typer.colors.RED,
            )
            raise typer.Exit(INVALID_CONFIG_EXIT_CODE)
        except OSError as exc:
            # error_text gives the file's name as given, not as its repr.
            secho(
                shown_on_one_line(f"Cannot read {config_path}: {error_text(exc)}"),
                fg=typer.colors.RED,
            )
            raise typer.Exit(1)
    else:
        console.print(
            Panel(
                "No existing config found -- starting from defaults.",
                title="ASH Config Wizard",
                border_style=COLORS["accent"],
            )
        )
        ash_config = AshConfig()

    from automated_security_helper.config.environment_record import (
        record_environment_references,
    )

    # --- 1. Project name ---
    # Offered as the file wrote it: a name read from the environment is shown,
    # and kept, as its reference.
    project_name = prompt(
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
    enable_offline = confirm(
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
        # Each name escaped on its own: the file's names are text, not markup.
        listed = ", ".join(f"'{escape_markup(mod)}'" for mod in existing_modules)
        console.print(f"  Currently configured: [{listed}]")

    added_modules: List[str] = []
    kept_old_indices: List[int] = []
    for old_index, mod in enumerate(existing_modules):
        keep = confirm(f"  Keep module '{mod}'?", default=True)
        if keep:
            kept_old_indices.append(old_index)

    while True:
        new_mod = prompt(
            "  Add a plugin module (blank to finish)",
            default="",
            show_default=False,
        )
        if not new_mod.strip():
            break
        added_modules.append(new_mod.strip())

    # A dropped entry moves every entry after it, so the references move to
    # the kept entries' new indices. On this path the moved tuples are empty
    # today: the wizard refuses an environment-reading file before editing
    # it and loads with AshConfig.from_file, so the loaded config carries no
    # references, and the generated file is dumped from user_config_data
    # (config_writer.render_config_file), not written through
    # record_of_config. The one call reads the old list from the config,
    # assigns the new one and moves the references with the entries, keeping
    # the model's index bookkeeping right for anything that reads the
    # references off this config object. The typed additions carry no
    # references.
    from automated_security_helper.config.plugin_module_trust import (
        replace_plugin_module_list,
    )

    replace_plugin_module_list(ash_config, kept_old_indices, added_modules)

    # --- Write config ---
    config_path.parent.mkdir(exist_ok=True, parents=True)
    _ensure_output_gitignore(config_path)

    comments = [SCHEMA_COMMENT]
    if enable_offline:
        comments.append(
            "# Reminder: export ASH_OFFLINE=YES before running ASH for offline mode"
        )
    config_path.write_text(
        render_config_file(config_path, ash_config, comments, keep_from=existing_data),
        encoding="utf-8",
    )

    console.print(
        Panel(
            # Shown, like the loading panel above.
            Text(shown_on_one_line(f"Config written to {config_path.absolute()}")),
            title="Done",
            border_style=COLORS["success"],
        )
    )


@config_app.command()
def validate(
    config: Annotated[
        str | None,
        typer.Option(
            "--config",
            "-c",
            help=_READ_CONFIG_HELP,
            envvar="ASH_CONFIG",
        ),
    ] = None,
    config_overrides: Annotated[
        List[str],
        typer.Option(
            "--config-overrides",
            help="Configuration overrides specified as key-value pairs (e.g., 'global_settings.severity_threshold=LOW'), checked as a scan given the same --config-overrides would apply them.",
        ),
    ] = [],
    source_dir: Annotated[
        str | None,
        typer.Option("--source-dir", help=_SOURCE_DIR_HELP, envvar="ASH_SOURCE_DIR"),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug", "-d", help="Enable debug logging")
    ] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
):
    """Validate an ASH configuration file the way a scan loads it.

    The file is loaded as a scan loads it: parsed (with ${VAR} and !ENV
    references resolved), its extends chain followed, and checked against the
    AshConfig model the JSON schema is generated from, with strict types. A
    config a scan would refuse is reported with every field it refuses, and the
    command exits 3, the exit code a scan gives for an invalid configuration.

    It also warns about things a scan accepts but that are probably mistakes:
    internal-only fields in scanners/reporters/converters, unknown or internal
    top-level sections, duplicate top-level keys, a missing project_name, and
    directory paths without a '**' glob. Warnings do not change the exit code;
    'ash config lint' reports the same checks and can fix some of them, with
    one exception: lint judges the file as written, so it reads neither
    --config-overrides nor ASH_PLUGIN_MODULES, and an input this command
    refuses for an environment-named module can still lint clean.

    Exit codes: 0 valid (warnings may be printed), 1 no config file found and
    none of the scan's other inputs given (--config-overrides,
    ASH_PLUGIN_MODULES), 3 invalid, or the named config file does not exist
    or cannot be read. A file that does not parse is invalid too, and a scan
    refuses it as well. With --config-overrides or ASH_PLUGIN_MODULES and no
    config file, the default configuration with those scan inputs applied is
    validated -- the config a scan of the directory would run with, and the
    one `ash config get` prints or refuses for the same input, exiting 3 when
    the environment names a module the scan's plugin loader refuses.

    Examples:
        # Validate the config a scan of the current directory would use
        ash config validate

        # Validate specific config file
        ash config validate --config path/to/config.yaml

        # Validate with the overrides a scan will be given
        ash config validate --config-overrides 'fail_on_findings=false'
    """
    # Setup logging
    logger = get_logger(
        name="ash.cli.config.validate",
        level=logging.DEBUG
        if debug
        else (logging.INFO if verbose else logging.WARNING),
        show_progress=False,
        use_color=color,
    )

    try:
        from automated_security_helper.config.config_validator import ConfigValidator

        scan_root = _source_dir(source_dir)
        config_path = _config_path_or_discovered(config, scan_root)

        # ASH_PLUGIN_MODULES is a scan input (the scan option's envvar), so
        # "A scan accepts it" has to be true of the scan these inputs start.
        from automated_security_helper.config.plugin_module_trust import (
            environment_plugin_modules,
        )

        environment_modules = environment_plugin_modules()

        if config_path is None:
            if not config_overrides and not environment_modules:
                _report_no_config_found(scan_root)
                raise typer.Exit(1)
            # Explicit --config-overrides, or ASH_PLUGIN_MODULES, with no
            # config file: a scan of this directory runs on the defaults with
            # those inputs applied, and `config get` refuses this same input,
            # so answering "no config file found" without checking them judged
            # a different question than the one asked. The effective config is
            # built through the same resolution path get uses, and judged as
            # get judges it.
            secho(
                shown_on_one_line(
                    f"No config file in {scan_root}: validating the default "
                    "configuration with the scan's own inputs applied "
                    "(--config-overrides, ASH_PLUGIN_MODULES), as a scan "
                    "would use them."
                ),
                fg=typer.colors.BLUE,
            )
            try:
                resolved = resolve_config(
                    None,
                    source_dir=scan_root,
                    config_overrides=list(config_overrides),
                    fallback_to_default=True,
                )
                if resolved is not None:
                    refuse_plugin_modules_a_scan_refuses(resolved, environment_modules)
            except (
                ASHConfigValidationError,
                yaml.YAMLError,
                ValueError,
                OSError,
            ) as e:
                _print_invalid_config(None, scan_root, list(config_overrides), e)
                raise typer.Exit(INVALID_CONFIG_EXIT_CODE)
            secho(
                "\n✅ Configuration is valid! A scan accepts it.",
                fg=typer.colors.GREEN,
            )
            return
        if not config_path.exists():
            _refuse_missing_config(config_path)

        # The path is the caller's text, so the header is one line whatever it
        # holds.
        secho(
            shown_on_one_line(
                f"Validating configuration file: {describe_config_path(config_path)}"
            ),
            fg=typer.colors.BLUE,
        )

        check = ConfigValidator.check_config_file(
            config_path,
            source_dir=scan_root,
            config_overrides=list(config_overrides or []),
            additional_plugin_modules=environment_modules,
        )
        _print_source_chain(check.chain, check.environment_paths)

        if check.ignored_by_scan:
            # The error alone: it carries its category prefix and reason, so a
            # "The file does not parse:" header stacked a third layer, and a
            # read failure's error already says the file could not be read. The
            # parser's lines, each on one line: a newline in the file's name,
            # which the parser quotes, starts none.
            for line in own_lines(f"\n❌ {check.errors[0]}", [config_path]):
                secho(shown_on_one_line(line), fg=typer.colors.RED)
            secho(
                f"\n❌ Configuration is invalid. "
                f"{_ignored_file_verdict(check.could_not_read)}. Exit "
                f"{INVALID_CONFIG_EXIT_CODE}.",
                fg=typer.colors.RED,
            )
            raise typer.Exit(INVALID_CONFIG_EXIT_CODE)

        if check.errors:
            secho(
                f"\n❌ {len(check.errors)} error(s); a scan refuses the "
                "configuration because of these:",
                fg=typer.colors.RED,
            )
            # One line each: an error can name the caller's path. A parser's
            # message, which keeps its own lines, is printed above.
            for i, error in enumerate(check.errors, 1):
                secho(shown_on_one_line(f"  {i}. {error}"), fg=typer.colors.RED)

        if check.warnings:
            secho(
                f"\n⚠️  {len(check.warnings)} warning(s); a scan accepts these, "
                "but check them:",
                fg=typer.colors.YELLOW,
            )
            # One line each, as lint's path issues are (_print_issue): a warning
            # quotes the file's text, such as an ignore path.
            for i, warning in enumerate(check.warnings, 1):
                secho(shown_on_one_line(f"  {i}. {warning}"), fg=typer.colors.YELLOW)
        if _lint_fix_removes_something(config_path, check):
            secho(
                "\n💡 'ash config lint --fix' removes internal-only fields and "
                "sections.",
                fg=typer.colors.YELLOW,
            )

        _print_unchecked_plugin_options_note(check)

        if check.scan_accepts:
            secho(
                "\n✅ Configuration is valid! A scan accepts it.",
                fg=typer.colors.GREEN,
            )
            return

        secho(
            f"\n❌ Configuration is invalid: a scan refuses it with exit "
            f"{INVALID_CONFIG_EXIT_CODE}. The configuration guide, and the JSON "
            "schema at automated_security_helper/schemas/AshConfig.json, give each "
            "field's type and allowed values.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(INVALID_CONFIG_EXIT_CODE)

    except typer.Exit:
        raise
    except Exception as e:
        logger.error(f"Error validating config: {e}")
        secho(f"❌ Error validating config: {e}", fg=typer.colors.RED)
        raise typer.Exit(1)


if __name__ == "__main__":
    from automated_security_helper.cli.entrypoint import run_module_app

    run_module_app(config_app)
