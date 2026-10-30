# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import io
import json
import logging
import os
import re
import stat
import sys
from pathlib import Path
from typing import Annotated, List, Optional, TextIO
import typer
import yaml

from rich.highlighter import JSONHighlighter
from rich.markdown import Markdown

from automated_security_helper.base.plugin_config import plugin_config_key
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    off_host_reporter_refused,
    reporter_classes_for_run,
    reporter_companion_file_names,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_validator import describe_results_error
from automated_security_helper.config.plugin_module_trust import (
    drop_untrusted_off_host_plugins,
)
from automated_security_helper.config.plugin_option_check import (
    refuse_unknown_plugin_options,
)
from automated_security_helper.config.operator_only_options import reporter_section
from automated_security_helper.config.plugin_section_names import ascii_lower
from automated_security_helper.config.recorded_config import (
    HOW_TO_SUPPLY,
    take_own_values,
)
from automated_security_helper.config.reporter_trust import (
    confine_declared_reporter_destinations,
    confine_off_host_reporters_to_overrides,
)
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.config.untrusted_source import (
    IN_TREE_OR_DELIVERED,
    REPORT_CONFIG_FILE,
    REPORT_CONFIG_FILE_IN_TREE,
    UntrustedSource,
)
from automated_security_helper.core.constants import (
    ASH_CONFIG_SOURCES_DESCRIPTION,
    ASH_EXIT_USAGE_ERROR,
)
from automated_security_helper.core.enums import (
    AWS_PLUGIN_MODULE_FORMATS,
    FORMATS_NO_REPORTER_WRITES,
    AshLogLevel,
    ExportFormat,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    warning_of_dropped_keys,
)
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.loader import (
    PluginModuleError,
    PluginModuleNamespaceError,
    load_plugins,
    plugin_module_fix,
    plugins_of,
)
from automated_security_helper.utils.command_safe_stream import (
    CommandSafeStream,
    json_commands_broken,
)
from automated_security_helper.utils.console import ash_console
from automated_security_helper.utils.error_text import error_text, traceback_text
from automated_security_helper.utils.log import escape_markup as escape
from automated_security_helper.utils.log import get_logger
from automated_security_helper.utils.output_dir_links import (
    OutputDirLinkRefused,
    refuse_linked_output_dir,
)
from automated_security_helper.utils.parser_text import own_lines
from automated_security_helper.utils.report_path_links import (
    refuse_linked_report_paths,
    refuse_report_names_outside,
)
from automated_security_helper.utils.terminal_text import (
    controls_shown,
    json_controls_shown,
    shown_not_obeyed,
)


# Reporters whose output is a JSON document, printed with rich's print_json.
#
# Every entry must be a real reporter's config name, because this is matched
# against --format. The list used to carry names no reporter has (asff,
# security-hub, security-lake, opensearch) and to miss JSON reporters, and spdx
# sat here while that reporter emitted YAML, so `ash report --format spdx` died
# in print_json. tests/unit/cli/test_report_format_output.py checks every name
# against the registered reporters.
#
# Pretty-printed only on an interactive terminal; see _write_report. To a regular
# file the report is written as the reporter produced it, and to a pipe with its
# CI command forms broken.
JSON_STDOUT_FORMATS = frozenset(
    {
        "aws-security-hub",
        "cloudwatch-logs",
        "cyclonedx",
        "flat-json",
        "github-ghas",
        "gitlab-cyclonedx",
        "gitlab-sast",
        "ocsf",
        "s3",
        "sarif",
        "spdx",
        # JSON by default and under output_format json; markdown under
        # output_format markdown, which _is_json_document tells apart by the
        # content, so the markdown is never broken with JSON's escapes.
        "unused-suppressions",
    }
)


def _is_json_document(content: str) -> bool:
    """Whether *content*, a report of a JSON format, is a JSON document.

    By its first character: a reporter of a JSON format may write something
    else (unused-suppressions writes markdown under its ``output_format:
    markdown``; a plugin reporter may return text). Such a report is written as
    text, not broken with JSON's escapes or parsed for the pretty printing,
    which failed it on a terminal and passed it to a pipe.
    """
    return content.lstrip()[:1] in ("{", "[")


# The JSON formats whose reporter also writes a text document by design
# (unused-suppressions under output_format markdown): for these a report that is
# not JSON is the report, not the reporter's error text, so the JSON check the
# command makes before writing (report_command) is made only when the content
# reads as a JSON document and then fails to parse.
TEXT_OR_JSON_FORMATS = frozenset({"unused-suppressions"})


# The longest content of a JSON format that failed the JSON check the error
# quotes. A reporter's error text in the report's place is one short line, and
# the line is the reason. Anything longer, on more than one line, or shaped like a
# JSON document (a truncated or malformed one, minified on one line) is a report
# that holds finding snippets, which can hold detected secrets, and the error goes
# to stderr, the CI log, where an operator who redirected stdout to a file kept
# the report out. Such content is described, by its decode error and its length,
# as this file describes the pydantic errors it refuses to quote the input of.
_QUOTED_REASON_CHARS = 200


def _non_json_report_text(content: str, error: ValueError) -> str:
    """What the error says about *content*, which failed ``json.loads``.

    A short one-line text that does not start as a JSON document is the reason
    and is returned as it is. Everything else is described: a reporter's error
    text never starts with ``{`` or ``[``, so content that does is a document
    that failed to parse, and quoting its first 200 characters would quote the
    findings in them.
    """
    reason = content.strip()
    if (
        len(reason) <= _QUOTED_REASON_CHARS
        and "\n" not in reason
        and "\r" not in reason
        and not _is_json_document(reason)
    ):
        return reason
    return (
        f"{error_text(error)}; the {len(content)} characters it returned are not shown"
    )


# Reporters whose output is Markdown, rendered with rich's Markdown on an
# interactive terminal.
MARKDOWN_STDOUT_FORMATS = frozenset({"markdown", "bedrock-summary-reporter"})


def _shown_not_obeyed(text: str, *, json_text: bool = False) -> str:
    """*text* with every character a terminal acts on written as an escape.

    For output that reaches an interactive terminal. A report repeats what the
    scanned repository contains (finding messages, snippets, the project name),
    and written as is, an OSC 52 sequence there sets the reader's clipboard, an
    OSC 8 sequence plants a hyperlink, a carriage return or CSI 2K overwrites
    what was printed before it, a bidirectional override shows text in an order
    other than the one it holds, and a line separator ends a line. The set is
    utils/terminal_text.py's one (is_shown_as_escape), the one every console
    sink uses, so a character added there is shown in a report too; each is
    written ``\\xNN``, ``\\uNNNN`` or ``\\UNNNNNNNN``. Tab, newline and a carriage
    return before a newline lay the report out and are kept.

    The backslashes of text that would read as such an escape (``\\x1b`` in a
    finding's message) are doubled, so an escape on the terminal is always a
    control character and never text the repository wrote to look like one: an
    odd run of backslashes before the text of an escape this function writes
    ends in an escape, an even one is text. Other backslashes are left alone, so
    a Windows path such as ``C:\\build\\x64\\Release`` is shown as it is.
    Rendered Markdown reads ``\\\\`` as one backslash, so _write_report does not
    render a Markdown report that holds a control or an escape's text.

    With *json_text*, as JSON escapes instead (``\\u00NN``, and a surrogate pair
    beyond U+FFFF). A JSON serializer escapes C0 controls in strings itself but
    writes DEL, C1 and the format characters as they are, and ``\\xNN`` is not a
    JSON escape, so the document stopped parsing. JSON's escapes parse to the
    same string, and JSON's own escaping already keeps text and escapes apart.
    """
    if json_text:
        return json_controls_shown(text)
    return controls_shown(text, lookalikes="written")


def _quoted(value: object, one_line: bool = False) -> str:
    """*value* as text for rich markup: escaped, with its controls shown and its
    CI command forms broken. ``escape`` is utils/log.py's escape_markup, which runs
    ``shown_not_obeyed`` itself, so the value goes through it once: twice, each
    escape it wrote had its backslash doubled again. An exception is its
    ``error_text``, which describes a pydantic error instead of quoting the input
    it refused. ``one_line`` shows its newlines as escapes too."""
    text = error_text(value) if isinstance(value, BaseException) else str(value)
    return escape(text, one_line=one_line)


def _print_refusal(template: str, *values: object) -> None:
    """_print_error, with each value on one line: a refusal that names a file is
    one line, and the file's path is the caller's text, which a newline in it
    would split."""
    console = ash_console(stderr=True, soft_wrap=True)
    template = template.format(*(_quoted(value, one_line=True) for value in values))
    console.print(template, highlight=False)


def _print_error(template: str, *values: object) -> None:
    """Print *template*, rich markup in ASH's own words, to stderr, unwrapped.

    *values* fill the ``{}`` fields of *template* as text, never as markup. They
    are exception text, paths and the --format value, and put into the markup
    as they were, a ``[/x]`` raised MarkupError in place of the message and a
    ``[link=...]`` became a hyperlink. They go through utils/terminal_text.py's
    shown_not_obeyed, as the console log does: stderr is a terminal or a CI log,
    so their controls are shown as escapes and their CI command forms broken.
    rich's print folds at the console width, 80 columns off a terminal, which
    split long paths in the messages across lines. Not highlighted: the console's
    highlighter colored a quoted path or a number apart from the rest of the
    message, splitting the text a reader or a log search looks for.
    """
    console = ash_console(stderr=True, soft_wrap=True)
    if values:
        template = template.format(*(_quoted(value) for value in values))
    console.print(template, highlight=False)


def _exists(path: Path) -> bool:
    """Whether *path* exists, with a path the user may not reach read as present.

    ``Path.exists`` raises PermissionError below Python 3.14 for a path under a
    directory the user cannot search; the command then ended in a traceback
    where it refuses a missing file with its own words. Read as absent, such a
    path gave the wrong answer twice: a ``--config`` under a directory the user
    cannot search was refused as "not found", and a results file there was
    skipped for a stale one in a later place, which was then reported on with no
    warning. Read as present, the open that follows refuses it with the real
    cause, through the paths that already handle an OSError (exit 3 for the
    configuration, exit 1 for the results). Any other OSError (a name too long, a
    component that is a file) reads as absent: the open would say the same, and
    the refusal for a missing file names the path.
    """
    try:
        return path.exists()
    except PermissionError:
        return True
    except OSError:
        return False


def _working_directory() -> Path:
    """The working directory, or the usage-error refusal when it is gone.

    ``Path.cwd()`` raises FileNotFoundError once the directory the command was
    started in was deleted or unmounted; the config loader handles that case and
    this command ended in a traceback.
    """
    try:
        return Path.cwd()
    except OSError as e:
        _print_refusal(
            "[red]Error: the working directory cannot be read ({}); it was deleted or "
            "unmounted. Change to a directory that exists and run the command "
            "again.[/red]",
            error_text(e),
        )
        raise typer.Exit(ASH_EXIT_USAGE_ERROR)


def _named_config_files(config: Optional[str]) -> List[str]:
    """The config files this run reads by name: ``--config``'s, and ASH_CONFIG's
    when the variable names another file.

    The defaults a scan starts from are the file ASH_CONFIG names
    (default_config.get_default_config), so with ``--config`` given as well both
    files are read; the off-host confinement and its warning named only the
    ``--config`` file, so a setting the ASH_CONFIG file wrote was neither held nor
    named.
    """
    named = [config] if config is not None else []
    from_environment = os.environ.get("ASH_CONFIG", "").strip()
    if from_environment and from_environment not in named:
        named.append(from_environment)
    return named


def _refused_config_name(config: Optional[str]) -> str:
    """The file a read or parse refusal names: ``--config``'s, else the ASH_CONFIG
    file the defaults are read from, else the configuration itself.

    With no ``--config`` the refusals printed the option's value, the text
    "None" ("could not read None").
    """
    if config is not None:
        return config
    return os.environ.get("ASH_CONFIG", "").strip() or "the configuration file"


def _source_of_named_config(ash_config: AshConfig, named_file: str) -> UntrustedSource:
    """Why ``named_file``, the config file this command was given, is not the operator's.

    A file ``resolve_config`` placed inside a git checkout or the working
    directory is among the files it recorded on ``ash_config`` and held for that
    reason, so its warning keeps that reason. Its remedy is still
    ``--config-overrides`` (``REPORT_CONFIG_FILE_IN_TREE``): this command holds any
    file it is named, so moving the file out of the tree would not help. A file it
    could not place in any tree may still be the scanned tree's own, since stored
    results do not record which tree was scanned: ``REPORT_CONFIG_FILE``, whose
    reason says so. All three fill a section the file leaves out the same way, so
    the choice changes the warning's words alone.
    """
    try:
        named = Path(named_file).resolve()
        placed = {Path(path).resolve() for path in ash_config._in_tree_config_files}
    except (OSError, RuntimeError):
        return REPORT_CONFIG_FILE
    return REPORT_CONFIG_FILE_IN_TREE if named in placed else REPORT_CONFIG_FILE


def _is_a_regular_file(stream: TextIO) -> bool:
    """Whether *stream* writes to a regular file, as ``ash report --format F > report``
    makes stdout."""
    try:
        return stat.S_ISREG(os.fstat(stream.fileno()).st_mode)
    except (AttributeError, OSError, ValueError):
        # No descriptor (io.UnsupportedOperation is both an OSError and a
        # ValueError), or a closed stream: written as to a pipe.
        return False


# A line feed that no carriage return precedes: the line end _write_report_data
# writes as os.linesep. The line feed of a CRLF is left with its carriage return.
_BARE_LINE_FEED = re.compile(r"(?<!\r)\n")


def _write_report_data(content: str, stream: TextIO) -> None:
    """*content* to *stream* as the report phase writes it to reports/.

    UTF-8, with each line end written as os.linesep, as utils/atomic_write's
    write_text_atomically writes it, whatever the stream's own encoding and newline
    handling are; a character UTF-8 cannot encode is written as a backslash escape
    rather than failing the command. To the byte buffer under the stream, so a
    stream that checks what it is given for CI commands is written past. A stream
    with no byte buffer under it is written as text.

    A line end the report already writes as CRLF (CSV rows) is kept as it is:
    only a line feed with no carriage return before it is written as os.linesep.
    Replacing every line feed turned a CRLF into CR CR LF on Windows, a blank
    line per row, and folding CRLF to LF before the replacement rewrote CSV rows
    as LF wherever os.linesep is LF, so `ash report --format csv > out.csv` on
    Linux or macOS wrote rows the reporter had not written, and a CRLF inside a
    quoted field (a multi-line snippet) was changed with them.
    """
    stream.flush()
    binary = getattr(stream, "buffer", None)
    if binary is None:
        stream.write(content)
        stream.flush()
        return
    data = _BARE_LINE_FEED.sub(os.linesep, content)
    binary.write(data.encode("utf-8", "backslashreplace"))
    binary.flush()


def _write_report_checked(content: str, stream: TextIO) -> None:
    """*content* to *stream* through the CI-command check, once.

    As UTF-8 to the byte buffer under the stream when there is one, because the
    reporters write UTF-8 and a Windows console or pipe would otherwise encode the
    text as cp1252, so the check is applied here, to a UTF-8 view of that buffer.
    A stream that already checks is written past to its buffer the same way, so
    each command is broken once. The check is utils/command_safe_stream.py's: off
    a terminal, and on one under a runner that reads commands from it, a line
    start's "::" has its first colon written ``\\x3a`` and a "##name[" its first
    "#" written ``\\x23``.
    """
    stream.flush()
    binary = getattr(stream, "buffer", None)
    if binary is None:
        checked = (
            stream
            if isinstance(stream, CommandSafeStream)
            else CommandSafeStream(lambda: stream)
        )
        checked.write(content)
        checked.flush()
        return
    text = io.TextIOWrapper(
        binary, encoding="utf-8", errors="backslashreplace", newline=""
    )
    try:
        CommandSafeStream(lambda: text).write(content)
        text.flush()
    finally:
        # Leave the buffer open: it is the stream's, not this wrapper's.
        text.detach()
    binary.flush()


def _write_report(
    content: str, report_format: str, *, pretty: bool, stream: Optional[TextIO] = None
) -> None:
    """Write a rendered report to *stream* (stdout by default).

    To a regular file (``ash report --format sarif > ash.sarif``) the report is
    the reporter's output, with the bytes the report phase writes to reports/
    (_write_report_data), so the file is a SARIF file. It is not byte for byte the
    file the scan wrote: a report rendered again from the saved results can
    differ (SARIF carries fields the saved results default, and CSV, HTML and
    Markdown are stamped with the time they are rendered). A CI runner reads a
    step's output from a pipe, and a file the step redirected stdout to is data.

    To anything else, a pipe or a terminal, the report repeats the scanned
    repository's file names and finding text, and stdout is often a CI log, so
    every line goes through the CI-command check (_write_report_checked): most
    reporters write a file named with a line feed and "::add-mask::" after it as
    a line of its own, which a runner would otherwise obey. A JSON report has
    the "#" of each "##name[" written as JSON's own escape first
    (json_commands_broken), so it is still the same document; a YAML or text
    report's broken line holds the escape as text. With ``pretty`` off -- not a
    terminal, or ``--no-color`` -- it is otherwise the reporter's output, not
    re-indented, highlighted or wrapped, so JSON carries no highlighting escape
    codes under ``--no-color``, and other formats are not soft-wrapped at 80
    columns, which would split CSV rows and break JUnit XML.

    ``pretty`` is color being on (no ``--no-color``, no NO_COLOR); it takes
    effect only when *stream* is an interactive terminal. Then JSON is indented
    and Markdown rendered, which is all rich is used for here.

    On an interactive terminal, with or without ``pretty``, control characters
    from the report are shown as ``\\xNN`` rather than obeyed (see
    ``_shown_not_obeyed``); in JSON, pretty or plain, as ``\\u00NN``, so it is
    still the same document. ``docker run -t`` gives the command a terminal:
    ``--no-color`` there stops the indenting and rendering, but control characters
    are still shown escaped. For the reporter's exact output, redirect stdout to a
    file.

    Limit: a runner that read command forms back from a file stdout was
    redirected to would not have them broken; none is known to.
    """
    stream = stream if stream is not None else sys.stdout
    fmt = report_format.lower()
    if _is_a_regular_file(stream):
        _write_report_data(content, stream)
        return
    # Both from the stream written to, not from sys.stdout, so a stream that is
    # not a terminal is never pretty.
    terminal = bool(getattr(stream, "isatty", lambda: False)())
    pretty = pretty and terminal
    is_json = fmt in JSON_STDOUT_FORMATS and _is_json_document(content)
    # Through the console's CI-command check, unless the stream checks already.
    report_console = ash_console(
        file=stream, check_commands=not isinstance(stream, CommandSafeStream)
    )
    if pretty and is_json:
        # Indented as rich's print_json indents, then escaped as JSON text, so
        # what reaches the terminal is still the report's document. Escaping the
        # strings one by one in the parsed data would change what they hold and
        # could merge two keys into one. A document that does not parse is
        # written as the reporter wrote it, below, as it is to a pipe: the
        # pretty printing is a rendering, never a check a terminal alone fails.
        try:
            document = json.dumps(json.loads(content), indent=2, ensure_ascii=False)
        except ValueError:
            document = None
        if document is not None:
            text = JSONHighlighter()(
                json_commands_broken(_shown_not_obeyed(document, json_text=True))
            )
            text.no_wrap = True
            text.overflow = None
            report_console.print(text, soft_wrap=True)
            return
    # rich's Markdown shows "\\" as "\", which would undo the doubling that keeps
    # an escape's text apart from an escaped control, so a report that holds
    # either is written as the escaped text, unrendered.
    renders = pretty and fmt in MARKDOWN_STDOUT_FORMATS
    if renders and _shown_not_obeyed(content) != content:
        renders = False
    if terminal:
        content = _shown_not_obeyed(content, json_text=is_json)
    if is_json:
        content = json_commands_broken(content)
    if renders:
        # hyperlinks=False: rich makes a link or an autolink an OSC 8 hyperlink
        # after the escape above has run, so a link in a finding's message would
        # be live with text and target the scanned repository chose. Without
        # them a link is shown as its text followed by its target.
        report_console.print(Markdown(content, hyperlinks=False))
        return
    _write_report_checked(content, stream)


def get_report_formats(incomplete: str = None) -> List[str]:
    """The formats a reporter ASH ships writes, containing ``incomplete``:
    ExportFormat's values but those no reporter writes, which --format refuses.
    The AWS plugin module's are among them, accepted once ``ash_plugin_modules``
    loads that module."""
    report_formats = []
    for report_format in ExportFormat:
        if report_format in FORMATS_NO_REPORTER_WRITES:
            continue
        if incomplete and incomplete not in report_format.value:
            continue
        report_formats.append(report_format.value)
    return report_formats


def _report_format_help() -> str:
    """--format's help: the formats it accepts by default, and the AWS plugin
    module's apart, from get_report_formats."""
    formats = get_report_formats("")
    built_in = [fmt for fmt in formats if fmt not in AWS_PLUGIN_MODULE_FORMATS]
    aws = [fmt for fmt in formats if fmt in AWS_PLUGIN_MODULE_FORMATS]
    return (
        "Report format to generate: a reporter's name. Defaults to 'markdown'. "
        f"Values: {', '.join(built_in)}. With the AWS plugin module "
        f"(ash_aws_plugins) in ash_plugin_modules, also, once enabled: "
        f"{', '.join(aws)}. A reporter another module there adds is named the "
        "same way."
    )


def report_command(
    report_format: Annotated[
        str,
        typer.Option(
            "--format",
            help=_report_format_help(),
            autocompletion=get_report_formats,
        ),
    ] = ExportFormat.MARKDOWN.value,
    output_dir: Annotated[
        str | None,
        typer.Option(
            help="The directory to output results to",
            envvar="ASH_OUTPUT_DIR",
        ),
    ] = None,
    log_level: Annotated[
        AshLogLevel,
        typer.Option(
            "--log-level",
            help="Set the log level.",
        ),
    ] = AshLogLevel.INFO,
    config: Annotated[
        str,
        typer.Option(
            "--config",
            "-c",
            help=f"The path to the configuration file. By default, ASH looks for the following config file names in the source directory of a scan: {ASH_CONFIG_SOURCES_DESCRIPTION}. Alternatively, the full path to a config file can be provided by setting the ASH_CONFIG environment variable before running ASH.",
            envvar="ASH_CONFIG",
        ),
    ] = None,
    config_overrides: Annotated[
        Optional[List[str]],
        typer.Option(
            "--config-overrides",
            help="Configuration overrides specified as key-value pairs (e.g., 'reporters.cloudwatch-logs.options.aws_region=us-west-2')",
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
    """Generate a report from ASH scan results using the specified reporter plugin."""
    if config_overrides is None:
        config_overrides = []
    # Set up logging
    final_log_level = (
        AshLogLevel.VERBOSE
        if verbose
        else (
            AshLogLevel.DEBUG
            if debug
            else (
                AshLogLevel.ERROR
                if log_level
                in [
                    AshLogLevel.QUIET,
                    AshLogLevel.ERROR,
                    AshLogLevel.SIMPLE,
                ]
                else log_level
            )
        )
    )
    final_logging_log_level = logging._nameToLevel.get(
        final_log_level.value, logging.INFO
    )
    # stderr: stdout carries the report and nothing else.
    ASH_LOGGER = get_logger(
        level=final_logging_log_level,
        show_progress=False,
        use_color=color,
        use_stderr=True,
    )
    # Resolve cwd-based default at call time (not import time). The default is the
    # directory a scan writes to, so only its own results file is read: the
    # candidates below, joined onto it, were .ash/ash_output/.ash/ash_output/...
    # and .ash/ash_output/ash_output/..., which no scan writes.
    cwd = _working_directory()
    results_file = None
    if output_dir is None:
        output_dir = cwd.joinpath(".ash", "ash_output").as_posix()
        output_dir_path = Path(output_dir)
        results_file_paths = [output_dir_path.joinpath("ash_aggregated_results.json")]
    else:
        output_dir_path = Path(output_dir)
        results_file_paths = [
            output_dir_path.joinpath(
                ".ash", "ash_output", "ash_aggregated_results.json"
            ),
            output_dir_path.joinpath("ash_output", "ash_aggregated_results.json"),
            output_dir_path.joinpath("ash_aggregated_results.json"),
        ]
    # Every place that holds one, not the first: an --output-dir whose three
    # searched places hold two results files (a scan run from the directory and
    # another run with --output-dir pointing at it) is ambiguous, and reporting
    # on the first found read as a report on the other. The refusal is below,
    # after the configuration and the format are checked, with the other usage
    # errors; results_file stays the first found for the checks between.
    found_results_files = [path for path in results_file_paths if _exists(path)]
    if found_results_files:
        results_file = found_results_files[0]
    # The output directory is the one the results were read from. --output-dir
    # may name the scanned repository's root (the first candidate reads
    # <dir>/.ash/ash_output/); the plugin context, the work directory and the
    # reports/ checks below then used <dir> itself, so a reporter that writes
    # files of its own wrote them into <dir>/reports, inside the scanned tree,
    # while the scan had written them under <dir>/.ash/ash_output/reports.
    if results_file is not None:
        output_dir_path = results_file.parent
    # Reporters write into reports/ here without the scan's clean-up first, so a
    # link at the output directory or reports/ is refused as a scan refuses it.
    try:
        refuse_linked_output_dir(cwd, output_dir_path)
        # That guard examines the components below the working directory only.
        # With --output-dir outside it, the directory as given and its .ash sit
        # above the resolved directory and below nothing the guard roots at, so
        # a link at either was written through; as the output directory itself
        # the given directory was refused. Guard from its parent down as well.
        # abspath, not Path.absolute(): pathlib's parent of a path that ends in
        # ".." drops the ".." instead of stepping up, so "--output-dir .." would
        # root this guard at the working directory and miss its parent's .ash.
        refuse_linked_output_dir(
            Path(os.path.abspath(output_dir)).parent, output_dir_path
        )
    except OutputDirLinkRefused as refusal:
        # The message names the output directory, built from the path as given:
        # on one line.
        _print_refusal("[red]{}[/red]", refusal)
        # 3, as a scan exits for the same refusal (OUTPUT_DIR_REFUSED_EXIT_CODE).
        raise typer.Exit(3)

    # A named file that does not exist is refused, as the config commands and a
    # scan refuse it: rendering with the defaults instead used settings the
    # operator did not choose, and the command then exited 1 for another reason.
    # ASH_CONFIG is this option's environment variable; a value it gave is
    # refused in the words a scan uses for ASH_CONFIG (get_default_config).
    # Read once: a second exists() for the load below let a file removed
    # between the two render the report under the defaults in silence.
    named = config is not None and _exists(Path(config))
    if config is not None and not named:
        if config == os.environ.get("ASH_CONFIG"):
            from automated_security_helper.config.default_config import (
                get_default_config,
            )

            try:
                get_default_config()
            except ASHConfigValidationError as e:
                _print_refusal("[red]Invalid configuration: {}[/red]", e)
                raise typer.Exit(3)
        _print_refusal(
            "[red]Invalid configuration: Configuration file not found: {}[/red]",
            Path(config).as_posix(),
        )
        raise typer.Exit(3)

    # Load the ASH configuration. A named file that exists must load: falling
    # back to the defaults for one that does not parse rendered the reports
    # with settings it does not hold (other reporters, other masking).
    refused_name = _refused_config_name(config)
    try:
        # A config file is judged against the repository the results came from
        # as well as the working directory: run from elsewhere, a --config inside
        # that repository was its own file and set the off-host reporters. This
        # command holds any file it is named to the overrides, so the warning for a
        # named file that resolve_config places in a tree gives the same remedy as
        # the one below (_source_of_named_config).
        ash_config = resolve_config(
            config_path=config,
            config_overrides=config_overrides,
            fallback_to_default=not named,
            also_scanned=[results_file.parent] if results_file is not None else [],
            named_config_source=REPORT_CONFIG_FILE_IN_TREE,
        )
        # The stored results do not say which tree was scanned, so the config file
        # read here may be that tree's own even when resolve_config cannot place it
        # in a git checkout or under the working directory (a scanned directory
        # beside this one). It does not choose whether a reporter sends findings
        # off the host, or where: those come from --config-overrides.
        # Both files this run reads by name: --config's and, when the variable
        # names another, ASH_CONFIG's, which the defaults are read from. The
        # first named is the one the warning describes.
        named_files = _named_config_files(config)
        named_source = IN_TREE_OR_DELIVERED
        if named_files:
            named_source = _source_of_named_config(ash_config, named_files[0])
            confine_off_host_reporters_to_overrides(
                ash_config,
                [Path(named_file) for named_file in named_files],
                config_overrides,
                named_source,
            )
    except ASHConfigValidationError as e:
        _print_refusal("[red]Invalid configuration: {}[/red]", e)
        raise typer.Exit(3)
    except OSError as e:
        # A file the command may not read is a config it cannot use, as one
        # that does not parse is: exit 3, in the words the scan uses, not an
        # unexpected error. The format names the file and error_text names an
        # OSError's own file as given, so the same name can appear twice; the
        # whole line is one line, as the name can hold a newline. Before the
        # parse arm: an OSError here is never a parse.
        _print_refusal(
            "[red]Invalid configuration: could not read {}: {}[/red]",
            refused_name,
            error_text(e),
        )
        raise typer.Exit(3)
    except (yaml.YAMLError, ValueError) as e:
        # ValueError covers json.JSONDecodeError and UnicodeDecodeError. A file
        # that does not parse arrives above, as an ASHConfigValidationError:
        # resolve_config refuses it in words that quote none of it
        # (unparsed_config_reason). To stderr, the name and the message as
        # text, as report's other errors: the name on one line, and the
        # message's own lines each on one line (_print_refusal), so a newline
        # in the name starts no line.
        first, *rest = own_lines(
            error_text(e), [Path(config)] if config is not None else []
        )
        _print_refusal(
            "[red]Invalid configuration: {} does not parse: {}[/red]",
            refused_name,
            first,
        )
        for line in rest:
            _print_refusal("[red]{}[/red]", line)
        raise typer.Exit(3)

    # Create plugin context
    plugin_context = PluginContext(
        source_dir=cwd,
        output_dir=output_dir_path,
        work_dir=output_dir_path.joinpath("work"),
        config=ash_config,
    )

    # Set the plugin context for the plugin manager
    ash_plugin_manager.set_context(plugin_context)
    try:
        load_plugins(plugin_context=plugin_context)
    except PluginModuleNamespaceError as e:
        # The config names something that is not a plugin module. Rendering the
        # report without its plugins would describe another configuration. In
        # the report's own closing words: the scan's say nothing was scanned
        # and name options this command does not have.
        _print_refusal(
            "[red]Invalid configuration: {}[/red]",
            e.shown_with(
                "Nothing was imported and no report was rendered. Rename the "
                "package or name the packages inside it, or remove the entry "
                "from the config file or --config-overrides."
            ),
        )
        raise typer.Exit(3)
    except PluginModuleError as e:
        # A configured module could not be loaded; the fix clause follows the
        # loss's stage (plugin_module_fix).
        _print_refusal(
            "[red]Invalid configuration: {}[/red]",
            e.shown_with(
                f"No report was rendered. {plugin_module_fix(e)}, or "
                "remove the entry from the config file or --config-overrides."
            ),
        )
        raise typer.Exit(3)
    except ASHConfigValidationError as e:
        # Any other refusal plugin loading raises is still an invalid
        # configuration: the arms above name the module refusals only to pick
        # their closing words, and this one keeps the type's documented exit
        # code instead of a traceback.
        _print_refusal("[red]Invalid configuration: {}[/red]", e)
        raise typer.Exit(3)

    # This run's plugins: ASH's built-ins and the modules its configuration names.
    # The registry is process-wide, so it can also hold reporters another run in
    # this process loaded (an MCP server, a test); they are not this run's.
    run_modules = list(getattr(ash_config, "ash_plugin_modules", None) or [])
    run_scope = plugins_of(run_modules)
    run_reporters = reporter_classes_for_run(run_modules, manager=ash_plugin_manager)

    # The options of a plugin loaded from ash_plugin_modules are checked only once
    # it is loaded, as the scan engine checks them (config/plugin_option_check.py).
    # Without this, a bad one reached the reporter's own model and the command
    # printed pydantic's raw error and exited 1, where a scan with the same config
    # says it is invalid and exits 3.
    try:
        refuse_unknown_plugin_options(
            ash_config,
            {
                "converter": ash_plugin_manager.plugin_modules(
                    "converter", filter_callback=run_scope
                ),
                "scanner": ash_plugin_manager.plugin_modules(
                    "scanner", filter_callback=run_scope
                ),
                "reporter": run_reporters,
            },
        )
    except ASHConfigValidationError as e:
        _print_refusal("[red]Invalid configuration: {}[/red]", e)
        raise typer.Exit(3)

    # Find the reporter plugin: among ASH's built-ins and the modules this run's
    # configuration names, not every reporter this process has registered.
    reporter_plugins = run_reporters
    # A reporter from an off-host plugin package that only an in-tree config's
    # module brought in is not one this command may run.
    reporter_plugins = drop_untrusted_off_host_plugins(
        ash_config, {"reporter": reporter_plugins}, None
    )["reporter"]
    # The config's plugin modules are loaded now, so the destination options each
    # reporter declares are known; a config file does not choose them. The warning
    # gives the reason the file is held for: that of a file named on the command
    # line which this command cannot place in any tree, or the reason for a file in
    # the working directory or a git checkout, which resolve_config placed in the
    # tree, with this command's remedy (``_source_of_named_config``).
    confine_declared_reporter_destinations(
        ash_config, reporter_plugins, source=named_source
    )
    reporter_class = None

    # By the name each reporter class declares (plugin_config_key), without
    # building it: a reporter whose default construction raised was passed over
    # and the --format reported as not found, with the cause at debug. ASCII case
    # only, as every other comparison of a plugin's name: the format is looked
    # up as that plugin's config key below.
    for plugin_class in reporter_plugins:
        if ascii_lower(plugin_config_key(plugin_class)) == ascii_lower(report_format):
            ASH_LOGGER.info(f"Found reporter plugin {plugin_class.__name__}")
            reporter_class = plugin_class
            break

    if reporter_class is None:
        _print_error("[red]Error: Reporter plugin '{}' not found.[/red]", report_format)
        _print_error("[yellow]Available reporter formats:[/yellow]")
        for plugin_class in reporter_plugins:
            _print_error("  - {}", plugin_config_key(plugin_class))
        # A --format no reporter answers to is a mistyped argument, so it exits with
        # the usage-error code rather than 1, which reports a failed run.
        raise typer.Exit(ASH_EXIT_USAGE_ERROR)

    try:
        reporter_plugin = reporter_class(context=plugin_context)
    except Exception as e:
        # The reporter exists and cannot be built: a failed run, with its cause,
        # not a mistyped --format.
        _print_error(
            "[red]Error: reporter '{}' could not be built: {}[/red]",
            report_format,
            e,
        )
        raise typer.Exit(1)

    # The order is configuration (exit 3), then the reporter (an unknown --format
    # is the command line's mistake whatever is on disk), then the results (exit 1,
    # a state problem), and nothing is created on the way: `ash report` in an
    # empty directory leaves no .ash/ash_output behind.
    if len(found_results_files) > 1:
        # A usage error, as the docs say (how-to/read-results.md, exit-codes.md):
        # the operator names the directory that holds the one to report on, and
        # nothing is reported on or created meanwhile.
        listed = ", ".join(path.as_posix() for path in found_results_files)
        _print_refusal(
            "[red]More than one scan results file found: {}. Point --output-dir "
            "at the directory that holds the one to report on.[/red]",
            listed,
        )
        raise typer.Exit(ASH_EXIT_USAGE_ERROR)
    if results_file is None:
        searched = ", ".join(path.as_posix() for path in results_file_paths)
        missing = (
            "{} does not exist" if len(results_file_paths) == 1 else "none of {} exists"
        )
        _print_refusal(
            f"[red]No scan results found: {missing}. Run 'ash scan' first, "
            "or point --output-dir at the output directory of a previous scan.[/red]",
            searched,
        )
        raise typer.Exit(1)

    # Load the results file
    #
    # encoding is explicit because text-mode open() without it uses the process's
    # locale encoding, which on Windows is cp1252. ASH writes this file as UTF-8, and
    # findings routinely carry bytes cp1252 cannot decode -- a snippet from a
    # non-ASCII source file, a tool's smart quotes. Measured on
    # `scan (python-local, windows-latest)`: `ash report --format text` died with
    # "'charmap' codec can't decode byte 0x9d", so on Windows this command could not
    # render a report for any scan whose results were not pure cp1252.
    try:
        with open(results_file, "r", encoding="utf-8") as f:
            with warning_of_dropped_keys(results_file) as context:
                model = AshAggregatedResults.model_validate_json(
                    f.read(), context=context
                )
    except Exception as e:
        # Not str(e): pydantic's text quotes the input, and this file holds
        # finding snippets. On one line: the path is the --output-dir as given.
        # An OSError's own text names the file again, quoted, so only its reason.
        reason = (
            (e.strerror or type(e).__name__)
            if isinstance(e, OSError)
            else describe_results_error(e)
        )
        _print_refusal(
            "[red]Could not read the scan results in {}: {}[/red]",
            results_file.as_posix(),
            reason,
        )
        raise typer.Exit(1)

    # A field the results' record holds as an environment reference it cannot
    # hold, such as severity_threshold, which the reports render
    # (config/recorded_config.py): taken from this command's configuration, or
    # refused rather than reported under the field's default.
    try:
        take_own_values(
            model.ash_config,
            ash_config,
            override_keys=[
                override.partition("=")[0].strip() for override in config_overrides
            ],
            refuse_unless_supplied=HOW_TO_SUPPLY,
        )
    except ASHConfigValidationError as e:
        _print_refusal("[red]Invalid configuration: {}[/red]", e)
        raise typer.Exit(3)

    # A reporter that sends findings off the host runs only when the operator
    # enables it, which here means --config-overrides: stored results do not
    # record which tree was scanned, so a config file does not choose it (see
    # confine_off_host_reporters_to_overrides above). Naming it with --format is
    # not enough: it would send the stored findings with whatever credentials
    # the host has.
    #
    # The reporter is built from reporter_section, the section a scan builds it
    # from: the operator's when the scanned repository wrote this config
    # (config/operator_only_options.reporter_section). That section comes from
    # the view resolve_config recorded, and a --config file outside every tree
    # that extends a file inside one is in that view. The step above applies its
    # rule to the view as well as to the resolved section, so this one read is
    # already the confined section: the refusal and the reporter both use it.
    plugin_config = reporter_section(ash_config, reporter_class)
    if off_host_reporter_refused(reporter_class, plugin_config):
        name = plugin_config_key(reporter_class)
        _print_error(
            "[red]Error: reporter '{}' sends findings off the host and is not "
            "enabled. ash report takes whether it runs, and where it sends, from "
            "--config-overrides: pass --config-overrides reporters.{}.enabled=true "
            "and its destination options.[/red]",
            name,
            name,
        )
        raise typer.Exit(1)

    # Generate the report
    try:
        if plugin_config is not None and reporter_class is not None:
            # reporter_section returns the section as get_plugin_config gives it,
            # a plain dict. Assigning that to reporter.config left a dict where
            # every reporter reads attributes, so `self.config.options...` raised
            # AttributeError (junitxml: 'dict' object has no attribute 'options')
            # and the command exited 1. Constructing the reporter with it lets the
            # plugin validate it into its own config model, which is what the
            # report phase of a scan does (core/phases/report_phase.py).
            reporter_plugin = reporter_class(
                context=plugin_context,
                config=plugin_config,
            )
        # The report goes to stdout, but a reporter that writes files of its own
        # writes them to the reports directory. A name among them that is not a file
        # there, or a link at one of them, refuses the command before the reporter
        # runs, as a scan refuses it; the handler below prints why.
        companions = reporter_companion_file_names(reporter_plugin)
        refuse_report_names_outside(
            output_dir_path.joinpath("reports"),
            [],
            [(report_format, name) for name in companions],
        )
        refuse_linked_report_paths(output_dir_path.joinpath("reports"), companions)
        report_content = reporter_plugin.report(model)
        if report_content is None:
            # `report` is annotated `-> str | None`, and a reporter returns None
            # when it could not build its artefact at all. Without this guard the
            # branches below hand None to print()/print_json(), so `ash report`
            # writes the literal "None" to stdout and exits 0 -- a caller
            # redirecting stdout to a file gets a four-byte report and a success
            # status. Exit non-zero instead: the reporter already logged why.
            _print_error(
                "[red]Error: reporter '{}' produced no report. "
                "See the log above for the reason.[/red]",
                report_format,
            )
            raise typer.Exit(1)
        if report_format.lower() in JSON_STDOUT_FORMATS and (
            report_format.lower() not in TEXT_OR_JSON_FORMATS
            or _is_json_document(report_content)
        ):
            # A reporter whose report is a JSON document may return its error
            # text in its place when it could not produce one (the cloudwatch-logs
            # reporter did, after a publish that failed its retries), and the
            # command took any text as a report: off a terminal the text went to
            # stdout as the document and the exit was 0, and on a terminal the
            # json.loads in _write_report failed, so a decode error stood in
            # for the reporter's reason. The text is the reason, so it is the
            # error, and the exit says the report was not produced. Content that
            # is long, on more than one line, or shaped like a JSON document is a
            # report, not a reason, and is described, not quoted
            # (_non_json_report_text).
            try:
                json.loads(report_content)
            except ValueError as exc:
                _print_error(
                    "[red]Error: reporter '{}' did not produce a JSON document: "
                    "{}[/red]",
                    report_format,
                    _non_json_report_text(report_content, exc),
                )
                raise typer.Exit(1)
        try:
            _write_report(
                report_content,
                report_format,
                pretty=(color and not os.environ.get("NO_COLOR")),
            )
        except BrokenPipeError:
            # The reader closed stdout (`ash report | head`): the report was
            # rendered, nobody is reading, and nothing is wrong with it. No
            # error line, and stdout is pointed at the null device so the
            # interpreter's own flush at exit does not report the pipe again;
            # the descriptor opened for it is closed once dup2 has copied it.
            # Exit 1, as Python's own guidance for a closed pipe: the output did
            # not all arrive. Only the write is read this way: a BrokenPipeError
            # from inside a reporter (a subprocess pipe, a socket the remote end
            # closed) is a failed run, reported by the handler below.
            try:
                devnull = os.open(os.devnull, os.O_WRONLY)
                try:
                    os.dup2(devnull, sys.stdout.fileno())
                finally:
                    os.close(devnull)
            except (OSError, ValueError, AttributeError):
                pass
            raise typer.Exit(1)
    except typer.Exit:
        # click.exceptions.Exit subclasses RuntimeError, so the handler below
        # would otherwise catch the deliberate exit above and relabel it
        # "Error generating report: 1".
        raise
    except Exception as e:
        _print_error("[red]Error generating report: {}[/red]", e)
        if debug:
            # The frames, with each pydantic error described, not quoted, and the
            # exception's text again, so shown the way _print_error shows it.
            ash_console(stderr=True, soft_wrap=True, markup=False).print(
                shown_not_obeyed(traceback_text(e))
            )
        raise typer.Exit(1)
