# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from enum import Enum
from pathlib import Path
from typing import Any

import typer
from typer.core import TyperGroup

# The vendored click, as in cli/json_input.py: Typer's commands raise this copy's
# exceptions, not the `click` distribution's.
from typer._click.exceptions import UsageError

from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.cli.config import config_app
from automated_security_helper.cli.dependencies import dependencies_app
from automated_security_helper.cli.image import build_ash_image_cli_command
from automated_security_helper.cli.inspect import inspect_app
from automated_security_helper.cli.json_input import (
    CliJsonInputCommand,
    usage_error_text,
)
from automated_security_helper.cli.merge import merge_command
from automated_security_helper.cli.plugin import plugin_app
from automated_security_helper.cli.scan import run_ash_scan_cli_command
from automated_security_helper.cli.report import report_command
from automated_security_helper.core.enums import AshLogLevel
from automated_security_helper.utils.console import echo, typer_console
from automated_security_helper.utils.log import show_debug_locals
from automated_security_helper.utils.terminal_text import shown_not_obeyed


def _shown_usage_error(exc: UsageError) -> BaseException:
    """Print *exc* as typer prints a usage error, through ASH's console, and return
    the exit to raise in its place.

    typer prints a usage error with its own Rich console, which writes the text as
    given, and click quotes an unknown option's name raw. An argument is often
    supplied by CI (a branch name, a PR title), so a "##vso[" in it, which Azure
    Pipelines reads anywhere in a line, or a newline then "::", reached the log.
    The layout keeps typer's usage line and help hint; the message itself
    prints as ASH's own one-line "Error: " form, unwrapped, so a token's
    content cannot change the layout (see the comment at the print). The
    text goes through terminal_text's shown_not_obeyed, and the console is one
    of ASH's, so the factory's stream check covers every line. typer's own
    NoArgsIsHelpError prints nothing there and is returned as is.
    """
    if type(exc).__name__ == "NoArgsIsHelpError":
        return exc
    from rich.text import Text
    from typer.rich_utils import highlighter

    # typer's console settings and option highlighting, so the error reads as
    # typer prints it; the highlighter only colors the text it is given.
    console = typer_console()
    ctx = exc.ctx
    if ctx is not None:
        console.print(highlighter(shown_not_obeyed(ctx.get_usage())), style="bold")
        if ctx.command.get_help_option(ctx) is not None:
            hint = f"'{ctx.command_path} {ctx.help_option_names[0]}'"
            console.print(
                Text.assemble("Try ", (shown_not_obeyed(hint), "blue"), " for help."),
                style="dim",
            )
    message = usage_error_text(exc)
    # One line, unwrapped, for every usage error. Most of these messages
    # carry an argv token as typed. A bordered panel wraps at spaces, breaks
    # a token wider than its line mid-run, and measures width in cells
    # rather than characters, so its layout depended on the token.
    # usage_error_text puts the message on one line, and this prints it as
    # the only output line, starting with ASH's own "Error: ". typer's
    # highlighter keeps the option coloring; it only colors the text it is
    # given.
    error_line = Text("Error: ", style="bold red")
    error_line.append_text(highlighter(message))
    console.print(error_line, soft_wrap=True)
    return typer.Exit(ASH_EXIT_USAGE_ERROR)


def _option_tokens(given: Any, target: Any, value: Any) -> list[str] | None:
    """Spell *value*, parsed by the root's option *given*, as tokens for *target*.

    None when *target* cannot take it the same way: it is not an option, it counts,
    takes several values per use, or differs from *given* in being a flag or in being
    repeatable. The target's own first long spelling is used, so a short alias that
    means something else on the subcommand (``-f`` is ``--output-formats`` on scan and
    ``--force`` on build-image) never decides what the token means.
    """
    if (
        getattr(target, "param_type_name", None) != "option"
        or target.count
        or target.nargs != 1
        or target.is_flag != given.is_flag
        or target.multiple != given.multiple
    ):
        return None
    spelling = next((opt for opt in target.opts if opt.startswith("--")), None)
    if spelling is None:
        return None
    if target.is_flag:
        if not target.is_bool_flag:
            return None
        if value:
            return [spelling]
        negative = next(
            (opt for opt in target.secondary_opts if opt.startswith("--")), None
        )
        return [negative] if negative is not None else None
    tokens: list[str] = []
    for item in value if target.multiple else [value]:
        tokens += [spelling, str(item.value if isinstance(item, Enum) else item)]
    return tokens


def _typed_spelling(param: Any, tokens: list[str]) -> str:
    """The spelling of *param* the operator typed among *tokens*, else its first one."""
    long_names = [
        opt for opt in (*param.opts, *param.secondary_opts) if opt[:2] == "--"
    ]
    short_names = [
        opt for opt in (*param.opts, *param.secondary_opts) if opt[:2] != "--"
    ]
    for token in tokens:
        if token.split("=", 1)[0] in long_names:
            return token.split("=", 1)[0]
        if token[:2] != "--":
            # click lets a short option's value, or further short flags, follow it.
            for name in short_names:
                if token.startswith(name):
                    return name
    return param.opts[0]


class AshTyperGroup(TyperGroup):
    """The root ``ash`` group: every usage error in the tree exits ASH_EXIT_USAGE_ERROR.

    click exits 2 for a usage error (an unknown option or command, a bad choice, a
    missing argument), and 2 is ASH's code for actionable findings, so a CI gate read
    a mistyped flag as a scan that found problems. Every such error raised anywhere
    below this group passes through its ``make_context`` (the root's own options) or
    its ``invoke`` (subcommands, their parsing, and the ``typer.BadParameter`` or
    ``UsageError`` ASH raises from a command body), so setting the code here covers
    every subcommand, including ones added later, without handling any option on its
    own. click's own handler then prints the error as usual and exits with the code.

    It also passes options given to ``ash`` before a subcommand on to that
    subcommand. The root takes the scan's options so that a bare ``ash`` scans; with
    a subcommand, its callback returns without scanning, and the options were parsed
    and then dropped: ``ash --source-dir /elsewhere scan`` scanned the working
    directory, and ``ash --output-dir out report`` read the default output directory.
    """

    def parse_args(self, ctx: Any, args: list[str]) -> list[str]:
        # Kept so a refusal below can name the spelling the operator typed: once
        # parsed, `-f` and `--format` are both just output_formats.
        ctx.meta["ash.root_argv"] = list(args)
        return super().parse_args(ctx, args)

    def make_context(
        self,
        info_name: str | None,
        args: list[str],
        parent: Any = None,
        **extra: Any,
    ) -> Any:
        try:
            return super().make_context(info_name, args, parent=parent, **extra)
        except UsageError as exc:
            exc.exit_code = ASH_EXIT_USAGE_ERROR
            shown = _shown_usage_error(exc)
            if shown is exc:  # typer's NoArgsIsHelpError, which prints nothing
                raise
            raise shown from exc

    def invoke(self, ctx: Any) -> Any:
        try:
            if ctx._protected_args and not ctx.resilient_parsing:
                # TyperGroup.invoke hands the subcommand everything after its name, so
                # tokens put first here are parsed as though written right after it:
                # an option the subcommand is also given directly resolves to that
                # later value, and a repeatable one collects both.
                ctx.args = [*self._options_for_subcommand(ctx), *ctx.args]
            return super().invoke(ctx)
        except UsageError as exc:
            exc.exit_code = ASH_EXIT_USAGE_ERROR
            shown = _shown_usage_error(exc)
            if shown is exc:  # typer's NoArgsIsHelpError, which prints nothing
                raise
            raise shown from exc

    def _options_for_subcommand(self, ctx: Any) -> list[str]:
        """The root options typed before the subcommand, spelled for the subcommand.

        Only options typed on the command line are passed on. One set through its
        environment variable (``ASH_SOURCE_DIR``) reaches the subcommand through the
        same variable. An option the subcommand does not take is a usage error, not a
        token that would be dropped again.
        """
        given = [
            param
            for param in self.get_params(ctx)
            if param.name is not None
            and getattr(ctx.get_parameter_source(param.name), "name", None)
            == "COMMANDLINE"
        ]
        if not given:
            return []
        name = ctx._protected_args[0]
        command = self.get_command(ctx, name)
        if command is None:
            # Not a command; super().invoke reports it as one.
            return []
        if set(ctx.args) & set(command.get_help_option_names(ctx)):
            # The subcommand prints its help and exits; nothing given here is used.
            return []
        declared = {
            param.name: param
            for param in command.get_params(ctx)
            if param.name is not None
        }
        tokens: list[str] = []
        refused = []
        for param in given:
            target = declared.get(param.name)
            spelled = (
                None
                if target is None
                else _option_tokens(param, target, ctx.params[param.name])
            )
            if spelled is None:
                refused.append(param)
            else:
                tokens.extend(spelled)
        if refused:
            argv = ctx.meta.get("ash.root_argv", [])
            before = argv[: len(argv) - len(ctx._protected_args) - len(ctx.args)]
            spellings = ", ".join(_typed_spelling(param, before) for param in refused)
            them = "it" if len(refused) == 1 else "them"
            ctx.fail(
                f"'ash {name}' does not take {spellings}, given before it (see "
                f"'ash {name} --help'). Options given before a subcommand are passed "
                f"to it only when it takes them: drop {them}, give {them} after a "
                f"subcommand that takes {them}, or leave out '{name}' to scan with "
                f"{them}."
            )
        return tokens


app = typer.Typer(
    name="ash",
    cls=AshTyperGroup,
    help="Automated Security Helper · one workflow for your security scanners.",
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    # Not on a CI runner: locals can hold secrets (utils/log.py).
    pretty_exceptions_show_locals=show_debug_locals(),
)

# Neither `scan` nor `build-image` sets click's ignore_unknown_options or
# allow_extra_args, so every argument is one the command declares or a usage
# error. Nothing hands the context to the container runner, so with them a
# misspelled option or a stray argument would be collected into ctx.args and
# dropped, and the command would run as though it had not been given.
app.callback(invoke_without_command=True)(run_ash_scan_cli_command)
app.command(
    name="scan",
    cls=CliJsonInputCommand,
    no_args_is_help=False,
)(run_ash_scan_cli_command)

app.command(
    name="build-image",
    cls=CliJsonInputCommand,
    no_args_is_help=False,
    help="""Builds the ASH container image, then scans the current directory with it unless --no-run is given.

It takes only the options below. To scan with scan options, run `ash scan --mode container`, which builds the image the same way and accepts every scan option.
""",
)(build_ash_image_cli_command)

app.command(name="report", cls=CliJsonInputCommand)(report_command)

app.command(
    name="merge",
    cls=CliJsonInputCommand,
    help="""Merges the results of a sharded scan into one unified report.

Pass one --results per shard. The command refuses to merge a set of shards that does not reconstruct exactly one whole scan, and its exit code is the verdict for the union — a shard that owned no failing scanner exits 0, so CI must gate on this command rather than on per-shard success.
""",
)(merge_command)


@app.command(name="mcp", help="Start the ASH MCP server (Model Context Protocol)")
def _mcp_wrapper(
    ctx: typer.Context,
    log_level: AshLogLevel = typer.Option(
        AshLogLevel.INFO,
        "--log-level",
        help="Set the log level.",
        case_sensitive=False,
    ),
    verbose: bool = typer.Option(
        False, "--verbose/--no-verbose", "-v", help="Enable verbose logging"
    ),
    debug: bool = typer.Option(
        False, "--debug/--no-debug", "-d", help="Enable debug logging"
    ),
    color: bool = typer.Option(True, help="Enable/disable colorized output"),
    quiet: bool = typer.Option(False, help="Hide all log output"),
    transport: str = typer.Option(
        "stdio",
        "--transport",
        help="Transport: 'stdio' (default), 'streamable-http', or 'sse'.",
    ),
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Host to bind for HTTP transports.",
    ),
    port: int = typer.Option(
        8000,
        "--port",
        help="Port to bind for HTTP transports.",
    ),
    mount_path: str = typer.Option(
        "/mcp",
        "--mount-path",
        help="HTTP path the transport listens on (default: /mcp for streamable-http, /sse for sse).",
    ),
    auth_header_name: str | None = typer.Option(
        None,
        "--auth-header-name",
        help="Required HTTP header name for single-tenant auth (HTTP transports only).",
    ),
    auth_header_value: str | None = typer.Option(
        None,
        "--auth-header-value",
        help="Expected value of --auth-header-name. Visible to other local users "
        "on the command line; prefer --auth-header-value-file or "
        "--auth-header-value-fd.",
    ),
    auth_header_value_file: Path = typer.Option(
        None,
        "--auth-header-value-file",
        help="Read the expected value of --auth-header-name from this file, once at "
        "startup: a regular file, not a symlink, readable by its owner only. One "
        "trailing newline is dropped.",
    ),
    auth_header_value_fd: int = typer.Option(
        None,
        "--auth-header-value-fd",
        help="Read the expected value of --auth-header-name from this inherited "
        "file descriptor (3 or above), once at startup, then close it.",
    ),
    stateless_http: bool = typer.Option(
        False,
        "--stateless-http/--no-stateless-http",
        help="Handle each streamable-HTTP request independently instead of "
        "binding it to a server-held session. Required behind a load balancer "
        "that may route consecutive requests to different replicas, and by "
        "managed runtimes that inject their own Mcp-Session-Id. Only valid "
        "with --transport streamable-http.",
    ),
    trust_upstream_session_id: bool = typer.Option(
        False,
        "--trust-upstream-session-id",
        help="Stateless streamable-HTTP only. Declare that a platform in front of "
        "ASH issues and authenticates the Mcp-Session-Id header, so it can name "
        "the caller's session. Without it a stateless server identifies no "
        "session, and tools that need one (source delivery, profiles, the scan "
        "registry) refuse.",
    ),
    allowed_host: list[str] | None = typer.Option(
        None,
        "--allowed-host",
        help="Host header value to accept, repeatable. Keeps DNS-rebinding "
        "protection enabled while allowing a known proxy or load balancer "
        "hostname. Required with a non-loopback --host unless "
        "--trust-upstream-host-check is given.",
    ),
    session_workspace_ttl: int | None = typer.Option(
        None,
        "--session-workspace-ttl",
        help="HTTP transports only. Seconds a session workspace (delivered source, "
        "uploads, bound profile) may go unused before it is removed. Covers "
        "sessions whose end the server cannot see, such as every stateless one. "
        "Default: 86400 (24 hours).",
    ),
    trust_upstream_host_check: bool = typer.Option(
        False,
        "--trust-upstream-host-check",
        help="HTTP transports only. Declare that a proxy or platform in front of "
        "ASH checks the Host and Origin headers, so ASH serves any. Without it, a "
        "non-loopback --host needs --allowed-host or the server refuses to start. "
        "Cannot be combined with --allowed-host.",
    ),
    profile: list[str] | None = typer.Option(
        None,
        "--profile",
        help="Register a named config profile as NAME=path/to/ash.yaml, "
        "repeatable. Clients list them with the list_profiles tool and bind "
        "one to their session with select_profile; a bound profile supplies "
        "the config for every later call in that session that names none. "
        "Each file is loaded and schema-validated now, so a typo fails "
        "startup rather than a scan.",
    ),
):
    """Lazy wrapper that imports and delegates to the real MCP command.

    Importing cli/mcp loads the MCP SDK, which would cost every other ash
    command about 0.6 s at startup, so instead of registering mcp_command
    directly its options are declared here a second time. Each declaration must
    match mcp_command's exactly, flags, default and help text, and each value
    must be forwarded below: an option declared only on mcp_command cannot be
    passed at all, which is how --profile was unreachable.
    tests/unit/cli/mcp/test_mcp_cli_wrapper_parity.py compares the two lists
    and checks the forwarding.
    """
    from automated_security_helper.cli.mcp import mcp_command

    mcp_command(
        ctx=ctx,
        log_level=log_level,
        verbose=verbose,
        debug=debug,
        color=color,
        quiet=quiet,
        transport=transport,
        host=host,
        port=port,
        mount_path=mount_path,
        auth_header_name=auth_header_name,
        auth_header_value=auth_header_value,
        auth_header_value_file=auth_header_value_file,
        auth_header_value_fd=auth_header_value_fd,
        stateless_http=stateless_http,
        trust_upstream_session_id=trust_upstream_session_id,
        allowed_host=allowed_host,
        trust_upstream_host_check=trust_upstream_host_check,
        session_workspace_ttl=session_workspace_ttl,
        profile=profile,
    )


@app.command(name="get-genai-guide")
def get_genai_guide(
    output_path: str = typer.Option(
        "ash-genai-guide.md",
        "--output",
        "-o",
        help="Output path for the GenAI integration guide",
    ),
    from_github: bool = typer.Option(
        False,
        "--from-github",
        help="Fetch from GitHub instead of local installation",
    ),
    branch: str = typer.Option(
        "main",
        "--branch",
        "-b",
        help="GitHub branch to fetch from when using --from-github (default: main)",
    ),
):
    """Write the ASH GenAI Integration Guide for AI assistants and LLMs to a file.

    This guide provides comprehensive instructions for GenAI tools on how to properly
    interact with ASH scan results, including:
    - Correct file formats to use (JSON vs HTML)
    - Creating suppressions properly
    - Working with CycloneDX SBOM for dependencies
    - Configuration file schema
    - Common pitfalls and solutions
    """
    import requests
    from pathlib import Path

    guide_content = None
    source = None

    # The guide of the installed ASH, unless --from-github asks for GitHub's. A
    # checkout has it in docs/, which is the copy to read there because it is the
    # one being edited; a wheel carries it in the package's assets/ (hatch_build.py
    # puts it there). With neither, the command refuses rather than downloading:
    # GitHub's `main` is not the installed version's guide, and on a host without
    # network access the download only fails.
    if not from_github:
        package_dir = Path(__file__).parent.parent
        candidates = [
            package_dir.parent.joinpath(
                "docs", "content", "docs", "genai-steering-guide.md"
            ),
            package_dir.joinpath("assets", "genai-steering-guide.md"),
        ]
        guide_path = next((path for path in candidates if path.is_file()), None)
        try:
            if guide_path is None:
                raise FileNotFoundError(candidates[-1].as_posix())
            guide_content = guide_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            echo(
                "Error: this ASH installation has no readable copy of the GenAI "
                f"Integration Guide ({e}). Pass --from-github to download it, with "
                "--branch <tag> for the guide of a given release.",
                err=True,
            )
            raise typer.Exit(1)
        source = "local"

    if guide_content is None:
        github_url = f"https://raw.githubusercontent.com/awslabs/automated-security-helper/{branch}/docs/content/docs/genai-steering-guide.md"

        try:
            echo(f"Fetching GenAI Integration Guide from GitHub ({branch} branch)...")
            response = requests.get(github_url, timeout=10)
            response.raise_for_status()
            guide_content = response.text
            source = "github"
        except requests.RequestException as e:
            echo(f"Error: Could not fetch from GitHub: {e}", err=True)
            echo("\nYou can download it directly from:", err=True)
            echo(github_url, err=True)
            raise typer.Exit(1)

    # Write to output file, as a new file renamed over the destination: a symlink
    # there is refused rather than written through (fs_guard).
    from automated_security_helper.utils.output_dir_links import OutputDirLinkRefused
    from automated_security_helper.utils.sandbox.fs_guard import (
        replace_without_following,
    )

    output_file = Path(output_path)
    # A destination whose directory is not there yet is made, as `ash scan
    # --output-dir` and `ash config init` make theirs. Without this the guarded
    # create below ran in a directory that did not exist and ended in an uncaught
    # FileNotFoundError traceback. A file, or a link to nothing, in the directory's
    # place is a refusal in the command's own words, not a traceback either.
    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        echo(
            f"Error: cannot create the directory for {output_file.absolute()}: {e}",
            err=True,
        )
        raise typer.Exit(1)
    # Written as it was read: UTF-8, because the guide holds characters a C,
    # latin-1 or Windows ANSI locale's codec cannot encode.
    try:
        replace_without_following(output_file, guide_content)
    except OutputDirLinkRefused as refused:
        # The family's base, a symlink or a file another name refers to alike.
        echo(f"Error: {refused}", err=True)
        raise typer.Exit(1)

    # ASCII only: the file is already written, and a console that cannot encode a
    # check mark or a bullet (latin-1, ASCII) must not turn that into exit 1.
    echo(f"GenAI Integration Guide saved to: {output_file.absolute()}")
    if source:
        echo(f"  Source: {source}")
    echo(f"  File size: {len(guide_content):,} bytes")
    echo("\nThis guide can be provided to AI assistants to help them:")
    echo("  - Use the correct ASH output formats (JSON, not HTML)")
    echo("  - Create suppressions correctly")
    echo("  - Analyze dependencies using CycloneDX SBOM")
    echo("  - Avoid common pitfalls and known issues")


app.add_typer(config_app, name="config")
app.add_typer(dependencies_app, name="dependencies")
app.add_typer(inspect_app, name="inspect")
app.add_typer(plugin_app, name="plugin")


def reset_logging_config():
    """Reset ASH's logging configuration to prevent duplicate handlers.

    Only the handlers ASH added are removed (utils/log.py's remove_ash_handlers):
    a handler something else put on the root logger or on "ash" stays.
    """
    import logging

    from automated_security_helper.utils.log import remove_ash_handlers

    remove_ash_handlers(logging.getLogger())
    ash_logger = logging.getLogger("ash")
    remove_ash_handlers(ash_logger)

    # Disable propagation for the ASH logger
    ash_logger.propagate = False


def run_app():
    """Run the ASH application with clean logging configuration."""
    # Reset logging configuration to prevent duplicate messages
    reset_logging_config()

    # Run the application
    app()


if __name__ == "__main__":
    # Routed through the console scripts' entry point so running this file
    # directly gets the same guaranteed-diagnosable failure path they do.
    from automated_security_helper.cli.entrypoint import main

    main()
