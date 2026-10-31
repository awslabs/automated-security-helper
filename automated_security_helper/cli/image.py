# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Annotated, Optional, List
import typer

from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    cancel_scope,
    shutdown_cancels,
    shutdown_requested,
)

# Import subprocess utilities
from automated_security_helper.core.constants import (
    ASH_CONFIG_SOURCES_DESCRIPTION,
    ASH_EXIT_INTERRUPTED,
    ASH_EXIT_TERMINATED,
)
from automated_security_helper.core.enums import AshLogLevel, BuildTarget, RunMode
from automated_security_helper.interactions.run_ash_scan import (
    resolved_console_log_level,
    run_ash_scan,
)
from automated_security_helper.utils.console import echo
from automated_security_helper.utils.log import configure_last_resort_level


def build_ash_image_cli_command(
    ctx: typer.Context,
    ### CONTAINER-RELATED OPTIONS
    no_build: Annotated[
        bool,
        typer.Option(
            "--no-build",
            help="Skip building the ASH container image; reuse an existing image if present",
        ),
    ] = False,
    no_run: Annotated[
        bool,
        typer.Option(
            "--no-run",
            help="Build the ASH container image but do not run a scan",
        ),
    ] = False,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Force rebuild of the ASH container image",
        ),
    ] = False,
    oci_runner: Annotated[
        Optional[str],
        typer.Option(
            "--oci-runner",
            "--oci",
            "--runner",
            "-r",
            help=(
                "Use the specified OCI runner instead of docker to run the containerized tools. "
                "To prefix every OCI command with a wrapper (e.g. sudo), set the "
                "OCI_RUNNER_WRAPPER environment variable instead of using this option "
                "(e.g. OCI_RUNNER_WRAPPER=sudo ash ...)."
            ),
            envvar="OCI_RUNNER",
        ),
    ] = None,
    container_network: Annotated[
        str,
        typer.Option(
            "--container-network",
            help="Docker network mode for the container run (e.g. 'bridge', 'none', 'host'). "
            "Pass 'none' to force offline/airgapped network isolation independently of --offline.",
        ),
    ] = "bridge",
    build_target: Annotated[
        Optional[BuildTarget],
        typer.Option(
            "--build-target",
            help="The ASH image stage to build: 'non-root' (an unprivileged user, the default) or 'ci' (root, the default on Windows). CI environment variables do not change it.",
            case_sensitive=False,
        ),
    ] = None,
    offline_semgrep_rulesets: Annotated[
        str,
        typer.Option(
            "--offline-semgrep-rulesets",
            help="Specify Semgrep rulesets for use in ASH offline mode",
        ),
    ] = "p/ci",
    container_uid: Annotated[
        Optional[str],
        typer.Option(
            "--container-uid",
            "-u",
            help="UID to use for the container user",
        ),
    ] = None,
    container_gid: Annotated[
        Optional[str],
        typer.Option(
            "--container-gid",
            "-g",
            help="GID to use for the container user",
        ),
    ] = None,
    ash_revision_to_install: Annotated[
        str | None,
        typer.Option(
            help="ASH branch, tag or full commit id to install in the container image for usage during containerized scans",
        ),
    ] = None,
    custom_containerfile: Annotated[
        str | None,
        typer.Option(
            help="Path to a custom container definition (e.g. Dockerfile) that you would like to build *after* the ASH container image builds. This is typically used when building a custom container image for ASH and including custom tooling that ASH does not come with by default. The fully qualified image name for the ASH image is passed in as the `ASH_BASE_IMAGE` build-arg so you can use it as a base. IMPORTANT: When a custom_containerfile path is provided, the build-target is set to `ci` so the container run-as configuration is not shifted to the non-root user. If you are using this parameter, you are responsible for securing your final container as appropriate.",
        ),
    ] = None,
    custom_build_arg: Annotated[
        Optional[List[str]],
        typer.Option(
            help="Custom build arguments to pass to the container build",
        ),
    ] = None,
    config_overrides: Annotated[
        Optional[List[str]],
        typer.Option(
            "--config-overrides",
            help="Configuration overrides specified as key-value pairs (e.g., 'reporters.cloudwatch-logs.options.aws_region=us-west-2')",
        ),
    ] = None,
    # General Options
    offline: Annotated[
        bool,
        typer.Option(
            help="Run scan in offline/airgapped mode. npm-audit does not run offline, because npm, yarn and pnpm audit by asking the registry: a project with a lockfile reports it MISSING, and one without reports it SKIPPED. IMPORTANT: Online access is needed when building ASH to prepare it for usage during a scan! If selecting Offline while performing a build, the ASH container image will be built in offline mode and any typically online-only dependencies like downloadable tool vulnerability databases will be cached in the image itself before publishing for scan usage."
        ),
    ] = False,
    quiet: Annotated[bool, typer.Option(help="Hide all log output")] = False,
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
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug", "-d", help="Enable debug logging")
    ] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
):
    if ctx.resilient_parsing or ctx.invoked_subcommand not in [None, "image"]:
        return

    # Rebind list defaults to fresh empty lists at call time.
    if custom_build_arg is None:
        custom_build_arg = []
    if config_overrides is None:
        config_overrides = []

    # The process-wide last-resort gate, set once at this command's start as
    # `ash scan` sets it (cli/scan.py): a record logged before run_ash_scan
    # attaches its handlers is shown at the verbosity the flags ask for, so
    # --quiet hides it and --debug and --verbose show it. Without this the gate
    # stayed at its import-time default whatever the flags said.
    configure_last_resort_level(
        resolved_console_log_level(
            log_level=log_level,
            verbose=verbose,
            debug=debug,
            quiet=quiet,
            simple=False,
        ).value
    )

    # Call run_ash_scan with all parameters, inside a scope the entry point's
    # SIGTERM handler cancels, as ash scan runs it (cli/scan.py;
    # core/cancellation.py, "SIGTERM on the CLI"). The container scan this
    # starts waits on the OCI runner the same way a scan in container mode does,
    # and the handler cooperates only while a scope is registered: with none, a
    # SIGTERM took the die-now kill instead of the cooperative stop.
    cancel_event = CancelEvent()
    try:
        with shutdown_cancels(cancel_event), cancel_scope(cancel_event):
            run_ash_scan(
                # Container-specific params
                build=not no_build,
                run=not no_run,
                force=force,
                oci_runner=oci_runner,
                container_network=container_network,
                # None picks the host's default: 'ci' on Windows, where the non-root
                # user cannot write the bind-mounted output directory, 'non-root'
                # elsewhere.
                build_target=build_target,
                offline_semgrep_rulesets=offline_semgrep_rulesets,
                container_uid=container_uid,
                container_gid=container_gid,
                ash_revision_to_install=ash_revision_to_install,
                custom_containerfile=custom_containerfile,
                custom_build_arg=custom_build_arg,
                # General params. The scan that follows the build is a container
                # scan, and the container is run with --no-show-summary so that
                # the host prints the one summary (run_ash_container): with False
                # here nobody did, and a scan with actionable findings exited 2
                # with no summary and no exit-code legend. With --no-run nothing
                # is scanned, so there is no summary to show.
                show_summary=not no_run,
                config=config,
                config_overrides=config_overrides,
                offline=offline,
                progress=False,
                log_level=log_level,
                quiet=quiet,
                verbose=verbose,
                debug=debug,
                color=color,
                mode=RunMode.container,
            )
            # The handler only sets the event; the phases raise on their next
            # poll. A SIGTERM that lands where nothing polls (between the image
            # build and the run, in a build step, after a --no-run build) lets
            # run_ash_scan return as if nothing happened, and the command then
            # exited 0 after a termination. The exit says what the handler saw.
            if shutdown_requested():
                raise ScanCancelled(
                    "SIGTERM landed where nothing in the run polled the event"
                )
    except ScanCancelled as error:
        if not shutdown_requested():
            # Not this frame's stop: nothing on the CLI sets the event but the
            # SIGTERM handler, so an unexplained cancel is a defect to report as
            # one, as ash scan reports it.
            raise
        # The handler printed nothing (a signal frame must not take the logger's
        # locks), so this is the only word on how the run ended.
        message = "ASH build-image stopped by SIGTERM before it finished"
        if not no_run:
            message += (
                ": the scan did not complete, and the output directory may hold "
                "partial results"
            )
        survivors = getattr(error, "could_not_stop", ())
        if survivors:
            names = "; ".join(f"{tool} (pid {pid})" for tool, pid in survivors)
            message += f". A tool the stop could not end may still be running: {names}"
        echo(f"{message}.", err=True)
        raise typer.Exit(ASH_EXIT_TERMINATED) from None
    except KeyboardInterrupt:
        # As ash scan does: the runtime has had the interrupt and its grace
        # (run_cmd_direct). The interrupt landed in ONE frame; a cancellable
        # spawn still running in another thread polls the scope's event, so it
        # is cancelled before the exit or that thread keeps running a scan the
        # operator stopped. A normal thread frame, so the real set calls are safe
        # here where the signal handler's are not. With --no-run there was no
        # scan, so no outcome was owed.
        cancel_event.stop_promptly = True
        cancel_event.set()
        message = "ASH build-image interrupted before it finished"
        if not no_run:
            message += (
                ": there is no verdict, and the output directory may hold partial "
                "results"
            )
        echo(f"{message}.", err=True)
        raise typer.Exit(ASH_EXIT_INTERRUPTED) from None
