# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import os
import re
import shlex
import logging
import threading
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple
from pydantic import Field, PrivateAttr, model_validator

from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    ToolExtraArg,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.package_identity import (
    NpmLockIndex,
    identity_properties,
    install_path,
)
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.config.path_trust import honored_path
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sarif_utils import attach_scanner_details
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.content_db_refresh import (
    default_cache_dir,
    prepare_content_db,
    sandboxed_online,
    scan_id_for,
)
from automated_security_helper.utils.process_env import snapshot_environ


#: The trivy misconfiguration scanner that downloads the module sources a .tf file
#: names. See TrivyRepoScanner._offline_misconfig_args.
_TERRAFORM_MISCONFIG_SCANNER = "terraform"

_DEFAULT_MISCONFIG_SCANNERS: Dict[Tuple[str, ...], Optional[List[str]]] = {}
_DEFAULT_MISCONFIG_SCANNERS_LOCK = threading.Lock()


def reset_trivy_default_misconfig_scanners() -> None:
    """Forget the lists trivy_default_misconfig_scanners read (tests)."""
    with _DEFAULT_MISCONFIG_SCANNERS_LOCK:
        _DEFAULT_MISCONFIG_SCANNERS.clear()


def trivy_default_misconfig_scanners(
    binary: str, subcommands: List[str]
) -> Optional[List[str]]:
    """trivy's default ``--misconfig-scanners`` list, as the installed trivy prints it.

    Read from ``<binary> <subcommands> --help`` (the "(default [...])" of that flag)
    rather than written down here, because the list differs between trivy releases
    and trivy given a value it does not know runs every misconfiguration scanner
    instead (measured with trivy 0.74.0). None when the list cannot be read. Read once
    per binary and subcommand.
    """
    key = (binary, *subcommands)
    with _DEFAULT_MISCONFIG_SCANNERS_LOCK:
        if key in _DEFAULT_MISCONFIG_SCANNERS:
            return _DEFAULT_MISCONFIG_SCANNERS[key]
    try:
        result = subprocess_utils.run_command(
            [binary, *subcommands, "--help"],
            capture_output=True,
            text=True,
            timeout=60,
            log_level=logging.DEBUG,
        )
        text = f"{result.stdout or ''}\n{result.stderr or ''}"
    except Exception as error:  # the list is unknown; the caller fails closed
        ASH_LOGGER.debug(
            f"Could not run {binary} {' '.join(subcommands)} --help: {error}"
        )
        text = ""
    match = re.search(r"--misconfig-scanners\b[^\n]*?\(default \[([^\]]*)\]\)", text)
    listed = (
        [name.strip() for name in match.group(1).split(",") if name.strip()]
        if match
        else None
    )
    listed = listed or None
    with _DEFAULT_MISCONFIG_SCANNERS_LOCK:
        _DEFAULT_MISCONFIG_SCANNERS[key] = listed
    return listed


class TrivyRepoScannerConfigOptions(ScannerOptionsBase):
    scanners: Annotated[
        List[Literal["vuln", "misconfig", "secret", "license"]],
        Field(
            description="List of what security issues to detect with Trivy Repo specifically",
        ),
    ] = [
        "vuln",
        "secret",
        "misconfig",
        "license",
    ]
    license_full: Annotated[
        bool,
        Field(
            description="Eagerly look for licenses in source code headers and license files",
        ),
    ] = True
    ignore_unfixed: Annotated[
        bool,
        Field(
            description="Display only fixed vulnerabilities",
        ),
    ] = True
    disable_telemetry: Annotated[
        bool,
        Field(
            description="Disable sending anonymous usage data to Aqua",
        ),
    ] = True
    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, skipping DB updates and check-update calls. When true, this scanner runs offline even if ASH does not. ASH's own offline mode (--offline or ASH_OFFLINE) applies whatever this is set to; false follows it.",
            default=False,
        ),
    ]
    ignore_file: Annotated[
        str | None,
        Field(
            description=(
                "A trivy ignore file, passed as --ignorefile. Used only when it is "
                "outside the scanned tree; a relative path is taken from the source "
                "directory. Unset, TRIVY_IGNOREFILE is used the same way, and "
                "otherwise trivy gets an empty one, so a .trivyignore in the scanned "
                "repository does not remove findings."
            ),
        ),
    ] = None
    secret_config_file: Annotated[
        str | None,
        Field(
            description=(
                "A trivy secret scanning config (trivy-secret.yaml), passed as "
                "--secret-config. Used only when it is outside the scanned tree; a "
                "relative path is taken from the source directory. Unset, "
                "TRIVY_SECRET_CONFIG is used the same way, and otherwise trivy gets "
                "an empty one, so a trivy-secret.yaml in the scanned repository does "
                "not disable secret rules."
            ),
        ),
    ] = None


class TrivyRepoScannerConfig(ScannerPluginConfigBase):
    """Configuration for the Trivy Repo scanner."""

    name: Literal["trivy-repo"] = "trivy-repo"
    enabled: bool = True
    options: Annotated[
        TrivyRepoScannerConfigOptions,
        Field(description="Configure trivy-repo scanner"),
    ] = TrivyRepoScannerConfigOptions()


@ash_scanner_plugin
class TrivyRepoScanner(ScannerPluginBase[TrivyRepoScannerConfig]):
    """Trivy repo scanner plugin."""

    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        # Every place content_db_refresh.default_cache_dir can put trivy's cache:
        # ~/.cache or XDG_CACHE_HOME on Linux, ~/Library/Caches on macOS, and
        # TRIVY_CACHE_DIR. Caches rather than read paths: a cache is read-only on
        # every backend but bwrap, whose overlay throws writes away, and
        # sandbox-exec runs no program from one, where it runs programs from read
        # paths. The database is updated outside the sandbox before an online scan
        # (utils/content_db_refresh.py), and trivy only reads it.
        cache_paths=(
            "~/.cache/trivy",
            "~/Library/Caches/trivy",
            "$XDG_CACHE_HOME/trivy",
            "$TRIVY_CACHE_DIR",
        ),
        env_prefixes=("TRIVY_",),
    )

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.CACHE_FLAGS

    # trivy exits 0 for a completed run, findings or not, unless --exit-code names
    # another code for findings (default 0, pkg/flag/report_flags.go), and 1 from
    # log.Fatal on any error (cmd/trivy/main.go). ASH passes no --exit-code, so 1 is
    # an error. An exit-code set in a trivy.yaml in the scanned directory (trivy
    # reads it from its working directory) or in TRIVY_EXIT_CODE makes a run with
    # findings exit with that code, and it is then recorded as a failed run: 1 is
    # indistinguishable from trivy's own error exit.
    success_exit_codes: ClassVar[Set[int]] = {0}

    # Env vars layered onto the subprocess. Populated by _process_config_options
    # when offline mode is active. Kept on the instance so concurrent scanners
    # do not race on os.environ.
    extra_env: Annotated[dict, Field(default_factory=dict)]

    # The in-tree trivy input files already reported as ignored.
    _warned_inputs: Set[str] = PrivateAttr(default_factory=set)

    def model_post_init(self, context):
        if self.config is None:
            self.config = TrivyRepoScannerConfig()
        self.command = "trivy"
        self.subcommands = ["repository"]
        self.tool_type = ScannerToolType.SAST
        self.args = ToolArgs(
            format_arg="--format",
            format_arg_value="sarif",
            output_arg="--output",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "TrivyRepoScanner":
        """Set up custom installation commands for trivy.

        trivy had no install path inside ASH. It could only arrive from the
        container image, the nix toolchain or a package manager, so a
        ``python-local`` run on a machine without it scanned without it.
        """
        self.custom_install_commands.update(pinned_tool_install_commands("trivy"))
        return self

    def validate_plugin_dependencies(self) -> bool:
        """Validate scanner configuration.

        Returns:
            bool: True if validation passes
        """
        trivy_binary = find_executable("trivy")
        if not trivy_binary or trivy_binary is None:
            return False
        return True

    def _process_config_options(self):
        if len(self.config.options.scanners) > 0:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--scanners",
                    value=",".join(self.config.options.scanners),
                )
            )

        if self.config.options.license_full:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--license-full",
                    value=None,
                )
            )

        if self.config.options.ignore_unfixed:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--ignore-unfixed",
                    value=None,
                )
            )

        if self.config.options.disable_telemetry:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--disable-telemetry",
                    value=None,
                )
            )

        severity_inclusion_map = {
            "LOW": "LOW,MEDIUM,HIGH,CRITICAL",
            "MEDIUM": "MEDIUM,HIGH,CRITICAL",
            "HIGH": "HIGH,CRITICAL",
            "CRITICAL": "CRITICAL",
        }
        threshold = self.config.options.severity_threshold
        if threshold is not None and threshold != "ALL":
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--severity",
                    value=severity_inclusion_map[threshold],
                )
            )

        if self._scanner_offline():
            # --skip-check-update only skips the checks bundle. trivy's version
            # check and its telemetry both contact check.trivy.dev, so offline both
            # are off whatever disable_telemetry says (measured with trivy 0.75.0).
            offline_flags = [
                "--skip-db-update",
                "--skip-java-db-update",
                "--offline-scan",
                "--skip-check-update",
                "--skip-version-check",
            ]
            if not self.config.options.disable_telemetry:
                offline_flags.append("--disable-telemetry")
            for flag in offline_flags:
                self.args.extra_args.append(ToolExtraArg(key=flag, value=None))

            from automated_security_helper.utils.offline_mode_validator import (
                validate_trivy_offline_mode,
            )

            offline_valid, offline_messages = validate_trivy_offline_mode()
            if not offline_valid:
                for msg in offline_messages:
                    self._plugin_log(msg, level=logging.WARNING)

            ASH_LOGGER.info(
                "Running Trivy in offline mode - DB updates and check-update disabled"
            )

        return super()._process_config_options()

    def _offline_misconfig_args(self, final_args: List[str]) -> List[str]:
        """``final_args`` without trivy's Terraform checks, for an offline scan.

        trivy's Terraform scanner fetches the source of every ``module`` block it
        evaluates, with every offline flag ASH passes and with
        ``--tf-exclude-downloaded-modules`` (measured with trivy 0.75.0): a registry
        source contacted registry.terraform.io, a ``git::`` source ran the host's
        git, with the operator's git configuration and credentials, against the URL
        the repository chose, and an ``https://`` archive was downloaded. trivy has
        no setting that stops it. So offline, trivy gets ``--misconfig-scanners``
        naming its own default list without ``terraform``. When that list cannot be
        read from trivy, the misconfiguration scanner is not run offline at all,
        rather than guessed at. checkov still checks Terraform.
        """
        if "misconfig" not in (self.config.options.scanners or []):
            return final_args
        binary = find_executable(self.command) or self.command
        defaults = trivy_default_misconfig_scanners(binary, list(self.subcommands))
        kept = [name for name in defaults or [] if name != _TERRAFORM_MISCONFIG_SCANNER]
        args = list(final_args)
        if kept:
            message = (
                "trivy's Terraform checks are skipped offline: trivy downloads the "
                "module sources a .tf file names, and has no setting that stops it. "
                "checkov still checks Terraform."
            )
            head = [self.command, *self.subcommands]
            insert_at = len(head) if args[: len(head)] == head else len(args)
            args[insert_at:insert_at] = [f"--misconfig-scanners={','.join(kept)}"]
        else:
            message = (
                "trivy's misconfiguration checks are skipped offline: ASH could not "
                f"read trivy's list of them from `{binary} "
                f"{' '.join(self.subcommands)} --help`, so it cannot leave out the "
                "Terraform checks, which download module sources."
            )
            index = args.index("--scanners") if "--scanners" in args else -1
            if index >= 0 and index + 1 < len(args):
                remaining = [
                    name for name in args[index + 1].split(",") if name != "misconfig"
                ]
                if not remaining:
                    raise ScannerError(message)
                args[index + 1] = ",".join(remaining)
        if message not in self._warned_inputs:
            self._warned_inputs.add(message)
            self._plugin_log(message, level=logging.WARNING)
        return args

    def _offline_config_file(self) -> str:
        """The trivy config file (``--config``) for an offline scan.

        Without the flag trivy reads ``trivy.yaml`` from its working directory, the
        source directory. A trivy.yaml in the scanned repository could turn on a VEX
        repository download or client/server mode, and both reach the network
        whatever offline flags ASH passes (measured with trivy 0.75.0). Offline,
        trivy gets ``TRIVY_CONFIG`` when that names a file outside the scanned tree
        (config/path_trust.py), and otherwise the null device, an empty config.
        Online, trivy still reads the tree's trivy.yaml.
        """
        source_dir = Path(self.context.source_dir)
        configured = os.environ.get("TRIVY_CONFIG")
        if configured:
            path = honored_path(
                configured,
                source_dir=source_dir,
                key="TRIVY_CONFIG",
                config=getattr(self.context, "config", None),
            )
            if path is not None:
                if not path.is_file():
                    raise ScannerError(
                        f"TRIVY_CONFIG is {configured!r}, which is not a file "
                        f"(resolved to {path.as_posix()}). Fix the path or unset it; "
                        "trivy is not run without it."
                    )
                return path.as_posix()
        in_tree = source_dir / "trivy.yaml"
        if in_tree.is_file() and in_tree.as_posix() not in self._warned_inputs:
            self._warned_inputs.add(in_tree.as_posix())
            self._plugin_log(
                f"Ignoring {in_tree.as_posix()} in offline mode: it is inside the "
                "scanned tree, and its settings can reach the network. Set "
                "TRIVY_CONFIG to a file outside the tree to use one.",
                level=logging.WARNING,
            )
        return os.devnull

    def _ignore_file(self) -> str:
        """The file trivy reads finding IDs to ignore from (``--ignorefile``)."""
        return self._trivy_input_file(
            option="ignore_file",
            env="TRIVY_IGNOREFILE",
            default_name=".trivyignore",
            ash_name="trivyignore-empty",
            ash_content="",
        )

    def _secret_config_file(self) -> str:
        """The file trivy reads secret rules from (``--secret-config``)."""
        return self._trivy_input_file(
            option="secret_config_file",
            env="TRIVY_SECRET_CONFIG",
            default_name="trivy-secret.yaml",
            ash_name="trivy-secret-empty.yaml",
            # An empty file is a decode error in trivy; an empty mapping is not.
            ash_content="{}\n",
        )

    def _trivy_input_file(
        self,
        *,
        option: str,
        env: str,
        default_name: str,
        ash_name: str,
        ash_content: str,
    ) -> str:
        """A file to pass trivy for an input it would otherwise read from its cwd.

        Without the flag, trivy reads ``default_name`` (``.trivyignore``,
        ``trivy-secret.yaml``) from its working directory, the source directory,
        so the scanned repository could remove findings from its own report
        (measured with trivy 0.75.0). The operator's file, from the option or the
        environment variable, is used when it is outside the scanned tree
        (config/path_trust.py); a refused option falls through to the variable.
        Otherwise trivy gets a file ASH writes into the results directory, which
        sets nothing.
        """
        context_config = getattr(self.context, "config", None)
        source_dir = Path(self.context.source_dir)
        for key, value in (
            (
                f"scanners.trivy-repo.options.{option}",
                getattr(self.config.options, option),
            ),
            (env, os.environ.get(env)),
        ):
            if not value:
                continue
            path = honored_path(
                value, source_dir=source_dir, key=key, config=context_config
            )
            if path is None:
                continue
            if not path.is_file():
                raise ScannerError(
                    f"{key} is {value!r}, which is not a file (resolved to "
                    f"{path.as_posix()}). Fix the path or unset it; trivy is not run "
                    "without it."
                )
            return path.as_posix()
        in_tree = source_dir / default_name
        if in_tree.is_file() and in_tree.as_posix() not in self._warned_inputs:
            self._warned_inputs.add(in_tree.as_posix())
            self._plugin_log(
                f"Ignoring {in_tree.as_posix()}: it is inside the scanned tree. Set "
                f"scanners.trivy-repo.options.{option} to a file outside the tree "
                "to use one.",
                level=logging.WARNING,
            )
        if self.results_dir is None:
            raise ScannerError("TrivyRepoScanner has no results directory")
        written = Path(os.path.abspath(self.results_dir)) / ash_name
        written.parent.mkdir(parents=True, exist_ok=True)
        with open_for_write(written) as handle:
            handle.write(ash_content)
        return written.as_posix()

    @staticmethod
    def _package_from_message(message: str | None) -> tuple[str | None, str | None]:
        """Name and version from trivy's vulnerability message.

        trivy writes ``Package: <name>`` and ``Installed Version: <version>``
        as their own lines. A message without them (a misconfiguration or
        secret finding) is not about a package.
        """
        name = version = None
        for line in (message or "").splitlines():
            if line.startswith("Package: "):
                name = line[len("Package: ") :].strip() or None
            elif line.startswith("Installed Version: "):
                version = line[len("Installed Version: ") :].strip() or None
        return name, version

    def _attach_package_identity(
        self, sarif_report: SarifReport, target: Path
    ) -> SarifReport:
        """Give each dependency result one package copy and say which it is.

        trivy groups packages by name and version before matching, so the same
        version installed at two places in one lockfile becomes ONE result with
        one location per copy. No suppression can then cover one copy and not
        the other. For npm lockfiles, each location's line is the line of that
        copy's ``packages`` key, so such a result is split into one result per
        location, each with ``package_path``. Results whose locations do not
        all resolve to a lockfile entry are left whole.
        """
        lock_index = NpmLockIndex(target)
        for run in sarif_report.runs or []:
            new_results = []
            for result in run.results or []:
                message = result.message.root.text if result.message else None
                name, version = self._package_from_message(message)
                if name is None:
                    new_results.append(result)
                    continue

                resolved = []
                for location in result.locations or []:
                    physical = location.physicalLocation
                    root = physical.root if physical else None
                    uri = (
                        root.artifactLocation.uri
                        if root and root.artifactLocation
                        else None
                    )
                    line = root.region.startLine if root and root.region else None
                    # Relativized the same way as grype's, so package_path is
                    # POSIX and scan-root-relative whatever form trivy used.
                    lock_rel = lock_index.relative(uri) if uri else None
                    entry = (
                        lock_index.by_line(lock_rel, line)
                        if lock_rel and line
                        else None
                    )
                    resolved.append(
                        install_path(lock_rel, entry.key)
                        if lock_rel and entry is not None
                        else None
                    )

                if resolved and all(resolved):
                    for location, path in zip(result.locations or [], resolved):
                        copy = result.model_copy(deep=True)
                        copy.locations = [location.model_copy(deep=True)]
                        self._set_identity(copy, name, version, path)
                        new_results.append(copy)
                else:
                    path = resolved[0] if len(resolved) == 1 else None
                    self._set_identity(result, name, version, path)
                    new_results.append(result)
            run.results = new_results
        return sarif_report

    @staticmethod
    def _set_identity(result, name, version, path) -> None:
        identity = identity_properties(name, version, path)
        if result.properties is None:
            result.properties = PropertyBag.model_validate(identity)
        else:
            for key, value in identity.items():
                setattr(result.properties, key, value)

    def content_databases_in_use(self) -> list:
        """trivy-db, unless the scan's ``--scanners`` leave out ``vuln``.

        The secret, misconfiguration and license scanners never open it. An empty
        ``scanners`` list passes no ``--scanners``, so trivy runs its own default
        (``vuln,secret``, pkg/flag/scan_flags.go) or what a trivy.yaml says, and the
        database is held to its bounds then too.
        """
        scanners = self.config.options.scanners or []
        if scanners and "vuln" not in scanners:
            return []
        return super().content_databases_in_use()

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        """Abstract stub — TrivyRepoScanner overrides scan() directly; this is unreachable."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        config: Any | None = None,
        *args,
        **kwargs,
    ) -> SarifReport | bool | None:
        """Scan a target file/directory.

        This example scanner simply logs the target and returns a mock finding.

        Args:
            target: Target file or directory to scan
            target_type: Type of target (source or converted)
            global_ignore_paths: List of paths to ignore
            config: Scanner configuration

        Returns:
            dict: Scan results
        """
        # Check if the target directory is empty or doesn't exist
        if not target.exists() or not any(target.iterdir()):
            message = (
                f"Target directory {target} is empty or doesn't exist. Skipping scan."
            )
            self._plugin_log(
                message,
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return True

        validated = self._pre_scan(
            target=target,
            target_type=target_type,
            config=config,
        )
        if not validated:
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        if not self.dependencies_satisfied:
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        try:
            target_results_dir = self.results_dir.joinpath(target_type)
            results_file = target_results_dir.joinpath("results_sarif.sarif")
            target_results_dir.mkdir(exist_ok=True, parents=True)

            final_args = self._resolve_arguments(
                target=target,
                results_file=results_file,
            )
            # Right after `trivy repository`, which needs no knowledge of how the
            # target is spelled further on; trivy takes flags in any position.
            head = [self.command, *self.subcommands]
            insert_at = (
                len(head) if final_args[: len(head)] == head else len(final_args)
            )
            subprocess_env = (
                {**snapshot_environ(), **self.extra_env} if self.extra_env else None
            )
            # The database's directory, resolved once as trivy resolves it on this
            # host and named to the scan, the refresh and the staleness check alike:
            # the sandbox drops XDG_CACHE_HOME, and the flag beats a cache.dir in a
            # trivy.yaml, the scanned repository's included. See "Which cache" in
            # utils/content_db_refresh.py.
            cache = default_cache_dir("trivy", subprocess_env or snapshot_environ())
            self._content_db_cache_dir = cache
            final_args[insert_at:insert_at] = [
                f"--ignorefile={self._ignore_file()}",
                f"--secret-config={self._secret_config_file()}",
                f"--cache-dir={cache.as_posix()}",
                *(
                    [f"--config={self._offline_config_file()}"]
                    if self._scanner_offline()
                    else []
                ),
            ]
            if self._scanner_offline():
                final_args = self._offline_misconfig_args(final_args)
            cache_flags: List[str] = []
            if sandboxed_online(self._scanner_offline()):
                # The sandbox mounts trivy's cache read-only, so its database (and
                # the checks bundle, for misconfiguration scans) is updated first,
                # outside the sandbox, and trivy only reads it: no update of its
                # own. See utils/content_db_refresh.py. Not the Java database:
                # `trivy repository` does not analyze JAR, WAR or EAR files and never
                # reads it (measured with trivy 0.75), so its update is skipped
                # rather than downloading about 935 MiB the scan would not use.
                checks = "misconfig" in (self.config.options.scanners or [])
                prepare_content_db(
                    "trivy",
                    cache,
                    offline=False,
                    source_dir=self.context.source_dir,
                    results_dir=self.results_dir or target_results_dir,
                    config=getattr(self.context, "config", None),
                    checks=checks,
                    scan_id=scan_id_for(self.context),
                )
                cache_flags += [
                    "--skip-db-update",
                    "--skip-java-db-update",
                    *(["--skip-check-update"] if checks else []),
                ]
            # Every run, sandboxed or not, online or offline: trivy keeps its scan
            # cache (fanal/fanal.db) in the cache directory, which every sandbox
            # backend but bwrap mounts read-only, and which can be read-only with
            # no sandbox at all (a shared or image-baked cache). Measured with trivy
            # 0.75.0 against a read-only cache, offline, sandboxed and not: "unable
            # to initialize fs cache: failed to create cache dir ... permission
            # denied", exit 1, and with --cache-backend=memory the same scan's
            # findings. The scan cache only saves re-analysing an unchanged target,
            # so the results are the same either way.
            cache_flags.append("--cache-backend=memory")
            final_args[insert_at:insert_at] = cache_flags

            self._plugin_log(
                f"Running command: {' '.join(final_args)}",
                target_type=target_type,
                level=logging.VERBOSE,
            )

            response = self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
                env=subprocess_env,
                timeout=self._effective_scan_timeout(),
            )
            self._record_target_exit_code(response)
            self._refuse_rejected_exit_code(results_file)

            # SARIF mode - parse SARIF results
            if Path(results_file).exists():
                with open(results_file, mode="r", encoding="utf-8") as f:
                    scanner_results = json.load(f)
                try:
                    sarif_report: SarifReport = SarifReport.model_validate(
                        scanner_results
                    )
                    sarif_report = self._attach_package_identity(sarif_report, target)

                    # Attach scanner details for proper identification
                    sarif_report = attach_scanner_details(
                        sarif_report=sarif_report,
                        scanner_name=self.config.name,
                        scanner_version=getattr(self, "tool_version", None),
                        invocation_details={
                            "command_line": " ".join(final_args),
                            "arguments": final_args[1:],
                            "working_directory": get_shortest_name(input=target),
                            "start_time": self.start_time.isoformat()
                            if self.start_time
                            else None,
                            "end_time": self.end_time.isoformat()
                            if self.end_time
                            else None,
                            "exit_code": self.exit_code,
                        },
                    )

                    if sarif_report.runs:
                        sarif_report.runs[0].invocations = [
                            Invocation(
                                commandLine=shlex.join(final_args),
                                arguments=final_args[1:],
                                startTimeUtc=self.start_time,
                                endTimeUtc=self.end_time,
                                executionSuccessful=self._exit_code_accepted(),
                                exitCode=self.exit_code,
                                exitCodeDescription="\n".join(self.errors),
                                workingDirectory=ArtifactLocation(
                                    uri=get_shortest_name(input=target),
                                ),
                            )
                        ]
                    self._post_scan(
                        target=target,
                        target_type=target_type,
                    )
                    return sarif_report
                except Exception as e:
                    self._plugin_log(
                        f"Failed to parse {self.__class__.__name__} results as SARIF: {str(e)}",
                        target_type=target_type,
                        level=logging.ERROR,
                        append_to_stream="stderr",
                    )
                    self._post_scan(
                        target=target,
                        target_type=target_type,
                    )
                    return
            else:
                self._plugin_log(
                    f"No results file found at {results_file}",
                    target_type=target_type,
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )
                self._post_scan(
                    target=target,
                    target_type=target_type,
                )

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"Trivy scan failed: {str(e)}")
