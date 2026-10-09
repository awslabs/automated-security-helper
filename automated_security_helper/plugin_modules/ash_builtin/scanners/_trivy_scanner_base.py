# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the builtin ``trivy`` scanner and the community ``trivy-repo`` scanner share.

Why this module exists
----------------------
trivy reached ASH first as the community plugin ``trivy-repo``
(``plugin_modules/ash_trivy_plugins``), which users enable through
``ash_plugin_modules``. The builtin ``trivy`` scanner runs the same binary, so the
logic that turns options into trivy flags, installs the pinned binary, and ties a
vulnerability result to one package copy lives here once instead of being copied
into a second module that would drift from the first.

Only behaviour is shared. Each scanner keeps its own config classes, because their
names and defaults differ (``trivy-repo`` runs all four trivy scanners and drops
unfixed vulnerabilities; ``trivy`` runs ``vuln`` only and keeps them), and its own
scan path: ``trivy-repo`` keeps the ``scan()`` override it has always had, so its
findings, names and outputs are byte-identical to what its users get today, and
``trivy`` uses the template-method ``scan()`` the builtin scanners use.

The options are read by attribute (``scanners``, ``license_full``,
``ignore_unfixed``, ``disable_telemetry``, ``offline``, ``severity_threshold``),
so both config classes satisfy it without sharing a base.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    Generic,
    List,
    Optional,
    Set,
    TypeVar,
)

from pydantic import Field, PrivateAttr, model_validator

from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import ToolExtraArg
from automated_security_helper.schemas.sarif_schema_model import (
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.config.path_trust import (
    honored_path,
    in_scanned_tree,
    resolved_path,
)
from automated_security_helper.utils.config_trust import (
    scan_root,
    set_by_operator,
)
from automated_security_helper.utils.content_db_refresh import (
    default_cache_dir,
    prepare_content_db,
    scan_id_for,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.package_identity import (
    NpmLockIndex,
    identity_properties,
    install_path,
)

C = TypeVar("C", bound=ScannerPluginConfigBase)

#: trivy's ``--severity`` value for each ASH severity threshold: the threshold and
#: every severity above it.
SEVERITY_INCLUSION = {
    "LOW": "LOW,MEDIUM,HIGH,CRITICAL",
    "MEDIUM": "MEDIUM,HIGH,CRITICAL",
    "HIGH": "HIGH,CRITICAL",
    "CRITICAL": "CRITICAL",
}

#: The flags that keep trivy off the network. ``--skip-db-update`` makes trivy use
#: whatever vulnerability database is in its cache, of any age; ASH's scan-time
#: staleness check (``utils/content_db_staleness.py``) is what holds that database
#: to its declared bound.
OFFLINE_FLAGS = (
    "--skip-db-update",
    "--skip-java-db-update",
    "--offline-scan",
    "--skip-check-update",
)

#: Why an option naming a trivy input file was not used, when the operator did
#: not set it (utils/config_trust.set_by_operator).
_NOT_THE_OPERATORS = (
    "it came from a config file in the scanned tree or from an MCP client; set it "
    "with --config-overrides or a config file outside the tree"
)


def _existing_file(key: str, value: Any, path: Path) -> str:
    """``path`` as trivy is given it; a configured file that is missing fails."""
    if not path.is_file():
        raise ScannerError(
            f"{key} is {str(value)!r}, which is not a file (resolved to "
            f"{path.as_posix()}). Fix the path or unset it; trivy is not run "
            "without it."
        )
    return path.as_posix()


class TrivyScannerBase(ScannerPluginBase[C], Generic[C]):
    """Shared trivy behaviour. Not registered: only its subclasses are scanners."""

    # Both subclasses run the same binary against the same vulnerability database:
    # online it downloads the DB into its cache, and it reads TRIVY_* settings.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        cache_paths=("~/.cache/trivy", "$TRIVY_CACHE_DIR"),
        # trivy's default cache on macOS (os.UserCacheDir), read-only like the
        # cache above: the database is updated there outside the sandbox before an
        # online scan (utils/content_db_refresh.py), and trivy only reads it.
        read_paths=("~/Library/Caches/trivy",),
        env_prefixes=("TRIVY_",),
    )

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.CACHE_FLAGS

    # Env vars ASH layers onto trivy's subprocess, kept on the instance so
    # concurrent scanners do not race on os.environ. Nothing fills it from config;
    # the database update reads only the host's environment (_shared_update_flags).
    extra_env: Annotated[Dict[str, str], Field(default_factory=dict)]

    # The in-tree trivy input files already reported as ignored.
    _warned_inputs: Set[str] = PrivateAttr(default_factory=set)

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

        Shared by ``trivy`` and ``trivy-repo``; both pass ``--ignorefile`` and
        ``--secret-config`` from here.

        Without the flag, trivy reads ``default_name`` (``.trivyignore``,
        ``trivy-secret.yaml``) from its working directory, the source directory,
        so the scanned repository could remove findings from its own report
        (measured with trivy 0.75.0). The option is used under the rule every
        trivy path option follows (``_operator_path``: set by the operator, for a
        file outside the scanned tree). A refused or unset option falls through to
        the environment variable, which is the operator's, used for a file outside
        the tree (config/path_trust.py). Otherwise trivy gets a file ASH writes
        into the results directory, which sets nothing.
        """
        if self.context is None:
            raise ScannerError(f"{self.__class__.__name__} has no plugin context")
        source_dir = Path(self.context.source_dir)
        name = self.config.name if self.config is not None else "trivy"
        options: Any = self.config.options  # type: ignore[union-attr]
        value = getattr(options, option)
        if value:
            path = self._operator_path(
                option,
                value,
                f"trivy gets {env}, if set, or ASH's empty file instead.",
            )
            if path is not None:
                return _existing_file(f"scanners.{name}.options.{option}", value, path)
        from_env = os.environ.get(env)
        if from_env:
            path = honored_path(
                from_env,
                source_dir=source_dir,
                key=env,
                config=getattr(self.context, "config", None),
            )
            if path is not None:
                return _existing_file(env, from_env, path)
        in_tree = source_dir / default_name
        if in_tree.is_file() and in_tree.as_posix() not in self._warned_inputs:
            self._warned_inputs.add(in_tree.as_posix())
            self._plugin_log(
                f"Ignoring {in_tree.as_posix()}: it is inside the scanned tree. Set "
                f"scanners.{name}.options.{option} to a file outside the tree "
                "to use one.",
                level=logging.WARNING,
            )
        if self.results_dir is None:
            raise ScannerError(f"{self.__class__.__name__} has no results directory")
        written = Path(os.path.abspath(self.results_dir)) / ash_name
        written.parent.mkdir(parents=True, exist_ok=True)
        with open_for_write(written) as handle:
            handle.write(ash_content)
        return written.as_posix()

    def _run_subprocess(
        self, command: List[str], *args: Any, **kwargs: Any
    ) -> Dict[str, str]:
        """Bring trivy's shared caches up to date first, then run ``command``.

        ``command`` gains, in place so the invocation ASH records is the one that
        ran, the flags that skip the update, the cache directory the update wrote
        and ``--cache-backend=memory``. trivy keeps its scan cache
        (``fanal/fanal.db``) in the cache directory unless told otherwise, ``trivy
        repository`` included, and a sandbox may mount that directory read-only:
        with the scan cache in memory the scan only reads the database and checks
        there. The scan cache only saves re-analysing an unchanged target, so
        results are the same either way.
        """
        flags = self._shared_update_flags(command)
        if not any(a.startswith("--cache-backend") for a in command):
            flags.append("--cache-backend=memory")
        command[2:2] = flags
        return super()._run_subprocess(command, *args, **kwargs)

    def _shared_update_flags(self, command: List[str]) -> List[str]:
        """Update trivy's database (and checks bundle) once, then skip it in the scan.

        Why: trivy and trivy-repo run concurrently and share trivy's cache. Each
        downloads the vulnerability database when it is out of date, and one can
        read ``metadata.json``, or the memory-mapped ``trivy.db``, while the other
        rewrites it. Seen in CI as ``failed to update downloaded_at: unable to get
        metadata: json decode error: unexpected EOF``, and reproduced locally as a
        SIGBUS inside bbolt, in 1 run of 5 against an empty shared cache. A
        sandbox may also mount the cache read-only, or through a throwaway
        overlay, so an update made inside it would not reach the cache the scan
        reads.

        So the update runs first, in ``utils/content_db_refresh.prepare_content_db``,
        sandboxed or not: outside the scanner sandbox, under a lock in the cache
        directory, once per scan, from an empty directory ASH makes outside every
        checkout and with an empty ``--config`` of ASH's own, so nothing in the
        scanned tree (a ``trivy.yaml`` whose ``db.repository`` names another
        database, measured with trivy 0.75.0) reaches it. The scan is then told to
        skip it: ``--skip-db-update``, ``--skip-check-update`` when ``misconfig``
        needs the checks bundle, and ``--skip-java-db-update``, since fs and
        repository scans never open the Java database (trivy 0.75). It is pointed
        at the cache the update wrote (``--cache-dir``), which is also the one the
        sandbox mounts. The scan-time staleness check
        (``utils/content_db_staleness.py``) still measures the database after.

        Not done offline, where ``OFFLINE_FLAGS`` already skip every update.
        """
        if self._offline():
            return []
        options: Any = self.config.options  # type: ignore[union-attr]
        wants_checks = "misconfig" in (options.scanners or [])
        # From the host's environment only: the update runs unsandboxed, so nothing
        # a scanner layers on (extra_env) may choose where it writes.
        cache = default_cache_dir("trivy", snapshot_environ())
        # The operator's trivy.yaml, under the rule the scan's --config follows,
        # so a database mirror it names applies to the update; otherwise the
        # update gets an empty config of its own.
        operator_config = (
            self._operator_path(
                "config_file",
                options.config_file,
                "The database update runs with an empty config instead.",
            )
            if options.config_file
            else None
        )
        prepare_content_db(
            "trivy",
            cache,
            offline=False,
            checks=wants_checks,
            scan_id=scan_id_for(self.context),
            executable=find_executable(command[0]),
            config_file=operator_config,
        )
        return [
            "--skip-db-update",
            "--skip-java-db-update",
            *(["--skip-check-update"] if wants_checks else []),
            f"--cache-dir={Path(os.path.abspath(cache)).as_posix()}",
        ]

    def _operator_path(
        self, option: str, value: Path | str, why: str
    ) -> Optional[Path]:
        """``value`` as a path, when the operator set ``option`` and it lies outside the tree.

        trivy reads a ``trivy.yaml`` that can name a directory of WASM modules
        (``module.dir``) and load them, and ``--module-dir`` names one directly. So
        a path for either is used only when the operator set the option
        (``--config-overrides`` or a config file outside the scanned tree, see
        ``utils/config_trust.py``) and it resolves outside that tree. Otherwise
        this logs ``why`` and returns None, and the caller uses ASH's own.
        """
        if self.context is None:
            raise ScannerError(f"{self.__class__.__name__} has no plugin context")
        source_dir = Path(self.context.source_dir)
        candidate = resolved_path(value, source_dir)
        name = self.config.name if self.config is not None else "trivy"
        key = f"scanners.{name}.options.{option}"
        if not set_by_operator(self.context.config, key, value):
            reason = _NOT_THE_OPERATORS
        elif in_scanned_tree(candidate, scan_root(self.context.config, source_dir)):
            reason = "it is inside the scanned tree"
        else:
            return candidate
        # Once per value: the scanners ask for each target and the update asks again.
        refusal = f"{key}={value}"
        if refusal not in self._warned_inputs:
            self._warned_inputs.add(refusal)
            self._plugin_log(
                f"Ignoring {key} ({str(value)!r}): {reason}. {why}",
                level=logging.WARNING,
            )
        return None

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "TrivyScannerBase[C]":
        """Set up custom installation commands for trivy.

        trivy had no install path inside ASH. It could only arrive from the
        container image, the nix toolchain or a package manager, so a
        ``python-local`` run on a machine without it scanned without it.
        """
        self.custom_install_commands.update(pinned_tool_install_commands("trivy"))
        return self

    def _offline(self) -> bool:
        """Whether this scan runs offline, for trivy and trivy-repo alike.

        ``ScannerPluginBase._scanner_offline``: ASH's offline mode, read when the
        scanner asks, or the scanner's own ``options.offline: true``. ``false``
        follows ASH and never turns the network back on under ``--offline``.
        """
        return self._scanner_offline()

    def _append_trivy_options(self) -> None:
        """Turn the configured options into trivy flags on ``self.args.extra_args``.

        The order is the order ``trivy-repo`` has always used, so its command
        line is unchanged.
        """
        # Read by attribute: both trivy config classes declare these fields.
        options: Any = self.config.options  # type: ignore[union-attr]
        if len(options.scanners) > 0:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--scanners",
                    value=",".join(options.scanners),
                )
            )

        if options.license_full:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--license-full",
                    value=None,
                )
            )

        if options.ignore_unfixed:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--ignore-unfixed",
                    value=None,
                )
            )

        if options.disable_telemetry:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--disable-telemetry",
                    value=None,
                )
            )

        threshold = options.severity_threshold
        if threshold is not None and threshold != "ALL":
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--severity",
                    value=SEVERITY_INCLUSION[threshold],
                )
            )

        if self._offline():
            for flag in OFFLINE_FLAGS:
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
    def _set_identity(
        result: Any, name: str | None, version: str | None, path: str | None
    ) -> None:
        identity = identity_properties(name, version, path)
        if result.properties is None:
            result.properties = PropertyBag.model_validate(identity)
        else:
            for key, value in identity.items():
                setattr(result.properties, key, value)
