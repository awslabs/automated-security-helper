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

import hashlib
import logging
import os
import shutil
import subprocess  # nosec B404 - spawn_run below is the sandbox choke point
import tempfile
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, Generic, List, Optional, TypeVar

from pydantic import Field, model_validator

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
from automated_security_helper.utils.config_trust import (
    inside_scanned_tree,
    set_by_operator,
)
from automated_security_helper.utils.file_lock import exclusive_lock
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.output_excerpt import head_and_tail
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.scope import outside_scanner_sandbox
from automated_security_helper.utils.subprocess_utils import find_executable, spawn_run
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


#: The lock file in trivy's cache directory that serializes its database update.
UPDATE_LOCK_NAME = ".ash-trivy-update.lock"

#: How long one update command (database or checks bundle) may take.
UPDATE_TIMEOUT_SECONDS = 900


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

    # Env vars layered onto the subprocess. Populated by _process_config_options
    # when offline mode is active. Kept on the instance so concurrent scanners
    # do not race on os.environ.
    extra_env: Annotated[Dict[str, str], Field(default_factory=dict)]

    def _trivy_cache_dir(self) -> Path:
        """trivy's cache directory, as trivy resolves it on Linux.

        Used only to place the update lock; trivy itself is never given a
        ``--cache-dir``, so where it reads and writes stays its own choice.
        """
        raw = self.extra_env.get("TRIVY_CACHE_DIR") or os.environ.get("TRIVY_CACHE_DIR")
        if raw:
            return Path(raw).expanduser()
        base = os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
        return Path(base) / "trivy"

    def _update_lock_path(self) -> Path:
        """Where the update lock lives: in trivy's cache, or beside it when read-only.

        A cache the operator provides read-only (a pre-seeded mount) still gets a
        lock, in the system temporary directory and named for the cache, so the
        scanners of this host still take turns; trivy then finds the database
        current and writes nothing, or fails to update it and says why.
        """
        cache = self._trivy_cache_dir()
        probe = cache if cache.exists() else cache.parent
        if os.access(probe, os.W_OK):
            return cache / UPDATE_LOCK_NAME
        digest = hashlib.sha256(os.fsencode(os.path.abspath(cache))).hexdigest()[:16]
        return Path(tempfile.gettempdir()) / f"ash-trivy-update-{digest}.lock"

    def _run_subprocess(
        self, command: List[str], *args: Any, **kwargs: Any
    ) -> Dict[str, str]:
        """Bring trivy's shared caches up to date first, then run ``command``.

        ``command`` gains, in place so the invocation ASH records is the one that
        ran, the flags that skip the update and ``--cache-backend=memory``. trivy
        keeps its scan cache (``fanal/fanal.db``) in the cache directory unless told
        otherwise, ``trivy repository`` included, and a sandbox may mount that
        directory read-only: with the scan cache in memory the scan only reads the
        database and checks there. The scan cache only saves re-analysing an
        unchanged target, so results are the same either way.
        """
        flags = self._shared_update_flags(command, kwargs.get("results_dir"))
        if not any(a.startswith("--cache-backend") for a in command):
            flags.append("--cache-backend=memory")
        command[2:2] = flags
        return super()._run_subprocess(command, *args, **kwargs)

    def _shared_update_flags(
        self, command: List[str], results_dir: Path | str | None
    ) -> List[str]:
        """Update trivy's database (and checks bundle) once, under a lock.

        Why: trivy and trivy-repo run concurrently and share trivy's cache. Each
        downloads the vulnerability database when it is out of date, and one can
        read ``metadata.json``, or the memory-mapped ``trivy.db``, while the other
        rewrites it. Seen in CI as ``failed to update downloaded_at: unable to get
        metadata: json decode error: unexpected EOF``, and reproduced locally as a
        SIGBUS inside bbolt, in 1 run of 5 against an empty shared cache. So the
        update runs here, serialized across threads and processes by a lock in
        the cache directory, and the scan is told to skip it: ``--skip-db-update``,
        and ``--skip-check-update`` when ``misconfig`` needs the checks bundle.
        The second scanner to take the lock finds the database current, and
        trivy's update command returns at once. The scan-time staleness check
        (``utils/content_db_staleness.py``) still measures the database after.

        The update runs outside the scanner sandbox (``outside_scanner_sandbox``):
        a sandbox may mount trivy's cache read-only, or through a throwaway
        overlay, so an update made inside it would not reach the cache the scan
        reads, or would let one sandboxed scanner change what the next one runs
        on. The sandboxed scan then only reads the cache, which trivy (0.75, whose
        default scan cache is in memory) does with the cache read-only. The update
        commands run no scanner code and read nothing from the scanned tree.

        Not done offline, where ``OFFLINE_FLAGS`` already skip every update.
        """
        if self._offline():
            return []
        options: Any = self.config.options  # type: ignore[union-attr]
        wants_checks = "misconfig" in (options.scanners or [])
        executable = find_executable(command[0]) or command[0]
        config_args = [a for a in command if a.startswith("--config=")]
        env = {**snapshot_environ(), **self.extra_env}
        with exclusive_lock(self._update_lock_path()), outside_scanner_sandbox():
            self._run_update(
                [
                    executable,
                    "image",
                    "--download-db-only",
                    "--no-progress",
                    *config_args,
                ],
                env,
                "its vulnerability database",
            )
            if wants_checks:
                # trivy has no command that only fetches the checks bundle; a
                # misconfiguration scan of an empty directory fetches it. ``trivy
                # config`` takes no --no-progress; its output is captured anyway.
                empty = (
                    Path(results_dir or self.results_dir or ".") / "trivy-checks-update"
                )
                if empty.is_symlink() or empty.is_file():
                    empty.unlink()
                elif empty.is_dir():
                    shutil.rmtree(empty)
                empty.mkdir(parents=True)
                self._run_update(
                    [
                        executable,
                        "config",
                        *config_args,
                        empty.as_posix(),
                    ],
                    env,
                    "its checks bundle",
                )
        return ["--skip-db-update", *(["--skip-check-update"] if wants_checks else [])]

    def _run_update(self, argv: List[str], env: Dict[str, str], what: str) -> None:
        """Run one trivy update command; raise ScannerError naming its stderr."""
        try:
            proc = spawn_run(  # nosec B603 - resolved trivy binary, list arguments
                argv,
                capture_output=True,
                text=True,
                env=env,
                timeout=UPDATE_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScannerError(
                f"trivy did not finish updating {what} within {UPDATE_TIMEOUT_SECONDS}s"
            ) from exc
        if proc.returncode != 0:
            detail = head_and_tail((proc.stderr or proc.stdout or "").strip(), 2000)
            raise ScannerError(
                f"trivy could not update {what} (exit {proc.returncode}): {detail}"
            )

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
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = source_dir / candidate
        name = self.config.name if self.config is not None else "trivy"
        key = f"scanners.{name}.options.{option}"
        if not set_by_operator(self.context.config, key, value):
            reason = (
                "it came from a config file in the scanned tree; set it with "
                "--config-overrides or a config file outside the tree"
            )
        elif inside_scanned_tree(candidate, source_dir):
            reason = "it is inside the scanned tree"
        else:
            return candidate
        self._plugin_log(
            f"Ignoring {key} ({str(value)!r}): {reason}. {why}", level=logging.WARNING
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
