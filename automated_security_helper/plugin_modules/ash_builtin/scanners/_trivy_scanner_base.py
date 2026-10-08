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
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, Generic, Optional, TypeVar

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
from automated_security_helper.utils.log import ASH_LOGGER
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
