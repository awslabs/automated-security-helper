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
``ignore_unfixed``, ``disable_telemetry``, ``offline``), so both config classes
satisfy it without sharing a base.
"""

from __future__ import annotations

import logging
import os
import re
import threading
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
from automated_security_helper.models.core import IgnorePathWithReason, ToolExtraArg
from automated_security_helper.schemas.sarif_schema_model import (
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.config.operator_paths import (
    anchored_environment_path,
)
from automated_security_helper.config.path_trust import honored_path
from automated_security_helper.config.tool_config_trust import empty_tool_config
from automated_security_helper.utils.config_trust import (
    operator_path,
    refusal_warning,
)
from automated_security_helper.utils.content_db_refresh import (
    default_cache_dir,
    prepare_content_db,
    scan_id_for,
)
from automated_security_helper.utils.content_db_shared import EMPTY_TOOL_CONFIG
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.link_exclusions import (
    trivy_skip_dirs,
    trivy_skip_files,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.package_identity import (
    NpmLockIndex,
    identity_properties,
    install_path,
)

C = TypeVar("C", bound=ScannerPluginConfigBase)

#: Flags every trivy scan gets, online or offline. ``trivy --offline-scan``: trivy scans
#: never contact package registries; the database refresh is a separate step
#: (``_shared_update_flags``). Measured with trivy 0.75.0: an online ``trivy fs`` of a
#: pom.xml requested its parent and dependency POMs from the repository the pom.xml
#: declares and from Maven Central, and with the flag requested nothing. trivy then
#: resolves Maven dependencies from the scanned tree and the local Maven repository
#: (``~/.m2/repository``) only.
SCAN_FLAGS = ("--offline-scan",)

#: The flag an online scan gets so trivy does not check for a new version. Without
#: it trivy asks check.trivy.dev about new versions and announcements (measured
#: through a proxy on 127.0.0.1, online), which a scan has no use for. Offline the
#: same check is turned off by ``TRIVY_SKIP_VERSION_CHECK`` in the environment
#: instead (``utils/offline_tool_env.py``, applied by ``PluginBase._run_subprocess``):
#: a trivy too old to know the flag refuses the whole command over it, and ignores
#: the variable.
ONLINE_FLAGS = ("--skip-version-check",)

#: The flags that skip trivy's own updates offline. ``trivy --skip-db-update`` makes trivy
#: use whatever vulnerability database is in its cache, of any age; ASH's scan-time
#: staleness check (``utils/content_db_staleness.py``) is what holds that database
#: to its declared bound.
OFFLINE_FLAGS = (
    "--skip-db-update",
    "--skip-java-db-update",
    "--skip-check-update",
)


#: The trivy misconfiguration scanner that downloads the module sources a .tf file
#: names. See TrivyScannerBase._offline_misconfig_args.
_TERRAFORM_MISCONFIG_SCANNER = "terraform"

_DEFAULT_MISCONFIG_SCANNERS: Dict[tuple[str, ...], Optional[List[str]]] = {}
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
    instead (measured with trivy 0.74.0). None when the list cannot be read. A list
    that was read is kept per binary and subcommand; a failed read is not, so the next
    scan tries again rather than every later scan in the process (a long-running MCP
    server, a workspace's projects) leaving out every misconfiguration check.
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
    if listed is not None:
        with _DEFAULT_MISCONFIG_SCANNERS_LOCK:
            _DEFAULT_MISCONFIG_SCANNERS[key] = listed
    return listed


def _existing_file(key: str, value: Any, path: Path) -> str:
    """``path`` as trivy is given it; a configured file that is missing fails.

    The refusal names ``key`` only: an option key, or an environment variable
    such as TRIVY_IGNOREFILE. Neither the value as written nor the path it
    resolved to is printed, so a value an environment variable chose never
    reaches the error text (config/path_trust.py: a value the environment
    chose is never printed). ``value`` is kept in the signature for the
    callers and for a debug line a later change may add.
    """
    if not path.is_file():
        raise ScannerError(
            f"{key} does not name a file: the path it is set to does not "
            "exist or is not a file. Fix the path or unset it; trivy is not "
            "run without it."
        )
    return path.as_posix()


class TrivyScannerBase(ScannerPluginBase[C], Generic[C]):
    """Shared trivy behaviour. Not registered: only its subclasses are scanners."""

    # Both subclasses run the same binary against the same vulnerability database,
    # and read TRIVY_* settings.
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

    # Env vars ASH layers onto trivy's subprocess, kept on the instance so
    # concurrent scanners do not race on os.environ. Nothing fills it from config;
    # the cache directory comes from the host's environment only (_trivy_cache_dir).
    extra_env: Annotated[Dict[str, str], Field(default_factory=dict)]

    # The in-tree trivy input files already reported as ignored.
    _warned_inputs: Set[str] = PrivateAttr(default_factory=set)

    # The cache directory a scan is pointed at (--cache-dir) is kept in the base
    # class's _content_db_cache_dir, so the staleness probe reads the same one
    # (content_database_probe_context). The --config file the last scan passed
    # trivy (_trivy_config_file) is kept for the same reason: a trivy.yaml can name
    # the cache (``cache.dir``).
    _scan_config_file: Optional[str] = PrivateAttr(default=None)

    def _trivy_cache_dir(self) -> Path:
        """trivy's cache directory, resolved as trivy resolves it on this host.

        ``content_db_refresh.default_cache_dir`` (``TRIVY_CACHE_DIR``, else
        ``XDG_CACHE_HOME`` on Linux, else the platform default), from the host's
        environment only: the database update runs unsandboxed, so nothing a
        scanner layers on (``extra_env``) may choose where it writes, and the scan
        and the probe read where the update wrote. Named to every scan, online and
        offline (``_run_subprocess``), and to the staleness probe: the sandbox does
        not pass ``XDG_CACHE_HOME``, and a sandboxed trivy left to its own default
        would read another cache.
        """
        return Path(os.path.abspath(default_cache_dir("trivy", snapshot_environ())))

    def _trivy_config_file(self) -> str:
        """The trivy config file a scan passes as ``--config``, online and offline.

        Without the flag trivy reads ``trivy.yaml`` from its working directory, the
        scanned repository. A ``trivy.yaml`` there can drop findings with nothing in
        the report saying so (``severity``, ``scan.skip-files``), load WASM modules
        (``module.dir``), and turn on a VEX repository download or client/server
        mode, both of which reach the network whatever offline flags ASH passes
        (measured with trivy 0.75.0). So trivy always gets ``--config``:

        1. ``options.config_file``, when ``_operator_path`` accepts it;
        2. otherwise ``TRIVY_CONFIG``, which is the operator's environment, for a
           file outside the scanned tree (``config/path_trust.honored_path``); a
           relative path in it is taken from the working directory ASH runs in;
        3. otherwise ``EMPTY_TOOL_CONFIG``, the empty config ASH ships, which every
           sandbox backend mounts read-only and no scanner can write.

        A path from 1 or 2 that is not a file fails the scan. The choice is kept for
        the staleness probe (``content_database_probe_context``), and the database
        update reads through the same file (``_shared_update_flags``).
        """
        chosen = self._operator_config_choice()
        if chosen is not None:
            key, value, path = chosen
            self._scan_config_file = _existing_file(key, value, path)
            return self._scan_config_file
        if self.context is not None:
            in_tree = Path(self.context.source_dir) / "trivy.yaml"
            if in_tree.is_file() and in_tree.as_posix() not in self._warned_inputs:
                self._warned_inputs.add(in_tree.as_posix())
                name = self.config.name if self.config is not None else "trivy"
                self._plugin_log(
                    f"Ignoring {in_tree.as_posix()}: it is inside the scanned tree, "
                    "and its settings can reach the network or change what is "
                    f"reported. Set scanners.{name}.options.config_file or "
                    "TRIVY_CONFIG to a file outside the tree to use one.",
                    level=logging.WARNING,
                )
        self._scan_config_file = EMPTY_TOOL_CONFIG.as_posix()
        return self._scan_config_file

    def _operator_config_choice(self) -> Optional[tuple[str, Any, Path]]:
        """The operator's trivy config, as (where it was set, its value, its path).

        ``options.config_file`` when ``_operator_path`` accepts it, else
        ``TRIVY_CONFIG`` when ``honored_path`` does; None when neither names one.
        Whether the file exists is the caller's question.
        """
        if self.context is None:
            raise ScannerError(f"{self.__class__.__name__} has no plugin context")
        name = self.config.name if self.config is not None else "trivy"
        options = getattr(self.config, "options", None)
        value = getattr(options, "config_file", None)
        if value:
            path = self._operator_path(
                "config_file",
                value,
                "trivy gets TRIVY_CONFIG, if set, or ASH's empty config instead.",
            )
            if path is not None:
                return f"scanners.{name}.options.config_file", value, path
        # The variable is the operator's, set where ASH runs, so a relative path in
        # it is taken from the working directory as written, as TRIVY_IGNOREFILE's
        # is (_trivy_input_file), not from the scanned directory. The value is
        # quoted as set.
        variable = os.environ.get("TRIVY_CONFIG")
        from_env = anchored_environment_path(variable, Path.cwd())
        if from_env:
            path = honored_path(
                from_env,
                source_dir=Path(self.context.source_dir),
                key="TRIVY_CONFIG",
                config=getattr(self.context, "config", None),
            )
            if path is not None:
                return "TRIVY_CONFIG", variable, path
        return None

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

    def _link_skip_args(
        self,
        target: Path | str,
        global_ignore_paths: Optional[List[IgnorePathWithReason]] = None,
    ) -> List[str]:
        """``--skip-files`` and ``--skip-dirs`` for ``target``.

        Each link leaving it, as a second guard (utils/link_exclusions.py): trivy
        follows no link and skips them on its own. And each path
        ``global_ignore_paths`` ignores, picked as ASH matches them below the source
        directory. In the joined form, since a path can start with "-".
        """
        if self.context is None:
            raise ScannerError(f"{self.__class__.__name__} has no plugin context")
        source_dir = self.context.source_dir
        return [
            *(
                f"--skip-files={path}"
                for path in trivy_skip_files(target, source_dir, global_ignore_paths)
            ),
            *(
                f"--skip-dirs={path}"
                for path in trivy_skip_dirs(target, source_dir, global_ignore_paths)
            ),
        ]

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
        the tree (config/path_trust.py); a relative path in it is taken from the
        working directory ASH runs in, as written
        (``config/operator_paths.anchored_environment_path``), not from the source
        directory. Otherwise trivy gets a file that sets
        nothing, which ASH writes outside the scanned tree (``empty_tool_config``).
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
        # The variable is the operator's, set where ASH runs, so a relative path
        # in it names a file there, as written, not one at the root of the
        # scanned tree.
        from_env = anchored_environment_path(os.environ.get(env), Path.cwd())
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
        return empty_tool_config(ash_name, ash_content, context=self.context).as_posix()

    def _run_subprocess(
        self, command: List[str], *args: Any, **kwargs: Any
    ) -> Dict[str, str]:
        """Bring trivy's shared caches up to date first, then run ``command``.

        ``command`` gains, in place so the invocation ASH records is the one that
        ran, the flags that skip the update (online), the cache directory
        (``_trivy_cache_dir``, online and offline, the one the update wrote),
        ``--cache-backend=memory`` and ``--exit-code=0``. trivy keeps its scan cache
        (``fanal/fanal.db``) in the cache directory unless told otherwise, ``trivy
        repository`` included, and a sandbox may mount that directory read-only:
        with the scan cache in memory the scan only reads the database and checks
        there. The scan cache only saves re-analysing an unchanged target, so
        results are the same either way.

        ``--exit-code`` is the code trivy exits with when it finds anything. The
        operator's ``TRIVY_EXIT_CODE``, which the sandbox passes through, and an
        ``exit-code`` in the operator's trivy.yaml both set it, and the flag outranks
        both (measured with trivy 0.75.0). Pinned to 0, a nonzero exit only ever
        means trivy failed: ``trivy`` refuses the report of any other run, and
        ``trivy-repo`` records the exit code in its SARIF invocation.
        """
        flags = self._shared_update_flags(command)
        cache = self._trivy_cache_dir()
        self._content_db_cache_dir = cache
        flags.append(f"--cache-dir={cache.as_posix()}")
        if not any(a.startswith("--cache-backend") for a in command):
            flags.append("--cache-backend=memory")
        flags.append("--exit-code=0")
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
        directory, once per scan, from a working directory outside the scanned tree
        (``config.path_trust.cwd_outside_scanned_tree``, given the scan's source and
        results directories and its config) and with an explicit ``--config``
        (``EMPTY_TOOL_CONFIG``, or the operator's file below), so nothing in the
        scanned tree (a ``trivy.yaml`` whose ``db.repository`` names another
        database, measured with trivy 0.75.0) reaches it. The scan is then told to
        skip it: ``--skip-db-update``, ``--skip-check-update`` when ``misconfig``
        needs the checks bundle, and ``--skip-java-db-update``, since fs and
        repository scans never open the Java database (trivy 0.75). It is pointed
        at the cache the update wrote (``--cache-dir``, ``_trivy_cache_dir``), which
        is also the one the sandbox mounts. The scan-time staleness check
        (``utils/content_db_staleness.py``) still measures the database after.
        An update the operator's own trivy settings turn off (``TRIVY_SKIP_DB_UPDATE``,
        or ``db.skip-update`` in the operator's config file) is left out, with a
        warning (``content_db_refresh.trivy_update_opt_outs``), and the scan reads
        the cache as it is.

        Not done offline, where ``OFFLINE_FLAGS`` already skip every update.
        """
        if self._offline():
            return []
        if self.context is None:
            raise ScannerError(f"{self.__class__.__name__} has no plugin context")
        options: Any = self.config.options  # type: ignore[union-attr]
        wants_checks = "misconfig" in (options.scanners or [])
        cache = self._trivy_cache_dir()
        # The operator's trivy.yaml (options.config_file or TRIVY_CONFIG), under the
        # rule the scan's --config follows (_trivy_config_file), so a database
        # mirror it names applies to the update; otherwise prepare_content_db
        # passes EMPTY_TOOL_CONFIG.
        chosen = self._scan_config_file or self._operator_config_file()
        operator_config = (
            chosen if chosen and Path(chosen) != EMPTY_TOOL_CONFIG else None
        )
        prepare_content_db(
            "trivy",
            cache,
            offline=False,
            source_dir=self.context.source_dir,
            results_dir=self.results_dir or self.context.output_dir,
            config=getattr(self.context, "config", None),
            checks=wants_checks,
            scan_id=scan_id_for(self.context),
            executable=find_executable(command[0]),
            config_file=operator_config,
        )
        return [
            "--skip-db-update",
            "--skip-java-db-update",
            *(["--skip-check-update"] if wants_checks else []),
        ]

    def content_database_probe_context(self):  # type: ignore[no-untyped-def]
        """The base's probe context, pointed at the cache the scan read.

        Every scan is given ``--cache-dir`` (``_run_subprocess``, from
        ``_trivy_cache_dir``), which is not where a sandboxed trivy looks on its
        own: the sandbox drops ``XDG_CACHE_HOME``. The ``trivy version`` probe gets
        the same directory, as ``--cache-dir`` (``content_db_staleness
        ._built_from_trivy``) and as ``TRIVY_CACHE_DIR``. A probe that runs before
        any scan, the offline dependency check, gets the directory the scan will
        be given. It also reads through the config file the scan passed, or the one
        it will pass.
        """
        context = super().content_database_probe_context()
        cache = (self._content_db_cache_dir or self._trivy_cache_dir()).as_posix()
        context.env = {**context.env, "TRIVY_CACHE_DIR": cache}
        context.cache_dir = cache
        context.config_file = self._scan_config_file or self._operator_config_file()
        return context

    def _operator_config_file(self) -> Optional[str]:
        """The operator's trivy config file, when it is honored and exists.

        ``_operator_config_choice``, for a probe that runs before the scan has chosen
        its ``--config`` (the offline dependency check), so it reads through the same
        file the scan will. A file that does not exist is not an error here: the
        scan itself then fails on it (``_trivy_config_file``).
        """
        if self.context is None:
            return None
        chosen = self._operator_config_choice()
        if chosen is None or not chosen[2].is_file():
            return None
        return chosen[2].as_posix()

    def _operator_path(
        self, option: str, value: Path | str, why: str
    ) -> Optional[Path]:
        """``value`` as a path, when the operator set ``option`` and it lies outside the tree.

        trivy reads a ``trivy.yaml`` that can name a directory of WASM modules
        (``module.dir``) and load them, and ``--module-dir`` names one directly. So
        a path for either is used only when the operator set the option
        (``--config-overrides`` or a config file outside every git checkout and the
        scanned directory, see ``utils/config_trust.py``) and it resolves outside the
        scanned tree, without a
        symbolic link in the tree leading it there. Otherwise this logs ``why``
        and returns None, and the caller uses ASH's own.
        """
        if self.context is None:
            raise ScannerError(f"{self.__class__.__name__} has no plugin context")
        name = self.config.name if self.config is not None else "trivy"
        key = f"scanners.{name}.options.{option}"
        chosen = operator_path(self.context.config, key, value, self.context.source_dir)
        if chosen.path is not None:
            return chosen.path
        reason = chosen.refusal
        # Once per value: the scanners ask for each target and the update asks again.
        refusal = f"{key}={value}"
        if refusal not in self._warned_inputs:
            self._warned_inputs.add(refusal)
            self._plugin_log(
                refusal_warning(
                    f"Ignoring {key} ({str(value)!r}): {reason}. {why}", reason
                ),
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

        Shared by ``trivy-repo``, which runs ``misconfig`` by default, and ``trivy``,
        which runs it when the operator adds it to ``scanners``.
        """
        options: Any = self.config.options  # type: ignore[union-attr]
        if "misconfig" not in (options.scanners or []):
            return final_args
        command = self.command or "trivy"
        binary = find_executable(command) or command
        defaults = self._default_misconfig_scanners(binary)
        kept = [name for name in defaults or [] if name != _TERRAFORM_MISCONFIG_SCANNER]
        args = list(final_args)
        if kept:
            message = (
                "trivy's Terraform checks are skipped offline: trivy downloads the "
                "module sources a .tf file names, and has no setting that stops it. "
                "checkov still checks Terraform."
            )
            head = [command, *self.subcommands]
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

    def _default_misconfig_scanners(self, binary: str) -> Optional[List[str]]:
        """trivy's default misconfiguration scanners for this scanner's subcommand."""
        return trivy_default_misconfig_scanners(binary, list(self.subcommands))

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

        # severity_threshold is not passed as --severity: trivy would drop the lower
        # findings before ASH saw them, so they would be neither reported nor
        # counted. ASH applies it after the scan, as for every scanner, to the
        # severity trivy gave each finding.

        for flag in SCAN_FLAGS:
            self.args.extra_args.append(ToolExtraArg(key=flag, value=None))

        if not self._offline():
            for flag in ONLINE_FLAGS:
                self.args.extra_args.append(ToolExtraArg(key=flag, value=None))
        else:
            # trivy's version check and telemetry are turned off by
            # TRIVY_SKIP_VERSION_CHECK and TRIVY_DISABLE_TELEMETRY, whatever
            # disable_telemetry says (utils/offline_tool_env.py); see ONLINE_FLAGS.
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
