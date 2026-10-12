import logging

"""Module containing the detect-secrets security scanner implementation."""

from importlib.metadata import version
import json
import os
import multiprocessing
from pathlib import Path
import re
import stat
import sys
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Union

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.config.path_trust import (
    honored_path,
    scanned_tree_reason,
)
from automated_security_helper.config.secret_verification_trust import (
    UntrustedDetectSecretsSettings,
    drop_untrusted_entries,
    is_verification_filter,
    same_baseline,
)
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.core.constants import (
    KNOWN_GENERATED_LOCKFILE_NAMES,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactContent,
    ArtifactLocation,
    Invocation,
    Kind,
    Level,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.ash_install import (
    ash_reinstall_command,
    install_command,
)
from automated_security_helper.utils.get_scan_set import (
    honors_ignore_files,
    scan_set,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command
from automated_security_helper.models.core import IgnorePathWithReason


def _missing_library_reason() -> str:
    """Why this scanner cannot run when its library is absent.

    Built once per scanner and used for both the recorded reason and the log
    line, so the two cannot drift. A function rather than a module constant
    because the reinstall it names is where the running ASH was installed from.
    """
    # ASH's distribution name on its own ("pip install --force-reinstall
    # automated-security-helper", the earlier text) is not a reinstall of ASH:
    # on PyPI that name belongs to an unrelated project.
    return (
        "detect-secrets is not importable, so the detect-secrets scanner cannot run. "
        f"It ships as a dependency of ASH; reinstall ASH (`{ash_reinstall_command()}`) "
        f"or install the library directly with `{install_command('detect-secrets')}`."
    )


def _detect_secrets_api():
    """Import the three detect-secrets entry points this scanner uses.

    IMPORTED HERE RATHER THAN AT MODULE LEVEL, and that placement is the fix
    rather than a style choice. Plugin registration is a decorator side effect at
    class-definition time, so it happens during import -- and
    ``scanners/__init__.py`` imports its ten scanners in one module in source
    order. A top-level ``import detect_secrets`` that raises therefore removed this
    scanner AND every plugin module imported after it: measured with the library
    blocked, the registry held 4 of 10 scanners, 0 of 15 reporters and neither
    event handler, while ``load_internal_plugins`` reported zeros for all three
    groups and four of its five call sites discarded that return value.

    ``config/ash_config.py`` also imports ``DetectSecretsScannerConfig`` from this
    module, so the top-level form additionally took out config resolution -- a hard
    startup failure rather than a degraded scan.

    Raising ImportError from here is deliberate: callers that need the library
    catch it and record ``dependency_unavailable_reason``, which is what routes the
    scanner to a MISSING row instead of to nowhere.
    """
    from detect_secrets import SecretsCollection
    from detect_secrets.core.plugins.util import (
        get_mapping_from_secret_type_to_class,
    )
    from detect_secrets.settings import transient_settings

    return SecretsCollection, transient_settings, get_mapping_from_secret_type_to_class


class DetectSecretsScanSettingsPluginsUsed(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str | None = None
    limit: float | None = None
    keyword_exclude: str | None = None


class DetectSecretsScanSettingsFiltersUsed(BaseModel):
    model_config = ConfigDict(extra="allow")
    path: str | None = None
    min_level: int | None = None
    keyword_exclude: str | None = None


class DetectSecretsScanSettingsResults(BaseModel):
    model_config = ConfigDict(extra="allow")
    __pydantic_extra__: Dict[str, List[Any]] = {}


class DetectSecretsScanSettings(BaseModel):
    model_config = ConfigDict(extra="allow")
    version: str | None = None
    generated_at: str | None = None
    plugins_used: List[DetectSecretsScanSettingsPluginsUsed] = []
    filters_used: List[DetectSecretsScanSettingsFiltersUsed] = []
    results: DetectSecretsScanSettingsResults = DetectSecretsScanSettingsResults()


class DetectSecretsScannerConfigOptions(ScannerOptionsBase):
    baseline_file: Annotated[
        Path | str | None,
        Field(
            description="Path to detect-secrets baseline file, relative to current source directory. Defaults to searching for `.secrets.baseline` in the root of the source directory. The settings from the baseline will be overwritten if scan_settings is provided.",
        ),
    ] = None
    scan_settings: Annotated[
        DetectSecretsScanSettings,
        Field(
            description="Settings to use with detect-secrets. Refer to the detect-secrets documentation for formatting information. By default, all plugins will be used and no filters are configured. scan_settings takes precedence over baseline_file",
        ),
    ] = DetectSecretsScanSettings()
    skip_generated_lockfiles: Annotated[
        bool,
        Field(
            description=(
                "Skip machine-generated dependency lockfiles (package-lock.json, "
                "yarn.lock, poetry.lock, and similar) before scanning. These are "
                "dense with integrity hashes and are regenerated rather than "
                "hand-edited, so findings in them are usually noise. Hand-authored "
                "dependency declarations such as requirements.txt, Pipfile and "
                "environment.yml are always scanned and are not affected by this "
                "option. Set to false to scan generated lockfiles as well."
            ),
        ),
    ] = True
    # scan_timeout is inherited from ScannerOptionsBase now. The local copy that
    # used to live here declared `int` with no `ge`, so it shadowed the base field
    # and gave detect-secrets a different contract from every other scanner:
    # `scan_timeout: null` -- which the base field's own description documents as
    # the way to run unbounded -- raised a validation error here only, and
    # `scan_timeout: 0` was accepted here and rejected elsewhere, then passed
    # straight to future.result(timeout=0) so every scan timed out instantly.


class DetectSecretsScannerConfig(ScannerPluginConfigBase):
    name: Literal["detect-secrets"] = "detect-secrets"
    enabled: bool = True
    options: Annotated[
        DetectSecretsScannerConfigOptions,
        Field(description="Configure detect-secrets scanner"),
    ] = DetectSecretsScannerConfigOptions()


@ash_scanner_plugin
class DetectSecretsScanner(ScannerPluginBase[DetectSecretsScannerConfig]):
    """DetectSecretsScanner implements SECRET scanning using detect-secrets."""

    # The baseline as parsed when the scanner was configured, read once from its
    # checked path. The scan uses this copy and never reopens the file, so a path
    # swapped for a link after the check is not followed.
    _baseline_document: Optional[Dict[str, Any]] = PrivateAttr(default=None)

    # Whether the settings, as configured, may verify secrets with their issuers.
    # Decided once from where each setting came from (_apply_settings_trust); the scan
    # checks it again, so a verification filter added afterwards does not run.
    _verification_permitted: bool = PrivateAttr(default=False)

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context):
        if self.config is None:
            self.config = DetectSecretsScannerConfig()
        self.command = "detect-secrets"
        self.tool_type = ScannerToolType.SECRETS
        # The library's absence is recorded, not raised. This runs inside a
        # constructor, and ScanPhase builds every scanner inside a try/except that
        # logs one line and does not append to scanner_instances -- so a raise here
        # deletes the scanner from the run rather than reporting it MISSING.
        try:
            secrets_collection_cls, _, _ = _detect_secrets_api()
        except ImportError as exc:
            reason = _missing_library_reason()
            self.dependency_unavailable_reason = reason
            # Data, not markup: the reason holds the path ASH was installed
            # from, and the console handler would read a "[" in it as a tag.
            ASH_LOGGER.warning(f"{reason} ({exc})", extra=NO_MARKUP)
            self._secrets_collection = None
        else:
            self._secrets_collection = secrets_collection_cls()
            # PackageNotFoundError is a subclass of ModuleNotFoundError, so this is
            # only reached when the library imports but its distribution metadata is
            # missing -- a vendored or frozen install. The scanner still works;
            # only the reported version is unknown.
            try:
                self.tool_version = version("detect-secrets")
            except Exception:  # pragma: no cover - depends on install shape
                self.tool_version = None
        super().model_post_init(context)

    @property
    def sandbox_requirements(self) -> SandboxRequirements:
        """What the sandbox must allow this scanner, from its effective settings.

        The scan runs in ``utils/detect_secrets_worker.py``, a subprocess of the same
        interpreter, which the baseline policy already exposes (ASH's package and
        ``sys.prefix``), so no extra paths are needed.

        A network is needed only when the settings enable detect-secrets'
        verification filter. That filter calls each plugin's ``verify()``, which
        sends a candidate secret to the issuer's API (AWS, Slack, Stripe, ...) and
        drops the ones the issuer rejects; ``detect-secrets scan`` writes the filter
        into every baseline it generates. Without a network every verification
        reads as unverified, nothing is dropped, and the sandboxed scan reports
        more findings than the unsandboxed one. A property rather than a class
        attribute because only the instance knows its settings, which
        ``_process_config_options`` has already merged from the baseline by the
        time the executor asks. Under --offline no scanner gets a network, so
        there the extra, unverified findings are reported.

        The need is declared with ``network_requires_grant``: a baseline the
        operator names can load a plugin from a file outside the tree, so the
        filter alone does not decide it. The sandbox grants it only when
        ``sandbox.network_scanners`` names detect-secrets. The filter itself is
        kept only when the operator turned verification on, and never offline
        (``_drop_refused_verification``).
        """
        verifying = any(
            is_verification_filter(item.path)
            for item in self.config.options.scan_settings.filters_used
        )
        return SandboxRequirements(network=verifying, network_requires_grant=True)

    def validate_plugin_dependencies(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        # The Python import is the authoritative signal, and it is now asked rather
        # than assumed. This used to return an unconditional True on the reasoning
        # that "if the Python import got this far then we know we're in a valid
        # runtime" -- true only while the import was at module level, where its
        # failure deleted the scanner from the run instead of reaching this method.
        # With the import moved into the methods that use it, getting this far no
        # longer proves the library is present, so the recorded reason decides.
        if self.dependency_unavailable_reason:
            return False

        # Consulted for diagnostic logging only — its return value never gates the
        # result, because this scanner uses the in-process Python API and not the CLI.
        cmd = get_uv_tool_command("detect-secrets", fallback_binary="detect-secrets")
        if cmd is not None:
            ASH_LOGGER.debug(
                f"detect-secrets CLI also reachable via {cmd[0]}; "
                "scanner will continue to use the in-process Python API."
            )
        return True

    def _baseline_path(self, value: Union[str, Path]) -> Path:
        """``value`` as the option means it: ``~`` expanded, and a relative path
        taken from the source directory, not from ASH's working directory."""
        path = Path(os.path.expanduser(str(value)))
        if path.is_absolute():
            return path
        source_dir = getattr(getattr(self, "context", None), "source_dir", None)
        return Path(source_dir if source_dir is not None else os.getcwd()) / path

    def _baseline_refusal(self, named: Path, real: Path) -> Optional[str]:
        """Why ASH may not read the baseline named ``named``, resolving to ``real``.

        None when it may. Its entries mark candidates as known, so they leave the
        report:

        - A baseline an MCP client delivered is never read, sandbox or not: the
          client chose which candidates to hide, as a client-supplied
          ``baseline_file`` would.
        - Under a sandbox, ASH reads the baseline itself, outside it, and hands
          its contents to the sandboxed worker. So it reads one only when it
          resolves inside the source tree, or, for a detect-secrets that
          sandbox.read_path_scanners names, inside one of the operator's
          sandbox.extra_read_paths entries: the same containment an option path
          a scanner reads itself gets (``policy._contained_option_paths``).
          Judged by the file the path resolves to, which ``_read_baseline``
          then reads.
        """
        from automated_security_helper.config.path_trust import (
            _client_delivered_reason,
        )
        from automated_security_helper.config.sandbox_grants import is_within

        delivered = _client_delivered_reason(named) or _client_delivered_reason(real)
        if delivered is not None:
            return delivered
        context = getattr(self, "context", None)
        sandbox = getattr(getattr(context, "config", None), "sandbox", None)
        if sandbox is None or getattr(sandbox, "mode", "off") == "off":
            return None
        source_dir = getattr(context, "source_dir", None)
        if source_dir is not None and is_within(
            real, Path(os.path.realpath(source_dir))
        ):
            return None
        if "detect-secrets" not in (getattr(sandbox, "read_path_scanners", None) or []):
            return (
                "it is outside the source tree, and under the sandbox a file outside "
                "the tree is read only for a scanner named in "
                "sandbox.read_path_scanners"
            )
        roots = [
            Path(os.path.realpath(os.path.expandvars(os.path.expanduser(entry))))
            for entry in (getattr(sandbox, "extra_read_paths", None) or [])
        ]
        if any(is_within(real, root) for root in roots):
            return None
        return (
            "it is outside the source tree and every sandbox.extra_read_paths entry, "
            "which a granted baseline outside the tree has to be inside"
        )

    @staticmethod
    def _read_baseline(real: Path) -> Dict[str, Any]:
        """Parse the baseline at ``real``, the resolved path that was checked.

        Only a regular file is opened (a FIFO would block the scan), without
        following a link at its last component, and the opened file must have the
        device and inode ``real`` named just before. That binds the read to the
        resolved path; a directory above it swapped for a link between the check
        and this stat is not detected, which needs a writer to the source tree
        while the scan runs, and a sandboxed scanner may only read it.
        """
        checked = os.stat(real)
        if not stat.S_ISREG(checked.st_mode):
            raise OSError(f"{real.as_posix()} is not a regular file")
        fd = os.open(real, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "r") as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != (checked.st_dev, checked.st_ino):
                raise OSError(f"{real.as_posix()} changed while it was being read")
            return json.load(handle)

    def _process_config_options(self):
        # The configured baseline, else the default names, each taken from the
        # source directory; the first that exists is used.
        possible_baseline_paths = [
            self._baseline_path(item)
            for item in [
                self.config.options.baseline_file,
                ".ash/.secrets.baseline",
                ".secrets.baseline",
            ]
            if item is not None
        ]
        ASH_LOGGER.debug(f"Possible baseline file paths: {possible_baseline_paths}")

        for baseline_path in possible_baseline_paths:
            if baseline_path.exists():
                ASH_LOGGER.debug(f"Identified detect-secrets config @ {baseline_path}")
                self.config.options.baseline_file = baseline_path
                break

        real_baseline: Optional[Path] = None
        if self.config.options.baseline_file is not None:
            baseline = self._baseline_path(self.config.options.baseline_file)
            real_baseline = Path(os.path.realpath(baseline))
            refusal = self._baseline_refusal(baseline, real_baseline)
            if refusal is not None:
                ASH_LOGGER.warning(
                    f"Not reading the detect-secrets baseline {baseline.as_posix()}: "
                    f"{refusal}. Candidates the baseline would have marked are "
                    "reported."
                )
                self.config.options.baseline_file = None
                real_baseline = None

        # If a baseline file was found, load its plugins_used and filters_used
        # into scan_settings so they are applied during scanning.
        # SecretsCollection.load_from_baseline() only loads results, not settings,
        # so we must propagate the baseline's configuration explicitly.
        settings_from_baseline = False
        # The config's own filters, told apart from the baseline's by identity
        # (_drop_in_tree_settings_paths keeps the same objects), so that
        # _apply_settings_trust judges each by its own source. When the baseline's
        # filters replace the config's, the config's verification filter is kept
        # beside them: an operator who names only that filter still verifies.
        config_filter_ids = {
            id(item) for item in self.config.options.scan_settings.filters_used
        }
        if real_baseline is not None:
            try:
                baseline_data = self._read_baseline(real_baseline)
                self._baseline_document = baseline_data

                # Only apply baseline settings if scan_settings was not explicitly
                # configured by the user (i.e. still at defaults)
                if (
                    self.config.options.scan_settings.version is None
                    and len(self.config.options.scan_settings.plugins_used) == 0
                ):
                    # Load plugins from baseline
                    if "plugins_used" in baseline_data:
                        self.config.options.scan_settings.plugins_used = [
                            DetectSecretsScanSettingsPluginsUsed(**plugin)
                            for plugin in baseline_data["plugins_used"]
                        ]
                        settings_from_baseline = True
                    # Load filters from baseline (includes should_exclude_file, etc.)
                    if "filters_used" in baseline_data:
                        config_verification = [
                            item
                            for item in self.config.options.scan_settings.filters_used
                            if is_verification_filter(item.path)
                        ]
                        self.config.options.scan_settings.filters_used = [
                            DetectSecretsScanSettingsFiltersUsed(**f)
                            for f in baseline_data["filters_used"]
                        ] + config_verification
                        settings_from_baseline = True
                    ASH_LOGGER.debug(
                        f"Loaded settings from baseline: "
                        f"{len(self.config.options.scan_settings.plugins_used)} plugins, "
                        f"{len(self.config.options.scan_settings.filters_used)} filters"
                    )
            except (json.JSONDecodeError, OSError) as e:
                ASH_LOGGER.warning(
                    f"Failed to read baseline file settings: {e}. "
                    f"Falling back to default settings."
                )

        self._drop_in_tree_settings_paths()
        self._apply_settings_trust(
            settings_from_baseline=settings_from_baseline,
            config_entries={
                id(item)
                for item in self.config.options.scan_settings.filters_used
                if id(item) in config_filter_ids
            },
        )

        # Skipped when the library is absent: the plugin list has to be read out of
        # detect-secrets itself, and there is no scan to configure for a scanner that
        # has already been recorded unable to run. Returning here rather than
        # raising keeps the instance alive so it can be reported MISSING.
        if self.dependency_unavailable_reason:
            return super()._process_config_options()

        # If no plugins are configured then use all detect-secrets plugins. This is
        # the same set the default_settings function provided by detect-secrets
        # installs.
        #
        # ``plugins_used`` is the only condition, because it is the only one that
        # decides whether there is anything to detect with. This was additionally
        # gated on ``version is None``, which turned naming a detect-secrets
        # version -- a compatibility knob -- into a way to switch every detector
        # off: the dump below drops the still-default empty list, so
        # ``transient_settings`` received ``{'version': ...}`` and nothing else,
        # and the scan reported clean at exit 0 with no detectors configured.
        #
        # Merged into the existing object rather than replacing it. Replacing
        # discarded the operator's ``version`` and ``generated_at``, any extra keys
        # the model accepts, and -- on the one path that has any -- the
        # ``filters_used`` the baseline block above loaded. A second silent loss on
        # the way to fixing the first.
        #
        # The ``filters_used`` clause is scoped that way deliberately, because it is
        # not true of every run that reaches this line. The baseline block is gated
        # on ``version is None`` as well as an empty ``plugins_used``, and only the
        # second of those two conditions is repeated here. So an operator who names
        # a detect-secrets version and supplies a baseline arrives with neither the
        # baseline's plugins nor its filters loaded, and there are no baseline
        # filters for this merge to preserve. That narrower gate is a separate
        # question from the merge, and is not addressed here.
        #
        # The class mapping is reached through ``_detect_secrets_api()`` rather than
        # a module-level import, so a missing detect-secrets records a reason and
        # reports MISSING instead of taking the entire plugin registry down at
        # import time. Both properties are load-bearing and neither subsumes the
        # other: the condition and the merge are what keep a configured scan from
        # silently detecting nothing, and the indirection is what keeps the other
        # nine scanners registered.
        if len(self.config.options.scan_settings.plugins_used) == 0:
            _, _, secret_type_to_class = _detect_secrets_api()
            self.config.options.scan_settings.plugins_used = [
                DetectSecretsScanSettingsPluginsUsed(name=plugin_type.__name__)
                for plugin_type in secret_type_to_class().values()
            ]
            settings = self.config.options.scan_settings.model_dump(
                exclude_defaults=True, exclude_none=True, exclude_unset=True
            )
            ASH_LOGGER.debug(f"Default settings identified: {settings}")

        return super()._process_config_options()

    def _drop_in_tree_settings_paths(self) -> None:
        """Keep plugins_used and filters_used file entries only from outside the tree.

        detect-secrets names a plugin or filter defined in a file as
        ``file://<path>`` (a filter adds ``::<function>``), and reads a relative
        path from its worker's working directory, which is not the source
        directory. So a relative ``file://`` entry is dropped, and an absolute one
        is kept only when the file is outside the scanned tree (see
        config/path_trust.py), rewritten to the resolved path that was checked.
        A path that is not ``file://`` is a module the worker imports, and is kept
        only when it is one of detect-secrets' own (``detect_secrets.``). This
        covers entries from the config and from the baseline file.
        """
        settings = self.config.options.scan_settings
        source_dir = Path(self.context.source_dir)

        def _checked(value: Any, key: str) -> tuple[bool, Any]:
            """(keep, value to use) for one entry's path."""
            if value is None:
                return True, value
            if not isinstance(value, str) or not value.startswith("file://"):
                # A dotted path is imported by the worker. Only detect-secrets'
                # own modules are named that way; anything else needs file://.
                if isinstance(value, str) and value.startswith("detect_secrets."):
                    return True, value
                ASH_LOGGER.warning(
                    f"Ignoring {key} {value!r}: only detect-secrets' own plugins "
                    "and filters may be named by module path. Name another one "
                    "with an absolute file:// path outside the scanned tree."
                )
                return False, value
            file_part, separator, function = value[len("file://") :].partition("::")
            if not Path(file_part).is_absolute():
                ASH_LOGGER.warning(
                    f"Ignoring {key} {value!r}: a file:// path must be absolute, "
                    "because detect-secrets resolves a relative one from its own "
                    "working directory."
                )
                return False, value
            honored = honored_path(
                file_part,
                source_dir=source_dir,
                key=key,
                config=getattr(self.context, "config", None),
            )
            if honored is None:
                return False, value
            return True, f"file://{honored.as_posix()}{separator}{function}"

        plugins_key = (
            "scanners.detect-secrets.options.scan_settings.plugins_used[].path"
        )
        plugins = []
        for plugin in settings.plugins_used:
            keep, value = _checked(getattr(plugin, "path", None), plugins_key)
            if keep:
                if value is not None:
                    setattr(plugin, "path", value)
                plugins.append(plugin)
        settings.plugins_used = plugins

        filters_key = (
            "scanners.detect-secrets.options.scan_settings.filters_used[].path"
        )
        filters = []
        for item in settings.filters_used:
            keep, value = _checked(item.path, filters_key)
            if keep:
                item.path = value
                filters.append(item)
        settings.filters_used = filters

    def _untrusted_baseline_reason(
        self, record: Optional[UntrustedDetectSecretsSettings]
    ) -> Optional[str]:
        """Why the baseline's settings are not the operator's, or None when they are.

        A baseline inside the scanned tree is the repository's whichever config named
        it; ``detect-secrets scan`` writes the verification filter into every baseline
        it generates, so a repository's ``.secrets.baseline`` normally carries it. One
        outside the tree is the operator's when the config is, or when the operator's
        own settings name that same ``baseline_file`` (``--config-overrides``, or a
        workspace's default config, beside a repository's own config).
        """
        baseline = self.config.options.baseline_file
        if baseline is None:
            return None
        config = getattr(self.context, "config", None)
        root = getattr(config, "_scanned_root", None) or self.context.source_dir
        why = scanned_tree_reason(Path(baseline), root)
        if why is not None:
            return f"the baseline {Path(baseline).as_posix()} is used, and {why}"
        if record is None or same_baseline(
            record.operator_baseline, baseline, self.context.source_dir
        ):
            return None
        return (
            f"the baseline {Path(baseline).as_posix()} was named by a config the "
            f"operator did not write ({record.reason})"
        )

    def _apply_settings_trust(
        self, *, settings_from_baseline: bool, config_entries: Set[int]
    ) -> None:
        """Keep only what each setting's source may turn on.

        Two settings act on the scanning host rather than the scanned files, and only
        the operator's own settings may supply them (config/secret_verification_trust.py):

        * the verification filter, which sends each candidate secret, and for an AWS
          key the key pair itself, to the service that issued it;
        * a plugin or filter named by ``file://``, which the worker imports.

        resolve_config has already removed them from the settings of a config the
        operator did not write, and recorded what the operator's settings name. Here
        the same rule is applied to the baseline's settings, which resolve_config
        never sees, and offline mode turns verification off whatever any source
        says. The rest of the
        settings, the baseline's exclusions included, still apply, and candidates the
        filter would have dropped as rejected by their issuer are reported.

        Args:
            settings_from_baseline: The plugins and filters were loaded from the
                baseline, replacing the config's.
            config_entries: ``id()`` of the filter entries that came from the config
                rather than the baseline.
        """
        settings = self.config.options.scan_settings
        record = getattr(
            getattr(self.context, "config", None),
            "_untrusted_detect_secrets_settings",
            None,
        )
        notes: List[tuple] = []
        if settings_from_baseline:
            why = self._untrusted_baseline_reason(record)
            if why is not None:
                own = [
                    item for item in settings.filters_used if id(item) in config_entries
                ]
                settings.filters_used = [
                    item
                    for item in settings.filters_used
                    if id(item) not in config_entries
                ]
                removed = drop_untrusted_entries(
                    settings,
                    UntrustedDetectSecretsSettings(reason=why),
                    keep_verification=False,
                )
                settings.filters_used = settings.filters_used + own
                if removed:
                    notes.append((removed, why))
            if record is not None and not record.operator_verifies:
                settings.filters_used = [
                    item
                    for item in settings.filters_used
                    if id(item) not in config_entries
                    or not is_verification_filter(item.path)
                ]
        offline = self._scanner_offline()
        if offline:
            dropped = [
                str(item.path)
                for item in settings.filters_used
                if is_verification_filter(item.path)
            ]
            settings.filters_used = [
                item
                for item in settings.filters_used
                if not is_verification_filter(item.path)
            ]
            if dropped:
                notes.append((dropped, "ASH is running in offline mode"))
        self._verification_permitted = any(
            is_verification_filter(item.path) for item in settings.filters_used
        )
        for removed, why in notes:
            verification = [path for path in removed if is_verification_filter(path)]
            files = [path for path in removed if path not in verification]
            if verification and not self._verification_permitted:
                self._plugin_log(
                    f"Not verifying candidate secrets with their issuers: {why}. "
                    "Verification runs only online, when the operator's own ASH "
                    "config names the filter in "
                    "scanners.detect-secrets.options.scan_settings.filters_used or "
                    "names a baseline outside the scanned tree that does.",
                    level=logging.INFO if offline else logging.WARNING,
                )
            if files:
                self._plugin_log(
                    f"Not loading the detect-secrets plugin or filter files "
                    f"{', '.join(files)}: {why}. A plugin or filter named by file is "
                    "loaded only from the operator's own ASH config, or a baseline "
                    "outside the scanned tree that it names.",
                    level=logging.WARNING,
                )

    @staticmethod
    def _get_baseline_exclude_patterns(
        scan_settings_dict: Dict[str, Any],
    ) -> List[re.Pattern]:
        """Extract file exclusion regex patterns from scan settings filters.

        Looks for detect_secrets.filters.regex.should_exclude_file entries
        in the filters_used configuration and compiles their patterns.

        Returns:
            List of compiled regex patterns for file exclusion.
        """
        patterns = []
        for filter_config in scan_settings_dict.get("filters_used", []):
            if filter_config.get("path") == (
                "detect_secrets.filters.regex.should_exclude_file"
            ):
                raw_patterns = filter_config.get("pattern", [])
                if isinstance(raw_patterns, str):
                    raw_patterns = [raw_patterns]
                for p in raw_patterns:
                    try:
                        patterns.append(re.compile(p))
                    except re.error as e:
                        ASH_LOGGER.warning(
                            f"Invalid exclude pattern '{p}' in baseline: {e}"
                        )
        return patterns

    @staticmethod
    def _apply_file_exclusions(
        files: List[str],
        exclude_patterns: List[re.Pattern],
    ) -> List[str]:
        """Filter out files matching any of the exclude patterns.

        Args:
            files: List of file paths to filter.
            exclude_patterns: Compiled regex patterns to match against.

        Returns:
            Filtered list of file paths.
        """
        if not exclude_patterns:
            return files
        return [
            f
            for f in files
            if not any(pattern.search(f) for pattern in exclude_patterns)
        ]

    @staticmethod
    def _ensure_fork_multiprocessing() -> None:
        """Ensure multiprocessing uses 'fork' start method on Linux.

        The scan itself now runs in ``utils/detect_secrets_worker.py``, which
        applies this same rule in its own process before calling scan_files; it
        cannot call this method because it must not import the plugin registry.

        detect-secrets' scan_files() uses multiprocessing.Pool internally.
        On macOS with Python 3.13+, the default start method is 'spawn',
        which causes recursive process creation (fork bomb) when called
        outside of 'if __name__ == "__main__"' guard.

        On Linux containers (CodeBuild, Docker), 'fork' is the default and
        works correctly, but we set it explicitly to be safe in case the
        default changes in future Python versions.
        """
        if sys.platform == "linux":
            try:
                multiprocessing.set_start_method("fork", force=True)
            except RuntimeError:
                # Already set — this is fine
                pass

    @staticmethod
    def _worker_command(request_file: Path, output_file: Path) -> List[str]:
        """The command that runs one scan in ``utils/detect_secrets_worker.py``.

        The same interpreter as ASH, so the worker sees the same detect-secrets.
        A separate method so tests can substitute the worker.
        """
        return [
            sys.executable,
            "-m",
            "automated_security_helper.utils.detect_secrets_worker",
            str(request_file),
            str(output_file),
        ]

    def _scan_in_worker(
        self,
        *,
        baseline: Dict[str, Any] | None,
        scan_paths: List[str],
        scan_settings_dict: Dict[str, Any],
        work_dir: Path,
        scan_timeout: float | None,
        verify: bool = False,
    ) -> Any:
        """Scan ``scan_paths`` in a subprocess; return the resulting collection.

        detect-secrets runs out of the ASH process so that ``--sandbox`` can wrap it:
        the spawn goes through ``run_command_with_output_handling``, the choke point
        every sandboxed scanner subprocess passes through. The worker does what this
        method used to do in-process -- load the baseline, set ``root``, scan under
        ``transient_settings`` -- and this method rebuilds the same
        ``SecretsCollection`` from its output, so everything downstream reads
        ``self._secrets_collection`` exactly as before.

        ``verify`` is whether this scan may send candidate secrets to their issuers.
        When it is False the worker refuses every HTTP request detect-secrets
        tries, so a filter or plugin that verifies under another name cannot
        either (see ``utils/detect_secrets_worker.py``).

        Returns None when the worker was killed at ``scan_timeout``. The caller then
        keeps the collection it already holds (the parsed baseline, or empty). This
        differs from the in-process scan, which kept whatever it had found before
        the cutoff: a killed worker's partial results are not recoverable. The scan
        is reported as timed out either way, so a partial result was never a
        complete one.

        Raises:
            ScannerError: the worker failed, or exited 0 without writing results.
        """
        from detect_secrets.core.potential_secret import PotentialSecret

        from automated_security_helper.utils.detect_secrets_worker import (
            REFUSE_HTTP_ENV,
        )
        from automated_security_helper.utils.process_env import snapshot_environ
        from automated_security_helper.utils.subprocess_utils import (
            run_command_with_output_handling,
        )

        secrets_collection_cls, _, _ = _detect_secrets_api()
        root = self._secrets_collection.root
        # Absolute, because the worker runs in a different working directory and
        # output_dir may be relative for a library caller.
        work_dir = Path(work_dir).absolute()
        worker_cwd = Path(self.results_dir or work_dir).absolute()
        request_file = work_dir.joinpath("detect-secrets-worker-request.json")
        output_file = work_dir.joinpath("detect-secrets-worker-output.json")
        output_file.unlink(missing_ok=True)
        with open_for_write(request_file) as fp:
            json.dump(
                {
                    "root": str(root),
                    "baseline": baseline,
                    "settings": scan_settings_dict,
                    "paths": scan_paths,
                    "verify": verify,
                },
                fp,
            )
        try:
            # cwd is the scanner's results directory, which ASH empties at the
            # start of each run: `python -m` puts the working directory first on
            # sys.path, so running from the scanned tree would let a repository's
            # own `detect_secrets/` package replace the library.
            response = run_command_with_output_handling(
                command=self._worker_command(request_file, output_file),
                stdout_preference="return",
                stderr_preference="return",
                cwd=worker_cwd,
                env=None if verify else {**snapshot_environ(), REFUSE_HTTP_ENV: "1"},
                encoding="utf-8",
                errors="replace",
                timeout=scan_timeout,
            )
            if response.get("timed_out"):
                self._plugin_log(
                    f"detect-secrets scan timed out after {scan_timeout}s",
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )
                return None
            if response.get("returncode") != 0 or not output_file.exists():
                detail = (response.get("stderr") or response.get("error") or "").strip()
                raise ScannerError(
                    f"detect-secrets worker exited {response.get('returncode')}"
                    + (f": {detail}" if detail else " without writing results")
                )
            with open(output_file, encoding="utf-8") as fp:
                scanned = json.load(fp)
        finally:
            request_file.unlink(missing_ok=True)
            output_file.unlink(missing_ok=True)

        collection = secrets_collection_cls()
        collection.root = root
        for key, secrets in scanned:
            for secret in secrets:
                collection.data[key].add(PotentialSecret.load_secret_from_dict(secret))
        return collection

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        """Abstract stub — DetectSecrets overrides scan() directly; this is unreachable."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: DetectSecretsScannerConfig | None = None,
    ) -> SarifReport | bool:
        """Execute detect-secrets scan and return results.

        Args:
            target: Path to scan

        Returns:
            SarifReport containing the scan findings and metadata

        Raises:
            ScannerError: If the scan fails or results cannot be parsed
        """
        if global_ignore_paths is None:
            global_ignore_paths = []
        # Per target; see ScannerPluginBase.scan().
        self.exit_code = 0
        tool_component = ToolComponent(
            name="detect-secrets",
            version=self.tool_version,
            informationUri="https://github.com/yelp/detect-secrets",
        )
        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=tool_component),
                    results=[],
                    invocations=[
                        Invocation(
                            commandLine=self.command,
                            executionSuccessful=True,
                            workingDirectory=ArtifactLocation(
                                uri=get_shortest_name(input=target)
                            ),
                        )
                    ],
                )
            ],
        )
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
            return sarif_report

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

        ASH_LOGGER.debug(f"self.config: {self.config}")
        ASH_LOGGER.debug(f"config: {config}")

        try:
            secrets_collection_cls, _, _ = _detect_secrets_api()
            self._secrets_collection = secrets_collection_cls()
            target_results_dir = self.results_dir.joinpath(target_type)
            results_file = target_results_dir.joinpath("results_sarif.sarif")
            results_file.parent.mkdir(exist_ok=True, parents=True)
            self._resolve_arguments(target=target, results_file=target_results_dir)

            # The baseline is read here and handed to the worker as data rather than
            # as a path: the worker may run in a sandbox that cannot see a baseline
            # outside the source tree. It is also loaded here, which only parses it,
            # so that a scan killed at its timeout still reports the baseline's
            # entries, as the in-process scan did.
            baseline_document = None
            if (
                target_type == "source"
                and self.config.options.baseline_file is not None
                and self._baseline_document is not None
            ):
                baseline_document = self._baseline_document
                self._secrets_collection = secrets_collection_cls.load_from_baseline(
                    baseline=baseline_document,
                )

            # ``root`` has to be set for every scan, not only for the baseline
            # case above. SecretsCollection.scan_files() has two branches: a
            # single file goes through scan_file() and is keyed by the path it
            # was handed, but two or more files go through a multiprocessing
            # pool and are keyed by os.path.relpath(secret.filename, self.root).
            # SecretsCollection defaults ``root`` to '', and os.path.abspath('')
            # is the process working directory -- so reported finding paths
            # silently depended on where ASH happened to be invoked from, and on
            # Windows there is no relative path between two drives at all:
            # scanning a tree on D: from a process on C: raised
            # "ValueError: path is on mount 'C:', start on mount 'D:'"
            # in place of the findings.
            #
            # Anchor it to the directory the scan set is enumerated from just
            # below, which is an ancestor of every scanned file by construction,
            # so the relative path is always expressible. ``absolute()`` and not
            # ``resolve()``: the file list keeps whatever symlinked prefix it was
            # walked with, and resolving only one side of os.path.relpath() would
            # turn every key into a chain of '..' segments.
            scan_root = (
                self.context.work_dir
                if target_type == "converted"
                else self.context.source_dir
            )
            self._secrets_collection.root = Path(scan_root).absolute()

            # Find all files to scan from the scan set.
            #
            # Only machine-generated lockfiles are dropped here. Hand-authored
            # dependency declarations -- requirements.txt, Pipfile,
            # environment.yml and friends -- stay in the scan set: a human types
            # those, so a credential can land in one, and this pre-filter runs
            # upstream of every other control, so anything dropped here is
            # unrecoverable by any baseline or ignore-path setting. See the
            # comment block on KNOWN_GENERATED_LOCKFILE_NAMES for why the two
            # lists must stay separate.
            #
            # The output-directory exclusion guards the SOURCE branch only. ASH
            # writes its output underneath the source tree by default, so without
            # it a source scan reads its own previous reports back in and
            # attributes their contents to the repository. The converted branch
            # enumerates ``work_dir``, which is itself inside ``output_dir``, so
            # applying the same test there discards every file the converters
            # produced.
            #
            # Expressed against the resolved ``output_dir`` rather than against the
            # substring "/.ash/". That substring matches ``work_dir`` under the
            # documented default layout, where ``output_dir`` is
            # ``<source>/.ash/ash_output`` -- so the converted scan set was emptied
            # in full and the scan still reported clean. It also never matched on
            # Windows, where these paths are separated by "\", leaving the guard
            # simultaneously dead on one platform and over-broad on the other.
            #
            # ``absolute()`` on both sides and not ``resolve()``, for the reason
            # given for ``root`` above: the file list keeps whatever symlinked
            # prefix it was walked with, and resolving one side of a containment
            # test while leaving the other unresolved answers a different question.
            candidates = (
                list(self.context.work_dir.glob("**/*.*"))
                if target_type == "converted"
                else scan_set(
                    source=self.context.source_dir,
                    output=self.context.output_dir,
                    honor_ignore_files=honors_ignore_files(self.context.config),
                )
            )
            absolute_output_dir = Path(self.context.output_dir).absolute()
            skipped_names = (
                frozenset(KNOWN_GENERATED_LOCKFILE_NAMES)
                if self.config.options.skip_generated_lockfiles
                else frozenset()
            )
            scannable = [
                str(item)
                for item in candidates
                if Path(item).name not in skipped_names
                and (
                    target_type == "converted"
                    or not Path(item).absolute().is_relative_to(absolute_output_dir)
                )
            ]

            # Build the scan_settings dict for transient_settings, ensuring
            # filters_used from the baseline are included so detect-secrets
            # can apply should_exclude_file and other filters during scanning.
            scan_settings_dict = self.config.options.scan_settings.model_dump(
                exclude_defaults=True, exclude_none=True, exclude_unset=True
            )
            # model_dump with exclude_defaults drops empty lists, but we need
            # filters_used to be present if the baseline defined any filters,
            # so that transient_settings -> configure_settings_from_baseline
            # actually configures them.
            if (
                len(self.config.options.scan_settings.filters_used) > 0
                and "filters_used" not in scan_settings_dict
            ):
                scan_settings_dict["filters_used"] = [
                    f.model_dump(exclude_none=True)
                    for f in self.config.options.scan_settings.filters_used
                ]

            # Verification is decided again on the settings the worker gets, because
            # offline mode is read when it is used and the settings can change
            # after the scanner was configured. See _apply_settings_trust.
            verify = any(
                is_verification_filter(item.get("path"))
                for item in scan_settings_dict.get("filters_used", [])
            )
            if verify and (self._scanner_offline() or not self._verification_permitted):
                scan_settings_dict["filters_used"] = [
                    item
                    for item in scan_settings_dict["filters_used"]
                    if not is_verification_filter(item.get("path"))
                ]
                verify = False

            # Apply exclude file patterns from baseline filters to the scan set
            # BEFORE passing files to detect-secrets. This prevents unnecessary
            # file I/O and entropy calculations on excluded files, which is
            # critical for performance on large repos (e.g. 400+ JSON test files).
            exclude_patterns = self._get_baseline_exclude_patterns(scan_settings_dict)
            if exclude_patterns:
                pre_filter_count = len(scannable)
                scannable = self._apply_file_exclusions(scannable, exclude_patterns)
                excluded_count = pre_filter_count - len(scannable)
                if excluded_count > 0:
                    self._plugin_log(
                        f"Excluded {excluded_count} files from detect-secrets scan "
                        f"based on baseline exclude patterns",
                        level=logging.VERBOSE,
                        target_type=target_type,
                    )

            if global_ignore_paths:
                from automated_security_helper.utils.suppression_matcher import (
                    file_path_matches as path_matches_pattern,
                )

                original_count = len(scannable)
                source_prefix = str(self.context.source_dir.resolve()) + "/"
                scannable = [
                    file_path
                    for file_path in scannable
                    if not any(
                        path_matches_pattern(
                            file_path.removeprefix(source_prefix),
                            ignore_path.path,
                        )
                        for ignore_path in global_ignore_paths
                    )
                ]
                if original_count != len(scannable):
                    ASH_LOGGER.debug(
                        f"Filtered {original_count - len(scannable)} files using global_ignore_paths"
                    )

            if len(scannable) == 0:
                message = f"There were no scannable files found in target '{target}'"
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
                return sarif_report

            self._plugin_log(
                f"Found {len(scannable)} files in scan set to scan with detect-secrets",
                level=logging.VERBOSE,
                target_type=target_type,
            )

            scan_timeout = self.config.options.scan_timeout

            # Refuse to scan with no detectors rather than reporting clean.
            #
            # detect-secrets with an empty ``plugins_used`` finds nothing by
            # construction, and what it hands back is indistinguishable from a
            # genuinely clean tree everywhere ASH reports from. Measured against a
            # two-file tree holding two real secrets: exit_code 0, errors [],
            # zero SARIF results, and executionSuccessful true. detect-secrets does
            # write "No plugins to scan with!" to its own stderr, so the condition
            # is not literally unannounced -- but none of it reaches the exit code
            # or the report, which is all a CI gate reads. A configuration that
            # removes every detector has to be louder than the result it would
            # otherwise produce, so it fails the scanner instead.
            #
            # Asserted on the dict that reaches ``transient_settings`` rather than
            # on the model, because the dump above is where an empty list gets
            # dropped and it is the dict that governs the scan.
            if not scan_settings_dict.get("plugins_used"):
                raise ScannerError(
                    "detect-secrets was configured with no detect-secrets plugins, "
                    "so the scan could only report clean. Set "
                    "scanners.detect-secrets.options.scan_settings.plugins_used to "
                    "the detectors you want, or leave it unset to get the full "
                    "default plugin set."
                )

            # scan_files() reads each name as os.path.join(self.root, name),
            # which is only a no-op for absolute names. ``source_dir`` may be
            # relative: the CLI absolutizes it in run_ash_scan, but a library
            # caller reaches ASHScanOrchestrator directly and
            # model_post_init only coerces a str to Path -- it does not
            # anchor it -- so source_dir="./sub" arrives relative and the
            # scan set inherits that. Absolutize here: with a relative name a
            # non-empty root would send detect-secrets looking for
            # <root>/<root>/<file> and quietly find nothing. Kept separate
            # from ``scannable`` so the baseline exclude patterns above still
            # match against the paths they were written for.
            scan_paths = [str(Path(item).absolute()) for item in scannable]
            ASH_LOGGER.debug(f"Settings: {scan_settings_dict}")
            scanned = self._scan_in_worker(
                baseline=baseline_document,
                scan_paths=scan_paths,
                scan_settings_dict=scan_settings_dict,
                work_dir=target_results_dir,
                scan_timeout=scan_timeout,
                verify=verify,
            )
            if scanned is not None:
                self._secrets_collection = scanned

            self._post_scan(
                target=target,
                target_type=target_type,
            )

            # Populate the Results list with findings from the scan
            results: List[Result] = []
            for filename, detections in self._secrets_collection.data.items():
                for finding in detections:
                    rule_id = re.sub(
                        pattern=r"\W+", repl="-", string=finding.type
                    ).upper()
                    results.append(
                        Result(
                            # Adjust as needed to capture findings from scanner as
                            # SARIF Result objects. Reference the current CDK Nag
                            # Scanner/Wrapper for examples on custom SARIF structure.
                            ruleId=f"SECRET-{rule_id}",
                            properties=PropertyBag(
                                tags=[
                                    "detect-secrets",
                                    "secret",
                                    "security",
                                    f"tool_name::{self.config.name}",
                                    f"tool_type::{self.tool_type or 'UNKNOWN'}",
                                ],
                            ),
                            level=Level.error,
                            kind=Kind.fail,
                            message=Message(
                                text=f"Secret of type '{finding.type}' detected in file '{filename}' at line {finding.line_number}"
                            ),
                            locations=[
                                Location(
                                    id=1,
                                    physicalLocation=PhysicalLocation(
                                        artifactLocation=ArtifactLocation(
                                            uri=get_shortest_name(input=filename),
                                        ),
                                        region=Region(
                                            startLine=finding.line_number,
                                            endLine=finding.line_number,
                                            snippet=ArtifactContent(
                                                text=f"Secret of type {finding.type} detected"
                                            ),
                                        ),
                                    ),
                                )
                            ],
                        )
                    )
            sarif_tool: Tool = Tool(
                driver=ToolComponent(
                    name="detect-secrets",
                    fullName="yelp/detect-secrets",
                    organization="Yelp",
                    version=self.tool_version,
                    informationUri="https://github.com/Yelp/detect-secrets",
                    downloadUri="https://github.com/Yelp/detect-secrets",
                    rules=[],
                )
            )
            sarif_invocation: Invocation = Invocation(
                commandLine="ash-detect-secrets-scanner",
                arguments=[
                    "--target",
                    get_shortest_name(input=target),
                    "--scanner",
                ],
                startTimeUtc=self.start_time,
                endTimeUtc=self.end_time,
                executionSuccessful=True,
                exitCode=self.exit_code,
                exitCodeDescription="\n".join(self.errors),
                workingDirectory=ArtifactLocation(
                    uri=get_shortest_name(input=target),
                ),
                properties=PropertyBag(
                    tool=sarif_tool,
                ),
            )
            sarif_report = SarifReport(
                version="2.1.0",
                runs=[
                    Run(
                        tool=sarif_tool,
                        invocations=[sarif_invocation],
                        results=results,
                    )
                ],
            )
            with open_for_write(results_file) as fp:
                report_str = sarif_report.model_dump_json(
                    exclude_none=True,
                    exclude_unset=True,
                )
                fp.write(report_str)

            # Set exit code to 0 when no findings are found
            if len(results) == 0:
                self.exit_code = 0

            return sarif_report

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"{self.__class__.__name__} failed: {str(e)}")


if __name__ == "__main__":
    scanner = DetectSecretsScanner(
        source_dir=Path.cwd(),
        output_dir=Path.cwd().joinpath(".ash", "ash_output"),
    )
    scanner.scan(target=Path.cwd())
