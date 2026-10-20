import logging

"""Module containing the detect-secrets security scanner implementation."""

from importlib.metadata import version
import json
import multiprocessing
import os
from pathlib import Path
import re
import stat
import sys
from typing import (
    Annotated,
    Any,
    ClassVar,
    Collection,
    Dict,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
)

from pydantic import ConfigDict, Field, PrivateAttr

from automated_security_helper.utils.redacted_model import RedactedSection
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.config.path_trust import (
    derived_roots,
    honored_path,
    scanned_checkout_reason,
)
from automated_security_helper.config.secret_verification_trust import (
    UntrustedDetectSecretsSettings,
    drop_untrusted_entries,
    is_verification_filter,
    same_baseline,
)
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.uv_tool_mixin import guarded_values_read
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
from automated_security_helper.utils.python_child import python_child
from automated_security_helper.utils.error_text import (
    error_text,
    pattern_error_text,
    text_without_values,
    timeout_limit_token,
)
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.sandbox.fs_guard import (
    OutputLinkRefused,
    open_for_write,
    read_bytes_at_most,
    unlink_beneath,
)
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


#: The worker's exchange files, written to the scanner's results directory for
#: one scan and deleted when it ends (``_scan_in_worker``'s ``finally``). The
#: request file carries the scan settings, environment-derived values included,
#: and the output file carries raw findings, so a leftover from a run killed
#: outright is removed when a later scan starts (see ``scan``). They live in
#: the results directory because that is what the sandbox mounts for the
#: worker: a private temp path outside it was measured unreadable there (bwrap
#: mounts a fresh tmpfs over /tmp; Landlock refuses the read).
WORKER_REQUEST_FILE_NAME = "detect-secrets-worker-request.json"
WORKER_OUTPUT_FILE_NAME = "detect-secrets-worker-output.json"
#: The default of the scanner's ``max_worker_output_mib``, the most of the
#: worker's output file read back. A finding is about 300 bytes of output
#: (measured: 215,903 findings made 66,203,080 bytes), so 256 MiB holds about
#: 900,000 of them; 64 MiB failed a legitimate scan of about 220,000. The read
#: is bounded by it: read_bytes_at_most allocates only what the file holds, but
#: json.loads then holds about three times its size (measured 3.06x).
DEFAULT_WORKER_OUTPUT_MIB = 256
#: The most ``max_worker_output_mib`` may be: about 14 million findings, whose
#: read holds about 12 GiB. Only the operator sets the option, from
#: --config-overrides or a config file outside the scanned tree
#: (config/operator_only_options.py).
MAX_WORKER_OUTPUT_MIB = 4096


class DetectSecretsScanSettingsPluginsUsed(RedactedSection):
    model_config = ConfigDict(extra="allow")
    name: str | None = None
    limit: float | None = None
    keyword_exclude: str | None = None


class DetectSecretsScanSettingsFiltersUsed(RedactedSection):
    model_config = ConfigDict(extra="allow")
    path: str | None = None
    min_level: int | None = None
    keyword_exclude: str | None = None


class DetectSecretsScanSettingsResults(RedactedSection):
    model_config = ConfigDict(extra="allow")
    __pydantic_extra__: Dict[str, List[Any]] = {}


class DetectSecretsScanSettings(RedactedSection):
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
            description="Path to detect-secrets baseline file. A relative path is taken from the directory of the config file that sets it, or from the working directory for --config-overrides, not from the source directory. Defaults to searching for `.secrets.baseline` in the root of the source directory. The settings from the baseline will be overwritten if scan_settings is provided.",
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
    max_worker_output_mib: Annotated[
        int,
        Field(
            gt=0,
            le=MAX_WORKER_OUTPUT_MIB,
            description=(
                "The most of the detect-secrets worker's output read back, in "
                f"MiB, at most {MAX_WORKER_OUTPUT_MIB}. A finding is about 300 "
                "bytes of output, so the "
                "default of 256 holds about 900,000 findings. Reading the output "
                "costs about three times its size in memory (1024 MiB of output "
                "needs about 3 GiB). A scan whose output is larger fails and "
                "records no findings, with an error that names this option. "
                "Honored only from --config-overrides or a config file outside "
                "the scanned tree."
            ),
        ),
    ] = DEFAULT_WORKER_OUTPUT_MIB
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

    #: detect-secrets runs in-process, from the Python library. See
    #: ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = True
    #: Its check asks whether the library imports and never looks for the
    #: detect-secrets console script, which a scan does not start, so
    #: ``ash dependencies install`` asks the check. See
    #: ScannerPluginBase.resolves_tool_off_path.
    resolves_tool_off_path: ClassVar[bool] = True

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    # The baseline as parsed when the scanner was configured, read once from its
    # checked path. The scan uses this copy and never reopens the file, so a path
    # swapped for a link after the check is not followed.
    _baseline_document: Optional[Dict[str, Any]] = PrivateAttr(default=None)

    # The resolved path the baseline gate checked (_baseline_refusal), which
    # _read_baseline then opens and binds to by device and inode. None until the
    # gate has passed a chosen baseline.
    _baseline_real: Optional[Path] = PrivateAttr(default=None)

    # Whether the settings, as configured, may verify secrets with their issuers.
    # Decided once from where each setting came from (_apply_settings_trust); the scan
    # checks it again, so a verification filter added afterwards does not run.
    _verification_permitted: bool = PrivateAttr(default=False)

    def model_post_init(self, context):
        if self.config is None:
            self.config = DetectSecretsScannerConfig()
        self.command = "detect-secrets"
        self.tool_type = ScannerToolType.SECRETS
        self._configured_baseline_missing = False
        self._configured_baseline_refused = False
        # Chosen, and then refused where ASH may not read it (_baseline_refusal:
        # an MCP client delivered it, or a sandboxed scan may not read it there).
        self._baseline_trust_refused = False
        self._chosen_baseline = None
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

        The need is declared with ``network_requires_grant``: the settings come
        from a baseline or ASH config that the scanned repository can write,
        and the same baseline can load a plugin from the repository, so a
        repository could otherwise give its own code a network. The sandbox
        grants it only when ``sandbox.network_scanners`` names detect-secrets.
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

    def _baseline_in_use(self) -> bool:
        """Whether the scan reads a baseline. A configured baseline that is not
        on disk, or that is refused as a derived work product, is decided
        here, where the baseline is used, and not by clearing the option: the
        config model keeps the value as written so every dump of it shows what
        the operator wrote."""
        return (
            (
                self.config.options.baseline_file is not None
                or self._chosen_baseline is not None
            )
            and not self._configured_baseline_missing
            and not self._configured_baseline_refused
            and not self._baseline_trust_refused
        )

    def _baseline_file_path(self) -> Path:
        """The configured baseline as the scan reads it: a relative value is
        taken from the scanned tree, the anchor the selection judged it
        from, never from the process's working directory. A selected
        baseline is already in this form, so resolving it again is a no-op."""
        from automated_security_helper.config.path_trust import resolved_path

        if self._chosen_baseline is not None:
            return Path(self._chosen_baseline)
        return resolved_path(
            self.config.options.baseline_file,
            Path(getattr(self.context, "source_dir", None) or "."),
        )

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
        # Check detect-secrets baseline path. The second element of each pair
        # says whether the candidate came from the option: the baseline the
        # scan loads is a suppression surface, so a baseline the scan derived
        # from the repository being scanned (under the output or work
        # directory) is not loaded unless the operator's own configuration
        # names it; see config/path_trust.py. The checkout's own in-tree
        # baseline stays accepted as before, as in the sibling scanners, so
        # only the derived-directory clause applies here.
        self._configured_baseline_missing = False
        self._configured_baseline_refused = False
        self._chosen_baseline = None
        possible_baseline_paths = [
            (item, from_option)
            for item, from_option in [
                (self.config.options.baseline_file, True),
                (".ash/.secrets.baseline", False),
                (".secrets.baseline", False),
            ]
            if item is not None
        ]
        # The configured path can come from the environment, and --debug raises
        # the console level, so a DEBUG line naming one reaches the console and
        # whatever captures it (CI logs); each such line is redacted. The
        # scan's file logs stay at INFO (run_ash_scan's _setup_logger passes
        # get_logger no file log level), which is where the WARNINGs land.
        values = self._environment_values()
        ASH_LOGGER.debug(
            text_without_values(
                "Possible baseline file paths: "
                f"{[item for item, _ in possible_baseline_paths]}",
                values,
            )
        )

        from automated_security_helper.config.operator_only_options import (
            operator_wrote_value,
        )
        from automated_security_helper.config.path_trust import (
            derived_roots,
            refused_derived_product,
            resolved_path,
        )

        context_config = getattr(self.context, "config", None)
        source_dir = Path(getattr(self.context, "source_dir", None) or ".")

        # Look through each baseline file path to see if it exists and configure
        # the scan settings according to the first baseline file found. Each
        # candidate is resolved once, from the scanned tree as the gate does,
        # and that one path is what is checked for existence, judged, stored
        # and later opened, so the file judged is the file read whatever
        # directory the process runs in. The as-given spelling is kept only
        # for the redacted text and for the operator-written comparison.
        chosen = None
        option_refused = False
        option_missing = None
        for baseline_path, from_option in possible_baseline_paths:
            resolved_baseline = resolved_path(baseline_path, source_dir)
            ASH_LOGGER.debug(
                text_without_values(
                    f"Checking for detect-secrets config @ {baseline_path}",
                    values,
                )
            )
            if resolved_baseline.exists():
                if refused_derived_product(
                    baseline_path,
                    source_dir=source_dir,
                    key="scanners.detect-secrets.options.baseline_file"
                    if from_option
                    else f"detect-secrets baseline file {baseline_path}",
                    config=context_config,
                    derived_dirs=derived_roots(self.context),
                    operator_written=operator_wrote_value(
                        context_config,
                        "scanner",
                        "detect-secrets",
                        ("options", "baseline_file"),
                        baseline_path,
                        config_from_context=self._config_from_context,
                    )
                    if from_option
                    else False,
                ):
                    if from_option:
                        # A refused configured baseline takes no checkout
                        # candidate in its place.
                        option_refused = True
                        break
                    continue
                ASH_LOGGER.debug(
                    text_without_values(
                        f"Identified detect-secrets config @ {baseline_path}",
                        values,
                    )
                )

                chosen = resolved_baseline
                break
            elif from_option:
                # A missing configured baseline takes no checkout candidate in
                # its place.
                option_missing = baseline_path
                break
        if chosen is not None:
            # The gate: whether ASH may read the chosen baseline at all (an MCP
            # client delivered it; a sandboxed scan may read it only inside the
            # source tree or a granted extra_read_paths entry). The resolved
            # path checked here is the one _read_baseline opens and binds to.
            real_baseline = Path(os.path.realpath(chosen))
            refusal = self._baseline_refusal(Path(chosen), real_baseline)
            if refusal is not None:
                ASH_LOGGER.warning(
                    text_without_values(
                        f"Not reading the detect-secrets baseline "
                        f"{Path(chosen).as_posix()}: {refusal}. Candidates the "
                        "baseline would have marked are reported.",
                        values,
                    )
                )
                self._baseline_trust_refused = True
            else:
                # Recorded on the scanner, not written into the option: the config
                # model keeps the value as written so every dump of it shows what
                # the operator wrote, as it does for a missing or refused file.
                self._chosen_baseline = chosen
                self._baseline_real = real_baseline
        elif option_missing is not None:
            # The configured file is not on disk, and no checkout candidate
            # replaces it. The path as the config gave it can be a value the
            # config read from the environment, so the warning carries the
            # redacted form. The scanner records that no baseline is in use,
            # so neither the settings load below nor the scan opens the
            # missing file: the scan runs without a baseline. The option on
            # the config model is left as written, because a config dump
            # describes what the operator wrote, not what the scan resolved.
            ASH_LOGGER.warning(
                text_without_values(
                    f"Configured detect-secrets baseline file does not exist: "
                    f"{Path(option_missing)}. detect-secrets will run without "
                    "a baseline; no baseline file is taken from the scanned "
                    "tree in its place.",
                    values,
                )
            )
            self._configured_baseline_missing = True
        elif option_refused:
            # The configured baseline is a derived work product and no
            # checkout candidate replaces it. The scanner records the
            # refusal, as it does a missing file, so neither the settings
            # load below nor the scan opens it: the scan runs without a
            # baseline. The option on the config model is left as written,
            # because a config dump describes what the operator wrote, not
            # what the scan resolved.
            ASH_LOGGER.warning(
                "Configured detect-secrets baseline file was not used because "
                "it is a work product derived from the scanned repository. "
                "detect-secrets will run without a baseline; no baseline file "
                "is taken from the scanned tree in its place."
            )
            self._configured_baseline_refused = True

        # If a baseline file was found, load its plugins_used and filters_used
        # into scan_settings so they are applied during scanning.
        # SecretsCollection.load_from_baseline() only loads results, not settings,
        # so we must propagate the baseline's configuration explicitly.
        #
        # The config's own filters, told apart from the baseline's by identity
        # (_drop_in_tree_settings_paths keeps the same objects), so that
        # _apply_settings_trust judges each by its own source. When the baseline's
        # filters replace the config's, the config's verification filter is kept
        # beside them: an operator who names only that filter still verifies.
        config_filter_ids = {
            id(item) for item in self.config.options.scan_settings.filters_used
        }
        loaded_from_baseline: set = set()
        if self._baseline_in_use() and self._baseline_real is not None:
            try:
                # Read once, bound to the resolved path the gate checked
                # (_read_baseline); the scan uses this same parsed copy and
                # never reopens the file.
                baseline_data = self._read_baseline(self._baseline_real)
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
                        loaded_from_baseline.add("plugins_used")
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
                        loaded_from_baseline.add("filters_used")
                    ASH_LOGGER.debug(
                        f"Loaded settings from baseline: "
                        f"{len(self.config.options.scan_settings.plugins_used)} plugins, "
                        f"{len(self.config.options.scan_settings.filters_used)} filters"
                    )
            except (json.JSONDecodeError, OSError) as e:
                ASH_LOGGER.warning(
                    text_without_values(
                        f"Failed to read baseline file settings: {e}. "
                        f"Falling back to default settings.",
                        values,
                    )
                )

        self._drop_in_tree_settings_paths(loaded_from_baseline)
        self._apply_settings_trust(
            settings_from_baseline=bool(loaded_from_baseline),
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
            ASH_LOGGER.debug(
                text_without_values(f"Default settings identified: {settings}", values)
            )

        return super()._process_config_options()

    def _drop_in_tree_settings_paths(
        self, loaded_from_baseline: Collection[str] = ()
    ) -> None:
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
        derived_dirs = derived_roots(self.context)

        def _operator_wrote(value: Any, option: str) -> bool:
            from automated_security_helper.config.operator_only_options import (
                operator_wrote_value,
            )

            if option in loaded_from_baseline:
                # The entry is the baseline file's content, not a write of the
                # operator's own configuration.
                return False
            return operator_wrote_value(
                getattr(self.context, "config", None),
                "scanner",
                "detect-secrets",
                ("options", "scan_settings", option, "path"),
                value,
                config_from_context=self._config_from_context,
            )

        def _checked(value: Any, key: str, option: str) -> tuple[bool, Any]:
            """(keep, value to use) for one entry's path."""
            if value is None:
                return True, value
            if not isinstance(value, str) or not value.startswith("file://"):
                # A dotted path is imported by the worker. Only detect-secrets'
                # own modules are named that way; anything else needs file://.
                if isinstance(value, str) and value.startswith("detect_secrets."):
                    return True, value
                # The key, not the value, which may have been read from the
                # environment (as the path checks below name it).
                ASH_LOGGER.warning(
                    f"Ignoring {key}: only detect-secrets' own plugins "
                    "and filters may be named by module path. Name another one "
                    "with an absolute file:// path outside the scanned tree."
                )
                return False, value
            file_part, separator, function = value[len("file://") :].partition("::")
            if not Path(file_part).is_absolute():
                ASH_LOGGER.warning(
                    f"Ignoring {key}: a file:// path must be absolute, "
                    "because detect-secrets resolves a relative one from its own "
                    "working directory."
                )
                return False, value
            honored = honored_path(
                file_part,
                source_dir=source_dir,
                key=key,
                config=getattr(self.context, "config", None),
                derived_dirs=derived_dirs,
                operator_written=_operator_wrote(value, option),
            )
            if honored is None:
                return False, value
            return True, f"file://{honored.as_posix()}{separator}{function}"

        plugins_key = (
            "scanners.detect-secrets.options.scan_settings.plugins_used[].path"
        )
        plugins = []
        for plugin in settings.plugins_used:
            keep, value = _checked(
                getattr(plugin, "path", None), plugins_key, "plugins_used"
            )
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
            keep, value = _checked(item.path, filters_key, "filters_used")
            if keep:
                item.path = value
                filters.append(item)
        settings.filters_used = filters

    def _untrusted_baseline_reason(
        self, record: Optional[UntrustedDetectSecretsSettings]
    ) -> Optional[str]:
        """Why the baseline's settings are not the operator's, or None when they are.

        A baseline inside the scanned tree, or inside a git checkout that holds the
        scanned tree, is the repository's whichever config named it
        (``scanned_checkout_reason``); ``detect-secrets scan`` writes the verification
        filter into every baseline it generates, so a repository's
        ``.secrets.baseline`` normally carries it. One outside both, in another
        checkout included, is the operator's when the config is, or when the
        operator's own settings name that same ``baseline_file``
        (``--config-overrides``, or a workspace's default config, beside a
        repository's own config).
        """
        if not self._baseline_in_use():
            return None
        baseline = self._baseline_file_path()
        config = getattr(self.context, "config", None)
        root = getattr(config, "_scanned_root", None) or self.context.source_dir
        why = scanned_checkout_reason(Path(baseline), root)
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
                    "names a baseline that does, outside the scanned tree and the "
                    "git checkout holding it (another checkout counts).",
                    level=logging.INFO if offline else logging.WARNING,
                )
            if files:
                self._plugin_log(
                    f"Not loading the detect-secrets plugin or filter files "
                    f"{', '.join(files)}: {why}. A plugin or filter named by file is "
                    "loaded only from the operator's own ASH config, or a baseline "
                    "it names outside the scanned tree and the git checkout holding "
                    "it, and only from a file outside the scanned tree and every git "
                    "checkout.",
                    level=logging.WARNING,
                )

    @staticmethod
    def _get_baseline_exclude_patterns(
        scan_settings_dict: Dict[str, Any],
        values: Tuple[str, ...] = (),
    ) -> List[re.Pattern]:
        """Extract file exclusion regex patterns from scan settings filters.

        Looks for detect_secrets.filters.regex.should_exclude_file entries
        in the filters_used configuration and compiles their patterns.

        Args:
            scan_settings_dict: The scan settings the filters are read from.
            values: The config's environment values; a pattern that does not
                compile is quoted back in a WARNING, and the warning is
                redacted with these.

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
                for index, p in enumerate(raw_patterns):
                    try:
                        patterns.append(re.compile(p))
                    except re.error as e:
                        # re.error's own text quotes a fragment of the pattern,
                        # which whole-value redaction cannot match, so a pattern
                        # holding a configured value gets the entry index and
                        # the position only (pattern_error_text).
                        ASH_LOGGER.warning(
                            text_without_values(
                                f"Invalid exclude pattern '{p}' (entry {index}) "
                                f"in baseline: {pattern_error_text(e, p, values)}",
                                values,
                            )
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
        """The arguments after the interpreter that run one scan in
        ``utils/detect_secrets_worker.py``.

        Not the interpreter itself: ``python_child`` puts ASH's own first (and
        ``-P`` after it where Python has the flag), so the worker sees the same
        detect-secrets. A ``sys.executable`` here would be the second one on the
        command line, which Python reads as the script to run: it opens the
        interpreter's executable file as source and stops on its null bytes.
        A separate method so tests can substitute the worker.
        """
        return [
            "-m",
            "automated_security_helper.utils.detect_secrets_worker",
            str(request_file),
            str(output_file),
        ]

    def _worker_output_mib(self) -> int:
        """The scanner's max_worker_output_mib, or the default where the
        options do not hold a whole number from 1 to MAX_WORKER_OUTPUT_MIB (a
        config built without validation)."""
        options = getattr(self.config, "options", None)
        value = getattr(options, "max_worker_output_mib", None)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 < value <= MAX_WORKER_OUTPUT_MIB
        ):
            return DEFAULT_WORKER_OUTPUT_MIB
        return value

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
        request_file = work_dir.joinpath(WORKER_REQUEST_FILE_NAME)
        output_file = work_dir.joinpath(WORKER_OUTPUT_FILE_NAME)

        warned: List[str] = []

        def remove(name: str) -> None:
            # Removed as the start-of-scan cleanup removes these names:
            # beneath the directory without following a link
            # (unlink_beneath), and rooted at the work directory's PARENT so
            # the work directory itself is opened without following one too.
            # In a scan that parent is the scanner's results directory, the
            # registered writable root, which is the root the start-of-scan
            # cleanup uses. The finally below runs right after the sandboxed
            # process ended, the moment a process that outlived it could have
            # replaced the work directory, or a name in it, with a link (the
            # fs_guard threat model); a removal rooted at the work directory
            # would follow that link and delete these names wherever it led.
            # A refused work directory leaves the files where it points, so
            # that is said, once per run, rather than left silent.
            if unlink_beneath(work_dir.parent, (work_dir.name, name)) or warned:
                return
            warned.append(name)
            ASH_LOGGER.warning(
                text_without_values(
                    "The detect-secrets worker's exchange files were not "
                    f"removed from {work_dir}: it is a link or not a "
                    "directory, and the removal does not follow one. Remove "
                    "them where it points.",
                    self._environment_values(),
                )
            )

        # Both names go before the request is written. The output, so a stale
        # one is never read back as this run's; the request, so this run's is
        # created 0o600 rather than reusing a file a killed run left behind,
        # which open_for_write would truncate but leave at its own mode. A
        # work directory these removals refuse (a link, or not a directory)
        # ends the scan here, before anything is written: outside a sandbox
        # open_for_write follows the link, and the request (environment-derived
        # settings) and the raw findings would land where it points, where this
        # run's own removal refuses to clean them up.
        for name in (WORKER_OUTPUT_FILE_NAME, WORKER_REQUEST_FILE_NAME):
            if not unlink_beneath(work_dir.parent, (work_dir.name, name)):
                # A link there is named the way every other write below the
                # output directory names a link it refuses (OutputLinkRefused),
                # with or without a sandbox.
                link_refusal = (
                    f" {OutputLinkRefused(request_file, work_dir).strerror}."
                    if work_dir.is_symlink()
                    else ""
                )
                raise ScannerError(
                    text_without_values(
                        f"The detect-secrets worker's directory {work_dir} is "
                        "a link or not a directory, so nothing was written "
                        "through it. Replace it with a directory to scan."
                        f"{link_refusal}",
                        self._environment_values(),
                    )
                )
        with open_for_write(request_file, mode=0o600) as fp:
            # Owner-only from its first instant: the settings below can hold
            # environment-derived values, and the results directory is what CI
            # uploads, so the file is CREATED 0o600 (open_for_write's mode) --
            # permissions are checked at open, and a default-mode create
            # tightened afterwards left a window in which a local reader who
            # opened the empty file kept read access to the JSON written next.
            # fchmod only tightens a file that still existed at the open (one
            # the removal above refused, or one recreated since), and that
            # tighten is best-effort: a filesystem that refuses chmod (CIFS,
            # some FUSE mounts) costs a DEBUG line, not the scan. Windows has
            # no fchmod before 3.13, and from 3.13 it only toggles the
            # read-only bit; the file keeps the platform default there.
            if hasattr(os, "fchmod"):
                try:
                    os.fchmod(fp.fileno(), 0o600)
                except OSError as e:
                    ASH_LOGGER.debug(
                        "could not tighten an existing worker request file: "
                        f"{type(e).__name__}"
                    )
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
            # `python -m` puts the working directory first on sys.path, so the
            # worker starts in an empty directory of its own (and with -P where
            # Python has it) rather than in the scanned tree or the results
            # directory under it, where a `detect_secrets/` or
            # `automated_security_helper/` package would replace the real one. The
            # directory is under work_dir, which a sandboxed worker can see.
            # Unless this scan may verify, the worker's environment carries
            # REFUSE_HTTP_ENV, so every HTTP request detect-secrets tries fails
            # before it leaves the process. The run's environment values go to
            # the runner, so the lines it logs itself (a timeout's limit among
            # them) name an env-typed limit as its option rather than print it.
            with python_child(
                *self._worker_command(request_file, output_file), parent=work_dir
            ) as child:
                response = run_command_with_output_handling(
                    command=child.argv,
                    stdout_preference="return",
                    stderr_preference="return",
                    cwd=child.cwd,
                    env={
                        **{
                            key: value
                            for key, value in snapshot_environ().items()
                            if key != REFUSE_HTTP_ENV
                        },
                        **({} if verify else {REFUSE_HTTP_ENV: "1"}),
                    },
                    encoding="utf-8",
                    errors="replace",
                    timeout=scan_timeout,
                    values=self._environment_values(),
                )
            if response.get("timed_out"):
                # The limit through the shared token (_timeout_limit_token),
                # the same one the base class's timeout error prints, so the
                # two messages cannot drift and an environment-derived number
                # never reaches either. The values come from the one guarded
                # read: a hook that raised or gave no usable answer cannot
                # abort this record, which loses the limit instead.
                read = guarded_values_read(self)
                if read.values is None:
                    self._plugin_log(
                        "detect-secrets scan timed out (the limit is not shown: "
                        f"the plugin's values hook {read.failure()})",
                        level=logging.WARNING,
                        append_to_stream="stderr",
                    )
                    return None
                self._plugin_log(
                    text_without_values(
                        "detect-secrets scan timed out after "
                        f"{timeout_limit_token(scan_timeout, read.values)}",
                        read.values,
                    ),
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
            # Read back without following a link at any component below the
            # writable root (read_bytes_at_most), and bounded: a process the
            # sandboxed worker left behind may have replaced the file since.
            limit_mib = self._worker_output_mib()
            limit = limit_mib << 20
            data = read_bytes_at_most(output_file, limit + 1)
            if len(data) > limit:
                # At the cap the option cannot be raised, so ignore_paths is
                # the only advice left.
                if limit_mib >= MAX_WORKER_OUTPUT_MIB:
                    raise ScannerError(
                        "The detect-secrets worker's output is larger than "
                        f"{limit_mib} MiB, the most max_worker_output_mib "
                        "allows, so none of its findings were read. Leave the "
                        "files that produce most of the findings out of the "
                        "scan with ignore_paths."
                    )
                raise ScannerError(
                    "The detect-secrets worker's output is larger than "
                    f"{limit_mib} MiB, the scanner's max_worker_output_mib, so "
                    "none of its findings were read. Raise "
                    "scanners.detect-secrets.options.max_worker_output_mib (at "
                    f"most {MAX_WORKER_OUTPUT_MIB}) with --config-overrides or a "
                    "config file outside the scanned tree, or leave the files "
                    "that produce most of the findings out of the scan with "
                    "ignore_paths."
                )
            scanned = json.loads(data)
        finally:
            # Each name on its own, as the start-of-scan cleanup removes them:
            # a refusal at one (a directory a process the worker left behind
            # put at the name, a filesystem that refuses the unlink) still
            # lets the other's removal run, and it is a warning, not an error
            # that would replace this scan's own result or exception.
            for name in (WORKER_REQUEST_FILE_NAME, WORKER_OUTPUT_FILE_NAME):
                try:
                    remove(name)
                except OSError as e:
                    ASH_LOGGER.warning(
                        text_without_values(
                            f"Could not remove the detect-secrets worker's "
                            f"{name} from {work_dir}: {error_text(e)}. Remove "
                            "it before the next scan.",
                            self._environment_values(),
                        )
                    )

        from automated_security_helper.utils.detect_secrets_worker import (
            START_COLUMN_KEY,
        )

        collection = secrets_collection_cls()
        collection.root = root
        # (file key, secret hash, type) -> the column the worker found the secret
        # at, for the SARIF region.
        self._secret_columns: Dict[tuple[str, str, str], int] = {}
        for key, secrets in scanned:
            for secret in secrets:
                loaded = PotentialSecret.load_secret_from_dict(secret)
                collection.data[key].add(loaded)
                column = secret.get(START_COLUMN_KEY)
                if isinstance(column, int) and column > 0:
                    self._secret_columns[(key, loaded.secret_hash, loaded.type)] = (
                        column
                    )
        return collection

    def _finding_uri(self, key: str, scan_root: Path) -> str:
        """The URI of the file detect-secrets keyed as *key*, relative to the source.

        ``SecretsCollection.scan_files`` keys one file by the name it was handed,
        which here is absolute, and two or more by ``os.path.relpath`` to ``root``.
        The URI was then ``get_shortest_name(key)``, relative to the working
        directory: run from an ancestor of the source directory, a scan set of one
        file reported ``proj/app.py`` where two files reported ``app.py``, and an
        ASH config in ``.ash/`` is a second file. Both keys are made absolute here
        and then relative to the source directory, as the path sanitizer reads
        them; a converted file outside the source directory stays absolute.
        """
        path = Path(key)
        if not path.is_absolute():
            path = Path(scan_root).absolute() / path
        path = Path(os.path.normpath(path))
        source = Path(os.path.abspath(self.context.source_dir))
        if path.is_relative_to(source):
            return path.relative_to(source).as_posix()
        return path.as_posix()

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
        # A run killed outright never reaches _scan_in_worker's finally, so its
        # worker exchange files survive in the results directory, which is what
        # CI uploads. They belong to no later run: remove them before every
        # early return -- an empty target, a failed pre-scan, missing
        # dependencies -- so this scan's upload cannot carry them. Removed
        # beneath the results directory without following a link
        # (unlink_beneath), as open_for_write refuses one on the write, so a
        # planted link cannot route the removal outside. A directory sitting at
        # a name, or any other refusal, is logged and left in place rather
        # than failing this cleanup: a scan that goes on to reach the worker
        # still fails at that directory (the write refuses it) until the
        # operator removes it, and the warning says so. A target directory that
        # is a link is refused here without a warning of its own: a scan that
        # reaches the worker refuses the same link before writing anything, and
        # its error names it.
        # Per target; see ScannerPluginBase.scan(). targets_attempted is the number
        # of files given to detect-secrets, set below; None until then (no claim).
        self.exit_code = 0
        self.targets_attempted: Optional[int] = None
        for stale_worker_file in (
            WORKER_REQUEST_FILE_NAME,
            WORKER_OUTPUT_FILE_NAME,
        ):
            try:
                unlink_beneath(
                    Path(self.results_dir).absolute(),
                    (target_type, stale_worker_file),
                )
            except IsADirectoryError:
                ASH_LOGGER.warning(
                    f"A directory sits at {stale_worker_file} in the "
                    f"{target_type} results directory; leaving it in place. "
                    "A scan that reaches the detect-secrets worker will fail "
                    "at it until it is removed."
                )
            except OSError as e:
                ASH_LOGGER.warning(
                    text_without_values(
                        f"Could not remove a stale {stale_worker_file} from "
                        f"the {target_type} results directory: {error_text(e)}",
                        self._environment_values(),
                    )
                )
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

        # The config dumps are _pre_scan's DEBUG lines (scanner_plugin); the
        # copy this method logged repeated them with its own model_dump
        # handling, which could drift from the base class's.
        values = self._environment_values()

        try:
            secrets_collection_cls, _, _ = _detect_secrets_api()
            self._secrets_collection = secrets_collection_cls()
            # Empty until a worker scan fills it; see _scan_in_worker.
            self._secret_columns = {}
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
                and self._baseline_in_use()
                and self._baseline_document is not None
            ):
                # The copy _process_config_options parsed from the checked path
                # (_read_baseline); the file is never reopened, so a path swapped
                # for a link after the check is not followed.
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
            # ASH's own output is not tested for here: the scan set already
            # leaves it out. ASH writes its output underneath the source tree by
            # default, and the scan-set walk skips the directories ASH names as its
            # output (utils/scan_output_dirs.py), keeping only the files git tracks
            # there. Those are the repository's own files, and a repository must
            # not be able to hide one from ASH by committing it under the output
            # directory. A second test here, which left out every file under the
            # output directory, did exactly that: with the default
            # ``<source>/.ash/ash_output``, a key committed to it was not scanned.
            # The executor drops what a scanner reports in ASH's own files anyway.
            #
            # The converted branch enumerates ``work_dir``, the converters' output,
            # which is inside ``output_dir`` and is scanned whole.
            candidates = (
                list(self.context.work_dir.glob("**/*.*"))
                if target_type == "converted"
                else scan_set(
                    source=self.context.source_dir,
                    output=self.context.output_dir,
                    honor_ignore_files=honors_ignore_files(self.context.config),
                    run_id=getattr(self.context, "run_id", None),
                )
            )
            skipped_names = (
                frozenset(KNOWN_GENERATED_LOCKFILE_NAMES)
                if self.config.options.skip_generated_lockfiles
                else frozenset()
            )
            scannable = [
                str(item) for item in candidates if Path(item).name not in skipped_names
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
            exclude_patterns = self._get_baseline_exclude_patterns(
                scan_settings_dict, values
            )
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
                    ignore_path_matches as path_matches_pattern,
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

            # Nothing to scan is SKIPPED (targets_attempted 0), not PASSED.
            self.targets_attempted = len(scannable)
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
            from automated_security_helper.config.environment_record import (
                setting_names,
            )

            # Which settings, never their values: beyond the environment-read
            # values text_without_values hides, a setting's own content (a
            # filter's pattern) does not belong in the log either.
            ASH_LOGGER.debug(
                f"Settings: {setting_names(scan_settings_dict)}", extra=NO_MARKUP
            )
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
                uri = self._finding_uri(filename, scan_root)
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
                                text=f"Secret of type '{finding.type}' detected in file '{uri}' at line {finding.line_number}"
                            ),
                            locations=[
                                Location(
                                    id=1,
                                    physicalLocation=PhysicalLocation(
                                        artifactLocation=ArtifactLocation(
                                            uri=uri,
                                        ),
                                        region=Region(
                                            startLine=finding.line_number,
                                            endLine=finding.line_number,
                                            # Where the secret starts, so two of
                                            # one type on one line are two
                                            # findings; see _scan_in_worker.
                                            startColumn=self._secret_columns.get(
                                                (
                                                    filename,
                                                    finding.secret_hash,
                                                    finding.type,
                                                )
                                            ),
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
            # The failure can name the baseline file, which can be a value the
            # config read from the environment.
            raise ScannerError(
                text_without_values(
                    f"{self.__class__.__name__} failed: {str(e)}", values
                )
            )


if __name__ == "__main__":
    scanner = DetectSecretsScanner(
        source_dir=Path.cwd(),
        output_dir=Path.cwd().joinpath(".ash", "ash_output"),
    )
    scanner.scan(target=Path.cwd())
