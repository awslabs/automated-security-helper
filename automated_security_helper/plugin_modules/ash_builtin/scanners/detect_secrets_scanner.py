import logging

"""Module containing the detect-secrets security scanner implementation."""

from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import importlib.util
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
    Iterable,
    List,
    Literal,
    Mapping,
    Optional,
    Set,
    Tuple,
)

from pydantic import ConfigDict, Field, PrivateAttr

from automated_security_helper.utils.redacted_model import (
    RedactedSection,
    environment_strings,
)
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.config.client_scanner_exclusions import (
    evaluated_within,
    files_kept_by_patterns,
)
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
    Kind1,
    Level,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Region,
    Result,
    Run,
    SarifReport,
    Suppression,
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

#: The detect-secrets filter whose ``pattern`` entries leave files out of the
#: scan. ASH applies it to the scan set itself, against each file's path
#: relative to the scan root, and does not hand it to the worker.
SHOULD_EXCLUDE_FILE_FILTER = "detect_secrets.filters.regex.should_exclude_file"

#: The detect-secrets filter that drops a candidate whose value is in a word
#: list. detect-secrets opens the list's ``file_name`` when the settings are
#: applied, in the worker, from the worker's own working directory, and the
#: filter needs the optional ``pyahocorasick`` package. ASH anchors the file
#: where it was named and checks both before the settings reach the worker
#: (``_check_wordlist_filter``).
WORDLIST_FILTER = "detect_secrets.filters.wordlist.should_exclude_secret"
#: The ``min_length`` detect-secrets' own ``wordlist.initialize`` defaults to.
WORDLIST_DEFAULT_MIN_LENGTH = 3

#: The type detect-secrets reports for a run of hex digits with high entropy, which
#: is how it reads the ``hashed_secret`` values a baseline lists
#: (``DetectSecretsScanner._baseline_hash_echoes``).
HEX_HIGH_ENTROPY_TYPE = "Hex High Entropy String"


def _module_importable(name: str) -> bool:
    """Whether ``name`` can be imported by this interpreter, without importing it.

    The worker runs the same interpreter (``python_child``), so what cannot be
    found here cannot be found there either.
    """
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


class DetectSecretsScanSettingsPluginsUsed(RedactedSection):
    # Built directly from a baseline's entries, so a refused value must not be
    # quoted in the error's text (a baseline's entry can hold a secret).
    model_config = ConfigDict(extra="allow", hide_input_in_errors=True)
    # The baseline segments keep no external plugin's raw config in their
    # extras, so a reference left in one leaves validation as plain text.
    _downcast_extras: ClassVar[bool] = True
    name: str | None = None
    limit: float | None = None
    keyword_exclude: str | None = None


class DetectSecretsScanSettingsFiltersUsed(RedactedSection):
    model_config = ConfigDict(extra="allow", hide_input_in_errors=True)
    _downcast_extras: ClassVar[bool] = True
    path: str | None = None
    min_level: int | None = None
    keyword_exclude: str | None = None


class DetectSecretsScanSettingsResults(RedactedSection):
    model_config = ConfigDict(extra="allow")
    _downcast_extras: ClassVar[bool] = True
    __pydantic_extra__: Dict[str, List[Any]] = {}


class DetectSecretsScanSettings(RedactedSection):
    model_config = ConfigDict(extra="allow")
    _downcast_extras: ClassVar[bool] = True
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

    # The chosen baseline as it was named, anchored to the source directory but
    # with no link resolved: the path whose location decides whose settings the
    # baseline carries (_untrusted_baseline_reason) and whether an MCP client
    # delivered it (_baseline_refusal). A ``.secrets.baseline`` inside the tree
    # that is a link to a file outside it is judged where it sits, not where it
    # points. None until a baseline is chosen.
    _baseline_named: Optional[Path] = PrivateAttr(default=None)

    # Whether the chosen baseline came from the baseline_file option rather than
    # from the tree's own ``.secrets.baseline`` locations. One of the two facts
    # that decide whether the baseline's entries may leave the report
    # (_baseline_entries_trusted).
    _baseline_from_option: bool = PrivateAttr(default=False)

    # Whether the settings, as configured, may verify secrets with their issuers.
    # Decided once from where each setting came from (_apply_settings_trust); the scan
    # checks it again, so a verification filter added afterwards does not run.
    _verification_permitted: bool = PrivateAttr(default=False)

    # ``id()`` of each ``filters_used`` entry the operator's own configuration
    # holds, as the settings stand after the baseline's filters were added
    # beside them and the trust rules ran. The scan matches an operator entry's
    # exclude patterns against the scan root, where the operator wrote them, and
    # the baseline's against the baseline's own anchor (_baseline_anchor).
    _operator_filter_ids: Set[int] = PrivateAttr(default_factory=set)

    # The same entries by position in ``filters_used``, and the list's length when
    # they were recorded. The base ``_pre_scan`` rebuilds ``self.config`` from a
    # dump of the config it is given, which makes new filter objects with new
    # ``id()`` values in the same order; the position is what survives that
    # (``_rekey_operator_filter_ids``).
    _operator_filter_positions: Set[int] = PrivateAttr(default_factory=set)
    _operator_filter_total: int = PrivateAttr(default=0)

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
        verifying = self._verifies(self.config.options.scan_settings.filters_used)
        return SandboxRequirements(network=verifying, network_requires_grant=True)

    @staticmethod
    def _verifies(filters: Optional[Iterable[Any]]) -> bool:
        """Whether a ``filters_used`` list turns detect-secrets' verification on.

        The one reading for every place that decides it. ``sandbox_requirements``
        and ``_apply_settings_trust`` read the settings model, whose entries carry
        a ``path`` attribute; ``scan`` reads the dictionary dumped for the worker,
        whose entries are mappings with a ``path`` key. Each site used to spell
        the check itself, and the two spellings could answer differently for the
        same settings (a sandbox asked for no network while the worker was told
        to verify, or the reverse). An entry of neither shape, or one with no
        path, enables nothing.
        """
        for item in filters or ():
            if isinstance(item, Mapping):
                path = item.get("path")
            else:
                path = getattr(item, "path", None)
            if is_verification_filter(path):
                return True
        return False

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

        # The scan runs the in-process library (utils/detect_secrets_worker.py), never
        # the CLI, so there is nothing to ask uv; a probe here started a tool for a log line.
        return True

    def _pre_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        config: Optional[ScannerPluginConfigBase] = None,
        *args,
        **kwargs,
    ) -> bool:
        """The base's pre-scan, then the settings of a config it swapped in.

        The base replaces ``self.config`` with the ``config`` argument when one
        is given. This scanner's settings are worked out from the config once,
        in ``_process_config_options`` (the baseline's plugins and filters, the
        default plugin set, the trust rules), so a config that arrives this way
        with default ``scan_settings`` failed the scan with "configured with no
        detect-secrets plugins" and skipped the baseline merge. The executor
        passes the very config the scanner was built from, whose settings that
        pass already filled in, so the swap changes nothing there; a config
        that differs is processed as a constructed one is.

        The swap does build new filter objects even when the dumps match, so
        the record of which ``filters_used`` entries are the operator's, kept
        by object identity, would point at objects that are gone: every entry
        then read as the baseline's, and the operator's exclude patterns were
        matched at the baseline's anchor. When the dumps match, the record is
        carried over by position instead.
        """
        before = None if config is None else self.config.model_dump(by_alias=True)
        validated = super()._pre_scan(target, target_type, config, *args, **kwargs)
        if validated and before is not None:
            if self.config.model_dump(by_alias=True) != before:
                self._process_config_options()
            else:
                self._rekey_operator_filter_ids()
        return validated

    def _rekey_operator_filter_ids(self) -> None:
        """Point the operator-authorship record at the entries the config swap made.

        The swap keeps the order and the length of ``filters_used``, so an entry
        recorded at a position is the entry at that position now. A list whose
        length is not the recorded one was changed after it was recorded, and
        nothing is carried over: those entries read as the baseline's, the
        one-anchor behavior ``_exclude_patterns_by_author`` documents.
        """
        entries = list(self.config.options.scan_settings.filters_used)
        if len(entries) != self._operator_filter_total:
            self._operator_filter_ids = set()
            return
        self._operator_filter_ids = {
            id(item)
            for position, item in enumerate(entries)
            if position in self._operator_filter_positions
        }

    def _configured_baseline_file(self) -> Path | str | None:
        """The ``baseline_file`` option, or None when it names nothing.

        An empty string resolves to the source directory itself, which was then
        chosen as the baseline, failed as "not a regular file", and stood in the
        way of the tree's own ``.secrets.baseline``. It is read as unset, as an
        operator who writes ``baseline_file: ""`` means it.
        """
        value = self.config.options.baseline_file
        if isinstance(value, str) and not value.strip():
            return None
        return value

    def _baseline_in_use(self) -> bool:
        """Whether the scan reads a baseline. A configured baseline that is not
        on disk, or that is refused as a derived work product, is decided
        here, where the baseline is used, and not by clearing the option: the
        config model keeps the value as written so every dump of it shows what
        the operator wrote."""
        return (
            (
                self._configured_baseline_file() is not None
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
            self._configured_baseline_file() or "",
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
        # Each entry as the sandbox policy reads it (policy._expand): ``~`` and
        # variables expanded, and an entry that is empty, relative or still
        # holds an unexpanded variable grants nothing. Resolving such an entry
        # here made it a root at the process's working directory, which the
        # sandbox never mounts, so a baseline under that directory was read
        # outside the sandbox and its contents handed to the worker.
        roots = []
        for entry in getattr(sandbox, "extra_read_paths", None) or []:
            expanded = os.path.expandvars(os.path.expanduser(str(entry)))
            if "$" in expanded or not os.path.isabs(expanded):
                continue
            roots.append(Path(os.path.realpath(expanded)))
        if any(is_within(real, root) for root in roots):
            return None
        return (
            "it is outside the source tree and every sandbox.extra_read_paths entry, "
            "which a granted baseline outside the tree has to be inside"
        )

    @staticmethod
    def _read_baseline(real: Path) -> Dict[str, Any]:
        """Parse the baseline at ``real``, the resolved path that was checked.

        Only a regular file is opened, without following a link at its last
        component, and the opened file must have the device and inode ``real``
        named just before. The open does not block (``O_NONBLOCK``), so a FIFO
        put at the name between the check and the open is opened at once and
        then refused by that comparison instead of holding the scan until
        something writes to it; a regular file reads the same with the flag.
        That binds the read to the resolved path; a directory above it swapped
        for a link between the check and this stat is not detected, which needs
        a writer to the source tree while the scan runs, and a sandboxed scanner
        may only read it.

        Decoded as UTF-8, the encoding detect-secrets writes a baseline in,
        whatever the locale: a text-mode open with no encoding read it with the
        locale's, so a baseline holding a non-ASCII file name was refused, or
        its keys misread, on a non-UTF-8 locale (Windows cp1252).
        """
        checked = os.stat(real)
        if not stat.S_ISREG(checked.st_mode):
            raise OSError(f"{real.as_posix()} is not a regular file")
        fd = os.open(
            real,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != (checked.st_dev, checked.st_ino):
                raise OSError(f"{real.as_posix()} changed while it was being read")
            return json.load(handle)

    @staticmethod
    def _check_baseline_shape(document: Any) -> None:
        """Refuse a baseline that parses as JSON but is not a baseline.

        The shape ``detect-secrets`` writes and reads: ``document["results"]``
        is a mapping of filename to a list of entries, each an object with a
        string ``type`` and ``hashed_secret`` (``PotentialSecret.load_secret_from_dict``
        reads both by key). The scanner's own reading of the entries
        (``_baseline_known``) needs the same two fields to match a candidate,
        and the worker, when a request hands it a baseline, loads it with
        ``SecretsCollection.load_from_baseline``, which raises KeyError or
        TypeError on anything else. A document of another shape is not a
        baseline, so the scan runs without one, as for a missing file. The
        message names the shape, never the content: a baseline's entries can
        hold a secret.

        Raises:
            ValueError: the document is not an object, its ``results`` is not a
                mapping of lists, or an entry is not an object with a string
                ``type`` and ``hashed_secret``.
        """
        if not isinstance(document, dict):
            raise ValueError("the baseline is not a JSON object")
        results = document.get("results")
        if not isinstance(results, dict):
            raise ValueError("the baseline's 'results' is not a JSON object")
        for entries in results.values():
            if not isinstance(entries, list):
                raise ValueError("a 'results' entry of the baseline is not a list")
            for item in entries:
                if not isinstance(item, dict):
                    raise ValueError(
                        "a 'results' entry of the baseline holds an item that is "
                        "not a JSON object"
                    )
                if not isinstance(item.get("type"), str) or not isinstance(
                    item.get("hashed_secret"), str
                ):
                    raise ValueError(
                        "a 'results' entry of the baseline holds an item without "
                        "a string 'type' and 'hashed_secret'"
                    )

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
        self._baseline_named = None
        self._baseline_from_option = False
        # Every record of a previous pass, so a second pass starts from its
        # own config: a trust refusal left standing kept a later, readable
        # baseline out of use, and a parsed document left standing was handed
        # to the worker as this pass's baseline.
        self._baseline_trust_refused = False
        self._baseline_real = None
        self._baseline_document = None
        possible_baseline_paths = [
            (item, from_option)
            for item, from_option in [
                (self._configured_baseline_file(), True),
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
        from automated_security_helper.config.sandbox_grants import (
            checkout_containing,
            is_within,
        )

        context_config = getattr(self.context, "config", None)
        source_dir = Path(getattr(self.context, "source_dir", None) or ".")
        # Where an in-tree baseline that is a link may point: the NEAREST git
        # checkout holding the scanned directory (the repository whose file
        # the link is; a monorepo's ``service/`` is inside it), or the scanned
        # directory itself when no checkout holds it. Not every ancestor
        # checkout: a scan under a home directory that is itself a checkout
        # would otherwise let a committed link reach any file under that
        # home. The settings-trust rule (_untrusted_baseline_reason) still
        # judges by every enclosing checkout, which only widens what reads as
        # the repository's. Resolved, as every other root is_within is given
        # here: is_within compares by samefile, so the resolution changes no
        # answer, but a root spelled through a link reads the same as the
        # other callers' and is not a question for the next reader.
        admitted_link_root = Path(
            os.path.realpath(checkout_containing(source_dir) or source_dir)
        )

        # Look through each baseline file path to see if it exists and configure
        # the scan settings according to the first baseline file found. Each
        # candidate is resolved once, from the scanned tree as the gate does,
        # and that one path is what is checked for existence, stored and later
        # opened, so the file read is the file the gate checked whatever
        # directory the process runs in. The candidate is JUDGED by the path
        # as named, anchored to the source directory with no link resolved
        # (``named``): a ``.secrets.baseline`` in the tree that is a link to a
        # file outside it was judged by its target's location, which made the
        # repository's settings, its verification filter included, read as the
        # operator's. ``named`` is made absolute and normalized (``..`` parts
        # folded, still no link resolved): a library caller can pass a relative
        # source directory, and the gate and the trust rule compare paths, so a
        # relative or ``..``-bearing name compared as text and judged wrong. The
        # as-given spelling is kept for the redacted text and for the
        # operator-written comparison.
        chosen = None
        chosen_named = None
        chosen_from_option = False
        option_refused = False
        option_missing = None
        for baseline_path, from_option in possible_baseline_paths:
            resolved_baseline = resolved_path(baseline_path, source_dir)
            named = Path(os.path.expanduser(str(baseline_path)))
            if not named.is_absolute():
                named = source_dir / named
            named = Path(os.path.normpath(os.path.abspath(named)))
            ASH_LOGGER.debug(
                text_without_values(
                    f"Checking for detect-secrets config @ {baseline_path}",
                    values,
                )
            )
            if resolved_baseline.exists():
                if not from_option and not is_within(
                    resolved_baseline, admitted_link_root
                ):
                    # A baseline found in the tree is the repository's file,
                    # and the repository cannot need it to point outside its
                    # own checkout. Reading the target would read a file the
                    # repository chose anywhere on the scanning host, under
                    # the repository's own settings. The operator names such
                    # a file with baseline_file. A target elsewhere in the
                    # nearest checkout that holds the scanned directory (a
                    # monorepo's ``service/.secrets.baseline ->
                    # ../.secrets.baseline``) is read: it is the repository's
                    # own file, and the trust rule judges it as such, so
                    # reading it grants nothing. A target in an outer
                    # checkout above that one is not the repository's.
                    ASH_LOGGER.warning(
                        text_without_values(
                            f"Not reading the detect-secrets baseline "
                            f"{named.as_posix()} found in the scanned tree: it is "
                            "a link to a file outside the scanned directory and "
                            "the nearest git checkout that holds it. Name the "
                            "file with scanners.detect-secrets.options.baseline_file "
                            "to use it.",
                            values,
                        )
                    )
                    continue
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
                chosen_named = named
                chosen_from_option = from_option
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
            # path checked here is the one _read_baseline opens and binds to;
            # the named path is what an MCP client's delivered-tree test sees.
            real_baseline = Path(os.path.realpath(chosen))
            refusal = self._baseline_refusal(Path(chosen_named), real_baseline)
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
                self._baseline_named = Path(chosen_named)
                self._baseline_from_option = chosen_from_option
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
        # _apply_settings_trust judges each by its own source. The baseline's
        # filters are added beside the config's, which are kept whole: the
        # option's documentation gives scan_settings precedence over the baseline.
        config_filter_ids = {
            id(item) for item in self.config.options.scan_settings.filters_used
        }
        loaded_from_baseline: set = set()
        # The settings as configured, put back whole if the baseline turns out
        # malformed partway through the load below: a baseline whose plugins
        # parsed but whose filters did not had already replaced the configured
        # plugins, so the fallback ran the baseline's plugins with none of its
        # filters, not the default settings the warning names.
        settings_before = (
            list(self.config.options.scan_settings.plugins_used),
            list(self.config.options.scan_settings.filters_used),
        )
        if self._baseline_in_use() and self._baseline_real is not None:
            try:
                # Read once, bound to the resolved path the gate checked
                # (_read_baseline); the scan uses this same parsed copy and
                # never reopens the file.
                baseline_data = self._read_baseline(self._baseline_real)
                self._check_baseline_shape(baseline_data)
                self._baseline_document = baseline_data

                # Only apply baseline settings if scan_settings names no
                # plugins of its own. The option's documentation gives
                # scan_settings precedence over the baseline, and plugins_used
                # is what carries that: an operator who names detectors has
                # chosen them. ``version`` is a compatibility knob, not a
                # choice of settings; it used to gate this too, so naming a
                # version alone silently dropped the baseline's plugins and
                # its filters (the exclusions among them).
                if len(self.config.options.scan_settings.plugins_used) == 0:
                    # Load plugins from baseline
                    if "plugins_used" in baseline_data:
                        self.config.options.scan_settings.plugins_used = [
                            DetectSecretsScanSettingsPluginsUsed(**plugin)
                            for plugin in baseline_data["plugins_used"]
                        ]
                        loaded_from_baseline.add("plugins_used")
                    # Load filters from baseline (includes should_exclude_file, etc.)
                    # The operator's own filters_used stay, every entry: the
                    # option's documentation says scan_settings takes precedence
                    # over the baseline, and only the verification filter used
                    # to survive this replacement. A baseline entry whose path
                    # the operator also configured is the operator's.
                    if "filters_used" in baseline_data:
                        config_filters = list(
                            self.config.options.scan_settings.filters_used
                        )
                        config_paths = {item.path for item in config_filters}
                        self.config.options.scan_settings.filters_used = [
                            item
                            for item in (
                                DetectSecretsScanSettingsFiltersUsed(**f)
                                for f in baseline_data["filters_used"]
                            )
                            if item.path not in config_paths
                        ] + config_filters
                        loaded_from_baseline.add("filters_used")
                    ASH_LOGGER.debug(
                        f"Loaded settings from baseline: "
                        f"{len(self.config.options.scan_settings.plugins_used)} plugins, "
                        f"{len(self.config.options.scan_settings.filters_used)} filters"
                    )
            except (OSError, TypeError, ValueError) as e:
                # ValueError covers json.JSONDecodeError, UnicodeDecodeError,
                # pydantic's ValidationError from a wrong-shaped plugin or
                # filter entry, and _check_baseline_shape; TypeError a plugin
                # or filter entry that is not a mapping. Each used to escape
                # the constructor, or leave a document behind that failed
                # every scan. The scan runs with no baseline, as it does for
                # a missing file, and with the settings as configured.
                self._baseline_document = None
                self.config.options.scan_settings.plugins_used = settings_before[0]
                self.config.options.scan_settings.filters_used = settings_before[1]
                loaded_from_baseline.clear()
                ASH_LOGGER.warning(
                    text_without_values(
                        f"Failed to read baseline file settings: {error_text(e)}. "
                        f"Falling back to default settings.",
                        values,
                    )
                )

        self._drop_in_tree_settings_paths(loaded_from_baseline, config_filter_ids)
        self._check_wordlist_filter(loaded_from_baseline, config_filter_ids)
        self._apply_settings_trust(
            settings_from_baseline=bool(loaded_from_baseline),
            config_entries={
                id(item)
                for item in self.config.options.scan_settings.filters_used
                if id(item) in config_filter_ids
            },
        )
        # The operator's entries that survived both rules, by identity (the
        # rules rebuild the list but keep the objects); the scan reads this to
        # match each exclude pattern where its author wrote it.
        survivors = list(self.config.options.scan_settings.filters_used)
        self._operator_filter_ids = {
            id(item) for item in survivors if id(item) in config_filter_ids
        }
        self._operator_filter_positions = {
            position
            for position, item in enumerate(survivors)
            if id(item) in config_filter_ids
        }
        self._operator_filter_total = len(survivors)

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
        # The baseline block above is gated on the same empty ``plugins_used``,
        # so a run that reaches this line with a baseline has the baseline's
        # filters loaded, and the merge keeps them.
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
        self,
        loaded_from_baseline: Collection[str] = (),
        config_filter_ids: Collection[int] = (),
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

        ``loaded_from_baseline`` names the options the baseline filled;
        ``config_filter_ids`` is the ``id()`` of each ``filters_used`` entry the
        operator's own configuration holds. The baseline's filters are added
        beside the operator's, so authorship is per ENTRY for that option: an
        operator entry keeps its own writer's judgment whether or not the
        baseline also had filters. Judged per option, every retained operator
        ``file://`` filter read as the baseline's once the baseline had any,
        and one under a derived output or work directory, which the operator's
        own configuration may name, was refused with a warning.
        """
        settings = self.config.options.scan_settings
        source_dir = Path(self.context.source_dir)
        derived_dirs = derived_roots(self.context)
        config_filters = set(config_filter_ids)

        def _operator_wrote(value: Any, option: str, entry: Any) -> bool:
            from automated_security_helper.config.operator_only_options import (
                operator_wrote_value,
            )

            if option in loaded_from_baseline and not (
                option == "filters_used" and id(entry) in config_filters
            ):
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

        def _checked(value: Any, key: str, option: str, entry: Any) -> tuple[bool, Any]:
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
                operator_written=_operator_wrote(value, option, entry),
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
                getattr(plugin, "path", None), plugins_key, "plugins_used", plugin
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
            keep, value = _checked(item.path, filters_key, "filters_used", item)
            if keep:
                item.path = value
                filters.append(item)
        settings.filters_used = filters

    def _check_wordlist_filter(
        self,
        loaded_from_baseline: Collection[str] = (),
        config_entries: Collection[int] = (),
    ) -> None:
        """Keep the wordlist filter only when its source may supply it and the
        worker can apply it.

        The word list is a suppression surface: every candidate whose value is
        a line of the file leaves the report. So an entry the baseline's
        settings supplied is honored only when the baseline is the operator's,
        by the rule the verification filter and ``file://`` entries already
        follow (``_untrusted_baseline_reason``, applied in
        ``_apply_settings_trust``): a baseline inside the scanned tree or the
        checkout holding it, or named by a config the operator did not write,
        cannot hand the worker a list of values to drop. Without this, a
        repository's own ``.secrets.baseline`` named a relative word list, the
        entry was anchored at the baseline's directory, admitted on the file
        being there, and handed over, and the tree chose which of its own
        secrets the report would not show. An entry the operator's config
        wrote (``config_entries``, by identity) is the operator's whatever
        baseline is in use.

        detect-secrets applies ``WORDLIST_FILTER`` when the settings are
        installed (``configure_settings_from_baseline``): it imports the
        optional ``pyahocorasick`` package and opens the entry's ``file_name``
        from the current directory, and ``initialize`` reads ``min_length`` and
        ``file_hash`` from the entry. That runs in the worker, whose working
        directory is an empty directory of its own, so an entry a baseline
        wrote with a relative ``file_name`` (the usual form: ``detect-secrets
        scan --word-list words.txt``) failed the worker, and with it the whole
        scan, as did an entry without the package or without those keys.

        A relative name is anchored where the entry was written: the directory
        of the file that named it, per entry (``_wordlist_anchor``). For an
        entry the baseline supplied, the file it resolves to has to lie inside
        that directory or inside the scanned tree, trusted or not: a ``..``, an
        absolute name or a link that leaves both is refused. So is an entry of a
        configuration read from files the operator did not write (the record
        ``_untrusted_detect_secrets_settings``), which holds entries a
        repository chose. Only an entry of the operator's own configuration is
        not confined: an absolute name, or a relative one that leaves the
        directory of its config file, is the operator's to choose. The entry is
        kept with the resolved absolute path and the defaults detect-secrets'
        own ``initialize`` uses for the keys it lacks; one its source may not
        supply, one that resolves outside those places, one whose file is not a
        regular file, or one whose package is not importable, is dropped with a
        warning that names the key, never the value (which can come from the
        environment).
        """
        settings = self.config.options.scan_settings
        filters_from_baseline = "filters_used" in loaded_from_baseline
        # Set when the configuration was read from files the operator did not
        # write (resolve_config); the record is read whatever the baseline did,
        # because that configuration reaches the entries below as well.
        record = getattr(
            getattr(self.context, "config", None),
            "_untrusted_detect_secrets_settings",
            None,
        )
        untrusted: Optional[str] = None
        if filters_from_baseline:
            untrusted = self._untrusted_baseline_reason(record)
        kept = []
        for item in settings.filters_used:
            if item.path != WORDLIST_FILTER:
                kept.append(item)
                continue
            from_baseline = filters_from_baseline and id(item) not in config_entries
            reason = self._wordlist_filter_refusal(
                item,
                from_baseline=from_baseline,
                untrusted=untrusted if from_baseline else None,
                # An entry is the operator's own only when the configuration
                # that holds it is: one read from the repository's files is
                # confined like a baseline's entry.
                confine=from_baseline or record is not None,
            )
            if reason is None:
                kept.append(item)
                continue
            ASH_LOGGER.warning(
                "Ignoring the detect-secrets wordlist filter "
                f"(scan_settings.filters_used[].path == {WORDLIST_FILTER}): "
                f"{reason}. Candidates its word list would have excluded are "
                "reported."
            )
        settings.filters_used = kept

    def _wordlist_filter_refusal(
        self,
        item: Any,
        *,
        from_baseline: bool,
        untrusted: Optional[str] = None,
        confine: Optional[bool] = None,
    ) -> Optional[str]:
        """Why ``item``, a wordlist filter entry, cannot reach the worker; None
        when it can, with its ``file_name`` made absolute and its keys filled.

        ``untrusted`` is why the baseline the entry came from is not the
        operator's (``_untrusted_baseline_reason``), or None when it is or the
        entry is the operator's own. An untrusted entry is refused before its
        ``file_name`` is read or resolved.

        ``confine`` says whether the file the name resolves to has to lie in
        the entry's anchor directory or the scanned tree. It is True for an
        entry a baseline supplied and for any entry of a configuration the
        operator did not write; it defaults to ``from_baseline``.
        """
        if confine is None:
            confine = from_baseline
        if untrusted is not None:
            return (
                f"it was loaded from the baseline's settings, and {untrusted}. "
                "Every candidate whose value is a line of the word list leaves "
                "the report, so only the operator's own settings may supply "
                "one: name the filter in "
                "scanners.detect-secrets.options.scan_settings.filters_used, or "
                "name a baseline outside the scanned tree and the git checkout "
                "holding it"
            )
        file_name = getattr(item, "file_name", None)
        if not isinstance(file_name, str) or not file_name.strip():
            return "its entry names no word list file (file_name)"
        if not _module_importable("ahocorasick"):
            return (
                "it needs the pyahocorasick package, which is not installed for the "
                "interpreter ASH and its detect-secrets worker run in"
            )
        from automated_security_helper.config.sandbox_grants import is_within

        anchor = self._wordlist_anchor(from_baseline)
        path = Path(os.path.expanduser(file_name))
        if not path.is_absolute():
            path = anchor / path
        real = Path(os.path.realpath(path))
        # An entry a BASELINE supplied is confined to where the baseline sits or
        # to the scanned tree, by the file the name resolves to: a ``..``, an
        # absolute name or a link that leaves both is refused, trusted or not.
        # So is an entry of a configuration read from files the operator did
        # not write. Only an entry of the operator's own configuration is not:
        # the operator wrote the name, and an absolute path to a list kept
        # elsewhere on the host (the form that worked before this check) is the
        # operator's to choose. Who wrote the entry is what decides, not
        # whether a baseline was loaded: the repository's configuration holds
        # entries too.
        config = getattr(self.context, "config", None)
        scan_root = Path(
            os.path.realpath(
                getattr(config, "_scanned_root", None)
                or getattr(self.context, "source_dir", None)
                or "."
            )
        )
        if confine and not (is_within(real, anchor) or is_within(real, scan_root)):
            return (
                "its word list file (file_name) resolves outside the directory of "
                "the file that named the entry and outside the scanned directory "
                "(a `..`, an absolute name or a link that leaves both); a word "
                "list is read only from where its entry was written or from the "
                "scanned tree"
            )
        if not real.is_file():
            return (
                "its word list file (file_name) is not a regular file where the "
                "entry names it; the worker reads it from its own working "
                "directory, so a relative name is taken from the directory of "
                "the file that named the entry: the baseline's for a baseline "
                "entry, the config file's for a configured one (the source "
                "directory when the config was not read from a file)"
            )
        setattr(item, "file_name", real.as_posix())
        if getattr(item, "min_length", None) is None:
            setattr(item, "min_length", WORDLIST_DEFAULT_MIN_LENGTH)
        if getattr(item, "file_hash", None) is None:
            setattr(item, "file_hash", "")
        return None

    def _wordlist_anchor(self, from_baseline: bool) -> Path:
        """The directory a relative word list name is taken from.

        A relative ``file_name`` was written relative to the file that named the
        entry, so it is read from that file's directory: the baseline's for an
        entry the baseline's settings supplied, the config file's
        (``AshConfig._loaded_from``, the file resolve_config read the config
        from) for an entry the operator's config wrote. A config that was not
        read from a file (the defaults, or one built in code) anchors at the
        source directory. Judged per entry: before, one flag for the whole pass
        sent a configured entry's relative name to the baseline's directory
        whenever the baseline's filters were loaded beside it.
        """
        if from_baseline and self._baseline_real is not None:
            return self._baseline_real.parent
        loaded_from = getattr(
            getattr(self.context, "config", None), "_loaded_from", None
        )
        if loaded_from:
            return Path(os.path.realpath(loaded_from)).parent
        return Path(os.path.realpath(getattr(self.context, "source_dir", None) or "."))

    def _baseline_checkout_reason(self) -> Optional[str]:
        """Why the baseline in use is the repository's file by where it sits, or None.

        Judged by both the path as named and the file it resolves to; either
        inside the scanned tree or a git checkout holding it makes the
        baseline the repository's. An in-tree ``.secrets.baseline`` that is a
        link out of the tree is named inside it (_baseline_named); a path the
        operator names outside the tree that is a link INTO it resolves inside
        it, and the file read is the repository's whatever the name. The named
        path alone judged only the first case, so the second read the
        repository's settings, its verification filter included, as the
        operator's. The one reading for both trust rules: the settings of the
        baseline (_untrusted_baseline_reason) and the candidates it lists
        (_baseline_entries_trusted).
        """
        baseline = self._baseline_file_path()
        judged = self._baseline_named if self._baseline_named is not None else baseline
        config = getattr(self.context, "config", None)
        root = getattr(config, "_scanned_root", None) or self.context.source_dir
        why = scanned_checkout_reason(Path(judged), root)
        if why is None and Path(judged) != Path(baseline):
            why = scanned_checkout_reason(Path(baseline), root)
        return why

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

        A baseline the scan FOUND in the tree (``.secrets.baseline``,
        ``.ash/.secrets.baseline``) is the repository's by structure, the same
        rule ``_baseline_entries_trusted`` applies to its entries: the checkout
        test is tried first so the reason names the checkout where it can, but a
        found baseline is never the operator's when that test says nothing. It
        was: with the configured scan root (``_scanned_root``) not holding the
        source directory, the checkout test found nothing to say and the
        repository's settings, its verification filter included, read as the
        operator's.
        """
        if not self._baseline_in_use():
            return None
        baseline = self._baseline_file_path()
        why = self._baseline_checkout_reason()
        if why is None and not self._baseline_from_option:
            why = (
                "it was found in the scanned tree rather than named by the "
                "operator's settings"
            )
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

    def _baseline_entries_trusted(self) -> bool:
        """Whether the baseline in use may take the candidates it lists out of the report.

        A baseline's ``results`` are a suppression surface: every candidate it
        lists by file, hash and type is one the report will not show as an
        ordinary finding. Removing a candidate is the operator's call to make,
        so the entries are honored as removals only when the OPERATOR NAMED the
        file: ``baseline_file`` written by the operator's own settings
        (``--config-overrides`` included), or named by a config the operator did
        not write while the operator's own settings name that same file
        (``same_baseline``), and the file is not inside the scanned tree or a
        git checkout holding it (``_baseline_checkout_reason``): a name the
        operator wrote that resolves into the checkout is still a file the
        repository controls. A baseline the scan found in the tree
        (``.secrets.baseline``, ``.ash/.secrets.baseline``) is never the
        operator's record, whatever the settings-trust rule says of the
        checkout layout: the structure says so here, where an earlier shape fell
        through to ``_untrusted_baseline_reason`` and read such a baseline as
        trusted whenever the configured scan root did not hold the source
        directory. Such a file may only mark: its known candidates stay in the
        report as suppressed findings, so the count is visible and each can be
        audited, and a repository cannot hide a secret still in its files by
        listing the hash in a file it commits. Under either baseline an entry
        audited as a real secret is reported as an ordinary finding (see
        ``scan``): a confirmed secret is not cleared by the record of it. The
        worker is told the answer as ``baseline_trusted`` (``_scan_in_worker``).
        """
        if not self._baseline_in_use() or not self._baseline_from_option:
            return False
        # Naming the file is not enough when it sits in the scanned checkout:
        # the repository controls it there, and an org-wide ``baseline_file:
        # .secrets.baseline`` would let every repository's committed baseline
        # remove any candidate by listing its hash. The same location test the
        # settings-trust rule applies (_untrusted_baseline_reason).
        if self._baseline_checkout_reason() is not None:
            return False
        record = getattr(
            getattr(self.context, "config", None),
            "_untrusted_detect_secrets_settings",
            None,
        )
        return record is None or same_baseline(
            record.operator_baseline,
            self._baseline_file_path(),
            self.context.source_dir,
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
        self._verification_permitted = self._verifies(settings.filters_used)
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
            if filter_config.get("path") == SHOULD_EXCLUDE_FILE_FILTER:
                raw_patterns = filter_config.get("pattern", [])
                if isinstance(raw_patterns, str):
                    raw_patterns = [raw_patterns]
                elif not isinstance(raw_patterns, list):
                    # Neither a pattern nor a list of them: nothing to exclude
                    # by, and nothing to iterate.
                    ASH_LOGGER.warning(
                        "Ignoring the exclude patterns in baseline: 'pattern' is "
                        "neither a string nor a list of strings"
                    )
                    continue
                for index, p in enumerate(raw_patterns):
                    if not isinstance(p, str):
                        # re.compile raises TypeError for a number or a mapping,
                        # which re.error's handler below does not catch, so one
                        # bad entry failed the whole scan instead of being
                        # skipped like a pattern that does not compile.
                        ASH_LOGGER.warning(
                            f"Invalid exclude pattern (entry {index}) in baseline: "
                            f"it is not a string ({type(p).__name__})"
                        )
                        continue
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

    def _exclude_patterns_by_author(
        self, values: Tuple[str, ...] = ()
    ) -> Tuple[List[re.Pattern], List[re.Pattern]]:
        """The compiled ``should_exclude_file`` patterns, the operator's apart from the baseline's.

        Each pattern is matched against a path relative to the directory its
        author wrote it for: the operator's (the ``filters_used`` entries of the
        operator's own configuration, ``_operator_filter_ids``) against the scan
        root, the baseline's against the baseline's anchor. Matched as one set
        against the baseline's anchor, an operator's ``^tests/`` stopped matching
        under a re-anchored monorepo baseline (``service/tests/x.py``), and the
        files it excluded were scanned with no warning. An entry not recorded as
        the operator's is read as the baseline's, which is the one-anchor
        behavior for a scanner whose settings were set after it was configured.

        Returns:
            ``(operator_patterns, baseline_patterns)``.
        """
        entries = list(self.config.options.scan_settings.filters_used)
        own = [item for item in entries if id(item) in self._operator_filter_ids]
        others = [item for item in entries if id(item) not in self._operator_filter_ids]

        def _dump(items: List[Any]) -> Dict[str, Any]:
            return {
                "filters_used": [item.model_dump(exclude_none=True) for item in items]
            }

        return (
            self._get_baseline_exclude_patterns(_dump(own), values),
            self._get_baseline_exclude_patterns(_dump(others), values),
        )

    @staticmethod
    def _root_relative(path: str, root: Optional[Path]) -> str:
        """``path`` relative to ``root``, ``/``-separated, as a baseline names a file.

        detect-secrets writes a baseline from the repository's root, so its
        ``should_exclude_file`` patterns and its result keys name files
        relative to that root: ``^tests/``, ``src/settings.py``. The scan set
        and the scan paths are absolute, so a pattern or key matched against
        them as they are matched nothing when anchored, and an unanchored one
        that happened to match a directory above the checkout matched every
        file. A path that is not under ``root`` (a converted file outside the
        source directory) is returned absolute, ``/``-separated. With no root
        the path is returned as given.
        """
        if root is None:
            return path
        absolute = os.path.normpath(os.path.abspath(path))
        root_abs = os.path.normpath(os.path.abspath(root))
        try:
            relative = os.path.relpath(absolute, root_abs)
        except ValueError:
            # Another drive on Windows: there is no relative path.
            return Path(absolute).as_posix()
        if relative == os.curdir or relative == os.pardir:
            return Path(absolute).as_posix()
        if relative.startswith(os.pardir + os.sep):
            return Path(absolute).as_posix()
        return Path(relative).as_posix()

    @staticmethod
    def _apply_file_exclusions(
        files: List[str],
        exclude_patterns: List[re.Pattern],
        root: Optional[Path] = None,
        timeout: Optional[float] = None,
        source: str = "the should_exclude_file filter of scan_settings.filters_used",
    ) -> List[str]:
        """Filter out files matching any of the exclude patterns.

        Each pattern is searched in the file's path relative to ``root``
        (``_root_relative``), the form the baseline's patterns were written
        for; with no root, in the path as given.

        The patterns are the baseline's, so the scanned repository's or a
        delivered config's, and they run here in ASH's own process, before the
        worker and its time limit start. ``timeout`` is the scanner's
        ``scan_timeout``: the whole filter runs under it in a child process
        (``evaluated_within``, ``files_kept_by_patterns``), and a filter still
        running at the deadline is killed and raises ScannerError naming
        ``source``. None runs it unbounded, inline, as ``scan_timeout: null``
        runs the scan.

        Args:
            files: List of file paths to filter.
            exclude_patterns: Compiled regex patterns to match against.
            root: The directory the scan set was enumerated from.
            timeout: Seconds the filter may take, or None.
            source: Where the patterns came from, for the error.

        Returns:
            Filtered list of file paths.

        Raises:
            ScannerError: the filter ran past ``timeout``.
        """
        if not exclude_patterns:
            return files
        # The relative texts are computed here and the patterns cross as their
        # text and flags: the child that runs the search does nothing else.
        items = [(f, DetectSecretsScanner._root_relative(f, root)) for f in files]
        specs = [(pattern.pattern, pattern.flags) for pattern in exclude_patterns]
        return evaluated_within(timeout, source, files_kept_by_patterns, items, specs)

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
        baseline_trusted: bool = False,
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

        ``baseline_trusted`` is whether the baseline in use is the operator's
        (``_baseline_entries_trusted``), written into the request beside
        ``baseline``. It is the scanner's half of the request contract the
        worker reads (``utils/detect_secrets_worker.py``, its
        ``baseline_trusted`` key): the worker drops an entry a baseline it is
        handed accepted as not a secret only when the request says
        ``"baseline_trusted": true``, and absent or false means no drop. This
        scanner passes ``baseline`` as None (``scan`` applies the baseline to
        the scan's own findings itself, so the worker never loads one and a
        stale entry cannot come back as a finding), so on ASH's own requests the
        flag changes nothing in the worker; it is kept stated so a request that
        does carry a baseline, another caller's or a later shape of this one,
        cannot reach the worker with a repository's baseline read as trusted by
        default. The two halves are tested apart: the request's keys here, the
        worker's reading beside the worker.

        A worker killed at ``scan_timeout`` fails the scan: the timeout is recorded
        on the scanner (``scan_timed_out_after``) and ScannerError is raised, as the
        template scan does for a tool it killed. The in-process scan kept whatever
        it had found before the cutoff, but a killed worker's partial results are
        not recoverable, and a report built from the baseline alone would be graded
        as a clean scan.

        Raises:
            ScannerError: the worker was killed at ``scan_timeout``, failed, or
                exited 0 without writing results.
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
        # The request is written inside the try whose finally removes both
        # exchange files: a json.dump that raises part way (a settings value
        # that is not JSON-serializable) left the partly written request, the
        # scan settings included, in the results directory CI uploads.
        try:
            with open_for_write(request_file, mode=0o600) as fp:
                # Owner-only from its first instant: the settings below can hold
                # environment-derived values, and the results directory is what
                # CI uploads, so the file is CREATED 0o600 (open_for_write's
                # mode) -- permissions are checked at open, and a default-mode
                # create tightened afterwards left a window in which a local
                # reader who opened the empty file kept read access to the JSON
                # written next. fchmod only tightens a file that still existed
                # at the open (one the removal above refused, or one recreated
                # since), and that tighten is best-effort: a filesystem that
                # refuses chmod (CIFS, some FUSE mounts) costs a DEBUG line, not
                # the scan. Windows has no fchmod before 3.13, and from 3.13 it
                # only toggles the read-only bit; the file keeps the platform
                # default there.
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
                        "baseline_trusted": bool(baseline_trusted),
                        "settings": scan_settings_dict,
                        "paths": scan_paths,
                        "verify": verify,
                    },
                    fp,
                )
            # `python -m` puts the working directory first on sys.path, so the
            # worker starts in an empty directory of its own (and with -P where
            # Python has it) rather than in the scanned tree or the results
            # directory under it, where a `detect_secrets/` or
            # `automated_security_helper/` package would replace the real one. The
            # directory is under work_dir, which a sandboxed worker can see.
            # The worker's environment always states REFUSE_HTTP_ENV: "1" unless
            # this scan may verify, "0" when it may, never absent. The worker
            # refuses every HTTP request detect-secrets tries unless the value is
            # exactly "0", so a variable an executor or environment filter drops
            # or rewrites fails safe (findings reported unverified) instead of
            # silently allowing the requests, as a worker keyed on "1" alone did
            # for a dropped key. An inherited value of the same name is replaced,
            # never passed through. The run's environment values go to the
            # runner, so the lines it logs itself (a timeout's limit among them)
            # name an env-typed limit as its option rather than print it.
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
                        REFUSE_HTTP_ENV: "0" if verify else "1",
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
                    timed_out_text = (
                        "detect-secrets scan timed out (the limit is not shown: "
                        f"the plugin's values hook {read.failure()})"
                    )
                else:
                    timed_out_text = text_without_values(
                        "detect-secrets scan timed out after "
                        f"{timeout_limit_token(scan_timeout, read.values)}",
                        read.values,
                    )
                self._plugin_log(
                    timed_out_text,
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )
                # A killed worker wrote no results, so the scan fails: the timeout
                # is recorded on the scanner (scan_timed_out_after), which is how
                # the executor names it, and ScannerError is raised, as the
                # template scan does for a tool it killed. Returning None here
                # sent scan() on with the collection it already held (the
                # baseline's entries, or none) and the executor graded that
                # PASSED: a tree that was never scanned read as clean. The text
                # raised is the logged line, which carries no environment value.
                self._record_timeout(response, scan_timeout)
                # A stop that failed (timed_out with no exit code, or the
                # runner's could_not_stop key) is recorded as the base class's
                # _run_subprocess records it, so the executor and run_ash_scan
                # fail the run: the worker may still be running and can write
                # its raw findings into the results directory after cleanup.
                # Without this record the run read as a plain timeout.
                self._record_could_not_stop(response)
                raise ScannerError(
                    f"{timed_out_text}, so the worker was killed and produced no "
                    "results file. Raise scanners.detect-secrets.options.scan_timeout "
                    "if this target legitimately needs longer, or set it to null to "
                    "leave this scanner unbounded."
                )
            if response.get("post_run_error"):
                # The worker ran, and ASH then failed to record the run (the
                # runner's post_run_error, with the worker's own exit code).
                # The template scan fails such a run rather than grade the
                # results file; reading only the exit code here graded a run
                # ASH could not record as complete.
                raise ScannerError(
                    text_without_values(
                        "the detect-secrets worker ran, but ASH could not record "
                        f"the run: {response.get('error')}",
                        self._environment_values(),
                    )
                )
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

    def _baseline_anchor(self, scan_root: Path, target_type: str) -> Path:
        """The directory the baseline's paths are relative to.

        ``detect-secrets scan`` writes a baseline from the directory it runs in,
        the repository's root, so its result keys and its ``should_exclude_file``
        patterns name files relative to that directory: ``service/app.py``,
        ``^service/tests/``. A baseline the scan FOUND in the tree whose file
        resolves into a strict ancestor of the scanned directory, the admitted
        in-tree link into the enclosing checkout (a monorepo's
        ``service/.secrets.baseline`` pointing at the checkout's own
        ``.secrets.baseline``), was written from that ancestor. Matched relative
        to the scanned subdirectory, no key met a finding and no pattern met a
        file, so the admitted link read a baseline whose entries never applied.
        Such a baseline's paths are read relative to its own directory; a
        baseline inside the scanned directory keeps the scan root.

        A baseline the OPERATOR names (``baseline_file``) keeps the scan root
        wherever its file sits, an ancestor directory included: the operator
        ran ``detect-secrets scan`` from a directory this scanner cannot know,
        and the contract pinned since the known-entries rule was written is that
        its keys and patterns are relative to the scanned directory (the file
        beside the scanned tree, keyed ``settings.py``, is the common shape). A
        first cut of this rule re-anchored such a baseline too, and its known
        candidates stopped matching.

        The anchor is spelled with the scan root's own prefix (the directory
        walked up, not the resolved path), so a scan root reached through a
        link keys the same way the scan set does. A converted-files scan keeps
        the work directory: the baseline's paths name source files, and the
        converted copies are keyed under the work directory as before.

        Only a baseline the scan HAS is anchored: a chosen file that turned out
        malformed left ``_baseline_real`` set but no document, and the anchor
        still moved to the file's directory, where it met no baseline path at
        all and moved the operator's own exclude patterns (see ``scan``).

        The walk up the spelled path is right only when every link sits ABOVE
        the baseline's directory. With a link between that directory and the
        scan root (``repo/api -> packages/api``, the baseline in ``repo``), the
        resolved gap is two levels but the spelled path is one below the
        checkout, so the walk left the checkout, no key or pattern met anything,
        and a deeper link could reach ``/``. The directory the walk lands on is
        checked against the baseline's; when it is not the same directory, the
        baseline's paths are read relative to the scan root, the shape before
        this rule, and a debug line says so.
        """
        if (
            target_type != "source"
            or self._baseline_real is None
            or self._baseline_document is None
            or self._baseline_from_option
        ):
            return scan_root
        root = Path(os.path.abspath(scan_root))
        real_root = Path(os.path.realpath(root))
        baseline_dir = Path(os.path.realpath(self._baseline_real)).parent
        if baseline_dir == real_root or not real_root.is_relative_to(baseline_dir):
            return scan_root
        depth = len(real_root.parts) - len(baseline_dir.parts)
        if depth < 1 or depth > len(root.parents):
            return scan_root
        anchor = root.parents[depth - 1]
        if Path(os.path.realpath(anchor)) != baseline_dir:
            ASH_LOGGER.debug(
                "The scanned directory reaches the baseline's directory through a "
                "link below it, so the baseline's paths are read relative to the "
                "scanned directory"
            )
            return scan_root
        return anchor

    def _baseline_known(
        self, baseline: Optional[Dict[str, Any]], scan_root: Path
    ) -> Dict[Tuple[str, Any, Any], bool]:
        """The candidates the baseline marks known, each with its audit result.

        Keyed by (URI, hashed secret, type), the fields ``detect-secrets``
        compares a scanned candidate against a baseline by
        (``PotentialSecret.fields_to_compare``; line numbers change and are not
        compared). The value is whether the baseline's author audited the entry
        as a real secret (``is_secret: true``); False for one audited as a false
        positive or not audited. A baseline is the record of the findings its
        author has seen, so what "known" does to a reported candidate depends on
        that audit and on whose baseline it is (see ``scan``). Each key is the
        URI ``_finding_uri`` gives the file, anchored at ``scan_root``, which
        the caller passes as the directory the baseline's paths are relative to
        (``_baseline_anchor``), so the baseline's spelling of a path and the
        scan's meet.
        """
        known: Dict[Tuple[str, Any, Any], bool] = {}
        results = (baseline or {}).get("results")
        if not isinstance(results, dict):
            return known
        for filename, entries in results.items():
            if not isinstance(entries, list):
                continue
            uri = self._finding_uri(str(filename).replace("\\", "/"), scan_root)
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                key = (uri, entry.get("hashed_secret"), entry.get("type"))
                # Two entries for one key (one audited real, one not) read as
                # audited real: the stricter reading is the one to report.
                known[key] = known.get(key, False) or entry.get("is_secret") is True
        return known

    @staticmethod
    def _baseline_hash_echoes(document: Optional[Dict[str, Any]]) -> frozenset[str]:
        """The hashes of the ``hashed_secret`` values a baseline lists.

        detect-secrets' hex entropy detector reads each ``hashed_secret`` in a
        baseline as a high-entropy string, and a finding is keyed by the hash of
        the string it found, so the finding on such a value has the hash of that
        value. A baseline scanned as an ordinary file reports one such finding
        per entry; those, and only those, are dropped
        (``scan``). A value that is not 40 hexadecimal digits is not a hash
        detect-secrets wrote, so its finding stays.
        """
        echoes: Set[str] = set()
        results = (document or {}).get("results")
        if not isinstance(results, dict):
            return frozenset()
        for entries in results.values():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                value = entry.get("hashed_secret") if isinstance(entry, dict) else None
                if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value):
                    echoes.add(
                        hashlib.sha1(
                            value.encode("utf-8"), usedforsecurity=False
                        ).hexdigest()
                    )
        return frozenset(echoes)

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
        # Where this target's errors start. ``self.errors`` is the instance's,
        # appended across targets (and read whole by the executor), so the
        # converted target's invocation record carried the source target's
        # failure text as its own exitCodeDescription.
        errors_before = len(self.errors)
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

            # The baseline is the copy _process_config_options parsed from the
            # checked path (_read_baseline); the file is never reopened, so a
            # path swapped for a link after the check is not followed. It is read
            # here, not by the worker, which may run in a sandbox that cannot see
            # a baseline outside the source tree.
            baseline_document = None
            if (
                target_type == "source"
                and self._baseline_in_use()
                and self._baseline_document is not None
            ):
                baseline_document = self._baseline_document
            # The worker's collection is never seeded with the baseline's
            # entries. Seeded, it came back holding every entry under the
            # baseline's spelling of its file beside every scanned secret under
            # the scan's, so a secret still in its file was reported twice and
            # an entry whose secret had left the file was reported at a stale
            # line (at line 0 for a --slim baseline's entry, which the SARIF
            # model refuses). The scan's own findings are the one copy; what the
            # baseline knows about each is applied to it below (_baseline_known).
            # Whose baseline it is (_baseline_entries_trusted) decides whether a
            # known candidate leaves the report or stays marked, and is told to
            # the worker as ``baseline_trusted`` so its own drop of accepted
            # entries, for a request that does carry a baseline, follows the
            # same rule.
            known_entries_trusted = self._baseline_entries_trusted()
            worker_baseline = None

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
            # The directory the baseline's keys and exclude patterns are
            # relative to: the scan root, or the baseline's own directory when
            # that is an ancestor of it (a monorepo's root-level baseline read
            # through an in-tree link; see _baseline_anchor).
            baseline_anchor = self._baseline_anchor(scan_root, target_type)

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
            # which is inside ``output_dir`` and is scanned whole: every regular
            # file, whatever its name. A ``*.*`` glob took only names holding a
            # dot, so an archive member named ``id_rsa``, ``credentials`` or
            # ``config``, or a ``.gz`` decompressed to a dotless name, was never
            # handed to detect-secrets.
            candidates = (
                [item for item in self.context.work_dir.rglob("*") if item.is_file()]
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

            # The baseline in use, under the name it was chosen by and the
            # name it resolves to. Its entries hold the hashes of the secrets
            # it records, which the entropy detectors report, and the file is
            # the record of the findings, not a finding, so the operator's
            # own baseline is left out of the scan set. A baseline the
            # repository controls is NOT: it is a file like any other, and
            # the parsed document is only what detect-secrets reads from it.
            # Left out, a repository hid anything it put in a file of that
            # name, under a key the shape check admits
            # (``{"results": {}, "notes": "<live key>"}``). The detectors'
            # reading of the hashes it lists is dropped from the findings
            # instead (_baseline_hash_echoes), and nothing else on the file.
            # Only a baseline the scan has (the parsed document): a chosen
            # file that turned out malformed is not in use
            # (_process_config_options fell back to the default settings), so
            # it is scanned like any other file.
            baseline_names: Set[str] = set()
            if target_type == "source" and self._baseline_document is not None:
                baseline_names = {
                    self._root_relative(str(path), scan_root)
                    for path in (self._baseline_named, self._baseline_real)
                    if path is not None
                }
                if baseline_names and known_entries_trusted:
                    scannable = [
                        item
                        for item in scannable
                        if self._root_relative(item, scan_root) not in baseline_names
                    ]
            baseline_echoes = (
                self._baseline_hash_echoes(self._baseline_document)
                if baseline_names and not known_entries_trusted
                else frozenset()
            )

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
            verify = self._verifies(scan_settings_dict.get("filters_used", []))
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
            #
            # Matched against each file's path relative to the directory its
            # author wrote it for (_root_relative): the operator's patterns
            # against the scan root, the baseline's against the baseline's
            # anchor (_exclude_patterns_by_author). The filter is then left out
            # of the settings the worker gets: detect-secrets applies it to the
            # absolute path it is handed, where an anchored pattern matched
            # nothing and an unanchored one that matched a directory above the
            # checkout matched every file, and a pattern written as one string
            # was read as one pattern per character. The files it would exclude
            # are already gone from the scan set here.
            #
            # Bounded by this scanner's scan_timeout, the limit the worker's
            # own run gets: the patterns are the baseline's, and one that
            # backtracks heavily held the scan here for as long as it liked,
            # before the worker's limit ever started.
            scan_timeout = self.config.options.scan_timeout
            own_patterns, baseline_patterns = self._exclude_patterns_by_author(values)
            if own_patterns or baseline_patterns:
                pre_filter_count = len(scannable)
                pattern_source = (
                    "the should_exclude_file filter of scan_settings.filters_used"
                )
                if self._baseline_in_use():
                    pattern_source += (
                        f", loaded with the baseline "
                        f"{Path(self._baseline_file_path()).as_posix()}"
                    )
                # The baseline's path can be a value read from the environment,
                # and this text is quoted in the error the filter raises:
                # redacted like every other line here that names the baseline.
                # The path prints with forward slashes (as_posix), so a Windows
                # value written with backslashes is hidden in that spelling too.
                named = environment_strings(values)
                forward = tuple(v.replace("\\", "/") for v in named if "\\" in v)
                pattern_source = text_without_values(
                    pattern_source, (*named, *forward)
                )
                scannable = self._apply_file_exclusions(
                    scannable,
                    own_patterns,
                    scan_root,
                    timeout=scan_timeout,
                    source=pattern_source,
                )
                scannable = self._apply_file_exclusions(
                    scannable,
                    baseline_patterns,
                    baseline_anchor,
                    timeout=scan_timeout,
                    source=pattern_source,
                )
                excluded_count = pre_filter_count - len(scannable)
                if excluded_count > 0:
                    self._plugin_log(
                        f"Excluded {excluded_count} files from detect-secrets scan "
                        f"based on baseline exclude patterns",
                        level=logging.VERBOSE,
                        target_type=target_type,
                    )
            if "filters_used" in scan_settings_dict:
                scan_settings_dict["filters_used"] = [
                    item
                    for item in scan_settings_dict["filters_used"]
                    if item.get("path") != SHOULD_EXCLUDE_FILE_FILTER
                ]

            if global_ignore_paths:
                from automated_security_helper.utils.suppression_matcher import (
                    ignore_path_matches as path_matches_pattern,
                )

                # Each path relative to the SOURCE directory, as the ignore paths
                # are written (_root_relative): a prefix cut from a resolved
                # source directory left a relative, symlinked or Windows source
                # directory's paths uncut, and then no ignore path matched. A
                # converted file keeps the source directory as its anchor too
                # (not the work directory it is scanned from): it reads
                # `.ash/ash_output/converted/x` when the output sits in the tree,
                # as it always did, so an ignore path written for the source
                # file `x` does not also drop an archive member extracted to the
                # same relative name. The baseline's patterns above are the
                # exception, written for the files the baseline names.
                ignore_root = Path(self.context.source_dir)
                original_count = len(scannable)
                scannable = [
                    file_path
                    for file_path in scannable
                    if not any(
                        path_matches_pattern(
                            self._root_relative(file_path, ignore_root),
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
            # <root>/<root>/<file> and quietly find nothing.
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
                baseline=worker_baseline,
                scan_paths=scan_paths,
                scan_settings_dict=scan_settings_dict,
                work_dir=target_results_dir,
                scan_timeout=scan_timeout,
                verify=verify,
                baseline_trusted=known_entries_trusted,
            )
            if scanned is not None:
                self._secrets_collection = scanned

            self._post_scan(
                target=target,
                target_type=target_type,
            )

            # Populate the Results list with findings from the scan. Every
            # candidate the scan found is reported once, at the scan's own line;
            # nothing is reported at a line the baseline alone names. A
            # candidate the baseline holds is known (_baseline_known), and what
            # that does depends on the baseline's own audit of it:
            #
            # * an entry audited as a real secret (is_secret: true) is a
            #   confirmed secret still in the file, so it is reported as an
            #   ordinary finding, whoever's baseline lists it: a baseline
            #   records such a finding, it does not clear it;
            # * any other known candidate is the baseline's call, and whose
            #   baseline it is decides what the call may be
            #   (_baseline_entries_trusted): a baseline the operator names may
            #   DROP it from the report, as `detect-secrets scan --baseline`
            #   would; a file the scanned repository controls may only MARK it,
            #   kept in the report as suppressed with the baseline as the
            #   reason, so it is counted and can be audited, and a repository
            #   cannot hide a secret still in its files by listing the hash.
            #   Tune findings with ASH suppressions, which are reported and
            #   counted, as the gitleaks scanner says of the tree's own ignore
            #   file. The worker applies the same rule to a baseline it is
            #   handed (``baseline_trusted``).
            known = self._baseline_known(baseline_document, baseline_anchor)
            baseline_suppression: Optional[Suppression] = None
            if known and not known_entries_trusted:
                listed_in = (
                    self._baseline_named
                    if self._baseline_named is not None
                    else self._baseline_file_path()
                )
                baseline_suppression = Suppression(
                    kind=Kind1.external,
                    justification=text_without_values(
                        "(ASH) Listed in the detect-secrets baseline "
                        f"{Path(listed_in).as_posix()}, a file the scanned "
                        "repository controls; kept in the report as suppressed "
                        "rather than removed, so it is counted. Name a baseline "
                        "outside the scanned tree and the git checkout holding it "
                        "with scanners.detect-secrets.options.baseline_file in "
                        "the operator's own config to have its entries removed; "
                        "an entry the baseline audits as a real secret is "
                        "reported as a finding either way.",
                        values,
                    ),
                )
            kept_known = 0
            dropped_known = 0
            audited_real = 0
            results: List[Result] = []
            for filename, detections in self._secrets_collection.data.items():
                uri = self._finding_uri(filename, scan_root)
                for finding in detections:
                    if (
                        baseline_echoes
                        and uri in baseline_names
                        and finding.type == HEX_HIGH_ENTROPY_TYPE
                        and finding.secret_hash in baseline_echoes
                    ):
                        # The detectors reading a hash the baseline lists.
                        continue
                    key = (uri, finding.secret_hash, finding.type)
                    is_known = key in known
                    is_real = bool(known.get(key))
                    if is_known and is_real:
                        audited_real += 1
                    elif is_known and known_entries_trusted:
                        dropped_known += 1
                        continue
                    suppressed = is_known and not is_real
                    if suppressed:
                        kept_known += 1
                    rule_id = re.sub(
                        pattern=r"\W+", repl="-", string=finding.type
                    ).upper()
                    results.append(
                        Result(
                            # Adjust as needed to capture findings from scanner as
                            # SARIF Result objects. Reference the current CDK Nag
                            # Scanner/Wrapper for examples on custom SARIF structure.
                            ruleId=f"SECRET-{rule_id}",
                            suppressions=(
                                [baseline_suppression]
                                if suppressed and baseline_suppression is not None
                                else None
                            ),
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
            if kept_known:
                self._plugin_log(
                    f"{kept_known} candidate(s) listed in the scanned repository's "
                    "own detect-secrets baseline are reported as suppressed, not "
                    "removed, so they are counted: only a baseline the operator "
                    "names may remove them.",
                    level=logging.INFO,
                    target_type=target_type,
                )
            if dropped_known:
                self._plugin_log(
                    f"{dropped_known} candidate(s) listed in the operator's "
                    "detect-secrets baseline left the report.",
                    level=logging.INFO,
                    target_type=target_type,
                )
            if audited_real:
                self._plugin_log(
                    f"{audited_real} candidate(s) the detect-secrets baseline audits "
                    "as real secrets (is_secret: true) are still in the scanned "
                    "files and are reported as findings: a baseline records a "
                    "confirmed secret, it does not clear it.",
                    level=logging.WARNING,
                    target_type=target_type,
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
                exitCodeDescription="\n".join(self.errors[errors_before:]),
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
            # The run ended, so its end is recorded as the template scan
            # records it right after its tool returns, whatever follows. Left
            # unrecorded, end_time kept the previous target's value, and the
            # executor read this target's end as before its start.
            self.end_time = datetime.now(timezone.utc)
            # Check if there are useful error details
            # The failure can name the baseline file, which can be a value the
            # config read from the environment.
            raise ScannerError(
                text_without_values(
                    f"{self.__class__.__name__} failed: {str(e)}", values
                )
            )


def _main(cwd: Path) -> SarifReport | bool:
    """Scan ``cwd`` as the module's own command line does: the source target,
    with the default config, the output under ``.ash/ash_output``."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config

    output_dir = cwd.joinpath(".ash", "ash_output")
    context = PluginContext(
        source_dir=cwd,
        output_dir=output_dir,
        work_dir=output_dir.joinpath("converted"),
        config=get_default_config(),
    )
    scanner = DetectSecretsScanner(context=context)
    return scanner.scan(target=cwd, target_type="source")


if __name__ == "__main__":
    # Built with a plugin context and scanned as the source target: the
    # scanner takes no source_dir or output_dir of its own, and scan() needs
    # the target type, so the previous form raised on every run.
    _main(Path.cwd())
