import logging

"""Module containing the detect-secrets security scanner implementation."""

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from importlib.metadata import version
import json
import multiprocessing
from pathlib import Path
import re
import sys
from typing import Annotated, Any, ClassVar, Dict, List, Literal

from pydantic import BaseModel, ConfigDict, Field
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.core.constants import KNOWN_LOCKFILE_NAMES
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
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command
from automated_security_helper.models.core import IgnorePathWithReason

#: Why this scanner cannot run when its library is absent. One string, used for
#: the recorded reason and for the log line, so the two cannot drift.
_MISSING_LIBRARY_REASON = (
    "detect-secrets is not importable, so the detect-secrets scanner cannot run. "
    "It ships as a dependency of ASH; reinstall ASH (`pip install --force-reinstall "
    "automated-security-helper`) or install the library directly with "
    "`pip install detect-secrets`."
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
            self.dependency_unavailable_reason = _MISSING_LIBRARY_REASON
            ASH_LOGGER.warning(f"{_MISSING_LIBRARY_REASON} ({exc})")
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

    def _process_config_options(self):
        # Check detect-secrets baseline path
        possible_baseline_paths = [
            item
            for item in [
                self.config.options.baseline_file,
                ".ash/.secrets.baseline",
                ".secrets.baseline",
            ]
            if item is not None
        ]
        ASH_LOGGER.debug(f"Possible baseline file paths: {possible_baseline_paths}")

        # Look through each baseline file path to see if it exists and configure
        # the scan settings according to the first baseline file found
        for baseline_path in possible_baseline_paths:
            ASH_LOGGER.debug(
                f"Checking for detect-secrets config @ {Path(baseline_path).absolute()}"
            )
            if Path(baseline_path).absolute().exists():
                ASH_LOGGER.debug(
                    f"Identified detect-secrets config @ {Path(baseline_path).absolute()}"
                )

                self.config.options.baseline_file = Path(baseline_path)
                break

        # If a baseline file was found, load its plugins_used and filters_used
        # into scan_settings so they are applied during scanning.
        # SecretsCollection.load_from_baseline() only loads results, not settings,
        # so we must propagate the baseline's configuration explicitly.
        if self.config.options.baseline_file is not None:
            try:
                with open(Path(self.config.options.baseline_file).absolute(), "r") as f:
                    baseline_data = json.load(f)

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
                    # Load filters from baseline (includes should_exclude_file, etc.)
                    if "filters_used" in baseline_data:
                        self.config.options.scan_settings.filters_used = [
                            DetectSecretsScanSettingsFiltersUsed(**f)
                            for f in baseline_data["filters_used"]
                        ]
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
        # discarded the operator's ``version`` and ``generated_at``, any
        # ``filters_used`` loaded from a baseline immediately above, and any extra
        # keys the model accepts -- a second silent loss on the way to fixing the
        # first.
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
            (
                secrets_collection_cls,
                transient_settings,
                _,
            ) = _detect_secrets_api()
            self._secrets_collection = secrets_collection_cls()
            target_results_dir = self.results_dir.joinpath(target_type)
            results_file = target_results_dir.joinpath("results_sarif.sarif")
            results_file.parent.mkdir(exist_ok=True, parents=True)
            self._resolve_arguments(target=target, results_file=target_results_dir)

            if (
                target_type == "source"
                and self.config.options.baseline_file is not None
            ):
                with open(self.config.options.baseline_file, "r") as f:
                    self._secrets_collection = (
                        secrets_collection_cls.load_from_baseline(
                            baseline=json.load(f),
                        )
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
                )
            )
            absolute_output_dir = Path(self.context.output_dir).absolute()
            scannable = [
                str(item)
                for item in candidates
                if Path(item).name not in [*KNOWN_LOCKFILE_NAMES]
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

            # Ensure multiprocessing uses 'fork' start method to avoid spawn-related
            # issues in containerized environments (CodeBuild, Docker) where 'spawn'
            # can cause recursive process creation and significant overhead.
            self._ensure_fork_multiprocessing()

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

            with transient_settings(scan_settings_dict) as settings:
                ASH_LOGGER.debug(f"Settings: {settings}")
                executor = ThreadPoolExecutor(max_workers=1)
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
                future = executor.submit(
                    self._secrets_collection.scan_files, *scan_paths
                )
                try:
                    future.result(timeout=scan_timeout)
                except FuturesTimeoutError:
                    future.cancel()
                    self._plugin_log(
                        f"detect-secrets scan timed out after {scan_timeout}s",
                        level=logging.WARNING,
                        append_to_stream="stderr",
                    )
                finally:
                    executor.shutdown(wait=False, cancel_futures=True)

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
            with open(results_file, mode="w", encoding="utf-8") as fp:
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
