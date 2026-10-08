import logging

"""Module containing the detect-secrets security scanner implementation."""

from importlib.metadata import version
import json
import multiprocessing
from pathlib import Path
import re
import sys
from typing import Annotated, Any, ClassVar, Dict, List, Literal

from pydantic import BaseModel, ConfigDict, Field
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
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
from automated_security_helper.core.constants import ash_reinstall_command
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command
from automated_security_helper.models.core import IgnorePathWithReason

#: Why this scanner cannot run when its library is absent. One string, used for
#: the recorded reason and for the log line, so the two cannot drift.
#: The reinstall goes through ASH's git repository: the PyPI name
#: automated-security-helper belongs to an unrelated third party.
_MISSING_LIBRARY_REASON = (
    "detect-secrets is not importable, so the detect-secrets scanner cannot run. "
    f"It ships as a dependency of ASH; reinstall ASH (`{ash_reinstall_command()}`) "
    "or install the library directly with `pip install detect-secrets`."
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


#: The detect-secrets filter that verifies candidate secrets against their issuer's
#: API over the network. See DetectSecretsScanner.sandbox_requirements.
_VERIFICATION_FILTER_PATH = (
    "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
)


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
            item.path == _VERIFICATION_FILTER_PATH
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
    ) -> Any:
        """Scan ``scan_paths`` in a subprocess; return the resulting collection.

        detect-secrets runs out of the ASH process so that ``--sandbox`` can wrap it:
        the spawn goes through ``run_command_with_output_handling``, the choke point
        every sandboxed scanner subprocess passes through. The worker does what this
        method used to do in-process -- load the baseline, set ``root``, scan under
        ``transient_settings`` -- and this method rebuilds the same
        ``SecretsCollection`` from its output, so everything downstream reads
        ``self._secrets_collection`` exactly as before.

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
            ):
                with open(self.config.options.baseline_file, "r") as f:
                    baseline_document = json.load(f)
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
