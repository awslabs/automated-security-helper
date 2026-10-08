"""Module containing the Grype security scanner implementation."""

import logging
import os
import re
from pathlib import Path
from typing import Annotated, ClassVar, Final, List, Literal, Mapping

import yaml
from pydantic import Field, model_validator
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolExtraArg,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    PropertyBag,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.package_identity import (
    NpmLockIndex,
    identity_properties,
    install_path,
)
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.process_env import snapshot_environ

#: grype configuration keys that remove matches from the report.
#:
#: A discovered grype config is passed straight through as ``--config``, so a key
#: like ``only-fixed`` narrows ASH's own results. Until these keys were named here
#: nothing in the run said the report had been filtered, and the only record was
#: the config file itself -- which nobody opens while reading a clean scan.
#: Warning on the key rather than fixing one config file is the general form: any
#: adopter can point ASH at a config that quietly withholds their own findings.
#:
#: Key names and effects are from grype's configuration reference at
#: https://oss.anchore.com/docs/reference/grype/configuration/ (generated for
#: grype 0.110.0):
#:
#: * ``only-fixed`` -- "ignore matches for vulnerabilities that are not fixed"
#: * ``only-notfixed`` -- "ignore matches for vulnerabilities that are fixed"
#: * ``ignore-wontfix`` -- "ignore matches for vulnerabilities with specified
#:   comma separated fix states"
#: * ``ignore`` -- "A list of vulnerability ignore rules"
#: * ``exclude`` -- "a list of globs to exclude from scanning"
#: * ``vex-add`` -- "VEX statuses to consider as ignored rules"
#:
#: ``fail-on-severity`` is excluded deliberately: it sets the return code and
#: removes nothing from the report, so warning about it would train a reader to
#: ignore the warning. ``show-suppressed`` is the inverse of a filter -- it
#: reveals matches that were dropped rather than dropping them.
OUTPUT_RESTRICTING_GRYPE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "only-fixed",
        "only-notfixed",
        "ignore-wontfix",
        "ignore",
        "exclude",
        "vex-add",
    }
)

# The per-result message grype's SARIF presenter writes for a package match.
_GRYPE_PACKAGE_MESSAGE = re.compile(
    r"vulnerability in \S+ package: (?P<name>[^,\s]+), version (?P<version>\S+) "
    r"was found at: "
)


class GrypeScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description="Path to Grype configuration file, relative to current source directory. Defaults to searching for `.grype.yaml` and `.grype.yml` in the root of the source directory.",
        ),
    ] = None
    severity_threshold: Literal["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = (
        None
    )
    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, disabling database updates and validation. When true, this scanner runs offline even if ASH does not. ASH's own offline mode (--offline or ASH_OFFLINE) applies whatever this is set to; false follows it.",
            default=False,
        ),
    ]


class GrypeScannerConfig(ScannerPluginConfigBase):
    name: Literal["grype"] = "grype"
    enabled: bool = True
    options: Annotated[
        GrypeScannerConfigOptions, Field(description="Configure Grype scanner")
    ] = GrypeScannerConfigOptions()


def _declared_grype_db_bound(
    environ: Mapping[str, str], grype_config: Path | None
) -> dict[str, str]:
    """The grype-db bound from the registry, minus anything the user set themselves."""
    from automated_security_helper.utils.content_databases import get

    user_config_keys: set[str] = set()
    if grype_config is not None:
        try:
            import yaml

            loaded = yaml.safe_load(grype_config.read_text(encoding="utf-8")) or {}
            db_section = loaded.get("db") if isinstance(loaded, dict) else None
            if isinstance(db_section, dict):
                user_config_keys = {str(key) for key in db_section}
        except Exception as exc:  # nosec B110 - an unreadable config is grype's to report
            ASH_LOGGER.debug(f"Could not read {grype_config} for db settings: {exc}")
    config_key_for_env = {
        "GRYPE_DB_MAX_ALLOWED_BUILT_AGE": "max-allowed-built-age",
        "GRYPE_DB_VALIDATE_AGE": "validate-age",
    }
    return {
        name: value
        for name, value in get("grype-db").bound_env.items()
        if name not in environ and config_key_for_env.get(name) not in user_config_keys
    }


@ash_scanner_plugin
class GrypeScanner(ScannerPluginBase[GrypeScannerConfig]):
    """GrypeScanner implements IaC scanning using Grype."""

    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        cache_paths=("~/.cache/grype", "$GRYPE_DB_CACHE_DIR"),
        env_prefixes=("GRYPE_",),
    )

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.CACHE_FLAGS
    check_conf: str = "NOT_PROVIDED"
    # Env vars to layer onto the subprocess. Populated by
    # _process_config_options (e.g. offline-mode flags). Kept local to the
    # scanner instance so concurrent scanners don't race on os.environ.
    extra_env: Annotated[dict, Field(default_factory=dict)]

    def model_post_init(self, context):
        if self.config is None:
            self.config = GrypeScannerConfig()
        self.command = "grype"
        self.tool_type = ScannerToolType.SCA
        self.args = ToolArgs(
            format_arg="--output",
            format_arg_value="sarif",
            output_arg="--file",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "GrypeScanner":
        """Set up custom installation commands for grype.

        grype had no install path inside ASH at all before this. It was one of
        three scanners (with syft and trivy) that could only arrive from the
        container image, a package manager or the nix toolchain -- so a
        ``python-local`` run on a machine without it scanned without it, reported
        the scanner as not having run, and still exited 0.
        """
        self.custom_install_commands.update(pinned_tool_install_commands("grype"))
        return self

    def validate_plugin_dependencies(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        found = find_executable(self.command)
        if not found:
            ASH_LOGGER.warning(
                "Grype executable not found in PATH. Please ensure grype is installed."
            )
        return found is not None

    @staticmethod
    def _strip_leading_slash_from_uri(location) -> None:
        """Strip leading slashes from the artifact location URI, if present."""
        if (
            location.physicalLocation
            and location.physicalLocation.root
            and location.physicalLocation.root.artifactLocation
        ):
            uri = location.physicalLocation.root.artifactLocation.uri
            if uri:
                location.physicalLocation.root.artifactLocation.uri = uri.lstrip("/")

    def _normalize_result_uris(self, result) -> None:
        """Strip leading slashes from all URIs in a single SARIF result."""
        try:
            for loc in result.locations or []:
                self._strip_leading_slash_from_uri(loc)

            for rel in getattr(result, "relatedLocations", None) or []:
                self._strip_leading_slash_from_uri(rel)

            if result.analysisTarget and result.analysisTarget.uri:
                result.analysisTarget.uri = result.analysisTarget.uri.lstrip("/")
        except Exception as e:
            ASH_LOGGER.warning(f"Error processing Grype result: {e}")

    @staticmethod
    def _output_restricting_keys(config_path: Path | str) -> List[str]:
        """Which keys in the grype config at *config_path* drop matches.

        Returns the matching key names sorted, and an empty list when the file
        removes nothing, cannot be read, or is not a YAML mapping.

        Deliberately does not raise. grype owns the verdict on its own config
        file, and turning a document ASH merely passes through into an ASH-side
        failure would replace grype's precise parse error with a worse one, on a
        scan grype itself might have run.

        A key present with a falsy value is not reported: ``only-fixed: false``
        is the documented default written out, and warning about it would train a
        reader to ignore the warning.

        Args:
            config_path: The grype config file ASH is about to pass as
                ``--config``.

        Returns:
            Sorted names of the keys that restrict grype's output.
        """
        try:
            with open(config_path, "r", encoding="utf-8") as config_file:
                document = yaml.safe_load(config_file)
        except (OSError, yaml.YAMLError):
            return []
        if not isinstance(document, dict):
            return []
        return sorted(key for key in OUTPUT_RESTRICTING_GRYPE_KEYS if document.get(key))

    def _process_config_options(self):
        # Grype config path
        possible_config_paths = [
            item
            for item in [
                self.config.options.config_file,
                ".grype.yaml",
                ".grype/config.yaml",
                ".ash/.grype.yaml",
                ".ash/grype.yaml",
            ]
            if item is not None
        ]

        # Resolve config candidates against source_dir, not the process working
        # directory, and hand grype an absolute path. Same fix, same reason, as
        # checkov_scanner._process_config_options.
        #
        # The subprocess runs with cwd=context.source_dir (see
        # PluginBase._run_subprocess), so probing with a bare Path(...).exists()
        # asked a different question than the one grype would answer: it tested the
        # directory ASH happens to be invoked from. Scanning ASH's own checkout,
        # the probe matched the tracked ".ash/.grype.yaml" and passed it through
        # get_shortest_name, which relativises against the process cwd. grype then
        # exited 1 in under 100ms with "invalid application config: file does not
        # exist: .ash/.grype.yaml", producing no SARIF -- so the scanner reported
        # EXECUTION FAILED with zero findings while grype itself was fine.
        source_dir = Path(self.context.source_dir)
        resolved_config: Path | None = None
        for conf_path in possible_config_paths:
            candidate = Path(conf_path)
            if not candidate.is_absolute():
                candidate = source_dir / candidate
            if candidate.exists():
                # Say so when the config narrows the report. Without this the
                # only record that matches were withheld is the config file
                # itself, which nobody reads while looking at a clean scan.
                restricting_keys = self._output_restricting_keys(candidate)
                if restricting_keys:
                    self._plugin_log(
                        f"The grype config at {candidate} sets "
                        f"{', '.join(restricting_keys)}, which restricts which "
                        "matches reach the report. Vulnerabilities grype detected "
                        "may be absent from these results, and the scan can pass "
                        "with findings withheld.",
                        level=logging.WARNING,
                    )
                resolved_config = candidate.resolve()
                self.args.extra_args.append(
                    ToolExtraArg(
                        key="--config",
                        value=resolved_config.as_posix(),
                    )
                )
                break

        # Online, the database's age bound is DECLARED rather than inherited: the
        # value comes from utils/content_databases.py, the same entry the CI cache
        # key and its freshness guard are computed from, so the cache window and
        # the bound grype enforces are one number. It equals grype's own default
        # today (the registry cites where), so this changes no verdict; it makes
        # the equality something a test can hold rather than a coincidence.
        #
        # An explicit choice still wins. A user who exported one of these, or
        # set `db.max-allowed-built-age` / `db.validate-age` in the grype config
        # ASH passes above, asked for that bound; grype puts the environment
        # above the config file, so setting the variable here regardless would
        # silently override their file.
        offline = self._scanner_offline()
        if not offline:
            self.extra_env.update(_declared_grype_db_bound(os.environ, resolved_config))

        # Handle offline mode. Stash offline-mode env vars on the instance
        # rather than writing to os.environ — scanners run concurrently
        # in thread pools and would race on the shared parent env.
        #
        # GRYPE_DB_VALIDATE_AGE=false stays: with it true, grype answers a stale
        # database by trying to download a new one, which an air-gapped host
        # cannot do. The bound is held instead by ASH's own check after the scan
        # (utils/content_db_staleness.py), which reads `built` from
        # `grype db status` the same way online and offline, and fails the scan
        # by default once the database is past the registry's bound.
        if offline:
            self.extra_env.update(
                {
                    "GRYPE_DB_VALIDATE_AGE": "false",
                    "GRYPE_DB_AUTO_UPDATE": "false",
                    "GRYPE_CHECK_FOR_APP_UPDATE": "false",
                }
            )

            # Validate offline mode requirements
            from automated_security_helper.utils.offline_mode_validator import (
                validate_grype_offline_mode,
            )

            offline_valid, offline_messages = validate_grype_offline_mode()
            if not offline_valid:
                for msg in offline_messages:
                    self._plugin_log(msg, level=logging.WARNING)

            ASH_LOGGER.info(
                "Running Grype in offline mode - database updates and validation disabled"
            )

        return super()._process_config_options()

    # Grype exits with 2 when vulnerabilities are found above threshold,
    # not 1 like most scanners. Override the template-method default.
    success_exit_codes: ClassVar[set] = {0, 2}

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ):
        """Resolve final argv, results path, and subprocess env for Grype."""
        target_results_dir = self.results_dir.joinpath(target_type)
        results_file = target_results_dir.joinpath("results_sarif.sarif")
        results_file.parent.mkdir(exist_ok=True, parents=True)
        final_args = self._resolve_arguments(
            # Grype expects directory scans to have the target begin with `dir:`
            target=f"dir:{target.as_posix()}",
            results_file=results_file,
        )
        subprocess_env = (
            {**snapshot_environ(), **self.extra_env} if self.extra_env else None
        )
        return final_args, results_file, subprocess_env

    def _ensure_runs(self, sarif_report: SarifReport) -> None:
        """Synthesize a fallback Run when Grype emits a runless SARIF."""
        if not sarif_report.runs:
            ASH_LOGGER.warning("Grype SARIF report has no runs, creating empty run")
            sarif_report.runs = [
                Run(
                    tool=Tool(driver=ToolComponent(name="grype", version="unknown")),
                    results=[],
                )
            ]

    def _invocation_extras(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> dict:
        """Attach the run's tool to the invocation's properties bag."""
        if not sarif_report.runs:
            return {}
        return {"properties": PropertyBag(tool=sarif_report.runs[0].tool)}

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Strip leading slashes from artifact URIs and attach package identity."""
        lock_index = NpmLockIndex(target)
        for result in sarif_report.get_all_results():
            self._normalize_result_uris(result)
            self._attach_package_identity(result, lock_index)
        return sarif_report

    @staticmethod
    def _attach_package_identity(result, lock_index: NpmLockIndex) -> None:
        """Record which package copy a grype result is about.

        grype's SARIF puts every dependency finding at line 1 of the manifest,
        and its rule's ``purls`` list is per rule, not per result, so the only
        per-result statement of the package is the message grype writes:
        ``A <sev> vulnerability in <type> package: <name>, version <version>
        was found at: <path>``. When the message has another shape nothing is
        attached, and a package-scoped suppression will not match the result.

        For an npm lockfile the name and version are looked up among the
        lockfile's entries; exactly one match gives ``package_path``. Two or
        more (the same version installed at two places) give no path, because
        grype's output does not say which copy it found.
        """
        message = result.message.root.text if result.message else None
        match = _GRYPE_PACKAGE_MESSAGE.search(message or "")
        if not match:
            return
        name, version = match.group("name"), match.group("version")

        path = None
        uri = None
        if result.locations:
            physical = result.locations[0].physicalLocation
            if physical and physical.root and physical.root.artifactLocation:
                uri = physical.root.artifactLocation.uri
        # grype's URI is not scan-root-relative on Windows: it is the scan root
        # followed by a backslashed relative path, "D:/a/r/r/\\deploy\\cdk\\...".
        # sanitize_sarif_paths fixes the location later, but package_path is
        # built here, so the lockfile is relativized here too. None (outside
        # the scan root) claims no path.
        lock_rel = lock_index.relative(uri) if uri else None
        if lock_rel:
            entry = lock_index.unique_by_name_version(lock_rel, name, version)
            if entry is not None:
                path = install_path(lock_rel, entry.key)

        identity = identity_properties(name, version, path)
        if result.properties is None:
            result.properties = PropertyBag(**identity)
        else:
            for key, value in identity.items():
                setattr(result.properties, key, value)
