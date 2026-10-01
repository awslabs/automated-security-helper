"""Module containing the Grype security scanner implementation."""

import logging
import os
from pathlib import Path
from typing import Annotated, ClassVar, List, Literal, Mapping

from pydantic import Field, model_validator
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
from automated_security_helper.core.constants import is_offline_mode
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
from automated_security_helper.utils.subprocess_utils import find_executable


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
            description="Run in offline mode, disabling database updates and validation",
            default_factory=is_offline_mode,
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
        if not self.config.options.offline:
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
        if self.config.options.offline:
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
            {**os.environ, **self.extra_env} if self.extra_env else None
        )
        return final_args, results_file, subprocess_env

    def _ensure_runs(self, sarif_report: SarifReport) -> None:
        """Synthesize a fallback Run when Grype emits a runless SARIF."""
        if not sarif_report.runs:
            ASH_LOGGER.warning(
                "Grype SARIF report has no runs, creating empty run"
            )
            sarif_report.runs = [
                Run(
                    tool=Tool(
                        driver=ToolComponent(name="grype", version="unknown")
                    ),
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
        """Strip leading slashes from artifact URIs across all results."""
        for result in sarif_report.get_all_results():
            self._normalize_result_uris(result)
        return sarif_report
