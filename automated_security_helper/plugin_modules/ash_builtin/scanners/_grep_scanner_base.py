"""Shared base for semgrep- and opengrep-style scanners.

`semgrep` and `opengrep` ship near-identical CLIs (`--config`, `--sarif`,
`--exclude`, `--severity`, `--no-rewrite-rule-ids`, …) and identical
offline-cache strategies. This module factors that out so each concrete
scanner becomes a thin shell that customises three things:

- the binary command (`tool_command`)
- the default ruleset (`default_rulesets`)
- the cache-dir env var (`cache_dir_env_var`)

Subclasses still own their own dependency-resolution path
(`validate_plugin_dependencies`) and any non-shared options (e.g. opengrep's
patterns mode, version-gated `--metrics`). Everything else lives here.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import ClassVar, Generic, List, Literal, Optional, Tuple, TypeVar

from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.constants import ASH_ASSETS_DIR
from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import (
    ToolExtraArg,
)
from automated_security_helper.utils.log import ASH_LOGGER

C = TypeVar("C", bound=ScannerPluginConfigBase)


class GrepScannerBase(ScannerPluginBase[C], Generic[C]):
    """Shared scaffolding for semgrep and opengrep scanners."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.CACHE_FLAGS

    # ---------------------------------------------------------------
    # Hooks subclasses override
    # ---------------------------------------------------------------

    def cache_dir_env_var(self) -> str:
        """Env var pointing at the offline rule cache (e.g. SEMGREP_RULES_CACHE_DIR).

        Subclasses MUST override.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement cache_dir_env_var()"
        )

    def default_rulesets(self) -> List[str]:
        """Default ruleset(s) to pass via --config when online (e.g. ['p/ci']).

        Subclasses MUST override.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement default_rulesets()"
        )

    def cache_dir_name(self) -> str:
        """Human-readable scanner name used in error messages."""
        return self.__class__.__name__.replace("Scanner", "")

    def emit_metrics_flag(self) -> bool:
        """Whether to emit a `--metrics` flag at all.

        Override (e.g. opengrep version >= 1.7.0) to suppress.
        """
        return True

    def metrics_value_online(self) -> str:
        """`--metrics` value used in online mode (auto/on/off)."""
        return "auto"

    def metrics_value_offline(self) -> str:
        """`--metrics` value used in offline mode (typically 'off')."""
        return "off"

    def extra_subprocess_env(self) -> Optional[dict]:
        """Extra env vars merged with os.environ for the scan subprocess.

        Default: inherit the parent env. Semgrep overrides this to set
        `SEMGREP_RULES` from the cache dir.
        """
        return None

    # ---------------------------------------------------------------
    # Shared arg-building (was duplicated in each scanner).
    # ---------------------------------------------------------------

    def _process_config_options(self):
        opts = self.config.options  # type: ignore[union-attr]

        # Drop any --metrics already pushed into extra_args (some scanners
        # re-call this and we want a clean state).
        self.args.extra_args = [
            a for a in self.args.extra_args if a.key != "--metrics"
        ]

        # Bundled ASH stargrep rules — picked up by both scanners.
        ash_stargrep_rules = [
            item
            for item in ASH_ASSETS_DIR.joinpath("ash_stargrep_rules").glob("*")
            if (item.as_posix().endswith(".yaml") or item.as_posix().endswith(".yml"))
        ]
        if ash_stargrep_rules:
            ASH_LOGGER.verbose(f"Found ASH *grep rulesets: {ash_stargrep_rules}")
            self.args.extra_args.extend(
                [
                    ToolExtraArg(key="--config", value=item.as_posix())
                    for item in ash_stargrep_rules
                ]
            )

        if getattr(opts, "offline", False):
            self._configure_offline_mode()
        else:
            self._configure_online_mode()

        # Exclude patterns / rules / severity filters — verbatim across both
        # scanners.
        for pattern in getattr(opts, "exclude", []) or []:
            self.args.extra_args.append(ToolExtraArg(key="--exclude", value=pattern))
        for rule_id in getattr(opts, "exclude_rule", []) or []:
            self.args.extra_args.append(
                ToolExtraArg(key="--exclude-rule", value=rule_id)
            )
        for severity in getattr(opts, "severity", []) or []:
            self.args.extra_args.append(ToolExtraArg(key="--severity", value=severity))

        # SARIF output mode.
        self.args.extra_args.append(ToolExtraArg(key="--sarif", value=""))

        return super()._process_config_options()

    def _configure_offline_mode(self) -> None:
        """Set --metrics off (when supported), validate cache dir, append cache --config."""
        if self.emit_metrics_flag():
            self.args.extra_args.append(
                ToolExtraArg(key="--metrics", value=self.metrics_value_offline())
            )

        from automated_security_helper.utils.offline_mode_validator import (
            OfflineModeValidator,
        )

        cache_env = self.cache_dir_env_var()
        cache_dir = os.environ.get(cache_env, "")
        scanner_label = self.cache_dir_name()

        offline_valid, _ = OfflineModeValidator.validate_cache_directory(
            cache_dir=cache_dir,
            file_extensions=[".yaml", ".yml"],
            scanner_name=scanner_label,
        )
        if not offline_valid:
            raise ScannerError(
                f"{scanner_label} is running in offline mode but no rule cache was found. "
                f"Set ${cache_env} to a directory containing .yaml/.yml rule files. "
                "Run `ash build-image --offline` to pre-warm the cache via Dockerfile, "
                "or download rulesets manually with `semgrep --config p/ci --dryrun` "
                "while online and copy to cache."
            )

        ASH_LOGGER.info(
            f"{scanner_label} offline mode: using cached rules from {cache_dir}"
        )
        self.args.extra_args.append(ToolExtraArg(key="--config", value=cache_dir))
        # Use the rule's own id rather than path-derived prefix — keeps
        # rule IDs stable between online and offline runs.
        self.args.extra_args.append(
            ToolExtraArg(key="--no-rewrite-rule-ids", value="")
        )

    def _configure_online_mode(self) -> None:
        opts = self.config.options  # type: ignore[union-attr]
        # Honour scanner-configured ruleset (defaults to default_rulesets()[0]).
        configured = getattr(opts, "config", None)
        if configured:
            self.args.extra_args.append(ToolExtraArg(key="--config", value=configured))
        else:
            for rs in self.default_rulesets():
                self.args.extra_args.append(ToolExtraArg(key="--config", value=rs))

        if self.emit_metrics_flag():
            metrics_val = getattr(opts, "metrics", None) or self.metrics_value_online()
            self.args.extra_args.append(
                ToolExtraArg(key="--metrics", value=metrics_val)
            )

    # ---------------------------------------------------------------
    # Template-method scan(): inherited from ScannerPluginBase.
    #
    # We only override _execute_scan to resolve argv + results path + env.
    # All SARIF parsing, invocation injection, and error handling lives in
    # the base class — keeping this scanner family aligned with checkov,
    # grype, and the rest of the migrated tools.
    #
    # success_exit_codes defaults to {0, 1} on the base class, which matches
    # semgrep/opengrep behaviour (exit 1 = findings present), so no override
    # is required here.
    # ---------------------------------------------------------------

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths,
    ) -> Tuple[List[str], Path, Optional[dict]]:
        """Resolve final argv + results path + subprocess env.

        Subclasses may override for bespoke result-file locations (e.g.
        opengrep patterns mode, which writes opengrep_results.json).
        """
        assert self.results_dir is not None, "results_dir must be set by model_post_init"
        target_results_dir = self.results_dir.joinpath(target_type)
        results_file = target_results_dir.joinpath("results_sarif.sarif")
        target_results_dir.mkdir(exist_ok=True, parents=True)

        final_args = self._resolve_arguments(target=target, results_file=results_file)

        env_vars = self.extra_subprocess_env()
        subprocess_env = {**os.environ, **env_vars} if env_vars else None
        return final_args, results_file, subprocess_env
