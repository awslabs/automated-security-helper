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

import fnmatch
import logging
import os
from pathlib import Path
from typing import (
    Any,
    ClassVar,
    Generic,
    List,
    Literal,
    Optional,
    Tuple,
    TypeVar,
    final,
)

from pydantic import PrivateAttr

from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.constants import ASH_ASSETS_DIR
from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolExtraArg,
)
from automated_security_helper.utils.get_scan_set import honors_ignore_files
from automated_security_helper.utils.link_exclusions import grep_ignore_names
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.process_env import snapshot_environ

C = TypeVar("C", bound=ScannerPluginConfigBase)


#: The default ``exclude`` entry of both scanners that names the files the
#: jupyter converter writes (``<notebook>-converted.py``). It is meant for the
#: source target, where an output directory inside the tree used to put those
#: files in front of the tool twice; the output-directory excludes
#: (_output_dir_exclude_patterns) cover that now. On the converted target the
#: same pattern names every file the target exists for, so it is left out there.
CONVERTED_FILE_EXCLUDE = "*-converted.py"

#: The tools' switch for their git-ignore reading. Both skip every file the
#: repository's ``.gitignore`` matches when the target is inside a git work tree.
#: ASH's own output directory carries a ``.gitignore`` that ignores everything in
#: it (utils/output_dir_links.ignore_output_dir_in_git), and the converted target
#: lives under it, so without this flag a converted target inside a repository
#: is skipped whole.
NO_GIT_IGNORE_FLAG = "--no-git-ignore"

#: The ``paths.skipped`` reasons under which the tool found a file in a language
#: its rules cover and did not read it. A target where nothing was scanned and a
#: file was skipped for one of these is not "nothing to scan": the tool says
#: nothing about that file, and the scan is refused rather than graded SKIPPED.
#: Every other reason (a language the rules do not cover, a path the tool's own
#: defaults or ASH's exclusions leave out, a minified or binary file) is a file
#: the tool chose not to scan, which SKIPPED describes.
UNREAD_SKIP_REASONS: frozenset[str] = frozenset(
    {
        "exceeded_size_limit",
        "too_big",
        "analysis_failed_parser_or_internal_error",
        "insufficient_permissions",
    }
)


#: The paths semgrep and opengrep skip by default when no .semgrepignore is
#: read. Passed as --exclude with --x-ignore-semgrepignore-files, so that a
#: repository's own .semgrepignore is not honored and the default coverage stays
#: the same. Measured: each entry here was skipped by both tools' defaults, and
#: .semgrep and .semgrep_logs, which semgrep's documentation also lists, were not.
SEMGREP_DEFAULT_IGNORES: tuple[str, ...] = (
    "node_modules/",
    "build/",
    "dist/",
    "vendor/",
    ".env/",
    ".venv/",
    ".tox/",
    "*.min.js",
    ".npm/",
    ".yarn/",
    "test/",
    "tests/",
    "*_test.go",
)


class GrepScannerBase(ScannerPluginBase[C], Generic[C]):
    """Shared scaffolding for semgrep and opengrep scanners."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.CACHE_FLAGS

    # The names the current target's command excludes for the global ignore paths
    # (_execute_scan), which _post_process_sarif tells apart from other excludes.
    _ignore_exclude_names: List[str] = PrivateAttr(default_factory=list)
    # The ASH output directories the current target's command excludes, relative
    # to the target (_output_dir_exclude_patterns), told apart the same way.
    _output_dir_excluded: List[Path] = PrivateAttr(default_factory=list)
    # Which target the current command is for: the converted target drops the
    # converted-file exclude and reads git-ignored files (_resolve_scan_arguments).
    _scan_target_type: str = PrivateAttr(default="source")

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

    def _validate_tool_dependencies(self) -> bool:
        """Whether this scanner's TOOL is reachable. Subclasses override THIS.

        Split out from ``validate_plugin_dependencies`` so the offline-cache verdict
        below cannot be bypassed by a subclass. Both concrete scanners resolve their
        binary through their own UV-or-PATH logic and neither chained to the base
        implementation, so a guard added to ``ScannerPluginBase`` was simply not
        reached -- measured: both returned True with the cache absent. Writing the
        same two lines into each subclass would work today and break on the third
        grep-family scanner, which is the failure mode this repository has already
        paid for elsewhere.
        """
        return super().validate_plugin_dependencies()

    @final
    def validate_plugin_dependencies(self) -> bool:
        """Final for this family: the offline-cache verdict, then the tool check.

        Subclasses customise ``_validate_tool_dependencies`` instead of this method.
        Overriding this one restores the bypass it exists to close.

        ``@final`` rather than a docstring asking not to override. The prose said
        "final" for a while with nothing enforcing it, and a sibling docstring in
        ``base/scanner_plugin.py`` told readers this family was structurally
        protected -- so the one place a reviewer would not look was the one place
        the protection was missing. mypy runs in this repository, so the decorator
        makes the claim checkable instead of aspirational.

        Before either: the tool-version probe a member deferred at construction
        (``deferred_tool_version_probes``), which is a no-op for a member that
        did not.
        """
        self.resolve_deferred_tool_version()
        if self.dependency_unavailable_reason:
            # Not re-logged. `_configure_offline_mode` already emitted this at
            # WARNING during construction, and ScanPhase logs its own line when it
            # records the scanner MISSING; a third copy per scanner per run says
            # nothing new.
            return False
        return self._validate_tool_dependencies()

    def content_databases_in_use(self) -> list:
        """The offline ruleset, and only in offline mode.

        Online, the rules come from the registry at scan time and no local copy is read,
        so there is nothing whose age could make the result stale.
        """
        if not self._scanner_offline():
            return []
        return super().content_databases_in_use()

    def content_database_probe_context(self):
        """The rules cache directory the offline scan passed as ``--config``."""
        context = super().content_database_probe_context()
        context.cache_dir = os.environ.get(self.cache_dir_env_var(), "") or None
        return context

    # ---------------------------------------------------------------
    # Shared arg-building (was duplicated in each scanner).
    # ---------------------------------------------------------------

    def _process_config_options(self):
        opts = self.config.options  # type: ignore[union-attr]

        # Drop any --metrics already pushed into extra_args (some scanners
        # re-call this and we want a clean state).
        self.args.extra_args = [a for a in self.args.extra_args if a.key != "--metrics"]

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

        if self._scanner_offline():
            self._configure_offline_mode()
        else:
            self._configure_online_mode()
        # The rule's own id rather than a path-derived prefix, online and offline
        # alike: the bundled ASH rules above are passed by path in both modes, and
        # passing this only offline gave the same rule two ids depending on the
        # mode the scan ran in.
        self.args.extra_args.append(ToolExtraArg(key="--no-rewrite-rule-ids", value=""))

        # A .semgrepignore in the scanned tree is the repository's own choice of
        # what to leave out, and both tools honor one on their own: semgrep from
        # the scan root or any directory up to the repository root, opengrep from
        # its working directory, which is the source directory. Neither is read.
        # Ignoring the files also drops each tool's built-in list of paths it
        # skips, so that list is passed back as --exclude patterns, keeping what
        # a scan covers unchanged (measured against semgrep 1.180 and opengrep
        # 1.15.1 and 1.30.0: the same files are reported as with no
        # .semgrepignore at all).
        self.args.extra_args = [
            a for a in self.args.extra_args if a.key != "--x-ignore-semgrepignore-files"
        ]
        self.args.extra_args.append(
            ToolExtraArg(key="--x-ignore-semgrepignore-files", value=None)
        )
        for pattern in SEMGREP_DEFAULT_IGNORES:
            self.args.extra_args.append(ToolExtraArg(key="--exclude", value=pattern))
        self._note_unhonored_semgrepignore()

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

    def _note_unhonored_semgrepignore(self) -> None:
        """Say in the results that a ``.semgrepignore`` the tool would have read was not.

        Looked for where either tool would read one: the source directory and
        each directory above it up to the repository root (the first one holding
        ``.git``). Only its presence is checked; the file is not read. The note
        is a config warning, which the orchestrator records in the results as a
        ``config_warning`` validation checkpoint, once per file. A file an MCP
        client delivered (``cli/mcp/sandbox.config_is_client_supplied``, judged by
        its path, each symlink on the way and the file it resolves to) is named
        as client-supplied.
        """
        # Imported here, as config/path_trust.py does: importing cli.mcp runs its
        # __init__, which imports the config modules.
        from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

        source = getattr(self.context, "source_dir", None)
        if source is None:
            return
        found = []
        directory = Path(os.path.abspath(source))
        for candidate in (directory, *directory.parents):
            ignore_file = candidate / ".semgrepignore"
            if os.path.lexists(ignore_file):
                found.append(ignore_file)
            if os.path.lexists(candidate / ".git"):
                break
        config = getattr(self.context, "config", None)
        warnings = getattr(config, "_resolution_warnings", None)
        for ignore_file in found:
            # The judgment resolves the path. A link loop at the name raises
            # RuntimeError on Python 3.10 to 3.12 and OSError on 3.13, and this runs
            # while the scanner is built, so either used to end the scanner; a
            # file that cannot be resolved is named as the repository's.
            try:
                client_supplied = config_is_client_supplied(ignore_file)
            except (OSError, RuntimeError):
                client_supplied = False
            if client_supplied:
                message = (
                    f"{ignore_file.as_posix()} is client-supplied (an MCP client "
                    "delivered it) and was not honored: ASH runs semgrep and opengrep "
                    "with --x-ignore-semgrepignore-files and their default "
                    "exclusions, so it does not leave files out. List them in "
                    "global_settings.ignore_paths instead, where a client's entries "
                    "apply marked client_supplied."
                )
            else:
                message = (
                    f"{ignore_file.as_posix()} was not honored: ASH runs semgrep and "
                    "opengrep with --x-ignore-semgrepignore-files and their default "
                    "exclusions, so a .semgrepignore in the scanned tree does not "
                    "leave files out. List them in global_settings.ignore_paths "
                    "instead."
                )
            if isinstance(warnings, list) and message not in warnings:
                warnings.append(message)
                self._plugin_log(message, level=logging.WARNING)

    def _local_rules_configured(self) -> Optional[str]:
        """The operator's ``options.config`` as an absolute path, when it names a
        rule file or directory on this host; None for a registry name or a URL.

        Offline, a local rule file needs no network, so it is what the scan runs
        with, as it is online. Absolute because the tool runs in the source
        directory while the path was written relative to ASH's working directory.
        """
        configured = getattr(self.config.options, "config", None)  # type: ignore[union-attr]
        if not configured or not isinstance(configured, str):
            return None
        if "://" in configured or _is_registry_name(configured):
            return None
        candidate = Path(os.path.abspath(configured))
        if candidate.is_file() or candidate.is_dir():
            return candidate.as_posix()
        return None

    def _configure_offline_mode(self) -> None:
        """Set --metrics off (when supported), then the rules: the operator's local
        rule file or directory when ``options.config`` names one, else the
        validated cache directory as ``--config``."""
        if self.emit_metrics_flag():
            self.args.extra_args.append(
                ToolExtraArg(key="--metrics", value=self.metrics_value_offline())
            )

        # Patterns mode (opengrep) searches for the configured patterns and drops
        # every --config from its command, so it reads no rules and needs no rule
        # cache; declining for a missing cache recorded it MISSING for nothing.
        if getattr(self.config.options, "patterns", None):  # type: ignore[union-attr]
            ASH_LOGGER.info(
                f"{self.cache_dir_name()} offline mode: patterns mode reads no rule "
                "configuration, so no rule cache is needed"
            )
            return

        local_rules = self._local_rules_configured()
        if local_rules is not None:
            # The operator's own rules, as online. The registry cache is not
            # needed for them and not read: online passes the configured rules
            # alone, and an offline scan of the same configuration should run
            # the same rules.
            ASH_LOGGER.info(
                f"{self.cache_dir_name()} offline mode: using the configured local "
                f"rules from {local_rules}"
            )
            self.args.extra_args.append(ToolExtraArg(key="--config", value=local_rules))
            return

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
            # RECORDED, NOT RAISED, and the difference is a scanner that exists
            # versus one that does not.
            #
            # This runs inside `_process_config_options`, whose only caller is
            # `ScannerPluginBase.model_post_init` -- a constructor. pydantic 2
            # propagates the exception unwrapped, and `ScanPhase`'s scanner-creation
            # loop catches it, logs one line, and does not append to
            # `scanner_instances`. The instance therefore did not exist to be asked
            # `validate_plugin_dependencies()` or `unsupported_platform_reason()`,
            # both of which exist so that "cannot run here" is recorded rather than
            # dropped, and both of which are consulted only on entries in that list.
            #
            # What that produced: two scanners absent from `scanner_results`, five
            # status counters summing correctly over the eight that remained, and a
            # results file a consumer cannot tell apart from a complete scan. A
            # false negative of exactly the shape the completeness gate exists to
            # catch, and one it could not see because the denominator shrank with
            # the numerator.
            #
            # The remediation text travels with the verdict rather than being
            # reconstructed by the reader, because it is the only thing that tells
            # an operator how to fix a real misconfiguration.
            self.dependency_unavailable_reason = (
                f"{scanner_label} is running in offline mode but no rule cache was found. "
                f"Set ${cache_env} to a directory containing .yaml/.yml rule files. "
                "Run `ash build-image --offline` to pre-warm the cache in the image, "
                "or, while online, download each ruleset from "
                "https://semgrep.dev/c/<ruleset> into that directory and record the "
                "time in .ash-rules-fetched-at. See 'Seeding the semgrep and opengrep "
                "rule cache' in docs/content/docs/advanced-usage.md."
            )
            ASH_LOGGER.warning(self.dependency_unavailable_reason)
            # No cache `--config` to append, so nothing further to configure. The
            # online default is deliberately NOT substituted: an offline run that
            # silently fetched the registry ruleset would be a different scan than
            # the one that was asked for, reported as the one that was asked for.
            return

        ASH_LOGGER.info(
            f"{scanner_label} offline mode: using cached rules from {cache_dir}"
        )
        # Absolute: the directory was validated against ASH's working directory,
        # and the tool runs in the source directory, so a relative value would
        # name a different directory there (one inside the scanned tree, when
        # the name exists in both).
        self.args.extra_args.append(
            ToolExtraArg(key="--config", value=os.path.abspath(cache_dir))
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

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: Any = None,
        *args,
        **kwargs,
    ) -> Any:
        """The template scan, with this target's scanned-file count reset first.

        ``targets_attempted`` is set from the tool's output (_post_process_sarif)
        and read by the executor after every target, so a target that returns
        before the tool runs (an empty directory) must not keep the last one's.
        """
        self.targets_attempted: Optional[int] = None
        return super().scan(
            target, target_type, global_ignore_paths, config, *args, **kwargs
        )

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
        # Not an assert: `python -O` strips assert statements, which would drop
        # this guard exactly where it matters and surface the failure one line
        # later as "'NoneType' object has no attribute 'joinpath'" instead of
        # naming the real problem. ScannerError matches how the rest of this
        # class reports unusable configuration.
        # Fail closed on a verdict that construction recorded instead of raising.
        #
        # `_configure_offline_mode` appends no cache `--config` when the rule cache
        # is absent, so a scanner that reached execution anyway would scan with
        # whatever rules it happened to have and report the result as an offline
        # scan. `ScanPhase` asks `validate_plugin_dependencies()` first and never
        # dispatches this scanner, but that is a property of one caller; this class
        # should not depend on it, and a second caller (an installer probe, a
        # plugin-inventory path, an out-of-tree orchestrator) would not inherit it.
        if self.dependency_unavailable_reason:
            raise ScannerError(self.dependency_unavailable_reason)

        if self.results_dir is None:
            raise ScannerError(
                f"{self.__class__.__name__} has no results_dir; it must be set by "
                "model_post_init before a scan is executed."
            )
        target_results_dir = self.results_dir.joinpath(target_type)
        results_file = target_results_dir.joinpath("results_sarif.sarif")
        target_results_dir.mkdir(exist_ok=True, parents=True)

        # Read by _resolve_scan_arguments, which the subclass may call again for
        # this target (opengrep's patterns mode).
        self._scan_target_type = target_type

        # No --exclude for links leaving the target: semgrep 1.180.0 and opengrep
        # 1.30.2 follow no link (measured), and their --exclude cannot name one
        # path. semgrep matches a pattern against paths below its project root, the
        # git work tree's root when the target is a directory inside one, so even a
        # name nothing below the target has can be one of the target's own
        # directories, and then it leaves out the whole target.
        # Resolved before this target's ignore names are computed, so the
        # resolution adds only the output-directory excludes
        # (_resolve_scan_arguments); the ignore names are inserted once, below.
        self._ignore_exclude_names = []
        final_args = self._resolve_scan_arguments(target, results_file)

        # The global ignore paths, as names that leave out nothing else (see
        # utils/link_exclusions.grep_ignore_names); an ignored path no such name
        # covers is still read, and ASH drops its findings. In the joined form,
        # since a name can start with "-".
        ignore_names = grep_ignore_names(
            target, getattr(self.context, "source_dir", None), global_ignore_paths
        )
        self._ignore_exclude_names = ignore_names
        if ignore_names:
            head = [self.command, *self.subcommands]
            insert_at = len(head) if final_args[: len(head)] == head else 1
            final_args[insert_at:insert_at] = [
                f"--exclude={name}" for name in ignore_names
            ]

        # The scanned and skipped paths, read after the run (_post_process_sarif).
        # Not in patterns mode, which writes its JSON results instead of SARIF.
        if not getattr(getattr(self.config, "options", None), "patterns", None):
            paths_file = target_results_dir.joinpath(
                f"{self.__class__.__name__}.paths.json"
            )
            paths_file.unlink(missing_ok=True)
            head = [self.command, *self.subcommands]
            insert_at = len(head) if final_args[: len(head)] == head else 1
            final_args[insert_at:insert_at] = [
                f"{_PATHS_OUTPUT_FLAG}={paths_file.as_posix()}",
                "--verbose",
            ]

        env_vars = self.extra_subprocess_env()
        subprocess_env = {**snapshot_environ(), **env_vars} if env_vars else None
        return final_args, results_file, subprocess_env

    def _reads_git_ignored_files(self) -> bool:
        """Whether this target's command carries ``--no-git-ignore``.

        The converted target always: it lives under ASH's output directory, whose
        ``.gitignore`` ignores everything in it, so inside a git work tree the tools
        skipped every converted file and the target graded SKIPPED. The source
        target when the operator set ``honor_ignore_files: false``, which asks for
        the files the repository's ignore files match to be scanned too; the
        tools' own git-ignore reading left them out whatever ASH's scan set did.
        """
        if self._scan_target_type == "converted":
            return True
        return not honors_ignore_files(getattr(self.context, "config", None))

    def _extra_args_for_target(self) -> List[ToolExtraArg]:
        """The configured extra arguments, as the current target's command takes them.

        The converted target drops ``CONVERTED_FILE_EXCLUDE``: there the pattern
        names every file the converter wrote, which is every file the target holds,
        so the tools found files and excluded them all, and the scanned-nothing
        refusal below (_post_process_sarif) made a repository of notebooks a
        scanner error. An operator's own exclude patterns stay as written.
        """
        if self._scan_target_type != "converted":
            return list(self.args.extra_args)
        return [
            arg
            for arg in self.args.extra_args
            if not (arg.key == "--exclude" and arg.value == CONVERTED_FILE_EXCLUDE)
        ]

    def _resolve_scan_arguments(self, target: Path, results_file: Path) -> List[str]:
        """``_resolve_arguments`` plus an ``--exclude`` per ASH output directory,
        and one per name the global ignore paths give (``_execute_scan``).

        Added for this resolution only, as checkov does: the patterns depend on the
        target, and extra_args persists across scan() calls. The names go in the
        joined form right after the command, since a name can start with "-".
        The converted target's command leaves out the converted-file exclude
        (_extra_args_for_target) and reads git-ignored files, as does the source
        target's when the operator does not honor ignore files
        (_reads_git_ignored_files).
        """
        original_extra_args = list(self.args.extra_args)
        self.args.extra_args = self._extra_args_for_target()
        self.args.extra_args.extend(
            ToolExtraArg(key="--exclude", value=pattern)
            for pattern in self._output_dir_exclude_patterns(target)
        )
        if self._reads_git_ignored_files():
            self.args.extra_args.append(
                ToolExtraArg(key=NO_GIT_IGNORE_FLAG, value=None)
            )
        try:
            final_args = self._resolve_arguments(
                target=target, results_file=results_file
            )
        finally:
            self.args.extra_args = original_extra_args
        names = self._ignore_exclude_names
        if names:
            head = [self.command, *self.subcommands]
            insert_at = len(head) if final_args[: len(head)] == head else 1
            final_args[insert_at:insert_at] = [f"--exclude={name}" for name in names]
        return final_args

    def _output_dir_exclude_patterns(self, target: Path) -> List[str]:
        """``--exclude`` values naming each ASH output directory under ``target``.

        semgrep reads ``--exclude`` with gitignore syntax, so a bare ``out`` would
        also skip ``src/out``. A leading ``/`` anchors the pattern, but at the
        project root rather than at the target: the nearest ancestor holding
        ``.git``, or the target when there is none. Measured with semgrep 1.180 on a
        target ``t/src`` inside the git repository ``t``: ``/shard-1`` left
        ``t/src/shard-1`` scanned and ``/src/shard-1`` excluded it, and without the
        repository it was the other way round. opengrep shares semgrep's file
        targeting.

        Every component is escaped (``utils/scan_output_dirs.escape_for_pattern``),
        the scanned directory's own name included when the anchor is above it:
        ``/out[1]`` skipped a directory ``out1`` and scanned ``out[1]``, on semgrep
        1.180.0 and opengrep 1.30.2.
        """
        from automated_security_helper.utils.scan_output_dirs import (
            PatternSyntax,
            escape_for_pattern,
        )

        relatives = self._ash_output_dirs_inside(target)
        self._output_dir_excluded = list(relatives)
        if not relatives:
            return []
        target_abs = Path(os.path.abspath(target))
        anchor = next(
            (
                candidate
                for candidate in (target_abs, *target_abs.parents)
                if candidate.joinpath(".git").exists()
            ),
            target_abs,
        )
        return [
            "/"
            + escape_for_pattern(
                target_abs.joinpath(relative).relative_to(anchor).as_posix(),
                PatternSyntax.GLOB,
                separator="/",
            )
            for relative in relatives
        ]

    def _left_out_by_ash(self, path: str) -> bool:
        """Whether ``path``, which the tool excluded, matches one of the exclusions
        ASH itself adds to every command rather than one the operator configured.

        Three sets, each what the tool would have skipped on its own or what ASH
        skips for every scanner: the names given for the global ignore paths
        (``_ignore_exclude_names``), the ASH output directories inside the target
        (``_output_dir_excluded``), and the tools' own default ignore list, which
        ASH re-passes as ``--exclude`` because ``--x-ignore-semgrepignore-files``
        drops it (``SEMGREP_DEFAULT_IGNORES``). Matched on path components, as the
        tools match a directory pattern, and on the file name for a file glob.
        """
        parts = Path(path).parts
        if set(self._ignore_exclude_names).intersection(parts):
            return True
        for relative in self._output_dir_excluded:
            needle = relative.parts
            if needle and any(
                parts[i : i + len(needle)] == needle
                for i in range(len(parts) - len(needle) + 1)
            ):
                return True
        name = parts[-1] if parts else ""
        for pattern in SEMGREP_DEFAULT_IGNORES:
            if pattern.endswith("/"):
                if pattern[:-1] in parts[:-1]:
                    return True
            elif fnmatch.fnmatchcase(name, pattern):
                return True
        return False

    def _post_process_sarif(self, sarif_report, final_args: List[str], target: Path):
        """Record how many files the tool scanned, and refuse a scan of none.

        semgrep 1.180.0 and opengrep 1.30.2 write ``paths.scanned`` to
        ``--json-output``, and with ``--verbose`` also ``paths.skipped``, each with
        its reason (measured). The count becomes ``targets_attempted``. None scanned
        while files were skipped by the operator's ``--exclude`` patterns
        (``cli_exclude_flags_match``, and not one of ASH's own exclusions, see
        ``_left_out_by_ash``) means the patterns left out every file the tool
        found, so the scan says nothing about them: that is an error, not a PASSED
        with no findings. The same when the tool found a file in a covered language
        and did not read it (``UNREAD_SKIP_REASONS``: too large, unreadable, a
        parse failure). None scanned otherwise means nothing below the target is
        in a language the rules cover, or every such file is one the tool's own
        defaults or ASH's exclusions leave out, which the executor grades SKIPPED
        (``targets_attempted`` 0). An absent or unreadable paths file leaves the
        count unset (no claim).

        Raises:
            ScannerError: When the operator's ``--exclude`` patterns left out every
                file the tool found, or the tool did not read a file it found in a
                covered language.
        """
        paths = _read_paths_output(final_args)
        if paths is not None:
            scanned = paths.get("scanned")
            skipped = paths.get("skipped")
            scanned = scanned if isinstance(scanned, list) else []
            skipped = skipped if isinstance(skipped, list) else []
            if scanned:
                self.targets_attempted = len(scanned)
            else:
                excluded = [
                    entry
                    for entry in skipped
                    if isinstance(entry, dict)
                    and entry.get("reason") == "cli_exclude_flags_match"
                ]
                # Files left out for the global ignore paths, the ASH output
                # directories or the tools' own default ignore list were left out
                # on purpose, so a scan that found only those had nothing to scan.
                # A target whose files all sit under tests/ or vendor/, say, was
                # SKIPPED by the tools' defaults before ASH re-passed that list as
                # --exclude, and is SKIPPED still.
                not_ignored = [
                    entry
                    for entry in excluded
                    if not self._left_out_by_ash(str(entry.get("path", "")))
                ]
                if not_ignored:
                    raise ScannerError(
                        f"{self.command} scanned no file below "
                        f"{Path(target).as_posix()}: its --exclude patterns left out "
                        f"all {len(excluded)} files it found, so its result says "
                        "nothing about them."
                    )
                unread = [
                    entry
                    for entry in skipped
                    if isinstance(entry, dict)
                    and str(entry.get("reason")) in UNREAD_SKIP_REASONS
                ]
                if unread:
                    unread_reasons = sorted(
                        {str(entry.get("reason")) for entry in unread}
                    )
                    raise ScannerError(
                        f"{self.command} scanned no file below "
                        f"{Path(target).as_posix()}: it found {len(unread)} file(s) in "
                        "a language its rules cover and did not read them "
                        f"(skipped: {', '.join(unread_reasons)}), so its result says "
                        "nothing about them."
                    )
                self.targets_attempted = 0
                if excluded:
                    self._plugin_log(
                        f"{self.command} scanned no file below "
                        f"{Path(target).as_posix()}: every file it found is in "
                        "global_settings.ignore_paths, in an ASH output directory, "
                        "or on the tool's own default ignore list.",
                        level=logging.INFO,
                    )
                    return super()._post_process_sarif(sarif_report, final_args, target)
                reasons = sorted(
                    {
                        str(entry.get("reason"))
                        for entry in skipped
                        if isinstance(entry, dict) and entry.get("reason")
                    }
                )
                self._plugin_log(
                    f"{self.command} scanned no file below "
                    f"{Path(target).as_posix()}: none is in a language its rules "
                    "cover"
                    + (f" (skipped: {', '.join(reasons)})" if reasons else "")
                    + ".",
                    level=logging.INFO,
                )
        return super()._post_process_sarif(sarif_report, final_args, target)


#: The ``--config`` spellings that name the tools' rule registry rather than a path:
#: ``auto``, and the ``p/<ruleset>`` and ``r/<rule-id>`` registry entries. A file or
#: directory in the working directory that happens to carry such a name is not read
#: as the operator's local rules; a local path is spelled so it cannot be confused
#: with a registry entry (``./p/ci``, an absolute path, a ``.yaml`` or ``.yml`` file).
_REGISTRY_PREFIXES = ("p/", "r/")


def _is_registry_name(configured: str) -> bool:
    """Whether ``configured`` is a registry entry name (``auto``, ``p/...``, ``r/...``)."""
    return configured == "auto" or configured.startswith(_REGISTRY_PREFIXES)


#: The flag the scanned-paths JSON is written with (semgrep and opengrep alike).
_PATHS_OUTPUT_FLAG = "--json-output"

#: The largest scanned-paths JSON read.
_PATHS_OUTPUT_READ_LIMIT = 64 * 1024 * 1024


def _read_paths_output(final_args: List[str]) -> Optional[dict]:
    """The ``paths`` object of the ``--json-output`` file named in ``final_args``.

    None when no such flag was passed, or the file is missing, not a regular file,
    larger than _PATHS_OUTPUT_READ_LIMIT, or not the JSON the tools write. Opened
    without following a link at its name.
    """
    import json
    import stat

    prefix = f"{_PATHS_OUTPUT_FLAG}="
    named = [arg[len(prefix) :] for arg in final_args if str(arg).startswith(prefix)]
    if not named:
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(named[-1], flags)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as handle:
            status = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(status.st_mode)
                or status.st_size > _PATHS_OUTPUT_READ_LIMIT
            ):
                return None
            data = json.loads(handle.read().decode("utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    paths = data.get("paths") if isinstance(data, dict) else None
    return paths if isinstance(paths, dict) else None
