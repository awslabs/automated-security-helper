"""Shared base for semgrep- and opengrep-style scanners.

`semgrep` and `opengrep` ship near-identical CLIs (`--config`, `--sarif`,
`--exclude`, `--severity`, `--no-rewrite-rule-ids`, …) and identical
offline-cache strategies. This module factors that out so each concrete
scanner becomes a thin shell that customises three things:

- the binary command (`tool_command`)
- the default ruleset (`default_rulesets`)
- the cache-dir env var (`cache_dir_env_var`)

Subclasses still own their own dependency-resolution path
(`validate_plugin_dependencies`) and any non-shared options (opengrep's
version-gated `--metrics`, and its refusal of the removed patterns mode).
Everything else lives here.
"""

from __future__ import annotations

import fnmatch
import logging
import os
from pathlib import Path
from dataclasses import dataclass
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
from automated_security_helper.config.path_trust import honored_path, resolved_path
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
#:
#: Two kinds, told apart by what the tool's report proves about the file's
#: language. A parse failure proves the tool chose a language for the file (a
#: parser ran), so the file was one the rules cover (UNPARSED_SKIP_REASONS). A
#: size or permission skip proves nothing about the language: semgrep 1.180.0
#: reports a 2 MB .csv and a 2 MB .svg, which no rule covers, as
#: ``exceeded_size_limit`` (measured on a Lambda MicroVM, aarch64, with
#: --x-ignore-semgrepignore-files; opengrep 1.30.2 lists such files nowhere, and
#: neither tool lists a small README.md), so the size test runs before, or without,
#: the language choice. Such a file is still refused when nothing was scanned,
#: because the result says nothing about it either way, but the refusal says that
#: whether a rule covers the file cannot be told, and names the remedies.
UNPARSED_SKIP_REASONS: frozenset[str] = frozenset(
    {"analysis_failed_parser_or_internal_error"}
)
UNREAD_SKIP_REASONS: frozenset[str] = frozenset(
    {"exceeded_size_limit", "too_big", "insufficient_permissions"}
)

#: Every reason semgrep 1.180.0 can write (its ``SkipReason`` enum, 17 members,
#: measured from the installed package; three are capitalized there, so the
#: comparison is on the lowercased spelling). A reason outside this list, when
#: nothing was scanned, is one this version of ASH cannot grade: it may mean the
#: file was never a candidate (SKIPPED) or that a covered file went unread (an
#: error), so the scan is refused naming the reason, never graded SKIPPED on a
#: guess. opengrep 1.30.2 wrote three of these in the same measurement
#: (cli_exclude_flags_match, exceeded_size_limit, insufficient_permissions) and
#: ships no readable list of its own.
KNOWN_SKIP_REASONS: frozenset[str] = frozenset(
    {
        "always_skipped",
        "semgrepignore_patterns_match",
        "cli_include_flags_do_not_match",
        "cli_exclude_flags_match",
        "exceeded_size_limit",
        "analysis_failed_parser_or_internal_error",
        "excluded_by_config",
        "wrong_language",
        "too_big",
        "minified",
        "binary",
        "irrelevant_rule",
        "too_many_matches",
        "gitignore_patterns_match",
        "dotfile",
        "nonexistent_file",
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


@dataclass(frozen=True)
class _ConfiguredRules:
    """What ``options.config`` resolved to (``GrepScannerBase._resolve_configured_rules``).

    ``kind`` is one of ``unset``, ``as_written``, ``local``, ``refused``, ``missing``;
    ``value`` is the string handed to the tool for ``as_written`` and ``local`` (the
    resolved absolute path for ``local``) and the configured text otherwise;
    ``detail`` says why for ``refused`` and ``missing`` and is None otherwise.
    """

    kind: str
    value: Optional[str]
    detail: Optional[str]


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
    # The offline rule cache the command reads as --config, absolute, or None when
    # the offline scan reads no cache (the operator's local rules, no cache found,
    # or an online scan). content_databases_in_use and the
    # staleness probe read it, so a scan that read other rules is not graded on
    # the cache's age.
    _cache_dir_in_use: Optional[str] = PrivateAttr(default=None)
    # What options.config resolved to, judged ONCE per _process_config_options
    # (_resolve_configured_rules); the offline and online branches and the refusal
    # read this instead of resolving again, so path trust runs and warns once.
    _configured_rules: Optional[_ConfiguredRules] = PrivateAttr(default=None)

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
        """The offline ruleset, and only when the offline scan read the cache.

        Online, the rules come from the registry at scan time and no local copy is read,
        so there is nothing whose age could make the result stale. Offline, the
        operator's local rules read no cache either (``_cache_dir_in_use`` stays
        None), and neither does a scan that found no cache.
        """
        if not self._scanner_offline() or self._cache_dir_in_use is None:
            return []
        return super().content_databases_in_use()

    def content_database_probe_context(self):
        """The rules cache directory the offline scan passed as ``--config``, absolute."""
        context = super().content_database_probe_context()
        cache_dir = self._cache_dir_in_use or os.environ.get(
            self.cache_dir_env_var(), ""
        )
        context.cache_dir = os.path.abspath(cache_dir) if cache_dir else None
        return context

    # ---------------------------------------------------------------
    # Shared arg-building (was duplicated in each scanner).
    # ---------------------------------------------------------------

    def _process_config_options(self):
        opts = self.config.options  # type: ignore[union-attr]

        # Drop any --metrics already pushed into extra_args (some scanners
        # re-call this and we want a clean state).
        self.args.extra_args = [a for a in self.args.extra_args if a.key != "--metrics"]
        self._cache_dir_in_use = None
        self._configured_rules = self._resolve_configured_rules()

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
        # scanners. The patterns and rule ids travel in the joined form
        # (``--exclude=<pattern>``), as the ignore names do (_execute_scan): in
        # the split form a value starting with "-" is read by the tools as an
        # option, and a blank value is dropped by _resolve_arguments after its
        # flag was appended, so the flag took the next argument as its value.
        # A blank value is left out here instead (_configured_values).
        for pattern in self._configured_values(opts, "exclude"):
            self.args.extra_args.append(
                ToolExtraArg(key=f"--exclude={pattern}", value=None)
            )
        for rule_id in self._configured_values(opts, "exclude_rule"):
            self.args.extra_args.append(
                ToolExtraArg(key=f"--exclude-rule={rule_id}", value=None)
            )
        for severity in getattr(opts, "severity", []) or []:
            self.args.extra_args.append(ToolExtraArg(key="--severity", value=severity))

        # SARIF output mode.
        self.args.extra_args.append(ToolExtraArg(key="--sarif", value=""))

        return super()._process_config_options()

    def _configured_values(self, opts: Any, name: str) -> List[str]:
        """The entries of the list option ``name`` that name something, in order.

        A blank entry (empty, or whitespace only) is left out with a warning
        naming the option: ``_resolve_arguments`` drops a blank value only after
        the flag before it was appended, so the flag would take the next argument
        of the command as its value.
        """
        values: List[str] = []
        for value in getattr(opts, name, []) or []:
            text = str(value)
            if not text.strip():
                self._plugin_log(
                    f"Ignoring a blank entry of {self._option_key(name)}: it names "
                    "nothing, and its flag would take the next argument as its value.",
                    level=logging.WARNING,
                )
                continue
            values.append(text)
        return values

    def _note_unhonored_semgrepignore(self) -> None:
        """Say in the results that a ``.semgrepignore`` the tool would have read was not.

        Looked for where either tool would read one (``_semgrepignore_files``):
        the source directory and each directory above it up to the repository
        root (the first one holding ``.git``), or the source directory alone when
        no repository holds it. Only its presence is checked; the file is not
        read. The note is a config warning, which the orchestrator records in the
        results as a ``config_warning`` validation checkpoint, once per file, and
        it is logged whether or not the context's config keeps such a list. A
        file an MCP client delivered (``cli/mcp/sandbox.config_is_client_supplied``,
        judged by its path, each symlink on the way and the file it resolves to)
        is named as client-supplied. A disabled scanner runs neither tool, so
        there is nothing it leaves unhonored and it records no note.
        """
        # Imported here, as config/path_trust.py does: importing cli.mcp runs its
        # __init__, which imports the config modules.
        from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

        if not getattr(self.config, "enabled", True):
            return
        source = getattr(self.context, "source_dir", None)
        if source is None:
            return
        found = _semgrepignore_files(Path(os.path.abspath(source)))
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
            if isinstance(warnings, list):
                if message in warnings:
                    continue
                warnings.append(message)
            self._plugin_log(message, level=logging.WARNING)

    def _resolve_configured_rules(self) -> "_ConfiguredRules":
        """Judge ``options.config`` once: what it is and, when ASH cannot pass it,
        why.

        Kinds: ``unset`` (empty); ``as_written`` (a URL, a registry entry name or
        one of the tool's own spellings, handed to the tool untouched,
        ``_passes_through_as_written``); ``local`` (a rule file or directory ASH may
        hand the tool, as the resolved absolute path); ``refused`` (path trust said
        no: the one rule every tool path option follows,
        ``config/path_trust.honored_path``, under which a relative value is taken
        from the source directory, the tool's working directory, and a path inside
        the scanned tree, one a repository's config names inside a git checkout, or
        one an MCP client delivered is refused with a warning, so the scanned
        repository cannot choose the rules it is scanned with); ``missing`` (passable,
        but nothing is there). One resolver for both modes: online and offline hand
        the tool the same file for the same configuration, and the refusal names the
        same cause in both.
        """
        configured = getattr(self.config.options, "config", None)  # type: ignore[union-attr]
        if not configured or not isinstance(configured, str):
            return _ConfiguredRules("unset", None, None)
        if self._passes_through_as_written(configured):
            return _ConfiguredRules("as_written", configured, None)
        source_dir = getattr(self.context, "source_dir", None)
        if source_dir is None:
            return _ConfiguredRules(
                "missing", configured, "no source directory to resolve it against"
            )
        resolved = resolved_path(configured, source_dir)
        candidate = honored_path(
            configured,
            source_dir=source_dir,
            key=self._config_option_key(),
            config=getattr(self.context, "config", None),
        )
        if candidate is None:
            return _ConfiguredRules(
                "refused",
                configured,
                f"path trust refused {resolved.as_posix()}: it sits inside the "
                "scanned tree, or a repository's config named it inside a git "
                "checkout, or an MCP client delivered it (the warning above names "
                "which)",
            )
        if candidate.is_file() or candidate.is_dir():
            return _ConfiguredRules("local", candidate.as_posix(), None)
        return _ConfiguredRules(
            "missing",
            configured,
            f"it resolved to {candidate.as_posix()}, which does not exist",
        )

    def _configured(self) -> "_ConfiguredRules":
        """The resolution of ``options.config`` for this build, judged once."""
        if self._configured_rules is None:
            self._configured_rules = self._resolve_configured_rules()
        return self._configured_rules

    def _local_rules_configured(self) -> Optional[str]:
        """The ``options.config`` rule file or directory ASH may hand the tool, as
        the resolved absolute path, or None (see ``_resolve_configured_rules``)."""
        rules = self._configured()
        return rules.value if rules.kind == "local" else None

    def _option_key(self, option: str) -> str:
        """The dotted key of ``options.<option>`` in the ASH config, as a warning
        names it (``scanners.semgrep.options.exclude``)."""
        name = getattr(self.config, "name", None) or "grep"
        return f"scanners.{name}.options.{option}"

    def _config_option_key(self) -> str:
        """The dotted key of ``options.config`` in the ASH config, as the path-trust
        warning names it (``scanners.semgrep.options.config``)."""
        return self._option_key("config")

    def _configured_registry_entry(self) -> Optional[str]:
        """``options.config`` when it is passed to the tool as written (a registry
        entry, a URL, or one of the tool's own spellings), else None."""
        rules = self._configured()
        return rules.value if rules.kind == "as_written" else None

    def _passes_through_as_written(self, configured: str) -> bool:
        """Whether a configured value is one the tool reads itself, not a path ASH
        resolves: a URL, a registry entry name (``_is_registry_name``), or a bare
        token the tool knows (``_is_tool_spelling``: semgrep's ``policy``,
        ``supply-chain`` and ``secrets`` products, or a bare ruleset name) that
        names no file or directory in the source tree. A bare token that does name
        one there is ambiguous, is read as the path, and goes through path trust
        like any other (the source directory is the tool's working directory, where
        the tool could read the name as that path)."""
        if "://" in configured or _is_registry_name(configured):
            return True
        source_dir = getattr(self.context, "source_dir", None)
        return _is_tool_spelling(configured, source_dir)

    def _configure_offline_mode(self) -> None:
        """Set --metrics off (when supported), then the rules: the operator's local
        rule file or directory when ``options.config`` names one, else the
        validated cache directory as ``--config``."""
        if self.emit_metrics_flag():
            self.args.extra_args.append(
                ToolExtraArg(key="--metrics", value=self.metrics_value_offline())
            )

        if self._refuse_unpassable_configured_rules():
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
            # RECORDED, NOT RAISED, and the difference is which row the scan
            # phase writes.
            #
            # This runs inside `_process_config_options`, whose only caller is
            # `ScannerPluginBase.model_post_init` -- a constructor. A constructor
            # that raises is caught by `ScanPhase`'s scanner-creation loop, which
            # records the scanner as ERROR ("could not be constructed") when it
            # was selected to run, and SKIPPED when it was not; before that loop
            # recorded anything, such a scanner was absent from `scanner_results`
            # and from every completeness counter. An ERROR row says the scanner
            # was reached and produced no result, and carries no remedy. Recorded
            # here instead, the instance exists to be asked
            # `validate_plugin_dependencies()`, which reads this reason and records
            # the scanner MISSING with the remedy below, the row that tells an
            # operator how to fix a real misconfiguration: the remediation text
            # travels with the answer rather than being reconstructed by the
            # reader.
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

        # Absolute: the directory was validated against ASH's working directory,
        # and the tool runs in the source directory, so a relative value would
        # name a different directory there (one inside the scanned tree, when
        # the name exists in both).
        cache_abs = os.path.abspath(cache_dir)
        if not self._cache_dir_is_passable(cache_abs, cache_env):
            # Recorded, not raised, as the missing-cache reason above is: the
            # scanner exists and declines, and the MISSING row says why.
            self.dependency_unavailable_reason = (
                f"{scanner_label} is running in offline mode, but ${cache_env} names "
                "a rule cache inside the scanned tree, or one an MCP client "
                "delivered, which ASH does not hand to the tool: the scanned "
                "repository must not choose the rules it is scanned with. Point "
                f"${cache_env} at a directory outside the scanned tree."
            )
            ASH_LOGGER.warning(self.dependency_unavailable_reason)
            return

        ASH_LOGGER.info(
            f"{scanner_label} offline mode: using cached rules from {cache_dir}"
        )
        self._cache_dir_in_use = cache_abs
        self.args.extra_args.append(
            ToolExtraArg(key="--config", value=self._cache_dir_in_use)
        )

    def _refuse_unpassable_configured_rules(self) -> bool:
        """Decline the scanner when ``options.config`` names rules ASH cannot hand
        the tool, and say so; True when it declined.

        A configured value that is neither a registry entry nor a URL is meant as a
        rule file or directory. When it resolves to nothing ASH may pass (a path that
        does not exist, a typo, or a file inside the scanned tree or a git checkout,
        which ``_local_rules_configured`` refuses), the scan is not run under other
        rules in its place: the operator asked for those rules, and a scan under the
        default rulesets or the offline cache would be a different scan reported as
        the one that was asked for. The reason is RECORDED, not raised, the way the
        missing offline cache is (see ``_configure_offline_mode``): the scanner then
        exists and reports itself declined, where a raise would drop it from the
        results with nothing in its place. Both modes call this before they choose
        their rules, so a bad value fails the same way online and offline.
        """
        rules = self._configured()
        if rules.kind not in ("refused", "missing"):
            return False
        self.dependency_unavailable_reason = (
            f"{self._config_option_key()} names rules ASH cannot pass to the tool: "
            f"{rules.detail}. The scan does not run under other rules in its place. "
            "Name a rules file or directory outside the scanned tree from an operator "
            "source (--config-overrides, or a config file outside every git checkout "
            "and the scanned directory, given with --config or ASH_CONFIG; a rules "
            "repository checked out elsewhere is admitted from such a source), a "
            "registry ruleset (auto, p/<ruleset>, r/<rule>, s/<snippet>), one of the "
            "tool's own config spellings, or a URL."
        )
        ASH_LOGGER.warning(self.dependency_unavailable_reason)
        return True

    def _cache_dir_is_passable(self, cache_abs: str, cache_env: str) -> bool:
        """Whether the validated rule cache may be handed to the tool.

        The one rule every tool path follows (``config/path_trust.honored_path``):
        a directory inside the scanned tree, or one an MCP client delivered, is
        refused with a warning, so the scanned repository cannot choose the rules
        it is scanned with by being the place ``$<cache env>`` points at. Judged on
        the absolute path the validator accepted, which is the directory the tool
        reads; the environment named it, so it is the operator's own. With no
        source directory to judge against, the directory is passed as before.
        """
        source_dir = getattr(self.context, "source_dir", None)
        if source_dir is None:
            return True
        return (
            honored_path(
                cache_abs,
                source_dir=source_dir,
                key=cache_env,
                config=getattr(self.context, "config", None),
                operator_written=True,
                env_named=True,
            )
            is not None
        )

    def _configure_online_mode(self) -> None:
        opts = self.config.options  # type: ignore[union-attr]
        # The configured rules: a registry entry or URL as written; a local rule
        # file or directory through the same resolver offline uses
        # (_local_rules_configured), so the two modes hand the tool one file and a
        # path the scanned repository chose is refused in both. A configured value
        # that names nothing ASH may pass declines the scanner
        # (_refuse_unpassable_configured_rules); the default rulesets run only
        # when nothing was configured.
        if self._refuse_unpassable_configured_rules():
            return
        configured = getattr(opts, "config", None)
        registry = self._configured_registry_entry()
        local_rules = self._local_rules_configured() if configured else None
        if registry is not None:
            self.args.extra_args.append(ToolExtraArg(key="--config", value=registry))
        elif local_rules is not None:
            self.args.extra_args.append(ToolExtraArg(key="--config", value=local_rules))
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

        Subclasses may override for bespoke result-file locations.
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

        # Read by _resolve_scan_arguments and _extra_args_for_target.
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

    def _extra_args_for_target(self, target: Path) -> List[ToolExtraArg]:
        """The configured extra arguments, as the current target's command takes them.

        The converted target drops ``CONVERTED_FILE_EXCLUDE``: there the pattern
        names every file the converter wrote, which is every file the target holds,
        so the tools found files and excluded them all, and the scanned-nothing
        refusal below (_post_process_sarif) made a repository of notebooks a
        scanner error. The pattern is dropped by its value, whoever wrote it: the
        documented default lists it, so a configuration ``ash config init`` wrote,
        or one copied from the reference, carries it as an operator value, and a
        drop keyed on provenance would scan nothing on every such configuration.

        The converted target also drops each re-passed default ignore
        (``SEMGREP_DEFAULT_IGNORES``, the split-form ``--exclude`` values ASH
        itself appends) that names one of the target's own directories below the
        project root (``_parts_of_target_below_root``): the tools anchor
        ``build/`` at the repository root, so an output directory under ``build``
        (``--output-dir build/ash``, say) put every converted file under a default
        ignore, the tools excluded them all, and ``_left_out_by_ash`` graded the
        target SKIPPED with no notebook scanned. Where ASH placed its own output
        is not a reason to leave the converted files out. The source target keeps
        every default: there the tools' own coverage is what ASH re-passes.

        Every other exclude pattern the operator wrote stays as written, on this
        target too; one that happens to match every converted file is the
        operator's choice, and the scanned-nothing refusal names it. The two drops
        tell ASH's values from the operator's by FORM: the operator's patterns
        travel in the joined form (``--exclude=<pattern>``, one key, no value;
        _process_config_options), ASH's re-passed defaults in the split form (key
        ``--exclude``, the pattern as the value), so a drop keyed on the split form
        reaches only what ASH itself appended, and an operator's ``build/`` stays.
        """
        if self._scan_target_type != "converted":
            return list(self.args.extra_args)
        dropped = f"--exclude={CONVERTED_FILE_EXCLUDE}"
        below_root = _parts_of_target_below_root(target)
        covering = {
            pattern
            for pattern in SEMGREP_DEFAULT_IGNORES
            if pattern.endswith("/") and pattern[:-1] in below_root
        }
        return [
            arg
            for arg in self.args.extra_args
            if arg.key != dropped
            and not (arg.key == "--exclude" and arg.value in covering)
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
        self.args.extra_args = self._extra_args_for_target(target)
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
        anchor = _pattern_anchor(target_abs)
        return [
            "/"
            + escape_for_pattern(
                target_abs.joinpath(relative).relative_to(anchor).as_posix(),
                PatternSyntax.GLOB,
                separator="/",
            )
            for relative in relatives
        ]

    def _left_out_by_ash(self, path: str, target: Path) -> bool:
        """Whether ``path``, which the tool excluded, matches one of the exclusions
        ASH itself adds to every command rather than one the operator configured.

        Three sets, each what the tool would have skipped on its own or what ASH
        skips for every scanner: the names given for the global ignore paths
        (``_ignore_exclude_names``), the ASH output directories inside the target
        (``_output_dir_excluded``), and the tools' own default ignore list, which
        ASH re-passes as ``--exclude`` because ``--x-ignore-semgrepignore-files``
        drops it (``SEMGREP_DEFAULT_IGNORES``). Matched on the path's components
        below the project root the tools anchor their patterns at
        (``_pattern_anchor``: the nearest ``.git`` at or above the target, else the
        target itself), as the tools match a directory pattern, and on the file
        name for a file glob. That is the target's own components below the root
        plus the reported path's below the target: a target that is itself the
        repository's ``tests/`` or ``vendor/`` directory is excluded whole by the
        tools' defaults, whether the tool reports its files relative to the target
        or to the root. The directories above the root never count: a checkout
        under ``/opt/atlassian/pipelines/agent/build`` or ``/home/travis/build``
        would otherwise read every excluded file as one the tools' defaults left
        out.
        """
        parts = (*_parts_of_target_below_root(target), *_parts_below(path, target))
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
        with no findings; when the operator configured no exclude, the pattern is
        one ASH does not recognize as its own, and the refusal says so. The same
        when the tool found a file in a covered language and could not parse it
        (``UNPARSED_SKIP_REASONS``), when it did not read a file for its size or
        permissions (``UNREAD_SKIP_REASONS``; the tool reports those before it
        chooses a language, so whether a rule covers the file cannot be told, and
        the refusal says that and names the remedies), and when it skipped a file
        for a reason this version of ASH does not know (``KNOWN_SKIP_REASONS``). None
        scanned otherwise means nothing below the target is in a language the rules
        cover, or every such file is one the tool's own defaults or ASH's exclusions
        leave out, which the executor grades SKIPPED (``targets_attempted`` 0). An
        absent or unreadable paths file leaves the count unset (no claim).

        Raises:
            ScannerError: When ``--exclude`` patterns left out every file the tool
                found, when the tool could not parse or did not read a file it
                found, or when it skipped a file for an unknown reason.
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
                # Lowercased, as every reason below is read: a capitalized spelling
                # of this one would otherwise skip the exclude refusal and lowercase
                # into the known list.
                excluded = [
                    entry
                    for entry in skipped
                    if isinstance(entry, dict)
                    and str(entry.get("reason")).lower() == "cli_exclude_flags_match"
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
                    if not self._left_out_by_ash(str(entry.get("path", "")), target)
                ]
                if not_ignored:
                    where = f"{self.command} scanned no file below {Path(target).as_posix()}"
                    if self._configured_values(
                        getattr(self.config, "options", None), "exclude"
                    ):
                        raise ScannerError(
                            f"{where}: its --exclude patterns left out all "
                            f"{len(excluded)} files it found, so its result says "
                            "nothing about them."
                        )
                    # No operator pattern on the command, so the match is against an
                    # exclusion ASH added and does not recognize as its own here.
                    shown = ", ".join(
                        str(entry.get("path", "")) for entry in not_ignored[:3]
                    )
                    raise ScannerError(
                        f"{where}: an --exclude pattern ASH does not recognize as its "
                        f"own left out all {len(excluded)} files it found ({shown}"
                        f"{', ...' if len(not_ignored) > 3 else ''}), so its result "
                        "says nothing about them."
                    )
                # Grouped by the LOWERCASED reason, once, so every test below
                # reads the same spelling: three of the tool's own spellings are
                # capitalized, and a capitalized unread spelling compared as
                # written would miss the unread test and then lowercase into the
                # known list, the one route by which an unknown spelling could
                # grade SKIPPED.
                by_reason: dict = {}
                for entry in skipped:
                    if isinstance(entry, dict):
                        by_reason.setdefault(
                            str(entry.get("reason")).lower(), []
                        ).append(entry)
                where = (
                    f"{self.command} scanned no file below {Path(target).as_posix()}"
                )
                unparsed = [r for r in by_reason if r in UNPARSED_SKIP_REASONS]
                if unparsed:
                    count = sum(len(by_reason[r]) for r in unparsed)
                    raise ScannerError(
                        f"{where}: it found {count} file(s) in a language its rules "
                        "cover and could not parse them "
                        f"(skipped: {', '.join(sorted(unparsed))}), so its result "
                        "says nothing about them."
                    )
                unread = [r for r in by_reason if r in UNREAD_SKIP_REASONS]
                if unread:
                    count = sum(len(by_reason[r]) for r in unread)
                    raise ScannerError(
                        f"{where}: it did not read {count} file(s) it found "
                        f"(skipped: {', '.join(sorted(unread))}). The tool reports a "
                        "size or permission skip before it chooses a language, so "
                        "whether a rule covers them cannot be told, and its result "
                        "says nothing about them. Raise the tool's size limit "
                        "(--max-target-bytes) or fix the permissions, or exclude the "
                        "files on purpose."
                    )
                unknown = sorted(
                    r for r in by_reason if r not in KNOWN_SKIP_REASONS and r != "none"
                )
                if unknown:
                    count = sum(len(by_reason[r]) for r in unknown)
                    raise ScannerError(
                        f"{where}: it skipped {count} file(s) for a reason this "
                        f"version of ASH does not know ({', '.join(unknown)}), so "
                        "whether a rule covers them cannot be told, and its result "
                        "says nothing about them."
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
                        str(entry.get("reason")).lower()
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
_REGISTRY_PREFIXES = ("p/", "r/", "s/")


def _is_registry_name(configured: str) -> bool:
    """Whether ``configured`` is a registry entry name (``auto``, ``p/...``, ``r/...``,
    ``s/...``)."""
    return configured == "auto" or configured.startswith(_REGISTRY_PREFIXES)


#: Suffixes that make a bare token a rule FILE name rather than a tool spelling.
_RULE_FILE_SUFFIXES = (".yaml", ".yml")


def _is_tool_spelling(configured: str, source_dir: Optional[Path]) -> bool:
    """Whether ``configured`` is a bare token the tool reads itself, not a path.

    semgrep's ``--config`` takes, beside paths and URLs and the registry entries
    ``_is_registry_name`` knows, product names such as ``policy``, ``supply-chain``
    and ``secrets``, and the set grows with the tool. ASH keeps no list: a token
    with no path separator and no rule-file suffix is read as the tool's own
    spelling and passed through, as the base passed every value, UNLESS a file or
    directory of that name exists in the source tree. Then the value is AMBIGUOUS:
    which of the two the tool, run in the source directory, resolves first is not
    established from the tool's own source, and the two readings differ in what
    runs (the product's rules, or a directory the repository ships), so the token
    is read as the path and goes through path trust, which declines an in-tree one.
    That holds for the reserved product names as for any other token: a
    ``policy/`` directory in the tree beside ``config: policy`` is declined, and
    the operator names the rules unambiguously (``p/...``, an absolute path, or
    a directory outside the tree). A repository therefore cannot smuggle its own
    rules in under a bare name.
    """
    if not configured or "/" in configured or "\\" in configured:
        return False
    if configured.lower().endswith(_RULE_FILE_SUFFIXES):
        return False
    if source_dir is not None and Path(source_dir).joinpath(configured).exists():
        return False
    return True


def _pattern_anchor(target_abs: Path) -> Path:
    """The project root the tools anchor their patterns at: the nearest directory
    at or above ``target_abs`` holding ``.git``, else the target itself."""
    return next(
        (
            candidate
            for candidate in (target_abs, *target_abs.parents)
            if candidate.joinpath(".git").exists()
        ),
        target_abs,
    )


def _parts_of_target_below_root(target: Path) -> tuple[str, ...]:
    """The target's own path components below the project root the tools anchor
    their patterns at (``_pattern_anchor``); none when the target is that root."""
    target_abs = Path(os.path.abspath(target))
    try:
        return target_abs.relative_to(_pattern_anchor(target_abs)).parts
    except ValueError:
        return ()


def _semgrepignore_files(directory: Path, exists=os.path.lexists) -> List[Path]:
    """The ``.semgrepignore`` files either tool would read for a scan of ``directory``.

    semgrep reads one in its project root, the git work tree holding the scan
    root, and ASH runs opengrep in the source directory; so the walk goes from
    ``directory`` up to the first directory holding ``.git`` and names each file
    on the way. Outside a repository there is no root to walk to and the tools
    read the one in the scanned directory alone, so only that one is named: the
    walk used to continue to the filesystem root and name a ``.semgrepignore`` in
    the home directory, say, as one in the scanned tree that was not honored.
    ``exists`` is the presence test, ``os.path.lexists`` (the file is not read).
    """
    found: List[Path] = []
    for candidate in (directory, *directory.parents):
        ignore_file = candidate / ".semgrepignore"
        if exists(ignore_file):
            found.append(ignore_file)
        if exists(candidate / ".git"):
            return found
    return [ignore_file for ignore_file in found if ignore_file.parent == directory]


def _parts_below(path: str, target: Path) -> tuple[str, ...]:
    """The components of a path the tool reported, below the target or the project
    root; the directories above them never count.

    The tools report a path as given or relative to their project root, so a
    relative path is taken as it is. An absolute one is made relative to the target,
    else to the project root (``_pattern_anchor``); one under neither keeps only its
    file name, so no directory above the scan can match a directory pattern. The
    target's own components below the project root (``tests/``, ``build/`` or
    ``vendor/`` in a git work tree, which the tools' default ignores match) are not
    this function's to add: ``_left_out_by_ash`` prefixes them once, from
    ``_parts_of_target_below_root``, so the target is tried first here and an
    absolute path under it contributes only what lies below the target.
    """
    reported = Path(path)
    if not reported.is_absolute():
        return reported.parts
    target_abs = Path(os.path.abspath(target))
    for root in (target_abs, _pattern_anchor(target_abs)):
        try:
            return reported.relative_to(root).parts
        except ValueError:
            continue
    return (reported.name,)


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
