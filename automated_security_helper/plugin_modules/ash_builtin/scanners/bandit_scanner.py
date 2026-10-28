"""Module containing the Bandit security scanner implementation."""

import fnmatch
import glob
import logging
import os
from pathlib import Path
from typing import Annotated, Any, ClassVar, List, Literal, Optional, Sequence, Tuple

from pydantic import Field, PrivateAttr
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.base.options import (
    ScannerOptionsBase,
    tool_version_constraint,
)
from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.config.tool_config_trust import empty_tool_config
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolExtraArg,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginConfigBase,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    SarifReport,
)
from automated_security_helper.utils.link_exclusions import walked_files
from automated_security_helper.utils.error_text import text_without_values
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.scanned_tree import REASON_LINK_LEAVES_TREE
from automated_security_helper.utils.scan_output_dirs import (
    PatternSyntax,
    escape_for_pattern,
)
from automated_security_helper.utils.sarif_utils import mask_secrets_in_sarif
from automated_security_helper.utils.suppression_matcher import active_ignore_paths
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command


_GLOB_CHARACTERS = set("*?[]")

#: What an ``--exclude`` entry cannot hold: bandit splits the value on commas and
#: reads ``* ? [`` as fnmatch syntax, and a line break fails ASH's flag-key check.
_BANDIT_EXCLUDE_UNSAFE = frozenset(",*?[\n\r")

#: The longest ``--exclude=...`` argument passed. Linux refuses one argument longer
#: than 128 KiB (MAX_ARG_STRLEN) with E2BIG.
_EXCLUDE_ARGUMENT_LIMIT = 120 * 1024


def _paths_holding_glob_characters(target: Path) -> List[str]:
    """The file paths under ``target`` with ``*?[]`` below it, as bandit spells them.

    bandit walks ``os.walk(<target as given>)`` and joins each file with
    ``os.path.join(root, name)``. Every --exclude entry ASH emits holds ``*`` or
    ``?`` after the target, so only a path with such a character below the
    target can hold an entry as text.
    """
    top = str(target)
    found = []
    for root, _dirs, files in os.walk(top):
        below = root[len(top) :]
        for name in files:
            if _GLOB_CHARACTERS & set(below + name):
                found.append(os.path.join(root, name))
    return found


def _entries_no_path_holds_as_text(
    target: Path,
    ignore_entries: List[str],
    output_entries: List[Tuple[str, Path]],
    holding: Optional[List[str]] = None,
) -> List[str]:
    """The entries, less any that a file path under ``target`` holds as text.

    bandit skips a file whose path contains an --exclude entry as a plain
    substring, as well as one the entry matches as a glob (bandit 1.9.4,
    ``manager._is_file_included``). Measured: ignore path ``docs/*.md`` gave
    ``<src>/docs/*.md``, and bandit skipped ``<src>/docs/*.md/evil.py``, in a
    directory literally named ``*.md``, which the ignore path does not cover.
    Such an entry is left out, and the SARIF step still applies the ignore
    path. ``output_entries`` pairs each of ASH's output directories inside
    ``target`` (relative to it) with its entry; an entry is kept for paths
    inside its own directory, which it is meant to skip.

    bandit also rewrites an entry that names an existing directory to
    ``<entry>/*`` (``manager.discover_files``), which covers the files of every
    directory the glob matches. Measured: with an empty directory, or a
    directory symlink, literally named ``docs/*.md`` (or ``*.md`` linked to
    ``.``, or ``lib/?``), bandit skipped an ``evil.py`` the ignore path does not
    cover. An entry that names an existing directory is left out too, unless it
    already ends in ``/*``, for which the rewrite only narrows it.

    ``holding`` is ``_paths_holding_glob_characters(target)``, when the caller
    has walked it already, so a caller that filters two entry sets walks once.
    """
    if holding is None:
        holding = _paths_holding_glob_characters(target)
    kept = [e for e in ignore_entries if not any(e in path for path in holding)]
    dropped = [e for e in ignore_entries if e not in kept]
    for output_entry, output_dir in output_entries:
        inside = os.path.join(str(target), *output_dir.parts) + os.sep
        outside = [path for path in holding if not path.startswith(inside)]
        if any(output_entry in path for path in outside):
            dropped.append(output_entry)
        else:
            kept.append(output_entry)
    named_directories = [e for e in kept if not e.endswith("/*") and os.path.isdir(e)]
    kept = [e for e in kept if e not in named_directories]
    dropped += named_directories
    if dropped:
        ASH_LOGGER.verbose(
            f"Not passing {dropped} to bandit --exclude: a file path under "
            f"'{target}' contains it as text, or it names an existing "
            "directory, and bandit would skip files it does not cover.",
            extra=NO_MARKUP,
        )
    return kept


def _not_a_plain_substring(literal: str) -> str:
    """``literal`` as an ``fnmatch`` glob that matches only itself and holds a
    ``[``, so bandit's substring test cannot fire on an ordinary path.

    bandit skips a file whose path contains an --exclude entry as plain text,
    so a literal ``<anchor>/app.py`` would also skip ``<anchor>/app.py.d/x.py``
    and ``<anchor>/app.pyx.py``. ``<anchor>/app.p[y]`` matches ``<anchor>/app.py``
    as a glob and nothing else, and as text it occurs only in a path that has a
    ``[`` itself, which ``_entries_no_path_holds_as_text`` checks the tree for.
    """
    for index in range(len(literal) - 1, -1, -1):
        if literal[index] not in "/!^-]":
            return f"{literal[:index]}[{literal[index]}]{literal[index + 1 :]}"
    return literal


def bandit_exclude_globs(anchor: str, pattern: str) -> List[str]:
    """bandit ``--exclude`` globs for an ignore path, anchored at ``anchor``.

    Only globs that make bandit skip no file the ignore path does not cover, so
    a glob emitted here may skip fewer files than the ignore path covers, never
    others.
    bandit tests each entry two ways against ``<anchor>/<relative path>``: as an
    ``fnmatch`` glob, where ``*`` crosses ``/``, and as a plain substring. So a
    literal is emitted in a form that is not a plain substring of anything
    (``_not_a_plain_substring``), and a ``**`` shape that has no exact
    ``fnmatch`` form is not emitted. What is not emitted is still scanned, and
    its findings are dropped by the SARIF step, which applies every ignore path;
    a file bandit skipped that the SARIF step would have kept would lose its
    findings instead.

    ASH matches case-sensitively on every platform. bandit's ``fnmatch`` does on
    POSIX, and on Windows it folds both sides to lower case (``os.path.normcase``).
    For a literal, ``*`` and ``?`` that only makes bandit skip, on Windows, another
    spelling of a name the file system already reads as the same file; for a
    character class it can make bandit skip other files (``[A-Z]`` folded is
    ``[a-z]``, which takes ``b.py``), so a pattern with ``[`` or ``]`` is not
    emitted.

    Emitted:

    * a literal (``app.py``, ``src/app.py``), which ASH reads as that path
      only: ``<anchor>/app.p[y]``.
    * ``dir/**`` and ``dir/`` (``dir`` literal, any depth of components):
      ``<anchor>/dir/*``.
    * ``**/dir/**`` and ``**/dir/``: ``<anchor>/dir/*`` and ``<anchor>/*/dir/*``.
    * a pattern without ``**`` that has ``*`` or ``?`` (``src/*.py``):
      ``<anchor>/src/*.py``. ASH matches such a pattern with ``fnmatch`` too.

    Not emitted: a pattern with a ``.`` or empty component, a leading ``./``
    included. ASH's matcher compares a path as it is given and drops no ``./``, so
    ``./app.py`` covers no file of the tree and bandit is told to skip none.
    """
    pattern = pattern.replace("\\", "/")
    if pattern.endswith("/") and pattern.strip("/"):
        pattern = pattern.rstrip("/") + "/**"
    anchor_glob = glob.escape(anchor)
    if not pattern.strip("/") or "," in pattern or "," in anchor:
        return []
    if "[" in pattern or "]" in pattern:
        # ASH compares a character class as written; bandit's fnmatch folds the
        # pattern and the path to lower case on Windows, which turns [A-Z] into
        # [a-z] and makes bandit skip b.py, a file the ignore path does not cover.
        # No character class reaches bandit. (While ASH lower-cased both sides,
        # bandit 1.9.4 skipped src/b.py for src/[!A-Z].py on every platform.)
        return []
    if "**" not in pattern:
        # A leading "/" names nothing to ASH's matcher, which compares the
        # pattern with the path as written; nor do "." or empty components.
        if pattern.startswith("/") or any(
            part in ("", ".", "..") for part in pattern.split("/")
        ):
            return []
        if _GLOB_CHARACTERS & set(pattern):
            return [f"{anchor_glob}/{pattern}"]
        return [f"{anchor_glob}/{_not_a_plain_substring(pattern)}"]
    parts = pattern.split("/")
    leading = parts[0] == "**"
    middle = parts[1:-1] if leading else parts[:-1]
    if (
        parts[-1] != "**"
        or not middle
        or any(
            part in ("", ".", "..", "**") or _GLOB_CHARACTERS & set(part)
            for part in middle
        )
    ):
        return []
    directory = "/".join(middle)
    if leading:
        return [f"{anchor_glob}/{directory}/*", f"{anchor_glob}/*/{directory}/*"]
    return [f"{anchor_glob}/{directory}/*"]


def bandit_excluded_path_globs(anchor: str, path: str) -> List[str]:
    """bandit ``--exclude`` globs for an ``excluded_paths`` entry or a known
    directory (``.venv/``), anchored at ``anchor``.

    Such an entry names a path anywhere below the scanned target, bandit's own
    reading, which ASH applies with nothing after the scan. It was emitted as
    ``**/<path>/**``, which bandit only matches inside a directory called
    ``<path>``: a file entry such as ``app.py`` never skipped its file, and
    ``tests/*`` skipped only files in subdirectories. Unanchored, it also
    matched the target's own path, so a project inside a directory named
    ``venv`` had every file skipped, and ``src/vendor`` under a target named
    ``src`` skipped the top-level ``vendor`` too.

    * A file or directory (``app.py``, ``vendor``) or a glob (``*.pyc``,
      ``tests/*``): the files it matches and the files under the directories
      it matches, at the top of the target or below any directory.
    * ``dir/``, ``dir/**``, ``**/dir/**``: only the files under such
      directories. A leading ``**/`` and a leading ``./`` add nothing.
    * ``**`` elsewhere reads as ``*``, which in bandit's ``fnmatch`` crosses
      ``/``, as the old form did.
    * A ``,`` (bandit splits on it), a ``.`` or empty component, or nothing at
      all: no entry.
    """
    spelled = path.replace("\\", "/")
    while spelled.startswith("./"):
        spelled = spelled[2:]
    spelled = spelled.lstrip("/")
    directory_only = False
    if spelled.endswith("/"):
        directory_only = True
        spelled = spelled.rstrip("/")
    if spelled.endswith("/**"):
        directory_only = True
        spelled = spelled[: -len("/**")]
    while spelled.startswith("**/"):
        spelled = spelled[len("**/") :]
    parts = spelled.split("/")
    if (
        not spelled
        or "," in spelled
        or "," in anchor
        or any(part in ("", ".", "..") for part in parts)
    ):
        return []
    body = "/".join("*" if part == "**" else part for part in parts)
    anchor_glob = glob.escape(anchor)
    entries = [f"{anchor_glob}/{body}/*", f"{anchor_glob}/*/{body}/*"]
    if not directory_only:
        top = body if _GLOB_CHARACTERS & set(body) else _not_a_plain_substring(body)
        entries += [f"{anchor_glob}/{top}", f"{anchor_glob}/*/{body}"]
    return entries


class BanditScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description="Path to Bandit configuration file. A relative path is taken from the directory of the config file that sets it, or from the working directory for --config-overrides, not from the source directory."
            f" {SET_BY_THE_OPERATOR}"
            " ASH does not look for one by name. A file named exactly `.bandit` is passed with `bandit --ini`, and any other file with `bandit --configfile`. Unless config_file names a `.bandit` file that exists, ASH passes bandit an empty config file with `bandit --ini`, so bandit does not read a `.bandit` file from the scanned tree. A path that is not a file is logged as a warning and ignored.",
        ),
    ] = None
    confidence_level: Annotated[
        str,
        Field(
            description="Confidence level for bandit scan (all, low, medium, high)",
            pattern="^(all|low|medium|high)$",
        ),
    ] = "all"
    ignore_nosec: Annotated[
        bool,
        Field(
            description="Whether to ignore #nosec comments in the code",
        ),
    ] = False
    excluded_paths: Annotated[
        List[IgnorePathWithReason],
        Field(
            description="List of paths to exclude from the bandit scan",
        ),
    ] = []
    additional_formats: Annotated[
        List[str],
        Field(
            description="Additional output formats to generate (e.g., html, csv, xml)",
        ),
    ] = []
    tool_version: Annotated[
        str | None,
        tool_version_constraint("scanners.bandit.options.tool_version"),
        Field(
            description="Version constraint for bandit tool installation (e.g., '>=1.7.0'). If not specified, uses '>=1.7.0,<2.0.0' for stability."
        ),
    ] = ">=1.7.0,<2.0.0"
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation (default: 300)"),
    ] = 300


class BanditScannerConfig(ScannerPluginConfigBase):
    """Bandit scanner configuration."""

    name: Literal["bandit"] = "bandit"
    enabled: bool = True
    options: Annotated[
        BanditScannerConfigOptions,
        Field(description="Configure Bandit scanner"),
    ] = BanditScannerConfigOptions()


@ash_scanner_plugin
class BanditScanner(ScannerPluginBase[BanditScannerConfig]):
    """Implementation of a Python security scanner using Bandit.

    This scanner uses Bandit to perform static security analysis of Python code
    and returns results in a structured format using the StaticAnalysisReport model.
    """

    #: bandit is a Python package ASH runs through uv. See
    #: ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = True

    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        env_prefixes=("BANDIT_",)
    )

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    # The operator's .bandit file, when config_file names one; see
    # _process_config_options.
    _ini_file: Optional[Path] = PrivateAttr(default=None)

    def model_post_init(self, context):
        if self.config is None:
            self.config = BanditScannerConfig()
        self.command = "bandit"
        self.tool_type = ScannerToolType.SAST
        self.use_uv_tool = True  # Enable UV tool execution

        # Set up explicit UV tool installation commands
        self._setup_uv_tool_install_commands()

        # Under a scan phase the probe is deferred until the dependency check
        # asks (uv_tool_mixin.deferred_tool_version_probes), so nothing runs
        # here then; see resolve_deferred_tool_version.
        self.tool_version = self._get_uv_tool_version("bandit")
        self.description = "Bandit is a Python source code security analyzer."
        extra_args = [
            ToolExtraArg(
                key="--recursive",
                value=None,
            ),
        ]
        if ASH_LOGGER.level == logging.DEBUG:
            extra_args.append(
                ToolExtraArg(
                    key="--verbose",
                    value=None,
                )
            )
        self.args = ToolArgs(
            format_arg="--format",
            format_arg_value="sarif",
            output_arg="--output",
            scan_path_arg=None,
            extra_args=extra_args,
        )
        super().model_post_init(context)

    def _get_tool_version_constraint(self) -> str | None:
        """Get version constraint for bandit installation.

        Returns:
            The configured ``tool_version`` constraint, whose default carries an
            upper bound excluding the next major version. No literal is repeated
            here: a copy of the constraint in this docstring went stale against
            the default beside it, which is what made the published docs drop the
            ceiling and tell readers to install an excluded major version.
        """
        # Use bandit-specific version constraint - bandit 1.7.0+ has better SARIF support
        return self.config.options.tool_version

    def _get_tool_package_extras(self) -> List[str] | None:
        """Get package extras for bandit installation.

        Returns:
            List of package extras needed for bandit (sarif and toml support)
        """
        # Bandit needs sarif extra for SARIF output format and toml extra for TOML config support
        return ["sarif", "toml"]

    def configure(self, config: ScannerPluginBase | None = None):
        """Configure the scanner with the provided configuration.

        Args:
            config: Scanner configuration

        Raises:
            ScannerError: If configuration fails
        """
        try:
            if config is not None:
                self.config = config

        except Exception as e:
            raise ScannerError(
                f"Failed to configure {self.__class__.__name__}: {str(e)}"
            )

    def validate_plugin_dependencies(self) -> bool:
        """Enhanced validation with explicit tool installation.

        Workflow:

        1. If UV tool execution is required but UV is not on PATH, defer to
           :func:`get_uv_tool_command` to see whether a direct binary fallback
           still satisfies the dependency.
        2. If UV is available and the tool is already reachable, succeed.
        3. Otherwise attempt explicit ``uv tool install`` with retry/timeout.
        4. As a last resort, ask :func:`get_uv_tool_command` to resolve the
           command — this consolidates the "uv missing → direct binary → None"
           fallback that used to be open-coded across scanners.

        Returns:
            True if validation passes, False otherwise
        """
        # First, while use_uv_tool still says what construction set: the
        # tool-version probe, which construction leaves to this point.
        self.resolve_deferred_tool_version()
        if not self._validate_uv_tool_availability():
            # UV is required but not present.  Defer to consolidated resolver:
            # if the tool is on PATH directly we can still run it.
            if get_uv_tool_command(self.command) is not None:
                self.use_uv_tool = False
                self.dependencies_satisfied = True
                return True
            self._plugin_log(
                "UV tool validation failed - UV is not available but required",
                level=logging.ERROR,
            )
            return False

        # For UV tool-based scanners, attempt explicit installation if needed
        if self.use_uv_tool:
            # Check if tool is already available (UV-installed or pre-installed)
            installation_info = self._get_tool_installation_info()

            if installation_info.get("available"):
                # Runs a verified binary on PATH directly instead of re-resolving
                # through uv, and fails offline with the missing extras named (#520).
                return self._select_tool_execution(installation_info)

            # Tool not available, attempt installation
            self._plugin_log(
                "Bandit not found via UV tool, attempting explicit installation...",
                level=logging.INFO,
            )

            # Attempt explicit tool installation with configured timeout
            timeout = self.config.options.install_timeout if self.config else 300
            retry_config = {
                "max_retries": 3,
                "base_delay": 1.0,
                "max_delay": 60.0,
            }

            if self._install_uv_tool(timeout=timeout, retry_config=retry_config):
                self._plugin_log(
                    "Successfully installed bandit via UV tool", level=logging.INFO
                )
                self.dependencies_satisfied = True
                return True

            self._plugin_log(
                "UV tool installation failed for bandit, falling back to consolidated resolver",
                level=logging.WARNING,
            )

        # Final fallback: consolidated UV-or-direct-binary resolver.
        return get_uv_tool_command(self.command) is not None

    def _process_config_options(self):
        # The operator's config file, if there is one. A config file inside the
        # scanned tree does not choose it (config/tool_config_trust.py), and ASH
        # does not look for .bandit, bandit.yaml or bandit.toml by name: their
        # skips and exclude_dirs would let the repository decide what its scan
        # reports. A scan always passes an --ini (the operator's .bandit, or an
        # empty one ASH writes), which ends bandit's own .bandit search.
        #
        # The configured value is read as the tool will read it (resolved from
        # the scanned tree, not from whatever directory the process runs in),
        # and one that is a work product the scan derived from the repository
        # being scanned (under the output or work directory) is not handed to
        # bandit unless the operator's own configuration names it; see
        # config/path_trust.py. A configured value that is refused or missing
        # takes no discovered replacement: bandit gets the empty ini.
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
        configured = self.config.options.config_file
        configured_path = None
        refused_configured = False
        if configured is not None:
            # The option as the tool will read it: the file that passed the
            # check below is exactly the file handed over.
            config_file_path = resolved_path(configured, source_dir)
            if not config_file_path.is_file():
                # The path as the config gave it, which can be a value the config
                # read from the environment, and env values are never logged.
                from automated_security_helper.config.config_validator import (
                    redact_values,
                )
                from automated_security_helper.utils.error_text import (
                    config_environment_values,
                )

                shown = redact_values(
                    str(Path(configured)),
                    config_environment_values(context_config),
                )
                ASH_LOGGER.warning(
                    f"Configured bandit config file does not exist or is not a "
                    f"file: {shown}. Bandit will run with an empty ini file that "
                    "ASH writes; no config file is discovered from the scanned "
                    "tree in its place."
                )
            elif refused_derived_product(
                configured,
                source_dir=source_dir,
                key="scanners.bandit.options.config_file",
                config=context_config,
                derived_dirs=derived_roots(self.context),
                operator_written=operator_wrote_value(
                    context_config,
                    "scanner",
                    "bandit",
                    ("options", "config_file"),
                    configured,
                    config_from_context=self._config_from_context,
                ),
            ):
                refused_configured = True
            else:
                configured_path = config_file_path
        if refused_configured:
            # A configured value that was refused takes no discovered
            # replacement (config/path_trust.py, "Configured tool inputs that
            # are refused or missing"): bandit runs with an empty ini file.
            ASH_LOGGER.warning(
                "Configured bandit config file was not used because it is a "
                "work product derived from the scanned repository. Bandit will "
                "run with an empty ini file that ASH writes; no config file is "
                "discovered from the scanned tree in its place."
            )
        if configured_path is not None and Path(configured).name == ".bandit":
            # The ini-or-config decision follows the name the operator's
            # configuration gave, so a link named .bandit keeps its format.
            self._ini_file = configured_path
            self.args.extra_args.append(
                ToolExtraArg(key="--ini", value=configured_path.as_posix())
            )
        elif configured_path is not None:
            self.args.extra_args.append(
                ToolExtraArg(key="--configfile", value=configured_path.as_posix())
            )
        # With no operator .bandit, each scan passes an empty --ini ASH writes
        # for that scanner run (_execute_scan), so bandit never reads one from
        # the scanned tree, --configfile or not.

        self.args.extra_args.append(
            ToolExtraArg(
                key="--confidence-level", value=self.config.options.confidence_level
            )
        )
        self.args.extra_args.append(ToolExtraArg(key="--severity-level", value="all"))
        for fmt in self.config.options.additional_formats:
            self.args.extra_args.append(ToolExtraArg(key="--format", value=fmt))
        if self.config.options.ignore_nosec:
            self.args.extra_args.append(ToolExtraArg(key="--ignore-nosec", value=None))

        required, _best_effort = self._configured_token_excludes(warn=True)
        self.args.extra_args.append(
            ToolExtraArg(key="--exclude=" + ",".join(required), value=None)
        )

        return super()._process_config_options()

    def _configured_token_excludes(self, warn: bool) -> Tuple[List[str], List[str]]:
        """The construction-time ``--exclude`` token's entries, for the source
        directory: ``_configured_excludes`` anchored there. Rebuilt per scan by
        ``_execute_scan``; this token only keeps the argument's shape visible."""
        anchor = Path(getattr(self.context, "source_dir", None) or ".")
        return self._configured_excludes(anchor, warn=warn), []

    def _configured_excludes(self, target: Path, warn: bool = False) -> List[str]:
        """The ``--exclude`` entries every scan of ``target`` gets: the known
        ignore paths and bandit's own ``excluded_paths`` (expired entries left
        out), anchored at the target (``bandit_excluded_path_globs``). ``warn``
        names an entry that has no bandit form; the scanner passes it once,
        when it is built."""
        anchor = Path(target).as_posix()
        bandit_excludes = []
        for item in KNOWN_IGNORE_PATHS:
            bandit_excludes.extend(bandit_excluded_path_globs(anchor, item))
        # Redacted: the entries are configured, a configured value can come from
        # the environment, and ash.log keeps these lines (DEBUG under --debug).
        environment_values = self._environment_values()
        for item in active_ignore_paths(
            self.config.options.excluded_paths,
            where="scanners.bandit.options.excluded_paths",
        ):
            ASH_LOGGER.debug(
                text_without_values(
                    f"Path '{item.path}' excluded from {self.config.name} scan "
                    f"for reason: {item.reason}",
                    environment_values,
                ),
                extra=NO_MARKUP,
            )
            entries = bandit_excluded_path_globs(anchor, item.path)
            if warn and not entries:
                ASH_LOGGER.warning(
                    text_without_values(
                        f"bandit excluded_paths entry '{item.path}' has no bandit "
                        "--exclude form, so it excludes nothing: write a file, a "
                        "directory, or a glob without ',' and without '.' or empty "
                        "path components.",
                        environment_values,
                    ),
                    extra=NO_MARKUP,
                )
            bandit_excludes.extend(entries)
        return bandit_excludes

    def _scan_excludes(
        self, target: Path, global_ignore_paths: Sequence[IgnorePathWithReason]
    ) -> Tuple[List[str], List[str]]:
        """The ``--exclude`` entries for one scan of ``target``, as
        ``(required, best_effort)``.

        Anchored at the target as it appears in argv, since bandit matches each
        entry against ``os.path.join(root, name)`` while walking that string.
        ``required``: the known ignore paths and ``excluded_paths``
        (``_configured_excludes``), and each of ASH's output directories inside
        the target: this run's, and an earlier run's default ``.ash/ash_output``,
        the directories every other scanner that walks a directory skips
        (``_ash_output_dirs_inside``). Without them, a source tree holding
        ``.ash/ash_output`` had the converters' output scanned in the source pass
        as well as in the converted pass, and each of its findings reported twice.
        None is inside the converted target, which lives inside the output
        directory. ``best_effort``: globs for the live global ignore paths that
        bandit can be given without skipping a file they do not cover
        (``bandit_exclude_globs``), when the target is the source directory; the
        SARIF step applies every ignore path either way, so a caller may drop
        them under an argv bound. Any entry a file path under the target holds
        as text is left out of both (``_entries_no_path_holds_as_text``, one
        walk for the two sets).
        """
        anchor = Path(target).as_posix()
        excludes: List[str] = self._configured_excludes(target)
        # Ignore paths are relative to the source directory, so they are anchored
        # only when bandit is scanning it. Under the converted target the same
        # pattern names different files: "archive/**" would skip everything the
        # archive converter wrote, which the SARIF step keeps.
        ignore_globs: List[str] = []
        source_dir = getattr(self.context, "source_dir", None)
        if (
            source_dir is not None
            and Path(target).absolute() == Path(source_dir).absolute()
        ):
            for ignore_path in active_ignore_paths(global_ignore_paths):
                ignore_globs.extend(bandit_exclude_globs(anchor, ignore_path.path))
        output_entries: List[Tuple[str, Path]] = []
        for relative in self._ash_output_dirs_inside(Path(target)):
            # The path as bandit spells it while walking the anchor, then the
            # separator and "*": bandit adds "/*" itself only to a value naming an
            # existing directory, which an escaped value does not.
            output_path = os.path.join(anchor, *relative.parts)
            if "," in output_path:
                ASH_LOGGER.warning(
                    f"Not excluding ASH's output directory {output_path} from "
                    "bandit: its --exclude value is comma-separated, and the path "
                    "has a comma. ASH drops bandit's findings there after the scan."
                )
                continue
            output_entries.append(
                (
                    escape_for_pattern(output_path, PatternSyntax.FNMATCH)
                    + os.sep
                    + "*",
                    relative,
                )
            )
        if not excludes and not ignore_globs and not output_entries:
            return [], []
        holding = _paths_holding_glob_characters(target)
        required = _entries_no_path_holds_as_text(
            target, excludes, output_entries, holding=holding
        )
        best_effort = (
            _entries_no_path_holds_as_text(target, ignore_globs, [], holding=holding)
            if ignore_globs
            else []
        )
        return required, best_effort

    # Bandit emits exit code 1 when findings are present; treat that as success
    # alongside 0. (Same as base default, but spelled out for clarity.)
    success_exit_codes: ClassVar[set] = {0, 1}

    # Python-only repos commonly have empty target dirs after conversion;
    # log at VERBOSE rather than INFO to keep the user-facing output clean.
    empty_target_log_level: ClassVar[int] = logging.VERBOSE

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

        ``targets_attempted`` is set from bandit's SARIF (_record_scanned_files) and
        read by the executor after every target, so a target that returns before
        bandit runs (an empty directory) must not keep the last one's.
        """
        self.targets_attempted: Optional[int] = None
        return super().scan(
            target, target_type, global_ignore_paths, config, *args, **kwargs
        )

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ):
        """Resolve final argv and results path for Bandit.

        The ``--exclude`` token built at construction is swapped, for this
        resolution only, for one that also carries this scan's entries
        (``_scan_excludes``) and the links leaving ``target``
        (``_link_excludes``); the scanner's own arguments are restored
        afterwards, so repeated scans do not accumulate them. Built only at
        construction, the token would miss the global ignore paths, which are
        merged here while ``_resolve_arguments`` runs: resolution does not
        rebuild the token.

        The value is bounded to one command-line argument
        (``_EXCLUDE_ARGUMENT_LIMIT``): the configured, output-directory and
        link entries have to fit, or bandit is not run on ``target`` (over the
        bound it would read the file a link points at, or exec would fail with
        E2BIG and blame nothing); the global-ignore globs are added while they
        fit and dropped with a warning past it, since the SARIF step applies
        every ignore path after the scan either way.
        """
        target_results_dir = self.results_dir.joinpath(target_type)
        results_file = target_results_dir.joinpath("bandit.sarif")
        results_file.parent.mkdir(exist_ok=True, parents=True)

        files, links = walked_files(target)
        required, best_effort = self._scan_excludes(target, global_ignore_paths or [])
        entries = required + self._link_excludes(target, files=files, links=links)
        length = len(f"--exclude={','.join(entries)}".encode())
        if length > _EXCLUDE_ARGUMENT_LIMIT:
            raise ScannerError(
                f"Not running bandit on {Path(target).as_posix()}: its --exclude "
                f"value, with the {len(links)} links that leave the scanned tree, is "
                f"longer than one command-line argument can be "
                f"({_EXCLUDE_ARGUMENT_LIMIT} bytes)."
            )
        left_out = 0
        for entry in best_effort:
            added = len(entry.encode()) + (1 if entries else 0)
            if length + added > _EXCLUDE_ARGUMENT_LIMIT:
                left_out += 1
                continue
            entries.append(entry)
            length += added
        if left_out:
            self._plugin_log(
                f"{left_out} globs for the global ignore paths are not in bandit's "
                "--exclude, which would be longer than one command-line argument "
                "can be; bandit reads the files they cover, and ASH drops their "
                "findings.",
                target_type=target_type,
                level=logging.WARNING,
            )

        # A new list: the one extra_args holds is put back as it was, unchanged.
        original_extra_args = self.args.extra_args
        resolution_args = [
            arg for arg in original_extra_args if not arg.key.startswith("--exclude=")
        ]
        if self._ini_file is None:
            # Given no --ini, bandit walks its targets for a .bandit file, which
            # can set skips and exclude. The --ini is an empty file ASH writes
            # for this scanner run, outside the scanned tree and removed when
            # the run ends (config/tool_config_trust.empty_tool_config), never
            # the results directory, which the default layout puts inside the
            # tree.
            resolution_args.append(
                ToolExtraArg(
                    key="--ini",
                    value=empty_tool_config(
                        "bandit-empty.ini", "[bandit]\n", context=self.context
                    ).as_posix(),
                )
            )
        self.args.extra_args = resolution_args + [
            ToolExtraArg(key=f"--exclude={','.join(entries)}", value=None)
        ]
        try:
            final_args = self._resolve_arguments(
                target=target, results_file=results_file
            )
        finally:
            self.args.extra_args = original_extra_args

        return final_args, results_file, None

    def _link_excludes(
        self,
        target: Path,
        files: List[str] | None = None,
        links: List[str] | None = None,
    ) -> List[str]:
        """``--exclude`` entries for each link to a file whose target leaves ``target``.

        bandit reads a link to a file wherever it points: its walk lists the link
        among the files and opens it by name. The links come from
        ``file_links_leaving_tree``, which walks as bandit does (``os.walk``, which
        does not descend links to directories) and ignores ignore files, as bandit
        does.

        bandit 1.9.4 (``bandit/core/manager.py``) splits ``--exclude`` on commas and
        leaves out a walked file when an entry matches its path with ``fnmatch`` or
        is a substring of it. So each entry is the link's path as bandit's walk
        spells it, ``<target>/<path below it>``, and it is used only when it leaves
        out that file alone: it holds no comma, no ``*``, ``?`` or ``[``, and no line
        break (a flag key with one fails ASH's own check, which would drop the whole
        ``--exclude``), and no other file's path under ``target`` contains it.

        ``files`` and ``links`` are ``walked_files(target)``, when the caller has
        walked it already.

        Raises:
            ScannerError: Naming the first link that cannot be left out that way,
                or the first link at all when walked paths are not joined with
                ``/`` (Windows). bandit is then not run on ``target``, rather than
                read the file the link points at.
        """
        if files is None or links is None:
            files, links = walked_files(target)
        if not links:
            return []
        root = Path(target).as_posix()
        walked = [f"{root}/{relative}" for relative in files]
        entries = []
        for relative in links:
            entry = f"{root}/{relative}"
            if (
                os.sep != "/"
                or any(character in entry for character in _BANDIT_EXCLUDE_UNSAFE)
                or any(entry in other for other in walked if other != entry)
            ):
                raise ScannerError(
                    f"Not running bandit on {root}: {relative!r}: "
                    f"{REASON_LINK_LEAVES_TREE}, and bandit's --exclude cannot leave "
                    "out that file alone, so bandit would read the file it points at."
                )
            entries.append(entry)
        return entries

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Record how many files bandit scanned, and mask secret-shaped strings."""
        self._record_scanned_files(sarif_report, final_args, target)
        return mask_secrets_in_sarif(sarif_report)

    def _record_scanned_files(
        self, sarif_report: SarifReport, final_args: List[str], target: Path
    ) -> None:
        """Set ``targets_attempted`` from the files bandit's SARIF lists.

        bandit's SARIF carries ``run.properties.metrics``: ``_totals`` and one entry
        per file it scanned. None listed while the target holds ``.py`` or ``.pyw``
        files bandit was not told to exclude (matched as bandit 1.9.4 matches its
        ``--exclude`` entries, by ``fnmatch`` or as a substring) means bandit
        scanned none of them, and its result says nothing about them: an error, not
        a PASSED with no findings. None listed and none there is SKIPPED
        (``targets_attempted`` 0). No metrics leaves the count unset (no claim).

        Raises:
            ScannerError: When bandit scanned no file of the Python files there.
        """
        scanned = None
        for run in sarif_report.runs or []:
            properties = run.properties.model_dump() if run.properties else {}
            metrics = properties.get("metrics")
            if isinstance(metrics, dict):
                scanned = (scanned or 0) + sum(1 for key in metrics if key != "_totals")
        if scanned is None:
            return
        if scanned:
            self.targets_attempted = scanned
            return
        prefix = "--exclude="
        entries = [
            entry
            for arg in final_args
            if str(arg).startswith(prefix)
            for entry in str(arg)[len(prefix) :].split(",")
            if entry
        ]
        root = Path(target).as_posix()
        all_files, _ = walked_files(target)
        python = [
            f"{root}/{relative}"
            for relative in all_files
            if relative.endswith((".py", ".pyw"))
        ]
        unexcluded = [
            path
            for path in python
            if not any(fnmatch.fnmatch(path, e) or e in path for e in entries)
        ]
        if unexcluded:
            raise ScannerError(
                f"bandit scanned no file below {root}, though {len(unexcluded)} Python "
                "files there are not excluded, so its result says nothing about them."
            )
        self.targets_attempted = 0


if __name__ == "__main__":
    # As npm_audit's block does: a scanner needs a context, and run as a script its
    # class resolves its "AshConfig" reference only once that name is bound here.
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    AshConfig.model_rebuild()
    ASH_LOGGER.debug("Running Bandit via __main__")
    scanner = BanditScanner(
        context=PluginContext(
            source_dir=Path.cwd(),
            output_dir=Path.cwd().joinpath(".ash", "ash_output"),
        ),
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                confidence_level="all",
                severity_threshold="ALL",
                ignore_nosec=False,
                excluded_paths=[],
                additional_formats=[],
            )
        ),
    )
    report = scanner.scan(target=Path("."), target_type="source")

    if isinstance(report, SarifReport):
        from automated_security_helper.utils.command_safe_stream import (
            json_commands_broken,
        )
        from automated_security_helper.utils.console import echo_raw

        # The SARIF repeats the tree's file names: no "##name[" of theirs is a
        # CI command where this prints, and the JSON is still the same document.
        echo_raw(
            json_commands_broken(
                report.model_dump_json(
                    indent=2,
                    by_alias=True,
                    exclude_unset=True,
                )
            )
        )
