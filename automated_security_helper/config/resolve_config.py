import errno
import hashlib
import json
import os
import stat
from pathlib import Path
from types import UnionType
from typing import (
    Annotated,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
    Union,
    get_args,
    get_origin,
)

from pydantic import ValidationError
import yaml
from automated_security_helper.config.archive_limits import confine_archive_limits
from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
from automated_security_helper.config.client_config_policy import (
    ClientConfigRules,
    apply_client_config_rules,
    clear_client_supplied_marks,
)
from automated_security_helper.config.config_sources import (
    AnchorPaths,
    ChainNames,
    RefuseEnv,
    ResolvedConfigDocument,
    _resolve_dict_key,
    by_every_name,
    check_discovered_source,
    deep_merge,
    default_confinement_root,
    describe_config_path,
    discover_config_source,
    discovery_warnings,
    env_refused_for,
    log_config_discovery,
    read_config_file,
    resolve_config_document,
)
from automated_security_helper.config.default_config import (
    default_config_chain,
    default_config_document,
    default_config_names,
    get_default_config,
)
from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING
from automated_security_helper.config.operator_paths import (
    anchor_override_paths,
    the_operators_files,
)
from automated_security_helper.config.path_trust import (
    OperatorPaths,
    operator_reason,
    parse_overrides,
)
from automated_security_helper.config.plugin_module_trust import (
    confine_plugin_modules,
)
from automated_security_helper.config.reporter_trust import (
    confine_reporter_destinations,
)
from automated_security_helper.config.tool_config_trust import (
    confine_scanner_config_files,
    confine_tool_versions,
)
from automated_security_helper.config.sandbox_grants import (
    REPOSITORY_WRITTEN,
    confine_sandbox_grants,
    files_inside,
    is_within,
    repository_written,
    scanned_trees,
    tree_holding,
    untrusted_path,
)
from automated_security_helper.config.secret_verification_trust import (
    confine_detect_secrets_settings,
)

#: Why a config an MCP client supplied may not grant, for the confinement warning.
CLIENT_SUPPLIED = "an MCP client supplied the file, not the operator"
from automated_security_helper.core.constants import (
    ASH_CONFIG_FILE_NAMES,
    ASH_PYPROJECT_FILE_NAME,
    ASH_RC_FILE_NAMES,
)
from automated_security_helper.core.exceptions import (
    ASHConfigFileNotFoundError,
    ASHConfigSourceError,
    ASHConfigValidationError,
)
from automated_security_helper.config.staleness_trust import (
    confine_content_db_staleness,
)
from automated_security_helper.config.untrusted_source import (
    IN_TREE_OR_DELIVERED,
    UntrustedSource,
)
from automated_security_helper.utils.log import ASH_LOGGER


class LoggedResolutionWarning(str):
    """A resolution warning resolve_config has already logged.

    Every resolution warning is reported with a scan's results; the orchestrator
    also logs each one, except these, so that none is logged twice. The sources
    discovery ignored are logged by discovery when resolve_config discovers.
    """

    __slots__ = ()


def find_config_file(
    search_dir: Path | None = None, permit: Optional[Callable[[Path], bool]] = None
) -> Optional[Path]:
    """Return the config source a scan of search_dir would use, or None.

    Applies the discovery precedence in ``config_sources.discover_config_source``:
    ASH_CONFIG_FILE_NAMES in order (each in search_dir, then search_dir/.ash/),
    then the ashrc names, then a pyproject.toml with a [tool.ash] table. The
    result can therefore be a TOML file; callers that edit the file in place
    must check its format. ``permit`` is passed to discovery, which checks every
    source it finds against it before opening any.
    """
    if search_dir is None:
        search_dir = Path.cwd()
    selected = discover_config_source(search_dir, permit=permit).selected
    return selected.path if selected is not None else None


def _empty_config_path() -> ASHConfigSourceError:
    # Path("") is the working directory, so an empty path is named as what it is
    # rather than reported as a directory that cannot be read.
    return ASHConfigSourceError(
        "The configuration file path is empty. Name a config file, or leave the "
        "path unset to use the configuration ASH discovers in the source directory."
    )


def _config_file_not_loadable(config_path: Path) -> ASHConfigSourceError:
    """The refusal for a config path that is missing or is not a regular file.

    Classified from ``os.stat`` alone; nothing at the path is opened.
    """
    where = describe_config_path(config_path)
    try:
        os.stat(config_path)
    except FileNotFoundError:
        if os.path.islink(config_path):
            return ASHConfigFileNotFoundError(
                f"Configuration file not found: {where} is a symbolic link to a "
                "file that does not exist."
            )
        return ASHConfigFileNotFoundError(f"Configuration file not found: {where}")
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return ASHConfigSourceError(
                f"Configuration file {where} is a symbolic link that leads back to "
                "itself, so it cannot be read."
            )
        return ASHConfigSourceError(
            f"Configuration file {where} cannot be read: {exc.strerror}"
        )
    return ASHConfigSourceError(
        f"Configuration file {where} is not a regular file, so it cannot be read."
    )


def check_config_path(config_path: Path | str) -> Path:
    """``config_path`` as a Path, refused when it is empty or not a regular file.

    The checks ``read_config_document`` makes before reading, for a caller that
    reads the file some other way (MCP ``get_config`` with ``raw``).
    """
    if isinstance(config_path, str) and not config_path.strip():
        raise _empty_config_path()
    path = Path(config_path)
    # os.stat, not Path.is_file: before Python 3.14 is_file raises for an error
    # other than "not found" (a directory above that cannot be searched).
    try:
        regular = stat.S_ISREG(os.stat(path).st_mode)
    except OSError:
        regular = False
    if not regular:
        raise _config_file_not_loadable(path)
    return path


def read_config_document(
    config_path: Path | str,
    confine_to: Optional[Path] = None,
    permit_base: Optional[Callable[[Path], bool]] = None,
    *,
    log_failure: bool = True,
    refuse_env: Optional[RefuseEnv] = None,
    anchor_relative_paths: Optional[AnchorPaths] = None,
    unquoted: bool = False,
) -> ResolvedConfigDocument:
    """``resolve_config_document``, refusing a config file that does not load.

    ``resolve_config_document`` raises ``ASHConfigSourceError`` for a TOML file
    and for anything wrong in an ``extends`` chain, but lets the root YAML or JSON
    file's own read and parse errors through as the reader raised them. Here a
    named file that is missing or not a regular file, and one that cannot be read
    or parsed (including one that is not UTF-8), raise ``ASHConfigSourceError``
    too. Every config file a scan reads comes through here, so none of them is
    ever replaced by the default config, which would scan with that file's
    suppressions, ignore paths and settings switched off and still report
    success.

    A parser's message can quote the line it stopped at. For a file an MCP
    client delivered (by any name on its way, ``_is_a_client_file``) or one the
    caller marks ``unquoted`` (a config a client named), that is text the client
    may not have written, so the error and the log line give only the parser's
    error type and position (``_unquoted_load_error``).

    ``log_failure`` False leaves out the "Failed to load configuration file" log
    line, for a caller that reads the file ahead of the resolution that reports
    the same failure. ``refuse_env`` and ``anchor_relative_paths`` are passed to
    ``resolve_config_document``.
    """
    path = check_config_path(config_path)
    try:
        return resolve_config_document(
            path,
            confine_to=confine_to,
            permit_base=permit_base,
            refuse_env=refuse_env,
            anchor_relative_paths=anchor_relative_paths,
        )
    except (OSError, UnicodeDecodeError, yaml.YAMLError, json.JSONDecodeError) as e:
        # json.JSONDecodeError and UnicodeDecodeError are ValueErrors, but a bare
        # ValueError is not caught: pydantic's ValidationError is one too.
        if not isinstance(e, OSError) and (unquoted or _is_a_client_file(path)):
            problem = _unquoted_load_error(path, e)
            if log_failure:
                ASH_LOGGER.error(f"Failed to load configuration file: {problem}")
            raise ASHConfigSourceError(problem) from None
        if log_failure:
            ASH_LOGGER.error(f"Failed to load configuration file: {str(e)}")
        verb = "read" if isinstance(e, OSError) else "parse"
        raise ASHConfigSourceError(
            f"could not {verb} {describe_config_path(path)}: {e}"
        ) from e


def _warnings_when_discovered(
    config_path: Path,
    source_dir: Path,
    permit_base: Optional[Callable[[Path], bool]] = None,
) -> List[str]:
    """Discovery's warnings for ``source_dir`` when ``config_path`` is the source it selects.

    ``ash scan`` and workspace mode run discovery themselves and pass the file it
    selected as the config path, so the sources it ignored are reported for
    them as they are when resolve_config discovers. Discovery is run again only
    for a file at one of its locations, and the ignored sources are not logged
    again: the caller that discovered them already did.
    """
    names = {*ASH_CONFIG_FILE_NAMES, *ASH_RC_FILE_NAMES, ASH_PYPROJECT_FILE_NAME}
    if config_path.name not in names:
        return []
    # Both sides resolved: a .ash that is a symbolic link resolves to its target.
    root = source_dir.resolve()
    if config_path.parent.resolve() not in (root, (root / ".ash").resolve()):
        return []
    try:
        discovery = discover_config_source(source_dir, permit=permit_base)
    except ASHConfigValidationError:
        return []
    selected = discovery.selected
    if selected is None or selected.path.resolve() != config_path.resolve():
        return []
    return discovery_warnings(discovery)


def validate_config_document(
    document: ResolvedConfigDocument, config_path: Path | str
) -> AshConfig:
    """The config ``document`` (``read_config_document``'s) holds, validated as a
    scan validates it; ``ASHConfigValidationError`` naming ``config_path`` if it
    does not validate."""
    try:
        return AshConfig.model_validate(document.data, strict=True)
    except ValidationError as e:
        raise ASHConfigValidationError(
            f"Configuration validation failed for "
            f"'{describe_config_path(Path(config_path))}': {str(e)}. "
            "Run 'ash config lint' to identify and fix issues."
        ) from e


def load_config_file(
    config_path: Path | str,
    confine_to: Optional[Path] = None,
    permit_base: Optional[Callable[[Path], bool]] = None,
    *,
    log_failure: bool = True,
    refuse_env: Optional[RefuseEnv] = None,
    anchor_relative_paths: Optional[AnchorPaths] = None,
) -> AshConfig:
    """``AshConfig.from_file``, with every way the file can fail to load refused.

    A missing, unreadable or unparseable file raises ``ASHConfigSourceError``
    (see ``read_config_document``) and one that does not validate raises
    ``ASHConfigValidationError``, both exit 3 from ``ash scan``.
    """
    document = read_config_document(
        config_path,
        confine_to=confine_to,
        permit_base=permit_base,
        log_failure=log_failure,
        refuse_env=refuse_env,
        anchor_relative_paths=anchor_relative_paths,
    )
    return validate_config_document(document, config_path)


def _apply_config_override(
    config_dict: Dict[str, Any], key_path: str, value: str
) -> None:
    """
    Apply a single config override to a configuration dictionary.

    Args:
        config_dict: The configuration dictionary to modify
        key_path: The dot-separated path to the config value (e.g., 'reporters.cloudwatch-logs.options.aws_region')
        value: The value to set at the specified path
    """
    # Check if this is an append operation (key_path ends with +)
    append_mode = False
    if key_path.endswith("+"):
        append_mode = True
        key_path = key_path[:-1]  # Remove the + from the key path

    # Split the key path into components
    keys = key_path.split(".")

    # Navigate to the nested dictionary
    current = config_dict
    for i, key in enumerate(keys[:-1]):
        resolved = _resolve_dict_key(current, key)
        # If the key doesn't exist or isn't a dict, create a new dict
        if resolved not in current or not isinstance(current[resolved], dict):
            current[resolved] = {}
        current = current[resolved]

    # Set the value at the final key
    final_key = _resolve_dict_key(current, keys[-1])

    # Parse the value
    parsed_value = _parse_config_value(value)

    # Handle append mode for lists
    if append_mode and final_key in current and isinstance(current[final_key], list):
        if isinstance(parsed_value, list):
            current[final_key].extend(parsed_value)
            ASH_LOGGER.debug(f"Appended to list at {key_path}: {parsed_value}")
        else:
            current[final_key].append(parsed_value)
            ASH_LOGGER.debug(f"Appended to list at {key_path}: {parsed_value}")
    else:
        # Set the value
        current[final_key] = parsed_value
        ASH_LOGGER.debug(f"Applied config override: {key_path}={parsed_value}")


def _parse_config_value(value: str) -> Any:
    """
    Parse a configuration value string into the appropriate Python type.

    Args:
        value: The string value to parse

    Returns:
        The parsed value as the appropriate type
    """
    # Check for list syntax: [item1, item2, ...]
    if value.startswith("[") and value.endswith("]"):
        try:
            # Try to parse as JSON
            return json.loads(value)
        except json.JSONDecodeError:
            # If not valid JSON, try a simpler approach for basic lists
            items = value[1:-1].split(",")
            return [_parse_config_value(item.strip()) for item in items if item.strip()]

    # Check for dict syntax: {key1: value1, key2: value2, ...}
    if value.startswith("{") and value.endswith("}"):
        try:
            # Try to parse as JSON
            return json.loads(value)
        except json.JSONDecodeError:
            # If not valid JSON, return as string
            return value

    # Handle boolean values
    if value.lower() == "true":
        return True
    elif value.lower() == "false":
        return False
    elif value.lower() in ("null", "none"):
        return None

    # Try numeric conversions
    try:
        # Try to convert to int
        return int(value)
    except ValueError:
        try:
            # Try to convert to float
            return float(value)
        except ValueError:
            # Keep as string
            return value


def split_config_override(override: str) -> Tuple[str, str]:
    """``override`` as ``(key path, value)``, split at its first ``=``.

    Raises:
        ASHConfigValidationError: There is no ``=``, or nothing but blanks before
            it. The one check ``--config-overrides`` and the MCP workspace tools'
            ``config_overrides`` share, so both report it as the same invalid
            config.
    """
    key_path, separator, value = override.partition("=")
    if not separator or not key_path.strip():
        raise ASHConfigValidationError(
            f"Invalid config override: '{override}'. Expected format: key.path=value"
        )
    return key_path, value


def apply_config_overrides(config: AshConfig, config_overrides: List[str]) -> AshConfig:
    """
    Apply configuration overrides to an AshConfig object.

    Args:
        config: The AshConfig object to modify
        config_overrides: List of strings in the format 'key.path=value'

    Returns:
        The modified AshConfig object

    Raises:
        ASHConfigValidationError: If an override cannot be parsed or applied, or
            if the merged configuration does not validate. Failing here is
            deliberate: silently dropping an override would run the scan with
            settings the operator did not choose and still report success.
    """
    if not config_overrides:
        return config

    # Convert config to dict for easier manipulation
    config_dict = config.model_dump()

    # Apply each override
    for override in config_overrides:
        key_path, value = split_config_override(override)
        try:
            _apply_config_override(config_dict, key_path, value)
        except Exception as e:
            raise ASHConfigValidationError(
                f"Failed to apply config override '{override}': {e}"
            ) from e

    # Convert back to AshConfig
    try:
        return AshConfig.model_validate(config_dict)
    except ValidationError as e:
        raise ASHConfigValidationError(
            "Configuration is invalid after applying the requested overrides "
            f"{config_overrides}: {e}"
        ) from e


def resolve_config(
    config_path: Path | str | None = None,
    source_dir: Path | str | None = None,
    fallback_to_default: bool = True,
    config_overrides: List[str] = None,
    permit_base: Optional[Callable[[Path], bool]] = None,
    scanned_root: Path | str | None = None,
    trusted_config_path: Path | str | None = None,
    untrusted_config: bool = False,
    client_overrides: bool = False,
    client_config_policy: Optional[ClientConfigRules] = None,
    remote_client: bool = False,
    overlay_config_path: Path | str | None = None,
) -> AshConfig:
    """
    Load configuration from file or return default configuration.

    The default configuration is returned only when there is no config file at
    all: none named and none discovered. A file that is named (``config_path``,
    ``ASH_CONFIG``) or discovered and cannot be loaded -- missing, a dangling
    link, not a regular file, unreadable, not UTF-8, not valid YAML, JSON or
    TOML, or not a valid config -- raises instead, whatever
    ``fallback_to_default`` says.

    Args:
        config_path: Path to the configuration file
        source_dir: Source directory to search for configuration files
        fallback_to_default: Whether to return the default configuration when no
            config file is named or found. When False, that case raises too.
        config_overrides: List of configuration overrides in the format 'key.path=value'
        permit_base: Optional check every ``extends`` base must also pass. The
            MCP server passes the calling session's; see
            ``config/config_sources.py``. A refusal is raised, never replaced by
            the default config.
        scanned_root: The directory being scanned. A config file inside the
            repository that holds it was written by the repository under scan,
            so the sandbox grants it makes are dropped; see
            ``config/sandbox_grants.py``. Defaults to ``source_dir``, or the
            working directory when that is None too.
        trusted_config_path: The operator's own config file, when the config
            actually selected is another file (workspace mode's operator config,
            for a project with a config file of its own). Used in place of the
            defaults as the trusted base the grants come from, unless it is
            inside the scanned tree as well.
        untrusted_config: The selected config file was written by the caller,
            not the operator: an MCP client's upload named as ``config_path``.
            Every file of its chain is then treated as a file inside the scanned
            tree is, wherever it is: its sandbox grants come from the trusted
            base instead, its ``network_scanners`` list only removes network,
            and its ``sandbox.mode`` cannot turn off or replace a mode the
            trusted base sets. Its ``ash_plugin_modules`` are limited the same way
            as an in-tree file's (``config/plugin_module_trust.py``), and so are
            its reporter destinations (``config/reporter_trust.py``), detect-secrets'
            secret verification and the plugin and filter files it imports
            (``config/secret_verification_trust.py``), and its
            ``honor_ignore_files`` is replaced by the trusted value
            (:func:`confine_honor_ignore_files`), and so are its archive extraction
            limits (``config/archive_limits.py``).
        client_overrides: ``config_overrides`` came from an MCP client (a
            workspace tool's), not the operator, so a tool path they name is not
            the operator's (``path_trust.OperatorPaths``). Implied when
            ``client_config_policy`` is set and there are overrides.
        client_config_policy: The rules a file of the chain that an MCP client
            delivered is checked against; see ``config/client_config_policy.py``.
            None takes the trusted base's. When set, ``config_overrides`` are the
            client's too (the MCP workspace tools' ``config_overrides``): what
            they set is marked and confined as a delivered file's is.
        remote_client: The config is read for an MCP call from a remote client
            (``cli/mcp/sandbox.caller_is_remote``). Every file of the chain the
            operator did not set aside then resolves no ``!ENV``, and one that
            uses it is refused; otherwise only a file an MCP client delivered is.
            See "Environment variables" in ``config/config_sources.py``. The
            operator's own files (``trusted_config_path``, ``ASH_CONFIG``) are
            read as before.
        overlay_config_path: A config file merged over the selected one before
            it is validated, by the ``extends`` rule with this file as the child
            (``config_sources.deep_merge``). The file is resolved on its own
            first, ``extends`` and ``patch`` included, so it means what it means
            as a trusted base or as a project's only config; then every field
            the result holds replaces the selected config's, mappings merge key
            by key, and a list it holds replaces the selected config's list
            whole. Its ``patch`` therefore does not reach the selected config: a
            key it removes is left to the selected config, and an ``add`` at
            ``/global_settings/suppressions/-`` adds to its own list, which then
            replaces the selected config's. ``config_overrides`` apply after it.
            When no config file was found, this file is used alone. A selected
            file that is missing or cannot be loaded is refused, as it is
            without an overlay, rather than replaced by this file: the
            project's own settings would be lost. Workspace mode passes the
            operator's ``--config`` here for a
            project that has a config of its own (``workspace/resolver.py``), and
            the same file as ``trusted_config_path``, so a field the operator set
            is its trusted value. Every file it is built from must be the
            operator's: one inside the scanned tree (from ``scanned_root``) or
            one an MCP client delivered would make its settings final over the
            tree, so such an overlay is refused (``check_operator_config``), as
            is one that is missing or does not validate on its own. Not combined
            with ``untrusted_config``.

    A file of the chain an MCP client delivered
    (``cli/mcp/sandbox.config_is_client_supplied``) is confined as a file inside
    the scanned tree is, wherever it is, and is never the trusted base: a
    session's client-patched profile is one. ``untrusted_config`` extends the
    same to a file a client named anywhere else. Each file is judged by every
    path it was reached by and every symlink on the way
    (``ResolvedConfigDocument.names``), so a file a delivered or in-tree link
    reaches is the client's or the repository's wherever it is. A validation
    error for a client's file names the file and each problem, and quotes none
    of the values it holds.

    Returns:
        The resolved AshConfig object

    Raises:
        ASHConfigValidationError: The config could not be resolved (exit 3 from
            ``ash scan``). ``ASHConfigSourceError``, a subclass, when a config file
            could not be loaded at all.
    """
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    if overlay_config_path is not None and untrusted_config:
        # untrusted_config treats every file of the chain as the caller's, which
        # would include the overlay, the operator's own file.
        raise ValueError("overlay_config_path cannot be combined with untrusted_config")
    # Under the MCP server the overrides come from the client, held to the
    # session's allowlist; see operator_overrides below. A caller that passes
    # client_overrides says the same of a workspace tool's overrides.
    client_overrides = client_overrides or (
        client_config_policy is not None and bool(config_overrides)
    )
    if not client_overrides and client_config_policy is None and config_overrides:
        # The operator's --config-overrides: a relative path in one is taken from
        # the working directory ASH runs in, not the scanned tree
        # (config/operator_paths.py). Anchored once here, so the config and every
        # replay onto the trusted base below read the same value.
        config_overrides = anchor_override_paths(config_overrides, Path.cwd())
    chain: List[Path] = []
    named: List[Path] = []
    spelled: List[Path] = []
    merged: List[Any] = []
    documents: Dict[Path, Any] = {}
    names: Dict[Path, Tuple[Path, ...]] = {}
    refuse_env = env_refused_for(
        remote_client, getattr(client_config_policy, "session_id", None)
    )
    trees = scanned_trees(
        Path(
            scanned_root
            if scanned_root is not None
            else (source_dir if source_dir is not None else Path.cwd())
        )
    )
    # The files whose relative paths are taken from their own directory.
    operators_files = the_operators_files(trees)
    overlay = (
        _load_overlay(
            overlay_config_path, source_dir, permit_base, refuse_env, operators_files
        )
        if overlay_config_path is not None
        else None
    )
    if overlay is not None:
        _refuse_unless_the_operators(
            overlay,
            scanned_root
            if scanned_root is not None
            else (source_dir if source_dir is not None else Path.cwd()),
        )
    config = _resolve_config(
        config_path,
        source_dir,
        fallback_to_default,
        config_overrides,
        permit_base,
        chain,
        documents,
        refuse_env=refuse_env,
        overlay=overlay,
        names=names,
        untrusted_config=untrusted_config,
        anchor_paths=None if untrusted_config else operators_files,
        named=named,
        spelled=spelled,
        merged=merged,
    )
    if config is None:
        return config
    default_document = default_config_document()
    default_chain = list(default_document.chain) if default_document else []
    default_names = dict(default_document.names) if default_document else {}
    if not chain and default_document is not None:
        # No file was read, so the config is get_default_config(): ASH_CONFIG's
        # file when that variable names one. A file of that chain under the MCP
        # workspace root is a client's, and is checked as one named with
        # --config is. The operator's own ASH_CONFIG is not checked.
        delivered = by_every_name(config_is_client_supplied, default_names)
        if any(delivered(path) for path in default_document.documents):
            documents.update(default_document.documents)
            names.update(default_names)
    config = clear_client_supplied_marks(config)
    config = apply_client_config_rules(
        config,
        documents,
        rules=client_config_policy,
        trusted_config_path=trusted_config_path,
        source_dir=source_dir,
        permit_base=permit_base,
        scanned_root=scanned_root,
        all_delivered=untrusted_config,
        client_overrides=client_overrides,
        names=names,
    )
    if scanned_root is None:
        scanned_root = source_dir if source_dir is not None else Path.cwd()
    root = Path(scanned_root)
    ash_config = os.environ.get("ASH_CONFIG")
    ash_config_named = [Path(ash_config)] if ash_config else []
    # Every file of a chain is judged by its resolved path and by the names that
    # reached it, the bases' extends entries included (ResolvedConfigDocument.named).
    default_spelled = [*ash_config_named, *default_config_names()]
    config._operator_paths = _operator_paths(
        chain or default_chain,
        [*named, *spelled] if chain else default_spelled,
        named if chain else ash_config_named,
        root,
        merged[0] if merged else None,
        untrusted=untrusted_config,
        overrides=[] if client_overrides else config_overrides,
    )
    # A file is not the operator's when the scanned repository could have written
    # it (repository_written: inside any git checkout or the scan root, under any
    # name), and when it is inside the scanned tree or an MCP client delivered it
    # (_not_the_operators). Either rule makes it untrusted.
    default_written = repository_written(default_chain, root, default_spelled)
    default_in_tree = default_written + [
        path
        for path in _not_the_operators(default_chain, trees, default_names)
        if path not in default_written
    ]
    if chain:
        if untrusted_config:
            in_tree = list(chain)
        else:
            written = repository_written(chain, root, [*named, *spelled])
            in_tree = written + [
                path
                for path in _not_the_operators(chain, trees, names)
                if path not in written
            ]
    else:
        # With no config file, the config is get_default_config(): ASH_CONFIG's
        # file when that variable names one, which can be untrusted too.
        in_tree = default_in_tree
    if client_overrides:
        # Named in the warnings as the source of what is confined.
        in_tree = [*in_tree, Path("config_overrides")]
    if not in_tree:
        return config
    operator = _load_operator_config(
        trusted_config_path, source_dir, permit_base, operators_files
    )
    own_mode = False
    if (
        operator is not None
        and not repository_written(
            operator.chain, root, [Path(trusted_config_path), *operator.named]
        )
        and not _not_the_operators(operator.chain, trees, operator.names)
    ):
        trusted = operator.config
    else:
        trusted = AshConfig() if default_in_tree else get_default_config()
        # A file that may grant, made untrusted only by a base it extends, keeps
        # the sandbox settings it writes itself.
        if default_in_tree and default_config_chain():
            trusted, wrote_mode = _with_own_sandbox(
                trusted,
                default_config_chain()[-1],
                root,
                ash_config_named,
                trees,
                default_names,
            )
            # ASH_CONFIG's own mode is the floor only when no operator file sets
            # one: below, the floor is the operator file's mode when there is one.
            own_mode = own_mode or (wrote_mode and operator is None)
        if operator is not None:
            trusted, wrote_mode = _with_own_sandbox(
                trusted,
                operator.chain[-1],
                root,
                [Path(trusted_config_path)],
                trees,
                operator.names,
            )
            own_mode = own_mode or wrote_mode
    # The same for the config file the scan selected: an operator's --config
    # outside every checkout that extends a base inside one.
    if chain and not untrusted_config:
        trusted, wrote_mode = _with_own_sandbox(
            trusted, chain[-1], root, named, trees, names
        )
        own_mode = own_mode or wrote_mode
    # The operator's mode is a floor wherever its file lives: a mode other than off
    # grants nothing, so an operator file in the tree may still turn the sandbox on.
    # Before the overrides, so `--sandbox off` still turns it off. A mode a file
    # that may grant writes itself is the operator's choice, `off` included.
    if trusted.sandbox.mode == "off" and not own_mode:
        trusted.sandbox.mode = (
            operator.config.sandbox.mode
            if operator is not None
            else get_default_config().sandbox.mode
        )
    # The overrides that count as the operator's choice, replayed onto the trusted
    # base below. Under the MCP server (``client_config_policy`` set) they are the
    # client's: the workspace tools' config_overrides, already held to the
    # session's allowlist. An allowlist that lets a client change a field does
    # not make the client's value the operator's, so none is replayed there.
    operator_overrides = (
        list(config_overrides or [])
        if client_config_policy is None and not client_overrides
        else []
    )
    confine_to_trusted_base(
        config,
        trusted,
        operator_overrides,
        Path(scanned_root),
        in_tree,
        in_tree_documents=[documents[path] for path in in_tree if path in documents],
    )
    # Not one of confine_to_trusted_base's steps: ash merge takes the verdict
    # settings, these among them, from the shards (cli/merge.py).
    confine_content_db_staleness(config, trusted, operator_overrides, in_tree)
    # Nor these: a scan's own settings, which no merge reads.
    reason = CLIENT_SUPPLIED if untrusted_config else REPOSITORY_WRITTEN
    confine_detect_secrets_settings(
        config, trusted, operator_overrides, in_tree, reason
    )
    confine_honor_ignore_files(config, trusted, operator_overrides, in_tree, reason)
    confine_archive_limits(config, trusted, operator_overrides, in_tree)
    return config


def confine_to_trusted_base(
    config: AshConfig,
    trusted: AshConfig,
    operator_overrides: Sequence[str],
    scanned_root: Path,
    in_tree: Sequence[Path],
    source: UntrustedSource = IN_TREE_OR_DELIVERED,
    in_tree_documents: Sequence[Any] = (),
) -> None:
    """Replace what a config that is not the operator's may not choose, in place.

    The steps ``resolve_config`` runs for a config built from a file inside the
    scanned tree or one an MCP client delivered, in order: the sandbox grants
    (``sandbox_grants``), ``ash_plugin_modules`` (``plugin_module_trust``), the
    reporters' destinations and whether the off-host reporters run
    (``reporter_trust``), the scanners' own config files, and every scanner's
    and converter's ``tool_version`` (``tool_config_trust``). Each takes the
    value from ``trusted`` with the
    operator's overrides replayed onto it, and names what it ignored in one
    warning. ``ash merge`` runs the same steps on the config a shard recorded,
    with its own ``source``, so a step added here applies to both.

    Args:
        config: The config to confine.
        trusted: The trusted base: the defaults, or the operator's config, without
            ``operator_overrides``.
        operator_overrides: The overrides that are the operator's choice.
        scanned_root: The tree the plugin module check is made against.
        in_tree: The files ``config`` was built from that are not the operator's,
            named in the warnings.
        source: Why those files are not the operator's, and the fix, for the
            warnings.
        in_tree_documents: Those files' documents as they were parsed, so the
            reporter step's warning quotes a section as they spelled it where the
            merge kept another spelling (the operator's, in workspace mode).
    """
    # Only an override under `sandbox` can change the sandbox section, and replaying
    # the rest onto the defaults could fail where the config file supplied the
    # section they write into.
    sandbox_overrides = [
        override
        for override in operator_overrides
        if override.partition("=")[0].removesuffix("+").split(".")[0] == "sandbox"
    ]
    if sandbox_overrides:
        trusted = apply_config_overrides(trusted, sandbox_overrides)
    files = list(in_tree)
    confine_sandbox_grants(config.sandbox, trusted.sandbox, files, source=source)
    confine_plugin_modules(
        config, trusted, operator_overrides, Path(scanned_root), files, source=source
    )
    confine_reporter_destinations(
        config,
        trusted,
        operator_overrides,
        files,
        source=source,
        in_tree_documents=in_tree_documents,
    )
    confine_scanner_config_files(
        config, trusted, operator_overrides, files, source=source
    )
    confine_tool_versions(config, trusted, operator_overrides, files, source=source)


def _is_a_client_file(path: Path | str) -> bool:
    """Whether ``path`` is a file an MCP client delivered, by any name on its way."""
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    return config_is_client_supplied(Path(path))


def _has_a_client_file(document: Any) -> bool:
    """Whether a file of ``document``'s chain is one an MCP client delivered."""
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    delivered = by_every_name(config_is_client_supplied, document.names)
    return any(delivered(path) for path in document.chain)


#: Pydantic error types whose message may repeat the value being validated: a
#: validator's own ``ValueError`` or assertion. Reported by type alone for a
#: client's file.
_MESSAGES_THAT_QUOTE = frozenset({"value_error", "assertion_error"})


#: Stands for a location segment the schema does not name: a key from the file.
_UNNAMED_KEY = "<key>"


def _without_optional(annotation: Any) -> Any:
    """``annotation`` with ``Optional`` and ``Annotated`` removed, when one type is left."""
    while True:
        args = [arg for arg in get_args(annotation) if arg is not type(None)]
        origin = get_origin(annotation)
        if origin is Annotated or (origin in (Union, UnionType) and len(args) == 1):
            annotation = args[0]
            continue
        return annotation


def _below(annotation: Any, keyed: bool) -> Any:
    """What one segment below ``annotation`` reaches: a list's item, or a mapping's value."""
    annotation = _without_optional(annotation)
    args = get_args(annotation)
    origin = get_origin(annotation)
    if origin in (list, tuple, set, frozenset) and not keyed:
        return args[0] if args else None
    if origin is dict and keyed:
        return args[1] if len(args) == 2 else None
    return None


def _schema_location(model: Any, loc: Iterable[Any]) -> str:
    """``loc`` with each segment the schema does not name replaced by ``<key>``.

    A field name or alias of the model reached so far, and a list index, are the
    schema's; anything else is a key from the file (a mapping's key, or a key
    ``extra="forbid"`` refuses), which a client's file may hold without the
    client having written it.
    """
    parts: List[str] = []
    shape: Any = model
    for segment in loc:
        if isinstance(segment, int):
            parts.append(str(segment))
            shape = _below(shape, keyed=False)
            continue
        current = _without_optional(shape)
        fields = getattr(current, "model_fields", None)
        named = None
        if isinstance(fields, dict):
            for name, info in fields.items():
                if segment in (name, info.alias):
                    named = info
                    break
        if named is not None:
            parts.append(str(segment))
            shape = named.annotation
        else:
            parts.append(_UNNAMED_KEY)
            shape = _below(shape, keyed=True)
    return ".".join(parts) or "(top level)"


def unquoted_validation_problems(
    error: ValidationError, model: Any = None
) -> List[str]:
    """Each problem in ``error`` as its location and pydantic's message, without the value.

    For a validator's own error (``_MESSAGES_THAT_QUOTE``), only its type. With
    ``model``, the model that was validated, a location segment its schema does
    not name is shown as ``<key>`` (``_schema_location``). Shared with the
    workspace policy file (``workspace/policy.py``), which a client can supply
    too.
    """
    problems = []
    for item in error.errors(include_url=False, include_input=False):
        loc = item.get("loc", ())
        where = (
            _schema_location(model, loc)
            if model is not None
            else ".".join(str(part) for part in loc) or "(top level)"
        )
        kind = item.get("type", "")
        what = (
            f"invalid value ({kind})" if kind in _MESSAGES_THAT_QUOTE else item["msg"]
        )
        problems.append(f"{where}: {what}")
    return problems


def _client_validation_error(
    config_path: Path | str,
    error: ValidationError,
    layered_over: Optional[Path] = None,
) -> ASHConfigValidationError:
    """The validation error for a client's file: where each problem is, and what kind.

    Pydantic's own text repeats each value it rejected, which for a file a
    client delivered or named (or a file a link of theirs reaches) is text the
    client may not have written. So the message gives each problem's location
    and pydantic's message for it, without the value, and for a validator's own
    error (``_MESSAGES_THAT_QUOTE``) only its type.
    """
    problems = unquoted_validation_problems(error, AshConfig)
    layered = (
        f" with '{describe_config_path(layered_over)}' layered over it"
        if layered_over is not None
        else ""
    )
    return ASHConfigValidationError(
        f"Configuration validation failed for '{describe_config_path(Path(config_path))}'"
        f"{layered}: {len(problems)} problem(s): {'; '.join(problems)}. The values are not "
        "shown because an MCP client supplied the file. Run 'ash config lint' to "
        "identify and fix issues."
    )


def _unquoted_load_error(config_path: Path | str, error: Exception) -> str:
    """Why a client's config file could not be parsed, without quoting it."""
    mark = getattr(error, "problem_mark", None)
    where = (
        f" at line {mark.line + 1}, column {mark.column + 1}"
        if mark is not None
        else ""
    )
    return (
        f"{describe_config_path(Path(config_path))} could not be parsed "
        f"({type(error).__name__}{where})"
    )


def _not_the_operators(
    paths: Iterable[Path],
    trees: Iterable[Path],
    names: Optional[ChainNames] = None,
) -> List[Path]:
    """The files of ``paths`` that are not the operator's.

    Those inside a scanned tree, which the repository wrote, and those an MCP
    client delivered (``cli/mcp/sandbox.config_is_client_supplied``), whoever
    names them: a ``--config`` or ``ASH_CONFIG`` under the MCP workspace root is
    a client's file even on the CLI, scanning another directory. Each file is
    judged by its own path and by each path in ``names`` it was reached by, so a
    file reached through a link the repository or a client wrote is theirs.
    """
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    paths = list(paths)
    inside = files_inside(paths, trees, names)
    delivered = by_every_name(config_is_client_supplied, names)
    return inside + [path for path in paths if path not in inside and delivered(path)]


def confine_honor_ignore_files(
    config: AshConfig,
    trusted: AshConfig,
    config_overrides: Optional[List[str]],
    in_tree: List[Path],
    reason: str = REPOSITORY_WRITTEN,
) -> None:
    """Take ``honor_ignore_files`` from the trusted base, never from an untrusted file.

    The setting decides whether the scanned repository's own ``.gitignore`` and
    ``.ignore`` files shrink the scan set, so the repository must not choose it in
    either direction. Its value comes from the trusted base (the defaults, or the
    operator's config outside the tree) with the ``--config-overrides`` entries for
    it replayed on top, the way the sandbox grants and ``ash_plugin_modules`` are
    decided. A different value in the in-tree file is replaced, with one warning
    naming the key and the file.

    Args:
        config: The resolved AshConfig, changed in place.
        trusted: The trusted base ``resolve_config`` built.
        config_overrides: ``--config-overrides``; only the entries for this key are
            replayed.
        in_tree: The repository-written config files (or the MCP client's
            upload), named in the warning.
        reason: Why those files may not choose it, for the warning.
    """
    key_overrides = [
        override
        for override in config_overrides or []
        if override.partition("=")[0].removesuffix("+").strip().replace("-", "_")
        == "honor_ignore_files"
    ]
    if key_overrides:
        trusted = apply_config_overrides(trusted, key_overrides)
    if config.honor_ignore_files == trusted.honor_ignore_files:
        return
    config.honor_ignore_files = trusted.honor_ignore_files
    files = ", ".join(describe_config_path(path) for path in in_tree)
    ASH_LOGGER.warning(
        f"Ignoring honor_ignore_files from {files}: {reason}, and whether the "
        "scanned repository's own .gitignore and .ignore files are honored is the "
        "operator's choice. Using honor_ignore_files: "
        f"{str(trusted.honor_ignore_files).lower()}. {KEEP_A_SETTING} Or turn it "
        "off with --no-honor-ignore-files."
    )


def _operator_paths(
    chain: List[Path],
    names: List[Path],
    root_names: List[Path],
    scan_root: Path,
    document: Any,
    *,
    untrusted: bool,
    overrides: Optional[List[str]],
) -> OperatorPaths:
    """Which tool paths in the config the operator named; see path_trust.

    The chain's merged ``document`` (or, with no config file, the default
    config's) when every file of the chain is the operator's
    (:func:`_operator_wrote`, under every name); only the selected file's own
    document when that file is the operator's and a base it extends is not; and
    what ``overrides`` set.
    """
    record = OperatorPaths(overrides=parse_overrides(overrides))
    if untrusted:
        return record
    if all(_operator_wrote(path, scan_root) for path in [*chain, *names]):
        if document is None:
            document = get_default_config().model_dump()
        record.documents = [document]
    elif chain and all(
        _operator_wrote(path, scan_root) for path in [chain[-1], *root_names]
    ):
        try:
            own = read_config_file(chain[-1])
        except Exception:  # noqa: BLE001 - the chain was read already; nothing to add
            own = None
        if isinstance(own, dict):
            record.documents = [own]
    return record


def _operator_wrote(path: Path, scan_root: Path) -> bool:
    """Whether the tool paths config file ``path`` names are the operator's.

    By the tier ``repository_written`` gives config files, the one the five
    confinements use (``sandbox_grants.untrusted_path``: inside any git checkout,
    or inside the scan root, by any name): a file in an ops checkout beside the
    scanned one may not grant, so the paths it names are not the operator's
    either. Nor are those of a file an MCP client delivered or a session profile
    a client's patch changed (``path_trust.operator_reason``).
    """
    return (
        not untrusted_path(Path(path), scan_root)
        and operator_reason(path, scan_root) is None
    )


def _own_sandbox_settings(path: Path) -> Dict[str, Any]:
    """The ``sandbox`` settings ``path`` writes itself, without its ``extends`` bases.

    Read from the file alone, so neither a base nor the file's own ``patch``
    operations, which edit what its bases gave it, contribute.
    """
    try:
        data = read_config_file(path)
    except Exception:  # noqa: BLE001 - the chain was read already; nothing to add
        return {}
    section = data.get("sandbox") if isinstance(data, dict) else None
    return dict(section) if isinstance(section, dict) else {}


def _with_own_sandbox(
    trusted: AshConfig,
    path: Path,
    scan_root: Path,
    lexical: List[Path],
    trees: Iterable[Path],
    names: Optional[ChainNames],
) -> Tuple[AshConfig, bool]:
    """``trusted`` with the sandbox settings ``path`` writes, when ``path`` may grant.

    ``path`` is one file of a chain that ``repository_written`` found untrusted
    because of a base: an operator's file outside every checkout that extends one
    inside. Its own settings are the operator's, and the base's are not, so only
    the file's own ``sandbox`` section joins the trusted settings. Judged by its
    resolved path and by ``lexical``, the names it was given, and, as every file
    of the chain is, by ``_not_the_operators`` over ``trees`` and ``names``: a
    file inside a scanned tree or one an MCP client delivered grants nothing, even
    outside every checkout.

    Returns the settings and whether the file wrote its own ``mode``. A section
    that does not validate on its own (one the file's ``patch`` repairs, say) adds
    nothing, so the file then keeps no grants, as before this rule.
    """
    if repository_written([path], scan_root, lexical) or _not_the_operators(
        [path], trees, names
    ):
        return trusted, False
    own = _own_sandbox_settings(path)
    if not own:
        return trusted, False
    current = trusted.sandbox.model_dump()
    try:
        # deep_merge spells each key the way the trusted settings do, as merging
        # the chain did (`network-scanners` is `network_scanners`).
        sandbox = SandboxConfig.model_validate(deep_merge(current, own), strict=True)
    except ValidationError:
        return trusted, False
    keys = dict.fromkeys(current)
    wrote_mode = any(_resolve_dict_key(keys, key) == "mode" for key in own)
    updated = trusted.model_copy()
    updated.sandbox = sandbox
    return updated, wrote_mode


class OperatorConfig(NamedTuple):
    """The operator's config as ``_load_operator_config`` read it."""

    #: The validated config.
    config: AshConfig
    #: The files it was built from, its bases first (``ResolvedConfigDocument.chain``).
    chain: List[Path]
    #: The names those files were reached by, in the chain's order
    #: (``ResolvedConfigDocument.named``).
    named: List[Path]
    #: The same names by file (``ResolvedConfigDocument.names``).
    names: Dict[Path, Tuple[Path, ...]]


def _load_operator_config(
    trusted_config_path: Path | str | None,
    source_dir: Path | str | None,
    permit_base: Optional[Callable[[Path], bool]],
    anchor_paths: Optional[AnchorPaths] = None,
) -> Optional[OperatorConfig]:
    """The operator's config file, the files it was built from, and their names.

    None only when no operator config was named. One that was named is loaded
    the way _resolve_config loads a config file, and refused the same way when it
    is missing, does not load or does not validate: dropping it would take the
    sandbox grants from the defaults instead of from the file the operator named.
    """
    if trusted_config_path is None:
        return None
    path = Path(trusted_config_path)
    document = read_config_document(
        path,
        confine_to=default_confinement_root(path, source_dir),
        permit_base=permit_base,
        anchor_relative_paths=anchor_paths,
    )
    return OperatorConfig(
        config=validate_config_document(document, path),
        chain=list(document.chain),
        named=list(document.named),
        names=dict(document.names),
    )


def _load_overlay(
    overlay_config_path: Path | str,
    source_dir: Path | str | None,
    permit_base: Optional[Callable[[Path], bool]],
    refuse_env: RefuseEnv,
    anchor_paths: Optional[AnchorPaths] = None,
) -> ResolvedConfigDocument:
    """The overlay file's merged document, read as the operator's config is.

    Refused rather than skipped when it is missing, cannot be read, or does not
    validate on its own: the caller asked for its fields to be final, and
    dropping the file would scan with the project's values for them instead.
    """
    path = Path(overlay_config_path)
    if not path.is_file():
        raise ASHConfigSourceError(
            f"Config file '{describe_config_path(path)}' does not exist or is not "
            "a file."
        )
    try:
        document = resolve_config_document(
            path,
            confine_to=default_confinement_root(path, source_dir),
            permit_base=permit_base,
            refuse_env=refuse_env,
            anchor_relative_paths=anchor_paths,
        )
    except ASHConfigValidationError:
        raise
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValueError) as e:
        # json.JSONDecodeError is a ValueError.
        raise ASHConfigSourceError(
            f"Config file '{describe_config_path(path)}' could not be read: {e}"
        ) from e
    try:
        AshConfig.model_validate(document.data, strict=True)
    except ValidationError as e:
        raise ASHConfigValidationError(
            f"Configuration validation failed for '{describe_config_path(path)}': "
            f"{str(e)}. Run 'ash config lint' to identify and fix issues."
        ) from e
    return document


def _refuse_unless_the_operators(
    overlay: ResolvedConfigDocument, scanned_root: Path | str
) -> None:
    """Refuse ``overlay`` when a file it is built from is not the operator's.

    The overlay is final over every project's own config, so a file of its chain
    inside the scanned tree, or one an MCP client delivered
    (``_not_the_operators``), would make that file's settings final over the tree
    that wrote it. Refused rather than confined: confining it field by field
    would still leave every field outside the confined settings final.
    """
    trees = scanned_trees(Path(scanned_root))
    others = _not_the_operators(overlay.chain, trees, overlay.names)
    if not others:
        return
    root = overlay.chain[-1]
    reasons = []
    places: List[str] = []
    for path in others:
        reason, place = _whose_file(path, trees, overlay.names)
        reasons.append(f"'{describe_config_path(path)}' {reason}")
        if place not in places:
            places.append(place)
    # A file of the scanned tree is refused for the repository's tier, which the
    # confinement remedy speaks to; one an MCP client delivered is not.
    of_the_repository = any(
        tree_holding(path, trees, overlay.names) is not None for path in others
    )
    raise ASHConfigValidationError(
        f"The operator config '{describe_config_path(root)}' is layered over each "
        "project's own config, so every file it is built from must be the "
        f"operator's, and {'; '.join(reasons)}. Move the config, and every base "
        f"it extends, outside {' and outside '.join(places)}."
        + (f" {KEEP_A_SETTING}" if of_the_repository else "")
    )


def _whose_file(
    path: Path, trees: List[Path], names: Optional[ChainNames]
) -> Tuple[str, str]:
    """Why ``path``, one of ``_not_the_operators``, is not the operator's, and the
    place to move it out of: the scanned checkout (or the scanned directory, when
    it is in no checkout) it is inside or was reached through, else the MCP
    workspace root it was delivered under."""
    from automated_security_helper.cli.mcp.sandbox import shared_workspace_root

    tree = tree_holding(path, trees, names)
    if tree is None:
        shared = shared_workspace_root()
        place = "the MCP workspace root" + (
            f" '{shared.as_posix()}'" if shared is not None else ""
        )
        return f"was delivered by an MCP client, under {place}", place
    # A scanned tree is a checkout's top, or the scan root when it is in none
    # (sandbox_grants._outermost_checkout).
    in_checkout = os.path.lexists(tree / ".git")
    kind = "the checkout" if in_checkout else "the scanned directory"
    place = f"{kind} '{tree.as_posix()}'"
    if any(is_within(path, each) for each in trees):
        return f"is inside {place}", place
    return f"is reached through a link inside {place}", place


def check_operator_config(
    operator_config_path: Path | str,
    scanned_root: Path | str,
    permit_base: Optional[Callable[[Path], bool]] = None,
    remote_client: bool = False,
) -> None:
    """Refuse an operator config that cannot be layered over a workspace's projects.

    The checks ``resolve_config`` makes of an ``overlay_config_path``: the file
    must exist, resolve and validate on its own, and every file of its chain must
    be the operator's (``_refuse_unless_the_operators``). Workspace resolution
    runs them once for the whole workspace, so a project with no config of its
    own, which uses the operator's file alone, is refused with the rest.

    Raises:
        ASHConfigValidationError: The config cannot be used; exit 3 in workspace
            mode.
    """
    overlay = _load_overlay(
        operator_config_path, None, permit_base, env_refused_for(remote_client)
    )
    _refuse_unless_the_operators(overlay, scanned_root)


def operator_config_digest(operator_config_path: Path | str) -> str:
    """A digest of the bytes of every file ``operator_config_path`` is built from.

    Workspace resolution records it with the plan, and each project's scan
    compares it before layering the file again, so a file that changed between
    the plan and the scan (another call rewriting a session's profile, an edit)
    is refused rather than scanned with settings ``--dry-run`` did not report.
    """
    path = Path(operator_config_path)
    document = resolve_config_document(path, confine_to=default_confinement_root(path))
    digest = hashlib.sha256()
    for member in document.chain:
        data = Path(member).read_bytes()
        digest.update(f"{Path(member).as_posix()}\0{len(data)}\0".encode("utf-8"))
        digest.update(data)
    return digest.hexdigest()


def _overlaid(
    overlay: ResolvedConfigDocument,
    chain: List[Path],
    documents: Dict[Path, Any],
    names: Optional[Dict[Path, Tuple[Path, ...]]] = None,
) -> AshConfig:
    """The overlay file alone, in place of the default config."""
    chain.extend(overlay.chain)
    documents.update(overlay.documents)
    if names is not None:
        names.update(overlay.names)
    return AshConfig.model_validate(overlay.data, strict=True)


def _resolve_config(
    config_path: Path | str | None,
    source_dir: Path | str | None,
    fallback_to_default: bool,
    config_overrides: Optional[List[str]],
    permit_base: Optional[Callable[[Path], bool]],
    chain: List[Path],
    documents: Dict[Path, Any],
    refuse_env: Optional[RefuseEnv] = None,
    overlay: Optional[ResolvedConfigDocument] = None,
    names: Optional[Dict[Path, Tuple[Path, ...]]] = None,
    untrusted_config: bool = False,
    anchor_paths: Optional[AnchorPaths] = None,
    named: Optional[List[Path]] = None,
    spelled: Optional[List[Path]] = None,
    merged: Optional[List[Any]] = None,
) -> AshConfig:
    """resolve_config without the sandbox confinement.

    Appends every file read to ``chain``, resolved, each file's parsed document to
    ``documents``, and the paths each was reached by to ``names``. It also
    appends the root config file's path as it was named (passed or discovered)
    to ``named``, every file read by the path that named it
    (``ResolvedConfigDocument.named``) to ``spelled``, and the merged document,
    before any override, to ``merged``.
    ``anchor_paths`` accepts the files whose relative paths are taken from their
    own directory (``config/operator_paths.py``).
    ``refuse_env`` decides which files of the chain resolve no ``!ENV``
    (``config_sources``). ``overlay`` is ``overlay_config_path``'s document,
    merged over the selected file's, and used alone wherever the default config
    would be returned. ``untrusted_config`` is resolve_config's: with it, or
    when a file of the chain is a client's, an error quotes nothing the files
    hold (``_client_validation_error``).
    """

    def fallback(default: Optional[AshConfig]) -> Optional[AshConfig]:
        # The default config, or the overlay alone in its place: falling back to
        # the defaults would drop the fields the overlay makes final.
        if overlay is None or default is None:
            return default
        return _overlaid(overlay, chain, documents, names)

    # The overlay's file, once it has been merged into the selected file's
    # document; named in a validation error.
    layered_over: Optional[Path] = None
    try:
        # Start with default config
        config = get_default_config() if fallback_to_default else None
        # An explicit config_path has to survive a missing source_dir. source_dir
        # only drives *discovery* of a config file; when the caller already named
        # one, there is nothing to discover and no reason to bail out to the
        # default. Testing source_dir alone here meant `ash report --config
        # <file>` accepted the option and then reported against default settings,
        # because cli/report.py passes config_path with no source_dir (as does
        # cli/config.py). Below, source_dir falls back to Path.cwd(), which is
        # only used to resolve a relative config_path at that point.
        if source_dir is None and config_path is None and fallback_to_default:
            ASH_LOGGER.verbose(
                "source_dir and config_path are both null, returning the default config"
            )
            config = fallback(config)
            # Apply overrides to default config if provided
            if config_overrides:
                return apply_config_overrides(config, config_overrides)
            return config

        # Only a source_dir the caller passed may widen where `extends` bases
        # may live. The cwd fallback below must not: `ash report --config
        # <file>` run from a home directory would otherwise let that file's
        # bases reach anywhere under it.
        confinement_source_dir = source_dir

        # Resolve cwd default at call time, not import time.
        if source_dir is None:
            source_dir = Path.cwd()

        if isinstance(source_dir, str):
            source_dir = Path(source_dir)

        # Check for config file if not explicitly provided. The precedence, and
        # why sources are selected rather than merged, is documented in
        # config/config_sources.py.
        confine_to = None
        # The sources discovery found and did not use. Their settings are not
        # applied, so they are reported with the scan's results as well as logged.
        ignored_sources: List[str] = []
        if config_path is None:
            ASH_LOGGER.verbose(
                "No configuration file provided, checking for default paths"
            )
            discovery = discover_config_source(source_dir, permit=permit_base)
            ignored_sources = [
                LoggedResolutionWarning(message)
                for message in log_config_discovery(discovery)
            ]
            if discovery.selected is not None:
                config_path = discovery.selected.path
                # A caller's gate covers the file found too: it may be a link
                # out of source_dir (config_sources, "Base paths").
                check_discovered_source(config_path, permit_base)
                confine_to = source_dir
                ASH_LOGGER.verbose(
                    f"Found configuration file at: {config_path.as_posix()}"
                )

        if config_path is None:
            if fallback_to_default:
                ASH_LOGGER.verbose(
                    "Configuration file not found or provided, using default config"
                )
                config = fallback(config)
                # Apply overrides to default config if provided
                if config_overrides:
                    return apply_config_overrides(config, config_overrides)
                return config  # Return default config if no config file found
            else:
                raise ValueError("Configuration file not found or provided")

        # A config file that was named or discovered and cannot be loaded refuses
        # resolution (read_config_document below); only "no config file at all"
        # above falls back to the defaults.
        if isinstance(config_path, str) and not config_path.strip():
            raise _empty_config_path()

        # Process config file
        try:
            config_path = (
                Path(config_path) if not isinstance(config_path, Path) else config_path
            )
            ASH_LOGGER.debug(f"Loading configuration from {config_path.as_posix()}")

            ASH_LOGGER.debug("Validating file config")
            if confine_to is None:
                confine_to = default_confinement_root(
                    config_path, confinement_source_dir
                )
                if confinement_source_dir is not None:
                    ignored_sources = _warnings_when_discovered(
                        config_path, source_dir, permit_base
                    )
            # AshConfig.from_file, keeping the list of files the config came from.
            document = read_config_document(
                Path(config_path),
                confine_to=confine_to,
                permit_base=permit_base,
                refuse_env=refuse_env,
                anchor_relative_paths=anchor_paths,
                unquoted=bool(untrusted_config),
            )
            data = document.data
            if overlay is not None and isinstance(data, dict):
                # A document that is not a mapping is left as it is, so its
                # validation error is still raised rather than replaced by the
                # overlay's content.
                data = deep_merge(data, overlay.data, AshConfig)
                layered_over = overlay.chain[-1]
            client_chain = untrusted_config or _has_a_client_file(document)
            try:
                config = AshConfig.model_validate(data, strict=True)
            except ValidationError as e:
                if not client_chain:
                    raise
                raise _client_validation_error(
                    config_path, e, layered_over=layered_over
                ) from None
            chain.extend(document.chain)
            documents.update(document.documents)
            if names is not None:
                names.update(document.names)
            if named is not None:
                named.append(Path(config_path))
            if spelled is not None:
                spelled.extend(document.named)
            if merged is not None:
                # What the config was validated from: the overlay merged in.
                merged.append(data)
            if overlay is not None:
                chain.extend(overlay.chain)
                documents.update(overlay.documents)
                if names is not None:
                    names.update(overlay.names)
                if spelled is not None:
                    spelled.extend(overlay.named)
            ASH_LOGGER.debug(f"Loaded config from file: {config_path}")

            # Apply config overrides if provided
            if config_overrides:
                config = apply_config_overrides(config, config_overrides)

            config._resolution_warnings.extend(ignored_sources)
            return config

        except ValidationError as e:
            ASH_LOGGER.error(f"Configuration validation failed: {str(e)}")
            layered = (
                f" with '{describe_config_path(layered_over)}' layered over it"
                if layered_over is not None
                else ""
            )
            raise ASHConfigValidationError(
                f"Configuration validation failed for "
                f"'{describe_config_path(config_path)}'{layered}: {str(e)}. "
                "Run 'ash config lint' to identify and fix issues."
            ) from e

        return config

    except ASHConfigValidationError:
        raise
    except Exception as e:
        if not fallback_to_default:
            raise e
        # Refused, never answered with the default config: a scan with the
        # defaults in place of a config that failed to resolve runs with that
        # config's suppressions and settings switched off and reports success.
        ASH_LOGGER.error(f"Unexpected error in resolve_config: {str(e)}")
        raise ASHConfigValidationError(
            f"The configuration could not be resolved: {type(e).__name__}: {e}"
        ) from e
    except BaseException as e:
        # pydantic-core reports a Rust panic as pyo3's PanicException, which is
        # a BaseException and so passes `except Exception`. Refused the same way;
        # anything else (KeyboardInterrupt, SystemExit) propagates.
        if type(e).__name__ != "PanicException" or type(e).__module__ != "pyo3_runtime":
            raise
        raise ASHConfigValidationError(
            f"The configuration could not be resolved: {type(e).__name__}: {e}"
        ) from e
