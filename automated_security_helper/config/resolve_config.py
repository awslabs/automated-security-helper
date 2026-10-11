import errno
import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from pydantic import ValidationError
import yaml
from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
from automated_security_helper.config.config_sources import (
    ResolvedConfigDocument,
    _resolve_dict_key,
    deep_merge,
    default_confinement_root,
    describe_config_path,
    discover_config_source,
    discovery_warnings,
    log_config_discovery,
    read_config_file,
    resolve_config_document,
)
from automated_security_helper.config.default_config import (
    default_config_chain,
    default_config_names,
    get_default_config,
)
from automated_security_helper.config.path_trust import (
    OperatorPaths,
    operator_reason,
    parse_overrides,
)
from automated_security_helper.config.plugin_module_trust import (
    confine_plugin_modules,
)
from automated_security_helper.config.sandbox_grants import (
    REPOSITORY_WRITTEN,
    confine_sandbox_grants,
    repository_written,
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
from automated_security_helper.utils.log import ASH_LOGGER


def find_config_file(search_dir: Path | None = None) -> Optional[Path]:
    """Return the config source a scan of search_dir would use, or None.

    Applies the discovery precedence in ``config_sources.discover_config_source``:
    ASH_CONFIG_FILE_NAMES in order (each in search_dir, then search_dir/.ash/),
    then the ashrc names, then a pyproject.toml with a [tool.ash] table. The
    result can therefore be a TOML file; callers that edit the file in place
    must check its format.
    """
    if search_dir is None:
        search_dir = Path.cwd()
    selected = discover_config_source(search_dir).selected
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
    if not path.is_file():
        raise _config_file_not_loadable(path)
    return path


def read_config_document(
    config_path: Path | str,
    confine_to: Optional[Path] = None,
    permit_base: Optional[Callable[[Path], bool]] = None,
    *,
    log_failure: bool = True,
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

    ``log_failure`` False leaves out the "Failed to load configuration file" log
    line, for a caller that reads the file ahead of the resolution that reports
    the same failure.
    """
    path = check_config_path(config_path)
    try:
        return resolve_config_document(
            path, confine_to=confine_to, permit_base=permit_base
        )
    except (OSError, UnicodeDecodeError, yaml.YAMLError, json.JSONDecodeError) as e:
        # json.JSONDecodeError and UnicodeDecodeError are ValueErrors, but a bare
        # ValueError is not caught: pydantic's ValidationError is one too.
        if log_failure:
            ASH_LOGGER.error(f"Failed to load configuration file: {str(e)}")
        verb = "read" if isinstance(e, OSError) else "parse"
        raise ASHConfigSourceError(
            f"could not {verb} {describe_config_path(path)}: {e}"
        ) from e


def _warnings_when_discovered(config_path: Path, source_dir: Path) -> List[str]:
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
    root = source_dir.resolve()
    if config_path.parent.resolve() not in (root, root / ".ash"):
        return []
    try:
        discovery = discover_config_source(source_dir)
    except ASHConfigValidationError:
        return []
    selected = discovery.selected
    if selected is None or selected.path.resolve() != config_path.resolve():
        return []
    return discovery_warnings(discovery)


def _validate_config_document(
    document: ResolvedConfigDocument, config_path: Path | str
) -> AshConfig:
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
    )
    return _validate_config_document(document, config_path)


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
        key_path, separator, value = override.partition("=")
        if not separator or not key_path.strip():
            raise ASHConfigValidationError(
                f"Invalid config override: '{override}'. "
                "Expected format: key.path=value"
            )
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
            actually selected can replace it (workspace mode's default config,
            which a project's own config file replaces). Used in place of the
            defaults as the trusted base the grants come from, unless it is
            inside the scanned tree as well.
        untrusted_config: The selected config file was written by the caller,
            not the operator: an MCP client's upload named as ``config_path``.
            Every file of its chain is then treated as a file inside the scanned
            tree is, wherever it is: its sandbox grants come from the trusted
            base instead, its ``network_scanners`` list only removes network,
            and its ``sandbox.mode`` cannot turn off or replace a mode the
            trusted base sets. Its ``ash_plugin_modules`` are limited the same way
            as an in-tree file's (``config/plugin_module_trust.py``).
        client_overrides: ``config_overrides`` came from an MCP client (a
            workspace tool's), not the operator, so a tool path they name is not
            the operator's (``path_trust.OperatorPaths``).

    Returns:
        The resolved AshConfig object

    Raises:
        ASHConfigValidationError: The config could not be resolved (exit 3 from
            ``ash scan``). ``ASHConfigSourceError``, a subclass, when a config file
            could not be loaded at all.
    """
    chain: List[Path] = []
    named: List[Path] = []
    spelled: List[Path] = []
    merged: List[Any] = []
    config = _resolve_config(
        config_path,
        source_dir,
        fallback_to_default,
        config_overrides,
        permit_base,
        chain,
        named,
        spelled,
        merged,
    )
    if config is None:
        return config
    if scanned_root is None:
        scanned_root = source_dir if source_dir is not None else Path.cwd()
    root = Path(scanned_root)
    ash_config = os.environ.get("ASH_CONFIG")
    ash_config_named = [Path(ash_config)] if ash_config else []
    # Every file of a chain is judged by its resolved path and by the names that
    # reached it, the bases' extends entries included (ResolvedConfigDocument.named).
    default_spelled = [*ash_config_named, *default_config_names()]
    config._operator_paths = _operator_paths(
        chain or default_config_chain(),
        [*named, *spelled] if chain else default_spelled,
        named if chain else ash_config_named,
        root,
        merged[0] if merged else None,
        untrusted=untrusted_config,
        overrides=[] if client_overrides else config_overrides,
    )
    if chain:
        in_tree = repository_written(
            chain, root, [*named, *spelled], all_untrusted=untrusted_config
        )
        if not in_tree:
            return config
        default_in_tree = repository_written(
            default_config_chain(), root, default_spelled
        )
    else:
        # With no config file, the config is get_default_config(): ASH_CONFIG's
        # file when that variable names one, which can be untrusted too.
        in_tree = default_in_tree = repository_written(
            default_config_chain(), root, default_spelled
        )
        if not in_tree:
            return config
    operator = _load_operator_config(trusted_config_path, source_dir, permit_base)
    own_mode = False
    if operator is not None and not repository_written(
        operator[1], root, [Path(trusted_config_path), *operator[2]]
    ):
        trusted = operator[0]
    else:
        trusted = AshConfig() if default_in_tree else get_default_config()
        # A file that may grant, made untrusted only by a base it extends, keeps
        # the sandbox settings it writes itself.
        if default_in_tree and default_config_chain():
            trusted, wrote_mode = _with_own_sandbox(
                trusted, default_config_chain()[-1], root, ash_config_named
            )
            # ASH_CONFIG's own mode is the floor only when no operator file sets
            # one: below, the floor is the operator file's mode when there is one.
            own_mode = own_mode or (wrote_mode and operator is None)
        if operator is not None:
            trusted, wrote_mode = _with_own_sandbox(
                trusted, operator[1][-1], root, [Path(trusted_config_path)]
            )
            own_mode = own_mode or wrote_mode
    # The same for the config file the scan selected: an operator's --config
    # outside every checkout that extends a base inside one.
    if chain and not untrusted_config:
        trusted, wrote_mode = _with_own_sandbox(trusted, chain[-1], root, named)
        own_mode = own_mode or wrote_mode
    # The operator's mode is a floor wherever its file lives: a mode other than off
    # grants nothing, so an operator file in the tree may still turn the sandbox on.
    # Before the overrides, so `--sandbox off` still turns it off. A mode a file
    # that may grant writes itself is the operator's choice, `off` included.
    if trusted.sandbox.mode == "off" and not own_mode:
        trusted.sandbox.mode = (
            operator[0].sandbox.mode
            if operator is not None
            else get_default_config().sandbox.mode
        )
    # Only an override under `sandbox` can change the sandbox section, and replaying
    # the rest onto the defaults could fail where the config file supplied the
    # section they write into.
    sandbox_overrides = [
        override
        for override in config_overrides or []
        if override.partition("=")[0].removesuffix("+").split(".")[0] == "sandbox"
    ]
    if sandbox_overrides:
        trusted = apply_config_overrides(trusted, sandbox_overrides)
    confine_sandbox_grants(
        config.sandbox,
        trusted.sandbox,
        in_tree,
        reason=CLIENT_SUPPLIED if untrusted_config else REPOSITORY_WRITTEN,
    )
    confine_plugin_modules(
        config, trusted, config_overrides, Path(scanned_root), in_tree
    )
    return config


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
    config's) when no file of the chain is inside the scanned tree or an MCP
    client's (``path_trust.operator_reason``, under every name); only the selected
    file's own document when that file is the operator's and a base it extends is
    not; and what ``overrides`` set.
    """
    record = OperatorPaths(overrides=parse_overrides(overrides))
    if untrusted:
        return record
    if all(operator_reason(path, scan_root) is None for path in [*chain, *names]):
        if document is None:
            document = get_default_config().model_dump()
        record.documents = [document]
    elif chain and all(
        operator_reason(path, scan_root) is None for path in [chain[-1], *root_names]
    ):
        try:
            own = read_config_file(chain[-1])
        except Exception:  # noqa: BLE001 - the chain was read already; nothing to add
            own = None
        if isinstance(own, dict):
            record.documents = [own]
    return record


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
    trusted: AshConfig, path: Path, scan_root: Path, lexical: List[Path]
) -> Tuple[AshConfig, bool]:
    """``trusted`` with the sandbox settings ``path`` writes, when ``path`` may grant.

    ``path`` is one file of a chain that ``repository_written`` found untrusted
    because of a base: an operator's file outside every checkout that extends one
    inside. Its own settings are the operator's, and the base's are not, so only
    the file's own ``sandbox`` section joins the trusted settings. Judged by its
    resolved path and by ``lexical``, the names it was given.

    Returns the settings and whether the file wrote its own ``mode``. A section
    that does not validate on its own (one the file's ``patch`` repairs, say) adds
    nothing, so the file then keeps no grants, as before this rule.
    """
    if repository_written([path], scan_root, lexical):
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


def _load_operator_config(
    trusted_config_path: Path | str | None,
    source_dir: Path | str | None,
    permit_base: Optional[Callable[[Path], bool]],
) -> Optional[Tuple[AshConfig, List[Path], List[Path]]]:
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
    )
    return (
        _validate_config_document(document, path),
        list(document.chain),
        list(document.named),
    )


def _resolve_config(
    config_path: Path | str | None,
    source_dir: Path | str | None,
    fallback_to_default: bool,
    config_overrides: Optional[List[str]],
    permit_base: Optional[Callable[[Path], bool]],
    chain: List[Path],
    named: List[Path],
    spelled: List[Path],
    merged: List[Any],
) -> AshConfig:
    """resolve_config without the sandbox confinement.

    Appends every file read to ``chain``, resolved, the root config file's path as
    it was named (passed or discovered) to ``named``, every file read by the
    path that named it (``ResolvedConfigDocument.named``) to ``spelled``, and the
    merged document, before any override, to ``merged``.
    """
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
            discovery = discover_config_source(source_dir)
            ignored_sources = log_config_discovery(discovery)
            if discovery.selected is not None:
                config_path = discovery.selected.path
                confine_to = source_dir
                ASH_LOGGER.verbose(
                    f"Found configuration file at: {config_path.as_posix()}"
                )

        if config_path is None:
            if fallback_to_default:
                ASH_LOGGER.verbose(
                    "Configuration file not found or provided, using default config"
                )
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
                    ignored_sources = _warnings_when_discovered(config_path, source_dir)
            # AshConfig.from_file, keeping the list of files the config came from.
            document = read_config_document(
                Path(config_path), confine_to=confine_to, permit_base=permit_base
            )
            config = AshConfig.model_validate(document.data, strict=True)
            chain.extend(document.chain)
            named.append(Path(config_path))
            spelled.extend(document.named)
            merged.append(document.data)
            ASH_LOGGER.debug(f"Loaded config from file: {config_path}")

            # Apply config overrides if provided
            if config_overrides:
                config = apply_config_overrides(config, config_overrides)

            config._resolution_warnings.extend(ignored_sources)
            return config

        except ValidationError as e:
            ASH_LOGGER.error(f"Configuration validation failed: {str(e)}")
            raise ASHConfigValidationError(
                f"Configuration validation failed for "
                f"'{describe_config_path(config_path)}': {str(e)}. "
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
