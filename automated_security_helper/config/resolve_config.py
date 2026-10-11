import hashlib
import json
from pathlib import Path
from types import UnionType
from typing import (
    Annotated,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
    get_args,
    get_origin,
)

from pydantic import ValidationError
import yaml
from automated_security_helper.config.ash_config import AshConfig
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
    env_refused_for,
    log_config_discovery,
    resolve_config_document,
)
from automated_security_helper.config.default_config import (
    default_config_document,
    get_default_config,
)
from automated_security_helper.config.operator_paths import (
    anchor_override_paths,
    the_operators_files,
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
    confine_sandbox_grants,
    files_inside,
    scanned_trees,
)
from automated_security_helper.config.staleness_trust import (
    confine_content_db_staleness,
)
from automated_security_helper.config.untrusted_source import (
    IN_TREE_OR_DELIVERED,
    UntrustedSource,
)
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)
from automated_security_helper.utils.log import ASH_LOGGER


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
    client_config_policy: Optional[ClientConfigRules] = None,
    remote_client: bool = False,
    overlay_config_path: Path | str | None = None,
) -> AshConfig:
    """
    Load configuration from file or return default configuration.

    Args:
        config_path: Path to the configuration file
        source_dir: Source directory to search for configuration files
        fallback_to_default: Whether to fall back to default configuration if no config file is found
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
            its reporter destinations (``config/reporter_trust.py``).
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
            Where the default config would be used instead of a selected file
            (none was found, or it could not be loaded), this file is used
            alone. Workspace mode passes the operator's ``--config`` here for a
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
    """
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    if overlay_config_path is not None and untrusted_config:
        # untrusted_config treats every file of the chain as the caller's, which
        # would include the overlay, the operator's own file.
        raise ValueError("overlay_config_path cannot be combined with untrusted_config")
    if client_config_policy is None and config_overrides:
        # The operator's --config-overrides: a relative path in one is taken from
        # the working directory ASH runs in, not the scanned tree
        # (config/operator_paths.py). Anchored once here, so the config and every
        # replay onto the trusted base below read the same value.
        config_overrides = anchor_override_paths(config_overrides, Path.cwd())
    chain: List[Path] = []
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
    # Under the MCP server the overrides come from the client, held to the
    # session's allowlist; see operator_overrides below.
    client_overrides = client_config_policy is not None and bool(config_overrides)
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
    default_in_tree = _not_the_operators(default_chain, trees, default_names)
    if chain:
        in_tree = (
            list(chain) if untrusted_config else _not_the_operators(chain, trees, names)
        )
    else:
        # With no config file, the config is get_default_config(): ASH_CONFIG's
        # file when that variable names one, which can be inside the tree too.
        in_tree = default_in_tree
    if client_overrides:
        # Named in the warnings as the source of what is confined.
        in_tree = [*in_tree, Path("config_overrides")]
    if not in_tree:
        return config
    operator = _load_operator_config(
        trusted_config_path, source_dir, permit_base, operators_files
    )
    if operator is not None and not _not_the_operators(operator[1], trees, operator[2]):
        trusted = operator[0]
    else:
        trusted = AshConfig() if default_in_tree else get_default_config()
    # The operator's mode is a floor wherever its file lives: a mode other than off
    # grants nothing, so an operator file in the tree may still turn the sandbox on.
    # Before the overrides, so `--sandbox off` still turns it off.
    if trusted.sandbox.mode == "off":
        trusted.sandbox.mode = (
            operator[0].sandbox.mode
            if operator is not None
            else get_default_config().sandbox.mode
        )
    # The overrides that count as the operator's choice, replayed onto the trusted
    # base below. Under the MCP server (``client_config_policy`` set) they are the
    # client's: the workspace tools' config_overrides, already held to the
    # session's allowlist. An allowlist that lets a client change a field does
    # not make the client's value the operator's, so none is replayed there.
    operator_overrides = (
        list(config_overrides or []) if client_config_policy is None else []
    )
    confine_to_trusted_base(
        config, trusted, operator_overrides, Path(scanned_root), in_tree
    )
    # Not one of confine_to_trusted_base's steps: ash merge takes the verdict
    # settings, these among them, from the shards (cli/merge.py).
    confine_content_db_staleness(config, trusted, operator_overrides, in_tree)
    return config


def confine_to_trusted_base(
    config: AshConfig,
    trusted: AshConfig,
    operator_overrides: Sequence[str],
    scanned_root: Path,
    in_tree: Sequence[Path],
    source: UntrustedSource = IN_TREE_OR_DELIVERED,
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
        config, trusted, operator_overrides, files, source=source
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


def _load_operator_config(
    trusted_config_path: Path | str | None,
    source_dir: Path | str | None,
    permit_base: Optional[Callable[[Path], bool]],
    anchor_paths: Optional[AnchorPaths] = None,
) -> Optional[Tuple[AshConfig, List[Path], Dict[Path, Tuple[Path, ...]]]]:
    """The operator's config file, the files it was built from, and their names, or None.

    Loaded the way _resolve_config loads a config file, and refused the same way
    when it does not validate.
    """
    if trusted_config_path is None or not Path(trusted_config_path).is_file():
        return None
    path = Path(trusted_config_path)
    document = resolve_config_document(
        path,
        confine_to=default_confinement_root(path, source_dir),
        permit_base=permit_base,
        anchor_relative_paths=anchor_paths,
    )
    try:
        config = AshConfig.model_validate(document.data, strict=True)
    except ValidationError as e:
        raise ASHConfigValidationError(
            f"Configuration validation failed for '{describe_config_path(path)}': "
            f"{str(e)}. Run 'ash config lint' to identify and fix issues."
        ) from e
    return config, list(document.chain), dict(document.names)


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
    others = _not_the_operators(
        overlay.chain, scanned_trees(Path(scanned_root)), overlay.names
    )
    if not others:
        return
    root = overlay.chain[-1]
    files = ", ".join(f"'{describe_config_path(path)}'" for path in others)
    verb = "is" if len(others) == 1 else "are each"
    raise ASHConfigValidationError(
        f"The operator config '{describe_config_path(root)}' is layered over each "
        "project's own config, so every file it is built from must be the "
        f"operator's. {files} {verb} inside the tree being scanned or delivered "
        "by an MCP client. Keep the config, and every base it extends, outside "
        "the scanned tree and outside the MCP workspace root."
    )


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
) -> AshConfig:
    """resolve_config without the sandbox confinement.

    Appends every file read to ``chain``, each file's parsed document to
    ``documents``, and the paths each was reached by to ``names``.
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
        if config_path is None:
            ASH_LOGGER.verbose(
                "No configuration file provided, checking for default paths"
            )
            discovery = discover_config_source(source_dir)
            log_config_discovery(discovery)
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

        # Process config file
        try:
            config_path = (
                Path(config_path) if not isinstance(config_path, Path) else config_path
            )
            ASH_LOGGER.debug(f"Loading configuration from {config_path.as_posix()}")

            if not config_path.exists():
                ASH_LOGGER.warning(
                    f"Configuration file not found: {config_path.as_posix()}"
                )
                config = fallback(config)
                # Apply overrides to default config if provided
                if config_overrides and config:
                    return apply_config_overrides(config, config_overrides)
                return config  # Return default config if specified file doesn't exist

            ASH_LOGGER.debug("Validating file config")
            if confine_to is None:
                confine_to = default_confinement_root(
                    config_path, confinement_source_dir
                )
            # AshConfig.from_file, keeping the list of files the config came from.
            document = resolve_config_document(
                Path(config_path),
                confine_to=confine_to,
                permit_base=permit_base,
                refuse_env=refuse_env,
                anchor_relative_paths=anchor_paths,
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
            if overlay is not None:
                chain.extend(overlay.chain)
                documents.update(overlay.documents)
                if names is not None:
                    names.update(overlay.names)
            ASH_LOGGER.debug(f"Loaded config from file: {config_path}")

            # Apply config overrides if provided
            if config_overrides:
                config = apply_config_overrides(config, config_overrides)

            return config

        except (IOError, yaml.YAMLError, json.JSONDecodeError) as e:
            # A parser's message can quote the line it stopped at; for a
            # client's file that is text the client may not have written.
            problem = (
                _unquoted_load_error(config_path, e)
                if untrusted_config or _is_a_client_file(config_path)
                else str(e)
            )
            ASH_LOGGER.error(f"Failed to load configuration file: {problem}")
            if fallback_to_default:
                ASH_LOGGER.warning("Using default configuration due to file load error")
                config = fallback(config)
                # Apply overrides to default config if provided
                if config_overrides and config:
                    config = apply_config_overrides(config, config_overrides)
                config._resolution_warnings.append(
                    f"Failed to load configuration file: {problem}. "
                    + (
                        "Using default configuration — suppressions and custom "
                        "settings are NOT active."
                        if overlay is None
                        else f"Using {describe_config_path(overlay.chain[-1])} "
                        "alone — the file's own suppressions and settings are NOT "
                        "active."
                    )
                )
                return config  # Return default config on file error
            else:
                raise e

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
        # Always return a valid config, even in case of unexpected errors
        if fallback_to_default:
            ASH_LOGGER.error(f"Unexpected error in resolve_config: {str(e)}")
            config = fallback(get_default_config())
            # Apply overrides to default config if provided
            if config_overrides:
                return apply_config_overrides(config, config_overrides)
            return config
        raise e
