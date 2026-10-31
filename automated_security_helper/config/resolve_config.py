import copy
import dataclasses
import errno
import hashlib
import json
import os
import re
import stat
import threading
from pathlib import Path
from types import UnionType
from typing import (
    Annotated,
    Any,
    Callable,
    Collection,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Literal,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
    get_args,
    get_origin,
)

from pydantic import ValidationError
import yaml
from automated_security_helper.config.ash_config import (
    AshConfig,
    SandboxConfig,
    plugin_key_lookup_names,
    reduced_plugin_name,
    sandbox_mode_in_document,
)
from automated_security_helper.config.plugin_section_names import (
    fold_known_plugin_sections,
)
from automated_security_helper.config.config_sources import (
    EXTENDS_KEY,
    PATCH_KEY,
    AnchorPaths,
    ChainNames,
    ConfigFileChangedError,
    RefuseEnv,
    ResolvedConfigDocument,
    _resolve_dict_key,
    by_every_name,
    check_search_directory,
    deep_merge,
    default_confinement_root,
    describe_config_path,
    discover_config_source,
    discovery_candidates,
    discovery_warnings,
    env_refused_for,
    FileIdentity,
    identity_to_hold,
    is_config_parse_error,
    is_json_file,
    is_symlink_loop,
    is_toml_file,
    log_config_discovery,
    original_of_scan_copy,
    parse_config_text,
    parse_config_text_literally,
    read_config_file,
    read_config_file_as_written,
    read_config_text,
    resolve_config_document,
    resolve_override_segment,
    unparsed_config_reason,
)
from automated_security_helper.config.archive_limits import confine_archive_limits
from automated_security_helper.config.confinement_remedy import (
    KEEP_A_SETTING,
    KEEP_A_SETTING_BESIDE_A_LOCATED_FILE,
    KEEP_A_SETTING_WHEN_THE_WALK_STOPPED,
    LET_THE_WALK_FINISH,
)
from automated_security_helper.config.operator_paths import (
    SCANNER_RULES_OPTIONS,
    anchor_override_paths,
    anchor_relative_paths as anchor_document_paths,
    the_operators_files,
)
from automated_security_helper.config.path_trust import (
    OperatorPaths,
    operator_reason,
    parse_overrides,
)
from automated_security_helper.config.reporter_trust import (
    confine_reporter_destinations,
)
from automated_security_helper.config.restrictions_kept import keep_restrictions
from automated_security_helper.config.secret_verification_trust import (
    confine_detect_secrets_settings,
)
from automated_security_helper.config.staleness_trust import (
    confine_content_db_staleness,
)
from automated_security_helper.config.tool_config_trust import (
    confine_scanner_config_files,
    confine_tool_versions,
)
from automated_security_helper.config.untrusted_source import (
    IN_TREE_OR_DELIVERED,
    UntrustedSource,
)
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.display_text import (
    escape_controls_in,
    path_spellings,
)
from automated_security_helper.utils.path_stat import (
    LOOP,
    UNREADABLE,
    StatProblem,
    stat_named_path,
)
from automated_security_helper.config.environment_record import (
    ENVIRONMENT_VALUE_SHOWN,
    WrittenKeyMapping,
    mappings_with_written_reference_keys,
)
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config.recorded_config import (
    override_field_paths,
    written_field_paths,
)
from automated_security_helper.config.operator_only_options import (
    RepositorySettings,
    SettledOption,
    confine_operator_only_options,
    record_operator_reporters,
    redacted_places,
    scan_repository_settings,
)
from automated_security_helper.config.plugin_module_trust import (
    confine_plugin_modules,
    drop_plugin_module_references_past_the_list,
)
from automated_security_helper.config.sandbox_grants import (
    REPOSITORY_WRITTEN,
    checkout_judgment,
    confine_sandbox_grants,
    confined_files,
    confinement_membership,
    described,
    files_inside,
    in_a_checkout,
    is_within,
    repository_written,
    scanned_trees,
    tree_holding,
    untrusted_path,
    working_directory,
)
from automated_security_helper.config.config_validator import (
    _string_leaves,
    describe_validation_error,
    environment_record_of_references,
    environment_record_read,
    placed_at_appends,
    redact_values,
)
from automated_security_helper.core.constants import (
    ASH_CONFIG_FILE_NAMES,
    ASH_PYPROJECT_FILE_NAME,
    ASH_RC_FILE_NAMES,
)
from automated_security_helper.core.exceptions import (
    ASHConfigFileNotFoundError,
    ASHConfigInputNotPermittedError,
    ASHConfigSourceError,
    ASHConfigUnparsedError,
    ASHConfigValidationError,
    ASHRespelledOverrideError,
)
from automated_security_helper.utils.error_text import (
    config_environment_values,
    error_text,
    os_error_without_named_file,
)
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.terminal_text import shown_on_one_line


def find_config_file(
    search_dir: Path | None = None, permit: Optional[Callable[[Path], bool]] = None
) -> Optional[Path]:
    """Return the config source a scan of search_dir would use, or None.

    Applies the discovery precedence in ``config_sources.discover_config_source``:
    ASH_CONFIG_FILE_NAMES in order (each in search_dir, then search_dir/.ash/),
    then the ashrc names, then a pyproject.toml with a [tool.ash] table. The
    result can therefore be a TOML file; callers that edit the file in place
    must check its format.

    ``permit`` is a caller's gate, the one an MCP session passes as
    ``permit_base`` (``cli/mcp/sandbox.config_base_gate``). With it, every name
    discovery looks at that is there (``config_sources.discovery_candidates``),
    the ``pyproject.toml`` discovery reads to learn whether it configures ASH
    among them, must be permitted before discovery runs, and the source
    discovery selects before anything reads it. Any can be a link out of the
    directories the caller may read, and so can a ``.ash`` directory, which is
    checked before anything in it.

    Raises:
        ASHConfigInputNotPermittedError: for a file ``permit`` refuses. The
            message names it by its name in search_dir, never by what it
            resolves to. Also, on Windows, for a ``search_dir`` that leads
            through a network share, a device path or a link that cannot be
            read; it is judged before any name is looked for under it.
    """
    if search_dir is None:
        search_dir = Path.cwd()
    if permit is not None:
        # The directory itself first: the lookups below lstat a spelling through
        # it, which follows a link among its components, so a directory that
        # leads to a share is refused before any of them.
        check_search_directory(Path(search_dir), permit)
        # Every name discovery looks at that is there, a link to a missing target
        # included, so the answer does not say whether the target exists.
        for candidate in discovery_candidates(Path(search_dir)):
            if not permit(candidate):
                raise _discovered_config_not_permitted(candidate, Path(search_dir))
    # Discovery takes the gate too: it checks each source by the path it
    # resolves to before anything opens it, so a pyproject.toml that appears
    # between the pass above and this read is not read for its table ungated.
    selected = discover_config_source(search_dir, permit=permit).selected
    if selected is None:
        return None
    if permit is not None and not permit(selected.path):
        raise _discovered_config_not_permitted(selected.path, Path(search_dir))
    return selected.path


def _discovered_config_not_permitted(
    found: Path, search_dir: Path
) -> ASHConfigInputNotPermittedError:
    try:
        name = found.relative_to(search_dir).as_posix()
    except ValueError:
        name = found.name
    if found == search_dir / ".ash":
        # A linked .ash, refused before anything in it is looked at.
        return ASHConfigInputNotPermittedError(
            f"The config directory '{name}' in '{search_dir.as_posix()}' is outside "
            f"the directories this caller may read config from, so nothing in it "
            f"was read."
        )
    return ASHConfigInputNotPermittedError(
        f"The config file '{name}' in '{search_dir.as_posix()}' is outside the "
        f"directories this caller may read config from, so it was not read."
    )


def _anchored_operator_overrides(config_overrides: Sequence[str]) -> List[str]:
    """The operator's ``--config-overrides``, each relative operator path taken
    from the working directory ASH runs in (``anchor_override_paths``).

    With that directory gone (deleted while ASH runs) a relative path has
    nothing to be taken from, and left relative it would reach the scanners,
    which join it to the scanned tree: the repository's file, not the
    operator's (``config/operator_paths.py``). An override that holds one
    refuses the load, naming its key and never its value; one that holds none
    is used as written.
    """
    cwd = working_directory()
    if cwd is not None:
        return anchor_override_paths(config_overrides, cwd)
    needs_a_directory = [
        _override_key_as_written(override)
        for override in config_overrides
        if _needs_a_working_directory(override)
    ]
    if needs_a_directory:
        raise ASHConfigValidationError(
            f"--config-overrides {', '.join(needs_a_directory)} set a relative "
            "path, which is taken from the working directory ASH was run from, "
            "and that directory is gone, so the load is refused."
        )
    return list(config_overrides)


#: Two directories no operator ran ASH from. An override anchored at either of
#: them comes back as written unless its value is taken from the directory it
#: is anchored at.
_PLACEHOLDER_ROOTS: Tuple[Path, Path] = (
    Path(os.sep, "ash-no-working-directory-1"),
    Path(os.sep, "ash-no-working-directory-2"),
)


def _needs_a_working_directory(override: str) -> bool:
    """Whether ``anchor_override_paths`` rewrites this override by the directory
    it is anchored at.

    ``anchor_override_paths`` reads each override on its own, so one is probed
    alone here, anchored at each placeholder root and compared with the
    override as written. It rewrites a relative operator path only: an
    absolute path, a ``~`` path, a URL and a value holding ``$`` come back as
    written (``operator_paths.anchored_path``), and so does a rules option
    (semgrep's and opengrep's ``config``) that names nothing under the
    directory. Probed at the real root, a rules value that happened to name a
    directory of the host (``etc``) read as anchored while one naming nothing
    there read as written, so what was refused depended on the host's own
    directories; under the placeholder roots every rules value names nothing,
    the probe reads it as written, and the rules rule below decides it. The two
    probes are compared with the written override, not with each other: a
    value that climbs out of its root (``../bandit.yaml``) normalizes to the
    same path under both roots and still needs the directory. A rules value
    that is a relative path and no registry form needs the directory too
    (``_rules_value_needs_the_directory``), ``etc`` included: under a live
    directory the anchoring reads the disk for it, and under a gone one there
    is no disk to read.
    """
    probe = [override]
    if any(anchor_override_paths(probe, root) != probe for root in _PLACEHOLDER_ROOTS):
        return True
    return _rules_value_needs_the_directory(override)


#: Rules values a grep scanner resolves without a file: the ``auto`` policy
#: and a registry ruleset, rule or snippet (``p/ci``, ``r/<id>``, ``s/<id>``).
_REGISTRY_RULES = re.compile(r"^(?:auto$|[prs]/)")


def _rules_value_needs_the_directory(override: str) -> bool:
    """Whether a ``--config-overrides`` entry sets a grep scanner's rules
    option (``operator_paths.SCANNER_RULES_OPTIONS``: semgrep's and opengrep's
    ``config``) to a relative path, which only the working directory places.

    A rules value is a file when one is there under the directory and a
    registry entry otherwise, so with the directory live the anchoring reads
    the disk. With the directory gone nothing is there to read, and a relative
    value left as written reaches the scanner, which joins it to the scanned
    tree: the repository's file in the operator's place, the case
    ``_anchored_operator_overrides`` refuses. The value may sit at the option's
    own key (``scanners.semgrep.options.config=<value>``) or inside a mapping
    set higher up (``scanners.semgrep.options={...}``, ``scanners.semgrep={...}``,
    ``scanners={...}``): the live anchoring walks a mapping value down to the
    option (``operator_paths.anchor_relative_paths``), so the probe here walks
    the same way, placing the parsed value at the key's segments and reading
    every scanner section's options for the rules option, under either
    spelling. Read at the option's own key only, a relative file inside a
    mapping passed as written with the directory gone. Admitted as written: a
    registry ruleset, rule or snippet (``p/``, ``r/``, ``s/``), ``auto``, a URL,
    an absolute or ``~`` path and a value holding ``$``, the shapes
    ``operator_paths.anchored_path`` never rewrites; a list, which the live
    anchoring leaves as written too (``anchored_path`` reads a string only);
    and an append (``config+=``), whose value the live anchoring places in a
    list.
    """
    key, separator, raw = override.partition("=")
    if not separator or key.endswith("+"):
        return False
    segments = [segment.strip() for segment in key.split(".")]
    if segments[0] != "scanners":
        return False
    scanners: Any = _parse_config_value(raw)
    for segment in reversed(segments[1:]):
        scanners = {segment: scanners}
    if not isinstance(scanners, dict):
        return False
    for scanner_key, section in scanners.items():
        if not isinstance(scanner_key, str) or not isinstance(section, dict):
            continue
        option_names = _rules_option_names(scanner_key)
        for options in _spelled(section, "options"):
            if not isinstance(options, dict):
                continue
            for option in option_names:
                if any(
                    _relative_rules_file(value) for value in _spelled(options, option)
                ):
                    return True
    return False


def _rules_option_names(scanner_key: str) -> List[str]:
    """The rules options (``operator_paths.SCANNER_RULES_OPTIONS``) of the grep
    scanner a ``scanners`` key names, as ``_``-spelled option names; empty for a
    key naming no grep scanner. The key matches a scanner as the live anchoring
    matches it (``operator_paths._scanner_matches``)."""
    lookup = plugin_key_lookup_names(scanner_key)
    return list(
        dict.fromkeys(
            name.replace("-", "_")
            for scanner, rules_options in SCANNER_RULES_OPTIONS.items()
            if scanner_key == scanner or reduced_plugin_name(scanner) in lookup
            for name in rules_options
        )
    )


def _spelled(container: Dict[str, Any], name: str) -> List[Any]:
    """The values ``container`` holds under ``name`` spelled with ``-`` or
    ``_``, the live anchoring's rule (``operator_paths._spellings``)."""
    wanted = name.replace("-", "_")
    return [
        value
        for key, value in container.items()
        if isinstance(key, str) and key.replace("-", "_") == wanted
    ]


def _relative_rules_file(value: Any) -> bool:
    """Whether a rules option's value is a relative path and no registry form,
    the one shape ``operator_paths.anchored_path`` reads the disk for."""
    if not isinstance(value, str) or not value.strip():
        return False
    if value.startswith("~") or "$" in value or "://" in value or "\x00" in value:
        return False
    if os.path.isabs(value) or value[:1] in ("/", "\\"):
        return False
    return _REGISTRY_RULES.match(value) is None


def _override_key_as_written(override: str) -> str:
    """The key of a ``--config-overrides`` entry for a refusal: ``key`` for a
    setting override, ``key+=`` for an appending one, never the value."""
    key = str(override).partition("=")[0].strip()
    return f"{key}=" if key.endswith("+") else key


def _sets_network_scanners(override: str) -> bool:
    """Whether a ``--config-overrides`` entry can set ``sandbox.network_scanners``.

    True for an entry at the key and for one at the ``sandbox`` section that
    holds it, with either separator spelling, the way ``_apply_config_override``
    reads keys. The operator's own list replaces the limit a file in another
    checkout kept (``restrictions_kept``), as an override replaces any base value.
    """
    key = override.partition("=")[0].removesuffix("+").strip()
    parts = [part.strip().replace("-", "_") for part in key.split(".")]
    return parts[0] == "sandbox" and (len(parts) == 1 or parts[1] == "network_scanners")


def _apply_config_override(
    config_dict: Dict[str, Any],
    key_path: str,
    value: str,
    environment_values: Sequence[str] = (),
) -> Tuple[List[str], Any, bool]:
    """
    Apply a single config override to a configuration dictionary.

    Args:
        config_dict: The configuration dictionary to modify
        key_path: The dot-separated path to the config value (e.g., 'reporters.cloudwatch-logs.options.aws_region')
        value: The value to set at the specified path
        environment_values: The values and keys the configuration read from
            the environment, for redacting a refusal that names a key
            (resolve_override_segment reads them at each segment, and refuses
            a single-use iterator: a caller reusing an exhausted one across
            calls would print an env-read key unredacted).

    Returns:
        The key segments the override landed on, as this apply resolved them
        (a folded spelling resolves to the key the document holds, so the
        caller's record of what the override wrote matches what it wrote),
        the parsed value, and whether the override appended rather than
        replaced.
    """
    # Check if this is an append operation (key_path ends with +)
    append_mode = False
    if key_path.endswith("+"):
        append_mode = True
        key_path = key_path[:-1]  # Remove the + from the key path

    # Split the key path into components
    keys = key_path.split(".")

    # Navigate to the nested dictionary. Each segment resolves against the key
    # before it, so a spelling of a declared plugin's section folds to the
    # section the document holds (resolve_override_segment), the same way the
    # document loader folded the file.
    current = config_dict
    parent: "str | None" = None
    resolved_keys: List[str] = []
    for i, key in enumerate(keys[:-1]):
        resolved = resolve_override_segment(current, parent, key, environment_values)
        # If the key doesn't exist or isn't a dict, create a new dict
        if resolved not in current or not isinstance(current[resolved], dict):
            current[resolved] = {}
        current = current[resolved]
        parent = resolved
        resolved_keys.append(resolved)

    # Set the value at the final key
    final_key = resolve_override_segment(current, parent, keys[-1], environment_values)
    resolved_keys.append(final_key)

    # Parse the value
    parsed_value = _parse_config_value(value)

    # Handle append mode for lists. The log lines name the key, never the value,
    # which can be a credential an override passes; a key segment can itself be
    # a section key the config read from the environment (the trusted replay
    # folds an override onto the file's own key), so the path is redacted too.
    # The redaction is by value, which cuts both ways: a hand-typed key word
    # that equals a value this file read from the environment ("enabled") is
    # blanked here too (accepted -- a blanked word costs less than a leaked
    # value), and a value shorter than MIN_REDACTED_LENGTH is replaced only
    # where a message quotes it, which these lines do not, so such a value can
    # print where the file used it as its own key.
    logged_path = redact_values(key_path, environment_values)
    if append_mode and final_key in current and isinstance(current[final_key], list):
        if isinstance(parsed_value, list):
            current[final_key].extend(parsed_value)
        else:
            current[final_key].append(parsed_value)
        ASH_LOGGER.debug(f"Appended to the list at {logged_path}", extra=NO_MARKUP)
        return resolved_keys, parsed_value, True
    elif append_mode and current.get(final_key) is None:
        # An append onto a list the document does not hold yet, or holds as
        # None, starts the list: as a plain set, a scalar appended stored a
        # bare string a list field refuses, and a list appended replaced the
        # field's None with no word of the append.
        current[final_key] = (
            list(parsed_value) if isinstance(parsed_value, list) else [parsed_value]
        )
        ASH_LOGGER.debug(f"Appended to the list at {logged_path}", extra=NO_MARKUP)
        return resolved_keys, parsed_value, True
    else:
        # Set the value
        current[final_key] = parsed_value
        ASH_LOGGER.debug(f"Applied a config override to {logged_path}", extra=NO_MARKUP)
        return resolved_keys, parsed_value, False


def _parsed_list_item(item: str) -> Any:
    """One item of a bracketed list that is not JSON (``[a, b]``,
    ``['semgrep']``): a quoted item is its text with the quotes removed, as the
    Python and shell spellings mean it, and an unquoted one is parsed as a
    value. The quotes were kept before, so ``['semgrep']`` named a scanner
    "'semgrep'" that matched nothing."""
    if len(item) >= 2 and item[0] == item[-1] and item[0] in "'\"":
        return item[1:-1]
    return _parse_config_value(item)


def _split_list_items(body: str) -> List[str]:
    """The items of ``body``, the inside of a bracketed list that is not JSON,
    split at the commas outside quotes and outside nested brackets or braces,
    each stripped. A split at every comma cut a quoted item holding one in two
    and broke a nested list (``[[a, b], [c]]``) into fragments."""
    items: List[str] = []
    piece: List[str] = []
    depth = 0
    quote: Optional[str] = None
    for character in body:
        if quote is not None:
            piece.append(character)
            if character == quote:
                quote = None
        elif character in "'\"":
            quote = character
            piece.append(character)
        elif character in "[{":
            depth += 1
            piece.append(character)
        elif character in "]}":
            depth = max(depth - 1, 0)
            piece.append(character)
        elif character == "," and depth == 0:
            items.append("".join(piece).strip())
            piece = []
        else:
            piece.append(character)
    items.append("".join(piece).strip())
    return items


def _parse_config_value(value: str) -> Any:
    """
    Parse a configuration value string into the appropriate Python type.

    Args:
        value: The string value to parse

    Returns:
        The parsed value as the appropriate type
    """
    # A list or object is recognized with the whitespace around it removed: a
    # value from `$(cat file.json)` keeps a CR from a CRLF file, and a trailing
    # space is easy to type, and either made the JSON a string. Other values
    # are kept as written.
    bracketed = value.strip()

    # Check for list syntax: [item1, item2, ...]
    if bracketed.startswith("[") and bracketed.endswith("]"):
        try:
            # Try to parse as JSON
            return json.loads(bracketed)
        except json.JSONDecodeError:
            # If not valid JSON, try a simpler approach for basic lists: the
            # items split at the top-level commas, each parsed as a value.
            items = _split_list_items(bracketed[1:-1])
            return [_parsed_list_item(item) for item in items if item]

    # An object is read as JSON only: {"key": "value"}. Text in braces that is
    # not JSON (the YAML flow form {key: value}) is kept as a string, which a
    # typed field refuses and an untyped plugin option stores as it is.
    if bracketed.startswith("{") and bracketed.endswith("}"):
        try:
            # Try to parse as JSON
            return json.loads(bracketed)
        except json.JSONDecodeError:
            # If not valid JSON, return as string
            return value

    # Handle boolean and null values, with the whitespace around them removed
    # as a number's is: "false\r" from a CRLF file and "null " were strings.
    word = bracketed.lower()
    if word == "true":
        return True
    elif word == "false":
        return False
    elif word in ("null", "none"):
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


def _validated_with_overrides(
    config_dict: Dict[str, Any],
    applied: List[Tuple[List[str], Any, bool]],
    raw_values: Sequence[str],
) -> AshConfig:
    """``config_dict`` validated as an AshConfig, with a string field's refusal
    of an override typed as a number cured by the override's own text.

    _parse_config_value types "007" as the int 7 and "1.10" as a float, "true"
    as a bool and "null" as None, so an override could never set a str option
    to such text (an account id, a tool version, the word "true"). Where the
    model refuses such a value as not a string at the place the override
    landed (``applied``, with the text of each override in ``raw_values``),
    the value is set back to the text the operator wrote and the document is
    validated once more. The retyped text is written back into ``applied``
    too, in place: the values a section's lines hide
    (AshConfig._override_values) are the string leaves of ``applied``, and
    the number the parse produced is not one, so the text the model now holds
    (an account id among the shapes) would otherwise print in clear. Any
    other refusal, and a refusal the retyping does not cure, is raised as it
    is.
    """
    try:
        return AshConfig.model_validate(config_dict)
    except ValidationError as error:
        retyped = False
        for item in error.errors():
            if item.get("type") != "string_type":
                continue
            place = tuple(str(part) for part in item.get("loc", ()))
            for index, ((segments, parsed, appended), raw) in enumerate(
                zip(applied, raw_values)
            ):
                if (
                    appended
                    or isinstance(parsed, (str, list, dict))
                    or tuple(segments) != place
                ):
                    continue
                container: Any = config_dict
                for segment in segments[:-1]:
                    container = (
                        container.get(segment) if isinstance(container, dict) else None
                    )
                if (
                    isinstance(container, dict)
                    and container.get(segments[-1]) == parsed
                ):
                    container[segments[-1]] = raw
                    applied[index] = (segments, raw, appended)
                    retyped = True
        if not retyped:
            raise
        return AshConfig.model_validate(config_dict)


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

    # The reporters sections as the input's document holds them, before this
    # (first) application: the trusted replay's fold reads it to tell a
    # section the input held from one an override created
    # (_folded_onto_trusted). Computed here and set on the rebuilt model
    # below, after the private-state copy, never on the input: stamping the
    # input mutated the caller's model, the trusted replay's operator
    # configuration among them, and kept the stamp even when the overridden
    # document failed validation. A model that already carries a record (a
    # rebuilt one sent through a second application) keeps its first
    # application's, so a key an override created never counts as a section
    # the document held.
    # The built-in scanners and reporters are typed fields, so they appear in
    # every dump: the record of a built-in section always holds every declared
    # plugin, and the fold's created-key gate never excludes one of them. That
    # is harmless, because the rewrite for a built-in lands on the field name
    # the apply resolves it to anyway. Only a section the document itself
    # introduced (an undeclared plugin) is told apart from one an override
    # created.
    reporters_before_overrides = config._reporters_before_overrides
    if reporters_before_overrides is None:
        reporters_before_overrides = tuple(
            key for key in (config_dict.get("reporters") or {}) if isinstance(key, str)
        )
    scanners_before_overrides = config._scanners_before_overrides
    if scanners_before_overrides is None:
        scanners_before_overrides = tuple(
            key for key in (config_dict.get("scanners") or {}) if isinstance(key, str)
        )

    # The field paths the operator supplied, before this application: the
    # input model's written fields (its model_fields_set, as a parsed file
    # holds them), or the record a rebuilt model already carries, since a
    # rebuild widens model_fields_set to every field. This application's
    # override keys join below, once the rebuilt model resolves their
    # spellings. recorded_config._sets answers from the stamped record:
    # without it, one unrelated override made every field count as
    # operator-set, and ash report rendered under a recorded field's default
    # instead of refusing it.
    written_before_overrides = config._written_before_overrides
    if written_before_overrides is None:
        written_before_overrides = written_field_paths(config)

    # Apply each override. The errors name the keys, never the values: a value
    # can be a credential, and these messages reach the log and the terminal.
    # A key the config read from the environment is a value too, so the
    # resolver redacts these in the refusal it raises.
    environment_values = config_environment_values(config)
    keys: List[str] = []
    applied: List[Tuple[List[str], Any, bool]] = []
    raw_values: List[str] = []
    for override in config_overrides:
        key_path, separator, value = override.partition("=")
        if not separator or not key_path.strip():
            raise ASHConfigValidationError(
                f"Invalid config override: {_override_shown(override)}. "
                "Expected format: key.path=value"
            )
        keys.append(key_path)
        # The key is applied exactly as written, so " reporters.x=1" wrote a
        # top-level " reporters" key nothing reads, and the setting it meant to
        # override kept the config file's value. So did an empty part ("a..b", a
        # leading or trailing "."), a character that does not print (a zero-width
        # space, a byte order mark) and a space inside a part ("aws security hub"
        # is a section of its own).
        segments = key_path.removesuffix("+").split(".")
        if any(
            not segment
            or not segment.isprintable()
            or any(character.isspace() for character in segment)
            for segment in segments
        ):
            raise ASHConfigValidationError(
                # As written: the sink that prints it shows the character that
                # does not print as its escape, once.
                f"Invalid config override: '{key_path}'. A dot-separated part of "
                "the key is empty, holds whitespace, or holds a character that "
                "does not print; write it as key.path=value."
            )
        try:
            applied.append(
                _apply_config_override(config_dict, key_path, value, environment_values)
            )
            raw_values.append(value)
        except ASHConfigValidationError:
            # Already an override refusal whose text names keys only (the
            # respelled-section refusal, resolve_override_segment).
            raise
        except Exception as e:
            # The exception's type only: its text can quote the value.
            raise ASHConfigValidationError(
                f"Failed to apply the config override for '{key_path}': "
                f"{type(e).__name__}"
            ) from e

    # Convert back to AshConfig
    try:
        rebuilt = _validated_with_overrides(config_dict, applied, raw_values)
    except ValidationError as e:
        # Not chained: see ASHConfigValidationError.validation_error. Without
        # the values and keys the configuration's files read from the
        # environment, which the merged document holds.
        raise ASHConfigValidationError(
            "Configuration is invalid after applying the requested overrides for "
            f"{', '.join(repr(key) for key in keys)}: "
            f"{describe_validation_error(e, config._environment_values)}",
            validation_error=e,
        ) from None
    # The rebuilt model is the same configuration with the operator's
    # overrides, so it keeps what its load recorded: the values its files read
    # from the environment and how each was written (AshConfig's private
    # attributes). Without them a run whose overrides were applied here, as to
    # the ASH_CONFIG configuration, printed and recorded those values.
    rebuilt.__pydantic_private__ = copy.deepcopy(config.__pydantic_private__)
    # Each string an override's value holds joins the values a line that prints
    # a section of this config hides (AshConfig._override_values). The value is
    # the operator's, not the environment's, but it can be a credential, and
    # get_plugin_config's debug line printed each reporter's section whole, an
    # override's value in it (ash merge --debug, ash report --debug). Strings
    # only: a bool or a number an override sets is no credential, and a short
    # word such as "true" would be hidden wherever a line prints it. A second
    # application (ash merge applies the overrides to each shard's record and
    # replays them onto the trusted base) keeps the first's.
    rebuilt._override_values = tuple(
        dict.fromkeys(
            (
                *rebuilt._override_values,
                *(
                    leaf
                    for _, value, _ in applied
                    for leaf in _string_leaves(value)
                    if leaf
                ),
            )
        )
    )
    # A model that already carries references (a second application) can
    # have its module list shortened here: the references it carried then
    # name entries the list no longer has.
    # A replacing override of the list (not an append) also leaves a reference
    # at an index the new list still has, naming an entry it replaced: the
    # applied tuples tell the two apart, so every reference of the list goes.
    # The answer is stamped on the model as well, for the load path, which
    # attaches its references after this application and reads the fact from
    # here instead of parsing the override text again.
    replaced = any(
        resolved_keys[0] == "ash_plugin_modules" and not appended
        for resolved_keys, _, appended in applied
    )
    if replaced:
        rebuilt._plugin_modules_replaced = True
    drop_plugin_module_references_past_the_list(rebuilt, replaced=replaced)
    rebuilt._reporters_before_overrides = reporters_before_overrides
    rebuilt._scanners_before_overrides = scanners_before_overrides
    # The record is built from the segments each override actually landed on
    # (the apply's own resolution, so a folded spelling is recorded as the key
    # it wrote), with a replacing override's value unwriting what it dropped
    # and writing what it holds.
    rebuilt._written_before_overrides = override_field_paths(
        rebuilt, written_before_overrides, applied
    )
    return rebuilt


def resolve_config_source(
    config_path: Path | str,
    source_dir: Path | str | None = None,
    permit_base: Optional[Callable[[Path], bool]] = None,
    reader: Callable[[Path], Any] = read_config_file,
    texts: Optional[Dict[Path, str]] = None,
    confine: Optional[Callable[[Path, Path, Any], Any]] = None,
    repository_file: Optional[Callable[[Path, Path], bool]] = None,
    refuse_env: Optional[RefuseEnv] = None,
    anchor_relative_paths: Optional[AnchorPaths] = None,
    expect: Optional[FileIdentity] = None,
) -> ResolvedConfigDocument:
    """Read a config file and its ``extends`` chain the way a scan reads them.

    ``expect`` is the identity ``identity_to_hold`` gave the file when the caller
    checked it (see ``resolve_config_document``).

    Bases are confined to ``default_confinement_root(config_path, source_dir)``:
    the scan's source directory when the file is inside it, otherwise the file's
    own directory. ``load_config_file`` calls this and then ``build_config``;
    ``resolve_config`` and ``ConfigValidator.check_config_file`` (behind
    ``ash config validate`` and ``lint``) both load config files through it, so
    a check cannot accept or refuse a file on rules the scan does not apply.
    ``reader`` reads each file; see ``resolve_config_document`` for the readers
    a check passes, and for ``confine`` and ``repository_file``.
    """
    config_path = Path(config_path)
    return resolve_config_document(
        config_path,
        confine_to=default_confinement_root(
            config_path, Path(source_dir) if source_dir is not None else None
        ),
        permit_base=permit_base,
        reader=reader,
        texts=texts,
        confine=confine,
        repository_file=repository_file,
        refuse_env=refuse_env,
        anchor_relative_paths=anchor_relative_paths,
        expect=expect,
    )


# The characters a path printed in a pasteable command may hold: ASCII letters
# and digits, `_ . / : -`. No shell (POSIX shells, cmd.exe, PowerShell) reads
# any of them specially. The set is deliberately narrow: a character outside it
# is not necessarily special, but a space, `&`, `;`, a quote, `~`, `+`, `@`, a
# comma or non-ASCII text either is in some shell or is not worth the doubt.
# Paths are printed with "/" (as_posix), so a backslash is never needed.
_PASTEABLE_PATH = re.compile(r"[A-Za-z0-9_./:-]+")


def pasteable_path(path: Path | str) -> bool:
    """Whether lint_hint prints ``path`` itself, rather than pointing at it."""
    return bool(_PASTEABLE_PATH.fullmatch(Path(path).as_posix()))


def lint_hint(config_path: Path | str, source_dir: Path | str | None = None) -> str:
    """What a refusal ends with: the command that lists every problem in the file.

    It names the file. A bare `ash config lint` lints the config of the current
    directory, which for `--config other.yaml`, or a scan of another directory,
    is a different file (or none), and reports it clean. With the scan's source
    directory when that is not the working directory: lint confines an
    `extends` chain to it, as the scan did, and without it reports the chain
    instead of the problem the scan refused.

    The command is last and unquoted, so it can be pasted as is. A path with a
    character outside letters, digits and `_ . / : -` (pasteable_path) is not
    printed in it: no one quoting is safe in both POSIX shells and cmd.exe, so
    the command points at the file the message names instead. When one path
    needs that, neither is printed: `--config <the file named above>
    --source-dir /srv/repo` is a valid POSIX command line (input from a file
    named `the`, output to one named `--source-dir`), while a line that ends
    in `>` is not.
    """
    # A scan's copy of a session profile is pointed back at the profile: the
    # copy is removed when the run ends, so a command naming it lints nothing,
    # while the profile holds the same content under the operator's own name.
    paths = [original_of_scan_copy(Path(config_path))]
    # The working directory can be deleted while the process runs; whatever
    # source_dir names, it is then not that directory, so the hint keeps
    # --source-dir instead of raising out of the refusal it decorates.
    cwd = working_directory()
    if source_dir is not None and (
        cwd is None or Path(source_dir).resolve() != cwd.resolve()
    ):
        paths.append(source_dir)
    if all(pasteable_path(path) for path in paths):
        shown = [Path(path).as_posix() for path in paths]
    else:
        shown = ["<the file named above>", "<the directory the scan scanned>"]
    command = f"ash config lint --config {shown[0]}"
    if len(paths) > 1:
        command += f" --source-dir {shown[1]}"
    return f"Run: {command}"


def build_config(data: Any, config_overrides: Optional[List[str]] = None) -> AshConfig:
    """The AshConfig a scan builds from a resolved document.

    Strict validation, then ``--config-overrides``. Raises pydantic's
    ValidationError for the document and ASHConfigValidationError for an
    override; see ``load_config_file``, which every config file goes through.
    """
    # The context selects the named refusal of an opted typed field's
    # environment reference (RedactedSection's validator): a strict load
    # refuses the reference text at the field either way, but pydantic's own
    # message calls the resolved text not-an-integer and names no variable.
    config = AshConfig.model_validate(
        data, strict=True, context={"strict_file_load": True}
    )
    if config_overrides:
        config = apply_config_overrides(config, config_overrides)
    return config


class ConfigFileRefused(ASHConfigValidationError):
    """The AshConfig model refused a config file, or the file after its overrides.

    Raised by ``load_config_file`` with the ``document`` the model was built
    from, so a check can still read the file's merged data and its chain, and
    with pydantic's ``validation_error`` naming each field the model refused:
    None when an override could not be applied at all. ``after_overrides``
    tells a refusal of the file from one of the file with the overrides
    applied.
    """

    def __init__(
        self,
        message: str,
        *,
        document: ResolvedConfigDocument,
        validation_error: Optional[ValidationError],
        after_overrides: bool,
    ) -> None:
        super().__init__(message, validation_error=validation_error)
        self.document = document
        self.after_overrides = after_overrides


def _cached_documents(in_tree: Sequence[Path], reads: Dict[Path, Any]) -> List[Any]:
    """The documents ``reads`` holds for the files of ``in_tree``, in order.

    The client-overrides sentinel (``CLIENT_OVERRIDES_SOURCE``, a relative
    path that names no file) is skipped before any path is resolved: resolving
    a relative path reads the working directory, and with that directory gone
    (the deleted-cwd case the load supports) it raised FileNotFoundError, so a
    load with a client's overrides crashed where every file of the chain was
    fine."""
    found: List[Any] = []
    for path in in_tree:
        if Path(path) == CLIENT_OVERRIDES_SOURCE:
            continue
        key = Path(path).resolve()
        if key in reads:
            found.append(reads[key])
    return found


def _cached_reader(
    reads: Dict[Path, Any], texts: Dict[Path, str]
) -> Callable[..., Any]:
    """A config file reader over the caches ``reads`` (each file's parsed data)
    and ``texts`` (the text it was parsed from), both keyed by resolved path.

    The one reader every file of a run's configuration is read through: the
    selected chain's (``load_config_file_for_run``) and the workspace overlay's
    (``_load_overlay``), so a file the two chains share is parsed once, and the
    as-written view each record is built from (environment_record_read) parses
    the text the load read, never a second read of the file.
    """

    def read_once(path: Path, expect: Optional[FileIdentity] = None) -> Any:
        key = Path(path).resolve()
        if expect is not None and key in reads and key in texts:
            # A caller vetted this file, and the cache already holds a read of
            # it that was made without that identity (the ASH_CONFIG chain is
            # loaded into the same cache first, and may name this very file).
            # The cached read is used only if it is what the vetted file holds:
            # the file is read once more, held to the identity, and the cached
            # text must be that text. A file replaced since, or rewritten in
            # place, is refused and not shown from a read nobody held to the
            # check. A cached read that holds no text has none to compare, so
            # it is not read again here: it is returned as the cache holds it,
            # and the load refuses it for the missing text
            # (``_file_references``), a reason that names the caller's cache and
            # no value.
            fresh = read_config_text(path, expect=expect)
            if texts.get(key) != fresh:
                raise ConfigFileChangedError(
                    errno.ESTALE,
                    "changed while it was being read, so it is not read",
                    os.fspath(path),
                )
            return reads[key]
        if key not in reads:
            # ``expect`` is the identity the chain walk vetted
            # (config_sources._read_into_state hands it to a reader that takes
            # it); a caller that vetted nothing gets the file's identity now,
            # and for a path that leads nowhere now, the identity no file has
            # (never None, which would hold the read to nothing).
            # read_config_text with an identity reads through
            # read_config_bytes, so the ASH_CONFIG_MAX_FILE_BYTES bound, the
            # non-blocking open and the check that the file read is the file
            # that was vetted bind on every chain read, as they do for the
            # stock reader.
            if expect is None:
                expect = identity_to_hold(path)
            texts[key] = read_config_text(path, expect=expect)
            reads[key] = parse_config_text(path, texts[key])
        return reads[key]

    return read_once


def load_config_file_for_run(
    config_path: Path | str,
    reads: Optional[Dict[Path, Any]] = None,
    texts: Optional[Dict[Path, str]] = None,
    **kwargs: Any,
) -> Tuple[ResolvedConfigDocument, AshConfig]:
    """load_config_file for the configuration a run uses, which knows the values
    and keys its files read from the environment.

    The config's ``_environment_values`` are set from the reads the load made,
    and its ``_environment_references`` from the document:
    the loader is given a reader that keeps each file's data, and each file is
    read once more only literally, so no file is parsed twice and no ``!ENV``
    warning is logged again (ConfigValidator.check_config_file does the same).
    A load given ``fill`` (the operator's copy of a profile a client patched)
    adds the references the fill read to the values and the record's rewrites,
    which the client's copy, holding them as text, gives no file read for.
    The lines built from the config once it has loaded, a loaded plugin's option
    refusal and get_plugin_config's debug line, are redacted with them.

    Not load_config_file itself, so not AshConfig.from_file: a private attribute
    is part of a model's equality, and a config from from_file equals the same
    config built in memory. For resolve_config's file, and get_default_config's.
    ``kwargs`` are load_config_file's, ``reader`` excepted.

    ``reads`` and ``texts`` are a caller's caches of files already read, keyed
    by resolved path: a caller that read a file of the chain itself (the
    config validator) hands them in, so no file is parsed or logged twice
    across the two reads. A cached file whose text the cache holds, asked for
    by the chain walk with an identity to hold the read to (``expect``), is
    read again held to it, and the cached read is used only if it holds the
    same text; otherwise the read is refused (``ConfigFileChangedError``). A
    cached file with no text in ``texts`` is refused for that instead (a
    ``TypeError``), as a reader that did not fill the cache is.
    """
    if reads is None:
        reads = {}
    # Each file's text as the load read it: its as-written view is parsed from
    # the same text, so a file another writer changes in between cannot give
    # values the load never read (environment_record_read).
    if texts is None:
        texts = {}

    read_once = _cached_reader(reads, texts)

    # The references the load filled in from the operator's copy of a profile
    # a client patched (``fill``), each at the place it was read.
    filled: List[Any] = []
    document, config = load_config_file(
        config_path, reader=read_once, texts=texts, filled_out=filled, **kwargs
    )
    # Each rewrite at the place the load followed its reference to, through
    # every patch of the chain (document.reference_places).
    values, rewrites = environment_record_read(
        document.chain, reads, texts, places=document.reference_places
    )
    # The client's copy holds those references as text, so reading its file
    # pairs none of them: they are recorded as the operator's copy read them,
    # at the places the fill put them (environment_record_of_references).
    filled_values, filled_rewrites = environment_record_of_references(filled)
    # Beside the reporter defaults the config recorded when it was built
    # (ash_config.reporter_default_values), each value once.
    config._environment_values = list(
        dict.fromkeys([*filled_values, *values, *config._environment_values])
    )
    # An append the load did not follow gets its index from the configuration
    # built.
    config._written_references = [
        *filled_rewrites,
        *placed_at_appends(config, rewrites),
    ]
    config._written_key_mappings = _written_key_mappings(document.chain, texts)
    # Each value and key the chain read from the environment, at its place in
    # the merged configuration (config/environment_record.py): what a message
    # or a view of the config shows as `<value>` or `<from ${VAR}>`. Set before
    # resolve_config's confinement steps, whose warnings name the entries. The
    # references the fill read are among them: the client's copy holds each as
    # text, so no file of the chain wrote them, and a view that leaves them out
    # shows the value.
    config._environment_references = (
        *filled,
        *document.environment_references,
    )
    # The ones the merged document still shows at their places: what a view of
    # the config writes back as the file wrote it (`ash config get`, the MCP
    # get_config tool). The filled ones stand at the places the fill put them.
    config._displayed_environment_references = (
        *filled,
        *document.displayed_environment_references,
    )
    overlay = kwargs.get("overlay")
    if overlay is not None:
        # The overlay's files were merged over the document before the model
        # was built (load_config_file), so what they read from the environment
        # is in the configuration too, and is recorded as the chain's own reads
        # are: the results file's record, the off-host payloads and the
        # redaction all read these attributes, and carried the overlay's
        # resolved values in clear while only _environment_references held
        # its reads.
        _record_overlay_reads(config, overlay, reads, texts)
    # The references above are the file's own document's, and the config's
    # overrides were applied before they were attached: an override that
    # replaced ash_plugin_modules with a shorter list leaves a reference
    # past its end, which the module movers (ash plugin's split, the trust
    # confinement) refuse by design. An override that REPLACED the list also
    # leaves a reference on an index the new list still has, so the drop takes
    # every reference of the list. Whether one replaced it is what the apply
    # stamped on the model from the key paths its overrides landed on (the
    # one place that resolves an override key), not a second reading of the
    # override text.
    drop_plugin_module_references_past_the_list(
        config, replaced=config._plugin_modules_replaced
    )
    return document, config


def _written_key_mappings(
    chain: Sequence[Path], texts: Dict[Path, str]
) -> Tuple[WrittenKeyMapping, ...]:
    """Each mapping where a file of ``chain`` writes a key as a reference, set
    or not (mappings_with_written_reference_keys), parsed from the text the load
    read, by each file's resolved path in ``texts``. YAML files only: JSON and
    TOML resolve no key. A file that cannot be read as written again counts as
    one such mapping with no place, which the rules refuse."""
    found: List[WrittenKeyMapping] = []
    for path in dict.fromkeys(Path(file) for file in chain):
        if is_json_file(path) or is_toml_file(path):
            continue
        key = path.resolve()
        try:
            if key in texts:
                written = parse_config_text_literally(
                    path, texts[key], keep_env_tags=True
                )
            else:
                written = read_config_file_as_written(path)
            # Folded as the load folded the document (plugin_section_names),
            # so a mapping under a respelled known-plugin section is named at
            # the place the configuration uses.
            written = fold_known_plugin_sections(written)
        except (ASHConfigSourceError, yaml.YAMLError, OSError, ValueError):
            found.append((None, frozenset()))
            continue
        found += mappings_with_written_reference_keys(written, (EXTENDS_KEY, PATCH_KEY))
    return tuple(found)


def _record_overlay_reads(
    config: AshConfig,
    overlay: ResolvedConfigDocument,
    reads: Dict[Path, Any],
    texts: Dict[Path, str],
) -> None:
    """Record on ``config`` what the files of ``overlay`` read from the
    environment, as ``load_config_file_for_run`` records the selected chain's
    own reads.

    A workspace's operator config (``resolve_config``'s ``overlay_config_path``)
    is merged over each project's document before the model is built, and
    stands alone where the project has no config file (``overlaid_fallback``),
    so its values are in the configuration like the chain's own. The results
    file's ``ash_config`` record and the payload an off-host reporter sends
    (record_of_config) read ``_written_references``; the free-text redaction and
    ``get_plugin_config``'s debug line read ``_environment_values``; the key
    rules read ``_written_key_mappings``. Each rewrite is at the place its value
    has in the merged configuration: a mapping key the overlay sets is the
    merged document's key, and a list the overlay sets replaces the project's
    whole (deep_merge), so the overlay's own indices hold. The overlay's files
    were read into ``reads`` and ``texts`` by the chain's cached reader
    (``_load_overlay``), so the as-written view is parsed from the text the
    load read.
    """
    values, rewrites = environment_record_read(
        overlay.chain, reads, texts, places=overlay.reference_places
    )
    config._environment_values = list(
        dict.fromkeys([*config._environment_values, *values])
    )
    config._written_references = [
        *config._written_references,
        *placed_at_appends(config, rewrites),
    ]
    config._written_key_mappings = (
        *tuple(config._written_key_mappings or ()),
        *_written_key_mappings(overlay.chain, texts),
    )
    config._environment_references = (
        *tuple(config._environment_references or ()),
        *tuple(overlay.environment_references),
    )
    config._displayed_environment_references = (
        *tuple(config._displayed_environment_references or ()),
        *tuple(overlay.displayed_environment_references),
    )


def load_config_file(
    config_path: Path | str,
    source_dir: Path | str | None = None,
    permit_base: Optional[Callable[[Path], bool]] = None,
    config_overrides: Optional[List[str]] = None,
    reader: Callable[[Path], Any] = read_config_file,
    confine_to: Optional[Path] = None,
    texts: Optional[Dict[Path, str]] = None,
    confine: Optional[Callable[[Path, Path, Any], Any]] = None,
    repository_file: Optional[Callable[[Path, Path], bool]] = None,
    refuse_env: Optional[RefuseEnv] = None,
    overlay: Optional[ResolvedConfigDocument] = None,
    fill: Sequence[Any] = (),
    filled_out: Optional[List[Any]] = None,
    anchor_relative_paths: Optional[AnchorPaths] = None,
    expect: Optional[FileIdentity] = None,
) -> Tuple[ResolvedConfigDocument, AshConfig]:
    """Load a config file the way every scan loads one.

    ``expect`` is the file's ``identity_to_hold`` as the caller took it when it
    checked the path; the file is read only if it is still that file.

    The file and its ``extends`` chain (``resolve_config_source``, which says
    where bases may be, or the directory ``confine_to`` names), then the
    AshConfig model with strict types and the ``config_overrides``
    (``build_config``). ``reader`` reads each file; a check passes one that
    returns what it read already. ``confine`` is resolve_config_document's: a
    caller that reads the chain as a scan reads it passes
    ``operator_only_options.scan_repository_settings(...).confine``, so what a
    file inside the tree or inside any other checkout writes for an
    operator-only option is left out before the
    model validates the document. ``repository_file`` is
    resolve_config_document's: the same settings' ``is_repository_file``, so
    an operator file's patch pointers fold only onto section keys the
    operator's own files wrote.

    Every config file ASH loads into an AshConfig comes through here, so a
    refusal made here is one each of them makes:

    - the scan's config file (``resolve_config``) and the operator's
      (``trusted_config_path``);
    - the file ``ash config validate`` and ``lint`` check, and the ASH_CONFIG
      file a scan starts from beside it (``ConfigValidator.check_config_file``);
    - every caller of ``AshConfig.from_file``: the ASH_CONFIG file a scan
      starts from (``get_default_config``), ``ash config update`` and the
      wizard, the MCP server's profiles and session configs, and a workspace
      project's config (``run_ash_scan._load_with_confinement``).

    One reader of config files loads no model: the MCP server's chain
    pre-check (``cli/mcp/sandbox.py``) asks only whether the session's grant
    permits every ``extends`` base, before the file is loaded here. The
    container sandbox-mode floor and the grant confinement read the views
    the one classified load carried out instead of resolving the chain
    again, and every reader of the ASH_CONFIG chain, with or without a
    working directory (``get_default_config`` under
    ``scan_repository_settings`` or ``repository_settings_for_root``),
    classifies it as a scan does: the operator-only writes of every checkout
    file are left out.

    ``fill`` is the references the operator's copy of a profile a client patched
    read from the environment: the client's copy holds each as text, and the
    document is filled from them before the model is built. ``filled_out``, when
    given, is extended with each of them that was read, at the place the fill
    read it (``environment_record.fill_environment_references``), for the record
    of the configuration (``load_config_file_for_run``).

    Raises:
        ASHConfigSourceError: The chain does not resolve. The message reads
            nothing from the environment (config_sources
            ``_environment_blind_error``); a base ``permit_base`` refused raises
            ASHConfigInputNotPermittedError.
        ConfigFileRefused: The model refuses the document, or the document
            after the overrides.
    """
    config_path = Path(config_path)
    # A chain that does not resolve raises with nothing read from the
    # environment in its message (resolve_config_document).
    if confine_to is not None:
        document = resolve_config_document(
            config_path,
            confine_to=confine_to,
            permit_base=permit_base,
            reader=reader,
            texts=texts,
            confine=confine,
            repository_file=repository_file,
            refuse_env=refuse_env,
            anchor_relative_paths=anchor_relative_paths,
            expect=expect,
        )
    else:
        document = resolve_config_source(
            config_path,
            source_dir=source_dir,
            permit_base=permit_base,
            reader=reader,
            texts=texts,
            confine=confine,
            repository_file=repository_file,
            refuse_env=refuse_env,
            anchor_relative_paths=anchor_relative_paths,
            expect=expect,
        )
    data = document.data
    if fill:
        # The checks of who set what compare each file's values with the
        # trusted base's, so the documents are filled too.
        from automated_security_helper.config.environment_record import (
            fill_environment_references,
        )

        data = fill_environment_references(data, fill, placed=filled_out)
        document.documents = {
            path: fill_environment_references(text, fill)
            for path, text in document.documents.items()
        }
    if overlay is not None and isinstance(data, dict):
        # A document that is not a mapping is left as it is, so its validation
        # error is still raised rather than replaced by the overlay's content.
        data = deep_merge(data, overlay.data, AshConfig)
    try:
        return document, build_config(data, config_overrides)
    except ValidationError as e:
        if _has_a_client_file(document):
            # A chain that holds a file an MCP client supplied, by any name on
            # the way (a link inside a delivered tree included), is refused in
            # the words a client's file gets everywhere else
            # (_client_validation_error, the form validate_config_document
            # gives it): each problem's location, with a key the schema does
            # not name as <key>, and its kind; no value and no key of the file.
            raise ConfigFileRefused(
                str(_client_validation_error(config_path, e)),
                document=document,
                validation_error=e,
                after_overrides=False,
            ) from None
        # Without pydantic's own text, which quotes every input: an input can
        # be a value the file read from the environment. And without the
        # values and keys the chain read from the environment: a key is
        # printed in an error's location ("Invalid value at
        # 'global_settings.<key>'"). Not chained: see
        # ASHConfigValidationError.validation_error.
        described = describe_validation_error(e, document.environment_values)
        # One period before the hint, whether or not the last message has one.
        raise ConfigFileRefused(
            f"Configuration validation failed for "
            f"'{describe_config_path(config_path)}': {described.rstrip('.')}. "
            f"{lint_hint(config_path, source_dir)}",
            document=document,
            validation_error=e,
            after_overrides=False,
        ) from None
    except ASHConfigValidationError as e:
        # An override that cannot be applied, or that leaves the config invalid.
        # Its message names each field, and a key the file read from the
        # environment is one. Not chained, as above.
        raise ConfigFileRefused(
            redact_values(str(e), document.environment_values),
            document=document,
            validation_error=e.validation_error,
            after_overrides=True,
        ) from None


def _with_any_checkout_files(
    inside: List[Path],
    files: Sequence[Path],
    named: Sequence[Path],
    undecided_out: Optional[List[Path]] = None,
) -> List[Path]:
    """*inside* extended with the *files* inside ANY checkout, or reached by a
    name that sits in one.

    The fail-closed membership a load with no scanned tree judges a chain by:
    files_inside with an empty tree list returns nothing, which would skip
    the confinement steps and hand a checkout file's writes to the operator.
    A name that sits in a checkout marks the file it resolves to, as
    files_inside judges a named entry.

    With *undecided_out*, each file added here on NO found checkout -- every
    judgment that admitted it was an unfinished walk's fail-closed answer
    (``checkout_judgment``) -- is appended to it, so the caller's warning can
    say the walk stopped instead of claiming a checkout. The membership is the
    same either way.
    """
    # realpath of each admitting name -> whether any walk of it FOUND a
    # checkout (True) rather than failing closed on an unfinished walk.
    reached: Dict[Path, bool] = {}
    for name in named:
        judgment = checkout_judgment(Path(name))
        if not judgment.verdict:
            continue
        real = Path(os.path.realpath(name))
        reached[real] = reached.get(real, False) or judgment.decided
    seen = set(inside)
    added: List[Path] = []
    for file in files:
        if file in seen:
            continue
        file_judgment = checkout_judgment(file)
        if not file_judgment.verdict and file not in reached:
            continue
        added.append(file)
        found = (file_judgment.verdict and file_judgment.decided) or reached.get(
            file, False
        )
        if undecided_out is not None and not found:
            undecided_out.append(file)
    return [*inside, *added]


def _with_outside_files(
    inside: List[Path],
    files: Sequence[Path],
    named: Sequence[Path],
    names: Optional[ChainNames] = None,
    undecided_out: Optional[List[Path]] = None,
    *,
    any_checkout: bool = True,
) -> List[Path]:
    """*inside* extended with the *files* of a chain that are not the scanned
    tree's but are not the operator's either: those inside ANY git checkout
    (``_with_any_checkout_files``) and those an MCP client delivered
    (``_delivered_by_a_client``, judged under every name in *names* that
    reached each).

    The membership the grants contract holds a config file to
    (``sandbox_grants``): a file inside any checkout, or one a client
    delivered, makes no sandbox grant, whether or not the scanned tree holds
    it. ``files_inside`` judges the scanned trees alone, so a load that had
    only that membership returned a chain wholly outside them as the
    operator's and skipped the confinement. With ``any_checkout`` False only
    the delivered leg runs. A file already in *inside* is not added twice,
    nor is one that a member of *inside* resolves to: a name in the tree that
    links to a file elsewhere already puts that file under the confinement,
    as the tree's.

    *undecided_out* is ``_with_any_checkout_files``'s: each file the
    checkout leg admitted only on an unfinished walk is appended to it.
    """
    represented = {Path(os.path.realpath(member)) for member in inside}
    fresh = [file for file in files if Path(os.path.realpath(file)) not in represented]
    members = (
        _with_any_checkout_files(inside, fresh, named, undecided_out=undecided_out)
        if any_checkout
        else list(inside)
    )
    delivered = [
        path for path in _delivered_by_a_client(fresh, names) if path not in members
    ]
    return [*members, *delivered]


def _flat_names(
    files: Sequence[Path], named: Sequence[Path]
) -> Dict[Path, Tuple[Path, ...]]:
    """*named*, a chain's names as one flat list, as the map of names each
    file was reached by that the membership checks take.

    The ASH_CONFIG load carries its names as a flat list, not per file
    (``default_views``), so every name counts for every file of the chain: a
    mixed chain is judged from the safe side, a file being taken as delivered
    when any name of the chain is.
    """
    return {Path(file): tuple(named) for file in files}


class _WordingMemberships(NamedTuple):
    """One confined chain's wording values (see ``_wording_memberships``)."""

    checkout: bool
    mixed: bool
    undecided: bool
    outside: bool = False


def _wording_memberships(
    checkout_added: Sequence[Path],
    in_tree: Sequence[Path],
    rootless_wording: bool,
    undecided_files: Sequence[Path],
    outside_files: Sequence[Path] = (),
) -> _WordingMemberships:
    """The ``checkout``, ``mixed`` and ``undecided`` wording values for one
    confined chain, shared by the sandbox, settle and module warnings.

    ``checkout`` holds for the any-checkout rule's files (``checkout_added``),
    or for the rootless reading (``rootless_wording`` in resolve_config: the
    host-marked files of a load with no trees). The rootless reading calls
    every file a checkout's, so no mixed split applies to it: one checkout
    sentence covers the line, and the mixed head would state two memberships
    for files the rootless reading reads one way. The undecided override
    below can still set the flag for a rootless load: the mixed-undecided
    sentence it then reaches names no tree (membership_clause), so the guard
    is not repeated there. All three values are for wording only; the module
    judgment stays on scanned_root and no_scanned_tree. Both chain branches
    of resolve_config call this, so the rule has one copy.

    ``undecided_files`` are the files on the line only by an unfinished link
    walk's fail-closed answer. With any, ``undecided`` holds and the mixed
    value is read from them instead: it holds when located files stand beside
    them, which the mixed-undecided head names file by file.

    ``outside_files`` are the files ``_with_outside_files`` put on the line: a
    file in a git checkout other than the scanned tree (on a load that has a
    scanned tree), or one an MCP client delivered. With any, ``outside`` holds
    and the one sentence names every membership a file can have
    (``membership_clause``), since the scanned-tree sentence is false for
    them and so is the checkout one, which speaks a load with no working
    directory.
    """
    checkout_membership = bool(checkout_added) or rootless_wording
    mixed_membership = (
        bool(checkout_added)
        and len(checkout_added) < len(in_tree)
        and not rootless_wording
    )
    undecided_membership = bool(undecided_files)
    if undecided_membership:
        mixed_membership = len(undecided_files) < len(in_tree)
    return _WordingMemberships(
        checkout=checkout_membership,
        mixed=mixed_membership,
        undecided=undecided_membership,
        outside=bool(outside_files),
    )


def _tier_two_source(
    *,
    checkout_membership: bool,
    client_supplied: bool,
    mixed: bool,
    given_root: bool,
    undecided: bool,
    outside: bool,
    client_overrides: bool = False,
) -> UntrustedSource:
    """The source the tier-two confinement steps explain their drops with.

    The reporters' destinations, the scanners' own configuration,
    ``tool_version`` and the content database staleness policy take it whole.
    Detect-secrets' scan settings and ``honor_ignore_files`` take its reason and its
    remedy (``resolve_config`` passes them ``CLIENT_SUPPLIED`` or
    ``REPOSITORY_WRITTEN`` as the reason where every file's membership was decided).
    Where every file's membership was decided this is ``IN_TREE_OR_DELIVERED``, as
    it always was. Where a file is on the line only because resolving its name
    stopped before the walk finished, the
    reason is the sentence the sandbox and settle warnings give for it
    (``confinement_membership``): "inside a git checkout or the scanned tree"
    would state a location the walk never established. The flags are the ones
    those warnings get.

    With *client_overrides* the warnings also name the overrides
    (``CLIENT_OVERRIDES_SOURCE``) among the files. The membership sentence is about
    the files, so alone it would blame a value the client's overrides set on the
    walk; the reason says the overrides are the client's.

    The remedy is the one for a file nobody could place. ``KEEP_A_SETTING`` tells
    the operator to move the file out of every checkout, which a file not known to
    be in one may already be; what keeps its settings is a walk that can finish
    (``KEEP_A_SETTING_WHEN_THE_WALK_STOPPED``). Beside a file that was found in a
    checkout or the scanned directory, that one still moves out
    (``KEEP_A_SETTING_BESIDE_A_LOCATED_FILE``).
    """
    if not undecided:
        return IN_TREE_OR_DELIVERED
    reason = confinement_membership(
        checkout_membership=checkout_membership,
        client_supplied=client_supplied,
        mixed=mixed,
        given_root=given_root,
        undecided=True,
        outside=outside,
    )
    if client_overrides:
        reason = (
            f"{reason}, and {CLIENT_OVERRIDES_SOURCE.as_posix()} came from an MCP "
            "client, which is not the operator"
        )
    remedy = (
        KEEP_A_SETTING_BESIDE_A_LOCATED_FILE
        if mixed
        else KEEP_A_SETTING_WHEN_THE_WALK_STOPPED
    )
    return dataclasses.replace(
        IN_TREE_OR_DELIVERED,
        reason=reason,
        remedy=remedy,
        modules_remedy=f"{remedy} Or name the module with --ash-plugin-modules.",
    )


def resolve_config(
    config_path: Path | str | None = None,
    source_dir: Path | str | None = None,
    fallback_to_default: bool = True,
    config_overrides: List[str] = None,
    permit_base: Optional[Callable[[Path], bool]] = None,
    scanned_root: Path | str | None = None,
    trusted_config_path: Path | str | None = None,
    untrusted_config: bool = False,
    confine_checkout_files: bool = False,
    no_scanned_tree: bool = False,
    no_discovery: bool = False,
    files_read: Optional[List[Path]] = None,
    also_scanned: Sequence[Path | str] = (),
    reads: Optional[Dict[Path, Any]] = None,
    texts: Optional[Dict[Path, str]] = None,
    repository_out: Optional[List[RepositorySettings]] = None,
    chain_out: Optional[List[Path]] = None,
    client_overrides: bool = False,
    client_config_policy: Optional[Any] = None,
    remote_client: bool = False,
    overlay_config_path: Path | str | None = None,
    expect: Optional[FileIdentity] = None,
    named_config_source: Optional[UntrustedSource] = None,
) -> AshConfig:
    """
    Load configuration from file or return default configuration.

    ``expect`` is ``identity_to_hold(config_path)`` as the caller took it when it
    checked the named ``config_path``: the file is read only if it is still
    that file, and one swapped in after the check is refused
    (``ConfigFileChangedError``). It applies to the named file only; a file
    discovery selects is read as found.

    ``reads`` and ``texts`` are ``load_config_file_for_run``'s caches of files
    already read, for a caller (the config validator) that read part of the
    chain itself and resolves it again: no file is then parsed twice.

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
            ``config/sandbox_grants.py``. So are the reporter options only the
            operator may set (``config/operator_only_options.py``), and so they
            are from a file inside any other git checkout or one an MCP client
            delivered: such a file is never the operator's. Defaults to
            ``source_dir``, or the working directory when that is None too; a
            working directory deleted while the process runs leaves no root,
            and the load then turns ``no_scanned_tree`` on itself.
        trusted_config_path: The operator's own config file, when the config
            actually selected can replace it (workspace mode's default config,
            which a project's own config file replaces). Used in place of the
            defaults as the trusted base the grants come from, unless it is
            inside the scanned tree as well, inside any git checkout, or a
            file an MCP client delivered.
        untrusted_config: The selected config file was written by the caller,
            not the operator: an MCP client's upload named as ``config_path``.
            Every file of its chain is then treated as a file inside the scanned
            tree is, wherever it is: its sandbox grants come from the trusted
            base instead, its ``network_scanners`` list only removes network,
            and its ``sandbox.mode`` cannot turn off or replace a mode the
            trusted base sets. Its ``ash_plugin_modules`` are limited the same way
            as an in-tree file's (``config/plugin_module_trust.py``), and so are
            the operator-only reporter options (``config/operator_only_options.py``).
        confine_checkout_files: Deprecated and ignored; it does nothing and will
            be removed. Every load leaves the operator-only options out of a
            chain file inside any git checkout, with or without this flag
            (``scan_repository_settings``), as the confinement steps below hold
            such a file to the trusted base.
        no_discovery: The caller already ran config discovery itself, under
            its own gates, and found nothing: this load never runs discovery,
            so a config file created in ``source_dir`` since the caller's own
            check cannot be selected here ungated. With ``config_path`` None
            the load then answers from the ASH_CONFIG chain and the defaults
            alone; ``source_dir`` keeps its other roles (the scanned-root
            fallback). Beside a named ``config_path``, which already skips
            the selection step, it also skips the ignored-sources re-check a
            discovered-and-named file otherwise gets
            (``_warnings_when_discovered``), keeping the promise that this
            load runs no discovery at all.
        no_scanned_tree: The caller knows no tree is scanned (the working
            directory was deleted while the server runs; the load also turns
            this on itself when it finds no root, no source directory and no
            working directory), so the in-tree membership that drives the
            confinement steps runs on the any-checkout rule instead of an
            empty tree list skipping it. Every read of the operator-only
            options already confines any checkout's file, with or without a
            tree (``scan_repository_settings``): the ASH_CONFIG chain and the
            trusted base as the MCP get_config tool's ASH_CONFIG pre-check
            reads them, and the selected config's own chain. The plugin-module
            drop is the one step whose RULE does not switch with it: modules
            stay judged against the given root when the caller passes one,
            and only the membership wording and the rootless judgment take
            the any-checkout rule. A value such a
            read leaves out then never refuses the file the caller asked for.
        files_read: A list to extend with every config file the result was
            built from: the config's ``extends`` chain, the operator's, and the
            ASH_CONFIG file's, for a caller that names them all without telling
            the chains apart. A caller that needs the selected chain itself
            takes ``chain_out``, and the operator-file marking takes
            ``repository_out``, below.
        also_scanned: Other directories whose repository counts as scanned too,
            for a caller with more than one: ``ash report`` passes the directory
            of the results it renders, whose repository wrote them, as well as
            the working directory.
        repository_out: A list to append the ``RepositorySettings`` the selected
            config's chain was read with: the record of what each checkout file
            of that chain wrote for the operator-only options. For the MCP
            get_config tool, which marks those options ignored from this one
            read instead of resolving the chain a second time against a
            filesystem that may have changed since.
        chain_out: A list to extend with the SELECTED config's chain, in
            chain order, from this load. The caller that needs the selected
            chain takes it here directly instead of reverse-engineering how
            ``files_read`` was put together: a subtraction there dropped the
            first copy of a base both chains extend, whichever chain it
            belonged to, and kept the operator's files.
        client_overrides: ``config_overrides`` came from an MCP client (a
            workspace tool's), not the operator, so none of them is replayed
            onto the trusted base, a tool path they name is not the
            operator's (``path_trust.OperatorPaths``), and the warnings name
            ``config_overrides`` as a confined source. Implied when
            ``client_config_policy`` is set and there are overrides.
        client_config_policy: The rules a file of the chain that an MCP client
            delivered is checked against; see ``config/client_config_policy.py``.
            None, with ``client_overrides`` set, takes the trusted base's.
            When set, ``config_overrides`` are the client's too.
        remote_client: The config is read for an MCP call from a remote client
            (``cli/mcp/sandbox.caller_is_remote``). Every file of the chain the
            operator did not set aside then resolves no ``!ENV``, and one that
            uses it is refused; otherwise only a file an MCP client delivered
            is. The operator's own files (``trusted_config_path``,
            ``ASH_CONFIG``) are read as before.
        overlay_config_path: A config file merged over the selected one before
            it is validated, by the ``extends`` rule with this file as the
            child (``config_sources.deep_merge``). The file is resolved on its
            own first; then every field the result holds replaces the selected
            config's, mappings merge key by key, and a list it holds replaces
            the selected config's list whole. ``config_overrides`` apply after
            it. When no config file was found, this file is used alone. Every
            file it is built from must be the operator's
            (``_refuse_unless_the_operators``); workspace mode passes the
            operator's ``--config`` here for a project with a config of its
            own, and the same file as ``trusted_config_path``. Not combined
            with ``untrusted_config``.
        named_config_source: The source the reporters' warning gives for every
            file this load holds to the rules for a repository's config, in place
            of the one its location gives: the named file, and a file inside a
            tree that it extends. For a command that holds any file it is named
            (``ash report``), so the built-in reporters' warning ends with the
            remedy that command's own warning for the plugin reporters gives,
            not one that moves the file. It changes only the warning's words:
            the sources fill a section the file leaves out alike.

    Returns:
        The resolved AshConfig object
    """
    chain: List[Path] = []
    named: List[Path] = []
    # The load's own caches when the caller brought none: each chain file's
    # one read, which the off-host reporter view below reads the files'
    # own documents from (_operator_chain_reporters). The per-file document
    # cache is always materialized here: the trusted base's sandbox-mode
    # floor reads each chain file's own write from it (_owned_sandbox_mode),
    # carried out of the same load as the views.
    if reads is None:
        reads = {}
    if texts is None:
        texts = {}
    # The files of the chain an extends entry chose with a value read from the
    # environment, and every base below each: the confinement warnings name
    # them <value>, as the source chain does.
    environment_paths: Set[Path] = set()
    if scanned_root is None:
        # The deleted-cwd-safe read: a caller that can run with no working
        # directory (MCP get_config, the validator's module check) either
        # passes source_dir or reaches working_directory(). With neither a
        # root, a source directory, nor a working directory, no tree is
        # known: no_scanned_tree turns on below, so the ASH_CONFIG chain, the
        # trusted base, the selected chain AND the in-tree membership all
        # fail closed on the any-checkout rule, instead of raising out of
        # Path.cwd() or an empty tree list skipping the confinement steps.
        scanned_root = source_dir if source_dir is not None else working_directory()
    if scanned_root is None:
        no_scanned_tree = True
        trees: List[Path] = []
    else:
        trees = scanned_trees(Path(scanned_root))
    for extra in also_scanned:
        trees.extend(tree for tree in scanned_trees(Path(extra)) if tree not in trees)
    # The files whose relative paths are taken from their own directory
    # (config/operator_paths.py).
    operators_files = the_operators_files(trees)
    # The wording flag for every no-tree load whose trees are known: they came
    # from a root (scanned_root, or the source directory it was rebound to) or
    # from also_scanned. Keyed on the trees, not on the root, so a load whose
    # only trees are also_scanned's never claims a scanned tree it declared it
    # does not have. Deliberately a load-shape flag, not a per-file one: it
    # stays True when every confined file is the any-checkout rule's, because
    # the sentence for a checkout file under known trees is the root-aware
    # one (membership_clause's checkout-and-given-root arm), and which files
    # are on the line is already said by checkout_membership and
    # mixed_membership below.
    given_root_membership = no_scanned_tree and bool(trees)
    # The load has no root at all and no known trees (the confine steps
    # below get scanned_root None, and confine_plugin_modules judges by the
    # any-checkout rule). With no trees, files_inside admits only the files
    # the host marked as the repository's, and a mark is the host's checkout
    # verdict (in_a_checkout counts a marked file wherever it sits); every
    # other confined file is the any-checkout rule's. So every file on a
    # rootless line is in a checkout, and the wording is the checkout one.
    # checkout_added below does not hold the marked files (files_inside
    # admitted them already), so without this term a marked file would be
    # worded as "inside the scanned tree" beside the every-checkout
    # judgment, one self-contradicting sentence. Computed here, once, so the
    # sandbox, settle and module warnings all speak the same value; the
    # resolve_config-level cell that pins it drives a marked file on a load
    # with no working directory.
    rootless_wording = (
        no_scanned_tree and scanned_root is None and not given_root_membership
    )
    # The client and overlay pipeline. Everything here is inert when
    # none of client_overrides, client_config_policy, remote_client and
    # overlay_config_path is given: the load then runs the plain protocol.
    if overlay_config_path is not None and untrusted_config:
        # untrusted_config treats every file of the chain as the caller's, which
        # would include the overlay, the operator's own file.
        raise ValueError("overlay_config_path cannot be combined with untrusted_config")
    # Under the MCP server the overrides come from the client, held to the
    # session's allowlist. A caller that passes client_overrides says the same
    # of a workspace tool's overrides.
    client_overrides = client_overrides or (
        client_config_policy is not None and bool(config_overrides)
    )
    if not client_overrides and client_config_policy is None and config_overrides:
        # The operator's --config-overrides: a relative path in one is taken from
        # the working directory ASH runs in, not the scanned tree
        # (config/operator_paths.py). Anchored once here, so the config and every
        # replay onto the trusted base below read the same value.
        config_overrides = _anchored_operator_overrides(config_overrides)
    # The overrides that count as the operator's choice, replayed onto the
    # trusted base below. An allowlist that lets a client change a field does
    # not make the client's value the operator's, so none is replayed there.
    operator_overrides = (
        list(config_overrides or [])
        if client_config_policy is None and not client_overrides
        else []
    )
    # An MCP client's overrides are applied, but they are not the operator's.
    client_supplied_overrides = (
        list(config_overrides or []) if client_overrides else None
    )
    # Which files of the selected chain resolve no !ENV. Computed only when one
    # of the client/overlay inputs is given, so a plain call keeps the load's
    # own default.
    refuse_env: Optional[RefuseEnv] = None
    if (
        remote_client
        or client_config_policy is not None
        or (overlay_config_path is not None)
    ):
        refuse_env = env_refused_for(
            remote_client, getattr(client_config_policy, "session_id", None)
        )
    overlay: Optional[ResolvedConfigDocument] = None
    if overlay_config_path is not None:
        overlay = _load_overlay(
            overlay_config_path,
            source_dir,
            permit_base,
            refuse_env,
            operators_files,
            reads=reads,
            texts=texts,
        )
        if scanned_root is None:
            # With no root there is nothing to judge the overlay's files
            # against, and a file that cannot be shown to be the operator's
            # must not be final over every project: refused, fail closed.
            raise ASHConfigValidationError(
                "The operator config layered over each project's own config "
                "cannot be checked with no scanned root (the working "
                "directory is gone), so it is refused."
            )
        _refuse_unless_the_operators(overlay, Path(scanned_root))
    # The copy of a profile a client patched holds each value the profile read
    # from the environment as its reference; it is read from the operator's
    # copy it was built from (cli/mcp/profile_registry.is_client_copy_of).
    fill: List[Any] = []
    if config_path is not None and trusted_config_path is not None:
        from automated_security_helper.cli.mcp.profile_registry import (
            is_client_copy_of,
        )

        if is_client_copy_of(config_path, trusted_config_path):
            fill = list(
                read_config_document(
                    Path(trusted_config_path),
                    confine_to=default_confinement_root(Path(trusted_config_path)),
                    permit_base=permit_base,
                ).environment_references
            )
    # The selected chain's per-file documents and names, for the client rules.
    client_documents: Dict[Path, Any] = {}
    client_names: Dict[Path, Tuple[Path, ...]] = {}
    # What the repository's files write for the options only the operator sets
    # is left out as the chain is read, before the model validates it
    # (config/operator_only_options.py). A file inside ANY checkout is the
    # repository's here, not only one the scanned trees hold (with no scanned
    # tree, the trees are the given root's when the caller passed one, and
    # none only when the load has no root at all): the confinement steps
    # below hold such a file to the trusted base (_with_outside_files), and the
    # options only the operator sets are held to the same membership, or one
    # file would be the operator's for one memory bound and not for the next.
    # Every loader that reads a chain as a scan reads it builds its settings
    # with the same constructor (scan_repository_settings) from the same
    # trees, so a pre-check made before this load takes the trees this load
    # takes (MCP get_config's ASH_CONFIG pre-check does).
    repository = scan_repository_settings(trees, every_file=untrusted_config)
    if repository_out is not None:
        repository_out.append(repository)
    # The same for the ASH_CONFIG chain, which the scan reads first and which is
    # its configuration when no config file is selected. One read: the values it
    # leaves out are recorded from the documents the configuration is built
    # from, so a file of the chain that changes after that read cannot leave a
    # value in place unsettled.
    default_repository = scan_repository_settings(trees)
    # The ASH_CONFIG chain's key reads and document views, carried out of the
    # one load below: the fail-closed warning redacts its place strings
    # against the KEY reads (a place string is built from mapping keys
    # alone), and the membership judgments read the chain the load read,
    # instead of resolving the chain a second time, which a file changed in
    # between could skew.
    default_key_values: List[str] = []
    default_document_views: List[Tuple[List[Path], List[Path], FrozenSet[Path]]] = []
    carried_default_config: List[AshConfig] = []
    # The selected chain's merged document, before overrides, carried out of
    # the one load for the operator-paths record (_operator_paths).
    merged_documents: List[Any] = []
    config = _resolve_config(
        config_path,
        source_dir,
        fallback_to_default,
        config_overrides,
        permit_base,
        chain,
        named,
        environment_paths,
        no_discovery=no_discovery,
        reads=reads,
        texts=texts,
        confine=repository.confine,
        default_confine=default_repository.confine,
        repository_file=repository.is_repository_file,
        default_repository_file=default_repository.is_repository_file,
        default_key_values=default_key_values,
        default_views=default_document_views,
        default_config_out=carried_default_config,
        merged=merged_documents,
        refuse_env=refuse_env,
        overlay=overlay,
        fill=fill,
        anchor_paths=None if untrusted_config else operators_files,
        documents_out=client_documents,
        names_out=client_names,
        expect=expect,
    )
    # The ASH_CONFIG slice of the files read: the one load's own chain, or
    # none when the load never read one -- never a fresh resolution, which
    # could describe files the load never confined.
    ash_config_slice = (
        list(default_document_views[0][0]) if default_document_views else []
    )
    if files_read is not None:
        files_read.extend(chain)
        files_read.extend(ash_config_slice)
    if chain_out is not None:
        chain_out.extend(chain)

    def warn_fail_closed() -> None:
        # The fail-closed read of the ASH_CONFIG chain left operator-written
        # values out, and no settle step will say so on this path, so this is
        # the one warning. Places only, never a value -- and a section KEY an
        # entry of that chain read from the environment IS what the variable
        # holds, so the places are redacted against the KEY reads the load
        # above carried out, through the one redaction the settle warnings
        # use (redacted_places), so the two voices cannot disagree on what a
        # place shows.
        from automated_security_helper.config.operator_only_options import (
            found_place,
            redacted_places,
        )

        places = {found_place(entry) for entry in default_repository.found}
        stopped = sorted(places & default_repository.undecided_places)
        located = sorted(places - default_repository.undecided_places)
        clauses = []
        if located and given_root_membership:
            # The trees are the given root's: a file is left out because the
            # root's tree holds it as well as because a checkout does, so the
            # sentence names both and claims no checkout for the first.
            clauses.append(
                f"{redacted_places(', '.join(located), default_key_values)} "
                "from its files in a checkout or in the given root's trees "
                "is left out, as a scan reads such a file as the repository's"
            )
        elif located:
            clauses.append(
                f"{redacted_places(', '.join(located), default_key_values)} "
                "from its files in a checkout is left out, as a scan of "
                "that checkout leaves it out"
            )
        if stopped:
            clauses.append(
                f"{redacted_places(', '.join(stopped), default_key_values)} "
                "from a file whose location could not be decided (resolving "
                "its name stopped before the walk finished) is left out, as "
                "a scan reads such a file as the repository's"
            )
        ASH_LOGGER.warning(
            "With no scanned tree, the configuration ASH_CONFIG names is "
            f"read fail-closed: {'; '.join(clauses)}",
            extra=NO_MARKUP,
        )

    warn_pending = bool(no_scanned_tree and default_repository.found)
    # Each file is judged by its resolved path and by the name that reached it:
    # a config file that is a symlink out of the tree was still put there by the
    # repository (files_inside). The chain, the names and the environment-chosen
    # paths come from the ONE load above where it read the ASH_CONFIG file
    # (default_document_views, carried out of get_default_config), so the
    # membership judgments and the warnings describe the same files that load
    # confined. With nothing carried that load never read an ASH_CONFIG
    # chain (the variable is unset, or a stand-in ignored the out-list), so
    # the views are empty: re-resolving the variable here could describe
    # files the load never confined.

    def default_views() -> Tuple[List[Path], List[Path], FrozenSet[Path]]:
        if default_document_views:
            return default_document_views[0]
        return ([], [], frozenset())

    # The chain the operator reporter view below walks: the selected config's
    # chain, or the ASH_CONFIG chain when no config file is selected -- the
    # configuration IS that chain then, so its operator files' reporter writes
    # are the operator's choice the same way a selected chain's are. The
    # no-config branch rebinds it.
    view_chain: Sequence[Path] = chain
    # How many extends trees the view chain holds. _resolve_config lays the
    # operator's overlay chain AFTER the selected config's (one root each), so
    # a chain longer than the overlay's own holds two; with the fallback taken
    # the overlay's chain is the whole chain, one root. Read as one tree, a
    # two-root chain failed to rebuild and the operator views took nothing,
    # the overlay's own writes included. The no-config branch rebinds it.
    view_roots = (
        2
        if overlay is not None and overlay.chain and len(chain) > len(overlay.chain)
        else 1
    )

    def refuse_owned_junk(
        selected_in_tree: Sequence[Path], default_in_tree_files: Sequence[Path]
    ) -> None:
        """The one junk pass over every operator-owned file of BOTH chains --
        the selected config's and the ASH_CONFIG file's, each with its own
        membership and views -- on every load path, before any early return.
        An owned file that writes a sandbox mode outside the known set, or a
        sandbox section that is not a mapping, refuses the load: a later
        write in the chain could bury it under a section the merged load
        accepts, so the scan would run without the sandbox the operator's own
        file tried to set. Both chains are walked whichever of them the
        flags selected, because the ASH_CONFIG file is the base either way and
        whether the junk is caught must not turn on which flags were given.
        Separate from the floor's computation (trusted_base_config), whose
        answer stays where it is; the answers here are discarded."""
        if chain:
            _owned_sandbox_mode(
                chain, selected_in_tree, reads, environment_paths, roots=view_roots
            )
        default_chain_files, _named, default_environment_paths = default_views()
        if default_chain_files:
            _owned_sandbox_mode(
                default_chain_files,
                default_in_tree_files,
                reads,
                default_environment_paths,
            )

    if config is None:
        # No config came out of the load (a caller that does not fall back
        # names a file that is not there), but the ASH_CONFIG chain was still
        # read as its base, so the junk pass runs here too, by the same
        # membership the no-config branch below uses, before this return.
        default_chain, ash_config_named, _ = default_views()
        default_in_tree = files_inside(default_chain, trees, ash_config_named)
        if no_scanned_tree:
            default_in_tree = _with_any_checkout_files(
                default_in_tree, default_chain, ash_config_named
            )
        refuse_owned_junk([], default_in_tree)
        if warn_pending:
            warn_fail_closed()
        return config

    # What the operator's copy of a client-patched profile read from the
    # environment joins the config's references first, as the source chain
    # ordered them. These are the references views, saved copies and messages
    # read; the record of the configuration (its rewrites) and the values
    # redacted took them at the load, at the places the fill read them
    # (load_config_file_for_run).
    if fill:
        config._environment_references = (
            *tuple(fill),
            *tuple(config._environment_references or ()),
        )
    # The client config rules: a delivered file's denied fields are
    # refused or dropped, and every client_supplied mark is ASH's own. Run on
    # every resolution, as a plain call: an untrusted or delivered file must
    # reach the refusal whether or not a policy object or client overrides
    # came with it, and with neither the call changes nothing.
    from automated_security_helper.config.client_config_policy import (
        apply_client_config_rules,
        clear_client_supplied_marks,
    )

    if not chain and default_document_views:
        # With no config file the configuration IS the ASH_CONFIG chain: a
        # file of it under the MCP workspace root is a client's, and is
        # checked as one named with --config is. The operator's own
        # ASH_CONFIG is not checked. (The per-file names of that chain are
        # not carried on this protocol; the documents are, from the one
        # load's reads.)
        from automated_security_helper.cli.mcp.sandbox import (
            config_is_client_supplied,
        )

        rules_chain, rules_named, _ = default_views()
        if any(
            config_is_client_supplied(path) for path in (*rules_chain, *rules_named)
        ):
            for path in rules_chain:
                key = Path(path).resolve()
                if key in reads:
                    client_documents.setdefault(Path(path), reads[key])
    config = clear_client_supplied_marks(config)
    config = apply_client_config_rules(
        config,
        client_documents,
        rules=client_config_policy,
        trusted_config_path=trusted_config_path,
        source_dir=source_dir,
        permit_base=permit_base,
        # The spine resolves the root before the load (the deleted-cwd
        # fallback above), so the rules see the resolved root where the
        # earlier code passed the caller's raw value.
        scanned_root=scanned_root,
        all_delivered=untrusted_config,
        client_overrides=client_overrides,
        names=client_names,
    )

    # Which tool paths in the configuration the operator named, recorded on the
    # config for ``path_trust.honored_path``'s operator tier
    # (``AshConfig._operator_paths``). With no scanned root there is nothing to
    # judge the files against, so only the overrides are recorded, which fails
    # closed (every configured path is then judged as repository-named).
    ash_config_value = os.environ.get("ASH_CONFIG")
    paths_default_chain, paths_default_named, _ = default_views()
    config._operator_paths = _operator_paths(
        chain or list(paths_default_chain),
        list(named)
        if chain
        else [
            *([Path(ash_config_value)] if ash_config_value else []),
            *paths_default_named,
        ],
        named[:1] if chain else ([Path(ash_config_value)] if ash_config_value else []),
        None if scanned_root is None else Path(scanned_root),
        merged_documents[0] if merged_documents else None,
        untrusted=untrusted_config,
        overrides=list(operator_overrides),
        reads=reads,
        default_config=(carried_default_config[0] if carried_default_config else None),
    )
    if overlay is not None and isinstance(overlay.data, dict):
        # The overlay's merged document is the operator's by construction
        # (_refuse_unless_the_operators), whatever the selected chain holds:
        # a tool path it names is the operator's for every project, the ones
        # with a config of their own included, which the record above judged
        # by the selected root's name alone.
        config._operator_paths.documents.append(overlay.data)

    if chain:
        if warn_pending:
            # With a selected config, the settle step below names only that
            # chain's options, so the ASH_CONFIG chain's left-out places get
            # the fail-closed warning here, once.
            warn_fail_closed()
        # The names of this chain no walk of the load could place: the walk over
        # the scanned trees, then the walks of the any-checkout helpers below, which
        # also walk each chain file and add to this list as they run. The root's own
        # sandbox section is judged by all of them (_with_own_sandbox): a root that
        # is on the confinement line only because the second kind of walk stopped is
        # not the operator's either.
        undecided_files: List[Path] = []
        if untrusted_config:
            in_tree = list(chain)
        else:
            judged = confined_files(chain, trees, named)
            in_tree = list(judged.members)
            undecided_files = list(judged.undecided)
        # The files the ANY-CHECKOUT rule put under the confinement, kept as
        # a list: the warnings' checkout wording follows the rule that added
        # each file, so a file files_inside added -- a plain non-checkout
        # root is its own tree -- is never said to be in a checkout, and a
        # chain holding files of BOTH memberships gets the mixed sentence
        # instead of one that is false for half its files.
        checkout_added: List[Path] = []
        if no_scanned_tree and not untrusted_config:
            # With no scanned tree, a chain file inside ANY checkout is the
            # repository's -- the fail-closed membership the chain's
            # operator-only read already used -- so the confinement steps
            # below run for it (off-host section included) instead of the
            # empty tree list returning the checkout file as the operator's.
            tree_members = len(in_tree)
            in_tree = _with_any_checkout_files(
                in_tree, chain, named, undecided_out=undecided_files
            )
            checkout_added = list(in_tree[tree_members:])
        # The files the scanned trees (and, with no tree, the any-checkout
        # rule above) hold, which the owned-junk pass reads as it always did:
        # the operator's own files are the rest, a file in another checkout
        # among them. The sandbox-mode floor reads the same membership
        # (_repository_members), not this list.
        owned_in_tree = list(in_tree)
        # A chain file in ANY checkout or delivered by an MCP client is not
        # the operator's either, whether or not the scanned tree holds it
        # (_with_outside_files): it joins the confinement, so a chain wholly
        # outside the scanned trees but not the operator's no longer returns
        # below as if it were. With no scanned tree the checkout leg ran above.
        outside_added: List[Path] = []
        if not untrusted_config:
            outside_from = len(in_tree)
            in_tree = _with_outside_files(
                in_tree,
                chain,
                named,
                client_names,
                undecided_out=undecided_files,
                any_checkout=not no_scanned_tree,
            )
            outside_added = list(in_tree[outside_from:])
        # The wording values, shared by the sandbox, settle and module
        # warnings (see _wording_memberships). Files on the line only by an
        # unfinished walk's fail-closed answer: the one sentence then says the
        # walk stopped (membership_clause's undecided arms) instead of stating
        # a location it never established, and with located files beside them
        # the mixed-undecided arm names each file's own reason. Wording only;
        # the judgment is unchanged.
        memberships = _wording_memberships(
            checkout_added=checkout_added,
            in_tree=in_tree,
            rootless_wording=rootless_wording,
            undecided_files=undecided_files,
            outside_files=outside_added,
        )
        checkout_membership = memberships.checkout
        mixed_membership = memberships.mixed
        undecided_membership = memberships.undecided
        outside_membership = memberships.outside
        if client_supplied_overrides:
            # Named in the warnings as the source of what is confined, and
            # non-empty so the confinement steps run even over a chain that is
            # wholly the operator's own.
            in_tree = [*in_tree, CLIENT_OVERRIDES_SOURCE]
            owned_in_tree = [*owned_in_tree, CLIENT_OVERRIDES_SOURCE]
        default_chain, ash_config_named, _ = default_views()
        default_judged = confined_files(default_chain, trees, ash_config_named)
        default_in_tree = list(default_judged.members)
        default_walk_stopped = list(default_judged.undecided)
        if no_scanned_tree:
            # The ASH_CONFIG chain by the same rule: with no tree, bool() of
            # this list decides whether the trusted base may be ASH_CONFIG's
            # file (trusted_base_config), so a checkout ASH_CONFIG file must
            # count as the repository's here too, or its sandbox grants and
            # plugin modules become the trusted base.
            default_in_tree = _with_any_checkout_files(
                default_in_tree,
                default_chain,
                ash_config_named,
                undecided_out=default_walk_stopped,
            )
        owned_default_in_tree = list(default_in_tree)
        # The same for the ASH_CONFIG chain: a file of it in ANY checkout or
        # delivered by an MCP client cannot be the trusted base the grants are
        # held to. Its names are carried as one flat list, so every name
        # counts for every file, which judges a mixed chain from the safe side.
        default_in_tree = _with_outside_files(
            default_in_tree,
            default_chain,
            ash_config_named,
            _flat_names(default_chain, ash_config_named),
            undecided_out=default_walk_stopped,
            any_checkout=not no_scanned_tree,
        )
        refuse_owned_junk(owned_in_tree, owned_default_in_tree)
        if not in_tree:
            # The chain is wholly the operator's own, so the confinement
            # steps below are skipped and the trusted-base build never walks
            # this chain. The junk pass above already ran over both chains.
            record_provenance(config, in_tree=[])
            return config
    else:
        # With no config file, the config is get_default_config(): ASH_CONFIG's
        # file when that variable names one, which can be inside the tree too.
        default_chain, ash_config_named, _ = default_views()
        view_chain = list(default_chain)
        view_roots = 1
        judged = confined_files(default_chain, trees, ash_config_named)
        in_tree = default_in_tree = list(judged.members)
        undecided_files = list(judged.undecided)
        checkout_added = []
        if no_scanned_tree:
            # The same fail-closed membership the selected chain's branch above
            # uses: with no tree, an ASH_CONFIG chain file inside ANY checkout
            # is the repository's, so the confine steps below (off-host section
            # and sandbox grants included) run for it instead of the empty tree
            # list returning its writes as the operator's.
            tree_members = len(in_tree)
            in_tree = default_in_tree = _with_any_checkout_files(
                in_tree, default_chain, ash_config_named, undecided_out=undecided_files
            )
            checkout_added = list(in_tree[tree_members:])
        # The files the scanned trees (and, with no tree, the any-checkout
        # rule above) hold: the junk pass reads that membership.
        owned_default_in_tree = list(in_tree)
        # The ASH_CONFIG chain's files in ANY checkout or delivered by an MCP
        # client are not the operator's either (_with_outside_files), as in
        # the selected chain's branch above; the flat list of names is
        # judged as the same branch judges it.
        outside_from = len(in_tree)
        in_tree = default_in_tree = _with_outside_files(
            in_tree,
            default_chain,
            ash_config_named,
            _flat_names(default_chain, ash_config_named),
            undecided_out=undecided_files,
            any_checkout=not no_scanned_tree,
        )
        outside_added = list(in_tree[outside_from:])
        # The answer for the root's own sandbox section: every walk of this chain,
        # the any-checkout helpers' included.
        default_walk_stopped = list(undecided_files)
        # The wording values, shared by the sandbox, settle and module
        # warnings (see _wording_memberships). As in the selected chain's
        # branch: an unfinished walk's files make the sentence say the walk
        # stopped. Wording only.
        memberships = _wording_memberships(
            checkout_added=checkout_added,
            in_tree=in_tree,
            rootless_wording=rootless_wording,
            undecided_files=undecided_files,
            outside_files=outside_added,
        )
        checkout_membership = memberships.checkout
        mixed_membership = memberships.mixed
        undecided_membership = memberships.undecided
        outside_membership = memberships.outside
        if client_supplied_overrides:
            # Named in the warnings as the source of what is confined.
            in_tree = [*in_tree, CLIENT_OVERRIDES_SOURCE]
        refuse_owned_junk(owned_default_in_tree, owned_default_in_tree)
        if not in_tree:
            if warn_pending:
                warn_fail_closed()
            # The ASH_CONFIG chain is wholly the operator's own: the junk
            # pass above ran over it, and nothing below confines it.
            record_provenance(config, in_tree=[])
            return config
        # The configuration IS the ASH_CONFIG chain and its files are in the
        # confinement, so the settle step below names the left-out places
        # itself: the fail-closed warning would say the same thing twice. The
        # settle step names only places whose written value DIFFERS from the
        # trusted one -- deliberately narrower than the found record, because
        # a repository write equal to the trusted value changes no behavior,
        # and warning on it would name a no-op.
        environment_paths = set(default_views()[2])
        repository = default_repository
    operator = _load_operator_config(
        trusted_config_path, source_dir, permit_base, operators_files
    )
    if files_read is not None and operator is not None:
        files_read.extend(operator.chain)
    # Whether a file of the ASH_CONFIG chain was delivered by an MCP client,
    # by the same names the default-chain membership above judges it under:
    # the base keeps what only restricts from ASH_CONFIG's file in another
    # checkout, and nothing from a delivered one (restrictions_kept).
    base_default_chain, base_default_named, _ = default_views()
    default_delivered = bool(
        _delivered_by_a_client(
            base_default_chain, _flat_names(base_default_chain, base_default_named)
        )
    )
    trusted = trusted_base_config(
        operator,
        trees,
        bool(default_in_tree),
        any_checkout=no_scanned_tree,
        # The default config THIS flow already loaded, under the identical
        # confine construction (default_repository above and the base's own
        # confine are both scan_repository_settings(trees): the scanned trees
        # and any other checkout), so the trusted
        # base is built from the same read the membership judgments used --
        # a second read could see a chain file changed in between. The views
        # and the per-file documents of that same read ride beside it, for
        # the floor's owned-mode walk.
        default_config=(carried_default_config[0] if carried_default_config else None),
        default_views=(default_document_views[0] if default_document_views else None),
        default_reads=reads,
        # The scan's own resolution: with no operator-owned write, the merged
        # mode stands, so a config the operator named inside the tree still
        # sets the mode the scan applies. The container floor passes False.
        merged_fallback=True,
        # The operator's config is the trusted base only when no file of its
        # chain is inside ANY checkout or delivered by an MCP client; the same
        # for ASH_CONFIG's file, which is "in the tree" for the base only by
        # those rules when the trees hold none of it.
        outside_files=True,
        default_outside=bool(default_in_tree) and not owned_default_in_tree,
        default_delivered=default_delivered,
    )
    # The trusted config's off-host reporter sections, named when that config is
    # not the operator's file for them (a file in a checkout or in the tree, or
    # a delivered one): the project's configuration never held them.
    _warn_dropped_operator_reporters(
        operator,
        trees,
        chain,
        given_root_membership=given_root_membership,
        rootless_wording=rootless_wording,
    )
    # The scanners a network_scanners list in the base's file in another
    # checkout allows a network (restrictions_kept), read here: the rebuilds of
    # the trusted sandbox settings below do not carry it.
    base_network_limit = trusted.sandbox.network_limit
    # The own-sandbox rule (_with_own_sandbox): a root config that may
    # grant, made untrusted only by a base it extends, keeps the sandbox
    # settings it writes itself. Judged fail-closed inside _with_own_sandbox by
    # the file's own location and names; a root that is itself the
    # repository's or a client's adds nothing. A mode such a file writes is
    # the operator's choice, so it stands over the floor the trusted base
    # carries, ``off`` included.
    # Each root is judged by the names it was reached by, from the per-file map
    # its load carried; only the root's own entry is read. The names of the
    # bases it extends are those bases', and a base inside the tree is the case
    # this rule exists for: judging the root by its bases' names would drop
    # what the root writes itself whenever a base sits there.
    if scanned_root is not None:
        own_root = Path(scanned_root)
        operator_walk_stopped: List[Path] = []
        operator_judged_in_tree: List[Path] = []
        operator_outside: List[Path] = []
        if operator is not None:
            operator_judged = confined_files(operator.chain, trees, operator.named)
            operator_judged_in_tree = list(operator_judged.members)
            operator_walk_stopped = list(operator_judged.undecided)
            # The files trusted_base_config's outside_files judges the same
            # way: delivered by an MCP client, and, with a scanned tree, inside
            # ANY checkout. (With no scanned tree its any_checkout arm covers
            # the checkout leg, and this list keeps its earlier reading.) The
            # files this leg admits only on a walk that stopped join
            # operator_walk_stopped, which the root's own sandbox section is
            # judged by.
            operator_outside = _with_outside_files(
                [],
                operator.chain,
                operator.named,
                operator.names,
                undecided_out=operator_walk_stopped,
                any_checkout=not no_scanned_tree,
            )
        operator_chain_in_tree = operator is not None and bool(
            operator_judged_in_tree or operator_outside
        )
        own_default_chain, own_default_named, _ = default_views()
        # A root the confinement warning already names for an unfinished walk
        # (it is among undecided_files: the selected config, or the ASH_CONFIG file
        # when no config is selected) is not asked about. The warning says the walk
        # could not be decided and which settings the file loses, and
        # _with_own_sandbox would leave the same file out for the same cause and
        # say it a second time. The file ASH_CONFIG names beside a selected config,
        # and the operator's trusted config, are not on that warning and are still
        # asked.
        if (
            (operator is None or operator_chain_in_tree)
            and default_in_tree
            and own_default_chain
            and not _root_walk_stopped(own_default_chain[-1], undecided_files)
        ):
            # The ASH_CONFIG views carry no per-file map; the name the root was
            # given is the first of them (get_default_config).
            default_root_names = list(own_default_named[:1])
            trusted, _wrote_own_mode = _with_own_sandbox(
                trusted,
                own_default_chain[-1],
                own_root,
                # The name ASH_CONFIG gave, when it sits in another checkout (a
                # link kept in an ops or dotfiles repository to a file
                # elsewhere): judged like the operator's and the selected
                # root's given names, which the resolved path alone would not
                # catch. A name in the tree or delivered is judged by the names
                # map below, which warns.
                [
                    name
                    for name in default_root_names
                    if not _not_the_operators([name], trees)
                ],
                trees,
                {Path(own_default_chain[-1]): tuple(default_root_names)},
                documents=reads,
                undecided=_root_walk_stopped(
                    own_default_chain[-1], default_walk_stopped
                ),
            )
        if operator_chain_in_tree:
            trusted, _wrote_own_mode = _with_own_sandbox(
                trusted,
                operator.chain[-1],
                own_root,
                list(operator.named[:1]),
                trees,
                operator.names,
                documents=operator.reads,
                undecided=_root_walk_stopped(operator.chain[-1], operator_walk_stopped),
            )
        if (
            chain
            and not untrusted_config
            and not _root_walk_stopped(chain[-1], undecided_files)
        ):
            # The last file of the chain is the overlay's root when there is
            # an overlay, not the config that was selected (named[0]), so its
            # names are the ones its own entry in the map holds.
            trusted, _wrote_own_mode = _with_own_sandbox(
                trusted,
                chain[-1],
                own_root,
                list(client_names.get(Path(chain[-1]), ())),
                trees,
                client_names,
                documents=client_documents,
                # The load's answer for this root: its walk finished, or the call
                # above was skipped.
                undecided=False,
            )
    # Provenance (utils/config_trust.set_by_operator), what scanners consult
    # before honoring an option that names code to run: the trusted base as
    # resolved, before the override replays, with the files that are not the
    # operator's, the operator's own overrides (replayed per section when a
    # scanner asks) and an MCP client's overrides kept apart. One record: a
    # config carries one, so a later call replaced an earlier one, and the
    # record that stood listed every override, a client's included, among the
    # operator's, so set_by_operator took a client's value for the operator's;
    # a record with no trusted view, meant for a client's overrides over an
    # operator-only chain, refused the operator's own file's values instead.
    record_provenance(
        config,
        in_tree=in_tree,
        trusted=trusted.model_copy(deep=True),
        config_overrides=operator_overrides,
        client_overrides=client_supplied_overrides,
    )
    # Only an override under `sandbox` can change the sandbox section, and replaying
    # the rest onto the defaults could fail where the config file supplied the
    # section they write into. Only the OPERATOR's overrides are replayed: an
    # MCP client's are applied to the config, never to the trusted base.
    sandbox_overrides = [
        override
        for override in operator_overrides
        if override.partition("=")[0].removesuffix("+").split(".")[0] == "sandbox"
    ]
    if sandbox_overrides:
        trusted = apply_config_overrides(trusted, sandbox_overrides)
    # The membership that put the files under the confinement, for the
    # warnings' one sentence (confinement_membership): client-supplied
    # content is confined wherever it sits (in_tree IS the chain then), so
    # neither location wording fits it.
    client_supplied = untrusted_config and bool(chain)

    # A file that is on the line only because its name walk stopped is not said to
    # sit in a checkout or the scanned tree, and is not told to move out of one:
    # the sandbox, module and tier-two steps give the sentence and the remedy for
    # it. A decided membership keeps their text.
    def tier_two_source_for(client_overrides: bool) -> UntrustedSource:
        return _tier_two_source(
            checkout_membership=checkout_membership,
            client_supplied=client_supplied,
            mixed=mixed_membership,
            given_root=given_root_membership,
            undecided=undecided_membership,
            outside=outside_membership,
            client_overrides=client_overrides,
        )

    tier_two_source = tier_two_source_for(bool(client_supplied_overrides))
    confine_sandbox_grants(
        config.sandbox,
        trusted.sandbox,
        in_tree,
        environment_paths,
        # The wording flags are the membership that built in_tree above: the
        # checkout wording only where the any-checkout rule actually added
        # files, and the mixed sentence where files of both memberships share
        # the line. A file files_inside added under a no-tree load -- a plain
        # non-checkout root is its own tree -- speaks the given root, since
        # "in a checkout" would claim a location it does not have and the
        # scanned-tree wording a tree the caller said does not exist; gating
        # on `not trees` or on the raw flag each claimed a membership wrong
        # for one of the two shapes. The given-root flag is keyed on the
        # trees themselves (given_root_membership above): a root rebound from
        # the source directory and also_scanned's trees both count, and only
        # the truly rootless load, whose files are all the any-checkout
        # rule's, is left out.
        checkout_membership=checkout_membership,
        client_supplied=client_supplied,
        mixed_membership=mixed_membership,
        given_root_membership=given_root_membership,
        undecided_membership=undecided_membership,
        outside_membership=outside_membership,
        network_limit_kept=(
            None
            if any(_sets_network_scanners(override) for override in sandbox_overrides)
            else base_network_limit
        ),
        # The warning ends with the remedy every confinement warning gives,
        # as confine_to_trusted_base's does; without a source it ends with the
        # older sentence that names no checkout.
        source=tier_two_source,
    )
    confine_plugin_modules(
        config,
        trusted,
        operator_overrides,
        # None with no scanned tree (the working directory deleted): the
        # confine then judges by the any-checkout arm (no_scanned_tree below)
        # instead of Path(None) raising out of it, and client-supplied content
        # refuses every entry outside the trusted list, since with no tree an
        # installed module's checkout could be the very one the missing
        # working directory would have named.
        None if scanned_root is None else Path(scanned_root),
        in_tree,
        environment_paths,
        no_scanned_tree=no_scanned_tree,
        # The wording follows the rule that added the files, as the sandbox
        # warning's does; the JUDGMENT stays on the real flag above.
        checkout_membership=checkout_membership,
        mixed_membership=mixed_membership,
        given_root_membership=given_root_membership,
        undecided_membership=undecided_membership,
        outside_membership=outside_membership,
        # The client blanket applies only when client content was actually
        # loaded: with a vanished config_path and the fallback taken, the
        # chain is empty and the modules being judged are the OPERATOR's
        # (ASH_CONFIG's chain), which keep the operator rules. The same
        # predicate keys the client-supplied wording of the confine steps
        # above (confinement_membership).
        untrusted=client_supplied,
        # The other scanned roots count as scanned here as they do for the
        # sandbox and settle steps above: a module location inside one of
        # their trees is refused as one inside the scan root's trees is.
        also_scanned=[Path(extra) for extra in also_scanned],
        # Only a file whose walk stopped has a source of its own here: the
        # closing sentence of a decided membership is the one this step has
        # always given.
        source=tier_two_source if undecided_membership else None,
    )
    # The confinement steps with no settle counterpart here, in the
    # order confine_to_trusted_base runs them: the reporters' destinations,
    # the scanners' own config files and tool versions, then the content
    # database staleness settings, detect-secrets' scan settings,
    # honor_ignore_files and the archive extraction limits. Each replays its
    # own overrides onto the trusted base itself.
    tier_two_documents = _cached_documents(in_tree, reads)
    tier_two_overrides = list(operator_overrides)
    # The source is recorded on config beside the record, for
    # confine_declared_reporter_destinations, which runs once the plugin modules
    # are loaded and is given no source of its own. A command that holds the file
    # it was named, and so any file that one extends, to the overrides gives its
    # own for every file of this load.
    reporter_source = (
        named_config_source if named_config_source is not None else tier_two_source
    )
    # The base the reporter confinement compares against is the operator's own
    # reporters view: the trusted base with the reporters sections the
    # operator's own chain files wrote, and their patch operations, merged over
    # it (_with_operator_chain_reporters). The trusted base alone is the
    # defaults whenever the operator's chain extends a repository file
    # (trusted_base_config, operator_in_tree), so it holds nothing the operator's
    # own files set for an off-host reporter, and comparing the resolved config
    # against it replaced the operator's own region and enable with the
    # defaults' and named them as the repository's. The view holds only what
    # operator-owned files wrote, never a repository file's values, so a
    # repository's write that differs from it is still replaced and named. The
    # reporters overrides are replayed onto this base by the confinement itself,
    # and onto the recorded view below by _with_reporter_overrides, each on a
    # copy, so an override is applied once per use.
    chain_reporters = _with_operator_chain_reporters(
        trusted, view_chain, in_tree, reads, environment_paths, roots=view_roots
    )
    confine_reporter_destinations(
        config,
        chain_reporters,
        tier_two_overrides,
        list(in_tree),
        source=reporter_source,
        in_tree_documents=tier_two_documents,
        environment_paths=environment_paths,
    )
    # The trusted base is the operator's by definition (the ASH_CONFIG chain,
    # the operator's own config, or the defaults), so a tool path the step
    # below copies in from it is the operator's for path_trust.honored_path.
    # Recorded here because the operator-paths record knows the selected
    # chain's documents only, which are the repository's in this arm, so a
    # path kept in another checkout was judged by the repository tier and
    # refused. Not for a chain the caller marked untrusted, whose record stays
    # the overrides alone.
    if config._operator_paths is not None and not untrusted_config:
        config._operator_paths.documents.append(trusted.model_dump())
    confine_scanner_config_files(
        config, trusted, tier_two_overrides, list(in_tree), source=tier_two_source
    )
    confine_tool_versions(
        config, trusted, tier_two_overrides, list(in_tree), source=tier_two_source
    )
    confine_content_db_staleness(
        config, trusted, tier_two_overrides, list(in_tree), source=tier_two_source
    )
    tier_two_reason = CLIENT_SUPPLIED if client_supplied else REPOSITORY_WRITTEN
    honor_reason = tier_two_reason
    # The overrides entry stands for a client's overrides in the warnings of
    # the other steps; here it is named only when those overrides set the key, or
    # the warning would blame them for a value the trusted base gave. For a file
    # whose walk stopped the reason says the overrides are the client's under the
    # same condition.
    honor_set_by_overrides = bool(
        _honor_ignore_files_overrides(client_supplied_overrides)
    )
    if undecided_membership:
        tier_two_reason = tier_two_source.reason
        honor_reason = tier_two_source_for(honor_set_by_overrides).reason
    confine_detect_secrets_settings(
        config,
        trusted,
        tier_two_overrides,
        list(in_tree),
        tier_two_reason,
        remedy=tier_two_source.remedy,
    )
    honor_in_tree = [path for path in in_tree if Path(path) != CLIENT_OVERRIDES_SOURCE]
    if honor_set_by_overrides:
        honor_in_tree.append(CLIENT_OVERRIDES_SOURCE)
    honor_decided_by_operator = confine_honor_ignore_files(
        config,
        trusted,
        tier_two_overrides,
        honor_in_tree,
        honor_reason,
        # Every file of the chain, not only the confined ones: the value in
        # force is the operator's, and kept, when the last file that writes the
        # key is one the confinement did not take.
        documents=reads,
        chain=view_chain,
        remedy=tier_two_source.remedy,
        environment_paths=environment_paths,
    )
    # The same for honor_ignore_files: a false the trusted config, or the file
    # ASH_CONFIG names beside a config of the project's own, wrote in a chain
    # that sits in another checkout is not applied, and nothing else says so.
    # With no config selected, ASH_CONFIG's chain IS the configuration and the
    # confinement step above names its files. Said once the value in force is
    # settled, so the warning reports the value the scan uses. When a file of the
    # operator's own that wrote the key last decided the value, it keeps its value
    # over the trusted base's, so the warning is given only for a dropped chain
    # that wrote the opposite of both, and it names that file.
    if operator is not None:
        operator_files_stopped: List[Path] = []
        _warn_dropped_honor_ignore_files(
            operator.config,
            operator.chain,
            _operator_files_under_the_rule(
                operator, trees, chain, undecided_out=operator_files_stopped
            ),
            operator.reads,
            config,
            chain,
            operator.environment_paths,
            given_root_membership=given_root_membership,
            rootless_wording=rootless_wording,
            undecided_files=operator_files_stopped,
            decided_by_operator=honor_decided_by_operator,
        )
    if chain and carried_default_config:
        _warn_dropped_honor_ignore_files(
            carried_default_config[0],
            base_default_chain,
            default_in_tree,
            reads,
            config,
            chain,
            default_views()[2],
            given_root_membership=given_root_membership,
            rootless_wording=rootless_wording,
            undecided_files=default_walk_stopped,
            decided_by_operator=honor_decided_by_operator,
        )
    confine_archive_limits(
        config,
        trusted,
        tier_two_overrides,
        list(in_tree),
        undecided_reason=tier_two_source.reason if undecided_membership else None,
        remedy=tier_two_source.remedy,
    )
    # The configuration as the operator set it, before confinement, so the one
    # warning for an off-host reporter's section can name what reporter_section
    # will ignore as well. The operator's own chain files (the ones outside the
    # tree: a --config that extends the repository's) merge over the trusted
    # base first (chain_reporters, built above for the reporter confinement),
    # then the operator's reporters overrides apply on top.
    operator_reporters = _with_reporter_overrides(
        chain_reporters, operator_overrides, config
    )
    settled = confine_operator_only_options(
        config,
        trusted,
        operator_overrides,
        in_tree,
        operator_reporters,
        environment_paths,
        repository=repository,
        # The same membership keying as the sandbox call above: the checkout
        # wording only where the any-checkout rule actually added the files,
        # the mixed sentence where both memberships share the line, and the
        # given-root sentence for files_inside's files under a no-tree load
        # with known trees (a root given, or also_scanned's).
        checkout_membership=checkout_membership,
        client_supplied=client_supplied,
        mixed_membership=mixed_membership,
        given_root_membership=given_root_membership,
        undecided_membership=undecided_membership,
        outside_membership=outside_membership,
    )
    # The scanner views: the same view with the scanner sections the operator
    # wrote added, for the ownership check of a configured path
    # (operator_wrote_value). The reporters view stays what the confinement
    # and the off-host reporters read.
    # A value is the operator's when ANY of these holds it: the trusted base
    # (with the reporters overrides), that base with the scanners overrides, or
    # the operator's chain files' scanner sections.
    scanner_views: List[Any] = [
        operator_reporters,
        _with_scanner_overrides(operator_reporters, operator_overrides, config),
    ]
    files_view = _with_operator_chain_scanners(
        operator_reporters,
        view_chain,
        in_tree,
        reads,
        environment_paths,
        environment_values=config_environment_values(config),
        roots=view_roots,
    )
    if files_view is not None:
        scanner_views.append(files_view)
    # One recording call sets the reporters view and the scanner views
    # together, so no other path that records the one can omit the others.
    record_operator_reporters(
        config,
        operator_reporters,
        in_tree,
        environment_paths,
        scanner_views=scanner_views,
        # The sentence the settle and sandbox warnings give for these files, so
        # the off-host reporter's warning names the same membership.
        membership=confinement_membership(
            checkout_membership=checkout_membership,
            client_supplied=client_supplied,
            mixed=mixed_membership,
            given_root=given_root_membership,
            undecided=undecided_membership,
            outside=outside_membership,
        ),
    )
    _take_confined_references(config, trusted, settled, in_tree)
    return config


#: The sandbox settings confine_sandbox_grants replaces with the trusted base's,
#: in the dump's keys. ``mode`` is one of a few names, and is kept as it is.
#: Every list confine_sandbox_grants puts the trusted base's value in place of
#: (sandbox_grants.confine_sandbox_grants): the references at each take the
#: trusted base's. With the last two missing, an in-tree file's reference at
#: sandbox.read_path_scanners or sandbox.env_scanners kept describing a value
#: the configuration no longer held, and the trusted value there was not
#: redacted.
_CONFINED_SANDBOX_SETTINGS = (
    ("sandbox", "network_scanners"),
    ("sandbox", "extra_read_paths"),
    ("sandbox", "read_path_scanners"),
    ("sandbox", "env_scanners"),
    ("sandbox", "environment"),
)


def _take_confined_references(
    config: AshConfig,
    trusted: AshConfig,
    settled: Collection[SettledOption],
    repository_files: Collection[Path],
) -> None:
    """Record the trusted base's references for the settings confinement gave
    ``config`` from it, and drop the references to values it left out.

    confine_sandbox_grants puts the trusted base's values in place of the
    in-tree file's at every setting in ``_CONFINED_SANDBOX_SETTINGS``, and
    confine_operator_only_options at the operator-only options it returned,
    *settled* (``settled_locations``). A reference the in-tree file wrote there
    named a value ``config`` no longer holds, and the value it does hold may be
    one the operator's file read from the environment. Each value is marked
    where its file wrote the reference, in the record (record_of_config,
    ``_written_references``) and in what a message or the MCP get_config tool
    shows (environment_record, ``_environment_references``), so those settings
    take the trusted base's references in both, and its values join the ones
    redacted.

    An operator-only option an override or a file outside the tree kept holds
    the value that override or file gave it. It takes none of the trusted
    base's references and keeps the one that file wrote; it drops one a file of
    *repository_files* (the chain's files inside the tree) wrote there, whose
    value was left out of the configuration as the chain was read
    (RepositorySettings). A reference names its file (``origin``); a rewrite
    does not, so one is dropped there when only such a reference matches it.
    """
    from automated_security_helper.config.config_validator import dumped_path
    from automated_security_helper.config.operator_only_options import (
        operator_only_locations,
        settled_locations,
    )

    def normal(path: Any) -> Tuple[Any, ...]:
        # environment_record's spelling of a path: '-' and '_' alike, any case.
        return tuple(
            segment.replace("-", "_").lower() if isinstance(segment, str) else "*"
            for segment in path
        )

    def place(reference: Any) -> Tuple[Any, ...]:
        return normal(
            (*reference.path, reference.resolved) if reference.key else reference.path
        )

    # A file named inside the tree can be a link out of it: its references name
    # the file it resolves to.
    repository = {Path(file) for file in repository_files} | {
        Path(file).resolve() for file in repository_files
    }
    sandbox = {normal(setting) for setting in _CONFINED_SANDBOX_SETTINGS}
    mine_settled = {normal(location) for location in settled_locations(config, settled)}
    mine_kept = {
        normal(location) for location in operator_only_locations(config)
    } - mine_settled
    theirs_settled = {
        normal(location) for location in settled_locations(trusted, settled)
    }

    def left_out(reference: Any) -> bool:
        # One of config's own that no longer describes its value there.
        where = place(reference)
        if where[:2] in sandbox or where[:4] in mine_settled:
            return True
        return (
            where[:4] in mine_kept
            and reference.origin is not None
            and Path(reference.origin[0]) in repository
        )

    def taken_from_trusted(reference: Any) -> bool:
        where = place(reference)
        return where[:2] in sandbox or where[:4] in theirs_settled

    own_places = tuple(getattr(config, "_environment_references", ()) or ())
    their_places = tuple(getattr(trusted, "_environment_references", ()) or ())
    dropped = [reference for reference in own_places if left_out(reference)]
    kept = [reference for reference in own_places if not left_out(reference)]
    if own_places or their_places:
        config._environment_references = tuple(kept) + tuple(
            reference for reference in their_places if taken_from_trusted(reference)
        )
        # The displayed view (what `ash config get` and the MCP get_config tool
        # write back) swaps the same way: the trusted base's values are in
        # place, so its displayed references describe them.
        own_shown = tuple(
            getattr(config, "_displayed_environment_references", ()) or ()
        )
        their_shown = tuple(
            getattr(trusted, "_displayed_environment_references", ()) or ()
        )
        config._displayed_environment_references = tuple(
            reference for reference in own_shown if not left_out(reference)
        ) + tuple(
            reference for reference in their_shown if taken_from_trusted(reference)
        )

    def left_out_where_kept(rewrite: Any) -> bool:
        # A rewrite at a kept operator-only option that a reference the
        # repository's file wrote there matches, and no other reference does.
        path = (
            rewrite.path
            if rewrite.kind == "value"
            else (*rewrite.path, rewrite.resolved)
        )
        where = normal(path)[:4]
        if where not in mine_kept:
            return False

        def matches(reference: Any) -> bool:
            return (
                place(reference)[:4] == where
                and reference.written == rewrite.written
                and reference.resolved == rewrite.resolved
            )

        return any(matches(reference) for reference in dropped) and not any(
            matches(reference) for reference in kept
        )

    def confined(
        source: AshConfig, options: Set[Tuple[Any, ...]]
    ) -> Callable[[Any], bool]:
        dumped = source.model_dump()
        sandbox_settings = set(_CONFINED_SANDBOX_SETTINGS)

        def check(rewrite: Any) -> bool:
            path = (
                rewrite.path
                if rewrite.kind == "value"
                else (*rewrite.path, rewrite.resolved)
            )
            # A sandbox setting by its own path, which is there whether or not
            # the list entry the rewrite named still is. An option by its
            # spelling, as a reference's place is compared: the dump keys a
            # scanner's section by its field name (detect_secrets), the option's
            # place by the section's name (detect-secrets).
            return (
                len(path) >= 2
                and dumped_path(source, dumped, path[:2]) in sandbox_settings
            ) or normal(path)[:4] in options

        return check

    own = list(config._written_references or [])
    theirs = list(getattr(trusted, "_written_references", None) or [])
    if not own and not theirs:
        return
    in_config = confined(config, mine_settled)
    in_trusted = confined(trusted, theirs_settled)
    taken = [rewrite for rewrite in theirs if in_trusted(rewrite)]
    config._written_references = [
        rewrite
        for rewrite in own
        if not in_config(rewrite) and not left_out_where_kept(rewrite)
    ] + taken
    config._environment_values = list(config._environment_values or []) + [
        value
        for rewrite in taken
        for value in dict.fromkeys((rewrite.resolved, rewrite.environment_part))
        if value
    ]


def _folded_onto_trusted(
    trusted: AshConfig,
    overrides: List[str],
    resolved: AshConfig,
    section: Literal["reporters", "scanners"] = "reporters",
) -> List[str]:
    """*overrides*, each *section* segment respelled to the trusted
    base's own key when both files hold that one section under their own
    spellings. *section* is ``reporters`` or ``scanners``: the fold is the
    same lockout in both, read from the matching before-overrides record.
    Any other *section* has no record to read and raises ``AttributeError``
    rather than folding against another section's.

    The scan's own apply resolved these overrides against the resolved
    configuration (*resolved*), whose spelling the repository controls; the
    trusted base is the operator's file, which can spell the same section
    another way. Without the fold each application refuses the other file's
    spelling and no spelling passes both. The rewrite is bounded to exactly
    that lockout: the segment must be a section the resolved configuration
    holds (a respelling of a section only the trusted base knows was never
    forced on the operator, and stays refused), under the one fold identity
    both patch walks read (``section_fold_key``: the folded section name
    paired with the reduced plugin name), so an override typed for a
    built-in plugin never lands on an operator-only section it merely
    folds with. A segment that matches no trusted section, whose fold is
    ambiguous there, or that sits under any top-level key but *section*
    is left as written for the apply's own resolver.
    """
    from automated_security_helper.config.ash_config import section_fold_key

    sections = trusted.model_dump().get(section) or {}
    by_fold: Dict[Tuple[str, str], Optional[str]] = {}
    for existing in sections:
        if isinstance(existing, str):
            fold = section_fold_key(existing)
            # Two trusted sections sharing one fold identity: ambiguous, no
            # rewrite. A pair that folds by name alone but names different
            # plugins (a split type word) is two identities, each its own
            # anchor, as the view's settle reads them.
            by_fold[fold] = None if fold in by_fold else existing
    # The repository's sections as its file spelled them, before the first
    # application landed the overrides' own keys: a key an override itself
    # created is not a spelling the repository forced on the operator.
    before_overrides = getattr(resolved, f"_{section}_before_overrides")
    repository_folds = {
        section_fold_key(existing) for existing in (before_overrides or ())
    }
    rewritten: List[str] = []
    for override in overrides:
        key_path, separator, value = override.partition("=")
        parts = key_path.split(".")
        if len(parts) >= 2 and parts[0] == section:
            segment = parts[1]
            appends = len(parts) == 2 and segment.endswith("+")
            name = segment.removesuffix("+") if appends else segment
            actual = by_fold.get(section_fold_key(name))
            # The pair key already requires the reduced plugin names to
            # agree, so the separate reduced-name gate this check carried is
            # implied by the lookup.
            if (
                actual is not None
                and actual != name
                and section_fold_key(name) in repository_folds
            ):
                parts[1] = actual + ("+" if appends else "")
                key_path = ".".join(parts)
        rewritten.append(key_path + separator + value)
    return rewritten


def _extends_count(document: Any) -> Optional[int]:
    """How many ``extends`` bases *document*, a chain file's own document, names:
    0 for no key or a non-mapping document, 1 for one reference, the list's
    length for a list, and None for a value of another shape, which the
    resolution would have refused."""
    from automated_security_helper.config.config_sources import EXTENDS_KEY

    if not isinstance(document, dict):
        return 0
    refs = document.get(EXTENDS_KEY)
    if refs is None:
        return 0
    if isinstance(refs, str):
        return 1
    if isinstance(refs, list):
        return len(refs)
    return None


#: A node of a rebuilt ``extends`` tree: the file's index into the chain, and
#: its bases' nodes.
_ExtendsNode = Tuple[int, List[Any]]


def _extends_forest(
    chain: Sequence[Path], reads: Dict[Path, Any]
) -> Tuple[List[_ExtendsNode], Optional[Path]]:
    """The ``extends`` trees *chain* rebuilds, and the file at which the rebuild
    failed, or None when it did not.

    *chain* is post-order: each file after the subtrees of its bases, one
    subtree per ``extends`` entry, in the entry's order. So a stack rebuilds the
    trees: each file takes as its bases the last N subtrees, N being its own
    ``extends`` count (*reads*, its own document; :func:`_extends_count`). The
    stack that is left holds one node per tree, in chain order. The rebuild
    fails at a file *reads* does not hold, or whose count is of an unreadable
    shape or exceeds the subtrees before it; the nodes rebuilt so far are
    returned with that file, for a caller that reports it.
    """
    stack: List[_ExtendsNode] = []
    for index, file in enumerate(chain):
        key = Path(file).resolve()
        if key not in reads:
            return stack, Path(file)
        count = _extends_count(reads[key])
        if count is None or count > len(stack):
            return stack, Path(file)
        bases = stack[len(stack) - count :] if count else []
        del stack[len(stack) - count :]
        stack.append((index, bases))
    return stack, None


def _operator_chain_occurrences(
    chain: Sequence[Path],
    repository_files: Sequence[Path],
    reads: Dict[Path, Any],
    environment_paths: Collection[Path],
    warn: bool = True,
    roots: int = 1,
) -> List[Path]:
    """The occurrences of *chain* the operator reached, in chain order.

    *chain* is post-order: each file after the subtrees of its bases, one
    subtree per ``extends`` entry, in the entry's order. So a stack rebuilds the
    tree (:func:`_extends_forest`): each file takes as its bases the last N
    subtrees, N being its own ``extends`` count (*reads*, its own document).
    From each root down, a file is the operator's when it is not a repository
    file (*repository_files*, by resolved path or name) and no file above it
    on its branch is one.

    *roots* is how many trees *chain* holds, which the caller knows from how
    it built the chain: one for a selected config's chain or an ASH_CONFIG
    chain, two when the operator's overlay chain was appended after a selected
    chain (``_resolve_config`` lays the overlay's files after the selected
    config's; the overlay layers over the selected config, so its files are
    the operator's by the same rule, walked from their own root). A chain read
    as one tree when it held two did not rebuild, and took NOTHING as the
    operator's, the overlay's own writes included.

    Answers [] -- nothing is the operator's -- when the trees do not rebuild:
    a file *reads* does not hold, or counts that do not add up to *roots*
    trees. The warning that says so names the file; one an ``extends`` entry
    chose with a value read from the environment (*environment_paths*, by the
    path or its resolved form) is named ``<value>`` instead, since the drift
    the warning exists for is likeliest exactly on such a file, and its real
    path is the environment's value.
    """
    from automated_security_helper.config.config_sources import describe_config_path
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    repository = {Path(file) for file in repository_files} | {
        Path(file).resolve() for file in repository_files
    }

    def not_rebuilt(file: Path) -> List[Path]:
        # By construction the chain rebuilds: *reads* holds each file's one
        # read, and the counts come from the documents the resolution walked.
        # A mismatch means this walk has drifted from the resolution's, and
        # taking nothing as the operator's own without a word would hide
        # that. The message names a file, never a value: a path an extends
        # entry read from the environment is the environment's value, so
        # such a file is named <value>. The sandbox-mode floor's walk over
        # the same chain passes ``warn=False`` and says its own word at
        # debug level, so a path where only the floor's walk runs is not
        # silent, while a load that runs both walks warns once, from the
        # reporter view's.
        hidden = file in environment_paths or file.resolve() in environment_paths
        shown = ENVIRONMENT_VALUE_SHOWN if hidden else describe_config_path(file)
        if not warn:
            ASH_LOGGER.debug(
                "The configuration's extends chain could not be rebuilt at "
                f"{shown}: no file of it is taken as the operator's own, so "
                "the sandbox-mode floor keeps the trusted base's own mode",
                extra=NO_MARKUP,
            )
            return []
        ASH_LOGGER.warning(
            "The configuration's extends chain could not be rebuilt at "
            f"{shown}: no file of it is taken as the operator's own, so an "
            "off-host reporter keeps the trusted base's settings",
            extra=NO_MARKUP,
        )
        return []

    forest, failed_at = _extends_forest(chain, reads)
    if failed_at is not None:
        return not_rebuilt(failed_at)
    if len(forest) != roots:
        return not_rebuilt(Path(chain[-1])) if chain else []

    owned: Set[int] = set()

    def walk(node: _ExtendsNode, above_is_repository: bool) -> None:
        index, bases = node
        file = Path(chain[index])
        is_repository = (
            above_is_repository or file in repository or file.resolve() in repository
        )
        if not is_repository:
            owned.add(index)
        for base in bases:
            walk(base, is_repository)

    for tree in forest:
        walk(tree, False)
    return [Path(chain[index]) for index in sorted(owned)]


def _repository_members(
    chain: Sequence[Path],
    named: Sequence[Path],
    trees: List[Path],
    any_checkout: bool,
) -> List[Path]:
    """The files of *chain* the repository under scan wrote, by the membership
    the chain reads use (``files_inside``), extended by the any-checkout rule
    where the caller knows no tree is scanned."""
    members = list(files_inside(chain, trees, named))
    if any_checkout:
        members = _with_any_checkout_files(members, chain, named)
    return members


# The mode spellings the configuration model accepts, read from the model's
# own field so the two cannot drift. The walk below checks written values
# against it because assignment onto the model is not validated: a value
# outside this set would otherwise ride into the floor and be requested of
# the container as written.
_SANDBOX_MODES: Tuple[str, ...] = tuple(
    get_args(SandboxConfig.model_fields["mode"].annotation)
)


def _owned_file_shown(file: Path | str, environment_paths: Collection[Path]) -> str:
    """How a refusal names an operator-owned file: by its hidden form when an
    ``extends`` entry chose it with a value read from the environment, since
    its path IS that value, and by its described path otherwise."""
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    file = Path(file)
    hidden = file in environment_paths or file.resolve() in environment_paths
    return ENVIRONMENT_VALUE_SHOWN if hidden else describe_config_path(file)


def _non_mapping_owned_sandbox_refusal(
    file: Path | str, environment_paths: Collection[Path]
) -> ASHConfigValidationError:
    """The refusal for an operator-owned file whose ``sandbox`` is written as
    something other than a mapping of settings, through its document or its
    own patch. It names the file and never the written value, as
    _unknown_owned_mode_refusal does: the operator's own file tried to set a
    sandbox, and a later write in the chain could replace it with a mapping,
    so the merged load would run without the sandbox the file wrote."""
    shown = _owned_file_shown(file, environment_paths)
    return ASHConfigValidationError(
        f"{shown} writes a sandbox section that is not a mapping of "
        "settings; the configuration was refused rather than resolved "
        "without the sandbox the file wrote"
    )


def _unknown_owned_mode_refusal(
    file: Path | str,
    environment_paths: Collection[Path],
    boolean: bool = False,
) -> ASHConfigValidationError:
    """The refusal for an operator-owned file whose sandbox mode is outside
    the known set. It names the file and never the written value: a mode
    written as an environment reference arrives as whatever the variable
    holds, which is not the message's to show. A file an ``extends`` entry
    chose with a value read from the environment (*environment_paths*) is
    named by its hidden form instead of its path, as the confinement
    warnings name it, because such a file's path IS the environment's
    value."""
    shown = _owned_file_shown(file, environment_paths)
    hint = (
        "; the value was read as a YAML boolean, so write the mode in quotes"
        if boolean
        else ""
    )
    return ASHConfigValidationError(
        f"{shown} sets a sandbox mode the "
        f"configuration does not define (the modes are "
        f"{', '.join(_SANDBOX_MODES)}{hint}); the configuration was refused "
        "rather than resolved without the mode the file wrote"
    )


def _owned_mode_spelling(
    value: Any, file: Path | str, environment_paths: Collection[Path]
) -> str:
    """The known mode an owned file's written *value* stands for, or the
    refusal. YAML 1.1 reads an unquoted ``off`` as the boolean False, which
    the config loader reads as the mode "off" (sandbox_mode_in_document), so
    the walk reads it the same way; True names no mode and is refused with the
    quoting hint. The result is a plain str: a mode read from an environment
    reference arrives as the loader's carrier subclass."""
    if value is False:
        return "off"
    if isinstance(value, str) and value in _SANDBOX_MODES:
        return str(value)
    raise _unknown_owned_mode_refusal(file, environment_paths, boolean=value is True)


def _mode_speller(
    file: Path | str, environment_paths: Collection[Path]
) -> Callable[[Any], str]:
    """``_owned_mode_spelling`` for *file*, as the one-argument reading
    ``_mode_after_patch`` takes."""

    def spell(value: Any) -> str:
        return _owned_mode_spelling(value, file, environment_paths)

    return spell


def _non_mapping_refuser(
    file: Path | str, environment_paths: Collection[Path]
) -> Callable[[], None]:
    """The refusal ``_non_mapping_owned_sandbox_refusal`` words for *file*, as the
    call ``_mode_after_patch`` makes when it meets that shape."""

    def refuse() -> None:
        raise _non_mapping_owned_sandbox_refusal(file, environment_paths)

    return refuse


def _mode_after_patch(
    mode: Any,
    operations: Any,
    spell: Optional[Callable[[Any], Any]] = None,
    on_non_mapping: Optional[Callable[[], None]] = None,
) -> Any:
    """The sandbox mode a file ends with: *mode*, the one it wrote directly (None
    for none), after its own ``patch`` *operations*, applied in order.

    The operations the sandbox-mode floor reads (``_owned_sandbox_mode``) and the
    file's own section reads (``_own_mode_after_patch``): ``add``, ``replace`` and
    ``remove`` at the whole document, at ``/sandbox`` and at ``/sandbox/mode``. A
    value that carries a mode sets it; one that rewrites the document or the
    section without a mode clears it (None). A ``remove`` of the whole document, a
    ``test``, ``move`` or ``copy``, a pointer anywhere else, and a value that is
    not a mapping where one is needed, set nothing.

    The walks differ only in what they do with a value, so they pass it in:

    - *spell* is called with each value a patch sets, in order, and its result is
      the mode (the floor spells ``False`` as "off" and refuses a value that names
      no mode; raising stops the walk). With none the value stands as written.
    - *on_non_mapping* is called when a value that is not None is written over the
      sandbox section (or the document's) and is not a mapping, where the mode
      would have been read from it; it may raise. With none that operation is
      dropped, as one whose value lacks the place is.
    """
    for operation in operations if isinstance(operations, list) else ():
        if not isinstance(operation, dict):
            continue
        name = operation.get("op")
        if name not in ("add", "replace", "remove"):
            continue
        segments = _pointer_segments(operation.get("path"))
        if (
            segments is None
            or segments[:1] not in ([], ["sandbox"])
            or len(segments) > 2
            or (len(segments) == 2 and segments[1] != "mode")
        ):
            continue
        if name == "remove":
            # A patch cannot remove the whole document.
            if segments:
                mode = None
            continue
        value = operation.get("value")
        unset = False
        dropped = False
        # The keys between the operation's place and the mode: a value that
        # rewrites the document or the section carries its mode under them, and
        # one that rewrites the place without a mode unsets it there.
        for key in ("sandbox", "mode")[len(segments) :]:
            if not isinstance(value, dict):
                if key == "mode" and value is not None and on_non_mapping is not None:
                    on_non_mapping()
                dropped = True
                break
            if key not in value:
                unset = True
                break
            value = value[key]
        if dropped:
            continue
        if unset:
            mode = None
        else:
            mode = spell(value) if spell is not None else value
    return mode


def _owned_sandbox_mode(
    chain: Sequence[Path],
    repository_files: Sequence[Path],
    reads: Dict[Path, Any],
    environment_paths: Collection[Path],
    roots: int = 1,
) -> Optional[str]:
    """The sandbox mode the operator's own files of *chain* set, or None.

    *roots* is the number of ``extends`` trees *chain* holds
    (``_operator_chain_occurrences``): two when the operator's overlay chain
    follows a selected chain. Each tree's root patches the running answer, so
    the overlay's root, laid after the selected config's, patches what the
    selected tree set, as the layering merges its document over it.

    Each owned occurrence contributes its EFFECTIVE write, read from the
    file's own document (*reads*), in chain order: the ``sandbox.mode`` key
    the document carries, then the document's own ``patch`` operations that
    target the mode -- ``/sandbox/mode``, ``/sandbox``, or the whole document
    -- applied in order, since a file's patch applies at the file's own level
    of the merge, so a mode an operator file sets through its own patch is
    the operator's write as much as a key is. The last owned file whose own
    effective document carries a mode answers. The merged chain is never
    read: it cannot tell the operator's write from a repository file's, so
    an in-tree base later in the chain could otherwise turn off the mode the
    operator's own file set, and when the operator's base sets its mode only
    through its own patch, a walk of the raw keys alone would miss the write
    for the same reason.

    A file's reach follows the merge. A BASE's patch reaches only its own
    document: an owned base's remove of the mode's place, or a rewrite of the
    place without a mode, unsets only what that base wrote, since the merge
    keeps a mode the patched document no longer carries -- a base whose
    effective document holds no mode contributes nothing, never a clearing
    of a sibling owned file's write. The ROOT is different: its bases merge
    under it before its own patch applies, so a root operation reaches the
    whole chain, and a root remove or modeless rewrite of the place unsets
    the walk's running answer, as the resolved load's own mode shows. The
    chain is post-order, so the root is its last occurrence. A nested owned
    base's patch over its own deeper bases is read as the base's own
    document only, which can keep the floor at a mode the merge dropped --
    on, never off, so the sandbox is not weakened by the approximation. A
    write whose value is not one of the known modes refuses the load
    (ASHConfigValidationError), whatever later files write: dropping it
    silently let a repository file later in the chain write ``off`` over a
    merged document the resolved load then accepted, so the scan ran with
    no sandbox although the operator's own file tried to set one, and the
    floor must never request an unknown mode -- the model accepts any
    assigned string unchecked. Operations the walk does not read (``test``,
    ``move``, ``copy``, a pointer spelled past the mode's place) set
    nothing here. None when no owned file writes one (an unbuildable chain
    included): the caller keeps the trusted base's own mode, never the
    merged chain's.

    Raises:
        ASHConfigValidationError: when an operator-owned file writes a
            sandbox mode outside the known set, through its key or its own
            patch. The message names the file and never the written value,
            which can arrive from an environment reference.
    """
    from automated_security_helper.config.config_sources import PATCH_KEY

    mode: Optional[str] = None
    # The roots: the chain's last occurrence for one tree (the chain is
    # post-order), and each tree's last occurrence when the chain holds more
    # (the overlay's root after the selected config's). The forest is read
    # only for more than one root; with one, the last occurrence is it.
    tree_roots: Set[Path] = {Path(chain[-1]).resolve()} if chain else set()
    if roots > 1:
        forest, failed_at = _extends_forest(chain, reads)
        if failed_at is None and len(forest) == roots:
            tree_roots = {Path(chain[index]).resolve() for index, _ in forest}
    for file in _operator_chain_occurrences(
        chain, repository_files, reads, environment_paths, warn=False, roots=roots
    ):
        document = reads.get(Path(file).resolve())
        if not isinstance(document, dict):
            continue
        # A BASE's effective write starts from nothing and is folded into
        # the walk's answer only when the base's own document ends up
        # carrying a mode: a base whose patch unsets its own write
        # contributes nothing, never a clearing of a sibling's. A ROOT
        # (a tree's last occurrence) patches the merged chain, so its walk
        # starts from the running answer and its result is the answer,
        # clears included.
        at_root = Path(file).resolve() in tree_roots
        file_mode: Optional[str] = mode if at_root else None
        sandbox = document.get("sandbox")
        if sandbox is not None and not isinstance(sandbox, dict):
            # A scalar or list where the section needs a mapping: the
            # operator's own file tried to set a sandbox, and a later write in
            # the chain could replace it with a mapping the merged load
            # accepts, so the scan would run without the sandbox it wrote.
            raise _non_mapping_owned_sandbox_refusal(file, environment_paths)
        if isinstance(sandbox, dict) and "mode" in sandbox:
            # The answer is downcast to a plain str: a mode the file reads
            # from an environment reference arrives as the loader's carrier
            # str subclass, and the walk's answer is assigned onto the
            # trusted model without the validation that would downcast it (a
            # str subclass has no SafeDumper representer and prints its
            # class name where a message names the mode). The carrier's
            # variable name is bookkeeping the floor does not need: the
            # mode is one of the model's own spellings, never a secret.
            file_mode = _owned_mode_spelling(
                sandbox.get("mode"), file, environment_paths
            )
        # The operations are read by the helper the file's own section shares
        # (_mode_after_patch); the refusals are this walk's. A patched value is
        # read as the key arm above reads it: a mode outside the known set
        # refuses, and a patch value can be read from an environment reference
        # too. A value written over the sandbox section that is not a mapping
        # is the file trying to set a sandbox, and the section refuses as a
        # document's own would.
        file_mode = _mode_after_patch(
            file_mode,
            document.get(PATCH_KEY),
            spell=_mode_speller(file, environment_paths),
            on_non_mapping=_non_mapping_refuser(file, environment_paths),
        )
        if at_root:
            mode = file_mode
        elif file_mode is not None:
            mode = file_mode
    return mode


def _operator_patch_reporters(
    merged: Dict[str, Any],
    ops: Any,
    settle: Callable[[str], str],
    fold_value: Callable[[Dict[str, Any]], Dict[str, Any]],
) -> Dict[str, Any]:
    """*merged*, the owned chain files' ``reporters`` view, with one owned
    file's ``patch`` operations that target ``/reporters`` applied. The
    pointer's section segment goes through *settle*, the same
    register-and-respell a direct write's key gets, so a patched section
    folds onto the one the view already holds instead of standing beside it,
    and a section a patch creates anchors the fold for later files' writes.
    A value that replaces all of ``/reporters`` goes through *fold_value*,
    the per-file fold itself, for the same reason: a key of it under another
    spelling must land on the trusted base's section, never beside it where
    the exact-spelling lookup would read the base's settings over the
    operator's.

    The operator's own file aims these at the configuration it extends, so an
    op under ``/reporters`` is the operator's choice for the off-host section
    as much as a direct write is. Only this view is patched: an ``add`` or
    ``replace`` sets the operation's value at its place, with a missing step
    on the way made a mapping, since the place can exist only on the full
    merged document, which holds the repository's values this view must not;
    a ``remove`` of a place the view holds removes it, one of a place it
    does not is dropped, and a ``test`` sets nothing. An op with an array
    pointer anywhere past the section (a ``-``, or an ASCII-digit index,
    which also covers a step through a list) is applied to the view with
    jsonpatch where the view holds the place: the list there is the
    operator's own writes, so the reporter runs with the element appended,
    replaced or removed, exactly as the resolved section has it. Where the
    pointer does not fit the view -- the list is only the full document's,
    the repository's -- the op is dropped, as is one whose path steps
    through a value the view holds as anything but a mapping. Every drop
    errs toward the trusted base. The full patch already applied to the
    merged document (_apply_patch), where a malformed or misaimed op refused
    the load, so nothing here refuses.
    """
    import jsonpatch  # type: ignore[import-untyped]

    from automated_security_helper.config.config_sources import _resolve_dict_key

    for op in ops if isinstance(ops, list) else ():
        if not isinstance(op, dict):
            continue
        pointer = op.get("path")
        if not isinstance(pointer, str) or not pointer.startswith("/"):
            continue
        segments = [
            part.replace("~1", "/").replace("~0", "~")
            for part in pointer[1:].split("/")
        ]
        if segments[0] != "reporters":
            continue
        name = op.get("op")
        if name not in ("add", "replace", "remove"):
            continue
        inside = segments[1:]
        if not inside:
            if name == "remove":
                merged = {}
            else:
                value = copy.deepcopy(op.get("value"))
                merged = fold_value(value) if isinstance(value, dict) else {}
            continue
        inside[0] = settle(inside[0])
        if any(
            segment == "-" or (segment.isascii() and segment.isdigit())
            for segment in (inside[1:] or inside)
        ):
            # Each dict step matches a key the view already uses that differs
            # only in "-" vs "_", as the plain-key branches below and the
            # full document's patch do (_normalize_pointer): a remove at
            # .../some-list/1 whose view spells some_list lands on the written
            # list instead of dropping and keeping the operator's unpatched
            # one. Index steps pass through to jsonpatch as written.
            resolved_steps: List[str] = []
            step_node: Any = merged
            for segment in inside:
                if isinstance(step_node, dict):
                    segment = _resolve_dict_key(step_node, segment)
                    step_node = step_node.get(segment)
                elif (
                    isinstance(step_node, list)
                    and segment.isascii()
                    and segment.isdigit()
                ):
                    position = int(segment)
                    step_node = (
                        step_node[position] if 0 <= position < len(step_node) else None
                    )
                else:
                    step_node = None
                resolved_steps.append(segment)
            shaped: Dict[str, Any] = {
                "op": name,
                "path": "/reporters/"
                + "/".join(
                    segment.replace("~", "~0").replace("/", "~1")
                    for segment in resolved_steps
                ),
            }
            if name != "remove":
                shaped["value"] = copy.deepcopy(op.get("value"))
            try:
                merged = jsonpatch.JsonPatch([shaped]).apply({"reporters": merged})[
                    "reporters"
                ]
            except (
                jsonpatch.JsonPatchException,
                jsonpatch.JsonPointerException,
                TypeError,
            ):
                # The pointer does not fit the view: the place is only the
                # full document's, so the op is the repository's to satisfy.
                # TypeError is jsonpatch's uncaught shape for an index into a
                # value the view holds as a scalar (a remove's `del text[0]`),
                # where the full document holds the repository's list: the
                # same misfit, dropped the same way.
                pass
            continue
        if name in ("add", "replace"):
            value = copy.deepcopy(op.get("value"))
            node = merged
            fits = True
            # Each step matches a key the view already uses that differs only
            # in "-" vs "_", as the full document's patch matches its steps
            # (_normalize_pointer): a replace at options/findings-scope lands
            # on the written findings_scope instead of standing beside it,
            # where the reporter's options model would refuse the stray key.
            for segment in inside[:-1]:
                segment = _resolve_dict_key(node, segment)
                if segment in node and not isinstance(node[segment], dict):
                    fits = False
                    break
                node = node.setdefault(segment, {})
            if not fits:
                continue
            node[_resolve_dict_key(node, inside[-1])] = value
        else:
            holder: Any = merged
            for segment in inside[:-1]:
                holder = (
                    holder.get(_resolve_dict_key(holder, segment))
                    if isinstance(holder, dict)
                    else None
                )
            if isinstance(holder, dict):
                holder.pop(_resolve_dict_key(holder, inside[-1]), None)
    return merged


def _with_operator_chain_reporters(
    trusted: AshConfig,
    chain: Sequence[Path],
    repository_files: Sequence[Path],
    reads: Dict[Path, Any],
    environment_paths: Collection[Path],
    roots: int = 1,
) -> AshConfig:
    """*trusted* with the ``reporters`` sections the operator's own chain files
    wrote merged over it, for the off-host reporter view.

    The operator's own chain files are the ones the operator reached: the
    root and the bases it extends, down to the first repository file of each
    branch. A ``--config`` outside the tree that ``extends`` the repository's
    file is one. A file reached THROUGH a repository file is the repository's,
    wherever it sits (beside the checkout, in another checkout): the
    repository chose it, as the operator-only options already treat it, since
    the confine hook strips them from a repository file's resolved document,
    its bases' contributions included. What the operator's files write for an
    off-host reporter is the operator's choice, so the section such a reporter
    runs with (``reporter_section``) holds it, merged over the trusted base's
    in chain order. Each file's writes are read from its own document
    (*reads*, the one read's cache), never from the merged chain, which cannot
    tell the operator's writes from the repository's.

    Who reached each file is read from the chain's order: ``chain`` lists each
    file after its bases (``ResolvedConfigDocument.chain``), so the ``extends``
    tree is rebuilt from it and each file's own count of ``extends`` entries
    (``_operator_chain_occurrences``). A file reached on two branches is judged
    per branch. *roots* is the number of trees the chain holds: two when the
    operator's overlay chain follows a selected chain, whose files are then
    walked from their own root instead of failing the rebuild.

    An owned file's own ``patch`` operations that target ``/reporters`` are
    the operator's writes too, so they count toward this view
    (_operator_patch_reporters): they apply to the view the owned files
    built, in chain order, after the file's ``reporters`` key. What is not
    taken: an op aimed anywhere else, whose target places are only known on
    the merged document, and a file *reads* does not hold. Both err toward
    the trusted base alone -- the reporter then runs with less than the
    operator's file wrote, never with the repository's values -- and the
    whole-section warning says the resolved section was not what the
    reporter runs with. A chain whose tree cannot be rebuilt takes nothing,
    and the warning that says so names a file an ``extends`` entry chose
    with a value read from the environment (*environment_paths*) as
    ``<value>``, as every confinement warning does.
    """
    from automated_security_helper.config.ash_config import section_fold_key
    from automated_security_helper.config.config_sources import PATCH_KEY, deep_merge

    # A section a file spells another way (separators, case) folds onto one
    # spelling instead of standing beside it, where the reporter would read
    # only one of the two: the trusted base's own spelling first, and
    # otherwise the first spelling an owned file used. The fold identity is
    # section_fold_key -- the folded section name paired with the reduced
    # plugin name, the same identity the document pointer walk reads
    # (_normalize_pointer) and the one _folded_onto_trusted gates an
    # override's segment by -- so a spelling whose type word a separator
    # splits anchors its own key instead of folding onto another plugin's.
    # Folded per file, before the chain merge, so the chain's order decides
    # a collision, not where each spelling first appeared.
    by_fold: Dict[Tuple[str, str], Optional[str]] = {}
    for existing in getattr(trusted.reporters, "__pydantic_extra__", None) or {}:
        if isinstance(existing, str):
            fold = section_fold_key(existing)
            by_fold[fold] = None if fold in by_fold else existing

    def respell(key: str) -> str:
        target = by_fold.get(section_fold_key(key))
        if target is None or target == key:
            return key
        return target

    def settled(key: str) -> str:
        # The register-and-respell a direct write's key gets: the first
        # spelling seen for a section anchors the fold for later files,
        # whether it came in as a key or as a patch pointer's segment.
        target = respell(key)
        fold = section_fold_key(target)
        if fold not in by_fold:
            by_fold[fold] = target
        return target

    def folded(reporters: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for key, section in reporters.items():
            target = settled(key) if isinstance(key, str) else key
            existing = out.get(target)
            # deep_merge's own rule covers a null or scalar section under a
            # colliding spelling: a non-mapping on either side means the
            # later word is taken as written.
            out[target] = deep_merge(existing, section) if target in out else section
        return out

    merged: Dict[str, Any] = {}
    for file in _operator_chain_occurrences(
        chain, repository_files, reads, environment_paths, roots=roots
    ):
        own = reads.get(Path(file).resolve())
        reporters = own.get("reporters") if isinstance(own, dict) else None
        if isinstance(reporters, dict):
            merged = deep_merge(merged, folded(copy.deepcopy(reporters)))
        if isinstance(own, dict):
            merged = _operator_patch_reporters(
                merged, own.get(PATCH_KEY), settled, folded
            )
    if not merged:
        return trusted
    operator = trusted.model_copy(deep=True)
    extra = getattr(operator.reporters, "__pydantic_extra__", None)
    if extra is None:
        return trusted
    combined = deep_merge(dict(extra), merged)
    extra.clear()
    extra.update(combined)
    return operator


def _with_reporter_overrides(
    trusted: AshConfig, config_overrides: Optional[List[str]], resolved: AshConfig
) -> AshConfig:
    """*trusted* with the operator's ``reporters`` overrides applied.

    The reporter sections as the operator set them, which a reporter that sends
    findings off the host takes in place of the resolved ones
    (``config/operator_only_options.reporter_section``). Only the overrides under
    ``reporters`` are replayed, as only those under ``sandbox`` are for the
    sandbox. An override whose section segment is the resolved configuration's
    (*resolved*, the repository's) spelling of one of the trusted base's own
    sections is folded onto that section first: the scan's own apply already
    made the operator use the repository's spelling, so refusing it here would
    leave no spelling that passes both applications. The fold is bounded to
    that case (_folded_onto_trusted): a respelling of a section only the
    trusted base knows is still refused (ASHRespelledOverrideError), and a
    key that names a different plugin than the trusted section it folds with
    is left as written. A section no file spells, such as one the reporter
    never reads, still absorbs an override as written -- naming a section is
    the operator's own choice, and nothing here can tell a decoy from a
    section a future plugin reads. The overrides are applied together first;
    when one of them does not apply to the trusted base, they are applied
    again one reporter section at a time, all or nothing per section: a
    section with a failing override is dropped whole, with one warning, so for
    a section the trusted base's model declares an ``enabled=true`` never lands
    without the destination override written beside it (which would send
    findings to the base's or the default destination), and the other
    sections' overrides still apply. An undeclared section has no model for an
    override to fail against, so its overrides land as written, as said
    above. A
    ``reporters.<section>.enabled=<false>``, in every spelling the field reads
    as False (``false``, ``0``, ``off``, ``no``, ``f``, ``n``), is applied
    whatever else its section asked for: a disable fails closed both ways. For
    a dropped section the off-host reporter keeps the base's settings, off
    unless the base turns it on.
    """
    reporter_overrides = [
        override
        for override in config_overrides or []
        if override.partition("=")[0].removesuffix("+").split(".")[0] == "reporters"
    ]
    if reporter_overrides:
        reporter_overrides = _folded_onto_trusted(trusted, reporter_overrides, resolved)
        try:
            return apply_config_overrides(trusted, reporter_overrides)
        except ASHRespelledOverrideError:
            # A respelled section key: tolerating it would keep the off-host
            # reporter on while the operator's disable lands as a new extra
            # key, so the scan refuses, as `config get` refuses the same key.
            raise
        except ASHConfigValidationError:
            # One of them does not apply to the trusted base. They are applied
            # again below, one reporter section at a time, so the sections
            # whose overrides all apply still reach the view and only the
            # section with a failing override is dropped, whole, with one
            # warning. Together first: a set that is valid only as a whole
            # stays whole.
            pass
        view = trusted.model_copy(deep=True)
        for section_overrides in _reporter_overrides_by_section(
            reporter_overrides, trusted
        ):
            try:
                view = apply_config_overrides(view, section_overrides)
                continue
            except ASHRespelledOverrideError:
                raise
            except ASHConfigValidationError as error:
                # All or nothing per section: an `enabled=true` that applied
                # while the destination override beside it failed would send
                # findings to the base's or the default destination, so every
                # override of the section is dropped with the failing one.
                failure = error
            # A disable is applied whatever else the section asked for: it
            # fails closed, and it can never send a finding anywhere. Applied
            # before the warning, so the warning says what happened.
            applied_disables: List[str] = []
            for override in section_overrides:
                if not _disables_a_reporter(override):
                    continue
                try:
                    view = apply_config_overrides(view, [override])
                except ASHRespelledOverrideError:
                    raise
                except ASHConfigValidationError:
                    # The disable itself does not apply (its section is not a
                    # mapping the trusted base knows); the warning below names
                    # it among the section's keys.
                    continue
                applied_disables.append(override)
            # The error can quote a section key the trusted file read from
            # the environment, so the warning is redacted with that file's
            # values; the overrides are named by key only (never a value,
            # which can be a credential), redacted the same way.
            values = config_environment_values(trusted)
            described = redact_values(str(failure), values)
            keys = ", ".join(
                redact_values(override.partition("=")[0], values)
                for override in section_overrides
            )
            kept = ""
            if applied_disables:
                disable_keys = ", ".join(
                    redact_values(override.partition("=")[0], values)
                    for override in applied_disables
                )
                kept = (
                    f" except the disable '{disable_keys}', which is applied on "
                    "its own,"
                )
            # An override of ``reporters`` itself puts every override in one
            # group (_reporter_overrides_by_section), so there is no other
            # section whose overrides still apply, and the warning says so.
            whole_set = any(
                len(override.partition("=")[0].removesuffix("+").strip().split(".")) < 2
                for override in section_overrides
            )
            scope = (
                "none of the reporters overrides is applied"
                if whole_set
                else "none of that section's overrides is applied"
            )
            others = (
                ""
                if whole_set
                else "; the other reporters sections' overrides still apply"
            )
            ASH_LOGGER.warning(
                "The --config-overrides under reporters do not apply to the "
                f"operator's own configuration for '{keys}' ({described}), so "
                f"{scope}{kept} and a reporter that sends findings off the host "
                f"keeps that configuration's settings for it{others}.",
                extra=NO_MARKUP,
            )
        return view
    return trusted.model_copy(deep=True)


def _reporter_overrides_by_section(
    overrides: List[str], trusted: AshConfig
) -> List[List[str]]:
    """``overrides``, every one under ``reporters``, grouped by the reporter
    section each lands on, in first-seen order.

    The section is the key the apply resolves the override's second segment
    to against the trusted base's own dump (``resolve_override_segment``, the
    one resolver every override walker reads keys with), not the segment's
    text: ``aws_security_hub`` and ``aws-security-hub`` land on one section,
    so an enable under one spelling and a failing destination override under
    the other are one group and fall together, as the all-or-nothing rule
    promises. A segment that resolves to no existing key is grouped as
    written, which is where the apply would create it. An override of
    ``reporters`` itself (``reporters={...}``) writes every section, so when
    one is present every override is one group and the set applies or falls
    as a whole.
    """
    sections = trusted.model_dump().get("reporters")
    current: Dict[str, Any] = sections if isinstance(sections, dict) else {}
    values = config_environment_values(trusted)
    groups: Dict[str, List[str]] = {}
    for override in overrides:
        segments = override.partition("=")[0].removesuffix("+").strip().split(".")
        if len(segments) < 2:
            return [list(overrides)]
        section = resolve_override_segment(
            current, "reporters", segments[1].strip(), values
        )
        groups.setdefault(section, []).append(override)
    return list(groups.values())


#: The strings pydantic's lax ``bool`` reads as False (pydantic 2.13.5,
#: ``PluginConfigBase.enabled`` is a plain ``bool`` under a model with no
#: ``strict`` setting), compared lower-cased and stripped; the ints 0 and 0.0
#: are read as False too.
_FALSE_SPELLINGS = frozenset({"0", "off", "f", "false", "n", "no"})


def _disables_a_reporter(override: str) -> bool:
    """Whether a ``reporters`` override sets one section's ``enabled`` to false:
    ``reporters.<section>.enabled=<false>``, with either separator spelling of
    the key and a value the model's ``enabled`` field reads as False: a parsed
    bool False, a numeric zero, or one of the six lax-bool spellings (``false``,
    ``0``, ``off``, ``no``, ``f``, ``n``, in any case, blanks stripped). A value
    admitted here that the model then refuses is attempted alone by the
    always-apply arm, fails validation there and is dropped, named among the
    section's keys in the warning and not as an applied disable."""
    key, separator, value = override.partition("=")
    if not separator or key.endswith("+"):
        return False
    segments = [segment.strip().replace("-", "_") for segment in key.split(".")]
    if not (
        len(segments) == 3 and segments[0] == "reporters" and segments[2] == "enabled"
    ):
        return False
    parsed = _parse_config_value(value)
    if isinstance(parsed, bool):
        return parsed is False
    if isinstance(parsed, (int, float)):
        return parsed == 0
    return isinstance(parsed, str) and parsed.strip().lower() in _FALSE_SPELLINGS


def _with_operator_chain_scanners(
    view: AshConfig,
    chain: Sequence[Path],
    repository_files: Sequence[Path],
    reads: Dict[Path, Any],
    environment_paths: Collection[Path],
    environment_values: Sequence[str] = (),
    roots: int = 1,
) -> Optional["_ScannerFileView"]:
    """The ``scanners`` sections the operator's own chain files wrote, merged
    over *view*'s, or None when those files wrote none.

    The scanner half of :func:`_with_operator_chain_reporters`: the same files
    (the ones the operator reached, from each file's own document in *reads*,
    under the same *roots*), merged in chain order. A section a file spells another way is folded onto
    the view's own spelling first (``section_fold_key``), so it lands on the
    section the scanner reads instead of beside it. What is not taken: an
    owned file's ``patch`` operations. The view then holds less than the
    operator wrote, so a value only such an operation wrote is judged not the
    operator's: the refusal gate errs toward refusing. The merged dump is not
    validated into a model (see ``_ScannerFileView``): the values compared are
    the files' own, and a dump that failed to round-trip through validation
    would silently empty the view.
    """
    from automated_security_helper.config.ash_config import section_fold_key
    from automated_security_helper.config.config_sources import deep_merge

    base = view.scanners.model_dump(by_alias=True)
    by_fold: Dict[Tuple[str, str], str] = {}
    for existing in base:
        if isinstance(existing, str):
            by_fold.setdefault(section_fold_key(existing), existing)

    merged: Dict[str, Any] = {}
    # warn=False: the reporters pass over the same chain already named a tree
    # that does not rebuild.
    for file in _operator_chain_occurrences(
        chain, repository_files, reads, environment_paths, warn=False, roots=roots
    ):
        own = reads.get(Path(file).resolve())
        if isinstance(own, dict):
            # As the chain walk read the file for the configuration: each
            # operator file's relative tool paths taken from its own directory
            # (config/operator_paths.py). The raw parse held the path as
            # written, which never equaled the anchored value the scanner
            # passes, so an operator's relative tool path read as unnamed.
            own = anchor_document_paths(own, Path(file).resolve().parent)
        scanners = own.get("scanners") if isinstance(own, dict) else None
        if not isinstance(scanners, dict):
            continue
        folded: Dict[str, Any] = {}
        for key, section in copy.deepcopy(scanners).items():
            target = key
            if isinstance(key, str):
                target = by_fold.get(section_fold_key(key), key)
            folded[target] = (
                deep_merge(folded[target], section) if target in folded else section
            )
        merged = deep_merge(merged, folded)
    if not merged:
        return None
    # The union of the trusted view's values and the caller's
    # *environment_values* (the resolved configuration's): a value only an
    # outer chain file's scanners section read is recorded on the resolved
    # configuration, never on the trusted view, and the view's debug line
    # must hide it too.
    return _ScannerFileView(
        deep_merge(base, merged),
        tuple(dict.fromkeys((*config_environment_values(view), *environment_values))),
    )


class _ScannerFileView:
    """The scanner sections of the operator's own chain files, merged over the
    trusted base's dump, answering ``get_plugin_config`` for scanners only.

    Not validated into a model: the values are the files' own, which is what
    the ownership check compares, and a dump that fails to round-trip through
    validation would silently empty the view. The lookup is the module
    function the resolved configuration's own ``get_plugin_config`` calls
    (``plugin_section_lookup``), never an AshConfig method borrowed over this
    object, so a change to what that method reads from ``self`` cannot break
    the view alone. The view carries the resolved configuration's
    environment-read values, because the lookup's debug line redacts with
    them: an outer chain file's section can hold an env-substituted value,
    and an empty list would print it. Both are instance state, set at
    construction; the class keeps no mutable defaults.
    """

    class _Segment:
        def __init__(self, dump: Dict[str, Any]) -> None:
            self._dump = dump

        def model_dump(self, by_alias: bool = True) -> Dict[str, Any]:
            return copy.deepcopy(self._dump)

    def __init__(
        self, dump: Dict[str, Any], environment_values: Sequence[str] = ()
    ) -> None:
        self.scanners = _ScannerFileView._Segment(dump)
        self._environment_values = list(environment_values)

    def get_plugin_config(self, plugin_type: str, plugin_name: str) -> Any:
        from automated_security_helper.config.ash_config import (
            plugin_section_lookup,
        )

        # The view holds scanners sections only, and the ownership check
        # consults it for scanners only (operator_wrote_value).
        if plugin_type != "scanner":
            return None
        return plugin_section_lookup(
            self.scanners.model_dump(by_alias=True),
            plugin_type,
            plugin_name,
            self._environment_values,
        )


def _with_scanner_overrides(
    view: AshConfig, config_overrides: Optional[List[str]], resolved: AshConfig
) -> AshConfig:
    """*view* with the operator's ``scanners`` overrides applied.

    An override is the operator's own write, so a scanner option it sets is
    one the operator wrote. Only the overrides under ``scanners`` are replayed,
    as only those under ``reporters`` are for the reporter sections. An
    override written with the repository's spelling of a trusted section is
    folded onto that section first, as the reporter path folds its own
    (``_folded_onto_trusted``). The whole list applies at once, as the scan's
    own apply takes it, so overrides that are valid only together all land.
    When that fails, each override is left out in turn: the ones whose
    removal alone makes the batch validate are dropped (several at once when
    removing either of them repairs it, which errs toward refusing), and the
    rest still land together. A value only a dropped override wrote is judged
    not the operator's. When no single removal repairs the batch (two or more
    independent failures), the overrides apply one at a time and each one
    that does not replay drops only itself. The scan's own
    apply ran against the resolved configuration and can accept an override
    this view refuses (a section spelled another way here), so a drop is not
    reported anywhere else. The warning is for the overrides that set a path,
    because the configured-path judgment is what this view feeds; a dropped
    override that sets no path changes no path judgment, so it is logged at
    debug level only.
    """
    scanner_overrides = [
        override
        for override in config_overrides or []
        if override.partition("=")[0].removesuffix("+").split(".")[0] == "scanners"
    ]
    if not scanner_overrides:
        return view
    scanner_overrides = _folded_onto_trusted(
        view, scanner_overrides, resolved, section="scanners"
    )
    try:
        return apply_config_overrides(view, scanner_overrides)
    except ASHConfigValidationError as batch_error:
        failure = batch_error
    # Leave one out: the overrides whose removal alone makes the batch
    # validate are the ones the batch cannot take, so the rest, valid only
    # together included, still land.
    culprits: List[int] = []
    for index in range(len(scanner_overrides)):
        try:
            apply_config_overrides(
                view, scanner_overrides[:index] + scanner_overrides[index + 1 :]
            )
        except ASHConfigValidationError:
            continue
        culprits.append(index)
    if culprits:
        remainder = [
            override
            for index, override in enumerate(scanner_overrides)
            if index not in culprits
        ]
        try:
            applied = apply_config_overrides(view, remainder)
        except ASHConfigValidationError:
            pass
        else:
            for index in culprits:
                _report_dropped_scanner_override(
                    view, scanner_overrides[index], failure
                )
            return applied
    out = view
    for override in scanner_overrides:
        try:
            out = apply_config_overrides(out, [override])
        except ASHConfigValidationError as error:
            _report_dropped_scanner_override(view, override, error)
    return out


def _report_dropped_scanner_override(
    view: AshConfig, override: str, error: ASHConfigValidationError
) -> None:
    """Say that *override* did not replay onto *view*: a warning when it sets a
    path, a debug line otherwise (see ``_with_scanner_overrides``)."""
    # The error can quote a section key the file read from the environment, so
    # the message is redacted with the view's values.
    described = redact_values(str(error), config_environment_values(view))
    if not _sets_a_path(override):
        ASH_LOGGER.debug(
            "A --config-overrides entry under scanners that sets no "
            "path does not apply to the operator's own configuration "
            f"({described})",
            extra=NO_MARKUP,
        )
        return
    ASH_LOGGER.warning(
        "A --config-overrides entry under scanners does not apply to "
        f"the operator's own configuration ({described}), so a "
        "configured path it sets is not judged the operator's.",
        extra=NO_MARKUP,
    )


#: Option-key tails that configure a path, for the one warning
#: _with_scanner_overrides scopes to path-setting overrides.
_PATH_OPTION_TAILS = ("file", "path", "dir", "directory", "baseline", "config")


def _sets_a_path(override: str) -> bool:
    """Whether *override* sets a path-shaped option: its value holds a path
    separator, or its last key segment ends in one of the path tails. A
    heuristic for the warning's scope only; the judgment itself reads every
    option. Known gap: a bare file name (no separator) under a key whose last
    segment carries none of the tails is not counted, so that override's drop
    is logged at debug level only, not warned."""
    key_path, _, value = override.partition("=")
    if "/" in value or "\\" in value:
        return True
    last = key_path.removesuffix("+").rsplit(".", 1)[-1].lower()
    return last.endswith(_PATH_OPTION_TAILS)


class OperatorConfig(NamedTuple):
    """The operator's trusted-base load, carried as one value.

    Built only by ``_load_operator_config``. ``chain`` and ``named`` are the
    files the load read and the names that reached them (the given path
    first), ``reads`` each file's own document, and ``environment_paths``
    the chain files the environment chose -- the inputs the membership
    judgments and the sandbox-mode floor walk read, named so a reader does
    not have to know the load's positional layout.
    """

    config: AshConfig
    chain: List[Path]
    named: List[Path]
    reads: Dict[Path, Any]
    environment_paths: FrozenSet[Path]
    #: The names each chain file was reached by, by file
    #: (``ResolvedConfigDocument.names``); the delivered-file judgment reads it.
    names: Dict[Path, Tuple[Path, ...]] = {}


def trusted_base_config(
    operator: Optional[OperatorConfig],
    trees: List[Path],
    default_in_tree: bool,
    any_checkout: bool = False,
    default_config: Optional[AshConfig] = None,
    default_views: Optional[Tuple[List[Path], List[Path], FrozenSet[Path]]] = None,
    default_reads: Optional[Dict[Path, Any]] = None,
    *,
    merged_fallback: bool,
    outside_files: bool = False,
    default_outside: bool = False,
    default_delivered: bool = False,
) -> AshConfig:
    """The trusted base an in-tree config's sandbox grants come from, before overrides.

    The operator's config (*operator*, from ``_load_operator_config``) when none of
    its files is inside *trees*, judged by where each resolves to and by the name
    that reached it, so a file in the tree that links out of it is still the
    tree's. With *any_checkout* (a caller that knows no tree is scanned), a file
    inside ANY checkout counts as the tree's too, by the same fail-closed
    membership the chain reads use. With *outside_files*, a file inside ANY
    checkout, or one an MCP client delivered (``_with_outside_files``), counts
    as well, whether or not a tree is scanned: such a file makes no sandbox
    grant (``sandbox_grants``), so it cannot be the base the grants are held
    to. Its mode still counts, since a mode other than ``off`` grants
    nothing: the base takes the mode the operator's config set, as it did when
    that config was the base. A file in a checkout other than the scanned one
    also keeps what it sets that only restricts (``keep_restrictions``: a
    lowered archive limit, a no-usage-data scanner option, a network list as a
    limit); a file an MCP client delivered keeps nothing, so its base is the
    defaults and the mode. *default_outside* says the same of ASH_CONFIG's
    file, which *default_in_tree* counts although the trees hold none of it
    (it is in a checkout, or delivered): the base is the defaults with the
    mode ASH_CONFIG's config set, and with its restrictions unless
    *default_delivered* says a file of its chain was delivered. The
    owned-file walk below, and so the mode
    floor, read the membership of *any_checkout* alone. The ASH_CONFIG read made
    here when none is carried confines the chain as a scan does
    (``scan_repository_settings``: the scanned *trees* and any other checkout).
    Otherwise the defaults: *default_config*
    when the caller carries the ASH_CONFIG config its own load already read
    (copied before use), ``get_default_config()`` when none is carried, or a
    plain ``AshConfig()`` when ASH_CONFIG's file is in the tree too
    (*default_in_tree*). Its sandbox mode is a floor wherever the operator's file
    lives, because a mode other than off grants nothing: when the base's mode is
    off it takes the mode the operator's OWN files set -- the chain's
    operator-owned occurrences, each contributing the mode its own document
    sets, directly or through its own patch (_owned_sandbox_mode), so a base
    in the scanned tree later in the chain cannot turn off the mode the
    operator's base set. When no owned file sets one, *merged_fallback*
    decides what stands, and it is keyword-only with no default because its
    two meanings are both live: a caller that said nothing would silently
    take one of them. False, the container floor's semantics: the base's
    own off stands, because the merged mode is then repository-written and
    the floor is the mode no file of the scanned tree can grant or take
    away. True, resolve_config's semantics for the scan's own resolution:
    the merged mode (the operator config's, or ASH_CONFIG's) stands, so a
    config the operator named inside the tree still sets the mode the scan
    applies, as any of its other settings apply. *default_views* and *default_reads* are the ASH_CONFIG
    load's ``(chain, named, environment_paths)`` and per-file documents,
    carried beside *default_config* for that walk. The overrides are replayed
    onto the result by the caller, so ``--sandbox off`` still turns it off.

    Shared by resolve_config and container mode's fallback
    (``interactions/run_ash_scan.py``, ``_sandbox_mode_without_the_config``), so
    the two read the operator's files alike; where no owned file sets a
    mode they diverge by *merged_fallback*, deliberately -- the scan applies
    the merged mode, the floor refuses a repository-written one -- and by
    *outside_files* and *default_outside*, which only the scan's own
    resolution sets: the floor reads the mode alone, which they leave as it was.
    """
    # ASH_CONFIG's file is read for its sandbox mode even when it is in the
    # tree, so what a file of its chain in the tree writes for an operator-only
    # option is left out of that read, as resolve_config's is: a value the
    # option refuses does not refuse the configuration. The confine identity
    # is the shared constructor's (scan_repository_settings), the same one the
    # chain read, the container floor and the MCP pre-check use.
    settings = scan_repository_settings(trees)
    confine = settings.confine
    operator_in_tree = operator is not None and bool(
        files_inside(operator.chain, trees, operator.named)
        or (
            any_checkout
            and _with_any_checkout_files([], operator.chain, operator.named)
        )
    )
    # Not the tree's, but not the operator's for a grant either: its mode
    # still counts (below), as it did when this config was the base.
    operator_outside = (
        operator is not None
        and not operator_in_tree
        and outside_files
        and bool(
            _with_outside_files([], operator.chain, operator.named, operator.names)
        )
    )
    # A file an MCP client delivered is the client's whole: nothing of it is
    # kept, not even what only restricts. Only a file in another checkout is.
    operator_delivered = operator_outside and bool(
        _delivered_by_a_client(operator.chain, operator.names)
    )

    # The ASH_CONFIG config *default_config*, when the caller already loaded
    # it (resolve_config's one read, made under this same confine identity):
    # a second read here could see a chain file changed in between, so the
    # base would not be the configuration the membership judgments read.
    # Copied before use -- the sandbox-mode floor below writes into it, and
    # the caller's object must stay what its load produced. With nothing
    # carried, ONE read is made here and memoized: the base build and the
    # floor below describe the same files, and the chain is not read twice.
    uncarried_read: List[
        Tuple[
            AshConfig,
            Optional[Tuple[List[Path], List[Path], FrozenSet[Path]]],
            Dict[Path, Any],
        ]
    ] = []

    def uncarried() -> Tuple[
        AshConfig,
        Optional[Tuple[List[Path], List[Path], FrozenSet[Path]]],
        Dict[Path, Any],
    ]:
        if not uncarried_read:
            views: List[Tuple[List[Path], List[Path], FrozenSet[Path]]] = []
            reads: Dict[Path, Any] = {}
            loaded = get_default_config(
                confine,
                views=views,
                repository_file=settings.is_repository_file,
                reads=reads,
            )
            uncarried_read.append((loaded, views[0] if views else None, reads))
        return uncarried_read[0]

    def ash_config_base() -> AshConfig:
        if default_config is not None:
            return default_config.model_copy(deep=True)
        return uncarried()[0].model_copy(deep=True)

    if operator is not None and not operator_in_tree and not operator_outside:
        trusted = operator.config
    else:
        trusted = AshConfig() if default_in_tree else ash_config_base()
        # A mode other than off grants nothing, so the base keeps the mode of
        # the config that was the base before the checkout and delivery legs
        # took its grants: the operator's, else ASH_CONFIG's.
        if operator_outside:
            trusted.sandbox.mode = operator.config.sandbox.mode
            if not operator_delivered:
                keep_restrictions(trusted, operator.config)
        elif default_outside:
            kept_from = ash_config_base()
            trusted.sandbox.mode = kept_from.sandbox.mode
            if not default_delivered:
                keep_restrictions(trusted, kept_from)
    # The floor mode comes from the chain's operator-owned files alone,
    # each contributing the mode its own document sets, directly or
    # through its own patch, in chain order: the merged chain cannot
    # tell the operator's write from a repository file's, so an in-tree
    # base later in the chain could turn off the mode the operator's own
    # base set. When no owned file sets one, merged_fallback decides
    # between the merged mode (the scan's own resolution) and the
    # trusted base's own off (the floor; see the docstring). The floor
    # is READ, never written into, so the carried config's own mode
    # serves without the deep copy a base build needs. The walk runs on
    # every load, not only when the trusted base's own mode is off: it is
    # also where an owned file whose written mode is outside the known set
    # refuses the load (_unknown_owned_mode_refusal), and a refusal gated
    # on the base's mode would miss the same write under a base whose own
    # mode is on. It reads only what this function already loaded, so the
    # hoist costs no extra read.
    if operator is not None:
        owned_mode = _owned_sandbox_mode(
            operator.chain,
            _repository_members(operator.chain, operator.named, trees, any_checkout),
            operator.reads,
            operator.environment_paths,
        )
        merged_mode = operator.config.sandbox.mode
    else:
        if default_config is not None:
            merged_mode = default_config.sandbox.mode
            views = default_views
            reads = default_reads or {}
        else:
            loaded, views, reads = uncarried()
            merged_mode = loaded.sandbox.mode
        owned_mode = None
        if views is not None:
            chain, named, environment_paths = views
            owned_mode = _owned_sandbox_mode(
                chain,
                _repository_members(chain, named, trees, any_checkout),
                reads,
                environment_paths,
            )
    if trusted.sandbox.mode == "off":
        if owned_mode is not None:
            trusted.sandbox.mode = owned_mode
        elif merged_fallback:
            trusted.sandbox.mode = merged_mode
    return trusted


def _load_operator_config(
    trusted_config_path: Path | str | None,
    source_dir: Path | str | None,
    permit_base: Optional[Callable[[Path], bool]],
    anchor_paths: Optional[AnchorPaths] = None,
) -> Optional[OperatorConfig]:
    """The operator's config, the files it was built from, the names they
    were reached by, each file's own document, and the files the environment
    chose (OperatorConfig); or None, only when no path was named.

    The files are resolved. The names hold *trusted_config_path* as given and
    each ``extends`` base as its ref names it, so ``trusted_base_config`` judges a
    file in the tree that links out of it, or one a link in the tree leads to, as
    the tree's. Loaded the way _resolve_config loads a config file, and refused
    the same way when it does not validate. A named file that is missing,
    mistyped, dangling or a directory is refused (``check_config_path``), never
    dropped: a silent None here would fall back to the defaults or ASH_CONFIG
    and lose the operator's sandbox-mode floor and the settings for options
    only the operator may set.

    A named file whose text does not parse is refused as an unparsed config
    naming itself (``ASHConfigUnparsedError``, in ``unparsed_config_reason``'s
    words). The chain walk reads the root file raw, so the parser's error
    carried no file name a caller could use: the MCP tools framed it with the
    only path they hold, the client's delivered file, and blamed that file
    for the operator's copy of a profile that would not parse. A base of the
    chain is already reworded by the walk, and a file the process cannot
    read is raised as it is, for the caller to name in its own words.
    """
    if trusted_config_path is None:
        return None
    # check_config_path refuses with os.stat, not Path.is_file, which before
    # Python 3.14 raises for an error other than "not found" (a directory
    # above that cannot be searched).
    check_config_path(trusted_config_path)
    # With its references, which the settings it confines a config's to take
    # (_take_confined_references).
    reads: Dict[Path, Any] = {}
    unparsed: Optional[str] = None
    try:
        document, config = load_config_file_for_run(
            trusted_config_path,
            reads=reads,
            source_dir=source_dir,
            permit_base=permit_base,
            anchor_relative_paths=anchor_paths,
        )
    except (yaml.YAMLError, ValueError) as exc:
        # ASH's own refusals and pydantic's ValidationError are ValueErrors
        # the classifier excludes; they are re-raised as they are.
        if not is_config_parse_error(exc):
            raise
        # The parser's own words can quote the file (unparsed_config_reason).
        unparsed = unparsed_config_reason(Path(trusted_config_path), exc)
    if unparsed is not None:
        # Outside the handler (unparsed_config_reason).
        raise ASHConfigUnparsedError(unparsed)
    return OperatorConfig(
        config=config,
        chain=list(document.chain),
        named=[Path(trusted_config_path), *document.named],
        reads=reads,
        environment_paths=frozenset(document.environment_paths),
        names=dict(document.names),
    )


def _warnings_when_discovered(
    config_path: Path,
    source_dir: Path,
    permit_base: Optional[Callable[[Path], bool]] = None,
) -> List[str]:
    """Discovery's warnings for ``source_dir`` when ``config_path`` is the source it selects.

    ``ash scan``'s workspace mode (``workspace/resolver.py`` and
    ``workspace/execution.py``) and the sandbox-mode probe run discovery
    themselves and pass the file it selected as the config path, so the sources
    it ignored are reported for them as they are when ``_resolve_config``
    discovers. Discovery is run again only for a file at one of its locations,
    under the same ``permit_base`` gate, and a gate refusal of another
    candidate yields no warnings rather than refusing a load the caller's own
    discovery already passed. The warnings are returned as plain strings, not
    ``LoggedResolutionWarning``: the discovering caller logged nothing
    (``run_ash_scan._discovered_config_path``), so the orchestrator logs each
    once when it reads ``_resolution_warnings``.
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


def _resolve_config(
    config_path: Path | str | None,
    source_dir: Path | str | None,
    fallback_to_default: bool,
    config_overrides: Optional[List[str]],
    permit_base: Optional[Callable[[Path], bool]],
    chain: List[Path],
    named: Optional[List[Path]] = None,
    environment_paths: Optional[Set[Path]] = None,
    no_discovery: bool = False,
    reads: Optional[Dict[Path, Any]] = None,
    texts: Optional[Dict[Path, str]] = None,
    confine: Optional[Callable[[Path, Path, Any], Any]] = None,
    default_confine: Optional[Callable[[Path, Path, Any], Any]] = None,
    repository_file: Optional[Callable[[Path, Path], bool]] = None,
    default_repository_file: Optional[Callable[[Path, Path], bool]] = None,
    default_key_values: Optional[List[str]] = None,
    default_views: Optional[
        List[Tuple[List[Path], List[Path], FrozenSet[Path]]]
    ] = None,
    default_config_out: Optional[List[AshConfig]] = None,
    merged: Optional[List[Any]] = None,
    refuse_env: Optional[RefuseEnv] = None,
    overlay: Optional[ResolvedConfigDocument] = None,
    fill: Sequence[Any] = (),
    anchor_paths: Optional[AnchorPaths] = None,
    documents_out: Optional[Dict[Path, Any]] = None,
    names_out: Optional[Dict[Path, Tuple[Path, ...]]] = None,
    expect: Optional[FileIdentity] = None,
) -> AshConfig:
    """resolve_config without the sandbox confinement.

    Appends every file read to ``chain``, resolved, and the config file as it was
    named (passed or discovered, before symlinks are followed) to ``named``.
    Adds to ``environment_paths`` the files of ``chain`` the environment chose
    (``ResolvedConfigDocument.environment_paths``). ``confine`` is handed to the
    config file's load (``load_config_file``), and ``default_confine`` to the
    load of the file ASH_CONFIG names (get_default_config);
    ``repository_file`` and ``default_repository_file`` ride beside them, the
    same settings' ``is_repository_file`` for each load's patch-pointer
    ownership (resolve_config_document).
    ``default_key_values`` receives the KEY references that load read from the
    environment, and ``default_views`` its ``(chain, named, environment_paths)``
    tuple -- both carried out of the one load, so the caller's warnings and
    membership judgments describe the files that load read, never a second
    resolution's. ``no_discovery`` skips the discovery step below entirely
    (see resolve_config). ``merged`` receives the selected chain's merged
    document (the overlay merged in), before overrides, for the caller's
    operator-paths record. ``refuse_env``, ``overlay`` and ``fill`` are the
    client and overlay pipeline's (see resolve_config): ``refuse_env`` and
    ``fill`` ride into the selected chain's load, ``overlay`` is merged over
    the selected document before validation and used alone wherever the
    default config would be returned. ``anchor_paths`` accepts the files whose
    relative paths are taken from their own directory
    (``config/operator_paths.py``); it rides into the selected chain's load.
    ``documents_out`` and ``names_out``
    receive the selected chain's per-file documents and the paths each file
    was reached by, for the client config rules.
    """

    def overlaid_fallback(
        default_config_value: Optional[AshConfig],
    ) -> Optional[AshConfig]:
        # The overlay alone in place of the default config: falling back to
        # the defaults would drop the fields the overlay makes final.
        if overlay is None or default_config_value is None:
            return default_config_value
        chain.extend(overlay.chain)
        if named is not None:
            named.extend(overlay.named)
        if merged is not None:
            merged.append(overlay.data)
        if documents_out is not None:
            documents_out.update(overlay.documents)
        if names_out is not None:
            names_out.update(overlay.names)
        overlaid = AshConfig.model_validate(
            overlay.data, strict=True, context={"strict_file_load": True}
        )
        # The overlay is the whole configuration here, so its environment
        # reads are the configuration's: values, rewrites, key mappings and
        # references, as a loaded chain's are.
        _record_overlay_reads(
            overlaid,
            overlay,
            reads if reads is not None else {},
            texts if texts is not None else {},
        )
        return overlaid

    try:
        # Start with default config. A scan starts from the file ASH_CONFIG names
        # (get_default_config) with a config file named too, and refuses the run
        # when that file is refused. A caller that does not fall back to the
        # defaults (`config get`, `validate-plugin-dependencies`, `report
        # --config`) still loads it, so it refuses what the scan refuses.
        config: Optional[AshConfig] = None

        def carry_default_values(default_config: AshConfig) -> AshConfig:
            # The ASH_CONFIG chain's environment KEY reads, for the caller's
            # fail-closed warning: load_config_file_for_run recorded them on
            # the config it built, so no second read of the chain is needed.
            # Keys only -- a place string is built from mapping keys alone,
            # so the warnings redact against keys, as the settle step's
            # redaction does. The loaded config itself travels too, so the
            # trusted base is built from this same read.
            if default_config_out is not None:
                default_config_out.append(default_config)
            if default_key_values is not None:
                default_key_values.extend(
                    reference.value
                    for reference in getattr(
                        default_config, "_environment_references", ()
                    )
                    if getattr(reference, "key", False)
                    and getattr(reference, "value", "")
                )
            return default_config

        if fallback_to_default:
            try:
                config = carry_default_values(
                    get_default_config(
                        default_confine,
                        views=default_views,
                        repository_file=default_repository_file,
                        reads=reads,
                        texts=texts,
                    )
                )
            except OSError as e:
                # A file ASH_CONFIG names that cannot be read is refused as the
                # config file below is when it cannot be read: exit 3, on one
                # line. Raised as it was, the handler at the end logged it as
                # an unexpected error, with the path's newline as it is. A
                # caller that turns the fallback off is given the OSError and
                # names the file in its own words (cli/config.py). A local
                # name, not the `named` parameter; and the error's own file
                # when ASH_CONFIG is somehow unset, so a KeyError never hides
                # the OSError.
                ash_config_file = Path(
                    os.environ.get("ASH_CONFIG")
                    or os.fsdecode(e.filename or "")
                    or "ASH_CONFIG"
                )
                refused = ASHConfigSourceError(
                    f"could not read {describe_config_path(ash_config_file)}: "
                    f"{os_error_without_named_file(e, ash_config_file)}"
                )
                refused.ash_config_file = ash_config_file
                raise refused from e
        # Any ASH_CONFIG that is set, as the scan reads it: a directory, a name
        # that does not exist, a link to nothing or only whitespace is refused
        # here as the scan refuses it. An exists test here skipped all but the
        # directory, and so did the check of a file outside the working
        # directory, which trusted_base_config takes as the base and so never
        # reads ASH_CONFIG: get and validate-plugin-dependencies exited 0.
        if not fallback_to_default and os.environ.get("ASH_CONFIG"):
            carry_default_values(
                get_default_config(
                    default_confine,
                    views=default_views,
                    repository_file=default_repository_file,
                    reads=reads,
                    texts=texts,
                )
            )
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
            config = overlaid_fallback(config)
            # Apply overrides to default config if provided
            if config_overrides:
                return apply_config_overrides(config, config_overrides)
            return config

        # Only a source_dir the caller passed may widen where `extends` bases
        # may live. The cwd fallback below must not: `ash report --config
        # <file>` run from a home directory would otherwise let that file's
        # bases reach anywhere under it.
        confinement_source_dir = source_dir

        # Resolve cwd default at call time, not import time. A working
        # directory deleted while the process runs gives None: no file can be
        # discovered in it, so discovery below is skipped and a named
        # config_path is read as given.
        if source_dir is None:
            source_dir = working_directory()

        if isinstance(source_dir, str):
            source_dir = Path(source_dir)

        # Check for config file if not explicitly provided. The precedence, and
        # why sources are selected rather than merged, is documented in
        # config/config_sources.py.
        # The directory `extends` bases are confined to depends on it (see
        # resolve_config_source): a discovered file is given source_dir, a named
        # file the caller's source_dir, if any. Either way the bases stay inside
        # that directory only when the file, its symlinks resolved, is inside
        # it; a discovered config that is a symlink to a file elsewhere has its
        # bases confined to that file's own directory (default_confinement_root).
        confinement_dir = confinement_source_dir
        # The discovered source, announced once it has loaded rather than when it is
        # found: a source that does not load is not the configuration in use.
        discovered_label = None
        # The sources discovery found and did not use. Their settings are not
        # applied, so they are reported with the scan's results as well as
        # logged. LoggedResolutionWarning: the orchestrator logs every other
        # resolution warning itself and skips these, so none is logged twice
        # (orchestrator.py reads the class).
        ignored_sources: List[str] = []
        if config_path is None and source_dir is not None and not no_discovery:
            ASH_LOGGER.verbose(
                "No configuration file provided, checking for default paths"
            )
            # The caller's permit_base gates discovery too: a discovered source
            # can be a symlink to any file on the host, and pyproject.toml is
            # read for its [tool.ash] table, so every source that exists is
            # checked by the path it resolves to before anything opens it
            # (config_sources.discover_config_source). With no permit_base
            # nothing is checked, as before.
            discovery = discover_config_source(source_dir, permit=permit_base)
            ignored_sources = [
                LoggedResolutionWarning(message)
                for message in log_config_discovery(discovery, announce_selected=False)
            ]
            if discovery.selected is not None:
                config_path = discovery.selected.path
                # The identity the permit check took of the discovered file
                # (ConfigSource.identity), so the load is held to the file the
                # permit judged: a name made to lead elsewhere between the
                # check and the open is refused at the open. With no permit
                # no check was made, the identity is None, and no identity is
                # expected of the file, as before.
                expect = discovery.selected.identity
                confinement_dir = source_dir
                discovered_label = discovery.selected.label
                ASH_LOGGER.verbose(
                    f"Found configuration file at: {config_path.as_posix()}",
                    extra=NO_MARKUP,
                )

        if config_path is None:
            if fallback_to_default:
                ASH_LOGGER.verbose(
                    "Configuration file not found or provided, using default config"
                )
                config = overlaid_fallback(config)
                # Apply overrides to default config if provided
                if config_overrides:
                    return apply_config_overrides(config, config_overrides)
                return config  # Return default config if no config file found
            else:
                raise ValueError("Configuration file not found or provided")

        # Process config file
        unparsed: Optional[str] = None
        try:
            config_path = (
                Path(config_path) if not isinstance(config_path, Path) else config_path
            )
            # NO_MARKUP, here and below: a path is data, as in the
            # load-error line further down. One line, as the warning below is:
            # the path is the caller's text.
            ASH_LOGGER.debug(
                shown_on_one_line(
                    f"Loading configuration from {config_path.as_posix()}"
                ),
                extra=NO_MARKUP,
            )

            # One stat, classified by its own error (utils/path_stat.py): not
            # exists(), which before 3.14 raises the stat's PermissionError
            # for a path under an unsearchable directory, and never a second
            # stat, which could answer differently and send a denied path to
            # the default config.
            config_stat = stat_named_path(config_path)
            if isinstance(config_stat, StatProblem):
                # Every stat problem is refused as the problem it is, a
                # missing file included: falling back to the default config
                # would run the scan with settings the operator did not
                # choose, and with none of the named file's suppressions and
                # ignore paths. Only the absence of any config file (above)
                # resolves to the defaults. A refusal names the errno's code
                # where it has one and the caller's own path text, never a
                # value.
                if config_stat.kind == LOOP:
                    raise ASHConfigValidationError(
                        f"Config file is a symbolic link loop: {config_path.as_posix()}"
                    ) from config_stat.cause()
                if config_stat.kind == UNREADABLE:
                    raise ASHConfigValidationError(
                        f"Config file cannot be read ({config_stat.code}): "
                        f"{config_path.as_posix()}"
                    ) from config_stat.cause()
                # MISSING, the one kind left: the words `ash report`, a scan and
                # named_config.py use.
                raise ASHConfigFileNotFoundError(
                    f"Configuration file not found: {config_path.as_posix()}"
                ) from config_stat.cause()

            # The second route to the one landing below: a caller that ran
            # discovery itself and named the file it selected (workspace mode,
            # the sandbox-mode probe) skipped the discovery branch above, so
            # the sources its discovery ignored are re-derived here, for a
            # named file only when it is exactly what discovery selects in the
            # caller's source directory (_warnings_when_discovered). Plain
            # strings: nothing has logged them, so the orchestrator logs each
            # once. ``no_discovery`` keeps its promise that this load runs no
            # discovery.
            if (
                discovered_label is None
                and confinement_source_dir is not None
                and not no_discovery
            ):
                ignored_sources = _warnings_when_discovered(
                    config_path, source_dir, permit_base
                )

            ASH_LOGGER.debug("Validating file config")
            # AshConfig.from_file, keeping the list of files the config came from.
            # A chain that does not resolve raises with nothing read from the
            # environment in its message (resolve_config_document).
            try:
                document, config = load_config_file_for_run(
                    config_path,
                    reads=reads,
                    texts=texts,
                    source_dir=confinement_dir,
                    permit_base=permit_base,
                    config_overrides=config_overrides,
                    confine=confine,
                    repository_file=repository_file,
                    refuse_env=refuse_env,
                    overlay=overlay,
                    fill=fill,
                    anchor_relative_paths=anchor_paths,
                    expect=expect,
                )
            except ConfigFileRefused as refusal:
                if not refusal.after_overrides:
                    # Without the values and keys the chain read from the
                    # environment, in the log line as in the refusal. NO_MARKUP:
                    # the description names keys the file wrote, and a "[/" in
                    # one is a closing Rich tag that raises instead of printing,
                    # before the refusal reaches the operator.
                    ASH_LOGGER.error(
                        "Configuration validation failed: "
                        + describe_validation_error(
                            refusal.validation_error,
                            refusal.document.environment_values,
                        ),
                        extra=NO_MARKUP,
                    )
                # Refused, never replaced by the default config, for a
                # discovered file as for a named one: the file is there to
                # configure this run, and the defaults would scan with its
                # suppressions, ignore paths and settings switched off
                # (ConfigCheck, `ash config validate` and the CHANGELOG all
                # promise exit 3 here, and the parse-error arm below refuses
                # the same file the same way).
                raise
            chain.extend(document.chain)
            if merged is not None:
                data_for_record = document.data
                if overlay is not None and isinstance(data_for_record, dict):
                    # The same merge the load validated (deep_merge is pure),
                    # so the record holds the overlaid document.
                    data_for_record = deep_merge(
                        data_for_record, overlay.data, AshConfig
                    )
                merged.append(data_for_record)
            if documents_out is not None:
                documents_out.update(document.documents)
            if names_out is not None:
                names_out.update(document.names)
            config._loaded_from = config_path
            if named is not None:
                named.append(config_path)
                named.extend(document.named)
            if environment_paths is not None:
                environment_paths.update(document.environment_paths)
            if overlay is not None:
                chain.extend(overlay.chain)
                if named is not None:
                    named.extend(overlay.named)
                if documents_out is not None:
                    documents_out.update(overlay.documents)
                if names_out is not None:
                    names_out.update(overlay.names)
                # What the overlay's files read from the environment was
                # recorded on the config by the load (_record_overlay_reads
                # in load_config_file_for_run): values, rewrites, key mappings
                # and references, as the chain's own reads are.
            ASH_LOGGER.debug(f"Loaded config from file: {config_path}", extra=NO_MARKUP)
            if discovered_label is not None:
                ASH_LOGGER.info(
                    f"Using ASH configuration from {discovered_label}", extra=NO_MARKUP
                )
            config._resolution_warnings.extend(ignored_sources)
            return config

        except (IOError, UnicodeDecodeError, yaml.YAMLError, ValueError) as e:
            # json.JSONDecodeError, UnicodeDecodeError and a constructor's
            # ValueError (!!int, !!float, the int digit limit) are all
            # ValueErrors. pydantic's ValidationError is one too; the
            # classifier (is_config_parse_error) excludes it, and ASH's own
            # refusals re-raise in the else branch below, so neither is
            # reported as a parse.
            if is_config_parse_error(e):
                # The parser's own words can quote the file
                # (unparsed_config_reason).
                unparsed = unparsed_config_reason(config_path, e)
            else:
                if not isinstance(e, OSError):
                    # The one guard for every excluded ValueError: ASH's own
                    # refusals (ConfigFileRefused above included) re-raise by
                    # identity to the ASHConfigValidationError handler below,
                    # and a raw pydantic ValidationError to the resolution
                    # handler; neither is a file the process could not read.
                    raise
                # NO_MARKUP: a "[/" in the file's path is a closing Rich tag
                # that raises instead of printing. The file is named as given
                # (error_text), not as an OSError's repr quotes it, and on one
                # line.
                ASH_LOGGER.error(
                    shown_on_one_line(
                        f"Failed to load configuration file: {error_text(e)}"
                    ),
                    extra=NO_MARKUP,
                )
                if not fallback_to_default:
                    # The caller refuses the file in its own words (`config
                    # get`, `report --config`, MCP get_config).
                    raise e
                # Refused, never replaced by the default config: the file is
                # there to configure this run, and the defaults would scan with
                # its suppressions, ignore paths and settings switched off and
                # report success. The defaults apply only when there is no
                # config file (above).
                raise ASHConfigSourceError(
                    f"could not read {describe_config_path(config_path)}: "
                    f"{os_error_without_named_file(e, config_path)}"
                ) from e
        if unparsed is not None:
            # No log record: each caller prints the raised refusal in its own
            # words (the scan's refusal line, config get and validate's), so
            # any record here showed the same thing beside it at some
            # verbosity — and only for YAML and JSON, since a TOML refusal
            # arrives already raised and was never logged here. The reason
            # alone in the raise: it already says the file could not be
            # parsed, so a "Failed to load configuration file:" prefix would
            # read double.
            # Refused whether or not the caller falls back to the defaults (an
            # unreadable file is instead re-raised raw when the fallback is
            # off, for the caller to name in its own words): raised outside
            # the handler, so the parser's error is neither its cause nor its
            # context.
            raise ASHConfigSourceError(unparsed)

        return config

    except ASHConfigValidationError:
        raise
    except Exception as e:
        if not fallback_to_default:
            raise e
        # Refused, never answered with the default config, for the same reason: a
        # config that failed to resolve would be replaced by the defaults.
        ASH_LOGGER.error(
            f"Unexpected error in resolve_config: {error_text(e)}", extra=NO_MARKUP
        )
        raise ASHConfigValidationError(
            "The configuration could not be resolved: "
            f"{type(e).__name__}: {error_text(e)}"
        ) from e
    except BaseException as e:
        # pydantic-core reports a Rust panic as pyo3's PanicException, which is
        # a BaseException and so passes `except Exception`. Refused the same way;
        # anything else (KeyboardInterrupt, SystemExit) propagates.
        if type(e).__name__ != "PanicException" or type(e).__module__ != "pyo3_runtime":
            raise
        raise ASHConfigValidationError(
            "The configuration could not be resolved: "
            f"{type(e).__name__}: {error_text(e)}"
        ) from e


#: Why a config an MCP client supplied may not grant, for the confinement warning.
CLIENT_SUPPLIED = "an MCP client supplied the file, not the operator"

#: Why a file's values are not repeated in an error about it.
CLIENT_FILE = "an MCP client supplied the file"
REPOSITORY_FILE = "the file is in a git checkout or the scanned directory"


class LoggedResolutionWarning(str):
    """A resolution warning resolve_config has already logged.

    Every resolution warning is reported with a scan's results; the orchestrator
    also logs each one, except these, so that none is logged twice. The sources
    discovery ignored are logged by discovery when resolve_config discovers.
    """

    __slots__ = ()


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
        if is_symlink_loop(exc):
            return ASHConfigSourceError(
                f"Configuration file {where} is a symbolic link that leads back to "
                "itself, so it cannot be read."
            )
        return ASHConfigSourceError(
            f"Configuration file {where} cannot be read: {exc.strerror}"
        )
    except ValueError:
        # os.stat raises ValueError for a NUL in the path and UnicodeEncodeError,
        # a ValueError, for a name the file system encoding cannot carry.
        return ASHConfigSourceError(
            f"Configuration file {where} cannot be read: the path is not a name "
            "the file system can carry."
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
    # os.stat raises ValueError for a string with an embedded NUL, and
    # UnicodeEncodeError, a ValueError, for a name the file system encoding
    # cannot carry; both are "not a file that can be read", refused as a missing
    # file is.
    try:
        regular = stat.S_ISREG(os.stat(path).st_mode)
    except (OSError, ValueError):
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
    too. Every config file a check surface reads outside ``load_config_file``
    comes through here, so none of them is
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
    problem: Optional[str] = None
    try:
        return resolve_config_document(
            path,
            confine_to=confine_to,
            permit_base=permit_base,
            refuse_env=refuse_env,
            anchor_relative_paths=anchor_relative_paths,
        )
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValueError) as e:
        # json.JSONDecodeError, UnicodeDecodeError and a YAML constructor's
        # ValueError (!!int abc, the int digit limit) are all ValueErrors, and
        # all parse failures (is_config_parse_error). pydantic's
        # ValidationError is a ValueError too; the classifier excludes it, so
        # it is re-raised as it was and never reported as a parse. A bare
        # except on the two named types let a constructor's ValueError
        # escape raw, with the file's text in its message.
        if not isinstance(e, OSError) and not is_config_parse_error(e):
            raise
        if isinstance(e, OSError) or not (unquoted or _is_a_client_file(path)):
            # A YAML parser's message quotes the file's path as given, so its
            # control characters are escaped there as describe_config_path
            # escapes them.
            reason = escape_controls_in(e, path_spellings(path))
            if log_failure:
                ASH_LOGGER.error(f"Failed to load configuration file: {reason}")
            verb = "read" if isinstance(e, OSError) else "parse"
            raise ASHConfigSourceError(
                f"could not {verb} {describe_config_path(path)}: {reason}"
            ) from e
        problem = _unquoted_load_error(path, e)
        if log_failure:
            ASH_LOGGER.error(f"Failed to load configuration file: {problem}")
    # Raised outside the handler, so the parser's error, which can quote the line
    # it stopped at, is neither the cause nor the context of this one.
    raise ASHConfigSourceError(problem)


def validate_config_document(
    document: ResolvedConfigDocument,
    config_path: Path | str,
    *,
    unquoted: Optional[str] = None,
) -> AshConfig:
    """The config ``document`` (``read_config_document``'s) holds, validated as a
    scan validates it; ``ASHConfigValidationError`` naming ``config_path`` if it
    does not validate.

    ``unquoted`` is why the file's values may not be repeated (``CLIENT_FILE``,
    ``REPOSITORY_FILE``): the error then gives each problem's location and kind
    only (``_client_validation_error``), and is raised with no cause or context
    that holds pydantic's text.
    """
    try:
        # The strict_file_load context, as build_config validates a document:
        # it selects the named refusal of a typed field's environment reference
        # (RedactedSection's validator), where pydantic's own message calls the
        # resolved text not-an-integer and names no variable.
        return AshConfig.model_validate(
            document.data, strict=True, context={"strict_file_load": True}
        )
    except ValidationError as e:
        if unquoted is None:
            # Not pydantic's own text, which quotes every input: a mapping key
            # the file read from the environment stands in an error's
            # location, and a validator's message can repeat the value it
            # refused. Each problem is given by its place and kind, redacted
            # with what the chain read from the environment, as every other
            # consumer of an AshConfig ValidationError gives it
            # (describe_validation_error). Not chained: the cause would carry
            # the text to the console, ash.log and an MCP reply.
            described = describe_validation_error(e, document.environment_values)
            raise ASHConfigValidationError(
                f"Configuration validation failed for "
                f"'{describe_config_path(Path(config_path))}': "
                f"{described.rstrip('.')}. "
                "Run 'ash config lint' to identify and fix issues."
            ) from None
        refused = _client_validation_error(config_path, e, why=unquoted)
    raise refused


def _load_single_config_file(
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
    ``ASHConfigValidationError``, both exit 3 from ``ash scan``. One file's
    document validated as an AshConfig, with no overrides and no run record:
    the single-file load an earlier version published as ``load_config_file``,
    renamed here because the run-protocol ``load_config_file`` above answers a
    different question (the whole chain, a document AND a config).
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
            f"Invalid config override: {_override_shown(override)}. "
            "Expected format: key.path=value"
        )
    return key_path, value


#: The shape of a key path: dotted names with the separators an override key
#: may hold, and no blank. An entry with no ``=`` that has this shape is a key
#: typed without its value, and is quoted; anything else may be a value.
_KEY_SHAPED_OVERRIDE = re.compile(r"^[A-Za-z0-9_.+$-]{1,80}$")

#: A digit run this long inside a key-shaped entry reads as an id or a token,
#: not a key path.
_DIGIT_RUN = re.compile(r"[0-9]{5,}")

#: A key-shaped entry longer than this is hidden whatever else it holds.
_LONGEST_QUOTED_KEY = 32

#: A key-shaped entry with no ``.`` and no ``_`` is hidden past this length: a
#: key path that long has a dot or an underscore in it, a token does not.
_LONGEST_QUOTED_BARE_WORD = 16


def _token_shaped(override: str) -> bool:
    """Whether a key-shaped entry has the shape of a secret rather than a key:
    too long for a key path, a digit run of five or more, or a bare word (no
    ``.`` and no ``_``) past sixteen characters. Any one hides it."""
    if len(override) > _LONGEST_QUOTED_KEY:
        return True
    if _DIGIT_RUN.search(override):
        return True
    return (
        "." not in override
        and "_" not in override
        and len(override) > _LONGEST_QUOTED_BARE_WORD
    )


def _override_shown(override: str) -> str:
    """How a refusal names a malformed override entry, given whole.

    An entry with an ``=`` and a blank key is named by its key part, quoted
    (``''``): what stands before the ``=`` is never a value. An entry with no
    ``=`` is quoted when it is key-shaped and not token-shaped, else named by
    its length alone: override refusals name keys and never values
    (apply_config_overrides), and an entry with no separator can be a value
    whose key the operator forgot, a hex digest or an access-key id among
    them. The CLI (apply_config_overrides, split_config_override) and the MCP
    workspace tools name the entry through this one function, so the two
    refusals read the same.
    """
    key_part, separator, _ = override.partition("=")
    if separator:
        return f"'{key_part}'"
    if _KEY_SHAPED_OVERRIDE.match(override) and not _token_shaped(override):
        return f"'{override}'"
    return f"an entry of {len(override)} characters with no '=' (not shown)"


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
    why: str = CLIENT_FILE,
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
        f"shown because {why}. Run 'ash config lint' to identify and fix issues."
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
    judged by its own path and by each path in ``names`` it was reached by
    (``sandbox_grants.tree_holding``), so a
    file reached through a link the repository or a client wrote is theirs.
    """
    paths = list(paths)
    trees = list(trees)
    inside = [path for path in paths if tree_holding(path, trees, names) is not None]
    return inside + [
        path for path in _delivered_by_a_client(paths, names) if path not in inside
    ]


def _delivered_by_a_client(
    paths: Iterable[Path], names: Optional[ChainNames] = None
) -> List[Path]:
    """The files of ``paths`` that an MCP client delivered
    (``cli/mcp/sandbox.config_is_client_supplied``), whoever names them.

    Each file is judged by its own path and by each path in ``names`` it was
    reached by (``config_sources.by_every_name``), so a file reached through a
    link a client wrote is the client's. The one definition of delivery the
    membership checks share (``_not_the_operators``, ``_with_outside_files``).
    """
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    delivered = by_every_name(config_is_client_supplied, names)
    return [path for path in paths if delivered(path)]


def _writes_honor_ignore_files(document: Any) -> bool:
    """Whether a config file's own *document* sets ``honor_ignore_files``, as a
    top-level key (either separator spelling) or as the target of a ``patch``
    entry."""
    if not isinstance(document, dict):
        return False

    def is_the_key(name: Any) -> bool:
        return isinstance(name, str) and name.replace("-", "_") == "honor_ignore_files"

    if any(is_the_key(key) for key in document):
        return True
    patch = document.get("patch")
    return isinstance(patch, list) and any(
        isinstance(entry, dict)
        and isinstance(entry.get("path"), str)
        and is_the_key(entry["path"].lstrip("/").split("/")[0])
        for entry in patch
    )


#: The entry the confinement warnings name for the overrides an MCP client sent,
#: which have no file.
CLIENT_OVERRIDES_SOURCE = Path("config_overrides")


def _honor_ignore_files_overrides(overrides: Optional[Sequence[str]]) -> List[str]:
    """The entries of *overrides* that set ``honor_ignore_files``, in either
    separator spelling and with ``+=`` allowed."""
    return [
        override
        for override in overrides or []
        if override.partition("=")[0].removesuffix("+").strip().replace("-", "_")
        == "honor_ignore_files"
    ]


def _honor_ignore_files_writers(
    in_tree: Sequence[Path],
    chain: Sequence[Path],
    documents: Optional[Mapping[Path, Any]],
) -> Tuple[List[Path], Optional[Path]]:
    """Which files wrote ``honor_ignore_files``, and the operator's file that wrote it last.

    Returns the files of *in_tree* whose document sets the key, in *in_tree*'s
    order and under its names, and the file that wrote the value in force when
    it is one outside *in_tree* (None otherwise). That file is the last one in
    *chain* order to write the key (bases first, the root last, as the chain
    merges), and a file outside *in_tree* is the operator's own: an operator
    file that extends a base inside a checkout still keeps what it writes itself.

    *documents* is keyed by resolved path, as ``resolve_config``'s read cache is.
    A confined file with no document stays a writer, because nothing shows it
    did not write the key; a file outside *in_tree* with no document is not one.
    With no *documents* every confined file is named and none is the operator's.
    """
    confined = [Path(path) for path in in_tree]
    if documents is None:
        return confined, None
    confined_keys = {path.resolve() for path in confined}
    ordered: List[Path] = []
    seen: Set[Path] = set()
    for path in (*(Path(each) for each in chain), *confined):
        key = path.resolve()
        if key not in seen:
            seen.add(key)
            ordered.append(key)
    wrote = [
        key
        for key in ordered
        if (
            _writes_honor_ignore_files(documents[key])
            if key in documents
            else key in confined_keys
        )
    ]
    wrote_set = set(wrote)
    named = [path for path in confined if path.resolve() in wrote_set]
    decided_by = wrote[-1] if wrote and wrote[-1] not in confined_keys else None
    return named, decided_by


def confine_honor_ignore_files(
    config: AshConfig,
    trusted: AshConfig,
    config_overrides: Optional[List[str]],
    in_tree: List[Path],
    reason: str = REPOSITORY_WRITTEN,
    documents: Optional[Mapping[Path, Any]] = None,
    chain: Sequence[Path] = (),
    remedy: str = KEEP_A_SETTING,
    environment_paths: Collection[Path] = frozenset(),
) -> Optional[Tuple[Path, bool]]:
    """Take ``honor_ignore_files`` from the trusted base, never from an untrusted file.

    The setting decides whether the scanned repository's own ``.gitignore`` and
    ``.ignore`` files shrink the scan set, so the repository must not choose it in
    either direction. Its value comes from the trusted base (the defaults, or the
    operator's config outside the tree and every other checkout) with the
    ``--config-overrides`` entries for it replayed on top, the way the sandbox
    grants and ``ash_plugin_modules`` are decided. A different value in the
    in-tree file is replaced, with one warning naming the key and the files that
    write it. A value the operator's own file wrote last in the chain stays: an
    operator file outside every checkout that extends a base inside one keeps
    what it writes, as it keeps its own sandbox section.

    Args:
        config: The resolved AshConfig, changed in place.
        trusted: The trusted base ``resolve_config`` built.
        config_overrides: ``--config-overrides``; only the entries for this key are
            replayed.
        in_tree: The repository-written config files (or the MCP client's
            upload), named in the warning.
        reason: Why those files may not choose it, for the warning.
        documents: The chain's files' own documents, by resolved path. With
            them, the warning names only the files whose document sets the key,
            and none is issued when no file of the chain does: the value then
            came from the trusted base (the operator's file replacing
            ASH_CONFIG), not from a file that may not choose it. A file of
            *in_tree* with no document here stays named.
        chain: Every file of the selected chain, in chain order. The value is the
            operator's, and kept, when the last file that writes the key is one
            of these that is not in *in_tree*.
        remedy: How to keep the setting, ending the warning. ``KEEP_A_SETTING``,
            unless a file's walk stopped.
        environment_paths: The files of the chain an ``extends`` entry chose
            with a value read from the environment, which the warning names
            ``<value>`` as the other confinement warnings do: the path is the
            variable's value.

    Returns:
        None, or, when the operator's own file decided the value (the last file
        of the chain that writes the key is one that is not in *in_tree*), that
        file and the value the trusted base gives. The value then does not
        depend on the trusted base, so a trusted chain that was dropped whole
        changed it only if it wrote the opposite of the trusted base's value
        too, which is what the warning that names such a chain checks.
    """
    key_overrides = _honor_ignore_files_overrides(config_overrides)
    if key_overrides:
        trusted = apply_config_overrides(trusted, key_overrides)
    writers, decided_by = _honor_ignore_files_writers(in_tree, chain, documents)
    if decided_by is not None:
        return decided_by, trusted.honor_ignore_files
    if config.honor_ignore_files == trusted.honor_ignore_files:
        return None
    config.honor_ignore_files = trusted.honor_ignore_files
    if not writers:
        return None
    files = ", ".join(_owned_file_shown(path, environment_paths) for path in writers)
    ASH_LOGGER.warning(
        f"Ignoring honor_ignore_files from {files}: {reason}, and whether the "
        "scanned repository's own .gitignore and .ignore files are honored is the "
        "operator's choice. Using honor_ignore_files: "
        f"{str(trusted.honor_ignore_files).lower()}. {remedy} Or turn it "
        "off with --no-honor-ignore-files."
    )
    return None


def confine_to_trusted_base(
    config: AshConfig,
    trusted: AshConfig,
    operator_overrides: Sequence[str],
    scanned_root: Path,
    in_tree: Sequence[Path],
    source: Optional[UntrustedSource] = None,
    in_tree_documents: Sequence[Any] = (),
    also_scanned: Sequence[Path | str] = (),
) -> None:
    """Replace what a config that is not the operator's may not choose, in place.

    The steps run for a config built from a file inside the
    scanned tree or one an MCP client delivered, in order: the sandbox grants
    (``sandbox_grants``), ``ash_plugin_modules`` (``plugin_module_trust``), the
    reporters' destinations and whether the off-host reporters run
    (``reporter_trust``), the scanners' own config files, and every scanner's
    and converter's ``tool_version`` (``tool_config_trust``). Each takes the
    value from ``trusted`` with the
    operator's overrides replayed onto it, and names what it ignored in one
    warning. ``ash merge`` runs the same steps on the config a shard recorded,
    with its own ``source``, so a step added here applies to both.

    The sandbox and plugin-module steps take the membership wording flags their
    superset signatures demand; they are computed here from the fail-closed
    walk machinery (``confined_files``, ``in_a_checkout``) over *in_tree*
    against ``scanned_root``'s trees, so the warnings' location sentences
    follow the same rules the scan's own resolution speaks.

    Args:
        config: The config to confine.
        trusted: The trusted base: the defaults, or the operator's config, without
            ``operator_overrides``.
        operator_overrides: The overrides that are the operator's choice.
        scanned_root: The tree the plugin module check is made against.
        in_tree: The files ``config`` was built from that are not the operator's,
            named in the warnings.
        source: Why those files are not the operator's, and the fix, for the
            warnings. With none, a file on the line only because its name walk
            stopped before the end gets the reason and the remedy for that
            (``_tier_two_source``), as it does in the load. A source passed is
            used as it is, ``IN_TREE_OR_DELIVERED`` included.
        in_tree_documents: Those files' documents as they were parsed, so the
            reporter step's warning quotes a section as they spelled it where the
            merge kept another spelling (the operator's, in workspace mode).
        also_scanned: Other roots whose trees count as scanned for the plugin
            module step (``resolve_config``'s ``also_scanned``): a module
            location inside one of their trees is refused as one inside
            ``scanned_root``'s trees is. ``ash merge`` passes none today.
    """
    # Only an override under `sandbox` can change the sandbox section, and replaying
    # the rest onto the defaults could fail where the config file supplied the
    # section they write into.
    sandbox_overrides = [
        override
        for override in operator_overrides
        if override.partition("=")[0].removesuffix("+").split(".")[0] == "sandbox"
    ]
    # Read before the overrides are replayed: that rebuild does not carry the
    # network limit (a private attribute), and an override of the list replaces it.
    network_limit_kept = (
        None
        if any(_sets_network_scanners(override) for override in sandbox_overrides)
        else trusted.sandbox.network_limit
    )
    if sandbox_overrides:
        trusted = apply_config_overrides(trusted, sandbox_overrides)
    files = list(in_tree)
    trees = scanned_trees(Path(scanned_root))
    judged = confined_files(files, trees, named=files)
    members = set(judged.members)
    undecided_set = set(judged.undecided)
    undecided_files = [path for path in files if path in undecided_set]
    checkout_added = [
        path for path in files if path not in members and in_a_checkout(path)
    ]
    memberships = _wording_memberships(
        checkout_added=checkout_added,
        in_tree=files,
        rootless_wording=False,
        undecided_files=undecided_files,
    )
    # The same source the load gives its steps (resolve_config): a file whose walk
    # stopped is not said to sit in a checkout, and is not told to move out of one.
    # A source another caller passes (ash merge's) is its own and is kept, the
    # default's text included: only a missing source is derived.
    if source is None:
        source = _tier_two_source(
            checkout_membership=memberships.checkout,
            client_supplied=False,
            mixed=memberships.mixed,
            given_root=False,
            undecided=memberships.undecided,
            outside=memberships.outside,
        )
    confine_sandbox_grants(
        config.sandbox,
        trusted.sandbox,
        files,
        checkout_membership=memberships.checkout,
        mixed_membership=memberships.mixed,
        given_root_membership=False,
        undecided_membership=memberships.undecided,
        network_limit_kept=network_limit_kept,
        source=source,
    )
    confine_plugin_modules(
        config,
        trusted,
        operator_overrides,
        Path(scanned_root),
        files,
        checkout_membership=memberships.checkout,
        mixed_membership=memberships.mixed,
        given_root_membership=False,
        undecided_membership=memberships.undecided,
        source=source,
        also_scanned=[Path(extra) for extra in also_scanned],
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


def _operator_paths(
    chain: List[Path],
    names: List[Path],
    root_names: List[Path],
    scan_root: Optional[Path],
    document: Any,
    *,
    untrusted: bool,
    overrides: Optional[List[str]],
    reads: Optional[Dict[Path, Any]] = None,
    default_config: Optional[AshConfig] = None,
) -> OperatorPaths:
    """Which tool paths in the config the operator named; see path_trust.

    The chain's merged ``document`` (or, with no config file, the default
    config's: ``default_config``, the configuration the load carried out of
    its one read of the ASH_CONFIG chain, so this record describes the files
    that load read; without it the chain is resolved again here, a second
    read outside the load's confinement and caches that a file changed in
    between could skew) when every file of the chain is the operator's
    (:func:`_operator_wrote`, under every name); only the selected file's own
    writes when that file is the operator's and a base it extends is not; and
    what ``overrides`` set. With no ``scan_root`` there is nothing to judge the
    files against, so only the overrides are recorded, which fails closed.

    The own-writes arm takes the root's document from ``reads``, the load's
    cache of each file's one parse, and records the merged ``document``'s
    values at the keys the root wrote (``_own_writes``): the merged document
    holds each relative tool path anchored and each plugin section folded as
    the configuration holds them, where a raw re-read of the file held the
    path as written, which never equaled the anchored value a scanner passes,
    so an operator's relative tool path was judged repository-named.
    """
    record = OperatorPaths(overrides=parse_overrides(overrides))
    if untrusted or scan_root is None:
        return record
    if all(_operator_wrote(path, scan_root) for path in [*chain, *names]):
        if document is None:
            if default_config is not None:
                document = default_config.model_dump()
            else:
                document = get_default_config().model_dump()
        record.documents = [document]
    elif chain and all(
        _operator_wrote(path, scan_root) for path in [chain[-1], *root_names]
    ):
        # The selected root by the name it was given, so an overlay root at
        # the chain's end does not stand in for it.
        own_root = Path(root_names[0] if root_names else chain[-1]).resolve()
        own = (reads or {}).get(own_root)
        if own is None:
            try:
                own = read_config_file(own_root)
            except Exception:  # noqa: BLE001 - the chain was read already; nothing to add
                own = None
        if isinstance(own, dict):
            own = fold_known_plugin_sections(own)
            record.documents = [
                _own_writes(document, own) if isinstance(document, dict) else own
            ]
    return record


def _own_writes(merged: Any, written: Any) -> Any:
    """``merged``, a chain's merged document, restricted to what ``written``,
    one file's own document, wrote: the file's keys (spelled as the merged
    document spells them, config_sources._resolve_dict_key) with the merged
    document's values under them, so a value the file wrote is read as the
    configuration holds it (anchored, folded), and a key only a base wrote is
    left out. A key the merged document lacks keeps the file's own value."""
    if not isinstance(written, dict) or not isinstance(merged, dict):
        return merged
    own: Dict[Any, Any] = {}
    for key, value in written.items():
        target = _resolve_dict_key(merged, key) if isinstance(key, str) else key
        if target in merged:
            own[target] = _own_writes(merged[target], value)
        else:
            own[key] = value
    return own


def _operator_wrote(path: Path, scan_root: Path) -> bool:
    """Whether the tool paths config file ``path`` names are the operator's.

    By the tier ``repository_written`` gives config files, the one the
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


def _own_sandbox_settings(
    path: Path, documents: Optional[Mapping[Path, Any]] = None
) -> Dict[str, Any]:
    """The ``sandbox`` settings ``path`` writes itself, without its ``extends`` bases
    (``_own_sandbox_read`` says how they are read)."""
    return _own_sandbox_read(path, documents)[0]


def _own_sandbox_read(
    path: Path, documents: Optional[Mapping[Path, Any]] = None
) -> Tuple[Dict[str, Any], Dict[str, List[Any]]]:
    """The ``sandbox`` settings ``path`` writes itself, without its ``extends`` bases,
    and the lists its own ``patch`` limits the scan to where the file wrote none.

    The file's own section, so nothing a base gives it contributes, read in the
    terms the config loader reads the file in:

    - ``documents`` holds the documents of the chain load that read ``path``, by
      resolved path, and the section is taken from the one for ``path``: the
      settings of the read the chain was built from, not of a second read that a
      change to the file in between could skew. A mapping that lacks the file
      gives nothing, and a warning names the file (``_warn_missing_document``).
      With no ``documents`` the file is read here.
    - An unquoted ``mode: off`` is the mode ``"off"`` (``sandbox_mode_in_document``),
      so the section validates.
    - A relative ``extra_read_paths`` entry is taken from the file's directory
      (``anchor_relative_paths``), as the merged chain has it.
    - The mode the file's own ``patch`` operations leave (``_own_mode_after_patch``)
      is the mode the file ends with, as the merge applies them last.
    - A setting those operations remove or rewrite (``_own_grants_after_patch``) is
      not what the file ends with. A grant list they rewrite is cut down to the
      entries that both it and the list the operations leave name, so it still
      replaces the trusted base's list; one they remove is left out, and the base's
      list stands. A ``network_scanners`` list is cut down the same way, and is
      empty when they remove it. A setting in no class is left out, and when they
      rewrite the section or the document only the mode and those lists stay.
    - A list the operations write where the file wrote none (a null, or no key) is
      not the file's setting, because the values a patch writes are never adopted.
      Each such list is returned beside the section, by setting name, as the limit
      the patch puts on the scan. ``_with_own_sandbox`` holds it to the list in force
      for that setting (the trusted base's), so it can only narrow it: the entries
      the base's list and the patched list both name stay. This holds for
      ``network_scanners`` and for each additive list. The same patch is read the same
      way whether the file wrote a null or nothing.

    Both halves read the three operations that write, ``add``, ``replace`` and
    ``remove``. The loader refuses every other operation but ``test`` before a file's
    section is read (``_PATCH_OPS`` in config_sources.py), so there is no ``move`` or
    ``copy`` to read.

    The document is never changed: the caller's mapping is shared.
    """
    if documents is None:
        try:
            document = read_config_file(path)
        except Exception:  # noqa: BLE001 - the chain was read already; nothing to add
            return {}, {}
    else:
        document = documents.get(Path(path).resolve(), documents.get(Path(path)))
        if document is None:
            # Fail closed: no second read, which a change to the file in between
            # could skew. The file's settings are left out, so it is named.
            _warn_missing_document(path)
            return {}, {}
    if not isinstance(document, dict):
        return {}, {}
    written = document.get("sandbox")
    if written is not None and not isinstance(written, dict):
        return {}, {}
    # A copy, anchored; the mode below is changed in place.
    anchored = anchor_document_paths(
        {"sandbox": written if written is not None else {}},
        Path(path).resolve().parent,
    )
    try:
        sandbox_mode_in_document(anchored)
    except ValueError:
        # `mode: on` names no mode; the chain load refused the file already.
        return {}, {}
    own = anchored["sandbox"]
    operations = document.get(PATCH_KEY)
    _own_mode_after_patch(own, operations)
    return own, _own_grants_after_patch(own, operations)


def _own_mode_after_patch(own: Dict[str, Any], operations: Any) -> None:
    """Apply to ``own``, in order, the ``patch`` operations of a file that set or
    clear its sandbox mode.

    The operations the sandbox-mode floor reads (``_owned_sandbox_mode``), read
    by the helper they share (``_mode_after_patch``): ``add``, ``replace`` and
    ``remove`` at the whole document, at ``/sandbox`` and at ``/sandbox/mode``. A
    value that carries a mode sets it, as written; one that rewrites the document
    or the section without a mode clears it. The merge applies a file's ``patch``
    after the file, so the mode left here is the mode the file chose, whatever it
    wrote directly.

    Only the mode. An operation that adds a grant, a pointer under ``/sandbox``
    past or beside ``mode`` (``/sandbox/extra_read_paths/0``,
    ``/sandbox/network_scanners``) or a key other than ``mode`` in a value that
    rewrites the section, adds nothing to ``own``; a ``test`` sets nothing. An
    operation whose value is not a mapping where one is needed is dropped. The grants
    the file wrote directly are ``_own_grants_after_patch``'s.
    """
    written = own.get("mode")
    left = _mode_after_patch(written, operations)
    if left is written:
        return
    if left is None:
        own.pop("mode", None)
    else:
        own["mode"] = left


#: How a sandbox setting that the file's own ``patch`` touches is read depends on the
#: setting's class. Every ``SandboxConfig`` setting is in exactly one of the three
#: below (a test requires it), because a setting in no class is simply left out of
#: the file's own section: that gives the scan less access for a setting that adds
#: access, and more for one that restricts, whose place the trusted base's looser
#: value would take.
#:
#: ``network_scanners`` restricts: a list there limits which scanners get a network,
#: and leaving it out would leave the default, which allows each scanner its declared
#: network. The file keeps the scanners that both the list it wrote and the list its
#: patch leaves name.
_NARROWED_SANDBOX_SETTING = "network_scanners"

#: The one setting a rewrite of the section or the document leaves in the file's own
#: section whatever the rewrite names: ``_own_mode_after_patch`` has applied the
#: rewrite to the mode already.
_REWRITE_KEPT_SANDBOX_SETTING = "mode"

#: The lists that only add access (``environment`` is one: each entry passes or sets
#: a variable in every sandboxed scanner). A list the patch rewrites is kept to the entries
#: that both the list the file wrote and the list the patch leaves name, so it still
#: replaces the trusted base's list and the scan gets no path that neither names. One
#: the file wrote and the patch removes is left out, and the trusted base's list
#: stands. One the file did not write and the patch leaves no list in is limited to
#: the setting's own default (nothing for the three lists whose default is empty,
#: the proxy and CA names for ``environment``), unless the patch only inserts an
#: entry, which takes nothing from the trusted list (``_own_grants_after_patch``).
_ADDITIVE_SANDBOX_SETTINGS = frozenset(
    {"extra_read_paths", "read_path_scanners", "env_scanners", "environment"}
)

#: What a patch leaves of a list setting when it removes the setting itself.
_SETTING_REMOVED = object()


def _spelled_setting(key: Any) -> Any:
    """*key* spelled with underscores, the way the loader reads a pointer's keys."""
    return key.replace("-", "_") if isinstance(key, str) else key


def _patch_writes(operations: Any) -> Iterable[Tuple[str, List[str], Any]]:
    """The writes a file's own ``patch`` operations make, in order, as ``(kind,
    pointer steps, value)``.

    ``add``, ``replace`` and ``remove`` are the writes they name. The loader admits no
    other writing operation (``_PATCH_OPS`` in config_sources.py), a ``test`` writes
    nothing, and a pointer that is not one makes no write here.
    """
    for operation in operations if isinstance(operations, list) else ():
        if not isinstance(operation, dict):
            continue
        name = operation.get("op")
        if name not in ("add", "replace", "remove"):
            continue
        segments = _pointer_segments(operation.get("path"))
        if segments is not None:
            yield name, segments, operation.get("value")


def _sandbox_place(segments: List[str]) -> Tuple[str, Any]:
    """Where the pointer *segments* land relative to the ``sandbox`` section, and the
    setting they name.

    The place is ``document`` (the whole document), ``section`` (``/sandbox``),
    ``setting`` (``/sandbox/<setting>``), ``entry`` (``/sandbox/<setting>/<step>``),
    ``inside`` (deeper than that) or ``outside`` (anywhere else). The setting is
    spelled with underscores, and is None for a place that names none.
    """
    if not segments:
        return "document", None
    if segments[0] != "sandbox":
        return "outside", None
    if len(segments) == 1:
        return "section", None
    setting = _spelled_setting(segments[1])
    if len(segments) == 2:
        return "setting", setting
    return ("entry" if len(segments) == 3 else "inside"), setting


def _is_list_step(step: str) -> bool:
    """Whether the pointer step *step* names a place in a list: an index, or ``-``,
    the end."""
    return step == "-" or (step.isascii() and step.isdigit())


def _list_written_at(setting: str, place: str, value: Any) -> Any:
    """The list that *value*, written at *place*, gives the list *setting*.

    The list itself; ``_SETTING_REMOVED`` when *value* holds no such setting (a
    section or a document written without it); None when it holds something that is
    not one list (a value of another type, or the setting in two spellings).
    """
    steps = {
        "document": ("sandbox", setting),
        "section": (setting,),
        "setting": (),
    }[place]
    for step in steps:
        if not isinstance(value, dict):
            return None
        found = [item for key, item in value.items() if _spelled_setting(key) == step]
        if not found:
            return _SETTING_REMOVED
        if len(found) != 1:
            return None
        value = found[0]
    return list(value) if isinstance(value, list) else None


def _list_after_patch(setting: str, written: Any, operations: Any) -> Tuple[bool, Any]:
    """Whether the file's own ``patch`` *operations* touch the list *setting*, and the
    list they leave of what the file wrote (*written*).

    The operations apply to the written list in order, the way the merge applies
    them: a write at the whole document, at ``/sandbox`` or at ``/sandbox/<setting>``
    sets the list its value carries, or removes it; a write at a step under the list
    inserts, replaces or removes an entry. The list left is a list; or
    ``_SETTING_REMOVED`` when the patch removes the setting, or leaves the file with
    none; or None when a step names no entry or a value is not a list. Entries a patch
    adds stay in that list and so can only be kept when the file wrote them too.
    """
    patched: Any = list(written) if isinstance(written, list) else _SETTING_REMOVED
    touched = False
    for kind, segments, value in _patch_writes(operations):
        place, name = _sandbox_place(segments)
        if place == "outside" or (name is not None and name != setting):
            continue
        if place == "document" and kind == "remove":
            # A patch cannot remove the whole document.
            continue
        touched = True
        if place in ("document", "section", "setting"):
            patched = (
                _SETTING_REMOVED
                if kind == "remove"
                else _list_written_at(setting, place, value)
            )
        elif not isinstance(patched, list):
            continue
        elif place == "entry" and _is_list_step(segments[2]):
            if segments[2] == "-":
                index = len(patched)
            else:
                index = int(segments[2])
            if kind == "add" and index <= len(patched):
                patched.insert(index, value)
            elif kind == "replace" and index < len(patched):
                patched[index] = value
            elif kind == "remove" and index < len(patched):
                del patched[index]
            else:
                patched = None
        else:
            patched = None
    return touched, patched


class _EntryEditLimit(List[Any]):
    """An empty limit that records how it came about: the file's own ``patch``
    removes or replaces entries of a grant list the file does not write.

    It compares equal to ``[]`` and is used as one. It is a class of its own only so
    that ``_warn_grant_list_limit`` can say that the patch edits entries of a list
    the file does not write, which is not what the sentence for a limit by a list the
    patch names describes."""


def _writes_touching(setting: str, operations: Any) -> List[Tuple[str, str, List[str]]]:
    """The writes of *operations* that touch the list *setting*, as ``(kind, place,
    pointer steps)``, by the rule ``_list_after_patch`` applies."""
    touching = []
    for kind, segments, _value in _patch_writes(operations):
        place, name = _sandbox_place(segments)
        if place == "outside" or (name is not None and name != setting):
            continue
        if place == "document" and kind == "remove":
            # A patch cannot remove the whole document.
            continue
        touching.append((kind, place, segments))
    return touching


def _only_inserts_into(setting: str, operations: Any) -> bool:
    """Whether every write of *operations* that touches the list *setting* inserts an
    entry (``add`` at ``/-`` or at an index), and at least one does.

    An entry a patch writes is never adopted, so a patch that only inserts adds to
    the list in force and takes nothing from the trusted list."""
    touching = _writes_touching(setting, operations)
    return bool(touching) and all(
        kind == "add" and place == "entry" and _is_list_step(segments[2])
        for kind, place, segments in touching
    )


class _DefaultLimit(List[Any]):
    """The limit for a grant list whose model default is not empty, which the file
    does not write and its ``patch`` leaves without a list: the setting's own default.

    A missing list is the model's default, and for ``environment`` that is the proxy
    and CA-bundle names, not nothing. It is a class of its own so that
    ``_warn_grant_list_limit`` can say that no list is named and the default stands,
    which neither of its other sentences describes."""


def _setting_default(setting: str) -> List[Any]:
    """The list the model gives the grant list *setting* when a file writes none."""
    default = SandboxConfig.model_fields[setting].default
    return list(default) if isinstance(default, (list, tuple)) else []


def _no_grants_left_by(setting: str, operations: Any) -> List[Any]:
    """The limit for the grant list *setting*, which the file did not write and
    *operations* leave without a list: what the model gives a missing list. That is
    the empty list for the lists whose default is empty, an ``_EntryEditLimit`` when
    every write that touches the list edits an entry of it, and the setting's own
    default for a list with one (``_DefaultLimit``)."""
    default = _setting_default(setting)
    if default:
        return _DefaultLimit(default)
    touching = _writes_touching(setting, operations)
    if touching and all(place == "entry" for _kind, place, _steps in touching):
        return _EntryEditLimit()
    return []


def _own_grants_after_patch(
    own: Dict[str, Any], operations: Any
) -> Dict[str, List[Any]]:
    """Read in ``own`` what the file's own ``patch`` removes or rewrites, and return
    the lists the patch limits the scan to where the file wrote none, by setting.

    The merge applies a file's ``patch`` after the file, so a setting the file
    writes and then removes or rewrites is not what the operator ends with. The
    values a patch writes are never adopted (``_own_mode_after_patch`` reads the
    mode alone), so the scan is given less than the file wrote, never more. How a
    setting is read depends on its class (a test requires every ``SandboxConfig``
    setting to be in one):

    - the additive lists (``_ADDITIVE_SANDBOX_SETTINGS``) a patch rewrites are cut
      down to the entries that both the list the file wrote and the list the patch
      leaves name. The result still replaces the trusted base's list, so the scan is
      granted nothing that neither list names, even when the base grants a path of
      its own. A list the patch removes is left out, and the base's list stands;
    - ``network_scanners`` is cut down the same way, and is empty when the patch
      removes it or leaves none (``_NARROWED_SANDBOX_SETTING``);
    - a file that wrote a null or no key for one of those lists has no list to cut
      down, and a null the patch touches is no list of the file's, so it is left out.
      A list the patch writes there is returned instead, under the setting's name, as
      a limit for ``_with_own_sandbox`` to hold to the trusted base's list. A patch
      that leaves no list there returns nothing for ``network_scanners`` and the
      base's list stands, because a missing network list is the widest. For a grant
      list it returns the model's own default: a missing grant list is the empty one
      for ``extra_read_paths``, ``read_path_scanners`` and ``env_scanners``, the
      narrowest, so the operator's own config ends with no entry and the scan gets
      none of the base's; for ``environment`` it is the proxy and CA-bundle names,
      so the scan keeps the entries of the base's list that the default names and
      loses the others, never the proxies it was passed before the patch. A patch
      that only inserts an entry into such a list
      (``add`` at ``/-`` or at an index) returns nothing: the entry is never adopted,
      so it takes nothing from the base's list, and the base's list stands. When the
      limit is empty because the patch removes or replaces entries of the list, it
      is an ``_EntryEditLimit``, which is equal to ``[]``;
    - the mode is ``_own_mode_after_patch``'s;
    - a setting in no class is taken out when an operation writes, replaces or
      removes it or a step under it (``/sandbox/<setting>/0``), or rewrites the
      section or the document. An ``add`` of a step under a list the file wrote
      (``/-`` or an index) only inserts an entry, so the list stays, and an ``add``
      inside any other value changes what the file wrote, so that setting goes.

    A ``test`` and a pointer elsewhere change nothing here. An entry is kept when it
    is equal to an entry the patch leaves, so a path the patch spells differently
    from the file's (a relative one, which the file's section has made absolute) is
    not kept.
    """
    limits: Dict[str, List[Any]] = {}
    limited = (_NARROWED_SANDBOX_SETTING, *sorted(_ADDITIVE_SANDBOX_SETTINGS))
    wrote = {_spelled_setting(key) for key in own}
    for key in list(own):
        setting = _spelled_setting(key)
        if setting not in limited:
            continue
        written = own[key]
        touched, patched = _list_after_patch(setting, written, operations)
        if not touched:
            continue
        if not isinstance(written, list):
            # A null the patch then writes over: the file wrote no list. Left in
            # `own` it would take the trusted base's list's place as a non-list,
            # fail the section's validation, and cost the file its other settings.
            # A list the patch writes is a limit (below), as when the key is missing.
            del own[key]
            if isinstance(patched, list):
                limits[setting] = patched
            elif setting in _ADDITIVE_SANDBOX_SETTINGS and not _only_inserts_into(
                setting, operations
            ):
                limits[setting] = _no_grants_left_by(setting, operations)
        elif setting == _NARROWED_SANDBOX_SETTING:
            narrowed = isinstance(patched, list)
            own[key] = [name for name in written if name in patched] if narrowed else []
        elif patched is _SETTING_REMOVED:
            del own[key]
        elif isinstance(patched, list):
            own[key] = [name for name in written if name in patched]
        else:
            own[key] = []
    for setting in limited:
        if setting in wrote:
            continue
        touched, patched = _list_after_patch(setting, None, operations)
        if not touched:
            continue
        if isinstance(patched, list):
            limits[setting] = patched
        elif setting in _ADDITIVE_SANDBOX_SETTINGS and not _only_inserts_into(
            setting, operations
        ):
            # The patch touches a grant list the file did not write and leaves no
            # list there (it removes it, rewrites the section or the document
            # without it, removes or replaces an entry whose place is not known
            # here, or writes a value that is no list). The operator's own config
            # ends with the model's default list: the empty one, the narrowest, for
            # three of the lists, so the scan gets none of the trusted base's
            # entries, and the proxy and CA names for `environment`. A missing
            # network list is the
            # widest, and the base's list stands for it. A patch that only inserts
            # an entry is not among these: the entry is never adopted, so the
            # trusted list stands.
            limits[setting] = _no_grants_left_by(setting, operations)
    classed = (
        _REWRITE_KEPT_SANDBOX_SETTING,
        _NARROWED_SANDBOX_SETTING,
        *_ADDITIVE_SANDBOX_SETTINGS,
    )
    for kind, segments, _value in _patch_writes(operations):
        place, setting = _sandbox_place(segments)
        if place == "outside":
            continue
        if place in ("document", "section"):
            if place == "document" and kind == "remove":
                # A patch cannot remove the whole document.
                continue
            gone = [key for key in own if _spelled_setting(key) not in classed]
        elif setting in classed:
            continue
        else:
            held = [own[key] for key in own if _spelled_setting(key) == setting]
            if (
                place == "entry"
                and kind == "add"
                and held
                and all(isinstance(value, list) for value in held)
                and _is_list_step(segments[2])
            ):
                # An insert into the list the file wrote adds an entry that is
                # never adopted; the entries the file wrote stay.
                continue
            gone = [key for key in own if _spelled_setting(key) == setting]
        for key in gone:
            del own[key]
    return limits


def _pointer_segments(pointer: Any) -> Optional[List[str]]:
    """The unescaped steps of a JSON pointer ([] for the whole document), or None
    for anything that is not a pointer."""
    if pointer == "":
        return []
    if isinstance(pointer, str) and pointer.startswith("/"):
        return [
            part.replace("~1", "/").replace("~0", "~")
            for part in pointer[1:].split("/")
        ]
    return None


def _root_walk_stopped(root: Path, undecided_files: Iterable[Path]) -> bool:
    """Whether *root* is one of *undecided_files*: the names the walks of a load
    could not place (``confined_files``'s ``undecided``, and the answers of the
    any-checkout helpers that walk each chain file after it).

    A name is compared by where it resolves, so a link that reaches the root counts
    for it, and a base's name that stopped does not."""
    wanted = Path(root).resolve()
    return any(Path(each).resolve() == wanted for each in undecided_files)


def _warn_grant_list_limit(
    path: Path, setting: str, in_force: List[Any], limit: List[Any]
) -> None:
    """Name the operator's own file when its patch's *limit* for the grant list
    *setting* leaves entries of the list in force out, or names entries that list
    lacks. Once per file and setting.

    The limit keeps the entries of *in_force* that *limit* names, compared as
    spelled. The list in force holds absolute paths, so a patch that spells the same
    path relatively keeps nothing; the result is fail-closed and the scanner is left
    without a file it needs, with nothing in the log. The patch's relative paths are
    not made absolute here: which directory a relative entry means is the patch
    file's to say, the trusted list may come from another file, and a guess would
    keep a path the operator did not name. The warning says how to spell the entry.
    """
    left_out = [entry for entry in in_force if entry not in limit]
    # The setting's default names entries the trusted list may not hold; that is
    # not an entry the patch wrote, so it is not a foreign one.
    foreign = (
        []
        if isinstance(limit, _DefaultLimit)
        else [entry for entry in limit if entry not in in_force]
    )
    if not left_out and not foreign:
        return
    key = f"limit:{os.path.realpath(path)}:{setting}"
    with _DROPPED_OWN_SANDBOX_LOCK:
        if key in _DROPPED_OWN_SANDBOX_WARNED:
            return
        _DROPPED_OWN_SANDBOX_WARNED.add(key)
    # The file's name is data: a newline or a control character in it must not
    # start a line of its own, so each message is shown on one line here, once,
    # as the other warnings that quote a file's path are.
    if isinstance(limit, _DefaultLimit):
        ASH_LOGGER.warning(
            shown_on_one_line(
                f"The patch in '{describe_config_path(path)}' leaves no list for "
                f"{setting}, which the file does not write, so the file's own "
                f"config ends with the setting's default list and {len(left_out)} "
                f"of the trusted list's {_entries(len(in_force))} "
                f"{'is' if len(left_out) == 1 else 'are'} left out. To keep the "
                "trusted entries, write the list in the file or leave it out of "
                "the patch."
            ),
            extra=NO_MARKUP,
        )
        return
    if isinstance(limit, _EntryEditLimit):
        # No list is named, so "the entries it names" would not describe this.
        ASH_LOGGER.warning(
            shown_on_one_line(
                f"The patch in '{describe_config_path(path)}' edits entries of "
                f"{setting}, a list the file does not write, so none of the "
                f"trusted list's {_entries(len(in_force))} is kept. An entry a "
                "patch writes is never adopted. To keep the trusted entries, "
                "write the list in the file or leave it out of the patch."
            ),
            extra=NO_MARKUP,
        )
        return
    text = (
        f"The patch in '{describe_config_path(path)}' limits {setting} to the "
        "entries it names that the trusted list also holds, leaving out "
        f"{len(left_out)} of the trusted list's {_entries(len(in_force))}"
    )
    if foreign:
        many = len(foreign) > 1
        # A scanner is named, a path is spelled; the relative-path clause is
        # about paths only.
        if setting in _PATH_GRANT_SETTINGS:
            hint = (
                "To keep a trusted path, spell it exactly as the trusted list "
                "does; a relative path there is already absolute."
            )
        elif setting in _ENTRY_GRANT_SETTINGS:
            hint = "To keep a trusted entry, write it exactly as the trusted list does."
        else:
            hint = (
                "To keep a trusted scanner, name it exactly as the trusted list does."
            )
        text += (
            f"; {_entries(len(foreign))} it names {'are' if many else 'is'} not in "
            "the trusted list as spelled, and an entry a patch writes is never "
            f"adopted, so {'they add' if many else 'it adds'} nothing. {hint}"
        )
    else:
        text += "."
    ASH_LOGGER.warning(shown_on_one_line(text), extra=NO_MARKUP)


#: The grant lists whose entries are paths; the others hold scanner names, except
#: the entry grants below.
_PATH_GRANT_SETTINGS = frozenset({"extra_read_paths"})

#: The grant lists whose entries are neither paths nor scanner names: environment
#: variables, as ``NAME`` or ``NAME=value``.
_ENTRY_GRANT_SETTINGS = frozenset({"environment"})


def _entries(count: int) -> str:
    """*count* with its noun, in agreement: "1 entry", "2 entries"."""
    return f"{count} {'entry' if count == 1 else 'entries'}"


def _with_own_sandbox(
    trusted: AshConfig,
    path: Path,
    scan_root: Path,
    lexical: List[Path],
    trees: Iterable[Path],
    names: Optional[ChainNames],
    documents: Optional[Mapping[Path, Any]] = None,
    undecided: Optional[bool] = None,
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

    A file whose name walk did not finish grants nothing either. No link in a tree
    was found, but the walk stopped before it could say there is none, and
    ``confined_files`` judges such a name the repository's: an unfinished walk
    hands out no grant. The file is named in a warning that says the walk stopped
    (``_warn_dropped_own_sandbox``), as every root that is left out is. The load
    does not ask about a root that ``confine_sandbox_grants`` names already, the
    selected config's files, or the ASH_CONFIG file when no config is selected: that
    warning says the walk stopped and which settings the file loses. The file
    ASH_CONFIG names beside a selected config and the operator's trusted config are
    not among them.

    *undecided* is the load's answer about ``path``: whether the walk of its name
    over the scanned trees stopped before the end, as the load found it
    (``_root_walk_stopped``). The load walked the chain once, under all the names
    it was reached by, and every warning it gives rests on that walk, so this
    function does not repeat that walk over the scanned trees: a second walk, under
    the names ``lexical`` holds, could read the file differently, and a file the load
    found undecided would keep its grant when the second walk finished. A direct
    caller that has no load behind it passes nothing, and the file is judged here.
    The check for an unfinished walk at the top is another walk, over the checkouts:
    it looks at ``path`` and at every name in ``lexical`` on each call, and a name
    that found a checkout wins over one whose walk stopped.

    ``documents`` is what the chain load that read ``path`` kept of each file, by
    resolved path (``_own_sandbox_settings``): the file's own section is taken from
    that read, not from a second one. The one thing taken beyond the section is a
    list that the file's own patch writes where the file wrote none, a network list
    or a grant list (``_own_grants_after_patch``): it narrows the list in force,
    never widens it.

    Returns the settings and whether the file wrote its own ``mode``, directly or
    through its own ``patch``. A section that does not validate on its own (a mode
    outside the known set, say) adds nothing, so the file then keeps no grants, as
    before this rule. A file whose own section is dropped because it is not the
    operator's is named in a warning, once per process
    (``_warn_dropped_own_sandbox``).
    """
    trees = list(trees)
    # A file whose name walk did not finish grants nothing either. No checkout was
    # found for it, but the walk could not say there is none, and
    # checkout_judgment reads such a name as inside one, as every other check of
    # the load does. The file is named in the warning for an unfinished walk, as it
    # is when the load's own answer says so below. This is asked before
    # repository_written, which answers for an unfinished walk as well
    # (sandbox_grants.UNFINISHED_WALK_REASON): asked after it, the file would be
    # left out with no warning, as repository_written leaves out a file the walk
    # found in a checkout, which the confinement warning names. A name that found
    # a checkout wins over one whose walk stopped: the file is located, moving it
    # out of that checkout is the remedy, and the walk's warning (make the walk
    # able to finish) would send the operator the wrong way.
    judgments = [checkout_judgment(Path(each)) for each in (path, *lexical)]
    # A checkout could not be ruled out and none was found by the walk of one name,
    # and no other name found one. Each judgment is read by its fields: comparing
    # whole judgments stops matching, without an error, when the type gains a field,
    # and the file would then be dropped with no warning.
    if any(each.verdict and not each.decided for each in judgments) and not any(
        each.verdict and each.decided for each in judgments
    ):
        _warn_dropped_own_sandbox(path, trees, names, documents, undecided=True)
        return trusted, False
    if repository_written([path], scan_root, lexical):
        return trusted, False
    if _not_the_operators([path], trees, names):
        _warn_dropped_own_sandbox(path, trees, names, documents)
        return trusted, False
    if undecided is None:
        undecided = bool(confined_files([path], trees, [path, *lexical]).undecided)
    if undecided:
        _warn_dropped_own_sandbox(path, trees, names, documents, undecided=True)
        return trusted, False
    own, limits = _own_sandbox_read(path, documents)
    if not own and not limits:
        return trusted, False
    current = trusted.sandbox.model_dump()
    # deep_merge spells each key the way the trusted settings do, as merging the
    # chain did (`network-scanners` is `network_scanners`).
    merged = deep_merge(current, own)
    # The limits on grant lists, named once the section validates: a section that
    # does not adds nothing, and the trusted list stays in full.
    limited: List[Tuple[str, List[Any], List[Any]]] = []
    for setting, limit in limits.items():
        # The file wrote no list for the setting and its patch wrote one: a limit,
        # held to the list in force so far, so it only narrows. A network list
        # that is None names every scanner, so the patched list stands; an
        # additive list keeps the entries of the list in force that the patched
        # list names, and an entry the list in force lacks adds nothing.
        in_force = merged.get(setting)
        if setting == _NARROWED_SANDBOX_SETTING:
            merged[setting] = [
                name for name in limit if in_force is None or name in in_force
            ]
        else:
            merged[setting] = [entry for entry in in_force or () if entry in limit]
            limited.append((setting, list(in_force or ()), limit))
    try:
        sandbox = SandboxConfig.model_validate(merged, strict=True)
    except ValidationError:
        return trusted, False
    for setting, in_force_entries, limit in limited:
        _warn_grant_list_limit(path, setting, in_force_entries, limit)
    keys = dict.fromkeys(current)
    wrote_mode = any(_resolve_dict_key(keys, key) == "mode" for key in own)
    # The network limit is a private attribute, which the rebuild above does not
    # carry: the trusted settings' limit stays on the settings that replace them.
    sandbox.network_limit = trusted.sandbox.network_limit
    updated = trusted.model_copy()
    updated.sandbox = sandbox
    return updated, wrote_mode


#: The files ``_warn_dropped_own_sandbox`` already named in this process. One
#: request resolves the same config more than once (the MCP server's checks
#: before a scan, then the scan), and one file should produce one warning.
_DROPPED_OWN_SANDBOX_WARNED: Set[str] = set()
_DROPPED_OWN_SANDBOX_LOCK = threading.Lock()


#: The off-host reporter sections ``_warn_dropped_operator_reporters`` already
#: named in this process, by file and section: the same config is resolved more
#: than once in a request, and a workspace resolves it once per project.
_DROPPED_OPERATOR_REPORTERS_WARNED: Set[Tuple[str, str]] = set()


def reset_dropped_own_sandbox_warnings() -> None:
    """Forget which files were already named (tests)."""
    with _DROPPED_OWN_SANDBOX_LOCK:
        _DROPPED_OWN_SANDBOX_WARNED.clear()
        _DROPPED_OPERATOR_REPORTERS_WARNED.clear()


def _dropped_chain_reason(
    under_the_rule: Sequence[Path],
    operators_own: Sequence[Path],
    membership: str,
    environment_paths: Collection[Path],
) -> str:
    """Why a trusted chain was dropped, for a warning that names its files.

    *membership* is the sentence for the files that put the whole chain under
    the rule (``confinement_membership``): it is true of those and false of an
    operator's own file outside every checkout that extends them. With such a
    file among the ones the warning names, the sentence is said of the files
    under the rule alone and the operator's own files get a clause of their
    own; with none, or with no file left to say it of, it stands as it is."""
    if not operators_own or not under_the_rule:
        return membership
    extended = "it" if len(under_the_rule) == 1 else "them"
    return (
        f"for {described(under_the_rule, environment_paths)}, {membership}; "
        f"the chain of {described(operators_own, environment_paths)} that "
        f"extends {extended} is dropped with {extended}"
    )


def _operator_files_under_the_rule(
    operator: OperatorConfig,
    trees: List[Path],
    selected_chain: Sequence[Path],
    undecided_out: Optional[List[Path]] = None,
) -> List[Path]:
    """The files of the trusted config's chain that put the whole chain under
    the rule: inside the scanned tree, inside any other git checkout, or
    delivered by an MCP client. A file of *selected_chain* is left out, because
    the steps that already name the selected chain's files speak for it.

    With *undecided_out*, each file that is on the list only because resolving its
    name stopped before the walk finished (``confined_files``'s and
    ``_with_outside_files``'s undecided answers) is appended to it, so a warning
    can say the walk stopped instead of stating a location. The files are the
    same either way."""
    selected = {Path(path).resolve() for path in selected_chain}
    judged = confined_files(operator.chain, trees, operator.named)
    if undecided_out is not None:
        undecided_out.extend(judged.undecided)
    return [
        file
        for file in _with_outside_files(
            list(judged.members),
            operator.chain,
            operator.named,
            operator.names,
            undecided_out=undecided_out,
        )
        if Path(file).resolve() not in selected
    ]


def _dropped_chain_membership(
    files: Sequence[Path],
    undecided_files: Sequence[Path],
    *,
    given_root_membership: bool,
    rootless_wording: bool,
) -> Tuple[str, str]:
    """The sentence and the remedy a warning for a dropped trusted chain gives.

    *files* are the ones that put the chain under the rule and *undecided_files*
    the ones the load found only through a walk that stopped. With none of *files*
    among them this is the sentence for a file in another checkout or a delivered
    one and ``KEEP_A_SETTING``, as the warnings always gave. A file whose walk
    stopped is not known to be in a checkout, so the sentence says the walk stopped
    and the remedy is the one every other warning gives for such a file: to let
    the walk finish, beside a file that was located (``_tier_two_source``)."""
    stopped = {Path(file) for file in undecided_files}
    if not any(Path(file) in stopped for file in files):
        return (
            confinement_membership(
                checkout_membership=rootless_wording,
                given_root=given_root_membership,
                outside=True,
            ),
            KEEP_A_SETTING,
        )
    source = _tier_two_source(
        checkout_membership=rootless_wording,
        client_supplied=False,
        mixed=any(Path(file) not in stopped for file in files),
        given_root=given_root_membership,
        undecided=True,
        outside=True,
    )
    return source.reason, source.remedy


def _warn_dropped_honor_ignore_files(
    dropped: Optional[AshConfig],
    chain: Sequence[Path],
    blamed: Sequence[Path],
    reads: Mapping[Path, Any],
    in_force: AshConfig,
    selected_chain: Sequence[Path],
    environment_paths: Collection[Path],
    *,
    given_root_membership: bool,
    rootless_wording: bool,
    undecided_files: Sequence[Path] = (),
    decided_by_operator: Optional[Tuple[Path, bool]] = None,
) -> None:
    """Name the files whose ``honor_ignore_files`` the trusted base left out.

    *dropped* is the configuration a trusted chain built (the trusted config's,
    or the file ASH_CONFIG names) and *blamed* the files that put the whole
    chain under the rule, so ``trusted_base_config`` took the defaults instead
    of it. When that chain is not the selected one -- the project's own config
    replaces ASH_CONFIG's file, and a workspace's trusted config is never part
    of the project's -- nothing else says its value was left out: the selected
    chain's warning (``confine_honor_ignore_files``) names only that chain's
    files. One warning names each file of the dropped chain that writes the key,
    when the value it built differs from the one in force.

    *in_force* is the resolved configuration once ``confine_honor_ignore_files``
    has run, so its value is the one the scan uses: the trusted base's with the
    operator's own ``--config-overrides`` for the key replayed on it, or the value
    a file of the operator's own wrote last, which that step keeps.

    *undecided_files* are the files of *blamed* the load found only because
    resolving their name stopped before the walk finished: the warning then says
    so and gives the remedy for a file nobody could place
    (``_dropped_chain_membership``).

    *decided_by_operator* is what ``confine_honor_ignore_files`` returned when a
    file of the operator's own that wrote the key last decided the value: that
    file and the value the trusted base gives. The dropped chain then lost to the
    operator's file whatever it wrote, so it is reported only when its value
    differs from the trusted base's as well as from the one in force: a dropped
    chain that wrote the trusted base's value was left out in favor of nothing
    different. The warning names the operator's file as the source of the value in
    force, and not the remedy for the dropped chain, which would change nothing.
    """
    if dropped is None or not blamed:
        return
    if dropped.honor_ignore_files == in_force.honor_ignore_files:
        return
    if (
        decided_by_operator is not None
        and dropped.honor_ignore_files == decided_by_operator[1]
    ):
        return
    selected = {Path(path).resolve() for path in selected_chain}
    writers = [
        Path(file)
        for file in chain
        if Path(file).resolve() not in selected
        and Path(file).resolve() in reads
        and _writes_honor_ignore_files(reads[Path(file).resolve()])
    ]
    if not writers:
        return
    once = (os.path.realpath(writers[0]), "honor_ignore_files")
    with _DROPPED_OWN_SANDBOX_LOCK:
        if once in _DROPPED_OPERATOR_REPORTERS_WARNED:
            return
        _DROPPED_OPERATOR_REPORTERS_WARNED.add(once)
    membership, remedy = _dropped_chain_membership(
        blamed,
        undecided_files,
        given_root_membership=given_root_membership,
        rootless_wording=rootless_wording,
    )
    # One entry per file: a base can reach the list under its name and its
    # resolved path both.
    blamed_keys = {Path(file).resolve() for file in blamed}
    under_the_rule = list(
        {Path(file).resolve(): Path(file).resolve() for file in blamed}.values()
    )
    reason = _dropped_chain_reason(
        under_the_rule,
        [file for file in writers if Path(file).resolve() not in blamed_keys],
        membership,
        environment_paths,
    )
    ending = f"{remedy} Or turn it off with --no-honor-ignore-files."
    if decided_by_operator is not None:
        ending = (
            f"{described([decided_by_operator[0]], environment_paths)} is the "
            "operator's own file and writes honor_ignore_files, so it decides "
            "the value, and moving the dropped file out of a checkout would not "
            "change it."
        )
    ASH_LOGGER.warning(
        shown_on_one_line(
            f"Ignoring honor_ignore_files from {described(writers, environment_paths)}: "
            f"{reason}, and whether the scanned repository's own .gitignore "
            "and .ignore files are honored is the operator's choice. Using "
            f"honor_ignore_files: {str(in_force.honor_ignore_files).lower()}. "
            f"{ending}"
        ),
        extra=NO_MARKUP,
    )


def _warn_dropped_operator_reporters(
    operator: Optional[OperatorConfig],
    trees: List[Path],
    selected_chain: Sequence[Path],
    *,
    given_root_membership: bool,
    rootless_wording: bool,
) -> None:
    """Name the off-host reporter sections the trusted config writes when that
    config is not the operator's file for them.

    A trusted config (``trusted_config_path``) any file of whose chain sits
    inside the scanned tree, inside any other git checkout, or was delivered by
    an MCP client is not the trusted base (``trusted_base_config`` drops the
    whole chain, the operator's own files with it), so the sections the chain
    writes for the reporters that send findings off the host are never in the
    base. They are read from the chain's merged configuration and its files'
    documents, not only from the files that are not the operator's: a section
    in ``~/ash.yaml`` is lost too when that file extends a base in a checkout.
    The configuration being resolved is the project's, which never held them,
    so nothing else says they were dropped. One warning names each section, the
    files that put the chain under the rule and the files that write a dropped
    section, with the sentence and the remedy every confinement warning gives. *given_root_membership* and
    *rootless_wording* are the load's wording flags: with no scanned tree the
    sentence never claims one.

    A file of *selected_chain* is left to the voices that already name it (the
    reporter destinations step and ``reporter_section``).
    """
    if operator is None:
        return
    from automated_security_helper.config.ash_config import (
        plugin_key_lookup_names,
        reduced_plugin_name,
    )
    from automated_security_helper.config.reporter_trust import (
        REPORTER_ENABLED_DEFAULTS,
        written_reporter_keys,
    )

    undecided_files: List[Path] = []
    files = _operator_files_under_the_rule(
        operator, trees, selected_chain, undecided_out=undecided_files
    )
    if not files:
        return
    # The whole chain is dropped, so every section it writes is lost: those of
    # the files' documents, and what the merged configuration holds (a patch
    # can add a section no file writes).
    written = list(
        written_reporter_keys(
            operator.reads[Path(file).resolve()]
            for file in operator.chain
            if Path(file).resolve() in operator.reads
        )
    )
    segment = getattr(operator.config, "reporters", None)
    for key in (
        *getattr(segment, "model_fields_set", ()),
        *(getattr(segment, "model_extra", None) or {}),
    ):
        # A section a file wrote is named as the file spelled it; the merged
        # configuration adds only the ones no file's spelling covers.
        if isinstance(key, str) and not any(
            reduced_plugin_name(key) == reduced_plugin_name(seen) for seen in written
        ):
            written.append(key)

    def sends_off_host(key: str) -> bool:
        return any(
            reduced_plugin_name(reporter) in plugin_key_lookup_names(key)
            for reporter in REPORTER_ENABLED_DEFAULTS
        )

    sections = [key for key in written if sends_off_host(key)]
    if not sections:
        return
    # The files that put the chain under the rule and the files that write a
    # section it dropped, in chain order: a section the operator's own file
    # wrote is lost with the whole chain, and the warning says where it was.
    blamed = {Path(file).resolve() for file in files}
    named = [
        file
        for file in operator.chain
        if Path(file).resolve() in blamed
        or any(
            sends_off_host(key)
            for key in written_reporter_keys([operator.reads.get(Path(file).resolve())])
        )
    ]
    anchor = os.path.realpath(files[0])
    with _DROPPED_OWN_SANDBOX_LOCK:
        fresh = [
            key
            for key in sections
            if (anchor, key) not in _DROPPED_OPERATOR_REPORTERS_WARNED
        ]
        _DROPPED_OPERATOR_REPORTERS_WARNED.update((anchor, key) for key in fresh)
    if not fresh:
        return
    places = redacted_places(
        ", ".join(f"reporters.{key}" for key in fresh),
        [
            reference.value
            for reference in getattr(operator.config, "_environment_references", ())
            if getattr(reference, "key", False) and getattr(reference, "value", "")
        ],
    )
    membership, remedy = _dropped_chain_membership(
        files,
        undecided_files,
        given_root_membership=given_root_membership,
        rootless_wording=rootless_wording,
    )
    reason = _dropped_chain_reason(
        [file for file in named if Path(file).resolve() in blamed],
        [file for file in named if Path(file).resolve() not in blamed],
        membership,
        operator.environment_paths,
    )
    ASH_LOGGER.warning(
        shown_on_one_line(
            f"Ignoring {places} from {described(named, operator.environment_paths)}: "
            f"{reason}, and a reporter that sends findings off the host does "
            "so with this host's credentials, so only the operator turns it on and "
            f"chooses where it sends. {remedy}"
        ),
        extra=NO_MARKUP,
    )


def _warn_missing_document(path: Path) -> None:
    """Name ``path``, a file whose document the chain load did not keep, so
    ``_own_sandbox_settings`` has no section to give for it. Once per process,
    like ``_warn_dropped_own_sandbox``; never a value the file sets."""
    key = f"missing:{os.path.realpath(path)}"
    with _DROPPED_OWN_SANDBOX_LOCK:
        if key in _DROPPED_OWN_SANDBOX_WARNED:
            return
        _DROPPED_OWN_SANDBOX_WARNED.add(key)
    ASH_LOGGER.warning(
        f"Could not read the sandbox settings '{describe_config_path(path)}' "
        "writes: the config load did not keep that file's document, so it grants "
        "no sandbox access.",
        extra=NO_MARKUP,
    )


def _warn_dropped_own_sandbox(
    path: Path,
    trees: List[Path],
    names: Optional[ChainNames],
    documents: Optional[Mapping[Path, Any]] = None,
    *,
    undecided: bool = False,
) -> None:
    """Name ``path``, a root whose own ``sandbox`` section ``_with_own_sandbox``
    leaves out of the trusted settings: one of ``_not_the_operators``, or, with
    *undecided*, one whose name walk stopped before the end.

    Only when the file writes such a section, or its own ``patch`` writes a list
    where the file wrote none, which ``_with_own_sandbox`` would have applied as a
    limit (``_own_sandbox_read`` gives both halves); the warning names the file and
    why it is not the operator's (``_whose_file``), never a value it sets, since the
    file is a client's or the repository's. For an *undecided* file no tree was
    found, so ``_whose_file`` has no place to name and would say an MCP client
    delivered it: the warning says the walk stopped, and that making the walk able
    to finish is how to keep the settings. A file a tree does hold (``trees``, by
    its path or the names it was reached by) is named by that place, whatever else
    is true of the walk of one of its names, since that is the place to move it out
    of.
    """
    own, limits = _own_sandbox_read(path, documents)
    if not own and not limits:
        return
    key = os.path.realpath(path)
    with _DROPPED_OWN_SANDBOX_LOCK:
        if key in _DROPPED_OWN_SANDBOX_WARNED:
            return
        _DROPPED_OWN_SANDBOX_WARNED.add(key)
    if undecided and tree_holding(path, trees, names) is None:
        ASH_LOGGER.warning(
            f"Ignoring the sandbox settings '{describe_config_path(path)}' writes: "
            "whether it is the operator's file could not be decided (resolving its "
            "name stopped before the walk finished), which is read as the "
            "repository's, so it grants no sandbox access. To keep them, "
            f"{LET_THE_WALK_FINISH}, or pass the settings with --config-overrides.",
            extra=NO_MARKUP,
        )
        return
    reason, place = _whose_file(path, trees, names)
    ASH_LOGGER.warning(
        f"Ignoring the sandbox settings '{describe_config_path(path)}' writes: it "
        f"{reason}, so it is not the operator's file and grants no sandbox access. "
        f"To keep them, move the file outside {place}, or pass the settings with "
        "--config-overrides.",
        extra=NO_MARKUP,
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


def _load_overlay(
    overlay_config_path: Path | str,
    source_dir: Path | str | None,
    permit_base: Optional[Callable[[Path], bool]],
    refuse_env: RefuseEnv,
    anchor_paths: Optional[AnchorPaths] = None,
    reads: Optional[Dict[Path, Any]] = None,
    texts: Optional[Dict[Path, str]] = None,
) -> ResolvedConfigDocument:
    """The overlay file's merged document, read as the operator's config is.

    Refused rather than skipped when it is missing, cannot be read, or does not
    validate on its own: the caller asked for its fields to be final, and
    dropping the file would scan with the project's values for them instead.

    ``reads`` and ``texts`` are the run's caches (``load_config_file_for_run``):
    given both, the overlay's files are read through the same cached reader as
    the selected chain, so the record of what they read from the environment
    (``_record_overlay_reads``) is built from the text this load read, the
    chain walkers that rebuild the extends tree find the overlay's documents
    in the cache, and a base both chains extend is parsed once.
    """
    path = Path(overlay_config_path)
    # os.stat, not Path.is_file: before Python 3.14 is_file raises for an error
    # other than "not found" (a directory above that cannot be searched), a
    # raw PermissionError in place of this refusal (check_config_path does the
    # same). A NUL in the path is a ValueError, refused the same way.
    try:
        regular = stat.S_ISREG(os.stat(path).st_mode)
    except (OSError, ValueError):
        regular = False
    if not regular:
        raise ASHConfigSourceError(
            f"Config file '{describe_config_path(path)}' does not exist or is not "
            "a file."
        )
    # A client's file is refused without its text, by the parser's error type and
    # position, or the problem locations, and outside the handler, so the
    # error under it, which can quote it, is not the context either.
    client_file = _is_a_client_file(path)
    unquoted: Optional[str] = None
    try:
        document = resolve_config_document(
            path,
            confine_to=default_confinement_root(path, source_dir),
            permit_base=permit_base,
            refuse_env=refuse_env,
            anchor_relative_paths=anchor_paths,
            reader=(
                _cached_reader(reads, texts)
                if reads is not None and texts is not None
                else None
            ),
            texts=texts,
        )
    except ASHConfigValidationError:
        raise
    except (OSError, UnicodeDecodeError, yaml.YAMLError, ValueError) as e:
        # json.JSONDecodeError is a ValueError.
        if isinstance(e, OSError) or not client_file:
            raise ASHConfigSourceError(
                f"Config file '{describe_config_path(path)}' could not be read: {e}"
            ) from e
        unquoted = _unquoted_load_error(path, e)
    if unquoted is not None:
        raise ASHConfigSourceError(unquoted)
    validate_config_document(
        document, path, unquoted=CLIENT_FILE if client_file else None
    )
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
    # A base an extends entry chose with a value read from the environment is
    # named <value>, as every other message names such a file: its path is
    # the variable's value.
    hidden = set(overlay.environment_paths)
    for path in others:
        reason, place = _whose_file(path, trees, overlay.names)
        shown = (
            ENVIRONMENT_VALUE_SHOWN
            if path in hidden or Path(path).resolve() in hidden
            else f"'{describe_config_path(path)}'"
        )
        reasons.append(f"{shown} {reason}")
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


def check_operator_config(
    operator_config_path: Path | str,
    scanned_root: Path | str,
    permit_base: Optional[Callable[[Path], bool]] = None,
    remote_client: bool = False,
    session_id: Optional[str] = None,
) -> None:
    """Refuse an operator config that cannot be layered over a workspace's projects.

    The checks made of a workspace's overlay config: the file
    must exist, resolve and validate on its own, and every file of its chain must
    be the operator's (``_refuse_unless_the_operators``). Workspace resolution
    runs them once for the whole workspace, so a project with no config of its
    own, which uses the operator's file alone, is refused with the rest.

    ``session_id`` is the MCP call's session, as ``env_refused_for`` takes it:
    for a remote caller, of the profile files the server writes in the sessions'
    ``config/`` directories only that session's own are set aside from ``!ENV``.
    Each project's resolution judges the chain with it
    (``resolve_config``'s ``client_config_policy.session_id``); judged without
    it here, a non-default session's own bound profile that uses ``!ENV`` was
    refused at planning though every project's resolution accepted it.

    Raises:
        ASHConfigValidationError: The config cannot be used; exit 3 in workspace
            mode.
    """
    overlay = _load_overlay(
        operator_config_path,
        None,
        permit_base,
        env_refused_for(remote_client, session_id),
    )
    _refuse_unless_the_operators(overlay, scanned_root)


def operator_config_digest(operator_config_path: Path | str) -> str:
    """A digest of the bytes of every file ``operator_config_path`` is built from.

    Workspace resolution records it with the plan, and each project's scan
    compares it before layering the file again, so a file that changed between
    the plan and the scan (another call rewriting a session's profile, an edit)
    is refused rather than scanned with settings ``--dry-run`` did not report.
    """
    from automated_security_helper.config.config_sources import read_config_bytes

    path = Path(operator_config_path)
    document = resolve_config_document(path, confine_to=default_confinement_root(path))
    digest = hashlib.sha256()
    for member in document.chain:
        # The bounded, non-blocking reader the loaders use (the
        # ASH_CONFIG_MAX_FILE_BYTES bound, no FIFO wait): a plain read_bytes
        # read without either. A file name the file system encoding cannot
        # carry is encoded with its escapes, where "utf-8" alone raised.
        data = read_config_bytes(Path(member))
        digest.update(
            f"{Path(member).as_posix()}\0{len(data)}\0".encode(
                "utf-8", "surrogateescape"
            )
        )
        digest.update(data)
    return digest.hexdigest()
