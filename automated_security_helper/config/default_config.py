# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    FrozenSet,
    List,
    Optional,
    Tuple,
    Union,
)

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.utils.path_stat import StatProblem


def refuse_unless_ash_config_names_a_file(
    config_env_var: str, named: Union[os.stat_result, "StatProblem"]
) -> None:
    """Refuse ASH_CONFIG's value unless ``named``, the answer of the one stat
    the caller made of it (``utils.path_stat.stat_named_path``), is a regular
    file.

    The caller's own answer, never a second stat: one made here could answer
    differently from the caller's (a permission or mount change, a link
    replaced) and name a denied or looping path, or a directory, as missing.
    The scan's ``--config`` pre-check passes the stat it made when ASH_CONFIG
    gave ``--config`` its value, so its refusal is in ASH_CONFIG's words and
    names what its stat found. A symbolic link loop or a denied stat is not a
    missing file. Keys only: the errno's code and the path as the caller wrote
    it. An empty value is ASH_CONFIG unset, which names nothing to refuse.
    """
    from automated_security_helper.core.exceptions import (
        ASHConfigFileNotFoundError,
        ASHConfigSourceError,
        ASHConfigValidationError,
    )
    from automated_security_helper.utils.path_stat import (
        LOOP,
        UNREADABLE,
        StatProblem,
        is_regular_file,
    )

    if not config_env_var:
        return
    path = Path(config_env_var)
    refused: ASHConfigValidationError
    cause: Optional[OSError] = None
    if not config_env_var.strip():
        refused = ASHConfigSourceError(
            "ASH_CONFIG is set to only whitespace. Unset it, or set it to the path "
            "of a config file."
        )
    elif isinstance(named, StatProblem):
        if named.kind == LOOP:
            refused = ASHConfigSourceError(
                f"ASH_CONFIG names {config_env_var}, which is a symbolic "
                "link loop. Point ASH_CONFIG at an existing config file, "
                "or unset it to use ASH's built-in defaults."
            )
            cause = named.cause()
        elif named.kind == UNREADABLE:
            refused = ASHConfigSourceError(
                f"ASH_CONFIG names {config_env_var}, which cannot be read "
                f"({named.code}). Point ASH_CONFIG at an existing config file, "
                "or unset it to use ASH's built-in defaults."
            )
            cause = named.cause()
        else:
            refused = ASHConfigFileNotFoundError(
                f"ASH_CONFIG names {config_env_var}, which does not exist. Point "
                "ASH_CONFIG at an existing config file, or unset it to use ASH's "
                "built-in defaults."
            )
    elif not is_regular_file(named):
        # A directory or a FIFO: opening it raised IsADirectoryError, which a
        # scan reported as an unexpected error and exit 1.
        from automated_security_helper.config.config_sources import (
            describe_config_path,
        )

        refused = ASHConfigValidationError(
            f"Configuration validation failed for "
            f"'{describe_config_path(path)}': ASH_CONFIG names it, and it "
            "is not a file"
        )
    else:
        return
    refused.ash_config_file = path
    if cause is not None:
        raise refused from cause
    raise refused


def _ash_config_file() -> Optional[Path]:
    """The file ASH_CONFIG names, or None when the variable is unset or empty.

    A named file that does not exist is refused rather than treated as unset:
    the operator chose a config, and scanning with the built-in one instead
    would drop its suppressions and settings while reporting success. An empty
    value counts as unset, as click treats an empty ``--config`` environment
    variable, so a CI template that passes an empty input keeps working.
    """
    from automated_security_helper.utils.path_stat import stat_named_path

    config_env_var = os.environ.get("ASH_CONFIG", None)
    if not config_env_var:
        return None
    # One stat, classified by its own error (utils/path_stat.py): not exists(),
    # which before 3.14 raises the stat's PermissionError for a path under an
    # unsearchable directory, and not a later is_file(), a second stat, which
    # could answer differently from the first: refuse a file the first found as
    # "not a file", or raise the second stat's PermissionError.
    refuse_unless_ash_config_names_a_file(
        config_env_var, stat_named_path(config_env_var)
    )
    return Path(config_env_var)


def _load_as_the_ash_config_files(
    named: Path, config_env_var: str, load: Callable[[], Any]
) -> Any:
    """Run *load*, mapping its errors to the ASH_CONFIG file's own refusal:
    one shape for every reader of the file the variable names, so the
    user-facing text cannot drift between them.

    An ASHConfigValidationError is tagged with the file and re-raised. A file
    that cannot be read is wrapped as "could not read ...", with the OSError's
    own copy of the name left out (an OSError's text quotes nothing the file
    holds) and raised from the OSError, so the MCP answer's category says the
    file could not be read. A parse error is replaced by its reason alone,
    raised after the handler has ended so the parser's error is not its
    context (a chain walker reads ``__context__``, ignoring
    ``__suppress_context__`` on purpose, and the parser's words can quote the
    file): the reason already says the file could not be parsed, so a
    "Configuration validation failed:" prefix would read double, and nothing
    was validated. An excluded ValueError (pydantic's ValidationError) is not
    a parse and re-raises.

    A function taking the load, not a context manager: an exception raised
    from a context manager's ``__exit__`` gets the with-body's exception as
    its context whatever the manager does first, so only a call can keep the
    raise outside the handler.
    """
    import yaml

    from automated_security_helper.config.config_sources import (
        describe_config_path,
        is_config_parse_error,
        unparsed_config_reason,
    )
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.utils.error_text import (
        os_error_without_named_file,
    )

    unparsed: Optional[str] = None
    try:
        return load()
    except ASHConfigValidationError as e:
        e.ash_config_file = named
        raise
    except OSError as e:
        # The file could not be read, so there is no syntax to send a reader
        # to; raised from the OSError, unlike the parse arm below.
        refused = ASHConfigValidationError(
            f"could not read {describe_config_path(named)}: "
            f"{os_error_without_named_file(e, config_env_var)}"
        )
        refused.ash_config_file = named
        raise refused from e
    except (yaml.YAMLError, ValueError) as e:
        # json.JSONDecodeError, UnicodeDecodeError and a constructor's
        # ValueError (!!int, !!float) are all ValueErrors, and the parser's
        # or constructor's own words can quote the file
        # (unparsed_config_reason). An excluded ValueError is not a parse.
        if not is_config_parse_error(e):
            raise
        unparsed = unparsed_config_reason(named, e)
    if unparsed is None:
        # Reached only through the parse arm above; a future arm that falls
        # through without binding fails here, not by returning to a caller
        # that would go on to use the defaults.
        raise AssertionError("the load neither returned nor raised")
    # Outside the handler, so the parser's error is not its context.
    refused = ASHConfigValidationError(unparsed)
    refused.ash_config_file = named
    raise refused


def get_default_config(
    confine: Optional[Callable[[Path, Path, Any], Any]] = None,
    views: "Optional[List[Tuple[List[Path], List[Path], FrozenSet[Path]]]]" = None,
    repository_file: Optional[Callable[[Path, Path], bool]] = None,
    reads: Optional[Dict[Path, Any]] = None,
    texts: Optional[Dict[Path, str]] = None,
):
    """The configuration a scan starts from: the file ASH_CONFIG names, or the defaults.

    A file ASH_CONFIG names that does not parse is refused like one the model
    refuses (ASHConfigValidationError, so a scan exits 3). The YAML or JSON
    error escaped instead, and resolve_config, which falls back to this
    function on an unexpected error, called it again and exited 1 with
    "Unexpected error in resolve_config". So is a name that does not exist, or
    that is only whitespace (_ash_config_file): every run fell back to the
    defaults without saying so.

    ``confine`` is handed to the file's load (``load_config_file``): a caller
    that reads the chain as a scan reads it passes
    ``operator_only_options.scan_repository_settings(...).confine``, so what a
    file of the chain inside the tree, or inside any other checkout, writes for
    an operator-only option is left out as that file is read, and recorded,
    before the model validates the document.
    ``repository_file`` is the same settings' ``is_repository_file``, handed
    beside it (resolve_config_document): an operator file's patch pointers
    then fold only onto section keys the operator's own files wrote.

    ``views``, when given, receives one ``(chain, named, environment_paths)``
    tuple from the SAME read when the ASH_CONFIG file is loaded -- the carry
    that lets a caller judge the chain's files without resolving the chain a
    second time, which a file changed in between could skew. Nothing is
    appended when the defaults are returned with no ASH_CONFIG file.
    ``reads`` and ``texts`` are the caller's caches of files already read,
    keyed by resolved path (load_config_file_for_run): a caller that walks
    the chain's own documents afterwards -- the operator reporter view when
    no config file is selected -- hands them in, so the walk reads the
    documents this load read.
    """

    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
    from automated_security_helper.utils.terminal_text import shown_on_one_line

    try:
        named_file = _ash_config_file()
    except ASHConfigValidationError as e:
        e.ash_config_file = Path(os.environ["ASH_CONFIG"])
        raise
    config_env_var = os.environ.get("ASH_CONFIG", None)
    if named_file is not None and config_env_var:
        named = named_file
        from automated_security_helper.config.operator_paths import (
            not_delivered_by_a_client,
        )

        # The variable's value is the caller's text: one line, not read as
        # markup.
        ASH_LOGGER.info(
            shown_on_one_line(
                f"Using ASH config path found in ASH_CONFIG variable: {config_env_var}"
            ),
            extra=NO_MARKUP,
        )

        def load():
            # AshConfig.from_file, with the values and keys the file's chain
            # read from the environment kept on the config, for the run's
            # lines built from it (a loaded plugin's option refusal): this is
            # the configuration a run uses when nothing else names one, the
            # MCP server's for a directory with none.
            document, config = load_config_file_for_run(
                Path(config_env_var),
                reads=reads,
                texts=texts,
                confine=confine,
                repository_file=repository_file,
                # The operator's file: its relative paths are taken from its
                # directory.
                anchor_relative_paths=not_delivered_by_a_client,
            )
            if views is not None:
                views.append(
                    (
                        list(document.chain),
                        [Path(config_env_var), *document.named],
                        document.environment_paths,
                    )
                )
            return config

        return _load_as_the_ash_config_files(named, config_env_var, load)

    return AshConfig()


def default_config_document():
    """The resolution of the file ASH_CONFIG names, with its extends bases, or None.

    A ``config_sources.ResolvedConfigDocument``: the files get_default_config()
    reads, each file's document, and the paths each was reached by. Read with
    ``resolve_config.read_config_document``, so a file that cannot be read or
    parsed is refused as that file (``ASHConfigSourceError``), and one an MCP
    client delivered without quoting it.

    The variable is classified as ``get_default_config`` classifies it
    (``_ash_config_file``): a value that names no file is refused with the same
    ``ASHConfigValidationError``, never answered with None. Classified with
    ``Path.exists`` instead, a path under an unsearchable directory raised the
    stat's PermissionError on Python 3.10 to 3.13, a symlink loop or a
    whitespace value answered None, and a file absent at this read answered
    None while ``get_default_config``, called next by ``trusted_default_config``,
    loaded the file that had appeared in between as the trusted config with no
    client-delivered check of its chain.
    """
    from automated_security_helper.config.resolve_config import read_config_document
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    try:
        named = _ash_config_file()
    except ASHConfigValidationError as e:
        e.ash_config_file = Path(os.environ["ASH_CONFIG"])
        raise
    if named is None:
        return None
    return read_config_document(named)


def default_config_names() -> List[Path]:
    """default_config_chain()'s files by the paths that named them; see
    ``ResolvedConfigDocument.named``."""
    document = default_config_document()
    return list(document.named) if document is not None else []


def default_config_chain() -> List[Path]:
    """The files get_default_config() reads: ASH_CONFIG and its extends bases, or none."""
    from automated_security_helper.config.resolve_config import read_config_document

    path = _ash_config_file()
    if path is None:
        return []
    return list(read_config_document(path).chain)


def default_config_documents() -> Dict[Path, Any]:
    """Each file of default_config_chain() with its parsed document, or none."""
    document = default_config_document()
    return dict(document.documents) if document is not None else {}


def default_config_for_tree(scan_root: Optional[Path] = None) -> "AshConfig":
    """get_default_config() loaded as a scan rooted at *scan_root* loads it;
    rooted at the working directory when None (one deleted while the process
    runs is no tree, ``sandbox_grants.working_directory``).

    What a file of ASH_CONFIG's chain inside that tree, or inside any other
    checkout, writes for an option only the operator sets is left out before
    the model validates it
    (``operator_only_options.scan_repository_settings``), so a value the option
    refuses, which such a scan ignores, does not make the configuration
    unloadable for this caller while the scan itself runs. For the callers
    with no selected config file that still read the operator's default
    configuration next to a repository: the exit-code record repair, the
    scanner inventory, the statistics fallback, and the MCP server's
    defaults, each rooted at the tree it describes.

    The settle-and-warn half of the confinement is ``resolve_config``'s:
    this load only tolerates what that path tolerates, it does not warn.
    """
    from automated_security_helper.config.operator_only_options import (
        repository_settings_for_root,
    )
    from automated_security_helper.config.sandbox_grants import working_directory

    # A root of None (the working directory deleted while the process runs)
    # confines fail-closed: every checkout file's operator-only options are
    # left out, never applied (repository_settings_for_root).
    root = working_directory() if scan_root is None else Path(scan_root)
    settings = repository_settings_for_root(root)
    return get_default_config(
        settings.confine, repository_file=settings.is_repository_file
    )


def default_config_document_for_tree(scan_root: Optional[Path] = None) -> Any:
    """The resolved document of the file ASH_CONFIG names, read as
    :func:`default_config_for_tree` reads it (the same confinement, the same
    operator-only settling for files inside *scan_root*'s tree), but not
    validated against the model; None when ASH_CONFIG names no file.

    A value :func:`_ash_config_file` refuses, a file that cannot be read and
    a file that does not parse are refused with an
    ``ASHConfigValidationError`` naming the file
    (:func:`_load_as_the_ash_config_files`), as ``get_default_config``
    refuses them. The variable is the one source of the file's name: a
    parameter that carried the name beside it would let the display name
    and the text the error trims disagree.
    """
    from automated_security_helper.config.operator_only_options import (
        repository_settings_for_root,
    )
    from automated_security_helper.config.operator_paths import (
        not_delivered_by_a_client,
    )
    from automated_security_helper.config.resolve_config import resolve_config_source
    from automated_security_helper.config.sandbox_grants import working_directory
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    try:
        named = _ash_config_file()
    except ASHConfigValidationError as e:
        e.ash_config_file = Path(os.environ["ASH_CONFIG"])
        raise
    if named is None:
        return None
    config_env_var = os.environ["ASH_CONFIG"]
    root = working_directory() if scan_root is None else Path(scan_root)
    settings = repository_settings_for_root(root)
    return _load_as_the_ash_config_files(
        named,
        config_env_var,
        lambda: resolve_config_source(
            named,
            confine=settings.confine,
            repository_file=settings.is_repository_file,
            # As get_default_config reads the file: the operator's relative
            # paths are taken from its directory.
            anchor_relative_paths=not_delivered_by_a_client,
        ),
    )
