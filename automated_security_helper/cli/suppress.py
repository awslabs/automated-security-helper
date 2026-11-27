# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash suppress``: write symbol suppressions and keep ``.ash.lock`` current.

``ash suppress add`` writes a symbol-scoped suppression into a config file and
the syntax-tree digests of the file it covers into ``.ash.lock`` in one
operation. It is the supported way to create the lock entry a symbol
suppression needs (``utils/ash_lock.py`` says why). ``ash suppress refresh``
records a new review of files whose code changed, ``ash suppress verify`` exits
non-zero when the lock is out of date, for CI, and ``ash suppress migrate``
converts version 1 entries whose files are unchanged.
"""

import shlex
from pathlib import Path
from typing import Annotated, Any, Dict, List, NoReturn, Optional

import typer
import yaml

from automated_security_helper.core.enums import InvalidationScope
from automated_security_helper.utils.ash_lock import (
    LEGACY_LOCK_RELATIVE_PATH,
    LOCK_RELATIVE_PATH,
    MAX_LOCKED_FILE_BYTES,
    MIGRATE_COMMAND,
    REFRESH_COMMAND,
    AshLock,
    AshLockError,
    LockScope,
    add_command_for,
    file_is_gone,
    recorded_scope,
    resolved_lock_key,
    scope_is_recorded,
)
from automated_security_helper.utils.console import echo
from automated_security_helper.utils.log import show_debug_locals
from automated_security_helper.utils.symbol_spans import SYMBOL_PATTERN, is_valid_symbol
from automated_security_helper.utils.terminal_text import shown_on_one_line

suppress_app = typer.Typer(
    name="suppress",
    help=(
        "Create symbol suppressions and keep the syntax-tree lock that binds "
        f"them to reviewed code ({LOCK_RELATIVE_PATH}) current."
    ),
    no_args_is_help=True,
    pretty_exceptions_enable=True,
    pretty_exceptions_short=True,
    # Not on a CI runner: locals can hold secrets (utils/log.py).
    pretty_exceptions_show_locals=show_debug_locals(),
)

_SOURCE_DIR_HELP = (
    "The directory the scan covers, which holds .ash.lock. Defaults to the "
    "current directory."
)

#: Why a file that exists cannot be checked (``ash_lock.locked_file_bytes``).
_UNHASHABLE = (
    "unreadable, not a regular file, larger than "
    f"{MAX_LOCKED_FILE_BYTES // (1024 * 1024)} MiB, or a link that leads out of "
    "the source directory"
)

#: The config key ``add`` reads for the kind of a new scope.
_CONFIG_KIND_KEY = "suppression_invalidation_scope"


def _fail(message: str, code: int = 1) -> NoReturn:
    echo(shown_on_one_line(f"Error: {message}"), err=True)
    raise typer.Exit(code)


def _root(source_dir: Optional[str]) -> Path:
    root = Path(source_dir) if source_dir else Path.cwd()
    if not root.is_dir():
        _fail(f"source directory {root.as_posix()} is not a directory", 5)
    return root.resolve()


def _load_lock(root: Path) -> AshLock:
    try:
        return AshLock.load(root)
    except AshLockError as e:
        _fail(str(e))


def _note_legacy(lock: AshLock) -> None:
    """After a save: the lock now lives at ``.ash.lock``; say what to do with the
    legacy file it was read from, which is left in place."""
    if lock.from_legacy:
        echo(
            shown_on_one_line(
                f"The lock was read from the deprecated {LEGACY_LOCK_RELATIVE_PATH} "
                f"and written to {LOCK_RELATIVE_PATH}. Remove the old file with "
                f"`git rm {LEGACY_LOCK_RELATIVE_PATH}`."
            )
        )


def _key_for(root: Path, path: str) -> str:
    """The lock key of ``path``: ``resolved_lock_key``, the file's own path
    with links followed, relative to the source directory.

    The key the scan's resolver looks up (``SymbolResolver._scope_is_current``)
    and the one the config check and ``verify`` look up: with ``link -> src``,
    an entry written under ``link/app.py`` would never be read by a scan looking
    up ``src/app.py``, and the suppression would sit inert with ``add`` and
    ``verify`` both green. A path is first resolved against the source
    directory, a relative one joined to it, as the scan's resolver resolves a
    finding's path before it builds its key, so one that leaves the directory
    is refused there.
    """
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        path = candidate.resolve().relative_to(root).as_posix()
    except (OSError, RuntimeError, ValueError):
        _fail(f"{path} is not inside the source directory {root.as_posix()}")
    key = resolved_lock_key(root, path)
    if key is None:
        _fail(f"{path} is not a path inside the source directory")
    return key


def _global_settings_in(config_path: Path) -> Dict[str, Any]:
    """The raw ``global_settings`` mapping of one YAML config.

    Read as the config's own loader reads it, aliases refused; a ``!ENV``
    reference is kept as written, nothing is read from the environment.
    """
    from automated_security_helper.config.ash_config import load_yaml_config

    try:
        document = load_yaml_config(config_path.read_text(encoding="utf-8"), env="keep")
    except (OSError, ValueError, yaml.YAMLError) as e:
        _fail(f"{config_path.as_posix()} cannot be read as YAML: {type(e).__name__}")
    if not isinstance(document, dict):
        return {}
    settings = document.get("global_settings")
    return settings if isinstance(settings, dict) else {}


def _suppressions_in(config_path: Path) -> List[Dict[str, Any]]:
    """The raw ``global_settings.suppressions`` entries one YAML config lists."""
    entries = _global_settings_in(config_path).get("suppressions")
    return [e for e in entries or [] if isinstance(e, dict)]


def _configured_kind(config_path: Path) -> Optional[str]:
    """``global_settings.suppression_invalidation_scope`` of the config ``add``
    writes to, or None when it does not set one.

    Read from that one file, as ``verify`` reads it: an ``extends`` base is not
    read. Only ``add`` reads it, for a scope it records; the lock alone decides
    at scan time, so a config edit cannot widen a reviewed binding.
    """
    settings = _global_settings_in(config_path)
    if _CONFIG_KIND_KEY not in settings:
        return None
    value = settings[_CONFIG_KIND_KEY]
    allowed = [kind.value for kind in InvalidationScope]
    if not isinstance(value, str) or value not in allowed:
        _fail(
            f"global_settings.{_CONFIG_KIND_KEY} in {config_path.as_posix()} is "
            f"not one of {', '.join(allowed)}"
        )
    return value


def _config_file(config: Optional[str], root: Path) -> Path:
    from automated_security_helper.config.resolve_config import find_config_file

    if config is not None:
        if not config.strip():
            _fail("--config is blank")
        path = Path(config)
        if not path.is_absolute():
            path = root / path
    else:
        found = find_config_file(root)
        if found is None:
            _fail(
                f"no ASH config file found in {root.as_posix()}; name one with "
                "--config",
            )
        path = Path(found)
    if not path.is_file():
        _fail(f"config file {path.as_posix()} does not exist")
    return path


def _invalidation_scope_option(help_text: str) -> Any:
    return typer.Option(
        "--invalidation-scope",
        case_sensitive=False,
        help=help_text,
    )


@suppress_app.command(name="add")
def add(
    rule_id: Annotated[
        str, typer.Argument(help="The rule id the suppression covers, e.g. B602.")
    ],
    symbol: Annotated[
        str,
        typer.Option(
            "--symbol",
            help="The definition the suppression covers, as a dotted qualified "
            "name such as 'MyClass.my_method'.",
        ),
    ],
    file: Annotated[
        str,
        typer.Option(
            "--file",
            help="The file that holds the definition, relative to the source "
            "directory. Its syntax-tree digests are recorded in the lock.",
        ),
    ],
    reason: Annotated[
        str, typer.Option("--reason", help="Why the finding is safe to suppress.")
    ],
    config: Annotated[
        Optional[str],
        typer.Option(
            "--config",
            "-c",
            help="The YAML config file to write the suppression to. Defaults to "
            "the config a scan of the source directory uses.",
        ),
    ] = None,
    source_dir: Annotated[
        Optional[str],
        typer.Option("--source-dir", help=_SOURCE_DIR_HELP),
    ] = None,
    invalidation_scope: Annotated[
        Optional[InvalidationScope],
        _invalidation_scope_option(
            "What makes the suppression stop applying until it is reviewed "
            "again: 'file', a change to the code of the file, or 'symbol', a "
            "change to the code of the definition itself. Defaults to the "
            "config's global_settings.suppression_invalidation_scope, else "
            "'file'. A suppression already recorded keeps its kind; change it "
            "with `ash suppress refresh --invalidation-scope`."
        ),
    ] = None,
):
    """Add a symbol suppression and lock its file's syntax tree.

    Writes the suppression into the config and digests of the file's
    tree-sitter parse into .ash.lock. While the code is unchanged the
    suppression applies; after a change, in the file or only in the symbol as
    the invalidation scope says, its findings are reported again until the
    change is reviewed and `ash suppress refresh` records it. Changes to
    spaces, tabs and line breaks between tokens do not count; comments, string
    literals and every other token do.

    A suppression already in the config for the same rule, file and symbol is
    not written twice; the lock entry is still created or completed, which is
    how an existing suppression is brought under the lock.

    Needs the optional 'symbols' extra, which parses the file.

    Example:
        ash suppress add B602 --symbol Handler.run --file src/app.py \\
            --reason "The command is a constant." --invalidation-scope symbol
    """
    # Stored stripped: rule ids match case-insensitively, so the duplicate
    # check below must not read ``b602`` and ``B602`` as two entries.
    rule_id = rule_id.strip()
    if not rule_id:
        _fail("the rule id is blank")
    if not reason.strip():
        _fail("--reason is blank; say why the finding is safe to suppress")
    if not is_valid_symbol(symbol):
        _fail(
            "--symbol must be a dotted qualified name such as 'MyClass.my_method' "
            f"(identifiers joined by '.'); got a value that is not one of "
            f"{SYMBOL_PATTERN.pattern!r}"
        )
    root = _root(source_dir)
    key = _key_for(root, file)
    if not (root / key).is_file():
        _fail(f"{key} is not a file in {root.as_posix()}")
    config_path = _config_file(config, root)
    if config_path.suffix.lower() not in (".yaml", ".yml"):
        _fail(
            f"{config_path.as_posix()} is not a YAML file; add the suppression "
            "to it by hand, then run "
            f"`{add_command_for(rule_id, symbol, key)}` against a YAML config to "
            "record the lock entry"
        )

    lock = _load_lock(root)
    existing = lock.entries.get(key)
    recorded = (
        recorded_scope(existing, rule_id, symbol) if existing is not None else None
    )
    configured = _configured_kind(config_path)
    note = None
    if invalidation_scope is not None:
        kind: Optional[str] = invalidation_scope.value
    elif recorded is not None:
        # The recorded kind stands: a config default never rewrites a binding.
        kind = None
        kept = recorded.invalidation_scope or InvalidationScope.FILE.value
        if configured is not None and configured != kept:
            note = (
                f"{recorded.describe()} keeps its recorded invalidation scope "
                f"({kept}); the config's default is {configured}. Change it after "
                f"review with `{REFRESH_COMMAND} --invalidation-scope {configured} "
                f"--symbol {shlex.quote(symbol)} {shlex.quote(key)}`."
            )
    else:
        kind = configured or InvalidationScope.FILE.value
    try:
        # In memory first: a file whose entry is out of date is refused before
        # the config is touched.
        entry = lock.bind(key, LockScope(rule_id, symbol), invalidation_scope=kind)
    except AshLockError as e:
        _fail(str(e))
    bound = recorded_scope(entry, rule_id, symbol)
    if bound is None:
        # bind records the scope or raises, so this is a defect, not an input.
        _fail(f"{key}: the lock entry does not record {rule_id} in {symbol}")

    # Keyed as the entry was (resolved_lock_key): a config entry written as
    # link/app.py is the suppression of src/app.py when link -> src, so it is
    # only locked, not written a second time under the other spelling.
    already = any(
        isinstance(e.get("rule_id"), str)
        and e["rule_id"].strip().casefold() == rule_id.casefold()
        and e.get("symbol") == symbol
        and isinstance(e.get("path"), str)
        and resolved_lock_key(root, e["path"]) == key
        for e in _suppressions_in(config_path)
    )
    if not already:
        from automated_security_helper.config.ash_config import (
            add_suppression_to_config,
        )
        from automated_security_helper.models.core import AshSuppression

        try:
            add_suppression_to_config(
                config_path,
                AshSuppression(
                    rule_id=rule_id, path=key, symbol=symbol, reason=reason.strip()
                ),
            )
        except (ValueError, OSError) as e:
            _fail(f"the suppression was not written: {e}")
    try:
        lock.save()
    except OSError as e:
        _fail(
            f"the lock was not written ({type(e).__name__}); the suppression is "
            "in the config, so run the same command again"
        )
    echo(
        shown_on_one_line(
            f"{'Already in' if already else 'Added to'} {config_path.as_posix()}: "
            f"{rule_id} in {symbol} ({key})"
        )
    )
    changes = symbol if bound.invalidation_scope == InvalidationScope.SYMBOL else key
    echo(
        shown_on_one_line(
            f"Locked {key}: {bound.describe()}, reviewed again when {changes} "
            f"changes ({LOCK_RELATIVE_PATH})"
        )
    )
    if note is not None:
        echo(shown_on_one_line(note))
    _note_legacy(lock)


def _scopes_text(scopes) -> str:
    return ", ".join(s.describe() for s in sorted(scopes)) or "no scopes"


@suppress_app.command(name="refresh")
def refresh(
    paths: Annotated[
        Optional[List[str]],
        typer.Argument(
            help="Locked files to record a new review of. Pass --all for every "
            "locked file.",
        ),
    ] = None,
    all_files: Annotated[
        bool,
        typer.Option(
            "--all",
            help="Refresh every locked file. A refresh re-approves each changed "
            "file it touches, so the whole-lock run is asked for explicitly.",
        ),
    ] = False,
    drop_missing: Annotated[
        bool,
        typer.Option(
            "--drop-missing",
            help="Remove the entry of a named file that no longer exists, and "
            "the symbol-scoped suppressions of a symbol the file no longer "
            "defines, instead of leaving them and exiting 1.",
        ),
    ] = False,
    invalidation_scope: Annotated[
        Optional[InvalidationScope],
        _invalidation_scope_option(
            "Set the invalidation scope of the named files' recorded "
            "suppressions, or with --symbol of that symbol's only: 'file' or "
            "'symbol'. Without it every suppression keeps its kind."
        ),
    ] = None,
    symbol: Annotated[
        Optional[str],
        typer.Option(
            "--symbol",
            help="With --invalidation-scope, change only the suppressions of "
            "this symbol. Every suppression of the file is re-recorded either "
            "way.",
        ),
    ] = None,
    source_dir: Annotated[
        Optional[str],
        typer.Option("--source-dir", help=_SOURCE_DIR_HELP),
    ] = None,
):
    """Record a new review: re-record locked files whose code changed.

    Run it after reading what changed in a file and confirming its suppressions
    still hold. It re-records every suppression of each named file from the
    code as it stands, and prints each file it re-recorded. A locked file that
    no longer exists is reported and left as it was (exit code 1), unless
    --drop-missing removes its dead entry, and so is a symbol-scoped
    suppression whose symbol the file no longer defines. A file that changed
    and cannot be parsed is left as it was (exit code 1).

    --invalidation-scope converts suppressions between 'file' and 'symbol'
    scope; recording a new kind is a review too. A version 1 entry is
    converted to a syntax-tree entry when its file is refreshed.
    """
    if symbol is not None and invalidation_scope is None:
        _fail(
            "--symbol selects the suppressions --invalidation-scope changes; "
            "pass --invalidation-scope too (a refresh re-records every "
            "suppression of the file either way)"
        )
    root = _root(source_dir)
    lock = _load_lock(root)
    if paths:
        keys = [_key_for(root, p) for p in paths]
        unknown = [k for k in keys if k not in lock.entries]
        if unknown:
            _fail(
                f"{', '.join(unknown)} has no entry in {LOCK_RELATIVE_PATH}; "
                "create one with `ash suppress add`"
            )
    elif all_files:
        keys = sorted(lock.entries)
    else:
        # Not a default: re-recording every locked file re-approves every
        # changed one in one step, without naming what is approved, which is
        # the failure the lock exists to stop. The whole-lock run is spelled
        # out.
        _fail(
            "name the locked files to refresh, or pass --all to refresh "
            "every locked file after reviewing every change"
        )
    if symbol is not None:
        lacking = [
            k
            for k in keys
            if not any(s.symbol == symbol for s in lock.entries[k].scopes)
        ]
        if lacking:
            _fail(f"{', '.join(lacking)} records no suppression scoped to {symbol}")
    counts = dict.fromkeys(
        ("refreshed", "unchanged", "missing", "dropped", "unverifiable", "gone"), 0
    )
    written = False
    for key in keys:
        scopes = list(lock.entries[key].scopes)
        try:
            outcome = lock.review(
                key,
                invalidation_scope=invalidation_scope,
                symbol=symbol,
                drop_gone=drop_missing,
            )
        except AshLockError as e:
            _fail(str(e))
        state = outcome.state
        if state == "missing":
            # No bytes also comes from a file that is still there (unreadable,
            # not a regular file, too large, a link out of the root). Only a
            # file that no longer exists has a dead entry to drop; the others
            # keep theirs, since dropping it leaves their suppressions
            # unrecorded and every scan refusing the config.
            gone = file_is_gone(root, key)
            if drop_missing and gone:
                lock.drop(key)
                counts["dropped"] += 1
                written = True
                echo(shown_on_one_line(f"dropped:   {key} (no longer exists)"))
            elif gone:
                counts["missing"] += 1
                echo(
                    shown_on_one_line(
                        f"missing:   {key} (no longer exists; left as it was; "
                        "drop the dead entry with --drop-missing)"
                    )
                )
            else:
                counts["missing"] += 1
                kept = (
                    "; --drop-missing removes only the entry of a file that "
                    "no longer exists"
                    if drop_missing
                    else ""
                )
                echo(
                    shown_on_one_line(
                        f"missing:   {key} (exists but cannot be hashed: "
                        f"{_UNHASHABLE}; left as it was{kept})"
                    )
                )
            continue
        if state == "gone":
            counts["gone"] += 1
            for name in outcome.gone:
                described = _scopes_text(s for s in scopes if s.symbol == name)
                echo(
                    shown_on_one_line(
                        f"gone:      {key} symbol {name} ({described}); the file no "
                        "longer defines it, so the entry is left as it was: rename "
                        "the suppression's symbol and record it with `ash suppress "
                        "add`, or remove it, then refresh with --drop-missing"
                    )
                )
            continue
        if state == "unverifiable":
            counts["unverifiable"] += 1
            echo(
                shown_on_one_line(
                    f"unverifiable: {key}; {outcome.reason}; left as it was"
                )
            )
            continue
        for scope in outcome.dropped:
            counts["dropped"] += 1
            echo(
                shown_on_one_line(
                    f"dropped:   {key} symbol {scope.symbol} ({scope.describe()}; "
                    "the file no longer defines it)"
                )
            )
        if state == "dropped":
            written = True
            continue
        if state == "refreshed":
            counts["refreshed"] += 1
            written = True
            echo(
                shown_on_one_line(
                    f"refreshed: {key} {(outcome.old or '')[:12]} -> "
                    f"{(outcome.new or '')[:12]}"
                )
            )
        elif state == "converted":
            counts["refreshed"] += 1
            written = True
            after = lock.entries[key].scopes
            echo(
                shown_on_one_line(
                    f"converted: {key} ("
                    + ", ".join(s.describe_with_kind() for s in sorted(after))
                    + ")"
                )
            )
        elif state == "upgraded":
            counts["unchanged"] += 1
            written = True
            echo(
                shown_on_one_line(
                    f"upgraded:  {key} (a version 1 entry, re-recorded as syntax-tree "
                    "digests of the same bytes)"
                )
            )
        else:
            counts["unchanged"] += 1
            echo(shown_on_one_line(f"unchanged: {key}"))
    if written or lock.from_legacy:
        try:
            lock.save()
        except OSError as e:
            _fail(f"the lock was not written ({type(e).__name__})")
        _note_legacy(lock)
    echo(
        f"{counts['refreshed']} refreshed, {counts['unchanged']} unchanged, "
        f"{counts['missing']} missing, {counts['dropped']} dropped"
    )
    if counts["unverifiable"] or counts["gone"]:
        echo(f"{counts['unverifiable']} unverifiable, {counts['gone']} gone")
    if counts["missing"] or counts["unverifiable"] or counts["gone"]:
        raise typer.Exit(1)


def _problem_line(root: Path, problem) -> str:
    key = problem.key
    quoted = shlex.quote(key)
    scopes = _scopes_text(problem.scopes)
    if problem.state == "missing" and file_is_gone(root, key):
        return (
            f"missing: {key} ({scopes}); the file is gone, so drop the dead entry "
            f"with `{REFRESH_COMMAND} --drop-missing {quoted}`"
        )
    if problem.state == "missing":
        # Still there, so --drop-missing keeps the entry: the cure is the
        # file, not the lock.
        return (
            f"missing: {key} ({scopes}); the file exists but cannot be hashed "
            f"({_UNHASHABLE}); make it a readable regular file, then, after "
            f"review, run `{REFRESH_COMMAND} {quoted}`"
        )
    where = f"{key} symbol {problem.symbol}" if problem.symbol else key
    if problem.state == "gone":
        return (
            f"gone: {where} ({scopes}); the file no longer defines it: rename the "
            "suppression's symbol and record it with `ash suppress add`, or remove "
            f"it, then run `{REFRESH_COMMAND} --drop-missing {quoted}`"
        )
    if problem.state == "unverifiable":
        return f"unverifiable: {where} ({scopes}); {problem.reason}"
    why = f"{problem.reason}; " if problem.reason and not problem.symbol else ""
    return (
        f"stale: {where} ({scopes}); {why}after review run `{REFRESH_COMMAND} {quoted}`"
    )


@suppress_app.command(name="verify")
def verify(
    config: Annotated[
        Optional[List[str]],
        typer.Option(
            "--config",
            "-c",
            help="A YAML config file whose symbol suppressions must each have a "
            "lock entry. Repeat it for several. Defaults to the config a scan of "
            "the source directory uses.",
        ),
    ] = None,
    source_dir: Annotated[
        Optional[str],
        typer.Option("--source-dir", help=_SOURCE_DIR_HELP),
    ] = None,
):
    """Check the lock against the tree. Exits 1 when anything is out of date.

    Lists every recorded suppression whose code changed (its file's, or its
    symbol's when it is symbol-scoped), whose symbol is gone, whose file is
    gone or changed and cannot be parsed, and every symbol suppression in the
    checked configs that the lock does not record (no entry for its file, or
    no recorded (rule_id, symbol) scope). It checks the named --config files,
    or the one config file a scan of the source directory discovers, and
    prints which; suppressions an `extends` base contributes are not read, so
    exit code 0 covers the checked files, not every config a scan could merge.

    Needs the optional 'symbols' extra only for a file that changed.
    """
    root = _root(source_dir)
    lock = _load_lock(root)
    problems: List[str] = []
    found = lock.problems()
    for problem in found:
        problems.append(_problem_line(root, problem))
    with_problems = {p.key for p in found}
    version_1 = sorted(
        key
        for key, entry in lock.entries.items()
        if entry.is_legacy and key not in with_problems
    )
    config_paths = (
        [_config_file(c, root) for c in config] if config else _default_configs(root)
    )
    if config_paths:
        checked = ", ".join(p.as_posix() for p in config_paths)
        echo(shown_on_one_line(f"checking suppressions in: {checked}"))
    else:
        echo(
            "checking no config file: none was named and the source directory "
            "has no YAML config, so only the lock itself is checked"
        )
    for config_path in config_paths:
        for entry in _suppressions_in(config_path):
            symbol = entry.get("symbol")
            path = entry.get("path")
            if not symbol or not isinstance(path, str):
                continue
            rule_id = entry.get("rule_id")
            if rule_id is not None and not isinstance(rule_id, str):
                # An unquoted `rule_id: 602` reads as a YAML integer, which the
                # config model's strict string field refuses, so a scan stops
                # on this config. Reported, not compared: the comparison
                # called .casefold() on it and raised AttributeError.
                problems.append(
                    f"malformed: {path} in {config_path.name}; its rule_id is "
                    f"not a string (it reads as {type(rule_id).__name__}); "
                    "write it quoted"
                )
                continue
            key = resolved_lock_key(root, path)
            locked = lock.entries.get(key) if key is not None else None
            if locked is None or not scope_is_recorded(locked, rule_id, str(symbol)):
                if file_is_gone(root, path):
                    # `add` refuses a path that is not a file, so its command
                    # cannot work here: the suppression itself is what is left.
                    problems.append(
                        f"unlocked: {path} in {config_path.name}; the file no "
                        "longer exists, so remove the suppression from the config"
                    )
                else:
                    problems.append(
                        f"unlocked: {path} in {config_path.name}; run "
                        f"`{add_command_for(rule_id, str(symbol), path)}`"
                    )
    for line in problems:
        echo(shown_on_one_line(line))
    if version_1:
        echo(
            shown_on_one_line(
                f"{len(version_1)} current entr{'y' if len(version_1) == 1 else 'ies'} "
                "predate syntax-tree digests (version 1 entries: any byte change "
                f"counts); convert them with `{MIGRATE_COMMAND}`"
            )
        )
    if problems:
        echo(f"{len(problems)} problem(s); a scan does not apply these suppressions.")
        raise typer.Exit(1)
    echo(f"{LOCK_RELATIVE_PATH} is current: {len(lock.entries)} file(s) locked.")


@suppress_app.command(name="migrate")
def migrate(
    source_dir: Annotated[
        Optional[str],
        typer.Option("--source-dir", help=_SOURCE_DIR_HELP),
    ] = None,
):
    """Convert version 1 lock entries whose files are unchanged.

    A version 1 entry is bound to the raw bytes of its file, so any byte change,
    line endings included, makes it stale. This re-records each entry whose
    bytes still match as syntax-tree digests with 'file' invalidation scope,
    which approves nothing: the bytes present are the ones reviewed. An entry
    whose file changed is listed with the refresh that records its review and
    left as it is; so are a file that is gone or cannot be parsed. Exits 0 only
    when no version 1 entry is left.

    Needs the optional 'symbols' extra, which parses the files.
    """
    root = _root(source_dir)
    lock = _load_lock(root)
    scopes = {key: list(entry.scopes) for key, entry in lock.entries.items()}
    counts = dict.fromkeys(("migrated", "stale", "missing", "unverifiable"), 0)
    for outcome in lock.migrate():
        key = outcome.key
        counts[outcome.state] += 1
        quoted = shlex.quote(key)
        if outcome.state == "migrated":
            echo(shown_on_one_line(f"migrated: {key}"))
        elif outcome.state == "stale":
            echo(
                shown_on_one_line(
                    f"stale:    {key} ({_scopes_text(scopes[key])}); its bytes "
                    "changed since the version 1 entry was written, so it is left "
                    f"as it is: after review run `{REFRESH_COMMAND} {quoted}`"
                )
            )
        elif outcome.state == "missing":
            echo(
                shown_on_one_line(
                    f"missing:  {key} ({_scopes_text(scopes[key])}); the file cannot "
                    f"be read ({_UNHASHABLE} or gone); left as it is"
                )
            )
        else:
            echo(
                shown_on_one_line(
                    f"unverifiable: {key}; {outcome.reason}; left as it is"
                )
            )
    if counts["migrated"] or lock.from_legacy:
        try:
            lock.save()
        except OSError as e:
            _fail(f"the lock was not written ({type(e).__name__})")
        _note_legacy(lock)
    echo(
        f"{counts['migrated']} migrated, {counts['stale']} stale, "
        f"{counts['missing']} missing, {counts['unverifiable']} unverifiable"
    )
    if any(entry.is_legacy for entry in lock.entries.values()):
        raise typer.Exit(1)


def _default_configs(root: Path) -> List[Path]:
    from automated_security_helper.config.resolve_config import find_config_file

    found = find_config_file(root)
    if found is None or Path(found).suffix.lower() not in (".yaml", ".yml"):
        return []
    return [Path(found)]
