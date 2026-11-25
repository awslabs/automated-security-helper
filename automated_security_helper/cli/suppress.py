# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash suppress``: write symbol suppressions and keep ``.ash.lock`` current.

``ash suppress add`` writes a symbol-scoped suppression into a config file and
the content hash of the file it covers into ``.ash.lock`` in one operation.
It is the supported way to create the lock entry a symbol suppression needs
(``utils/ash_lock.py`` says why). ``ash suppress refresh`` records a new review
of files whose bytes changed, and ``ash suppress verify`` exits non-zero when
the lock is out of date, for CI.
"""

from pathlib import Path
from typing import Annotated, Any, Dict, List, NoReturn, Optional

import typer
import yaml

from automated_security_helper.utils.ash_lock import (
    LEGACY_LOCK_RELATIVE_PATH,
    LOCK_RELATIVE_PATH,
    REFRESH_COMMAND,
    AshLock,
    AshLockError,
    LockScope,
    add_command_for,
    lock_key,
)
from automated_security_helper.utils.console import echo
from automated_security_helper.utils.log import show_debug_locals
from automated_security_helper.utils.symbol_spans import SYMBOL_PATTERN, is_valid_symbol
from automated_security_helper.utils.terminal_text import shown_on_one_line

suppress_app = typer.Typer(
    name="suppress",
    help=(
        "Create symbol suppressions and keep their content-hash lock "
        f"({LOCK_RELATIVE_PATH}) current."
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
    """The lock key of ``path``, read relative to the source directory."""
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve().relative_to(root)
        except (OSError, ValueError):
            _fail(f"{path} is not inside the source directory {root.as_posix()}")
    key = lock_key(candidate.as_posix())
    if key is None:
        _fail(f"{path} is not a path inside the source directory")
    return key


def _suppressions_in(config_path: Path) -> List[Dict[str, Any]]:
    """The raw ``global_settings.suppressions`` entries one YAML config lists.

    Read as the config's own loader reads it, aliases refused; a ``!ENV``
    reference is kept as written, nothing is read from the environment.
    """
    from automated_security_helper.config.ash_config import load_yaml_config

    try:
        document = load_yaml_config(config_path.read_text(encoding="utf-8"), env="keep")
    except (OSError, ValueError, yaml.YAMLError) as e:
        _fail(f"{config_path.as_posix()} cannot be read as YAML: {type(e).__name__}")
    if not isinstance(document, dict):
        return []
    settings = document.get("global_settings")
    entries = settings.get("suppressions") if isinstance(settings, dict) else None
    return [e for e in entries or [] if isinstance(e, dict)]


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
            "directory. Its content hash is recorded in the lock.",
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
):
    """Add a symbol suppression and lock its file's content hash.

    Writes the suppression into the config and the hash of the file's bytes
    into .ash.lock. While the file is unchanged the suppression applies;
    after any edit to the file its findings are reported again until the change
    is reviewed and `ash suppress refresh` records it.

    A suppression already in the config for the same rule, file and symbol is
    not written twice; the lock entry is still created or completed, which is
    how an existing suppression is brought under the lock.

    Example:
        ash suppress add B602 --symbol Handler.run --file src/app.py \\
            --reason "The command is a constant."
    """
    if not rule_id.strip():
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
    try:
        # In memory first: a file whose entry is out of date is refused before
        # the config is touched.
        entry = lock.bind(key, LockScope(rule_id, symbol))
    except AshLockError as e:
        _fail(str(e))

    already = any(
        e.get("rule_id") == rule_id
        and e.get("symbol") == symbol
        and isinstance(e.get("path"), str)
        and lock_key(e["path"]) == key
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
    echo(
        shown_on_one_line(
            f"Locked {key} at sha256 {entry.sha256[:12]} in {LOCK_RELATIVE_PATH}"
        )
    )
    _note_legacy(lock)


@suppress_app.command(name="refresh")
def refresh(
    paths: Annotated[
        Optional[List[str]],
        typer.Argument(
            help="Locked files to re-hash. Every locked file when none is named.",
        ),
    ] = None,
    source_dir: Annotated[
        Optional[str],
        typer.Option("--source-dir", help=_SOURCE_DIR_HELP),
    ] = None,
):
    """Record a new review: re-hash locked files whose bytes changed.

    Run it after reading what changed in a file and confirming its suppressions
    still hold. It prints each file whose hash changed. A locked file that no
    longer exists is reported and left as it was; exit code 1 then.
    """
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
    else:
        keys = sorted(lock.entries)
    changed = 0
    missing = 0
    for key in keys:
        old, new = lock.refresh(key)
        if new is None:
            missing += 1
            echo(
                shown_on_one_line(f"missing:   {key} (cannot be read; left as it was)")
            )
        elif old != new:
            changed += 1
            echo(shown_on_one_line(f"refreshed: {key} {old[:12]} -> {new[:12]}"))
        else:
            echo(shown_on_one_line(f"unchanged: {key}"))
    if changed or lock.from_legacy:
        try:
            lock.save()
        except OSError as e:
            _fail(f"the lock was not written ({type(e).__name__})")
        _note_legacy(lock)
    echo(
        f"{changed} refreshed, {len(keys) - changed - missing} unchanged, {missing} missing"
    )
    if missing:
        raise typer.Exit(1)


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

    Lists every locked file whose bytes changed or that is gone, and every
    symbol suppression in the named configs whose file has no lock entry. Exit
    code 0 means a scan applies every symbol suppression.
    """
    root = _root(source_dir)
    lock = _load_lock(root)
    problems: List[str] = []
    for key, state in lock.problems():
        scopes = ", ".join(s.describe() for s in sorted(lock.entries[key].scopes))
        label = "stale" if state == "stale" else "missing"
        problems.append(
            f"{label}: {key} ({scopes or 'no scopes'}); after review run "
            f"`{REFRESH_COMMAND} {key}`"
        )
    config_paths = (
        [_config_file(c, root) for c in config] if config else _default_configs(root)
    )
    for config_path in config_paths:
        for entry in _suppressions_in(config_path):
            symbol = entry.get("symbol")
            path = entry.get("path")
            if not symbol or not isinstance(path, str):
                continue
            key = lock_key(path)
            if key is None or key not in lock.entries:
                problems.append(
                    f"unlocked: {path} in {config_path.name}; run "
                    f"`{add_command_for(entry.get('rule_id'), str(symbol), path)}`"
                )
    for line in problems:
        echo(shown_on_one_line(line))
    if problems:
        echo(f"{len(problems)} problem(s); a scan does not apply these suppressions.")
        raise typer.Exit(1)
    echo(f"{LOCK_RELATIVE_PATH} is current: {len(lock.entries)} file(s) locked.")


def _default_configs(root: Path) -> List[Path]:
    from automated_security_helper.config.resolve_config import find_config_file

    found = find_config_file(root)
    if found is None or Path(found).suffix.lower() not in (".yaml", ".yml"):
        return []
    return [Path(found)]
