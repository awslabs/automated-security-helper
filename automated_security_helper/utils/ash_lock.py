# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``.ash.lock``: the content hash a symbol-scoped suppression is bound to.

A symbol suppression keeps covering a definition wherever edits move it, which
is its strength and its risk: the definition can be rewritten and the old
review still applies. The lock closes that. For every file a symbol suppression
names, the lock records the SHA-256 of the file's bytes at the time somebody
reviewed the suppression. While the file still hashes to that value the
suppression applies. When the file changes, every symbol suppression bound to
it stops applying (its findings return) and the scan names the file, the
suppressions, and the command that records the new review.

The file is committed, so a change to a hash shows up in a code review beside
the change to the file it covers.

Format
------

One JSON document with a fixed key order and two-space indentation::

    {
      "files": {
        "src/app.py": {
          "created": "2026-11-25T18:00:00Z",
          "scopes": [{"rule_id": "B602", "symbol": "Handler.run"}],
          "sha256": "9f86d081..."
        }
      },
      "version": 1
    }

Keys are sorted, entries are sorted by path, and scopes by rule id then symbol,
so the same tree always produces the same bytes. The whole file is hashed, not
the symbol's span: a span hash would change on every reformat of the definition
and say nothing the whole-file hash does not say more simply.

Files are read as bytes, with no newline normalization, so a checkout that
rewrites line endings changes the hash and the suppressions go inert until the
lock is refreshed on that checkout.

The commands that write the lock are ``ash suppress add`` and
``ash suppress refresh`` (``cli/suppress.py``); the lock is meant to be written
by them and read by people.
"""

from __future__ import annotations

import hashlib
import json
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP

#: The lock's place, relative to the scan root: a dotfile at the repository root,
#: beside ``.ash.yaml``.
LOCK_RELATIVE_PATH = ".ash.lock"

#: The legacy lock's file name inside ``.ash/``. Its own file-name constant so the
#: docs check, which accepts an ``ash.<name>`` a page names only when the package
#: declares that file (scripts/docs_checks.py), accepts the suppression guide's
#: ``git mv .ash/ash.lock .ash.lock``.
LEGACY_LOCK_FILE_NAME = "ash.lock"

#: Where the lock was first written. Still read, with a deprecation warning, when
#: ``.ash.lock`` does not exist; never written. Deprecated since v3.9, removed in
#: v4.0, as the other renamed config paths are.
LEGACY_LOCK_RELATIVE_PATH = f".ash/{LEGACY_LOCK_FILE_NAME}"

#: The legacy locations already warned about in this process, so a scan that loads
#: the lock for each file it checks says it once.
_LEGACY_WARNED: set[str] = set()

#: The lock format version this module reads and writes.
LOCK_VERSION = 1

#: The command that records a new review of locked files.
REFRESH_COMMAND = "ash suppress refresh"

#: A file larger than this is refused rather than read whole into memory.
MAX_LOCKED_FILE_BYTES = 64 * 1024 * 1024


class AshLockError(ValueError):
    """The lock file cannot be used: unreadable, not JSON, or the wrong shape."""


@dataclass(frozen=True, order=True)
class LockScope:
    """One suppression bound to a locked file: its rule id and symbol."""

    rule_id: str
    symbol: str

    def describe(self) -> str:
        rule = self.rule_id or "(any rule)"
        return f"{rule} in {self.symbol}"


@dataclass
class LockEntry:
    """One locked file: the hash of its bytes, when it was first locked, and the
    suppression scopes bound to it."""

    sha256: str
    created: str
    scopes: List[LockScope] = field(default_factory=list)

    def to_json(self) -> Dict[str, Any]:
        return {
            "created": self.created,
            "scopes": [
                {"rule_id": s.rule_id, "symbol": s.symbol} for s in sorted(self.scopes)
            ],
            "sha256": self.sha256,
        }


def lock_key(path: str) -> Optional[str]:
    """The key a suppression's ``path`` is locked under, or None when it cannot be one.

    Posix separators, no leading ``./``. A path that is absolute, climbs out of
    the scan root with ``..``, or is empty is no key: a lock entry names a file
    inside the scanned tree.
    """
    if not isinstance(path, str) or not path.strip():
        return None
    normalized = PurePosixPath(path.replace("\\", "/"))
    if normalized.is_absolute() or ".." in normalized.parts:
        return None
    text = normalized.as_posix()
    return None if text in ("", ".") else text


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def file_sha256(source_dir: Path, key: str) -> Optional[str]:
    """SHA-256 of the bytes of ``key`` under ``source_dir``, or None.

    None when the file is missing, is not a regular file, lies outside the
    source directory once links are followed, is larger than
    ``MAX_LOCKED_FILE_BYTES`` or cannot be read. Callers treat None as "this
    file has no hash", so a suppression bound to it stays inert.
    """
    try:
        root = Path(source_dir).resolve()
        target = (root / key).resolve()
        if not target.is_relative_to(root):
            return None
        info = target.stat()
        if not target.is_file() or info.st_size > MAX_LOCKED_FILE_BYTES:
            return None
        # Whole file, at most MAX_LOCKED_FILE_BYTES (checked above).
        return hashlib.sha256(target.read_bytes()).hexdigest()
    except (OSError, RuntimeError, ValueError):
        return None


@dataclass
class AshLock:
    """The parsed ``.ash.lock`` of one scan root."""

    source_dir: Path
    entries: Dict[str, LockEntry] = field(default_factory=dict)
    #: True when the entries were read from the legacy ``.ash/ash.lock``. The
    #: next ``save`` writes ``.ash.lock``; the legacy file is left as it is.
    from_legacy: bool = False

    @property
    def path(self) -> Path:
        """The file ``save`` writes: always ``.ash.lock``."""
        return Path(self.source_dir) / LOCK_RELATIVE_PATH

    @property
    def legacy_path(self) -> Path:
        return Path(self.source_dir) / LEGACY_LOCK_RELATIVE_PATH

    @classmethod
    def load(cls, source_dir: Path | str) -> "AshLock":
        """Read the lock of ``source_dir``; a missing file is an empty lock.

        ``.ash.lock`` wins. Only when it does not exist is the legacy
        ``.ash/ash.lock`` read, with a deprecation warning (once per process).

        Raises:
            AshLockError: the file exists and cannot be used. A broken lock is
                never read as an empty one, which would turn a damaged file
                into "nothing is locked" and hide it.
        """
        root = Path(source_dir)
        lock = cls(source_dir=root)
        shown = LOCK_RELATIVE_PATH
        path = lock.path
        if not path.exists() and lock.legacy_path.exists():
            path = lock.legacy_path
            shown = LEGACY_LOCK_RELATIVE_PATH
            lock.from_legacy = True
            key = str(root.resolve())
            if key not in _LEGACY_WARNED:
                _LEGACY_WARNED.add(key)
                # Advises the move alone. The old advice also offered the
                # re-hashing command, and following it on a lock with stale
                # entries re-approved every unreviewed change in one step,
                # which is the failure the lock exists to stop.
                ASH_LOGGER.warning(
                    f"{LEGACY_LOCK_RELATIVE_PATH} is deprecated since v3.9 and "
                    f"will not be read from v4.0. Move it with "
                    f"`git mv {LEGACY_LOCK_RELATIVE_PATH} {LOCK_RELATIVE_PATH}`.",
                    extra=NO_MARKUP,
                )
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return lock
        except OSError as e:
            raise AshLockError(f"{shown} cannot be read: {e}") from None
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise AshLockError(f"{shown} is not valid JSON") from None
        lock.entries = _entries_of(document, shown)
        return lock

    def to_text(self) -> str:
        """The lock's bytes: sorted keys, two-space indent, one trailing newline."""
        document = {
            "files": {key: self.entries[key].to_json() for key in sorted(self.entries)},
            "version": LOCK_VERSION,
        }
        return json.dumps(document, indent=2, sort_keys=True) + "\n"

    def save(self) -> None:
        """Write the lock through the atomic writer other config files use.

        The staging file has a random name, is created exclusively and without
        following a link, and is renamed over the lock in one step; a failed
        write leaves the lock as it was.
        """
        # Not at the top: fs_guard imports the sandbox package.
        from automated_security_helper.utils.sandbox.fs_guard import (
            open_for_atomic_write,
        )

        path = self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        # newline="": the text reaches the file as given, "\n" on every platform.
        with open_for_atomic_write(path, encoding="utf-8", newline="") as handle:
            handle.write(self.to_text())

    def bind(
        self,
        key: str,
        scope: LockScope,
        *,
        now: Optional[str] = None,
    ) -> LockEntry:
        """Lock ``key`` at its current hash and bind ``scope`` to it.

        A file already locked at the same hash keeps its entry and gains the
        scope. A file locked at another hash is re-hashed: its old scopes were
        reviewed against bytes that no longer exist, so only a deliberate
        ``refresh`` does that, and ``bind`` refuses it (``AshLockError``).
        """
        digest = file_sha256(self.source_dir, key)
        if digest is None:
            raise AshLockError(f"{key} is not a readable file inside the scan root")
        entry = self.entries.get(key)
        if entry is None:
            entry = LockEntry(sha256=digest, created=now or _utc_now())
            self.entries[key] = entry
        elif entry.sha256 != digest:
            raise AshLockError(
                f"{key} changed since it was locked; review its suppressions, "
                f"then run `{REFRESH_COMMAND} {shlex.quote(key)}` before adding another"
            )
        if scope not in entry.scopes:
            entry.scopes.append(scope)
            entry.scopes.sort()
        return entry

    def refresh(self, key: str) -> Tuple[Optional[str], Optional[str]]:
        """Re-hash one locked file. Returns ``(old, new)``; ``new`` is None when
        the file can no longer be hashed (the entry is left as it was)."""
        entry = self.entries[key]
        new = file_sha256(self.source_dir, key)
        if new is None:
            return entry.sha256, None
        old = entry.sha256
        entry.sha256 = new
        return old, new

    def drop(self, key: str) -> None:
        """Remove one entry: the way out for a locked file that is gone.

        ``refresh`` cannot cure a ``missing`` entry (there are no bytes to
        hash), so without this the only remedy was hand-editing the file the
        module docstring says only the commands write.
        """
        del self.entries[key]

    def status(self, key: str) -> str:
        """``"ok"``, ``"stale"`` (hash differs), ``"missing"`` (file gone or
        unreadable) or ``"unlocked"`` (no entry)."""
        entry = self.entries.get(key)
        if entry is None:
            return "unlocked"
        digest = file_sha256(self.source_dir, key)
        if digest is None:
            return "missing"
        return "ok" if digest == entry.sha256 else "stale"

    def problems(self) -> List[Tuple[str, str]]:
        """Every locked file that is not ``ok``, as ``(key, status)``, by path."""
        found = []
        for key in sorted(self.entries):
            state = self.status(key)
            if state != "ok":
                found.append((key, state))
        return found


def _entries_of(document: Any, where: str = LOCK_RELATIVE_PATH) -> Dict[str, LockEntry]:
    """The entries of a parsed lock; ``where`` names the file in a refusal."""
    if not isinstance(document, dict) or document.get("version") != LOCK_VERSION:
        raise AshLockError(f"{where} is not a version {LOCK_VERSION} lock file")
    files = document.get("files")
    if not isinstance(files, dict):
        raise AshLockError(f"{where} has no 'files' mapping")
    entries: Dict[str, LockEntry] = {}
    for key, raw in files.items():
        if lock_key(key) != key or not isinstance(raw, dict):
            raise AshLockError(f"{where} has a malformed entry for a file")
        digest = raw.get("sha256")
        created = raw.get("created")
        scopes = raw.get("scopes", [])
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or not isinstance(created, str)
            or not isinstance(scopes, list)
        ):
            raise AshLockError(f"{where} has a malformed entry for {key}")
        parsed: List[LockScope] = []
        for scope in scopes:
            if (
                not isinstance(scope, dict)
                or not isinstance(scope.get("symbol"), str)
                or not isinstance(scope.get("rule_id", ""), str)
            ):
                raise AshLockError(f"{where} has a malformed scope for {key}")
            parsed.append(LockScope(scope.get("rule_id", ""), scope["symbol"]))
        entries[key] = LockEntry(sha256=digest, created=created, scopes=sorted(parsed))
    return entries


def add_command_for(rule_id: Optional[str], symbol: str, path: str) -> str:
    """The ``ash suppress add`` line that locks one suppression.

    Every value is shell-quoted: the rule id, symbol and path come from the
    config, which a pull request controls, so an unquoted ``x; curl ... | sh``
    in a path would run something else when a maintainer pastes the suggested
    command from CI output.
    """
    return (
        f"ash suppress add {shlex.quote(rule_id or '<rule-id>')} "
        f"--symbol {shlex.quote(symbol)} --file {shlex.quote(path)} "
        f"--reason '<why this is safe>'"
    )


def symbol_suppressions(suppressions: Iterable[Any]) -> List[Any]:
    """The suppressions that set ``symbol``."""
    return [s for s in suppressions or [] if getattr(s, "symbol", None)]


def scope_is_recorded(entry: LockEntry, rule_id: Optional[str], symbol: str) -> bool:
    """Whether ``entry`` records the scope ``(rule_id, symbol)``.

    The rule id is compared case-insensitively, as suppression rule ids match
    everywhere else; the symbol is exact, as symbol resolution is.
    """
    wanted = (rule_id or "").casefold()
    return any(
        scope.rule_id.casefold() == wanted and scope.symbol == symbol
        for scope in entry.scopes
    )


def unlocked_symbol_suppressions(
    suppressions: Iterable[Any], lock: AshLock
) -> List[Any]:
    """The symbol-scoped suppressions the lock does not record.

    A suppression is unlocked when its file has no entry, or when the entry
    does not record its ``(rule_id, symbol)`` scope: a scope the lock does not
    hold was never reviewed, so a suppression hand-added to an already locked
    file (a different rule, a broader symbol) is refused until
    ``ash suppress add`` records it. A path that cannot be a lock key (a
    wildcard that names no one file is still looked up as written, so it is
    unlocked; an absolute path or one climbing out of the root never is)
    counts as unlocked.
    """
    missing = []
    for suppression in symbol_suppressions(suppressions):
        key = lock_key(getattr(suppression, "path", None) or "")
        entry = lock.entries.get(key) if key is not None else None
        if entry is None or not scope_is_recorded(
            entry, getattr(suppression, "rule_id", None), suppression.symbol
        ):
            missing.append(suppression)
    return missing


def refusal_text(unlocked: Sequence[Any]) -> str:
    """The validation message for symbol suppressions with no lock entry."""
    lines = [
        (
            f"{len(unlocked)} symbol-scoped suppression(s) are not recorded in "
            f"{LOCK_RELATIVE_PATH}: a symbol suppression is bound, rule and "
            "symbol by name, to the content hash of its file, so a change to "
            "the file or an unreviewed scope is reviewed again. Run the "
            "command for each one, which writes the suppression and its lock entry "
            "together (an entry already in the config is only locked):"
        )
    ]
    for suppression in unlocked[:10]:
        path = getattr(suppression, "path", "") or "<path>"
        # `ash suppress add` would refuse a path that is not one file, so the
        # command it names cannot work for one; say what can.
        if any(character in path for character in "*?[") or path.endswith("/"):
            lines.append(
                f"  a symbol suppression must name one file; {path!r} is a "
                "pattern or a directory. Name the file that holds the "
                "definition, locking each such file with its own entry."
            )
            continue
        lines.append(
            "  "
            + add_command_for(
                getattr(suppression, "rule_id", None),
                suppression.symbol,
                path,
            )
        )
    if len(unlocked) > 10:
        lines.append(f"  ... and {len(unlocked) - 10} more")
    return "\n".join(lines)


def refuse_unlocked_symbol_suppressions(
    suppressions: Iterable[Any], source_dir: Path | str
) -> None:
    """Raise ``ASHConfigValidationError`` for a symbol suppression with no lock entry.

    Nothing is checked when no suppression sets ``symbol``, so a config without
    one never reads the lock. A lock file that cannot be used is the same
    refusal, in its own words.
    """
    symbols = symbol_suppressions(suppressions)
    if not symbols:
        return
    try:
        lock = AshLock.load(source_dir)
    except AshLockError as e:
        raise ASHConfigValidationError(str(e)) from None
    unlocked = unlocked_symbol_suppressions(symbols, lock)
    if unlocked:
        raise ASHConfigValidationError(refusal_text(unlocked))


def stale_notice(key: str, entry: LockEntry, state: str) -> str:
    """The one notice a scan prints for a locked file whose hash does not match.

    A ``stale`` file has bytes to review, so the advice is the refresh; a
    ``missing`` one has none, and ``refresh`` on it exits 1 and changes
    nothing, so the advice is the drop. The two used to share the refresh
    advice, which left a deleted file failing ``verify`` forever.
    """
    scopes = ", ".join(s.describe() for s in sorted(entry.scopes)) or "none recorded"
    if state == "missing":
        return (
            f"Stale suppression: {key} no longer exists or cannot be read, so "
            f"the symbol suppressions bound to it do not apply. Suppressions: "
            f"{scopes}. Drop the dead entry with "
            f"`{REFRESH_COMMAND} --drop-missing {shlex.quote(key)}` and remove "
            f"its suppressions from the config."
        )
    return (
        f"Stale suppression: {key} has changed since its suppressions were "
        f"reviewed, so the symbol suppressions bound to it do not apply and "
        f"their findings are reported again. Suppressions: {scopes}. After "
        f"reviewing the change, record it with "
        f"`{REFRESH_COMMAND} {shlex.quote(key)}`."
    )
