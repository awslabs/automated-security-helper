# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``.ash.lock``: the syntax-tree digests a symbol-scoped suppression is bound to.

A symbol suppression keeps covering a definition wherever edits move it, which
is its strength and its risk: the definition can be rewritten and the old
review still applies. The lock closes that. For every file a symbol suppression
names, the lock records digests of the file's tree-sitter parse at the time
somebody reviewed the suppression (``utils/ast_digest.py``). While the code is
unchanged the suppression applies. When it changes, the suppression stops
applying (its findings return) and the scan names the file, the suppression
and the command that records the new review.

The file is committed, so a change to a digest shows up in a code review beside
the change to the file it covers.

Format
------

One JSON document with a fixed key order and two-space indentation::

    {
      "files": {
        "src/app.py": {
          "created": "2026-11-26T19:00:00Z",
          "digests": {
            "algorithm": "ash-ast-2",
            "file": "<64 hex>",
            "symbols": {"Handler.run": "<64 hex>"}
          },
          "grammar": {
            "distribution": "tree-sitter-python 0.25.0",
            "fingerprint": "<64 hex>",
            "language": "python",
            "tree_sitter": "0.26.0"
          },
          "scopes": [
            {"invalidation_scope": "file", "rule_id": "B603", "symbol": "other"},
            {"invalidation_scope": "symbol", "rule_id": "B602", "symbol": "Handler.run"}
          ],
          "source_sha256": "<64 hex>"
        }
      },
      "version": 2
    }

Keys are sorted, entries are sorted by path, and scopes by rule id then symbol,
so the same tree always produces the same bytes.

What each value covers
----------------------

``source_sha256`` is the SHA-256 of the file's bytes with CRLF and lone CR
rewritten to LF (a leading byte order mark kept). While it matches, every scope
of the entry is current with no parse at all, so a checkout that converts line
endings stays current. When the bytes changed, the scope's own digest decides:

- ``invalidation_scope: file``: the digest of the whole file's tree. Spaces,
  tabs and line breaks between tokens do not count; every token does, comments
  included, and so do the exact text of string literals and, in JavaScript and
  TypeScript, whether a line break precedes a token.
- ``invalidation_scope: symbol``: the digest of the suppressed definition alone:
  every token on its lines, every definition bearing its name, the headers of
  the definitions it sits in (and, in JavaScript and TypeScript, the directive
  run at the top of a function it sits in), and the file's prelude (byte order
  mark, encoding declaration, ``#!`` line, ``from __future__`` imports, leading
  comments and directives). An edit elsewhere in the file keeps the suppression.

``digests.algorithm`` names the canonical form and ``grammar`` the grammar the
digests were computed under; a changed file whose grammar tables are not the
recorded ones cannot be compared and reads stale until it is refreshed.

Version 1
---------

A version 1 entry (``created``, ``scopes`` and a ``sha256`` of the raw bytes) is
still read with version 1 meaning: any byte change, line endings included,
makes it stale. ``ash suppress migrate`` converts every entry whose bytes still
match; ``add`` converts the entry it touches and ``refresh`` the files it
names. Nothing converts an entry whose file changed without a review.

The commands that write the lock are ``ash suppress add``, ``refresh`` and
``migrate`` (``cli/suppress.py``); the lock is meant to be written by them and
read by people.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat as stat_module
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from automated_security_helper.utils.invalidation_scope import InvalidationScope
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.utils.ast_digest import ALGORITHM, DigestUnavailable
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

#: The lock format version this module writes.
LOCK_VERSION = 2

#: The versions this module reads: version 1 entries keep version 1 meaning.
READABLE_LOCK_VERSIONS = (1, 2)

#: The command that records a new review of locked files.
REFRESH_COMMAND = "ash suppress refresh"

#: The command that converts version 1 entries whose bytes still match.
MIGRATE_COMMAND = "ash suppress migrate"

#: A file larger than this is refused rather than read whole into memory.
MAX_LOCKED_FILE_BYTES = 64 * 1024 * 1024

#: What a version 1 entry's staleness means, for messages.
VERSION_1_REASON = "a version 1 entry, so any byte change counts"

_HEX64 = re.compile(r"[0-9a-f]{64}")
_KINDS = {kind.value for kind in InvalidationScope}

_DOCUMENT_KEYS = {"files", "version"}
_LEGACY_ENTRY_KEYS = {"created", "scopes", "sha256"}
_TREE_ENTRY_KEYS = {"created", "digests", "grammar", "scopes", "source_sha256"}
_DIGEST_KEYS = {"algorithm", "file", "symbols"}
_GRAMMAR_KEYS = {"distribution", "fingerprint", "language", "tree_sitter"}
_LEGACY_SCOPE_KEYS = {"rule_id", "symbol"}
_TREE_SCOPE_KEYS = {"invalidation_scope", "rule_id", "symbol"}
#: Fields only a version 2 entry has: a version 1 document holding one is refused.
_VERSION_2_ENTRY_FIELDS = ("source_sha256", "digests", "grammar")


class AshLockError(ValueError):
    """The lock file cannot be used: unreadable, not JSON, or the wrong shape."""


@dataclass(frozen=True, order=True)
class LockScope:
    """One suppression bound to a locked file: its rule id and symbol, and the
    invalidation scope that decides when it stops applying.

    A version 1 scope carries no invalidation scope (None). The kind is not
    compared: two scopes of one entry never differ by it alone, and leaving it
    out keeps the order of scopes rule id then symbol in both versions.
    """

    rule_id: str
    symbol: str
    invalidation_scope: Optional[str] = field(default=None, compare=False)

    def describe(self) -> str:
        rule = self.rule_id or "(any rule)"
        return f"{rule} in {self.symbol}"

    def describe_with_kind(self) -> str:
        if self.invalidation_scope is None:
            return self.describe()
        return f"{self.describe()} ({self.invalidation_scope} scope)"


@dataclass(frozen=True)
class LockGrammar:
    """The grammar a tree entry's digests were computed under."""

    language: str
    fingerprint: str
    distribution: str
    tree_sitter: str

    def to_json(self) -> Dict[str, Any]:
        return {
            "distribution": self.distribution,
            "fingerprint": self.fingerprint,
            "language": self.language,
            "tree_sitter": self.tree_sitter,
        }


@dataclass
class LockEntry:
    """One locked file: when it was first locked, the suppression scopes bound
    to it and what they are bound to.

    A version 1 entry has ``sha256``, the hash of the raw bytes. A tree entry
    has ``source_sha256`` (the anchor), the digests and the grammar.
    """

    created: str
    scopes: List[LockScope] = field(default_factory=list)
    sha256: Optional[str] = None
    source_sha256: Optional[str] = None
    algorithm: Optional[str] = None
    file_digest: Optional[str] = None
    symbol_digests: Dict[str, str] = field(default_factory=dict)
    grammar: Optional[LockGrammar] = None

    @property
    def is_legacy(self) -> bool:
        """A version 1 entry: bound to the raw bytes, with version 1 meaning."""
        return self.source_sha256 is None

    @property
    def anchor(self) -> Optional[str]:
        """The hash that, while it matches, makes every scope current."""
        return self.sha256 if self.is_legacy else self.source_sha256

    def to_json(self) -> Dict[str, Any]:
        if self.is_legacy:
            # Field for field as the version 1 writer wrote it.
            return {
                "created": self.created,
                "scopes": [
                    {"rule_id": s.rule_id, "symbol": s.symbol}
                    for s in sorted(self.scopes)
                ],
                "sha256": self.sha256,
            }
        if self.grammar is None:
            # The reader and _snapshot never build one; refuse to write it.
            raise ValueError("a syntax-tree lock entry has no grammar")
        return {
            "created": self.created,
            "digests": {
                "algorithm": self.algorithm,
                "file": self.file_digest,
                "symbols": dict(sorted(self.symbol_digests.items())),
            },
            "grammar": self.grammar.to_json(),
            "scopes": [
                {
                    "invalidation_scope": s.invalidation_scope,
                    "rule_id": s.rule_id,
                    "symbol": s.symbol,
                }
                for s in sorted(self.scopes)
            ],
            "source_sha256": self.source_sha256,
        }


@dataclass(frozen=True)
class ScopeState:
    """The state of one recorded scope against one read of its file.

    ``state`` is ``ok``, ``stale``, ``gone`` (a symbol scope whose symbol the
    file no longer defines), ``missing`` (the file cannot be read) or
    ``unverifiable`` (the file changed and cannot be digested). ``reason``
    says why, when there is more to say than the state. ``per_symbol`` is True
    when the state comes from the symbol's own digest rather than from the
    file as a whole.
    """

    state: str
    reason: str = ""
    per_symbol: bool = False


_OK = ScopeState("ok")
_MISSING = ScopeState("missing")


@dataclass(frozen=True)
class LockProblem:
    """One problem ``ash suppress verify`` reports: per file for a file-scope or
    version 1 entry and for a cause the whole file shares, per symbol for a
    symbol-scope one."""

    key: str
    state: str
    scopes: Tuple[LockScope, ...]
    symbol: Optional[str] = None
    reason: str = ""


@dataclass(frozen=True)
class RefreshOutcome:
    """What ``AshLock.review`` did to one entry.

    ``state`` is ``refreshed`` (re-bound to changed code), ``converted`` (a
    kind changed, the code did not), ``unchanged``, ``upgraded`` (a version 1
    entry whose bytes still matched, rewritten as a tree entry), ``dropped``
    (every scope was gone and was dropped, and the entry with them),
    ``missing``, ``gone`` (a symbol scope's symbol is not defined; the entry is
    left as it was) or ``unverifiable`` (the entry is left as it was).
    """

    key: str
    state: str
    old: Optional[str]
    new: Optional[str]
    reason: str = ""
    gone: Tuple[str, ...] = ()
    dropped: Tuple[LockScope, ...] = ()


@dataclass(frozen=True)
class MigrateOutcome:
    """What ``AshLock.migrate`` did to one version 1 entry: ``migrated``,
    ``stale`` (left as written), ``missing`` or ``unverifiable``."""

    key: str
    state: str
    reason: str = ""


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


def resolved_lock_key(source_dir: Path | str, path: Any) -> Optional[str]:
    """The key the lock holds for ``path`` under ``source_dir``: the file's own
    path, with symbolic links followed, or None when it cannot be one.

    The one key function for every place that writes or looks up an entry for
    a suppression's file: ``ash suppress add`` and its check for a suppression
    already in the config, ``ash suppress verify``, and the check of a config
    (``unlocked_symbol_suppressions``). It is also the key a scan looks up: the
    scan's resolver follows links in a finding's path before it builds its key
    (``SymbolResolver._scope_is_current``). With ``link -> src``, a
    suppression whose ``path`` is ``link/app.py`` is locked, found and refused
    under ``src/app.py`` by every one of them. Before this, ``add`` followed
    the link and the config check did not, so the refusal's own advice
    (``add ... --file link/app.py``) locked ``src/app.py`` and the check went on
    asking for ``link/app.py``.

    ``path`` is read as ``lock_key`` reads it first (a backslash is a
    separator, a leading ``./`` is dropped), so a path that is no key there
    (absolute, climbing out with ``..``, empty) is none here either, and
    neither is one whose links lead out of ``source_dir``. A path that names no
    existing file keeps its spelling, so a pattern or a file that is gone is
    looked up as written.
    """
    key = lock_key(path)
    if key is None:
        return None
    try:
        root = Path(source_dir).resolve()
        relative = (root / key).resolve().relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return None
    return lock_key(relative.as_posix())


def file_is_gone(source_dir: Path | str, path: Any) -> bool:
    """Whether the file a suppression's ``path`` names under ``source_dir`` no
    longer exists.

    Read with ``os.path.lexists``: a symbolic link that exists counts as
    existing, whether or not its target does. A file that exists but cannot be
    hashed (unreadable, not a regular file, larger than
    ``MAX_LOCKED_FILE_BYTES``, or a link that leads out of the root) is not
    gone. Its entry stays and the advice is to fix the file, where a gone
    file's advice is to drop its entry and remove its suppressions. A path
    that cannot be a lock key (``lock_key``) is never called gone, and neither
    is a pattern or a directory spelling (a glob character, a trailing
    separator), which names no one file to be gone.
    """
    key = lock_key(path)
    if key is None:
        return False
    if any(character in path for character in "*?[") or path.endswith(("/", "\\")):
        return False
    return not os.path.lexists(Path(source_dir) / key)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_line_endings(data: bytes) -> bytes:
    """CRLF and lone CR rewritten to LF, nothing else.

    Meaning-preserving in every language the lock digests: Python's tokenizer,
    ECMAScript's line terminators and template literals, and Java's line
    terminators and text blocks all read CR and CRLF as LF.
    """
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def source_sha256(raw: bytes) -> str:
    """The anchor of a tree entry: SHA-256 of ``raw`` with its line endings
    normalized (``normalize_line_endings``) and a leading byte order mark kept,
    since the mark changes how javac reads a file and pairs with a Python
    encoding declaration."""
    return hashlib.sha256(normalize_line_endings(raw)).hexdigest()


#: How a locked file is opened. ``O_NONBLOCK`` (absent on Windows, which has no
#: FIFO to wait on) keeps the open of a FIFO from waiting for a writer, so what
#: the name holds is judged on the descriptor before any byte is read.
#: ``O_BINARY`` is Windows' mode without newline translation, and 0 elsewhere.
_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)


def read_bounded(path: Path) -> bytes:
    """The bytes of the regular file ``path``, at most ``MAX_LOCKED_FILE_BYTES``.

    The one read every lock check and every analysis makes: the file is
    opened once without waiting (``_OPEN_FLAGS``), checked as a regular file on
    the open descriptor before a byte is read, and read with a bound, so a file
    that grows during the read is refused rather than read past the bound. A
    FIFO, a device or a directory at the name is refused at once, where an open
    that waited for a writer held the command until one came. Raises OSError, or
    ValueError naming why the file is refused.
    """
    descriptor = os.open(path, _OPEN_FLAGS)
    try:
        if not stat_module.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("not a regular file")
        if hasattr(os, "O_NONBLOCK"):
            # O_NONBLOCK was for the open. A regular file is then read
            # normally: on some file systems a non-blocking read of one can
            # return early.
            os.set_blocking(descriptor, True)
        handle = os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise
    with handle:
        data = handle.read(MAX_LOCKED_FILE_BYTES + 1)
    if len(data) > MAX_LOCKED_FILE_BYTES:
        raise ValueError(f"larger than {MAX_LOCKED_FILE_BYTES // (1024 * 1024)} MiB")
    return data


def locked_file_bytes(source_dir: Path | str, key: str) -> Optional[bytes]:
    """The bytes of ``key`` under ``source_dir``, or None.

    None when the file is missing, is not a regular file, lies outside the
    source directory once links are followed, is larger than
    ``MAX_LOCKED_FILE_BYTES`` or cannot be read. Callers treat None as "this
    file cannot be checked", so a suppression bound to it stays inert.
    """
    try:
        root = Path(source_dir).resolve()
        target = (root / key).resolve()
        if not target.is_relative_to(root):
            return None
        return read_bounded(target)
    except (OSError, RuntimeError, ValueError):
        return None


def file_sha256(source_dir: Path, key: str) -> Optional[str]:
    """SHA-256 of the bytes of ``key`` under ``source_dir``, or None
    (``locked_file_bytes``): what a version 1 entry records."""
    data = locked_file_bytes(source_dir, key)
    return None if data is None else hashlib.sha256(data).hexdigest()


class LockedFile:
    """One read of one locked file, and what a check needs from it.

    Every check of a file (one ``bind``, one ``refresh`` of it, one resolver's
    view of it) reads it once through this, so the lock state and the spans a
    finding is checked against come from the same bytes. The analysis
    (``symbol_spans.analyze``) is made on first use.
    """

    __slots__ = ("key", "raw", "_raw_sha256", "_anchor", "_analysis")

    def __init__(self, key: str, raw: Optional[bytes]) -> None:
        self.key = key
        self.raw = raw
        self._raw_sha256: Optional[str] = None
        self._anchor: Optional[str] = None
        self._analysis: Any = None

    @classmethod
    def load(cls, source_dir: Path | str, key: str) -> "LockedFile":
        return cls(key, locked_file_bytes(source_dir, key))

    @property
    def raw_sha256(self) -> Optional[str]:
        if self.raw is None:
            return None
        if self._raw_sha256 is None:
            self._raw_sha256 = hashlib.sha256(self.raw).hexdigest()
        return self._raw_sha256

    @property
    def anchor(self) -> Optional[str]:
        if self.raw is None:
            return None
        if self._anchor is None:
            self._anchor = source_sha256(self.raw)
        return self._anchor

    def analysis(self) -> Any:
        if self._analysis is None:
            # Imported here: symbol_spans imports this module at module level.
            from automated_security_helper.utils.symbol_spans import analyze

            if self.raw is None:
                # Callers read the state of an unread file as missing first;
                # one that does not is told the file cannot be digested.
                raise DigestUnavailable("the file cannot be read")
            self._analysis = analyze(self.raw, self.key)
        return self._analysis


def _kind_value(kind: Any) -> Optional[str]:
    if kind is None:
        return None
    value = kind.value if isinstance(kind, InvalidationScope) else str(kind)
    if value not in _KINDS:
        raise AshLockError(
            f"invalidation scope {value!r} is not one of {', '.join(sorted(_KINDS))}"
        )
    return value


def _converted_scopes(scopes: Iterable[LockScope]) -> List[LockScope]:
    """A version 1 entry's scopes as tree-entry scopes: each ``file``, and
    case-variant duplicates collapsed to one."""
    seen: set = set()
    converted: List[LockScope] = []
    for scope in sorted(scopes):
        identity = (scope.rule_id.casefold(), scope.symbol)
        if identity in seen:
            continue
        seen.add(identity)
        converted.append(
            LockScope(scope.rule_id, scope.symbol, InvalidationScope.FILE.value)
        )
    return converted


def recorded_scope(
    entry: LockEntry, rule_id: Optional[str], symbol: str
) -> Optional[LockScope]:
    """The scope of ``entry`` for ``(rule_id, symbol)``, or None.

    The rule id is compared case-insensitively, as suppression rule ids match
    everywhere else; the symbol is exact, as symbol resolution is.
    """
    wanted = (rule_id or "").casefold()
    for scope in entry.scopes:
        if scope.rule_id.casefold() == wanted and scope.symbol == symbol:
            return scope
    return None


def _digest_failure(exc: BaseException) -> str:
    return f"the digest could not be computed ({type(exc).__name__}: {exc})"


def _grammar_changed(grammar: LockGrammar, identity: Any) -> str:
    recorded = f"{grammar.language} {grammar.distribution}"
    running = f"{identity.language} {identity.distribution}"
    if recorded == running:
        running += " with other grammar tables"
    return (
        f"the file changed and its grammar changed (recorded {recorded}, running "
        f"{running}), so the change cannot be compared"
    )


def _file_level(entry: LockEntry, locked: LockedFile) -> Optional[ScopeState]:
    """The state every scope of ``entry`` shares, or None when each scope's
    own digest decides (the file changed and can be digested)."""
    if locked.raw is None:
        return _MISSING
    if entry.is_legacy:
        if locked.raw_sha256 == entry.sha256:
            return _OK
        return ScopeState("stale", VERSION_1_REASON)
    if locked.anchor == entry.source_sha256:
        return _OK
    if entry.algorithm != ALGORITHM:
        return ScopeState(
            "unverifiable",
            f"its entry was written with digest {entry.algorithm}, which this ASH "
            "does not compute",
        )
    try:
        analysis = locked.analysis()
        analysis.require_digestible()
        identity = analysis.identity()
    except DigestUnavailable as exc:
        return ScopeState("unverifiable", str(exc))
    except Exception as exc:  # noqa: BLE001 - a binding error fails closed
        return ScopeState("unverifiable", _digest_failure(exc))
    grammar = entry.grammar
    if grammar is None:
        # The reader refuses a tree entry without one; fail closed regardless.
        return ScopeState("unverifiable", "its entry records no grammar")
    if (
        identity.language != grammar.language
        or identity.fingerprint != grammar.fingerprint
    ):
        return ScopeState("stale", _grammar_changed(grammar, identity))
    return None


def _digest_state(entry: LockEntry, scope: LockScope, locked: LockedFile) -> ScopeState:
    """A scope's state from its own digest, the file being digestible."""
    analysis = locked.analysis()
    try:
        if scope.invalidation_scope == InvalidationScope.SYMBOL.value:
            digest = analysis.symbol_digest(scope.symbol)
            if digest is None:
                return ScopeState(
                    "gone", f"the file no longer defines {scope.symbol}", True
                )
            if digest == entry.symbol_digests.get(scope.symbol):
                return _OK
            return ScopeState("stale", f"{scope.symbol} changed", True)
        if analysis.file_digest() == entry.file_digest:
            return _OK
        return ScopeState("stale")
    except DigestUnavailable as exc:
        return ScopeState("unverifiable", str(exc))
    except Exception as exc:  # noqa: BLE001 - a binding error fails closed
        return ScopeState("unverifiable", _digest_failure(exc))


def check_scope(entry: LockEntry, scope: LockScope, locked: LockedFile) -> ScopeState:
    """The state of ``scope`` of ``entry`` against one read of its file.

    In order: a file that cannot be read is ``missing``; a version 1 entry is
    current while the raw bytes hash to it; a tree entry is current while the
    bytes, line endings normalized, hash to its anchor, under any grammar; a
    changed file that cannot be digested, or whose entry another algorithm
    wrote, is ``unverifiable``; one whose grammar tables are not the recorded
    ones is ``stale``; otherwise the scope's own digest (the file's or the
    symbol's) decides, and a symbol the file no longer defines is ``gone``.
    """
    level = _file_level(entry, locked)
    if level is not None:
        return level
    return _digest_state(entry, scope, locked)


_SEVERITY = ("unverifiable", "stale", "gone")


def scopes_of_problem(
    entry: LockEntry, symbol: Optional[str], state: ScopeState
) -> List[LockScope]:
    """The scopes a problem covers: those of one symbol for a symbol-scope
    problem, the file-scope ones for a file digest that changed, every scope
    for a cause the whole file shares."""
    if symbol is not None:
        return [
            s
            for s in entry.scopes
            if s.symbol == symbol
            and s.invalidation_scope == InvalidationScope.SYMBOL.value
        ]
    if entry.is_legacy or state.state != "stale" or state.reason:
        return list(entry.scopes)
    return [
        s
        for s in entry.scopes
        if s.invalidation_scope != InvalidationScope.SYMBOL.value
    ]


class _RepeatedKey(ValueError):
    """An object of the lock writes one key more than once. ``str`` of it names
    the key and the object that holds it."""


class _RepeatSignal(Exception):
    """Raised by the fast parse when an object holds a repeated key."""


class _Pairs(dict):
    """A JSON object read with its pairs kept in order, repeats included: a
    dict keeps only the last of two equal keys."""

    def __init__(self, pairs: List[Tuple[str, Any]]) -> None:
        super().__init__(pairs)
        self.pairs = list(pairs)


def _dict_unless_repeated(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise _RepeatSignal
    return result


def _pointer_segment(key: str) -> str:
    """``key`` as one RFC 6901 pointer segment, as written.

    A message quotes a lock's key as written, as ``refusal_text`` quotes a
    path: the sink that prints it escapes a control character
    (``utils/terminal_text``), and an escape written here would be escaped
    again there, so one ESC would read with its backslash doubled.
    """
    return key.replace("~", "~0").replace("/", "~1")


def _first_repeated_key(document: Any) -> Optional[Tuple[str, str]]:
    """The first key any object of ``document`` (read with ``_Pairs``) writes
    more than once, as ``(key, pointer)``, or None.

    An object's own keys are checked first, then each value in the order
    written, list items in order. The pointer (RFC 6901) is that of the object
    that holds the key twice, empty for the top level.
    """
    stack: List[Tuple[Any, str]] = [(document, "")]
    while stack:
        node, pointer = stack.pop()
        if isinstance(node, _Pairs):
            keys = [key for key, _ in node.pairs]
            counts: Dict[str, int] = {}
            for key in keys:
                counts[key] = counts.get(key, 0) + 1
            for key in keys:
                if counts[key] > 1:
                    return key, pointer
            children = [
                (value, f"{pointer}/{_pointer_segment(key)}")
                for key, value in node.pairs
            ]
        elif isinstance(node, list):
            children = [
                (value, f"{pointer}/{index}") for index, value in enumerate(node)
            ]
        else:
            continue
        stack.extend(reversed(children))
    return None


def _loads_refusing_repeated_keys(text: str) -> Any:
    """``json.loads`` that raises ``_RepeatedKey`` when any object in ``text``
    writes a key more than once.

    Python's JSON reader keeps only the last of two equal keys, so a lock that
    repeated a file key would read as its second block alone, and the next save
    would write it without the first block's scopes, digests and date. Every
    other error propagates as ``json.loads`` raises it. The result equals
    ``json.loads(text)`` for every document with no repeat.
    """
    try:
        return json.loads(text, object_pairs_hook=_dict_unless_repeated)
    except _RepeatSignal:
        pass
    found = _first_repeated_key(json.loads(text, object_pairs_hook=_Pairs))
    if found is None:
        raise _RepeatedKey("an object writes a key more than once") from None
    key, pointer = found
    where = "at the top level" if not pointer else f"in the object at {pointer}"
    raise _RepeatedKey(f"key '{key}' appears more than once {where}") from None


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
        The file is read through ``read_bounded``, so a FIFO, a device or a
        directory at the lock's name is refused at once, where an open that
        waited for a writer held the command until one came.

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
            raw = read_bounded(path)
        except FileNotFoundError:
            return lock
        except ValueError as e:
            # Not a regular file, or larger than the bound: what read_bounded
            # refuses, worded as the reason the lock cannot be read.
            raise AshLockError(f"{shown} cannot be read: it is {e}") from None
        except OSError as e:
            raise AshLockError(f"{shown} cannot be read: {e}") from None
        try:
            document = _loads_refusing_repeated_keys(raw.decode("utf-8"))
        except _RepeatedKey as e:
            # A repeated key would keep only the last block, and the next save
            # would write the lock without the first one.
            raise AshLockError(
                f"{shown}: {e}; a lock that repeats a key is not read: merge the "
                "two entries for that file into one"
            ) from None
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
        """Write the lock through a staged file that replaces it in one step."""
        path = self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        staged = path.with_name(path.name + f".{os.getpid()}.tmp")
        try:
            staged.write_text(self.to_text(), encoding="utf-8", newline="\n")
            os.replace(staged, path)
        finally:
            if staged.exists():
                staged.unlink()

    def locked_file(self, key: str) -> LockedFile:
        """One read of the locked file ``key``."""
        return LockedFile.load(self.source_dir, key)

    def _snapshot(
        self,
        key: str,
        locked: LockedFile,
        scopes: Sequence[LockScope],
        *,
        created: str,
    ) -> Tuple[LockEntry, Tuple[str, ...]]:
        """A tree entry for ``scopes`` from one read: the anchor, the file
        digest, the grammar's identity and a digest for each symbol-scoped
        symbol. Returns the entry and the symbol-scoped symbols the file does
        not define (left out of the entry's digests).

        Raises AshLockError naming the file and why when it cannot be digested;
        a missing extra's reason carries the install command.
        """
        try:
            analysis = locked.analysis()
            analysis.require_digestible()
            identity = analysis.identity()
            file_digest = analysis.file_digest()
            symbols: Dict[str, str] = {}
            gone: List[str] = []
            for scope in scopes:
                if scope.invalidation_scope != InvalidationScope.SYMBOL.value:
                    continue
                if scope.symbol in symbols or scope.symbol in gone:
                    continue
                digest = analysis.symbol_digest(scope.symbol)
                if digest is None:
                    gone.append(scope.symbol)
                else:
                    symbols[scope.symbol] = digest
        except DigestUnavailable as exc:
            raise AshLockError(f"{key} cannot be locked: {exc}") from None
        except AshLockError:
            raise
        except Exception as exc:  # noqa: BLE001 - a binding error fails closed
            raise AshLockError(
                f"{key} cannot be locked: {_digest_failure(exc)}"
            ) from None
        anchor = locked.anchor
        if anchor is None:
            raise AshLockError(f"{key} is not a readable file inside the scan root")
        entry = LockEntry(
            created=created,
            scopes=sorted(scopes),
            source_sha256=anchor,
            algorithm=ALGORITHM,
            file_digest=file_digest,
            symbol_digests=symbols,
            grammar=LockGrammar(
                language=identity.language,
                fingerprint=identity.fingerprint,
                distribution=identity.distribution,
                tree_sitter=identity.tree_sitter,
            ),
        )
        return entry, tuple(gone)

    def bind(
        self,
        key: str,
        scope: LockScope,
        *,
        invalidation_scope: Any = None,
        now: Optional[str] = None,
    ) -> LockEntry:
        """Lock ``key`` from one read of it and bind ``scope`` to it.

        The kind of a new scope is ``invalidation_scope`` (or the scope's own),
        ``file`` when neither says. A new file gets a tree entry. A version 1
        entry whose raw bytes still match is converted (its scopes become
        ``file``) and gains the scope. A tree entry gains it only while every
        scope it already records is current; then it is re-snapshotted from
        this read, which re-approves nothing, since every digest it rewrites
        equals the one it replaces. A file whose recorded scopes are not all
        current is refused (``AshLockError``) naming the refresh, or for a
        symbol the file no longer defines the drop that clears it: only a
        deliberate review re-binds them.

        A scope the entry already records is not added again, a rule id that
        differs only in case included, and leaves the entry as it was; asking
        for it with another kind is refused naming the conversion. A symbol
        scope for a symbol the file does not define is refused; a file scope
        binds it.

        Writing needs a digest, so a file that cannot be digested (no grammar
        for its extension, the ``symbols`` extra missing, a parse error) is
        refused too.
        """
        requested = _kind_value(
            invalidation_scope
            if invalidation_scope is not None
            else scope.invalidation_scope
        )
        locked = self.locked_file(key)
        if locked.raw is None:
            raise AshLockError(f"{key} is not a readable file inside the scan root")
        entry = self.entries.get(key)
        if entry is None:
            kind = requested or InvalidationScope.FILE.value
            built, gone = self._snapshot(
                key,
                locked,
                [LockScope(scope.rule_id, scope.symbol, kind)],
                created=now or _utc_now(),
            )
            if gone:
                raise AshLockError(_undefined(key, gone[0]))
            self.entries[key] = built
            return built
        converted = entry.is_legacy
        if converted:
            if locked.raw_sha256 != entry.sha256:
                raise AshLockError(
                    f"{key} changed since it was locked; review its suppressions, "
                    f"then run `{REFRESH_COMMAND} {shlex.quote(key)}` before adding "
                    "another"
                )
            current = _converted_scopes(entry.scopes)
        else:
            for recorded in entry.scopes:
                state = check_scope(entry, recorded, locked)
                if state.state != "ok":
                    why = f": {state.reason}" if state.reason else ""
                    if state.state == "gone":
                        # A plain refresh of a gone symbol exits 1 and changes
                        # nothing, so the way out is the drop, in its order.
                        next_step = gone_symbol_advice(key)
                    else:
                        next_step = (
                            f"review them, then run `{REFRESH_COMMAND} "
                            f"{shlex.quote(key)}` before adding another"
                        )
                    raise AshLockError(
                        f"{key} changed since its suppressions were reviewed "
                        f"({recorded.describe_with_kind()} is {state.state}{why}); "
                        f"{next_step}"
                    )
            current = list(entry.scopes)
        recorded = _find(current, scope.rule_id, scope.symbol)
        if recorded is not None:
            if requested is not None and requested != recorded.invalidation_scope:
                raise AshLockError(
                    f"{recorded.describe()} is recorded for {key} with "
                    f"invalidation scope {recorded.invalidation_scope}; change it "
                    f"after review with `{REFRESH_COMMAND} --invalidation-scope "
                    f"{requested} --symbol {shlex.quote(scope.symbol)} "
                    f"{shlex.quote(key)}`"
                )
            if not converted:
                return entry
            additions: List[LockScope] = []
        else:
            additions = [
                LockScope(
                    scope.rule_id,
                    scope.symbol,
                    requested or InvalidationScope.FILE.value,
                )
            ]
        built, gone = self._snapshot(
            key, locked, current + additions, created=entry.created
        )
        if gone:
            raise AshLockError(_undefined(key, gone[0]))
        self.entries[key] = built
        return built

    def review(
        self,
        key: str,
        *,
        invalidation_scope: Any = None,
        symbol: Optional[str] = None,
        drop_gone: bool = False,
    ) -> RefreshOutcome:
        """Record a new review of one locked file: re-bind every scope of it
        from one read, converting a version 1 entry.

        ``invalidation_scope`` sets the kind of the selected scopes: every
        scope, or those of ``symbol``. An entry whose bytes did not change and
        whose kinds stay is ``unchanged`` and not rewritten; a version 1 entry
        whose bytes still match is ``upgraded``. A symbol scope whose symbol the
        file no longer defines leaves the whole entry as it was (``gone``),
        unless ``drop_gone``, which drops that scope and the entry with its
        last one. A file that cannot be read is ``missing`` and one that
        changed and cannot be digested ``unverifiable``; both are left as they
        were.
        """
        entry = self.entries[key]
        kind = _kind_value(invalidation_scope)
        old = entry.anchor
        scopes = (
            _converted_scopes(entry.scopes) if entry.is_legacy else list(entry.scopes)
        )
        if symbol is not None and not any(s.symbol == symbol for s in scopes):
            raise AshLockError(f"{key} records no suppression scoped to {symbol}")
        kind_changed = False
        if kind is not None:
            updated = []
            for scope in scopes:
                if symbol is None or scope.symbol == symbol:
                    if scope.invalidation_scope != kind:
                        kind_changed = True
                    scope = replace(scope, invalidation_scope=kind)
                updated.append(scope)
            scopes = updated
        locked = self.locked_file(key)
        if locked.raw is None:
            return RefreshOutcome(key, "missing", old, None)
        unchanged_bytes = (
            locked.raw_sha256 == entry.sha256
            if entry.is_legacy
            else locked.anchor == entry.source_sha256
        )
        if entry.is_legacy and unchanged_bytes and kind is not None:
            # The legacy kinds were never chosen, so naming one converts.
            kind_changed = True
        if unchanged_bytes and not kind_changed:
            if not entry.is_legacy:
                return RefreshOutcome(key, "unchanged", old, old)
            try:
                built, gone = self._snapshot(key, locked, scopes, created=entry.created)
            except AshLockError:
                # No digest without the extra: the bytes are the reviewed ones,
                # so the entry is current as it is.
                return RefreshOutcome(key, "unchanged", old, old)
            self.entries[key] = built
            return RefreshOutcome(key, "upgraded", old, built.source_sha256)
        try:
            built, gone = self._snapshot(key, locked, scopes, created=entry.created)
        except AshLockError as exc:
            return RefreshOutcome(key, "unverifiable", old, None, reason=str(exc))
        dropped: Tuple[LockScope, ...] = ()
        if gone:
            if not drop_gone:
                return RefreshOutcome(key, "gone", old, None, gone=gone)
            dropped = tuple(
                s
                for s in scopes
                if s.invalidation_scope == InvalidationScope.SYMBOL.value
                and s.symbol in gone
            )
            kept = [s for s in scopes if s not in dropped]
            if not kept:
                del self.entries[key]
                return RefreshOutcome(
                    key, "dropped", old, None, gone=gone, dropped=dropped
                )
            built, _ = self._snapshot(key, locked, kept, created=entry.created)
        self.entries[key] = built
        state = "converted" if unchanged_bytes else "refreshed"
        return RefreshOutcome(
            key, state, old, built.source_sha256, gone=gone, dropped=dropped
        )

    def refresh(self, key: str) -> Tuple[Optional[str], Optional[str]]:
        """Re-bind one locked file (``review``). Returns ``(old, new)``, the
        anchors before and after; ``new`` is None when the file was left as it
        was (missing, a gone symbol, or a change that cannot be digested)."""
        outcome = self.review(key)
        if outcome.state in ("refreshed", "converted", "unchanged", "upgraded"):
            return outcome.old, outcome.new
        return outcome.old, None

    def migrate(self) -> List[MigrateOutcome]:
        """Convert every version 1 entry whose raw bytes still match.

        A converted entry approves nothing: the bytes present are the bytes
        reviewed. A stale entry is left as written (its change needs a review,
        ``refresh``), and so are one whose file cannot be read and one that
        cannot be digested. Never re-hashes a changed file.
        """
        outcomes: List[MigrateOutcome] = []
        converted: Dict[str, LockEntry] = {}
        for key in sorted(self.entries):
            entry = self.entries[key]
            if not entry.is_legacy:
                continue
            locked = self.locked_file(key)
            if locked.raw is None:
                outcomes.append(MigrateOutcome(key, "missing"))
                continue
            if locked.raw_sha256 != entry.sha256:
                outcomes.append(MigrateOutcome(key, "stale", VERSION_1_REASON))
                continue
            try:
                built, _ = self._snapshot(
                    key, locked, _converted_scopes(entry.scopes), created=entry.created
                )
            except AshLockError as exc:
                outcomes.append(MigrateOutcome(key, "unverifiable", str(exc)))
                continue
            converted[key] = built
            outcomes.append(MigrateOutcome(key, "migrated"))
        self.entries.update(converted)
        return outcomes

    def drop(self, key: str) -> None:
        """Remove one entry: the way out for a locked file that is gone.

        ``refresh`` cannot cure a ``missing`` entry (there are no bytes to
        hash), so without this the only remedy was hand-editing the file the
        module docstring says only the commands write.
        """
        del self.entries[key]

    def scope_state(
        self, key: str, scope: LockScope, locked: Optional[LockedFile] = None
    ) -> ScopeState:
        """The state of one recorded scope (``check_scope``), from ``locked``
        or a fresh read."""
        if locked is None:
            locked = self.locked_file(key)
        return check_scope(self.entries[key], scope, locked)

    def status(self, key: str) -> str:
        """``"unlocked"`` (no entry), ``"missing"`` (the file cannot be read),
        ``"ok"``, or the most severe state of its scopes: ``"unverifiable"``,
        then ``"stale"``, then ``"gone"``."""
        entry = self.entries.get(key)
        if entry is None:
            return "unlocked"
        locked = self.locked_file(key)
        level = _file_level(entry, locked)
        if level is not None:
            return level.state
        scopes = entry.scopes or [LockScope("", "", InvalidationScope.FILE.value)]
        states = {_digest_state(entry, s, locked).state for s in scopes}
        for state in _SEVERITY:
            if state in states:
                return state
        return "ok"

    def problems(self) -> List[LockProblem]:
        """Every problem with the lock, by path: one per file for a file-scope or
        version 1 entry and for a cause the whole file shares (missing,
        unverifiable, its grammar changed), one per symbol for a symbol scope."""
        found: List[LockProblem] = []
        for key in sorted(self.entries):
            found.extend(
                self._problems_of(key, self.entries[key], self.locked_file(key))
            )
        return found

    def _problems_of(
        self, key: str, entry: LockEntry, locked: LockedFile
    ) -> List[LockProblem]:
        level = _file_level(entry, locked)
        if level is not None:
            if level.state == "ok":
                return []
            return [
                LockProblem(
                    key, level.state, tuple(sorted(entry.scopes)), None, level.reason
                )
            ]
        found: List[LockProblem] = []
        file_scopes = [
            s
            for s in entry.scopes
            if s.invalidation_scope != InvalidationScope.SYMBOL.value
        ]
        if file_scopes or not entry.scopes:
            state = _digest_state(
                entry, LockScope("", "", InvalidationScope.FILE.value), locked
            )
            if state.state != "ok":
                found.append(
                    LockProblem(
                        key, state.state, tuple(sorted(file_scopes)), None, state.reason
                    )
                )
        symbols = sorted(
            {
                s.symbol
                for s in entry.scopes
                if s.invalidation_scope == InvalidationScope.SYMBOL.value
            }
        )
        for name in symbols:
            of_symbol = [
                s
                for s in entry.scopes
                if s.symbol == name
                and s.invalidation_scope == InvalidationScope.SYMBOL.value
            ]
            state = _digest_state(entry, of_symbol[0], locked)
            if state.state != "ok":
                found.append(
                    LockProblem(
                        key, state.state, tuple(sorted(of_symbol)), name, state.reason
                    )
                )
        return found


def _find(
    scopes: Iterable[LockScope], rule_id: str, symbol: str
) -> Optional[LockScope]:
    wanted = (rule_id or "").casefold()
    for scope in scopes:
        if scope.rule_id.casefold() == wanted and scope.symbol == symbol:
            return scope
    return None


def _undefined(key: str, symbol: str) -> str:
    return (
        f"{key} defines no {symbol}, so a symbol-scoped suppression has no "
        "definition to bind to; check the name, or record it with "
        "--invalidation-scope file"
    )


def _unknown_keys(where: str, what: str, value: Dict[str, Any], allowed: set) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        # Quoted as written; _pointer_segment says why.
        keys = ", ".join(f"'{key}'" for key in unknown)
        raise AshLockError(
            f"{where} has an unknown key {keys} in "
            f"{what}; a lock with a key this ASH does not know was written by a "
            "newer ASH, so it is not read"
        )


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _legacy_entry(where: str, key: str, raw: Dict[str, Any], strict: bool) -> LockEntry:
    if strict:
        _unknown_keys(where, f"the entry for {key}", raw, _LEGACY_ENTRY_KEYS)
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
        if strict:
            _unknown_keys(where, f"a scope of {key}", scope, _LEGACY_SCOPE_KEYS)
        parsed.append(LockScope(scope.get("rule_id", ""), scope["symbol"]))
    return LockEntry(created=created, scopes=sorted(parsed), sha256=digest)


def _tree_entry(where: str, key: str, raw: Dict[str, Any]) -> LockEntry:
    _unknown_keys(where, f"the entry for {key}", raw, _TREE_ENTRY_KEYS)
    created = raw.get("created")
    anchor = raw.get("source_sha256")
    digests = raw.get("digests")
    grammar = raw.get("grammar")
    scopes = raw.get("scopes")
    if (
        not isinstance(created, str)
        or not _is_hex64(anchor)
        or not isinstance(digests, dict)
        or not isinstance(grammar, dict)
        or not isinstance(scopes, list)
    ):
        raise AshLockError(f"{where} has a malformed entry for {key}")
    _unknown_keys(where, f"the digests of {key}", digests, _DIGEST_KEYS)
    _unknown_keys(where, f"the grammar of {key}", grammar, _GRAMMAR_KEYS)
    algorithm = digests.get("algorithm")
    file_digest = digests.get("file")
    symbols = digests.get("symbols")
    if (
        not isinstance(algorithm, str)
        or not algorithm
        or not _is_hex64(file_digest)
        or not isinstance(symbols, dict)
        or not all(isinstance(k, str) and _is_hex64(v) for k, v in symbols.items())
    ):
        raise AshLockError(f"{where} has malformed digests for {key}")
    if (
        not all(isinstance(grammar.get(k), str) for k in _GRAMMAR_KEYS)
        or not grammar.get("language")
        or not _is_hex64(grammar.get("fingerprint"))
    ):
        raise AshLockError(f"{where} has a malformed grammar for {key}")
    parsed: List[LockScope] = []
    seen: set = set()
    for scope in scopes:
        if not isinstance(scope, dict):
            raise AshLockError(f"{where} has a malformed scope for {key}")
        _unknown_keys(where, f"a scope of {key}", scope, _TREE_SCOPE_KEYS)
        rule_id = scope.get("rule_id")
        symbol = scope.get("symbol")
        kind = scope.get("invalidation_scope")
        if not isinstance(rule_id, str) or not isinstance(symbol, str):
            raise AshLockError(f"{where} has a malformed scope for {key}")
        if kind not in _KINDS:
            raise AshLockError(
                f"{where} has a scope for {key} without a valid invalidation scope "
                f"(one of {', '.join(sorted(_KINDS))})"
            )
        identity = (rule_id.casefold(), symbol)
        if identity in seen:
            raise AshLockError(f"{where} records {rule_id} in {symbol} twice for {key}")
        seen.add(identity)
        parsed.append(LockScope(rule_id, symbol, kind))
    symbol_scoped = {
        s.symbol
        for s in parsed
        if s.invalidation_scope == InvalidationScope.SYMBOL.value
    }
    if set(symbols) != symbol_scoped:
        raise AshLockError(
            f"{where} has symbol digests for {key} that do not match its "
            "symbol-scoped suppressions"
        )
    return LockEntry(
        created=created,
        scopes=sorted(parsed),
        source_sha256=anchor,
        algorithm=algorithm,
        file_digest=file_digest,
        symbol_digests=dict(symbols),
        grammar=LockGrammar(
            language=grammar["language"],
            fingerprint=grammar["fingerprint"],
            distribution=grammar["distribution"],
            tree_sitter=grammar["tree_sitter"],
        ),
    )


def _has_version_2_fields(raw: Dict[str, Any]) -> bool:
    scopes = raw.get("scopes")
    return any(k in raw for k in _VERSION_2_ENTRY_FIELDS) or (
        isinstance(scopes, list)
        and any(isinstance(s, dict) and "invalidation_scope" in s for s in scopes)
    )


def _is_tree_entry(raw: Dict[str, Any]) -> Optional[bool]:
    """True for a tree entry, False for a version 1 entry, None for neither."""
    tree_fields = [k for k in _VERSION_2_ENTRY_FIELDS if k in raw]
    scopes = raw.get("scopes")
    kinds = (
        [isinstance(s, dict) and "invalidation_scope" in s for s in scopes]
        if isinstance(scopes, list)
        else []
    )
    if "sha256" in raw and not tree_fields and not any(kinds):
        return False
    if len(tree_fields) == len(_VERSION_2_ENTRY_FIELDS) and "sha256" not in raw:
        if all(kinds):
            return True
    return None


def _entries_of(document: Any, where: str = LOCK_RELATIVE_PATH) -> Dict[str, LockEntry]:
    """The entries of a parsed lock; ``where`` names the file in a refusal.

    The version is compared by type, so ``true`` and ``1.0`` are refused: in
    Python ``True == 1``. A version 1 document holds version 1 entries only and
    its unknown keys are ignored, as they always were. A version 2 document is
    strict: an unknown key anywhere is refused, since an older writer that
    dropped keys would otherwise erase a newer writer's choices.
    """
    version = document.get("version") if isinstance(document, dict) else None
    if type(version) is not int or version not in READABLE_LOCK_VERSIONS:
        raise AshLockError(f"{where} is not a version 1 or 2 lock file")
    strict = version == 2
    if strict:
        _unknown_keys(where, "the document", document, _DOCUMENT_KEYS)
    files = document.get("files")
    if not isinstance(files, dict):
        raise AshLockError(f"{where} has no 'files' mapping")
    entries: Dict[str, LockEntry] = {}
    for key, raw in files.items():
        if lock_key(key) != key or not isinstance(raw, dict):
            raise AshLockError(f"{where} has a malformed entry for a file")
        if not strict and _has_version_2_fields(raw):
            raise AshLockError(
                f"{where} is a version 1 lock file but its entry for {key} has "
                "version 2 fields"
            )
        kind = _is_tree_entry(raw)
        if kind is None:
            raise AshLockError(
                f"{where} has an entry for {key} that is neither a version 1 entry "
                "nor a tree entry"
            )
        entries[key] = (
            _tree_entry(where, key, raw)
            if kind
            else _legacy_entry(where, key, raw, strict)
        )
    return entries


def add_command_for(rule_id: Any, symbol: str, path: str) -> str:
    """The ``ash suppress add`` line that locks one suppression.

    Every value is shell-quoted: the rule id, symbol and path come from the
    config, which a pull request controls, so an unquoted ``x; curl ... | sh``
    in a path would run something else when a maintainer pastes the suggested
    command from CI output. A rule id that is not a string (an unquoted
    ``rule_id: 602`` read from YAML) is written as its text: ``shlex.quote``
    takes only a string, and raised ``TypeError`` on it.
    """
    if isinstance(rule_id, str):
        rule = rule_id
    else:
        rule = "" if rule_id is None else str(rule_id)
    return (
        f"ash suppress add {shlex.quote(rule or '<rule-id>')} "
        f"--symbol {shlex.quote(symbol)} --file {shlex.quote(path)} "
        f"--reason '<why this is safe>'"
    )


def symbol_suppressions(suppressions: Iterable[Any]) -> List[Any]:
    """The suppressions that set ``symbol``."""
    return [s for s in suppressions or [] if getattr(s, "symbol", None)]


def scope_is_recorded(entry: LockEntry, rule_id: Optional[str], symbol: str) -> bool:
    """Whether ``entry`` records the scope ``(rule_id, symbol)``
    (``recorded_scope``)."""
    return recorded_scope(entry, rule_id, symbol) is not None


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

    The file is looked up under ``resolved_lock_key``, the key ``add`` writes
    and a scan reads: a path through a symbolic link is found under the file
    it leads to.
    """
    missing = []
    for suppression in symbol_suppressions(suppressions):
        key = resolved_lock_key(
            lock.source_dir, getattr(suppression, "path", None) or ""
        )
        entry = lock.entries.get(key) if key is not None else None
        if entry is None or not scope_is_recorded(
            entry, getattr(suppression, "rule_id", None), suppression.symbol
        ):
            missing.append(suppression)
    return missing


def refusal_text(
    unlocked: Sequence[Any], source_dir: Optional[Path | str] = None
) -> str:
    """The validation message for symbol suppressions with no lock entry.

    With ``source_dir``, the scanned directory, a suppression whose file no
    longer exists there (``file_is_gone``) is told to be removed from the
    config rather than given the ``add`` command, which refuses a path that is
    not a file. That is the state ``refresh --drop-missing`` leaves: the entry
    dropped, the suppressions still in the config. Without ``source_dir``
    every suppression that names one file gets the command.

    A path is quoted as written, ``'...'``. The sink that prints the message
    escapes a control character in it (``utils/terminal_text``); a repr had
    escaped it already, and the sink then doubled that escape's backslash.
    """
    lines = [
        (
            f"{len(unlocked)} symbol-scoped suppression(s) are not recorded in "
            f"{LOCK_RELATIVE_PATH}: a symbol suppression is bound, rule and "
            "symbol by name, to the syntax tree of its file or of its symbol as "
            "it was reviewed, so a change to the code or an unreviewed scope is "
            "reviewed again. Run the command for each one, which writes the "
            "suppression and its lock entry together (an entry already in the "
            "config is only locked):"
        )
    ]
    for suppression in unlocked[:10]:
        path = getattr(suppression, "path", "") or "<path>"
        # `ash suppress add` would refuse a path that is not one file, so the
        # command it names cannot work for one; say what can.
        if any(character in path for character in "*?[") or path.endswith("/"):
            lines.append(
                f"  a symbol suppression must name one file; '{path}' is a "
                "pattern or a directory. Name the file that holds the "
                "definition, locking each such file with its own entry."
            )
            continue
        if source_dir is not None and file_is_gone(source_dir, path):
            rule = getattr(suppression, "rule_id", None) or "(any rule)"
            lines.append(
                f"  '{path}' no longer exists, so its suppression ({rule} in "
                f"{suppression.symbol}) cannot be locked: remove it from the config."
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
    suppressions: Iterable[Any],
    source_dir: Path | str,
    *,
    scanned_tree: bool = True,
) -> None:
    """Raise ``ASHConfigValidationError`` for a symbol suppression with no lock entry.

    Nothing is checked when no suppression sets ``symbol``, so a config without
    one never reads the lock. A lock file that cannot be used is the same
    refusal, in its own words. Only the recorded scopes are checked: no file
    is read or parsed here.

    ``scanned_tree`` False says ``source_dir`` is only a guess at the directory
    a scan reads (the config check given no source directory takes the config
    file's own location), so a file missing from it is not called gone, and
    every unrecorded suppression gets the ``add`` command.
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
        raise ASHConfigValidationError(
            refusal_text(unlocked, source_dir if scanned_tree else None)
        )


def gone_symbol_advice(key: str) -> str:
    """The steps that clear a scope whose symbol the file no longer defines, in
    the order that works.

    ``add`` refuses a file while any recorded scope of it is out of date, so the
    old name's record is dropped before a renamed symbol is added; a plain
    refresh of a gone symbol exits 1 and changes nothing. The drop is a refresh,
    so it records the file's other suppressions again from the code as it
    stands, which is why the change is reviewed first. The suppression in the
    config is the user's to rename or remove: the drop leaves it, and a scan
    refuses a config entry the lock does not record.
    """
    return (
        "rename or remove the suppression in the config, review the file's "
        f"change, then run `{REFRESH_COMMAND} --drop-missing {shlex.quote(key)}`, "
        "which records the file's other suppressions again from the code as it "
        "stands, and record a renamed symbol with `ash suppress add`"
    )


def stale_notice(
    key: str,
    entry: LockEntry,
    state: str,
    *,
    gone: bool = True,
    symbol: Optional[str] = None,
    reason: Optional[str] = None,
    scopes: Optional[Sequence[LockScope]] = None,
) -> str:
    """The one notice a scan prints for a recorded scope that is not current.

    A ``stale`` scope has code to review, so the advice is the refresh; a
    ``missing`` file has none, and ``refresh`` on it exits 1 and changes
    nothing, so the advice is the drop. The two used to share the refresh
    advice, which left a deleted file failing ``verify`` forever.

    ``gone`` says whether a ``missing`` file no longer exists
    (``file_is_gone``). One that still exists but cannot be hashed keeps its
    entry, which ``refresh --drop-missing`` does not drop, so its advice is to
    make the file hashable again.

    ``symbol`` names the definition a symbol-scope problem is about (a
    ``stale`` or ``gone`` symbol), ``reason`` says why when there is more to
    say, and ``scopes`` are the suppressions it covers (every scope of the
    entry when not given). A version 1 entry's notice says the entry predates
    syntax-tree digests, so any byte change counts.
    """
    listed = scopes if scopes is not None else entry.scopes
    described = (
        ", ".join(s.describe_with_kind() for s in sorted(listed)) or "none recorded"
    )
    quoted = shlex.quote(key)
    if state == "missing" and gone:
        return (
            f"Stale suppression: {key} no longer exists, so the symbol "
            f"suppressions bound to it do not apply. Suppressions: {described}. "
            f"Drop the dead entry with "
            f"`{REFRESH_COMMAND} --drop-missing {quoted}` and remove "
            f"its suppressions from the config."
        )
    if state == "missing":
        return (
            f"Stale suppression: {key} exists but cannot be hashed (it cannot "
            f"be read, is not a regular file, is larger than "
            f"{MAX_LOCKED_FILE_BYTES // (1024 * 1024)} MiB, or is a link that "
            f"leads out of the scan root), so the symbol suppressions bound to "
            f"it do not apply. Suppressions: {described}. Make it a readable "
            f"regular file inside the scan root, then, after reviewing any "
            f"change, record it with `{REFRESH_COMMAND} {quoted}`."
        )
    if state == "gone":
        return (
            f"Stale suppression: {key} no longer defines {symbol}, so the "
            f"symbol-scoped suppressions bound to it do not apply. Suppressions: "
            f"{described}. To fix this, {gone_symbol_advice(key)}."
        )
    if state == "unverifiable":
        return (
            f"Stale suppression: {key} has changed since its suppressions were "
            f"reviewed and the change cannot be checked ({reason}), so the "
            f"symbol suppressions bound to it do not apply and their findings "
            f"are reported again. Suppressions: {described}. Fix what stops the "
            f"check, or, after reviewing the change, record it with "
            f"`{REFRESH_COMMAND} {quoted}`."
        )
    what = f"{symbol} in {key}" if symbol else key
    why = ""
    if entry.is_legacy:
        why = (
            " Its entry predates syntax-tree digests (a version 1 entry), so any "
            "byte change counts."
        )
    elif reason and not symbol:
        why = f" ({reason[0].upper()}{reason[1:]}.)"
    return (
        f"Stale suppression: {what} has changed since its suppressions were "
        f"reviewed, so the symbol suppressions bound to it do not apply and "
        f"their findings are reported again.{why} Suppressions: {described}. "
        f"After reviewing the change, record it with "
        f"`{REFRESH_COMMAND} {quoted}`."
    )
