# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Where an ASH configuration comes from, and how one config extends another.

Discovery (#313)
----------------
When no config path is given, ``discover_config_source`` picks exactly one
source from the scan root. Sources are never merged with each other. In order:

1. The dedicated file names in ``ASH_CONFIG_FILE_NAMES``, in that list's order,
   each checked at the scan root and then in ``.ash/``. This is the order ASH
   has always used, kept unchanged.
2. ``ASH_RC_FILE_NAMES`` (``.ashrc.toml`` ... ``ashrc.json``) at the scan root.
3. ``pyproject.toml`` at the scan root, only if it has a ``[tool.ash]`` table.
   A ``pyproject.toml`` without one is not a config source at all.

An explicit path (``--config`` or ``ASH_CONFIG``) skips discovery.

The dedicated names win over the newer sources because #313 asks for
``[tool.ash]`` to be read "when no .ash/.ash.yaml exists" and for an existing
``.ash/.ash.yaml`` to keep working. Letting a newer source win would change the
config of every repository that has ``.ash/.ash.yaml`` and then gains an
unrelated ``[tool.ash]`` table. The source used is logged, every other source
found is logged as ignored, and when a dedicated file shadows a newer source the
warning says the dedicated names are deprecated.

Rejected: merging the sources found (two files each holding half a config is the
confusion this is meant to remove, and pytest does not merge either), and
failing when more than one exists (that breaks every repository with both on
upgrade, for a situation a warning already explains).

Extends (#289)
--------------
A config may name one or more base configs, plus RFC 6902 JSON-Patch ops::

    extends: ../shared/ash-base.yaml        # or a list of paths
    patch:
      - op: add
        path: /global_settings/suppressions/-
        value: {rule_id: B101, path: "tests/**", reason: "asserts in tests"}

One file resolves as follows:

1. Each base is resolved the same way (recursively), and the bases are merged
   left to right, so a later base wins over an earlier one.
2. The file's own keys are merged over the result. The file always wins.
3. The file's ``patch`` ops are applied, in order, to that result.

Merge rules: two mappings merge key by key, recursively. Anything else -- a
list, a scalar, ``null`` -- replaces what was there. Lists are replaced, never
concatenated, so a child that writes ``suppressions`` drops its base's
suppressions; to keep them and add more, use a ``patch`` ``add`` at
``/global_settings/suppressions/-``. To delete a key a base set, use a ``patch``
``remove``. JSON-Patch pointers are matched to the document's own spelling,
where a key differs only in ``-`` versus ``_`` (``_resolve_dict_key``).

Spellings: a setting is merged as the config model reads it (``deep_merge``
with the model). Where the model reads a field under two spellings, its name
and its alias (``cdk_nag`` and ``cdk-nag``), both are one setting: each
document's spellings are folded as the model folds them, the child's result is
merged over the base's, and the result is written once, under the alias. A
spelling the model does not read (``global-settings`` for ``global_settings``)
in the base is left as it is, so it cannot take the child's value away from the
setting. One in the child still reaches the base's spelling of the setting, as
keys differing only in ``-`` versus ``_`` always did, unless the child also
sets the setting under a spelling the model reads, which wins. Two
spellings of a plugin's section in ``scanners``, ``reporters`` or
``converters`` that ``get_plugin_config`` reads for the same plugin
(``plugin_key_lookup_names``: ``BedrockSummary`` and
``bedrock-summary-reporter``) are one section, written under the child's
spelling. Keys inside a section whose model is not known (a plugin's own
section) keep the older rule: keys that differ only in ``-`` versus ``_`` are
one key. Workspace mode merges the operator's ``--config`` over a project's
config by the same rules (``resolve_config``'s ``overlay_config_path``).

``move`` and ``copy`` are refused, as in ``runtime_patch.py``; #289 asks for
``add``, ``remove`` and ``replace``, and ``test`` is allowed because it reads
only.

Base paths
----------
A base path is relative to the directory of the file that names it, after that
file's own symlinks are resolved; an absolute path is also accepted. Nothing is
fetched: a reference that looks like a URL is refused with an error, not
downloaded.

Every base must resolve, after following symlinks, to a location inside the
confinement root. ``Path.resolve`` alone normalizes a path and confines nothing,
so the check is ``is_relative_to`` between two resolved paths. A ``..`` that
stays inside the root is fine. One that leaves it is refused, and so is a
symlink inside the root whose target is outside. The root is the scan's source
directory when the root config is inside it, otherwise the root config's own
directory (the parent of ``.ash/`` for a file in ``.ash/``); see
``default_confinement_root``. A root config reached through a link an MCP
client delivered is placed where that link sits for this, not where it leads,
so a named link in a delivered tree cannot extend a file beside its target.

A file is judged by every path it was reached by
(``ResolvedConfigDocument.names``), and a base also by the paths of the files
above it, since the file that names a base chose it: a base of a file a client
delivered, or of a file a client's link reaches, is the client's wherever it
is.

A caller can narrow that further with ``permit_base``, a predicate every base
must also pass after its symlinks are resolved. The MCP server passes one built
from the calling session's allowed config roots
(``cli/mcp/sandbox.config_base_gate``), so a grant naming a ``.ash/`` directory
confines the chain to that directory rather than to its parent. The predicate is
consulted before the confinement root, and its refusal,
``ASHConfigInputNotPermittedError``, names the ``extends`` entry as written and
not the path it resolved to. Without a predicate the rules above are unchanged.

Discovery takes the same predicate (``discover_config_source(..., permit=)``).
A source found in the scanned directory can be a symbolic link to any file, and
discovery reads ``pyproject.toml`` to look for its table, so every source that
exists is checked by the path it resolves to before anything opens it. A refused
one raises ``ASHConfigInputNotPermittedError`` naming the source as found, so the
refusal reads the same whether its target is missing, unreadable or readable.

The same predicate is applied to the file discovery selects, when a caller
passes one (``check_discovered_source``). The directory searched is one the
caller may read, but a file found there may be a symlink to a file elsewhere,
and reading that file would let the caller choose a file on the host. The
MCP server's ``get_config`` already checks a file it finds this way. The refusal
names the file as found, not the file it resolves to. Discovery looks only at
whether each candidate exists before the predicate is applied to it; a
``pyproject.toml`` is read for its ``[tool.ash]`` table only after it passed.

Bounds
------
Every config file is opened without blocking and read only when the opened file
is a regular file, and at most ``ASH_CONFIG_MAX_FILE_BYTES`` of it
(``read_config_bytes``). A FIFO or a device at a config name, including one
swapped in after a caller checked the name, is refused rather than blocking the
scan or being read until memory runs out.

A file that appears twice on its own chain is a cycle and fails with the chain
printed. The same file reached on two branches (a diamond) is not a cycle. A
chain deeper than ``ASH_CONFIG_EXTENDS_MAX_DEPTH`` fails, and so does reading
more than ``ASH_CONFIG_EXTENDS_MAX_FILES`` files in total, which bounds a chain
that fans out where depth alone would not.

Environment variables
---------------------
Each file is read by the same parser the single-file loader always used: YAML
through ``load_yaml_config``, TOML by passing each string value that starts with
``${`` through ``resolve_env_references`` (the same function the YAML ``!ENV``
constructor calls), and JSON with no interpolation, as before. The
``ASH_CONFIG_ENV_VAR_PREFIX`` / ``ASH_CONFIG_ENV_VAR_ALLOWLIST`` bound therefore
holds for every value in the merged result, whichever file it came from.

Some files resolve no environment variable at all, and one of them that uses
``!ENV`` (tagged, a plain ``${VAR:default}`` scalar, or a TOML string starting
with one) is refused with ``ASHConfigEnvNotResolvedError`` naming the file and
the line or key. Which files is a ``RefuseEnv`` predicate the caller passes to
``read_config_file`` and ``resolve_config_document``; ``env_refused_for`` gives
the MCP server's two:

* For a remote caller (``cli/mcp/sandbox.caller_is_remote``), every file the
  operator did not set aside: anything outside ``ASH_MCP_ALLOWED_CONFIG_ROOTS``
  except the profile files the server writes in the calling session's
  ``config/`` directory (``cli/mcp/sandbox.client_named_config_is_untrusted``).
  That covers a path the
  client names, a file discovered in a directory it names, and a scan target's
  own config, as well as anything it delivered.
* For any other caller, the CLI included, and the default when none is passed:
  a file an MCP client delivered (``cli/mcp/sandbox.config_is_client_supplied``),
  that is anything under the MCP workspace root except the profile files the
  server writes in the sessions' ``config/`` directories, judged on the path as
  named and on the file it resolves to. A local stdio caller launched the server and holds its
  environment already, so its own repository config keeps ``!ENV``.

``validate_config``'s ``config_content`` from a remote caller is refused
wherever it is written (``refuse_env_everywhere``). Each base is judged by the
same predicate, on the path its ``extends`` entry spells and on the file that
resolves to, and every base of a refused file is refused with it: the file that
names a base is what chose it.

The bound above cannot cover this case. There the variables are the operator's
own, set wherever ASH runs; here they are the MCP server's, and a remote client
reads the result back (``get_config`` returns the resolved config, and a scan's
results carry it). Refused rather than left as written, because a value that
silently stays a literal is a config that is not what either side meant, and
the other refusals for delivered configs work the same way. A config the CLI
reads keeps ``!ENV`` exactly as before.

Failure
-------
Every failure here raises ``ASHConfigSourceError``, which ``resolve_config``
re-raises instead of falling back to the default config. A root YAML or JSON
file that cannot be read or parsed raises what the reader raised;
``resolve_config.read_config_document`` turns that into an
``ASHConfigSourceError`` too, so a root file that does not load refuses the
scan just as a base that does not load does. Neither is replaced by the
defaults, which would scan with the file's suppressions and settings off.

Discovery selects a config name that exists, not only one that is a regular
file: a dangling symbolic link or a directory at ``.ash/.ash.yaml`` is selected
and then refused when it is read, rather than skipped as though the repository
had no config. A ``pyproject.toml`` that cannot be read refuses the same way
when it would be the selected source, because whether it holds a ``[tool.ash]``
table cannot be told. Discovery opens ``pyproject.toml`` to look for that table
only when it is a regular file; one that is not is told by its type and never
opened (``_pyproject_is_a_source``).
"""

from __future__ import annotations

import copy
import errno
import functools
import io
import json
import os
import re
import stat
import types
import typing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

# jsonpatch ships no type information (no py.typed, no stubs package).
import jsonpatch  # type: ignore[import-untyped]
import yaml

from pydantic import BaseModel

from automated_security_helper.config.ash_config import (
    ENV_REFERENCE_PATTERN,
    AshConfig,
    EnvReferenceNotResolved,
    _PluginConfigSegment,
    load_yaml_config,
    plugin_key_lookup_names,
    resolve_env_references,
)
from automated_security_helper.core.constants import (
    ASH_CONFIG_EXTENDS_MAX_DEPTH,
    ASH_CONFIG_EXTENDS_MAX_FILES,
    ASH_CONFIG_FILE_NAMES,
    ASH_CONFIG_MAX_FILE_BYTES,
    ASH_PYPROJECT_FILE_NAME,
    ASH_RC_FILE_NAMES,
)
from automated_security_helper.core.exceptions import (
    ASHConfigEnvNotResolvedError,
    ASHConfigFileNotFoundError,
    ASHConfigInputNotPermittedError,
    ASHConfigSourceError,
)
from automated_security_helper.utils.link_locations import link_locations
from automated_security_helper.utils.log import ASH_LOGGER

# tomllib is stdlib only from Python 3.11; requires-python starts at 3.10, so
# fall back to the already-declared `toml` dependency, as
# utils/version_management.py does.
try:  # pragma: no cover - branch depends on interpreter version
    import tomllib

    _TOMLDecodeError: Any = tomllib.TOMLDecodeError

    def _parse_toml(text: str) -> Dict[str, Any]:
        return tomllib.loads(text)

except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    # No stubs for `toml` are installed; it is only the 3.10 fallback.
    import toml  # type: ignore[import-untyped]

    _TOMLDecodeError = toml.TomlDecodeError

    def _parse_toml(text: str) -> Dict[str, Any]:
        return toml.loads(text)


EXTENDS_KEY = "extends"
PATCH_KEY = "patch"

#: Decides whether one resolved base path may be read. True permits it. See
#: "Base paths" in the module docstring.
PermitBase = Callable[[Path], bool]

#: Decides whether one config file may not resolve ``!ENV``. True refuses it. See
#: "Environment variables" in the module docstring.
RefuseEnv = Callable[[Path], bool]

#: Decides whether one config file is the operator's, so its relative paths are
#: taken from its directory (``config/operator_paths.py``). True anchors them.
AnchorPaths = Callable[[Path], bool]

SOURCE_KIND_EXPLICIT = "explicit"
SOURCE_KIND_DEDICATED = "dedicated"
SOURCE_KIND_ASHRC = "ashrc"
SOURCE_KIND_PYPROJECT = "pyproject"

_PATCH_OPS = {"add", "remove", "replace", "test"}
_URL_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
# A [tool.ash] or [tool.ash.*] header, or a top-level dotted `tool.ash...` key.
# Only consulted for a pyproject.toml that failed to parse, to decide whether it
# was meant to configure ASH, and to report the table's line.
_TOOL_ASH_PATTERN = re.compile(
    r"^[ \t]*(\[[ \t]*tool[ \t]*\.[ \t]*ash[ \t]*[\].]|tool[ \t]*\.[ \t]*ash[ \t]*[.=])",
    re.MULTILINE,
)


def _resolve_dict_key(container: Dict[str, Any], key: str) -> str:
    """Return the key `container` already uses for `key`, if it differs only in '-' vs '_'.

    The dict an override is applied to comes from `model_dump()` without
    `by_alias=True`, so a section with an alias is keyed by its Python field name
    -- `cdk_nag`, not `cdk-nag`. Operators type the spelling in their own config
    file, which for those sections is the alias; this option's own documented
    example is a kebab-case key. Writing the typed spelling verbatim added a
    second section beside the dumped one, and since pydantic resolves an alias
    ahead of a field name the new one won revalidation -- so the override applied
    and every other field under that section came back as a default.

    Only a key that already exists is ever followed. A name absent under both
    spellings is created exactly as typed, which is what keeps a plugin-supplied
    section (an extra key, present under one spelling only) reachable.

    Comparing the two spellings is equivalent to consulting the alias map here
    because every alias declared anywhere under `AshConfig` is its field name
    with '_' replaced by '-'; that held for 9 of 9 aliases across 75 models when
    this was written, walking `model_fields` from `AshConfig` down.

    `extends` merging and `patch` pointers use the same rule, for the same
    reason: a base and a child are as likely to spell a section differently as a
    file and an override are.
    """
    if key in container:
        return key
    for variant in (key.replace("-", "_"), key.replace("_", "-")):
        if variant != key and variant in container:
            return variant
    return key


def is_pyproject(path: Path) -> bool:
    return Path(path).name == ASH_PYPROJECT_FILE_NAME


def is_regular_file(path: Path) -> bool:
    """Whether `path` leads to a regular file; False for any error.

    os.stat rather than Path.is_file: before Python 3.14, is_file raises for an
    error other than "not found" (a directory above that cannot be searched),
    which let a bare OSError out of a check that only meant to ask.
    """
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (OSError, ValueError):
        # ValueError: a path with a NUL in it.
        return False


FileIdentity = Tuple[int, int]


def file_identity(path: Path) -> Optional[FileIdentity]:
    """(device, inode) of the file `path` leads to now, or None when it leads nowhere.

    Taken when a caller checks a config path, and handed to ``read_config_bytes``
    as ``expect``, so the file read is the file that was checked.
    """
    try:
        info = os.stat(path)
    except (OSError, ValueError):
        return None
    return info.st_dev, info.st_ino


def read_config_bytes(path: Path, expect: Optional[FileIdentity] = None) -> bytes:
    """A config file's bytes; see "Bounds" in the module docstring.

    Opened with ``O_NONBLOCK``, so opening a FIFO does not wait for a writer, and
    ``O_NOCTTY``, so a tty swapped in at the name cannot become the controlling
    terminal of a process that has none (a daemonized MCP server). Checked with
    ``fstat`` on the open descriptor, so what is read is the regular file that was
    opened and not whatever the name pointed at when a caller checked it. With
    ``expect`` (from ``file_identity`` at the caller's check), the opened file's
    device and inode must be those, so a file replaced between a check and this
    read is refused rather than read. Raises ``OSError`` for anything else, and
    ``ASHConfigSourceError`` for a file longer than ``ASH_CONFIG_MAX_FILE_BYTES``.
    """
    nonblock = getattr(os, "O_NONBLOCK", 0)
    flags = (
        os.O_RDONLY | nonblock | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_BINARY", 0)
    )
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError(errno.EINVAL, "not a regular file", os.fspath(path))
        if expect is not None and (opened.st_dev, opened.st_ino) != expect:
            raise OSError(
                errno.ESTALE,
                "changed after it was checked, so it is not read",
                os.fspath(path),
            )
        if nonblock:
            # O_NONBLOCK was for the open. A regular file is then read normally:
            # on some filesystems a non-blocking read of one can return early.
            os.set_blocking(fd, True)
        limit = ASH_CONFIG_MAX_FILE_BYTES
        chunks: List[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(fd)
    if remaining <= 0:
        raise ASHConfigSourceError(
            f"{Path(path).as_posix()} is larger than {limit} bytes, the most ASH "
            "reads from one config file."
        )
    return b"".join(chunks)


def _read_toml_text(path: Path, expect: Optional[FileIdentity] = None) -> str:
    """A TOML file's text. A leading UTF-8 byte order mark is dropped, since
    tomllib rejects it and editors on some platforms write one."""
    text = read_config_bytes(path, expect=expect).decode("utf-8")
    return text.removeprefix("\ufeff")


def _tool_ash_line(path: Path) -> Optional[int]:
    # Only a regular file is read: this names a file in messages, including the
    # one that says a path is not a regular file.
    if not is_regular_file(path):
        return None
    try:
        text = _read_toml_text(path)
    except (OSError, UnicodeDecodeError, ASHConfigSourceError):
        return None
    match = _TOOL_ASH_PATTERN.search(text)
    if match is None:
        return None
    return text.count("\n", 0, match.start()) + 1


def describe_config_path(path: Path) -> str:
    """Name a config source for a message: the path, plus the table for pyproject."""
    path = Path(path)
    if is_pyproject(path):
        line = _tool_ash_line(path)
        where = f" (line {line})" if line else ""
        return f"{path.as_posix()} [tool.ash]{where}"
    return path.as_posix()


@dataclass(frozen=True)
class ConfigSource:
    path: Path
    kind: str

    @property
    def label(self) -> str:
        return describe_config_path(self.path)


@dataclass
class ConfigDiscovery:
    """The source discovery selected, and every other source it found.

    ``notes`` are what discovery could not use behind the selected source, such
    as a pyproject.toml it could not read. They are reported with the ignored
    sources (``discovery_warnings``), so they are logged once per scan and
    recorded with its results, rather than logged by each of the several readers
    that run discovery.
    """

    selected: Optional[ConfigSource] = None
    ignored: List[ConfigSource] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def pyproject_has_ash_table(path: Path) -> bool:
    """Whether `path` is a pyproject.toml that configures ASH.

    A pyproject.toml that does not parse (including one that is not UTF-8,
    which TOML requires) is skipped unless its text declares a ``tool.ash``
    table, in which case it is an error: skipping it would scan with the default
    config while the repository's own config sat unread. Read errors propagate.
    """
    try:
        text = _read_toml_text(path)
    except UnicodeDecodeError as exc:
        # Latin-1 decodes any byte string, which is all the pattern needs.
        if _TOOL_ASH_PATTERN.search(read_config_bytes(path).decode("latin-1")):
            raise ASHConfigSourceError(
                f"{describe_config_path(path)} declares an ASH configuration but "
                f"is not valid UTF-8, which TOML requires: {exc}"
            ) from exc
        return False
    try:
        document = _parse_toml(text)
    except _TOMLDecodeError as exc:
        if _TOOL_ASH_PATTERN.search(text):
            raise ASHConfigSourceError(
                f"{describe_config_path(path)} declares an ASH configuration but "
                f"is not valid TOML: {exc}"
            ) from exc
        ASH_LOGGER.debug(
            f"Skipping {Path(path).as_posix()} as a config source: it is not "
            f"valid TOML and has no [tool.ash] table ({exc})"
        )
        return False
    tool = document.get("tool")
    table = tool.get("ash") if isinstance(tool, dict) else None
    if table is None:
        return False
    if not isinstance(table, dict):
        raise ASHConfigSourceError(
            f"tool.ash in {Path(path).as_posix()} must be a table, got "
            f"{type(table).__name__}"
        )
    return True


def _unreadable_pyproject(
    path: Path, found_before: List[ConfigSource], exc: OSError, notes: List[str]
) -> bool:
    """Refuse a pyproject.toml that could not be read, or note it behind a source."""
    if not found_before:
        refusal = (
            ASHConfigFileNotFoundError
            if isinstance(exc, FileNotFoundError)
            else ASHConfigSourceError
        )
        raise refusal(
            f"Could not read {path.as_posix()} ({exc}), so ASH cannot tell "
            "whether it holds a [tool.ash] table. Make it readable, remove "
            "it, or name a config file with --config."
        ) from exc
    notes.append(
        f"Could not read {path.as_posix()} ({exc}); it is not used as an ASH "
        "config source."
    )
    return False


def _pyproject_is_a_source(
    path: Path, found_before: List[ConfigSource], notes: List[str]
) -> bool:
    """Probe pyproject.toml without letting it break an unrelated config.

    When a higher-precedence source already exists, pyproject.toml is probed
    only to report it as ignored, so nothing about it may fail the load: before
    #313 a repository with .ash/.ash.yaml was unaffected by whatever its
    pyproject.toml held. When it would be the selected source, a pyproject that
    declares [tool.ash] but cannot be parsed fails closed, and so does one that
    cannot be read at all (a dangling link, a directory, no permission): there
    is no way to tell whether it configures ASH, and skipping it would scan with
    the defaults while its [tool.ash] table, if it has one, sat unread.

    Only a regular file is opened. Discovery runs on whatever a cloned
    repository holds, and opening a device can act on it even when nothing is
    read: a watchdog arms, a tape rewinds. So a FIFO, a device or a directory at
    this name is told by its type, from ``stat``, and refused or ignored unopened.

    What cannot be used behind a higher-precedence source is appended to
    ``notes`` rather than logged; see ``ConfigDiscovery``.
    """
    # Classified from os.stat and its errno, so each name that cannot be followed
    # is reported for what it is.
    try:
        regular = stat.S_ISREG(os.stat(path).st_mode)
    except FileNotFoundError:
        # The name exists (discovery found it) but leads nowhere.
        missing = FileNotFoundError(
            errno.ENOENT, "a symbolic link to nothing", os.fspath(path)
        )
        return _unreadable_pyproject(path, found_before, missing, notes)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            exc = OSError(
                errno.ELOOP,
                "a symbolic link that leads back to itself",
                os.fspath(path),
            )
        return _unreadable_pyproject(path, found_before, exc, notes)
    if not regular:
        return _unreadable_pyproject(
            path,
            found_before,
            OSError(errno.EINVAL, "not a regular file", os.fspath(path)),
            notes,
        )
    try:
        return pyproject_has_ash_table(path)
    except OSError as exc:
        return _unreadable_pyproject(path, found_before, exc, notes)
    except ASHConfigSourceError as exc:
        if not found_before:
            raise
        notes.append(
            f"Ignoring {path.as_posix()}: {found_before[0].label} takes precedence, "
            f"and the [tool.ash] table there could not be read ({exc})."
        )
        return False


def _name_exists(path: Path) -> bool:
    """Whether a config name exists, as ``os.path.lexists`` says, but never guessed.

    ``lexists`` answers False for any error, so a ``.ash/`` directory that cannot
    be searched hid the config inside it and the scan ran with the defaults.
    Only "no such file" and "a path component is not a directory" mean absent;
    any other error refuses, since whether the repository has a config there
    cannot be told.
    """
    try:
        os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as exc:
        raise ASHConfigSourceError(
            f"Could not look for a config file at {Path(path).as_posix()} "
            f"({exc.strerror}), so ASH cannot tell whether one is there. Make the "
            "directory readable, or name a config file with --config."
        ) from exc
    return True


def _not_permitted(found: Path) -> ASHConfigInputNotPermittedError:
    # Names the source as found, never what it resolves to, so the refusal reads
    # the same whether that target is missing, unreadable or readable.
    return ASHConfigInputNotPermittedError(
        f"{found.as_posix()}, a config source found in the scanned directory, "
        "reaches a file outside the directories this caller may read config from."
    )


def _on_windows() -> bool:
    return os.name == "nt"


def _is_a_link(path: Path) -> bool:
    """Whether `path` is a symbolic link or, on Windows, any reparse point."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(getattr(info, "st_file_attributes", 0) & reparse)


def _permitted(path: Path, permit: PermitBase) -> bool:
    if _on_windows() and _is_a_link(path):
        # Resolving a link on Windows can open a connection to the host a UNC
        # target names, so a linked source is refused unresolved, as an extends
        # base whose spelling leaves the root is (_resolve_base_path).
        return False
    # realpath reads links and opens nothing, and does not raise on a loop.
    return permit(Path(os.path.realpath(path)))


def _existing_candidates(
    search_dir: Path, permit: Optional[PermitBase] = None
) -> List[ConfigSource]:
    """Every config name in `search_dir` that exists, in precedence order, unopened.

    Under ``permit`` a ``.ash`` that is a link out of the grant is refused before
    anything looks inside it: whether a name exists there would otherwise answer
    whether a file exists in a directory the caller may not read.
    """
    dot_ash = search_dir / ".ash"
    if permit is not None and _name_exists(dot_ash) and not _permitted(dot_ash, permit):
        raise _not_permitted(dot_ash)
    candidates: List[ConfigSource] = []
    for name in ASH_CONFIG_FILE_NAMES:
        for candidate in (search_dir / name, dot_ash / name):
            if _name_exists(candidate):
                candidates.append(ConfigSource(candidate, SOURCE_KIND_DEDICATED))
    for name in ASH_RC_FILE_NAMES:
        candidate = search_dir / name
        if _name_exists(candidate):
            candidates.append(ConfigSource(candidate, SOURCE_KIND_ASHRC))
    pyproject = search_dir / ASH_PYPROJECT_FILE_NAME
    if _name_exists(pyproject):
        candidates.append(ConfigSource(pyproject, SOURCE_KIND_PYPROJECT))
    return candidates


def _check_candidates(
    candidates: List[ConfigSource], permit: Optional[PermitBase]
) -> None:
    if permit is None:
        return
    for candidate in candidates:
        if not _permitted(candidate.path, permit):
            raise _not_permitted(candidate.path)


def check_discovery_candidates(search_dir: Path, permit: Optional[PermitBase]) -> None:
    """Refuse `search_dir` when a config source in it resolves outside `permit`.

    The check ``discover_config_source(search_dir, permit=permit)`` makes before
    it opens anything, for a caller that refuses before a scan starts (MCP
    ``scan_directory``). Opens nothing itself.
    """
    search_dir = Path(search_dir)
    _check_candidates(_existing_candidates(search_dir, permit), permit)


def discover_config_source(
    search_dir: Path, permit: Optional[PermitBase] = None
) -> ConfigDiscovery:
    """Find every config source in `search_dir` and select one by precedence.

    A name counts when it exists, whatever it is; see "Failure" in the module
    docstring for why a dangling link is selected rather than skipped.

    ``permit`` is the caller's predicate for the files it may read config from,
    as for an ``extends`` base. Every source that exists -- the one selected and
    the ones ignored, which are reported and, for ``pyproject.toml``, read -- is
    checked by the path it resolves to before anything opens it, and one the
    predicate refuses raises ``ASHConfigInputNotPermittedError`` naming the
    source as found. Without it nothing is checked.
    """
    search_dir = Path(search_dir)
    candidates = _existing_candidates(search_dir, permit)
    _check_candidates(candidates, permit)
    found: List[ConfigSource] = []
    notes: List[str] = []
    for candidate in candidates:
        if candidate.kind != SOURCE_KIND_PYPROJECT or _pyproject_is_a_source(
            candidate.path, found, notes
        ):
            found.append(candidate)
    if not found:
        return ConfigDiscovery()
    return ConfigDiscovery(selected=found[0], ignored=found[1:], notes=notes)


def check_discovered_source(path: Path, permit_base: Optional[PermitBase]) -> None:
    """Refuse a discovered config file that resolves to one ``permit_base`` does not permit.

    See "Base paths". Nothing is checked without ``permit_base``. Raises
    ``ASHConfigInputNotPermittedError`` naming ``path`` as it was found, never the
    file it resolves to.
    """
    if permit_base is None or permit_base(Path(path).resolve()):
        return
    raise ASHConfigInputNotPermittedError(
        f"{Path(path).as_posix()}, the config file found in the scanned directory, "
        "reaches a file outside the directories this caller may read config from."
    )


def discovery_warnings(discovery: ConfigDiscovery) -> List[str]:
    """One warning per source discovery found and did not select, then its notes.

    The settings in an ignored source are not applied, so a scan reports these
    with its results as well as in the log; see ``log_config_discovery`` and
    ``resolve_config``. A note says what discovery could not use behind the
    selected source (``ConfigDiscovery.notes``).
    """
    selected = discovery.selected
    if selected is None:
        return []
    warnings: List[str] = []
    for other in discovery.ignored:
        message = (
            f"Ignoring ASH configuration at {other.label}: {selected.label} takes "
            "precedence, and configuration sources are never merged."
        )
        if selected.kind == SOURCE_KIND_DEDICATED and other.kind in (
            SOURCE_KIND_ASHRC,
            SOURCE_KIND_PYPROJECT,
        ):
            message += (
                f" The config file names {', '.join(ASH_CONFIG_FILE_NAMES)} (at the "
                "repository root or in .ash/) are deprecated in favor of "
                f"{', '.join(ASH_RC_FILE_NAMES)} or a [tool.ash] table in "
                f"{ASH_PYPROJECT_FILE_NAME}. Move the settings into one source "
                "and delete the other."
            )
        warnings.append(message)
    warnings.extend(discovery.notes)
    return warnings


def log_config_discovery(
    discovery: ConfigDiscovery, announce_selected: bool = True
) -> List[str]:
    """Say which source is used and which were found but ignored.

    ``announce_selected`` is False for a caller that reports the selected file
    through its own logger; the ignored sources are always reported here.
    Returns the warnings logged, ``discovery_warnings(discovery)``.
    """
    selected = discovery.selected
    if selected is None:
        return []
    if announce_selected:
        ASH_LOGGER.info(f"Using ASH configuration from {selected.label}")
    warnings = discovery_warnings(discovery)
    for message in warnings:
        ASH_LOGGER.warning(message)
    return warnings


def _resolve_toml_env(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _resolve_toml_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_toml_env(v) for v in value]
    if isinstance(value, str) and ENV_REFERENCE_PATTERN.match(value):
        return resolve_env_references(value)
    return value


def _toml_env_reference(value: Any, key: str = "") -> Optional[str]:
    """The key of the first value `_resolve_toml_env` would resolve, or None."""
    if isinstance(value, dict):
        items = ((f"{key}.{k}" if key else str(k), v) for k, v in value.items())
    elif isinstance(value, list):
        items = ((f"{key}[{i}]", v) for i, v in enumerate(value))
    else:
        if isinstance(value, str) and ENV_REFERENCE_PATTERN.match(value):
            return key
        return None
    for child_key, child in items:
        found = _toml_env_reference(child, child_key)
        if found is not None:
            return found
    return None


def config_is_client_delivered(path: Path) -> bool:
    """Whether an MCP client delivered `path`; see "Environment variables".

    ``cli.mcp.sandbox.config_is_client_supplied``, imported when called. The
    ``RefuseEnv`` every caller gets unless it passes another.
    """
    # Imported here, as config/path_trust.py does: importing cli.mcp runs its
    # __init__, which imports profile_registry and through it ash_config.
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    return config_is_client_supplied(path)


def env_refused_for(remote_client: bool, session_id: Optional[str] = None) -> RefuseEnv:
    """The files that resolve no ``!ENV`` for a caller; see "Environment variables".

    ``remote_client`` is ``cli.mcp.sandbox.caller_is_remote`` for the MCP call
    the config is read for, and False for everything else. ``session_id`` is
    that call's session: of the profile files the server writes in the sessions'
    ``config/`` directories, only its own are set aside for a remote caller.
    """
    if not remote_client:
        return config_is_client_delivered
    from automated_security_helper.cli.mcp.sandbox import (
        client_named_config_is_untrusted,
    )

    def refused(path: Path) -> bool:
        return client_named_config_is_untrusted(path, session_id=session_id)

    return refused


def refuse_env_everywhere(path: Path) -> bool:
    """A ``RefuseEnv`` that refuses every file: content a remote client sent."""
    return True


def _refuse_env_nowhere(path: Path) -> bool:
    return False


def _env_rule(refused: bool) -> RefuseEnv:
    """The ``RefuseEnv`` for one file of a chain, once its refusal is decided."""
    return refuse_env_everywhere if refused else _refuse_env_nowhere


def _env_not_resolved(path: Path, where: str) -> ASHConfigEnvNotResolvedError:
    return ASHConfigEnvNotResolvedError(
        f"{describe_config_path(path)} uses !ENV ({where}). !ENV is not resolved "
        "in a config an MCP client delivered, so the file is refused. Write the "
        "value itself in the file (in YAML, quote a value that only looks like a "
        "${VAR} reference), or leave the setting to the server's config."
    )


def read_config_file(
    path: Path,
    expect: Optional[FileIdentity] = None,
    refuse_env: Optional[RefuseEnv] = None,
) -> Any:
    """Parse one config file, without resolving its `extends`.

    A ``pyproject.toml`` yields its ``[tool.ash]`` table; any other ``.toml``
    file is a config at its top level. YAML and JSON are read exactly as
    ``AshConfig.from_file`` always read them, except that a YAML or TOML file
    ``refuse_env`` refuses (by default, one an MCP client delivered) is refused
    if it uses ``!ENV``; see "Environment variables". JSON has no ``!ENV``.
    ``expect`` is passed to ``read_config_bytes``.
    """
    path = Path(path)
    if path.name.endswith(".json"):
        # utf-8-sig: a leading byte order mark is dropped, as YAML and TOML drop
        # it; Windows PowerShell 5 writes one.
        return json.loads(read_config_bytes(path, expect=expect).decode("utf-8-sig"))
    delivered = (refuse_env or config_is_client_delivered)(path)
    if path.name.endswith(".toml"):
        try:
            text = _read_toml_text(path, expect=expect)
        except UnicodeDecodeError as exc:
            raise ASHConfigSourceError(
                f"{describe_config_path(path)} is not valid UTF-8, which TOML "
                f"requires: {exc}"
            ) from exc
        try:
            document = _parse_toml(text)
        except _TOMLDecodeError as exc:
            raise ASHConfigSourceError(
                f"{describe_config_path(path)} is not valid TOML: {exc}"
            ) from exc
        if is_pyproject(path):
            tool = document.get("tool")
            table = tool.get("ash") if isinstance(tool, dict) else None
            if table is None:
                raise ASHConfigSourceError(
                    f"{path.as_posix()} has no [tool.ash] table, so it holds no "
                    "ASH configuration"
                )
            if not isinstance(table, dict):
                raise ASHConfigSourceError(
                    f"tool.ash in {path.as_posix()} must be a table, got "
                    f"{type(table).__name__}"
                )
            document = table
        if delivered:
            key = _toml_env_reference(document)
            if key is not None:
                raise _env_not_resolved(path, f"key {key}")
            return document
        return _resolve_toml_env(document)
    try:
        return load_yaml_config(
            named_text_stream(
                read_config_bytes(path, expect=expect).decode("utf-8"), path
            ),
            env="refuse" if delivered else "resolve",
        )
    except EnvReferenceNotResolved as exc:
        raise _env_not_resolved(path, f"line {exc.line}") from exc


def named_text_stream(text: str, path: Path) -> io.StringIO:
    """`text` as a stream named `path`, for a YAML parser.

    A parse error then names the file and gives its line and column, as it did
    when the parser read the open file, rather than "<unicode string>" followed
    by a copy of the offending line.
    """
    stream = io.StringIO(text)
    stream.name = os.fspath(path)
    return stream


def default_confinement_root(
    config_path: Path, source_dir: Optional[Path] = None
) -> Path:
    """The directory every base in `config_path`'s chain must stay inside.

    The scan's source directory when `config_path` is inside it, so a project
    config may extend a file anywhere in the repository being scanned.
    Otherwise -- no source directory, or a config kept outside it -- the root
    config's own directory, or the parent of ``.ash/`` for a file in ``.ash/``.

    A root config reached through a link an MCP client delivered is placed
    where that link sits, not where it leads (``_client_link``): the client
    chose the file by placing the link, so its bases stay in the tree the client
    delivered, as the bases of a file written there do.
    """
    placed = _client_link(Path(config_path))
    config_real = placed if placed is not None else Path(config_path).resolve()
    if source_dir is not None:
        source_real = Path(source_dir).resolve()
        if config_real.is_relative_to(source_real):
            return source_real
    parent = config_real.parent
    if parent.name == ".ash":
        parent = parent.parent
    return parent


def _client_link(path: Path) -> Optional[Path]:
    """Where the first link on the way to ``path`` that sits in a client's tree is, or None.

    A link sits in a client's tree when the directory holding it is one an MCP
    client delivered (``config_is_client_delivered``); a link elsewhere that
    leads into such a tree was not placed by the client. Each location is under
    its parent with that parent's links resolved (``link_locations``), so it
    compares with resolved paths.
    """
    for location in link_locations(path):
        if config_is_client_delivered(location.parent):
            return location
    return None


@dataclass
class ResolvedConfigDocument:
    """A config's merged data, and the files it was built from.

    ``chain`` lists every file read, in merge order: bases before the files that
    extend them, the root config last. A file reached on two branches appears
    twice, because it was merged twice. ``named`` lists the same files, in the same
    order, by the path that named them before any symlink was followed: the root
    as the caller gave it, and each base as its ``extends`` entry spells it from
    the file that extends it. A base that is a symlink is judged by that name too
    (``config/sandbox_grants.py``), since whoever can write the link chooses the
    file it reaches. ``documents`` holds each file's document
    as it was parsed, before its ``extends`` and ``patch`` were applied, so a
    caller checking what a file sets checks what was read rather than reading the
    file again.

    ``chain`` and ``documents`` name each file by its resolved path. ``names``
    gives, for each of them, the paths it was reached by before any symlink was
    followed: the root config as it was passed or discovered, and a base as its
    ``extends`` entry spells it, relative to the resolved directory of the file
    that names it. After those, a base's names include the resolved path and the
    names of every file above it in the chain, since the file that names a base
    chose it. A check of who wrote a file judges it by each of these and by
    every symlink on the way (``by_every_name``), since a link's location says who
    chose the file it reaches.
    """

    data: Any
    chain: List[Path] = field(default_factory=list)
    root: Optional[Path] = None
    named: List[Path] = field(default_factory=list)
    documents: Dict[Path, Any] = field(default_factory=dict)
    names: Dict[Path, Tuple[Path, ...]] = field(default_factory=dict)


#: The paths each file of a chain was reached by; see ``ResolvedConfigDocument``.
ChainNames = Mapping[Path, Sequence[Path]]


def by_every_name(
    judge: Callable[[Path], bool], names: Optional[ChainNames] = None
) -> Callable[[Path], bool]:
    """``judge`` for a chain file, true when it holds for any name the file has.

    The names are the file's resolved path and each path in ``names`` it was
    reached by. ``judge`` takes one path, as named; the checks it is used with
    (``cli/mcp/sandbox.config_is_client_supplied`` and
    ``client_named_config_is_untrusted``) also judge each symlink on the way.
    """
    known = names or {}

    def judged(path: Path) -> bool:
        return any(judge(name) for name in (path, *known.get(path, ())))

    return judged


@dataclass
class _ChainState:
    root: Path
    permit_base: Optional[PermitBase] = None
    refuse_env: RefuseEnv = config_is_client_delivered
    anchor_relative_paths: Optional[AnchorPaths] = None
    files_read: int = 0
    order: List[Path] = field(default_factory=list)
    named: List[Path] = field(default_factory=list)
    documents: Dict[Path, Any] = field(default_factory=dict)
    names: Dict[Path, List[Path]] = field(default_factory=dict)
    #: For each base, the paths of the files above it in the chain.
    above: Dict[Path, List[Path]] = field(default_factory=dict)

    def reached(self, real: Path, named: Path) -> None:
        spellings = self.names.setdefault(real, [])
        if named != real and named not in spellings:
            spellings.append(named)

    def chosen_by(self, real: Path, paths: Sequence[Path]) -> None:
        recorded = self.above.setdefault(real, [])
        for path in paths:
            if path != real and path not in recorded:
                recorded.append(path)

    def all_names(self) -> Dict[Path, Tuple[Path, ...]]:
        """``ResolvedConfigDocument.names``: own spellings first, then the files above.

        A file with no spelling of its own but files above it is listed under
        its own path first, so a message that names a file by the first of
        these (``client_config_policy._as_reached``) names the file itself.
        """
        result: Dict[Path, Tuple[Path, ...]] = {}
        for real in dict.fromkeys([*self.names, *self.above]):
            own = list(self.names.get(real, ()))
            inherited = [p for p in self.above.get(real, ()) if p not in own]
            if inherited:
                own = (own or [real]) + inherited
            if own:
                result[real] = tuple(own)
        return result


def _format_chain(paths: Tuple[Path, ...]) -> str:
    return " -> ".join(describe_config_path(p) for p in paths)


def _extends_refs(value: Any, path: Path) -> List[str]:
    if value is None:
        return []
    refs = [value] if isinstance(value, str) else value
    if not isinstance(refs, list) or not all(
        isinstance(r, str) and r.strip() for r in refs
    ):
        raise ASHConfigSourceError(
            f"'{EXTENDS_KEY}' in {describe_config_path(path)} must be a path or a "
            f"list of paths, got {value!r}"
        )
    return [r.strip() for r in refs]


def _base_not_permitted(ref: str, extending: Path) -> ASHConfigInputNotPermittedError:
    # Names the ref as written, never what it resolves to; see "Base paths".
    return ASHConfigInputNotPermittedError(
        f"'{EXTENDS_KEY}: {ref}' in {describe_config_path(extending)} names a "
        "file outside the directories this caller may read config from."
    )


def _resolve_base_path(
    ref: str,
    extending: Path,
    root: Path,
    permit_base: Optional[PermitBase] = None,
) -> Tuple[Path, Optional[FileIdentity]]:
    """The base `ref` names, resolved and checked, and the identity checked.

    The identity is the file the resolved path led to when the checks ran; the
    read of the base must open that same file (``read_config_bytes(expect=)``).
    """
    if _URL_PATTERN.match(ref):
        raise ASHConfigSourceError(
            f"'{EXTENDS_KEY}: {ref}' in {describe_config_path(extending)} looks like "
            "a URL. ASH does not fetch remote configs; copy the file into the "
            "repository and extend it by path."
        )
    if "\x00" in ref:
        raise ASHConfigSourceError(
            f"'{EXTENDS_KEY}' in {describe_config_path(extending)} contains a NUL "
            "character"
        )
    candidate = Path(ref)
    relative = not candidate.is_absolute()
    if relative:
        candidate = extending.parent / candidate
    lexical = Path(os.path.normpath(candidate))
    # Refused before resolve() touches the filesystem when the spelling alone
    # leaves the root. For a relative ref that is a `..` escape. On Windows it
    # also covers an absolute ref, because resolving a UNC path opens a
    # connection to the host it names. A POSIX absolute ref is resolved first,
    # since it may name a location inside the root through a symlinked prefix.
    if not lexical.is_relative_to(root) and (relative or os.name == "nt"):
        if permit_base is not None:
            # Under a caller's gate every refused base is reported one way, so
            # the refusal does not depend on which check caught it -- or on the
            # platform, since on Windows this check runs before resolve() for
            # an absolute ref too.
            raise _base_not_permitted(ref, extending)
        raise ASHConfigSourceError(
            f"'{EXTENDS_KEY}: {ref}' in {describe_config_path(extending)} names "
            f"{lexical.as_posix()}, which is outside the directory config bases "
            f"must stay inside ({root.as_posix()})."
        )
    resolved = candidate.resolve()
    checked = file_identity(resolved)
    # Ahead of the root check, whose message names the resolved target: this
    # refusal must read the same whether or not that target exists.
    if permit_base is not None and not permit_base(resolved):
        raise _base_not_permitted(ref, extending)
    if not resolved.is_relative_to(root):
        # `extending` is already resolved, so a lexically normalized candidate
        # that is inside the root got out only by following a symlink.
        how = " through a symlink" if lexical.is_relative_to(root) else ""
        raise ASHConfigSourceError(
            f"'{EXTENDS_KEY}: {ref}' in {describe_config_path(extending)} resolves"
            f"{how} to {resolved.as_posix()}, which is outside the directory "
            f"config bases must stay inside ({root.as_posix()})."
        )
    return resolved, checked


@dataclass(frozen=True)
class _Setting:
    """One field of a config model, as the model reads it from a document."""

    #: The spelling a merged value is written under: the alias, else the name.
    written: str
    #: Every spelling the model reads, lowest precedence first.
    spellings: Tuple[str, ...]
    #: The model the value is validated as, when it is one.
    model: Optional[type[BaseModel]]
    #: Where a document holds several spellings, whether the model takes the
    #: last one whole (pydantic's alias over name) rather than merging them key
    #: by key (``_PluginConfigSegment``'s validator).
    whole: bool


def _value_model(annotation: Any) -> Optional[type[BaseModel]]:
    """The pydantic model a field's mapping is validated as, or None.

    Only through ``Optional`` and other unions: a list is replaced whole, and the
    keys of a ``Dict`` field are names, not settings.
    """
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation
    if typing.get_origin(annotation) in (typing.Union, types.UnionType):
        models = {_value_model(arg) for arg in typing.get_args(annotation)}
        models.discard(None)
        return models.pop() if len(models) == 1 else None
    return None


@functools.lru_cache(maxsize=None)
def _settings_of(model: type[BaseModel]) -> Dict[str, _Setting]:
    """Each field of ``model``, keyed by every spelling the model reads it under."""
    segment = issubclass(model, _PluginConfigSegment)
    by_name = segment or bool(
        model.model_config.get("populate_by_name")
        or model.model_config.get("validate_by_name")
    )
    settings: Dict[str, _Setting] = {}
    for name, info in model.model_fields.items():
        alias = info.alias if info.alias and info.alias != name else None
        if alias is None:
            spellings: Tuple[str, ...] = (name,)
        elif by_name:
            spellings = (name, alias)
        else:
            spellings = (alias,)
        setting = _Setting(
            written=alias or name,
            spellings=spellings,
            model=_value_model(info.annotation),
            whole=not segment,
        )
        for spelling in spellings:
            settings[spelling] = setting
    return settings


def _fold(values: List[Any], setting: _Setting) -> Any:
    """One document's spellings of ``setting``, read as the model reads them."""
    if setting.whole:
        return values[-1]
    folded = values[0]
    for value in values[1:]:
        folded = deep_merge(folded, value, setting.model)
    return folded


def deep_merge(base: Any, overlay: Any, model: Optional[type[BaseModel]] = None) -> Any:
    """Merge `overlay` over `base` under the rules in the module docstring.

    ``model`` is the config model both mappings are read as (``AshConfig`` for
    a whole config document). With it, a setting is merged under the spellings
    the model reads (see "Spellings"); without it, keys that differ only in
    ``-`` versus ``_`` are one key.
    """
    if not isinstance(base, dict) or not isinstance(overlay, dict):
        return copy.deepcopy(overlay)
    merged = copy.deepcopy(base)
    rest = dict(overlay)
    settings = _settings_of(model) if model is not None else {}
    # The spellings of the fields the overlay sets under a spelling the model
    # reads: settled here, so no other key of the overlay reaches them below.
    settled: set[str] = set()
    for setting in dict.fromkeys(settings.values()):
        upper = [rest.pop(key) for key in setting.spellings if key in rest]
        if not upper:
            continue
        settled.update(setting.spellings)
        lower = [merged.pop(key) for key in setting.spellings if key in merged]
        value = _fold(upper, setting)
        merged[setting.written] = (
            deep_merge(_fold(lower, setting), value, setting.model)
            if lower
            else copy.deepcopy(value)
        )
    if model is not None and issubclass(model, _PluginConfigSegment):
        # A plugin's section: every spelling get_plugin_config reads for the
        # same plugin is one section, under the overlay's spelling.
        for key in list(rest):
            names = plugin_key_lookup_names(key)
            same = [
                other
                for other in merged
                if other not in settings and plugin_key_lookup_names(other) & names
            ]
            if not same:
                continue
            lower_value: Any = merged.pop(same[0])
            for other in same[1:]:
                lower_value = deep_merge(lower_value, merged.pop(other))
            merged[key] = deep_merge(lower_value, rest.pop(key))
    # The rest: a key the model does not read as a field. Keys that differ
    # only in '-' versus '_' are one key here, as they always were, so an
    # overlay's unread spelling of a field still reaches the base's spelling of
    # it -- but not a field the overlay set above under a spelling the model
    # reads, which wins. Those the overlay spells exactly as the base does (or
    # that are new) are applied last, so where the overlay carries both
    # spellings of one key, its exact spelling wins.
    base_keys = dict.fromkeys(
        key for key in base if key in merged and key not in settled
    )
    items = sorted(
        rest.items(),
        key=lambda kv: _resolve_dict_key(base_keys, kv[0]) == kv[0],
    )
    for key, value in items:
        target = _resolve_dict_key(base_keys, key)
        if target in merged:
            field = settings.get(target)
            merged[target] = deep_merge(
                merged[target], value, field.model if field else None
            )
        else:
            merged[target] = copy.deepcopy(value)
    return merged


def _unescape(segment: str) -> str:
    return segment.replace("~1", "/").replace("~0", "~")


def _escape(segment: str) -> str:
    return segment.replace("~", "~0").replace("/", "~1")


def _normalize_pointer(document: Any, pointer: str) -> str:
    """Respell a JSON pointer's keys the way `document` spells them."""
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        return pointer
    current = document
    segments = []
    for raw in pointer[1:].split("/"):
        segment = _unescape(raw)
        if isinstance(current, dict):
            segment = _resolve_dict_key(current, segment)
            current = current.get(segment)
        elif isinstance(current, list) and segment.isascii() and segment.isdigit():
            index = int(segment)
            current = current[index] if index < len(current) else None
        else:
            current = None
        segments.append(_escape(segment))
    return "/" + "/".join(segments)


def _apply_patch(document: Dict[str, Any], ops: Any, path: Path) -> Any:
    where = describe_config_path(path)
    if not isinstance(ops, list):
        raise ASHConfigSourceError(
            f"'{PATCH_KEY}' in {where} must be a list of JSON-Patch operations, "
            f"got {type(ops).__name__}"
        )
    result: Any = document
    for index, op in enumerate(ops):
        if not isinstance(op, dict) or not isinstance(op.get("path"), str):
            raise ASHConfigSourceError(
                f"'{PATCH_KEY}' entry {index} in {where} must be a mapping with "
                f"'op' and 'path', got {op!r}"
            )
        op_name = op.get("op")
        if not isinstance(op_name, str) or op_name not in _PATCH_OPS:
            raise ASHConfigSourceError(
                f"'{PATCH_KEY}' entry {index} in {where} uses op {op.get('op')!r}; "
                f"allowed ops are {', '.join(sorted(_PATCH_OPS))}"
            )
        normalized = dict(op, path=_normalize_pointer(result, op["path"]))
        try:
            result = jsonpatch.apply_patch(result, [normalized], in_place=False)
        except jsonpatch.JsonPatchTestFailed as exc:
            # jsonpatch's own message quotes the value it found, which may come
            # from a base the author of this file did not write.
            raise ASHConfigSourceError(
                f"'{PATCH_KEY}' entry {index} in {where}: the value at "
                f"{op['path']!r} does not equal the value the test op gives"
            ) from exc
        except (jsonpatch.JsonPatchException, jsonpatch.JsonPointerException) as exc:
            raise ASHConfigSourceError(
                f"'{PATCH_KEY}' entry {index} in {where} ({op!r}) failed: {exc}"
            ) from exc
    return result


def _resolve(
    path: Path,
    stack: Tuple[Path, ...],
    state: _ChainState,
    ref: Optional[str] = None,
    env_refused_above: bool = False,
    named: Optional[Path] = None,
    above: Tuple[Path, ...] = (),
    expect: Optional[FileIdentity] = None,
) -> Any:
    real = path.resolve()
    named = path if named is None else named
    if real in stack:
        raise ASHConfigSourceError(
            f"Config '{EXTENDS_KEY}' cycle: {_format_chain(stack + (real,))}"
        )
    if len(stack) > ASH_CONFIG_EXTENDS_MAX_DEPTH:
        raise ASHConfigSourceError(
            f"Config '{EXTENDS_KEY}' chain is deeper than "
            f"{ASH_CONFIG_EXTENDS_MAX_DEPTH} levels: {_format_chain(stack + (real,))}"
        )
    state.files_read += 1
    if state.files_read > ASH_CONFIG_EXTENDS_MAX_FILES:
        raise ASHConfigSourceError(
            f"Config '{EXTENDS_KEY}' chain reads more than "
            f"{ASH_CONFIG_EXTENDS_MAX_FILES} files; stopped at "
            f"{_format_chain(stack + (real,))}"
        )

    if not stack:
        # The root config: a read or parse error propagates as the reader raised
        # it, and resolve_config.read_config_document refuses it.
        # Read and judged as named rather than as `real`, so a refusal names the
        # path the caller gave and not the target of a symlink.
        env_refused = state.refuse_env(path)
        data = read_config_file(path, expect=expect, refuse_env=_env_rule(env_refused))
    else:
        extending = stack[-1]
        if not is_regular_file(real):
            raise ASHConfigSourceError(
                f"'{EXTENDS_KEY}: {ref}' in {describe_config_path(extending)} names "
                f"{real.as_posix()}, which does not exist or is not a file"
            )
        # Judged by the name the entry spells as well as the file it reaches, as
        # the root is: a base reached through a client's link is the client's.
        env_refused = (
            env_refused_above or state.refuse_env(named) or state.refuse_env(real)
        )
        unquoted: Optional[str] = None
        try:
            data = read_config_file(
                real, expect=expect, refuse_env=_env_rule(env_refused)
            )
        except ASHConfigSourceError:
            raise
        except (OSError, UnicodeDecodeError, yaml.YAMLError, ValueError) as exc:
            # json.JSONDecodeError is a ValueError. A base of a client's chain, or
            # one a client delivered, is not quoted: the parser's message repeats
            # the line it stopped at, and a client's link can reach a file on
            # the server. Raised outside the handler, so that message is not the
            # context either.
            if isinstance(exc, OSError) or not (
                env_refused
                or config_is_client_delivered(real)
                or config_is_client_delivered(named)
            ):
                raise ASHConfigSourceError(
                    f"Base config {describe_config_path(real)}, extended by "
                    f"{describe_config_path(extending)}, could not be read: {exc}"
                ) from exc
            mark = getattr(exc, "problem_mark", None)
            where = (
                f" at line {mark.line + 1}, column {mark.column + 1}"
                if mark is not None
                else ""
            )
            unquoted = (
                f"Base config {describe_config_path(real)}, extended by "
                f"{describe_config_path(extending)}, could not be parsed "
                f"({type(exc).__name__}{where})"
            )
        if unquoted is not None:
            raise ASHConfigSourceError(unquoted)
        if not isinstance(data, dict):
            raise ASHConfigSourceError(
                f"Base config {describe_config_path(real)}, extended by "
                f"{describe_config_path(extending)}, must be a mapping, got "
                f"{type(data).__name__}"
            )

    state.documents.setdefault(real, copy.deepcopy(data))
    state.reached(real, named)
    # The file that names a base chose it, so a base is judged by the paths of
    # the files above it too, as env_refused_above carries a refusal down.
    state.chosen_by(real, above)
    anchor = state.anchor_relative_paths is not None and (
        state.anchor_relative_paths(real) and state.anchor_relative_paths(named)
    )
    if anchor:
        # Each operator file's own relative paths are taken from its directory,
        # before the merge loses which file set them (config/operator_paths.py).
        # ``documents`` keeps what the file holds, for the checks of who set what.
        from automated_security_helper.config.operator_paths import (
            anchor_relative_paths,
        )

        data = anchor_relative_paths(data, real.parent)
    if not isinstance(data, dict) or (
        EXTENDS_KEY not in data and PATCH_KEY not in data
    ):
        state.order.append(real)
        state.named.append(named)
        return data

    try:
        own = dict(data)
        refs = _extends_refs(own.pop(EXTENDS_KEY, None), real)
        ops = own.pop(PATCH_KEY, None)
        if anchor:
            from automated_security_helper.config.operator_paths import (
                anchor_patch_operations,
            )

            ops = anchor_patch_operations(ops, real.parent)
        merged: Any = {}
        for base_ref in refs:
            base_path, checked = _resolve_base_path(
                base_ref, real, state.root, state.permit_base
            )
            # The base as its entry spells it, before any symlink is followed:
            # relative to the resolved file that extends it, as base_path is.
            spelled = Path(base_ref)
            base_named = spelled if spelled.is_absolute() else real.parent / spelled
            merged = deep_merge(
                merged,
                _resolve(
                    base_path,
                    stack + (real,),
                    state,
                    base_ref,
                    env_refused,
                    base_named,
                    (real, named, *above),
                    expect=checked,
                ),
                AshConfig,
            )
        merged = deep_merge(merged, own, AshConfig)
        if ops is not None:
            merged = _apply_patch(merged, ops, real)
    except ASHConfigSourceError:
        raise
    except Exception as exc:  # noqa: BLE001 -- see below
        # Anything unforeseen while following `extends` or applying `patch`
        # (an OSError from resolve(), a malformed value no check above caught)
        # must not reach resolve_config's catch-all, which returns the default
        # config. The file was not loaded as written, so it is an error.
        raise ASHConfigSourceError(
            f"Could not resolve '{EXTENDS_KEY}'/'{PATCH_KEY}' in "
            f"{describe_config_path(real)}: {type(exc).__name__}: {exc}"
        ) from exc
    state.order.append(real)
    state.named.append(named)
    return merged


def resolve_config_document(
    config_path: Path,
    confine_to: Optional[Path] = None,
    permit_base: Optional[PermitBase] = None,
    refuse_env: Optional[RefuseEnv] = None,
    anchor_relative_paths: Optional[AnchorPaths] = None,
) -> ResolvedConfigDocument:
    """Read `config_path` and every base it extends into one merged document.

    `permit_base` is checked for every base, in addition to `confine_to`; see
    "Base paths" in the module docstring. It is not checked for `config_path`
    itself, which the caller chose and is responsible for having checked.
    `refuse_env` decides which files of the chain resolve no ``!ENV``; None
    refuses the files an MCP client delivered. See "Environment variables".
    `anchor_relative_paths` judges each file of the chain by its resolved path
    and by the path it was reached by; for a file it accepts under both, the
    relative paths the file sets for the options in ``config/operator_paths.py``
    are taken from its directory. ``resolve_config`` passes one that accepts the
    operator's files. ``documents`` holds each file as written either way.
    """
    config_path = Path(config_path)
    root = (
        Path(confine_to).resolve()
        if confine_to is not None
        else default_confinement_root(config_path)
    )
    state = _ChainState(
        root=root,
        permit_base=permit_base,
        refuse_env=refuse_env or config_is_client_delivered,
        anchor_relative_paths=anchor_relative_paths,
    )
    # The root is read as the file the name leads to now, when its caller has
    # just checked it; one swapped in before the open is refused.
    data = _resolve(config_path, (), state, expect=file_identity(config_path))
    return ResolvedConfigDocument(
        data=data,
        chain=state.order,
        root=root,
        named=state.named,
        documents=state.documents,
        names=state.all_names(),
    )


def load_config_document(
    config_path: Path,
    confine_to: Optional[Path] = None,
    permit_base: Optional[PermitBase] = None,
    refuse_env: Optional[RefuseEnv] = None,
    anchor_relative_paths: Optional[AnchorPaths] = None,
) -> Any:
    return resolve_config_document(
        config_path,
        confine_to=confine_to,
        permit_base=permit_base,
        refuse_env=refuse_env,
        anchor_relative_paths=anchor_relative_paths,
    ).data
