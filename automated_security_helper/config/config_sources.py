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
``remove``. Keys that differ only in ``-`` versus ``_`` are one key, the same
equivalence ``--config-overrides`` uses (``_resolve_dict_key``), so a base that
writes ``cdk-nag`` and a child that writes ``cdk_nag`` merge instead of standing
side by side. JSON-Patch pointers are matched to the document's own spelling
the same way.

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
``default_confinement_root``.

A caller can narrow that further with ``permit_base``, a predicate every base
must also pass after its symlinks are resolved. The MCP server passes one built
from the calling session's allowed config roots
(``cli/mcp/sandbox.config_base_gate``), so a grant naming a ``.ash/`` directory
confines the chain to that directory rather than to its parent. The predicate is
consulted before the confinement root, and its refusal,
``ASHConfigInputNotPermittedError``, names the ``extends`` entry as written and
not the path it resolved to. Without a predicate the rules above are unchanged.

Bounds
------
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

Failure
-------
Every failure here raises ``ASHConfigSourceError``, which ``resolve_config``
re-raises instead of falling back to the default config. A root config file
that fails to parse as YAML or JSON keeps its existing behavior (default config
plus a resolution warning); a base that fails to parse is an error, because the
file that names it was not loaded as written.
"""

from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# jsonpatch ships no type information (no py.typed, no stubs package).
import jsonpatch  # type: ignore[import-untyped]
import yaml

from automated_security_helper.config.ash_config import (
    ENV_REFERENCE_PATTERN,
    load_yaml_config,
    resolve_env_references,
)
from automated_security_helper.core.constants import (
    ASH_CONFIG_EXTENDS_MAX_DEPTH,
    ASH_CONFIG_EXTENDS_MAX_FILES,
    ASH_CONFIG_FILE_NAMES,
    ASH_PYPROJECT_FILE_NAME,
    ASH_RC_FILE_NAMES,
)
from automated_security_helper.core.exceptions import (
    ASHConfigInputNotPermittedError,
    ASHConfigSourceError,
)
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


def _read_toml_text(path: Path) -> str:
    """A TOML file's text. A leading UTF-8 byte order mark is dropped, since
    tomllib rejects it and editors on some platforms write one."""
    text = Path(path).read_text(encoding="utf-8")
    return text.removeprefix("\ufeff")


def _tool_ash_line(path: Path) -> Optional[int]:
    try:
        text = _read_toml_text(path)
    except (OSError, UnicodeDecodeError):
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
    """The source discovery selected, and every other source it found."""

    selected: Optional[ConfigSource] = None
    ignored: List[ConfigSource] = field(default_factory=list)


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
        if _TOOL_ASH_PATTERN.search(Path(path).read_bytes().decode("latin-1")):
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


def _pyproject_is_a_source(path: Path, found_before: List[ConfigSource]) -> bool:
    """Probe pyproject.toml without letting it break an unrelated config.

    When a higher-precedence source already exists, pyproject.toml is probed
    only to report it as ignored, so nothing about it may fail the load: before
    #313 a repository with .ash/.ash.yaml was unaffected by whatever its
    pyproject.toml held. When it would be the selected source, a pyproject that
    declares [tool.ash] but cannot be parsed fails closed. One that cannot be
    read at all is skipped with a warning either way, because there is no way
    to tell whether it configures ASH, and most pyproject.toml files do not.
    """
    try:
        return pyproject_has_ash_table(path)
    except OSError as exc:
        ASH_LOGGER.warning(
            f"Could not read {path.as_posix()} ({exc}); it is not used as an ASH "
            "config source."
        )
        return False
    except ASHConfigSourceError as exc:
        if not found_before:
            raise
        ASH_LOGGER.warning(
            f"Ignoring {path.as_posix()}: {found_before[0].label} takes precedence, "
            f"and the [tool.ash] table there could not be read ({exc})."
        )
        return False


def discover_config_source(search_dir: Path) -> ConfigDiscovery:
    """Find every config source in `search_dir` and select one by precedence."""
    search_dir = Path(search_dir)
    found: List[ConfigSource] = []
    for name in ASH_CONFIG_FILE_NAMES:
        for candidate in (search_dir / name, search_dir / ".ash" / name):
            if candidate.is_file():
                found.append(ConfigSource(candidate, SOURCE_KIND_DEDICATED))
    for name in ASH_RC_FILE_NAMES:
        candidate = search_dir / name
        if candidate.is_file():
            found.append(ConfigSource(candidate, SOURCE_KIND_ASHRC))
    pyproject = search_dir / ASH_PYPROJECT_FILE_NAME
    if pyproject.is_file() and _pyproject_is_a_source(pyproject, found):
        found.append(ConfigSource(pyproject, SOURCE_KIND_PYPROJECT))
    if not found:
        return ConfigDiscovery()
    return ConfigDiscovery(selected=found[0], ignored=found[1:])


def log_config_discovery(
    discovery: ConfigDiscovery, announce_selected: bool = True
) -> None:
    """Say which source is used and which were found but ignored.

    ``announce_selected`` is False for a caller that reports the selected file
    through its own logger; the ignored sources are always reported here.
    """
    selected = discovery.selected
    if selected is None:
        return
    if announce_selected:
        ASH_LOGGER.info(f"Using ASH configuration from {selected.label}")
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
        ASH_LOGGER.warning(message)


def _resolve_toml_env(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _resolve_toml_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_toml_env(v) for v in value]
    if isinstance(value, str) and ENV_REFERENCE_PATTERN.match(value):
        return resolve_env_references(value)
    return value


def read_config_file(path: Path) -> Any:
    """Parse one config file, without resolving its `extends`.

    A ``pyproject.toml`` yields its ``[tool.ash]`` table; any other ``.toml``
    file is a config at its top level. YAML and JSON are read exactly as
    ``AshConfig.from_file`` always read them.
    """
    path = Path(path)
    if path.name.endswith(".json"):
        with open(path, mode="r", encoding="utf-8") as f:
            return json.load(f)
    if path.name.endswith(".toml"):
        try:
            text = _read_toml_text(path)
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
        return _resolve_toml_env(document)
    with open(path, mode="r", encoding="utf-8") as f:
        return load_yaml_config(f)


def default_confinement_root(
    config_path: Path, source_dir: Optional[Path] = None
) -> Path:
    """The directory every base in `config_path`'s chain must stay inside.

    The scan's source directory when `config_path` is inside it, so a project
    config may extend a file anywhere in the repository being scanned.
    Otherwise -- no source directory, or a config kept outside it -- the root
    config's own directory, or the parent of ``.ash/`` for a file in ``.ash/``.
    """
    config_real = Path(config_path).resolve()
    if source_dir is not None:
        source_real = Path(source_dir).resolve()
        if config_real.is_relative_to(source_real):
            return source_real
    parent = config_real.parent
    if parent.name == ".ash":
        parent = parent.parent
    return parent


@dataclass
class ResolvedConfigDocument:
    """A config's merged data, and the files it was built from.

    ``chain`` lists every file read, in merge order: bases before the files that
    extend them, the root config last. A file reached on two branches appears
    twice, because it was merged twice.
    """

    data: Any
    chain: List[Path] = field(default_factory=list)
    root: Optional[Path] = None


@dataclass
class _ChainState:
    root: Path
    permit_base: Optional[PermitBase] = None
    files_read: int = 0
    order: List[Path] = field(default_factory=list)


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
) -> Path:
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
    return resolved


def deep_merge(base: Any, overlay: Any) -> Any:
    """Merge `overlay` over `base` under the rules in the module docstring."""
    if not isinstance(base, dict) or not isinstance(overlay, dict):
        return copy.deepcopy(overlay)
    merged = copy.deepcopy(base)
    base_keys = dict.fromkeys(base)
    # Keys the overlay spells exactly as the base does (or that are new) are
    # applied last, so where the overlay itself carries both spellings of one
    # key, its exact spelling wins, matching how a single file is read.
    items = sorted(
        overlay.items(),
        key=lambda kv: _resolve_dict_key(base_keys, kv[0]) == kv[0],
    )
    for key, value in items:
        target = _resolve_dict_key(base_keys, key)
        if target in merged:
            merged[target] = deep_merge(merged[target], value)
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
) -> Any:
    real = path.resolve()
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
        # The root config: parse errors behave exactly as they always have.
        data = read_config_file(path)
    else:
        extending = stack[-1]
        if not real.is_file():
            raise ASHConfigSourceError(
                f"'{EXTENDS_KEY}: {ref}' in {describe_config_path(extending)} names "
                f"{real.as_posix()}, which does not exist or is not a file"
            )
        try:
            data = read_config_file(real)
        except ASHConfigSourceError:
            raise
        except (OSError, UnicodeDecodeError, yaml.YAMLError, ValueError) as exc:
            # json.JSONDecodeError is a ValueError.
            raise ASHConfigSourceError(
                f"Base config {describe_config_path(real)}, extended by "
                f"{describe_config_path(extending)}, could not be read: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise ASHConfigSourceError(
                f"Base config {describe_config_path(real)}, extended by "
                f"{describe_config_path(extending)}, must be a mapping, got "
                f"{type(data).__name__}"
            )

    if not isinstance(data, dict) or (
        EXTENDS_KEY not in data and PATCH_KEY not in data
    ):
        state.order.append(real)
        return data

    try:
        own = dict(data)
        refs = _extends_refs(own.pop(EXTENDS_KEY, None), real)
        ops = own.pop(PATCH_KEY, None)
        merged: Any = {}
        for base_ref in refs:
            base_path = _resolve_base_path(
                base_ref, real, state.root, state.permit_base
            )
            merged = deep_merge(
                merged, _resolve(base_path, stack + (real,), state, base_ref)
            )
        merged = deep_merge(merged, own)
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
    return merged


def resolve_config_document(
    config_path: Path,
    confine_to: Optional[Path] = None,
    permit_base: Optional[PermitBase] = None,
) -> ResolvedConfigDocument:
    """Read `config_path` and every base it extends into one merged document.

    `permit_base` is checked for every base, in addition to `confine_to`; see
    "Base paths" in the module docstring. It is not checked for `config_path`
    itself, which the caller chose and is responsible for having checked.
    """
    config_path = Path(config_path)
    root = (
        Path(confine_to).resolve()
        if confine_to is not None
        else default_confinement_root(config_path)
    )
    state = _ChainState(root=root, permit_base=permit_base)
    data = _resolve(config_path, (), state)
    return ResolvedConfigDocument(data=data, chain=state.order, root=root)


def load_config_document(
    config_path: Path,
    confine_to: Optional[Path] = None,
    permit_base: Optional[PermitBase] = None,
) -> Any:
    return resolve_config_document(
        config_path, confine_to=confine_to, permit_base=permit_base
    ).data
