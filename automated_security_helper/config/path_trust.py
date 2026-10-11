# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tool config and plugin paths are honored only from outside the scanned tree.

Some scanner options name a file the scanner's tool reads as its own configuration,
or a file it loads as a plugin. Who named the path decides which rule applies:

- A path the operator named (``--config-overrides``, a config file outside the
  scanned tree, or an environment variable) is refused only when it is inside the
  scanned tree itself (``sandbox_grants.in_tree_reason``: the scan root, or the
  outermost checkout holding it) or an MCP client delivered it. The operator may
  keep tool configs in a checkout of their own, such as an ops repository.
- A path a config file inside the scanned tree named, or a file ASH found by name
  in the source directory, is refused when the scanned repository could have
  written it (``sandbox_grants.untrusted_path``: inside any git checkout, or the
  scan root under each name it has). The repository cannot point a tool at a
  file in someone's checkout.

Every name the path has is checked: as written, resolved, and every symlink on
the way. ``OperatorPaths``, recorded on the config by ``resolve_config``, says
which option values the operator named.

Each refusal logs one warning naming the option, however many times the scanner
asks.
"""

from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple, Union

from automated_security_helper.utils.log import ASH_LOGGER

_WARNED: Set[Tuple[str, str]] = set()
_WARNED_LOCK = threading.Lock()


def reset_path_refusal_warnings() -> None:
    """Forget which refusals were already logged (tests)."""
    with _WARNED_LOCK:
        _WARNED.clear()


def _key_part(text: str) -> str:
    return str(text).replace("-", "_").lower()


def _key_segments(key: str) -> List[Tuple[str, bool]]:
    """``a.b[].c`` as ``[("a", False), ("b", True), ("c", False)]``."""
    segments = []
    for part in key.split("."):
        many = part.endswith("[]")
        segments.append((_key_part(part[:-2] if many else part), many))
    return segments


def _leaves(node: Any, segments: List[Tuple[str, bool]]) -> Iterator[Any]:
    """The values at ``segments`` in a parsed config document."""
    if not segments:
        if isinstance(node, list):
            yield from node
        else:
            yield node
        return
    (name, many), rest = segments[0], segments[1:]
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        if _key_part(key) != name:
            continue
        if many and isinstance(value, list):
            for item in value:
                yield from _leaves(item, rest)
        elif not many:
            yield from _leaves(value, rest)


def _same_path(leaf: Any, value: Union[str, Path]) -> bool:
    """Whether a config value names ``value``; a ``file://...::name`` entry by its file."""
    if not isinstance(leaf, str):
        return False
    if leaf.startswith("file://"):
        leaf = leaf[len("file://") :].partition("::")[0]
    return leaf == str(value)


@dataclass
class OperatorPaths:
    """Which tool paths in a config the operator named; see the module docstring.

    Recorded by ``resolve_config`` as ``AshConfig._operator_paths``. A value
    counts as the operator's only when one of these sets it at the option's key,
    so a value a scanner adds later (detect-secrets' entries from a baseline file
    in the tree) does not, even under the same key.

    Attributes:
        documents: Config documents the operator wrote: the merged chain, before
            any override, when every file of it is the operator's (outside the
            scanned tree and not an MCP client's); or the selected file's own
            document when that file is the operator's but a file it extends is
            not, so what a base gives it does not count.
        overrides: ``--config-overrides``, as (key, parsed value).
    """

    documents: List[Any] = field(default_factory=list)
    overrides: List[Tuple[str, Any]] = field(default_factory=list)

    def named(self, key: str, value: Union[str, Path]) -> bool:
        """Whether the operator named ``value`` for the option ``key``."""
        segments = _key_segments(key)
        if any(
            _same_path(leaf, value)
            for document in self.documents
            for leaf in _leaves(document, segments)
        ):
            return True
        for override_key, parsed in self.overrides:
            prefix = _key_segments(override_key)
            if [name for name, _ in segments[: len(prefix)]] != [
                name for name, _ in prefix
            ]:
                continue
            rest = segments[len(prefix) :]
            # An override that sets a list (`plugins_used=[...]`) is the list itself.
            items = (
                parsed
                if prefix and segments[len(prefix) - 1][1] and isinstance(parsed, list)
                else [parsed]
            )
            if any(
                _same_path(leaf, value)
                for item in items
                for leaf in _leaves(item, rest)
            ):
                return True
        return False


def parse_overrides(config_overrides: Optional[List[str]]) -> List[Tuple[str, Any]]:
    """``key=value`` and ``key+=value`` overrides as (key, parsed value)."""
    import yaml

    parsed = []
    for override in config_overrides or []:
        key, separator, raw = override.partition("=")
        if not separator:
            continue
        try:
            value = yaml.safe_load(raw)
        except yaml.YAMLError:
            value = raw
        parsed.append((key.removesuffix("+").strip(), value))
    return parsed


#: A key that names an environment variable: the operator's environment.
_ENVIRONMENT_KEY = re.compile(r"[A-Z][A-Z0-9_]*")


def named_by_operator(key: str, value: Union[str, Path], config: Any) -> bool:
    """Whether the operator named ``value``: by an environment variable, or by an
    option ``OperatorPaths`` says the operator set."""
    if _ENVIRONMENT_KEY.fullmatch(key):
        return True
    operator_paths = getattr(config, "_operator_paths", None)
    return isinstance(operator_paths, OperatorPaths) and operator_paths.named(
        key, value
    )


def operator_reason(
    path: Union[str, Path], scan_root: Union[str, Path]
) -> Optional[str]:
    """Why a path the operator named is refused, or None: inside the scanned tree
    itself (``sandbox_grants.in_tree_reason``), or delivered by an MCP client."""
    from automated_security_helper.config.sandbox_grants import in_tree_reason

    reason = in_tree_reason(Path(path), Path(scan_root))
    if reason is not None:
        return reason
    return _client_delivered_reason(path)


def _client_delivered_reason(path: Union[str, Path]) -> Optional[str]:
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    if config_is_client_supplied(path) or config_is_client_supplied(
        os.path.realpath(path)
    ):
        return "it is a file an MCP client delivered"
    return None


def in_scanned_tree(path: Union[str, Path], scan_root: Union[str, Path]) -> bool:
    """Whether ``path`` was written by the party whose code is being scanned.

    True for a path the scanned repository could have written
    (``sandbox_grants.untrusted_path``, the same rule ``resolve_config`` applies to
    config files: inside any git checkout, or inside the scan root), and, under the
    MCP server,
    for any file an MCP client delivered (``cli.mcp.sandbox
    .config_is_client_supplied``: a delivered tree, an upload or its staging, in
    this session or another), which a client-written config could otherwise name
    from outside the tree it scans. The one membership test this module and
    ``plugin_module_trust`` use, so the rule changes in one place.
    """
    return scanned_tree_reason(path, scan_root) is not None


def scanned_tree_reason(
    path: Union[str, Path], scan_root: Union[str, Path]
) -> Optional[str]:
    """Why ``in_scanned_tree`` holds for ``path``, for a warning, or None.

    Pass ``path`` as it was named. Both it and its resolved path are checked, so a
    symlink is judged by where it sits and by where it points.
    """
    # Imported here: sandbox_grants imports ash_config, which imports the scanners
    # that import this module.
    from automated_security_helper.config.sandbox_grants import untrusted_reason

    reason = untrusted_reason(Path(path), Path(scan_root))
    if reason is not None:
        return reason
    return _client_delivered_reason(path)


#: Fallback working directories already made, by filesystem root, so a process
#: makes at most one per root (see cwd_outside_scanned_tree).
_FALLBACK_CWDS: Dict[str, Path] = {}


def _remove_fallback_cwds() -> None:
    """Remove the fallback working directories at exit; rmdir leaves any that hold anything."""
    for directory in _FALLBACK_CWDS.values():
        try:
            os.rmdir(directory)
        except OSError:
            pass
    _FALLBACK_CWDS.clear()


def _new_directory(parent: Optional[Path]) -> Optional[Path]:
    """A new empty directory under ``parent`` (the system temp dir for None)."""
    import tempfile

    try:
        return Path(tempfile.mkdtemp(prefix="ash-tool-cwd-", dir=parent))
    except OSError:
        return None


def cwd_outside_scanned_tree(
    target: Union[str, Path],
    *,
    results_dir: Union[str, Path],
    source_dir: Union[str, Path],
    config: Any = None,
) -> Path:
    """A working directory for a tool that reads its config file from its cwd.

    Normally the filesystem root of ``target``: outside the scanned tree, and with
    every path relative to it absolute, which checkov_scanner.rewrite_checkov_paths
    relies on. When that root is inside the tree itself (a source directory that
    is a drive root, such as a ``subst`` or mapped drive on Windows, or a scan of a
    whole filesystem), a new empty directory is made instead, in this order:

    1. In the system temp directory, when that is outside the tree. On Windows
       that is another drive, where checkov writes paths without the drive, so
       they still read as relative to the target's root.
    2. Directly under the target's root. checkov removes the ``/..`` its paths
       start with, so a directory one level below the root gives the same paths
       as the root.
    3. Under ``results_dir``, which a sandboxed tool can enter. checkov's paths
       can then lose directories the file shares with the results directory, so
       this is used only when 1 and 2 are not possible, and under a sandbox.

    Each is new and empty, so it holds no config file. One is made per root and
    process and reused, and removed at exit if it is still empty; nothing is
    cleared.
    """
    root = getattr(config, "_scanned_root", None) or source_dir
    anchor = Path(Path(os.path.abspath(target)).anchor)
    if not in_scanned_tree(anchor, root):
        return anchor
    from automated_security_helper.utils.sandbox.scope import active_scope

    if active_scope() is None:
        cached = _FALLBACK_CWDS.get(anchor.as_posix())
        if (
            cached is not None
            and cached.is_dir()
            and not any(cached.iterdir())
            and (cached.parent == anchor or not in_scanned_tree(cached, root))
        ):
            return cached
        for parent in (None, anchor):
            made = _new_directory(parent)
            if made is None:
                continue
            if parent is None and in_scanned_tree(made, root):
                made.rmdir()
                continue
            if not _FALLBACK_CWDS:
                import atexit

                atexit.register(_remove_fallback_cwds)
            _FALLBACK_CWDS[anchor.as_posix()] = made
            return made
    directory = Path(os.path.abspath(results_dir))
    directory.mkdir(parents=True, exist_ok=True)
    made = _new_directory(directory)
    if made is None:
        raise OSError(f"cannot create a working directory under {directory}")
    ASH_LOGGER.warning(
        f"The filesystem root of {Path(target).as_posix()} is inside the scanned "
        f"tree, so the tool runs from {made.as_posix()}; paths in its findings "
        "may leave out directories they share with that location."
    )
    return made


def resolved_path(value: Union[str, Path], source_dir: Union[str, Path]) -> Path:
    """``value`` as the tool will read it: ``~`` expanded, a relative path taken from
    ``source_dir``, and symlinks and ``..`` resolved.

    ``honored_path`` checks this path and returns it, so a caller that hands the
    tool the returned value hands it exactly the file that was checked.
    """
    path = Path(os.path.expanduser(str(value)))
    if not path.is_absolute():
        path = Path(source_dir) / path
    return Path(os.path.realpath(path))


def honored_path(
    value: Union[str, Path, None],
    *,
    source_dir: Union[str, Path],
    key: str,
    config: Any = None,
) -> Optional[Path]:
    """The resolved path to hand the tool, or None when it may not be used.

    Callers pass the tool this return value and nothing rebuilt from ``value``.
    Which rule applies depends on who named the path; see the module docstring.

    Args:
        value: The configured or discovered path. None or blank returns None.
        source_dir: The scan's source directory. Relative paths are taken from it.
        key: The option or file name the warning names: a dotted option key, an
            environment variable's name, or a description of a file found by
            name. ``named_by_operator`` reads it.
        config: The scan's AshConfig. When it records a wider scanned root
            (``AshConfig._scanned_root``, the workspace root in workspace mode),
            the tree is taken from that instead of from ``source_dir``; its
            ``_operator_paths`` says which option values the operator named.
    """
    if value is None or str(value).strip() == "":
        return None
    path = resolved_path(value, source_dir)
    root = getattr(config, "_scanned_root", None) or source_dir
    # Checked as named, not as resolved: scanned_tree_reason checks both, so a link
    # the repository planted is judged by where it sits as well as where it points.
    named = Path(os.path.expanduser(str(value)))
    if not named.is_absolute():
        named = Path(source_dir) / named
    operator = named_by_operator(key, value, config)
    if operator:
        reason = operator_reason(named.absolute(), root)
    else:
        reason = scanned_tree_reason(named.absolute(), root)
    if reason is None:
        return path
    with _WARNED_LOCK:
        first = (key, path.as_posix()) not in _WARNED
        _WARNED.add((key, path.as_posix()))
    if first:
        if operator:
            advice = (
                "A file inside the scanned tree, or one an MCP client delivered, is "
                "not passed to the tool; name one outside it."
            )
        else:
            advice = (
                "A file that a config inside the scanned tree names, or that ASH "
                "finds there, is passed to the tool only from outside every git "
                "checkout and the scanned directory. To use a file in a checkout of "
                "your own, name it with --config-overrides or in a config file "
                "outside the scanned tree."
            )
        ASH_LOGGER.warning(f"Ignoring {key} ({named.as_posix()}): {reason}. {advice}")
    return None
