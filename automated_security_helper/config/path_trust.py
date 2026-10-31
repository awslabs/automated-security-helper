# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tool config and plugin paths are honored only from outside the scanned tree.

Some scanner options name a file the scanner's tool reads as its own configuration,
or a file it loads as a plugin. Who named the path decides which rule applies:

- A path the operator named (``--config-overrides``, a config file outside every
  git checkout and the scanned directory, or an environment variable) is refused
  only when it is inside the scanned tree itself (``sandbox_grants.in_tree_reason``:
  the scan root, or the outermost checkout holding it), when its name cannot be
  resolved to the end (a directory on the way cannot be searched, so the walk that
  looks for a link in the tree stopped), or when an MCP client delivered it. The
  operator may keep tool configs in a checkout of their own, such as an ops
  repository.
- A path a config file inside any git checkout or the scanned directory named, or
  a file ASH found by name in the source directory, is refused when the scanned
  repository could have written it (``sandbox_grants.untrusted_path``: inside any
  git checkout, or the scan root under each name it has). The repository cannot
  point a tool at a file in someone's checkout. A config file in an ops checkout
  counts here: it is the tier ``sandbox_grants.repository_written`` gives config
  files, so a file that may not grant does not name tool paths as the operator.

Every name the path has is checked: as written, resolved, and every symlink on
the way. ``OperatorPaths``, recorded on the config by ``resolve_config``, says
which option values the operator named.

Each refusal logs one warning naming the option, however many times the scanner
asks.

Configured tool inputs that are refused or missing
--------------------------------------------------

One rule covers a tool input the configuration names (a config file or a
baseline file) when that input is refused or does not exist: it never falls back
to anything the repository being scanned can influence. No discovery by name, no
in-tree candidate and no checkout candidate takes its place. Where the tool
tolerates running without the input and looks for one itself when it is given
none, or demands one, it gets a neutral file ASH owns. Where the tool neither
looks nor demands, it runs without it. Each case logs a warning that says which
happened. Discovery still runs when nothing was configured at all; the rule
governs only the configured-but-refused and configured-but-missing arms.

A tool that discovers its own config from its working directory or its targets
(syft ``.syft.yaml``, grype ``.grype.yaml``, bandit ``.bandit``) would take the
repository's file the moment it is handed none, so for these a refused or
missing input is replaced by an explicit neutral file, not by the absence of
the option.

The call sites, by module path:

* ``plugin_modules/ash_builtin/scanners/bandit_scanner.py``: an empty ``--ini``
  file ASH writes, so ``.bandit`` is not searched for.
* ``plugin_modules/ash_builtin/scanners/grype_scanner.py``: an empty
  ``--config`` file ASH writes.
* ``plugin_modules/ash_builtin/scanners/syft_scanner.py``: an empty
  ``--config`` file ASH writes.
* ``plugin_modules/ash_builtin/scanners/checkov_scanner.py``: runs with no
  ``--config-file``, from a working directory outside the scanned tree.
* ``plugin_modules/ash_builtin/scanners/detect_secrets_scanner.py``: runs
  without a baseline.
* ``plugin_modules/ash_ferret_plugins/ferret_scanner.py``: the tool demands a
  config, so it gets the default bundled with ASH (refused) or the empty file
  ASH writes (missing), both ASH's own.
* ``plugin_modules/ash_trivy_plugins/trivy_repo_scanner.py``
  (``_trivy_input_file``): the demanded-input arm. A refused option falls to the
  operator's environment variable and then to a neutral file ASH writes into the
  results directory; a configured file that is not a file stops the scan. Nothing
  it falls to is influenced by the repository.
"""

from __future__ import annotations

import os
import re
import shutil
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Collection,
    Dict,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

from automated_security_helper.config.confinement_remedy import (
    KEEP_A_SETTING,
    LET_THE_WALK_FINISH,
)
from automated_security_helper.utils.display_text import escape_controls
from automated_security_helper.utils.link_locations import link_locations
from automated_security_helper.utils.log import ASH_LOGGER, current_run_log_scope

if TYPE_CHECKING:
    from automated_security_helper.config.sandbox_grants import WalkJudgment

#: The path refusals already logged, as (run log scope, option key, path). Keyed
#: on the run's log scope so a long-lived process (the MCP server) logs a
#: refusal again for a later scan run that refuses the same option and path;
#: within one run the many per-path checks stay deduplicated. None is the scope
#: outside every run. The derived-root clause of refused_derived_product adds
#: its entries as (option key, path), without the scope, so the declared shape
#: is a tuple of optional strings.
_WARNED: Set[Tuple[Optional[str], ...]] = set()
_WARNED_LOCK = threading.Lock()

#: The scan run the derived roots recorded and judged here belong to, set by
#: :func:`derived_roots_scope`; None outside every run.
_DERIVED_ROOTS_RUN: ContextVar[Optional[str]] = ContextVar(
    "ash_derived_roots_run", default=None
)
#: Held over each read-and-replace of a config's derived-root record, so two
#: runs recording on one config at once never lose each other's roots.
_DERIVED_ROOTS_LOCK = threading.Lock()


def reset_path_refusal_warnings() -> None:
    """Forget which refusals were already logged (tests)."""
    with _WARNED_LOCK:
        _WARNED.clear()


def _key_part(text: str) -> str:
    """A key as config merging compares it: ``-`` and ``_`` alike, case kept."""
    return str(text).replace("-", "_")


def _key_segments(key: str) -> List[Tuple[str, bool]]:
    """``a.b[].c`` as ``[("a", False), ("b", True), ("c", False)]``."""
    segments = []
    for part in key.split("."):
        many = part.endswith("[]")
        segments.append((_key_part(part[:-2] if many else part), many))
    return segments


def _section_key_matches(key: Any, name: str, parent: Optional[str]) -> bool:
    """Whether document key ``key`` is the option segment ``name``.

    Directly under a plugin segment (``scanners``, ``reporters``,
    ``converters``) a section is matched under the fold the configuration
    reads it by (``folded_section_name``: ASCII case and the separators
    dropped), so an operator's override written under ``scanners.Syft`` or
    ``scanners.detectsecrets`` is credited to the section the document holds.
    Elsewhere the two separators are alike and case is kept, as config
    merging compares keys.
    """
    if not isinstance(key, str):
        return False
    if parent is not None:
        from automated_security_helper.config.plugin_section_names import (
            PLUGIN_SEGMENT_KEYS,
            folded_section_name,
        )

        if parent in PLUGIN_SEGMENT_KEYS:
            return folded_section_name(key) == folded_section_name(name)
    return _key_part(key) == name


def _leaves(
    node: Any, segments: List[Tuple[str, bool]], parent: Optional[str] = None
) -> Iterator[Any]:
    """The values at ``segments`` in a parsed config document.

    ``parent`` is the key the ``node`` sits under, which decides how the next
    segment is matched (``_section_key_matches``).
    """
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
        if not _section_key_matches(key, name, parent):
            continue
        if many and isinstance(value, list):
            for item in value:
                yield from _leaves(item, rest, name)
        elif not many:
            yield from _leaves(value, rest, name)


def _same_path(leaf: Any, value: Union[str, Path]) -> bool:
    """Whether a config value names ``value``; a ``file://...::name`` entry by its file.

    ``leaf`` is what the operator wrote and is compared as written and as
    ``os.path.normpath`` normalizes it, so an operator spelling such as
    ``/ops/./rules.yaml`` or ``/ops//rules.yaml`` names the anchored form a
    scanner holds. ``value`` is the configuration's value, which a repository
    file may have written, and it is compared ONLY as written: a value carrying
    ``..`` that normalizes to the operator's spelling is not the operator's,
    because the operating system walks ``..`` through whatever the path's
    parent is at run time (a link the repository plants, say), while the
    lexical normalization does not; crediting it would judge such a value by
    the operator's tier. A relative value against an absolute one differs,
    since the document's directory is not known here.
    """
    if not isinstance(leaf, str):
        return False
    if leaf.startswith("file://"):
        leaf = leaf[len("file://") :].partition("::")[0]
    written = str(value)
    return leaf == written or os.path.normpath(leaf) == written


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
            # Segment by segment under the same matching the document walk
            # uses: a section segment under a plugin segment folds, so an
            # override typed under a respelled section is credited too.
            if len(prefix) > len(segments) or any(
                not _section_key_matches(
                    prefix[index][0],
                    segments[index][0],
                    segments[index - 1][0] if index else None,
                )
                for index in range(len(prefix))
            ):
                continue
            rest = segments[len(prefix) :]
            # An override that sets a list (`plugins_used=[...]`) is the list itself.
            items = (
                parsed
                if prefix and segments[len(prefix) - 1][1] and isinstance(parsed, list)
                else [parsed]
            )
            under = segments[len(prefix) - 1][0] if prefix else None
            if any(
                _same_path(leaf, value)
                for item in items
                for leaf in _leaves(item, rest, under)
            ):
                return True
        return False


def parse_overrides(config_overrides: Optional[List[str]]) -> List[Tuple[str, Any]]:
    """``key=value`` and ``key+=value`` overrides as (key, parsed value), parsed
    the way ``resolve_config.apply_config_overrides`` applies them."""
    # Imported here: resolve_config imports this module.
    from automated_security_helper.config.resolve_config import _parse_config_value

    parsed = []
    for override in config_overrides or []:
        key, separator, raw = override.partition("=")
        if not separator:
            continue
        value = _parse_config_value(raw)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            # Digit text (``2024``, ``007``) parses as a number, and a string
            # option keeps the text the operator wrote
            # (``resolve_config._validated_with_overrides``), so a path named
            # that way is compared as written.
            value = raw
        parsed.append((key.removesuffix("+"), value))
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
    """Why a path the operator named is refused, or why a config file is not the
    operator's, or None: inside the scanned tree itself, or a name whose directory
    walk did not finish (``sandbox_grants.in_tree_reason``), delivered by an MCP
    client, or a session profile a client's patch changed."""
    from automated_security_helper.cli.mcp.profile_registry import (
        session_config_was_patched,
    )
    from automated_security_helper.config.sandbox_grants import (
        UNFINISHED_WALK_REASON,
        in_tree_reason,
    )

    reason = in_tree_reason(Path(path), Path(scan_root))
    # A name whose walk did not finish is only guessed to be in the tree, so a
    # reason that holds whatever the walk would find comes ahead of that guess:
    # a delivered file or a patched profile is refused after the walk ends too.
    if reason is not None and reason != UNFINISHED_WALK_REASON:
        return reason
    # Both checks resolve the name themselves, and Path.resolve raises RuntimeError
    # for a symlink loop up to Python 3.12 and OSError for a name the system
    # refuses: the names whose walk stopped are the ones that can raise. A check
    # that cannot answer is not an answer of "no": the walk's reason stands, or, for
    # a name the walk had decided, the one that says resolving it failed.
    try:
        if session_config_was_patched(path):
            return "it is a session profile an MCP client's patch changed"
        return _client_delivered_reason(path) or reason
    except (OSError, RuntimeError):
        return UNFINISHED_WALK_REASON if reason is None else reason


def _client_delivered_reason(path: Union[str, Path]) -> Optional[str]:
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    if config_is_client_supplied(path) or config_is_client_supplied(
        os.path.realpath(path)
    ):
        return "it is a file an MCP client delivered"
    return None


def in_scanned_tree(path: Union[str, Path], scan_root: Union[str, Path, None]) -> bool:
    """Whether ``path`` was written by the party whose code is being scanned.

    The fail-closed collapse of :func:`scanned_tree_judgment`: a path whose
    walk never decided it reads as the scanned party's. A caller whose answer
    feeds a sentence uses ``scanned_tree_judgment`` instead, so the sentence
    can say when the walk never decided it.
    """
    return scanned_tree_judgment(path, scan_root).verdict


def scanned_tree_judgment(
    path: Union[str, Path], scan_root: Union[str, Path, None]
) -> "WalkJudgment":
    """:func:`in_scanned_tree`'s verdict, with whether a walk established it.

    True for a path in a tree the scanned repository controls, judged by the
    membership rule every other site applies (``sandbox_grants.confined_files``
    over ``scanned_trees`` of the scan root, the same trees ``resolve_config``
    checks config files against): tree containment, a name a repository link
    resolves, and the marks the host set for the scan inside a container
    (``marked_repository_written``, ``marked_files_repository_written``), whose
    mounted copies sit in no checkout there. Also true, under the MCP server,
    for any file an MCP client delivered (``cli.mcp.sandbox
    .config_is_client_supplied``: a delivered tree, an upload or its staging, in
    this session or another), which a client-written config could otherwise name
    from outside the tree it scans. The one membership test this module and
    ``plugin_module_trust`` use, so the rule changes in one place. A mark only
    takes grants away. ``decided`` is False when the True verdict is only an
    unfinished walk's fail-closed answer (``ConfinedFiles.undecided``), so a
    sentence that explains the judgment can say the walk stopped instead of
    claiming the tree.
    """
    # Imported here: sandbox_grants imports ash_config, which imports the scanners
    # that import this module.
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied
    from automated_security_helper.config.sandbox_grants import (
        WalkJudgment,
        confined_files,
        scanned_trees,
    )

    # A None scan root is no scanned tree (``scanned_trees(None)`` is no tree),
    # so only the marks and the client-supplied arm below can make the path
    # the scanned party's.
    trees = scanned_trees(None if scan_root is None else Path(scan_root))
    judged = confined_files([Path(path)], trees, named=[Path(path)])
    if judged.members:
        return WalkJudgment(verdict=True, decided=not judged.undecided)
    delivered = config_is_client_supplied(path)
    return WalkJudgment(verdict=delivered, decided=True, client_delivered=delivered)


def scanned_tree_reason(
    path: Union[str, Path], scan_root: Union[str, Path]
) -> Optional[str]:
    """Why the scanned party could have chosen ``path``, for a warning, or None.

    The reason-tier judgment for a path a repository's config names
    (``sandbox_grants.untrusted_reason``: inside any git checkout, or the scan
    root under each name it has, or reached through a link inside one), plus
    the client-delivered arm. Pass ``path`` as it was named. Both it and its
    resolved path are checked, so a
    symlink is judged by where it sits and by where it points.
    """
    # Imported here, in this module's functions: sandbox_grants imports ash_config,
    # which imports the scanners that import this module.
    from automated_security_helper.config.sandbox_grants import untrusted_reason

    reason = untrusted_reason(Path(path), Path(scan_root))
    if reason is not None:
        return reason
    return _client_delivered_reason(path)


def _checkouts_holding(scan_root: Path) -> List[Path]:
    """Every git checkout at or above the scan root, under each name the root has.

    All of them rather than the nearest: a scanned submodule's superproject chose
    the submodule's commit, so its files are the scanned repository's too.
    """
    from automated_security_helper.config.sandbox_grants import (
        _git_shaped,
        scan_root_names,
    )

    # The one checkout definition (sandbox_grants._git_shaped): an empty .git
    # directory, or one a stranger left in a shared parent, marks no checkout
    # here either, so this judgment and the sandbox grants' agree on where the
    # repository ends.
    checkouts: List[Path] = []
    for name in scan_root_names(scan_root):
        for candidate in (name, *name.parents):
            if _git_shaped(candidate / ".git") and candidate not in checkouts:
                checkouts.append(candidate)
    return checkouts


def scanned_checkout_reason(
    path: Union[str, Path], scan_root: Union[str, Path]
) -> Optional[str]:
    """Why ``path`` belongs to the scanned repository, or None when it does not.

    The rule for a detect-secrets baseline, whose settings the operator names
    rather than a tool reading them from its working directory. ``path`` is the
    scanned repository's when it is inside the scan root, or inside a git checkout
    that holds the scan root (scanning ``repo/service`` leaves ``repo/ops`` the
    repository's), by the path as named or as resolved; and, under the MCP server,
    when an MCP client delivered it. A file in some other checkout is not: a team's
    shared baselines kept in a repository of their own, checked out beside the
    scanned one, are the operator's. ``scanned_tree_reason``, which refuses every
    checkout, stays the rule for files a tool reads as its own config or loads as
    code.
    """
    from automated_security_helper.config.sandbox_grants import (
        UNFINISHED_WALK_REASON,
        _named_within,
        _walk_links,
        is_within,
        scan_root_names,
    )

    path = Path(path)
    root = Path(scan_root)
    names = scan_root_names(root)
    if any(is_within(path, name) for name in names) or _named_within(path, names):
        return f"it is inside the scanned directory {root.as_posix()}"
    checkouts = _checkouts_holding(root)
    for checkout in checkouts:
        if is_within(path, checkout) or _named_within(path, [checkout]):
            return (
                f"it is inside the git checkout at {checkout.as_posix()}, which "
                f"holds the scanned directory"
            )
    # A baseline reached through a link that sits in the scanned tree, or in a
    # checkout holding it, was chosen by whoever placed the link: the
    # repository's, as the other reason tiers read it (``in_tree_reason``). A
    # walk that never finished is refused the same way, since the links beyond
    # the stop were never seen.
    links, decided = _walk_links(path)
    for link in links:
        for tree in (*names, *checkouts):
            if is_within(link.parent, tree):
                return (
                    f"it is reached through {link.as_posix()}, a link inside the "
                    f"scanned repository at {tree.as_posix()}"
                )
    if not decided:
        return UNFINISHED_WALK_REASON
    return _client_delivered_reason(path)


#: Fallback working directories already made, so a process makes at most one
#: for each filesystem root and scanned tree, and one for each results
#: directory under a sandbox (see cwd_outside_scanned_tree).
_FALLBACK_CWDS: Dict[str, Path] = {}
#: Held over each look-up, making and recording of a fallback working
#: directory: two scanners that both found none would each make one, and the
#: later record would leave the earlier directory out of the removal at exit.
_FALLBACK_CWDS_LOCK = threading.Lock()


def _remove_fallback_cwds() -> None:
    """Remove the fallback working directories at exit; rmdir leaves any that hold anything."""
    for directory in list(_FALLBACK_CWDS.values()):
        try:
            os.rmdir(directory)
        except OSError:
            pass
    _FALLBACK_CWDS.clear()


def _record_fallback_cwd(key: str, made: Path) -> None:
    """Keep ``made`` as the fallback working directory for ``key``, removed at exit.

    The caller holds ``_FALLBACK_CWDS_LOCK``."""
    if not _FALLBACK_CWDS:
        import atexit

        atexit.register(_remove_fallback_cwds)
    _FALLBACK_CWDS[key] = made


def _fallback_key(anchor: Path, root: Union[str, Path]) -> str:
    """The cache key of the fallback directory for the filesystem root ``anchor``
    and the scanned tree ``root``: a directory made for one scanned tree is not
    handed to a scan of another, whose tree it may sit in."""
    return f"{anchor.as_posix()}|{Path(os.path.abspath(root)).as_posix()}"


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

    Each is new and empty, so it holds no config file. One is made per
    filesystem root, scanned tree and process (per results directory for the
    third) and reused while it stays empty, and removed at exit if it is still
    empty; nothing is cleared.
    """
    root = getattr(config, "_scanned_root", None) or source_dir
    anchor = Path(Path(os.path.abspath(target)).anchor)
    if not in_scanned_tree(anchor, root):
        return anchor
    from automated_security_helper.utils.sandbox.scope import active_scope

    with _FALLBACK_CWDS_LOCK:
        if active_scope() is None:
            key = _fallback_key(anchor, root)
            cached = _FALLBACK_CWDS.get(key)
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
                _record_fallback_cwd(key, made)
                return made
        directory = Path(os.path.abspath(results_dir))
        directory.mkdir(parents=True, exist_ok=True)
        key = f"results|{directory.as_posix()}"
        made = _FALLBACK_CWDS.get(key)
        if not (
            made is not None
            and made.parent == directory
            and made.is_dir()
            and not any(made.iterdir())
        ):
            made = _new_directory(directory)
            if made is None:
                raise OSError(f"cannot create a working directory under {directory}")
            _record_fallback_cwd(key, made)
    ASH_LOGGER.warning(
        f"The filesystem root of {Path(target).as_posix()} is inside the scanned "
        f"tree, so the tool runs from {made.as_posix()}; paths in its findings "
        "may leave out directories they share with that location."
    )
    return made


@contextmanager
def private_cwd_outside_scanned_tree(
    *,
    results_dir: Union[str, Path],
    source_dir: Union[str, Path],
    config: Any = None,
) -> Iterator[Path]:
    """A new, empty working directory that only this user can enter, for one scan.

    For a tool that resolves the relative paths in an operator's config file
    against its working directory and is handed only absolute paths otherwise
    (cfn-lint). From the filesystem root, which ``cwd_outside_scanned_tree``
    normally gives, a relative ``tmp/x`` names ``/tmp/x``, which any local user
    can write to. From here a relative path names nothing: the directory is new
    and empty, and ``tempfile.mkdtemp`` makes it mode 0700, so nobody else can
    add to it. A path that climbs out with ``..`` still names whatever is there.

    Made in the system temp directory, or under ``results_dir`` when that is
    inside the scanned tree (a scan of the whole filesystem). A sandbox grants
    the working directory read-only, so either is visible to a sandboxed tool.
    Removed, with anything the tool left in it, when the block ends.
    """
    root = getattr(config, "_scanned_root", None) or source_dir
    made = _new_directory(None)
    if made is not None and in_scanned_tree(made, root):
        made.rmdir()
        made = None
    if made is None:
        directory = Path(os.path.abspath(results_dir))
        directory.mkdir(parents=True, exist_ok=True)
        made = _new_directory(directory)
        if made is None:
            raise OSError(f"cannot create a working directory under {directory}")
    try:
        yield made
    finally:
        shutil.rmtree(made, ignore_errors=True)


def resolved_path(value: Union[str, Path], source_dir: Union[str, Path]) -> Path:
    """``value`` as the tool will read it: ``~`` expanded, a relative path taken from
    ``source_dir``, and symlinks and ``..`` resolved.

    ``honored_path`` checks this path and returns it, so a caller that hands the
    tool the returned value hands it exactly the file that was checked.

    A value holding a NUL names no file, and ``os.path.realpath`` refuses it.
    The path comes back normalized and unresolved, which does not exist, so a
    caller's existence check reads the value as missing instead of raising.
    """
    path = Path(os.path.expanduser(str(value)))
    if not path.is_absolute():
        path = Path(source_dir) / path
    try:
        return Path(os.path.realpath(path))
    except ValueError:
        return Path(os.path.normpath(path))


def _first_warning(key: str, path: Path) -> bool:
    """Whether the refusal of ``path`` for ``key`` is not yet logged in this run; records it."""
    entry = (current_run_log_scope(), key, path.as_posix())
    with _WARNED_LOCK:
        first = entry not in _WARNED
        _WARNED.add(entry)
    return first


def derived_roots(context: Any) -> Tuple[Union[str, Path], ...]:
    """The directories whose files the scan derived from the repository being
    scanned: the output directory, the plugin work directory and, in a
    workspace scan, the workspace output directory. A directory the context
    does not hold is left out.

    This is the one place the list is built: ``PluginContext`` records exactly
    this list on its config, and every caller that passes ``derived_dirs`` to
    ``honored_path`` reads it. A run that registers further derived locations
    extends it here and every caller follows without changing.
    """
    return tuple(
        directory
        for directory in (
            getattr(context, "output_dir", None),
            getattr(context, "work_dir", None),
            getattr(context, "workspace_output_dir", None),
        )
        if directory is not None
    )


@contextmanager
def derived_roots_scope(run: str) -> Iterator[None]:
    """Record derived roots as scan run *run*'s inside the block.

    A config can outlive one scan (a caller can hand one ``resolved_config``
    to several orchestrators, one after another or at the same time). Inside
    the block, ``record_derived_roots`` files the directories under *run*. A
    path is judged against the whole record, every run's roots with the
    unscoped ones (``_recorded_roots``), so a run that is still going refuses
    paths under another run's output directory too. A run's roots leave the
    record only through :func:`forget_derived_roots`, which the orchestrator
    calls when its scan ends: a run that is still going keeps every root it
    filed, whatever another run on the same config does.

    The scope is a context variable, so it holds in the thread or task that
    enters it and in what copies its context (the scanner pool submits each
    scanner with ``contextvars.copy_context().run``). It decides which run a
    root is filed under, so the run can be forgotten as a whole.
    ``ASHScanOrchestrator`` enters the scope under its run id where it builds
    its plugin context and where it runs its phases.
    """
    token = _DERIVED_ROOTS_RUN.set(run)
    try:
        yield
    finally:
        _DERIVED_ROOTS_RUN.reset(token)


def record_derived_roots(config: Any, *dirs: Union[str, Path, None]) -> None:
    """Record *dirs* on *config* as locations holding repository-derived files.

    ``honored_path`` and ``refused_derived_product`` read the record, so a
    caller that does not pass ``derived_dirs`` still has the scan's output and
    work directories judged as derived. The record is the de-duplicated union
    over every plugin context that holds *config* (a config can serve more than
    one context, as the context's own copies do): a path under any of them is a
    derived product, which fails closed. Inside a scan run
    (:func:`derived_roots_scope`) the directories are filed under that run, and
    the union is the run's own; outside every run they go to the unscoped
    record, which every reader judges against.

    This is the one place the record is maintained. Nothing is recorded for a
    config that is not an ``AshConfig`` (None, a stand-in), and blank or None
    directories are skipped.
    """
    # Imported here: config.ash_config imports this module.
    from automated_security_helper.config.ash_config import AshConfig

    if not isinstance(config, AshConfig):
        return
    resolved_dirs = [
        Path(os.path.realpath(Path(directory)))
        for directory in dirs
        if directory is not None and str(directory).strip() != ""
    ]
    run = _DERIVED_ROOTS_RUN.get()
    with _DERIVED_ROOTS_LOCK:
        try:
            unscoped = config._derived_roots
            by_run = config._run_derived_roots
        except AttributeError:
            return
        recorded = unscoped if run is None else by_run.get(run, ())
        additions = []
        for resolved in resolved_dirs:
            if resolved not in recorded and resolved not in additions:
                additions.append(resolved)
        if not additions:
            return
        # A NEW list or mapping, never an in-place change: model_copy() copies
        # the private state shallowly, so the original and its copies hold the
        # one object, and a change through any of them changed all. A reader
        # takes the attribute once, so it sees one record or the next, whole.
        if run is None:
            config._derived_roots = [*unscoped, *additions]
        else:
            config._run_derived_roots = {**by_run, run: (*recorded, *additions)}


def forget_derived_roots(config: Any, run: str) -> None:
    """Remove scan run *run*'s roots from *config*'s record.

    Called once, when the run ends (``ASHScanOrchestrator.execute_scan``), so a
    config that serves many runs does not keep every finished run's output
    directory in the record, copy it on each ``record_derived_roots`` call, or
    refuse paths under it for readers outside every run. The unscoped record
    and every other run's roots are unchanged. Nothing happens for a config
    that holds no record or none for *run*."""
    with _DERIVED_ROOTS_LOCK:
        try:
            by_run = config._run_derived_roots
        except AttributeError:
            return
        if run not in by_run:
            return
        # A NEW mapping, as in record_derived_roots.
        config._run_derived_roots = {
            name: roots for name, roots in by_run.items() if name != run
        }


def _recorded_roots(config: Any) -> Tuple[Path, ...]:
    """The derived roots recorded on *config* that judge a path here; empty
    when it holds none.

    The whole record: the unscoped roots and every run's roots that have not
    ended (:func:`forget_derived_roots`), whichever run the reader is in. A
    file under another run's output directory was derived from that run's
    repository, so it is refused like one under this run's own."""
    try:
        unscoped = tuple(getattr(config, "_derived_roots", None) or ())
    except Exception:  # a stand-in whose attribute access raises
        return ()
    try:
        by_run = getattr(config, "_run_derived_roots", None) or {}
        scoped = tuple(root for roots in by_run.values() for root in roots)
    except Exception:  # a stand-in whose attribute access raises
        return unscoped
    return (*unscoped, *scoped)


def _shown(message: str, config: Any) -> str:
    """*message* with every value *config* read from the environment shown as
    ``<value>``.

    The refusal warnings name the path they refused, and a configured path can
    come from the environment: environment values are never logged, so such a
    value is shown through the shown form, as every other message that can
    quote one does. A value the environment did not choose is the
    configuration's own text and stays named."""
    # Imported here: error_text imports the validator package lazily itself,
    # and this module is imported by the scanners the config package loads.
    from automated_security_helper.utils.error_text import (
        config_environment_values,
        text_without_values,
    )

    return text_without_values(message, config_environment_values(config))


def _shown_escaped(text: str, config: Any) -> str:
    """*text* with the environment values of *config* hidden, then its control
    characters escaped, in that order: an escaped control character no longer
    matches the environment value that held it, so escaping first would print
    the value in its escaped spelling."""
    return escape_controls(_shown(text, config))


def _warn_of_an_unreadable_value(
    key: str, source_dir: Union[str, Path], config: Any
) -> None:
    """Log, once per run, that the value of *key* holds a NUL and names no file.

    The value is never printed: a repository's baseline can write it, and an
    environment variable can hold it."""
    if _first_warning(key, Path(os.fspath(source_dir)) / "<unreadable value>"):
        ASH_LOGGER.warning(
            _shown(
                f"Ignoring {key}: the value holds a character no file name "
                "can hold, so it names no file and is not passed to the tool.",
                config,
            )
        )


#: The characters that separate the components of a path on this platform.
_PATH_SEPARATORS = re.compile("[" + re.escape(os.sep + (os.altsep or "")) + "]+")


def _path_parts(text: str) -> Tuple[str, ...]:
    """The components of *text* read as a path: normalized (``.`` and ``..``
    applied), with the root and any leading ``..`` left out."""
    return tuple(
        part
        for part in _PATH_SEPARATORS.split(os.path.normpath(text))
        if part not in ("", ".", "..")
    )


def _same_tail(left: str, right: str) -> bool:
    """Whether the components of the shorter of two paths are the last
    components of the other. Whole components only: ``rules`` is the tail of
    ``/etc/rules`` and is not part of ``/etc/rules.yaml``."""
    first, second = _path_parts(left), _path_parts(right)
    size = min(len(first), len(second))
    return size > 0 and first[-size:] == second[-size:]


def _named(
    value: Union[str, Path], path: Path, config: Any, env_named: bool = False
) -> str:
    """How a refusal warning names the path it refused.

    ``<value>`` when the caller read the value from an environment variable
    itself (*env_named*), or when the WRITTEN value corresponds to a reference
    the config chain read from the environment
    (``config._environment_references``), as the recorded spelling or anchored
    under one; the resolved path otherwise.
    Keyed on the written value, not the resolved spelling, because resolution
    (a relative value, a link) can produce a path that shares no text with the
    environment's value while still being derived from it."""
    # Imported here, as in _shown.
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    if env_named:
        return ENVIRONMENT_VALUE_SHOWN
    written = str(value)
    for reference in getattr(config, "_environment_references", ()) or ():
        for recorded in (
            getattr(reference, "resolved", None),
            getattr(reference, "value", None),
        ):
            if not recorded:
                continue
            # Either side can carry a scheme or directory prefix around the
            # other: the config can anchor the environment's value under a
            # prefix, and a caller can strip a scheme (``file://``) before
            # judging the path, so a tail match in either direction is a
            # correspondence. Compared as normalized paths, whole components
            # only: loading anchors and normalizes the value (``./`` and ``..``
            # applied), which a text comparison misses, and a value that is
            # only a piece of a name (``rules`` in ``rules.yaml``) is not the
            # value.
            if _same_tail(recorded, written):
                return ENVIRONMENT_VALUE_SHOWN
    return path.as_posix()


def _inside(path: Path, root: Path) -> bool:
    """Whether *path* is *root* or under it: by spelling, or as the same file.

    The spelling test holds for a root that does not exist yet. The identity
    test is ``sandbox_grants.is_within`` (``os.path.samefile`` on each parent),
    the test the tree judgment uses, so a case-only spelling or a second path
    to the same directory (a bind mount) counts as inside too."""
    if path == root or root in path.parents:
        return True
    # Imported here, as in scanned_tree_judgment.
    from automated_security_helper.config.sandbox_grants import is_within

    return is_within(path, root)


def refused_derived_product(
    value: Union[str, Path, None],
    *,
    source_dir: Union[str, Path],
    key: str,
    config: Any = None,
    derived_dirs: Collection[Union[str, Path]] = (),
    operator_written: bool = False,
    env_named: bool = False,
) -> bool:
    """Whether *value* is a repository-derived work product the tool is not handed.

    The derived-directory clause of :func:`honored_path`, on its own: a value
    that is not the operator's own write and resolves under one of
    ``derived_dirs`` (the output and work directories, ``derived_roots``) is
    refused with the same warning. For the scanners whose in-tree configs are
    accepted deliberately (bandit, grype, syft), where ``honored_path``'s tree
    clause does not apply but a config the scan derived from the repository
    being scanned must still not reach the tool.

    The directories judged are ``derived_dirs`` together with those recorded on
    *config* (``record_derived_roots``): the whole record, every scan run's
    roots that have not ended and the ones recorded outside every run. A derived root
    that contains a scanned tree (the config's ``_scanned_root`` or
    *source_dir*), as with an output directory above the source directory, does
    not refuse a file inside that same tree: judging it there would make every
    repository file a work product. The same root still refuses a file under it
    that sits in no tree the root contains, which is a real work product. Omitting ``operator_written`` judges the value as not the
    operator's own.

    A value an environment variable chose is never printed: with *env_named*
    the warning names only the key, and the path shows as the shown form.

    Args as for :func:`honored_path`. True means refused; the caller passes
    nothing built from *value* to the tool. False for a blank value: the
    caller's own handling of a missing option stands. A value holding a NUL
    names no file and is refused too, whoever wrote it, with a warning that
    does not print it.
    """
    if value is None or str(value).strip() == "":
        return False
    if "\x00" in str(value):
        _warn_of_an_unreadable_value(key, source_dir, config)
        return True
    if operator_written:
        return False
    path = resolved_path(value, source_dir)
    scanned = {
        Path(os.path.realpath(Path(held)))
        for held in (getattr(config, "_scanned_root", None), source_dir)
        if held is not None and str(held).strip() != ""
    }
    for base in (*derived_dirs, *_recorded_roots(config)):
        if base is None or str(base).strip() == "":
            continue
        resolved_base = Path(os.path.realpath(Path(base)))
        # One tree has to hold the file and sit under the derived root. Judging
        # the two tests against different trees (the file in one, the root's
        # containment in another) let a work product outside the tree the root
        # was meant for pass whenever any other scanned tree held it.
        if any(
            _inside(path, held) and _inside(held, resolved_base) for held in scanned
        ):
            continue
        if _inside(path, resolved_base):
            if _first_warning(key, path):
                shown_path = _shown_escaped(
                    _named(value, path, config, env_named), config
                )
                ASH_LOGGER.warning(
                    _shown(
                        f"Ignoring {key} ({shown_path}): it is under "
                        "the scan's own output or work directory, which "
                        "holds files derived from the scanned repository, "
                        "and the entry is not the operator's own. Such a "
                        "file is not passed to the tool; name one outside "
                        "them with the operator's configuration.",
                        config,
                    )
                )
            return True
    return False


def honored_path(
    value: Union[str, Path, None],
    *,
    source_dir: Union[str, Path],
    key: str,
    config: Any = None,
    derived_dirs: Collection[Union[str, Path]] = (),
    operator_written: bool = False,
    env_named: bool = False,
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
        derived_dirs: Directories whose files the scan derived from the
            repository being scanned (the output directory and the plugin work
            directory). They sit outside the scanned tree, so a path under one
            passes the tree check; a value that is not the operator's own is
            refused there the same way an in-tree path is, because handing the
            tool a repository-derived file honors the repository's writes
            through a location the tree check cannot see. The directories
            recorded on *config* (``record_derived_roots``, filled by every
            ``PluginContext`` that holds it) are judged too, so omitting this
            argument does not skip the clause.
        operator_written: Whether *value* is the operator's own write
            (``operator_only_options.operator_wrote_value``). Omitting it
            judges the value as not the operator's, so a caller that does not
            say where the value came from gets the strict judgment. Feeds only
            the derived-product clause; who named the path is judged by
            ``named_by_operator``.
        env_named: Whether *value* came from an environment variable the
            caller read. A value an environment variable chose is never
            printed: the warning names only *key*, and the path shows as the
            shown form.
    """
    if value is None or str(value).strip() == "":
        return None
    if "\x00" in str(value):
        # A value holding a NUL names no file; it is dropped like a refused path
        # instead of raising out of the scanner's construction.
        _warn_of_an_unreadable_value(key, source_dir, config)
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
        if refused_derived_product(
            value,
            source_dir=source_dir,
            key=key,
            config=config,
            derived_dirs=derived_dirs,
            operator_written=operator_written,
            env_named=env_named,
        ):
            return None
        return path
    if _first_warning(key, path):
        # Imported here: sandbox_grants imports ash_config, which imports the
        # scanners that import this module.
        from automated_security_helper.config.sandbox_grants import (
            UNFINISHED_WALK_REASON,
        )

        if reason == UNFINISHED_WALK_REASON:
            # Neither "name one outside it" nor "move the file out of every
            # checkout" can help: no place was found to move it out of. What
            # helps is a walk that can finish.
            advice = (
                "The path is not passed to the tool until ASH can resolve its "
                f"name to the end. To use it, {LET_THE_WALK_FINISH}."
            )
        elif operator:
            advice = (
                "A file inside the scanned tree, or one an MCP client delivered, is "
                "not passed to the tool; name one outside it."
            )
        else:
            advice = (
                "A file that a config file inside a git checkout or the scanned "
                "directory names, or that ASH finds in the scanned directory, is "
                "passed to the tool only from outside every git checkout and the "
                f"scanned directory. {KEEP_A_SETTING}"
            )
        # The value and the paths in the reason are written with their control
        # characters escaped: a newline in an environment variable's value would
        # otherwise start a line of its own in the log. A value an environment
        # variable chose is never printed: the path shows as the shown form
        # (_named), and each piece has the configuration's environment values
        # hidden before it is escaped (_shown_escaped), since an escaped value
        # no longer matches the value it was made from. The whole message is
        # shown once more for the key.
        shown_path = _shown_escaped(_named(value, named, config, env_named), config)
        ASH_LOGGER.warning(
            _shown(
                f"Ignoring {key} ({shown_path}): "
                f"{_shown_escaped(reason, config)}. {advice}",
                config,
            )
        )
    return None


def leaves_the_tree_through_a_link(
    value: Union[str, Path], source_dir: Union[str, Path], root: Union[str, Path]
) -> bool:
    """Whether ``value`` reaches a file outside the scanned tree through a link inside it.

    ``value`` as written (``~`` expanded, a relative path taken from
    ``source_dir``) is looked up as the kernel does, one component at a time, and
    every symbolic link that lookup follows is found where it sits
    (``utils/link_locations``): a link at any depth, a directory link, each link
    of a chain, and a link reached through a link outside the tree. True when one
    of them sits in the scanned tree (``in_scanned_tree`` of the directory
    holding it, from ``root``) and the path ends outside the tree: the
    repository chose that file by placing the link. A path that leaves by ``..``
    with no link in the tree is the path as written.
    """
    path = Path(os.path.expanduser(str(value)))
    if not path.is_absolute():
        path = Path(os.path.abspath(source_dir)) / path
    if in_scanned_tree(Path(os.path.realpath(path)), root):
        return False
    return any(
        in_scanned_tree(location.parent, root) for location in link_locations(path)
    )
