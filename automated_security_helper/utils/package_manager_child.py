# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Start npm, pnpm or yarn reading no settings file the scanned repository wrote.

The operator's own settings (``~/.npmrc``, the global npmrc, ``~/.yarnrc``,
``~/.yarnrc.yml``) are trusted and still apply: a private registry and its
credentials live there. The scanned repository's (``.npmrc``, the settings in
``pnpm-workspace.yaml``, ``.yarnrc``, ``.yarnrc.yml``) are not.

Measured with npm 10.9.4, pnpm 12.6.0 and yarn 1.22.22, each run in a directory
holding a marker registry in its settings: npm and pnpm applied the one in ``.npmrc``,
pnpm also the one in ``pnpm-workspace.yaml``, yarn 1 the one in ``.yarnrc``; and yarn
ran the JavaScript file a ``.yarnrc`` ``yarn-path`` or ``.yarnrc.yml`` ``yarnPath``
names in place of itself, ``yarn --version`` included.

* npm and pnpm have no option that skips the project's file, and read it only from the
  directory they run in, not its parents (measured from a copy inside the scanned
  tree), so they start in a new directory holding copies of ``package.json`` and the
  lockfile and nothing else. Their audit requests from such a copy, recorded through
  a local registry stand-in, were identical to the in-tree ones, npm and pnpm
  workspaces included: both read the workspace from the lockfile.
* yarn reads ``.yarnrc`` and ``.npmrc`` from its directory and every parent, and
  finds a workspace's members through their manifests. Unsandboxed it starts in a
  copy outside the scanned tree of the lockfile and every ``package.json`` below the
  package, so the repository's files are on no path it reads and the operator's
  still are (measured). The copy's ancestors decide which other settings files it
  reads, so the copy goes under the scan's own output directory when that is
  outside the tree (where npm's and pnpm's copies go), else under the operator's
  cache directory (``$XDG_CACHE_HOME/ash``, or ``~/.cache/ash``), else under the
  user's runtime directory (``$XDG_RUNTIME_DIR/ash``), and never under the
  system temporary directory or below any directory another account owns or can
  write: on a shared host ``/tmp``'s ancestors are writable by every user, and a
  ``.npmrc`` or ``.yarnrc`` planted there would redirect the audit
  (``_yarn_copy_parent``, ``_untrusted_ancestor``). When no candidate will do,
  yarn runs in place with every settings file dropped and a warning says so,
  since ``--no-default-rc`` also drops the operator's files, ``~/.npmrc`` with no
  way to add it back (measured: it ignores ``npm_config_userconfig``).
* Under a sandbox the tool's home is private, so the operator's files were never
  visible to it, and the copy has to be somewhere it can see. yarn then runs in the
  package directory with ``--no-default-rc`` (yarn 1) or ``YARN_RC_FILENAME`` naming
  no file (yarn 2+), which drop every settings file; npm and pnpm use the copy under
  ``parent``.
* yarn always gets ``YARN_IGNORE_PATH=1``, so no ``yarn-path`` or ``yarnPath`` runs
  (measured for yarn 1; yarn 2+'s ``ignorePath`` setting).

The repository's own ``package.json`` keeps its ``pnpm.auditConfig`` (pnpm's
advisory ignore lists), a suppression the repository holds, as ASH honors repository
suppressions; under ``--ignore-suppressions`` it is removed from the copy, as that
flag lifts every suppression. pnpm 10 reads the same lists from ``auditConfig`` in
``pnpm-workspace.yaml``, beside the registry and every other setting that file
holds, so the copy gets a ``pnpm-workspace.yaml`` holding that one key (and the
member globs that stay inside the package) when the repository's file has it and
the flag is not set; the rest of the file, the settings the first paragraph
distrusts, is never copied.

The pnpm copy always holds a ``pnpm-workspace.yaml``, with at least
``packages: ["."]``, whether or not the repository has one. The copy sits below
``parent``, which by default is inside the scanned tree, and pnpm 10 finds its
workspace root by walking up from the directory it runs in and reads that root's
``.npmrc``: without a workspace file of its own the copy's root was the
repository's, so the audit went to the registry the repository's ``.npmrc`` names
(measured with pnpm 10.34.9: two requests to that registry; pnpm 12.17.0 made
none). A workspace file in the copy makes the copy its own workspace root, so
the walk ends there. pnpm 10.34.9 and 12.17.0 both accept the file with
``packages: ["."]``.

The same shape as ``utils/python_child.py``: the private directory is made for the
child and removed when the block ends. yarn 2+ itself was not measured: none was
installed and none was downloaded; its two variables are documented settings.

npm, pnpm and yarn follow links, and none has an option not to (measured with the
versions above, offline under bwrap: a ``package-lock.json`` linking to a file
outside the scanned tree was read by each). So every file the tool reads from the
package (``package_manager_inputs``) has to resolve inside the scanned tree and be a
regular file (``input_refusal``). The scanner refuses a package with any other one
before starting anything for it, and the copy here never holds one either: each
input is opened first and judged through the open descriptor (``_read_admitted``):
its shape by ``fstat``, its place by the descriptor's own path where the platform
names one (Linux), else by its name tied to the open file by identity. So a file
swapped for a link or a FIFO between the scanner's check and the copy is refused
(``InputRefused``) rather than read through its new shape, and one that cannot be
opened is a raised failure too (``InputUnreadable``): neither is ever a copy
silently missing a file the tool would read in place.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import stat
import string
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.process_env import snapshot_environ

#: pnpm's workspace settings file: pnpm 10 keeps ``auditConfig`` there as well as
#: under ``pnpm`` in the manifest.
PNPM_WORKSPACE_FILE = "pnpm-workspace.yaml"

#: The files npm and pnpm read from the package: the manifest and the lockfiles,
#: and for pnpm the workspace settings file, which is copied reduced to its
#: ``auditConfig`` and member globs (``_pnpm_workspace_copy``), and is otherwise
#: no settings file. The pnpm copy holds one even when the repository has none.
_PACKAGE_MANAGER_INPUTS: Dict[str, Tuple[str, ...]] = {
    "npm": ("package.json", "package-lock.json", "npm-shrinkwrap.json"),
    "pnpm": ("package.json", "pnpm-lock.yaml", PNPM_WORKSPACE_FILE),
    "yarn": ("package.json", "yarn.lock"),
}

#: The lockfile names a package manager audits. A link of one of these names that
#: resolves to nothing is listed as an input like a dangling ``package.json`` link,
#: so the package is refused with the reason rather than read as having no
#: lockfile and passed over with nothing recorded.
_LOCKFILE_NAMES = frozenset(
    {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"}
)

#: The prefix of the settings file name yarn 2+ is told to look for
#: (YARN_RC_FILENAME) when it must read no ``.yarnrc.yml``. The rest of the name
#: is drawn fresh for every child (``no_yarnrc_name``), so no directory holds a
#: file of that name. A fixed, published name could be written into the scanned
#: package, which is where yarn runs in place; yarn would then read that file as
#: its settings, ``yarnPath`` and registry included.
NO_YARNRC_PREFIX = ".ash-no-yarnrc-"
_NO_YARNRC_TOKEN_CHARS = 32


def no_yarnrc_name() -> str:
    """A settings file name no directory has, drawn for one child."""
    return f"{NO_YARNRC_PREFIX}{secrets.token_hex(_NO_YARNRC_TOKEN_CHARS // 2)}.yml"


def is_no_yarnrc_name(value: object) -> bool:
    """Whether ``value`` is a name :func:`no_yarnrc_name` draws."""
    if not isinstance(value, str) or not value.startswith(NO_YARNRC_PREFIX):
        return False
    if not value.endswith(".yml"):
        return False
    token = value[len(NO_YARNRC_PREFIX) : -len(".yml")]
    return len(token) == _NO_YARNRC_TOKEN_CHARS and all(
        c in string.digits or c in "abcdef" for c in token
    )


#: Directories never copied for yarn: installed packages and version control.
_SKIPPED_DIR_NAMES = frozenset({"node_modules", ".git"})

#: How many linked directories the yarn input walk will enter for one package
#: before it refuses the package (``TooManyLinkedDirectories``). Each real
#: directory is walked once whatever the number of links to it, so the count is
#: of distinct linked directories reached, and a repository that chains that many
#: is not one yarn would audit in bounded time either.
_MAX_LINKED_DIRECTORY_WALKS = 1000

#: How many manifest paths the walk may add for the links it did not enter
#: (``_manifests_below_links``) before it refuses the package, also with
#: ``TooManyLinkedDirectories``. Each is a file yarn reads at the link's path.
_MAX_LINK_ALIAS_MANIFESTS = 10000

#: Why a file the package manager would read is not handed to it.
LINK_LEAVES_TREE = "link leaves the scanned tree"
NOT_A_REGULAR_FILE = "not a regular file"
#: The two reasons only the copy can give, once it holds the file open.
OPENED_FILE_NOT_IN_TREE = (
    "the file it opened is outside the scanned tree or was removed"
)
CHANGED_WHILE_READ = "it changed while it was being read"


class InputUnreadable(OSError):
    """An input the package manager would read could not be read for the copy.

    Raised by ``_read_admitted`` for an open failure (EACCES, EIO, a file gone
    between the listing and the copy). The scanner's check (``refused_inputs``)
    had passed it, so before this the copy silently lacked a file yarn would
    have read in place, and the audit ran on part of the workspace with nothing
    recorded. The scanner's scan loop records the raise as that audit's failure.
    """


class InputRefused(ValueError):
    """An input the scanner admitted was refused when the copy opened it.

    Raised by ``_read_admitted`` when the open file is not a regular file, lies
    outside the scanned tree, or is not the file the name still points at: the
    file was swapped, or removed, after the scanner's check (``refused_inputs``)
    passed it. Answering None here left the copy without a file the tool reads
    in place, so yarn audited a partial workspace with nothing recorded. The
    package is refused instead, with the file and the reason; the scan loop
    records the raise as that audit's failure.
    """


class SuppressionsNotLiftable(ValueError):
    """Under ``--ignore-suppressions`` a pnpm package's manifest could not be
    parsed, so its ``pnpm.auditConfig`` could not be removed.

    Raised for pnpm only: npm and yarn read no such key. The flag lifts every
    suppression. A manifest this interpreter cannot parse
    but the package manager can (nested past the recursion limit, say) kept its
    ignore lists in the copy, and pnpm applied them under the flag; the package
    is refused instead, with this reason, which the scan loop records.
    """


class TooManyLinkedDirectories(ValueError):
    """The yarn input walk entered more linked directories than
    ``_MAX_LINKED_DIRECTORY_WALKS`` for one package.

    Every real directory is walked once, so a chain of links cannot multiply the
    walk; this is the hard bound behind that rule, for a repository (ASH scans
    untrusted ones) laid out to reach thousands of distinct directories through
    links. The package is refused with this reason, which the scan loop records
    as that audit's failure, rather than walked on. It is also raised when the
    manifests listed again under the links that were not walked pass
    ``_MAX_LINK_ALIAS_MANIFESTS``.
    """


@dataclass(frozen=True)
class PackageManagerChild:
    """The arguments to put right after the binary, the directory and environment."""

    leading_args: Tuple[str, ...]
    cwd: Path
    env: Dict[str, str]


def _sandboxed() -> bool:
    from automated_security_helper.utils.sandbox.scope import active_scope

    return active_scope() is not None


def _within(path: Path, root: Optional[Path]) -> bool:
    """Whether ``path`` is ``root`` or below it, by file identity.

    ``sandbox_grants.is_within`` compares the resolved path and each of its
    parents with the root as files, so a root named through a bind mount or,
    on a case-folding filesystem, in another case still counts; comparing
    real-path strings read those as outside, and yarn's copy then went inside
    the scanned tree. A path that does not exist yet (an output directory
    about to be made) is judged by its nearest existing parent, as before.
    """
    if root is None:
        return False
    # Imported here: sandbox_grants imports ash_config, which imports the scanners.
    from automated_security_helper.config.sandbox_grants import is_within

    return is_within(Path(path), Path(root))


def _operator_cache_dir() -> Optional[Path]:
    """``$XDG_CACHE_HOME/ash``, else ``~/.cache/ash``; None with no home.

    A relative ``XDG_CACHE_HOME`` is ignored, as the specification says and as
    the tools reading it do (``content_db_refresh.default_cache_dir``): it would
    name a directory under whatever the current directory is. A leading ``~`` is
    expanded first, as the tools do.
    """
    xdg = os.environ.get("XDG_CACHE_HOME", "")
    if xdg:
        expanded = os.path.expanduser(xdg) if xdg.startswith("~") else xdg
        if os.path.isabs(expanded):
            return Path(expanded) / "ash"
    try:
        return Path.home() / ".cache" / "ash"
    except (KeyError, RuntimeError):
        return None


def _runtime_dir() -> Optional[Path]:
    """``$XDG_RUNTIME_DIR/ash``, or None when the variable is unset or relative.

    The runtime directory (``/run/user/<uid>`` on systemd hosts) is the user's
    own, mode 0700 with root-owned ancestors, so it holds the copy where the
    home directory cannot: a container with an unset or read-only ``HOME``, or
    a home directory other accounts can write.
    """
    runtime = os.environ.get("XDG_RUNTIME_DIR", "")
    if runtime and os.path.isabs(runtime):
        return Path(runtime) / "ash"
    return None


def _nearest_real_directory(path: Path) -> Path:
    """The real path of ``path``'s nearest existing ancestor (``path`` itself
    when it exists).

    yarn takes its directory from ``process.cwd()``, which is the RESOLVED
    path, so the parents it reads settings files from are the parents of a
    link's TARGET. A check that walked the path as written judged the parents
    of the link instead: a cache directory reached through
    ``~/.cache -> /scratch/me/cache`` passed on the home's ancestors while yarn
    read ``/scratch/.npmrc``, which any account there can write (``/scratch``
    at 1777). Both ancestor checks start from the real path (sshd's
    ``safe_path`` resolves the same way).
    """
    current = Path(os.path.abspath(path))
    while not current.exists():
        if current.parent == current:
            break
        current = current.parent
    return Path(os.path.realpath(current))


def _untrusted_ancestor(path: Path) -> Optional[Path]:
    """The nearest directory at or above ``path`` another account could write, or None.

    yarn reads ``.npmrc``, ``.yarnrc`` and ``.yarnrc.yml`` from every parent of
    its directory, so a copy below a directory any other account can write to
    (``/tmp`` with its sticky bit, a group- or world-writable directory, one
    owned by another account) can be redirected by a settings file planted
    beside it. The check is sshd's StrictModes one: from the real path of the
    nearest existing directory (``_nearest_real_directory``, the directory
    yarn reads its parents from) up to the root, each has to be owned by this
    account or root and writable by its owner only. Where ownership and the
    mode bits mean nothing of the kind (Windows) every directory passes.
    """
    if os.name == "nt":
        return None
    current = _nearest_real_directory(path)
    uid = os.getuid() if hasattr(os, "getuid") else None
    for directory in (current, *current.parents):
        try:
            status = os.stat(directory)
        except OSError:
            return directory
        if uid is not None and status.st_uid not in (uid, 0):
            return directory
        if status.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return directory
    return None


#: The settings files yarn reads from the copy's directory and every parent.
_YARN_SETTINGS_FILES: Tuple[str, ...] = (".npmrc", ".yarnrc", ".yarnrc.yml")


def _settings_file_ancestor(path: Path) -> Optional[Tuple[Path, str]]:
    """The nearest directory at or above ``path`` that holds a yarn settings
    file, with the file's name, or None.

    yarn reads ``.npmrc``, ``.yarnrc`` and ``.yarnrc.yml`` from every parent of
    its directory, so a copy below a directory that holds one runs under that
    file's registry and settings whoever wrote it. The ownership check
    (``_untrusted_ancestor``) does not see this case: an output directory
    inside a checkout above the scanned tree (``--source-dir ./src
    --output-dir ./ash-out``) has ancestors the operator owns, and the
    checkout's root holds the repository's own ``.npmrc``. The operator's home
    directory is left out: the files there are the operator's, and yarn reads
    them wherever it runs. The walk starts at the real path of the nearest
    existing directory (``_nearest_real_directory``): yarn resolves its working
    directory, so the parents it reads from are the link target's, and a
    settings file beside the target of a linked cache or output directory is
    found where a walk of the path as written passed it by. The home is
    matched by its real path, so a home spelled through a link
    (``HOME=/home/me`` where ``/home`` links to ``/local/home``, or the cache
    path spelled one way and ``HOME`` the other) is still the home and its
    files do not disqualify the cache below it.
    """
    try:
        home: Optional[str] = os.path.realpath(Path.home())
    except (KeyError, RuntimeError, OSError):
        home = None
    current = _nearest_real_directory(path)
    for directory in (current, *current.parents):
        if home is not None and os.path.realpath(directory) == home:
            continue
        for name in _YARN_SETTINGS_FILES:
            try:
                present = (directory / name).exists()
            except OSError:
                present = False
            if present:
                return directory, name
    return None


def _make_private_directory(path: Path) -> None:
    """Make ``path`` and each missing parent with mode 0700.

    ``Path.mkdir(parents=True)`` makes every part with the process umask, so
    under umask 002 (the user-private-group setup several distributions ship)
    a fresh ``~/.cache/ash`` came out group-writable: the first run copied
    below a directory the ancestor check had never seen, and every run after it
    named that directory and fell to in-place yarn with the operator's
    ``~/.npmrc`` dropped. Each missing part is made with 0700 (a umask can only
    narrow that); a part that exists already is left as found, and the caller
    re-runs the ancestor check on the made path.
    """
    missing: List[Path] = []
    current = Path(os.path.abspath(path))
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    for part in reversed(missing):
        try:
            os.mkdir(part, 0o700)
        except FileExistsError:
            continue


def _yarn_copy_parent(
    parent: Path, scan_root: Optional[Path]
) -> Tuple[Optional[Path], Tuple[str, ...]]:
    """Where yarn's unsandboxed copy goes, and why each candidate before it failed.

    yarn reads ``.yarnrc``, ``.npmrc`` and ``.yarnrc.yml`` from the copy's
    directory and every parent, so the copy's ancestors decide which settings
    files it reads besides the operator's own. The scan's output directory
    (``parent``, where npm's and pnpm's copies go) is first, then the operator's
    cache directory (the default output directory is inside the tree), then the
    user's runtime directory (``_runtime_dir``; a read-only or shared home has
    no usable cache directory, and in-place yarn drops ``~/.npmrc`` with the
    operator's registry and credentials). A candidate is passed over when it is
    inside the scanned tree (the repository's
    own files would be on yarn's path), when it is under the system temporary
    directory (``--output-dir /tmp/ash-out`` or ``XDG_CACHE_HOME=/tmp/cache`` put
    ``/tmp``, which every account can write, back on it), when any directory at
    or above it is writable by, or owned by, another account
    (``_untrusted_ancestor``), when a directory at or above it other than the
    operator's home holds a settings file yarn would read
    (``_settings_file_ancestor``; an output directory inside a larger checkout
    above the scanned tree puts that checkout's ``.npmrc`` and ``.yarnrc`` on
    the path, and those files are the repository's, whoever owns the
    directories), or when it cannot be made. None, with every reason, when no
    candidate will do: yarn then runs in place with every settings file dropped.
    """
    passed_over: List[str] = []
    temp_root = Path(tempfile.gettempdir())
    candidates = (
        ("the output directory", Path(parent)),
        ("the operator's cache directory", _operator_cache_dir()),
        ("the runtime directory", _runtime_dir()),
    )
    for what, candidate in candidates:
        if candidate is None:
            passed_over.append(f"{what} is not known")
            continue
        if _within(candidate, scan_root):
            passed_over.append(f"{what} {candidate} is inside the scanned tree")
            continue
        if _within(candidate, temp_root):
            passed_over.append(
                f"{what} {candidate} is under the system temporary directory "
                f"{temp_root}, which every account can write"
            )
            continue
        shared = _untrusted_ancestor(candidate)
        if shared is not None:
            passed_over.append(
                f"{what} {candidate} is below {shared}, which another account "
                "owns or can write"
            )
            continue
        settings = _settings_file_ancestor(candidate)
        if settings is not None:
            holder, name = settings
            passed_over.append(
                f"{what} {candidate} is below {holder}, which holds {name}, a "
                "settings file yarn would read"
            )
            continue
        try:
            _make_private_directory(candidate)
        except OSError as error:
            passed_over.append(f"{what} {candidate} cannot be made ({error})")
            continue
        # Read again on the directory as made: the check above ran on the
        # nearest EXISTING ancestor, so a part found half-way with a lax mode,
        # or one another process made meanwhile, is on yarn's path unchecked.
        shared = _untrusted_ancestor(candidate)
        if shared is not None:
            passed_over.append(
                f"{what} {candidate} is below {shared}, which another account "
                "owns or can write"
            )
            continue
        return candidate, tuple(passed_over)
    return None, tuple(passed_over)


def _write_copy(target: Path, data: bytes, private: Path) -> None:
    """Write ``data`` at ``target`` in the ``private`` directory, through fs_guard.

    ``private`` is the directory mkdtemp made for this child. For npm and pnpm it is
    below the scanner's results directory, so below the output directory, where ASH
    writes nothing through a link; it is guarded for this write whatever the
    platform's registered roots are.
    """
    # Imported here: fs_guard imports the sandbox package, which this module's
    # callers may be importing.
    from automated_security_helper.utils.sandbox.fs_guard import open_for_write

    with open_for_write(target, binary=True, make_parents=True, root=private) as out:
        out.write(data)


def _copy_manifest(
    data: bytes,
    target: Path,
    *,
    binary: str,
    ignore_suppressions: bool,
    private: Path,
) -> None:
    """Copy ``package.json``, without ``pnpm.auditConfig`` when suppressions are off.

    ``data`` is the manifest's bytes, read by ``_read_admitted``. Under
    ``--ignore-suppressions`` a manifest this parser cannot read is REFUSED
    for pnpm (``SuppressionsNotLiftable``), never copied as it is: pnpm may
    still parse it, ignore lists included, and the flag's promise is that
    nothing is suppressed. Only pnpm reads ``pnpm.auditConfig``, so for npm and
    yarn there is nothing to lift, and their copy is always the bytes as they
    were: yarn's copy holds every ``package.json`` below the package, a
    parser's broken-input fixture or a template with ``{{deps}}`` among them,
    and refusing the package for one of those failed the audit of a workspace
    pnpm never reads. A manifest that did parse and held the key was still
    rewritten for them, which turned an invalid byte into U+FFFD and ``1e400``
    into ``Infinity`` and failed an audit that had nothing to lift.
    """
    if not ignore_suppressions or binary != "pnpm":
        _write_copy(target, data, private)
        return
    try:
        # utf-8-sig: a manifest that starts with a byte order mark is JSON to
        # the package managers, and json.loads refuses the mark, so the
        # auditConfig stayed in the copy of such a manifest and pnpm applied
        # the repository's ignore lists under the flag that lifts them.
        # errors="replace": Node decodes an invalid byte as U+FFFD and parses
        # on, so a manifest with one stray byte is JSON to the tool; a strict
        # decode refused it here and the copy kept its ignore lists.
        # RecursionError: a manifest nested past the interpreter's limit is
        # refused by json.loads with that, not ValueError, and it escaped the
        # copy step as a crash of the scan instead of reaching the tool.
        manifest = json.loads(data.decode("utf-8-sig", errors="replace"))
    except (ValueError, RecursionError) as error:
        # Not JSON to this parser. V8 nests far past CPython's recursion
        # limit, so the tool may read what was refused here, auditConfig
        # included: copying the bytes as they were kept the repository's
        # ignore lists under the flag that lifts them. The package is refused
        # with the reason instead; the scan loop records it as the audit's
        # failure, and the scan fails closed.
        raise SuppressionsNotLiftable(
            f"{target.name} could not be parsed ({type(error).__name__}: {error}), "
            "so its pnpm.auditConfig cannot be removed under "
            "--ignore-suppressions; the package was not audited"
        ) from error
    pnpm = manifest.get("pnpm") if isinstance(manifest, dict) else None
    if isinstance(pnpm, dict) and "auditConfig" in pnpm:
        pnpm.pop("auditConfig")
        data = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    _write_copy(target, data, private)


def _pnpm_workspace_copy(data: Optional[bytes], *, ignore_suppressions: bool) -> bytes:
    """The ``pnpm-workspace.yaml`` the copy gets, which is always a file.

    ``data`` is the repository's file, or None when it has none. The copy holds
    a workspace file whatever the repository has, so that it is its own
    workspace root: pnpm 10 walks up from the directory it runs in to the
    workspace root and reads that directory's ``.npmrc``, and the copy sits
    below the scanner's output directory, which is inside the scanned tree by
    default. A copy without the file took the repository's root and its
    registry. The file carries ``packages: ["."]`` at least (a workspace file
    without ``packages`` is one some pnpm releases refuse).

    ``auditConfig`` crosses: pnpm 10 reads its advisory ignore lists from that
    key of the workspace file as well as from ``pnpm.auditConfig`` in the
    manifest, and a repository that keeps them there lost its suppressions when
    the file was left out of the copy. ``packages`` crosses with it, when it is
    a list of strings: it is the workspace's member globs, which name no
    registry or proxy, and a workspace file without it is one some pnpm
    releases refuse as an invalid workspace configuration, so a copy cut down
    to ``auditConfig`` alone failed an audit that ran with no file at all. A
    glob only crosses when it stays inside the package: a relative pattern with
    no ``..`` component and no brace group (a leading ``!`` negation is
    admitted). An absolute pattern, one that climbs out, and one with a brace
    (pnpm expands ``{a,b}`` into patterns of its own, so it can reach a path
    the pattern as written does not name) are left out, each with a debug line
    naming the glob and why; leaving out a negation lets the audit reach
    members it excluded, and the line says so. When none remains the globs are
    ``["."]``.
    Every other key (the registry among them) is a setting the module does not
    let the repository set, and stays out. Under ``--ignore-suppressions``
    nothing crosses, as the manifest's key is dropped, and the file is
    ``packages: ["."]`` alone. So is the file for a repository file that is not
    YAML, not a mapping, or without ``auditConfig``, and for no file at all.
    """
    import yaml

    default: Dict[str, object] = {"packages": ["."]}
    if data is None or ignore_suppressions:
        return yaml.safe_dump(default).encode("utf-8")
    try:
        document = yaml.safe_load(data.decode("utf-8-sig"))
    except (ValueError, RecursionError, yaml.YAMLError):
        return yaml.safe_dump(default).encode("utf-8")
    if not isinstance(document, dict) or "auditConfig" not in document:
        return yaml.safe_dump(default).encode("utf-8")
    copied: Dict[str, object] = {
        "auditConfig": document["auditConfig"],
        "packages": ["."],
    }
    packages = document.get("packages")
    if isinstance(packages, list) and all(isinstance(p, str) for p in packages):
        inside = []
        for glob in packages:
            refusal = _member_glob_refusal(glob)
            if refusal is None:
                inside.append(glob)
                continue
            # A negation that is left out stops excluding what it excluded, so
            # the copy can audit more members than the repository's file does.
            widens = (
                "; it is a negation, so the audit can reach members it excluded"
                if glob.startswith("!")
                else ""
            )
            ASH_LOGGER.debug(
                f"npm-audit: the pnpm-workspace.yaml member glob {glob!r} "
                f"{refusal}, so the private copy leaves it out{widens}",
                extra={"markup": False},
            )
        if inside:
            copied["packages"] = inside
    return yaml.safe_dump(copied).encode("utf-8")


def _member_glob_stays_inside(glob: str) -> bool:
    """Whether a ``pnpm-workspace.yaml`` member glob names paths inside the package.

    ``_member_glob_refusal`` holds the rule and says which part of it a glob
    breaks.
    """
    return _member_glob_refusal(glob) is None


def _member_glob_refusal(glob: str) -> Optional[str]:
    """Why a ``pnpm-workspace.yaml`` member glob is left out of the copy, or None
    when it names paths inside the package.

    pnpm resolves the globs against the workspace root with forward or
    backward slashes, so a pattern is read on both separators: it stays inside
    when it is relative on both path flavors (no leading slash or backslash,
    no drive: a root-relative ``\\packages\\*`` names the current drive's root,
    not the workspace, and ``PureWindowsPath.is_absolute`` alone admits it),
    holds no ``..`` component and is not empty. Leading ``!`` characters mark a
    pattern pnpm excludes (a second one undoes the first) and are all read past.
    A pattern with a brace is refused: pnpm's matcher expands ``{a,b}`` into
    separate patterns, so ``{..,x}/*`` reaches ``../*`` and ``{/srv/shared,x}/*``
    an absolute path while no component of the pattern as written is ``..`` or
    absolute. A brace-free component that merely contains two dots
    (``packages/..cache/*``, ``v1..2/*``) is not a parent step and stays inside.
    """
    body = glob.lstrip("!")
    if not body:
        return "is empty"
    if "{" in body or "}" in body:
        return "holds a brace group, which pnpm expands into patterns of its own"
    windows = PureWindowsPath(body)
    if PurePosixPath(body).is_absolute() or windows.is_absolute():
        return "is an absolute path"
    if windows.drive or windows.root:
        return "is rooted at a drive or at the root of the current one"
    if ".." in re.split(r"[\\/]+", body):
        return "has a parent step (..)"
    return None


def _links_into_skipped_dir(linked: Path, package_dir: Path) -> bool:
    """Whether the linked directory resolves inside a ``node_modules`` or ``.git``.

    Read on the part of the link's real path that the package directory does
    not share, so a package that itself sits below such a directory is not
    judged by its own ancestors: for ``deps -> node_modules`` in the package
    that part is ``node_modules``; for a link to a sibling of a package that
    lives under a vendored ``node_modules`` it is the sibling's own name.
    """
    real = os.path.realpath(linked)
    shared = os.path.commonpath([real, os.path.realpath(package_dir)])
    relative = Path(os.path.relpath(real, shared))
    return bool(_SKIPPED_DIR_NAMES.intersection(relative.parts))


def _manifests_below_links(
    aliases: Sequence[Tuple[Path, str]],
    walked: Sequence[Path],
    listed: Iterable[Path],
) -> List[Path]:
    """The manifests the walk found below each link's target, named by the link.

    ``aliases`` are the links the input walk did not enter because their
    target is listed at its own path (``package_manager_inputs``), each with the
    real path of its target. yarn finds a workspace's members by walking the
    paths its globs name, a link's path included, so a member below the target
    (``libs/foo/plugins/x`` for ``packages/foo -> ../libs/foo``) is read at
    ``packages/foo/plugins/x`` as well, and a glob such as ``packages/*/*``
    reaches it only there. Listing the link's own ``package.json`` alone left
    those members out of yarn's copy, and they went unaudited.

    Nothing is walked again: ``walked`` already holds every manifest the walk
    found, so each is matched against the targets above its real path. The
    ``listed`` paths are skipped. At most ``_MAX_LINK_ALIAS_MANIFESTS`` paths
    are added; past that the package is refused (``TooManyLinkedDirectories``),
    since a repository with many links to one large directory would otherwise
    multiply the copy.
    """
    targets: Dict[str, List[Path]] = {}
    for linked, real in aliases:
        targets.setdefault(real, []).append(linked)
    seen = set(listed)
    added: List[Path] = []
    for manifest in walked:
        # The real directory the manifest sits in; the name stays package.json
        # whatever the file itself is.
        real_home = os.path.realpath(manifest.parent)
        directory = real_home
        while True:
            for linked in targets.get(directory, ()):
                path = linked / os.path.relpath(real_home, directory) / manifest.name
                if path in seen:
                    continue
                seen.add(path)
                added.append(path)
                if len(added) > _MAX_LINK_ALIAS_MANIFESTS:
                    raise TooManyLinkedDirectories(
                        f"more than {_MAX_LINK_ALIAS_MANIFESTS} manifests are "
                        "reached through links to directories already listed, so "
                        "the package's inputs cannot be listed in bounded time; "
                        "the package was not audited"
                    )
            parent = os.path.dirname(directory)
            if parent == directory:
                break
            directory = parent
    return added


def package_manager_inputs(
    binary: str,
    package_dir: Path,
    *,
    skip: Iterable[Path] = (),
    roots: Iterable[Path] = (),
) -> List[Path]:
    """Every file ``binary`` reads from the package, named as it sits in the tree.

    npm and pnpm: the manifest and each lockfile they read that is present
    (``_PACKAGE_MANAGER_INPUTS``; npm reads ``npm-shrinkwrap.json`` ahead of
    ``package-lock.json``), and for pnpm its workspace settings file. yarn: its
    lockfile and every ``package.json`` below the package, a linked one and those
    in a linked directory included, since yarn follows both when it looks for a
    workspace's members; ``node_modules``, ``.git`` and the ``skip`` directories
    are left out. A name that resolves to nothing is not listed: no tool can read
    it. The package's own ``package.json`` and the lockfiles are the exception:
    each is listed when it is a link, even one to nothing, so that a dangling
    link is refused with its reason rather than the tool started without a
    manifest, or the package read as having no lockfile and passed over with
    nothing recorded.

    A ``skip`` directory that holds the package itself (ASH's output directory,
    when the package sits in the converted work directory below it) skips nothing:
    pruning it pruned every directory of the package, so a workspace's member
    manifests there were neither refusal-checked nor copied.

    ``roots`` are the trees a linked directory may be walked into (the scanned
    tree): yarn walks a linked directory for members like any other, so one that
    resolves inside a root is walked here too, and a member manifest two levels
    below the link is listed. Each REAL directory is walked once, whatever the
    number of links that reach it: a link that resolves inside the package
    directory is never walked (os.walk reaches that directory at its own path,
    so its members are listed there, where a workspace glob over the real path
    finds them; the link's own ``package.json`` is listed as a file yarn reads
    at the link's path, and the alias is logged), and a link that resolves
    outside the package but inside a root is walked the first time it is
    reached and not walked after that. Each link left unwalked, a link back to
    an ancestor excepted, also gets the manifests found below its target listed
    under its own name (``_manifests_below_links``), without another walk: yarn
    reads a member through the path a workspace glob names, and a glob over the
    link's path reaches members the real path's glob does not. A walk that
    re-entered a real directory once per distinct link chain cost 2^N walks on
    a tree of N directories each holding two links to the next, a bound a
    scanned repository could remove; ``_MAX_LINKED_DIRECTORY_WALKS`` distinct
    linked directories is the hard cap behind the rule, past which the package
    is refused (``TooManyLinkedDirectories``). Three linked directories inside
    the roots are never walked: one that resolves into a ``node_modules`` or
    ``.git`` (left out like the real directories of those names), one that
    resolves to the package directory or an ancestor of it (which would walk
    the scanned tree again under the link's name), and one whose real path was
    walked already; each has its own ``package.json`` listed, and the last,
    like a link into the package, also the members found below its target, as
    above. A linked
    directory that resolves outside every root has only its own
    ``package.json`` listed, present or not, which ``input_refusal`` then refuses
    for resolving outside the tree, so the package is refused and nothing below
    the link is read: a link to a large tree elsewhere is never walked. With no
    ``roots`` no linked directory is walked and only a manifest that exists at
    the link's top is listed.
    """
    package_dir = Path(package_dir)
    manifest = package_dir / "package.json"
    inputs: List[Path] = []
    if manifest.is_symlink() and not manifest.exists():
        inputs.append(manifest)

    def _present(name: str) -> bool:
        # A lockfile link to nothing is listed too, for the same reason the
        # manifest's is: refused with its reason, never read as "no lockfile".
        path = package_dir / name
        return path.exists() or (name in _LOCKFILE_NAMES and path.is_symlink())

    if binary != "yarn":
        names = _PACKAGE_MANAGER_INPUTS.get(binary, ("package.json",))
        return inputs + [package_dir / name for name in names if _present(name)]
    if _present("yarn.lock"):
        inputs.append(package_dir / "yarn.lock")
    skipped = [
        Path(os.path.realpath(p)) for p in skip if not _within(package_dir, Path(p))
    ]
    bounds = [Path(r) for r in roots]
    # The real paths of the linked directories walked so far, each walked once.
    # A link into the package directory itself is never walked: os.walk reaches
    # that directory at its own path and lists its members there, which is
    # where a workspace glob over the real path (``packages/ui/plugins/*``)
    # looks in yarn's copy; a walk through the link listed them under the
    # link's name only. A walk that re-entered a real directory once per link
    # chain (no visited set, cycles cut only) was unbounded on a tree of N
    # directories each holding two links to the next: 2^N walks, twice per
    # package. The count of linked directories entered is capped as well.
    visited: set[str] = set()
    walked_links = 0
    # The manifests the walk found, each at the path it was reached by, and the
    # links it did not walk (link path, real path of the target): the manifests
    # below such a target are listed again under the link's name afterwards.
    walked: List[Path] = []
    aliases: List[Tuple[Path, str]] = []

    def _walk(start: Path) -> None:
        nonlocal walked_links
        for root, dirs, files in os.walk(start, followlinks=False):
            here = Path(root)
            manifest = here / "package.json"
            dirs[:] = [
                d
                for d in dirs
                if d not in _SKIPPED_DIR_NAMES
                and not any(_within(here / d, s) for s in skipped)
            ]
            if "package.json" in files and manifest.exists():
                inputs.append(manifest)
                walked.append(manifest)
            # os.walk does not descend a linked directory; yarn does.
            for d in dirs:
                linked = here / d
                if not linked.is_symlink():
                    continue
                if bounds and any(_within(linked, bound) for bound in bounds):
                    if _links_into_skipped_dir(linked, package_dir):
                        # ``deps -> node_modules``: the names above prune the
                        # real directory; a link to it was walked in full,
                        # every installed package's manifest listed, checked
                        # and copied, three times per package.
                        continue
                    real = os.path.realpath(linked)
                    loops_back = _within(here, linked)
                    if (
                        loops_back
                        or _within(Path(real), package_dir)
                        or real in visited
                    ):
                        # ``packages/root -> ..`` (an ancestor of this
                        # directory, the whole scanned tree included); a link
                        # into the package (``ui -> packages/ui``), whose
                        # target os.walk reaches at its own path; or a link to
                        # a directory walked already. Walking any of them
                        # would list the same directory again under another
                        # name, and a loop without end for the first two. Its
                        # own manifest is a file yarn reads at this path, so
                        # that is listed; nothing below it is walked, and the
                        # alias is logged. Except for a link back to an
                        # ancestor, the manifests found below its target are
                        # listed under the link's name too once the walk is
                        # done (``_manifests_below_links``), since yarn
                        # reaches those members through the link's path.
                        if (linked / "package.json").exists():
                            inputs.append(linked / "package.json")
                        if not loops_back:
                            aliases.append((linked, real))
                        ASH_LOGGER.debug(
                            f"npm-audit: {linked} is a link to {real}, which the "
                            "walk lists at its own path; its members are listed "
                            "under the link's name without walking it again",
                            extra={"markup": False},
                        )
                        continue
                    walked_links += 1
                    if walked_links > _MAX_LINKED_DIRECTORY_WALKS:
                        raise TooManyLinkedDirectories(
                            f"{package_dir}: more than {_MAX_LINKED_DIRECTORY_WALKS} "
                            "linked directories to walk for one package, so its "
                            "inputs cannot be listed in bounded time; the package "
                            "was not audited"
                        )
                    visited.add(real)
                    _walk(linked)
                elif bounds or (linked / "package.json").exists():
                    # Outside every root the link's own manifest is listed
                    # whether or not it exists: input_refusal refuses it for
                    # resolving outside the tree either way, and a link whose
                    # target holds members only deeper down (packages/ext ->
                    # /elsewhere with /elsewhere/x/package.json) was listed
                    # for nothing, so nothing was refused and in-place yarn
                    # read those members from outside the tree.
                    inputs.append(linked / "package.json")

    _walk(package_dir)
    if aliases:
        inputs.extend(_manifests_below_links(aliases, walked, inputs))
    return inputs


def input_refusal(path: Path, roots: Iterable[Path]) -> Optional[str]:
    """Why ``path`` is not handed to the package manager, or None when it can be.

    It has to resolve inside one of ``roots``, the scanned tree, so that neither a
    link nor a linked directory above it hands the tool a file from elsewhere, and
    to be a regular file. ``sandbox_grants.is_within`` decides inside: the resolved
    path, compared with each root by file identity, so a root named through a link
    still counts.
    """
    # Imported here: sandbox_grants imports ash_config, which imports the scanners.
    from automated_security_helper.config.sandbox_grants import is_within

    if not any(is_within(Path(path), Path(root)) for root in roots):
        return LINK_LEAVES_TREE
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return NOT_A_REGULAR_FILE
    return None if stat.S_ISREG(mode) else NOT_A_REGULAR_FILE


def refused_inputs(
    binary: str,
    package_dir: Path,
    *,
    roots: Iterable[Path],
    skip: Iterable[Path] = (),
) -> List[Tuple[Path, str]]:
    """Each file ``binary`` would read from the package that it must not, and why."""
    roots = list(roots)
    refused = []
    for path in package_manager_inputs(binary, package_dir, skip=skip, roots=roots):
        reason = input_refusal(path, roots)
        if reason is not None:
            refused.append((path, reason))
    return refused


def _descriptor_within(fd: int, roots: Iterable[Path]) -> Optional[bool]:
    """Whether the file open on ``fd`` lies inside one of ``roots``, judged by
    the descriptor's own path; None where the platform names no such path.

    Linux names an open file at ``/proc/self/fd/<n>``, a link to the file as
    it is NOW, whatever name it was opened by. Judging the location by the
    NAME (``input_refusal`` on it, then ``os.stat`` of it, after the open)
    resolved the name three times, and a name pointed at an in-tree regular
    file for the middle read and at an outside file for the other two passed
    with the identities matching. The descriptor's path is read once and
    judged as ``input_refusal`` judges a name (``sandbox_grants.is_within``,
    by file identity). A descriptor that names no path (a pipe, a socket) is
    outside every root.
    """
    link = f"/proc/self/fd/{fd}"
    if not os.path.islink(link):
        return None
    opened_path = os.path.realpath(link)
    if not os.path.isabs(opened_path) or not os.path.exists(opened_path):
        return False
    # Imported here: sandbox_grants imports ash_config, which imports the scanners.
    from automated_security_helper.config.sandbox_grants import is_within

    return any(is_within(Path(opened_path), Path(root)) for root in roots)


def _input_refused(path: Path, reason: str) -> InputRefused:
    """The refusal ``_read_admitted`` raises, naming the file and the reason."""
    return InputRefused(f"{path}: {reason}; the package was not audited")


def _read_admitted(path: Path, roots: Iterable[Path]) -> bytes:
    """The bytes of ``path`` when it may be handed to the tool; else it raises.

    The file is opened FIRST and judged through the open descriptor: a regular
    file by ``fstat``; inside a root by the descriptor's own path where the
    platform names one (``_descriptor_within``, Linux), else by
    ``input_refusal`` on the name tied to the open file by identity (device
    and inode). Checking the name and then reading by name left a window in
    which the file could be swapped for a link out of the tree or a FIFO, and
    the read followed the new shape; here the descriptor's path judges the
    open file itself, and on a platform without one a swap before the open is
    caught by the check on the new object and a swap after it by the identity
    compare (a double swap between those name reads is not; the descriptor
    path closes it where it exists). A file that cannot be OPENED raises
    ``InputUnreadable``, and one the open file shows not to be admissible
    raises ``InputRefused`` with the reason: both passed the scanner's check,
    so dropping either would hand the tool a copy missing a file it reads in
    place, with nothing recorded. Where the platform has ``O_NONBLOCK``
    it keeps the open of a FIFO from waiting for a writer, and it is cleared
    before the read. Windows has no ``O_NONBLOCK``, so the open there is plain
    and nothing is cleared: its ``os.set_blocking`` (3.12 and later) accepts
    pipes only and refuses a file handle with ERROR_INVALID_PARAMETER, which
    read as "the audit raised OSError: [WinError 87]" on every lockfile.
    """
    roots = list(roots)
    nonblocking = getattr(os, "O_NONBLOCK", 0)
    # O_BINARY where the platform has it (Windows; 0 elsewhere): os.open adds
    # none of its own, and a descriptor in the C runtime's text mode turns
    # CRLF into LF and reads Ctrl-Z as the end of the file, so the bytes
    # handed to the tool were not the file's.
    binary = getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, os.O_RDONLY | nonblocking | binary)
    except OSError as error:
        raise InputUnreadable(
            error.errno,
            f"{path}: cannot be read for the copy ({error.strerror or error})",
            str(path),
        ) from error
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise _input_refused(path, NOT_A_REGULAR_FILE)
        inside = _descriptor_within(fd, roots)
        if inside is False:
            raise _input_refused(path, OPENED_FILE_NOT_IN_TREE)
        if inside is None:
            refusal = input_refusal(path, roots)
            if refusal is not None:
                raise _input_refused(path, refusal)
            try:
                named = os.stat(path)
            except OSError:
                raise _input_refused(path, CHANGED_WHILE_READ) from None
            if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
                raise _input_refused(path, CHANGED_WHILE_READ)
        if nonblocking:
            os.set_blocking(fd, True)
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            return handle.read()
    finally:
        if fd >= 0:
            os.close(fd)


def _copy_inputs(
    binary: str,
    package_dir: Path,
    project: Path,
    *,
    roots: Sequence[Path],
    skip: Iterable[Path],
    ignore_suppressions: bool,
    private: Path,
) -> None:
    """Each input that stays in the tree, at its place below ``project``.

    Read through ``_read_admitted`` (one that cannot be read raises
    ``InputUnreadable``, and one refused on opening it ``InputRefused``, to the
    scan loop, which records it; the copy is never left without a file the
    tool would read in place) and written through fs_guard (``_write_copy``),
    which makes the parents and refuses a link on the way, with ``private`` as
    the guarded root.

    pnpm's copy always ends up with a ``pnpm-workspace.yaml`` (``_pnpm_workspace_copy``):
    the repository's, reduced, when it has one, else the default, so the copy is
    its own workspace root whatever the repository holds.
    """
    workspace_written = False
    for source in package_manager_inputs(binary, package_dir, skip=skip, roots=roots):
        data = _read_admitted(source, roots)
        target = project / source.relative_to(package_dir)
        if source.name == "package.json":
            _copy_manifest(
                data,
                target,
                binary=binary,
                ignore_suppressions=ignore_suppressions,
                private=private,
            )
        elif binary == "pnpm" and source.name == PNPM_WORKSPACE_FILE:
            reduced = _pnpm_workspace_copy(
                data, ignore_suppressions=ignore_suppressions
            )
            _write_copy(target, reduced, private)
            workspace_written = True
        else:
            _write_copy(target, data, private)
    if binary == "pnpm" and not workspace_written:
        _write_copy(
            project / PNPM_WORKSPACE_FILE,
            _pnpm_workspace_copy(None, ignore_suppressions=ignore_suppressions),
            private,
        )


@contextmanager
def package_manager_child(
    binary: str,
    package_dir: Path,
    *,
    parent: Path,
    scan_root: Optional[Path] = None,
    skip: Iterable[Path] = (),
    roots: Optional[Sequence[Path]] = None,
    yarn_major: Optional[int] = None,
    ignore_suppressions: bool = False,
) -> Iterator[PackageManagerChild]:
    """How to start ``binary`` (npm, pnpm or yarn) for the package in ``package_dir``.

    Spawn ``[binary, *child.leading_args, ...]`` with ``cwd=child.cwd`` and
    ``env=child.env``. Refuse the package first when ``refused_inputs`` names a
    file: in place, yarn would read it.

    Args:
        parent: Where a private directory may go that a sandboxed tool can see (the
            scanner's results directory).
        scan_root: The scanned tree. yarn's unsandboxed copy is made outside it
            (``_yarn_copy_parent``), or outside the package directory when it is
            not given; when no directory outside can hold the copy, yarn falls
            back to the sandbox's flags.
        skip: Directories not to copy manifests from (ASH's output directory).
        roots: The trees a copied file has to resolve inside (``input_refusal``);
            ``scan_root`` when not given, else the package directory.
        yarn_major: The major version when known; None for the version probe,
            which then gets ``YARN_IGNORE_PATH`` and ``YARN_RC_FILENAME`` naming
            a file no directory has (``no_yarnrc_name``, drawn per child), on
            every path, but no ``--no-default-rc``.
        ignore_suppressions: ``--ignore-suppressions`` is in effect.
    """
    package_dir = Path(package_dir)
    if roots is None:
        roots = [Path(scan_root) if scan_root is not None else package_dir]
    sandboxed = _sandboxed()
    env = snapshot_environ()
    env["YARN_IGNORE_PATH"] = "1"
    if binary == "yarn" and yarn_major is None:
        # The version probe does not know which yarn it starts. yarn 1 keeps an
        # unknown variable as a setting nothing reads (measured: 1.22.22 loads
        # YARN_* names as config keys), and yarn 2+ reads no settings file when
        # none has this name. ``--no-default-rc`` is left out: yarn 2+ would not
        # accept it.
        env["YARN_RC_FILENAME"] = no_yarnrc_name()
    copy_parent: Optional[Path] = None
    if binary == "yarn" and not sandboxed:
        # The tree the copy has to leave is the scanned one, else the package
        # itself (the same fallback ``roots`` takes): with no scan_root the
        # output directory was accepted wherever it was, so a results directory
        # under the package put the copy inside it, and yarn read the
        # package's own .npmrc and .yarnrc as parent-directory files.
        copy_parent, passed_over = _yarn_copy_parent(
            Path(parent), Path(scan_root) if scan_root is not None else package_dir
        )
        if copy_parent is None:
            # The fallback below drops the operator's ~/.npmrc and ~/.yarnrc
            # (a private registry and its credentials live there) and nothing
            # said so: a container with HOME unset or read-only, or an output
            # directory and cache both inside the tree, audited against the
            # public registry with no line in the log.
            ASH_LOGGER.warning(
                "yarn runs in %s with every settings file dropped, the operator's "
                "~/.npmrc and ~/.yarnrc included: no directory outside the scanned "
                "tree could hold its copy (%s)",
                package_dir,
                "; ".join(passed_over) or "no candidate",
            )
    in_place_yarn = binary == "yarn" and (sandboxed or copy_parent is None)
    if in_place_yarn:
        # Every settings file is dropped: the operator's are not visible under a
        # sandbox anyway, and outside one this is only when no copy can be made
        # outside the scanned tree.
        if yarn_major is not None and yarn_major >= 2:
            env["YARN_RC_FILENAME"] = no_yarnrc_name()
        leading: Tuple[str, ...] = (
            ("--no-default-rc",) if yarn_major is not None and yarn_major < 2 else ()
        )
        yield PackageManagerChild(leading_args=leading, cwd=package_dir, env=env)
        return
    where = str(copy_parent) if binary == "yarn" else str(parent)
    directory = Path(tempfile.mkdtemp(prefix=f"ash-{binary}-", dir=where)).absolute()
    try:
        project = directory / "project"
        project.mkdir()
        _copy_inputs(
            binary,
            package_dir,
            project,
            roots=list(roots),
            skip=skip,
            ignore_suppressions=ignore_suppressions,
            private=directory,
        )
        yield PackageManagerChild(leading_args=(), cwd=project, env=env)
    finally:
        shutil.rmtree(directory, ignore_errors=True)
