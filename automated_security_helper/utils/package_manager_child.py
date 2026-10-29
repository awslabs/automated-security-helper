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
  cache directory (``$XDG_CACHE_HOME/ash``, or ``~/.cache/ash``), and never under
  the system temporary directory: on a shared host its ancestors (``/tmp``) are
  writable by every user, and a ``.npmrc`` or ``.yarnrc`` planted there would
  redirect the audit (``_yarn_copy_parent``). ``--no-default-rc`` would also drop
  the operator's files,
  ``~/.npmrc`` with no way to add it back (measured: it ignores
  ``npm_config_userconfig``).
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
flag lifts every suppression.

The same shape as ``utils/python_child.py``: the private directory is made for the
child and removed when the block ends. yarn 2+ itself was not measured: none was
installed and none was downloaded; its two variables are documented settings.

npm, pnpm and yarn follow links, and none has an option not to (measured with the
versions above, offline under bwrap: a ``package-lock.json`` linking to a file
outside the scanned tree was read by each). So every file the tool reads from the
package (``package_manager_inputs``) has to resolve inside the scanned tree and be a
regular file (``input_refusal``). The scanner refuses a package with any other one
before starting anything for it, and the copy here never holds one either.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import stat
import string
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from automated_security_helper.utils.process_env import snapshot_environ

#: The files npm and pnpm get in their private directory: the manifest and the
#: lockfiles they read, and no settings file.
_PACKAGE_MANAGER_INPUTS: Dict[str, Tuple[str, ...]] = {
    "npm": ("package.json", "package-lock.json", "npm-shrinkwrap.json"),
    "pnpm": ("package.json", "pnpm-lock.yaml"),
    "yarn": ("package.json", "yarn.lock"),
}

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

#: Why a file the package manager would read is not handed to it.
LINK_LEAVES_TREE = "link leaves the scanned tree"
NOT_A_REGULAR_FILE = "not a regular file"


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
    if root is None:
        return False
    real, real_root = os.path.realpath(path), os.path.realpath(root)
    return real == real_root or real.startswith(real_root.rstrip(os.sep) + os.sep)


def _operator_cache_dir() -> Optional[Path]:
    """``$XDG_CACHE_HOME/ash``, else ``~/.cache/ash``; None with no home."""
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg).expanduser() / "ash"
    try:
        return Path.home() / ".cache" / "ash"
    except (KeyError, RuntimeError):
        return None


def _yarn_copy_parent(parent: Path, scan_root: Optional[Path]) -> Optional[Path]:
    """Where yarn's unsandboxed copy goes, or None when no directory will do.

    yarn reads ``.yarnrc``, ``.npmrc`` and ``.yarnrc.yml`` from the copy's
    directory and every parent, so the copy's ancestors decide which settings
    files it reads besides the operator's own. The scan's output directory
    (``parent``, where npm's and pnpm's copies go) is first, when it is outside
    the scanned tree: its ancestors are the operator's. When it is inside the
    tree (the default output directory is) the operator's cache directory is
    used instead. The system temporary directory is never used: on a shared
    host its ancestors (``/tmp``) are writable by every user, and a ``.npmrc``
    planted there would redirect the audit and its dependency list. None when
    both are inside the tree or cannot be made: yarn then runs in place with
    every settings file dropped.
    """
    for candidate in (Path(parent), _operator_cache_dir()):
        if candidate is None or _within(candidate, scan_root):
            continue
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError:
            continue
        return candidate
    return None


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
    source: Path, target: Path, *, ignore_suppressions: bool, private: Path
) -> None:
    """Copy ``package.json``, without ``pnpm.auditConfig`` when suppressions are off."""
    data = source.read_bytes()
    if not ignore_suppressions:
        _write_copy(target, data, private)
        return
    try:
        # utf-8-sig: a manifest that starts with a byte order mark is JSON to
        # the package managers, and json.loads refuses the mark, so the
        # auditConfig stayed in the copy of such a manifest and pnpm applied
        # the repository's ignore lists under the flag that lifts them.
        manifest = json.loads(data.decode("utf-8-sig"))
    except ValueError:
        # Not JSON (or not UTF-8): the tool reports it as it would.
        _write_copy(target, data, private)
        return
    pnpm = manifest.get("pnpm") if isinstance(manifest, dict) else None
    if isinstance(pnpm, dict) and "auditConfig" in pnpm:
        pnpm.pop("auditConfig")
        data = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    _write_copy(target, data, private)


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
    ``package-lock.json``). yarn: its lockfile and every ``package.json`` below the
    package, a linked one and those in a linked directory included, since yarn
    follows both when it looks for a workspace's members; ``node_modules``,
    ``.git`` and the ``skip`` directories are left out. A name that resolves to
    nothing is not listed: no tool can read it. The package's own ``package.json``
    is the exception: it is listed when it is a link, even one to nothing, so that
    a dangling link is refused with its reason rather than the tool started
    without a manifest.

    A ``skip`` directory that holds the package itself (ASH's output directory,
    when the package sits in the converted work directory below it) skips nothing:
    pruning it pruned every directory of the package, so a workspace's member
    manifests there were neither refusal-checked nor copied.

    ``roots`` are the trees a linked directory may be walked into (the scanned
    tree): yarn walks a linked directory for members like any other, so one that
    resolves inside a root is walked here too, and a member manifest two levels
    below the link is listed. A linked directory that resolves outside every root
    has only its own ``package.json`` listed, which ``input_refusal`` then refuses,
    so nothing below it is read and a link to a large tree elsewhere is never
    walked. With no ``roots`` no linked directory is walked.
    """
    package_dir = Path(package_dir)
    manifest = package_dir / "package.json"
    inputs: List[Path] = []
    if manifest.is_symlink() and not manifest.exists():
        inputs.append(manifest)
    if binary != "yarn":
        names = _PACKAGE_MANAGER_INPUTS.get(binary, ("package.json",))
        return inputs + [
            package_dir / name for name in names if (package_dir / name).exists()
        ]
    if (package_dir / "yarn.lock").exists():
        inputs.append(package_dir / "yarn.lock")
    skipped = [
        Path(os.path.realpath(p)) for p in skip if not _within(package_dir, Path(p))
    ]
    bounds = [Path(r) for r in roots]
    # Directories already walked, by real path: a link back into the walked
    # tree, or two links to one directory, would otherwise list a manifest
    # twice or never end.
    seen: set = set()

    def _walk(start: Path) -> None:
        for root, dirs, files in os.walk(start, followlinks=False):
            here = Path(root)
            real = os.path.realpath(here)
            if real in seen:
                dirs[:] = []
                continue
            seen.add(real)
            dirs[:] = [
                d
                for d in dirs
                if d not in _SKIPPED_DIR_NAMES
                and not any(_within(here / d, s) for s in skipped)
            ]
            if "package.json" in files and (here / "package.json").exists():
                inputs.append(here / "package.json")
            # os.walk does not descend a linked directory; yarn does.
            for d in dirs:
                linked = here / d
                if not linked.is_symlink():
                    continue
                if bounds and any(_within(linked, bound) for bound in bounds):
                    _walk(linked)
                elif (linked / "package.json").exists():
                    inputs.append(linked / "package.json")

    _walk(package_dir)
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

    Written through fs_guard (``_write_copy``), which makes the parents and refuses
    a link on the way, with ``private`` as the guarded root.
    """
    for source in package_manager_inputs(binary, package_dir, skip=skip, roots=roots):
        if input_refusal(source, roots) is not None:
            continue
        target = project / source.relative_to(package_dir)
        if source.name == "package.json":
            _copy_manifest(
                source,
                target,
                ignore_suppressions=ignore_suppressions,
                private=private,
            )
        else:
            _write_copy(target, source.read_bytes(), private)


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
            (``_yarn_copy_parent``); when no directory outside it can hold the
            copy, yarn falls back to the sandbox's flags.
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
        copy_parent = _yarn_copy_parent(Path(parent), scan_root)
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
