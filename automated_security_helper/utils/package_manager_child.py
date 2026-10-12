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
  still are (measured). ``--no-default-rc`` would also drop the operator's files,
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
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, Optional, Tuple

from automated_security_helper.utils.process_env import snapshot_environ

#: The files npm and pnpm get in their private directory: the manifest and the
#: lockfiles they read, and no settings file.
_PACKAGE_MANAGER_INPUTS: Dict[str, Tuple[str, ...]] = {
    "npm": ("package.json", "package-lock.json", "npm-shrinkwrap.json"),
    "pnpm": ("package.json", "pnpm-lock.yaml"),
    "yarn": ("package.json", "yarn.lock"),
}

#: The settings file name yarn 2+ is told to look for under a sandbox
#: (YARN_RC_FILENAME): no directory has one, so it reads no .yarnrc.yml.
NO_YARNRC = ".ash-no-yarnrc.yml"

#: Directories never copied for yarn: installed packages and version control.
_SKIPPED_DIR_NAMES = frozenset({"node_modules", ".git"})


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


def _copy_manifest(source: Path, target: Path, *, ignore_suppressions: bool) -> None:
    """Copy ``package.json``, without ``pnpm.auditConfig`` when suppressions are off."""
    if not ignore_suppressions:
        shutil.copyfile(source, target)
        return
    text = source.read_text(encoding="utf-8")
    try:
        manifest = json.loads(text)
    except ValueError:
        shutil.copyfile(source, target)  # not JSON: the tool reports it as it would
        return
    pnpm = manifest.get("pnpm") if isinstance(manifest, dict) else None
    if isinstance(pnpm, dict) and "auditConfig" in pnpm:
        pnpm.pop("auditConfig")
        text = json.dumps(manifest, indent=2) + "\n"
    target.write_text(text, encoding="utf-8")


def _copy_yarn_tree(
    package_dir: Path, project: Path, skip: Iterable[Path], ignore_suppressions: bool
) -> None:
    """The lockfile, and every ``package.json`` below ``package_dir`` at its place."""
    skipped = [Path(os.path.realpath(p)) for p in skip]
    lock = package_dir / "yarn.lock"
    if lock.is_file():
        shutil.copyfile(lock, project / "yarn.lock")
    for root, dirs, files in os.walk(package_dir, followlinks=False):
        here = Path(root)
        dirs[:] = [
            d
            for d in dirs
            if d not in _SKIPPED_DIR_NAMES
            and not any(_within(here / d, s) for s in skipped)
        ]
        if "package.json" in files and not (here / "package.json").is_symlink():
            target = project / here.relative_to(package_dir)
            target.mkdir(parents=True, exist_ok=True)
            _copy_manifest(
                here / "package.json",
                target / "package.json",
                ignore_suppressions=ignore_suppressions,
            )


@contextmanager
def package_manager_child(
    binary: str,
    package_dir: Path,
    *,
    parent: Path,
    scan_root: Optional[Path] = None,
    skip: Iterable[Path] = (),
    yarn_major: Optional[int] = None,
    ignore_suppressions: bool = False,
) -> Iterator[PackageManagerChild]:
    """How to start ``binary`` (npm, pnpm or yarn) for the package in ``package_dir``.

    Spawn ``[binary, *child.leading_args, ...]`` with ``cwd=child.cwd`` and
    ``env=child.env``.

    Args:
        parent: Where a private directory may go that a sandboxed tool can see (the
            scanner's results directory).
        scan_root: The scanned tree. yarn's unsandboxed copy is made outside it;
            when the system temporary directory is inside it, yarn falls back to
            the sandbox's flags.
        skip: Directories not to copy manifests from (ASH's output directory).
        yarn_major: The major version when known; None for the version probe,
            which then gets only ``YARN_IGNORE_PATH``.
        ignore_suppressions: ``--ignore-suppressions`` is in effect.
    """
    package_dir = Path(package_dir)
    sandboxed = _sandboxed()
    env = snapshot_environ()
    env["YARN_IGNORE_PATH"] = "1"
    in_place_yarn = binary == "yarn" and (
        sandboxed or _within(Path(tempfile.gettempdir()), scan_root)
    )
    if in_place_yarn:
        # Every settings file is dropped: the operator's are not visible under a
        # sandbox anyway, and outside one this is only when no copy can be made
        # outside the scanned tree.
        if yarn_major is not None and yarn_major >= 2:
            env["YARN_RC_FILENAME"] = NO_YARNRC
        leading: Tuple[str, ...] = (
            ("--no-default-rc",) if yarn_major is not None and yarn_major < 2 else ()
        )
        yield PackageManagerChild(leading_args=leading, cwd=package_dir, env=env)
        return
    where = None if binary == "yarn" else str(parent)
    directory = Path(tempfile.mkdtemp(prefix=f"ash-{binary}-", dir=where)).absolute()
    try:
        project = directory / "project"
        project.mkdir()
        if binary == "yarn":
            _copy_yarn_tree(package_dir, project, skip, ignore_suppressions)
        else:
            for name in _PACKAGE_MANAGER_INPUTS.get(binary, ("package.json",)):
                source = package_dir / name
                if not source.is_file():
                    continue
                if name == "package.json":
                    _copy_manifest(
                        source,
                        project / name,
                        ignore_suppressions=ignore_suppressions,
                    )
                else:
                    shutil.copyfile(source, project / name)
        yield PackageManagerChild(leading_args=(), cwd=project, env=env)
    finally:
        shutil.rmtree(directory, ignore_errors=True)
