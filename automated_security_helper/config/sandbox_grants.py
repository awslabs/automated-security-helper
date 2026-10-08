# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Sandbox grants a config file inside the scanned tree is not allowed to make.

The repository being scanned is untrusted. Anyone who can commit to it can write a
config file there, and ASH picks up ``.ash/.ash.yaml`` from the scan root without
being asked. Two sandbox settings grant scanners access:

* ``sandbox.network_scanners`` gives the scanners it names a network.
* ``sandbox.extra_read_paths`` mounts host paths into every sandbox.

If any file the config was built from is inside the scanned tree (the root config
or any ``extends`` base), both settings are taken from the defaults plus
``--config-overrides`` instead. That is the value ASH would use if those files did
not exist. Comparing against that resolution, and not against override key names,
is what makes ``key+=[...]``, the dashed spelling, and a whole-``sandbox`` override
behave the same as a plain ``key=value``.

The in-tree ``network_scanners`` is kept as a limit (``SandboxConfig.network_limit``):
a scanner it does not name gets no network. A repository can still take network
away from its own scan, which is what the docs recommend for detect-secrets. It just
can't add network.

Whether a file is in the tree is decided with ``os.path.samefile`` on each of the
file's parents, not by comparing path strings. A symlink, a ``..`` segment, or a
case-only difference on a case-insensitive filesystem therefore can't make an
in-tree file look like it is outside.

Known limitation: a trusted config outside the tree that ``extends`` a base inside
it loses its own grants as well. The merged document no longer records which file
set a value, so the outside file's grants can't be separated from the base's. In
that layout, set the grants with ``--config-overrides``.
"""

import os
from pathlib import Path
from typing import Iterable, List

from automated_security_helper.config.ash_config import SandboxConfig
from automated_security_helper.config.config_sources import describe_config_path
from automated_security_helper.utils.log import ASH_LOGGER


def is_within(path: Path, root: Path) -> bool:
    """True when ``path``, or a directory above it, is the same file as ``root``."""
    real = Path(os.path.realpath(path))
    for candidate in (real, *real.parents):
        try:
            if os.path.samefile(candidate, root):
                return True
        except OSError:
            continue
    return False


def files_inside(chain: Iterable[Path], scanned_root: Path) -> List[Path]:
    """The files of ``chain`` that the scanned repository can write."""
    return [path for path in chain if is_within(path, scanned_root)]


def confine_sandbox_grants(
    sandbox: SandboxConfig, trusted: SandboxConfig, in_tree: List[Path]
) -> None:
    """Replace the grants in ``sandbox`` with ``trusted``'s, keeping its list as a limit.

    Args:
        sandbox: The resolved settings, from the config files plus the overrides.
        trusted: The same settings resolved from the defaults plus the overrides.
        in_tree: The config files inside the scanned tree. Named in the warning.
    """
    dropped = []
    if sandbox.network_scanners != trusted.network_scanners:
        dropped.append("sandbox.network_scanners")
    if list(sandbox.extra_read_paths) != list(trusted.extra_read_paths):
        dropped.append("sandbox.extra_read_paths")
    limit = sandbox.network_scanners
    sandbox.network_scanners = (
        list(trusted.network_scanners) if trusted.network_scanners is not None else None
    )
    sandbox.extra_read_paths = list(trusted.extra_read_paths)
    sandbox.network_limit = list(limit) if limit is not None else None
    if dropped:
        files = ", ".join(describe_config_path(path) for path in in_tree)
        ASH_LOGGER.warning(
            f"Not granting {' or '.join(dropped)} from {files}: the file is inside "
            "the scanned tree, so the repository being scanned wrote it. Its "
            "network_scanners list still removes network from scanners it does "
            "not name. Grant access with --config-overrides or a config file "
            "outside the tree."
        )
