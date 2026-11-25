# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The launch environment a runtime-compatibility POLYFILL row asks for.

A POLYFILL row (``base/scanner_operational_facets.py``) declares a shim that is
applied over {runtime range x tool range} when the tool launches. The shim is a
``sitecustomize`` module that ships under
``automated_security_helper/assets/polyfills/<name>/``; this module puts that
directory on the child's ``PYTHONPATH`` so CPython's startup imports it before
any tool code runs, the tool's ``multiprocessing`` children included (they
inherit the environment). Nothing is written into the uv-managed tool
environment, which ``uv tool install --reinstall`` (ASH issues it) would
discard and which other uv users on the host share.

The two halves of the range gate sit on different sides, because the
interpreter uv picks is not known before launch:

- the TOOL range is decided here, from the scanner's effective version
  constraint (:meth:`RuntimeCompatRow.applies_to`);
- the RUNTIME range is decided by the shim itself, whose first act is to
  return when ``sys.version_info`` is outside it.

Python imports one ``sitecustomize``, so at most one polyfill row may apply to
a scanner; the register's consistency gate refuses a second.

Like :func:`automated_security_helper.utils.offline_tool_env.with_offline_tool_environment`,
which is this function's shape, the result is the environment unchanged for a
scanner with no row, and an ``env`` of None stays None in that case.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

#: Where the shims ship, one directory per polyfill name.
POLYFILLS_DIR = Path(__file__).resolve().parent.parent / "assets" / "polyfills"


def polyfill_directory(name: str) -> Path:
    """The directory holding polyfill *name*'s ``sitecustomize.py``."""
    return POLYFILLS_DIR / name


def runtime_compat_environment(plugin: Any) -> Dict[str, str]:
    """The environment additions *plugin*'s applicable POLYFILL rows ask for.

    ``{}`` when the class declares no register row, no row applies, or no
    applicable row is a POLYFILL.
    """
    from automated_security_helper.base.scanner_operational_facets import (
        declared_runtime_compat,
    )

    compat = declared_runtime_compat(type(plugin))
    if compat is None:
        return {}
    constraint_hook = getattr(plugin, "_get_tool_version_constraint", None)
    constraint = constraint_hook() if callable(constraint_hook) else None
    rows = compat.polyfills(constraint)
    if not rows:
        return {}
    if len(rows) > 1:
        raise ValueError(
            f"{type(plugin).__name__} declares {len(rows)} applicable polyfill "
            "rows; Python imports one sitecustomize, so at most one may apply"
        )
    return {"PYTHONPATH": str(polyfill_directory(rows[0].polyfill or ""))}


def with_runtime_compat_environment(
    env: Optional[Mapping[str, str]], plugin: Any
) -> Optional[Dict[str, str]]:
    """*env* with the shim directory prepended to its ``PYTHONPATH``.

    The caller's own ``PYTHONPATH`` is kept after the shim directory, never
    replaced. ``env`` None means "inherit": it stays None when there is nothing
    to add, and otherwise becomes a copy of the current environment with the
    addition.
    """
    additions = runtime_compat_environment(plugin)
    if not additions:
        return None if env is None else dict(env)
    if env is None:
        from automated_security_helper.utils.process_env import snapshot_environ

        env = snapshot_environ()
    shim_dir = additions["PYTHONPATH"]
    existing = env.get("PYTHONPATH", "")
    merged = shim_dir + (os.pathsep + existing if existing else "")
    return {**env, "PYTHONPATH": merged}
