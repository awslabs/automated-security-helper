#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Which alpha scanners a CI leg must load and check, read from plugin metadata.

The container leg used to name hadolint and GuardDog twice, as two
``--ash-plugin-modules`` flags and two entries of an expected-scanner list, so a
alpha scanner added to the image was checked only after someone remembered to
edit the action. This script answers both questions from two things the plugins
and the image already declare:

* the image's list of alpha plugin modules, the ``ASH_ALPHA_PLUGIN_MODULES``
  build argument of the Dockerfile (every copy of it, which must agree), and
* each module's own ``ASH_SCANNERS``, the scanner classes the plugin package
  declares.

Nothing here looks at where a plugin was published or which registry serves it. A
plugin is an alpha plugin because its package declares scanners and the image
lists its module; a leg that keyed off a registry would treat a plugin differently
when it moved registries, and which registry serves a plugin must not matter.

Subcommands, each printing one value per line:

``modules``   the module paths the image ships
``args``      ``--ash-plugin-modules <module>`` pairs, one flag and one value per line
``scanners``  the scanner names those modules declare, as ``ash scan --scanners`` takes them

Exit status: 0, or 2 when the Dockerfile lists no module, its copies disagree, or a
listed module declares no scanner (a leg with nothing to check must fail, not pass).
"""

from __future__ import annotations

import argparse
import importlib
import re
import sys
from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parents[2] / "Dockerfile"
_ARG = re.compile(r'^ARG\s+ASH_ALPHA_PLUGIN_MODULES="([^"]*)"\s*$', re.MULTILINE)


class LegError(Exception):
    """The metadata cannot give a usable answer."""


def image_modules(dockerfile: Path = DOCKERFILE) -> list[str]:
    """Module paths from every ``ARG ASH_ALPHA_PLUGIN_MODULES`` line, which must agree."""
    values = _ARG.findall(dockerfile.read_text(encoding="utf-8"))
    if not values:
        raise LegError(f"{dockerfile} has no ARG ASH_ALPHA_PLUGIN_MODULES line")
    lists = [[m.strip() for m in v.split(",") if m.strip()] for v in values]
    if any(entry != lists[0] for entry in lists):
        raise LegError(
            f"the ASH_ALPHA_PLUGIN_MODULES copies in {dockerfile} disagree: {lists}"
        )
    if not lists[0]:
        raise LegError("ASH_ALPHA_PLUGIN_MODULES lists no module")
    return lists[0]


def scanner_name(cls: type) -> str:
    """The name ``ash scan --scanners`` takes for a scanner class.

    Read from the scanner's own config class, whose ``name`` field declares it
    (``GuardDogScanner`` declares ``guarddog``, which no spelling rule on the class
    name gives). A class that declares none falls back to its name, hyphenated
    (``CdkNagScanner`` -> ``cdk-nag``).
    """
    from automated_security_helper.core.scanner_inventory import (
        _declared_config_class,
    )

    config = _declared_config_class(cls)
    field = getattr(config, "model_fields", {}).get("name")
    default = getattr(field, "default", None)
    if isinstance(default, str) and default:
        return default
    raw = re.sub(r"Scanner$", "", cls.__name__)
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "-", raw).lower()


def module_scanners(module: str) -> list[str]:
    """The scanner names the plugin package declares in its ``ASH_SCANNERS``."""
    try:
        imported = importlib.import_module(module)
    except ImportError as err:
        raise LegError(
            f"cannot import {module} ({err}); run this with the Python ASH is installed in"
        ) from err
    declared = getattr(imported, "ASH_SCANNERS", None) or []
    if not declared:
        raise LegError(f"{module} declares no scanner in ASH_SCANNERS")
    return [scanner_name(cls) for cls in declared]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("what", choices=("modules", "args", "scanners"))
    parser.add_argument("--dockerfile", type=Path, default=DOCKERFILE)
    ns = parser.parse_args(argv)
    try:
        modules = image_modules(ns.dockerfile)
        if ns.what == "modules":
            lines = modules
        elif ns.what == "args":
            lines = [part for m in modules for part in ("--ash-plugin-modules", m)]
        else:
            lines = [name for m in modules for name in module_scanners(m)]
    except LegError as err:
        print(f"alpha-scanner-legs: {err}", file=sys.stderr)
        return 2
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
