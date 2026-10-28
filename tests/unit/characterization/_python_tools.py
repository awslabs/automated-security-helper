# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shapes a Python tool on PATH can take, for the uv-backed scanners' checks.

``UVToolMixin._select_tool_execution`` reads the file it finds on PATH to decide how
to verify it (``utils/pre_installed_tool.py``). A plain stand-in has no Python
environment, so it is "unverifiable". A ``python`` stand-in beside it gives it one.
:func:`nix_wrapped` rewrites a stand-in into the two files nixpkgs generates for a
Python program, so the Nix branch is reached by reading files, as on a Nix host.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional


def nix_wrapped(
    char,
    name: str,
    *,
    distribution: Optional[str],
    python: str = "python3.12",
) -> Path:
    """Make ``<BIN>/<name>`` a nixpkgs makeWrapper script for a Python program.

    The wrapper execs ``.<name>-wrapped``, whose shebang names a store interpreter
    and whose second line adds one store site-packages directory. With
    ``distribution`` (``"semgrep-1.130.0"``) that directory holds the
    distribution's METADATA; with None it holds none, which ASH reports as a Nix
    program it cannot verify. The stand-in must already be declared with
    ``char.tool(name, ...)``; only its content changes, so the harness still routes
    its launch to the double.
    """
    store = char.tmp / "nix" / "store"
    interpreter = store / "aaaa-python3-3.12.8" / "bin" / python
    package = store / f"bbbb-{name}"
    site = package / "lib" / python / "site-packages"
    site.mkdir(parents=True, exist_ok=True)
    interpreter.parent.mkdir(parents=True, exist_ok=True)
    interpreter.write_text("", encoding="utf-8")
    if distribution is not None:
        package_name, _, version = distribution.rpartition("-")
        dist_info = site / f"{distribution}.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {package_name}\nVersion: {version}\n",
            encoding="utf-8",
        )
    wrapped = package / "bin" / f".{name}-wrapped"
    wrapped.parent.mkdir(parents=True, exist_ok=True)
    wrapped.write_text(
        f"#!{interpreter}\n"
        "import sys;import site;import functools;"
        f"sys.argv[0] = '{package}/bin/{name}';"
        "functools.reduce(lambda k, p: site.addsitedir(p, k), "
        f"['{site}'], site._init_pathinfo());\n",
        encoding="utf-8",
    )
    wrapper = char.bin / name
    if not wrapper.is_file():
        raise AssertionError(f"declare {name} with char.tool() before wrapping it")
    wrapper.write_text(
        f'#! {store}/cccc-bash-5.2/bin/bash -e\nexec -a "$0" "{wrapped}"  "$@"\n',
        encoding="utf-8",
    )
    return wrapper
