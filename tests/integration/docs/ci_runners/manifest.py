# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reading the pinned manifest, runners.toml, for the launchers.

install_tools.py downloads and checks every tool and image the manifest pins; the
launchers only read it: where a tool's program is under the bin directory
install_tools.py filled, and the digest of each image a runner is told to use.
Entries are named as install_tools.RUNNER_PINS names them: ``tools.<name>``,
``images.<name>``, ``jenkins.cores.<core>``.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

RUNNERS_TOML = Path(__file__).resolve().with_name("runners.toml")


def load_toml(path: Path) -> dict[str, Any]:
    with Path(path).open("rb") as handle:
        return tomllib.load(handle)


def load_manifest(path: Path = RUNNERS_TOML) -> dict[str, Any]:
    return load_toml(path)


def entry(manifest: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    """The table ``key`` names, for example ``tools.act`` or ``jenkins.cores.lts``."""
    table: Any = manifest
    for part in key.split(".", 2 if key.startswith("jenkins.") else 1):
        if not isinstance(table, Mapping) or part not in table:
            raise KeyError(f"runners.toml has no {key}")
        table = table[part]
    if not isinstance(table, Mapping):
        raise KeyError(f"runners.toml's {key} is not a table")
    return table


def tool_executable(manifest: Mapping[str, Any], bin_dir: Path, key: str) -> Path:
    """The program of tool ``key``, as install_tools.py installed it under ``bin_dir``."""
    if not key.startswith("tools."):
        raise ValueError(f"{key} is not a tool")
    executable = entry(manifest, key).get("executable")
    relative = PurePosixPath(str(executable or ""))
    if not executable or relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{key}'s executable {executable!r} is not a relative path")
    return Path(bin_dir) / key.split(".", 1)[1] / Path(*relative.parts)


def image_ref(manifest: Mapping[str, Any], key: str) -> str:
    """The digest reference of image ``key``."""
    if not key.startswith("images."):
        raise ValueError(f"{key} is not an image")
    ref = entry(manifest, key).get("ref")
    if not isinstance(ref, str) or "@sha256:" not in ref:
        raise ValueError(f"{key} has no digest reference")
    return ref


def image_digest(ref: str) -> str:
    """``sha256:<hex>`` of a digest reference."""
    _, _, digest = ref.partition("@")
    if not digest.startswith("sha256:"):
        raise ValueError(f"{ref} is not a digest reference")
    return digest
