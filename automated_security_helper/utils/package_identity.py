# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Package identity for dependency-scanner findings.

A dependency scanner reports one finding per (advisory, package copy). Its
SARIF location is usually just the manifest or lockfile, so two copies of one
package in one lockfile -- a top-level ``brace-expansion`` and a copy bundled
inside ``aws-cdk-lib`` -- land on the same file and often the same line. The
only thing that tells them apart is which package the finding is about.

Converters record that in ``result.properties`` under three keys:

``package_name``
    The package's name as the ecosystem spells it.
``package_version``
    The installed version (not the advisory's vulnerable range).
``package_path``
    Where the package is installed, relative to the scan root: the lockfile's
    directory joined with the lockfile's ``packages`` key, for example
    ``deploy/cdk/node_modules/aws-cdk-lib/node_modules/brace-expansion``. Only
    set when the lockfile pins the finding to exactly one entry.

Each key is written only when the converter knows it. A package-scoped
suppression that asks for a key the finding does not carry does not match, so
a missing key can only leave a finding unsuppressed, never hide one.

Only npm lockfiles (``package-lock.json`` and ``npm-shrinkwrap.json``, format
v2 and later, which carry a ``packages`` map) can produce ``package_path``.
Other lockfile formats produce name and version only.
"""

from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from automated_security_helper.utils.log import ASH_LOGGER

PACKAGE_NAME_KEY = "package_name"
PACKAGE_VERSION_KEY = "package_version"
PACKAGE_PATH_KEY = "package_path"

NPM_LOCKFILE_NAMES = frozenset({"package-lock.json", "npm-shrinkwrap.json"})

_JSON_KEY_LINE = re.compile(r'^\s*("(?:[^"\\]|\\.)*")\s*:')


@dataclass(frozen=True)
class NpmLockEntry:
    """One entry of an npm lockfile's ``packages`` map."""

    key: str
    """The ``packages`` key, e.g. ``node_modules/a/node_modules/b``."""
    name: str
    version: Optional[str]
    line: Optional[int]
    """1-based line of the key in the lockfile text, when it could be found."""


def _name_from_key(key: str, entry: Dict[str, Any]) -> str:
    name = entry.get("name")
    if isinstance(name, str) and name:
        return name
    marker = "node_modules/"
    idx = key.rfind(marker)
    return key[idx + len(marker) :] if idx >= 0 else posixpath.basename(key)


def load_npm_lock_entries(lockfile: Path) -> Optional[List[NpmLockEntry]]:
    """Parse an npm v2+ lockfile into its ``packages`` entries.

    Returns None when the file is not an npm lockfile, cannot be read, or has
    no ``packages`` map (lockfile v1). The root entry (key ``""``) is skipped.
    """
    if lockfile.name not in NPM_LOCKFILE_NAMES:
        return None
    try:
        text = lockfile.read_text(encoding="utf-8")
        data = json.loads(text)
    except (OSError, ValueError) as exc:
        ASH_LOGGER.debug(f"Could not read npm lockfile {lockfile}: {exc}")
        return None
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return None

    # Line numbers: trivy reports each package by the line range of its entry,
    # and the entry starts on the line holding its key. A key is a JSON string
    # followed by a colon at the start of a line. Only keys containing
    # "node_modules/" are located: an entry's own "dependencies" object uses
    # bare package names, which could collide with a workspace key such as
    # "lib", but never with a node_modules path. The first occurrence wins,
    # because the packages map precedes the legacy v2 "dependencies" section.
    key_lines: Dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        match = _JSON_KEY_LINE.match(line)
        if not match:
            continue
        try:
            key = json.loads(match.group(1))
        except ValueError:
            continue
        if (
            isinstance(key, str)
            and "node_modules/" in key
            and key in packages
            and key not in key_lines
        ):
            key_lines[key] = number

    entries = []
    for key, entry in packages.items():
        if not key or not isinstance(entry, dict):
            continue
        version = entry.get("version")
        entries.append(
            NpmLockEntry(
                key=key,
                name=_name_from_key(key, entry),
                version=version if isinstance(version, str) else None,
                line=key_lines.get(key),
            )
        )
    return entries


class NpmLockIndex:
    """Caches parsed lockfiles for one converter pass."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self._cache: Dict[str, Optional[List[NpmLockEntry]]] = {}

    def entries(self, lockfile_rel: str) -> Optional[List[NpmLockEntry]]:
        rel = lockfile_rel.lstrip("/")
        if rel not in self._cache:
            self._cache[rel] = load_npm_lock_entries(self.root / rel)
        return self._cache[rel]

    def entry(self, lockfile_rel: str, key: str) -> Optional[NpmLockEntry]:
        for candidate in self.entries(lockfile_rel) or []:
            if candidate.key == key:
                return candidate
        return None

    def unique_by_name_version(
        self, lockfile_rel: str, name: str, version: str
    ) -> Optional[NpmLockEntry]:
        """The one entry with this name and version, or None if zero or several.

        Several entries is the collision case: the scanner's finding could be
        any of them, so no path is claimed.
        """
        matches = [
            e
            for e in self.entries(lockfile_rel) or []
            if e.name == name and e.version == version
        ]
        return matches[0] if len(matches) == 1 else None

    def by_line(self, lockfile_rel: str, line: int) -> Optional[NpmLockEntry]:
        for candidate in self.entries(lockfile_rel) or []:
            if candidate.line == line:
                return candidate
        return None


def install_path(lockfile_rel: str, key: str) -> str:
    """Join the lockfile's directory and a ``packages`` key into a posix path."""
    directory = posixpath.dirname(lockfile_rel.replace("\\", "/").lstrip("/"))
    return posixpath.normpath(posixpath.join(directory, key)) if directory else key


def identity_properties(
    name: Optional[str], version: Optional[str], path: Optional[str]
) -> Dict[str, str]:
    """The properties to write, omitting any piece that is unknown."""
    out: Dict[str, str] = {}
    if name:
        out[PACKAGE_NAME_KEY] = name
    if version:
        out[PACKAGE_VERSION_KEY] = version
    if path:
        out[PACKAGE_PATH_KEY] = path
    return out


def extract_package_identity(
    properties: Any,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Read (name, version, path) from a SARIF result's properties.

    Accepts a PropertyBag, a dict, or None. Non-string values are ignored.
    """
    if properties is None:
        return None, None, None
    if hasattr(properties, "model_dump"):
        properties = properties.model_dump(exclude_none=True)
    if not isinstance(properties, dict):
        return None, None, None

    def _get(key: str) -> Optional[str]:
        value = properties.get(key)
        return value if isinstance(value, str) and value else None

    return _get(PACKAGE_NAME_KEY), _get(PACKAGE_VERSION_KEY), _get(PACKAGE_PATH_KEY)
