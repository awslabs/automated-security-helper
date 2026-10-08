# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Runs INSIDE a built ASH image: does every bundled executable ship its license files?

Fed to the image's own ``python3 -c`` by assert-image-third-party-licenses.py, with
the expectations as JSON on stdin, and prints its verdict as JSON on stdout. Standard
library only, because it runs under whatever interpreter the image has.

It checks two directions, and the second is the reason it exists beside the build's
own ``install-pinned-tool --verify-third-party``:

1. Every entry of THIRD_PARTY_LICENSES has its directory, its files (matching their
   pinned SHA256 where there is one), a SOURCE file naming its commit, an
   index.json row, and its executables on PATH. The build checks this too; doing it
   again against the finished image catches a later layer deleting or masking the
   files, and checks them as the image's own user.
2. Every ELF executable on the image's PATH is accounted for: owned by a Debian
   package (whose copyright file dpkg installs under /usr/share/doc), installed by
   a Python distribution (listed in its dist-info RECORD, beside its license
   metadata), owned by a license entry, or named in ``exempt`` with the license
   file that covers it. A
   binary added to the image by some route that never touched the license table --
   a new `RUN curl ...`, a new install path -- fails here by name. The build-time
   check cannot see that, because it only reads the table.
"""

from __future__ import annotations

import csv
import glob
import hashlib
import json
import os
import re
import stat
import sys
import sysconfig

_ELF_MAGIC = b"\x7fELF"


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 256), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == _ELF_MAGIC
    except OSError:
        return False


def _dpkg_owned(dpkg_info_dir: str) -> set:
    """Every path a Debian package installed, from dpkg's own file lists."""
    owned = set()
    if not os.path.isdir(dpkg_info_dir):
        return owned
    for name in os.listdir(dpkg_info_dir):
        if not name.endswith(".list"):
            continue
        with open(os.path.join(dpkg_info_dir, name), encoding="utf-8") as handle:
            owned.update(line.rstrip("\n") for line in handle if line.strip())
    return owned


def _python_owned(site_dirs: list) -> set:
    """Real paths of every file a Python distribution's RECORD says it installed."""
    owned = set()
    for site_dir in site_dirs:
        for record in glob.glob(os.path.join(site_dir, "*.dist-info", "RECORD")):
            with open(record, encoding="utf-8", errors="replace", newline="") as handle:
                for row in csv.reader(handle):
                    if row:
                        owned.add(os.path.realpath(os.path.join(site_dir, row[0])))
    return owned


def _world_traversable(path: str) -> bool:
    mode = os.stat(path).st_mode
    return bool(mode & stat.S_IROTH and mode & stat.S_IXOTH)


def _aliases(path: str) -> set:
    """The spellings dpkg may have recorded ``path`` under on a merged-/usr system."""
    real = os.path.realpath(path)
    names = {path, real}
    for name in list(names):
        if name.startswith("/usr/"):
            names.add(name[len("/usr") :])
        else:
            names.add("/usr" + name)
    return names


def probe(spec: dict) -> dict:
    """Check the image (or, under test, a directory tree) against ``spec``."""
    problems = []
    doc_dir = spec["doc_dir"]
    search_dirs = spec.get("search_dirs") or os.environ.get("PATH", "").split(
        os.pathsep
    )

    index_path = os.path.join(doc_dir, "index.json")
    indexed = None
    try:
        with open(index_path, encoding="utf-8") as handle:
            indexed = {row["tool"] for row in json.load(handle)["tools"]}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        problems.append(f"{index_path} is missing or unreadable: {exc}")

    if os.path.isdir(doc_dir) and not _world_traversable(doc_dir):
        problems.append(f"{doc_dir} cannot be listed by every user")

    owners = {}
    for tool in spec["tools"]:
        name = tool["tool"]
        directory = os.path.join(doc_dir, name)
        if os.path.isdir(directory) and not _world_traversable(directory):
            problems.append(f"{name}: {directory} cannot be listed by every user")
        if indexed is not None and name not in indexed:
            problems.append(f"{name}: not listed in {index_path}")
        for license_file in tool["files"] + [{"name": "SOURCE", "sha256": None}]:
            path = os.path.join(directory, license_file["name"])
            if not os.path.isfile(path) or os.path.getsize(path) == 0:
                problems.append(f"{name}: {path} is missing or empty")
                continue
            if not os.access(path, os.R_OK) or not os.stat(path).st_mode & stat.S_IROTH:
                problems.append(f"{name}: {path} is not readable by every user")
                continue
            if license_file["sha256"] and _sha256(path) != license_file["sha256"]:
                problems.append(f"{name}: {path} does not match its pinned SHA256")
        source = os.path.join(directory, "SOURCE")
        if os.path.isfile(source):
            with open(source, encoding="utf-8") as handle:
                if tool["commit"] not in handle.read():
                    problems.append(f"{name}: {source} does not name {tool['commit']}")
        for executable in tool["executables"]:
            owners[executable] = name
        # Only the first is required: the others may come from elsewhere (uvx is
        # in uv's release archive on one install path and only in its PyPI wheel
        # on another).
        primary = tool["executables"][0]
        if not any(
            os.access(os.path.join(d, primary), os.X_OK) for d in search_dirs if d
        ):
            problems.append(f"{name}: {primary} is not on PATH")

    owned = _dpkg_owned(spec.get("dpkg_info_dir", "/var/lib/dpkg/info"))
    paths = sysconfig.get_paths()
    python_owned = _python_owned(
        spec.get("site_dirs") or sorted({paths["purelib"], paths["platlib"]})
    )
    exempt = spec.get("exempt", {})
    seen = set()
    accounted = []
    for directory in search_dirs:
        if not directory or not os.path.isdir(directory):
            continue
        for entry in sorted(os.listdir(directory)):
            path = os.path.join(directory, entry)
            real = os.path.realpath(path)
            if real in seen or not os.path.isfile(real) or not _is_elf(real):
                continue
            seen.add(real)
            if _aliases(path) & owned:
                continue
            if real in python_owned:
                accounted.append(f"{path}: installed by a Python distribution")
                continue
            base = os.path.basename(real)
            if entry in owners or base in owners:
                accounted.append(f"{path}: {owners.get(entry) or owners[base]}")
                continue
            covering = next(
                (
                    lic.format(name=base)
                    for pattern, lic in exempt.items()
                    if re.fullmatch(pattern, base)
                ),
                None,
            )
            if covering is None:
                problems.append(
                    f"{path} is an executable on PATH that no Debian package and no "
                    "THIRD_PARTY_LICENSES entry owns, so nothing ships its license. "
                    "Add an entry for it in utils/tool_downloads.py."
                )
            elif not os.path.isfile(covering):
                problems.append(f"{path} is exempt on {covering}, which is missing")
            else:
                accounted.append(f"{path}: exempt, covered by {covering}")

    return {"problems": problems, "accounted": accounted}


if __name__ == "__main__":
    json.dump(probe(json.load(sys.stdin)), sys.stdout)
