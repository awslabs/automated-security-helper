# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Bring a scanner's content database up to date outside the scanner sandbox.

Why this exists
---------------
A scanner sandbox mounts the scanner's caches read-only, or under bwrap through an
overlay that throws writes away, so grype and trivy cannot update their
vulnerability databases from inside it. Measured: trivy fails online once its
database is past ``NextUpdate``, grype once its database is past its age bound,
and under bwrap a due update was downloaded on every run only to be discarded.
So before a sandboxed online scan ASH updates the database itself, unsandboxed,
and the scanner then runs with its own update turned off against the read-only
cache. ASH's scan-time staleness check (``utils/content_db_staleness.py``) still
holds the database it reads to the bound declared in
``utils/content_databases.py``.

What runs
---------
grype: ``grype db update``. trivy: ``trivy image --download-db-only``; with
``checks`` (a scan that includes misconfiguration checks) also ``trivy config`` of
an empty directory, which is how trivy fetches its checks bundle, as it has no
command that fetches only that; and with ``java`` also ``trivy image
--download-java-db-only``. Offline, nothing runs.

The Java database (about 935 MiB) is only for trivy modes that analyze JAR, WAR
and EAR files, which ``image`` and ``rootfs`` do. ``repository`` and ``fs`` do not:
measured with trivy 0.75, a repository holding a jar and a pom.xml reports the
pom.xml's vulnerabilities, ignores the jar, and never opens or downloads the Java
database. So a caller asks for it only for a mode that reads it.

Isolation
---------
These commands run outside the sandbox, so nothing from the scanned repository may
reach them. They run from a fresh empty directory outside every checkout, with an
explicit empty config file (``-c`` for grype, ``--config`` for trivy) so neither
tool looks for one in the working directory, the home directory or anywhere else,
and with the cache directory passed explicitly. The environment is the operator's
own (``snapshot_environ``), not anything a scanner derived from the scanned tree.
They scan nothing but that empty directory.

Concurrency and repetition
--------------------------
Serialized by ``utils/file_lock.exclusive_lock`` on a lock file in the cache
directory, or in the temporary directory named for the cache when the cache is not
writable: the scanners of one scan run in threads, and other ASH processes may
share the cache. The second caller to take the lock finds the database current,
and the tool returns at once. ``scan_id`` also skips every call after the first
that succeeded for the same tool, cache and scan.

Failure modes
-------------
A refresh that fails, or does not finish within ``UPDATE_TIMEOUT_SECONDS``, raises
``ScannerError`` naming what the tool printed; the scanner is then reported as
failed rather than run against a database that could not be brought up to date.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess  # nosec B404 - TimeoutExpired only; spawns go through spawn_run
import sys
import tempfile
import threading
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Set, Tuple, Union

from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.utils.file_lock import exclusive_lock
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.scope import outside_scanner_sandbox
from automated_security_helper.utils.subprocess_utils import find_executable, spawn_run

#: The tools this module knows how to refresh.
TOOLS = ("grype", "trivy")

#: How long one refresh command may take. A first download of either database is
#: a few hundred megabytes.
UPDATE_TIMEOUT_SECONDS = 900

#: Environment for grype inside the sandbox once its database has been prepared:
#: no update of its own (the cache is read-only), no update check for grype itself,
#: and no age validation, which ASH's staleness check does instead under the
#: operator's staleness policy, as it does offline.
GRYPE_PREPARED_ENV = {
    "GRYPE_DB_AUTO_UPDATE": "false",
    "GRYPE_DB_VALIDATE_AGE": "false",
    "GRYPE_CHECK_FOR_APP_UPDATE": "false",
}

_prepared_lock = threading.Lock()
_prepared: Set[Tuple[str, str, bool, bool, str]] = set()


def default_cache_dir(tool: str, env: Optional[Mapping[str, str]] = None) -> Path:
    """The cache directory ``tool`` uses inside a scanner sandbox.

    The sandbox passes ``GRYPE_*`` and ``TRIVY_*`` through but not ``XDG_CACHE_HOME``,
    so inside it each tool falls back to its default. The refresh has to write the
    directory the sandboxed scan then reads, so this resolves the same way. grype's
    default follows the XDG base directory spec as its library reads it on each
    platform, which on macOS puts the cache in ``~/Library/Caches``.
    """
    env = os.environ if env is None else env
    if tool == "grype":
        raw = env.get("GRYPE_DB_CACHE_DIR")
        if raw:
            return Path(raw).expanduser()
        if sys.platform == "darwin":
            return Path.home() / "Library" / "Caches" / "grype" / "db"
        return Path.home() / ".cache" / "grype" / "db"
    if tool == "trivy":
        raw = env.get("TRIVY_CACHE_DIR")
        return Path(raw).expanduser() if raw else Path.home() / ".cache" / "trivy"
    raise ValueError(f"no content database refresh for {tool!r}")


def update_lock_path(tool: str, cache_dir: Union[str, Path]) -> Path:
    """Where the refresh lock for ``cache_dir`` lives.

    In the cache directory when it, or the directory it will be created in, is
    writable; otherwise in the temporary directory, named for the cache, so the
    callers on this host still take turns.
    """
    cache = Path(cache_dir)
    probe = cache if cache.exists() else cache.parent
    if os.access(probe, os.W_OK):
        return cache / f".ash-{tool}-update.lock"
    digest = hashlib.sha256(os.fsencode(os.path.abspath(cache))).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / f"ash-{tool}-update-{digest}.lock"


def prepare_content_db(
    tool: str,
    cache_dir: Union[str, Path],
    offline: bool,
    *,
    checks: bool = False,
    java: bool = False,
    scan_id: Optional[str] = None,
    executable: Optional[str] = None,
) -> None:
    """Bring ``tool``'s database in ``cache_dir`` up to date, outside any sandbox.

    Args:
        tool: ``grype`` or ``trivy``.
        cache_dir: The cache the sandboxed scan reads (see ``default_cache_dir``).
        offline: When true nothing runs; the database is used as it is.
        checks: trivy only: also fetch the checks bundle a misconfiguration scan
            reads.
        java: trivy only: also update the Java database, for a mode that analyzes
            JAR, WAR and EAR files (``image``, ``rootfs``).
        scan_id: Refresh at most once per tool, cache and scan id. None refreshes
            on every call (the tool itself returns at once when current).
        executable: The tool to run; found on PATH when not given.

    Raises:
        ScannerError: The tool is missing, failed, or timed out.
    """
    if tool not in TOOLS:
        raise ValueError(f"no content database refresh for {tool!r}")
    if offline:
        return
    cache = Path(os.path.abspath(Path(cache_dir).expanduser()))
    key = (tool, cache.as_posix(), checks, java, scan_id or "")
    if scan_id is not None:
        with _prepared_lock:
            if key in _prepared:
                return
    program = executable or find_executable(tool)
    if not program:
        raise ScannerError(
            f"{tool} is not installed, so its database cannot be updated"
        )
    with exclusive_lock(update_lock_path(tool, cache)), outside_scanner_sandbox():
        workdir = Path(tempfile.mkdtemp(prefix=f"ash-{tool}-refresh-"))
        try:
            config = workdir / "empty-config.yaml"
            config.write_text("")
            cwd = workdir if not _inside_a_checkout(workdir) else Path(workdir.anchor)
            for argv, env, what in _commands(
                tool, program, cache, config, workdir, checks, java
            ):
                _run(argv, env, cwd, f"{tool} {what}")
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
    if scan_id is not None:
        with _prepared_lock:
            _prepared.add(key)


def _commands(
    tool: str,
    program: str,
    cache: Path,
    config: Path,
    workdir: Path,
    checks: bool,
    java: bool,
) -> List[Tuple[List[str], Dict[str, str], str]]:
    env = snapshot_environ()
    if tool == "grype":
        env["GRYPE_DB_CACHE_DIR"] = cache.as_posix()
        return [([program, "db", "update", "-c", config.as_posix()], env, "database")]
    common = ["--config", config.as_posix(), "--cache-dir", cache.as_posix()]
    commands = [
        (
            [program, "image", "--download-db-only", "--no-progress", *common],
            env,
            "database",
        )
    ]
    if java:
        commands.append(
            (
                [program, "image", "--download-java-db-only", "--no-progress", *common],
                env,
                "Java database",
            )
        )
    if checks:
        empty = workdir / "empty-target"
        empty.mkdir()
        commands.append(
            ([program, "config", *common, empty.as_posix()], env, "checks bundle")
        )
    return commands


def _inside_a_checkout(path: Path) -> bool:
    """Whether ``path`` or a directory above it holds a ``.git`` entry."""
    return any((p / ".git").exists() for p in [path, *path.parents])


def _run(argv: List[str], env: Dict[str, str], cwd: Path, what: str) -> None:
    try:
        proc = spawn_run(  # nosec B603 - resolved tool binary, list arguments
            argv,
            capture_output=True,
            text=True,
            env=env,
            cwd=cwd,
            timeout=UPDATE_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(
            f"could not update the {what} within {UPDATE_TIMEOUT_SECONDS}s"
        ) from exc
    except OSError as exc:
        raise ScannerError(f"could not update the {what}: {exc}") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        if len(detail) > 2000:
            detail = f"{detail[:1000]} ... {detail[-1000:]}"
        raise ScannerError(
            f"could not update the {what} (exit {proc.returncode}): {detail}"
        )


def sandboxed_online(offline: bool) -> bool:
    """Whether a spawn made now runs in a scanner sandbox, with a network to use."""
    from automated_security_helper.utils.sandbox.scope import (
        SandboxScope,
        active_scope,
    )

    return not offline and isinstance(active_scope(), SandboxScope)


def scan_id_for(context: object) -> str:
    """An id for the scan ``context`` belongs to: its output directory and the
    context object, so a second scan into the same directory refreshes again."""
    return f"{getattr(context, 'output_dir', '')}:{id(context)}"


def forget_prepared() -> None:
    """Forget which scans were prepared. For tests."""
    with _prepared_lock:
        _prepared.clear()
