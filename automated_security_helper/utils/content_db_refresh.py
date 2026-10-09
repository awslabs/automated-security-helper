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
reach them. They run from a working directory outside the scanned tree
(``config.path_trust.cwd_outside_scanned_tree``, the same rule checkov's scans use),
with ``EMPTY_TOOL_CONFIG`` as an explicit config file (``-c`` for grype,
``--config`` for trivy) so neither tool looks for one in the working directory, the
home directory or anywhere else, and with the cache directory passed explicitly.
The environment is the operator's own (``snapshot_environ``), not anything a
scanner derived from the scanned tree. They scan nothing but an empty directory
ASH creates for the purpose.

Which cache
-----------
``default_cache_dir`` resolves each tool's cache the way the tool itself does on
the host, ``XDG_CACHE_HOME`` included. The sandbox does not pass
``XDG_CACHE_HOME``, so the scanners hand the resolved directory to the sandboxed
scan explicitly (``--cache-dir`` for trivy, ``GRYPE_DB_CACHE_DIR`` for grype), and
to the staleness check through ``content_database_probe_context``. The refresh,
the scan and the check then name one directory, whatever the tool would have
picked inside the sandbox, and a ``cache.dir`` or ``db.cache-dir`` in a config
file cannot move the scan elsewhere: a flag or variable beats a config file in
both tools (measured with grype 0.120.1 and trivy 0.75.0).

Concurrency and repetition
--------------------------
Serialized by ``utils/file_lock.exclusive_lock`` on a lock file in the cache
directory, or in the temporary directory named for the cache when the cache is not
writable: the scanners of one scan run in threads, and other ASH processes may
share the cache. The second caller to take the lock finds the database current,
and the tool returns at once. ``scan_id`` also skips every call after the first
that succeeded for the same tool, cache and scan. It is the scan's
``PluginContext.scan_id``, a random id, rather than anything derived from the
context object's address, which a long-running process such as the MCP server
can hand to a later scan's context once the first is freed.

Failure modes
-------------
A refresh that fails, or does not finish within ``UPDATE_TIMEOUT_SECONDS``, raises
``ScannerError`` naming what the tool printed; the scanner is then reported as
failed rather than run against a database that could not be brought up to date.
"""

from __future__ import annotations

import hashlib
import ntpath
import os
import posixpath
import shutil
import subprocess  # nosec B404 - TimeoutExpired only; spawns go through spawn_run
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple, Union

from automated_security_helper.config.path_trust import cwd_outside_scanned_tree
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

#: An empty file, shipped with ASH, passed as the config file of every grype and
#: trivy command ASH runs on a scan's behalf (the refresh here and the staleness
#: probes in utils/content_db_staleness.py), so the tool reads no config of its
#: own finding: not ``trivy.yaml``, ``.grype.yaml`` or ``.grype/config.yaml`` in
#: its working directory, nor one under the home directory. In ASH's package
#: because every sandbox backend mounts that read-only (``sandbox.policy
#: ._ash_paths``) and a probe runs inside the scanner's sandbox, where a file in a
#: temporary directory would not be visible and one in the results directory
#: would be writable by the scanner. An empty file rather than trivy's
#: ``--config ""``, which disables loading only from trivy 0.75.0
#: (pkg/commands/app.go initConfig; 0.74.0 and earlier fail on it).
EMPTY_TOOL_CONFIG = Path(__file__).resolve().with_name("empty-tool-config.yaml")

_prepared_lock = threading.Lock()
_prepared: Set[Tuple[str, str, bool, bool, str]] = set()


def default_cache_dir(
    tool: str,
    env: Optional[Mapping[str, str]] = None,
    platform: Optional[str] = None,
) -> Path:
    """The cache directory ``tool`` uses on this host, resolved as the tool does.

    The refresh writes it, the scan is pointed at it and the staleness check reads
    it, so all three name the directory the operator's own grype or trivy would use
    outside ASH (see "Which cache" above):

    - grype: ``GRYPE_DB_CACHE_DIR``, else ``xdg.CacheHome/grype/db``
      (grype/db/v6/installation/curator.go, grype 0.120.1). github.com/adrg/xdg
      v0.5.3 sets ``CacheHome`` to ``XDG_CACHE_HOME`` when that is an absolute
      path, else to ``~/Library/Caches`` on macOS (paths_darwin.go), ``~/.cache``
      on other Unix (paths_unix.go) and ``%LOCALAPPDATA%\\cache`` on Windows
      (paths_windows.go).
    - trivy: ``TRIVY_CACHE_DIR``, else ``os.UserCacheDir()/trivy``
      (pkg/cache/dir.go, trivy 0.75.0), and ``os.TempDir()/trivy`` when Go cannot
      name a user cache directory. Go's ``os.UserCacheDir`` is ``XDG_CACHE_HOME``
      (an error when relative) or ``~/.cache`` on Unix other than macOS,
      ``~/Library/Caches`` on macOS, whatever ``XDG_CACHE_HOME`` says, and
      ``%LocalAppData%`` on Windows.

    Args:
        tool: ``grype`` or ``trivy``.
        env: The environment the scan runs with; the process environment when
            None. Only the variables above are read from it; the home directory
            is this process's (``Path.home()``), which is also the ``HOME`` every
            sandbox backend gives the scanner.
        platform: A ``sys.platform`` value; this one when None.

    Returns:
        An absolute path. A relative ``*_CACHE_DIR`` is taken from ASH's working
        directory, once, so the refresh, the scan and the check, which run from
        different directories, still name one cache.
    """
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    windows = platform == "win32"
    isabs = ntpath.isabs if windows else posixpath.isabs

    def variable(name: str) -> str:
        if windows:  # Windows variable names are case-insensitive.
            for key, value in env.items():
                if key.upper() == name:
                    return value
            return ""
        return env.get(name, "")

    def absolute(raw: str) -> Path:
        return Path(os.path.abspath(Path(raw).expanduser()))

    xdg = variable("XDG_CACHE_HOME")
    local_app_data = variable("LOCALAPPDATA")
    if tool == "grype":
        raw = variable("GRYPE_DB_CACHE_DIR")
        if raw:
            return absolute(raw)
        if xdg and isabs(xdg):
            cache_home = Path(xdg)
        elif windows:
            cache_home = Path(local_app_data or Path.home() / "AppData" / "Local")
            cache_home = cache_home / "cache"
        elif platform == "darwin":
            cache_home = Path.home() / "Library" / "Caches"
        else:
            cache_home = Path.home() / ".cache"
        return cache_home / "grype" / "db"
    if tool == "trivy":
        raw = variable("TRIVY_CACHE_DIR")
        if raw:
            return absolute(raw)
        if windows:
            user_cache = Path(local_app_data) if local_app_data else None
        elif platform == "darwin":
            user_cache = Path.home() / "Library" / "Caches"
        elif not xdg:
            user_cache = Path.home() / ".cache"
        else:
            user_cache = Path(xdg) if isabs(xdg) else None
        if user_cache is None:
            # Go's os.TempDir: $TMPDIR on Unix, GetTempPath on Windows.
            temp = "" if windows else variable("TMPDIR")
            user_cache = Path(temp or tempfile.gettempdir())
        return user_cache / "trivy"
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
    source_dir: Union[str, Path],
    results_dir: Union[str, Path],
    config: Any = None,
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
        source_dir: The scan's source directory, and ``results_dir`` the
            scanner's results directory, and ``config`` the scan's AshConfig:
            what ``cwd_outside_scanned_tree`` needs to place the tools' working
            directory outside the scanned tree.
        checks: trivy only: also fetch the checks bundle a misconfiguration scan
            reads.
        java: trivy only: also update the Java database, for a mode that analyzes
            JAR, WAR and EAR files (``image``, ``rootfs``).
        scan_id: Refresh at most once per tool, cache and scan id
            (``scan_id_for``). None refreshes on every call (the tool itself
            returns at once when current).
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
            # Placed by the same rule as checkov's scans, inside this block so that
            # it is chosen for an unsandboxed spawn.
            cwd = cwd_outside_scanned_tree(
                workdir, results_dir=results_dir, source_dir=source_dir, config=config
            )
            for argv, env, what in _commands(
                tool, program, cache, workdir, checks, java
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
    workdir: Path,
    checks: bool,
    java: bool,
) -> List[Tuple[List[str], Dict[str, str], str]]:
    env = snapshot_environ()
    config = EMPTY_TOOL_CONFIG.as_posix()
    if tool == "grype":
        env["GRYPE_DB_CACHE_DIR"] = cache.as_posix()
        return [([program, "db", "update", "-c", config], env, "database")]
    common = ["--config", config, "--cache-dir", cache.as_posix()]
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


def in_scanner_sandbox() -> bool:
    """Whether a spawn made now runs in a scanner sandbox."""
    from automated_security_helper.utils.sandbox.scope import (
        SandboxScope,
        active_scope,
    )

    return isinstance(active_scope(), SandboxScope)


def sandboxed_online(offline: bool) -> bool:
    """Whether a spawn made now runs in a scanner sandbox, with a network to use."""
    return not offline and in_scanner_sandbox()


def scan_id_for(context: object) -> Optional[str]:
    """The id of the scan ``context`` belongs to (``PluginContext.scan_id``).

    None for a context that carries no id, which refreshes on every call rather
    than risk skipping one: a key built from anything else about the context
    object can be shared by two scans.
    """
    scan_id = getattr(context, "scan_id", None)
    return scan_id if isinstance(scan_id, str) and scan_id else None


def forget_prepared() -> None:
    """Forget which scans were prepared. For tests."""
    with _prepared_lock:
        _prepared.clear()
