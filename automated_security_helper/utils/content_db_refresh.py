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
explicit config file (``-c`` for grype, ``--config`` for trivy) so neither tool
looks for one in the working directory, the home directory or anywhere else: an
empty one, or for trivy the operator's ``trivy.yaml`` once the caller has checked it
is the operator's and outside the scanned tree (``config_file``), so a database
mirror it names applies to the update too. The cache directory is passed
explicitly. The environment is the operator's
own (``snapshot_environ``), not anything a scanner derived from the scanned tree.
They scan nothing but that empty directory.

The operator's opt-out
----------------------
trivy refuses ``--download-db-only`` when its own settings also say to skip the update
(``TRIVY_SKIP_DB_UPDATE``, or ``db.skip-update`` in its config): "--skip-db-update and
--download-db-only cannot be specified together", and likewise for the Java database.
An operator sets that to keep trivy off the database registry, typically in CI that
restores a cached database instead of downloading one per job. ASH's update replaced
trivy's own, so the setting applies to ASH's update too: that update is left out, with
a warning naming the setting, and the scan reads the database already in the cache.
The scan-time staleness check still holds that database to its bound, so a cache that
is not kept current fails the scan (or warns, under ``content_db_staleness: warn``).
Overriding the setting instead (``--skip-db-update=false``, which trivy accepts) would
download in exactly the runs the operator configured not to. ``trivy_update_opt_outs``
reads the setting the way trivy 0.75.0 does, measured case by case in
``tests/unit/utils/test_content_db_refresh.py``; a form it does not recognize leaves
the update in, and trivy's refusal then fails the scan with trivy's own message.

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
import re
import shutil
import subprocess  # nosec B404 - TimeoutExpired only; spawns go through spawn_run
import sys
import tempfile
import threading
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Set, Tuple, Union

import yaml

from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.utils.file_lock import exclusive_lock
from automated_security_helper.utils.log import ASH_LOGGER
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

#: trivy's own opt-out of each of its database updates: the environment variables it
#: reads the setting from, in the order it reads them, and its config file key. The
#: second variable for the vulnerability database is the deprecated ``--skip-update``'s.
#: Measured with trivy 0.75.0, as each of these makes it refuse the matching
#: ``--download-*-only``.
TRIVY_UPDATE_OPT_OUTS: Mapping[str, Tuple[Tuple[str, ...], Tuple[str, str]]] = {
    "database": (("TRIVY_SKIP_DB_UPDATE", "TRIVY_SKIP_UPDATE"), ("db", "skip-update")),
    "Java database": (("TRIVY_SKIP_JAVA_DB_UPDATE",), ("db", "java-skip-update")),
}

#: The strings Go's ``strconv.ParseBool`` reads as true, which is how trivy reads a
#: boolean from the environment or a config string. Anything else, ``yes`` included,
#: is false.
_GO_TRUE = frozenset({"1", "t", "T", "TRUE", "true", "True"})

_prepared_lock = threading.Lock()
_prepared: Set[Tuple[str, str, bool, bool, str, str]] = set()


def default_cache_dir(tool: str, env: Optional[Mapping[str, str]] = None) -> Path:
    """The cache directory ``tool`` uses inside a scanner sandbox.

    The refresh has to write the directory the sandboxed scan then reads, so this
    resolves it the way each tool does. The sandbox passes ``GRYPE_*`` and
    ``TRIVY_*`` through, and those win, but not ``XDG_CACHE_HOME``, so inside it
    each tool falls back to its platform default under ``$HOME``:

    - grype: ``xdg.CacheHome/grype/db`` (grype/db/v6/installation/curator.go), and
      github.com/adrg/xdg puts ``CacheHome`` at ``~/Library/Caches`` on macOS and
      ``~/.cache`` elsewhere on Unix.
    - trivy: ``os.UserCacheDir()/trivy`` (pkg/cache/dir.go), which is the same pair
      of directories.

    There is no sandbox on Windows, so the refresh never runs there.
    """
    env = os.environ if env is None else env
    user_cache = (
        Path.home() / "Library" / "Caches"
        if sys.platform == "darwin"
        else Path.home() / ".cache"
    )
    if tool == "grype":
        raw = env.get("GRYPE_DB_CACHE_DIR")
        return Path(raw).expanduser() if raw else user_cache / "grype" / "db"
    if tool == "trivy":
        raw = env.get("TRIVY_CACHE_DIR")
        return Path(raw).expanduser() if raw else user_cache / "trivy"
    raise ValueError(f"no content database refresh for {tool!r}")


def trivy_update_opt_outs(
    env: Mapping[str, str], config_file: Optional[Union[str, Path]]
) -> Dict[str, str]:
    """Which of trivy's database updates the operator's settings turn off, and how.

    Keyed as ``TRIVY_UPDATE_OPT_OUTS`` (``database``, ``Java database``), each value
    naming the setting (``TRIVY_SKIP_DB_UPDATE=true``, or the key and the file). Read
    as trivy 0.75.0 reads it: the first of the variables set to a non-empty value
    decides, true or not, and only when none is set does ``config_file``, the
    operator's trivy.yaml the update is given, count. ``env`` and ``config_file`` must
    be what the update itself runs with.
    """
    config = _composed_yaml(Path(config_file)) if config_file is not None else None
    found: Dict[str, str] = {}
    for what, (names, key) in TRIVY_UPDATE_OPT_OUTS.items():
        setting = _env_opt_out(env, names)
        if setting is None and not any(env.get(name) for name in names):
            setting = _config_opt_out(config, key, config_file)
        if setting is not None:
            found[what] = setting
    return found


def _env_opt_out(env: Mapping[str, str], names: Tuple[str, ...]) -> Optional[str]:
    for name in names:
        value = env.get(name)
        if value:
            return f"{name}={value}" if value in _GO_TRUE else None
    return None


def _composed_yaml(path: Path) -> Optional[yaml.Node]:
    """The file's YAML node tree, or None when it cannot be read as YAML.

    Composed rather than loaded, so a scalar keeps its text and whether it was
    quoted: PyYAML would load an unquoted ``yes`` as true, where trivy's YAML parser
    reads a string that ``strconv.ParseBool`` rejects. An unreadable file is no
    opt-out; trivy then fails on it with its own message.
    """
    try:
        return yaml.compose(path.read_text(encoding="utf-8"), Loader=yaml.SafeLoader)
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return None


def _config_opt_out(
    root: Optional[yaml.Node],
    key: Tuple[str, str],
    config_file: Optional[Union[str, Path]],
) -> Optional[str]:
    """``key`` (``db``, ``skip-update``) in the composed config, as trivy reads it.

    Nested or dotted (``db.skip-update``), and case-insensitively, as trivy's config
    library matches keys. True for a plain integer other than 0 and for a string
    ``strconv.ParseBool`` accepts, quoted or not.
    """
    value = _mapping_get(_mapping_get(root, key[0]), key[1])
    if value is None:
        value = _mapping_get(root, ".".join(key))
    if not isinstance(value, yaml.ScalarNode):
        return None
    text = value.value
    if value.style is None and re.fullmatch(r"[-+]?[0-9]+", text):
        enabled = int(text) != 0
    else:
        enabled = text in _GO_TRUE
    return f"{'.'.join(key)}: {text} in {config_file}" if enabled else None


def _mapping_get(node: Optional[yaml.Node], key: str) -> Optional[yaml.Node]:
    if not isinstance(node, yaml.MappingNode):
        return None
    found = None
    for key_node, value_node in node.value:
        if isinstance(key_node, yaml.ScalarNode) and key_node.value.lower() == key:
            found = value_node
    return found


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
    config_file: Optional[Union[str, Path]] = None,
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
        config_file: trivy only: the config file to pass instead of an empty one.
            Only a file the caller has established is the operator's and outside
            the scanned tree (``TrivyScannerBase._operator_path``); never one the
            scanned repository could have written.

    A trivy update the operator's settings turn off is not run, with a warning; see
    "The operator's opt-out" above.

    Raises:
        ScannerError: The tool is missing, failed, or timed out.
    """
    if tool not in TOOLS:
        raise ValueError(f"no content database refresh for {tool!r}")
    if config_file is not None and tool != "trivy":
        raise ValueError(f"no config file for the {tool} refresh")
    if offline:
        return
    cache = Path(os.path.abspath(Path(cache_dir).expanduser()))
    operator_config = (
        Path(os.path.abspath(config_file)) if config_file is not None else None
    )
    key = (
        tool,
        cache.as_posix(),
        checks,
        java,
        scan_id or "",
        operator_config.as_posix() if operator_config else "",
    )
    if scan_id is not None:
        with _prepared_lock:
            if key in _prepared:
                return
    env = snapshot_environ()
    wanted = ["database"]
    if tool == "trivy":
        wanted += [
            *(["Java database"] if java else []),
            *(["checks bundle"] if checks else []),
        ]
    skipped = {
        what: setting
        for what, setting in (
            trivy_update_opt_outs(env, operator_config) if tool == "trivy" else {}
        ).items()
        if what in wanted
    }
    for what, setting in skipped.items():
        ASH_LOGGER.warning(
            f"ASH did not update trivy's {what} in {cache.as_posix()} before the "
            f"scan: the operator's {setting} turns trivy's own update off, and ASH "
            "honors it. trivy reads what is already in the cache; the scan-time "
            "staleness check still holds trivy's vulnerability database to its bound."
        )
    if any(what not in skipped for what in wanted):
        program = executable or find_executable(tool)
        if not program:
            raise ScannerError(
                f"{tool} is not installed, so its database cannot be updated"
            )
        with exclusive_lock(update_lock_path(tool, cache)), outside_scanner_sandbox():
            workdir = Path(tempfile.mkdtemp(prefix=f"ash-{tool}-refresh-"))
            try:
                if operator_config is not None:
                    config = operator_config
                else:
                    config = workdir / "empty-config.yaml"
                    config.write_text("")
                cwd = (
                    workdir if not _inside_a_checkout(workdir) else Path(workdir.anchor)
                )
                for argv, command_env, what in _commands(
                    tool, program, cache, config, workdir, checks, java, env
                ):
                    if what not in skipped:
                        _run(argv, command_env, cwd, f"{tool} {what}")
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
    env: Dict[str, str],
) -> List[Tuple[List[str], Dict[str, str], str]]:
    """The update commands, each with its environment and what it updates.

    ``what`` is a key of ``TRIVY_UPDATE_OPT_OUTS`` for the commands that have one.
    """
    env = dict(env)
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
