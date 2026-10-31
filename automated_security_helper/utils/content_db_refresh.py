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
with an explicit config file (``-c`` for grype, ``--config`` for trivy) so neither
tool looks for one in the working directory, the home directory or anywhere else:
``EMPTY_TOOL_CONFIG`` (``utils/content_db_shared.py``, which the staleness probes
share), or the operator's own config file (trivy's ``trivy.yaml``, grype's
``.grype.yaml``) once the caller has checked it is the operator's and outside the
scanned tree (``config_file``), so a database mirror or CA it names applies to the
update too; ``prepare_content_db`` refuses a config file inside the scanned tree
itself, whatever a caller passes. The cache directory is passed explicitly. The
environment is the operator's own (``snapshot_environ``), not anything a scanner
derived from the scanned tree. They scan nothing but an empty directory ASH creates
for the purpose.

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

grype has a setting of the same kind, ``GRYPE_DB_AUTO_UPDATE`` (``db.auto-update`` in
its config), read as false by ``strconv.ParseBool`` to turn its own scan-time
download off. It is not an opt-out of ASH's update: ``grype db update`` runs beside
it, and the setting is commonly set across a CI image or a team's environment file
only to skip grype's check on each scan, so reading it as one left the cached
database to age past its bound and fail every scan after it. ASH updates grype's
database anyway and says so once per process (``grype_update_opt_outs`` reads the
setting for that notice). An operator who wants ASH off the registry scans offline.
The setting is read from the environment the refresh runs with, which is the
process's own: ASH hands sandboxed grype ``GRYPE_PREPARED_ENV`` (the same value)
through the child's environment only, never through ``os.environ``, so the refresh
does not read its own setting back.

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
import re
import shutil
import subprocess  # nosec B404 - TimeoutExpired only; spawns go through spawn_run
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

import yaml

from automated_security_helper.config.path_trust import (
    cwd_outside_scanned_tree,
    in_scanned_tree,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.utils.content_db_shared import EMPTY_TOOL_CONFIG
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

#: grype's own opt-out of its database update: ``GRYPE_DB_AUTO_UPDATE`` and its
#: config key ``db.auto-update``, read in that order as viper reads them. Set to
#: false, grype itself downloads nothing at scan time. Unlike trivy's, it does not
#: block ``grype db update``, so ASH only reports it (one notice per process) and
#: updates anyway.
GRYPE_UPDATE_OPT_OUT: Tuple[Tuple[str, ...], Tuple[str, str]] = (
    ("GRYPE_DB_AUTO_UPDATE",),
    ("db", "auto-update"),
)

#: The strings Go's ``strconv.ParseBool`` reads as true, which is how trivy reads a
#: boolean from the environment or a config string. Anything else, ``yes`` included,
#: is false.
_GO_TRUE = frozenset({"1", "t", "T", "TRUE", "true", "True"})

#: The strings Go's ``strconv.ParseBool`` reads as false. grype's auto-update is on
#: unless its setting reads as one of these; a string that is neither true nor false
#: is an error grype reports itself, and no opt-out.
_GO_FALSE = frozenset({"0", "f", "F", "FALSE", "false", "False"})

_prepared_lock = threading.Lock()
#: The scans prepared so far, oldest first (a dict keeps insertion order). Bounded
#: at ``_PREPARED_LIMIT`` entries: a long-running process (the MCP server) hands
#: every scan a new id, and an unbounded set grew with each one. A key dropped by
#: the bound costs one more refresh call for that scan, which the tool answers at
#: once when the database is current.
_prepared: Dict[Tuple[str, str, bool, bool, str, str], None] = {}
_PREPARED_LIMIT = 1024
#: The grype update settings already said once in this process (see
#: ``_say_grype_auto_update_once``), under ``_prepared_lock``.
_grype_notices: set = set()

#: The Go ``os.TempDir`` fallback on Unix when ``TMPDIR`` is unset.
_GO_UNIX_TEMP_DIR = "/tmp"  # nosec B108 - Go's own constant, read, never written


def _remember_prepared(key: Tuple[str, str, bool, bool, str, str]) -> None:
    """Record ``key`` as prepared, dropping the oldest keys past the bound."""
    with _prepared_lock:
        _prepared[key] = None
        while len(_prepared) > _PREPARED_LIMIT:
            del _prepared[next(iter(_prepared))]


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
      v0.5.3 sets ``CacheHome`` to ``XDG_CACHE_HOME`` when that, with a leading
      ``~`` expanded to the home directory (pathutil.ExpandHome), is an absolute
      path, else to ``~/Library/Caches`` on macOS (paths_darwin.go), ``~/.cache``
      on other Unix (paths_unix.go) and ``%LOCALAPPDATA%\\cache`` on Windows
      (paths_windows.go).
    - trivy: ``TRIVY_CACHE_DIR``, else ``os.UserCacheDir()/trivy``
      (pkg/cache/dir.go, trivy 0.75.0), and ``os.TempDir()/trivy`` when Go cannot
      name a user cache directory. Go's ``os.UserCacheDir`` is ``XDG_CACHE_HOME``
      (an error when relative, and no ``~`` expansion) or ``$HOME/.cache`` on Unix
      other than macOS, ``$HOME/Library/Caches`` on macOS, whatever
      ``XDG_CACHE_HOME`` says, and ``%LocalAppData%`` on Windows; an unset or
      empty ``HOME`` is an error there (Go reads the variable, not the passwd
      entry), so trivy then falls to the temporary directory. Go's ``os.TempDir``
      is ``TMPDIR`` else ``/tmp`` on Unix, and on Windows ``TMP``, then ``TEMP``,
      then ``USERPROFILE``, then the Windows directory (GetTempPath).

    Args:
        tool: ``grype`` or ``trivy``.
        env: The environment the scan runs with; the process environment when
            None. Only the variables above are read from it, ``HOME`` included
            where the tool reads it (trivy); grype's home is this process's
            (``Path.home()``), which is also the ``HOME`` every sandbox backend
            gives the scanner.
        platform: A ``sys.platform`` value; this one when None.

    Returns:
        An absolute path. A relative ``*_CACHE_DIR`` is taken from ASH's working
        directory, once, so the refresh, the scan and the check, which run from
        different directories, still name one cache.
    """
    # A locked copy, not the live mapping: another thread may be changing it
    # (utils/process_env.py).
    env = snapshot_environ() if env is None else env
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
        # adrg/xdg expands a leading ``~`` before it asks whether the path is
        # absolute, so ``XDG_CACHE_HOME=~/caches`` names a directory under the
        # home directory to grype, and here.
        xdg_expanded = os.path.expanduser(xdg) if xdg.startswith("~") else xdg
        if xdg_expanded and isabs(xdg_expanded):
            cache_home = Path(xdg_expanded)
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
        # The home directory is the scan's ``HOME`` when its environment sets
        # one, else this process's: every sandbox backend gives the scanner
        # the operator's home, and an environment built for the scan without
        # the variable (a caller that names only the variables it changes)
        # still means that home, not Go's temporary-directory fallback for a
        # HOME that is unset in the scanner's own process.
        home = Path(variable("HOME")) if variable("HOME") else Path.home()
        if windows:
            user_cache = Path(local_app_data) if local_app_data else None
        elif platform == "darwin":
            user_cache = home / "Library" / "Caches"
        elif not xdg:
            user_cache = home / ".cache"
        else:
            user_cache = Path(xdg) if isabs(xdg) else None
        if user_cache is None:
            user_cache = Path(_go_temp_dir(variable, windows))
        return user_cache / "trivy"
    raise ValueError(f"no content database refresh for {tool!r}")


def _go_temp_dir(variable: Any, windows: bool) -> str:
    """Go's ``os.TempDir`` over ``variable``: the directory trivy falls back to.

    Unix: ``TMPDIR``, else ``/tmp``. Windows: GetTempPath's order, ``TMP``, then
    ``TEMP``, then ``USERPROFILE``, then the Windows directory, which is read from
    Python's own search when none of the three is set. Python's
    ``tempfile.gettempdir`` is not used for the Unix side: its order (``TMPDIR``,
    ``TEMP``, ``TMP``, then a writability probe of ``/tmp``, ``/var/tmp`` and
    ``/usr/tmp``) names another directory than Go's when ``TMPDIR`` is unset and
    ``TEMP`` or ``TMP`` is, or ``/tmp`` is not writable.
    """
    if not windows:
        return variable("TMPDIR") or _GO_UNIX_TEMP_DIR
    for name in ("TMP", "TEMP", "USERPROFILE"):
        value = variable(name)
        if value:
            return value
    return tempfile.gettempdir()


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


def grype_update_opt_outs(
    env: Mapping[str, str], config_file: Optional[Union[str, Path]]
) -> Dict[str, str]:
    """Whether the operator's settings turn grype's OWN database update off, and how.

    Read for the one notice the refresh gives (``prepare_content_db`` updates
    either way). Keyed as ``trivy_update_opt_outs`` is (``database`` only; grype has one
    database), naming the setting. Read as viper reads it for grype:
    ``GRYPE_DB_AUTO_UPDATE`` when set to a non-empty value, else ``db.auto-update``
    in ``config_file``, the operator's grype config the update is given. The
    setting opts out when it reads as false (``_GO_FALSE``); grype's default is on.
    """
    names, key = GRYPE_UPDATE_OPT_OUT
    setting = _env_opt_out(env, names, opt_out=_GO_FALSE)
    if setting is None and not any(env.get(name) for name in names):
        config = _composed_yaml(Path(config_file)) if config_file is not None else None
        setting = _config_opt_out(config, key, config_file, opt_out=_GO_FALSE)
    return {"database": setting} if setting is not None else {}


def _env_opt_out(
    env: Mapping[str, str],
    names: Tuple[str, ...],
    opt_out: frozenset = _GO_TRUE,
) -> Optional[str]:
    for name in names:
        value = env.get(name)
        if value:
            return f"{name}={value}" if value in opt_out else None
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
    opt_out: frozenset = _GO_TRUE,
) -> Optional[str]:
    """``key`` (``db``, ``skip-update``) in the composed config, as the tool reads it.

    Dotted (``db.skip-update``) or nested, and case-insensitively, as both tools'
    config library (viper) matches keys. The dotted spelling is read first: viper
    searches a path's longest literal key prefix before it descends into nested
    maps (searchIndexableWithPathPrefixes), so a top-level ``db.skip-update`` key
    beats a nested ``db: skip-update:`` when a file holds both. The value is an
    opt-out when it reads as one of ``opt_out``: true for trivy's skip settings,
    false for grype's auto-update. A plain integer reads as true unless it is 0;
    a string reads as what ``strconv.ParseBool`` makes of it, quoted or not, and
    a string it rejects is neither, so it is no opt-out.
    """
    value = _mapping_get(root, ".".join(key))
    if value is None:
        value = _mapping_get(_mapping_get(root, key[0]), key[1])
    if not isinstance(value, yaml.ScalarNode):
        return None
    text = value.value
    if value.style is None and re.fullmatch(r"[-+]?[0-9]+", text):
        reads_as = "1" if int(text) != 0 else "0"
    else:
        reads_as = text
    return f"{'.'.join(key)}: {text} in {config_file}" if reads_as in opt_out else None


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

    In the cache directory when it, or the nearest directory above it that exists
    (the one it will be created under), is writable; otherwise in the temporary
    directory, named for the cache, so the callers on this host still take turns.

    The nearest existing ancestor rather than the parent alone: a first refresh of
    a cache whose parent does not exist yet either (``~/.cache/grype/db`` on a host
    with no ``~/.cache/grype``) would otherwise read the missing parent as not
    writable and take the temporary-directory lock, and a caller arriving once the
    refresh had created the cache would take the lock inside it, so the two ran at
    once.

    A lock file another account left in a shared cache (mode 0644) is no reason to
    leave the cache: ``exclusive_lock`` opens a lock file it may not write for
    reading alone and ``flock`` takes an exclusive lock on that descriptor
    (``utils/file_lock._open_lock_file``), so the second account's update waits on
    the first's. This function used to send such a caller to a per-account lock in
    the temporary directory, and the two accounts then ran ``trivy image
    --download-db-only`` or ``grype db update`` into the one cache at once. Only a
    cache that cannot be written at all takes the temporary-directory lock, and
    that name carries no account: a refresh from before this change and one from
    after it, or two accounts that share the temporary directory, still meet at one
    file, which ``exclusive_lock`` opens read-only when it is another's.
    """
    cache = Path(cache_dir)
    probe = cache
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    # The ancestor has to be a directory the cache can be created under:
    # ``exclusive_lock`` creates the lock's missing parents, which fails under a
    # regular file at the cache's path, so that case takes the temporary lock.
    if probe.is_dir() and os.access(probe, os.W_OK):
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
    config_file: Optional[Union[str, Path]] = None,
    values: Sequence[str] = (),
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
        config_file: The operator's config file to pass instead of an empty one
            (``--config`` for trivy, ``-c`` for grype), so a database mirror or
            CA it names applies to the update as it does to the scan. Only a
            file the caller has established is the operator's and outside the
            scanned tree (``TrivyScannerBase._operator_path``); never one the
            scanned repository could have written.
        values: The caller's env-read values: a failed update's stderr excerpt
            is redacted with them BEFORE it is cut, so the cut cannot split a
            value and leave a fragment the downstream whole-spelling
            redaction misses.

    An update the operator's trivy skip settings turn off is not run, with a
    warning. grype's ``GRYPE_DB_AUTO_UPDATE=false`` does not leave the update out:
    it is run and the setting is said once; see "The operator's opt-out" above.

    Raises:
        ScannerError: The tool is missing, failed, or timed out.
    """
    if tool not in TOOLS:
        raise ValueError(f"no content database refresh for {tool!r}")
    if offline:
        return
    cache = Path(os.path.abspath(Path(cache_dir).expanduser()))
    operator_config = (
        Path(os.path.abspath(config_file)) if config_file is not None else None
    )
    if operator_config is not None and in_scanned_tree(operator_config, source_dir):
        # Defense in depth behind the callers' own check: this update runs outside
        # the sandbox and writes the shared cache, so a config the scanned
        # repository could have written (a database mirror, a CA) never reaches
        # it, whatever a caller passes.
        raise ValueError(
            f"the {tool} config file given to the database refresh, "
            f"{operator_config.as_posix()}, is inside the scanned tree "
            f"{Path(source_dir).as_posix()}; the refresh takes only the operator's "
            "own config, outside the tree it scans"
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
    if tool == "grype":
        # trivy's skip settings make `--download-db-only` fail, so they have to be
        # honored. grype's setting only turns off grype's own update during a
        # scan, and `grype db update` runs fine beside it. Many CI images and team
        # environment files set it globally just to skip grype's check per scan,
        # and ASH refreshed anyway before it read the setting as an opt-out: a
        # database that nothing then refreshed passed its bound in about five days
        # and the default `fail` policy refused every scan after it. The update
        # runs; the setting is said once.
        setting = grype_update_opt_outs(env, operator_config).get("database")
        if setting is not None:
            _say_grype_auto_update_once(setting, cache)
        skipped: Dict[str, str] = {}
    else:
        opt_outs = trivy_update_opt_outs(env, operator_config)
        skipped = {
            what: setting for what, setting in opt_outs.items() if what in wanted
        }
    for what, setting in skipped.items():
        ASH_LOGGER.warning(
            f"ASH did not update {tool}'s {what} in {cache.as_posix()} before the "
            f"scan: the operator's {setting} turns {tool}'s own update off, and ASH "
            f"honors it. {tool} reads what is already in the cache; the scan-time "
            f"staleness check still holds {tool}'s vulnerability database to its bound."
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
                # Placed by the same rule as checkov's scans, inside this block so
                # that it is chosen for an unsandboxed spawn.
                cwd = cwd_outside_scanned_tree(
                    workdir,
                    results_dir=results_dir,
                    source_dir=source_dir,
                    config=config,
                )
                for argv, command_env, what in _commands(
                    tool,
                    program,
                    cache,
                    operator_config or EMPTY_TOOL_CONFIG,
                    workdir,
                    checks,
                    java,
                    env,
                ):
                    if what not in skipped:
                        _run(argv, command_env, cwd, f"{tool} {what}", values)
            finally:
                shutil.rmtree(workdir, ignore_errors=True)
    if scan_id is not None:
        _remember_prepared(key)


def _say_grype_auto_update_once(setting: str, cache: Path) -> None:
    """Say, once per process and setting, that grype's own update setting does
    not keep ASH's refresh off: the scan runs against a read-only cache, so ASH
    updates the database for it. An offline scan updates nothing."""
    with _prepared_lock:
        if setting in _grype_notices:
            return
        _grype_notices.add(setting)
    ASH_LOGGER.warning(
        f"The operator's {setting} turns grype's own database update off, which "
        "ASH does not read as a request to leave its own refresh out: ASH still "
        f"updates grype's database in {cache.as_posix()} before the scan, because "
        "the scanner cannot update it itself. To keep ASH off the database "
        "registry, run the scan offline."
    )


def _commands(
    tool: str,
    program: str,
    cache: Path,
    config_file: Path,
    workdir: Path,
    checks: bool,
    java: bool,
    env: Dict[str, str],
) -> List[Tuple[List[str], Dict[str, str], str]]:
    """The update commands, each with its environment and what it updates.

    ``config_file`` is ``EMPTY_TOOL_CONFIG``, or the operator's own file for either
    tool (``-c`` for grype, ``--config`` for trivy). ``what`` is a key of
    ``TRIVY_UPDATE_OPT_OUTS`` for trivy's commands and ``database``, the key of
    ``grype_update_opt_outs``, for grype's.
    """
    env = dict(env)
    config = config_file.as_posix()
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
        # The report of this scan of nothing goes to a file in the work directory,
        # removed with it, in the default format: pinned on the command line, where
        # it beats the operator's TRIVY_OUTPUT or TRIVY_FORMAT and the `output:` or
        # `format:` of the trivy.yaml this command runs with. Left to those, the
        # fetch wrote an empty report over the operator's own report file, or
        # failed on a format that needs a template.
        report = workdir / "checks-bundle-report"
        commands.append(
            (
                [
                    program,
                    "config",
                    *common,
                    "--format",
                    "table",
                    "--output",
                    report.as_posix(),
                    empty.as_posix(),
                ],
                env,
                "checks bundle",
            )
        )
    return commands


def _run(
    argv: List[str],
    env: Dict[str, str],
    cwd: Path,
    what: str,
    values: Sequence[str] = (),
) -> None:
    try:
        proc = spawn_run(  # nosec B603 - resolved tool binary, list arguments
            argv,
            capture_output=True,
            text=True,
            # Replacement, not the strict default: a byte the locale encoding
            # does not read in the tool's output raised UnicodeDecodeError out
            # of here, past the ScannerError every other failure becomes, even
            # when the tool had succeeded.
            errors="replace",
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
        from automated_security_helper.utils.error_text import shown_tool_stderr

        # The stderr when it holds anything beyond whitespace, else the stdout:
        # a stderr of a bare line break is no reason, and the reason is then on
        # stdout. REDACTED BEFORE the excerpt is cut: a cut can split a quoted
        # env-read value, and the downstream whole-spelling redaction cannot
        # match the fragment.
        printed = (proc.stderr or "").strip() or (proc.stdout or "").strip()
        detail = shown_tool_stderr(printed, values)
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
        _grype_notices.clear()


def prepared_count() -> int:
    """How many scans are remembered as prepared. For tests."""
    with _prepared_lock:
        return len(_prepared)
