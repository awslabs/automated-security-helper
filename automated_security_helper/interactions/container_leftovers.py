# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Containers a container-mode run left behind, and the sweep that removes them.

A container-mode run names its container and records that name, with the
creating process, under the user's ASH state directory before the runtime
starts. Nothing else can find the container afterwards: when the run is ended
by a second shutdown signal the runtime client is interrupted and the process
dies at once, and a container that does not stop on that interrupt keeps
running and keeps writing into the host-mounted output directories until the
runtime's own ``--rm`` reaps it.

The next container-mode start sweeps the records. A record whose creating
process is gone names a container that nobody owns, and it is removed with the
runtime's ``rm -f``. A record whose creating process is alive is another run's
and is never touched. So is a record from another host: the state directory can
be a shared home and the runtime a remote one, and this host cannot tell whether
that host's creating process is alive.

A SIGKILL also strands the private directories a run made for its env file and
for a docker config copy. :func:`sweep_env_dirs` deletes those too, by name
prefix under every place such a directory can be, when a record names a creator
that is gone or the directory is older than the age bound. It deletes and never
reads: what is in them is the operator's.

The sweep runs from the scan entry point (``run_ash_scan``), before the host
clears the previous run's declared outputs, not only before the runtime starts.
A surviving container could otherwise write a declared output after that clear
and before the read, and the run would vouch for the old container's bytes.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import stat
import sys
import tempfile
import time
from pathlib import Path
from subprocess import SubprocessError
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.error_text import text_without_values
from automated_security_helper.utils.log import ASH_LOGGER

#: Names the state directory outright; otherwise ``~/.ash/state/containers``.
STATE_DIR_ENV = "ASH_STATE_DIR"

#: The only kind of record there is today. A record with no kind is one, so a
#: later kind (a directory a run leaves behind) is additive.
_KIND_CONTAINER = "container"

#: What a container this module names looks like. A record is read back from a
#: file, so the name is held to this before it reaches a command line.
_NAME_PATTERN = re.compile(r"ash-scan-[0-9]+-[0-9a-f]{8}", re.ASCII)

#: How long one ``rm -f`` may take before the sweep leaves that record.
_REMOVE_TIMEOUT_SECONDS = 60

#: How old a record can be before it is forgotten, record only: no runtime is
#: asked about it and no container is touched. A record kept forever for a
#: runtime that never answers (another host's, one that was uninstalled, a boot
#: long gone) would be tried at every start. A week is far longer than any scan.
RECORD_MAX_AGE_SECONDS = 7 * 24 * 3600

#: The name a record is written under before its rename into place. A run killed
#: between the create and the rename strands one; a write takes milliseconds, so
#: one older than this bound belongs to no live writer and the next start removes
#: it. Nothing is read from it.
_TEMPORARY_RECORD_PREFIX = ".record-"
_TEMPORARY_RECORD_MAX_AGE_SECONDS = 3600


def _docker_current_context() -> Optional[str]:
    """The context ``docker`` selects from its config file, or None.

    Without DOCKER_HOST or DOCKER_CONTEXT the client reads ``currentContext``
    from ``config.json`` under ``DOCKER_CONFIG`` (``~/.docker`` by default), so a
    run under another context talks to another daemon with no variable changed.
    Best effort: a file that cannot be read or parsed is None, as an unset
    variable is.
    """
    directory = os.environ.get("DOCKER_CONFIG") or os.path.join(
        os.path.expanduser("~"), ".docker"
    )
    try:
        with open(os.path.join(directory, "config.json"), encoding="utf-8") as stream:
            document = json.load(stream)
    except (OSError, ValueError):
        return None
    context = document.get("currentContext") if isinstance(document, dict) else None
    return context if isinstance(context, str) and context else None


def _podman_default_connection() -> Optional[str]:
    """The connection ``podman`` selects when no variable names one, or None.

    ``podman system connection default NAME`` writes it to
    ``podman-connections.json`` under the containers config directory (older
    podman: ``active_service`` in ``containers.conf``), so a run after the switch
    talks to another machine's daemon with no variable changed, as a docker
    context switch does. Best effort: a file that cannot be read or parsed is
    None, as an unset variable is.
    """
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    directory = os.path.join(base, "containers")
    try:
        with open(
            os.path.join(directory, "podman-connections.json"), encoding="utf-8"
        ) as stream:
            document = json.load(stream)
    except (OSError, ValueError):
        document = None
    connection = document.get("Connection") if isinstance(document, dict) else None
    default = connection.get("Default") if isinstance(connection, dict) else None
    if isinstance(default, str) and default:
        return default
    try:
        with open(
            os.path.join(directory, "containers.conf"), encoding="utf-8"
        ) as stream:
            text = stream.read()
    except (OSError, ValueError):
        return None
    found = re.search(r'^\s*active_service\s*=\s*"([^"\n]+)"', text, re.MULTILINE)
    return found.group(1) if found else None


def _daemon_environment() -> Dict[str, Optional[str]]:
    """The environment a container runtime client picks its daemon from.

    A record keeps what these were when the container was started, so a later
    start talks to the same daemon or leaves the record alone. An unset variable
    is None. Beside docker's host and context variables: the docker config
    directory and the context its file selects, podman's connection and the
    default connection its config selects, and containerd's address and
    namespace (nerdctl), each of which selects a daemon on its own; a sweep that
    recorded only the first three asked the wrong daemon under a changed one of
    these, heard "no such container" and dropped the record of a live container.
    """
    return {
        "DOCKER_HOST": os.environ.get("DOCKER_HOST"),
        "DOCKER_CONTEXT": os.environ.get("DOCKER_CONTEXT"),
        "DOCKER_CONFIG": os.environ.get("DOCKER_CONFIG"),
        "docker_config_current_context": _docker_current_context(),
        "CONTAINER_HOST": os.environ.get("CONTAINER_HOST"),
        "CONTAINER_CONNECTION": os.environ.get("CONTAINER_CONNECTION"),
        "podman_default_connection": _podman_default_connection(),
        "CONTAINERD_ADDRESS": os.environ.get("CONTAINERD_ADDRESS"),
        "CONTAINERD_NAMESPACE": os.environ.get("CONTAINERD_NAMESPACE"),
    }


#: Runtime wording for a container that is already gone. Docker, nerdctl and
#: finch say the first, podman the second.
_ALREADY_GONE = ("no such container", "no container with name")

#: What ``_removed`` answers when the runtime said it has no such container. It
#: is truthy, so a caller that only asks "is it gone" reads it as True; one that
#: must tell a container it removed from one it never had reads the difference.
_ABSENT = "absent"

#: The kind of a record for a private directory a run made and a SIGKILL stranded.
_KIND_ENV_DIR = "env-dir"

#: The names of those directories, by prefix: the env-file directory (empty once
#: its file is unlinked, holding the env file for a runtime that reads it by path)
#: and the docker config copy (a 0600 config.json and symlinks into the real
#: config directory). The first is made here, by the env-file writer. No code
#: path in this tree creates the second today; it is swept anyway because the
#: component that writes a proxy-stripped docker config copy under
#: ``ash-container-docker-*`` lists this sweep as its cleanup, so one sweep
#: covers both kinds of directory.
_ENV_DIR_PREFIXES = ("ash-container-env-", "ash-container-docker-")

#: Where such a directory can be, after the temporary directory the environment
#: names (``TMPDIR``, ``TEMP`` and ``TMP``, the three ``tempfile`` honors, in its
#: order) and the one ``tempfile`` itself settles on. Each prefix is looked for
#: under every one.
_ENV_DIR_PARENTS = ("/dev/shm", "/var/tmp", "/tmp")  # nosec B108 - a search list

#: The variables ``tempfile.gettempdir`` reads, in the order it reads them.
_TEMP_DIR_VARIABLES = ("TMPDIR", "TEMP", "TMP")

#: A private directory's own name: a prefix and the random suffix ``mkdtemp`` adds.
_ENV_DIR_NAME = re.compile(
    "(?:" + "|".join(re.escape(p) for p in _ENV_DIR_PREFIXES) + r")[A-Za-z0-9_]{1,32}",
    re.ASCII,
)

_ENV_DIR_RECORD_PREFIX = "ash-envdir-"


def _now() -> float:
    return time.time()


#: Whether this process has said that the named state directory is relative.
_RELATIVE_STATE_DIR_WARNED = False


def state_dir() -> Optional[Path]:
    """The directory the records live in, or None when there is none.

    There is none where the platform has no directory descriptors (Windows) and
    where there is no home. Both callers return at once on None, before any
    directory is made or any log line written.

    A named directory has ``~`` expanded, as a shell expands it. A relative one is
    kept as given, which keys the records to the working directory of each run,
    usually the repository being scanned, so a run started elsewhere never finds
    them: that is said once, at warning, so the operator can name an absolute
    directory.
    """
    global _RELATIVE_STATE_DIR_WARNED
    if sys.platform == "win32":
        return None
    named = os.environ.get(STATE_DIR_ENV, "").strip()
    if named:
        expanded = os.path.expanduser(named)
        if not os.path.isabs(expanded) and not _RELATIVE_STATE_DIR_WARNED:
            _RELATIVE_STATE_DIR_WARNED = True
            ASH_LOGGER.warning(
                f"{STATE_DIR_ENV} names a relative directory, which is resolved "
                "against the working directory of each run, so the records of "
                "containers left behind are found only by runs started from the "
                "same directory. Name an absolute directory."
            )
        return Path(expanded)
    try:
        return Path.home() / ".ash" / "state" / "containers"
    except RuntimeError:
        return None


_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
_PID_NAMESPACE_LINK = "/proc/self/ns/pid"
_PROC_SELF_LINK = "/proc/self"


def _linux_scope() -> Optional[str]:
    """The boot id and PID namespace of this process, or None without a boot id.

    The boot id changes at every boot, so a record from before a reboot names a
    process that is gone. The PID namespace (the link ``/proc/self/ns/pid``, whose
    inode names it; namespaces(7)) decides which pid space a creator pid belongs
    to: two containers on one kernel each count their own pids. A namespace that
    cannot be read gives no key at all, so nothing is swept on a guess: a key every
    process with an unreadable namespace shared would match another namespace's
    records.
    """
    try:
        boot_id = _BOOT_ID_PATH.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError):
        return None
    boot_id = boot_id.strip()
    if not boot_id:
        return None
    try:
        namespace = os.readlink(_PID_NAMESPACE_LINK)
        # /proc may be another PID namespace's mount: then its pids and start
        # times, which _process_start and _creator_alive read through it, are
        # not this namespace's, and /proc/self is not this process. No key
        # then, as for an unreadable namespace: a key shared by every process
        # whose namespace could not be read looked a live creator's pid up in
        # another namespace and judged it gone. Nothing is swept on a guess.
        if os.readlink(_PROC_SELF_LINK) != str(os.getpid()):
            return None
    except (OSError, ValueError):
        return None
    return f"linux:{boot_id}:{namespace}"


def _macos_scope() -> Optional[str]:
    """The boot session id macOS keeps in ``kern.bootsessionuuid``, or None.

    The sysctl is a read-only string in the kernel's ``kern`` node (xnu,
    ``bsd/kern/kern_sysctl.c``: ``SYSCTL_STRING(_kern, OID_AUTO, bootsessionuuid,
    CTLFLAG_RD | CTLFLAG_LOCKED, &bootsessionuuid_string, ...)``). It is read with
    ``sysctlbyname`` through ctypes, so no process is started.
    """
    try:
        import ctypes
        import ctypes.util

        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.dylib")
        size = ctypes.c_size_t(0)
        name = b"kern.bootsessionuuid"
        if libc.sysctlbyname(name, None, ctypes.byref(size), None, 0) != 0:
            return None
        buffer = ctypes.create_string_buffer(size.value)
        if libc.sysctlbyname(name, buffer, ctypes.byref(size), None, 0) != 0:
            return None
        session = buffer.value.decode("ascii").strip()
    except Exception:
        return None
    return f"darwin:{session}" if session else None


def host_key() -> Optional[str]:
    """What tells this host's records from another host's, or None when it cannot.

    A pid and its start time mean something only inside the boot and the PID
    namespace that have them: Linux names both, macOS names the boot session.
    Where the identity cannot be read (Windows, another platform, an unreadable
    boot id) there is no key, and a record written then carries none. A record
    with no key matches no host, and a host with no key matches no record, so
    nothing is swept on a guess: the key never falls back to a value every record
    shares, such as the host name.
    """
    if sys.platform.startswith("linux"):
        return _linux_scope()
    if sys.platform == "darwin":
        return _macos_scope()
    return None


#: Called once the state directory is open and checked, before any record is
#: read or written through it. A test sets it to swap the path for a symlink
#: at exactly the moment a path-based check would have gone stale.
_AFTER_STATE_DIR_OPENED: Optional[Callable[[], None]] = None


def _open_state_dir(directory: Path) -> Optional[int]:
    """Open ``directory`` for records and return its descriptor, or None.

    Every later read, write and removal goes through this descriptor, so what
    was checked is what is used: a path swapped for a symlink after the check
    changes nothing. A symlink is never followed (``O_NOFOLLOW``): the records
    name containers to remove, so whoever can repoint the directory would choose
    what the sweep reads. A directory that is ours and laxer than 0700 is
    tightened; one that is someone else's is not used. The caller closes the
    descriptor. Where the platform has no directory descriptors there are no
    records and no sweep.
    """
    if sys.platform == "win32":
        return None
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        status = os.fstat(fd)
        if not stat.S_ISDIR(status.st_mode):
            raise OSError("not a directory")
        if status.st_uid != os.geteuid():
            ASH_LOGGER.debug(f"Not using {directory}: it belongs to another user")
            raise OSError("not ours")
        if status.st_mode & 0o077:
            os.fchmod(fd, 0o700)
    except OSError:
        os.close(fd)
        return None
    if _AFTER_STATE_DIR_OPENED is not None:
        _AFTER_STATE_DIR_OPENED()
    return fd


def new_container_name() -> str:
    """A name for this run's container: the creating pid and a random suffix."""
    return f"ash-scan-{os.getpid()}-{secrets.token_hex(4)}"


def _process_start(pid: int) -> Optional[str]:
    """The start time ``/proc`` reports for ``pid``, or None where it has none.

    It tells a creator from a later process that was given the same pid.
    """
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="replace")
    except OSError:
        return None
    # The command name is in parentheses and may hold spaces; the start time is
    # the twentieth field after it.
    fields = text.rpartition(")")[2].split()
    return fields[19] if len(fields) > 19 else None


def _creator_alive(pid: int, start: Optional[str]) -> bool:
    if pid == os.getpid():
        # This process, unless the record's start time is another's: a record
        # left by a process that held this pid before it names a creator that
        # is gone, however the pid reads now.
        now = _process_start(pid)
        return start is None or now is None or start == now
    try:
        # Signal 0 delivers nothing: it only asks whether the pid exists.
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    except (OSError, OverflowError, ValueError):
        return False
    now = _process_start(pid)
    if start is not None and now is not None and start != now:
        return False
    return True


def record_container(
    name: str, runner_command: Optional[Sequence[str]] = None
) -> Optional[Path]:
    """Write the record for ``name`` under this process, before its runtime starts.

    ``runner_command`` is the runtime as the run starts it, wrapper prefix first
    and the resolved runtime last. The record keeps it, and the environment the
    runtime picks its daemon from, so a later start removes the container only
    through the same runtime and daemon. A record written without it (an older
    one) can be tried but never dropped on the runtime's word.

    Returns the record's path, or None when it could not be written. A run is
    not refused for that: the container then has no sweep owner, which is the
    state every run was in before records existed.
    """
    directory = state_dir()
    if directory is None:
        return None
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as e:
        # Its own reason: a read-only or missing home is not a directory that
        # belongs to someone else, which is what the warning below says.
        ASH_LOGGER.debug(
            f"Not recording container {name}: could not create {directory}: {e}"
        )
        return None
    fd = _open_state_dir(directory)
    if fd is None:
        ASH_LOGGER.warning(
            f"Could not record container {name} for cleanup: {directory} is not a "
            "directory of this user's, or is a symlink."
        )
        return None
    record: Dict[str, Any] = {
        "kind": _KIND_CONTAINER,
        "host": host_key(),
        "name": name,
        "creator_pid": os.getpid(),
        "creator_start": _process_start(os.getpid()),
        "created": _now(),
    }
    if runner_command:
        record["runtime"] = str(runner_command[-1])
        record["runner_argv"] = [str(part) for part in runner_command[:-1]]
        record["daemon_env"] = _daemon_environment()
    path = directory / f"{name}.json"
    temporary = f".record-{secrets.token_hex(8)}"
    try:
        handle = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=fd,
        )
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(record, stream)
            os.rename(temporary, path.name, src_dir_fd=fd, dst_dir_fd=fd)
        except BaseException:
            _unlink_in(fd, temporary)
            raise
    except OSError as e:
        ASH_LOGGER.warning(
            f"Could not record container {name} for cleanup after an interrupted run: {e}"
        )
        return None
    finally:
        os.close(fd)
    return path


def _unlink_in(fd: int, name: str) -> bool:
    """Remove ``name`` from the open directory. Whether it is gone afterwards.

    A file that is already gone counts. Any other refusal (a read-only mount,
    permissions) is False and is not raised: every caller is a best-effort
    clean-up that must not end a run.
    """
    try:
        os.unlink(name, dir_fd=fd)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return True


def discard_record(path: Optional[Path]) -> None:
    """Drop a record whose container is known to be gone."""
    if path is None:
        return
    fd = _open_state_dir(path.parent)
    if fd is None:
        return
    try:
        _unlink_in(fd, path.name)
    except OSError:
        pass
    finally:
        os.close(fd)


def _read_record(fd: int, file_name: str) -> Optional[Dict[str, Any]]:
    """Read the record in ``file_name`` from the open state directory."""
    try:
        handle = os.open(file_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        with os.fdopen(handle, encoding="utf-8") as stream:
            record = json.load(stream)
    except (OSError, ValueError):
        return None
    if not isinstance(record, dict):
        return None
    if record.get("kind", _KIND_CONTAINER) != _KIND_CONTAINER:
        return None
    name, pid = record.get("name"), record.get("creator_pid")
    if not isinstance(name, str) or not _NAME_PATTERN.fullmatch(name):
        return None
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return None
    return record


def _removed(runner_command: Sequence[str], name: str) -> Union[bool, str]:
    """Whether ``rm -f name`` left the container gone.

    True when the runtime removed it, ``_ABSENT`` when the runtime said it has no
    such container (also gone, to a caller that asks only that), False otherwise.

    The runtime inherits the terminal, so a wrapper such as ``sudo`` can prompt.
    That is bounded: the prompt is reachable only when a sweepable record exists,
    and ``_REMOVE_TIMEOUT_SECONDS`` ends it, leaving the record for the next start.
    """
    try:
        result = subprocess_utils.run_command(
            [*runner_command, "rm", "-f", name],
            capture_output=True,
            check=False,
            log_level=logging.DEBUG,
            timeout=_REMOVE_TIMEOUT_SECONDS,
        )
    except (OSError, SubprocessError) as e:
        ASH_LOGGER.warning(f"Could not remove the leftover container {name}: {e}")
        return False
    # The wording before the exit code: docker's ``rm -f`` of a container it never
    # had prints "No such container" and exits 0, so an exit 0 alone is not a
    # removal, and a caller that keeps an unknown runtime's record on anything
    # but a removal would otherwise drop it on this runtime's word.
    said = f"{result.stdout}\n{result.stderr}".lower()
    if any(phrase in said for phrase in _ALREADY_GONE):
        return _ABSENT
    if result.returncode == 0 and subprocess_utils.run_succeeded(result):
        return True
    ASH_LOGGER.warning(
        f"The leftover container {name} was not removed (exit {result.returncode}); "
        "it stays recorded for the next start."
    )
    return False


def leftover_records() -> List[Tuple[str, str]]:
    """The records that name a container to remove: ``(file name, container name)``.

    Those of this host whose creating process is gone. Reading them starts no
    process, so a caller can find out whether there is anything to sweep before it
    looks for a runtime.
    """
    directory = state_dir()
    if directory is None:
        return []
    fd = _open_state_dir(directory)
    if fd is None:
        return []
    try:
        return _records_in(fd)
    finally:
        os.close(fd)


def _forget_if_aged(
    fd: int, file_name: str, record: Optional[Dict[str, Any]] = None
) -> bool:
    """Drop a record file older than the age bound. Whether it was dropped.

    Record only: no runtime is asked and no container is touched, whatever host
    or runtime the record names. A file that is no record of this module's, or
    one it cannot read, is aged by its file alone, so a file nothing can act on is
    not re-read at every start forever.
    """
    age = _record_age(fd, file_name, record if record is not None else {})
    if age > RECORD_MAX_AGE_SECONDS and _unlink_in(fd, file_name):
        ASH_LOGGER.debug(f"Forgot {file_name}: it is older than the age bound")
        return True
    return False


def _forget_stranded_temporaries(fd: int, names: Sequence[str]) -> None:
    """Remove the temporary record files a killed run left between create and
    rename: those older than their bound, by file age, never read."""
    for name in names:
        if not name.startswith(_TEMPORARY_RECORD_PREFIX):
            continue
        try:
            status = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except OSError:
            continue
        if _now() - status.st_mtime > _TEMPORARY_RECORD_MAX_AGE_SECONDS:
            if _unlink_in(fd, name):
                ASH_LOGGER.debug(f"Removed the stranded temporary record {name}")


def _records_in(fd: int) -> List[Tuple[str, str]]:
    found: List[Tuple[str, str]] = []
    here = host_key()
    try:
        names = os.listdir(fd)
    except OSError:
        return []
    _forget_stranded_temporaries(fd, names)
    files = sorted(
        f for f in names if f.startswith("ash-scan-") and f.endswith(".json")
    )
    for file_name in files:
        record = _read_record(fd, file_name)
        if record is None:
            _forget_if_aged(fd, file_name)
            continue
        if _forget_if_aged(fd, file_name, record):
            continue
        if here is None or record.get("host") != here:
            # Another host's creator cannot be looked up from here, and its
            # container may be live: neither removed nor forgotten. A host that
            # cannot name itself (or a record that could not) matches nothing.
            ASH_LOGGER.debug(f"Leaving {file_name}: it is another host's record")
            continue
        if _creator_alive(record["creator_pid"], record.get("creator_start")):
            continue
        found.append((file_name, record["name"]))
    return found


def _record_age(fd: int, file_name: str, record: Dict[str, Any]) -> float:
    """Seconds since the record was taken; its file's age when it says nothing."""
    created = record.get("created")
    if isinstance(created, (int, float)) and not isinstance(created, bool):
        return max(0.0, _now() - float(created))
    try:
        return max(0.0, _now() - os.stat(file_name, dir_fd=fd).st_mtime)
    except OSError:
        return 0.0


def _has_runtime_fields(record: Dict[str, Any]) -> bool:
    argv = record.get("runner_argv")
    env = record.get("daemon_env")
    return (
        isinstance(record.get("runtime"), str)
        and isinstance(argv, list)
        and all(isinstance(part, str) for part in argv)
        and isinstance(env, dict)
    )


def _differs_from_this_run(
    record: Dict[str, Any], runner_command: Sequence[str]
) -> Optional[str]:
    """The name of the first thing the record was started under that this run
    differs in: ``runtime``, ``runner_argv`` or an environment variable's name.

    Only the name is returned. What the values are is never part of an answer:
    they may be a daemon address with credentials in it.
    """
    if record["runtime"] != str(runner_command[-1]):
        return "runtime"
    if record["runner_argv"] != [str(part) for part in runner_command[:-1]]:
        return "runner_argv"
    recorded = record["daemon_env"]
    for key, now in _daemon_environment().items():
        if recorded.get(key) != now:
            return key
    return None


def _left_alone(file_name: str, key: str, record: Dict[str, Any]) -> None:
    """Say, at debug, which setting a record was taken under that this run lacks.

    The line names the key and nothing else, and goes through the redaction layer
    with every value of those variables, recorded and current, in case a value is
    ever the text the line shows.
    """
    values = [now or "" for now in _daemon_environment().values()]
    recorded = record.get("daemon_env")
    if isinstance(recorded, dict):
        values += [v for v in recorded.values() if isinstance(v, str)]
    ASH_LOGGER.debug(
        text_without_values(
            f"Leaving {file_name}: it was recorded under a different {key}.",
            [v for v in values if v],
        )
    )


def _remove_in(
    fd: int, runner_command: Sequence[str], records: Sequence[Tuple[str, str]]
) -> List[str]:
    removed: List[str] = []
    for file_name, name in records:
        record = _read_record(fd, file_name)
        if record is None:
            continue
        known = _has_runtime_fields(record)
        if known:
            different = _differs_from_this_run(record, runner_command)
            if different is not None:
                # Another runtime or daemon's container, which this runtime
                # cannot see: not removed, and the record is not dropped on the
                # word of a runtime that was never asked the right question.
                _left_alone(file_name, different, record)
                continue
        outcome = _removed(runner_command, name)
        if not outcome:
            continue
        if outcome is not True:
            if not known:
                # A record with no runtime fields may be another runtime's: "no
                # such container" from this one proves nothing. Only the age bound
                # forgets it.
                ASH_LOGGER.debug(f"Keeping {file_name}: its runtime is unknown")
                continue
            # Its own runtime never had it: reaped by --rm, or stopped on its own.
            # The record is dropped, and nothing was removed to report.
            if _unlink_in(fd, file_name):
                ASH_LOGGER.debug(
                    f"Dropped {file_name}: the runtime has no such container"
                )
            else:
                ASH_LOGGER.warning(
                    f"The runtime has no container {name} but its record "
                    f"{file_name} could not be dropped."
                )
            continue
        if not _unlink_in(fd, file_name):
            ASH_LOGGER.warning(
                f"Removed the leftover container {name} but could not drop "
                f"its record {file_name}."
            )
        removed.append(name)
    return removed


def remove_leftovers(
    runner_command: Sequence[str], records: Sequence[Tuple[str, str]]
) -> List[str]:
    """Remove the containers ``records`` name, and drop the record of each one gone.

    The directory is opened again here, so a state directory swapped for a symlink
    since the records were read is refused and nothing is removed.

    Args:
        runner_command: The runtime as the run resolves it, wrapper prefix
            included, without a subcommand.
        records: ``(file name, container name)`` pairs from :func:`leftover_records`.

    Returns:
        The names removed. One the runtime refused to remove keeps its record.
    """
    directory = state_dir()
    if directory is None or not records:
        return []
    fd = _open_state_dir(directory)
    if fd is None:
        return []
    try:
        return _remove_in(fd, runner_command, records)
    finally:
        os.close(fd)


def sweep_leftover_containers(runner_command: Sequence[str]) -> List[str]:
    """Remove the recorded containers whose creating process is gone.

    Reads and removes through one open of the state directory. Returns the names
    removed. A record whose creator is alive is left alone, and so is one the
    runtime refused to remove.
    """
    directory = state_dir()
    if directory is None:
        return []
    fd = _open_state_dir(directory)
    if fd is None:
        return []
    try:
        return _remove_in(fd, runner_command, _records_in(fd))
    finally:
        os.close(fd)


def _env_dir_parents() -> List[str]:
    """The places a private directory can be, each spelled as tempfile spells it.

    ``tempfile.mkdtemp`` names the directory it makes under the normalized
    temporary directory (``os.path.normcase(os.path.abspath(...))``: a trailing
    separator dropped, the case folded where the platform does), and that name is
    what the record keeps. The parents are spelled the same way here, so a record
    is matched byte for byte against them: with a ``TMPDIR`` ending in a
    separator, the macOS default, no env-dir record matched any parent, a
    stranded directory stayed for up to a week and its record was never dropped.

    ``mkdtemp`` puts the directory where ``tempfile.gettempdir`` points: the first
    of ``TMPDIR``, ``TEMP`` and ``TMP`` that names a usable directory, else a
    platform default, else the working directory. All three variables are
    searched, and so is what ``gettempdir`` answers now, so a directory made under
    ``TEMP`` or ``TMP`` is found: one searched only under ``TMPDIR`` and the fixed
    places outlived every sweep, and its record was never dropped.
    """
    named = [os.environ.get(variable) or "" for variable in _TEMP_DIR_VARIABLES]
    try:
        named.append(tempfile.gettempdir())
    except OSError:
        pass
    parents: List[str] = []
    for parent in (*named, *_ENV_DIR_PARENTS):
        if not parent or not os.path.isabs(parent):
            continue
        parent = os.path.normcase(os.path.abspath(parent))
        if parent not in parents:
            parents.append(parent)
    return parents


def record_env_dir(directory: Path) -> Optional[Path]:
    """Record a private directory this process just made, so a later start can name
    its creator if a SIGKILL strands it.

    Best effort, like :func:`record_container`: a record that cannot be written
    leaves the directory to the age bound alone.
    """
    state = state_dir()
    if state is None:
        return None
    try:
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        return None
    fd = _open_state_dir(state)
    if fd is None:
        return None
    record = {
        "kind": _KIND_ENV_DIR,
        "host": host_key(),
        "dir": str(directory),
        "creator_pid": os.getpid(),
        "creator_start": _process_start(os.getpid()),
        "created": _now(),
    }
    file_name = f"{_ENV_DIR_RECORD_PREFIX}{directory.name}.json"
    temporary = f".record-{secrets.token_hex(8)}"
    try:
        handle = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=fd,
        )
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(record, stream)
            os.rename(temporary, file_name, src_dir_fd=fd, dst_dir_fd=fd)
        except BaseException:
            _unlink_in(fd, temporary)
            raise
    except OSError:
        return None
    finally:
        os.close(fd)
    return state / file_name


def _env_dir_records(fd: int) -> Dict[Tuple[str, str], Tuple[str, Dict[str, Any]]]:
    """The env-dir records, by ``(parent, name)`` of the directory each names.

    A record names a directory, and nothing in it is trusted further than that:
    the name must be one of the prefixes' own shape and the parent one of the
    places searched, or the record is ignored. The directory itself is then found
    by listing the parent, never by following the path in the record.

    A record that is ignored is still subject to the age bound, by its own
    ``created`` or its file's age: one that cannot be read, one of another shape,
    or one whose parent is no longer searched (a ``TMPDIR`` that changed between
    runs) was otherwise kept and re-read at every start forever.
    """
    parents = set(_env_dir_parents())
    found: Dict[Tuple[str, str], Tuple[str, Dict[str, Any]]] = {}
    try:
        names = os.listdir(fd)
    except OSError:
        return found
    _forget_stranded_temporaries(fd, names)
    files = sorted(
        f for f in names if f.startswith(_ENV_DIR_RECORD_PREFIX) and f.endswith(".json")
    )
    for file_name in files:
        try:
            handle = os.open(file_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            with os.fdopen(handle, encoding="utf-8") as stream:
                record = json.load(stream)
        except (OSError, ValueError):
            _forget_if_aged(fd, file_name)
            continue
        if not isinstance(record, dict) or record.get("kind") != _KIND_ENV_DIR:
            _forget_if_aged(fd, file_name)
            continue
        target = record.get("dir")
        pid = record.get("creator_pid")
        # A bool is an int to isinstance; _read_record refuses one the same way,
        # and a True here would make pid 1 the liveness probe.
        if (
            not isinstance(target, str)
            or not isinstance(pid, int)
            or isinstance(pid, bool)
            or pid <= 0
        ):
            _forget_if_aged(fd, file_name, record)
            continue
        parent, name = os.path.split(target)
        if parent in parents and _ENV_DIR_NAME.fullmatch(name):
            found[(parent, name)] = (file_name, record)
        else:
            _forget_if_aged(fd, file_name, record)
    return found


def _remove_tree(dir_fd: int, depth: int = 0) -> None:
    """Delete everything under an open directory without reading any of it.

    Names are listed to be unlinked and nothing is opened as a file: a symlink is
    unlinked, never followed, so a docker config copy's links into the real config
    directory go and what they point at stays.
    """
    if depth > 8:
        raise OSError("private directory nested too deep")
    for entry in os.listdir(dir_fd):
        status = os.stat(entry, dir_fd=dir_fd, follow_symlinks=False)
        if stat.S_ISDIR(status.st_mode):
            child = os.open(
                entry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd
            )
            try:
                _remove_tree(child, depth + 1)
            finally:
                os.close(child)
            os.rmdir(entry, dir_fd=dir_fd)
        else:
            os.unlink(entry, dir_fd=dir_fd)


def _env_dir_sweepable(
    status: os.stat_result,
    entry: Optional[Tuple[str, Dict[str, Any]]],
    here: Optional[str],
) -> bool:
    """Whether a private directory, found by prefix, is one to delete.

    Recorded by this host: its creator decides. Gone: yes. Alive and confirmed
    by its start time: no, whatever the directory's age; a run older than the
    bound that is still alive owns its directory, and deleting it under that run
    on its age alone broke the run. Alive by pid alone, with no start time to
    confirm it (the record was written without one, or this host has no ``/proc``
    or a hidden one): the age bound decides, since a later process given the same
    pid reads as the creator there, and a directory holding the operator's values
    must not stay until the next boot on that reading. Not recorded by this host:
    older than the age bound, yes; anything else is left, since an unrecorded
    directory younger than the bound may be a live run's, made before its record
    or by a writer with none.
    """
    aged = _now() - status.st_mtime > RECORD_MAX_AGE_SECONDS
    record = entry[1] if entry is not None else None
    if record is not None and here is not None and record.get("host") == here:
        pid, start = record["creator_pid"], record.get("creator_start")
        if not _creator_alive(pid, start):
            return True
        if start is None or _process_start(pid) is None:
            return aged
        return False
    return aged


def sweep_env_dirs() -> List[str]:
    """Delete the private directories a run stranded, and drop their records.

    A SIGKILL runs no clean-up, so the env-file directory and the docker config
    copy a run made stay behind, mode 0700 and this user's. Each prefix is looked
    for under every place such a directory can be. A directory is deleted when it
    is this user's, mode 0700, and either older than the age bound or recorded by a
    creator that is gone. Its contents are never read or logged: they are the
    operator's values. Best effort: any failure is one warning and the run goes on.

    Returns the directory names deleted.
    """
    try:
        return _sweep_env_dirs()
    except Exception as e:
        ASH_LOGGER.warning(f"Could not sweep private directories: {e}")
        return []


def _sweep_env_dirs() -> List[str]:
    if sys.platform == "win32":
        # No directory descriptors, so no records and no sweep (state_dir says
        # the same): the listing below opens with O_DIRECTORY, which Windows
        # has no name for, and that read as a failed sweep at every start.
        return []
    state = state_dir()
    state_fd = _open_state_dir(state) if state is not None else None
    removed: List[str] = []
    try:
        records = _env_dir_records(state_fd) if state_fd is not None else {}
        here = host_key()
        found: set[Tuple[str, str]] = set()
        # The parents that could not be listed: a symlink (O_NOFOLLOW refuses it;
        # macOS's /tmp, a TMPDIR naming a link), a directory gone or unreadable.
        # A record under one says nothing about whether its directory is gone,
        # so it is kept; dropping it as "the directory is gone" left a stranded
        # directory with no record and no sweep.
        unlisted: set[str] = set()
        for parent in _env_dir_parents():
            # Listed through the parent's real path: TMPDIR naming a link, or the
            # macOS /tmp -> /private/tmp link, is where tempfile made the
            # directory, and O_NOFOLLOW on the spelled path refused to list it,
            # so a directory stranded there was never swept. The real path's
            # last component is no link, so O_NOFOLLOW still refuses a path
            # swapped for a link between the resolution and the open; the
            # record is matched by the spelled parent, as it was recorded.
            try:
                parent_fd = os.open(
                    os.path.realpath(parent),
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                )
            except OSError:
                unlisted.add(parent)
                continue
            try:
                for name in sorted(os.listdir(parent_fd)):
                    if _ENV_DIR_NAME.fullmatch(name):
                        found.add((parent, name))
                        if _sweep_one_env_dir(
                            parent_fd, name, records.get((parent, name)), here, state_fd
                        ):
                            removed.append(name)
            finally:
                os.close(parent_fd)
        if state_fd is not None:
            for key, (file_name, record) in records.items():
                if key in found or key[0] in unlisted:
                    continue
                # The directory is gone: the record has nothing left to name.
                aged = _record_age(state_fd, file_name, record) > RECORD_MAX_AGE_SECONDS
                creator_gone = (
                    here is not None
                    and record.get("host") == here
                    and not _creator_alive(
                        record["creator_pid"], record.get("creator_start")
                    )
                )
                if aged or creator_gone:
                    _unlink_in(state_fd, file_name)
    finally:
        if state_fd is not None:
            os.close(state_fd)
    if removed:
        ASH_LOGGER.info(
            f"Removed {len(removed)} private director(ies) left by an earlier run: "
            f"{', '.join(removed)}"
        )
    return removed


def _sweep_one_env_dir(
    parent_fd: int,
    name: str,
    entry: Optional[Tuple[str, Dict[str, Any]]],
    here: Optional[str],
    state_fd: Optional[int],
) -> bool:
    try:
        dir_fd = os.open(
            name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd
        )
    except OSError:
        return False
    try:
        status = os.fstat(dir_fd)
        if status.st_uid != os.geteuid() or stat.S_IMODE(status.st_mode) != 0o700:
            ASH_LOGGER.debug(f"Leaving {name}: not a private directory of this user")
            return False
        if not _env_dir_sweepable(status, entry, here):
            return False
        try:
            _remove_tree(dir_fd)
            os.rmdir(name, dir_fd=parent_fd)
        except OSError as e:
            ASH_LOGGER.warning(
                f"Could not delete the private directory {name}: "
                f"{e.strerror or type(e).__name__}"
            )
            return False
    finally:
        os.close(dir_fd)
    if entry is not None and state_fd is not None:
        _unlink_in(state_fd, entry[0])
    return True
