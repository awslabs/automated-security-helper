"""What a sandboxed scanner may touch, independent of how a backend enforces it.

A :class:`SandboxPolicy` is built once per scanner and target by
:func:`build_scanner_policy` and handed to a backend in ``backends.py``, which turns it
into a command line. Keeping the policy backend-neutral is what lets the escape tests
assert one set of expectations against every backend.

See docs/content/docs/scanner-sandbox.md for the threat model this serves.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from automated_security_helper.utils.inner_run_outcome import OUTER_RUN_ID_ENV


class SandboxUnavailable(OSError):
    """A sandbox was requested and cannot be provided for this scanner.

    The message is the reason, written for the operator: it ends up in the scanner's
    MISSING entry. An OSError because that is what a process that could not be
    started raises, so a caller that already handles a failed spawn handles this.
    """


@dataclass(frozen=True)
class SandboxRequirements:
    """What one scanner needs beyond the baseline policy.

    Declared as a class attribute on a scanner plugin (``sandbox_requirements``). The
    default is the strictest: no network, no extra paths, no extra environment.

    Attributes:
        network: The scanner needs a network when the scan is online (to download a
            database, a rule pack, or registry data). Never granted under --offline.
        read_paths: Extra host paths, ``~`` and ``$VAR`` expanded, mounted read-only.
            Missing paths are skipped.
        cache_paths: Host paths the tool keeps caches, settings or a content
            database in. Writable through a throwaway overlay where the backend has
            one (bwrap), so writes never reach the host; read-only everywhere else,
            because a write in place would change what later runs, sandboxed or
            not, read from the cache.
        cache_env: Variables that move a tool's writable cache (``npm_config_cache``).
            Where ``cache_paths`` are read-only, each variable named here points at
            a private, empty directory for the spawn, so a tool that has to write
            its cache still can. A cache that is only read, such as a scanner's
            database prepared before the scan, is not listed.
        env_prefixes: Environment variable name prefixes passed through in addition to
            the baseline allowlist (``GRYPE_``, ``SEMGREP_``, ...). Credential-shaped
            names under an allowed prefix are still dropped; see ``env_names``.
        env_names: Exact variable names passed through even though they look like
            credentials, because the scanner needs them (``SNYK_TOKEN``).
        network_requires_grant: The network need follows settings the scanned
            repository can write (detect-secrets' baseline enables verification),
            so the scanner's own declaration does not grant it. It gets a network
            only when ``sandbox.network_scanners``, which only a trusted source
            can set, names it.
        system_trust_roots: The tool reads the system's root certificates itself
            rather than through the OS's TLS stack: semgrep-core uses OCaml's
            ca-certs, which on macOS runs ``security find-certificate`` against the
            system keychains. The sandbox-exec profile keeps the keychain daemon
            out of reach, so for such a tool ASH exports the same certificates to
            a read-only file before the spawn and sets ``SSL_CERT_FILE`` to it,
            which ca-certs reads instead. Other backends leave the tool alone.
        sandbox_exec_env: ``(name, value)`` pairs set in the scanner's environment
            under sandbox-exec only, after the allowlist. That backend has no
            throwaway overlay, so a cache it could write would be written in place
            and read by every later run. For a tool that would otherwise reach for
            a shared cache that backend keeps out of reach: cdk-nag turns jsii's
            package cache (``~/Library/Caches/com.amazonaws.jsii``) off.
        unpack_dir_env: The tool unpacks itself and runs what it unpacked, at a
            location this environment variable decides (opengrep's macOS binary,
            built with Nuitka's onefile mode, unpacks to
            ``$XDG_CACHE_HOME/opengrep/<version>`` and runs ``opengrep.bin`` from
            there). Under sandbox-exec, which runs programs only from tool paths,
            the variable points at a directory created for the spawn, writable and
            executable for it alone and removed afterwards, so nothing it unpacks
            reaches another run. Other backends give the tool a private home
            directory and do not restrict exec, and leave the variable alone.
        read_paths_require_grant: ``read_paths`` and ``cache_paths`` follow the
            scanner's options, which the scanned repository can write (a rules
            file or baseline path, for example). ``read_paths`` are mounted only
            when ``sandbox.read_path_scanners`` names the scanner, and then only
            inside the source tree or an ``extra_read_paths`` entry;
            ``cache_paths`` are never mounted.
        env_requires_grant: ``env_prefixes`` and ``env_names`` follow the
            scanner's options (a token for an online check, for example). They are
            passed only when ``sandbox.env_scanners`` names the scanner.
        read_path_env: Variables in ASH's own environment that name a directory
            the tool reads, mounted read-only and, under sandbox-exec, not
            executable: semgrep's offline rule cache,
            ``SEMGREP_RULES_CACHE_DIR``. Read from ASH's process environment when
            the policy is built, never from the scanner's options, which the
            scanned repository can write, so no grant is needed. An unset or empty
            variable, a relative path, anything but a directory, and a directory
            as broad as a filesystem root, ``$HOME`` or a directory holding
            ``$HOME`` grant nothing. A directory directly under ``$HOME`` (``~/rules``)
            is mounted as named: the operator chose it.
        staged_input_only: The tool is handed a staged copy of its input outside the
            scanned tree, and reads nothing else of the scan: nbconvert converts one
            notebook ASH copied to a private directory. The source and output
            directories are left out of its read paths and named in the policy's
            ``unread``, so it reads its scan target, its working directory and its
            tools, and writes its results directory.
    """

    network: bool = False
    read_paths: Tuple[str, ...] = ()
    cache_paths: Tuple[str, ...] = ()
    cache_env: Tuple[str, ...] = ()
    env_prefixes: Tuple[str, ...] = ()
    env_names: Tuple[str, ...] = ()
    network_requires_grant: bool = False
    system_trust_roots: bool = False
    sandbox_exec_env: Tuple[Tuple[str, str], ...] = ()
    unpack_dir_env: Optional[str] = None
    read_paths_require_grant: bool = False
    env_requires_grant: bool = False
    read_path_env: Tuple[str, ...] = ()
    staged_input_only: bool = False


#: The variables a TLS client reads its trusted roots from: the files (a bundle),
#: and the directory (a hashed directory, or several joined with the path separator).
#: Each is passed through by the environment list below, and a backend that hides
#: the home directory grants reading what the operator's value names.
CA_BUNDLE_FILE_ENV_NAMES = (
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
)
CA_BUNDLE_DIR_ENV_NAMES = ("SSL_CERT_DIR",)
CA_BUNDLE_ENV_NAMES = CA_BUNDLE_FILE_ENV_NAMES + CA_BUNDLE_DIR_ENV_NAMES

#: Names every sandboxed scanner gets whatever the environment list says.
_FIXED_ENV_NAMES = frozenset(
    {
        "PATH",
        "LANG",
        "LANGUAGE",
        "TERM",
        "TZ",
        "NO_COLOR",
        "FORCE_COLOR",
        "COLUMNS",
        "VIRTUAL_ENV",
        "JAVA_HOME",
        "GEM_HOME",
        "GEM_PATH",
        "SYSTEMROOT",
    }
)
#: The baseline environment allowlist as the reference documents it: the fixed
#: names and the CA-bundle names the default environment list holds. Exact names,
#: then prefixes. Anything else in the parent environment -- AWS_*, GITHUB_TOKEN,
#: *_PASSWORD -- is dropped. Only the fixed names are always passed; the CA-bundle
#: names follow ``SandboxPolicy.environment``.
BASE_ENV_NAMES = _FIXED_ENV_NAMES | frozenset(CA_BUNDLE_ENV_NAMES)
BASE_ENV_PREFIXES = ("LC_", "ASH_", "UV_", "PYTHON")
#: Dropped whatever a scanner declares. The run ID a container or nix scan's outer
#: process gives its inner run is for the inner run's results file only; see
#: utils/inner_run_outcome.py.
DROPPED_ENV_NAMES = frozenset({OUTER_RUN_ID_ENV})
#: Inside an allowed prefix these still mark a credential (UV_PUBLISH_TOKEN,
#: UV_INDEX_X_PASSWORD, npm_config__authToken), so the variable is dropped unless
#: the scanner names it in ``env_names``.
CREDENTIAL_MARKERS = (
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "CREDENTIAL",
    "AUTH",
    "APIKEY",
    "API_KEY",
    "PRIVATE_KEY",
    "SESSION",
)
#: A URL value that carries a user name and password before its host is a
#: credential whatever the variable is called.
_URL_USERINFO = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/@\s]*@")

#: Proxy settings only matter, and are only passed, when the scanner has a network.
#: ALL_PROXY too: curl, Go's net/http and Python's urllib read it where no
#: scheme-specific variable is set, so a host configured that way alone would
#: otherwise lose its proxy inside the sandbox.
PROXY_ENV_NAMES = frozenset(
    {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    }
)

#: The environment list a sandbox starts from, written the way a docker-compose
#: ``environment`` list is: the proxy family and the CA-bundle set, by name, each
#: passed with the value the caller has. These are the variables an operator's host
#: sets for the whole system, not a channel for a tool's own settings. A policy
#: built with another list passes that list instead of these (``SandboxPolicy.environment``).
DEFAULT_ENVIRONMENT: Tuple[str, ...] = (
    *sorted(PROXY_ENV_NAMES),
    *CA_BUNDLE_ENV_NAMES,
)

#: A variable name, matched whole: a pattern anchored with ``$`` alone would admit
#: one trailing newline.
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _environment_entries(entries: Iterable[str]) -> Tuple[str, ...]:
    """*entries* as a tuple, once it is known to be a list of entries.

    A bare string is an iterable of one-letter names, and a mapping is an iterable
    of its keys with the values gone, so both would be read as a list that says
    something else than what was written. They are refused with the shape named.

    Raises:
        ValueError: *entries* is a string, bytes or a mapping.
    """
    if isinstance(entries, (str, bytes, Mapping)):
        kind = type(entries).__name__
        raise ValueError(
            f"the environment must be a list of entries, not a {kind}: "
            "write [NAME, NAME=value]"
        )
    return tuple(entries)


def parse_environment(
    entries: Iterable[str],
) -> Tuple[Tuple[str, ...], Dict[str, str]]:
    """The names an environment list passes, and the values it sets.

    Each entry is a variable name, which passes the caller's value, or
    ``NAME=value``, which sets the value (and passes it whether or not the caller
    has the variable), as in a docker-compose ``environment`` list. A name that
    appears twice takes its last entry. Returns the names in the order first
    listed and a map of the entries that carry a value.

    A name that marks a credential (``CREDENTIAL_MARKERS``) and a name the sandbox
    always drops (``DROPPED_ENV_NAMES``) are refused even when listed, so the
    list cannot open the channel that a scanner's own ``env_names`` grant is for.
    ``TMPDIR`` is refused too: the Landlock and sandbox-exec backends replace it with
    a private directory after this list is applied, and the bwrap and firejail
    backends do not, so a listed value would reach the scanner under two of the
    four.
    The error names the variable and never shows a value, which may be a secret:
    an entry with no ``=`` that is not a variable name is named by its position,
    because the whole entry may be a value written without its name.

    Raises:
        ValueError: The list is a string or a mapping, or an entry is not text,
            names no variable, names a credential, a dropped variable or
            ``TMPDIR``, or carries a NUL in its value.
    """
    names: Dict[str, None] = {}
    values: Dict[str, str] = {}
    for position, entry in enumerate(_environment_entries(entries), start=1):
        if not isinstance(entry, str):
            raise ValueError(
                f"an environment entry must be text, not {type(entry).__name__}"
            )
        name, has_value, value = entry.partition("=")
        if not _ENV_NAME.fullmatch(name):
            shown = f"{name!r}" if has_value else f"number {position}"
            raise ValueError(
                f"environment entry {shown} is not a variable name: write NAME to "
                "pass the caller's value or NAME=value to set one"
            )
        if name in DROPPED_ENV_NAMES:
            raise ValueError(
                f"environment entry {name!r} is refused: the sandbox never passes it"
            )
        if name == "TMPDIR":
            raise ValueError(
                f"environment entry {name!r} is refused: every scanner gets a "
                "private TMPDIR of the sandbox's own, which a listed value cannot "
                "replace"
            )
        marker = next((m for m in CREDENTIAL_MARKERS if m in name.upper()), None)
        if marker is not None:
            raise ValueError(
                f"environment entry {name!r} is refused: a name containing {marker} "
                "marks a credential, which a listed name does not pass. A scanner "
                "that needs one is granted it with sandbox.env_scanners and its own "
                "env_names"
            )
        if "\x00" in value:
            raise ValueError(f"environment entry {name!r} has a NUL in its value")
        names.setdefault(name)
        if has_value:
            values[name] = value
        else:
            values.pop(name, None)
    return tuple(names), values


#: Host directories every sandbox mounts read-only when they exist. These are the
#: system's own files; nothing user-specific lives here on a normal installation.
SYSTEM_READ_PATHS = (
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/etc",
    "/opt",
    "/nix",
    "/snap",
    # macOS
    "/System",
    "/Library",
    "/Applications/Xcode.app",
    "/private/etc",
    "/private/var/db/timezone",
    "/opt/homebrew",
    "/usr/local",
)


#: System read paths that hold configuration and data, not programs, so they are
#: readable and never executable.
_DATA_SYSTEM_PATHS = (
    Path("/etc"),
    Path("/private/etc"),
    Path("/private/var/db/timezone"),
)


@dataclass(frozen=True)
class SandboxPolicy:
    """A resolved policy for one scanner invocation. All paths are absolute.

    ``read_only`` and ``writable`` keep the caller's spelling of each path (which may
    run through a symlink, such as a home directory that links elsewhere); backends
    that need real paths resolve them, and recreate the symlinks, themselves.

    ``executable`` and ``scan_data`` are for a backend that can restrict which files
    a process may execute (sandbox-exec). ``executable`` is ``read_only`` without the
    scan's own data, so the system and tool paths. Programs run from there, and from
    the spawn's private uv cache, which the backend adds because ``uv tool run``
    keeps the environments of tools it was not asked to install there. ``scan_data`` is the scan's data
    (the source tree, the output directory, every other root of the active scan,
    the scan target, the working directory, the directories ``read_path_env``
    names, the directory of config files ASH wrote for the tool, and the
    directories ASH's own code granted the spawn for reading through
    ``scope.reads_directory``), which stays non-executable under sandbox-exec even
    where a tool path contains it, so a repository checked out under ``/opt``
    cannot have its own binaries run. The other backends do not restrict exec.
    """

    scanner_name: str
    read_only: Tuple[Path, ...]
    writable: Tuple[Path, ...]
    cache: Tuple[Path, ...]
    network: bool
    home: Path
    cwd: Optional[Path]
    env_prefixes: Tuple[str, ...] = ()
    env_names: Tuple[str, ...] = ()
    extra_env: Dict[str, str] = field(default_factory=dict)
    #: Variables a backend points at a private writable directory when it mounts
    #: ``cache`` read-only, which is everywhere but bwrap's throwaway overlay.
    cache_env: Tuple[str, ...] = ()
    executable: Tuple[Path, ...] = ()
    scan_data: Tuple[Path, ...] = ()
    system_trust_roots: bool = False
    sandbox_exec_env: Dict[str, str] = field(default_factory=dict)
    unpack_dir_env: Optional[str] = None
    #: uv's tools-directory lock file, which ``uv tool run`` opens read-write before
    #: it looks for an installed tool. The file, not the directory: writing the
    #: lock changes nothing a later run reads.
    uv_tool_locks: Tuple[Path, ...] = ()
    #: Directories the tool may not read even where a path the policy shows holds
    #: them: the source and output directories, and every other root of the active
    #: scan, of a tool given a staged copy
    #: (``SandboxRequirements.staged_input_only``). bwrap mounts an empty directory
    #: over each that a wider mount would show, and sandbox-exec denies reading
    #: them after the reads it allows; both give back what the policy lists inside
    #: them. Landlock only grants, and firejail shows everything outside ``$HOME``
    #: and ``/tmp``, so under those a tree inside a directory they show stays
    #: readable.
    unread: Tuple[Path, ...] = ()
    #: The environment list: the variables passed besides the fixed baseline, written
    #: as a docker-compose ``environment`` list (``parse_environment``). A name passes
    #: the caller's value; ``NAME=value`` sets it. Every backend reads this one list
    #: through ``filter_env``, and a backend that hides the home directory grants
    #: reading what the operator's CA-bundle settings in it name. A proxy name is
    #: passed only to a scanner that has a network, listed or not.
    environment: Tuple[str, ...] = DEFAULT_ENVIRONMENT

    def __post_init__(self) -> None:
        # Checked where the list is set, so a policy never reaches a backend with an
        # entry the sandbox refuses; the config validator and the policy builder
        # answer the same question through the same function.
        try:
            parse_environment(self.environment)
        except ValueError as refused:
            raise SandboxUnavailable(str(refused)) from None

    @property
    def results_dir(self) -> Path:
        """The scanner's results directory, the one writable path."""
        return self.writable[0]

    def filter_env(self, env: Mapping[str, str]) -> Dict[str, str]:
        """Reduce ``env`` to the allowlist, then point HOME inside."""
        prefixes = BASE_ENV_PREFIXES + tuple(self.env_prefixes)
        named = set(self.env_names)
        listed_names, listed_values = parse_environment(self.environment)
        listed = set(listed_names)
        kept = {}
        # A NAME=value entry sets the value before anything is screened, so it is
        # held to the same rules as a value the caller has.
        for key, value in {**env, **listed_values}.items():
            if key in DROPPED_ENV_NAMES:
                continue
            if key == "PYTHONPATH":
                # Passed through for the workers ASH starts with its own
                # interpreter; a relative or empty entry would be read against the
                # scanner's working directory, the scanned tree. Cleaned before
                # the named allowlist is consulted, so a PYTHONPATH a scanner
                # declares or is granted by name is held to the same rule as one
                # the PYTHON prefix passes.
                value = _anchored_entries(value)
                if not value:
                    continue
            if key in named:
                kept[key] = value
                continue
            allowed = (
                key in _FIXED_ENV_NAMES
                or key.startswith(prefixes)
                or (key in listed and (self.network or key not in PROXY_ENV_NAMES))
            )
            if not allowed:
                continue
            if any(marker in key.upper() for marker in CREDENTIAL_MARKERS):
                continue
            if _URL_USERINFO.match(value or ""):
                continue
            kept[key] = value
        kept["HOME"] = self.home.as_posix()
        kept.update(self.extra_env)
        return kept


def _anchored_entries(value: str) -> str:
    """``value``, a PATH-like list, without its relative and empty entries.

    PYTHONPATH reaches every scanner (the ``PYTHON`` prefix) so a worker started
    with ASH's interpreter imports from the same entries. A relative entry, or an
    empty one, is read against the process's working directory, which for a
    scanner is the scanned tree, so a Python-based scanner would import the
    repository's modules; only the absolute entries are passed.
    """
    return os.pathsep.join(
        entry for entry in value.split(os.pathsep) if os.path.isabs(entry)
    )


def _expand(raw: str) -> Optional[Path]:
    expanded = os.path.expandvars(os.path.expanduser(raw))
    if "$" in expanded or not os.path.isabs(expanded):
        return None
    return Path(expanded)


def _existing(paths: Iterable[Optional[Path]]) -> List[Path]:
    seen: Dict[str, Path] = {}
    for path in paths:
        if path is None:
            continue
        try:
            if not path.exists():
                continue
        except OSError:
            continue
        seen.setdefault(path.absolute().as_posix(), path.absolute())
    return list(seen.values())


def _screened_uv_directory(path: Optional[Path], named_by: str) -> Optional[Path]:
    """``path`` unless it is too broad to mount for uv, with a warning when it is.

    uv's directories are mounted for every scanner. One that is "/", a home, a
    directory holding one, or a directory directly in one (~/.local) would expose
    far more than uv's own files, so it is not mounted, the way the rule cache
    variables are treated (_env_named_read_paths).
    """
    if path is None or not _broader_than_a_tool(path):
        return path
    from automated_security_helper.utils.log import ASH_LOGGER

    ASH_LOGGER.warning(
        f"{named_by} names {path.as_posix()!r}, which is not mounted in the scanner "
        "sandbox: it would expose far more than uv's own files. Point it at a "
        "directory that holds only uv's, such as ~/.local/share/uv/tools."
    )
    return None


def _xdg_directory(name: str, default: Path) -> Path:
    """``$name`` when it is set and absolute, else ``default``.

    The XDG base directory specification says a relative value is invalid and is
    to be ignored, and uv ignores one the same way. Read as given, a relative
    XDG_DATA_HOME or XDG_CACHE_HOME named uv's directories under ASH's working
    directory, usually the scanned repository, which ``_existing`` then made
    absolute and the policy mounted, as executable where uv's tools would be.
    """
    value = os.environ.get(name, "")
    return Path(value) if value and os.path.isabs(value) else default


def _uv_data_directories() -> Tuple[Optional[Path], Optional[Path]]:
    """uv's tools directory and its managed-interpreter directory, as uv finds them.

    UV_TOOL_DIR and UV_PYTHON_INSTALL_DIR where set, each screened
    (_screened_uv_directory), else ``uv/tools`` and ``uv/python`` under the XDG
    data home. None for a directory that is screened out; nothing says here
    whether a directory exists.
    """
    data = _xdg_directory("XDG_DATA_HOME", _policy_home() / ".local" / "share")
    tools = (
        _screened_uv_directory(_expand(os.environ["UV_TOOL_DIR"]), "UV_TOOL_DIR")
        if os.environ.get("UV_TOOL_DIR")
        else data / "uv" / "tools"
    )
    pythons = (
        _screened_uv_directory(
            _expand(os.environ["UV_PYTHON_INSTALL_DIR"]), "UV_PYTHON_INSTALL_DIR"
        )
        if os.environ.get("UV_PYTHON_INSTALL_DIR")
        else data / "uv" / "python"
    )
    return tools, pythons


def _holds_a_python_lib(prefix: Path) -> bool:
    """Whether ``prefix`` has a ``lib/python*`` directory: an interpreter installation."""
    try:
        return any(prefix.glob("lib/python*"))
    except OSError:
        return False


#: uv's tools directory and its managed-interpreter directory, as
#: ``_uv_data_directories`` returns them; a caller that has them passes them on.
UvData = Tuple[Optional[Path], Optional[Path]]


def _uv_directories(data: Optional[UvData] = None) -> List[Path]:
    """uv's tool and interpreter directories, without starting uv.

    ``uv tool run`` resolves the tool's environment from its cache and runs it with a
    uv-managed interpreter, so both have to be visible. Computed from uv's documented
    environment variables and XDG defaults rather than by running ``uv tool dir``:
    this runs for every scanner spawn, and a spawn here would itself need wrapping.
    A directory UV_TOOL_DIR or UV_PYTHON_INSTALL_DIR names is screened first
    (_screened_uv_directory, which warns about one too broad to mount); ``data``
    is that reading when the caller has made it already, so one policy screens,
    and warns, once rather than at each of the three places that need it. Every
    filesystem predicate here runs under an OSError guard: a tools directory whose
    entries cannot be examined (a name past the system's length limit, an
    unreadable entry) contributes nothing rather than failing the policy.
    """
    tools, pythons = _uv_data_directories() if data is None else data
    found = _existing([tools, pythons])
    # Each installed tool's environment runs on the interpreter it was created
    # with, which need not be in uv's default python directory: a tool installed
    # with UV_PYTHON_INSTALL_DIR set elsewhere keeps pointing there. Its
    # bin/python symlink names it.
    for tools_dir in [p for p in found if tools is not None and p == tools]:
        try:
            entries = list(tools_dir.iterdir())
        except OSError:
            continue
        for tool in entries:
            interpreter = tool / "bin" / "python"
            try:
                if not interpreter.is_symlink():
                    continue
                real = Path(os.path.realpath(interpreter))
                # The link's path as spelled at each hop: a link that passes
                # through a symlinked directory (a minor-version alias of the
                # installation) dangles inside a sandbox that mounts only the
                # resolved prefix, so each spelling of the prefix is mounted too.
                spelled = [hop.parent.parent for hop in _symlink_hops(interpreter)[1:]]
            except OSError:
                continue
            prefix = real.parent.parent
            # Only an interpreter installation: a prefix with a lib/python*
            # directory, never a broad directory a link happens to point into.
            if (
                real.parent.name in _BIN_DIR_NAMES
                and _holds_a_python_lib(prefix)
                and not _broader_than_a_tool(prefix)
            ):
                found.append(prefix)
                found += [
                    hop
                    for hop in spelled
                    if hop != prefix and Path(os.path.realpath(hop)) == prefix
                ]
    return _existing(found)


def _uv_tool_locks(data: Optional[UvData] = None) -> List[Path]:
    """The ``.lock`` file of uv's tools directory, where one exists.

    Granted writable by every backend, since ``uv tool run`` takes uv's advisory
    lock on it before it starts a tool. Only a regular file with this one name: a
    symlink is not followed, and a file that has another name on disk (a hard
    link, ``st_nlink`` above 1) is not granted either, since the grant would reach
    the other name's file and a scanner could hold uv's lock on it through this
    one. Read with lstat, so the link test and the name count come from one call.
    ``data`` is ``_uv_data_directories``'s reading when the caller has it.
    """
    tool_dir, _pythons = _uv_data_directories() if data is None else data
    # Not the lock of a tools directory too broad to mount (_uv_directories warns).
    if tool_dir is None or _broader_than_a_tool(tool_dir):
        return []
    lock = tool_dir / ".lock"
    try:
        info = os.lstat(lock)
    except OSError:
        return []
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        return []
    return [lock.absolute()]


def uv_cache_directory() -> Optional[Path]:
    """uv's cache directory, the same way uv resolves it."""
    if os.environ.get("UV_CACHE_DIR"):
        return _expand(os.environ["UV_CACHE_DIR"])
    return _xdg_directory("XDG_CACHE_HOME", _policy_home() / ".cache") / "uv"


def _uv_environment(
    mounted: Sequence[Path],
    uv_cache: Optional[Path],
    data: Optional[UvData] = None,
) -> Dict[str, str]:
    """Variables that point a sandboxed uv at the directories the policy mounts.

    uv finds its tools, its managed interpreters and its cache from UV_TOOL_DIR,
    UV_PYTHON_INSTALL_DIR and UV_CACHE_DIR, else from the XDG data and cache
    homes, else under $HOME. ``filter_env`` drops the XDG variables and every
    backend gives the scanner another HOME (a private one, or the real one with
    a tmpfs over it), so a uv that computed those directories inside the sandbox
    looked where the policy mounted nothing: ``uv tool run`` found no installed
    tool, and under bwrap's throwaway overlay the host cache sat mounted while uv
    used an empty one in the private home. Each variable the environment does not
    set is set to the mounted directory uv would otherwise have computed. A
    backend that mounts the cache read-only points UV_CACHE_DIR at a private
    directory on top of this (``_private_caches``). ``data`` is
    ``_uv_data_directories``'s reading when the caller has it.
    """
    tools, pythons = _uv_data_directories() if data is None else data
    mounted_real = {os.path.realpath(p) for p in mounted}
    hints: Dict[str, str] = {}
    for name, path in (
        ("UV_TOOL_DIR", tools),
        ("UV_PYTHON_INSTALL_DIR", pythons),
        ("UV_CACHE_DIR", uv_cache),
    ):
        if path is None or os.environ.get(name):
            continue
        if os.path.realpath(path) in mounted_real:
            hints[name] = path.absolute().as_posix()
    return hints


_BIN_DIR_NAMES = ("bin", "sbin", "Scripts")


def _inside(path: Path, parent: Path) -> bool:
    try:
        Path(os.path.realpath(path)).relative_to(Path(os.path.realpath(parent)))
        return True
    except ValueError:
        return False


def _a_bin_directory(
    path: Path, homes: Sequence[Path], links: Optional[Sequence[Path]] = None
) -> bool:
    """Whether ``path`` really is a bin, sbin or Scripts directory.

    Judged on the directory it resolves to, not on its spelling: ~/bin -> ~/.aws is
    spelled bin and is a configuration directory, and $WORK/bin -> . with
    HOME=$WORK/home is spelled bin and holds a home. A filesystem root, a home and a
    directory holding one are never a bin directory, whatever their name, and nor is
    a directory holding one a link at the top of a home names (_home_link_targets).
    """
    real = Path(os.path.realpath(path))
    if real.name not in _BIN_DIR_NAMES:
        return False
    links = _home_link_targets(homes) if links is None else links
    return not (
        real == Path(real.anchor)
        or any(real == home or real in home.parents for home in homes)
        or any(real in link.parents for link in links)
    )


def _passwd_home() -> Optional[Path]:
    """The home directory the passwd entry names, or None where there is none.

    Not always the policy's home: that is Path.home(), which reads HOME, and an
    operator or a CI job can set HOME elsewhere. backends imports this name, so a
    test that fakes the passwd home patches it in both modules.
    """
    try:
        import pwd

        return Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (ImportError, KeyError, AttributeError, OSError):
        return None


def _distinct_home(home: Path, passwd_home: Optional[Path]) -> Optional[Path]:
    """``passwd_home``, resolved, when it is a second home directory beside ``home``.

    None when there is no entry, when pw_dir is relative or empty (it names no
    directory), when it is "/" (a service account's: as a home it would make every
    top-level directory "directly under a home", and sandbox-exec would deny
    reading everything the policy does not list), and when it resolves to ``home``.
    """
    if passwd_home is None or not passwd_home.is_absolute():
        return None
    real = Path(os.path.realpath(passwd_home))
    if real == Path(os.path.realpath(home)) or real == Path("/"):
        return None
    return real


def _policy_home() -> Path:
    """The home directory the policy hides and hands the scanner as HOME.

    ``core.constants.usable_home``'s answer: HOME when it is set, not empty and
    absolute; else the passwd entry's home when that is absolute. ``Path.home()``
    read HOME as given, so a relative HOME named a directory under ASH's working
    directory, usually the scanned repository: the backends hid that part of the
    tree as the home and told the scanner its home was there, and uv's default
    directories were computed under it. An empty HOME read as the root.

    With no usable home, and for a home of "/" (a container's), the filesystem
    root is returned. The root names no home: ``_homes`` leaves it out, the
    backends mount no private home over it and deny no reads under it, and the
    scanner's HOME is the root, as a process with that environment reads it.

    The read goes through ``Path.home()`` so a test that fakes the home by
    patching it is honored, with ``usable_home``'s screening applied around it:
    an empty HOME is treated as unset before the read (``Path.home()`` would read
    it as the root), a value that is not anchored (a relative HOME) is passed
    over, and the RuntimeError an unset HOME with no passwd entry raises is read
    as no home. Each of those falls to the passwd entry's home when that is
    absolute, and to the filesystem root with none.
    """
    home: Optional[Path] = None
    if os.name == "nt" or os.environ.get("HOME") != "":
        try:
            home = Path.home()
        except (RuntimeError, KeyError):
            home = None
    if home is not None and not home.is_absolute():
        home = None
    if home is None:
        passwd = _passwd_home()
        if passwd is not None and passwd.is_absolute():
            home = passwd
    if home is None:
        return Path(Path.cwd().anchor)
    return home


def _homes() -> List[Path]:
    """The home directories, resolved, that a path's breadth is measured against.

    HOME's, and the passwd entry's when that is another directory. sandbox-exec
    denies reading both and then allows the policy's paths again, and firejail hides
    the passwd one, so a path under either must be screened the same way. "/" is
    left out of both: a HOME of "/", as in some containers, names no home, and as
    one it would make every top-level directory "directly under a home".
    """
    home = Path(os.path.realpath(_policy_home()))
    homes = [] if home == Path(home.anchor) else [home]
    other = _distinct_home(home, _passwd_home())
    return homes if other is None else [*homes, other]


def _path_directories(trees: Sequence[Path] = ()) -> List[Path]:
    """Directories on PATH, minus ones that would expose far more than programs.

    Skipped: a relative entry (``.``), ``/``, a home directory itself, and any entry
    inside a home directory not named ``bin``, ``sbin`` or ``Scripts``. A PATH entry
    such as ``~/.config/tool`` would otherwise mount a configuration directory, and
    those hold tokens. The home directories are $HOME's and, when HOME names another
    directory, the passwd entry's. Also skipped: an entry inside one of ``trees``
    (the scanned tree and the output directory). Those are the scan's data, which
    the repository writes, and as a tool directory an entry there would be given
    back as runnable after sandbox-exec denies running anything from the tree.
    """
    from automated_security_helper.utils.scanned_tree import is_inside_tree

    homes = _homes()
    # A directory a link at the top of a home names counts as one in that home.
    links = _home_link_targets(homes)
    entries = []
    for raw in os.environ.get("PATH", "").split(os.pathsep):
        if not raw or not os.path.isabs(raw):
            continue
        path = Path(raw)
        if any(is_inside_tree(path, tree) for tree in trees):
            continue
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved == Path("/") or resolved in homes:
            continue
        if _broader_than_a_tool(path, homes, links):
            continue
        in_a_home = any(_inside(path, home) for home in [*homes, *links])
        if in_a_home and not _a_bin_directory(path, homes, links):
            continue
        entries.append(path)
    return _existing(entries)


def _contained_option_paths(
    spelled: Sequence[str], roots: Sequence[Path]
) -> Tuple[str, ...]:
    """The paths a scanner's options name that may be mounted, as resolved paths.

    Options are repository-writable, so a path they name is mounted only when it
    resolves inside one of ``roots`` (the source tree and the operator's
    ``extra_read_paths``) and is a regular file or directory, never a socket or
    device. The resolved path is what goes into the policy, so the policy names
    the file this check examined and not the spelling the option gave. The
    backends resolve every policy path again when they plan the spawn, so a link
    put in the resolved path's place between this check and the spawn is followed
    then; the containment is decided here, the mount is made there.
    """
    real_roots = [Path(os.path.realpath(root)) for root in roots]
    kept: List[str] = []
    for value in spelled:
        path = _expand(value)
        if path is None:
            continue
        real = Path(os.path.realpath(path))
        try:
            mode = os.stat(real).st_mode
        except OSError:
            continue
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            continue
        if _inside_any(real, real_roots):
            kept.append(str(real))
    return tuple(kept)


def _inside_any(real: PurePath, roots: Sequence[PurePath]) -> bool:
    """Whether ``real`` is one of ``roots`` or below one, by path comparison alone.

    Both sides are already resolved. Pure-path comparison follows the platform's
    rules: on Windows, case-insensitive, and never equal across drives.
    """
    return any(real == root or root in real.parents for root in roots)


#: Pseudo-filesystems a link must not get hidden or refused by: shared memory that
#: multiprocessing scanners use, and the runtime directory the system keeps its
#: sockets in. Neither is a directory of the user's.
_PSEUDO_FS_ROOTS = (
    Path("/dev/shm"),  # nosec B108 - compared against, never written
    Path("/run"),
)


def _home_link_targets(
    homes: Sequence[Path], *, files: bool = False, ancestors: bool = False
) -> List[Path]:
    """The real directories that links at the top of a home name outside the homes.

    ~/.local can be a link to /persist/me/.local on another disk. The breadth rules
    measure real paths, by which that directory is outside every home, so it was
    mounted with its keyrings. Each such directory counts as directly in its home in
    every home check, next to the checks of the real path. Left out are links to "/",
    to a home or a directory holding or inside one (measured already), to, into
    or above a system read path (~/u -> /usr names no directory of the user's), and
    to or into a pseudo-filesystem (``_PSEUDO_FS_ROOTS``). The backends and the
    breadth rules read this one list, so they agree on which links count.

    ``files`` also returns the files such links name (~/.netrc kept on another
    disk), which a backend that hides the directories can hide too. ``ancestors``
    keeps a directory that holds one of ``homes``: the breadth rules leave it out
    because it holds a real home, but where ``homes`` are not homes at all but
    directories a link named (policy hiding walks them), its other entries are the
    user's as well.
    """
    system = [Path(path) for path in SYSTEM_READ_PATHS]
    system += [Path(os.path.realpath(path)) for path in system]
    pseudo = [Path(os.path.realpath(root)) for root in _PSEUDO_FS_ROOTS]
    targets: List[Path] = []
    for home in homes:
        try:
            names = [entry.name for entry in os.scandir(home) if entry.is_symlink()]
        except OSError:
            continue
        for name in names:
            real = Path(os.path.realpath(home / name))
            if (
                real == Path(real.anchor)
                or not (real.is_dir() or (files and real.is_file()))
                or any(
                    real == other
                    or other in real.parents
                    or (not ancestors and real in other.parents)
                    for other in homes
                )
                or _inside_any(real, system)
                or any(real in path.parents for path in system)
                or _inside_any(real, pseudo)
            ):
                continue
            if real not in targets:
                targets.append(real)
    return targets


def _broader_than_a_tool(
    path: Path,
    homes: Optional[Sequence[Path]] = None,
    links: Optional[Sequence[Path]] = None,
) -> bool:
    """Whether mounting ``path`` would expose more than one tool installation.

    True for /, for a home directory, for any directory that contains one, and for
    any directory directly under one (~/.local, ~/.cargo): each of those holds other
    files of the user's. A directory a link at the top of a home names (``links``,
    _home_link_targets) counts as directly under that home, so it and any directory
    holding it are true too. Also true for the XDG data home, ``~/.local/share``,
    and for any directory in a home that holds a ``keyrings`` directory: two
    levels down, so the rule above admitted it, and it holds the user's keyrings.
    ``homes`` defaults to _homes().
    """
    real = Path(os.path.realpath(path))
    if real == Path("/"):
        return True
    homes = _homes() if homes is None else homes
    links = _home_link_targets(homes) if links is None else links
    if any(
        real == home or real in home.parents or real.parent == home for home in homes
    ) or any(real == link or real in link.parents for link in links):
        return True
    in_a_home = any(home in real.parents for home in homes)
    return in_a_home and (
        (real.name == "share" and real.parent.name == ".local")
        or os.path.lexists(real / "keyrings")
    )


def _exposes_a_home(real: Path, homes: Sequence[Path]) -> bool:
    """Whether a read grant of ``real`` would expose far more than one directory.

    A filesystem root, a home directory, a directory holding one, or a directory
    holding a directory a link at the top of a home names (~/.local kept on
    another disk is part of that home). A directory directly under a home
    (``~/.gem``, ``~/rules``) is admitted: whoever named it chose it.
    """
    return (
        real == Path(real.anchor)
        or any(real == home or real in home.parents for home in homes)
        or any(real in link.parents for link in _home_link_targets(homes))
    )


def _env_named_read_paths(names: Sequence[str]) -> List[Path]:
    """The directories ``names`` name in ASH's own environment, as read grants.

    See ``SandboxRequirements.read_path_env``. A value that would expose far more
    than one directory -- a filesystem root, a home directory, or a directory
    holding one -- is refused with a warning, so the tool then finds nothing there
    and says so, rather than reading the whole home directory. The home directories
    are $HOME's and, when HOME names another directory, the passwd entry's.
    """
    homes = _homes()
    granted: List[Path] = []
    for name in names:
        value = os.environ.get(name, "")
        if not value or not os.path.isabs(value):
            continue
        if not os.path.isdir(value):
            # A rules directory, not a file, and not a path that does not exist.
            if os.path.lexists(value):
                from automated_security_helper.utils.log import ASH_LOGGER

                ASH_LOGGER.warning(
                    f"${name}={value} is not mounted in the scanner sandbox: it is "
                    "not a directory."
                )
            continue
        if _exposes_a_home(Path(os.path.realpath(value)), homes):
            from automated_security_helper.utils.log import ASH_LOGGER

            ASH_LOGGER.warning(
                f"${name}={value} is not mounted in the scanner sandbox: it would "
                "expose far more than one directory. Point it at the directory "
                "itself."
            )
            continue
        granted.append(Path(value))
    return granted


def _screened_declared_paths(
    spelled: Sequence[str], scanner_name: str, kind: str
) -> List[Path]:
    """A scanner's declared ``read_paths`` or ``cache_paths``, expanded and screened.

    Each is ``_expand``ed (``~`` and ``$VAR``), and the same breadth screen the
    ``read_path_env`` values get applies (``_exposes_a_home``): a value that
    resolves to a filesystem root, a home or a directory holding one is refused
    with a warning. cfn-nag declares ``$GEM_HOME``, trivy and grype declare their
    cache variables; an operator who points one of those at the home directory
    or at ``/`` would otherwise have it mounted whole, and executable, for the
    scanner. ``~/.gem`` itself, a directory directly in the home, is admitted.
    """
    homes = _homes()
    kept: List[Path] = []
    for raw in spelled:
        path = _expand(raw)
        if path is None:
            continue
        if _exposes_a_home(Path(os.path.realpath(path)), homes):
            from automated_security_helper.utils.log import ASH_LOGGER

            ASH_LOGGER.warning(
                f"{scanner_name}'s {kind} entry {raw!r} names {path.as_posix()!r}, "
                "which is not mounted in the scanner sandbox: it would expose far "
                "more than one directory."
            )
            continue
        kept.append(path)
    return kept


def _symlink_hops(path: Path) -> List[Path]:
    """``path`` and every path its symlink chain passes through, as spelled.

    A venv's ``bin/python`` links to ``/home/me/.local/share/uv/python/.../python3``,
    which may itself pass through a symlinked ``/home/me``. Mounting only the final
    real file leaves the intermediate spellings dangling inside the sandbox, and
    exec fails with ENOENT on a file that exists.

    A relative link target is read against the directory the link really sits in,
    as the kernel reads it: ``..`` in the target names that directory's parent,
    not the parent of the spelling, which differs once the spelling passed through
    a symlinked directory. Folded lexically against the spelling, ``../b`` after a
    link ``/a -> /x/y`` named ``/b`` where the kernel reads ``/x/b``.
    """
    hops = [path]
    current = path
    for _ in range(40):  # the kernel's own limit on symlink depth
        if not current.is_symlink():
            break
        target = Path(os.readlink(current))
        if target.is_absolute():
            current = target
        else:
            current = Path(os.path.realpath(current.parent)) / target
        hops.append(Path(os.path.normpath(current)))
    return hops


def _lookup(name: str) -> Optional[str]:
    """``find_executable``: never from the working directory or the scanned tree."""
    from automated_security_helper.utils.subprocess_utils import find_executable

    return find_executable(name)


def _executable_prefix(argv0: str) -> List[Path]:
    """The executable's directory, and its install prefix when it sits in a bin dir.

    For a script installed by a package manager the interpreter and libraries live
    beside the bin directory (``<prefix>/bin/tool`` with ``<prefix>/lib``), so the
    prefix is what has to be visible, not only the file.
    """
    found = argv0 if os.path.isabs(argv0) else _lookup(argv0)
    if not found:
        return []
    homes = _homes()
    links = _home_link_targets(homes)

    def too_broad(prefix: Path) -> bool:
        # A prefix of /, of a home directory, of a directory holding one (a Python
        # at $WORK/bin with HOME=$WORK/home), or directly under one (~/.local,
        # ~/.cargo) holds far more than the tool: ~/.local/share carries keyrings
        # and ~/.cargo carries credentials.toml. Deeper prefixes, such as
        # ~/.nvm/versions/node/v22, are a single installation.
        return _broader_than_a_tool(prefix, homes, links)

    paths: List[Path] = []
    candidates = set(_symlink_hops(Path(found))) | {Path(os.path.realpath(found))}
    # A script runs on the interpreter its first line names, whose libraries sit in
    # that interpreter's own prefix: cfn_nag_scan is a RubyGems wrapper whose Ruby,
    # on the hosted macOS runners, is installed under $HOME.
    interpreter = _shebang_interpreter(Path(found))
    if interpreter is not None:
        candidates |= set(_symlink_hops(interpreter)) | {
            Path(os.path.realpath(interpreter))
        }
    for candidate in candidates:
        parent = candidate.parent
        # A bin directory by what it resolves to (_a_bin_directory), so a link
        # spelled bin that names a home's directory, or one holding a home, is
        # judged by the breadth rules like any other directory.
        is_bin = _a_bin_directory(parent, homes, links)
        if is_bin or not too_broad(parent):
            paths.append(parent)
        # The prefix above a bin directory: refused when it is directly in a home
        # (~/.local, ~/.cargo), unless it is one installation (a venv or a conda
        # root, ~/.venv or ~/miniconda3), which is what _refuse_a_home_among admits
        # for ASH's own interpreter; a tool installed there could otherwise not
        # start, its bin directory mounted and its library not.
        if is_bin and (
            not too_broad(parent.parent)
            or _an_installation_directly_in_a_home(parent.parent, homes)
        ):
            paths.append(parent.parent)
    return _existing(paths)


def _an_installation_directly_in_a_home(path: Path, homes: Sequence[Path]) -> bool:
    """Whether ``path`` resolves to a venv or conda root directly in one of ``homes``."""
    real = Path(os.path.realpath(path))
    return real.parent in homes and _is_an_installation_root(real)


#: env's options that take the next word as their argument: GNU's ``-u``/``--unset``,
#: ``-C``/``--chdir`` and ``-a``/``--argv0``, and the BSD and macOS env's ``-P``
#: (the search path for the program) and ``-L`` (the login class). Read as the
#: program, the argument would name one that exists nowhere.
_ENV_OPTIONS_WITH_AN_ARGUMENT = frozenset(
    {"-u", "--unset", "-C", "--chdir", "-a", "--argv0", "-P", "-L"}
)


def _env_program(words: Sequence[str]) -> Optional[str]:
    """The program an ``env`` shebang line runs: the first word after env's own.

    Skipped: env's options (``--`` and a bare ``-`` among them), the argument of
    one that takes one (``-u NAME``, ``-C DIR``, BSD's ``-P PATH``), a
    ``--option=value`` or attached ``-uNAME`` spelling, ``-S`` (what follows is the
    split command line, whose first word is the program) and ``NAME=value``
    assignments.
    Read as the program, an assignment or an option's argument named a program
    that exists nowhere, so the interpreter's prefix was not mounted and the
    script could not start inside the sandbox.
    """
    skip_next = False
    for word in words:
        if skip_next:
            skip_next = False
            continue
        if word in ("-S", "--split-string"):
            continue
        if word.startswith("-"):
            skip_next = word in _ENV_OPTIONS_WITH_AN_ARGUMENT
            continue
        if "=" in word:
            continue
        return word
    return None


def _shebang_interpreter(script: Path) -> Optional[Path]:
    """The interpreter a ``#!`` script names, resolved through ``env`` and PATH."""
    try:
        with open(script, "rb") as f:
            first = f.readline(256)
    except OSError:
        return None
    if not first.startswith(b"#!"):
        return None
    words = first[2:].decode("utf-8", errors="replace").split()
    if not words:
        return None
    program = words[0]
    if os.path.basename(program) == "env":
        name = _env_program(words[1:])
        if name is None:
            return None
        program = _lookup(name) or ""
    return Path(program) if os.path.isabs(program) else None


def _ash_paths() -> Tuple[List[Path], List[Path]]:
    """ASH's own package (rule packs and configs it passes to scanners) and Python.

    Returns every path to mount, and the entries among them that are data where
    they sit in the scan's data: the sys.path entries that are only import entries
    (not an interpreter directory or a link directory of it), and the ASH bin
    directory. The caller keeps those from being executable, and from being read
    by a tool given a staged copy, where they lie inside a scanned tree; ASH's
    interpreter and link directories stay executable wherever they are.

    The ASH bin directory is mounted when it is anchored. A relative ASH_BIN_PATH is
    not searched for tools (subprocess_utils.find_executable), and here _existing
    would make it absolute against the cwd: ASH_BIN_PATH=bin, run from the
    repository, made the bin/ it committed a read-only and executable path. An
    anchored one inside the scanned tree is mounted, as data.

    An interpreter with no path (an embedding that leaves ``sys.executable``
    empty) names no binary directory and no link directory: ``realpath("")`` is
    the working directory, whose grandparent was mounted as the interpreter's
    prefix and which was itself mounted as a link directory.
    """
    from automated_security_helper.utils.subprocess_utils import _bin_path, _is_anchored

    package_dir = Path(__file__).resolve().parents[2]
    # The directory holding the package too: importlib lists each sys.path entry, and
    # Landlock refuses that listing unless the entry itself is readable. That is
    # site-packages for an installed ASH, or the checkout for an editable one.
    import_root = package_dir.parent
    homes = _homes()
    if Path(os.path.realpath(import_root)) in homes:
        import_root = package_dir
    # And every directory on sys.path. A worker started with this interpreter
    # (detect-secrets, cdk-nag) imports from the same entries, and an editable
    # install's .pth file adds entries outside site-packages. Landlock denies an
    # entry it was not given, so the import fails with ModuleNotFoundError.
    #
    # Inside a home directory ($HOME's, or the passwd entry's when HOME names
    # another) only entries that belong to the interpreter (under sys.prefix or
    # sys.base_prefix, which is where uv keeps managed Pythons and venvs) or that
    # hold the ASH package are added: a PYTHONPATH pointing at ~/anything, or
    # ``python -m`` run from the home directory, would otherwise mount that
    # directory for every scanner.
    interpreter_roots = {
        Path(os.path.realpath(p))
        for p in (sys.prefix, sys.base_prefix, sys.exec_prefix)
    } | {Path(os.path.realpath(import_root))}

    links = _home_link_targets(homes)

    def _importable(entry: str) -> bool:
        if not entry or not os.path.isabs(entry) or not os.path.isdir(entry):
            return False
        real = Path(os.path.realpath(entry))
        if _broader_than_a_tool(real, homes, links):
            return False
        in_a_home = any(home in real.parents for home in homes) or any(
            real == link or link in real.parents for link in links
        )
        if not in_a_home:
            return True
        return any(real == root or root in real.parents for root in interpreter_roots)

    import_path = [Path(entry) for entry in sys.path if _importable(entry)]
    interpreter_dirs = [Path(sys.prefix), Path(sys.base_prefix), Path(sys.exec_prefix)]
    link_dirs: List[Path] = []
    if sys.executable:
        # The real interpreter's install prefix, read from where its binary is. For
        # a binary directly in a top-level directory that is the filesystem root,
        # which names no installation. Where that directory is already a system
        # read path (/bin without a merged /usr, /opt), the root is left out: the
        # binary's directory is mounted as a link directory below, and that grants
        # nothing new. Anywhere else (/mnt/python3, /srv/python3) it stays in and is
        # refused, since leaving it out would mount that whole top-level directory
        # for every scanner. A sys prefix of "/" is refused either way.
        real_binary_dir = Path(os.path.realpath(sys.executable)).parent
        real_prefix = real_binary_dir.parent
        if real_prefix.parent != real_prefix or not _inside_any(
            real_binary_dir, _system_read_paths_real()
        ):
            interpreter_dirs.append(real_prefix)
        link_dirs = [hop.parent for hop in _symlink_hops(Path(sys.executable))]
    bin_path = _bin_path()
    # Only when anchored: a relative ASH_BIN_PATH is not searched for tools
    # (subprocess_utils.find_executable), and _existing would make it absolute
    # against the cwd (see the docstring). Nothing is mounted for None, and
    # _refuse_a_home_among has nothing to measure for it.
    if bin_path is not None and not _is_anchored(str(bin_path)):
        bin_path = None
    _refuse_a_home_among(
        interpreter_dirs, link_dirs, bin_path, homes, interpreter_roots
    )
    interpreter_real = {os.path.realpath(p) for p in [*interpreter_dirs, *link_dirs]}
    data_entries = [
        p for p in import_path if os.path.realpath(p) not in interpreter_real
    ] + ([bin_path] if bin_path is not None else [])
    return (
        _existing(
            [
                package_dir,
                import_root,
                *import_path,
                *interpreter_dirs,
                *link_dirs,
                bin_path,
            ]
        ),
        _existing(data_entries),
    )


def _system_read_paths_real() -> List[Path]:
    """The system read paths, as spelled and resolved."""
    system_paths = [Path(path) for path in SYSTEM_READ_PATHS]
    return system_paths + [Path(os.path.realpath(path)) for path in system_paths]


def _is_an_installation_root(path: Path) -> bool:
    """Whether ``path`` is a venv's root (pyvenv.cfg) or a conda installation's.

    A marker alone is not enough where the directory holds the user's data:
    ``.local`` holds ``.local/share`` and the keyrings in it, and a pyvenv.cfg or
    conda-meta there (``conda create -p ~/.local``, or one any program run as the
    user wrote) would admit it. So ``.local``, and any directory holding
    share/keyrings, is never an installation root.
    """
    if path.name == ".local" or os.path.lexists(path / "share" / "keyrings"):
        return False
    return (path / "pyvenv.cfg").is_file() or (path / "conda-meta").is_dir()


#: Said in every refusal of an interpreter prefix: a venv made from that Python keeps
#: it as sys.base_prefix, so the venv is refused the same way and is no way out.
_A_VENV_IS_REFUSED_TOO = (
    "a virtual environment made from this one is refused too, since it keeps this "
    "prefix as its base."
)


def _refused_prefix(
    path: Path, real: Path, homes: Sequence[Path], links: Sequence[Path] = ()
) -> str:
    """Why ASH's Python prefix ``path`` is refused, and what to do instead."""
    named = path.as_posix()
    if real == Path(real.anchor):
        return (
            f"ASH's Python prefix {named!r} is the filesystem root, so the sandbox "
            "would mount every directory for every scanner. Use a Python installed "
            f"under a prefix of its own; {_A_VENV_IS_REFUSED_TOO}"
        )
    if any(real == home or real in home.parents for home in homes) or any(
        real in link.parents for link in links
    ):
        reason = (
            "is a home directory or holds one, or holds a directory a home links "
            "to, so the sandbox would mount the home's files"
        )
    else:
        reason = (
            "is directly in a home directory and is not a single Python installation "
            "(a virtual environment or a conda installation), so the sandbox would "
            "mount all of it"
        )
    return (
        f"ASH's Python prefix {named!r} {reason} for every scanner. Use a Python "
        f"installed outside the home directory; {_A_VENV_IS_REFUSED_TOO}"
    )


def _refused_link(
    path: Path, real: Path, homes: Sequence[Path], links: Sequence[Path] = ()
) -> str:
    """Why a directory ASH's Python is reached through is refused, and the way out."""
    reached = (
        f"ASH's Python {sys.executable!r} is reached through a link in "
        f"{path.as_posix()!r}"
    )
    outside_the_home = (
        "Use an interpreter or virtual environment outside the home directory, or a "
        "virtual environment created from the interpreter's real path."
    )
    if real in homes:
        return (
            f"{reached}, a home directory, so the sandbox would mount it for every "
            f"scanner. {outside_the_home}"
        )
    if (
        real == Path(real.anchor)
        or any(real in home.parents for home in homes)
        or any(real in link.parents for link in links)
    ):
        return (
            f"{reached}, which is the filesystem root or a directory holding a home, "
            "so the sandbox would mount it for every scanner. Use an interpreter "
            "whose path passes through no such directory, or a virtual environment "
            "created from the interpreter's real path."
        )
    return (
        f"{reached}, a directory in a home that is not a bin directory, so the "
        f"sandbox would mount it for every scanner. {outside_the_home}"
    )


def _refuse_a_home_among(
    interpreter_dirs: Sequence[Path],
    link_dirs: Sequence[Path],
    bin_path: Optional[Path],
    homes: Sequence[Path],
    interpreter_roots: Iterable[Path],
) -> None:
    """Refuse the spawn when mounting ASH's own paths would mount a home's contents.

    ASH's interpreter is mounted by its prefixes and by the directory of every link
    sys.executable passes through, so that it starts inside the sandbox by the path
    it was started with, and ASH_BIN_PATH is mounted for the tools in it. None of
    them went through a breadth filter. A venv made by ``~/python3 -m venv ~/env``
    links env/bin/python3 to ~/python3, which mounted the whole home, ~/.ssh
    included; a Python whose prefix is ~/.local mounted ~/.local/share and its
    keyrings. Mounting less instead would leave a link dangling, or the interpreter
    without its library, and it would not start, so the spawn is refused.

    Measured against ``homes`` (_homes(): HOME's and the passwd entry's):
    - a prefix that is "/", a home or holds one, or is directly in a home without
      being a venv or conda root (~/.venv and ~/miniconda3 are one installation,
      ~/.local is not);
    - a link's directory that is "/", a home or holds one, or is inside a home
      without being a bin, sbin or Scripts directory or lying inside an interpreter
      (~/.config for ~/.config/python3), or is a top-level directory that is not a
      system read path (/srv for /srv/python3: mounted, it would show every
      scanner all of that directory, the way a prefix of "/" would);
    - an ASH_BIN_PATH that is "/", a home or holds one, or is directly in a home
      without being a bin, sbin or Scripts directory (~/.local).
    Whether a directory is a bin directory is judged on what it resolves to
    (_a_bin_directory), so ~/bin -> ~/.aws is not one. A directory a link at the top
    of a home names (_home_link_targets, ~/.local kept on another disk) counts as
    directly in that home, so it is measured like ~/.local, and holding it is
    holding part of the home.

    ``bin_path`` is None when ASH has no bin directory to mount: ASH_BIN_PATH is
    unset and there is no default directory, or it is relative and _ash_paths leaves
    it out (a relative value names a directory under the working directory, usually
    the scanned repository). Nothing is mounted for it, so there is nothing to
    measure, and the interpreter and link directories above are measured as always.
    A relative path that does reach this function is measured where the working
    directory puts it, which is where _existing would mount it.
    """
    roots = [Path(os.path.realpath(root)) for root in interpreter_roots]
    links = _home_link_targets(homes)

    def holds_a_home(real: Path) -> bool:
        return (
            real == Path("/")
            or any(real == home or real in home.parents for home in homes)
            or any(real in link.parents for link in links)
        )

    def directly_in_a_home(real: Path) -> bool:
        return real.parent in homes or real in links

    for path in interpreter_dirs:
        real = Path(os.path.realpath(path))
        if holds_a_home(real) or (
            directly_in_a_home(real) and not _is_an_installation_root(real)
        ):
            raise SandboxUnavailable(_refused_prefix(path, real, homes, links))
    system_paths = _system_read_paths_real()
    for path in link_dirs:
        real = Path(os.path.realpath(path))
        in_a_home = any(home in real.parents for home in homes) or any(
            real == link or link in real.parents for link in links
        )
        part_of_an_interpreter = any(
            real == root or root in real.parents for root in roots
        )
        if holds_a_home(real) or (
            in_a_home
            and not _a_bin_directory(path, homes, links)
            and not part_of_an_interpreter
        ):
            raise SandboxUnavailable(_refused_link(path, real, homes, links))
        if (
            real != Path(real.anchor)
            and real.parent == Path(real.anchor)
            and not _inside_any(real, system_paths)
        ):
            raise SandboxUnavailable(
                f"ASH's Python {sys.executable!r} is reached through a link in "
                f"{path.as_posix()!r}, a top-level directory that is not a system "
                "read path, so the sandbox would mount all of it for every scanner. "
                "Use an interpreter whose path passes through no such directory, or "
                "a virtual environment created from the interpreter's real path."
            )
    if bin_path is not None and os.path.isdir(bin_path):
        real = Path(os.path.realpath(bin_path))
        if holds_a_home(real) or (
            directly_in_a_home(real) and not _a_bin_directory(bin_path, homes, links)
        ):
            raise SandboxUnavailable(
                f"ASH_BIN_PATH {bin_path.as_posix()!r} is a home directory, holds one, "
                "or is a directory directly in one that is not a bin directory, so the "
                "sandbox "
                "would mount it for every scanner. Point ASH_BIN_PATH at a "
                "directory that holds only tools, outside the home directory or in "
                "one of its bin directories."
            )


def _refuse_symlinked_results_dir(
    output_dir: Path, results_dir: Path, source_dir: Optional[Path] = None
) -> None:
    """Refuse a results directory reached through a symlink below the output dir.

    The default output directory is inside the source tree, so the scanned
    repository can commit ``.ash/ash_output/scanners/<name>`` as a symlink to any
    directory the user can write. Mounting the results directory writable would
    then hand the scanner that directory.

    Every component below the output directory is examined. A results directory
    outside the output directory but inside ``source_dir`` is examined below the
    source directory the same way: those components are the repository's too, and
    examining the final one alone left a committed link above it unseen. A
    results directory under neither is examined at its final component only;
    the components above it are the operator's spelling.
    """
    output_dir = Path(os.path.abspath(output_dir))
    results_dir = Path(os.path.abspath(results_dir))
    components = [results_dir]
    for root in [output_dir] + (
        [Path(os.path.abspath(source_dir))] if source_dir else []
    ):
        try:
            relative = results_dir.relative_to(root)
        except ValueError:
            continue
        components = []
        current = root
        for part in relative.parts:
            current = current / part
            components.append(current)
        break
    for component in components:
        if component.is_symlink():
            raise SandboxUnavailable(
                f"the results directory path {component.as_posix()} is a symlink, so "
                "mounting it writable would expose wherever it points"
            )


def _readable_cwd(cwd: Optional[Path]) -> Optional[Path]:
    """``cwd`` as a read grant, or None for a filesystem root.

    checkov and ferret-scan run from the filesystem root so that they read no
    config file from the scanned tree, and are handed only absolute paths
    (``_subprocess_cwd`` on each scanner). Granting the root would let every
    sandboxed process read the whole filesystem; every backend can still change
    into ``/`` without it.
    """
    if cwd is None:
        return None
    absolute = Path(os.path.abspath(cwd))
    return None if absolute == Path(absolute.anchor) else cwd


def refuse_symlinked_output_dir(source_dir: Path, output_dir: Path) -> None:
    """Refuse an output directory reached through a symlink in the scanned tree.

    Every sandbox mounts the output directory read-only and the results directory
    below it writable, and ASH writes there unsandboxed. The default
    ``.ash/ash_output``, or an ``--output-dir`` inside the source tree, is spelled
    through directories the scanned repository controls: committing
    ``build -> /some/host/dir`` and being scanned with ``--output-dir build/ash``
    would let the repository pick a host directory for the sandbox to show and
    for ASH to write.

    The same check every scan makes before it starts, whatever the sandbox mode
    (utils/output_dir_links.py), made again here for each scanner's policy so a
    link that appeared since is not mounted. Links at or above the source
    directory are the operator's own spelling and are not examined.
    """
    from automated_security_helper.utils.output_dir_links import (
        linked_output_component,
    )

    found = linked_output_component(source_dir, output_dir)
    if found is not None:
        raise SandboxUnavailable(
            f"{found}, so mounting the output directory would expose wherever it points"
        )


def _under_home(path: Path, homes: Sequence[Path]) -> bool:
    """Whether ``path``, resolved, is one of ``homes`` or sits under one.

    ``homes`` is _homes()'s set: HOME's and the passwd entry's, resolved, with "/"
    left out, so a HOME of "/" (a container's) names no home and drops nothing. An
    entry that contains a home (``/opt`` with a HOME of ``/opt/app/home``) is not
    under it and is kept: dropping it would take away a tool's installation prefix.
    """
    real = Path(os.path.realpath(path))
    return any(real == home or home in real.parents for home in homes)


def build_scanner_policy(
    scanner_name: str,
    requirements: SandboxRequirements,
    *,
    argv0: str,
    source_dir: Path,
    output_dir: Path,
    results_dir: Path,
    scan_target: Optional[Path],
    cwd: Optional[Path],
    offline: bool,
    network_scanners: Optional[Sequence[str]],
    extra_read_paths: Sequence[str] = (),
    network_limit: Optional[Sequence[str]] = None,
    read_path_scanners: Sequence[str] = (),
    env_scanners: Sequence[str] = (),
    tool_config_dir: Optional[Path] = None,
    also_runs: Sequence[str] = (),
    scanned_trees: Sequence[Path] = (),
    read_grants: Sequence[Path] = (),
    environment: Optional[Sequence[str]] = None,
) -> SandboxPolicy:
    """The policy one scanner gets for one spawn.

    Args:
        network_scanners: When not None, replaces every scanner's declared network
            need: only scanners named here get a network (still never under offline).
        network_limit: When not None, a scanner not named here gets no network
            whatever the rest says. Set from a config file in the scanned tree,
            which may take network away but not grant it.
        read_path_scanners: Scanners whose ``read_paths_require_grant`` paths
            are granted.
        env_scanners: Scanners whose ``env_requires_grant`` variables are
            granted.
        tool_config_dir: The directory of config files ASH wrote for this scanner
            run's tool (``utils/tool_config_dir``). Read-only, and in
            ``scan_data``, so a backend that limits where programs run from
            (sandbox-exec) runs none from it.
        also_runs: Programs the spawn starts besides argv0, named by ASH's own
            code (``scope.also_runs``). Each is granted as argv0 is, through
            ``_executable_prefix`` and its breadth filter.
        scanned_trees: The roots of the active scan
            (``subprocess_utils.scanned_trees()``), which the scanned repository
            writes: data, like ``source_dir``, and never a grant. Each root joins
            ``scan_data``, so under sandbox-exec, the one backend that restricts
            where programs run from, nothing runs from it and an import entry of
            ASH's interpreter inside one is read as source, not run from; and a
            tool given a staged copy does not read one (``unread``). A root is
            not added to ``read_only``: what a spawn may read is decided by the
            other arguments.
        read_grants: Directories ASH's own code granted this spawn for reading
            (``scope.reads_directory``), already resolved: each is readable and
            joins ``scan_data``, so under sandbox-exec nothing in it is executable
            (the other backends do not restrict exec). The pre-installed tool
            check's staged Nix metadata under TMPDIR is the one such directory.
        environment: The operator's environment list (``parse_environment``), or
            None for ``DEFAULT_ENVIRONMENT``. A list replaces the default, as a
            docker-compose ``environment`` list replaces the image's. An entry the
            sandbox refuses (a credential-shaped name), or a list that is a bare
            string, raises SandboxUnavailable naming the variable or the shape.
    """
    try:
        listed_environment = (
            DEFAULT_ENVIRONMENT
            if environment is None
            else _environment_entries(environment)
        )
    except ValueError as refused:
        raise SandboxUnavailable(str(refused)) from None
    real_home = _policy_home()
    read_granted = not requirements.read_paths_require_grant or scanner_name in set(
        read_path_scanners
    )
    env_granted = not requirements.env_requires_grant or scanner_name in set(
        env_scanners
    )
    declared_read = requirements.read_paths if read_granted else ()
    declared_cache = requirements.cache_paths if read_granted else ()
    if requirements.read_paths_require_grant:
        # Paths taken from options the repository can write. Even when granted,
        # only what the trusted policy already reaches: the source tree and the
        # operator's extra_read_paths. Never a writable cache.
        declared_read = _contained_option_paths(
            declared_read,
            [source_dir]
            + [p for p in (_expand(e) for e in extra_read_paths) if p is not None],
        )
        declared_cache = ()
    declared_prefixes = requirements.env_prefixes if env_granted else ()
    declared_names = requirements.env_names if env_granted else ()
    if network_scanners is None:
        network = requirements.network and not requirements.network_requires_grant
    else:
        network = scanner_name in set(network_scanners)
    if network_limit is not None and scanner_name not in set(network_limit):
        network = False
    if offline:
        network = False

    # Data the tool reads, like the scan's own: readable, never executable.
    env_named_reads = _env_named_read_paths(requirements.read_path_env)
    # A tool given a staged copy reads that copy (the scan target), not the scan's
    # tree, its output, or any other root of the scan.
    unread = (
        _existing([source_dir, output_dir, *scanned_trees])
        if requirements.staged_input_only
        else []
    )
    scan_tree = [] if requirements.staged_input_only else [source_dir, output_dir]
    ash_paths, ash_data_entries = _ash_paths()
    homes = _homes()
    trees = (source_dir, output_dir, *scanned_trees)
    # Declared read paths from the scanner's own code, and the operator's extra
    # read paths: screened and expanded here, named again below where the
    # executable set is decided.
    screened_declared_read = _screened_declared_paths(
        declared_read, scanner_name, "read_paths"
    )
    tool_prefixes = _executable_prefix(argv0) + [
        path for program in also_runs for path in _executable_prefix(program)
    ]
    # uv's data directories, read and screened once for this policy: the mounts,
    # the environment hints and the tools lock below all take this reading, so a
    # UV_TOOL_DIR too broad to mount is warned about once per spawn, not three
    # times, and the environment and the home are read once.
    uv_data = _uv_data_directories()
    read_only = _existing(
        [p for p in (Path(p) for p in SYSTEM_READ_PATHS) if not _under_home(p, homes)]
        + _path_directories(list(trees))
        + _uv_directories(uv_data)
        + ash_paths
        + tool_prefixes
        + screened_declared_read
        + env_named_reads
        + [_expand(p) for p in extra_read_paths]
        + [*scan_tree, scan_target, _readable_cwd(cwd), tool_config_dir]
        + list(read_grants)
    )

    uv_cache = _screened_uv_directory(
        uv_cache_directory(),
        "UV_CACHE_DIR" if os.environ.get("UV_CACHE_DIR") else "XDG_CACHE_HOME",
    )
    cache = _existing(
        [uv_cache]
        + _screened_declared_paths(declared_cache, scanner_name, "cache_paths")
    )

    refuse_symlinked_output_dir(source_dir, output_dir)
    _refuse_symlinked_results_dir(output_dir, results_dir, source_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    writable = [results_dir.absolute()]

    # A read-only path inside a writable one (a cwd under the results directory) is
    # already visible through the writable mount. Kept, it would be mounted read-only
    # on top and take away the write access the scanner needs there.
    def _inside_writable(path: Path) -> bool:
        real = Path(os.path.realpath(path))
        return any(
            real == w or w in real.parents
            for w in (Path(os.path.realpath(p)) for p in writable)
        )

    read_only = [p for p in read_only if not _inside_writable(p)]
    cache = [p for p in cache if not _inside_writable(p)]

    # The working directory the same way the read list takes it: a filesystem root
    # (checkov and ferret-scan run from one so that they read no config file from
    # the scanned tree) is not the scan's data.
    # The offline rule cache too: data the tool reads, which sandbox-exec then
    # denies exec in even where an executable root (/opt, /usr/local) contains it.
    # And the directory of config files ASH wrote for this run's tool.
    # And every root of the active scan: the repository's, like source_dir.
    # And a directory ASH granted this spawn for reading: data, never programs.
    scan_data = _existing(
        [
            source_dir,
            output_dir,
            scan_target,
            _readable_cwd(cwd),
            *env_named_reads,
            tool_config_dir,
            *scanned_trees,
            *read_grants,
        ]
    )
    # An import entry of ASH's interpreter inside the scanned tree, the output
    # directory or another root of the scan (PYTHONPATH=src), and an ASH bin
    # directory there, are the repository's to write and are read as data, not
    # run from: readable, and under sandbox-exec not executable, like the tree.
    # ASH's interpreter and link directories stay executable wherever they are
    # (the other backends do not restrict exec at all). A tool given a
    # staged copy, which reads none of the scan's trees, does not read such an
    # entry either: hidden with the tree it sits in, the policy would give it
    # back as a listed path.
    from automated_security_helper.utils.scanned_tree import is_inside_tree

    in_tree_data = [
        entry
        for entry in ash_data_entries
        if any(is_inside_tree(entry, tree) for tree in trees)
    ]
    if requirements.staged_input_only:
        hidden = {os.path.realpath(p) for p in in_tree_data}
        read_only = [p for p in read_only if os.path.realpath(p) not in hidden]
    not_programs = {
        os.path.realpath(p) for p in [*scan_data, *_DATA_SYSTEM_PATHS, *in_tree_data]
    }
    # A path the scanner's own declaration names (``read_paths``, which the
    # scanned repository can write when the paths follow its options) that sits
    # inside the scan's data is data too, so sandbox-exec does not give exec back
    # beneath it after the tree's deny. A tool prefix inside the tree (a venv in
    # the scanned project that ASH itself runs from) and an operator's
    # ``extra_read_paths`` entry there stay executable, as they were: a declared
    # path that names the operator's entry exactly is the operator's grant, not
    # the repository's.
    scan_data_real = [Path(os.path.realpath(p)) for p in scan_data]
    operator_reads = {
        os.path.realpath(p)
        for p in (_expand(e) for e in extra_read_paths)
        if p is not None
    }
    declared_in_data = (
        {
            os.path.realpath(p)
            for p in screened_declared_read
            if _inside_any(Path(os.path.realpath(p)), scan_data_real)
        }
        - {os.path.realpath(p) for p in tool_prefixes}
        - operator_reads
    )
    not_programs |= declared_in_data
    executable = [p for p in read_only if os.path.realpath(p) not in not_programs]

    extra_env: Dict[str, str] = {}
    if not network:
        # uv otherwise tries the index before using what it has cached, and fails
        # with a DNS error rather than running the tool.
        extra_env["UV_OFFLINE"] = "1"
    # Where uv looks for its tools, interpreters and cache inside the sandbox.
    extra_env.update(_uv_environment([*read_only, *cache], uv_cache, uv_data))
    # uv opens its cache for writing on every run, to lock it, so it cannot use one
    # it may only read: where the host cache is read-only, uv gets a private one.
    cache_env = tuple(dict.fromkeys(("UV_CACHE_DIR", *requirements.cache_env)))

    return SandboxPolicy(
        scanner_name=scanner_name,
        read_only=tuple(read_only),
        writable=tuple(writable),
        cache=tuple(cache),
        network=network,
        home=real_home,
        cwd=cwd.absolute() if cwd else None,
        env_prefixes=tuple(declared_prefixes),
        env_names=tuple(declared_names),
        extra_env=extra_env,
        cache_env=cache_env,
        executable=tuple(executable),
        scan_data=tuple(scan_data),
        system_trust_roots=requirements.system_trust_roots,
        sandbox_exec_env=dict(requirements.sandbox_exec_env),
        unpack_dir_env=requirements.unpack_dir_env,
        uv_tool_locks=tuple(_uv_tool_locks(uv_data)),
        unread=tuple(unread),
        environment=listed_environment,
    )
