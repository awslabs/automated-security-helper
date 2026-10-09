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
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


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
            its cache still can. A cache that is only read, such as a vulnerability
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


#: The baseline environment allowlist. Exact names, then prefixes. Anything else in
#: the parent environment -- AWS_*, GITHUB_TOKEN, *_PASSWORD -- is dropped.
BASE_ENV_NAMES = frozenset(
    {
        "PATH",
        "LANG",
        "LANGUAGE",
        "TERM",
        "TZ",
        "NO_COLOR",
        "FORCE_COLOR",
        "COLUMNS",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "VIRTUAL_ENV",
        "JAVA_HOME",
        "GEM_HOME",
        "GEM_PATH",
        "SYSTEMROOT",
    }
)
BASE_ENV_PREFIXES = ("LC_", "ASH_", "UV_", "PYTHON")
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
PROXY_ENV_NAMES = frozenset(
    {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"}
)

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
    (the source tree, the output directory, the scan target and the working
    directory), which stays non-executable even where a tool path contains it, so a
    repository checked out under ``/opt`` cannot have its own binaries run.
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

    @property
    def results_dir(self) -> Path:
        """The scanner's results directory, the one writable path."""
        return self.writable[0]

    def filter_env(self, env: Mapping[str, str]) -> Dict[str, str]:
        """Reduce ``env`` to the allowlist, then point HOME inside."""
        prefixes = BASE_ENV_PREFIXES + tuple(self.env_prefixes)
        named = set(self.env_names)
        kept = {}
        for key, value in env.items():
            if key in named:
                kept[key] = value
                continue
            allowed = (
                key in BASE_ENV_NAMES
                or key.startswith(prefixes)
                or (self.network and key in PROXY_ENV_NAMES)
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


def _uv_directories() -> List[Path]:
    """uv's tool and interpreter directories, without starting uv.

    ``uv tool run`` resolves the tool's environment from its cache and runs it with a
    uv-managed interpreter, so both have to be visible. Computed from uv's documented
    environment variables and XDG defaults rather than by running ``uv tool dir``:
    this runs for every scanner spawn, and a spawn here would itself need wrapping.
    """
    home = Path.home()
    data = Path(os.environ.get("XDG_DATA_HOME") or home / ".local" / "share")
    candidates = [
        _expand(os.environ["UV_TOOL_DIR"]) if os.environ.get("UV_TOOL_DIR") else None,
        _expand(os.environ["UV_PYTHON_INSTALL_DIR"])
        if os.environ.get("UV_PYTHON_INSTALL_DIR")
        else None,
        data / "uv" / "tools",
        data / "uv" / "python",
    ]
    found = _existing(candidates)
    # Each installed tool's environment runs on the interpreter it was created
    # with, which need not be in uv's default python directory: a tool installed
    # with UV_PYTHON_INSTALL_DIR set elsewhere keeps pointing there. Its
    # bin/python symlink names it.
    for tools_dir in [p for p in found if p.name == "tools" or p == candidates[0]]:
        try:
            entries = list(tools_dir.iterdir())
        except OSError:
            continue
        for tool in entries:
            interpreter = tool / "bin" / "python"
            if not interpreter.is_symlink():
                continue
            real = Path(os.path.realpath(interpreter))
            prefix = real.parent.parent
            # Only an interpreter installation: a prefix with a lib/python*
            # directory, never a broad directory a link happens to point into.
            if (
                real.parent.name in _BIN_DIR_NAMES
                and any(prefix.glob("lib/python*"))
                and not _broader_than_a_tool(prefix)
            ):
                found.append(prefix)
    return _existing(found)


def _uv_tool_locks() -> List[Path]:
    """The ``.lock`` file of uv's tools directory, where one exists."""
    home = Path.home()
    data = Path(os.environ.get("XDG_DATA_HOME") or home / ".local" / "share")
    tool_dir = (
        _expand(os.environ["UV_TOOL_DIR"])
        if os.environ.get("UV_TOOL_DIR")
        else data / "uv" / "tools"
    )
    if tool_dir is None:
        return []
    lock = tool_dir / ".lock"
    return [lock.absolute()] if lock.is_file() and not lock.is_symlink() else []


def uv_cache_directory() -> Optional[Path]:
    """uv's cache directory, the same way uv resolves it."""
    if os.environ.get("UV_CACHE_DIR"):
        return _expand(os.environ["UV_CACHE_DIR"])
    cache = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return cache / "uv"


_BIN_DIR_NAMES = ("bin", "sbin", "Scripts")


def _inside(path: Path, parent: Path) -> bool:
    try:
        Path(os.path.realpath(path)).relative_to(Path(os.path.realpath(parent)))
        return True
    except ValueError:
        return False


def _path_directories(home: Path) -> List[Path]:
    """Directories on PATH, minus ones that would expose far more than programs.

    Skipped: a relative entry (``.``), ``/``, ``$HOME`` itself, and any entry inside
    ``$HOME`` not named ``bin``, ``sbin`` or ``Scripts``. A PATH entry such as
    ``~/.config/tool`` would otherwise mount a configuration directory, and those
    hold tokens.
    """
    entries = []
    for raw in os.environ.get("PATH", "").split(os.pathsep):
        if not raw or not os.path.isabs(raw):
            continue
        path = Path(raw)
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved in (Path("/"), home.resolve()) or _broader_than_a_tool(path):
            continue
        if _inside(path, home) and path.name not in _BIN_DIR_NAMES:
            continue
        entries.append(path)
    return _existing(entries)


def _broader_than_a_tool(path: Path) -> bool:
    """Whether mounting ``path`` would expose more than one tool installation.

    True for /, for $HOME, for any directory that contains $HOME, and for any
    directory directly under $HOME (~/.local, ~/.cargo): each of those holds
    other files of the user's.
    """
    real = Path(os.path.realpath(path))
    home = Path(os.path.realpath(Path.home()))
    return (
        real == Path("/") or real == home or real in home.parents or real.parent == home
    )


def _symlink_hops(path: Path) -> List[Path]:
    """``path`` and every path its symlink chain passes through, as spelled.

    A venv's ``bin/python`` links to ``/home/me/.local/share/uv/python/.../python3``,
    which may itself pass through a symlinked ``/home/me``. Mounting only the final
    real file leaves the intermediate spellings dangling inside the sandbox, and
    exec fails with ENOENT on a file that exists.
    """
    hops = [path]
    current = path
    for _ in range(40):  # the kernel's own limit on symlink depth
        if not current.is_symlink():
            break
        target = Path(os.readlink(current))
        current = target if target.is_absolute() else current.parent / target
        hops.append(Path(os.path.normpath(current)))
    return hops


def _executable_prefix(argv0: str) -> List[Path]:
    """The executable's directory, and its install prefix when it sits in a bin dir.

    For a script installed by a package manager the interpreter and libraries live
    beside the bin directory (``<prefix>/bin/tool`` with ``<prefix>/lib``), so the
    prefix is what has to be visible, not only the file.
    """
    found = argv0 if os.path.isabs(argv0) else shutil.which(argv0)
    if not found:
        return []
    home = Path.home()
    real_home = Path(os.path.realpath(home))

    def too_broad(prefix: Path) -> bool:
        # A prefix of /, of $HOME, or directly under $HOME (~/.local, ~/.cargo,
        # ~/.toolbox) holds far more than the tool: ~/.local/share carries keyrings
        # and ~/.cargo carries credentials.toml. Deeper prefixes, such as
        # ~/.nvm/versions/node/v22, are a single installation.
        real = Path(os.path.realpath(prefix))
        return real in (Path("/"), real_home) or real.parent == real_home

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
        if parent.name in _BIN_DIR_NAMES or not too_broad(parent):
            if Path(os.path.realpath(parent)) != real_home:
                paths.append(parent)
        if parent.name in _BIN_DIR_NAMES and not too_broad(parent.parent):
            paths.append(parent.parent)
    return _existing(paths)


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
        names = [w for w in words[1:] if not w.startswith("-")]
        if not names:
            return None
        program = shutil.which(names[0]) or ""
    return Path(program) if os.path.isabs(program) else None


def _ash_paths() -> List[Path]:
    """ASH's own package (rule packs and configs it passes to scanners) and Python."""
    from automated_security_helper.utils.subprocess_utils import _bin_path

    package_dir = Path(__file__).resolve().parents[2]
    # The directory holding the package too: importlib lists each sys.path entry, and
    # Landlock refuses that listing unless the entry itself is readable. That is
    # site-packages for an installed ASH, or the checkout for an editable one.
    import_root = package_dir.parent
    if Path(os.path.realpath(import_root)) == Path(os.path.realpath(Path.home())):
        import_root = package_dir
    # And every directory on sys.path. A worker started with this interpreter
    # (detect-secrets, cdk-nag) imports from the same entries, and an editable
    # install's .pth file adds entries outside site-packages. Landlock denies an
    # entry it was not given, so the import fails with ModuleNotFoundError.
    #
    # Inside $HOME only entries that belong to the interpreter (under sys.prefix or
    # sys.base_prefix, which is where uv keeps managed Pythons and venvs) or that
    # hold the ASH package are added: a PYTHONPATH pointing at ~/anything would
    # otherwise mount that directory for every scanner.
    real_home = Path(os.path.realpath(Path.home()))
    interpreter_roots = {
        Path(os.path.realpath(p))
        for p in (sys.prefix, sys.base_prefix, sys.exec_prefix)
    } | {Path(os.path.realpath(import_root))}

    def _importable(entry: str) -> bool:
        if not entry or not os.path.isabs(entry) or not os.path.isdir(entry):
            return False
        real = Path(os.path.realpath(entry))
        if _broader_than_a_tool(real):
            return False
        if real_home not in real.parents:
            return True
        return any(real == root or root in real.parents for root in interpreter_roots)

    import_path = [Path(entry) for entry in sys.path if _importable(entry)]
    return _existing(
        [
            package_dir,
            import_root,
            *import_path,
            Path(sys.prefix),
            Path(sys.base_prefix),
            Path(sys.exec_prefix),
            Path(os.path.realpath(sys.executable)).parent.parent,
            *[hop.parent for hop in _symlink_hops(Path(sys.executable))],
            _bin_path(),
        ]
    )


def _refuse_symlinked_results_dir(output_dir: Path, results_dir: Path) -> None:
    """Refuse a results directory reached through a symlink below the output dir.

    The default output directory is inside the source tree, so the scanned
    repository can commit ``.ash/ash_output/scanners/<name>`` as a symlink to any
    directory the user can write. Mounting the results directory writable would
    then hand the scanner that directory.
    """
    output_dir = Path(os.path.abspath(output_dir))
    results_dir = Path(os.path.abspath(results_dir))
    try:
        relative = results_dir.relative_to(output_dir)
    except ValueError:
        relative = None
    if relative is None:
        components = [results_dir]
    else:
        components = []
        current = output_dir
        for part in relative.parts:
            current = current / part
            components.append(current)
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

    Refused, with the path in the message: any component from below the source
    directory down to the output directory that is a symlink; the output
    directory itself if it is one, wherever it is; and an output directory inside
    the source tree whose real path is not the source directory's real path plus
    the rest of its spelling (a ``..`` after a symlink resolves elsewhere than it
    reads). Components at and above the source directory are the operator's own
    spelling (a home directory that links elsewhere, macOS's ``/var``) and are not
    examined, so an ordinary output directory outside the tree is unaffected.
    """
    source = Path(os.path.abspath(source_dir))
    spelled = Path(output_dir).absolute()

    def refuse_link(path: Path) -> None:
        if path.is_symlink():
            raise SandboxUnavailable(
                f"the output directory path {path.as_posix()} is a symlink, so "
                "mounting the output directory would expose wherever it points"
            )

    # Walked as spelled, `..` included, so a link that a later `..` would step
    # back out of is still seen.
    current = Path(spelled.anchor)
    for part in spelled.parts[1:]:
        if part == "..":
            current = current.parent
            continue
        if part in ("", "."):
            continue
        current = current / part
        if source in current.parents:
            refuse_link(current)
    refuse_link(current)
    lexical = Path(os.path.abspath(spelled))
    if source in lexical.parents:
        expected = Path(os.path.realpath(source)) / lexical.relative_to(source)
        actual = Path(os.path.realpath(lexical))
        if actual != expected:
            raise SandboxUnavailable(
                f"the output directory {lexical.as_posix()} resolves to "
                f"{actual.as_posix()}, not where its path inside the source "
                "directory reads, so mounting it would expose another directory"
            )


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
) -> SandboxPolicy:
    """The policy one scanner gets for one spawn.

    Args:
        network_scanners: When not None, replaces every scanner's declared network
            need: only scanners named here get a network (still never under offline).
        network_limit: When not None, a scanner not named here gets no network
            whatever the rest says. Set from a config file in the scanned tree,
            which may take network away but not grant it.
    """
    real_home = Path.home()
    if network_scanners is None:
        network = requirements.network and not requirements.network_requires_grant
    else:
        network = scanner_name in set(network_scanners)
    if network_limit is not None and scanner_name not in set(network_limit):
        network = False
    if offline:
        network = False

    read_only = _existing(
        [Path(p) for p in SYSTEM_READ_PATHS]
        + _path_directories(real_home)
        + _uv_directories()
        + _ash_paths()
        + _executable_prefix(argv0)
        + [_expand(p) for p in requirements.read_paths]
        + [_expand(p) for p in extra_read_paths]
        + [source_dir, output_dir, scan_target, _readable_cwd(cwd)]
    )

    cache = _existing(
        [uv_cache_directory()] + [_expand(p) for p in requirements.cache_paths]
    )

    refuse_symlinked_output_dir(source_dir, output_dir)
    _refuse_symlinked_results_dir(output_dir, results_dir)
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

    scan_data = _existing([source_dir, output_dir, scan_target, cwd])
    not_programs = {os.path.realpath(p) for p in [*scan_data, *_DATA_SYSTEM_PATHS]}
    executable = [p for p in read_only if os.path.realpath(p) not in not_programs]

    extra_env: Dict[str, str] = {}
    if not network:
        # uv otherwise tries the index before using what it has cached, and fails
        # with a DNS error rather than running the tool.
        extra_env["UV_OFFLINE"] = "1"
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
        env_prefixes=tuple(requirements.env_prefixes),
        env_names=tuple(requirements.env_names),
        extra_env=extra_env,
        cache_env=cache_env,
        executable=tuple(executable),
        scan_data=tuple(scan_data),
        system_trust_roots=requirements.system_trust_roots,
        sandbox_exec_env=dict(requirements.sandbox_exec_env),
        unpack_dir_env=requirements.unpack_dir_env,
        uv_tool_locks=tuple(_uv_tool_locks()),
    )
