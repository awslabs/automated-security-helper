"""Sandbox backends: turn a :class:`SandboxPolicy` into a command line.

Each backend answers two questions. ``probe()`` says whether it can actually start a
sandbox on this machine, by starting one, because "the binary is on PATH" is not the
same thing: Ubuntu 24.04 ships a bwrap that AppArmor stops from creating a user
namespace unless it is the packaged one, a kernel can be built without Landlock, and
inside a container firejail can exit 0 having run its command with no sandbox at all.
``plan()`` returns the argv to run, the environment to pass, and anything to clean up
when the process has exited.

See docs/content/docs/scanner-sandbox.md for what each backend can and cannot hide.
"""

from __future__ import annotations

import errno
import fnmatch
import json
import os
import platform
import shutil
import subprocess  # nosec B404 - probing and wrapping sandboxed scanner processes is this module's purpose
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.process_env import startup_environ
from automated_security_helper.utils.sandbox.policy import (
    CA_BUNDLE_DIR_ENV_NAMES,
    CA_BUNDLE_ENV_NAMES,
    SandboxPolicy,
    SandboxUnavailable,
    _distinct_home,
    _exposes_a_home,
    _home_link_targets,
    _passwd_home,
    parse_environment,
)

PROBE_TIMEOUT_SECONDS = 20

#: The shared temporary directory firejail's --private-tmp and /tmp whitelists cover.
_TMP_ROOT = Path("/tmp")  # nosec B108 - compared against, never written

#: The Landlock wrapper, which bwrap and firejail also run inside their sandbox for
#: its seccomp socket filter alone (``--socket-filter``).
LANDLOCK_EXEC = Path(__file__).with_name("landlock_exec.py")


def _with_socket_filter(argv: Sequence[str]) -> List[str]:
    """``argv`` started through landlock_exec.py's Unix-socket filter.

    For bwrap and firejail, whose namespaces and mounts leave Unix sockets
    reachable: one in any directory they mount (the Nix daemon's socket is under
    /nix, and firejail shows nearly everything outside $HOME, /run included), a
    datagram socket by path from a socketpair, and, when the scanner has a
    network, every abstract socket in the host's network namespace (X11, some
    session buses). The filter refuses socket(AF_UNIX), datagram socketpairs and
    io_uring, as it does under Landlock. It does not refuse IP sockets even
    without a network: the private network namespace already confines those, so
    a tool may keep using its own loopback.

    Runs ASH's interpreter, which every policy mounts, with -I so nothing in the
    working directory (the scanned tree) or the environment is imported.
    """
    return [
        sys.executable,
        "-I",
        str(LANDLOCK_EXEC),
        "--socket-filter",
        "unix",
        "--",
        *argv,
    ]


def _private_caches(
    policy: SandboxPolicy, child_env: Dict[str, str], overlaid: Sequence[Path] = ()
) -> Tuple[List[Callable[[], None]], List[Path]]:
    """Give the tools that must write a cache a private one.

    Only bwrap's throwaway overlay lets a scanner write a host cache without the
    write reaching the host. Every other backend mounts ``policy.cache`` read-only
    and calls this, which points each variable in ``policy.cache_env``
    (``UV_CACHE_DIR``, and what the scanner declares) at its own empty directory:
    a fresh directory under the results directory, the one place the scanner may
    write, removed once the process has exited. A tool redirected this way starts
    from an empty cache, so online it fetches what it needs and offline it has
    nothing cached. A cache that is only read, such as a scanner's database,
    is not redirected and stays read-only.

    bwrap calls this too when some of the caches, not all, took an overlay (a
    cache on a filesystem that refuses to be an overlay's lower layer is mounted
    read-only; see BwrapBackend._overlay_over). ``overlaid`` names the caches,
    resolved, that got one: a variable whose value in ``child_env`` names a path
    on or under one of them is left alone, since what the tool writes there is the
    overlay's and goes with it, and only the variables for the read-only caches
    are redirected. A variable with no value in ``child_env`` names a cache this
    function cannot place, so it is redirected as before.

    Returns the cleanup step that removes the directory and, for
    ``SpawnPlan.private_dirs``, the directory itself, so the spawn's sweep of the
    results directory passes it over (both empty when nothing is redirected).
    """
    redirected = [
        name
        for name in policy.cache_env
        if not _names_a_path_under(child_env.get(name), overlaid)
    ]
    if not redirected:
        return [], []
    root = Path(tempfile.mkdtemp(prefix=".sandbox-cache-", dir=policy.results_dir))
    try:
        for name in redirected:
            # npm reads npm_config_* without regard to case, so a NPM_CONFIG_CACHE
            # passed through from the parent would compete with the redirect.
            for key in [
                k for k in child_env if k.lower() == name.lower() and k != name
            ]:
                del child_env[key]
            private = root / name.lower()
            private.mkdir()
            child_env[name] = private.as_posix()
    except BaseException:
        # Nothing is returned, so no cleanup step would remove the directory
        # made above: it is removed here, and the results directory is left as it
        # was (two names that differ only in case raise FileExistsError here).
        shutil.rmtree(root, ignore_errors=True)
        raise
    return [lambda: shutil.rmtree(root, ignore_errors=True)], [root]


def _names_a_path_under(value: Optional[str], roots: Sequence[Path]) -> bool:
    """Whether ``value``, a variable's value, names a path at or under one of
    ``roots`` (resolved paths) once resolved itself; False for no value."""
    if not value or not roots:
        return False
    named = _real(Path(value))
    return any(named == root or root in named.parents for root in roots)


@dataclass
class SpawnPlan:
    """What to hand ``subprocess`` in place of the scanner's own argv and env."""

    argv: List[str]
    env: Dict[str, str]
    cleanup: List[Callable[[], None]] = field(default_factory=list)
    #: Whether the spawner starts the child as the leader of a session of its
    #: own (``Popen(start_new_session=True)``). A wrapper that calls setsid
    #: itself (bwrap, the sandbox-exec plan) leaves it False; firejail does not,
    #: so its plan sets it, and the stop paths' group signals then reach every
    #: process the tool starts rather than the wrapper alone.
    start_new_session: bool = False
    #: The directories the backend made for this spawn under a root the scanner
    #: may write (the private cache of ``_private_caches``, under the results
    #: directory). The spawn's sweep (scope._plan_spawn, fs_guard.sweep_writable)
    #: passes over them: a step in ``cleanup`` removes each whole, and what they
    #: hold (uv links its cache entries) is ASH's own, not something the scanner
    #: left to be counted and removed as a scanner's.
    private_dirs: List[Path] = field(default_factory=list)

    def run_cleanup(self) -> None:
        """Run each cleanup once; later calls do nothing."""
        pending, self.cleanup = self.cleanup, []
        for fn in pending:
            try:
                fn()
            except Exception as e:  # pragma: no cover - best effort
                # The exception can name a path an option chose: redacted
                # with the active scope's env-read values before it is logged.
                from automated_security_helper.utils.sandbox.scope import (
                    scope_shown_text,
                )

                ASH_LOGGER.debug(scope_shown_text(f"Sandbox cleanup failed: {e}"))


#: The errnos that name a resource refused for now: the system had no process or
#: memory to give, or the resource was busy. EWOULDBLOCK is EAGAIN on Linux and
#: a different number elsewhere.
_TRANSIENT_PROBE_ERRNOS = frozenset({errno.EAGAIN, errno.EWOULDBLOCK, errno.EBUSY})


def _is_transient_probe_error(error: BaseException) -> bool:
    """Whether a probe that raised ``error`` met a condition that may pass.

    A probe process that outran its timeout, or an OS error whose errno says
    the resource was refused for now. By the exception's type and errno, not by
    its text: a reworded message, or a tool's own output saying "timed out",
    names nothing about the next request.
    """
    if isinstance(error, subprocess.TimeoutExpired):
        return True
    return isinstance(error, OSError) and error.errno in _TRANSIENT_PROBE_ERRNOS


class SandboxBackend:
    """Base class. Subclasses set ``name`` and implement ``_probe`` and ``plan``."""

    name = ""
    platforms: Tuple[str, ...] = ()

    @property
    def caches_are_throwaway(self) -> bool:
        """Whether a scanner's writes to its declared caches are discarded with it.

        False unless the backend mounts caches through a throwaway overlay, in which
        case each spawn writes its own copy and nothing it writes reaches the host.
        """
        return False

    #: True when the last ``probe()`` failed through a passing condition: the probe
    #: process outran its timeout, or the system refused a resource for now
    #: (``_is_transient_probe_error``). Set where the exception is caught, because
    #: the reason is text from then on; a reason that is only an exit status or a
    #: missing program never sets it. The scope reads it to decide how long to
    #: remember the refusal.
    probe_was_transient = False

    def probe(self) -> Optional[str]:
        """None when the backend works here, otherwise why it does not."""
        self.probe_was_transient = False
        if platform.system().lower() not in self.platforms:
            return f"{self.name} is not available on {platform.system()}"
        try:
            return self._probe()
        except Exception as e:
            self.probe_was_transient = _is_transient_probe_error(e)
            return f"{self.name} probe failed: {e}"

    def _probe(self) -> Optional[str]:
        raise NotImplementedError

    def plan(
        self, argv: Sequence[str], env: Mapping[str, str], policy: SandboxPolicy
    ) -> SpawnPlan:
        raise NotImplementedError


def _other_home(policy: SandboxPolicy) -> Optional[Path]:
    """The passwd entry's home when it is a directory other than ``policy.home``."""
    return _distinct_home(policy.home, _passwd_home())


def _home_to_hide(policy: SandboxPolicy) -> Optional[Path]:
    """``policy.home`` resolved, or None when it is a filesystem root.

    The policy hands a root as the home when there is no usable one (an empty,
    relative or unset HOME; ``policy._policy_home``) and for a HOME of "/" (a
    container's). A root names no home: hidden as one, bwrap mounted a tmpfs over
    the sandbox's whole root and sandbox-exec denied reading everything the policy
    did not list.
    """
    home = _real(policy.home)
    return None if home == Path(home.anchor) else home


def _homes_to_hide(policy: SandboxPolicy) -> List[Path]:
    """The home directories a backend hides, resolved: HOME's and the passwd entry's."""
    homes = [h for h in [_home_to_hide(policy)] if h is not None]
    other = _other_home(policy)
    return homes + ([other] if other is not None else [])


def _hidden_around(
    root: Path,
    shown: Sequence[Path],
    homes: Sequence[Path] = (),
    seen: Optional[Set[Path]] = None,
) -> List[Path]:
    """What to blacklist so that ``root`` shows only ``shown`` and the way to them.

    firejail whitelists only inside the home and a few system directories, so a
    directory a link at the top of a home names (policy._home_link_targets) is hidden
    with --blacklist: all of it, or, where the policy grants paths inside it, every
    entry beside the way to those paths. A link among the entries is not blacklisted
    itself, since firejail would blacklist the directory it points to; the directory
    (or file) it names is hidden the same way as ``root`` is, unless it is one
    _home_link_targets leaves out or a home. The links followed are those at the top
    of every directory that is hidden or walked here, whether it is blacklisted whole
    or kept for a path inside it, and the ones naming a directory above ``root``
    count too. A directory the policy grants whole is not searched for links: they
    are inside what the policy itself reads, and neither is a path at or below one
    it grants, so a file inside the scanned tree is not blacklisted. Nothing in /tmp is hidden, and no
    link target in a pseudo-filesystem (``_home_link_targets`` leaves it out) is followed. ``homes``
    are the homes ``root`` was
    reached from; ``seen`` holds the directories already handled, each is handled
    once, so links among directories cannot loop.
    """
    seen = set() if seen is None else seen
    if root in seen:
        return []
    seen.add(root)
    if _is_within(root, _real(_TMP_ROOT)):
        # /tmp is covered by --private-tmp and the /tmp whitelists, whichever link
        # led here.
        return []
    if any(root == p or _is_within(root, p) for p in shown):
        # The policy grants this path, or a directory holding it, for the scan.
        return []
    inside = [p for p in shown if _is_within(p, root)]
    hidden: List[Path] = []
    # Where links are looked for: the top of each directory this call hides or walks,
    # so that what a link inside it names is found whatever is done with the
    # directory itself.
    searched: List[Path] = [root]
    entries: List[Path] = []
    if not inside:
        hidden.append(root)
    else:
        try:
            entries = sorted(root.iterdir())
        except OSError:
            hidden.append(root)
    for entry in entries:
        if entry.is_symlink():
            continue
        if any(p == entry or _is_within(p, entry) for p in inside):
            hidden += _hidden_around(entry, shown, homes, seen)
        else:
            hidden.append(entry)
            searched.append(entry)
    for target in _home_link_targets(searched, files=True, ancestors=True):
        if target in seen or any(
            target == home or home in target.parents or target in home.parents
            for home in homes
        ):
            continue
        hidden += _hidden_around(target, shown, homes, seen)
    return hidden


def _probe_env() -> Dict[str, str]:
    """The environment a probe runs with: PATH, and the home directory.

    The home is this process's usable one (``core.constants.usable_home``), as
    HOME, or USERPROFILE on Windows, so that ``~`` in the probe is the operator's.
    With no usable home (an empty or relative HOME) the probe gets none: a
    relative one would be read against the probe's working directory.
    """
    from automated_security_helper.core.constants import usable_home

    env = {"PATH": os.environ.get("PATH", "")}
    home = usable_home()
    if home is not None:
        env["USERPROFILE" if os.name == "nt" else "HOME"] = str(home)
    return env


def _probe_process(
    argv: Sequence[str], env: Optional[Mapping[str, str]] = None
) -> "subprocess.CompletedProcess[str]":
    """Run ``argv`` with its output captured, as a probe.

    Plain subprocess.run, as for every probe in this module: bounded by
    PROBE_TIMEOUT_SECONDS, one running when an MCP server stops ends on its own
    soon after (subprocess_utils.run_ended_with_the_server is for longer runs).
    The output is read as text with undecodable bytes replaced: a probe's
    answer is a reason to show, and a byte in it that is not text (a path in
    bwrap's own words, say) must not raise out of the probe and fail the spawn
    whose plan asked.
    """
    return subprocess.run(  # nosec B603 - fixed argv built in this module
        list(argv),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=PROBE_TIMEOUT_SECONDS,
        env=dict(env) if env is not None else _probe_env(),
        check=False,
    )


def _exit_failure(result: "subprocess.CompletedProcess[str]") -> Optional[str]:
    """None if ``result`` exited 0, otherwise its last line of output as the reason.

    The last non-blank line of stderr, else of stdout: a stderr holding only
    whitespace is not output, so the failure text a program wrote to stdout is
    read instead of reporting "no output".
    """
    if result.returncode == 0:
        return None
    for output in (result.stderr, result.stdout):
        lines = [line.strip() for line in (output or "").splitlines() if line.strip()]
        if lines:
            return f"exit {result.returncode}: {lines[-1]}"
    return f"exit {result.returncode}: no output"


def _probe_run(
    argv: Sequence[str], env: Optional[Mapping[str, str]] = None
) -> Optional[str]:
    """Run ``argv``; None if it exited 0, otherwise its stderr as the reason."""
    return _exit_failure(_probe_process(argv, env))


def _sandbox_program(name: str) -> Optional[str]:
    """A program the sandbox itself runs, never one from the scanned tree or the cwd.

    Not ``shutil.which``: with an empty or ``.`` PATH entry that answers from the
    working directory, which is usually the repository being scanned, and the
    sandbox's own programs decide what a scanner can reach. See
    ``subprocess_utils.find_trusted_executable``.
    """
    from automated_security_helper.utils.subprocess_utils import (
        find_trusted_executable,
    )

    return find_trusted_executable(name)


def _true() -> str:
    return _sandbox_program("true") or "/bin/true"


def _real(path: Path) -> Path:
    return Path(os.path.realpath(path))


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


#: The CA-bundle entries already reported as unspellable, as (variable, entry). A
#: backend that cannot write an entry in its options leaves it out at every spawn;
#: the warning is for the first one.
_ca_unspelled_warned: Set[Tuple[str, str]] = set()


def _link_inside_a_home(spelling: Path, homes: Sequence[Path]) -> bool:
    """Whether ``spelling`` passes through a symlink that lives inside one of ``homes``.

    ``spelling`` is the path as the operator wrote it. A backend that hides the home
    shows what the link names by the resolved path alone, so the link itself, a
    ``~/.config/corp/ca.pem`` pointing at ``/etc/ssl/certs/corp.pem``, is missing
    inside the sandbox and the scanner's open of the written path fails. A path the
    host cannot examine counts as having no such link.
    """
    try:
        links = _links_to_recreate(spelling)
    except OSError:
        return False
    return any(_is_within(where, home) for where, _ in links for home in homes)


def _operator_ca_reads(
    policy: SandboxPolicy,
    child_env: Mapping[str, str],
    spell: Optional[Callable[[Path], str]] = None,
    recreates_links: bool = False,
    warns_of_hidden_links: bool = False,
) -> List[Path]:
    """The files and directories the operator's CA-bundle settings name, as spelled.

    Every backend that hides the home directory gives these back as read-only, so
    a bundle kept under the home (``~/corp-ca.pem``) is readable inside the sandbox
    on bwrap, firejail and Landlock as it is under sandbox-exec. Read for the
    variables the policy's environment list passes: ``SSL_CERT_FILE``,
    ``REQUESTS_CA_BUNDLE``, ``CURL_CA_BUNDLE`` and ``NODE_EXTRA_CA_CERTS`` name a
    file, ``SSL_CERT_DIR`` names directories joined with the path separator.

    The grant is for the operator's value alone: the one in the environment ASH
    started with (``process_env.startup_environ``), not the live one, because
    scanner threads change the environment while others spawn and a value one of
    them set is not the operator's; or one the operator wrote as a ``NAME=value``
    entry of the environment list. A value the spawn's environment carries from
    elsewhere is passed through like every listed variable and opens nothing. Left
    out: a relative entry, one that does not exist, a directory that is, holds or
    sits above a home directory (it would expose far more than the directory the
    operator meant, so it is warned about), and anything inside a path the policy
    already lists, which the spawn sees.

    ``spell`` is the backend's way of writing a path in its options (it raises
    SandboxUnavailable for one it cannot write). An entry it refuses is left out
    with a warning, once, rather than refusing every spawn: the grant is a
    convenience, and the setting is still passed through as it was without it.

    An entry written through a symlink that sits inside a home (a dotfile-managed
    ``~/.config/corp/ca.pem`` pointing at ``/etc/ssl/certs/corp.pem``) is kept even
    when what it names is visible already, if ``recreates_links``: the backend
    writes the link into the hidden home from the spelling, which it can do only
    for an entry it is given. A backend that cannot write a link
    (``warns_of_hidden_links``) grants what the link names and warns, once, that
    the written path stays unreadable.
    """
    listed, configured = parse_environment(policy.environment)
    started = startup_environ()
    homes = _homes_to_hide(policy)
    seen = [_real(p) for p in [*policy.read_only, *policy.cache, *policy.writable]]
    reads: List[Path] = []
    for name in CA_BUNDLE_ENV_NAMES:
        value = child_env.get(name)
        if name not in listed or not value:
            continue
        if value != started.get(name) and value != configured.get(name):
            continue
        is_directory = name in CA_BUNDLE_DIR_ENV_NAMES
        for entry in value.split(os.pathsep) if is_directory else [value]:
            if not entry or not os.path.isabs(entry):
                continue
            real = _real(Path(entry))
            # os.path answers False for a path it cannot stat. Path.is_dir and
            # Path.is_file raise PermissionError on Python 3.10 to 3.12 for a path
            # below a directory this user cannot search, which would fail every
            # spawn over a setting that only grants a convenience.
            if is_directory:
                if not os.path.isdir(real):
                    continue
                if _exposes_a_home(real, homes):
                    ASH_LOGGER.warning(
                        f"${name} names {entry!r}, which is not readable in the "
                        "scanner sandbox: it would expose far more than one "
                        "directory. Point it at the directory of certificates."
                    )
                    continue
            elif not os.path.isfile(real):
                continue
            # Visible already, unless a home carved out of the path that shows it
            # (a HOME under /opt) is where it sits.
            in_a_home = any(real == h or _is_within(real, h) for h in homes)
            hidden_link = _link_inside_a_home(Path(entry), homes)
            if hidden_link and warns_of_hidden_links:
                if (f"{name} link", entry) not in _ca_unspelled_warned:
                    _ca_unspelled_warned.add((f"{name} link", entry))
                    ASH_LOGGER.warning(
                        f"${name} names {entry!r}, a symlink inside the home "
                        "directory. What it points to is readable in the scanner "
                        "sandbox, the link is not, so a scanner that opens the "
                        "written path will not find it. Point it at the file itself."
                    )
            if (
                not in_a_home
                and not (hidden_link and recreates_links)
                and any(real == p or _is_within(real, p) for p in seen)
            ):
                continue
            if spell is not None:
                try:
                    spell(real)
                except SandboxUnavailable as e:
                    if (name, entry) not in _ca_unspelled_warned:
                        _ca_unspelled_warned.add((name, entry))
                        ASH_LOGGER.warning(
                            f"${name} names {entry!r}, which is not readable in "
                            f"the scanner sandbox: {e}"
                        )
                    continue
            if Path(entry) not in reads:
                reads.append(Path(entry))
    return reads


def _carved_homes(policy: SandboxPolicy) -> List[Path]:
    """The homes a granted path that holds one must not reopen, resolved.

    HOME's directory, the passwd entry's when it is another one, and each directory
    or file a link at the top of either names (``policy._home_link_targets``), which
    is part of that home. The filesystem root is left out: a HOME of "/" (a
    container's) names no home, and as one it would sit inside no path and take
    every other home's place.
    """
    homes = _homes_to_hide(policy)
    return homes + _home_link_targets(homes, files=True)


def _around(paths: Sequence[Path], homes: Sequence[Path]) -> List[Path]:
    """``paths``, resolved, with each of ``homes`` carved out of the ones holding it.

    For a backend whose rules only grant (Landlock): a rule on /opt reads everything
    beneath it, a home at /opt/app/home included, and no rule takes a subtree back.
    The policy keeps a system read path that holds a home (``policy._under_home``:
    dropping /opt for a HOME of /opt/app/home would take away a tool's installation
    prefix), so such a path is replaced here by what sits beside the way to the
    home: its entries, and the entries of each directory on the way, all but the
    home, any entry that resolves to or into a home, and any symlink. A link is not
    granted by what it names: granted so, a link beside the way (``/opt/x ->
    /srv/secrets``, or to "/", which a scanned tree holding the home writes itself)
    would grant its target; Landlock checks the resolved path, so the link stays
    usable where its target is granted on its own, and _hidden_around passes links
    over the same way. A path that is a home, or sits inside one, is the policy's
    own grant (the scanned tree under ~, a cache it lists) and is kept as it is. A
    directory on the way that cannot be listed is left out whole, nothing beneath
    it granted, rather than the home.
    """
    kept: List[Path] = []
    seen: Set[Path] = set()

    def beside(root: Path) -> None:
        if root in seen:
            return
        seen.add(root)
        try:
            entries = sorted(root.iterdir())
        except OSError:
            return
        for entry in entries:
            if entry.is_symlink():
                continue
            real = _real(entry)
            if any(real == home or _is_within(real, home) for home in homes):
                continue
            if any(_is_within(home, real) for home in homes):
                beside(real)
            else:
                kept.append(real)

    for path in paths:
        real = _real(path)
        if any(home != real and _is_within(home, real) for home in homes):
            beside(real)
        else:
            kept.append(real)
    return list(dict.fromkeys(kept))


def _symlinked_components(path: Path) -> List[Tuple[Path, str]]:
    """Every component of ``path`` that is a symlink on the host, shallowest first.

    Returned as (where the link lives, with its parent resolved; what it points to).
    Backends that mount real paths recreate these links so the caller's spelling of a
    path -- ``/home/me`` linking to ``/local/home/me``, ``/bin`` to ``usr/bin`` --
    still resolves inside the sandbox.
    """
    links: List[Tuple[Path, str]] = []
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if current.is_symlink():
            links.append((_real(current.parent) / current.name, os.readlink(current)))
    return links


def _links_to_recreate(spelling: Path) -> List[Tuple[Path, str]]:
    """``_symlinked_components`` of ``spelling`` and of every link target it names.

    A link's target can itself pass through another link (``/home/me`` ->
    ``/local/home/me`` with ``/local`` -> ``/mnt/local``): recreated alone, the
    first link dangled inside the sandbox, since nothing resolved its target's
    own spelling. Each target is walked the same way, as the kernel would walk it
    (a relative target against the directory the link really sits in), until no
    new link is found.
    """
    found: List[Tuple[Path, str]] = []
    seen: Set[Path] = set()
    pending = [spelling]
    while pending:
        path = pending.pop()
        for where, target in _symlinked_components(path):
            if where in seen:
                continue
            seen.add(where)
            found.append((where, target))
            resolved = Path(target) if os.path.isabs(target) else where.parent / target
            pending.append(Path(os.path.normpath(resolved)))
    return found


# ---------------------------------------------------------------------------
# bubblewrap
# ---------------------------------------------------------------------------

_RO, _CACHE, _RW = 1, 2, 3

#: The shared temporary directories every bwrap spawn gets a fresh tmpfs at, by
#: their literal spelling: bwrap creates these directories inside its root, so a
#: host link at either spelling is never recreated over them.
_SHARED_TMPFS: Tuple[Path, ...] = (
    Path("/tmp"),  # nosec B108 - a fresh tmpfs mounted inside the sandbox
    Path("/var/tmp"),  # nosec B108 - a fresh tmpfs inside the sandbox
)

#: The resolver configuration, which systemd-resolved makes a link into /run.
_RESOLV_CONF = Path("/etc/resolv.conf")

#: The bwrap options every probe runs with, after the program's path.
_BWRAP_PROBE_BASE: Tuple[str, ...] = (
    "--unshare-all",
    "--die-with-parent",
    "--ro-bind",
    "/",
    "/",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
)


class BwrapBackend(SandboxBackend):
    name = "bwrap"
    platforms = ("linux",)

    def __init__(self) -> None:
        self._executable: Optional[str] = None
        self._overlay = False
        #: Whether a throwaway overlay mounts over each filesystem (by st_dev) a
        #: cache path was found on, probed once per filesystem; see _overlay_over.
        #: Scanner threads plan at the same time, so the probe of a filesystem and
        #: the record of its answer happen under one lock.
        self._overlay_devices: Dict[int, bool] = {}
        self._overlay_lock = threading.Lock()

    @property
    def caches_are_throwaway(self) -> bool:
        """Whether the probe found overlays supported; a cache on a filesystem that
        refuses to be an overlay's lower layer is still mounted read-only
        (_overlay_over)."""
        return self._overlay

    def _probe(self) -> Optional[str]:
        found = _sandbox_program("bwrap")
        if not found:
            return "bwrap is not installed (install the 'bubblewrap' package)"
        base = [found, *_BWRAP_PROBE_BASE]
        failure = _probe_run(base + [_true()])
        if failure:
            return (
                f"bwrap cannot create a sandbox here ({failure}). Unprivileged user "
                "namespaces may be disabled; on Ubuntu 23.10+ use the packaged bwrap, "
                "whose AppArmor profile allows them"
            )
        failure = _probe_run(base + _with_socket_filter([_true()]))
        if failure:
            return (
                f"bwrap cannot apply the Unix-socket filter in its sandbox ({failure})"
            )
        with tempfile.TemporaryDirectory(prefix="ash-bwrap-probe-") as tmp:
            overlay_failure = _probe_run(
                base + ["--overlay-src", tmp, "--tmp-overlay", tmp, _true()]
            )
        self._overlay = overlay_failure is None
        if not self._overlay:
            ASH_LOGGER.warning(
                "bwrap cannot mount a throwaway overlay here (needs bubblewrap 0.8+ "
                "and Linux 5.11+): scanner caches will be mounted read-only, and uv "
                "and any tool that has to write its cache get an empty private one."
            )
        # Recorded last: a probe that failed leaves plan()'s guard unsatisfied, so
        # a plan on a backend whose probe refused is refused too.
        self._executable = found
        return None

    def _overlay_over(self, real: Path) -> bool:
        """Whether a throwaway overlay mounts over the filesystem ``real`` is on.

        The probe mounted one over a fresh temporary directory, which says the
        kernel and bwrap support overlays at all. overlayfs refuses some
        filesystems as a lower layer (another overlay, some network and FUSE
        filesystems), and a cache on one made every spawn fail at the mount. So
        the first cache path met on each filesystem is tried once, with the
        probe's own command, and the caches on a filesystem that refuses are
        mounted read-only, with a private cache for the tools that write one.
        """
        try:
            device = os.stat(real).st_dev
        except OSError:
            return False
        with self._overlay_lock:
            if device not in self._overlay_devices:
                # A probe that cannot run or does not finish (bwrap gone since the
                # probe, a filesystem that hangs the mount) answers as a refusal:
                # the caches are mounted read-only rather than the spawn failing.
                try:
                    failure = _probe_run(
                        [
                            self._executable or "",
                            *_BWRAP_PROBE_BASE,
                            "--overlay-src",
                            real.as_posix(),
                            "--tmp-overlay",
                            real.as_posix(),
                            _true(),
                        ]
                    )
                except (OSError, subprocess.SubprocessError) as e:
                    failure = f"{type(e).__name__}: {e}"
                self._overlay_devices[device] = failure is None
                if failure:
                    # The path and bwrap's own words can name a value an option
                    # chose: redacted with the active scope's env-read values, as
                    # run_cleanup redacts what it logs.
                    from automated_security_helper.utils.sandbox.scope import (
                        scope_shown_text,
                    )

                    ASH_LOGGER.warning(
                        scope_shown_text(
                            f"bwrap cannot mount a throwaway overlay over "
                            f"{real.as_posix()} ({failure}): the caches on that "
                            "filesystem are mounted read-only, and a tool that has "
                            "to write its cache gets an empty private one."
                        )
                    )
            return self._overlay_devices[device]

    def plan(
        self, argv: Sequence[str], env: Mapping[str, str], policy: SandboxPolicy
    ) -> SpawnPlan:
        if not self._executable:
            raise RuntimeError(f"{self.name}: probe() must succeed before plan()")
        mounts: Dict[Path, int] = {}

        def add(path: Path, mode: int) -> None:
            real = _real(path)
            mounts[real] = max(mounts.get(real, 0), mode)

        for p in policy.read_only:
            add(p, _RO)
        child_env = policy.filter_env(env)
        # The bundle or directory the operator's CA-bundle settings name, readable
        # even where it sits under the home directory the sandbox hides.
        ca_reads = _operator_ca_reads(policy, child_env, recreates_links=True)
        for p in ca_reads:
            add(p, _RO)
        caches_read_only = not self._overlay
        # The caches that did take an overlay, so that _private_caches redirects
        # only the variables of the read-only ones when the two kinds meet in one
        # plan (one cache on a filesystem that refuses, the others not).
        overlaid: List[Path] = []
        for p in policy.cache:
            real = _real(p)
            if self._overlay and self._overlay_over(real):
                add(p, _CACHE)
                overlaid.append(real)
            else:
                caches_read_only = True
                add(p, _RO)
        for p in policy.writable:
            add(p, _RW)
        # uv's tools-directory lock, which `uv tool run` opens read-write before it
        # looks for an installed tool: the one file in the read-only tools
        # directory it may write, as sandbox-exec grants it.
        locks = [_real(p) for p in policy.uv_tool_locks]

        def covered_by_a_bind(path: Path) -> bool:
            return any(
                mounted != Path("/") and path != mounted and _is_within(path, mounted)
                for mounted in mounts
            )

        # (depth, precedence) puts every ancestor ahead of what is mounted inside it,
        # and at one depth the private home tmpfs (precedence 0) ahead of a bind of the
        # same directory, so scanning $HOME itself still shows it, read-only.
        ops: List[Tuple[int, int, List[str]]] = [
            (len(shared.parts), 0, ["--tmpfs", shared.as_posix()])
            for shared in _SHARED_TMPFS
        ]
        # The private home, and the passwd entry's home when HOME names another
        # directory: the scanner is told its home is HOME's, and the passwd home
        # would otherwise stay visible wherever a mounted system path holds it. A
        # home that does not exist on the host and sits inside a read-only bind is
        # left alone: bwrap cannot create the mount point there, and there is
        # nothing to hide; one outside every bind is created in bwrap's own root.
        home = _home_to_hide(policy)
        tmpfs_roots: List[Path] = list(_SHARED_TMPFS)
        for hidden in _homes_to_hide(policy):
            if hidden.is_dir() or not covered_by_a_bind(hidden):
                ops.append((len(hidden.parts), 0, ["--tmpfs", hidden.as_posix()]))
                tmpfs_roots.append(hidden)
        for real, mode in mounts.items():
            if real == Path("/"):
                continue
            src = dst = real.as_posix()
            if mode == _RO:
                args = ["--ro-bind", src, dst]
            elif mode == _CACHE:
                args = ["--overlay-src", src, "--tmp-overlay", dst]
            else:
                args = ["--bind", src, dst]
            ops.append((len(real.parts), mode, args))
        for lock in locks:
            if lock.is_file():
                ops.append(
                    (len(lock.parts), _RW, ["--bind", lock.as_posix(), lock.as_posix()])
                )
        # A directory the tool may not read, inside one mounted to show something
        # else (a checkout under /opt), gets an empty directory over it. Ordered like
        # the home tmpfs: after the mount around it, before what is mounted inside it,
        # such as the results directory. One inside an unread directory that got an
        # empty directory is covered by it; one inside an unread directory that got
        # none (nothing showed it) is not, and gets its own.
        unread = sorted({_real(p) for p in policy.unread}, key=lambda p: len(p.parts))
        emitted: List[Path] = []
        for real in unread:
            covered = any(_is_within(real, outer) for outer in emitted)
            shown = any(
                real != mounted and _is_within(real, mounted) for mounted in mounts
            )
            if real != Path("/") and shown and not covered:
                ops.append((len(real.parts), 0, ["--tmpfs", real.as_posix()]))
                emitted.append(real)
        tmpfs_roots += emitted
        resolver_spelling: List[Path] = []
        if policy.network and _RESOLV_CONF.is_symlink():
            # systemd-resolved: resolv.conf points into /run, which is not mounted.
            # The one file is bound where it really is, in order with the other
            # mounts; its directory holds the resolver's sockets and nothing the
            # tool needs. The link's own chain is recreated below.
            resolver = _real(_RESOLV_CONF)
            if resolver.is_file():
                ops.append(
                    (
                        len(resolver.parts),
                        _RO,
                        ["--ro-bind", resolver.as_posix(), resolver.as_posix()],
                    )
                )
                mounts.setdefault(resolver, _RO)
                resolver_spelling.append(_RESOLV_CONF)
        ops.sort(key=lambda op: (op[0], op[1]))

        cmd: List[str] = [
            self._executable,
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-cgroup-try",
            "--die-with-parent",
            "--new-session",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
        ]
        if not policy.network:
            cmd.append("--unshare-net")
        for _, _, args in ops:
            cmd.extend(args)

        # The binds that show a host path as it is. Not "/": a policy read path of
        # the root is never mounted (above), so it shows nothing, and counted as a
        # bind it made every link look shown and skipped them all. Not the home: a
        # bind of the home sits under its tmpfs at the same depth, and its links
        # are recreated as they always were.
        bound = [p for p in mounts if p != Path("/") and p != home]
        seen_links: Set[Path] = set()
        spellings = (
            list(policy.read_only)
            + list(policy.writable)
            + list(policy.cache)
            + ca_reads
        )
        if policy.cwd:
            spellings.append(policy.cwd)
        spellings.append(policy.home)
        spellings += resolver_spelling

        def shown_by_a_bind(where: Path) -> bool:
            # A link is visible inside the sandbox when the innermost mount that
            # covers its location is a bind of the host; a tmpfs covering it more
            # closely (the private home, the shared temp directories, an empty
            # directory over an unread tree) hides it, and it is recreated there.
            binds = [b for b in bound if _is_within(where, b)]
            if not binds:
                return False
            innermost = max(len(b.parts) for b in binds)
            return not any(
                len(root.parts) > innermost
                for root in tmpfs_roots
                if _is_within(where, root)
            )

        for spelling in spellings:
            for where, target in _links_to_recreate(Path(spelling)):
                if (
                    where in seen_links
                    or where in mounts
                    or where in tmpfs_roots
                    or shown_by_a_bind(where)
                ):
                    continue
                seen_links.add(where)
                cmd.extend(["--symlink", target, where.as_posix()])

        if policy.cwd:
            cmd.extend(["--chdir", _real(policy.cwd).as_posix()])
        cmd.append("--")
        cmd.extend(_with_socket_filter(argv))
        cleanup: List[Callable[[], None]] = []
        private_dirs: List[Path] = []
        if caches_read_only:
            cleanup, private_dirs = _private_caches(policy, child_env, overlaid)
        return SpawnPlan(
            argv=cmd, env=child_env, cleanup=cleanup, private_dirs=private_dirs
        )


# ---------------------------------------------------------------------------
# firejail
# ---------------------------------------------------------------------------


#: The confinement options every firejail spawn gets, ahead of the policy's paths.
#: The probe runs its command under them too, so a firejail that rejects one (an old
#: release, a feature turned off in firejail.config) is unavailable before any scan.
_FIREJAIL_CONFINEMENT: Tuple[str, ...] = (
    "--noprofile",
    "--private-dev",
    "--nonewprivs",
    "--caps.drop=all",
    "--seccomp",
    "--nogroups",
    "--dbus-user=none",
    "--dbus-system=none",
    "--read-only=/",
)

#: Tried before PATH for the probe's command, because --private hides $HOME: a
#: readlink found first in ~/bin or a Nix profile would fail to start inside the
#: sandbox, and firejail would be refused for that.
_SYSTEM_READLINK: Tuple[str, ...] = ("/usr/bin/readlink", "/bin/readlink")

#: Printed by firejail, unless --quiet, when it runs a command without a sandbox.
_FIREJAIL_NO_SANDBOX = "existing sandbox"

#: Characters firejail reads in a path option as a glob (``*``, ``?``, ``[``, ``]``,
#: ``{``, ``}``) or a macro (``~``, ``${HOME}`` and the like), with no way to write
#: them literally; a path holding one names something else to firejail.
_FIREJAIL_PATTERN_CHARACTERS = frozenset("*?[]{}~$")


def _firejail_path(path: Path) -> str:
    """``path`` as a firejail option value, or SandboxUnavailable when it cannot be one.

    firejail expands globs and macros in --whitelist, --blacklist, --read-only
    and --read-write values and offers no escaping, so a path spelled with one of
    those characters (a results directory named ``out[1]``, a home holding ``$``)
    would be read as a pattern: the wrong paths shown or hidden, in silence.
    Such a path is refused, and the operator pointed at the backends that take a
    path as it is.
    """
    text = path.as_posix()
    if any(ch in _FIREJAIL_PATTERN_CHARACTERS for ch in text) or any(
        ord(ch) < 0x20 for ch in text
    ):
        raise SandboxUnavailable(
            f"firejail cannot be given the path {text!r}: it reads *, ?, [, ], {{, "
            "}, ~ and $ in a path option as a pattern or a macro and offers no way "
            "to write them literally. Use --sandbox bwrap or --sandbox landlock for "
            "this scan"
        )
    return text


def _firejail_hidden_path(path: Path, granted: Sequence[Path] = ()) -> str:
    """``path`` as a --blacklist value, each pattern character replaced with ``?``.

    A blacklist names what the scanner may not see, so a value that matches more
    than the path is the safe direction: ``?`` matches the character it stands for
    (and any other), so ``notes~`` stays hidden, and a sibling spelled like it is
    hidden with it. The siblings _hidden_around lists are the user's own files,
    whose names ASH does not choose, and one odd name among them must not refuse
    the whole spawn the way a pattern in a whitelist or a read-write value does. A
    control character still cannot be written and is refused as _firejail_path
    refuses it.

    The one way "more" is wrong: firejail expands the value with glob(3), where
    ``?`` matches exactly one character, so ``too~`` beside a granted ``tool``
    becomes ``too?`` and hides the tool, and the scanner cannot start. A substituted
    value is therefore matched against every path in ``granted`` (the policy's
    readable and writable paths, resolved) and each directory above one; a match
    refuses the plan, naming both paths, rather than hiding what the policy grants.
    fnmatch's ``?`` also matches ``/``, so the check is at least as wide as glob's.
    """
    text = path.as_posix()
    if any(ord(ch) < 0x20 for ch in text):
        return _firejail_path(path)
    if not any(ch in _FIREJAIL_PATTERN_CHARACTERS for ch in text):
        return text
    value = "".join("?" if ch in _FIREJAIL_PATTERN_CHARACTERS else ch for ch in text)
    for shown in granted:
        for candidate in (shown, *shown.parents):
            if fnmatch.fnmatchcase(candidate.as_posix(), value):
                raise SandboxUnavailable(
                    f"firejail cannot hide the path {text!r}: it reads *, ?, [, ], "
                    "{, }, ~ and $ in a path option as a pattern or a macro, and the "
                    f"pattern that would hide it ({value!r}) also matches "
                    f"{candidate.as_posix()!r}, which this scan needs. Use --sandbox "
                    "bwrap or --sandbox landlock for this scan"
                )
    return value


class FirejailBackend(SandboxBackend):
    name = "firejail"
    platforms = ("linux",)

    def __init__(self) -> None:
        self._executable: Optional[str] = None

    def _probe(self) -> Optional[str]:
        found = _sandbox_program("firejail")
        if not found:
            return "firejail is not installed"
        readlink = next(
            (path for path in _SYSTEM_READLINK if os.access(path, os.X_OK)), None
        ) or _sandbox_program("readlink")
        if not readlink:
            return (
                "readlink is not installed, so ASH cannot check that firejail "
                "confines what it runs"
            )
        # Exiting 0 proves nothing: when firejail finds no kernel threads among PIDs
        # 1-10, as in a container with its own PID namespace (unless a container=
        # variable names LXC, Docker or nspawn), it decides it is already inside a
        # sandbox and runs the command with none of its options.
        # Every sandbox it does build has its own mount namespace, which is where
        # the read-only root, the private home and the whitelists are, so a command
        # that reports ASH's mount namespace ran unconfined. Without --quiet here,
        # firejail's own warning, when it prints one, goes into the reason.
        own_namespace = os.readlink("/proc/self/ns/mnt")
        result = _probe_process(
            [
                found,
                *_FIREJAIL_CONFINEMENT,
                "--net=none",
                "--private",
                "--private-tmp",
                "--",
                readlink,
                "/proc/self/ns/mnt",
            ]
        )
        failure = _exit_failure(result)
        if failure:
            return f"firejail cannot create a sandbox here ({failure})"
        namespaces = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip().startswith("mnt:[")
        ]
        warnings = [
            line.strip()
            for line in f"{result.stderr}\n{result.stdout}".splitlines()
            if _FIREJAIL_NO_SANDBOX in line
        ]
        evidence: List[str] = []
        if namespaces and namespaces[-1] == own_namespace:
            evidence.append("the command ran in ASH's own mount namespace")
        if warnings:
            evidence.append(f"firejail said: {warnings[0]}")
        if evidence:
            return (
                "firejail ran a test command without a sandbox ("
                + "; ".join(evidence)
                + "), so it would run scanners unconfined. firejail does this when "
                "it decides it is already inside a sandbox, as in a container that "
                "does not share the host's PID namespace. Use --sandbox bwrap or "
                "--sandbox landlock here"
            )
        if not namespaces:
            output = result.stdout.strip().splitlines()
            return (
                "ASH could not confirm that firejail confines what it runs: its test "
                "command printed no mount namespace ("
                + (repr(output[-1]) if output else "no output")
                + ")"
            )
        # A separate run, without --private: the filter runs ASH's own interpreter,
        # which may live under $HOME, and every real spawn whitelists it.
        failure = _probe_run(
            [found, "--quiet", "--noprofile", "--net=none", "--"]
            + _with_socket_filter([_true()])
        )
        if failure:
            return f"firejail cannot start a sandbox with the Unix-socket filter ({failure})"
        self._executable = found
        return None

    def plan(
        self, argv: Sequence[str], env: Mapping[str, str], policy: SandboxPolicy
    ) -> SpawnPlan:
        if not self._executable:
            raise RuntimeError(f"{self.name}: probe() must succeed before plan()")
        # firejail is setuid, so it takes the home it makes private, and the one a
        # whitelist inside $HOME applies to, from the passwd entry, never from HOME
        # (init_cfg in firejail's main.c). Its whitelists are decided against that
        # home. HOME's own directory, when it is another one, is blacklisted below.
        # A passwd home of "/" (a service account's) names no home: decided
        # against it, every readable path was "inside the home", so /usr, /etc
        # and the rest were whitelisted and --private dropped. The root stays the
        # home firejail reads, flagged so that nothing is whitelisted against it
        # and --private is not asked for. HOME's directory is not put in its
        # place: firejail would not treat it as the home either, so a path
        # whitelisted under it would empty the rest of its top-level directory,
        # and taken for the home it was no longer blacklisted below, which is
        # what hides its ~/.ssh and ~/.aws.
        home = _real(_passwd_home() or policy.home)
        home_is_a_root = home == Path(home.anchor)
        home_variable = _real(policy.home)
        tmp_root = _real(_TMP_ROOT)
        # What the scan needs to see: a --blacklist value spelled with ? must not
        # match any of these (_firejail_hidden_path). The program and the working
        # directory are usually inside read_only already; a name that resolves
        # nowhere fails at the spawn, so nothing is added for it here.
        program = argv[0] if os.path.isabs(argv[0]) else _sandbox_program(argv[0])
        child_env = policy.filter_env(env)
        # The bundle or directory the operator's CA-bundle settings name, readable
        # even where it sits under the home directory --private hides.
        ca_reads = [
            _real(p)
            for p in _operator_ca_reads(
                policy, child_env, spell=_firejail_path, warns_of_hidden_links=True
            )
        ]
        granted = [
            _real(p)
            for p in [
                *([Path(program)] if program else []),
                *([policy.cwd] if policy.cwd else []),
                *policy.read_only,
                *policy.cache,
                *policy.writable,
                *policy.uv_tool_locks,
            ]
        ] + ca_reads
        cmd = [self._executable, "--quiet", *_FIREJAIL_CONFINEMENT]
        if not policy.network:
            cmd.append("--net=none")
        # firejail leaves everything outside $HOME visible, including the local IPC
        # endpoints a scanner could use to act outside the sandbox: the container
        # runtime sockets, the per-user runtime directory (session bus, gpg-agent,
        # rootless Docker or Podman) and the SSH agent.
        ipc = [
            "/run/docker.sock",
            "/var/run/docker.sock",
            "/run/podman",
            "/run/containerd",
            "/var/run/containerd",
            f"/run/user/{os.getuid()}",
            os.environ.get("SSH_AUTH_SOCK", ""),
        ]
        for path in ipc:
            if path and os.path.lexists(path):
                cmd.append(f"--blacklist={_firejail_hidden_path(Path(path), granted)}")

        # firejail has no throwaway overlay, so a cache is read-only like the rest;
        # _private_caches gives the tools that write one a private directory.
        readable = (
            [_real(p) for p in policy.read_only]
            + [_real(p) for p in policy.cache]
            + ca_reads
        )
        writable = [_real(p) for p in policy.writable]
        # Whitelisting any path inside $HOME (or /tmp) makes everything else there
        # invisible, which is how firejail hides the home directory.
        whitelisted = [
            p
            for p in readable + writable
            if (not home_is_a_root and _is_within(p, home)) or _is_within(p, tmp_root)
        ]
        if not home_is_a_root and not any(_is_within(p, home) for p in whitelisted):
            cmd.append("--private")
        if not any(_is_within(p, tmp_root) for p in whitelisted):
            cmd.append("--private-tmp")
        for p in whitelisted:
            cmd.append(f"--whitelist={_firejail_path(p)}")
        # HOME names a directory firejail does not treat as the home: the scanner is
        # told its home is there, and its ~/.ssh and ~/.aws would stay readable.
        # Under /tmp it is already hidden by --private-tmp or by the /tmp whitelists.
        # A policy path inside it is blacklisted with it, so a tool kept there fails
        # to start rather than the directory being shown.
        if (
            home_variable != home
            and home_variable != Path(home_variable.anchor)
            and not _is_within(home_variable, tmp_root)
        ):
            cmd.append(f"--blacklist={_firejail_hidden_path(home_variable, granted)}")
        # A directory a link at the top of either home names (~/.local kept on
        # another disk) is part of that home but outside it, where firejail shows
        # everything: it is blacklisted, all but the policy's own paths inside it.
        homes = [h for h in [home] if not home_is_a_root] + (
            [home_variable]
            if home_variable not in (home, Path(home_variable.anchor))
            else []
        )
        for target in _home_link_targets(homes, files=True):
            if _is_within(target, tmp_root):
                continue
            for hidden in _hidden_around(target, readable + writable, homes):
                cmd.append(f"--blacklist={_firejail_hidden_path(hidden, granted)}")
        # A whitelisted path is mounted read-write whatever --read-only=/ said, so
        # every readable path is made read-only again here, and only then are the
        # writable ones (the results directory, inside the read-only output and
        # often the source tree) opened back up. Without this, CI measured the
        # source tree and the output directory writable whenever they sat in /tmp.
        for p in readable:
            # A readable path inside a writable one (the results dir) is left to
            # the --read-write below rather than made read-only first.
            if not any(p == w or _is_within(p, w) for w in writable):
                cmd.append(f"--read-only={_firejail_path(p)}")
        for p in writable:
            cmd.append(f"--read-write={_firejail_path(p)}")
        # uv's tools-directory lock, which `uv tool run` opens read-write before it
        # looks for an installed tool: the one file in the read-only tools
        # directory it may write, as sandbox-exec grants it.
        for lock in policy.uv_tool_locks:
            if _real(lock).is_file():
                cmd.append(f"--read-write={_firejail_path(_real(lock))}")
        cmd.append("--")
        cmd.extend(_with_socket_filter(argv))
        cleanup, private_dirs = _private_caches(policy, child_env)
        # firejail does not call setsid, so the spawner starts it as the leader
        # of a session of its own and the stop paths' group signals reach the
        # tool and what it starts, not firejail alone.
        return SpawnPlan(
            argv=cmd,
            env=child_env,
            cleanup=cleanup,
            start_new_session=True,
            private_dirs=private_dirs,
        )


# ---------------------------------------------------------------------------
# Landlock
# ---------------------------------------------------------------------------


#: The first Landlock ABI that controls truncation (Linux 6.2). Below it a scanner
#: can truncate a file it may only read, so the source tree is not read-only, and
#: the backend counts as unavailable.
MIN_LANDLOCK_ABI = 3


def _landlock_program(name: str) -> str:
    """The absolute path the Landlock wrapper starts for ``name``.

    The wrapper starts its command with ``os.execve``, which does not search PATH: a
    name with no leading slash is read against the working directory, which is usually
    the tree being scanned. An unsandboxed spawn, bwrap and firejail search PATH for
    the name instead (anchored entries only), and a tool that is not installed is not
    found in any of them. So a name that is not absolute is resolved here the way
    ASH's own lookup resolves it, and one that resolves nowhere is the
    ``FileNotFoundError`` a spawn of a program that is not installed raises, never a
    name handed to the wrapper.

    Raises:
        FileNotFoundError: ``name`` is not an absolute path and no program of that
            name was found outside the scanned tree.
    """
    if os.path.isabs(name):
        return name
    found = _sandbox_program(name)
    if found is not None:
        return found
    from automated_security_helper.utils.subprocess_utils import in_tree_refusal

    raise FileNotFoundError(
        errno.ENOENT, in_tree_refusal(name) or f"{name} was not found on PATH", name
    )


class LandlockBackend(SandboxBackend):
    name = "landlock"
    platforms = ("linux",)

    def __init__(self) -> None:
        self._abi = 0

    def _probe(self) -> Optional[str]:
        failure = _probe_run(
            [sys.executable, "-I", str(LANDLOCK_EXEC), "--abi"],
        )
        if failure:
            return f"Landlock is not available ({failure})"
        result = _probe_process([sys.executable, "-I", str(LANDLOCK_EXEC), "--abi"])
        self._abi = int(result.stdout.strip() or 0)
        if self._abi < MIN_LANDLOCK_ABI:
            return (
                f"Landlock ABI {self._abi} is below {MIN_LANDLOCK_ABI} (Linux 6.2), so "
                "it cannot stop a scanner from truncating files it may only read, and "
                "the source tree would not be read-only"
            )
        policy = json.dumps({"read_only": ["/"], "writable": [], "network": False})
        failure = _probe_run(
            [
                sys.executable,
                "-I",
                str(LANDLOCK_EXEC),
                "--policy",
                policy,
                "--",
                _true(),
            ]
        )
        if failure:
            return f"Landlock could not restrict a process ({failure})"
        if self._abi < 6:
            ASH_LOGGER.warning(
                f"Landlock ABI {self._abi} (below 6): abstract Unix sockets and signals "
                "to processes outside the sandbox are not restricted."
            )
        return None

    def plan(
        self, argv: Sequence[str], env: Mapping[str, str], policy: SandboxPolicy
    ) -> SpawnPlan:
        # First, so a program that is not found is refused with nothing made.
        resolved_argv0 = _landlock_program(argv[0])
        private_root = Path(tempfile.mkdtemp(prefix="ash-sandbox-"))
        private_cleanup: List[Callable[[], None]] = []
        try:
            return self._plan(
                argv, env, policy, resolved_argv0, private_root, private_cleanup
            )
        except BaseException:
            # A step after the private root was made raised (a link that could not
            # be made, a private cache that could not be created): nothing is
            # returned, so nothing would have run the cleanup.
            SpawnPlan(argv=[], env={}, cleanup=private_cleanup).run_cleanup()
            shutil.rmtree(private_root, ignore_errors=True)
            raise

    def _plan(
        self,
        argv: Sequence[str],
        env: Mapping[str, str],
        policy: SandboxPolicy,
        resolved_argv0: str,
        private_root: Path,
        private_cleanup: List[Callable[[], None]],
    ) -> SpawnPlan:
        private_tmp = private_root / "tmp"
        private_home = private_root / "home"
        private_tmp.mkdir()
        private_home.mkdir()
        _link_policy_paths_into(private_home, policy)
        # Landlock rules only grant, so a granted path that holds a home (a HOME
        # under /opt or /usr/local, which the policy keeps for the tool prefix)
        # would read the home with it: the home is carved out of such a path here,
        # and the policy's own paths inside the home stay granted as listed.
        carved = _carved_homes(policy)
        # The policy's executable paths are granted read and exec; the rest of its
        # read paths (the scanned tree, the scan target, the working directory, the
        # directories read_path_env names) are the scan's data and are granted read
        # alone, as sandbox-exec denies exec in them. Landlock rules add up, so a
        # data path under an executable root (a checkout under /opt) is still
        # executable through the root; one under no such root, the common
        # checkout under $HOME, is not. Caches keep read and exec: a tool's
        # installed environment can live in one.
        programs = {os.path.realpath(p) for p in policy.executable}
        # The executable paths as the policy lists them: build_scanner_policy draws
        # them from read_only, so this is the same set it would be filtered to, and
        # a policy built by hand with an executable path outside read_only gets the
        # exec grant it asks for rather than none.
        exec_paths = list(policy.executable)
        child_env = policy.filter_env(env)
        # The bundle or directory the operator's CA-bundle settings name is data
        # too: read, never run, and readable where it sits under the home.
        ca_reads = _operator_ca_reads(policy, child_env)
        data_paths = [
            p for p in policy.read_only if os.path.realpath(p) not in programs
        ] + ca_reads
        read_only = _around(exec_paths + list(policy.cache), carved)
        read_data = _around(data_paths, carved)
        document = {
            # Caches are read-only: Landlock cannot discard a write, so one in place
            # would change what later runs read. See _private_caches.
            "read_only": [p.as_posix() for p in read_only]
            + ["/proc", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/full"],
            "read_data": [p.as_posix() for p in read_data],
            "writable": [_real(p).as_posix() for p in policy.writable]
            # uv's tools-directory lock, the one file in the read-only tools
            # directory `uv tool run` writes, as sandbox-exec grants it.
            + [_real(p).as_posix() for p in policy.uv_tool_locks]
            # /dev/shm because POSIX semaphores live there and multiprocessing needs
            # them (detect-secrets scans files in a process pool). Landlock cannot
            # make it private, so this is the host's: a documented gap of this
            # backend that bwrap does not have. Not /dev/tty or /dev/pts: the
            # wrapper starts a new session, so there is no terminal to reach.
            + [private_root.as_posix(), "/dev/null", "/dev/shm"],  # nosec B108 - a Landlock grant, not a file ASH creates
            "network": policy.network,
        }
        if policy.cwd is None:
            # A spawn with no working directory of its own (a version probe)
            # would otherwise start in ASH's, which the policy may not grant: the
            # wrapper changes into the private TMPDIR instead, as bwrap and
            # sandbox-exec move such a process out of ASH's directory.
            document["cwd"] = private_tmp.as_posix()
        cmd = [
            sys.executable,
            "-I",
            str(LANDLOCK_EXEC),
            "--policy",
            json.dumps(document),
            "--",
            resolved_argv0,
            *argv[1:],
        ]
        child_env["TMPDIR"] = private_tmp.as_posix()
        child_env["HOME"] = private_home.as_posix()
        caches, private_dirs = _private_caches(policy, child_env)
        private_cleanup += caches
        return SpawnPlan(
            argv=cmd,
            env=child_env,
            cleanup=[lambda: shutil.rmtree(private_root, ignore_errors=True)]
            + private_cleanup,
            private_dirs=private_dirs,
        )


def _link_policy_paths_into(private_home: Path, policy: SandboxPolicy) -> None:
    """Give a private $HOME the policy's paths under the real one, as symlinks.

    Landlock cannot mount an empty home over the real one, and denying the real one
    breaks every tool that writes a settings or version file under ~ (semgrep,
    opengrep's unpack cache). So the scanner gets a fresh, writable $HOME, and each
    path the policy grants under the real home appears at the same relative place
    in it as a symlink to the real path, where the Landlock rules for that path
    apply. Shallowest first; a path under one already linked is reached through it.
    A home that is a filesystem root names no home (``_home_to_hide``), and every
    path is under it: nothing is linked then.
    """
    if _home_to_hide(policy) is None:
        return
    real_home = _real(policy.home)
    relatives = []
    for path in list(policy.read_only) + list(policy.cache) + list(policy.writable):
        for candidate in (Path(os.path.abspath(path)), _real(path)):
            for home in (Path(os.path.abspath(policy.home)), real_home):
                try:
                    relatives.append((candidate.relative_to(home), _real(path)))
                except ValueError:
                    continue
    linked: List[Path] = []
    for relative, target in sorted(set(relatives), key=lambda item: len(item[0].parts)):
        if not relative.parts or any(
            relative == done or done in relative.parents for done in linked
        ):
            continue
        link = private_home / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        if not link.exists() and not link.is_symlink():
            link.symlink_to(target)
            linked.append(relative)


# ---------------------------------------------------------------------------
# macOS sandbox-exec
# ---------------------------------------------------------------------------


def _sbpl_string(path: Path) -> str:
    """A path as an SBPL string literal.

    Only backslash and double quote are escaped. json.dumps would also turn non-ASCII
    into \\uXXXX, which SBPL does not decode, so a deny on a home directory with a
    non-ASCII name would silently match nothing.
    """
    return _sbpl_literal(path.as_posix())


def _sbpl_literal(text: str) -> str:
    if any(ord(ch) < 0x20 for ch in text):
        raise SandboxUnavailable(f"cannot express {text!r} in a sandbox-exec profile")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


#: Starts a new session, so there is no controlling terminal to inject keystrokes
#: into through TIOCSTI, changes to the directory in argv[1] when it is not empty,
#: then execs the rest of argv. macOS ships no setsid(1).
_SETSID_EXEC = (
    "import os,sys;os.setsid();sys.argv[1] and os.chdir(sys.argv[1]);"
    "os.execv(sys.argv[2],sys.argv[2:])"
)

#: The Mach services every sandboxed scanner may look up. Measured: the ten builtin
#: scanners were run through the scanner parity fixture on the macOS 14.8, 15.7 and
#: 26.6 CI runners with every lookup reported, and they looked up the same thirteen
#: services on all three. Nine are allowed, here and in the network list. Not
#: allowed: LaunchServices (denied below), which node looks up on start and does
#: without, and the two that /usr/bin/security looks up, com.apple.SecurityServer
#: (the keychain daemon, denied below) and com.apple.analyticsd. semgrep-core runs
#: security only to read the system root certificates, and gets them from a file
#: instead (see ``system_trust_roots``). See docs/content/docs/scanner-sandbox.md
#: for finding a service that is missing.
MACH_SERVICES: Tuple[str, ...] = (
    # CFPreferences, which CoreFoundation reads on start (Python, Go, node, ruby).
    "com.apple.cfprefsd.agent",
    "com.apple.cfprefsd.daemon",
    # os_log and notify(3), both used by libSystem in every process.
    "com.apple.logd",
    "com.apple.system.notification_center",
    # User and group lookups: getpwuid(3) and friends, and group membership (ruby).
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.opendirectoryd.membership",
)

#: Allowed only to a scanner with a network: name resolution, network and proxy
#: configuration, and certificate trust for TLS.
MACH_SERVICES_WITH_NETWORK: Tuple[str, ...] = (
    "com.apple.SystemConfiguration.DNSConfiguration",
    "com.apple.SystemConfiguration.configd",
    "com.apple.trustd.agent",
)

#: Denied after every allow, so no allowlist entry can ever reach them: in SBPL the
#: last matching rule wins. LaunchServices asks launchd to start an app, and launchd
#: starts it outside the sandbox, so a scanner that can reach it can run code that is
#: not sandboxed (a .command file opened in Terminal). The pasteboard holds whatever
#: the user last copied. node looks up launchservicesd and com.apple.lsd.modifydb on
#: start and carries on without them. SecurityServer is the keychain daemon.
_DENIED_MACH_SERVICES = (
    '(global-name "com.apple.coreservices.launchservicesd")'
    ' (global-name "com.apple.CoreServices.coreservicesd")'
    ' (global-name-prefix "com.apple.lsd.")'
    ' (global-name-prefix "com.apple.pasteboard.")'
    ' (global-name "com.apple.SecurityServer")'
)

#: The keychains that hold root certificates, in the order and form OCaml's ca-certs
#: reads them on macOS when SSL_CERT_FILE is not set: Apple's roots, then the ones an
#: administrator added (a corporate proxy's, for example).
_TRUST_ROOT_KEYCHAINS = (
    "/System/Library/Keychains/SystemRootCertificates.keychain",
    "/Library/Keychains/System.keychain",
)

_trust_roots_cache: List[Optional[str]] = []

#: Non-empty once the failed-export warning has been logged. An export that
#: failed in time is tried again at every spawn (below), so the warning would
#: otherwise repeat at every spawn of the run; later failures are logged at DEBUG.
_trust_roots_warned: List[bool] = []


def _system_trust_roots() -> Optional[str]:
    """The system's root certificates as PEM, exported once per process.

    Runs outside the sandbox, as ASH, with the same command ca-certs runs. None when
    neither keychain gave a certificate, in which case the tool is left to find its
    own and fails the way it would have without the export. An export that gave
    certificates is remembered, and so is one that ran out of time: ``security``
    is run at every spawn, so an export that hangs would cost each spawn up to
    PROBE_TIMEOUT_SECONDS per keychain, and a hang is not a condition the next
    spawn finds cured. A run that failed in time (refused, exit non-zero, no
    certificate) is tried again at the next spawn rather than disabling the
    export for the rest of the process.
    """
    if _trust_roots_cache:
        return _trust_roots_cache[0]
    exported = []
    timed_out = False
    for keychain in _TRUST_ROOT_KEYCHAINS:
        if not Path(keychain).exists():
            continue
        try:
            result = subprocess.run(  # nosec B603 - fixed argv, run by ASH itself
                ["/usr/bin/security", "find-certificate", "-a", "-p", keychain],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=PROBE_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            ASH_LOGGER.debug(f"Exporting root certificates from {keychain}: {e}")
            timed_out = True
            continue
        except (OSError, subprocess.SubprocessError) as e:
            ASH_LOGGER.debug(f"Exporting root certificates from {keychain}: {e}")
            continue
        if result.returncode == 0 and "BEGIN CERTIFICATE" in result.stdout:
            exported.append(result.stdout)
    pem = "\n".join(exported) if exported else None
    if pem is None:
        message = (
            "Could not export the system root certificates; a sandboxed scanner "
            "that reads them itself (semgrep) may fail to verify TLS."
            + (
                " The export ran out of time and is not tried again in this run."
                if timed_out
                else ""
            )
        )
        if _trust_roots_warned:
            ASH_LOGGER.debug(message)
        else:
            _trust_roots_warned.append(True)
            ASH_LOGGER.warning(message)
        if timed_out:
            _trust_roots_cache.append(None)
        return None
    _trust_roots_cache.append(pem)
    return pem


def _sbpl_subpaths(paths: Sequence[Path]) -> str:
    return " ".join(f"(subpath {_sbpl_string(path)})" for path in paths)


def _mach_rule(names: Sequence[str]) -> str:
    filters = " ".join(f"(global-name {_sbpl_literal(name)})" for name in names)
    return f"(allow mach-lookup {filters})"


def _exec_rules(
    policy: SandboxPolicy, private_tmp: Path, spawn_executable: Sequence[Path] = ()
) -> List[str]:
    """Programs run from the policy's executable paths, and from nowhere else.

    Then exec is denied again in the scan's own data, which the scanned repository
    wrote, and everywhere else the scanner can write (the results directory, its
    caches, the private TMPDIR), even where a tool path contains one of them: a
    checkout under /opt is not executable because /opt is. A path inside one of
    those that has to be executable is given back last: a tool path (a virtualenv
    in the scanned project that ASH itself runs from), and ``spawn_executable``,
    the directories made for this spawn alone that a tool runs programs from (its
    private uv cache, a self-unpacking tool's unpack directory). In SBPL the last
    matching rule wins.
    """
    executable = sorted(
        {_real(p) for p in policy.executable} | {_real(p) for p in spawn_executable}
    )
    denied = sorted(
        {
            _real(p)
            for p in [*policy.scan_data, *policy.writable, *policy.cache, private_tmp]
        }
        - set(executable)
    )
    nested = [path for path in executable if any(_is_within(path, d) for d in denied)]
    # An empty filter list is a syntax error, so each rule is written only when it
    # names something. Never empty in practice: /usr is executable, and the private
    # TMPDIR is always denied.
    rules = []
    for verdict, paths in (("allow", executable), ("deny", denied), ("allow", nested)):
        if paths:
            rules.append(f"({verdict} process-exec {_sbpl_subpaths(paths)})")
    # uv's tools-directory lock is the one file inside an executable tool path
    # the scanner may write (profile grants it file-write*): a file it can write
    # and run would be a program of its own making, so exec is denied there last.
    locks = sorted({_real(p) for p in policy.uv_tool_locks})
    if locks:
        literals = " ".join(f"(literal {_sbpl_string(lock)})" for lock in locks)
        rules.append(f"(deny process-exec {literals})")
    return rules


class SandboxExecBackend(SandboxBackend):
    name = "sandbox-exec"
    platforms = ("darwin",)
    executable = "/usr/bin/sandbox-exec"

    def _probe(self) -> Optional[str]:
        if not Path(self.executable).exists():
            return "sandbox-exec is not present (it has been removed from this macOS)"
        return _probe_run(
            [self.executable, "-p", "(version 1)(allow default)", "/usr/bin/true"]
        )

    def profile(
        self,
        policy: SandboxPolicy,
        private_tmp: Path,
        trust_roots: Optional[Path] = None,
        unpack_dir: Optional[Path] = None,
        private_uv_cache: Optional[Path] = None,
        ca_reads: Sequence[Path] = (),
    ) -> str:
        # HOME's directory and the passwd entry's home, when HOME names another
        # directory: reading starts from "/", so a home that is not denied here
        # stays readable. A home that is the filesystem root names no home
        # (_home_to_hide): denied, it took back every read the policy did not list.
        homes = _homes_to_hide(policy)
        # And each directory a link at the top of a home names (~/.local kept on
        # another disk), which is part of that home; the policy's own paths inside
        # it are allowed again after the denies, as they are inside the homes.
        denied = homes + _home_link_targets(homes, files=True)
        # Caches are read-only here too; see _private_caches.
        readable = " ".join(
            f"(subpath {_sbpl_string(_real(p))})"
            for p in list(policy.read_only) + list(policy.cache)
        )
        writable = " ".join(
            [
                f"(subpath {_sbpl_string(_real(p))})"
                for p in list(policy.writable)
                + [private_tmp]
                + ([unpack_dir] if unpack_dir is not None else [])
            ]
            + [f"(literal {_sbpl_string(_real(p))})" for p in policy.uv_tool_locks]
        )
        lines = [
            "(version 1)",
            "(deny default)",
            "(allow process-fork)",
            *_exec_rules(
                policy,
                private_tmp,
                [p for p in (unpack_dir, private_uv_cache) if p is not None],
            ),
            "(allow signal (target same-sandbox))",
            "(allow process-info* (target same-sandbox))",
            "(allow sysctl-read)",
            _mach_rule(MACH_SERVICES),
        ]
        if policy.network:
            lines.append(_mach_rule(MACH_SERVICES_WITH_NETWORK))
        lines += [
            f"(deny mach-lookup {_DENIED_MACH_SERVICES})",
            # POSIX shared memory by name: libSystem's notification center segment,
            # which every process maps, and the segments Python's multiprocessing
            # makes for its own pools (detect-secrets). Allowed for every name, a
            # scanner could open and write the segments of any other process of
            # the same user.
            (
                "(allow ipc-posix-shm-read* "
                '(ipc-posix-name "apple.shm.notification_center"))'
            ),
            '(allow ipc-posix-shm (ipc-posix-name-regex #"^/?(psm_|mp-|sem\\.)"))',
            "(allow ipc-posix-sem)",
            "(allow file-ioctl)",
            "(allow file-read-metadata)",
            # Read anywhere, then take back the home directory and the shared temp
            # directories, then give back the paths the policy lists. In SBPL the
            # last matching rule wins. /private/var/tmp is the third shared
            # temporary directory, where other users' and processes' files sit.
            '(allow file-read* (subpath "/"))',
            *[f"(deny file-read* (subpath {_sbpl_string(h)}))" for h in denied],
            (
                '(deny file-read* (subpath "/private/tmp") (subpath "/private/var/tmp")'
                ' (subpath "/private/var/folders"))'
            ),
        ]
        if readable:
            lines.append(f"(allow file-read* {readable})")
        # A path the policy lists can hold a home (a HOME under /opt or /usr/local,
        # which the policy keeps for the tool prefix; an extra read path naming a
        # home's parent), and the allow above reopened that home: take it back
        # again, then give back the policy's own paths inside it.
        listed = sorted({_real(p) for p in list(policy.read_only) + list(policy.cache)})
        reopened = sorted(
            {
                h
                for h in _carved_homes(policy)
                if any(p != h and _is_within(h, p) for p in listed)
            }
        )
        if reopened:
            lines.append(f"(deny file-read* {_sbpl_subpaths(reopened)})")
            inside_homes = [
                p for p in listed if any(_is_within(p, h) for h in reopened)
            ]
            if inside_homes:
                lines.append(f"(allow file-read* {_sbpl_subpaths(inside_homes)})")
        # Then take back what the tool may not read, wherever it is (a checkout under
        # /opt is otherwise read through "/" or a tool path), and give back what the
        # policy lists inside it. The results directory comes back with the
        # writable paths, next.
        unread = sorted({_real(p) for p in policy.unread})
        if unread:
            lines.append(f"(deny file-read* {_sbpl_subpaths(unread)})")
            listed_inside = sorted(
                {
                    _real(p)
                    for p in list(policy.read_only) + list(policy.cache)
                    if any(_is_within(_real(p), u) for u in unread)
                }
            )
            if listed_inside:
                lines.append(f"(allow file-read* {_sbpl_subpaths(listed_inside)})")
        lines.append(f"(allow file-read* file-write* {writable})")
        lines.append(
            '(allow file-read* file-write* (literal "/dev/null") (literal "/dev/zero")'
            ' (literal "/dev/dtracehelper") (regex #"^/dev/fd/"))'
        )
        if trust_roots is not None:
            lines.append(
                f"(allow file-read* (literal {_sbpl_string(_real(trust_roots))}))"
            )
        # The operator's other CA-bundle settings: a file by its literal path, a
        # directory by its subpath, read-only like the trust roots above.
        for real in sorted({_real(p) for p in ca_reads}):
            kind = "subpath" if os.path.isdir(real) else "literal"
            lines.append(f"(allow file-read* ({kind} {_sbpl_string(real)}))")
        # Last of the file rules, so no path the policy grants can reopen them: the
        # system and login keychains, whatever the keychain daemon would allow.
        keychains = " ".join(
            f"(subpath {_sbpl_string(h / 'Library' / 'Keychains')})" for h in homes
        )
        lines.append(
            f'(deny file-read* file-write* (subpath "/Library/Keychains") {keychains})'
        )
        if policy.network:
            # IP only. Unix-domain sockets stay denied (Docker Desktop's socket, the
            # launchd SSH agent) except the resolver's, which name lookup needs.
            lines += [
                "(allow system-socket)",
                "(allow network-outbound (remote ip))",
                "(allow network-inbound (local ip))",
                "(allow network-bind (local ip))",
                '(allow network-outbound (literal "/private/var/run/mDNSResponder"))',
            ]
        # Without a network nothing is allowed: (deny default) covers every socket.
        return "\n".join(lines)

    def plan(
        self, argv: Sequence[str], env: Mapping[str, str], policy: SandboxPolicy
    ) -> SpawnPlan:
        private_tmp = Path(tempfile.mkdtemp(prefix="ash-sandbox-tmp-"))
        cleanup: List[Callable[[], None]] = [
            lambda: shutil.rmtree(private_tmp, ignore_errors=True)
        ]
        try:
            return self._plan(argv, env, policy, private_tmp, cleanup)
        except BaseException:
            # The profile refused (SandboxUnavailable), or a step raised: nothing is
            # returned, so the directories made so far are removed here.
            SpawnPlan(argv=[], env={}, cleanup=cleanup).run_cleanup()
            raise

    def _plan(
        self,
        argv: Sequence[str],
        env: Mapping[str, str],
        policy: SandboxPolicy,
        private_tmp: Path,
        cleanup: List[Callable[[], None]],
    ) -> SpawnPlan:
        child_env = policy.filter_env(env)
        child_env["TMPDIR"] = private_tmp.as_posix()
        # Caches are read-only here; see _private_caches. uv's private cache is
        # also where `uv tool run` builds the environment of a tool it was not asked
        # to install and runs it from, so the profile lets that one run programs.
        caches, private_dirs = _private_caches(policy, child_env)
        cleanup += caches
        private_uv_cache = (
            Path(child_env["UV_CACHE_DIR"])
            if "UV_CACHE_DIR" in policy.cache_env and child_env.get("UV_CACHE_DIR")
            else None
        )
        trust_roots = None
        # An SSL_CERT_FILE the operator set is passed through and wins, as it
        # would unsandboxed; the profile is told to allow reading it, since the
        # file can sit where the profile denies reads (under the home directory).
        # The grant is for the operator's value alone, read from the environment
        # ASH started with (process_env.startup_environ), not the live one: scanner
        # threads change the environment while others spawn, and a value one of
        # them set must not be granted as the operator's. A value the spawn's
        # environment carries from elsewhere is passed through like every
        # allowlisted variable but opens nothing the profile denies, as under
        # bwrap and Landlock, which grant nothing for it.
        if child_env.get("SSL_CERT_FILE"):
            named = Path(child_env["SSL_CERT_FILE"])
            operators = child_env["SSL_CERT_FILE"] == startup_environ().get(
                "SSL_CERT_FILE"
            )
            if operators and named.is_absolute() and os.path.isfile(named):
                trust_roots = named
        elif policy.system_trust_roots:
            pem = _system_trust_roots()
            if pem is not None:
                # A directory of its own, outside the writable private TMPDIR, so
                # the profile can grant it read-only.
                roots_dir = Path(tempfile.mkdtemp(prefix="ash-sandbox-roots-"))
                cleanup.append(lambda: shutil.rmtree(roots_dir, ignore_errors=True))
                trust_roots = roots_dir / "roots.pem"
                trust_roots.write_text(pem, encoding="ascii", errors="replace")
                child_env["SSL_CERT_FILE"] = trust_roots.as_posix()
        # The other CA-bundle settings the operator made, the way the other
        # backends grant them; the SSL_CERT_FILE above has its own rule.
        ca_reads = [
            p
            for p in _operator_ca_reads(policy, child_env, spell=_sbpl_string)
            if trust_roots is None or _real(p) != _real(trust_roots)
        ]
        unpack_dir = None
        if policy.unpack_dir_env:
            unpack_dir = Path(tempfile.mkdtemp(prefix="ash-sandbox-unpack-"))
            cleanup.append(lambda: shutil.rmtree(unpack_dir, ignore_errors=True))
            child_env[policy.unpack_dir_env] = unpack_dir.as_posix()
        # Last, so the scanner's own setting cannot ask for the write the profile
        # will refuse (a grype database update into its read-only cache).
        child_env.update(policy.sandbox_exec_env)
        cmd = [
            sys.executable,
            "-I",
            "-c",
            _SETSID_EXEC,
            # A spawn with no working directory of its own (a version probe) would
            # otherwise start in ASH's, which is often under $HOME and unreadable
            # here, and uv fails on its config lookup there. bwrap moves such a
            # process to its private home for the same reason.
            "" if policy.cwd else private_tmp.as_posix(),
            self.executable,
            "-p",
            self.profile(
                policy,
                private_tmp,
                trust_roots,
                unpack_dir,
                private_uv_cache,
                ca_reads,
            ),
            *argv,
        ]
        return SpawnPlan(
            argv=cmd, env=child_env, cleanup=cleanup, private_dirs=private_dirs
        )


BACKENDS: Dict[str, type] = {
    "bwrap": BwrapBackend,
    "firejail": FirejailBackend,
    "landlock": LandlockBackend,
    "sandbox-exec": SandboxExecBackend,
}

#: What ``--sandbox auto`` tries, in order, per platform.
AUTO_ORDER: Dict[str, Tuple[str, ...]] = {
    "linux": ("bwrap", "firejail", "landlock"),
    "darwin": ("sandbox-exec",),
    "windows": (),
}
