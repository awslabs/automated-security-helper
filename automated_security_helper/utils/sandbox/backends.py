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

import json
import os
import platform
import shutil
import subprocess  # nosec B404 - probing and wrapping sandboxed scanner processes is this module's purpose
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import (
    SandboxPolicy,
    SandboxUnavailable,
)

PROBE_TIMEOUT_SECONDS = 20

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
    policy: SandboxPolicy, child_env: Dict[str, str]
) -> List[Callable[[], None]]:
    """Give the tools that must write a cache a private one; returns the cleanup.

    Only bwrap's throwaway overlay lets a scanner write a host cache without the
    write reaching the host. Every other backend mounts ``policy.cache`` read-only
    and calls this, which points each variable in ``policy.cache_env``
    (``UV_CACHE_DIR``, and what the scanner declares) at its own empty directory:
    a fresh directory under the results directory, the one place the scanner may
    write, removed once the process has exited. A tool redirected this way starts
    from an empty cache, so online it fetches what it needs and offline it has
    nothing cached. A cache that is only read, such as a vulnerability database,
    is not redirected and stays read-only.
    """
    if not policy.cache_env:
        return []
    root = Path(tempfile.mkdtemp(prefix=".sandbox-cache-", dir=policy.results_dir))
    for name in policy.cache_env:
        # npm reads npm_config_* without regard to case, so a NPM_CONFIG_CACHE
        # passed through from the parent would compete with the redirect.
        for key in [k for k in child_env if k.lower() == name.lower() and k != name]:
            del child_env[key]
        private = root / name.lower()
        private.mkdir()
        child_env[name] = private.as_posix()
    return [lambda: shutil.rmtree(root, ignore_errors=True)]


@dataclass
class SpawnPlan:
    """What to hand ``subprocess`` in place of the scanner's own argv and env."""

    argv: List[str]
    env: Dict[str, str]
    cleanup: List[Callable[[], None]] = field(default_factory=list)

    def run_cleanup(self) -> None:
        """Run each cleanup once; later calls do nothing."""
        pending, self.cleanup = self.cleanup, []
        for fn in pending:
            try:
                fn()
            except Exception as e:  # pragma: no cover - best effort
                ASH_LOGGER.debug(f"Sandbox cleanup failed: {e}")


class SandboxBackend:
    """Base class. Subclasses set ``name`` and implement ``_probe`` and ``plan``."""

    name = ""
    platforms: Tuple[str, ...] = ()

    def probe(self) -> Optional[str]:
        """None when the backend works here, otherwise why it does not."""
        if platform.system().lower() not in self.platforms:
            return f"{self.name} is not available on {platform.system()}"
        try:
            return self._probe()
        except Exception as e:
            return f"{self.name} probe failed: {e}"

    def _probe(self) -> Optional[str]:
        raise NotImplementedError

    def plan(
        self, argv: Sequence[str], env: Mapping[str, str], policy: SandboxPolicy
    ) -> SpawnPlan:
        raise NotImplementedError


def _probe_process(
    argv: Sequence[str], env: Optional[Mapping[str, str]] = None
) -> "subprocess.CompletedProcess[str]":
    """Run ``argv`` with its output captured, as a probe."""
    return subprocess.run(  # nosec B603 - fixed argv built in this module
        list(argv),
        capture_output=True,
        text=True,
        timeout=PROBE_TIMEOUT_SECONDS,
        env=dict(env) if env is not None else {"PATH": os.environ.get("PATH", "")},
        check=False,
    )


def _exit_failure(result: "subprocess.CompletedProcess[str]") -> Optional[str]:
    """None if ``result`` exited 0, otherwise its last line of output as the reason."""
    if result.returncode == 0:
        return None
    detail = (result.stderr or result.stdout or "").strip().splitlines()
    return f"exit {result.returncode}: {detail[-1] if detail else 'no output'}"


def _probe_run(
    argv: Sequence[str], env: Optional[Mapping[str, str]] = None
) -> Optional[str]:
    """Run ``argv``; None if it exited 0, otherwise its stderr as the reason."""
    return _exit_failure(_probe_process(argv, env))


def _true() -> str:
    return shutil.which("true") or "/bin/true"


def _real(path: Path) -> Path:
    return Path(os.path.realpath(path))


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


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


# ---------------------------------------------------------------------------
# bubblewrap
# ---------------------------------------------------------------------------

_RO, _CACHE, _RW = 1, 2, 3


class BwrapBackend(SandboxBackend):
    name = "bwrap"
    platforms = ("linux",)

    def __init__(self) -> None:
        self._executable: Optional[str] = None
        self._overlay = False

    def _probe(self) -> Optional[str]:
        found = shutil.which("bwrap")
        if not found:
            return "bwrap is not installed (install the 'bubblewrap' package)"
        self._executable = found
        base = [
            found,
            "--unshare-all",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
        ]
        failure = _probe_run(base + ["true"])
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
                base + ["--overlay-src", tmp, "--tmp-overlay", tmp, "true"]
            )
        self._overlay = overlay_failure is None
        if not self._overlay:
            ASH_LOGGER.warning(
                "bwrap cannot mount a throwaway overlay here (needs bubblewrap 0.8+ "
                "and Linux 5.11+): scanner caches will be mounted read-only, and uv "
                "and any tool that has to write its cache get an empty private one."
            )
        return None

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
        for p in policy.cache:
            add(p, _CACHE if self._overlay else _RO)
        for p in policy.writable:
            add(p, _RW)

        home = _real(policy.home)
        # (depth, precedence) puts every ancestor ahead of what is mounted inside it,
        # and at one depth the private home tmpfs (precedence 0) ahead of a bind of the
        # same directory, so scanning $HOME itself still shows it, read-only.
        ops: List[Tuple[int, int, List[str]]] = [
            (len(home.parts), 0, ["--tmpfs", home.as_posix()]),
            (2, 0, ["--tmpfs", "/tmp"]),  # nosec B108 - a fresh tmpfs mounted inside the sandbox
            (3, 0, ["--tmpfs", "/var/tmp"]),  # nosec B108 - a fresh tmpfs inside the sandbox
        ]
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

        bound = [p for p, m in mounts.items() if m in (_RO, _RW, _CACHE)]
        seen_links: Set[Path] = set()
        spellings = list(policy.read_only) + list(policy.writable) + list(policy.cache)
        if policy.cwd:
            spellings.append(policy.cwd)
        spellings.append(policy.home)
        if policy.network and Path("/etc/resolv.conf").is_symlink():
            # systemd-resolved: resolv.conf points into /run, which is not mounted.
            resolver_dir = _real(Path("/etc/resolv.conf")).parent
            if resolver_dir.exists():
                cmd.extend(
                    ["--ro-bind", resolver_dir.as_posix(), resolver_dir.as_posix()]
                )
        for spelling in spellings:
            for where, target in _symlinked_components(Path(spelling)):
                if where in seen_links or any(
                    _is_within(where, b) for b in bound if b != home
                ):
                    continue
                seen_links.add(where)
                cmd.extend(["--symlink", target, where.as_posix()])

        if policy.cwd:
            cmd.extend(["--chdir", _real(policy.cwd).as_posix()])
        cmd.append("--")
        cmd.extend(_with_socket_filter(argv))
        child_env = policy.filter_env(env)
        cleanup: List[Callable[[], None]] = []
        if not self._overlay:
            cleanup = _private_caches(policy, child_env)
        return SpawnPlan(argv=cmd, env=child_env, cleanup=cleanup)


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


class FirejailBackend(SandboxBackend):
    name = "firejail"
    platforms = ("linux",)

    def __init__(self) -> None:
        self._executable: Optional[str] = None

    def _probe(self) -> Optional[str]:
        found = shutil.which("firejail")
        if not found:
            return "firejail is not installed"
        readlink = next(
            (path for path in _SYSTEM_READLINK if os.access(path, os.X_OK)), None
        ) or shutil.which("readlink")
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
        home = _real(policy.home)
        tmp_root = _real(Path("/tmp"))  # nosec B108 - compared against, never written
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
                cmd.append(f"--blacklist={path}")

        # firejail has no throwaway overlay, so a cache is read-only like the rest;
        # _private_caches gives the tools that write one a private directory.
        readable = [_real(p) for p in policy.read_only] + [
            _real(p) for p in policy.cache
        ]
        writable = [_real(p) for p in policy.writable]
        # Whitelisting any path inside $HOME (or /tmp) makes everything else there
        # invisible, which is how firejail hides the home directory.
        whitelisted = [
            p
            for p in readable + writable
            if _is_within(p, home) or _is_within(p, tmp_root)
        ]
        if not any(_is_within(p, home) for p in whitelisted):
            cmd.append("--private")
        if not any(_is_within(p, tmp_root) for p in whitelisted):
            cmd.append("--private-tmp")
        for p in whitelisted:
            cmd.append(f"--whitelist={p.as_posix()}")
        # A whitelisted path is mounted read-write whatever --read-only=/ said, so
        # every readable path is made read-only again here, and only then are the
        # writable ones (the results directory, inside the read-only output and
        # often the source tree) opened back up. Without this, CI measured the
        # source tree and the output directory writable whenever they sat in /tmp.
        for p in readable:
            # A readable path inside a writable one (the results dir) is left to
            # the --read-write below rather than made read-only first.
            if not any(p == w or _is_within(p, w) for w in writable):
                cmd.append(f"--read-only={p.as_posix()}")
        for p in writable:
            cmd.append(f"--read-write={p.as_posix()}")
        cmd.append("--")
        cmd.extend(_with_socket_filter(argv))
        child_env = policy.filter_env(env)
        cleanup = _private_caches(policy, child_env)
        return SpawnPlan(argv=cmd, env=child_env, cleanup=cleanup)


# ---------------------------------------------------------------------------
# Landlock
# ---------------------------------------------------------------------------


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
        result = subprocess.run(  # nosec B603 - fixed argv
            [sys.executable, "-I", str(LANDLOCK_EXEC), "--abi"],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_SECONDS,
            env={"PATH": os.environ.get("PATH", "")},
            check=False,
        )
        self._abi = int(result.stdout.strip() or 0)
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
        private_root = Path(tempfile.mkdtemp(prefix="ash-sandbox-"))
        private_tmp = private_root / "tmp"
        private_home = private_root / "home"
        private_tmp.mkdir()
        private_home.mkdir()
        _link_policy_paths_into(private_home, policy)
        resolved_argv0 = (
            argv[0] if os.path.isabs(argv[0]) else (shutil.which(argv[0]) or argv[0])
        )
        document = {
            # Caches are read-only: Landlock cannot discard a write, so one in place
            # would change what later runs read. See _private_caches.
            "read_only": [_real(p).as_posix() for p in policy.read_only]
            + [_real(p).as_posix() for p in policy.cache]
            + ["/proc", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/full"],
            "writable": [_real(p).as_posix() for p in policy.writable]
            # /dev/shm because POSIX semaphores live there and multiprocessing needs
            # them (detect-secrets scans files in a process pool). Landlock cannot
            # make it private, so this is the host's: a documented gap of this
            # backend that bwrap does not have. Not /dev/tty or /dev/pts: the
            # wrapper starts a new session, so there is no terminal to reach.
            + [private_root.as_posix(), "/dev/null", "/dev/shm"],  # nosec B108 - a Landlock grant, not a file ASH creates
            "network": policy.network,
        }
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
        child_env = policy.filter_env(env)
        child_env["TMPDIR"] = private_tmp.as_posix()
        child_env["HOME"] = private_home.as_posix()
        private_cleanup = _private_caches(policy, child_env)
        return SpawnPlan(
            argv=cmd,
            env=child_env,
            cleanup=[lambda: shutil.rmtree(private_root, ignore_errors=True)]
            + private_cleanup,
        )


def _link_policy_paths_into(private_home: Path, policy: SandboxPolicy) -> None:
    """Give a private $HOME the policy's paths under the real one, as symlinks.

    Landlock cannot mount an empty home over the real one, and denying the real one
    breaks every tool that writes a settings or version file under ~ (semgrep,
    opengrep's unpack cache). So the scanner gets a fresh, writable $HOME, and each
    path the policy grants under the real home appears at the same relative place
    in it as a symlink to the real path, where the Landlock rules for that path
    apply. Shallowest first; a path under one already linked is reached through it.
    """
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


def _system_trust_roots() -> Optional[str]:
    """The system's root certificates as PEM, exported once per process.

    Runs outside the sandbox, as ASH, with the same command ca-certs runs. None when
    neither keychain gave a certificate, in which case the tool is left to find its
    own and fails the way it would have without the export.
    """
    if _trust_roots_cache:
        return _trust_roots_cache[0]
    exported = []
    for keychain in _TRUST_ROOT_KEYCHAINS:
        if not Path(keychain).exists():
            continue
        try:
            result = subprocess.run(  # nosec B603 - fixed argv, run by ASH itself
                ["/usr/bin/security", "find-certificate", "-a", "-p", keychain],
                capture_output=True,
                text=True,
                timeout=PROBE_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as e:
            ASH_LOGGER.debug(f"Exporting root certificates from {keychain}: {e}")
            continue
        if result.returncode == 0 and "BEGIN CERTIFICATE" in result.stdout:
            exported.append(result.stdout)
    pem = "\n".join(exported) if exported else None
    if pem is None:
        ASH_LOGGER.warning(
            "Could not export the system root certificates; a sandboxed scanner "
            "that reads them itself (semgrep) may fail to verify TLS."
        )
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
    ) -> str:
        home = _real(policy.home)
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
            "(allow ipc-posix-shm)",
            "(allow ipc-posix-sem)",
            "(allow file-ioctl)",
            "(allow file-read-metadata)",
            # Read anywhere, then take back the home directory and the shared temp
            # directories, then give back the paths the policy lists. In SBPL the
            # last matching rule wins.
            '(allow file-read* (subpath "/"))',
            f"(deny file-read* (subpath {_sbpl_string(home)}))",
            '(deny file-read* (subpath "/private/tmp") (subpath "/private/var/folders"))',
        ]
        if readable:
            lines.append(f"(allow file-read* {readable})")
        lines.append(f"(allow file-read* file-write* {writable})")
        lines.append(
            '(allow file-read* file-write* (literal "/dev/null") (literal "/dev/zero")'
            ' (literal "/dev/dtracehelper") (regex #"^/dev/fd/"))'
        )
        if trust_roots is not None:
            lines.append(
                f"(allow file-read* (literal {_sbpl_string(_real(trust_roots))}))"
            )
        # Last of the file rules, so no path the policy grants can reopen them: the
        # system and login keychains, whatever the keychain daemon would allow.
        lines.append(
            '(deny file-read* file-write* (subpath "/Library/Keychains")'
            f" (subpath {_sbpl_string(home / 'Library' / 'Keychains')}))"
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
        child_env = policy.filter_env(env)
        child_env["TMPDIR"] = private_tmp.as_posix()
        # Caches are read-only here; see _private_caches. uv's private cache is
        # also where `uv tool run` builds the environment of a tool it was not asked
        # to install and runs it from, so the profile lets that one run programs.
        cleanup += _private_caches(policy, child_env)
        private_uv_cache = (
            Path(child_env["UV_CACHE_DIR"])
            if "UV_CACHE_DIR" in policy.cache_env and child_env.get("UV_CACHE_DIR")
            else None
        )
        trust_roots = None
        # An SSL_CERT_FILE the operator set is passed through and wins, as it
        # would unsandboxed.
        if policy.system_trust_roots and "SSL_CERT_FILE" not in child_env:
            pem = _system_trust_roots()
            if pem is not None:
                # A directory of its own, outside the writable private TMPDIR, so
                # the profile can grant it read-only.
                roots_dir = Path(tempfile.mkdtemp(prefix="ash-sandbox-roots-"))
                cleanup.append(lambda: shutil.rmtree(roots_dir, ignore_errors=True))
                trust_roots = roots_dir / "roots.pem"
                trust_roots.write_text(pem, encoding="ascii", errors="replace")
                child_env["SSL_CERT_FILE"] = trust_roots.as_posix()
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
                policy, private_tmp, trust_roots, unpack_dir, private_uv_cache
            ),
            *argv,
        ]
        return SpawnPlan(argv=cmd, env=child_env, cleanup=cleanup)


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
