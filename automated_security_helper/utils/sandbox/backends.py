"""Sandbox backends: turn a :class:`SandboxPolicy` into a command line.

Each backend answers two questions. ``probe()`` says whether it can actually start a
sandbox on this machine, by starting one, because "the binary is on PATH" is not the
same thing: Ubuntu 24.04 ships a bwrap that AppArmor stops from creating a user
namespace unless it is the packaged one, and a kernel can be built without Landlock.
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


@dataclass
class SpawnPlan:
    """What to hand ``subprocess`` in place of the scanner's own argv and env."""

    argv: List[str]
    env: Dict[str, str]
    cleanup: List[Callable[[], None]] = field(default_factory=list)

    def run_cleanup(self) -> None:
        for fn in self.cleanup:
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


def _probe_run(
    argv: Sequence[str], env: Optional[Mapping[str, str]] = None
) -> Optional[str]:
    """Run ``argv``; None if it exited 0, otherwise its stderr as the reason."""
    result = subprocess.run(  # nosec B603 - fixed argv built in this module
        list(argv),
        capture_output=True,
        text=True,
        timeout=PROBE_TIMEOUT_SECONDS,
        env=dict(env) if env is not None else {"PATH": os.environ.get("PATH", "")},
        check=False,
    )
    if result.returncode == 0:
        return None
    detail = (result.stderr or result.stdout or "").strip().splitlines()
    return f"exit {result.returncode}: {detail[-1] if detail else 'no output'}"


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
        with tempfile.TemporaryDirectory(prefix="ash-bwrap-probe-") as tmp:
            overlay_failure = _probe_run(
                base + ["--overlay-src", tmp, "--tmp-overlay", tmp, "true"]
            )
        self._overlay = overlay_failure is None
        if not self._overlay:
            ASH_LOGGER.warning(
                "bwrap cannot mount a throwaway overlay here (needs bubblewrap 0.8+ "
                "and Linux 5.11+): scanner caches will be mounted read-write, so a "
                "scanner can change what a later scan reads from them."
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
            add(p, _CACHE if self._overlay else _RW)
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
        cmd.extend(argv)
        return SpawnPlan(argv=cmd, env=policy.filter_env(env))


# ---------------------------------------------------------------------------
# firejail
# ---------------------------------------------------------------------------


class FirejailBackend(SandboxBackend):
    name = "firejail"
    platforms = ("linux",)

    def __init__(self) -> None:
        self._executable: Optional[str] = None

    def _probe(self) -> Optional[str]:
        found = shutil.which("firejail")
        if not found:
            return "firejail is not installed"
        self._executable = found
        return _probe_run([found, "--quiet", "--noprofile", "--net=none", "true"])

    def plan(
        self, argv: Sequence[str], env: Mapping[str, str], policy: SandboxPolicy
    ) -> SpawnPlan:
        if not self._executable:
            raise RuntimeError(f"{self.name}: probe() must succeed before plan()")
        home = _real(policy.home)
        tmp_root = _real(Path("/tmp"))  # nosec B108 - compared against, never written
        cmd = [
            self._executable,
            "--quiet",
            "--noprofile",
            "--private-dev",
            "--nonewprivs",
            "--caps.drop=all",
            "--seccomp",
            "--nogroups",
            "--dbus-user=none",
            "--dbus-system=none",
            "--read-only=/",
        ]
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

        readable = [_real(p) for p in policy.read_only]
        writable = [_real(p) for p in policy.writable] + [
            _real(p) for p in policy.cache
        ]
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
            if p not in writable:
                cmd.append(f"--read-only={p.as_posix()}")
        for p in writable:
            cmd.append(f"--read-write={p.as_posix()}")
        cmd.append("--")
        cmd.extend(argv)
        return SpawnPlan(argv=cmd, env=policy.filter_env(env))


# ---------------------------------------------------------------------------
# Landlock
# ---------------------------------------------------------------------------

LANDLOCK_EXEC = Path(__file__).with_name("landlock_exec.py")


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
                shutil.which("true") or "/bin/true",
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
            "read_only": [_real(p).as_posix() for p in policy.read_only]
            + ["/proc", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/full"],
            "writable": [_real(p).as_posix() for p in policy.writable]
            + [_real(p).as_posix() for p in policy.cache]
            # /dev/shm because POSIX semaphores live there and multiprocessing needs
            # them (detect-secrets scans files in a process pool). Landlock cannot
            # make it private, so this is the host's: a documented gap of this
            # backend that bwrap does not have. Not /dev/tty or /dev/pts: the
            # wrapper starts a new session, so there is no terminal to reach.
            # nosec B108 - a Landlock grant, not a file ASH creates
            + [private_root.as_posix(), "/dev/null", "/dev/shm"],  # nosec B108
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
        return SpawnPlan(
            argv=cmd,
            env=child_env,
            cleanup=[lambda: shutil.rmtree(private_root, ignore_errors=True)],
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
    text = path.as_posix()
    if any(ord(ch) < 0x20 for ch in text):
        raise SandboxUnavailable(f"cannot express {text!r} in a sandbox-exec profile")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


#: Starts a new session, so there is no controlling terminal to inject keystrokes
#: into through TIOCSTI, then execs the rest of argv. macOS ships no setsid(1).
_SETSID_EXEC = "import os,sys;os.setsid();os.execv(sys.argv[1],sys.argv[1:])"


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

    def profile(self, policy: SandboxPolicy, private_tmp: Path) -> str:
        home = _real(policy.home)
        readable = " ".join(
            f"(subpath {_sbpl_string(_real(p))})" for p in policy.read_only
        )
        writable = " ".join(
            f"(subpath {_sbpl_string(_real(p))})"
            for p in list(policy.writable) + list(policy.cache) + [private_tmp]
        )
        lines = [
            "(version 1)",
            "(deny default)",
            "(allow process-fork)",
            "(allow process-exec)",
            "(allow signal (target same-sandbox))",
            "(allow process-info* (target same-sandbox))",
            "(allow sysctl-read)",
            "(allow mach-lookup)",
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
        cmd = [
            sys.executable,
            "-I",
            "-c",
            _SETSID_EXEC,
            self.executable,
            "-p",
            self.profile(policy, private_tmp),
            *argv,
        ]
        child_env = policy.filter_env(env)
        child_env["TMPDIR"] = private_tmp.as_posix()
        return SpawnPlan(
            argv=cmd,
            env=child_env,
            cleanup=[lambda: shutil.rmtree(private_tmp, ignore_errors=True)],
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
