# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run the shell and python blocks of a docs page the way a reader would.

Not a test module: test_docs_examples.py runs every page through this, and
test_docs_runner_can_fail.py proves it reports what it should. Blocks and markers come
from scripts/docs_checks.py, the same parser the static checks use, so the two never
disagree about which blocks exist or what their markers say.

One page is one session. Its blocks run in document order in one copy of a fixture
project, so a later block sees the files an earlier one wrote. Each shell block is its
own bash process, and the session is carried between them: the working directory, and
every variable the block exported or assigned (blocks run under ``set -a``, so a plain
``FOO=bar`` is exported too). A python block runs in a fresh interpreter, in the
session's directory and environment, and changes neither.

Nothing a block does can reach the network or the developer's machine. HOME and the XDG
directories are private to the session, every proxy variable points at a local port
that refuses connections, the container clients point at a socket that does not exist,
and uv, pip and npm are told they are offline, so anything that tries to download fails
at once instead of after a retry budget. Measured: a
default ``ash`` scan of the sample fixture took 134 s with only the proxies set (uv
retried each tool install) and 12.6 s with UV_OFFLINE added.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
OUTPUT_TAIL_LINES = 25


def load_docs_checks():
    """scripts/docs_checks.py, loaded by path the way verify_docs_freshness.py loads it."""
    name = "_ash_docs_checks"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(
        name, REPO_ROOT / "scripts" / "docs_checks.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@dataclass
class BlockResult:
    page: str
    line: int
    lang: str
    command: str
    expected: str
    exit_code: int | None
    output: str
    seconds: float
    timed_out: bool = False
    #: Why the step failed when it is not about an exit code (a refused save-as).
    refused: str | None = None

    @property
    def ok(self) -> bool:
        if self.refused or self.timed_out or self.exit_code is None:
            return False
        if self.expected == "any":
            return True
        if self.expected == "nonzero":
            return self.exit_code != 0
        return self.exit_code == int(self.expected)

    def report(self) -> str:
        tail = "\n".join(self.output.rstrip().splitlines()[-OUTPUT_TAIL_LINES:])
        command = "\n".join(
            "    " + line for line in self.command.strip().splitlines()[:12]
        )
        if self.refused:
            verdict = self.refused
        elif self.timed_out:
            verdict = f"timed out after {self.seconds:.0f} s"
        else:
            verdict = f"exit code {self.exit_code}, expected {self.expected}"
        return (
            f"{self.page}:{self.line}: {self.lang} block failed: {verdict}\n"
            f"  command:\n{command}\n"
            f"  output (last {OUTPUT_TAIL_LINES} lines):\n"
            + "\n".join("    " + line for line in tail.splitlines())
        )


def runnable_blocks(page) -> list:
    """The blocks of a page the runner executes: unmarked or ``run`` shell and python."""
    checks = load_docs_checks()
    selected = []
    for block in page.blocks:
        if block.mode != "run" or not block.closed:
            continue
        if block.family == "python" or (
            block.family == "shell" and block.lang in checks.RUNNER_SHELLS
        ):
            selected.append(block)
    return selected


def session_blocks(page) -> list:
    """Every block a session handles, in page order: runnable ones and save-as ones.

    A save-as block whose path is refused stays in, so the refusal is reported.
    """
    runnable = {id(block) for block in runnable_blocks(page)}
    return [
        block
        for block in page.blocks
        if block.closed
        and (id(block) in runnable or (block.save_as and block.mode != "illustrative"))
    ]


def _refusing_port() -> socket.socket:
    """A bound, never-listening socket: connections to its port are refused at once."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    return sock


@dataclass
class Session:
    root: Path
    fixture: str
    cwd: Path
    env: dict[str, str]
    blocked_port: socket.socket = field(repr=False)
    #: The fixture copy the page runs in; save-as paths are relative to it.
    project: Path | None = None


_SHELL_PRELUDE = """\
__ash_docs_state=$1
__ash_docs_cwd=$2
__ash_docs_save() {
  __ash_docs_rc=$?
  env -0 > "$__ash_docs_state"
  pwd > "$__ash_docs_cwd"
  exit "$__ash_docs_rc"
}
trap __ash_docs_save EXIT
set -a
set -e
(set -o pipefail) 2>/dev/null && set -o pipefail
"""


class PageRunner:
    """Runs one page's blocks in one session and returns a result per block."""

    def __init__(
        self,
        page,
        scratch: Path,
        default_timeout: float | None = None,
        docs_root: Path | None = None,
    ):
        self.checks = load_docs_checks()
        self.page = page
        # Fixtures are docs data, so they come from the docs tree; the commands run
        # with the ASH in this interpreter's environment, whichever tree that is.
        self.docs_root = docs_root or REPO_ROOT
        self.scratch = scratch
        self.default_timeout = default_timeout or self.checks.DEFAULT_TIMEOUT_S
        self.session: Session | None = None

    # -- sessions ----------------------------------------------------------

    def _base_env(self, root: Path, port: int) -> dict[str, str]:
        home = root / "home"
        for sub in (".config", ".cache", ".local/share", ".local/state", "tmp"):
            (home / sub).mkdir(parents=True, exist_ok=True)
        proxy = f"http://127.0.0.1:{port}"
        venv_bin = str(Path(sys.executable).parent)
        env = {
            "PATH": os.pathsep.join(
                [venv_bin, os.environ.get("PATH", "/usr/bin:/bin")]
            ),
            "VIRTUAL_ENV": str(Path(sys.executable).parent.parent),
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_DATA_HOME": str(home / ".local/share"),
            "XDG_STATE_HOME": str(home / ".local/state"),
            "TMPDIR": str(home / "tmp"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TERM": "dumb",
            "COLUMNS": "100",
            "PYTHONDONTWRITEBYTECODE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": "Docs Example",
            "GIT_AUTHOR_EMAIL": "docs-example@example.com",
            "GIT_COMMITTER_NAME": "Docs Example",
            "GIT_COMMITTER_EMAIL": "docs-example@example.com",
            "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
            # No container daemon either: a scan in container mode would pull images
            # through the daemon, which does not read the proxy variables above.
            "DOCKER_HOST": f"unix://{root / 'no-docker.sock'}",
            "CONTAINER_HOST": f"unix://{root / 'no-podman.sock'}",
            "UV_OFFLINE": "1",
            "UV_NO_PROGRESS": "1",
            "PIP_NO_INDEX": "1",
            "npm_config_offline": "true",
            "NO_PROXY": "",
            "no_proxy": "",
        }
        for name in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ):
            env[name] = proxy
        return env

    def _start(self, fixture: str) -> Session:
        if self.session is not None:
            self.session.blocked_port.close()
        root = Path(tempfile.mkdtemp(prefix="session-", dir=self.scratch))
        work = root / "project"
        source = self.docs_root / self.checks.DOC_FIXTURES_DIR / fixture
        shutil.copytree(source, work, ignore=shutil.ignore_patterns(".keep"))
        port = _refusing_port()
        env = self._base_env(root, port.getsockname()[1])
        for args in (
            ["init", "-q", "-b", "main"],
            ["add", "-A"],
            ["commit", "-q", "--allow-empty", "-m", "fixture"],
        ):
            subprocess.run(
                ["git", *args], cwd=work, env=env, check=True, capture_output=True
            )
        self.session = Session(
            root=root,
            fixture=fixture,
            cwd=work,
            env=env,
            blocked_port=port,
            project=work,
        )
        return self.session

    def close(self) -> None:
        if self.session is not None:
            self.session.blocked_port.close()
            self.session = None

    # -- blocks ------------------------------------------------------------

    def _marker_value(self, block, key: str, default):
        if block.marker is None:
            return default
        return block.marker.keys.get(key, default)

    def _run_process(
        self, argv: list[str], cwd: Path, env: dict[str, str], timeout: float
    ) -> tuple[int | None, str, bool]:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            output, _ = process.communicate(timeout=timeout)
            return process.returncode, output.decode("utf-8", errors="replace"), False
        except subprocess.TimeoutExpired:
            # The block's own children share its session; end all of them.
            os.killpg(process.pid, signal.SIGKILL)
            output, _ = process.communicate()
            return None, output.decode("utf-8", errors="replace"), True

    def _save(self, block, session: Session) -> tuple[Path | None, str | None]:
        """Write a save-as block into the session's project: (path, or why it was refused).

        The path must stay inside the project: no absolute path, no "..", and no
        existing link on the way, since a link could point anywhere.
        """
        relative = block.save_as
        problem = self.checks.save_as_problem(relative)
        if problem:
            return None, f"save-as refused: {problem}"
        project = session.project or session.cwd
        target = project
        for part in [
            p for p in relative.replace("\\", "/").split("/") if p not in ("", ".")
        ]:
            target = target / part
            if target.is_symlink():
                return (
                    None,
                    f"save-as refused: {relative} goes through a link ({target.name})",
                )
        if not target.resolve().is_relative_to(project.resolve()):
            return None, f"save-as refused: {relative} leaves the page's project"
        if target.is_dir():
            return None, f"save-as refused: {relative} is a directory"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(block.body + "\n", encoding="utf-8")
        return target, None

    def run_block(self, block) -> BlockResult:
        fixture = str(self._marker_value(block, "fixture", self.checks.DEFAULT_FIXTURE))
        fresh = bool(self._marker_value(block, "fresh", False))
        session = self.session
        if session is None or fresh or fixture != session.fixture:
            session = self._start(fixture)
        saved: Path | None = None
        if block.save_as:
            saved, refused = self._save(block, session)
            if (
                refused
                or block.mode != "run"
                or block.family not in ("python", "shell")
            ):
                return BlockResult(
                    page=self.page.rel,
                    line=block.fence_line,
                    lang=block.lang,
                    command=f"save-as={block.save_as}",
                    expected="0",
                    exit_code=None if refused else 0,
                    output="",
                    seconds=0.0,
                    refused=refused,
                )
        timeout = float(self._marker_value(block, "timeout", self.default_timeout))
        expected = str(self._marker_value(block, "expect-exit", "0"))
        block_env = {}
        for pair in str(self._marker_value(block, "env", "")).split(","):
            name, sep, value = pair.strip().partition("=")
            if sep:
                block_env[name] = value
        env = {**session.env, **block_env}
        started = time.monotonic()

        if block.family == "python":
            # A saved module runs from where it was saved, so __file__ is that path.
            script = saved or session.root / f"block-{block.fence_line}.py"
            if saved is None:
                script.write_text(block.body + "\n", encoding="utf-8")
                # A reader runs the snippet as a script in the current directory, so
                # modules saved there earlier on the page import the way they would.
                env["PYTHONPATH"] = os.pathsep.join(
                    p for p in (str(session.cwd), env.get("PYTHONPATH", "")) if p
                )
            code, output, timed_out = self._run_process(
                [sys.executable, str(script)], session.cwd, env, timeout
            )
            command = block.body
        else:
            body = (
                self.checks.console_commands(block.body)
                if block.lang == "console"
                else block.body
            )
            script = session.root / f"block-{block.fence_line}.sh"
            script.write_text(_SHELL_PRELUDE + body + "\n", encoding="utf-8")
            state = session.root / "state.env"
            cwd_file = session.root / "state.cwd"
            interpreter = "sh" if block.lang == "sh" else "bash"
            code, output, timed_out = self._run_process(
                [interpreter, str(script), str(state), str(cwd_file)],
                session.cwd,
                env,
                timeout,
            )
            command = body
            self._carry_state(session, state, cwd_file, block_env)

        return BlockResult(
            page=self.page.rel,
            line=block.fence_line,
            lang=block.lang,
            command=command,
            expected=expected,
            exit_code=code,
            output=output,
            seconds=time.monotonic() - started,
            timed_out=timed_out,
        )

    @staticmethod
    def _carry_state(
        session: Session, state: Path, cwd_file: Path, block_env: dict[str, str]
    ) -> None:
        """Take the environment and directory a shell block ended with into the session."""
        if state.is_file():
            entries = state.read_bytes().split(b"\0")
            carried = {}
            for entry in entries:
                name, sep, value = entry.decode("utf-8", errors="replace").partition(
                    "="
                )
                if sep and name and not name.startswith("__ash_docs"):
                    carried[name] = value
            # A marker's env= applies to its block only.
            for name in block_env:
                if name in session.env:
                    carried[name] = session.env[name]
                else:
                    carried.pop(name, None)
            if carried:
                session.env = carried
            state.unlink()
        if cwd_file.is_file():
            directory = Path(cwd_file.read_text(encoding="utf-8").strip())
            if directory.is_dir():
                session.cwd = directory
            cwd_file.unlink()

    def run(self) -> list[BlockResult]:
        try:
            return [self.run_block(block) for block in session_blocks(self.page)]
        finally:
            self.close()


def failure_report(results: list[BlockResult]) -> str:
    failed = [r for r in results if not r.ok]
    lines = [f"{len(failed)} of {len(results)} runnable block(s) failed."]
    for position, result in enumerate(failed):
        lines.append("")
        if position:
            lines.append(
                "  (after an earlier failure on this page; this one may follow from it)"
            )
        lines.append(result.report())
    return "\n".join(lines)
