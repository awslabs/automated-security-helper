"""The MCP auth header value reaches ``ash mcp`` without being in its environment.

WHAT IS UNDER TEST
------------------
The image pipeline's two container scripts, run for real:

* ``ash-container-init`` (the ENTRYPOINT) reads the value from Secrets Manager;
* ``ash-mcp-serve`` (the CMD) builds the ``ash mcp`` command line and execs it.

The init script used to export the value as ``ASH_MCP_AUTH_HEADER_VALUE`` before
it exec'd the command, so it sat in the environment of ``ash mcp`` and of every
process ``ash`` started. A config file may read any ``ASH_*`` variable through
``${ASH_...}``, so a config naming this one copied the value into the effective
config, and from there into logs and reports.

The value now travels in an in-memory file whose descriptor the command inherits,
named by ``ASH_MCP_AUTH_HEADER_VALUE_FD``. ``ash-mcp-serve`` reads it, closes it and
removes both variables before it execs ``ash mcp``; a value an operator sets
directly as ``ASH_MCP_AUTH_HEADER_VALUE`` is removed the same way. Measured here:

* the command the init script execs has no ``ASH_MCP_AUTH_HEADER_VALUE``, a config
  it resolves that reads the variable gets nothing for it, and the descriptor holds
  the value byte for byte. The references are written ``${ASH_MCP_AUTH_HEADER_VALUE:}``
  (empty default) and ``${ASH_MCP_AUTH_HEADER_VALUE:not-set}``: those are the forms
  ``resolve_env_references`` reads a variable for. A bare ``${NAME}`` is left as
  written whether or not the variable is set, so it would pass here before the
  change too and cannot tell the two apart;
* ``ash mcp`` started through both scripts refuses a request without the header or
  with another value and accepts one with the right value, while its environment,
  its open descriptors and everything the scripts and the server printed are free
  of the value.

Secrets Manager is a local moto server (``conftest.py``); nothing leaves the host,
and the server binds loopback only.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from contextlib import closing
from pathlib import Path
from typing import Dict, Iterator, List, Optional

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
FILES = REPO_ROOT / "deploy" / "terraform" / "modules" / "ash-image-pipeline" / "files"
INIT = FILES / "ash-container-init"
SERVE = FILES / "ash-mcp-serve"

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason=(
        "the scripts run in a Linux container: the hand-over uses memfd_create, and "
        "the checks read /proc/<pid> of the server"
    ),
)

HEADER_NAME = "X-Ash-Auth"
# Distinctive, so that finding it anywhere is a finding.
SECRET_VALUE = "hdr-value-5f0c9e1d-not-for-output"  # pragma: allowlist secret

PROBE = """\
import json
import os
import sys

from automated_security_helper.config.ash_config import load_yaml_config
from automated_security_helper.config.resolve_config import resolve_config

config_path, source_dir, report_path, handover_path = sys.argv[1:5]
effective = resolve_config(config_path=config_path, source_dir=source_dir)
raw = load_yaml_config("value: ${ASH_MCP_AUTH_HEADER_VALUE:}\\n")
handed_over = None
fd_text = os.environ.get("ASH_MCP_AUTH_HEADER_VALUE_FD")
if fd_text:
    fd = int(fd_text)
    os.lseek(fd, 0, os.SEEK_SET)
    with open(fd, "rb") as handle, open(handover_path, "wb") as out:
        out.write(handle.read())
    handed_over = True
with open(report_path, "w", encoding="utf-8") as out:
    json.dump(
        {
            "environ": dict(os.environ),
            "project_name": effective.project_name,
            "raw_value": raw["value"],
            "effective": effective.model_dump(mode="json"),
            "handed_over": handed_over,
        },
        out,
    )
"""


@pytest.fixture
def secretsmanager(moto_endpoint: str):
    import boto3

    return boto3.client(
        "secretsmanager", endpoint_url=moto_endpoint, region_name="us-east-1"
    )


@pytest.fixture
def secret_arn(secretsmanager, unique_name) -> str:
    created = secretsmanager.create_secret(
        Name=unique_name("ash/mcp/auth"), SecretString=SECRET_VALUE
    )
    return created["ARN"]


def _scrubbed(env: Dict[str, str]) -> Dict[str, str]:
    """The child environment without any MCP or config variable of the suite's."""
    return {
        key: value
        for key, value in env.items()
        if not key.startswith("ASH_MCP_")
        and key not in ("ASH_CONFIG", "ASH_BASE_CONFIG_SSM_PARAMETER")
    }


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(process: subprocess.Popen, port: int, timeout: float = 90.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            out, err = process.communicate()
            raise AssertionError(
                f"the server exited {process.returncode} before it listened:\n"
                f"{out.decode(errors='replace')}\n{err.decode(errors='replace')}"
            )
        try:
            with closing(socket.create_connection(("127.0.0.1", port), timeout=0.5)):
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"the server never listened on 127.0.0.1:{port}")


def _post(port: int, header_value: Optional[str]) -> int:
    """POST an MCP initialize request; the HTTP status."""
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "auth-probe", "version": "0"},
            },
        }
    ).encode()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if header_value is not None:
        headers[HEADER_NAME] = header_value
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/mcp", data=body, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310 - loopback test server
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def _environ_of(pid: int) -> List[bytes]:
    return Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")


def _open_memfds(pid: int) -> List[str]:
    found = []
    for entry in Path(f"/proc/{pid}/fd").iterdir():
        try:
            target = os.readlink(entry)
        except OSError:
            continue
        if target.startswith("/memfd:"):
            found.append(target)
    return found


@pytest.fixture
def served(child_env, tmp_path) -> Iterator:
    """Start a command under a fresh loopback port; stop it afterwards."""
    started: List[subprocess.Popen] = []

    def start(argv: List[str], extra: Dict[str, str]):
        port = _free_port()
        env = _scrubbed(child_env)
        env.update(
            {
                "ASH_MCP_TRANSPORT": "streamable-http",
                "ASH_MCP_HOST": "127.0.0.1",
                "ASH_MCP_PORT": str(port),
                "ASH_MCP_AUTH_HEADER_NAME": HEADER_NAME,
            }
        )
        env.update(extra)
        process = subprocess.Popen(  # nosec B603 - fixed scripts, list argv
            argv,
            cwd=tmp_path,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        started.append(process)
        _wait_for_port(process, port)
        return process, port

    yield start
    for process in started:
        if process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()


def _stop(process: subprocess.Popen) -> bytes:
    process.terminate()
    out, err = process.communicate(timeout=30)
    return out + err


def _command_lines() -> List[bytes]:
    """Every process's command line, as any local user can read it."""
    lines = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            lines.append((entry / "cmdline").read_bytes())
        except OSError:
            continue
    return lines


def _assert_serves_and_keeps_the_value_to_itself(process, port):
    assert _post(port, None) == 401
    assert _post(port, "another-value") == 401
    assert _post(port, SECRET_VALUE) == 200

    cmdline = Path(f"/proc/{process.pid}/cmdline").read_bytes().split(b"\0")
    assert b"mcp" in cmdline, cmdline  # the exec'd ash mcp, not a script before it
    # Handed over on a descriptor, so the value is on no command line.
    assert b"--auth-header-value-fd" in cmdline, cmdline
    assert b"--auth-header-value" not in cmdline, cmdline
    assert not [line for line in _command_lines() if SECRET_VALUE.encode() in line]
    environ = _environ_of(process.pid)
    assert not [e for e in environ if e.startswith(b"ASH_MCP_AUTH_HEADER_VALUE")]
    assert not [e for e in environ if SECRET_VALUE.encode() in e]
    assert _open_memfds(process.pid) == []

    printed = _stop(process)
    assert SECRET_VALUE.encode() not in printed


class TestTheExecdCommandsEnvironment:
    def test_the_value_is_handed_over_outside_the_environment(
        self, child_env, secret_arn, tmp_path
    ):
        probe = tmp_path / "probe.py"
        probe.write_text(PROBE, encoding="utf-8")
        config = tmp_path / "project" / ".ash" / ".ash.yaml"
        config.parent.mkdir(parents=True)
        config.write_text(
            "project_name: ${ASH_MCP_AUTH_HEADER_VALUE:not-set}\n", encoding="utf-8"
        )
        report = tmp_path / "report.json"
        handover = tmp_path / "handover"
        env = _scrubbed(child_env)
        env["ASH_MCP_AUTH_SECRET_ARN"] = secret_arn

        result = subprocess.run(  # nosec B603 - fixed scripts, list argv
            [
                sys.executable,
                str(INIT),
                sys.executable,
                str(probe),
                str(config),
                str(config.parent.parent),
                str(report),
                str(handover),
            ],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            timeout=120,
        )

        assert result.returncode == 0, result.stderr.decode(errors="replace")
        text = report.read_text(encoding="utf-8")
        seen = json.loads(text)
        assert "ASH_MCP_AUTH_HEADER_VALUE" not in seen["environ"]
        assert seen["project_name"] == "not-set"
        assert seen["raw_value"] is None
        assert SECRET_VALUE not in text
        assert SECRET_VALUE.encode() not in result.stdout + result.stderr
        assert seen["handed_over"] is True
        assert handover.read_bytes() == SECRET_VALUE.encode()

    def test_an_unreadable_descriptor_stops_the_server_before_it_starts(
        self, child_env, tmp_path
    ):
        env = _scrubbed(child_env)
        env.update(
            {
                "ASH_MCP_AUTH_HEADER_NAME": HEADER_NAME,
                "ASH_MCP_AUTH_HEADER_VALUE_FD": "987",
            }
        )

        result = subprocess.run(  # nosec B603 - fixed script, list argv
            [sys.executable, str(SERVE)],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 1, result.stdout + result.stderr
        assert "ASH_MCP_AUTH_HEADER_VALUE_FD" in result.stderr
        assert "ash-mcp-serve: exec " not in result.stderr


STAND_IN_ASH = """\
#!{python}
import json
import os
import sys

if sys.argv[1:] == ["mcp", "--help"]:
    print("Usage: ash mcp [OPTIONS]\\n  --auth-header-name TEXT\\n  --auth-header-value TEXT")
    if os.environ.get("STAND_IN_HAS_FD") == "1":
        print("  --auth-header-value-fd INTEGER")
    sys.exit(0)
record = {{"argv": sys.argv[1:]}}
if "--auth-header-value-fd" in sys.argv:
    fd = int(sys.argv[sys.argv.index("--auth-header-value-fd") + 1])
    os.lseek(fd, 0, os.SEEK_SET)
    record["handed_over"] = os.read(fd, 65536).decode("utf-8")
with open(os.environ["STAND_IN_RECORD"], "w", encoding="utf-8") as out:
    json.dump(record, out)
"""


class TestTheHandOverToAshMcp:
    """What ash-mcp-serve passes ``ash mcp``, with a stand-in ``ash`` on PATH."""

    def _run(self, child_env, tmp_path, has_fd: bool):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        ash = bin_dir / "ash"
        ash.write_text(STAND_IN_ASH.format(python=sys.executable), encoding="utf-8")
        ash.chmod(0o755)
        record = tmp_path / "record.json"
        env = _scrubbed(child_env)
        env.update(
            {
                "PATH": f"{bin_dir}{os.pathsep}{env.get('PATH', '')}",
                "ASH_MCP_AUTH_HEADER_NAME": HEADER_NAME,
                "ASH_MCP_AUTH_HEADER_VALUE": SECRET_VALUE,
                "STAND_IN_RECORD": str(record),
                "STAND_IN_HAS_FD": "1" if has_fd else "0",
            }
        )
        result = subprocess.run(  # nosec B603 - fixed script, list argv
            [sys.executable, str(SERVE)],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        return json.loads(record.read_text(encoding="utf-8")), result.stderr

    def test_an_ash_with_the_option_gets_the_value_on_a_descriptor(
        self, child_env, tmp_path
    ):
        seen, printed = self._run(child_env, tmp_path, has_fd=True)

        assert "--auth-header-value-fd" in seen["argv"]
        assert "--auth-header-value" not in seen["argv"]
        assert SECRET_VALUE not in " ".join(seen["argv"])
        assert seen["handed_over"] == SECRET_VALUE
        assert SECRET_VALUE not in printed
        assert "WARNING" not in printed

    def test_an_older_ash_gets_it_on_the_command_line_with_a_warning(
        self, child_env, tmp_path
    ):
        seen, printed = self._run(child_env, tmp_path, has_fd=False)

        index = seen["argv"].index("--auth-header-value")
        assert seen["argv"][index + 1] == SECRET_VALUE
        assert "--auth-header-value-fd" in printed and "WARNING" in printed
        assert SECRET_VALUE not in printed


class TestTheServer:
    def test_it_authenticates_with_the_secret_and_keeps_it_out_of_its_environment(
        self, served, secret_arn
    ):
        process, port = served(
            [sys.executable, str(INIT), sys.executable, str(SERVE)],
            {"ASH_MCP_AUTH_SECRET_ARN": secret_arn},
        )

        _assert_serves_and_keeps_the_value_to_itself(process, port)

    def test_a_value_set_directly_is_kept_out_of_its_environment_too(self, served):
        """An operator may set ASH_MCP_AUTH_HEADER_VALUE instead of a secret ARN."""
        process, port = served(
            [sys.executable, str(INIT), sys.executable, str(SERVE)],
            {"ASH_MCP_AUTH_HEADER_VALUE": SECRET_VALUE},
        )

        _assert_serves_and_keeps_the_value_to_itself(process, port)
