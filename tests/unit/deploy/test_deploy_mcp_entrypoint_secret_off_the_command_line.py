"""The committed MCP entrypoint passes the shared secret on a descriptor, not argv.

WHAT IS UNDER TEST
------------------
The MCP entrypoint as every committed template under ``deploy/cdk/templates/``
writes it into its image, run for real with a stand-in ``ash`` and a stand-in
``python3`` in place of the Secrets Manager read.

A process's command line is readable by every user in the container, and from the
host by anyone who can list its processes. When the image's ``ash mcp --help``
lists ``--auth-header-value-fd``, the entrypoint passes the secret on descriptor 3,
a here-document, so it is on no command line. An ``ash mcp`` without the option
(an older AshVersion) still gets ``--auth-header-value``, the only form it takes.

The templates are the deliverable, so this runs what they carry, not the
TypeScript constant; ``deploy/cdk/test/ash-container-scripts.test.ts`` runs the
constant.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
from typing import Dict, List, Optional, Tuple

import pytest

from tests.unit.deploy.buildspec_extraction import (
    MCP_ENTRYPOINT_MARKER,
    heredoc_body,
    joined_buildspec_document,
    posix_shell,
    sole_command_containing,
    templates_with_joined_buildspec_marker,
)

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="executes a POSIX entrypoint destined for a Linux container",
)

ENTRYPOINT_DESTINATION = "ash-src/ash-mcp-entrypoint.sh"
DELIMITER = "ASH_CDK_EOF"
# Characters a here-document or an expansion would mangle if the quoting were wrong.
SECRET = "hdr-${not-expanded}-`not-run`-$HOME-a1b2c3"  # pragma: allowlist secret

STAND_IN_ASH = """\
#!/bin/sh
if [ "$1" = "mcp" ] && [ "$2" = "--help" ]; then
  echo "  --stateless-http/--no-stateless-http"
  echo "  --allowed-host TEXT"
  echo "  --auth-header-name TEXT"
  echo "  --auth-header-value TEXT"
  if [ -n "${STAND_IN_FD:-}" ]; then
    echo "  --auth-header-value-fd INTEGER"
  fi
  exit 0
fi
: > "$STAND_IN_ARGV"
for arg in "$@"; do
  printf '%s\\n' "$arg" >> "$STAND_IN_ARGV"
done
if [ -n "${STAND_IN_FD:-}" ]; then
  cat <&3 > "$STAND_IN_ARGV.fd3"
fi
"""


def _templates() -> Dict[str, dict]:
    return templates_with_joined_buildspec_marker(MCP_ENTRYPOINT_MARKER)


@pytest.fixture(params=sorted(_templates()))
def entrypoint(request) -> str:
    buildspec = joined_buildspec_document(
        _templates()[request.param], MCP_ENTRYPOINT_MARKER
    )
    command = sole_command_containing(
        buildspec, "build", f"{ENTRYPOINT_DESTINATION} <<'{DELIMITER}'"
    )
    body = heredoc_body(command, delimiter=DELIMITER)
    assert "ash mcp" in body, f"{request.param}: not the MCP entrypoint"
    return body


def _run(
    entrypoint: str, tmp_path: pathlib.Path, with_fd: bool
) -> Tuple[int, List[str], Optional[bytes]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    ash = bin_dir / "ash"
    ash.write_text(STAND_IN_ASH, encoding="utf-8")
    ash.chmod(0o755)
    secret_file = tmp_path / "secret"
    secret_file.write_text(SECRET, encoding="utf-8")
    python3 = bin_dir / "python3"
    python3.write_text(f"#!/bin/sh\ncat '{secret_file}'\n", encoding="utf-8")
    python3.chmod(0o755)
    script = tmp_path / "entrypoint.sh"
    script.write_text(entrypoint, encoding="utf-8")
    argv_file = tmp_path / "argv"
    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "HOME": str(tmp_path / "home"),
        "STAND_IN_ARGV": str(argv_file),
        "STAND_IN_FD": "1" if with_fd else "",
        "ASH_MCP_STATELESS": "false",
        "ASH_MCP_ALLOWED_HOST": "alb.example.com",
        "ASH_MCP_AUTH_HEADER_NAME": "X-Ash-Token",
        # Only checked for being set; the stand-in python3 answers for the read.
        "ASH_MCP_AUTH_HEADER_VALUE_SECRET_ARN": "probe-secret-arn",  # pragma: allowlist secret
    }
    result = subprocess.run(  # nosec B603 - the committed entrypoint, list argv
        [posix_shell(env), str(script)],
        capture_output=True,
        env=env,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    argv = argv_file.read_text(encoding="utf-8").splitlines()
    fd3 = pathlib.Path(f"{argv_file}.fd3")
    return result.returncode, argv, fd3.read_bytes() if fd3.exists() else None


def test_the_secret_goes_on_a_descriptor_when_ash_takes_one(entrypoint, tmp_path):
    _status, argv, fd3 = _run(entrypoint, tmp_path, with_fd=True)

    assert "--auth-header-value-fd" in argv, argv
    assert "--auth-header-value" not in argv, argv
    assert not [arg for arg in argv if SECRET in arg], argv
    assert fd3 == SECRET.encode() + b"\n"


def test_an_older_ash_still_gets_the_secret_on_argv(entrypoint, tmp_path):
    _status, argv, _fd3 = _run(entrypoint, tmp_path, with_fd=False)

    assert "--auth-header-value-fd" not in argv, argv
    assert argv[argv.index("--auth-header-value") + 1] == SECRET
