# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Under each sandbox, the Snyk CLI can read the copy of the scan set it is given.

snyk-code tests a copy of the scan set that it makes in a temporary directory
outside the source tree and the output directory, because Snyk Code has no exclude
option. Nothing else grants a sandboxed tool that directory, so the scanner grants
it read access for the one run. A stand-in ``snyk`` on PATH records the directory
it was given, what it could read there, and whether it could read a file in a
directory beside the copy under the same TMPDIR. The neighbor is the control: it is
readable with ``--sandbox off`` and unreadable under a sandbox, which shows the
sandbox was confining the tool and that the copy was readable because of the grant.

A backend that is not available on the machine is skipped, unless it is named in
ASH_REQUIRE_SANDBOX_BACKENDS.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.sandbox import clear_backend_cache, resolve_backend
from automated_security_helper.utils.sandbox.scope import SandboxUnavailable
from tests.utils.helpers import importing_this_checkout
from tests.utils.stand_in_uv import (
    UV_PROBED_TOOLS,
    assert_reached_the_stand_in,
    calls_naming,
    install_stand_in_uv,
    reaching_the_stand_in,
    recorded_calls,
    stand_in_env,
)

pytestmark = pytest.mark.integration

BACKENDS = ["bwrap", "firejail", "landlock", "sandbox-exec"]

STAND_IN = """#!/bin/sh
# Stand-in for the Snyk CLI. It writes, next to its SARIF output (a path every
# sandbox lets a scanner write), the directory it was given, the files it could
# read there, and whether it could read a file in a directory beside that one. The
# neighbor's path is derived from the target because the sandbox does not pass
# arbitrary environment variables through.
target=""
for a in "$@"; do
  case "$a" in
    --sarif-file-output=*) out="${a#--sarif-file-output=}" ;;
    code|test|--*) ;;
    *) target="$a" ;;
  esac
done
record="$(dirname "$out")/stand-in-saw.json"
files=$(cd "$target" 2>/dev/null && find . -type f | sort | sed 's/.*/"&"/' | paste -sd, -)
if cat "$(dirname "$target")/neighbor/file.txt" >/dev/null 2>&1; then neighbor=true; else neighbor=false; fi
printf '{"target": "%s", "files": [%s], "neighbor_readable": %s}' \\
  "$target" "$files" "$neighbor" > "$record"
printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"SnykCode","rules":[]}},"results":[]}]}' > "$out"
exit 0
"""


def _required() -> set:
    raw = os.environ.get("ASH_REQUIRE_SANDBOX_BACKENDS", "")
    return {name.strip() for name in raw.split(",") if name.strip()}


def _require_backend(name: str) -> None:
    clear_backend_cache()
    try:
        resolve_backend(name)
    except SandboxUnavailable as e:
        if name in _required():
            pytest.fail(f"{name} is required (ASH_REQUIRE_SANDBOX_BACKENDS) but: {e}")
        pytest.skip(f"{name} unavailable: {e}")


#: `ash`, in a child of this interpreter that reaches the stand-in uv.
ASH_DRIVER = reaching_the_stand_in(
    """
    import sys

    from automated_security_helper.cli.main import app

    sys.argv = ["ash", *sys.argv[1:]]
    app()
    """
)


def _scan(tmp_path: Path, mode: str) -> dict:
    source = tmp_path / "src"
    (source / "app").mkdir(parents=True)
    (source / "app" / "main.js").write_text("console.log('hello');\n")
    (source / ".ash").mkdir()
    # No ignore path: snyk-code does not run on a tree that holds a file one
    # matches, so a tree with one never reaches the copy.
    (source / ".ash" / ".ash.yaml").write_text("project_name: snyk-copy-grant\n")
    output = tmp_path / "out"
    # TMPDIR inside a stand-in $HOME: firejail hides only what is in $HOME or /tmp
    # and not whitelisted, so a neighbor anywhere else would be visible to it
    # whatever the grant.
    home = tmp_path / "home"
    temp_root = home / "tmp"
    neighbor = temp_root / "neighbor" / "file.txt"
    neighbor.parent.mkdir(parents=True)
    neighbor.write_text("not granted\n")
    # Not in a directory named bin: a sandbox grants a tool in <prefix>/bin read
    # access to the whole <prefix> (policy._executable_prefix), which here would be
    # tmp_path and would include the copy.
    bin_dir = tmp_path / "stand-in"
    bin_dir.mkdir()
    stand_in = bin_dir / "snyk"
    stand_in.write_text(STAND_IN)
    stand_in.chmod(0o755)

    # A stand-in uv as well, which records any call: the run is online, because
    # snyk-code does not run offline, and no unselected scanner may ask uv about its
    # tool (checked by the unsandboxed control below).
    uv_bin, uv_log = install_stand_in_uv(tmp_path / "uv-stand-in")
    env = {
        **os.environ,
        "PATH": os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]),
        "HOME": str(home),
        "TMPDIR": str(temp_root),
        "SNYK_TOKEN": "stand-in",
    }
    env = stand_in_env(uv_bin, uv_log, env)
    env.pop("ASH_OFFLINE", None)
    command = [
        sys.executable,
        "-I",
        "-c",
        importing_this_checkout(ASH_DRIVER),
        "scan",
        "--source-dir",
        str(source),
        "--output-dir",
        str(output),
        "--mode",
        "local",
        "--scanners",
        "snyk-code",
        "--ash-plugin-modules",
        "automated_security_helper.plugin_modules.ash_snyk_plugins",
        "--sandbox",
        mode,
        "--no-progress",
        # A flag pair: "--fail-on-findings false" is an unexpected argument, exit 5.
        "--no-fail-on-findings",
    ]
    result = subprocess.run(  # nosec B603 - fixed argv
        command,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    record = output / "scanners" / "snyk-code" / "source" / "stand-in-saw.json"
    assert record.exists(), (
        f"the stand-in snyk did not run (exit {result.returncode}):\n"
        f"{result.stdout[-3000:]}\n{result.stderr[-3000:]}"
    )
    saw = json.loads(record.read_text())
    saw["leftover"] = sorted(
        path.name for path in temp_root.iterdir() if path.name.startswith("ash-snyk")
    )
    saw["source"] = source
    saw["output"] = output
    saw["temp_root"] = temp_root
    saw["uv_calls"] = recorded_calls(uv_log)
    return saw


def _assert_tested_the_copy(saw: dict) -> None:
    target = Path(saw["target"])
    assert target.parent == saw["temp_root"], target
    assert not target.is_relative_to(saw["source"]), target
    assert not target.is_relative_to(saw["output"]), target
    assert saw["files"] == ["./.ash/.ash.yaml", "./app/main.js"], saw["files"]
    assert saw["leftover"] == [], "the copy outlived the run"


def test_without_a_sandbox_the_neighbor_is_readable(tmp_path):
    """The control: the stand-in's neighbor check can succeed."""
    saw = _scan(tmp_path, "off")
    _assert_tested_the_copy(saw)
    assert saw["neighbor_readable"] is True
    # Online, and still no tool resolved for a scanner this run did not select, by
    # a run that did reach the stand-in uv.
    assert_reached_the_stand_in(saw["uv_calls"])
    assert calls_naming(saw["uv_calls"], UV_PROBED_TOOLS) == [], saw["uv_calls"]


@pytest.mark.parametrize("backend", BACKENDS)
def test_a_sandboxed_snyk_reads_the_copy_and_nothing_beside_it(tmp_path, backend):
    _require_backend(backend)
    saw = _scan(tmp_path, backend)
    _assert_tested_the_copy(saw)
    assert saw["neighbor_readable"] is False, (
        f"{backend} let the tool read a file beside the copy: either the grant is "
        "wider than the copy or the sandbox is not confining the tool"
    )
