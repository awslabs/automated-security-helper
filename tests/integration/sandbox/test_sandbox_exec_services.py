# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Under sandbox-exec, a scanner cannot reach LaunchServices or the pasteboard.

macOS only. The scanner is the sandbox-escape fixture plugin running
tests/test_data/sandbox_escape/macos_services_probe.py as its tool, through a real
``ash scan``, so the spawn goes through the same choke point as a builtin scanner.

Each attempt is made twice. ``--sandbox off`` is the control and has to succeed: that
proves the session has a pasteboard and a LaunchServices to reach, which a login over
SSH without a GUI session does not. Then ``--sandbox sandbox-exec``, where the tool must
start (exec is allowed) and the service must refuse it. A control that fails skips the
test, unless ASH_REQUIRE_SANDBOX_BACKENDS names sandbox-exec, as CI's macOS leg does,
in which case it fails.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Iterator

import pytest

from automated_security_helper.utils.sandbox import clear_backend_cache, resolve_backend
from automated_security_helper.utils.sandbox.scope import SandboxUnavailable

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "darwin", reason="sandbox-exec is macOS only"),
]

FIXTURE = Path(__file__).resolve().parents[2] / "test_data" / "sandbox_escape"
PROBE = FIXTURE / "macos_services_probe.py"

#: What the sandboxed attempt must fail with: the tool ran and the service refused.
#: A PermissionError here would mean exec was denied, which is not what is tested.
REFUSED = {
    "launch_services": "blocked: RuntimeError: open exited",
    "pasteboard_read": "blocked: RuntimeError: pbpaste did not return the pasteboard",
}


def _required() -> bool:
    raw = os.environ.get("ASH_REQUIRE_SANDBOX_BACKENDS", "")
    return "sandbox-exec" in {name.strip() for name in raw.split(",")}


def _unavailable(reason: str) -> None:
    if _required():
        pytest.fail(
            f"sandbox-exec is required (ASH_REQUIRE_SANDBOX_BACKENDS): {reason}"
        )
    pytest.skip(reason)


def _require_sandbox_exec() -> None:
    clear_backend_cache()
    try:
        resolve_backend("sandbox-exec")
    except SandboxUnavailable as e:
        _unavailable(f"sandbox-exec unavailable: {e}")


def _ash_executable() -> str:
    beside = Path(sys.executable).with_name("ash")
    found = str(beside) if beside.exists() else shutil.which("ash")
    if not found:
        pytest.fail("the ash entry point is not installed beside this interpreter")
    return found


def _textedit_running() -> bool:
    return (
        subprocess.run(  # nosec B603 - fixed argv
            ["/usr/bin/pgrep", "-x", "TextEdit"], capture_output=True, check=False
        ).returncode
        == 0
    )


def _quit_textedit() -> None:
    subprocess.run(  # nosec B603 - fixed argv
        ["/usr/bin/pkill", "-x", "TextEdit"], capture_output=True, check=False
    )
    deadline = time.monotonic() + 15
    while _textedit_running() and time.monotonic() < deadline:
        time.sleep(0.2)


@pytest.fixture
def pasteboard() -> Iterator[str]:
    """A fresh canary on the pasteboard; what was there before is put back."""
    saved = subprocess.run(  # nosec B603 - fixed argv
        ["/usr/bin/pbpaste"], capture_output=True, timeout=30, check=False
    ).stdout
    canary = f"ash-pasteboard-canary-{uuid.uuid4().hex}"
    copied = subprocess.run(  # nosec B603 - fixed argv
        ["/usr/bin/pbcopy"],
        input=canary.encode(),
        capture_output=True,
        timeout=30,
        check=False,
    )
    if copied.returncode != 0:
        _unavailable(
            f"pbcopy failed, so there is no pasteboard here: {copied.stderr!r}"
        )
    yield canary
    subprocess.run(  # nosec B603 - fixed argv
        ["/usr/bin/pbcopy"], input=saved, capture_output=True, timeout=30, check=False
    )


@pytest.fixture
def textedit() -> Iterator[bool]:
    """Whether this test may quit TextEdit: only when it was not already running."""
    ours = not _textedit_running()
    yield ours
    if ours:
        _quit_textedit()


def _attempt(tmp_path: Path, mode: str, check: str, secret: str) -> str:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n")
    # Copied into the source tree: the checkout can sit under $HOME, which the
    # sandbox hides, and the source tree is always readable.
    shutil.copy(PROBE, source / PROBE.name)
    (source / ".ash").mkdir()
    (source / ".ash" / ".ash.yaml").write_text(
        "project_name: sandbox-macos-services\nash_plugin_modules:\n  - escape_plugins\n"
    )
    output = tmp_path / "out"
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(
        json.dumps(
            {"probe": str(source / PROBE.name), "secret": secret, "checks": [check]}
        )
    )
    env = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join(
            [str(FIXTURE), os.environ.get("PYTHONPATH", "")]
        ).rstrip(os.pathsep),
        "ASH_SANDBOX_ESCAPE_SPEC": str(spec_file),
    }
    command = [
        _ash_executable(),
        "scan",
        "--source-dir",
        str(source),
        "--output-dir",
        str(output),
        "--scanners",
        "sandbox-escape",
        "--sandbox",
        mode,
        "--offline",
        "--no-progress",
        "--fail-on-findings",
        "false",
    ]
    result = subprocess.run(  # nosec B603 - fixed argv
        command, env=env, capture_output=True, text=True, timeout=600, check=False
    )
    outcome_file = output / "scanners" / "sandbox-escape" / "source" / "outcome.json"
    assert outcome_file.exists(), (
        f"the probe wrote no outcome under --sandbox {mode} (exit {result.returncode})."
        f"\nstdout:\n{result.stdout[-4000:]}\nstderr:\n{result.stderr[-4000:]}"
    )
    return json.loads(outcome_file.read_text())[check]


def test_a_sandboxed_scanner_cannot_open_an_app_through_launch_services(
    tmp_path_factory, textedit
):
    _require_sandbox_exec()
    control = _attempt(tmp_path_factory.mktemp("control"), "off", "launch_services", "")
    if control != "succeeded":
        _unavailable(f"open -a TextEdit fails even unsandboxed: {control}")
    if textedit:
        assert _textedit_running(), "the control's open -a TextEdit started nothing"
        _quit_textedit()

    outcome = _attempt(
        tmp_path_factory.mktemp("sandboxed"), "sandbox-exec", "launch_services", ""
    )
    assert outcome != "succeeded", (
        "sandbox-exec let the scanner open TextEdit through LaunchServices, and an "
        "app launched that way runs outside the sandbox"
    )
    assert outcome.startswith(REFUSED["launch_services"]), outcome
    if textedit:
        assert not _textedit_running(), "TextEdit was started from inside the sandbox"


def test_a_sandboxed_scanner_cannot_read_the_pasteboard(tmp_path_factory, pasteboard):
    _require_sandbox_exec()
    control = _attempt(
        tmp_path_factory.mktemp("control"), "off", "pasteboard_read", pasteboard
    )
    if control != "succeeded":
        _unavailable(f"pbpaste cannot read the pasteboard even unsandboxed: {control}")

    outcome = _attempt(
        tmp_path_factory.mktemp("sandboxed"),
        "sandbox-exec",
        "pasteboard_read",
        pasteboard,
    )
    assert outcome != "succeeded", "sandbox-exec let the scanner read the pasteboard"
    assert outcome.startswith(REFUSED["pasteboard_read"]), outcome
