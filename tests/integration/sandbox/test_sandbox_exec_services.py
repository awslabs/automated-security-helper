# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""sandbox-exec keeps a scanner from LaunchServices, the pasteboard and the keychain.

macOS only. The scanner is the sandbox-escape fixture plugin running
tests/test_data/sandbox_escape/macos_services_probe.py as its tool, through a real
``ash scan``, so the spawn goes through the same choke point as a builtin scanner.

Three levels: the tools a user would reach for (``open -a TextEdit``, ``pbpaste``,
``security find-generic-password``); the Mach lookup of each service itself, which
is what the profile's Mach rules decide and which a process could use without going
through those tools; and the keychain files, which the profile denies outright.

Each attempt is made twice. ``--sandbox off`` is the control and has to succeed: that
proves the session has the service to reach, which a login over SSH without a GUI
session may not (no pasteboard, no LaunchServices, a locked keychain). Then
``--sandbox sandbox-exec``, where the tool must
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
    "mach_lookup": "blocked: RuntimeError: bootstrap_look_up returned",
    "keychain_read": "blocked: RuntimeError: security did not return the keychain item",
    "read_files": "blocked: RuntimeError: no file was readable (PermissionError)",
}

#: The keychain directories the profile denies outright: the system keychain and
#: the login keychain, which keychain items live in whatever the daemon allows.
KEYCHAIN_DIRECTORIES = {
    "system": Path("/Library/Keychains"),
    "login": Path.home() / "Library" / "Keychains",
}

#: Services no scanner has a use for, looked up directly; all of them are denied
#: after every allow. LaunchServices (launchservicesd, coreservicesd and the lsd
#: database) can start apps outside the sandbox, the pasteboard holds whatever the
#: user last copied, and SecurityServer is the keychain daemon.
UNNEEDED_SERVICES = (
    "com.apple.coreservices.launchservicesd",
    "com.apple.CoreServices.coreservicesd",
    "com.apple.lsd.mapdb",
    "com.apple.pasteboard.1",
    "com.apple.SecurityServer",
)


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
def keychain_item() -> Iterator[tuple]:
    """A throwaway item in the default keychain, removed afterwards."""
    service = f"ash-sandbox-canary-{uuid.uuid4().hex}"
    canary = f"ash-keychain-canary-{uuid.uuid4().hex}"
    added = subprocess.run(  # nosec B603 - fixed argv
        [
            "/usr/bin/security",
            "add-generic-password",
            "-a",
            "ash-sandbox-test",
            "-s",
            service,
            "-w",
            canary,
        ],
        capture_output=True,
        timeout=30,
        check=False,
    )
    if added.returncode != 0:
        _unavailable(f"no writable default keychain here: {added.stderr!r}")
    yield service, canary
    subprocess.run(  # nosec B603 - fixed argv
        ["/usr/bin/security", "delete-generic-password", "-s", service],
        capture_output=True,
        timeout=30,
        check=False,
    )


@pytest.fixture
def textedit() -> Iterator[bool]:
    """Whether this test may quit TextEdit: only when it was not already running."""
    ours = not _textedit_running()
    yield ours
    if ours:
        _quit_textedit()


def _attempt(
    tmp_path: Path,
    mode: str,
    check: str,
    secret: str,
    service: str = "",
    keychain_service: str = "",
    files: "list[str] | None" = None,
) -> str:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n")
    # Copied into the source tree: the checkout can sit under $HOME, which the
    # sandbox hides, and the source tree is always readable.
    shutil.copy(PROBE, source / PROBE.name)
    (source / ".ash").mkdir()
    (source / ".ash" / ".ash.yaml").write_text("project_name: sandbox-macos-services\n")
    output = tmp_path / "out"
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(
        json.dumps(
            {
                "probe": str(source / PROBE.name),
                "secret": secret,
                "service": service,
                "keychain_service": keychain_service,
                "files": files or [],
                "checks": [check],
            }
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
        # The fixture plugin, as an operator installs one. Its module sits in this
        # git checkout, which an in-tree config may not import from.
        "--config-overrides",
        "ash_plugin_modules=[escape_plugins]",
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


def test_a_sandboxed_scanner_cannot_read_the_keychain(tmp_path_factory, keychain_item):
    _require_sandbox_exec()
    service, canary = keychain_item
    control = _attempt(
        tmp_path_factory.mktemp("control"),
        "off",
        "keychain_read",
        canary,
        keychain_service=service,
    )
    if control != "succeeded":
        _unavailable(f"security cannot read its own item even unsandboxed: {control}")

    outcome = _attempt(
        tmp_path_factory.mktemp("sandboxed"),
        "sandbox-exec",
        "keychain_read",
        canary,
        keychain_service=service,
    )
    assert outcome != "succeeded", "sandbox-exec let the scanner read the keychain"
    assert outcome.startswith(REFUSED["keychain_read"]), outcome


def _readable_files(directory: Path) -> "list[str]":
    """Files under ``directory`` this process can read, which is the control."""
    readable = []
    for path in sorted(directory.rglob("*")) if directory.is_dir() else []:
        try:
            if path.is_file():
                with open(path, "rb") as f:
                    f.read(1)
                readable.append(str(path))
        except OSError:
            continue
    return readable


@pytest.mark.parametrize("which", sorted(KEYCHAIN_DIRECTORIES))
def test_a_sandboxed_scanner_cannot_read_the_keychain_files(tmp_path_factory, which):
    _require_sandbox_exec()
    files = _readable_files(KEYCHAIN_DIRECTORIES[which])
    if not files:
        _unavailable(f"nothing under {KEYCHAIN_DIRECTORIES[which]} is readable here")
    control = _attempt(
        tmp_path_factory.mktemp("control"), "off", "read_files", "", files=files
    )
    if control != "succeeded":
        _unavailable(f"the probe cannot read {files} even unsandboxed: {control}")

    outcome = _attempt(
        tmp_path_factory.mktemp("sandboxed"),
        "sandbox-exec",
        "read_files",
        "",
        files=files,
    )
    assert outcome != "succeeded", (
        f"sandbox-exec let the scanner read a file under {KEYCHAIN_DIRECTORIES[which]}"
    )
    assert outcome == REFUSED["read_files"], outcome


@pytest.mark.parametrize("service", UNNEEDED_SERVICES)
def test_a_sandboxed_scanner_cannot_look_up_an_unneeded_service(
    tmp_path_factory, service
):
    _require_sandbox_exec()
    control = _attempt(
        tmp_path_factory.mktemp("control"), "off", "mach_lookup", "", service
    )
    if control != "succeeded":
        _unavailable(f"{service} cannot be looked up even unsandboxed: {control}")

    outcome = _attempt(
        tmp_path_factory.mktemp("sandboxed"), "sandbox-exec", "mach_lookup", "", service
    )
    assert outcome != "succeeded", f"sandbox-exec let the scanner look up {service}"
    assert outcome.startswith(REFUSED["mach_lookup"]), outcome
