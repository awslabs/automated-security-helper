# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline mode must actually reach the subprocess with corepack's network off.

Why this file exists
--------------------
#451 taught npm-audit to set ``COREPACK_ENABLE_NETWORK=0`` when
``options.offline`` is set. ``COREPACK_ENABLE_DOWNLOAD_PROMPT=0`` (set in the
Dockerfile) stops corepack *asking* before it downloads a package manager; it
does not stop the download. In offline mode a download is wrong twice over --
there is no network, so it fails, and it fails instead of using the package
manager already cached in the image.

Nothing tested it. Grepping the tree for ``COREPACK_ENABLE_NETWORK`` before this
file found two hits, both in the scanner source and neither in a test, and that
absence let two separate defects through:

1. ``os.environ`` was used to build the environment while the module never
   imported ``os``. ruff reports it as F821 and offline scans raised
   ``NameError: name 'os' is not defined``. It shipped to main, because the only
   code path that evaluates the expression is guarded by ``options.offline`` and
   no test set that flag.

2. A later merge resolved a conflict on the ``_run_subprocess`` call by keeping
   the ``timeout=`` argument the other side added and dropping ``env=``. The
   ``subprocess_env`` local was still computed just above the call, so the code
   read as though it worked while the environment reached nothing -- a silent
   revert of #451 that no test noticed.

Both failure modes are invisible in a diff that looks reasonable, which is why
the assertion here is on what ``_run_subprocess`` actually receives rather than
on the shape of the source.

Why assert on the call rather than run corepack
-----------------------------------------------
The contract worth pinning is "the offline environment reaches the child
process". Actually invoking pnpm would need a package manager, a lock file and a
network policy in the test environment, and would still not distinguish "env was
never passed" from "corepack ignored it". The double records its kwargs, so a
dropped argument fails loudly and immediately.
"""

from unittest.mock import patch

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    npm_audit_scanner as npm_audit_module,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
    NpmAuditScannerConfigOptions,
)


def _scanner(context, *, offline: bool):
    scanner = NpmAuditScanner(
        context=context,
        config=NpmAuditScannerConfig(
            options=NpmAuditScannerConfigOptions(offline=offline)
        ),
    )
    scanner.exit_code = 0
    scanner.dependencies_satisfied = True
    scanner.tool_version = "1.0.0"
    return scanner


def _run_scan(scanner, tmp_path):
    """Drive scan() over one pnpm project and return the recorded kwargs.

    ``fake_run`` takes ``**kwargs`` deliberately. Pinning the real signature here
    would make this test fail whenever _run_subprocess gains an argument, which
    is what happened to the syft double when ``timeout`` was added -- and a test
    that breaks for that reason gets "fixed" by loosening the assertion.
    """
    root = tmp_path / "repo"
    nested = root / "packages" / "sub"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text('{"name":"sub"}')
    (nested / "pnpm-lock.yaml").write_text("")
    scanner.context.source_dir = root

    captured = []

    def fake_run(command, **kwargs):
        captured.append(kwargs)
        return {"stdout": '{"vulnerabilities":{}}', "returncode": 0}

    with (
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner.find_executable",
            return_value="/usr/local/bin/pnpm",
        ),
        patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner.scan_set",
            return_value=[str(nested / "package.json")],
        ),
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=fake_run),
    ):
        scanner.scan(target=root, target_type="source")

    return captured


def test_the_module_binds_os():
    """Names the NameError directly, so the diagnosis is not 'offline scan broke'.

    Kept separate from the behavioural tests because it fails for exactly one
    reason and says so, where the scan-level test below fails for either defect.
    """
    assert hasattr(npm_audit_module, "os"), (
        "npm_audit_scanner builds its offline environment from os.environ but "
        "does not import os; offline scans raise NameError"
    )


def test_offline_mode_disables_corepack_network(test_plugin_context, tmp_path):
    """The whole point of #451: the child process must see the flag."""
    scanner = _scanner(test_plugin_context, offline=True)

    captured = _run_scan(scanner, tmp_path)

    assert captured, "scan() never reached _run_subprocess"
    envs = [kw.get("env") for kw in captured]
    assert any(
        env is not None and env.get("COREPACK_ENABLE_NETWORK") == "0" for env in envs
    ), (
        "offline mode did not pass COREPACK_ENABLE_NETWORK=0 to the subprocess; "
        f"envs seen: {[None if e is None else sorted(set(e) & {'COREPACK_ENABLE_NETWORK'}) for e in envs]}"
    )


def test_the_offline_environment_still_carries_the_parent_environment(
    test_plugin_context, tmp_path
):
    """Replacing rather than extending os.environ would strip PATH, and the
    package manager is found on PATH."""
    scanner = _scanner(test_plugin_context, offline=True)

    captured = _run_scan(scanner, tmp_path)

    env = next(
        kw["env"]
        for kw in captured
        if kw.get("env") and kw["env"].get("COREPACK_ENABLE_NETWORK") == "0"
    )
    for key in os_keys_expected_present():
        assert key in env, f"offline env dropped {key} from the parent environment"


def os_keys_expected_present():
    """Parent-environment keys that are present on every platform CI runs on.

    PATH is the load-bearing one; it is how the package manager is located.
    """
    return ["PATH"]


@pytest.mark.parametrize("offline", [False])
def test_online_mode_passes_no_environment_override(
    test_plugin_context, tmp_path, offline
):
    """Online scans must not inherit the offline override.

    Asserting None rather than "no COREPACK_ENABLE_NETWORK key" on purpose: the
    scanner's contract is that it does not touch the environment unless offline,
    and passing a full copy of os.environ online would silently change what the
    child inherits if the caller ever set that variable themselves.
    """
    scanner = _scanner(test_plugin_context, offline=offline)

    captured = _run_scan(scanner, tmp_path)

    assert captured, "scan() never reached _run_subprocess"
    assert all(kw.get("env") is None for kw in captured), (
        f"online scan passed an env override: {[kw.get('env') for kw in captured]}"
    )
