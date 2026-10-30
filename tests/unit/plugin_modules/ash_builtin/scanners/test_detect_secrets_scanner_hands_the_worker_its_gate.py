# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""DetectSecretsScanner hands utils/detect_secrets_worker.py its two gates.

The worker refuses every HTTP request detect-secrets tries unless its environment
states ``REFUSE_HTTP_ENV`` as exactly ``"0"``, and it drops an entry a baseline it
is handed accepted only when the request says ``"baseline_trusted": true``. Both
halves are tested on their own beside the worker, and each half of the handoff
has its own pin through the real scan
(test_detect_secrets_worker_env_always_states_refusal.py for the environment,
test_detect_secrets_baseline_entries_are_known.py for the request's flag). This
file reads BOTH from one call of the scanner's own ``_scan_in_worker``: the
environment the worker is spawned with states ``"0"`` only when the scan may
verify and ``"1"`` otherwise, an inherited value of the same name is replaced,
and the request file carries the trust flag as a JSON bool. Placeholder values
only; nothing here is a credential.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.utils.detect_secrets_worker import (
    BASELINE_TRUSTED_KEY,
    REFUSE_HTTP_ENV,
)

pytestmark = pytest.mark.unit


def _worker_ready_scanner(tmp_path, monkeypatch):
    """A scanner and a work directory inside a results tree, set up to call
    ``_scan_in_worker`` directly, as the stale-worker-files tests do."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        detect_secrets_scanner as module,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
        DetectSecretsScannerConfig,
    )

    # Into tmp_path first: the baseline lookup checks .secrets.baseline paths
    # against the working directory.
    monkeypatch.chdir(tmp_path)
    for name in ("source", "output", "work"):
        (tmp_path / name).mkdir()
    (tmp_path / "source" / "app.py").write_text("x = 1\n", encoding="utf-8")
    ctx = PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="worker-gates"),
    )
    scanner = DetectSecretsScanner(context=ctx, config=DetectSecretsScannerConfig())
    scanner.dependencies_satisfied = True
    monkeypatch.setattr(scanner, "_pre_scan", lambda **_kwargs: True)
    secrets_collection_cls, _, _ = module._detect_secrets_api()
    scanner._secrets_collection = secrets_collection_cls()
    scanner._secrets_collection.root = ctx.source_dir
    work_dir = tmp_path / "results" / "source"
    work_dir.mkdir(parents=True)
    return scanner, ctx, module, work_dir


def _recording_worker(monkeypatch, module, work_dir):
    """Stand in for the worker's spawn: keep the environment it was given and
    the request it was handed, and write an empty result."""
    from automated_security_helper.utils import subprocess_utils

    seen = {}
    request = work_dir / module.WORKER_REQUEST_FILE_NAME
    output = work_dir / module.WORKER_OUTPUT_FILE_NAME

    def _record(**kwargs):
        seen["env"] = dict(kwargs["env"])
        seen["request"] = json.loads(request.read_text(encoding="utf-8"))
        output.write_text("[]", encoding="utf-8")
        return {"returncode": 0}

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", _record)
    return seen


def _scan(scanner, ctx, work_dir, **gates):
    return scanner._scan_in_worker(
        baseline=None,
        scan_paths=[str(ctx.source_dir / "app.py")],
        scan_settings_dict={"plugins_used": [{"name": "AWSKeyDetector"}]},
        work_dir=work_dir,
        scan_timeout=60,
        **gates,
    )


@pytest.mark.parametrize(
    ("verify", "stated"), [(False, "1"), (True, "0")], ids=["no-verify", "verify"]
)
def test_the_worker_environment_states_the_http_gate(
    tmp_path, monkeypatch, verify, stated
):
    scanner, ctx, module, work_dir = _worker_ready_scanner(tmp_path, monkeypatch)
    seen = _recording_worker(monkeypatch, module, work_dir)

    _scan(scanner, ctx, work_dir, verify=verify)

    assert seen["env"][REFUSE_HTTP_ENV] == stated


def test_an_inherited_gate_value_is_replaced_not_passed_through(tmp_path, monkeypatch):
    """A "0" in ASH's own environment does not let a scan that may not verify
    send anything: the worker's variable is the scan's answer, never inherited."""
    scanner, ctx, module, work_dir = _worker_ready_scanner(tmp_path, monkeypatch)
    seen = _recording_worker(monkeypatch, module, work_dir)
    monkeypatch.setenv(REFUSE_HTTP_ENV, "0")

    _scan(scanner, ctx, work_dir, verify=False)

    assert seen["env"][REFUSE_HTTP_ENV] == "1"


@pytest.mark.parametrize("trusted", [False, True], ids=["untrusted", "trusted"])
def test_the_request_carries_the_baseline_trust_as_a_json_bool(
    tmp_path, monkeypatch, trusted
):
    scanner, ctx, module, work_dir = _worker_ready_scanner(tmp_path, monkeypatch)
    seen = _recording_worker(monkeypatch, module, work_dir)

    _scan(scanner, ctx, work_dir, baseline_trusted=trusted)

    assert seen["request"][BASELINE_TRUSTED_KEY] is trusted


def test_the_default_request_leaves_the_baseline_untrusted(tmp_path, monkeypatch):
    """Asked nothing, the scanner states False: the worker reads anything but a
    JSON true as "report every entry", so the default cannot drop one."""
    scanner, ctx, module, work_dir = _worker_ready_scanner(tmp_path, monkeypatch)
    seen = _recording_worker(monkeypatch, module, work_dir)

    _scan(scanner, ctx, work_dir)

    assert seen["request"][BASELINE_TRUSTED_KEY] is False
    assert seen["env"][REFUSE_HTTP_ENV] == "1"
