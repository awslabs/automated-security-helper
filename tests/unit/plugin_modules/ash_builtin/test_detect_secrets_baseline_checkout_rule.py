# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An operator's baseline outside the scanned tree verifies, even in another git checkout.

The baseline's settings were judged by "inside any git checkout", the rule for config
files, so a team that keeps shared baselines in a repository of their own, checked out
next to the scanned one (a common CI layout), lost verification. The warning then said
that verification needs "a baseline outside the scanned tree", which that one is.

A baseline is the scanned repository's when it is inside the scanned tree, or
inside the git checkout that holds the scanned tree. A baseline in some other checkout,
named by the operator, is the operator's. Requests are observed through the refusing
proxy, as in test_detect_secrets_operator_settings.py; nothing leaves the machine.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.core.enums import ExecutionStrategy
from tests.unit.plugin_modules.ash_builtin.test_detect_secrets_operator_settings import (
    KEY_ID,
    KEY_SECRET,
    VERIFICATION_FILTER,
)
from tests.utils.refusing_proxy import (
    RecordingProxy,
    route_through,
    scrub_cloud_credentials,
)

ISSUER = "sts.amazonaws.com"


@pytest.fixture
def recorder(monkeypatch, tmp_path):
    scrub_cloud_credentials(monkeypatch)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    proxy = RecordingProxy()
    route_through(monkeypatch, proxy)
    yield proxy
    proxy.close()


def _verifying_baseline(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "version": "1.5.0",
                "plugins_used": [{"name": "AWSKeyDetector"}],
                "filters_used": [{"path": VERIFICATION_FILTER, "min_level": 2}],
                "results": {},
                "generated_at": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    return path


def _operator_config(tmp_path: Path, baseline: Path) -> Path:
    """The operator's config, outside every checkout and the scanned tree."""
    path = tmp_path / "operator" / "ash.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "project_name": "operator",
                "fail_on_findings": False,
                "scanners": {
                    "detect-secrets": {
                        "enabled": True,
                        "options": {"baseline_file": baseline.as_posix()},
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _project(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "creds.py").write_text(
        f'aws_access_key_id = "{KEY_ID}"\naws_secret_access_key = "{KEY_SECRET}"\n',
        encoding="utf-8",
    )
    return root


def _scan(source: Path, out: Path, config: Path) -> dict:
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    try:
        run_ash_scan(
            source_dir=str(source),
            output_dir=str(out),
            config=str(config),
            scanners=["detect-secrets"],
            strategy=ExecutionStrategy.SEQUENTIAL,
            progress=False,
            fail_on_findings=False,
            fail_on_incomplete_scanners=False,
            show_summary=False,
            quiet=True,
            color=False,
        )
    except SystemExit:
        pass
    results = out / "ash_aggregated_results.json"
    assert results.is_file()
    return json.loads(results.read_text(encoding="utf-8"))


def _issuer_requests(proxy: RecordingProxy) -> list:
    return [line for line in proxy.external_requests() if ISSUER in line]


@pytest.mark.integration
def test_an_operator_baseline_in_another_checkout_verifies(recorder, tmp_path):
    shared = tmp_path / "shared-baselines"
    (shared / ".git").mkdir(parents=True)  # a checkout of its own
    baseline = _verifying_baseline(shared / "verifying.baseline")
    source = _project(tmp_path / "repo")

    _scan(source, tmp_path / "out", _operator_config(tmp_path, baseline))

    assert _issuer_requests(recorder), (
        "an operator-named baseline outside the scanned tree, in another checkout, "
        f"did not verify; the recorder saw {recorder.requests}"
    )


@pytest.mark.integration
def test_a_baseline_in_the_scanned_tree_s_own_checkout_does_not_verify(
    recorder, tmp_path
):
    """Scanning a subdirectory: the rest of that repository is still the repository's."""
    checkout = tmp_path / "repo"
    (checkout / ".git").mkdir(parents=True)
    source = _project(checkout / "service")
    baseline = _verifying_baseline(checkout / "ops" / "verifying.baseline")

    results = _scan(source, tmp_path / "out", _operator_config(tmp_path, baseline))

    assert _issuer_requests(recorder) == [], recorder.requests
    row = results["scanner_results"]["detect-secrets"]
    assert int(row.get("finding_count") or 0) >= 1, "detection went off with it"


@pytest.mark.integration
def test_control_an_operator_baseline_outside_any_checkout_verifies(recorder, tmp_path):
    baseline = _verifying_baseline(tmp_path / "plain" / "verifying.baseline")
    source = _project(tmp_path / "repo")

    _scan(source, tmp_path / "out", _operator_config(tmp_path, baseline))

    assert _issuer_requests(recorder), recorder.requests


@pytest.mark.unit
def test_the_reason_names_the_scanned_checkout(tmp_path):
    from automated_security_helper.config.path_trust import scanned_checkout_reason

    # Each checkout carries a HEAD: the one checkout definition
    # (sandbox_grants._git_shaped) counts a .git directory only when git would
    # open it, so a bare empty .git marks no checkout here.
    checkout = tmp_path / "repo"
    (checkout / ".git").mkdir(parents=True)
    (checkout / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    source = checkout / "service"
    source.mkdir()
    inside_checkout = checkout / "ops" / "v.baseline"
    inside_checkout.parent.mkdir()
    inside_checkout.write_text("{}")
    elsewhere = tmp_path / "shared" / "v.baseline"
    (tmp_path / "shared" / ".git").mkdir(parents=True)
    (tmp_path / "shared" / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    elsewhere.write_text("{}")

    reason = scanned_checkout_reason(inside_checkout, source)
    assert reason is not None and "checkout" in reason, reason
    assert scanned_checkout_reason(source / "v.baseline", source) is not None
    assert scanned_checkout_reason(elsewhere, source) is None
