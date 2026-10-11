"""Which detect-secrets settings count as the operator's, beyond the verification filter.

Three cases the first round of the verification rule got wrong:

* The operator names a baseline outside the scanned tree through
  ``--config-overrides`` while the scanned repository has its own ``.ash/.ash.yaml``.
  The override is the operator's, so the baseline it names is too, and the filter in
  it verifies (``test_operator_override_naming_an_outside_baseline_verifies``).
* The operator's config names the verification filter in ``scan_settings`` without
  ``plugins_used`` or ``version``, and the scanned tree has a ``.secrets.baseline``.
  The baseline's plugins and filters then replace the config's, and the operator's
  filter was lost with them.
* A repository's config, or its ``.secrets.baseline``, names a plugin or filter by
  ``file://`` path to a file outside the tree. detect-secrets imports that file in its
  worker, so the repository chose code to run; only the operator's own settings may
  name one (``test_repository_settings_import_no_file``).

Requests are observed through the refusing proxy, as in
test_detect_secrets_verification_trust.py; nothing leaves the machine.
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.core.enums import ExecutionStrategy
from tests.utils.refusing_proxy import (
    RecordingProxy,
    route_through,
    scrub_cloud_credentials,
)

VERIFICATION_FILTER = (
    "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
)
KEY_ID = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])  # noqa: FLY002
KEY_SECRET = "".join(["wJalrXUtnFEMI/K7MDENG/", "bPxRfiCY", "EXAMPLEKEY"])  # noqa: FLY002
ISSUER = "sts.amazonaws.com"


def _baseline(path: Path, filters: list) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "version": "1.5.0",
                "plugins_used": [{"name": "AWSKeyDetector"}],
                "filters_used": filters,
                "results": {},
                "generated_at": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    return path


def _config(path: Path, options: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "project_name": "operator-settings",
                "fail_on_findings": False,
                "scanners": {"detect-secrets": {"enabled": True, "options": options}},
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def recorder(monkeypatch):
    scrub_cloud_credentials(monkeypatch)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    proxy = RecordingProxy()
    route_through(monkeypatch, proxy)
    yield proxy
    proxy.close()


@pytest.fixture
def repo(tmp_path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "creds.py").write_text(
        f'aws_access_key_id = "{KEY_ID}"\naws_secret_access_key = "{KEY_SECRET}"\n',
        encoding="utf-8",
    )
    return root


@pytest.fixture
def elsewhere(tmp_path, monkeypatch) -> Path:
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    return cwd


def _scan(repo: Path, out: Path, *, config=None, config_overrides=None) -> dict:
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    try:
        run_ash_scan(
            source_dir=str(repo),
            output_dir=str(out),
            config=str(config) if config is not None else None,
            config_overrides=list(config_overrides or []),
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
    assert results.is_file(), f"the scan wrote no {results.name}"
    return json.loads(results.read_text(encoding="utf-8"))


def _issuer_requests(proxy: RecordingProxy) -> list:
    return [line for line in proxy.external_requests() if ISSUER in line]


def test_operator_override_naming_an_outside_baseline_verifies(
    recorder, repo, tmp_path, elsewhere
):
    outside = _baseline(
        tmp_path / "shared" / "verifying.baseline",
        [{"path": VERIFICATION_FILTER, "min_level": 2}],
    )
    _config(repo / ".ash" / ".ash.yaml", {})

    _scan(
        repo,
        tmp_path / "out",
        config_overrides=[
            f"scanners.detect-secrets.options.baseline_file={outside.as_posix()}"
        ],
    )

    assert _issuer_requests(recorder), (
        "the baseline the operator named with --config-overrides did not verify; "
        f"the recorder saw {recorder.requests}"
    )


@pytest.mark.parametrize("baseline_filters", ["none", "verifying"])
def test_operator_filter_survives_an_in_tree_baseline(
    recorder, repo, tmp_path, elsewhere, baseline_filters
):
    """The operator's config names only the filter; the tree has a baseline."""
    filters = (
        [{"path": VERIFICATION_FILTER, "min_level": 2}]
        if baseline_filters == "verifying"
        else []
    )
    _baseline(repo / ".secrets.baseline", filters)
    operator = _config(
        tmp_path / "operator" / "ash.yaml",
        {
            "scan_settings": {
                "filters_used": [{"path": VERIFICATION_FILTER, "min_level": 2}]
            }
        },
    )

    _scan(repo, tmp_path / "out", config=operator)

    assert _issuer_requests(recorder), (
        "the operator's verification filter was replaced by the tree's baseline; "
        f"the recorder saw {recorder.requests}"
    )


def test_control_repository_override_of_baseline_file_still_does_not_verify(
    recorder, repo, tmp_path, elsewhere
):
    """The same outside baseline named by the repository's own config."""
    outside = _baseline(
        tmp_path / "shared" / "verifying.baseline",
        [{"path": VERIFICATION_FILTER, "min_level": 2}],
    )
    _config(repo / ".ash" / ".ash.yaml", {"baseline_file": outside.as_posix()})

    _scan(repo, tmp_path / "out")

    assert _issuer_requests(recorder) == [], recorder.requests


# ---------------------------------------------------------------------------
# Plugins and filters named by file
# ---------------------------------------------------------------------------


def _host_module(tmp_path: Path) -> tuple[Path, Path]:
    """A file outside every tree that records being imported."""
    marker = tmp_path / "imported.marker"
    module = tmp_path / "host" / "anymodule.py"
    module.parent.mkdir(parents=True, exist_ok=True)
    module.write_text(
        "from pathlib import Path\n"
        f"Path({marker.as_posix()!r}).write_text('imported')\n"
        "def anyfilter(secret):\n"
        "    return False\n",
        encoding="utf-8",
    )
    return module, marker


def _file_entries(module: Path) -> dict:
    return {
        "plugins_used": [
            {"name": "AWSKeyDetector"},
            {"name": "AnyPlugin", "path": f"file://{module.as_posix()}"},
        ],
        "filters_used": [{"path": f"file://{module.as_posix()}::anyfilter"}],
    }


@pytest.mark.parametrize("source", ["repository config", "repository baseline"])
def test_repository_settings_import_no_file(
    recorder, repo, tmp_path, elsewhere, source
):
    module, marker = _host_module(tmp_path)
    entries = _file_entries(module)
    if source == "repository config":
        _config(
            repo / ".ash" / ".ash.yaml",
            {"scan_settings": {"version": "1.5.0", **entries}},
        )
    else:
        baseline = repo / ".secrets.baseline"
        baseline.write_text(
            json.dumps(
                {
                    "version": "1.5.0",
                    **entries,
                    "results": {},
                    "generated_at": "2026-01-01T00:00:00Z",
                }
            ),
            encoding="utf-8",
        )

    results = _scan(repo, tmp_path / "out")

    assert not marker.exists(), (
        f"the {source} made detect-secrets import {module} from the host"
    )
    row = (results.get("scanner_results") or {}).get("detect-secrets") or {}
    assert int(row.get("finding_count") or 0) >= 1, (
        "the harness did not reach detect-secrets: the planted key was not reported"
    )


def test_control_operator_settings_still_import_their_file(
    recorder, repo, tmp_path, elsewhere
):
    module, marker = _host_module(tmp_path)
    operator = _config(
        tmp_path / "operator" / "ash.yaml",
        {"scan_settings": {"version": "1.5.0", **_file_entries(module)}},
    )

    _scan(repo, tmp_path / "out", config=operator)

    assert marker.exists(), "the operator's own plugin file was not loaded"
