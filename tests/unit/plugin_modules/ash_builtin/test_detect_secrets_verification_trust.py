"""detect-secrets verification is operator-only, and never runs under ``--offline``.

What verification does
----------------------
detect-secrets has one filter that sends each candidate secret to its issuer:
``detect_secrets.filters.common.is_ignored_due_to_verification_policies``. With it
configured, every plugin's ``verify()`` runs, and for an AWS access key id that sits
next to a secret access key that is an STS request to ``sts.amazonaws.com`` signed
with the pair found in the scanned file. ``detect-secrets scan`` writes the filter
into every baseline it generates, so a repository's ``.secrets.baseline`` normally
carries it.

The required behavior
---------------------
1. Under ``--offline`` no verification request is sent, whatever the scanned
   repository's ``.secrets.baseline``, its ASH config, an MCP client's config or the
   operator's own config says.
2. Online, verification is enabled only by the operator. A repository's
   ``.secrets.baseline``, a repository-local ASH config and an MCP client's config
   cannot turn it on: otherwise a key planted in the scanned tree makes the scanning
   host contact the key's issuer.
3. Online, an operator config that enables verification keeps working (control).

How the tests observe it
------------------------
Every proxy variable points at a local proxy (``tests/utils/refusing_proxy.py``)
that records each request and answers 403, so a verification attempt shows up as
``CONNECT sts.amazonaws.com:443`` and nothing leaves the machine. ``NO_PROXY`` is
emptied so a host exclusion list cannot route around it, and AWS credentials are
removed from the environment. The assertion is on requests, not on settings, so it
holds whichever way a fix turns verification off, and whichever spelling of the
filter a config uses (the dotted module path, or a ``file://`` path to a file
outside the scanned tree that provides the same function; see ``_filter_by_file``).

Every case runs a real in-process scan through ``run_ash_scan`` with only
detect-secrets selected, so the config tiers are decided exactly as for ``ash scan``
(``--config`` outside the tree: operator; ``.ash/.ash.yaml`` found in the tree:
repository; ``untrusted_config=True``: an MCP client's upload, as
``cli/mcp_tools.py`` passes it).

Cases that read a ``.secrets.baseline`` run from a working directory outside the
scanned tree (``elsewhere``): the scanner looks a relative baseline up from the
source directory (see test_detect_secrets_baseline_lookup.py), so running from
elsewhere still reads it, and a lookup that fell back to the working directory would
not.

Every case that refuses verification also asserts the planted key is still a
finding: refusing verification by turning the detector off would send nothing and
report nothing, and the request assertion alone cannot tell that from a fix.
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
# Assembled at runtime so this file holds no key-shaped literal for ASH's own
# self-scan to report. AWS's documentation placeholders.
KEY_ID = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])  # noqa: FLY002
KEY_SECRET = "".join(["wJalrXUtnFEMI/K7MDENG/", "bPxRfiCY", "EXAMPLEKEY"])  # noqa: FLY002
ISSUER = "sts.amazonaws.com"


def _filter_by_file(tmp_path: Path) -> str:
    """The verification filter named by a ``file://`` path outside the scanned tree.

    In an install outside any checkout (a container image, a uv tool environment)
    a config can name detect-secrets' own ``filters/common.py`` this way, and ASH's
    in-tree path check keeps it because the file is not in the scanned tree. In this
    test run the library sits in the checkout's virtual environment, which that
    check refuses for another reason, so a file outside every checkout that
    re-exports the same function stands in for it: detect-secrets loads it with
    ``import_file_as_module`` and calls the filter exactly as it would the original.
    """
    shim = tmp_path / "installed" / "filters_common.py"
    shim.parent.mkdir(parents=True, exist_ok=True)
    shim.write_text(
        "from detect_secrets.filters.common import "
        "is_ignored_due_to_verification_policies  # noqa: F401\n",
        encoding="utf-8",
    )
    return f"file://{shim.as_posix()}::is_ignored_due_to_verification_policies"


def _settings(filter_path: str = VERIFICATION_FILTER) -> dict:
    return {
        "plugins_used": [{"name": "AWSKeyDetector"}],
        "filters_used": [{"path": filter_path, "min_level": 2}],
    }


def _write_baseline(path: Path, settings: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "version": "1.5.0",
                **settings,
                "results": {},
                "generated_at": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    return path


def _write_ash_config(path: Path, settings: dict | None) -> Path:
    """An ASH config that selects detect-secrets, with ``settings`` if given.

    JSON is valid YAML, so the file is written with json.dumps whatever its name.
    """
    options = {}
    if settings is not None:
        options["scan_settings"] = {"version": "1.5.0", **settings}
    document = {
        "project_name": "verification-trust",
        "fail_on_findings": False,
        "scanners": {"detect-secrets": {"enabled": True, "options": options}},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")
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
    """The scanned tree: one file with an access key id next to its secret."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "creds.py").write_text(
        f'aws_access_key_id = "{KEY_ID}"\naws_secret_access_key = "{KEY_SECRET}"\n',
        encoding="utf-8",
    )
    return root


@pytest.fixture
def elsewhere(tmp_path, monkeypatch) -> Path:
    """A working directory with nothing in it, outside the scanned tree."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    return cwd


def _scan(
    repo: Path,
    out: Path,
    *,
    offline: bool,
    config: Path | None = None,
    untrusted_config: bool = False,
) -> dict:
    """Run ``ash scan --scanners detect-secrets`` in-process; return the results."""
    # Imported here, as the other in-process scan tests do: importing it at module
    # load starts plugin registration before the reporters' imports can resolve.
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    try:
        run_ash_scan(
            source_dir=str(repo),
            output_dir=str(out),
            config=str(config) if config is not None else None,
            offline=offline,
            scanners=["detect-secrets"],
            strategy=ExecutionStrategy.SEQUENTIAL,
            progress=False,
            fail_on_findings=False,
            fail_on_incomplete_scanners=False,
            show_summary=False,
            quiet=True,
            color=False,
            untrusted_config=untrusted_config,
        )
    except SystemExit:
        pass
    results = out / "ash_aggregated_results.json"
    assert results.is_file(), f"the scan wrote no {results.name}"
    return json.loads(results.read_text(encoding="utf-8"))


def _refused_scan(repo: Path, out: Path, *, offline: bool, config: Path) -> object:
    """Run the scan ``_scan`` runs with a config an MCP client supplied; its exit code.

    Such a config that sets detect-secrets' settings is refused before anything
    runs: the scanner's section is denied whole to a client
    (ALWAYS_DENIED_PATHS), so no verification can be configured through it.
    """
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    try:
        run_ash_scan(
            source_dir=str(repo),
            output_dir=str(out),
            config=str(config),
            offline=offline,
            scanners=["detect-secrets"],
            strategy=ExecutionStrategy.SEQUENTIAL,
            progress=False,
            fail_on_findings=False,
            fail_on_incomplete_scanners=False,
            show_summary=False,
            quiet=True,
            color=False,
            untrusted_config=True,
        )
    except SystemExit as exited:
        assert not (out / "ash_aggregated_results.json").exists()
        return exited.code
    raise AssertionError("the scan ran with the client's detect-secrets settings")


def _workspace_scan(root: Path, out: Path, *, offline: bool, project: str) -> dict:
    """Run a workspace-mode scan of ``root`` with one project, detect-secrets only.

    Returns the project's own results (``projects/<key>/``), which carry its
    detect-secrets row.
    """
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan
    from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

    plan = WorkspacePlan(
        workspace_file=(root / "dev.code-workspace").as_posix(),
        workspace_root=root.as_posix(),
        projects=[
            ProjectPlan(
                key=project,
                relative_path=project,
                path=(root / project).as_posix(),
                label=project,
                display_label=project,
                severity_threshold="MEDIUM",
            )
        ],
    )
    try:
        run_ash_scan(
            source_dir=str(root),
            output_dir=str(out),
            offline=offline,
            scanners=["detect-secrets"],
            strategy=ExecutionStrategy.SEQUENTIAL,
            progress=False,
            fail_on_findings=False,
            fail_on_incomplete_scanners=False,
            show_summary=False,
            quiet=True,
            color=False,
            workspace_plan=plan,
        )
    except SystemExit:
        pass
    results = out / "projects" / project / "ash_aggregated_results.json"
    assert results.is_file(), f"the project wrote no {results.name}"
    return json.loads(results.read_text(encoding="utf-8"))


def _issuer_requests(proxy: RecordingProxy) -> list:
    return [line for line in proxy.external_requests() if ISSUER in line]


def _detect_secrets_findings(results: dict) -> int:
    row = (results.get("scanner_results") or {}).get("detect-secrets") or {}
    return int(row.get("finding_count") or 0)


def _assert_key_still_reported(results: dict) -> None:
    """Refusing verification must leave detection on: the planted key is a finding."""
    assert _detect_secrets_findings(results) >= 1, (
        "verification was refused and the planted key was not reported either: "
        "detection was turned off with it"
    )


# ---------------------------------------------------------------------------
# 1. --offline: no verification request from any source
# ---------------------------------------------------------------------------


class TestOfflineScanSendsNoVerificationRequest:
    def test_repository_baseline_enabling_verification(
        self, recorder, repo, tmp_path, elsewhere
    ):
        _write_baseline(repo / ".secrets.baseline", _settings())

        results = _scan(repo, tmp_path / "out", offline=True)

        assert _issuer_requests(recorder) == [], (
            "an --offline scan sent the planted key to its issuer because the "
            f"repository's .secrets.baseline enabled verification: {recorder.requests}"
        )
        _assert_key_still_reported(results)

    def test_operator_config_enabling_verification(
        self, recorder, repo, tmp_path, elsewhere
    ):
        operator = _write_ash_config(tmp_path / "operator" / "ash.yaml", _settings())

        results = _scan(repo, tmp_path / "out", offline=True, config=operator)

        assert _issuer_requests(recorder) == [], (
            "an --offline scan verified secrets because the operator config named "
            f"the verification filter: {recorder.requests}"
        )
        _assert_key_still_reported(results)

    def test_operator_config_naming_the_filter_by_file_path(
        self, recorder, repo, tmp_path, elsewhere
    ):
        operator = _write_ash_config(
            tmp_path / "operator" / "ash.yaml", _settings(_filter_by_file(tmp_path))
        )

        results = _scan(repo, tmp_path / "out", offline=True, config=operator)

        assert _issuer_requests(recorder) == [], (
            "an --offline scan verified secrets through the verification filter "
            f"named by a file:// path: {recorder.requests}"
        )
        _assert_key_still_reported(results)

    def test_mcp_client_config_enabling_verification(
        self, recorder, repo, tmp_path, elsewhere
    ):
        delivered = _write_ash_config(tmp_path / "delivered" / "ash.yaml", _settings())

        code = _refused_scan(repo, tmp_path / "out", offline=True, config=delivered)

        assert code == 3
        assert _issuer_requests(recorder) == [], recorder.requests

    def test_workspace_project_config_enabling_verification(
        self, recorder, repo, tmp_path, elsewhere
    ):
        """Workspace mode: the project's own config is repository-written too."""
        _write_ash_config(repo / ".ash" / ".ash.yaml", _settings())

        results = _workspace_scan(
            tmp_path, tmp_path / "out", offline=True, project=repo.name
        )

        assert _issuer_requests(recorder) == [], recorder.requests
        _assert_key_still_reported(results)

    def test_control_offline_scan_still_reports_the_key(
        self, recorder, repo, tmp_path, elsewhere
    ):
        """Control: no verification configured anywhere, and the key is reported."""
        operator = _write_ash_config(tmp_path / "operator" / "ash.yaml", None)

        results = _scan(repo, tmp_path / "out", offline=True, config=operator)

        assert _issuer_requests(recorder) == []
        assert _detect_secrets_findings(results) >= 1, (
            "the harness did not reach detect-secrets: the planted key was not reported"
        )


# ---------------------------------------------------------------------------
# 2. Online: only the operator can enable verification
# ---------------------------------------------------------------------------


class TestOnlyTheOperatorEnablesVerification:
    def test_repository_baseline_cannot_enable_verification(
        self, recorder, repo, tmp_path, elsewhere
    ):
        _write_baseline(repo / ".secrets.baseline", _settings())

        results = _scan(repo, tmp_path / "out", offline=False)

        assert _issuer_requests(recorder) == [], (
            "the scanned repository's .secrets.baseline made the scanning host send "
            f"the planted key to its issuer: {recorder.requests}"
        )
        _assert_key_still_reported(results)

    def test_repository_baseline_under_ash_dir_cannot_enable_verification(
        self, recorder, repo, tmp_path, elsewhere
    ):
        _write_baseline(repo / ".ash" / ".secrets.baseline", _settings())

        results = _scan(repo, tmp_path / "out", offline=False)

        assert _issuer_requests(recorder) == [], recorder.requests
        _assert_key_still_reported(results)

    def test_repository_ash_config_cannot_enable_verification(
        self, recorder, repo, tmp_path, elsewhere
    ):
        _write_ash_config(repo / ".ash" / ".ash.yaml", _settings())

        results = _scan(repo, tmp_path / "out", offline=False)

        assert _issuer_requests(recorder) == [], (
            "a repository-local .ash/.ash.yaml enabled secret verification: "
            f"{recorder.requests}"
        )
        _assert_key_still_reported(results)

    def test_repository_ash_config_naming_the_filter_by_file_path(
        self, recorder, repo, tmp_path, elsewhere
    ):
        _write_ash_config(
            repo / ".ash" / ".ash.yaml", _settings(_filter_by_file(tmp_path))
        )

        results = _scan(repo, tmp_path / "out", offline=False)

        assert _issuer_requests(recorder) == [], recorder.requests
        _assert_key_still_reported(results)

    def test_repository_ash_config_naming_a_baseline_outside_the_tree(
        self, recorder, repo, tmp_path, elsewhere
    ):
        """A repository config that points baseline_file at a verifying baseline."""
        outside = _write_baseline(
            tmp_path / "shared" / "verifying.baseline", _settings()
        )
        document = {
            "project_name": "verification-trust",
            "fail_on_findings": False,
            "scanners": {
                "detect-secrets": {
                    "enabled": True,
                    "options": {"baseline_file": outside.as_posix()},
                }
            },
        }
        (repo / ".ash").mkdir()
        (repo / ".ash" / ".ash.yaml").write_text(json.dumps(document), encoding="utf-8")

        results = _scan(repo, tmp_path / "out", offline=False)

        assert _issuer_requests(recorder) == [], recorder.requests
        _assert_key_still_reported(results)

    def test_mcp_client_config_cannot_enable_verification(
        self, recorder, repo, tmp_path, elsewhere
    ):
        delivered = _write_ash_config(tmp_path / "delivered" / "ash.yaml", _settings())

        code = _refused_scan(repo, tmp_path / "out", offline=False, config=delivered)

        assert code == 3
        assert _issuer_requests(recorder) == [], (
            f"an MCP client's config enabled secret verification: {recorder.requests}"
        )

    def test_workspace_project_config_cannot_enable_verification(
        self, recorder, repo, tmp_path, elsewhere
    ):
        _write_ash_config(repo / ".ash" / ".ash.yaml", _settings())

        results = _workspace_scan(
            tmp_path, tmp_path / "out", offline=False, project=repo.name
        )

        assert _issuer_requests(recorder) == [], (
            "a workspace project's own config enabled secret verification: "
            f"{recorder.requests}"
        )
        _assert_key_still_reported(results)

    def test_control_operator_config_enables_verification_online(
        self, recorder, repo, tmp_path, elsewhere
    ):
        """Control: the operator's own config still verifies online.

        This is also what shows the recorder sees verification at all: the same
        scan with the filter named by the operator produces the issuer request.
        """
        operator = _write_ash_config(tmp_path / "operator" / "ash.yaml", _settings())

        _scan(repo, tmp_path / "out", offline=False, config=operator)

        assert _issuer_requests(recorder), (
            "an operator config naming the verification filter sent no request to "
            f"the issuer; the recorder saw {recorder.requests}"
        )
