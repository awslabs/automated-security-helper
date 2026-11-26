# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""GgshieldScanner over ggshield's own captured report, and under the sandbox.

``tests/test_data/scanners/ggshield/captured/`` holds the SARIF that ggshield 1.56.1
wrote from its real ``secret scan path`` command, with only the GitGuardian HTTP
calls stubbed (see the README there for exactly what that means). These tests serve
those files from the fake subprocess, so the expected findings below follow the
tool's report shape and not a shape this module's author wrote.

The sandbox half builds the policy with ``build_scanner_policy``, the function every
sandboxed spawn goes through, so a declaration the policy ignores fails here.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_ggshield_plugins.ggshield_scanner import (
    API_KEY_ENV,
    GgshieldScanner,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.policy import build_scanner_policy

# The helpers of the behavior tests; the three small fixtures are redefined below.
from .test_ggshield_scanner_behavior import (
    FAKE_KEY_VALUE,
    FakeGgshield,
    _findings,
    _run,
    _scanner,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "app").mkdir(parents=True)
    (src / "app" / "config.py").write_text("API_TOKEN = 'x'\n")
    return src


@pytest.fixture(autouse=True)
def key_set(monkeypatch):
    monkeypatch.setenv(API_KEY_ENV, FAKE_KEY_VALUE)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)


@pytest.fixture
def deps_ok(monkeypatch):
    """The tool is installed: the dependency check is not what these tests probe."""
    monkeypatch.setattr(GgshieldScanner, "validate_plugin_dependencies", lambda s: True)


# parents[3] is the tests/ directory.
CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "ggshield"
    / "captured"
)

#: The directory prefix the capture's run had; replaced by the scan root below,
#: as the README says.
CAPTURED_ROOT = "/work"


def _captured(name: str, root: Path) -> str:
    text = (CAPTURED / name).read_text(encoding="utf-8")
    return text.replace(
        f"file://{CAPTURED_ROOT}/", f"file://{root.absolute().as_posix()}/"
    )


class TestCapturedReport:
    def test_the_captured_positive_report_is_what_the_tool_wrote(self):
        """The fixture is the writer's shape: one result, no rules, no properties."""
        raw = json.loads((CAPTURED / "positive.sarif").read_text(encoding="utf-8"))
        run = raw["runs"][0]
        assert run["tool"]["driver"]["name"] == "ggshield"
        assert run["tool"]["driver"]["version"] == "1.56.1"
        assert "rules" not in run["tool"]["driver"]
        (result,) = run["results"]
        assert result["level"] == "error"
        assert "properties" not in result
        assert set(result["partialFingerprints"]) == {"secret/v1"}

    def test_the_captured_positive_report_yields_the_expected_finding(
        self,
        tree,
        tmp_path,
        deps_ok,
        monkeypatch,
    ):
        report = _run(
            _scanner(tree, tmp_path),
            FakeGgshield(report_text=_captured("positive.sarif", tree)),
            monkeypatch,
        )
        assert isinstance(report, SarifReport)
        assert _findings(report) == [
            ("Generic High Entropy Secret", "error", "CRITICAL", "app/config.py", 2)
        ]
        (result,) = report.get_all_results()
        assert {"secret", "security"} <= set(result.properties.tags)
        assert result.partialFingerprints == {
            "secret/v1": "6ac47f1fcf69290007530f0dd3450711042f2c836703f08ae0d84935fd44c6bf"
        }
        region = result.locations[0].physicalLocation.root.region
        assert (region.startColumn, region.endLine, region.endColumn) == (14, 2, 47)

    def test_the_match_locations_are_source_relative_too(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        """ggshield writes one relatedLocations entry per match with the same
        absolute file:// URI; the flat row reads those as references, so no
        absolute path of the host may survive in the report."""
        report = _run(
            _scanner(tree, tmp_path),
            FakeGgshield(report_text=_captured("positive.sarif", tree)),
            monkeypatch,
        )
        (result,) = report.get_all_results()
        related = [
            loc.physicalLocation.root.artifactLocation.uri
            for loc in result.relatedLocations
        ]
        assert related == ["app/config.py"]
        # Only the findings' own locations: the run's invocation record keeps the
        # command line and the working directory, which name the scan path.
        dumped = result.model_dump_json()
        uris = [part for part in re.findall(r'"uri":"([^"]*)"', dumped) if part]
        assert uris
        assert not [u for u in uris if tree.absolute().as_posix() in u], uris

    def test_the_captured_negative_report_is_a_clean_scan(
        self,
        tree,
        tmp_path,
        deps_ok,
        monkeypatch,
    ):
        report = _run(
            _scanner(tree, tmp_path),
            FakeGgshield(report_text=_captured("negative.sarif", tree), exit_code=0),
            monkeypatch,
        )
        assert isinstance(report, SarifReport)
        assert report.get_all_results() == []

    def test_the_captured_file_uri_form_is_made_source_relative(self, tree):
        from automated_security_helper.plugin_modules.ash_ggshield_plugins import (
            ggshield_scanner as gs,
        )

        assert gs._relative_uri(
            f"file://{tree.absolute().as_posix()}/app/config.py", tree
        ) == ("app/config.py")


@pytest.fixture
def layout(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    source = tmp_path / "src"
    source.mkdir()
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    return SimpleNamespace(home=home, source=source, output=output)


def _policy(layout, *, offline=False):
    return build_scanner_policy(
        "ggshield",
        GgshieldScanner.sandbox_requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "ggshield",
        scan_target=layout.source,
        cwd=layout.source,
        offline=offline,
        network_scanners=None,
    )


class TestSandboxPolicy:
    def test_an_online_run_gets_the_network(self, layout):
        assert _policy(layout).network is True

    def test_an_offline_run_gets_no_network(self, layout):
        assert _policy(layout, offline=True).network is False

    def test_the_gitguardian_variables_pass_and_nothing_else_secret_does(self, layout):
        kept = _policy(layout).filter_env(
            {
                API_KEY_ENV: "not-a-real-key-for-tests",
                "GITGUARDIAN_API_URL": "https://api.example.invalid",
                "SNYK_TOKEN": "not-a-real-token",
                "AWS_SECRET_ACCESS_KEY": "not-a-real-secret",
                "SOME_OTHER_SECRET": "x",
            }
        )
        assert kept[API_KEY_ENV] == "not-a-real-key-for-tests"
        assert kept["GITGUARDIAN_API_URL"] == "https://api.example.invalid"
        for name in ("SNYK_TOKEN", "AWS_SECRET_ACCESS_KEY", "SOME_OTHER_SECRET"):
            assert name not in kept

    def test_the_results_directory_is_the_writable_place(self, layout):
        policy = _policy(layout)
        results = (layout.output / "scanners" / "ggshield").resolve()
        assert results in {p.resolve() for p in policy.writable}
        assert layout.source.resolve() not in {p.resolve() for p in policy.writable}
