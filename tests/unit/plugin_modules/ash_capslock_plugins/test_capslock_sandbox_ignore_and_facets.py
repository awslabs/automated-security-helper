# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Capslock: sandbox declaration, operator ignore paths, schema-derived fixtures, registers.

The fixtures under tests/test_data/scanners/capslock/schema_derived are written
from Capslock v0.3.4's source, not captured from a run; their README says so,
and the facets register declares UNCONFIRMED every cell a real run would settle.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.plugin_manifest import PluginTier
from automated_security_helper.base.scanner_facets import (
    FACET_NAMES,
    SCANNER_FACETS_ATTR,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_manifests import manifest_for
from automated_security_helper.plugin_modules.ash_capslock_plugins import (
    capslock_scanner as cs,
)
from automated_security_helper.plugin_modules.ash_capslock_plugins.capslock_scanner import (
    CapslockScanner,
    convert_capslock_output,
    drop_ignored_modules,
    find_go_modules,
)
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    build_scanner_policy,
)

pytestmark = pytest.mark.unit

FIXTURES = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "capslock"
    / "schema_derived"
)

#: The cells a real Capslock run would settle; the rest cannot exist.
UNREAD_CELLS = {
    "rule_id",
    "severity",
    "file_path",
    "line_range",
    "column",
    "message",
    "package_name",
    "package_path",
    "tags",
    "extras",
}


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


def _policy(layout, requirements):
    return build_scanner_policy(
        "capslock",
        requirements,
        argv0=sys.executable,
        source_dir=layout.source,
        output_dir=layout.output,
        results_dir=layout.output / "scanners" / "capslock",
        scan_target=layout.source,
        cwd=layout.source,
        offline=False,
        network_scanners=None,
    )


def _real(paths):
    return {p.resolve() for p in paths}


class TestSandboxRequirements:
    def test_declares_the_strict_default(self, layout):
        declared = CapslockScanner.sandbox_requirements
        assert declared == SandboxRequirements()
        policy = _policy(layout, declared)
        default = _policy(layout, SandboxRequirements())
        assert policy.network is False
        assert _real(policy.read_only) == _real(default.read_only)
        assert _real(policy.cache) == _real(default.cache)

    def test_the_operator_go_environment_is_not_passed_in(self, layout):
        # Nothing of the shell's Go configuration reaches the sandboxed tool, so a
        # GOFLAGS, GOPROXY or GOMODCACHE in the environment cannot change what runs.
        policy = _policy(layout, CapslockScanner.sandbox_requirements)
        passed = policy.filter_env(
            {
                "GOFLAGS": "-mod=mod",
                "GOPROXY": "https://proxy.example/",
                "GOMODCACHE": "/elsewhere",
            }
        )
        assert passed.keys() == {"HOME"} | set(policy.extra_env)

    def test_the_scanner_still_sets_its_own_readonly_flag_for_unsandboxed_runs(self):
        assert CapslockScanner._subprocess_env()["GOFLAGS"] == "-mod=readonly"


class TestOperatorIgnorePaths:
    @staticmethod
    def _modules(tmp_path: Path) -> Path:
        root = tmp_path / "t"
        for rel in ("go.mod", "svc/go.mod", "third_party/lib/go.mod", "tools/go.mod"):
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("module example.com/m\n")
        return root

    @staticmethod
    def _ignores(*paths: str):
        return [IgnorePathWithReason(path=p, reason="test") for p in paths]

    def test_a_module_under_an_ignored_directory_is_not_analyzed(self, tmp_path):
        root = self._modules(tmp_path)
        found = find_go_modules(root)
        assert len(found) == 4
        kept = drop_ignored_modules(found, root, self._ignores("third_party/"))
        assert sorted(m.relative_to(root).as_posix() for m in kept) == [
            ".",
            "svc",
            "tools",
        ]

    def test_an_ignored_go_mod_file_path_drops_that_module_only(self, tmp_path):
        root = self._modules(tmp_path)
        kept = drop_ignored_modules(
            find_go_modules(root), root, self._ignores("svc/go.mod")
        )
        assert "svc" not in {m.relative_to(root).as_posix() for m in kept}
        assert len(kept) == 3

    def test_no_ignore_paths_keeps_every_module(self, tmp_path):
        root = self._modules(tmp_path)
        found = find_go_modules(root)
        assert drop_ignored_modules(found, root, None) == found
        assert drop_ignored_modules(found, root, []) == found

    def test_an_unrelated_ignore_path_keeps_every_module(self, tmp_path):
        root = self._modules(tmp_path)
        found = find_go_modules(root)
        assert drop_ignored_modules(found, root, self._ignores("docs/")) == found

    def test_the_root_module_is_ignored_by_its_go_mod_path(self, tmp_path):
        root = self._modules(tmp_path)
        kept = drop_ignored_modules(
            find_go_modules(root), root, self._ignores("go.mod")
        )
        assert root not in kept
        assert len(kept) == 3


class TestSchemaDerivedFixtures:
    def test_positive_fixture_is_converted_row_by_row(self, tmp_path):
        document = json.loads((FIXTURES / "positive.json").read_text())
        target = tmp_path / "t"
        results = convert_capslock_output(document, target, target, "example.com/app")
        rows = [
            (
                r["ruleId"],
                r["level"],
                r["properties"]["issue_severity"],
                r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                r["locations"][0]["physicalLocation"]
                .get("region", {})
                .get("startLine"),
                r["properties"]["capslock_type"],
            )
            for r in results
        ]
        assert rows == [
            ("CAPSLOCK-FILES", "none", "INFO", "store/load.go", 30, "DIRECT"),
            ("CAPSLOCK-NETWORK", "none", "INFO", "server/serve.go", 12, "DIRECT"),
            # util.Cast is itself the capability: one step, no site.
            ("CAPSLOCK-UNSAFE_POINTER", "none", "INFO", "go.mod", None, "DIRECT"),
            # The call inside util.Run, not the later call in internal/exe.
            ("CAPSLOCK-EXEC", "none", "INFO", "util/run.go", 7, "TRANSITIVE"),
        ]
        # Severity and level agree on every result: the only severity is INFO.
        assert {r["properties"]["issue_severity"] for r in results} == {"INFO"}
        assert {r["level"] for r in results} == {"none"}

    def test_negative_fixture_has_no_results(self, tmp_path):
        document = json.loads((FIXTURES / "negative.json").read_text())
        target = tmp_path / "t"
        assert (
            convert_capslock_output(document, target, target, "example.com/app") == []
        )

    def test_the_fixture_directory_says_it_is_not_captured_output(self):
        readme = (FIXTURES / "README.md").read_text()
        assert "NOT captured output" in readme
        assert not (FIXTURES.parent / "captured").exists()


class TestFacetsDeclaration:
    def test_the_scanner_declares_its_own_facets_row(self):
        declared = vars(CapslockScanner).get(SCANNER_FACETS_ATTR)
        assert isinstance(declared, ScannerFacets)
        assert set(FACET_NAMES) == set(type(declared).model_fields)

    def test_every_cell_a_real_run_settles_is_unconfirmed_and_says_why(self):
        declared = vars(CapslockScanner)[SCANNER_FACETS_ATTR]
        unconfirmed = {
            name
            for name in FACET_NAMES
            if getattr(declared, name).state is FacetState.UNCONFIRMED
        }
        assert unconfirmed == UNREAD_CELLS
        for name in UNREAD_CELLS:
            assert getattr(declared, name).reason.startswith(cs._NO_CAPTURE), name

    def test_the_other_cells_cannot_exist_and_say_why(self):
        declared = vars(CapslockScanner)[SCANNER_FACETS_ATTR]
        for name in set(FACET_NAMES) - UNREAD_CELLS:
            cell = getattr(declared, name)
            assert cell.state is FacetState.NA, name
            assert (cell.reason or "").strip(), name
            assert "unconfirmed" not in cell.reason.lower(), name

    def test_operational_row_mirrors_the_class_declarations(self):
        row = vars(CapslockScanner)[opsf.OPERATIONAL_FACETS_ATTR]
        assert row.scanner_name == "capslock"
        assert row.exit_codes.success_exit_codes == tuple(
            sorted(CapslockScanner.success_exit_codes)
        )
        assert row.network.offline_strategy is CapslockScanner.offline_strategy
        assert row.runtime.python_only is CapslockScanner.python_only
        assert row.runtime.external_programs == ("capslock", "go")
        assert row.runtime_compat.rows == ()
        assert row.severity.severity_class is opsf.SeverityClass.CONSTANT
        assert row.provenance.source is opsf.ProvenanceSource.USER_INSTALLED

    def test_the_register_carries_the_license_read_at_the_pinned_commit(self):
        citation = CapslockScanner.operational_facets.provenance.upstream_license
        assert citation == cs.LICENSE_CITATION
        assert citation.startswith("BSD-3-Clause (source: the LICENSE file of ")
        assert cs.CAPSLOCK_VERSION in citation
        assert cs.CAPSLOCK_COMMIT[:7] in citation
        assert cs.CAPSLOCK_LICENSE_SHA256 in citation
        assert len(cs.CAPSLOCK_COMMIT) == 40 and len(cs.CAPSLOCK_LICENSE_SHA256) == 64

    def test_the_manifest_is_alpha_and_loads_only_when_listed(self):
        manifest = manifest_for("capslock")
        assert manifest is not None
        assert manifest.tier is PluginTier.ALPHA
        assert manifest.default_enabled is False
        assert manifest.plugin_module == (
            "automated_security_helper.plugin_modules.ash_capslock_plugins"
        )
        assert manifest.entry_points.scanner == (
            "automated_security_helper.plugin_modules.ash_capslock_plugins."
            "capslock_scanner:CapslockScanner"
        )
        assert manifest.options_model.endswith(
            "capslock_scanner:CapslockScannerConfigOptions"
        )
