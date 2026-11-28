# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The fixture plugin's scanner: the smallest plugin that conforms.

This is a declarative stand-in, not a registered scanner: it carries the two register rows
(``facets`` and ``operational_facets``) a real scanner class carries and nothing else, so
the conformance harness can be exercised end to end without any tool, without loading a
real plugin, and without touching the plugin registry. Its transcript is the
``transcripts`` directory beside this package.

It is the positive control of ``tests/unit/plugin_conformance``: every row of the promotion
bar that can be evaluated without CI reads green over it, and each planted-defect test
breaks exactly one thing about a copy of it and expects exactly one row to go red.
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.scanner_facets import (
    FacetDecl,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType


class FixtureOptions(BaseModel):
    """The options model the manifest names; the fixture scanner has none."""


def _na(reason: str) -> FacetDecl:
    return FacetDecl(state=FacetState.NA, reason=reason)


def _mapped(field: str) -> FacetDecl:
    return FacetDecl(state=FacetState.MAPPED, native_field=field)


class FixtureScanner:
    """A scanner that reports one finding per line of the fixture source it is given."""

    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=_mapped('result "ruleId"'),
        severity=_mapped('result "level"'),
        file_path=_mapped("locations[].physicalLocation.artifactLocation.uri"),
        line_range=_mapped("region.startLine"),
        column=_mapped("region.startColumn"),
        message=_mapped('result "message.text"'),
        resource_id=_na("the fixture reports file locations, not resources"),
        resource_type=_na("the fixture reports file locations, not resources"),
        package_name=_na("the fixture reports no package"),
        package_version=_na("the fixture reports no package"),
        package_path=_na("the fixture reports no package"),
        taxonomy_cve=_na("the fixture's rules carry no CVE taxonomy"),
        taxonomy_cwe=_na("the fixture's rules carry no CWE taxonomy"),
        fingerprints=_na("the fixture's results carry no fingerprint"),
        fix_available=_na("the fixture carries no fix state"),
        remediation_text=_na("the fixture's advice is the message itself"),
        snippet=_na("the fixture's regions carry no snippet"),
        references=_na("the fixture's driver has no rules array"),
        tags=_na("the fixture's results carry no tags"),
        extras=_na("the fixture writes no property bag"),
    )

    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="fixture-lint",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source="ash_fixture_plugin/scanner.py",
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
                note="one SARIF file",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SOURCE_CODE,),
                tool_type=ScannerToolType.SAST,
                selection="every python file in the scan set",
                covers_note="a fixture; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="installed by the user; ASH provisions nothing",
            ),
            image=opsf.ImageFacet(
                route=opsf.ImageRoute.NOT_IN_IMAGE,
                reason="a test fixture; the user installs its CLI",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.DERIVED,
                note="the native level through one table",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="the fixture has no tool, so no tool-side layer",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="identity is file and line through the shared floor",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="none: the fixture has no options",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="0 is the only status a completed run gives",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_fixture_plugin in ash_plugin_modules",),
                upstream_license="not applicable (source: a test fixture with no upstream)",
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="python files in the scan set; the fixture-lint CLI on PATH",
            ),
        )
    )
