# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Three readings of the suppression pass that lost a finding or a file name.

A suppression copied from the report in the report's own spelling (``a%20b.py``)
never matched, because the pass matched the decoded spelling alone. A
client-supplied scanner exclusion was applied on the first location it matched,
so a finding located in an excluded file and in a kept file was hidden, where
the ignore paths keep such a finding. And a URI spelled through an outside link
to the scan root was relativized at the deepest ancestor that resolves to the
root, so an in-tree link back to the root was dropped from the recorded path.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation2,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import (
    _client_exclusion_for,
    _normalize_sarif_uri,
    _relative_to_resolved_root,
    apply_suppressions_to_sarif,
)
from automated_security_helper.utils.undecodable_text import path_in_record_form

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


def _location(uri: str) -> Location:
    return Location(
        physicalLocation=PhysicalLocation2(
            artifactLocation=ArtifactLocation(uri=uri),
            region=Region(startLine=3, endLine=3),
        )
    )


def _result(*uris: str, **overrides) -> Result:
    values = {
        "ruleId": "RULE-1",
        "level": "error",
        "message": Message(text="finding"),
        "locations": [_location(uri) for uri in uris],
    }
    values.update(overrides)
    return Result(**values)


def _report(*results: Result) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="scripted")),
                results=list(results),
            )
        ],
    )


def _context(tmp_path: Path, config: AshConfig) -> PluginContext:
    source = tmp_path / "src"
    output = source / ".ash" / "ash_output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=config,
    )


def _suppressing(path: str) -> AshConfig:
    return AshConfig(
        project_name="u28",
        global_settings={
            "suppressions": [
                AshSuppression(rule_id="RULE-1", path=path, reason="known")
            ]
        },
    )


class TestACopiedSpellingMatches:
    def test_the_report_spelling_of_an_encoded_name_matches_too(self, tmp_path):
        """The report records ``my%20app/a.py``; a suppression copied from it
        names the file that way, and the pass read only ``my app/a.py``."""
        report = apply_suppressions_to_sarif(
            _report(_result("my%20app/a.py")),
            _context(tmp_path, _suppressing("my%20app/a.py")),
        )
        assert report.runs[0].results[0].suppressions

    def test_the_decoded_spelling_still_matches_first(self, tmp_path):
        report = apply_suppressions_to_sarif(
            _report(_result("my%20app/a.py")),
            _context(tmp_path, _suppressing("my app/a.py")),
        )
        assert report.runs[0].results[0].suppressions

    def test_another_encoded_name_does_not_match(self, tmp_path):
        report = apply_suppressions_to_sarif(
            _report(_result("my%20app/a.py")),
            _context(tmp_path, _suppressing("other%20app/a.py")),
        )
        assert not report.runs[0].results[0].suppressions

    def test_normalize_keeps_the_escapes_when_told_not_to_decode(self):
        args = ("/work/", "/work/", None, None)
        assert _normalize_sarif_uri("src/a%20b.py", *args) == "src/a b.py"
        assert (
            _normalize_sarif_uri("src/a%20b.py", *args, decode=False) == "src/a%20b.py"
        )
        assert _normalize_sarif_uri("/work/src/a%20b.py", *args, decode=False) == (
            "src/a%20b.py"
        )


def _ignoring(path: str) -> AshConfig:
    return AshConfig(
        project_name="u28",
        global_settings={
            "ignore_paths": [IgnorePathWithReason(path=path, reason="vendored")]
        },
    )


class TestAnIgnorePathMeetsBothSpellings:
    """The same second match for the ignore paths: an entry copied from the report
    (``my%20app/``) names the directory a person reads there; the inline read
    needs none, because it opens the file under whichever spelling names one on
    disk (``_only_the_spelling_as_written_names_a_file``)."""

    def test_an_ignore_path_in_the_report_spelling_drops_the_result(self, tmp_path):
        report = apply_suppressions_to_sarif(
            _report(_result("my%20app/a.py"), _result("src/keep.py")),
            _context(tmp_path, _ignoring("my%20app/")),
        )
        remaining = [
            r.locations[0].physicalLocation.root.artifactLocation.uri
            for r in report.runs[0].results
        ]
        assert remaining == ["src/keep.py"]

    def test_the_decoded_spelling_still_drops_it(self, tmp_path):
        report = apply_suppressions_to_sarif(
            _report(_result("my%20app/a.py"), _result("src/keep.py")),
            _context(tmp_path, _ignoring("my app/")),
        )
        assert len(report.runs[0].results) == 1

    def test_another_encoded_directory_keeps_it(self, tmp_path):
        report = apply_suppressions_to_sarif(
            _report(_result("my%20app/a.py")),
            _context(tmp_path, _ignoring("other%20app/")),
        )
        assert len(report.runs[0].results) == 1


class TestAClientExclusionNeedsEveryLocation:
    @pytest.fixture
    def excluding_vendor(self, monkeypatch):
        """``matching_exclusion`` stands in: a location under ``vendor/`` is
        excluded, any other is kept."""
        import automated_security_helper.config.client_scanner_exclusions as module

        exclusion = SimpleNamespace(applies_to=lambda name: True, name="vendor")

        def fake(exclusions, *, scanner_name, relative, absolute, rule_id, budget):
            return exclusions[0] if relative.startswith("vendor/") else None

        monkeypatch.setattr(module, "matching_exclusion", fake)
        return [exclusion]

    _run = SimpleNamespace(tool=SimpleNamespace(driver=SimpleNamespace(name="checkov")))

    def _excluded_by(self, result: Result, exclusions):
        return _client_exclusion_for(
            result, self._run, exclusions, lambda raw: raw, Path("/work")
        )

    def test_every_located_location_excluded_is_excluded(self, excluding_vendor):
        both = _result("vendor/x.py", "vendor/y.py")
        assert self._excluded_by(both, excluding_vendor) is excluding_vendor[0]
        one = _result("vendor/x.py")
        assert self._excluded_by(one, excluding_vendor) is excluding_vendor[0]

    def test_a_kept_location_keeps_the_finding(self, excluding_vendor):
        """Located in an excluded ``vendor/x.py`` and in ``src/a.py``: a finding
        about ``src/a.py``, as the ignore paths read it; applied on the one
        matching location, the exclusion hid it."""
        mixed = _result("vendor/x.py", "src/a.py")
        assert self._excluded_by(mixed, excluding_vendor) is None
        reversed_order = _result("src/a.py", "vendor/x.py")
        assert self._excluded_by(reversed_order, excluding_vendor) is None

    def test_a_location_naming_no_file_is_not_counted(self, excluding_vendor):
        with_logical = _result("vendor/x.py")
        with_logical.locations.append(Location(message=Message(text="handler")))
        assert self._excluded_by(with_logical, excluding_vendor) is excluding_vendor[0]

    def test_no_located_location_is_not_excluded(self, excluding_vendor):
        assert self._excluded_by(_result(), excluding_vendor) is None


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs privileges")
class TestTheResolvedRootIsTheShallowestAncestor:
    @pytest.fixture
    def tree(self, tmp_path):
        """``real/`` is the scan root, spelled from outside through ``alias``
        (the macOS ``/tmp`` to ``/private/tmp`` shape) and holding ``self``, a
        link back to the root itself."""
        real = tmp_path / "real"
        (real / "src").mkdir(parents=True)
        (real / "src" / "a.py").write_text("x = 1\n")
        os.symlink(real, tmp_path / "alias", target_is_directory=True)
        os.symlink(real, real / "self", target_is_directory=True)
        return SimpleNamespace(
            real=real,
            alias=tmp_path / "alias",
            source=path_in_record_form(real.resolve()),
        )

    def test_an_in_tree_link_to_the_root_stays_in_the_recorded_path(self, tree):
        uri = str(tree.alias / "self" / "src" / "a.py")
        assert _relative_to_resolved_root(uri, tree.source) == os.path.join(
            "self", "src", "a.py"
        )

    def test_a_plain_file_through_the_outside_link_relativizes_as_before(self, tree):
        uri = str(tree.alias / "src" / "a.py")
        assert _relative_to_resolved_root(uri, tree.source) == os.path.join(
            "src", "a.py"
        )

    def test_a_uri_outside_the_root_still_raises(self, tree, tmp_path):
        (tmp_path / "elsewhere").mkdir()
        with pytest.raises(ValueError):
            _relative_to_resolved_root(
                str(tmp_path / "elsewhere" / "b.py"), tree.source
            )
