# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Image attribution: stamped on results, keyed into the identity, matched by
``image:`` suppressions, and invisible to a filesystem scan.

The rows are the design's C4 and C9 identity, suppression and oracle rows. No
tool runs and no image is read: a SARIF result is built here, stamped the way
the scanner executor stamps it, and read back through the same extractors a
scan's results go through.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import Run
from automated_security_helper.utils.finding_identity import (
    IMAGE_DIGEST_PROPERTY,
    IMAGE_REF_PROPERTY,
    finding_identity,
    relative_to_scan_root,
)
from automated_security_helper.utils.image_attribution import (
    image_digest_of_run,
    mark_image_results,
)

pytestmark = pytest.mark.unit

DIGEST = "sha256:" + "ab" * 32
OTHER_DIGEST = "sha256:" + "cd" * 32
REF = "registry.example.com/team/app:1.2.3"


def _run(path: str = "/usr/lib/libssl.so.3", **run_properties) -> Run:
    return Run.model_validate(
        {
            "tool": {"driver": {"name": "trivy", "version": "0.0.0"}},
            "properties": run_properties or None,
            "results": [
                {
                    "ruleId": "CVE-2024-0001",
                    "message": {"text": "libssl is vulnerable"},
                    "level": "error",
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": path},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
            ],
        }
    )


class _Report:
    def __init__(self, *runs: Run) -> None:
        self.runs = list(runs)


def _flat(run: Run) -> FlatVulnerability:
    return FlatVulnerability.from_sarif_result(
        run.results[0], tool_name="trivy", tool_type="SCA", run=run
    )


def _stamped(run: Run, image: ImageLocator) -> FlatVulnerability:
    mark_image_results(_Report(run), image)
    return _flat(run)


# -- the executor's stamp ---------------------------------------------------


def test_every_result_of_an_image_scan_carries_the_submitted_ref():
    run = _run()
    assert mark_image_results(_Report(run), ImageLocator(ref=REF)) == 1
    assert getattr(run.results[0].properties, IMAGE_REF_PROPERTY) == REF


def test_a_run_that_names_an_image_id_supplies_the_digest():
    run = _run(imageID=DIGEST)
    mark_image_results(_Report(run), ImageLocator(ref=REF))
    assert getattr(run.results[0].properties, IMAGE_DIGEST_PROPERTY) == DIGEST


def test_a_repo_digest_is_read_when_there_is_no_image_id():
    run = _run(repoDigests=[f"registry.example.com/team/app@{DIGEST}"])
    assert image_digest_of_run(run) == DIGEST


def test_a_run_that_names_no_digest_leaves_the_property_off():
    run = _run()
    mark_image_results(_Report(run), ImageLocator(ref=REF))
    assert getattr(run.results[0].properties, IMAGE_DIGEST_PROPERTY, None) is None


def test_the_locators_resolved_digest_is_the_fallback_digest():
    run = _run()
    mark_image_results(
        _Report(run), ImageLocator(ref=REF, resolved_digest=OTHER_DIGEST)
    )
    assert getattr(run.results[0].properties, IMAGE_DIGEST_PROPERTY) == OTHER_DIGEST


def test_a_digest_pinned_ref_is_its_own_digest():
    run = _run()
    mark_image_results(
        _Report(run), ImageLocator(ref=f"registry.example.com/team/app@{DIGEST}")
    )
    assert getattr(run.results[0].properties, IMAGE_DIGEST_PROPERTY) == DIGEST


def test_a_tag_only_ref_names_no_digest():
    run = _run()
    mark_image_results(_Report(run), ImageLocator(ref="registry.example.com/app:1.2"))
    assert getattr(run.results[0].properties, IMAGE_DIGEST_PROPERTY, None) is None


def test_a_pinned_ref_and_a_tag_of_the_same_image_share_ids_when_the_run_names_the_digest():
    pinned = _stamped(
        _run(imageID=DIGEST),
        ImageLocator(ref=f"registry.example.com/team/app@{DIGEST}"),
    )
    tagged = _stamped(_run(imageID=DIGEST), ImageLocator(ref=REF))
    assert pinned.id == tagged.id


def test_the_runs_own_digest_beats_the_locators():
    run = _run(imageID=DIGEST)
    mark_image_results(
        _Report(run), ImageLocator(ref=REF, resolved_digest=OTHER_DIGEST)
    )
    assert getattr(run.results[0].properties, IMAGE_DIGEST_PROPERTY) == DIGEST


# -- the flat columns and the identity --------------------------------------


def test_the_flat_finding_carries_the_attribution_columns():
    flat = _stamped(_run(imageID=DIGEST), ImageLocator(ref=REF))
    assert (flat.image_ref, flat.image_digest) == (REF, DIGEST)
    assert flat.file_path.endswith("/usr/lib/libssl.so.3")


def test_two_ref_spellings_that_resolve_to_one_digest_share_an_id():
    one = _stamped(_run(imageID=DIGEST), ImageLocator(ref=REF))
    other = _stamped(_run(imageID=DIGEST), ImageLocator(ref="mirror.local/app:latest"))
    assert one.id == other.id


def test_two_digests_of_one_ref_are_two_findings():
    one = _stamped(_run(imageID=DIGEST), ImageLocator(ref=REF))
    other = _stamped(_run(imageID=OTHER_DIGEST), ImageLocator(ref=REF))
    assert one.id != other.id


def test_without_a_digest_the_submitted_ref_keys_the_finding():
    one = _stamped(_run(), ImageLocator(ref=REF))
    other = _stamped(_run(), ImageLocator(ref="registry.example.com/team/app:9"))
    assert one.id != other.id


def test_an_image_finding_never_collides_with_a_source_finding_at_the_same_path():
    source = _flat(_run())
    image = _stamped(_run(), ImageLocator(ref=REF))
    assert source.id != image.id


def test_the_scan_root_never_rebases_an_in_image_path(tmp_path):
    identity = finding_identity(
        scanner="trivy",
        rule_id="CVE-2024-0001",
        file_path="/usr/lib/libssl.so.3",
        line_start=1,
        line_end=1,
        fingerprints=(),
        package_name=None,
        package_path=None,
        workspace_project=None,
        image=DIGEST,
    )
    assert relative_to_scan_root(identity, tmp_path) is identity
    assert identity.base["tree"] == "image"
    assert identity.base["image"] == DIGEST


# -- the zero-change oracle for a filesystem scan ----------------------------


def test_a_filesystem_identity_has_no_image_component():
    identity = finding_identity(
        scanner="trivy",
        rule_id="CVE-2024-0001",
        file_path="src/app.py",
        line_start=1,
        line_end=1,
        fingerprints=(),
        package_name=None,
        package_path=None,
        workspace_project=None,
    )
    assert "image" not in identity.base
    assert "tree" not in identity.base


def test_a_filesystem_result_keeps_its_id_and_has_no_attribution():
    flat = _flat(_run("src/app.py"))
    assert (flat.image_ref, flat.image_digest, flat.layer_digest) == (None, None, None)
    # The same result after the executor's stamp is a no-op for a filesystem
    # scan (no locator): the id is what it was.
    run = _run("src/app.py")
    before = _flat(run).id
    mark_image_results(_Report(run), None)
    assert _flat(run).id == before == flat.id


ATTRIBUTION_COLUMNS = {"image_ref", "image_digest", "layer_digest"}


def test_a_filesystem_finding_dumps_none_of_the_attribution_columns():
    flat = _flat(_run("src/app.py"))
    assert not ATTRIBUTION_COLUMNS & set(flat.model_dump())
    assert not ATTRIBUTION_COLUMNS & set(flat.model_dump(exclude_none=False))
    assert not any(name in flat.model_dump_json() for name in ATTRIBUTION_COLUMNS)


def test_an_image_finding_dumps_all_three_attribution_columns():
    flat = _stamped(_run(imageID=DIGEST), ImageLocator(ref=REF))
    dumped = flat.model_dump()
    assert ATTRIBUTION_COLUMNS <= set(dumped)
    assert dumped["layer_digest"] is None
    assert dumped["image_ref"] == REF


def test_the_csv_header_of_a_scan_with_no_findings_has_no_attribution_columns():
    from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
        CsvReporter,
    )

    assert not ATTRIBUTION_COLUMNS & set(CsvReporter._header(False))


def test_marking_with_no_locator_changes_nothing():
    run = _run()
    assert mark_image_results(_Report(run), None) == 0
    assert run.results[0].properties is None or (
        getattr(run.results[0].properties, IMAGE_REF_PROPERTY, None) is None
    )


# -- the suppression field ---------------------------------------------------


def _suppression(**fields) -> AshSuppression:
    return AshSuppression(
        path="**", reason="accepted for this image", rule_id="CVE-*", **fields
    )


def test_an_image_scoped_suppression_matches_the_submitted_ref():
    flat = _stamped(_run(imageID=DIGEST), ImageLocator(ref=REF))
    assert _suppression(image="registry.example.com/team/*").matches(flat)


def test_an_image_scoped_suppression_matches_the_resolved_digest():
    flat = _stamped(_run(imageID=DIGEST), ImageLocator(ref=REF))
    assert _suppression(image="sha256:abab*").matches(flat)


def test_an_image_pattern_is_case_insensitive():
    flat = _stamped(_run(), ImageLocator(ref=REF))
    assert _suppression(image="REGISTRY.EXAMPLE.COM/*").matches(flat)


def test_an_image_pattern_that_names_another_image_does_not_match():
    flat = _stamped(_run(imageID=DIGEST), ImageLocator(ref=REF))
    assert not _suppression(image="alpine:*").matches(flat)


def test_a_finding_with_no_image_never_matches_an_image_scoped_suppression():
    assert not _suppression(image="*").matches(_flat(_run("src/app.py")))


def test_a_suppression_with_no_image_field_matches_either_kind_of_finding():
    entry = _suppression()
    assert entry.matches(_flat(_run("src/app.py")))
    assert entry.matches(_stamped(_run(), ImageLocator(ref=REF)))


def test_the_path_still_matches_the_in_image_path_as_written():
    flat = _stamped(_run(), ImageLocator(ref=REF))
    entry = AshSuppression(
        path="/usr/lib/**", reason="base image", rule_id="CVE-*", image=REF
    )
    assert entry.matches(flat)


def test_a_blank_image_pattern_is_refused():
    with pytest.raises(ValueError, match="image"):
        _suppression(image="  ")


def test_an_image_scoped_entry_has_its_own_id():
    assert _suppression().id != _suppression(image="alpine:*").id
    assert _suppression(image="a:*").id != _suppression(image="b:*").id


def test_an_entry_without_an_image_keeps_the_id_it_had():
    assert _suppression().id == "**|CVE-*|*|*"


# -- the SARIF pass the executor runs ---------------------------------------


def _suppressed_after_the_sarif_pass(tmp_path, run: Run, entry: AshSuppression) -> bool:
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.schemas.sarif_schema_model import SarifReport
    from automated_security_helper.utils.sarif_utils import (
        apply_suppressions_to_sarif,
    )

    config = AshConfig(project_name="p", global_settings={"suppressions": [entry]})
    context = PluginContext(
        source_dir=tmp_path, output_dir=tmp_path / "out", config=config
    )
    report = SarifReport(version="2.1.0", runs=[run])
    applied = apply_suppressions_to_sarif(report, context)
    return bool(applied.runs[0].results[0].suppressions)


def test_the_sarif_pass_applies_an_image_scoped_suppression_to_that_image(tmp_path):
    run = _run()
    mark_image_results(_Report(run), ImageLocator(ref=REF))
    assert _suppressed_after_the_sarif_pass(
        tmp_path, run, _suppression(image="registry.example.com/*")
    )


def test_the_sarif_pass_leaves_another_image_s_finding_alone(tmp_path):
    run = _run()
    mark_image_results(_Report(run), ImageLocator(ref=REF))
    assert not _suppressed_after_the_sarif_pass(
        tmp_path, run, _suppression(image="alpine:*")
    )


def test_the_sarif_pass_never_applies_an_image_scoped_entry_to_a_source_finding(
    tmp_path,
):
    assert not _suppressed_after_the_sarif_pass(
        tmp_path, _run("app.py"), _suppression(image="*")
    )


def test_the_sarif_pass_still_applies_an_unscoped_entry_to_a_source_finding(tmp_path):
    assert _suppressed_after_the_sarif_pass(tmp_path, _run("app.py"), _suppression())
