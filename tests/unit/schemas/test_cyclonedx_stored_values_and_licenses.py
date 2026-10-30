# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The CycloneDX models keep a BOM's values as written and type its licenses.

A BOM is a scanner's document that ASH stores in a results file and emits again,
so the model has to hand back what the scanner wrote:

* Contact and action e-mails are text. The generated ``EmailStr`` refused a
  dotless or special-use domain, rewrote an accepted address (domain casefolded,
  display name dropped), and quoted the refused domain in its message.
* A spec default on an optional field (``Component.scope``, ``Versions.status``,
  ``Attachment.contentType``, ``Volume.mode``, the three ``Swid`` fields) is a
  consumer's assumption. As a model default it was a plain string on an
  enum-typed field, which warned on every dump, and the full dump a results file
  keeps wrote it, so ``ash report`` emitted a field the scanner never wrote.
* ``Signer.algorithm`` is text, not ``AnyUrl``, which added a trailing slash to a
  path-less URI.
* ``LicenseChoice`` entries are typed. An entry that fits neither license form
  is kept as written with a warning, whatever its type, so a stored BOM written
  by another ASH version, whose bare list accepted anything, still loads. A license
  id the bundled SPDX list lacks is kept as text, and an enum member given as an
  id is stored as its text.
"""

from __future__ import annotations

import json
import warnings
from unittest.mock import patch

import pydantic
import pytest

from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
    Attachment,
    Component,
    CycloneDXReport,
    IdentifiableAction,
    License1,
    License2,
    LicenseAcknowledgementEnumeration,
    LicenseChoice,
    LicenseEntry,
    LicenseExpression,
    OrganizationalContact,
    Scope,
    Signer,
    Swid,
    Versions,
    Versions1,
    Volume,
    spdx,
)

pytestmark = pytest.mark.unit


# --- e-mail addresses ---------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "firstname.lastname@example.com",
        "dev@localhost",
        "ops@build.internal.invalid",
        "Dev.Team@EXAMPLE.COM",
        "Dev Team <dev@example.com>",
    ],
)
def test_a_contact_email_is_kept_as_the_bom_wrote_it(address):
    contact = OrganizationalContact.model_validate({"name": "n", "email": address})
    assert contact.email == address
    assert contact.model_dump(exclude_none=True)["email"] == address


@pytest.mark.parametrize(
    "address",
    ["dev@localhost", "Dev.Team@EXAMPLE.COM", "Dev Team <dev@example.com>"],
)
def test_an_action_email_is_kept_as_the_bom_wrote_it(address):
    action = IdentifiableAction.model_validate({"name": "n", "email": address})
    assert action.email == address


def test_a_special_use_domain_does_not_refuse_the_whole_report():
    report = CycloneDXReport.model_validate(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {
                "authors": [{"name": "n", "email": "dev@secret-host.invalid"}]
            },
        }
    )
    assert report.metadata.authors[0].email == "dev@secret-host.invalid"


def test_control_an_email_that_is_not_text_is_still_refused():
    with pytest.raises(pydantic.ValidationError):
        OrganizationalContact.model_validate({"email": 5})
    with pytest.raises(pydantic.ValidationError):
        IdentifiableAction.model_validate({"email": ["dev@example.com"]})


# --- spec defaults on optional fields ----------------------------------------


UNWRITTEN_FIELDS = [
    pytest.param(Component, {"type": "library", "name": "lib"}, ["scope"], id="scope"),
    pytest.param(Versions, {"version": "1.0"}, ["status"], id="versions-status"),
    pytest.param(
        Versions1, {"range": "vers:npm/>=1.0.0"}, ["status"], id="range-status"
    ),
    pytest.param(Attachment, {"content": "text"}, ["contentType"], id="content-type"),
    pytest.param(Volume, {}, ["mode"], id="volume-mode"),
    pytest.param(
        Swid,
        {"tagId": "tag", "name": "name"},
        ["version", "tagVersion", "patch"],
        id="swid",
    ),
]


@pytest.mark.parametrize("model, payload, fields", UNWRITTEN_FIELDS)
def test_a_field_the_bom_did_not_write_stays_none_and_dumps_quietly(
    model, payload, fields
):
    instance = model.model_validate(payload)
    for field in fields:
        assert getattr(instance, field) is None, field
    with warnings.catch_warnings():
        warnings.simplefilter("error", UserWarning)
        dumped = instance.model_dump(by_alias=True)
        instance.model_dump_json(by_alias=True)
    for field in fields:
        assert dumped[field] is None, field


def test_control_a_value_the_bom_wrote_is_kept():
    component = Component.model_validate(
        {"type": "library", "name": "lib", "scope": "excluded"}
    )
    assert component.scope == Scope.excluded
    assert component.model_dump(mode="json", by_alias=True)["scope"] == "excluded"
    attachment = Attachment.model_validate(
        {"content": "x", "contentType": "application/json"}
    )
    assert attachment.contentType == "application/json"
    swid = Swid.model_validate(
        {"tagId": "t", "name": "n", "version": "2.0", "tagVersion": 3, "patch": True}
    )
    assert (swid.version, swid.tagVersion, swid.patch) == ("2.0", 3, True)


BOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "components": [
        {"type": "library", "name": "unscoped", "bom-ref": "pkg:unscoped@1"},
        {
            "type": "library",
            "name": "scoped",
            "bom-ref": "pkg:scoped@1",
            "scope": "optional",
        },
    ],
}


def _as_the_reporter_emits(report: CycloneDXReport) -> dict:
    """The document ``cyclonedx_reporter`` writes, through the reporter's own
    serialization (``serialize_bom``), not a copy of it.

    The reporter dumps the fields that were set, and before dumping it marks the
    envelope fields set, so a BOM whose scanner wrote no ``version`` is emitted
    with the spec default, 1, before and after a results-file round trip alike.
    A bare exclude_unset dump reads ``version`` as unset before the round trip
    and as set after it (the stored results file is a full dump, which writes the
    default, and re-validation marks it set), and that difference is the
    reporter's own envelope, not something the round trip added. Calling the
    reporter's function means a change to its dump flags or its envelope marks
    changes what these tests compare, as it changes ``ash report``.
    """
    from automated_security_helper.plugin_modules.ash_builtin.reporters.cyclonedx_reporter import (
        serialize_bom,
    )

    return json.loads(serialize_bom(report))


def test_the_reporter_itself_emits_what_the_round_trip_tests_compare(tmp_path):
    """The must-flag control for using the reporter's function: the reporter's
    ``report`` output for a results model carrying BOM is byte for byte what
    ``serialize_bom`` returns for that BOM, and the BOM given in is left as it
    was (no envelope field marked set on the caller's model)."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.plugin_modules.ash_builtin.reporters.cyclonedx_reporter import (
        CycloneDXReporter,
        CycloneDXReporterConfig,
        serialize_bom,
    )

    report = CycloneDXReport.model_validate(BOM)
    fields_set_before = set(report.model_fields_set)
    model = AshAggregatedResults(cyclonedx=report)
    context = PluginContext(source_dir=tmp_path, output_dir=tmp_path / "out")
    reporter = CycloneDXReporter(context=context, config=CycloneDXReporterConfig())
    assert reporter.report(model) == serialize_bom(report)
    assert json.loads(serialize_bom(report))["version"] == 1
    assert set(report.model_fields_set) == fields_set_before


def test_a_results_file_round_trip_adds_no_field_the_scanner_did_not_write():
    report = CycloneDXReport.model_validate(BOM)
    stored = report.model_dump_json(by_alias=True)
    reread = CycloneDXReport.model_validate_json(stored)
    emitted = _as_the_reporter_emits(reread)
    assert "scope" not in emitted["components"][0]
    assert emitted["components"][1]["scope"] == "optional"
    assert emitted == _as_the_reporter_emits(report)


# --- Signer.algorithm ---------------------------------------------------------


def test_a_signature_algorithm_uri_is_kept_as_written():
    signer = Signer.model_validate(
        {"algorithm": "https://example.com", "value": "c2ln"}
    )
    assert signer.model_dump(mode="json")["algorithm"] == "https://example.com"
    assert signer.model_dump()["algorithm"] == "https://example.com"


def test_control_a_registered_signature_algorithm_is_kept():
    signer = Signer.model_validate({"algorithm": "RS256", "value": "c2ln"})
    assert signer.model_dump(mode="json")["algorithm"] == "RS256"


# --- license entries ----------------------------------------------------------


def test_a_license_entry_by_spdx_id_is_typed_and_kept():
    choice = LicenseChoice.model_validate([{"license": {"id": "MIT"}}])
    (entry,) = choice.root
    assert isinstance(entry, LicenseEntry)
    assert entry.license.root.id == "MIT"
    assert choice.model_dump(by_alias=True, exclude_none=True) == [
        {"license": {"id": "MIT"}}
    ]


def test_a_license_id_the_spdx_snapshot_lacks_is_kept_as_text():
    """A BOM written by a newer ASH can carry an id this snapshot does not list;
    it must still load, or a results file read by an older ASH is refused."""
    choice = LicenseChoice.model_validate([{"license": {"id": "Imaginary-9.9"}}])
    assert choice.model_dump(by_alias=True, exclude_none=True) == [
        {"license": {"id": "Imaginary-9.9"}}
    ]


def test_a_named_license_is_typed_and_kept():
    choice = LicenseChoice.model_validate(
        [{"license": {"name": "Acme Software License", "url": "https://example.com"}}]
    )
    assert choice.root[0].license.root.name == "Acme Software License"
    assert choice.model_dump(by_alias=True, exclude_none=True) == [
        {"license": {"name": "Acme Software License", "url": "https://example.com"}}
    ]


def test_a_license_expression_is_typed_and_keeps_its_bom_ref():
    choice = LicenseChoice.model_validate(
        [{"expression": "MIT OR Apache-2.0", "bom-ref": "lic-1"}]
    )
    (entry,) = choice.root
    assert isinstance(entry, LicenseExpression)
    assert entry.expression == "MIT OR Apache-2.0"
    assert choice.model_dump(by_alias=True, exclude_none=True) == [
        {"expression": "MIT OR Apache-2.0", "bom-ref": "lic-1"}
    ]


LOGGER = "automated_security_helper.utils.log.ASH_LOGGER"


@pytest.fixture(autouse=True)
def _fresh_license_warnings(monkeypatch):
    """Each test starts with no license entry shape warned about yet: the
    module warns once per shape per process, and the tests below count calls."""
    import automated_security_helper.schemas.cyclonedx_bom_1_6_schema as module

    monkeypatch.setattr(module, "_LICENSE_ENTRY_SHAPES_WARNED", set())


@pytest.mark.parametrize(
    "entries",
    [
        [{"license": {}}],
        [{"license": {"id": "MIT"}, "expression": "MIT"}],
        [{"licence": {"id": "MIT"}}],
        [{"license": {"id": "MIT", "unknown_key": 1}}],
    ],
    ids=["no-id-or-name", "both-forms", "misspelled-key", "extra-key"],
)
def test_an_entry_that_fits_neither_form_is_kept_as_written_with_a_warning(entries):
    """A results file written by another ASH version can hold what the old bare
    list accepted; one such entry must not refuse the stored BOM."""
    with patch(LOGGER) as logger:
        choice = LicenseChoice.model_validate(entries)
    assert choice.root == entries
    assert logger.warning.call_count == 1
    assert "MIT" not in logger.warning.call_args.args[0]


def test_a_stray_entry_leaves_its_neighbors_typed_and_warns_once():
    entries = [
        {"license": {"id": "MIT"}},
        {"license": {}},
        {"expression": "MIT OR Apache-2.0"},
    ]
    with patch(LOGGER) as logger:
        choice = LicenseChoice.model_validate(entries)
    assert isinstance(choice.root[0], LicenseEntry)
    assert choice.root[1] == {"license": {}}
    assert isinstance(choice.root[2], LicenseExpression)
    assert logger.warning.call_count == 1
    message = logger.warning.call_args.args[0]
    assert "entry 1" in message
    assert "an object with the keys license" in message


def test_the_same_entry_shape_warns_once_per_process():
    """A BOM with thousands of components carrying the same stray entry, or a
    results file loaded again, repeats no warning; a new shape warns again."""
    stray = {"license": {"id": "MIT"}, "expression": "MIT"}
    with patch(LOGGER) as logger:
        LicenseChoice.model_validate([stray, stray, {"license": {"id": "MIT"}}])
        LicenseChoice.model_validate([stray])
        Component.model_validate(
            {"type": "library", "name": "lib", "licenses": [stray, "MIT"]}
        )
    assert logger.warning.call_count == 2
    first, second = (call.args[0] for call in logger.warning.call_args_list)
    assert "an object with the keys expression, license" in first
    assert "a value of type str" in second


def test_control_a_well_formed_list_warns_nothing():
    with patch(LOGGER) as logger:
        LicenseChoice.model_validate(
            [{"license": {"id": "MIT"}}, {"license": {"name": "Acme"}}]
        )
    logger.warning.assert_not_called()


@pytest.mark.parametrize(
    "entries",
    [["MIT"], [1], [[{"license": {"id": "MIT"}}]]],
    ids=["string", "number", "list"],
)
def test_a_list_entry_that_is_not_an_object_is_kept_as_written_too(entries):
    """The old bare ``List`` accepted a bare id, a number or a nested list, so a
    stored BOM can hold one; it is kept and warned about like a stray object."""
    with patch(LOGGER) as logger:
        choice = LicenseChoice.model_validate(entries)
    assert choice.root == entries
    assert choice.model_dump(by_alias=True) == entries
    assert logger.warning.call_count == 1


def test_a_bare_license_id_does_not_refuse_the_component_that_carries_it():
    with patch(LOGGER):
        component = Component.model_validate(
            {"type": "library", "name": "lib", "licenses": ["MIT"]}
        )
    assert component.name == "lib"
    assert component.model_dump(by_alias=True, exclude_none=True)["licenses"] == ["MIT"]


def test_a_stray_license_entry_does_not_refuse_the_component_that_carries_it():
    with patch(LOGGER):
        component = Component.model_validate(
            {"type": "library", "name": "lib", "licenses": [{"license": {}}]}
        )
    assert component.name == "lib"
    dumped = component.model_dump(by_alias=True, exclude_none=True)
    assert dumped["licenses"] == [{"license": {}}]


def test_the_acknowledgement_of_a_license_keeps_its_enum_in_every_form():
    choice = LicenseChoice.model_validate(
        [
            {"license": {"id": "MIT", "acknowledgement": "declared"}},
            {"license": {"name": "Acme", "acknowledgement": "concluded"}},
            {"expression": "MIT", "acknowledgement": "declared"},
        ]
    )
    by_id, by_name, expression = choice.root
    declared = LicenseAcknowledgementEnumeration.declared
    assert by_id.license.root.acknowledgement is declared
    assert by_name.license.root.acknowledgement is (
        LicenseAcknowledgementEnumeration.concluded
    )
    assert expression.acknowledgement is declared


def test_an_spdx_enum_member_is_stored_as_its_text():
    by_id = License1.model_validate({"id": spdx.Schema.MIT})
    assert type(by_id.id) is str
    assert by_id.id == "MIT"
    by_name = License2.model_validate({"id": spdx.Schema.Apache_2_0, "name": "n"})
    assert type(by_name.id) is str
    assert by_name.id == "Apache-2.0"


def test_a_stored_bom_with_an_unlisted_license_id_loads_and_round_trips():
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "type": "library",
                "name": "lib",
                "licenses": [
                    {"license": {"id": "Imaginary-9.9"}},
                    {"license": {"name": "Acme Software License"}},
                ],
            }
        ],
    }
    report = CycloneDXReport.model_validate(bom)
    reread = CycloneDXReport.model_validate_json(report.model_dump_json(by_alias=True))
    emitted = _as_the_reporter_emits(reread)
    assert emitted["components"][0]["licenses"] == bom["components"][0]["licenses"]
    assert emitted == _as_the_reporter_emits(report)
