# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The package and resource identity projections, one record and many.

``identity_properties`` and the ``extract_*`` readers answer for one record. The
frame forms answer for a sequence of records as columns, and every row of a frame
is exactly what the per-record function answers for that record: the first block
pins the per-record answers, the second pins the frames against them.
"""

from __future__ import annotations

import polars as pl
import pytest

from automated_security_helper.schemas.sarif_schema_model import PropertyBag
from automated_security_helper.utils.package_identity import (
    ASH_RESOURCE_ID_KEY,
    ASH_RESOURCE_TYPE_KEY,
    PACKAGE_NAME_KEY,
    PACKAGE_PATH_KEY,
    PACKAGE_VERSION_KEY,
    extract_package_identity,
    extract_resource_identity,
    identity_properties,
    identity_properties_from_frame,
    package_identities_from_frame,
    package_identity_frame,
    resource_identities_from_frame,
    resource_identity_frame,
)

pytestmark = pytest.mark.unit


class TestPerRecordProjections:
    @pytest.mark.parametrize(
        "name, version, path, expected",
        [
            (
                "a",
                "1",
                "p/a",
                {"package_name": "a", "package_version": "1", "package_path": "p/a"},
            ),
            ("a", None, None, {"package_name": "a"}),
            (None, "1", None, {"package_version": "1"}),
            ("", "", "", {}),
            (None, None, None, {}),
        ],
    )
    def test_identity_properties_leaves_out_what_is_unknown(
        self, name, version, path, expected
    ):
        assert identity_properties(name, version, path) == expected

    def test_extract_package_identity_reads_the_three_keys(self):
        props = {
            PACKAGE_NAME_KEY: "a",
            PACKAGE_VERSION_KEY: "1",
            PACKAGE_PATH_KEY: "p/a",
        }
        assert extract_package_identity(props) == ("a", "1", "p/a")

    @pytest.mark.parametrize(
        "props",
        [None, 5, "text", [], {}, {PACKAGE_NAME_KEY: 5}, {PACKAGE_NAME_KEY: ""}],
    )
    def test_extract_package_identity_ignores_non_text_and_empty(self, props):
        assert extract_package_identity(props) == (None, None, None)

    def test_a_property_bag_reads_like_its_dict(self):
        bag = PropertyBag(**{PACKAGE_NAME_KEY: "a", PACKAGE_VERSION_KEY: "1"})
        assert extract_package_identity(bag) == ("a", "1", None)

    def test_resource_identity_prefers_the_flat_keys_then_the_cdk_nag_bag(self):
        flat = {ASH_RESOURCE_ID_KEY: "r", ASH_RESOURCE_TYPE_KEY: "T"}
        assert extract_resource_identity(flat) == ("r", "T")
        legacy = {
            "cdk_nag_finding": {"resource_id": "Stack/Bucket"},
            "cfn_resource": {"Resources": {"B": {"Type": "AWS::S3::Bucket"}}},
        }
        assert extract_resource_identity(legacy) == (
            "Stack/Bucket",
            "AWS::S3::Bucket",
        )
        two = {"cfn_resource": {"Resources": {"A": {"Type": "x"}, "B": {"Type": "y"}}}}
        assert extract_resource_identity(two) == (None, None)
        mixed = {
            ASH_RESOURCE_ID_KEY: "r",
            "cfn_resource": {"Resources": {"B": {"Type": "T"}}},
        }
        assert extract_resource_identity(mixed) == ("r", "T")


_RECORDS = [
    {PACKAGE_NAME_KEY: "a", PACKAGE_VERSION_KEY: "1", PACKAGE_PATH_KEY: "p/a"},
    {PACKAGE_NAME_KEY: "b"},
    None,
    {},
    {PACKAGE_NAME_KEY: 5, PACKAGE_VERSION_KEY: ""},
    {PACKAGE_NAME_KEY: "d\udcffir", PACKAGE_PATH_KEY: "dir/\udcff/x"},
    {PACKAGE_NAME_KEY: "é", PACKAGE_VERSION_KEY: "\U0001f600"},
    PropertyBag(**{PACKAGE_NAME_KEY: "bag", PACKAGE_VERSION_KEY: "2"}),
    {ASH_RESOURCE_ID_KEY: "r1", ASH_RESOURCE_TYPE_KEY: "T1"},
    {
        "cdk_nag_finding": {"resource_id": "S/B"},
        "cfn_resource": {"Resources": {"B": {"Type": "AWS::X"}}},
    },
    {ASH_RESOURCE_ID_KEY: "r\ud800"},
]


class TestFramesAgreeWithTheRecordFunctions:
    def test_package_frame_rows_are_the_extracted_tuples_in_order(self):
        frame = package_identity_frame(_RECORDS)
        # Named for the property-bag keys they are read from, not the bare
        # name/version/path, which read as three other model fields.
        assert frame.columns == [
            PACKAGE_NAME_KEY,
            PACKAGE_VERSION_KEY,
            PACKAGE_PATH_KEY,
        ]
        assert frame.schema == {
            PACKAGE_NAME_KEY: pl.String,
            PACKAGE_VERSION_KEY: pl.String,
            PACKAGE_PATH_KEY: pl.String,
        }
        assert package_identities_from_frame(frame) == [
            extract_package_identity(record) for record in _RECORDS
        ]

    def test_the_columns_bear_the_model_field_names_they_fill(self):
        # One vocabulary: the frame columns are the SARIF property keys, which
        # are the FlatVulnerability fields these values fill. A rename on either
        # side fails here until the other follows.
        from automated_security_helper.models.flat_vulnerability import (
            FlatVulnerability,
        )

        for column in (
            package_identity_frame([]).columns + resource_identity_frame([]).columns
        ):
            assert column in FlatVulnerability.model_fields, column
        assert package_identity_frame([]).columns == [
            PACKAGE_NAME_KEY,
            PACKAGE_VERSION_KEY,
            PACKAGE_PATH_KEY,
        ]

    def test_resource_frame_rows_are_the_extracted_tuples_in_order(self):
        frame = resource_identity_frame(_RECORDS)
        assert frame.columns == ["resource_id", "resource_type"]
        assert resource_identities_from_frame(frame) == [
            extract_resource_identity(record) for record in _RECORDS
        ]

    def test_properties_from_frame_are_identity_properties_per_row(self):
        frame = package_identity_frame(_RECORDS)
        assert identity_properties_from_frame(frame) == [
            identity_properties(*extract_package_identity(record))
            for record in _RECORDS
        ]

    def test_empty_input_gives_typed_empty_frames(self):
        packages = package_identity_frame([])
        resources = resource_identity_frame(iter(()))
        assert packages.height == 0 and resources.height == 0
        assert packages.schema == {
            PACKAGE_NAME_KEY: pl.String,
            PACKAGE_VERSION_KEY: pl.String,
            PACKAGE_PATH_KEY: pl.String,
        }
        assert identity_properties_from_frame(packages) == []
        assert package_identities_from_frame(packages) == []

    def test_equal_text_is_equal_in_the_frame_and_surrogates_stay_distinct(self):
        records = [
            {PACKAGE_NAME_KEY: "x\udcff"},
            {PACKAGE_NAME_KEY: "x\udcff"},
            {PACKAGE_NAME_KEY: "xÿ"},
        ]
        frame = package_identity_frame(records)
        names = frame[PACKAGE_NAME_KEY].to_list()
        assert names[0] == names[1] != names[2]
        assert frame[PACKAGE_NAME_KEY].n_unique() == 2

    def test_each_cell_lands_in_the_column_named_for_it(self):
        """Three different values in one record: a version in the name column, or a
        path in the version column, is a swapped cell the row-equality tests above
        would also pass if both sides were swapped alike."""
        frame = package_identity_frame(
            [
                {
                    PACKAGE_NAME_KEY: "the-name",
                    PACKAGE_VERSION_KEY: "the-version",
                    PACKAGE_PATH_KEY: "the/path",
                }
            ]
        )
        assert frame.to_dicts() == [
            {
                PACKAGE_NAME_KEY: "the-name",
                PACKAGE_VERSION_KEY: "the-version",
                PACKAGE_PATH_KEY: "the/path",
            }
        ]
        resources = resource_identity_frame(
            [{ASH_RESOURCE_ID_KEY: "the-id", ASH_RESOURCE_TYPE_KEY: "the-type"}]
        )
        assert resources.to_dicts() == [
            {"resource_id": "the-id", "resource_type": "the-type"}
        ]

    def test_a_generator_of_records_is_read_once(self):
        frame = package_identity_frame(({PACKAGE_NAME_KEY: str(n)} for n in range(3)))
        assert package_identities_from_frame(frame) == [
            ("0", None, None),
            ("1", None, None),
            ("2", None, None),
        ]
