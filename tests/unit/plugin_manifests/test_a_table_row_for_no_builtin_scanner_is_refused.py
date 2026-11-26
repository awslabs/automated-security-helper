# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A builtin table row that names no builtin scanner fails the import.

``_builtin`` reads ``_EXCLUSIONS`` with ``.get``, so a row left behind by a renamed
or removed scanner answered "no exclusion options" for nobody and was dropped
silently, and a description for no scanner was never read at all. The tables are
checked against the declared scanners when the module is imported.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_manifest import ExclusionOption
from automated_security_helper.plugin_manifests import ManifestRegistryError, builtin

pytestmark = pytest.mark.unit

ROW = (ExclusionOption(option="exclude", kind="glob"),)


def _args():
    return (
        builtin.MANIFESTS,
        dict(builtin._SECTION_DESCRIPTIONS),
        dict(builtin._EXCLUSIONS),
    )


def test_control_the_shipped_tables_pass():
    builtin._check_tables(*_args())


def test_a_description_for_no_scanner_is_refused():
    manifests, descriptions, exclusions = _args()
    descriptions["renamed-scanner"] = "Configure the options for renamed-scanner"

    with pytest.raises(ManifestRegistryError, match="renamed-scanner"):
        builtin._check_tables(manifests, descriptions, exclusions)


def test_a_scanner_without_a_description_is_refused():
    manifests, descriptions, exclusions = _args()
    dropped = min(descriptions)
    del descriptions[dropped]

    with pytest.raises(ManifestRegistryError, match=dropped):
        builtin._check_tables(manifests, descriptions, exclusions)


def test_an_exclusion_row_for_no_scanner_is_refused():
    manifests, descriptions, exclusions = _args()
    exclusions["removed-scanner"] = ROW

    with pytest.raises(ManifestRegistryError, match="removed-scanner"):
        builtin._check_tables(manifests, descriptions, exclusions)


def test_the_error_type_covers_a_single_malformed_entry():
    """The type's docstring names both shapes of fault it is raised for."""
    doc = ManifestRegistryError.__doc__ or ""

    assert "malformed" in doc and "contradict" in doc
