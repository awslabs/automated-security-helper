# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A manifest-module table row that names no scanner of that module fails the import.

``_builtin`` and ``_alpha`` read their tables with ``.get``, so a row left behind
by a renamed or removed scanner answered "nothing declared" for nobody and was
dropped silently: the scanner shipped without its exclusion options or its
denied option defaults. Each module checks its tables against the scanners it
declares when it is imported.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.plugin_manifest import ExclusionOption
from automated_security_helper.plugin_manifests import (
    ManifestRegistryError,
    alpha,
    builtin,
    check_table_rows,
)

pytestmark = pytest.mark.unit

ROW = (ExclusionOption(option="exclude", kind="glob"),)


def _names(module) -> set[str]:
    return {manifest.name for manifest in module.MANIFESTS}


def test_control_the_shipped_tables_pass():
    check_table_rows(
        "builtin",
        _names(builtin),
        _SECTION_DESCRIPTIONS=builtin._SECTION_DESCRIPTIONS,
        _EXCLUSIONS=builtin._EXCLUSIONS,
    )
    check_table_rows(
        "alpha",
        _names(alpha),
        _EXCLUSIONS=alpha._EXCLUSIONS,
        _DENIED_OPTION_DEFAULTS=alpha._DENIED_OPTION_DEFAULTS,
    )


def test_a_row_for_no_scanner_is_refused_naming_table_and_row():
    with pytest.raises(ManifestRegistryError, match=r"_EXCLUSIONS.*removed-scanner"):
        check_table_rows(
            "alpha",
            _names(alpha),
            _EXCLUSIONS={**alpha._EXCLUSIONS, "removed-scanner": ROW},
        )


def test_an_alpha_denied_default_row_for_no_scanner_is_refused():
    """The same silent drop the builtin tables had: ``_alpha`` reads this table
    with ``.get`` too."""
    with pytest.raises(
        ManifestRegistryError, match=r"_DENIED_OPTION_DEFAULTS.*renamed-scanner"
    ):
        check_table_rows(
            "alpha",
            _names(alpha),
            _DENIED_OPTION_DEFAULTS={
                **alpha._DENIED_OPTION_DEFAULTS,
                "renamed-scanner": {"offline": False},
            },
        )


def test_a_description_for_no_builtin_scanner_is_refused():
    with pytest.raises(ManifestRegistryError, match=r"_SECTION_DESCRIPTIONS.*ghost"):
        check_table_rows(
            "builtin",
            _names(builtin),
            _SECTION_DESCRIPTIONS={**builtin._SECTION_DESCRIPTIONS, "ghost": "x"},
        )


def test_every_manifest_module_calls_the_check(monkeypatch):
    """The check runs when the module is imported, so a stale row stops the
    import and not only a test that calls the function."""
    import importlib

    calls = []
    real = check_table_rows
    monkeypatch.setattr(
        "automated_security_helper.plugin_manifests.check_table_rows",
        lambda module, names, **tables: (
            calls.append(module),
            real(module, names, **tables),
        )[1],
    )

    importlib.reload(builtin)
    importlib.reload(alpha)

    assert calls == [builtin.__name__, alpha.__name__]
