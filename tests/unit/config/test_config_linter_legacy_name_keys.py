# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The legacy-name check reads every section key, and says what a scan does.

Why this file exists
--------------------
``_check_legacy_name_variants`` tested each key of ``scanners``, ``reporters``
and ``converters`` with ``"-" in key``. YAML reads an unquoted ``on:``,
``true:`` or ``1:`` as a bool or a number, and the ``in`` test raised a
``TypeError`` that ended the whole lint run.

Its LEGACY_NAME_CONFLICT message told the operator that a scan ignores the
legacy-spelled section when the canonical one is also set. The segments'
before-validator merges the two key by key, the canonical form winning where
both set the same key, so a key only the legacy section sets still applies.
The message now says so.
"""

import pytest

from automated_security_helper.config.config_linter import ConfigLinter, LintCategory

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("section", ["scanners", "reporters", "converters"])
@pytest.mark.parametrize("key", ["on", "true", "1"])
def test_a_non_string_section_key_does_not_end_the_lint_run(tmp_path, key, section):
    """Red at the base: ``TypeError: argument of type 'bool' is not iterable``,
    from the ``"-" in key`` test over each of the three sections' keys. The
    lint runs to its end and reports no legacy-name issue for a key that is
    not a name at all."""
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(
        f"project_name: demo\n{section}:\n  {key}:\n    enabled: false\n",
        encoding="utf-8",
    )

    result = ConfigLinter.lint(config_path)

    legacy = [
        i
        for i in result.issues
        if i.category
        in (LintCategory.LEGACY_NAME_CONFLICT, LintCategory.LEGACY_NAME_VARIANT)
    ]
    assert legacy == [], result.issues


def test_the_conflict_message_says_the_two_sections_are_merged(tmp_path):
    """Red at the base: the message said a scan ignores the legacy section."""
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(
        "project_name: demo\n"
        "scanners:\n"
        "  cdk_nag:\n"
        "    enabled: false\n"
        "  cdk-nag:\n"
        "    options:\n"
        "      nag_packs:\n"
        "        AwsSolutionsChecks: true\n",
        encoding="utf-8",
    )

    result = ConfigLinter.lint(config_path)

    conflicts = [
        i for i in result.issues if i.category == LintCategory.LEGACY_NAME_CONFLICT
    ]
    assert len(conflicts) == 1, result.issues
    message = conflicts[0].message
    assert "merges them key by key" in message
    assert "'cdk-nag' wins" in message
    assert "ignores" not in message
