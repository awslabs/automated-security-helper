# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""When ``config/operator_only_options.py`` reports an option as ignored.

A repository file's value for an operator-only option is reported as ignored
only when the scan uses something else:

* A scanner option is compared in the form its options model holds, so a quoted
  ``"256"`` equals the trusted base's 256.
* A reporter option the trusted base does not set is unset, which is the
  option's default: writing that default changes nothing.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.operator_only_options import (
    OPERATOR_ONLY_DEFAULTS,
    OPERATOR_ONLY_OPTIONS,
    RepositorySettings,
    ignored_operator_only_options,
)

pytestmark = pytest.mark.unit

SH = "aws-security-hub"
LIMIT_PLACE = "scanners.detect-secrets.options.max_worker_output_mib"
ARCHIVE_PLACE = f"reporters.{SH}.options.archive_resolved_findings"


def _repository(*entries) -> RepositorySettings:
    """Settings that hold what the repository's files wrote, as a scan records
    it: ``(kind, plugin, section key, option, value)`` for each option."""
    repository = RepositorySettings(trees=[])
    repository.found.extend(entries)
    return repository


def _limit(value):
    return _repository(
        ("scanners", "detect-secrets", "detect-secrets", "max_worker_output_mib", value)
    )


def _both_ways(repository: RepositorySettings, trusted: AshConfig):
    """The ignored places by the scan's settle step and by `ash config validate`."""
    return (
        ignored_operator_only_options(trusted, trusted, [], repository),
        repository.ignored_against(trusted),
    )


@pytest.mark.parametrize(
    "written, ignored",
    [
        ("256", False),
        (256, False),
        ("1024", True),
        (1024, True),
        ("not-a-number", True),
    ],
    ids=["quoted-equal", "int-equal", "quoted-other", "int-other", "refused"],
)
def test_a_scanner_value_is_compared_as_the_option_holds_it(written, ignored):
    """The trusted base holds the default limit, 256. The repository writes it
    as a number or as text: only a value other than 256 is ignored."""
    by_settle, by_validate = _both_ways(_limit(written), AshConfig())

    expected = [LIMIT_PLACE] if ignored else []
    assert by_settle == expected
    assert by_validate == expected


@pytest.mark.parametrize(
    "option, written, ignored",
    [
        ("archive_resolved_findings", False, False),
        ("archive_resolved_findings", True, True),
        ("findings_scope", None, False),
        ("findings_scope", "a-scope", True),
    ],
)
def test_a_reporter_default_written_beside_no_trusted_section_is_not_ignored(
    option, written, ignored
):
    """The trusted base has no aws-security-hub section, so the option is unset
    and the scan uses its default. A file that writes that default changes
    nothing; any other value is dropped."""
    repository = _repository(("reporters", SH, SH, option, written))

    by_settle, by_validate = _both_ways(repository, AshConfig())

    expected = [f"reporters.{SH}.options.{option}"] if ignored else []
    assert by_settle == expected
    assert by_validate == expected


@pytest.mark.parametrize(
    "written, ignored", [(False, True), (True, False)], ids=["differs", "equal"]
)
def test_a_reporter_value_is_compared_with_the_trusted_one(written, ignored):
    """The control: where the trusted base sets the option, its value decides,
    the default aside."""
    trusted = AshConfig.model_validate(
        {"reporters": {SH: {"options": {"archive_resolved_findings": True}}}}
    )
    repository = _repository(
        ("reporters", SH, SH, "archive_resolved_findings", written)
    )

    by_settle, by_validate = _both_ways(repository, trusted)

    expected = [ARCHIVE_PLACE] if ignored else []
    assert by_settle == expected
    assert by_validate == expected


def test_the_listed_defaults_are_the_reporters_own():
    """The defaults are listed here because the reporter's model is in a plugin
    package this module does not import; each must be the model's default."""
    from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
        SecurityHubReporterConfigOptions,
    )

    assert set(OPERATOR_ONLY_DEFAULTS) == {
        (reporter, option)
        for reporter, names in OPERATOR_ONLY_OPTIONS.items()
        for option in names
    }
    fields = SecurityHubReporterConfigOptions.model_fields
    for (reporter, option), default in OPERATOR_ONLY_DEFAULTS.items():
        assert reporter == SH
        assert fields[option].default == default, option
