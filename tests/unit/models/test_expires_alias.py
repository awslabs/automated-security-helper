# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``expires`` is a validation alias of ``expiration`` on suppression entries.

The key users reach for on their own (``expires: "2026-12-31"``) was refused as
an unknown key, with ``expiration`` offered as the did-you-mean. The entry is
now read with either spelling; it is still written and stored as ``expiration``,
so results files do not churn, and every expiration validator runs on the
aliased value too.
"""

import pytest
from pydantic import ValidationError

from automated_security_helper.models.core import (
    AshSuppression,
    EXPIRATION_RULE,
    IgnorePathWithReason,
)
from automated_security_helper.utils.unknown_keys import known_keys

pytestmark = pytest.mark.unit


class TestExpiresAlias:
    def test_expires_parses_as_expiration(self):
        suppression = AshSuppression.model_validate(
            {
                "rule_id": "RULE-1",
                "path": "src/app.py",
                "reason": "test",
                "expires": "2099-12-31",
            }
        )
        assert suppression.expiration == "2099-12-31"

    def test_expiration_spelling_still_parses(self):
        suppression = AshSuppression.model_validate(
            {
                "rule_id": "RULE-1",
                "path": "src/app.py",
                "reason": "test",
                "expiration": "2099-12-31",
            }
        )
        assert suppression.expiration == "2099-12-31"

    def test_expires_on_an_ignore_path(self):
        entry = IgnorePathWithReason.model_validate(
            {"path": "build/", "reason": "generated", "expires": "2099-01-01"}
        )
        assert entry.expiration == "2099-01-01"

    def test_date_format_validator_fires_on_the_alias(self):
        with pytest.raises(ValidationError) as excinfo:
            AshSuppression.model_validate(
                {
                    "rule_id": "RULE-1",
                    "path": "src/app.py",
                    "reason": "test",
                    "expires": "not-a-date",
                }
            )
        assert EXPIRATION_RULE in str(excinfo.value)

    def test_unquoted_date_refusal_fires_on_the_alias(self):
        from datetime import date

        with pytest.raises(ValidationError) as excinfo:
            AshSuppression.model_validate(
                {
                    "rule_id": "RULE-1",
                    "path": "src/app.py",
                    "reason": "test",
                    "expires": date(2099, 1, 31),
                }
            )
        assert "quoted YYYY-MM-DD string" in str(excinfo.value)

    def test_serialization_still_says_expiration(self):
        suppression = AshSuppression.model_validate(
            {
                "rule_id": "RULE-1",
                "path": "src/app.py",
                "reason": "test",
                "expires": "2099-12-31",
            }
        )
        dumped = suppression.model_dump()
        assert dumped["expiration"] == "2099-12-31"
        assert "expires" not in dumped

    def test_known_keys_lists_both_spellings(self):
        keys = known_keys(AshSuppression)
        assert "expiration" in keys
        assert "expires" in keys

    def test_both_spellings_disagreeing_are_refused(self):
        with pytest.raises(ValidationError) as excinfo:
            AshSuppression.model_validate(
                {
                    "rule_id": "RULE-1",
                    "path": "src/app.py",
                    "reason": "test",
                    "expiration": "2099-12-31",
                    "expires": "2026-01-01",
                }
            )
        assert "two spellings of one field" in str(excinfo.value)

    def test_an_equal_duplicate_is_accepted_and_stays_applicable(self):
        entry = AshSuppression.model_validate(
            {
                "rule_id": "RULE-1",
                "path": "src/app.py",
                "reason": "test",
                "expiration": "2099-12-31",
                "expires": "2099-12-31",
            }
        )
        assert entry.expiration == "2099-12-31"
        # The alias must not survive as an extra, which would silently make
        # the entry inert.
        assert not entry.has_unknown_keys

    def test_a_tolerated_disagreement_is_kept_but_inert(self):
        from automated_security_helper.models.core import (
            BOTH_EXPIRATION_SPELLINGS_NOTE,
        )
        from automated_security_helper.utils.unknown_keys import (
            TOLERATE_STORED_CONFIG,
        )

        notes: list = []
        entry = AshSuppression.model_validate(
            {
                "rule_id": "RULE-1",
                "path": "src/app.py",
                "reason": "test",
                "expiration": "2099-12-31",
                "expires": "2026-01-01",
            },
            context={TOLERATE_STORED_CONFIG: notes},
        )
        assert BOTH_EXPIRATION_SPELLINGS_NOTE in notes
        assert entry.has_unknown_keys  # the unconsumed alias marks it inert

    def test_expires_is_not_refused_as_unknown(self):
        # The refusal path must not fire for the alias: a key refusal would
        # name it as "Unknown key 'expires'".
        entry = AshSuppression.model_validate(
            {
                "rule_id": "RULE-1",
                "path": "src/app.py",
                "reason": "test",
                "expires": "2099-12-31",
            }
        )
        assert not entry.has_unknown_keys
