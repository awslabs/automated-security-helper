# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH 4.0 removed the ``expiration`` spelling of ``expires`` from configs.

``expires`` is the one spelling a config accepts. A config entry that writes
``expiration`` is refused as an unknown key, with ``expires`` as the
did-you-mean; with ``fail_on_unknown_keys: false`` (the warn mode) the entry
loads with a warning and applies to nothing. ASH versions before the rename
wrote ``expiration`` into results files themselves, so a stored results entry
(read under ``TOLERATE_STORED_CONFIG``) still reads it as ``expires``.
"""

import warnings
from datetime import date

import pytest
from pydantic import ValidationError

from automated_security_helper.models.core import (
    BOTH_EXPIRATION_SPELLINGS_NOTE,
    AshSuppression,
    IgnorePathWithReason,
)
from automated_security_helper.utils.unknown_keys import (
    TOLERATE_STORED_CONFIG,
    WARN_UNKNOWN_KEYS,
    known_keys,
)

pytestmark = pytest.mark.unit

SUPPRESSION = {"rule_id": "RULE-1", "path": "src/app.py", "reason": "test"}
IGNORE_PATH = {"path": "build/", "reason": "generated"}


class TestExpiresIsTheOnlyConfigSpelling:
    def test_expires_parses_as_the_field(self):
        suppression = AshSuppression.model_validate(
            {**SUPPRESSION, "expires": "2099-12-31"}
        )
        assert suppression.expires == "2099-12-31"
        assert not suppression.has_unknown_keys

    @pytest.mark.parametrize(
        ("model", "base", "kind"),
        [
            (AshSuppression, SUPPRESSION, "a suppression"),
            (IgnorePathWithReason, IGNORE_PATH, "an ignore path"),
        ],
    )
    def test_a_config_entry_with_expiration_is_refused_with_a_did_you_mean(
        self, model, base, kind
    ):
        # Fails at the base: the alias was accepted there, with a
        # DeprecationWarning, so no ValidationError was raised.
        with pytest.raises(ValidationError) as excinfo:
            model.model_validate({**base, "expiration": "2099-12-31"})
        message = str(excinfo.value)
        assert "Unknown key 'expiration'" in message
        assert "did you mean 'expires'?" in message
        assert kind in message

    def test_the_refusal_does_not_echo_the_value(self):
        with pytest.raises(ValidationError) as excinfo:
            AshSuppression.model_validate({**SUPPRESSION, "expiration": "CANARY-7"})
        assert "CANARY-7" not in str(excinfo.value)

    def test_the_accepted_keys_listing_leaves_expiration_out(self):
        with pytest.raises(ValidationError) as excinfo:
            AshSuppression.model_validate({**SUPPRESSION, "expiration": "2099-12-31"})
        accepted = str(excinfo.value).split("Accepted keys:", 1)[1]
        assert "expires" in accepted
        assert "expiration" not in accepted

    def test_no_deprecation_warning_is_raised_either_way(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            AshSuppression.model_validate({**SUPPRESSION, "expires": "2099-12-31"})
            with pytest.raises(ValidationError):
                AshSuppression.model_validate(
                    {**SUPPRESSION, "expiration": "2099-12-31"}
                )
        assert [w for w in caught if issubclass(w.category, DeprecationWarning)] == []

    def test_an_unquoted_expires_date_is_still_refused_with_what_to_write(self):
        with pytest.raises(ValidationError) as excinfo:
            AshSuppression.model_validate({**SUPPRESSION, "expires": date(2099, 1, 31)})
        assert "quoted YYYY-MM-DD string" in str(excinfo.value)

    def test_both_spellings_in_a_config_are_refused_as_an_unknown_key(self):
        with pytest.raises(ValidationError) as excinfo:
            AshSuppression.model_validate(
                {**SUPPRESSION, "expires": "2099-12-31", "expiration": "2026-01-01"}
            )
        assert "Unknown key 'expiration'" in str(excinfo.value)

    def test_the_attribute_is_gone(self):
        # Fails at the base: ``entry.expiration`` mirrored ``expires``.
        suppression = AshSuppression.model_validate(
            {**SUPPRESSION, "expires": "2099-12-31"}
        )
        with pytest.raises(AttributeError):
            suppression.expiration  # noqa: B018

    def test_serialization_says_expires(self):
        dumped = AshSuppression.model_validate(
            {**SUPPRESSION, "expires": "2099-12-31"}
        ).model_dump()
        assert dumped["expires"] == "2099-12-31"
        assert "expiration" not in dumped


class TestWarnModeKeepsTheEntryInert:
    """``fail_on_unknown_keys: false`` binds the warn list in the context."""

    def test_the_entry_warns_and_is_inert(self):
        warned: list = []
        entry = AshSuppression.model_validate(
            {**SUPPRESSION, "expiration": "2099-12-31"},
            context={WARN_UNKNOWN_KEYS: warned},
        )
        assert len(warned) == 1
        assert "Unknown key 'expiration'" in warned[0]
        assert "did you mean 'expires'?" in warned[0]
        assert entry.has_unknown_keys
        assert entry.expires is None


class TestStoredResultsStillReadExpiration:
    """A results file an earlier ASH wrote, read under TOLERATE_STORED_CONFIG."""

    def test_a_stored_entry_with_expiration_reads_as_expires_without_a_warning(self):
        notes: list = []
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            entry = AshSuppression.model_validate(
                {**SUPPRESSION, "expiration": "2099-12-31"},
                context={TOLERATE_STORED_CONFIG: notes},
            )
        assert entry.expires == "2099-12-31"
        assert not entry.has_unknown_keys
        assert notes == []
        assert [w for w in caught if issubclass(w.category, DeprecationWarning)] == []

    def test_a_stored_ignore_path_with_expiration_reads_as_expires(self):
        entry = IgnorePathWithReason.model_validate(
            {**IGNORE_PATH, "expiration": "2099-01-01"},
            context={TOLERATE_STORED_CONFIG: []},
        )
        assert entry.expires == "2099-01-01"

    def test_an_equal_duplicate_is_applicable(self):
        notes: list = []
        entry = AshSuppression.model_validate(
            {**SUPPRESSION, "expires": "2099-12-31", "expiration": "2099-12-31"},
            context={TOLERATE_STORED_CONFIG: notes},
        )
        assert entry.expires == "2099-12-31"
        # The duplicate must not survive as an extra: that would make the
        # entry inert.
        assert not entry.has_unknown_keys
        assert notes == []

    def test_a_disagreement_is_noted_and_inert(self):
        notes: list = []
        entry = AshSuppression.model_validate(
            {**SUPPRESSION, "expires": "2099-12-31", "expiration": "2026-01-01"},
            context={TOLERATE_STORED_CONFIG: notes},
        )
        assert BOTH_EXPIRATION_SPELLINGS_NOTE in notes
        assert entry.has_unknown_keys  # the leftover extra marks it inert
        assert entry.expires == "2099-12-31"

    def test_a_stored_date_that_is_not_a_date_is_kept_and_noted_via_expires(self):
        notes: list = []
        entry = AshSuppression.model_validate(
            {**SUPPRESSION, "expiration": "TBD"},
            context={TOLERATE_STORED_CONFIG: notes},
        )
        assert entry.expires == "TBD"
        assert entry.is_expired


class TestTheSchemaPublishesNoExpiration:
    @pytest.mark.parametrize("model", [AshSuppression, IgnorePathWithReason])
    def test_the_schema_has_expires_and_no_expiration_and_stays_closed(self, model):
        schema = model.model_json_schema()
        properties = schema["properties"]
        assert "expires" in properties
        # Fails at the base: the schema published ``expiration`` as an alias.
        assert "expiration" not in properties
        assert schema["additionalProperties"] is False
        assert "alias" not in properties["expires"]["description"].lower()

    @pytest.mark.parametrize("model", [AshSuppression, IgnorePathWithReason])
    def test_known_keys_no_longer_lists_expiration(self, model):
        keys = known_keys(model)
        assert "expires" in keys
        # Fails at the base: the AliasChoices put both names in the set.
        assert "expiration" not in keys
