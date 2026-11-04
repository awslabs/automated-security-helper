# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``expires`` is the canonical spelling; ``expiration`` is a deprecated alias.

The key users reach for on their own (``expires: "2026-12-31"``) is the field:
it is what the entry models write, store and document. ``expiration``, the
field's earlier name, is still accepted when a config or a stored results file
is read, with a ``DeprecationWarning`` for a config; the alias is removed in
ASH v4. Every expiration validator runs on the aliased value too.
"""

import warnings

import pytest
from pydantic import ValidationError

from automated_security_helper.models.core import (
    AshSuppression,
    EXPIRATION_RULE,
    EXPIRATION_SPELLING_DEPRECATION,
    IgnorePathWithReason,
)
from automated_security_helper.utils.unknown_keys import known_keys

pytestmark = pytest.mark.unit


class TestExpiresCanonical:
    def test_expires_parses_as_the_field(self):
        suppression = AshSuppression.model_validate(
            {
                "rule_id": "RULE-1",
                "path": "src/app.py",
                "reason": "test",
                "expires": "2099-12-31",
            }
        )
        assert suppression.expires == "2099-12-31"

    def test_expiration_spelling_still_parses_with_a_deprecation(self):
        with pytest.warns(DeprecationWarning, match="removed in ASH v4"):
            suppression = AshSuppression.model_validate(
                {
                    "rule_id": "RULE-1",
                    "path": "src/app.py",
                    "reason": "test",
                    "expiration": "2099-12-31",
                }
            )
        assert suppression.expires == "2099-12-31"

    def test_the_canonical_spelling_warns_nothing(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            AshSuppression.model_validate(
                {
                    "rule_id": "RULE-1",
                    "path": "src/app.py",
                    "reason": "test",
                    "expires": "2099-12-31",
                }
            )
        assert [
            w for w in caught if str(w.message) == EXPIRATION_SPELLING_DEPRECATION
        ] == []

    def test_a_stored_results_file_is_not_warned_about(self):
        # A results file written before the swap stores "expiration" itself;
        # the deprecation addresses config authors, not old machine-written
        # files, which the stored-config tolerance reads.
        from automated_security_helper.utils.unknown_keys import (
            TOLERATE_STORED_CONFIG,
        )

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            entry = AshSuppression.model_validate(
                {
                    "rule_id": "RULE-1",
                    "path": "src/app.py",
                    "reason": "test",
                    "expiration": "2099-12-31",
                },
                context={TOLERATE_STORED_CONFIG: []},
            )
        assert entry.expires == "2099-12-31"
        assert [
            w for w in caught if str(w.message) == EXPIRATION_SPELLING_DEPRECATION
        ] == []

    def test_the_deprecated_attribute_name_still_reads(self):
        # Code written against ``entry.expiration`` (a plugin, a script) keeps
        # working until v4; the property mirrors the field.
        suppression = AshSuppression.model_validate(
            {
                "rule_id": "RULE-1",
                "path": "src/app.py",
                "reason": "test",
                "expires": "2099-12-31",
            }
        )
        assert suppression.expiration == "2099-12-31"

    def test_expiration_on_an_ignore_path(self):
        with pytest.warns(DeprecationWarning):
            entry = IgnorePathWithReason.model_validate(
                {"path": "build/", "reason": "generated", "expiration": "2099-01-01"}
            )
        assert entry.expires == "2099-01-01"

    def test_date_format_validator_fires_on_the_alias(self):
        with pytest.warns(DeprecationWarning):
            with pytest.raises(ValidationError) as excinfo:
                AshSuppression.model_validate(
                    {
                        "rule_id": "RULE-1",
                        "path": "src/app.py",
                        "reason": "test",
                        "expiration": "not-a-date",
                    }
                )
        assert EXPIRATION_RULE in str(excinfo.value)

    def test_unquoted_date_refusal_fires_on_the_alias(self):
        from datetime import date

        with pytest.warns(DeprecationWarning):
            with pytest.raises(ValidationError) as excinfo:
                AshSuppression.model_validate(
                    {
                        "rule_id": "RULE-1",
                        "path": "src/app.py",
                        "reason": "test",
                        "expiration": date(2099, 1, 31),
                    }
                )
        assert "quoted YYYY-MM-DD string" in str(excinfo.value)

    def test_serialization_says_expires(self):
        with pytest.warns(DeprecationWarning):
            suppression = AshSuppression.model_validate(
                {
                    "rule_id": "RULE-1",
                    "path": "src/app.py",
                    "reason": "test",
                    "expiration": "2099-12-31",
                }
            )
        dumped = suppression.model_dump()
        assert dumped["expires"] == "2099-12-31"
        assert "expiration" not in dumped

    def test_known_keys_lists_both_spellings(self):
        keys = known_keys(AshSuppression)
        assert "expires" in keys
        assert "expiration" in keys

    def test_both_spellings_disagreeing_are_refused(self):
        with pytest.warns(DeprecationWarning):
            with pytest.raises(ValidationError) as excinfo:
                AshSuppression.model_validate(
                    {
                        "rule_id": "RULE-1",
                        "path": "src/app.py",
                        "reason": "test",
                        "expires": "2099-12-31",
                        "expiration": "2026-01-01",
                    }
                )
        assert "two spellings of one field" in str(excinfo.value)

    def test_an_equal_duplicate_is_accepted_and_stays_applicable(self):
        with pytest.warns(DeprecationWarning):
            entry = AshSuppression.model_validate(
                {
                    "rule_id": "RULE-1",
                    "path": "src/app.py",
                    "reason": "test",
                    "expires": "2099-12-31",
                    "expiration": "2099-12-31",
                }
            )
        assert entry.expires == "2099-12-31"
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
                "expires": "2099-12-31",
                "expiration": "2026-01-01",
            },
            context={TOLERATE_STORED_CONFIG: notes},
        )
        assert BOTH_EXPIRATION_SPELLINGS_NOTE in notes
        assert entry.has_unknown_keys  # the unconsumed alias marks it inert

    def test_expiration_is_not_refused_as_unknown(self):
        # The refusal path must not fire for the alias: a key refusal would
        # name it as "Unknown key 'expiration'".
        with pytest.warns(DeprecationWarning):
            entry = AshSuppression.model_validate(
                {
                    "rule_id": "RULE-1",
                    "path": "src/app.py",
                    "reason": "test",
                    "expiration": "2099-12-31",
                }
            )
        assert not entry.has_unknown_keys


class TestExpirationInTheSchema:
    """The published schema admits what the loader admits.

    The entry models pin ``additionalProperties: false``, so without an
    ``expiration`` property a schema-validating editor, a CI check against the
    published AshConfig.json, or an MCP client reading the served suppression
    schema would flag the deprecated alias as invalid while ASH still loads it
    (``_entry_schema_admits_expiration`` in models/core.py).
    """

    @pytest.mark.parametrize("model", [AshSuppression, IgnorePathWithReason])
    def test_the_schema_publishes_the_alias(self, model):
        schema = model.model_json_schema()
        properties = schema["properties"]
        assert "expiration" in properties
        # The alias mirrors the field's value shape, so a config valid under
        # one spelling is valid under the other.
        assert properties["expiration"]["anyOf"] == properties["expires"]["anyOf"]
        description = properties["expiration"]["description"].lower()
        assert "deprecated alias of 'expires'" in description
        assert "removed in ash v4" in description
        # The entry schema stays closed: the alias is a declared property,
        # not a loosened schema.
        assert schema["additionalProperties"] is False
