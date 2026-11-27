"""The places that skip a check keep the spellings they had for a renamed key.

``config_document_denials`` takes a write out of a check in three places: an
``inert`` pattern skips every check, an ``exempt`` one skips ``denied_paths``,
and a ``moved`` pointer lifts the section floor. A match there that read a
renamed key's other spelling would skip more than the caller named, so these
places match a pattern as written and with '-' read as '_', while the places
that find a denial also read the spelling table's rows.

These pin ``inert`` and ``exempt`` with the shipped row: a pattern written in
one spelling of a suppression's expiry does not take a ``patch`` op written in
the other spelling out of its check. They pass at the base and after. ``moved``
needs a row of its own, since no scanner exclusion option has a second spelling
today, and is pinned with the spelling table's tests.
"""

from typing import Any, Dict, List

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.client_config_policy import policy_of
from automated_security_helper.config.runtime_patch import (
    DocumentDenial,
    config_document_denials,
)

pytestmark = pytest.mark.unit

OLD_PATTERN = "/global_settings/suppressions/*/expiration"
CANONICAL_PATTERN = "/global_settings/suppressions/*/expires"
OLD_LEAF = "/global_settings/suppressions/0/expiration"
CANONICAL_LEAF = "/global_settings/suppressions/0/expires"

#: (the skipping pattern, the denial, the op's pointer): the skipping pattern in
#: one spelling, the denial and the op in the other. A change that respells only
#: the skipping pattern turns the first red, one that respells only the op's
#: pointer the second, and one that respells both turns both red.
CROSSED = [
    pytest.param(
        OLD_PATTERN, CANONICAL_PATTERN, CANONICAL_LEAF, id="old-skip-canonical-write"
    ),
    pytest.param(
        CANONICAL_PATTERN, OLD_PATTERN, OLD_LEAF, id="canonical-skip-old-write"
    ),
]

#: A pattern and an op's pointer in the same spelling, either one.
ALIKE = [
    pytest.param(OLD_PATTERN, OLD_LEAF, id="old"),
    pytest.param(CANONICAL_PATTERN, CANONICAL_LEAF, id="canonical"),
]


def _trusted(denial: str) -> AshConfig:
    """A profile with one suppression whose one denial, replacing the
    defaults, is ``denial``."""
    return AshConfig.model_validate(
        {
            "project_name": "renamed-key-skips",
            "global_settings": {
                "suppressions": [
                    {
                        "rule_id": "B101",
                        "path": "src/app.py",
                        "reason": "reviewed",
                        "expires": "2099-01-01",
                    }
                ],
                "mcp": {
                    "runtime_overrides": {
                        "replace_default_denied_paths": True,
                        "denied_paths": [denial],
                    }
                },
            },
        }
    )


def _denials(denial: str, pointer: str, **skipping: Any) -> List[DocumentDenial]:
    """The denials of a delivered document whose one write is a ``patch`` op at
    ``pointer``, under ``denial`` and the skipping patterns given."""
    trusted = _trusted(denial)
    op: Dict[str, Any] = {"op": "replace", "path": pointer, "value": "2199-12-31"}
    return config_document_denials(
        {"patch": [op]}, allowlist=policy_of(trusted), config=trusted, **skipping
    )


@pytest.mark.parametrize("skipped,denial,pointer", CROSSED)
def test_an_inert_pattern_in_the_other_spelling_does_not_skip_the_check(
    skipped: str, denial: str, pointer: str
) -> None:
    """An ``inert`` pattern names fields that have no effect in the document,
    and a write at or under one is not checked at all. Written in the other
    spelling of the key the op writes, it names another place, and the denial
    still refuses the op.

    What turns this red: the inert check's ``_covered`` call matched with the
    table's spellings (``denying=True``, or that as the default), which reads
    the pattern in the op's spelling and skips the op as inert.
    """
    denials = _denials(denial, pointer, inert=(skipped,))

    assert [(d.pointer, d.from_patch) for d in denials] == [(pointer, True)]
    assert f"denied_paths entry {denial!r}" in denials[0].reason


@pytest.mark.parametrize("skipped,denial,pointer", CROSSED)
def test_an_exempt_pattern_in_the_other_spelling_does_not_lift_the_denial(
    skipped: str, denial: str, pointer: str
) -> None:
    """An ``exempt`` pattern takes a write out of the ``denied_paths`` check, as
    ``client_config_policy.exempt_paths`` does for the restrict-only and
    suppression fields. Written in the other spelling of the key the op writes,
    it exempts another place, and the denial still refuses the op.

    What turns this red: the exempt check's ``_covered`` call matched with the
    table's spellings, which exempts the op; with no value pattern, nothing
    then refuses it.
    """
    denials = _denials(denial, pointer, exempt=(skipped,))

    assert [(d.pointer, d.from_patch) for d in denials] == [(pointer, True)]
    assert f"denied_paths entry {denial!r}" in denials[0].reason


@pytest.mark.parametrize("skipping", ["inert", "exempt"])
@pytest.mark.parametrize("pattern,pointer", ALIKE)
def test_a_skipping_pattern_spelled_as_the_op_skips_it(
    pattern: str, pointer: str, skipping: str
) -> None:
    """The control, at the base too: spelled as the op, either pattern takes it
    out of the check, so the cases above are refused because the spellings
    differ, not because the pattern never applies."""
    assert _denials(pattern, pointer, **{skipping: (pattern,)}) == []
