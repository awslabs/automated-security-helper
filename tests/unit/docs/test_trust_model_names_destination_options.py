# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The trust-model page says reporters declare their destination options.

The page once said that a third-party reporter's destination options are not known to
ASH. A reporter declares them in the ``destination_options`` class attribute of the
reporter base class, and the trust layer reads that declaration, so the page has to name
it. This reads the page text only and imports nothing from the product.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
TRUST_MODEL = REPO_ROOT / "docs" / "content" / "concepts" / "trust-model.md"

STALE_CLAIM = "destination options are not known to ASH"


def _page() -> str:
    return TRUST_MODEL.read_text(encoding="utf-8")


def test_trust_model_does_not_say_destination_options_are_unknown() -> None:
    assert STALE_CLAIM not in _page(), (
        f"{TRUST_MODEL.name} says {STALE_CLAIM!r}, but a reporter declares its "
        "destination options with ``destination_options`` and ASH reads them"
    )


def test_trust_model_names_destination_options() -> None:
    assert "destination_options" in _page(), (
        f"{TRUST_MODEL.name} does not name ``destination_options``, the class "
        "attribute through which a reporter declares its destination options"
    )
