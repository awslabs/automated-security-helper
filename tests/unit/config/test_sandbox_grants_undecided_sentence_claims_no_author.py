# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sentence for a file whose name walk ended early does not say who wrote it.

``membership_clause`` says that whether such a file is the repository's could not
be decided and that it is read as the repository's. The tail
``confinement_membership`` adds must not then state, as found, that the repository
wrote it: nothing was found. A located file keeps the plain statement.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.sandbox_grants import confinement_membership

pytestmark = pytest.mark.unit

_STATED_AS_FOUND = "wrote it"
_HEDGED = "may have written it"


@pytest.mark.parametrize(
    "flags",
    [
        {},
        {"mixed": True},
        {"outside": True},
        {"given_root": True},
        {"mixed": True, "given_root": True},
    ],
    ids=["undecided", "mixed", "outside", "given-root", "mixed-given-root"],
)
def test_an_undecided_sentence_hedges_who_wrote_the_file(flags):
    sentence = confinement_membership(
        checkout_membership=False, undecided=True, **flags
    )

    assert sentence.endswith(_HEDGED), sentence
    assert _STATED_AS_FOUND not in sentence, sentence


def test_a_client_supplied_file_keeps_its_own_tail():
    sentence = confinement_membership(
        checkout_membership=False, client_supplied=True, undecided=True
    )

    assert sentence.endswith("so that content wrote it"), sentence


@pytest.mark.parametrize(
    "flags, tail",
    [
        ({}, "so the repository being scanned wrote it"),
        ({"checkout_membership": True}, "so that repository wrote it"),
        ({"given_root": True}, "so that repository wrote it"),
        ({"outside": True}, "so someone other than the operator may have written it"),
    ],
    ids=["scanned-tree", "checkout", "given-root", "outside"],
)
def test_a_located_file_keeps_the_plain_statement(flags, tail):
    flags = {"checkout_membership": False, **flags}

    sentence = confinement_membership(**flags)

    assert sentence.endswith(tail), sentence
