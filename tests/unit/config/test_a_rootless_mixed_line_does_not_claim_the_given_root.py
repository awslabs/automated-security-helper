# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The mixed membership sentence is root-aware where it is built.

``membership_clause`` used to word every mixed line as "inside the given
root's trees", whatever ``given_root`` said. A load without known trees has
no root claim to make, so a caller passing ``mixed=True, given_root=False``
got a root claim the load does not have. The rule lives in the sentence
builder: with known trees the mixed head speaks the given root's trees;
without them it speaks the host's mark and the checkout reading, the only
memberships such a load can state.
"""

import logging
from pathlib import Path

import pytest

from automated_security_helper.config.sandbox_grants import (
    confinement_membership,
    membership_clause,
)

pytestmark = pytest.mark.unit

#: The mixed head of a load without known trees: both halves carry the
#: checkout reading (a host mark is a checkout verdict), and no half claims
#: a tree the load declared it does not have.
_ROOTLESS_MIXED_HEAD = (
    "each file is the repository's -- by the host's mark (a checkout "
    "verdict), or in a checkout, which with no working directory is "
    "read as the scanned tree --"
)


def test_a_direct_callers_rootless_mixed_shape_names_no_given_root(caplog):
    """A direct caller holding a host-marked file and a checkout-added file
    on a rootless load states checkout=True, mixed=True, given_root=False.
    No resolve_config load states this set -- the rootless reading forces
    the mixed flag off, and the undecided override reaches the
    mixed-undecided arm, which names no tree -- so the shape is a direct
    caller's alone. Neither confiner may build a sentence that names a
    given root for it: the load has none."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.plugin_module_trust import (
        confine_plugin_modules,
    )
    from automated_security_helper.config.sandbox_grants import (
        confine_sandbox_grants,
    )

    files = [Path("/zz-marked/cfg.yaml"), Path("/zz-elsewhere/base.yaml")]
    resolved = AshConfig()
    resolved.ash_plugin_modules = ["zz_rootless_mixed_mod"]
    resolved.sandbox.extra_read_paths = ["/zz-rootless-mixed-read"]
    with caplog.at_level(logging.WARNING):
        confine_sandbox_grants(
            resolved.sandbox,
            AshConfig().sandbox,
            files,
            frozenset(),
            checkout_membership=True,
            mixed_membership=True,
            given_root_membership=False,
            undecided_membership=False,
        )
        confine_plugin_modules(
            resolved,
            AshConfig(),
            [],
            None,
            files,
            frozenset(),
            no_scanned_tree=True,
            checkout_membership=True,
            mixed_membership=True,
            given_root_membership=False,
            undecided_membership=False,
        )
    sandbox_lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring sandbox.")
    ]
    module_lines = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring ash_plugin_modules")
    ]
    assert sandbox_lines and module_lines, caplog.text
    for line in sandbox_lines:
        assert "inside the given root's trees" not in line, line
        assert "each file is the repository's" in line, line
    expected_module = (
        f"{_ROOTLESS_MIXED_HEAD} "
        "so only installed modules outside every checkout are imported from it"
    )
    for line in module_lines:
        assert "inside the given root's trees" not in line, line
        assert expected_module in line, line


def test_a_rootless_mixed_head_does_not_claim_the_given_root():
    head = membership_clause(checkout_membership=True, mixed=True, given_root=False)
    assert head == _ROOTLESS_MIXED_HEAD, head


def test_a_rootless_mixed_confinement_sentence_does_not_claim_the_given_root():
    sentence = confinement_membership(checkout_membership=True, mixed=True)
    assert sentence == (f"{_ROOTLESS_MIXED_HEAD} so that repository wrote it"), sentence


def test_the_rootless_mixed_head_does_not_depend_on_the_checkout_flag():
    """The mixed arm words the whole line; which files are checkout-added is
    already said by the mixed split itself, so the checkout flag changes
    nothing. Pinned here because the byte-compatibility cell for decided
    sentences no longer carries the mixed one (it changed when the head
    became root-aware; this file holds its full-text pin)."""
    assert confinement_membership(
        checkout_membership=False, mixed=True
    ) == confinement_membership(checkout_membership=True, mixed=True)


@pytest.mark.parametrize("checkout_membership", [True, False])
def test_a_rooted_mixed_head_keeps_the_given_root_wording(checkout_membership):
    head = membership_clause(
        checkout_membership=checkout_membership, mixed=True, given_root=True
    )
    assert head == (
        "each file is the repository's -- inside the given root's trees, "
        "or in a checkout, which with no scanned tree is read as the "
        "repository's --"
    )
