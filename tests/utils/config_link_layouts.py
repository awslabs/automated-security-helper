# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Config paths that reach an operator's file through a link inside a checkout.

A local scan counts a config file as repository-written when a symlink its path
follows sits inside the scanned checkout, even though neither the path the
operator gave nor the file it resolves to is in it: the scanned repository chose
where the name leads (``sandbox_grants.files_inside`` judges the links a name
follows against the scanned trees). Container mode marks such a config with
``--config-from-scanned-repository``, so the scan inside the container reaches
the same verdict. A link in some other checkout does not make the config the
scanned repository's, as it does not on the host: ``resolve_config`` widens the
judgment to any checkout only for a load with no scanned tree. The tests of the
handoff use these layouts so every route is held to the same cases.
"""

from __future__ import annotations

from pathlib import Path

from tests.utils.helpers import mark_git_checkout

#: Layouts where the config is named outside every checkout, resolves to a file
#: outside every checkout, and goes through a link inside the SCANNED checkout
#: on the way: repository-written, so container mode marks it.
LINKS_IN_THE_SCANNED_CHECKOUT = [
    "file-link-in-the-scanned-checkout",
    "directory-link-in-the-scanned-checkout",
]

#: The same shape with the link in ANOTHER checkout: the operator's for the
#: scan, so no mark.
LINKS_IN_ANOTHER_CHECKOUT = [
    "file-link-in-another-checkout",
    "named-as-a-link-in-another-checkout",
]

LINKED_LAYOUTS = [*LINKS_IN_THE_SCANNED_CHECKOUT, *LINKS_IN_ANOTHER_CHECKOUT]

#: Layouts where the scanned checkout steers the name itself: a ``..`` after a
#: link that sits in the checkout lands where the link's target decides, and a
#: directory alias onto a real checkout directory puts the name in the tree
#: before a tree file link leads out of it. The name is the scanned tree's and
#: the file resolves outside it, so every entrypoint refuses it.
NAMES_STEERED_BY_THE_SCANNED_CHECKOUT = [
    "dotdot-after-a-link-in-the-scanned-checkout",
    "directory-alias-onto-a-real-checkout-directory",
]

#: The control: every link on the way is outside every checkout.
LINKS_OUTSIDE_EVERY_CHECKOUT = "links-outside-every-checkout"


def config_through_links(layout: str, checkout: Path, tmp_path: Path) -> Path:
    """The config path for one layout, under *tmp_path*.

    The path is ``tmp_path/ops/cfg.yaml``, a link, unless the layout names the
    config elsewhere, and every chain ends at the plain file
    ``tmp_path/operator/ash.yaml``, outside every checkout. *checkout* is the
    scanned checkout, with a ``ci`` directory outside the scanned directory.
    """
    operator = tmp_path / "operator"
    operator.mkdir(exist_ok=True)
    real = operator / "ash.yaml"
    real.write_text("project_name: p\n", encoding="utf-8")
    ops = tmp_path / "ops"
    ops.mkdir()
    named = ops / "cfg.yaml"
    if layout == "file-link-in-the-scanned-checkout":
        (checkout / "ci" / "link.yaml").symlink_to(real)
        named.symlink_to(checkout / "ci" / "link.yaml")
    elif layout == "directory-link-in-the-scanned-checkout":
        (checkout / "ci" / "conf").symlink_to(operator, target_is_directory=True)
        named.symlink_to(checkout / "ci" / "conf" / "ash.yaml")
    elif layout == "file-link-in-another-checkout":
        # Relative targets, each with a `..`, followed from the link's directory.
        mark_git_checkout(tmp_path / "other")
        (tmp_path / "other" / "link.yaml").symlink_to(
            Path("..", "operator", "ash.yaml")
        )
        named.symlink_to(Path("..", "other", "link.yaml"))
    elif layout == "named-as-a-link-in-another-checkout":
        mark_git_checkout(tmp_path / "other")
        named = tmp_path / "other" / "cfg.yaml"
        named.symlink_to(real)
    elif layout == "dotdot-after-a-link-in-the-scanned-checkout":
        # The link leads to a directory outside every checkout, one level below
        # the operator's file; the kernel resolves `..` out of that directory.
        (operator / "deep").mkdir()
        (checkout / "ci" / "jump").symlink_to(
            operator / "deep", target_is_directory=True
        )
        named = Path(f"{checkout}/ci/jump/../ash.yaml")
    elif layout == "directory-alias-onto-a-real-checkout-directory":
        (ops / "dir").symlink_to(checkout / "ci", target_is_directory=True)
        (checkout / "ci" / "cfg.yaml").symlink_to(real)
        named = ops / "dir" / "cfg.yaml"
    elif layout == LINKS_OUTSIDE_EVERY_CHECKOUT:
        (tmp_path / "plain").mkdir()
        (tmp_path / "plain" / "link.yaml").symlink_to(real)
        named.symlink_to(tmp_path / "plain" / "link.yaml")
    else:
        raise AssertionError(layout)
    return named


def config_through_a_link_in(scanned: Path, tmp_path: Path) -> Path:
    """``tmp_path/ops/cfg.yaml``, a link to ``scanned/.ash/link.yaml``, a link to
    the plain file ``tmp_path/operator/ash.yaml``.

    For a scanned directory outside every checkout, which is then the scanned tree
    itself: the link in it is the scanned repository's.
    """
    operator = tmp_path / "operator"
    operator.mkdir(exist_ok=True)
    real = operator / "ash.yaml"
    real.write_text("project_name: p\n", encoding="utf-8")
    (scanned / ".ash").mkdir(parents=True)
    (scanned / ".ash" / "link.yaml").symlink_to(real)
    (tmp_path / "ops").mkdir()
    named = tmp_path / "ops" / "cfg.yaml"
    named.symlink_to(scanned / ".ash" / "link.yaml")
    return named
