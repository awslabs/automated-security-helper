# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Config paths that reach an operator's file through a link inside a checkout.

A local scan counts a config file as repository-written when a symlink its path
follows sits inside a git checkout, the scanned one or another, even though neither
the path the operator gave nor the file it resolves to is in one
(``config/sandbox_grants.links_followed``): whoever wrote the link chose the file.
Container mode marks such a config with ``--config-from-scanned-repository`` in
the Python launcher, ``./ash`` and ``Invoke-ASH``; the tests of each use these
layouts so the three are held to the same cases.
"""

from __future__ import annotations

from pathlib import Path

#: Layouts where the config is named outside every checkout, resolves to a file
#: outside every checkout, and goes through a link inside one on the way.
LINKED_LAYOUTS = [
    "file-link-in-the-scanned-checkout",
    "directory-link-in-the-scanned-checkout",
    "file-link-in-another-checkout",
    "named-as-a-link-in-another-checkout",
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
        (tmp_path / "other" / ".git").mkdir(parents=True)
        (tmp_path / "other" / "link.yaml").symlink_to(
            Path("..", "operator", "ash.yaml")
        )
        named.symlink_to(Path("..", "other", "link.yaml"))
    elif layout == "named-as-a-link-in-another-checkout":
        (tmp_path / "other" / ".git").mkdir(parents=True)
        named = tmp_path / "other" / "cfg.yaml"
        named.symlink_to(real)
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
