# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How a confinement step names a config that is not the operator's, and the fix.

``resolve_config`` replaces what a config file inside the scanned tree, or one an
MCP client delivered, may not choose with the trusted base's values. The steps are
in ``sandbox_grants``, ``plugin_module_trust``, ``reporter_trust`` and
``tool_config_trust``, and ``resolve_config.confine_to_trusted_base`` runs them in
order. Each names what it ignored in one warning, which says why the config is not
the operator's and where the operator sets those values instead.

``ash merge`` runs the same steps on the config a shard recorded in its results.
That config is not a file in a tree, and the merge's operator sets the values with
``ash merge``'s own options, so each step takes an ``UntrustedSource`` carrying
both clauses: ``IN_TREE_OR_DELIVERED`` by default, ``SHARD_RECORDED`` for a merge.

``named_modules_only`` is the merge's rule for ``ash_plugin_modules``. Nothing the
merge imports is a shard's choice, so an entry the trusted base does not name is
dropped, where a scan keeps an installed module outside the tree.
"""

from dataclasses import dataclass
from typing import Optional

from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING


@dataclass(frozen=True)
class UntrustedSource:
    """Why a config is not the operator's, and where the operator sets what it may not.

    Attributes:
        reason: A clause saying why the config's values are not taken. It follows
            the files a warning names.
        remedy: The sentences that end a warning, saying how the operator keeps
            those values. For a file, ``confinement_remedy.KEEP_A_SETTING``, the
            text every confinement warning about a file ends with.
        modules_remedy: The same for ``ash_plugin_modules``.
        named_modules_only: Drop every ``ash_plugin_modules`` entry the trusted
            base does not name, rather than keeping an installed module outside
            the tree.
        scanner_steps_note: What the sandbox and scanner-config steps' warnings
            say in place of their remedy, where no scanner runs. None gives the
            remedy.
        fills_missing_sections: Give a reporter section the config leaves out the
            trusted base's destination options. A file inside the tree, or one an
            MCP client delivered, replaces the operator's config, so leaving a
            section out would drop the operator's values. ``ash merge``'s
            ``--config`` supplies values for what a shard recorded without adding
            to it (``cli/merge.py``), so the merge does not fill sections.
    """

    reason: str
    remedy: str
    modules_remedy: str
    named_modules_only: bool = False
    scanner_steps_note: Optional[str] = None
    fills_missing_sections: bool = True


#: A config file inside a git checkout or the scanned tree, or one an MCP client
#: delivered.
IN_TREE_OR_DELIVERED = UntrustedSource(
    reason=(
        "that config is inside a git checkout or the scanned tree, or was delivered "
        "by an MCP client"
    ),
    remedy=KEEP_A_SETTING,
    modules_remedy=f"{KEEP_A_SETTING} Or name the module with --ash-plugin-modules.",
)

#: The config a shard recorded in its results, as ``ash merge`` reads it.
SHARD_RECORDED = UntrustedSource(
    reason=(
        "that is the config a shard recorded in its results, which ash merge holds "
        "to the rules for a repository's config"
    ),
    remedy="To keep a setting, pass it with ash merge's --config-overrides or --config.",
    modules_remedy=(
        "To keep a module, pass it with ash merge's --config-overrides or --config."
    ),
    named_modules_only=True,
    scanner_steps_note=(
        "No scanner runs during a merge, so this changes only the merged results, "
        "which record the operator's value"
    ),
    fills_missing_sections=False,
)

#: A config file ``ash report`` reads (``--config``, ``ASH_CONFIG``), for the
#: reporters that send findings off the host. Stored results do not record which
#: tree was scanned, so a file outside the working directory and every git
#: checkout may still be the scanned tree's own (``reporter_trust.
#: confine_off_host_reporters_to_overrides``).
REPORT_CONFIG_FILE = UntrustedSource(
    reason=(
        "ash report cannot tell that config from the scanned repository's own, "
        "since stored results do not record which tree was scanned"
    ),
    remedy=(
        "To send findings off the host from ash report, pass the reporter's "
        "settings with --config-overrides (for example "
        "--config-overrides reporters.s3.enabled=true)."
    ),
    modules_remedy="To load a module, pass it with ash report's --config-overrides.",
)
