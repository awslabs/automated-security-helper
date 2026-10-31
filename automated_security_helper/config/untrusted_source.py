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
merge imports is a shard's choice, so the merge loads the modules the trusted base
names, and an entry only the shard names is dropped, where a scan keeps an
installed module outside the tree.
"""

import dataclasses
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
        named_modules_only: Replace ``ash_plugin_modules`` with the trusted
            base's list: drop every entry it does not name, rather than keeping
            an installed module outside the tree, and add the ones it names.
        scanner_steps_note: What the sandbox and scanner-config steps' warnings
            say in place of their remedy, where no scanner runs. None gives the
            remedy.
        fills_missing_sections: Give a reporter section the config leaves out the
            trusted base's destination options. A file inside the tree, or one an
            MCP client delivered, replaces the operator's config, so leaving a
            section out would drop the operator's values. ``ash merge``'s
            ``--config`` supplies values for what a shard recorded without adding
            to it (``cli/merge.py``), so the merge does not fill sections.
        located: The config is a file the confinement walk placed, so the
            sandbox and plugin-module warnings explain the drop by where it
            sits (``sandbox_grants.membership_clause``). False for a config
            that is no file in a tree (``SHARD_RECORDED``): those warnings say
            ``reason`` instead, as the reporter and scanner-config steps do.
    """

    reason: str
    remedy: str
    modules_remedy: str
    named_modules_only: bool = False
    scanner_steps_note: Optional[str] = None
    fills_missing_sections: bool = True
    located: bool = True


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
    remedy=(
        "To keep a setting, pass it with ash merge's --config-overrides or --config. "
        "A reporter setting that sends findings off the host is the exception: "
        "ash merge replaces the --config file's value for it, so pass it with "
        "--config-overrides."
    ),
    modules_remedy=(
        "To keep a module, pass it with ash merge's --config-overrides or --config."
    ),
    named_modules_only=True,
    scanner_steps_note=(
        "No scanner runs during a merge, so this changes only the merged results, "
        "which record the operator's value"
    ),
    fills_missing_sections=False,
    located=False,
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
        "To send findings off the host from ash report, pass each of these "
        "settings with --config-overrides instead."
    ),
    modules_remedy="To load a module, pass it with ash report's --config-overrides.",
)

#: A config file ``ash report`` was named and ``resolve_config`` placed inside a git
#: checkout or the working directory. The reason is the one for a file in a tree.
#: The remedy is ``REPORT_CONFIG_FILE``'s: ``ash report`` holds any file it is
#: named, so moving this one out of the tree would not change that.
REPORT_CONFIG_FILE_IN_TREE = dataclasses.replace(
    IN_TREE_OR_DELIVERED,
    remedy=REPORT_CONFIG_FILE.remedy,
    modules_remedy=REPORT_CONFIG_FILE.modules_remedy,
)

#: ``ash merge``'s ``--config`` file, for the reporters that send findings off the
#: host. The shards do not record which tree was scanned, so the file may be the
#: scanned tree's own, as for ``REPORT_CONFIG_FILE``.
MERGE_CONFIG_FILE = UntrustedSource(
    reason=(
        "ash merge cannot tell that config from the scanned repository's own, "
        "since the shards do not record which tree was scanned"
    ),
    remedy=(
        "To send the merged findings off the host, pass each of these settings "
        "with ash merge's --config-overrides instead."
    ),
    modules_remedy="To load a module, pass it with ash merge's --config-overrides.",
)
