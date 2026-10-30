# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Relaxing the stale content database gate is the operator's choice.

Why this exists
---------------
A scan fails when a scanner's content database (grype's or trivy's vulnerability
database, the offline semgrep and opengrep rulesets) is older than its declared
bound (``utils/content_db_staleness.py``). Three settings relax that:
``content_db_staleness: warn`` for every database, a
``content_db_staleness_overrides`` entry with ``policy: warn`` for one, and
``content_db_staleness_offline_image_default: true``, which holds trivy-db to
``warn`` in an image built with ``OFFLINE=YES``. All are top-level keys of the
config; no scanner has a staleness option of its own. A config file inside the
scanned tree could set any of them, so the repository being scanned could have
its scan pass against an out-of-date database.

What happens now
----------------
When the config was built from a file inside the scanned tree, or from a file an
MCP client delivered, ``resolve_config`` runs ``confine_content_db_staleness``
after the other confinement steps. The values come from the trusted base (the
defaults, ``ASH_CONFIG`` or an operator config outside the tree) with the
operator's ``--config-overrides`` replayed, which is how
``--allow-stale-content-db`` and its ``--no-`` form arrive. A repository value
equal to the operator's is kept: ``content_db_staleness`` equal to the trusted
base's, and an overrides entry equal to one of the trusted base's entries. A
value that only makes the gate stricter is kept too: ``content_db_staleness:
fail``, and any entry with ``policy: fail``. Every other entry, a ``policy: warn``
the operator did not set, is dropped, and the policy and the dropped entries' databases are
named in one warning. An own ``policy: fail`` entry that has expired is dropped too when the
operator holds that database to ``fail`` with an entry still in force: at run time an expired
entry is ignored and the database returns to the scan-wide policy, laxer than the operator's,
so the operator's entry is carried in its place. One kind of entry is added: the operator's ``policy: fail``
entries for databases the repository's config has no entry for, since those
narrow a scan-wide ``warn`` the config may have repeated, and without them the
repository's config would hold those databases to a laxer policy than the
operator's. A ``policy: warn`` entry of the operator's is not copied in: the
policy the repository's config keeps is at least as strict for that database.
``content_db_staleness_offline_image_default``
is kept when it is false, or when the trusted base's is true; a true where the
operator's is false is set back to false, and named in the same warning when a
file wrote it (the field defaults to true, so a config that never mentions it is
set back without being named).

Under the MCP server the default ``denied_paths`` already refuse a client's file
that sets any of these keys, and an MCP runtime patch cannot change them.

Constraints and known limitations
---------------------------------
* ``ash merge`` does not run this step. The settings its verdict reads, these
  among them, come from the shards, each of which ran it when it resolved its own
  config, and shards that disagree are refused (``cli/merge.py``).
* An entry is kept or dropped whole, and compared field by field: a repository
  entry that relaxes the same database as the operator's but with another
  ``expiration`` or ``reason`` is dropped.
* The policy is not copied from the operator into a repository's config either:
  where ``ASH_CONFIG`` sets ``warn`` and a repository's config is selected, the
  repository's ``fail`` (its own or the default) applies, as before.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence

from automated_security_helper.config.recorded_config import _sets
from automated_security_helper.config.untrusted_source import (
    IN_TREE_OR_DELIVERED,
    UntrustedSource,
)
from automated_security_helper.utils.content_databases import (
    STALENESS_CONFIG_FIELD,
    STALENESS_FAIL,
    STALENESS_OFFLINE_IMAGE_CONFIG_FIELD,
    STALENESS_OVERRIDES_CONFIG_FIELD,
)
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig


def _is_staleness_override(override: str) -> bool:
    key = override.partition("=")[0].removesuffix("+").strip().split(".")[0]
    return key.replace("-", "_") in (
        STALENESS_CONFIG_FIELD,
        STALENESS_OVERRIDES_CONFIG_FIELD,
        STALENESS_OFFLINE_IMAGE_CONFIG_FIELD,
    )


def _dump(entry: Any) -> Dict[str, Any]:
    return entry.model_dump(mode="json")


def confine_content_db_staleness(
    config: "AshConfig",
    trusted_config: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    in_tree: Sequence[Path],
    source: UntrustedSource = IN_TREE_OR_DELIVERED,
) -> None:
    """Replace the staleness relaxations a config that is not the operator's set.

    Args:
        config: The resolved AshConfig, changed in place.
        trusted_config: The trusted base ``resolve_config`` built: the defaults,
            or the operator's config outside the tree.
        config_overrides: The operator's ``--config-overrides``. Those that set
            ``content_db_staleness``, ``content_db_staleness_overrides`` or
            ``content_db_staleness_offline_image_default`` are replayed onto
            ``trusted_config``.
        in_tree: The config files that are not the operator's, named in the
            warning.
        source: Why those files are not the operator's, and the fix, for the
            warning.
    """
    from automated_security_helper.config.config_sources import describe_config_path
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    replayed = [o for o in config_overrides or [] if _is_staleness_override(o)]
    if replayed:
        trusted_config = apply_config_overrides(trusted_config, replayed)

    ignored: List[str] = []
    policy = config.content_db_staleness
    if policy != trusted_config.content_db_staleness and policy != STALENESS_FAIL:
        ignored.append(STALENESS_CONFIG_FIELD)
        config.content_db_staleness = trusted_config.content_db_staleness

    trusted_entries = [
        _dump(entry) for entry in trusted_config.content_db_staleness_overrides
    ]
    # The databases the operator holds to ``fail`` with an entry still in force.
    # A config's own entry for one of them that has expired holds the database
    # to nothing: at run time an expired entry is ignored and the database
    # returns to the scan-wide policy (``utils/content_db_staleness.py``), laxer
    # than the operator's entry for it, and the run-time read stops at the first
    # entry naming the database. Kept, it blocked the carry below; it is dropped
    # first, and the operator's entry is carried in its place.
    operator_fail_databases = {
        entry.database
        for entry in trusted_config.content_db_staleness_overrides
        if entry.policy == STALENESS_FAIL and not entry.is_expired()
    }
    kept = []
    dropped: List[str] = []
    for entry in config.content_db_staleness_overrides:
        if entry.database in operator_fail_databases and entry.is_expired():
            dropped.append(entry.database)
        elif entry.policy == STALENESS_FAIL or _dump(entry) in trusted_entries:
            kept.append(entry)
        else:
            dropped.append(entry.database)
    if dropped:
        ignored.append(
            f"{STALENESS_OVERRIDES_CONFIG_FIELD} entries for {', '.join(dropped)}"
        )
    # The operator's per-database ``policy: fail`` entries narrow the scan-wide
    # policy for the databases they name. A config that repeats the operator's
    # ``content_db_staleness: warn`` (kept above as equal) but leaves those
    # entries out would hold those databases to warn, laxer than the operator's
    # setting for them, so each one the config has no entry for is carried over.
    # An entry the config has for the same database is the config's own: a
    # ``fail`` is already as strict, and a dropped ``warn`` makes way for the
    # operator's entry here.
    kept_databases = {entry.database for entry in kept}
    carried = [
        entry
        for entry in trusted_config.content_db_staleness_overrides
        if entry.policy == STALENESS_FAIL and entry.database not in kept_databases
    ]
    if dropped or carried:
        config.content_db_staleness_overrides = [*kept, *carried]

    # true holds trivy-db to warn in an image built with OFFLINE=YES, so it relaxes
    # the gate as warn does; false only makes it stricter. The field defaults to
    # true, so a true here is the file's own only when a file wrote it: a config
    # that never mentions the field is set back to false without being blamed.
    if (
        config.content_db_staleness_offline_image_default
        and not trusted_config.content_db_staleness_offline_image_default
    ):
        if _sets(config, [STALENESS_OFFLINE_IMAGE_CONFIG_FIELD]):
            ignored.append(STALENESS_OFFLINE_IMAGE_CONFIG_FIELD)
        config.content_db_staleness_offline_image_default = False

    if ignored:
        files = ", ".join(describe_config_path(path) for path in in_tree)
        ASH_LOGGER.warning(
            f"Ignoring {'; '.join(ignored)} from {files}: relaxing the stale content "
            "database check is the operator's choice, and "
            f"{source.reason}. The operator's policy, or the default "
            f"({STALENESS_FAIL}), applies instead. {source.remedy} Or pass "
            "--allow-stale-content-db."
        )
