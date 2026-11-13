# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which detect-secrets settings a config the operator did not write may supply.

Two of detect-secrets' settings act on the scanning host rather than on the scanned
files:

* The verification filter,
  ``detect_secrets.filters.common.is_ignored_due_to_verification_policies``, sends
  each candidate secret to the service that issued it; for an AWS access key id next
  to its secret key that is a request to ``sts.amazonaws.com`` signed with the pair
  found in the scanned file.
* A plugin or filter named by ``file://<path>`` is a Python file the detect-secrets
  worker imports, and a file outside the scanned tree is any file on the host.

So only the operator's own settings may turn either on. When ``resolve_config`` built
the config from a file the scanned repository or an MCP client wrote
(``config/sandbox_grants.py`` decides which), ``confine_detect_secrets_settings``
removes them from ``scanners.detect-secrets.options.scan_settings`` and records an
``UntrustedDetectSecretsSettings`` on the config, unless the trusted base the sandbox
grants come from (the operator's config file outside the tree, ``ASH_CONFIG``'s, or
the defaults) plus ``--config-overrides`` names the same thing: the operator asked
for it. The detect-secrets scanner reads the record for the baseline file, whose
settings resolve_config never sees: a baseline counts as the operator's only when it
is outside the scanned tree and either the config is the operator's or the trusted
base names that same ``baseline_file``. Offline, the scanner turns verification off
from every source.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, FrozenSet, Iterable, List, Optional, Sequence

from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    ASHRespelledOverrideError,
)
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanSettings,
    )

#: The function detect-secrets' verification filter is, whatever path names it.
VERIFICATION_FILTER_FUNCTION = "is_ignored_due_to_verification_policies"


@dataclass(frozen=True)
class UntrustedDetectSecretsSettings:
    """Recorded on a config built from files the operator did not write.

    Attributes:
        reason: Why those files are not the operator's, for warnings.
        operator_verifies: The trusted base, with ``--config-overrides`` replayed,
            names the verification filter itself.
        operator_baseline: The ``baseline_file`` the trusted base names, as written,
            or None.
        operator_paths: The ``file://`` plugin and filter paths the trusted base
            names. No other ``file://`` entry from this config, or from a baseline
            that is not the operator's, is imported.
    """

    reason: str
    operator_verifies: bool = False
    operator_baseline: Optional[str] = None
    operator_paths: FrozenSet[str] = field(default_factory=frozenset)


def is_verification_filter(path: object) -> bool:
    """Whether a ``filters_used`` path names detect-secrets' verification filter.

    Matched on the function, so both spellings count: the module path
    (``detect_secrets.filters.common.<function>``) and a ``file://<file>::<function>``
    entry, where a file outside the scanned tree can provide the same function.
    The scheme is read the way ``is_file_entry`` reads it, ignoring surrounding
    space and case, so an entry that counts as a file to import is also recognized as
    the verification filter when it names that function.
    """
    if not isinstance(path, str):
        return False
    if path.strip().lower().startswith("file://"):
        function = path.partition("::")[2]
    else:
        function = path.rpartition(".")[2]
    return function.strip() == VERIFICATION_FILTER_FUNCTION


def is_file_entry(path: object) -> bool:
    """Whether a ``plugins_used``/``filters_used`` path names a file to import."""
    return isinstance(path, str) and path.strip().lower().startswith("file://")


def file_entry_paths(entries: Iterable[object]) -> List[str]:
    """The ``file://`` paths of ``entries`` (plugin or filter settings), in order."""
    return [
        str(getattr(entry, "path", None)).strip()
        for entry in entries
        if is_file_entry(getattr(entry, "path", None))
    ]


def names_verification(config: "AshConfig") -> bool:
    """Whether ``config``'s detect-secrets scan settings name the verification filter."""
    settings = config.scanners.detect_secrets.options.scan_settings
    return any(is_verification_filter(item.path) for item in settings.filters_used)


def same_baseline(
    named: Optional[str | Path], chosen: Optional[str | Path], source_dir: str | Path
) -> bool:
    """Whether two ``baseline_file`` values name the same file, read from source_dir."""
    if not named or not chosen:
        return False
    resolved = []
    for value in (named, chosen):
        path = Path(os.path.expanduser(str(value)))
        if not path.is_absolute():
            path = Path(source_dir) / path
        resolved.append(os.path.realpath(path))
    return resolved[0] == resolved[1]


def _detect_secrets_overrides(config_overrides: Optional[Sequence[str]]) -> List[str]:
    """The ``--config-overrides`` entries that can change detect-secrets' settings.

    An entry at ``scanners`` whole, or one whose section segment is any spelling
    the apply folds onto the declared ``detect-secrets`` section
    (``DetectSecrets``, ``detectsecrets``, ``Detect-Secrets``;
    ``plugin_section_names.plugin_key_in``): an entry the apply lands on the
    section is replayed, so what the operator asked for is kept as the
    operator's under every spelling the config accepts.
    """
    from automated_security_helper.config.plugin_section_names import (
        folded_section_name,
    )

    wanted = folded_section_name("detect_secrets")
    selected: List[str] = []
    for override in config_overrides or []:
        key = override.partition("=")[0].removesuffix("+").strip()
        parts = [part.strip() for part in key.split(".")]
        if parts[0] != "scanners":
            continue
        if len(parts) == 1 or folded_section_name(parts[1]) == wanted:
            selected.append(override)
    return selected


def _replayed(trusted_config: "AshConfig", overrides: List[str]) -> "AshConfig":
    """``trusted_config`` with the detect-secrets ``overrides`` applied to it.

    Together first, as the scan's own apply takes them, so entries that are valid only
    as a set all land. When the set does not apply, each entry is applied on its own,
    in order, and one that does not apply drops only itself: it turns nothing on, and
    the entries that do apply still count as the operator's. This is the replay the
    reporters overrides get (``resolve_config._with_reporter_overrides``), including
    its one refusal: a respelled section (``ASHRespelledOverrideError``) is raised,
    not dropped.
    """
    if not overrides:
        return trusted_config
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    try:
        return apply_config_overrides(trusted_config, overrides)
    except ASHRespelledOverrideError:
        raise
    except ASHConfigValidationError:
        # One of them does not apply to the trusted base. They are applied again
        # one at a time below.
        pass
    replayed = trusted_config
    for override in overrides:
        try:
            replayed = apply_config_overrides(replayed, [override])
        except ASHRespelledOverrideError:
            raise
        except ASHConfigValidationError:
            # They applied to the resolved config already; one that does not apply
            # to the trusted base turns nothing on.
            continue
    return replayed


def confine_detect_secrets_settings(
    config: "AshConfig",
    trusted_config: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    in_tree: Iterable[Path],
    reason: str,
    remedy: str = KEEP_A_SETTING,
) -> None:
    """Remove what a config the operator did not write may not turn on, and record it.

    Args:
        config: The resolved AshConfig, changed in place.
        trusted_config: The trusted base ``resolve_config`` built for the sandbox
            settings. What it names, with the detect-secrets ``--config-overrides``
            replayed onto it, is the operator's and is kept.
        config_overrides: ``--config-overrides``.
        in_tree: The config files the operator did not write, named in the record.
        reason: Why those files are not the operator's.
        remedy: How to keep the settings, ending the warning. ``KEEP_A_SETTING``,
            unless a file's walk stopped.
    """
    # Imported here: config_sources imports ash_config, which imports the
    # detect-secrets scanner, which imports this module.
    from automated_security_helper.config.config_sources import describe_config_path

    trusted_config = _replayed(
        trusted_config, _detect_secrets_overrides(config_overrides)
    )
    trusted_options = trusted_config.scanners.detect_secrets.options
    trusted_settings = trusted_options.scan_settings
    files = ", ".join(describe_config_path(path) for path in in_tree) or "a config file"
    record = UntrustedDetectSecretsSettings(
        reason=f"the configuration was read from {files}: {reason}",
        operator_verifies=names_verification(trusted_config),
        operator_baseline=(
            str(trusted_options.baseline_file)
            if trusted_options.baseline_file is not None
            else None
        ),
        operator_paths=frozenset(
            file_entry_paths(trusted_settings.plugins_used)
            + file_entry_paths(trusted_settings.filters_used)
        ),
    )
    config._untrusted_detect_secrets_settings = record
    settings = config.scanners.detect_secrets.options.scan_settings
    removed = drop_untrusted_entries(settings, record)
    if removed:
        ASH_LOGGER.warning(
            "Ignoring scanners.detect-secrets.options.scan_settings entries "
            f"{', '.join(removed)}: {record.reason}. Only the operator's own "
            "configuration may turn on secret verification, which sends candidate "
            "secrets to their issuers, or name a plugin or filter file to import. "
            f"{remedy}"
        )


def drop_untrusted_entries(
    settings: "DetectSecretsScanSettings",
    record: UntrustedDetectSecretsSettings,
    *,
    keep_verification: Optional[bool] = None,
) -> List[str]:
    """Remove from ``settings`` what ``record`` does not let its source supply.

    The verification filter unless the operator names it, and every ``file://``
    plugin or filter the operator does not name. Returns what was removed.

    Args:
        settings: A ``DetectSecretsScanSettings``, changed in place.
        record: What the operator's own settings name.
        keep_verification: Overrides ``record.operator_verifies``.
    """
    verifies = (
        record.operator_verifies if keep_verification is None else keep_verification
    )
    removed: List[str] = []

    def keep(entry: object, *, filters: bool) -> bool:
        path = getattr(entry, "path", None)
        if filters and is_verification_filter(path) and not verifies:
            removed.append(str(path))
            return False
        if is_file_entry(path) and str(path).strip() not in record.operator_paths:
            removed.append(str(path))
            return False
        return True

    settings.plugins_used = [
        entry for entry in settings.plugins_used if keep(entry, filters=False)
    ]
    settings.filters_used = [
        entry for entry in settings.filters_used if keep(entry, filters=True)
    ]
    return removed
