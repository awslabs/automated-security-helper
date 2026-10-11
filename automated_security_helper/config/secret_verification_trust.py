# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Who may turn on detect-secrets' secret verification.

detect-secrets verifies a candidate secret by sending it to the service that issued
it. The filter ``detect_secrets.filters.common.is_ignored_due_to_verification_policies``
calls each plugin's ``verify()``; for an AWS access key id next to its secret key
that is a request to ``sts.amazonaws.com`` signed with the pair found in the scanned
file. Whoever turns the filter on decides that the scanning host contacts those
services with credentials taken from the scanned tree, so only the operator does.

When ``resolve_config`` built the config from a file the scanned repository or an MCP
client wrote (``config/sandbox_grants.py`` decides which), the filter is removed from
``scanners.detect-secrets.options.scan_settings`` and the config records why in
``AshConfig._secret_verification_refusal``. The detect-secrets scanner reads that
record and removes the filter from the baseline file too, including a baseline
outside the tree that such a config names. Both are skipped when the trusted base
the sandbox grants come from (the operator's config file outside the tree,
``ASH_CONFIG``'s, or the defaults) plus ``--config-overrides`` names the filter: the
operator then asked for verification.

The scanner applies two more rules itself (``DetectSecretsScanner``): a baseline
inside the scanned tree never turns verification on, whichever config led to it,
and in offline mode nothing does.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Optional, Sequence

from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig

#: The function detect-secrets' verification filter is, whatever path names it.
VERIFICATION_FILTER_FUNCTION = "is_ignored_due_to_verification_policies"


def is_verification_filter(path: object) -> bool:
    """Whether a ``filters_used`` path names detect-secrets' verification filter.

    Matched on the function, so both spellings count: the module path
    (``detect_secrets.filters.common.<function>``) and a ``file://<file>::<function>``
    entry, where a file outside the scanned tree can provide the same function.
    """
    if not isinstance(path, str):
        return False
    if path.startswith("file://"):
        function = path.partition("::")[2]
    else:
        function = path.rpartition(".")[2]
    return function.strip() == VERIFICATION_FILTER_FUNCTION


def names_verification(config: "AshConfig") -> bool:
    """Whether ``config``'s detect-secrets scan settings name the verification filter."""
    settings = config.scanners.detect_secrets.options.scan_settings
    return any(is_verification_filter(item.path) for item in settings.filters_used)


def _detect_secrets_overrides(config_overrides: Optional[Sequence[str]]) -> list:
    """The ``--config-overrides`` entries that can change detect-secrets' settings."""
    selected = []
    for override in config_overrides or []:
        key = override.partition("=")[0].removesuffix("+").strip().replace("-", "_")
        if key == "scanners" or key.startswith("scanners.detect_secrets"):
            selected.append(override)
    return selected


def confine_secret_verification(
    config: "AshConfig",
    trusted_config: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    in_tree: Iterable[Path],
    reason: str,
) -> None:
    """Refuse secret verification for a config the operator did not write.

    Args:
        config: The resolved AshConfig, changed in place.
        trusted_config: The trusted base ``resolve_config`` built for the sandbox
            settings. When it, with the detect-secrets ``--config-overrides``
            replayed onto it, names the filter, nothing is refused.
        config_overrides: ``--config-overrides``.
        in_tree: The config files the operator did not write, named in the record.
        reason: Why those files are not the operator's.
    """
    # Imported here: config_sources imports ash_config, which imports the
    # detect-secrets scanner, which imports this module.
    from automated_security_helper.config.config_sources import describe_config_path

    overrides = _detect_secrets_overrides(config_overrides)
    if overrides:
        from automated_security_helper.config.resolve_config import (
            apply_config_overrides,
        )

        try:
            trusted_config = apply_config_overrides(trusted_config, overrides)
        except ASHConfigValidationError:
            # They applied to the resolved config already; one that does not apply
            # to the trusted base turns nothing on.
            pass
    if names_verification(trusted_config):
        return
    files = ", ".join(describe_config_path(path) for path in in_tree) or "a config file"
    refusal = (
        f"the configuration was read from {files}: {reason}. Secret verification is "
        "turned on only by the operator's own configuration"
    )
    config._secret_verification_refusal = refusal
    settings = config.scanners.detect_secrets.options.scan_settings
    kept = [
        item for item in settings.filters_used if not is_verification_filter(item.path)
    ]
    if len(kept) != len(settings.filters_used):
        ASH_LOGGER.warning(
            "Ignoring scanners.detect-secrets.options.scan_settings.filters_used "
            f"entry {VERIFICATION_FILTER_FUNCTION}: {refusal}. Candidate secrets are "
            "reported without asking their issuers."
        )
        settings.filters_used = kept
