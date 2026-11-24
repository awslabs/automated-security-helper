# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, List, Optional, Sequence

from automated_security_helper.config.untrusted_source import (
    IN_TREE_OR_DELIVERED,
    UntrustedSource,
)
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig

SCANNER_SELECTION_CONFIG_FIELD = "scanner_selection"


def _is_selection_override(override: str) -> bool:
    key = override.partition("=")[0].removesuffix("+").strip().split(".")[0]
    return key.replace("-", "_") == SCANNER_SELECTION_CONFIG_FIELD


def confine_scanner_selection(
    config: "AshConfig",
    trusted_config: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    in_tree: Sequence[Path],
    source: UntrustedSource = IN_TREE_OR_DELIVERED,
) -> None:
    from automated_security_helper.config.config_sources import describe_config_path
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    replayed = [o for o in config_overrides or [] if _is_selection_override(o)]
    if replayed:
        trusted_config = apply_config_overrides(trusted_config, replayed)

    wanted = trusted_config.scanner_selection
    if config.scanner_selection == wanted:
        return
    changed: List[str] = []
    for name in ("only_scanners", "add_scanners"):
        if getattr(config.scanner_selection, name) != getattr(wanted, name):
            changed.append(f"{SCANNER_SELECTION_CONFIG_FIELD}.{name}")
    config.scanner_selection = wanted.model_copy(deep=True)
    files = ", ".join(describe_config_path(path) for path in in_tree)
    ASH_LOGGER.warning(
        f"Ignoring {', '.join(changed)} from {files}: the default scanner "
        f"selection is the operator's choice, and {source.reason}. The "
        f"operator's selection, or none, applies instead. {source.remedy}"
    )
