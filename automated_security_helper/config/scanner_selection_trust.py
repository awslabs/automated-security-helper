# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, List, Optional, Sequence

from automated_security_helper.config.operator_only_options import (
    SCANNER_SELECTION_FIELD,
    SCANNER_SELECTION_KEYS,
    RepositorySettings,
)
from automated_security_helper.config.recorded_config import _sets
from automated_security_helper.config.untrusted_source import (
    IN_TREE_OR_DELIVERED,
    UntrustedSource,
)
from automated_security_helper.utils.log import ASH_LOGGER

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig


def _is_selection_override(override: str) -> bool:
    key = override.partition("=")[0].removesuffix("+").strip().split(".")[0]
    return key.replace("-", "_") == SCANNER_SELECTION_FIELD


def confine_scanner_selection(
    config: "AshConfig",
    trusted_config: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    in_tree: Sequence[Path],
    source: UntrustedSource = IN_TREE_OR_DELIVERED,
    repository: Optional[RepositorySettings] = None,
) -> None:
    from automated_security_helper.config.config_sources import describe_config_path
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    replayed = [o for o in config_overrides or [] if _is_selection_override(o)]
    if replayed:
        trusted_config = apply_config_overrides(trusted_config, replayed)

    wanted = trusted_config.scanner_selection
    written = dict(repository.selection_written) if repository is not None else {}
    named: List[str] = []
    for key in SCANNER_SELECTION_KEYS:
        held = getattr(config.scanner_selection, key)
        trusted = getattr(wanted, key)
        if (held != trusted and _sets(config, [SCANNER_SELECTION_FIELD, key])) or (
            key in written and _differs_from(written[key], trusted)
        ):
            named.append(f"{SCANNER_SELECTION_FIELD}.{key}")
    if SCANNER_SELECTION_FIELD in written:
        named.append(SCANNER_SELECTION_FIELD)
    if config.scanner_selection != wanted:
        config.scanner_selection = wanted.model_copy(deep=True)
    if not named:
        return
    paths = ", ".join(named)
    files = ", ".join(describe_config_path(path) for path in in_tree)
    ASH_LOGGER.warning(
        f"Ignoring {paths} from {files}: the default scanner selection is the "
        f"operator's choice, and {source.reason}. The operator's selection, or "
        f"none, applies instead. {source.remedy}"
    )


def _differs_from(written: object, trusted: Sequence[str]) -> bool:
    return not isinstance(written, list) or list(written) != list(trusted)
