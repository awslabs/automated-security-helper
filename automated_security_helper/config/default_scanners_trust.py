# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, List, Optional, Sequence, Tuple

from automated_security_helper.config.operator_only_options import (
    DEFAULT_SCANNERS_FIELD,
    DEFAULT_SCANNERS_KEYS,
    RepositorySettings,
)
from automated_security_helper.config.recorded_config import _sets
from automated_security_helper.config.untrusted_source import (
    IN_TREE_OR_DELIVERED,
    UntrustedSource,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.override_key import split_override_key

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig


def _is_selection_override(override: str) -> bool:
    key = split_override_key(override)[0].strip().split(".")[0]
    return key.replace("-", "_") == DEFAULT_SCANNERS_FIELD


def confine_default_scanners(
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

    wanted = trusted_config.default_scanners
    written = dict(repository.selection_written) if repository is not None else {}
    named: List[str] = []
    for key in DEFAULT_SCANNERS_KEYS:
        held = getattr(config.default_scanners, key)
        trusted = getattr(wanted, key)
        if (held != trusted and _sets(config, [DEFAULT_SCANNERS_FIELD, key])) or (
            key in written and _differs_from(written[key], trusted)
        ):
            named.append(f"{DEFAULT_SCANNERS_FIELD}.{key}")
    if DEFAULT_SCANNERS_FIELD in written:
        named.append(DEFAULT_SCANNERS_FIELD)
    if config.default_scanners != wanted:
        config.default_scanners = wanted.model_copy(deep=True)
    if not named:
        return
    paths = ", ".join(named)
    files = ", ".join(describe_config_path(path) for path in in_tree)
    ASH_LOGGER.warning(
        f"Ignoring {paths} from {files}: the default scanners are the "
        f"operator's choice, and {source.reason}. The operator's selection, or "
        f"none, applies instead. {source.remedy}"
    )


def ignored_default_scanners(
    trusted_config: "AshConfig",
    config_overrides: Optional[Sequence[str]],
    repository: RepositorySettings,
) -> Tuple[List[str], List[str]]:
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    replayed = [o for o in config_overrides or [] if _is_selection_override(o)]
    wanted = trusted_config.default_scanners
    if replayed:
        try:
            wanted = apply_config_overrides(trusted_config, replayed).default_scanners
        except Exception:
            pass
    written = repository.selection_written
    ignored = [
        f"{DEFAULT_SCANNERS_FIELD}.{key}"
        for key in DEFAULT_SCANNERS_KEYS
        if key in written and _differs_from(written[key], getattr(wanted, key))
    ]
    if DEFAULT_SCANNERS_FIELD in written:
        ignored.append(DEFAULT_SCANNERS_FIELD)
    unknown = [
        f"{DEFAULT_SCANNERS_FIELD}.{key}"
        for key in dict.fromkeys(repository.selection_unknown)
    ]
    return ignored, unknown


def _differs_from(written: object, trusted: Sequence[str]) -> bool:
    return not isinstance(written, list) or list(written) != list(trusted)
