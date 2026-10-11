# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from pathlib import Path
from typing import List, Optional


def _ash_config_file() -> Optional[Path]:
    """The file ASH_CONFIG names, or None when the variable is unset or empty.

    A named file that does not exist is refused rather than treated as unset:
    the operator chose a config, and scanning with the built-in one instead
    would drop its suppressions and settings while reporting success. An empty
    value counts as unset, as click treats an empty ``--config`` environment
    variable, so a CI template that passes an empty input keeps working.
    """
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    config_env_var = os.environ.get("ASH_CONFIG", None)
    if not config_env_var:
        return None
    if not config_env_var.strip():
        raise ASHConfigSourceError(
            "ASH_CONFIG is set to only whitespace. Unset it, or set it to the path "
            "of a config file."
        )
    path = Path(config_env_var)
    if not path.exists():
        raise ASHConfigSourceError(
            f"ASH_CONFIG names {config_env_var}, which does not exist. Point "
            "ASH_CONFIG at an existing config file, or unset it to use ASH's "
            "built-in defaults."
        )
    return path


def get_default_config():
    from automated_security_helper.utils.log import ASH_LOGGER
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.resolve_config import load_config_file

    path = _ash_config_file()
    if path is not None:
        ASH_LOGGER.info(
            "Using ASH config path found in ASH_CONFIG variable: "
            f"{os.environ['ASH_CONFIG']}"
        )
        return load_config_file(path)

    return AshConfig()


def default_config_names() -> List[Path]:
    """default_config_chain()'s files by the paths that named them; see
    ``ResolvedConfigDocument.named``."""
    from automated_security_helper.config.config_sources import (
        resolve_config_document,
    )

    config_env_var = os.environ.get("ASH_CONFIG", None)
    if not (config_env_var and Path(config_env_var).exists()):
        return []
    return list(resolve_config_document(Path(config_env_var)).named)


def default_config_chain() -> List[Path]:
    """The files get_default_config() reads: ASH_CONFIG and its extends bases, or none."""
    from automated_security_helper.config.resolve_config import read_config_document

    path = _ash_config_file()
    if path is None:
        return []
    return list(read_config_document(path).chain)
