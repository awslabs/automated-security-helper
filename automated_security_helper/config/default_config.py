# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple


def get_default_config():
    from automated_security_helper.utils.log import ASH_LOGGER
    from automated_security_helper.config.ash_config import AshConfig

    config_env_var = os.environ.get("ASH_CONFIG", None)
    if config_env_var and Path(config_env_var).exists():
        ASH_LOGGER.info(
            f"Using ASH config path found in ASH_CONFIG variable: {config_env_var}"
        )
        return AshConfig.from_file(config_env_var)

    return AshConfig()


def default_config_document():
    """The resolution of the file ASH_CONFIG names, with its extends bases, or None.

    A ``config_sources.ResolvedConfigDocument``: the files get_default_config()
    reads, each file's document, and the paths each was reached by.
    """
    from automated_security_helper.config.config_sources import (
        resolve_config_document,
    )

    config_env_var = os.environ.get("ASH_CONFIG", None)
    if not (config_env_var and Path(config_env_var).exists()):
        return None
    return resolve_config_document(Path(config_env_var))


def default_config_chain() -> List[Path]:
    """The files get_default_config() reads: ASH_CONFIG and its extends bases, or none."""
    document = default_config_document()
    return list(document.chain) if document is not None else []


def default_config_documents() -> Dict[Path, Any]:
    """Each file of default_config_chain() with its parsed document, or none."""
    document = default_config_document()
    return dict(document.documents) if document is not None else {}


def default_config_names() -> Dict[Path, Tuple[Path, ...]]:
    """The paths each file of default_config_chain() was reached by, or none."""
    document = default_config_document()
    return dict(document.names) if document is not None else {}
