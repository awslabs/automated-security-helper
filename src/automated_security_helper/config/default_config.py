# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import os
from pathlib import Path


def get_default_config():
    from automated_security_helper.utils.log import ASH_LOGGER
    from automated_security_helper.config.ash_config import ASHConfig

    config_env_var = os.environ.get("ASH_CONFIG", None)
    if config_env_var and Path(config_env_var).exists():
        ASH_LOGGER.info(
            f"Using ASH config path found in ASH_CONFIG variable: {config_env_var}"
        )
        return ASHConfig.from_file(config_env_var)

    return ASHConfig()
