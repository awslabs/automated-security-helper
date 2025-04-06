# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from automated_security_helper.config.config import (
    ASHConfig,
)


DEFAULT_ASH_CONFIG = ASHConfig(
    project_name="automated-security-helper",
    output_dir="ash_output",
    fail_on_findings=True,
    ignore_paths=["tests/**"],
)
