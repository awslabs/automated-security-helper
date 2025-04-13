# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


def get_default_config():
    from automated_security_helper.config.ash_config import ASHConfig

    return ASHConfig(
        project_name="automated-security-helper",
        output_dir="ash_output",
        fail_on_findings=True,
        ignore_paths=["tests/**"],
    )
