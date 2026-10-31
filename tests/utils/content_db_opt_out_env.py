# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The environment variables a tool reads as its own database update setting.

The content database refresh tests clear these so a developer's or a CI shell's
setting cannot change what a test sees. One list, here, for every such test file:
grype's ``GRYPE_DB_AUTO_UPDATE`` is a common caching recipe in CI images, and
trivy's skip settings make its download-only commands refuse.
"""

TOOL_UPDATE_OPT_OUT_ENV = (
    "TRIVY_SKIP_DB_UPDATE",
    "TRIVY_SKIP_UPDATE",
    "TRIVY_SKIP_JAVA_DB_UPDATE",
    "GRYPE_DB_AUTO_UPDATE",
)
